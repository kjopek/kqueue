/*-
 * (c) 2016
 *
 * Naive implementation of Internet topology scanner.
 *
 * Uses mmaped files as required amount of memory exceedes typical PC
 * limitation.
 */

#define __USE_BSD
#define __FAVOR_BSD

#include <sys/types.h>
#include <sys/param.h>
#include <sys/cdefs.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/capsicum.h>

#include <arpa/inet.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <inttypes.h>
#include <limits.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>
#include <time.h>

#include "utils.h"

#define ICMP_OFFSET (sizeof(struct ip))
#define PACKET_SIZE (sizeof(struct ip) + ICMP_MINLEN)
#define MAX_CONCURRENT_SCANS 1024

/*
 * During runtime our graph will be represented as adjancency list stored in
 * memory-mapped file. All offsets in file must be translated into memory
 * addresses.
 *
 * TODO: think about conversion to CSR (after scan completion)
 * TODO: minimize memory usage (apart from MAP_SHARED)
 * TODO: insertion shoud be O(1) (head-insert)
 * TODO: fast scan in case of timeouts?
 */

struct edge {
	in_addr_t	 addr;
	/*
	 * Offset in file. Must be
	 * converted into vm addr.
	 */
	uint64_t	 next;
} __packed;

struct vertex {
	/* Absolute offset in file or 0 if no neighbours. */
	struct edge	*neighbours;

#if BYTE_ORDER == LITTLE_ENDIAN
	uint8_t		 achievable:1,
			 padding1:7;
#elif BYTE_ORDER == BIG_ENDIAN
	uint8_t		 padding1:7,
			 achievable:1;
#else
#error "Unknown byte ordering."
#endif

} __packed;

struct session {
	struct timespec	 ts;
	struct in_addr	 dest;
	int		 last_ttl;
	int		 active;
};

struct graph {
	void		*vm_map;
	size_t		 vm_map_size;

	/* Number of vertices = (1 << 32). Pointers based on vm_map_size */
	struct vertex	*vertices;
	struct edge	*edges;

	/* Workspace */
	struct session	 sessions[MAX_CONCURRENT_SCANS];
	int		 free[MAX_CONCURRENT_SCANS];
	int		 nidx;
	uint64_t	 counter;
	uint64_t	 max_counter;

	int		 fd;
};

static struct option opts[] = {
	{"net",		required_argument,	NULL,	'n'},
	{"mask",	required_argument,	NULL,	'm'},
	{"graph",	required_argument,	NULL,	'g'},
	{"help",	no_argument,		NULL,	'h'},
	{NULL,		0,			NULL,	0}
};

static void usage(const char *progname);
static ssize_t send_packet(int sock, in_addr_t addr, unsigned char ttl, int id);
static ssize_t recv_packet(int sock, unsigned char *buffer, const int nbytes);
static ssize_t scan_next(int kq, int sock, struct graph *graph, int idx);
static ssize_t scan_curr(int kq, int sock, struct graph *graph, int idx);
static void dispatch_evwrite(int kq, int sock, struct graph *graph);
static void dispatch_evread(int kq, int sock, intptr_t nbytes, struct graph *graph);
static bool dispatch_evtimeout(int kq, int sock, struct graph *graph);
static void mainloop(int sock, struct graph *graph);
static int create_raw_sock(void);

static void
usage(const char *progname)
{

	fprintf(stderr, "%s: [--net <ipaddr>] [--mask <int>] [--help] [--graph]\n", progname);
}


static ssize_t
send_packet(int sock, in_addr_t addr, unsigned char ttl, int id)
{
	unsigned char buffer[PACKET_SIZE] __attribute__((aligned(64)));
	struct ip *ip;
	struct icmp *icmp;
	struct sockaddr_in inaddr;
	ssize_t ret;

	assertx(id < MAX_CONCURRENT_SCANS, "Invalid id: %d", id);
	assertx(id >= 0, "Invalid id: %d", id);

	/* We sent constant-sized packets. */
	memset(buffer, '\0', PACKET_SIZE);
	ip = (struct ip *)buffer;
	icmp = (struct icmp *)(buffer + ICMP_OFFSET);

	memset(&inaddr, 0, sizeof(inaddr));
	inaddr.sin_family = AF_INET;
	inaddr.sin_addr.s_addr = addr;
	inaddr.sin_port = 0;

	/* Fill the buffer. Pay attention to byte ordering and checksums. */
	ip->ip_v = IPVERSION;
	ip->ip_hl = sizeof(*ip) >> 2;
	ip->ip_tos = 0;
	ip->ip_id = 0;
	ip->ip_off = 0;
	ip->ip_ttl = ttl;
	ip->ip_p = IPPROTO_ICMP;
	ip->ip_src.s_addr = INADDR_ANY;
	ip->ip_dst.s_addr = addr;
	ip->ip_len = htons(PACKET_SIZE);
	ip->ip_sum = 0;

	icmp->icmp_type = 8;
	icmp->icmp_code = 0;
	icmp->icmp_id = htons(id & 0xffff);
	icmp->icmp_seq = 1;

	icmp->icmp_cksum = in_cksum((uint16_t *)icmp, ICMP_MINLEN);

	ret = sendto(sock, (void *)buffer, PACKET_SIZE, 0,
	    (const struct sockaddr *)&inaddr, sizeof(inaddr));

#ifdef DEBUG
	printf("OUT :% 3d %-15s (%d)\n", ip->ip_ttl, inet_ntoa(ip->ip_dst),
	    icmp->icmp_type);
#endif

	if (ret < 0) {
		fprintf(stderr, "Warning: sendto(2) returned %jd while sending to %s",
		    ret, inet_ntoa(inaddr.sin_addr));
		fprintf(stderr, " errno=%zd\n", errno);
	}

	return (ret);
}

static ssize_t
recv_packet(int sock, unsigned char *buffer, const int nbytes)
{
	ssize_t ret;

	assertx(buffer != NULL, "Buffer is null");

	ret = recvfrom(sock, (void *)buffer, nbytes, 0, NULL, NULL);
	if (ret < 0)
		err(1, "recv(2) failed with ret=%zd", ret);

	return (ret);
}

static ssize_t
scan_next(int kq, int sock, struct graph *graph, int idx)
{
	struct session *session;

	if (graph->counter < graph->max_counter) {
		graph->counter = ip4_next_addr(graph->counter);

		session = &graph->sessions[idx];
		session->dest.s_addr = htonl((uint32_t)graph->counter);
		session->last_ttl = 0;

		return (scan_curr(kq, sock, graph, idx));
	}

	fprintf(stderr, "Finished scan.\n");
	return (-1);
}

static ssize_t
scan_curr(int kq, int sock, struct graph *graph, int idx)
{
	struct session *session;
	ssize_t ret;

	session = &graph->sessions[idx];
	session->last_ttl++;
	session->active = 1;

	assertx(session->dest.s_addr != 0, "Destination is 0");

	clock_gettime(CLOCK_REALTIME_PRECISE, &session->ts);
	ret = send_packet(sock, session->dest.s_addr, session->last_ttl, idx);

	if (ret < 0) {
		/*
		 * Check error reason. If host is unreachable we should rather
		 * continue scanning instead of reverse state.
		 */
		if (errno == EHOSTDOWN && graph->counter < graph->max_counter)
			return scan_next(kq, sock, graph, idx);

		if (errno != EHOSTDOWN) {
			keventx(kq, sock, EVFILT_WRITE, EV_ADD | EV_ENABLE |
			    EV_ONESHOT, 0, 0, NULL);
			session->last_ttl--;
		}
	}

	return (ret);
}

static void
dispatch_evwrite(int kq, int sock, struct graph *graph)
{
	int idx;

	while (graph->nidx < MAX_CONCURRENT_SCANS &&
	    graph->counter < graph->max_counter) {
		idx = graph->nidx;

		/*
		 * Continue scanning until sendto returns error.
		 */
		if (scan_next(kq, sock, graph, idx) == PACKET_SIZE)
			graph->nidx++;
		else
			break;
	}
}

static void
dispatch_evread(int kq, int sock, intptr_t nbytes, struct graph *graph)
{
	unsigned char buffer[1024];
	struct ip *ip, *orig_ip;
	struct icmp *icmp, *orig_icmp;
	int idx;
	ssize_t ret;

	ret = recv_packet(sock, buffer, nbytes < (intptr_t)sizeof(buffer) ?
	    nbytes : sizeof(buffer));

	assertx(ret > 0, "Ret is %d <= 0", ret);

	idx = 0;
	ip = (struct ip *)buffer;
	icmp = (struct icmp *)(buffer + ICMP_OFFSET);

#ifdef DEBUG
	printf("IN  :% 3d %-15s (%d)\n", ip->ip_ttl, inet_ntoa(ip->ip_src),
	    icmp->icmp_type);
#endif

	if (ret >= (ssize_t)(2 * PACKET_SIZE)) {
		/* We got reply with original packet. */
		orig_ip = (struct ip *)(buffer + PACKET_SIZE);
		orig_icmp = (struct icmp *)(buffer + PACKET_SIZE +
		    sizeof(*orig_ip));

		/* If possible - take index from original packet. */
		idx = ntohs(orig_icmp->icmp_id);
		assertx(orig_ip->ip_dst.s_addr == graph->sessions[idx].dest.s_addr,
		    "invalid destination IP: %s",
		    inet_ntoa(orig_ip->ip_dst));
	} else {
		/* If not - take it from incoming icmp_id */
		idx = ntohs(icmp->icmp_id);
	}

	switch (icmp->icmp_type) {
	case ICMP_TIMXCEED:
		assertx(ret >= (ssize_t)(2 * PACKET_SIZE),
		    "Invalid packet size: %d", ret);
		scan_curr(kq, sock, graph, idx);
		break;
	case ICMP_UNREACH:
		assertx(ret >= (ssize_t)(2 * PACKET_SIZE),
		    "Invalid packet size: %d", ret);
		graph->sessions[idx].active = 0;
		scan_next(kq, sock, graph, idx);
		break;
	case ICMP_ECHOREPLY:
		/*
		 * Echo reply may not have original data. But we can
		 * still use packet from destination.
		 */
		assertx(ip->ip_src.s_addr == graph->sessions[idx].dest.s_addr,
		    "Source address (%08x) is not the same as destination address (%08x)",
		    ntohl(ip->ip_src.s_addr),
		    ntohl(graph->sessions[idx].dest.s_addr));

		graph->sessions[idx].active = 0;

		printf("Reached: %s\n", inet_ntoa(ip->ip_src));
		scan_next(kq, sock, graph, idx);
		break;
	default:
		/*
		 * This should not happen as long as we use sockets
		 * from underlying OS. In case of NetMap we will have
		 * to deal with all possible range of packets.
		 * */
		printf("Invalid ICMP message: %d\n", icmp->icmp_type);
		break;
	}
}

static bool
dispatch_evtimeout(int kq, int sock, struct graph *graph)
{
	int idx;
	bool active;
	ssize_t ret;
	struct session *session;
	struct timespec ts;

	clock_gettime(CLOCK_REALTIME_PRECISE, &ts);

	assertx(graph->nidx <= MAX_CONCURRENT_SCANS, "Invalid nidx: %d",
	    graph->nidx);

	active = false;
	for (idx = 0; idx < graph->nidx; idx++) {
		session = &graph->sessions[idx];
		assertx(session->dest.s_addr != 0, "Invalid destination value: %s",
		    inet_ntoa(session->dest));
		assertx(session->last_ttl != 0, "Invalid last ttl value: %d",
		    session->last_ttl);

		/* Timeout = 1s */
		if (time_diff(&session->ts, &ts) < 1.0) {
			active = true;
			continue;
		}

		if (session->last_ttl == 255 || !session->active) {
			ret = scan_next(kq, sock, graph, idx);
			if (ret > 0)
				active = true;
		} else {
			scan_curr(kq, sock, graph, idx);
			active = true;
		}
	}

	if (graph->nidx < MAX_CONCURRENT_SCANS)
		active = true;

	return (active);
}

static void
mainloop(int sock, struct graph *graph)
{
	int kq, nev;
	struct kevent ev;
	struct timespec tv;
	bool running;

	kq = kqueue();
	if (kq == -1)
		err(1, "kqueue(2) failed");

	/*
	 * Register events. ONESHOT is only for writing as we want to
	 * re-register that event after successful packet transmission.
	 */
	keventx(kq, sock, EVFILT_READ, EV_ADD | EV_ENABLE, 0, 0, NULL);
	keventx(kq, sock, EVFILT_WRITE, EV_ADD | EV_ENABLE | EV_ONESHOT, 0, 0,
	    NULL);
	keventx(kq, SIGINT, EVFILT_SIGNAL, EV_ADD | EV_ENABLE, 0, 0, NULL);

	running = true;
	while (running) {
		tv.tv_sec = 0;
		tv.tv_nsec = 500000000;
		nev = kevent(kq, NULL, 0, &ev, 1, &tv);

		if (nev == -1)
			err(1, "kevent(2) failed");

		if (nev == 1) {
			switch (ev.filter) {

			case EVFILT_READ:
				dispatch_evread(kq, sock, ev.data, graph);
				break;

			case EVFILT_WRITE:
				dispatch_evwrite(kq, sock, graph);
				break;

			case EVFILT_SIGNAL:
				printf("exiting...\n");
				return;
			}
		}

		/*
		 * In case of timeout - simply scan workspace and find
		 * sessions that stucked.
		 */
		if (nev == 0)
			running = dispatch_evtimeout(kq, sock, graph);
	}

	return;
}

static void
setup_graph_file(in_addr_t addr, int mask, const char *filename,
    struct graph *graph)
{
	mode_t perms;

	graph->counter = ntohl(addr);
	graph->max_counter = graph->counter + (1 << (32 - mask)) - 1;
	graph->vm_map_size = (size_t)0x100000000 * sizeof(struct vertex);

	perms = S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH;

	graph->fd = open(filename, O_CREAT | O_RDWR, perms);
	if (graph->fd < 0)
		err(1, "open(2) failed");

	if (ftruncate(graph->fd, graph->vm_map_size) < 0)
		err(1, "ftruncate(2) failed");

	graph->vm_map = mmap(NULL, graph->vm_map_size, PROT_READ | PROT_WRITE,
	    MAP_SHARED | MAP_NOCORE, graph->fd, 0);

	if (graph->vm_map == MAP_FAILED)
		err(1, "mmap(2) failed");

	graph->vertices = (struct vertex *)graph->vm_map;
	graph->edges = (struct edge *)((unsigned char *)graph->vm_map +
	    graph->vm_map_size);

	memset(graph->sessions, 0, sizeof(graph->sessions));
	graph->nidx = 0;
}

static void
setup_capabilities(int sock, int fd)
{
	cap_rights_t rights;

	cap_rights_init(&rights, CAP_READ, CAP_WRITE, CAP_EVENT, CAP_EVENT,
	    CAP_CONNECT, CAP_KQUEUE);
	if (cap_rights_limit(sock, &rights) == -1)
		errx(EX_OSERR, "Cannot limit rights for socket");

	cap_rights_init(&rights, CAP_READ, CAP_WRITE, CAP_KQUEUE, CAP_EVENT,
	    CAP_FSYNC);
	if (cap_rights_limit(fd, &rights) == -1)
		errx(EX_OSERR, "Cannot limit rights for graph file");

	if (cap_enter() == -1)
		errx(EX_OSERR, "Cannot enter sandbox");
}

static int
create_raw_sock(void)
{
	int icmp_sock, hdrinc;
	struct sockaddr_in addr;

	icmp_sock = socket(AF_INET, SOCK_RAW | SOCK_NONBLOCK, IPPROTO_ICMP);
	if (icmp_sock < 0)
		err(1, "socket(2) failed");

	hdrinc = 1;
	if (setsockopt(icmp_sock, IPPROTO_IP, IP_HDRINCL, &hdrinc,
	    sizeof(hdrinc)) < 0)
		err(1, "setsockopt(2) failed");

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = 0;
	if (bind(icmp_sock, (const struct sockaddr *)&addr, sizeof(addr)) < 0)
		err(1, "bind(2) failed");

	return (icmp_sock);
}

int
main(int argc, char **argv)
{
	int ch, icmp_sock, mask;
	char *filename, *endptr;
	struct graph graph;
	struct in_addr addr;

	icmp_sock = create_raw_sock();
	drop_permissions();

	mask = 0;
	addr.s_addr = 0;
	filename = "./graph";
	while ((ch = getopt_long(argc, argv, "g:hm:n:", opts, NULL)) != -1) {
		switch (ch) {
		case 'g':
			filename = optarg;
			break;
		case 'n':
			if (inet_aton(optarg, &addr) != 1) {
				perror("inet_aton");
				usage(argv[0]);
				exit(1);
			}
			break;
		case 'm':
			mask = strtoimax(optarg, &endptr, 10);
			if (*endptr != '\0' || mask < 0 || mask > 32) {
				fprintf(stderr, "Invalid mask.\n");
				usage(argv[0]);
				exit(1);
			}
			break;
		case 'h':
			/* FALLTHROUGH */
		default:
			usage(argv[0]);
			exit(1);
		}
	}

	if (signal(SIGINT, SIG_IGN) == SIG_ERR)
		err(1, "signal(3) failed");

	setup_graph_file(addr.s_addr, mask, filename, &graph);
	/* For now - disable capabilities. Wait for migration to netmap. */
#if 0
	setup_capabilities(icmp_sock, graph.fd);
#endif
	mainloop(icmp_sock, &graph);

	if (fsync(graph.fd) < 0)
		err(1, "fsync(2) failed");
	if (munmap(graph.vm_map, graph.vm_map_size) < 0)
		err(1, "munmap(2) failed");
	close(graph.fd);

	return (0);
}
