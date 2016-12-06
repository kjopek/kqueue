#include <err.h>
#include <pwd.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>

#include "utils.h"

#define SIZEOF(u) (sizeof((u)) / sizeof(*(u)))

struct inet_range {
	in_addr_t	 addr;
	uint32_t	 size;
};

/*
 * Reserved IPv4 ranges as defined in RFC 1700, 1918, 6598 and others.
 * Structure is aligned to 16 bytes to allow future optimizations using
 * SSE2/AVX/AVX2.
 */
const struct inet_range inet_reserved_addrs[] __attribute__((aligned(16))) = {
	{ .addr = 0x00000000, .size = (1 << 24) }, /* 0.0.0.0/8 */
	{ .addr = 0x0A000000, .size = (1 << 24) }, /* 10.0.0.0/8 */
	{ .addr = 0x64040000, .size = (1 << 22) }, /* 100.65.0.0/10 */
	{ .addr = 0x7f000000, .size = (1 << 24) }, /* 127.0.0.0/8 */
	{ .addr = 0xA9FE0000, .size = (1 << 16) }, /* 169.254.0.0/16 */
	{ .addr = 0xAC100000, .size = (1 << 20) }, /* 172.16.0.0/12 */
	{ .addr = 0xC0000000, .size = (1 << 8)  }, /* 192.0.0.0/24 */
	{ .addr = 0xC0000200, .size = (1 << 8)  }, /* 192.0.2.0/24 */
	{ .addr = 0xC0586300, .size = (1 << 8)  }, /* 192.88.99.0/24 */
	{ .addr = 0xC0A80000, .size = (1 << 16) }, /* 192.168.0.0/16 */
	{ .addr = 0xC6120000, .size = (1 << 17) }, /* 198.18.0.0/15 */
	{ .addr = 0xC6336400, .size = (1 << 8)  }, /* 198.51.100.0/24 */
	{ .addr = 0xCB007100, .size = (1 << 8)  }, /* 203.0.113.0/24 */
	{ .addr = 0xE0000000, .size = (1 << 28) }, /* 224.0.0.0/4 */
	{ .addr = 0xF0000000, .size = (1 << 28) }, /* 240.0.0.0/4 */
	{ .addr = 0xFFFFFFFF, .size = (1 << 0)  }  /* 255.255.255.255/32 */
};

bool
ip4_is_reserved(in_addr_t addr)
{
	int i;
	uint32_t len;
	in_addr_t base_addr;

	/*
	 * Check if given address belongs to any of the reserved spaces defined
	 * above.
	 */
	for (i = 0; i < SIZEOF(inet_reserved_addrs); i++) {
		base_addr = inet_reserved_addrs[i].addr;
		len = inet_reserved_addrs[i].size;

		if (base_addr <= addr && addr < base_addr + len)
			return (true);
	}

	/* Address is not reserved. */
	return (false);
}

uint64_t
ip4_usable_addrs(void)
{
	uint64_t cnt;
	int i;

	cnt = ((uint64_t)1 << 32);
	for (i = 0; i < SIZEOF(inet_reserved_addrs); i++)
		cnt -= inet_reserved_addrs[i].size;

	return (cnt);
}

uint64_t
ip4_next_addr(uint64_t addr)
{
	int i;
	uint32_t len;
	in_addr_t base_addr;

	for (i = 0; i < SIZEOF(inet_reserved_addrs); i++) {
		base_addr = inet_reserved_addrs[i].addr;
		len = inet_reserved_addrs[i].size;

		if (base_addr <= addr && addr < base_addr + len)
			return (ip4_next_addr(base_addr + len));
	}

	return (addr + 1);
}

#undef SIZEOF

double
time_diff(struct timespec *t1, struct timespec *t2)
{
	double diff;

	diff = t2->tv_sec - t1->tv_sec;
	diff += (t2->tv_nsec - t1->tv_nsec) * 1e-9;
	return (diff);
}

void
print_hex(const unsigned char *data, int len)
{
	int i;

	for (i = 0; i < len; i++)
		printf("%02x", data[i]);
	printf("\n");
}

void
keventx(int kq, uintptr_t ident, short filter, u_short flags, u_int fflags,
    intptr_t data, void *udata)
{
	struct kevent ev;

	EV_SET(&ev, ident, filter, flags, fflags, data, udata);
	if (kevent(kq, &ev, 1, NULL, 0, NULL) < 0)
		err(1, "kevent(2) failed");
}

void
drop_permissions(void)
{
	int ret;
	struct passwd *passwd;

	/* Drop god mode. */
	passwd = getpwnam("nobody");
	if (passwd == NULL)
		err(1, "getpwnam(3) failed");

	ret = initgroups("nobody", passwd->pw_gid);
	if (ret < 0)
		err(1, "initgroups(3) failed");

	ret = setregid(passwd->pw_gid, passwd->pw_gid);
	if (ret < 0)
		err(1, "setregid(2) failed");

	ret = setreuid(passwd->pw_uid, passwd->pw_uid);
	if (ret < 0)
		err(1, "setreuid(2) failed");
}

uint16_t
in_cksum(uint16_t *addr, int len)
{
	uint32_t sum;

	sum = 0;
	while (len > 1) {
		sum += *(addr++);
		len -= 2;
	}

	if (len > 0)
		sum += *(uint8_t *)addr;

	while (sum >> 16 != 0)
		sum = (sum & 0xffff) + (sum >> 16);

	return ((uint16_t)~sum);
}

void
__assertx(const char *func, const char *file, int line, const char *e,
    const char *fmt, ...)
{
	va_list list;

	(void)fprintf(stderr, "Assertion failed: %s\n", e);
	(void)fprintf(stderr, "  func: %s in %s at %d\n   msg: ",
	    func == NULL ? "" : func, file, line);

	va_start(list, fmt);
	vfprintf(stderr, fmt, list);
	va_end(list);

	(void)fprintf(stderr, "\n");
	abort();
}
