#ifndef UTILS_H
#define UTILS_H

#include <sys/types.h>
#include <sys/timespec.h>
#include <sys/event.h>

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#define assertx(cond, fmt, ...) ((cond) ? (void)0 : __assertx(__func__, \
	__FILE__, __LINE__, #cond, fmt, ##__VA_ARGS__))

/* Inet-related functions. */
bool ip4_is_reserved(in_addr_t addr);
uint64_t ip4_usable_addrs(void);
uint64_t ip4_next_addr(uint64_t addr);
uint16_t in_cksum(uint16_t *addr, int len);

/* Time, OS */
double time_diff(struct timespec *t1, struct timespec *t2);
void drop_permissions(void);
void keventx(int kq, uintptr_t ident, short filter, u_short flags, u_int fflags,
    intptr_t data, void *udata);

/* Utils. */
void print_hex(const unsigned char *data, int len);
void __assertx(const char *func, const char *file, int line, const char *e,
    const char *fmt, ...) __dead2;
#endif /* UTILS_H */
