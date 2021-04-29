#ifndef ICMP_H
#define ICMP_H

struct ctx;

void icmp_sock_handler(struct ctx *c, int s, uint32_t events,
		       struct timespec *now);
int icmp_tap_handler(struct ctx *c, int af, void *addr,
		     struct tap_msg *msg, int count, struct timespec *now);
int icmp_sock_init(struct ctx *c);

/**
 * struct icmp_ctx - Execution context for ICMP routines
 * @s4:		ICMP socket number
 * @s6:		ICMPv6 socket number
 * @fd_min:	Lowest file descriptor number for ICMP/ICMPv6 ever used
 * @fd_max:	Highest file descriptor number for ICMP/ICMPv6 ever used
 */
struct icmp_ctx {
	int s4;
	int s6;
	int fd_min;
	int fd_max;
};

#endif /* ICMP_H */
