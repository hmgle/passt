#ifndef ICMP_H
#define ICMP_H

#define ICMP_TIMER_INTERVAL		1000 /* ms */

struct ctx;

void icmp_sock_handler(struct ctx *c, union epoll_ref ref, uint32_t events,
		       struct timespec *now);
int icmp_tap_handler(struct ctx *c, int af, void *addr,
		     struct tap_msg *msg, int count, struct timespec *now);
void icmp_timer(struct ctx *c, struct timespec *ts);

/**
 * union icmp_epoll_ref - epoll reference portion for ICMP tracking
 * @v6:			Set for IPv6 sockets or connections
 * @u32:		Opaque u32 value of reference
 */
union icmp_epoll_ref {
	struct {
		uint32_t	v6:1;
	};
	uint32_t u32;
};

/**
 * struct icmp_ctx - Execution context for ICMP routines
 * @timer_run:		Timestamp of most recent timer run
 */
struct icmp_ctx {
	struct timespec timer_run;
};

#endif /* ICMP_H */
