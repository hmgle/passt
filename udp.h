#ifndef UDP_H
#define UDP_H

#define UDP_TIMER_INTERVAL		1000 /* ms */

void udp_sock_handler(struct ctx *c, int s, uint32_t events,
		      struct timespec *now);
int udp_tap_handler(struct ctx *c, int af, void *addr,
		    struct tap_msg *msg, int count, struct timespec *now);
int udp_sock_init(struct ctx *c);
void udp_timer(struct ctx *c, struct timespec *ts);

/**
 * struct udp_ctx - Execution context for UDP
 * @fd_min:		Lowest file descriptor number for UDP ever used
 * @fd_max:		Highest file descriptor number for UDP ever used
 * @timer_run:		Timestamp of most recent timer run
 */
struct udp_ctx {
	int fd_min;
	int fd_max;
	struct timespec timer_run;
};

#endif /* UDP_H */
