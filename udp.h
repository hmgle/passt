#ifndef UDP_H
#define UDP_H

#define UDP_TIMER_INTERVAL		1000 /* ms */

void udp_sock_handler(struct ctx *c, union epoll_ref ref, uint32_t events,
		      struct timespec *now);
int udp_tap_handler(struct ctx *c, int af, void *addr,
		    struct tap_msg *msg, int count, struct timespec *now);
int udp_sock_init(struct ctx *c);
void udp_timer(struct ctx *c, struct timespec *ts);
void udp_update_l2_buf(unsigned char *eth_d, unsigned char *eth_s,
		       uint32_t *ip_da);

/**
 * union udp_epoll_ref - epoll reference portion for TCP connections
 * @bound:		Set if this file descriptor is a bound socket
 * @splice:		Set if descriptor is associated to "spliced" connection
 * @v6:			Set for IPv6 sockets or connections
 * @port:		Source port for connected sockets, bound port otherwise
 * @u32:		Opaque u32 value of reference
 */
union udp_epoll_ref {
	struct {
		uint32_t	bound:1,
				splice:3,
#define UDP_TO_NS		1
#define	UDP_TO_INIT		2
#define UDP_BACK_TO_NS		3
#define UDP_BACK_TO_INIT	4

				v6:1,
				port:16;
	};
	uint32_t u32;
};

/**
 * struct udp_ctx - Execution context for UDP
 * @port6_to_tap:	IPv6 ports bound host/init-side, packets to guest/tap
 * @port4_to_init:	IPv4 ports bound namespace-side, spliced to init
 * @port6_to_init:	IPv6 ports bound namespace-side, spliced to init
 * @port4_to_ns:	IPv4 ports bound init-side, spliced to namespace
 * @port6_to_ns:	IPv6 ports bound init-side, spliced to namespace
 * @timer_run:		Timestamp of most recent timer run
 */
struct udp_ctx {
	uint8_t port4_to_tap	[USHRT_MAX / 8];
	uint8_t port6_to_tap	[USHRT_MAX / 8];
	uint8_t port4_to_init	[USHRT_MAX / 8];
	uint8_t port6_to_init	[USHRT_MAX / 8];
	uint8_t port4_to_ns	[USHRT_MAX / 8];
	uint8_t port6_to_ns	[USHRT_MAX / 8];
	struct timespec timer_run;
};

#endif /* UDP_H */
