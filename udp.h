#ifndef UDP_H
#define UDP_H

#define UDP_TIMER_INTERVAL		1000 /* ms */

void udp_sock_handler(struct ctx *c, union epoll_ref ref, uint32_t events,
		      struct timespec *now);
int udp_tap_handler(struct ctx *c, int af, void *addr,
		    struct tap_l4_msg *msg, int count, struct timespec *now);
int udp_sock_init(struct ctx *c, struct timespec *now);
void udp_timer(struct ctx *c, struct timespec *ts);
void udp_update_l2_buf(unsigned char *eth_d, unsigned char *eth_s,
		       uint32_t *ip_da);
void udp_remap_to_tap(in_port_t port, in_port_t delta);
void udp_remap_to_init(in_port_t port, in_port_t delta);

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
 * @port_to_tap:	Ports bound host-side, data to tap or ns L4 socket
 * @port_to_init:	Ports bound namespace-side, data to init L4 socket
 * @timer_run:		Timestamp of most recent timer run
 */
struct udp_ctx {
	uint8_t port_to_tap		[USHRT_MAX / 8];
	uint8_t port_to_init		[USHRT_MAX / 8];
	struct timespec timer_run;
};

#endif /* UDP_H */
