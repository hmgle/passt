#ifndef UDP_H
#define UDP_H

void udp_sock_handler(struct ctx *c, int s, uint32_t events);
int udp_tap_handler(struct ctx *c, int af, void *addr,
		    struct tap_msg *msg, int count);
int udp_sock_init(struct ctx *c);

/**
 * struct udp_ctx - Execution context for UDP
 * @fd_min:		Lowest file descriptor number for UDP ever used
 * @fd_max:		Highest file descriptor number for UDP ever used
 */
struct udp_ctx {
	int fd_min;
	int fd_max;
};

#endif /* UDP_H */
