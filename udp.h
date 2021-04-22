void udp_sock_handler(struct ctx *c, int s, uint32_t events);
int udp_tap_handler(struct ctx *c, int af, void *addr,
		    struct tap_msg *msg, int count);
int udp_sock_init(struct ctx *c);
