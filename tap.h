void tap_ip_send(struct ctx *c, struct in6_addr *src, uint8_t proto,
		 char *in, size_t len, uint32_t flow);
int tap_send(struct ctx *c, void *data, size_t len, int vnet_pre);
void tap_handler(struct ctx *c, uint32_t events, struct timespec *now);
void tap_sock_init(struct ctx *c);
