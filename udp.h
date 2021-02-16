void udp_sock_handler(struct ctx *c, int s, uint32_t events);
void udp_tap_handler(struct ctx *c, int af, void *addr, char *in, size_t len);
int udp_sock_init(struct ctx *c);
