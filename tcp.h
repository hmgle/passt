void tcp_sock_handler(struct ctx *c, int s, uint32_t events);
void tcp_tap_handler(struct ctx *c, int af, void *addr, char *in, size_t len);
int tcp_sock_init(struct ctx *c);
void tcp_periodic_fast(struct ctx *c);
void tcp_periodic_slow(struct ctx *c);
