void tap_ip_send(struct ctx *c, struct in6_addr *src, uint8_t proto,
		 char *in, size_t len);
int tap_send(int fd, void *data, size_t len, int flags);
