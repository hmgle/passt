void err(const char *format, ...);
void warn(const char *format, ...);
void info(const char *format, ...);

#ifdef DEBUG
void debug(const char *format, ...);
#else
#define debug(...) { }
#endif

uint16_t csum_fold(uint32_t sum);
uint16_t csum_ip4(void *buf, size_t len);
void csum_tcp4(struct iphdr *iph);
char *ipv6_l4hdr(struct ipv6hdr *ip6h, uint8_t *proto);
int sock_l4_add(struct ctx *c, int v, uint16_t proto, uint16_t port);
int timespec_diff_ms(struct timespec *a, struct timespec *b);
