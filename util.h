uint16_t csum_fold(uint32_t sum);
uint16_t csum_ip4(void *buf, size_t len);
unsigned char *ipv6_l4hdr(struct ipv6hdr *ip6h, uint8_t *proto);
