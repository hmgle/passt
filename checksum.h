uint32_t sum_16b(void *buf, size_t len);
uint16_t csum_fold(uint32_t sum);
uint16_t csum_unaligned(void *buf, size_t len, uint32_t init);
void csum_tcp4(struct iphdr *iph);
uint16_t csum(const void *buf, size_t len, uint32_t init);
