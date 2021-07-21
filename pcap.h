void pcap(char *pkt, size_t len);
void pcapm(struct msghdr *mh);
void pcapmm(struct mmsghdr *mmh, unsigned int vlen);
void pcap_init(struct ctx *c, int sock_index);
