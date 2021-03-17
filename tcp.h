#ifndef TCP_H
#define TCP_H

struct ctx;

void tcp_sock_handler(struct ctx *c, int s, uint32_t events);
void tcp_tap_handler(struct ctx *c, int af, void *addr, char *in, size_t len);
int tcp_sock_init(struct ctx *c);
void tcp_timer(struct ctx *c, struct timespec *ts);

/**
 * struct tcp_ctx - Execution context for TCP routines
 * @hash_secret:	128-bit secret for hash functions, ISN and hash table
 */
struct tcp_ctx {
	uint64_t hash_secret[2];
};

#endif /* TCP_H */
