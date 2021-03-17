#ifndef ICMP_H
#define ICMP_H

struct ctx;

void icmp_sock_handler(struct ctx *c, int s, uint32_t events);
void icmp_tap_handler(struct ctx *c, int af, void *addr, char *in, size_t len);
int icmp_sock_init(struct ctx *c);

/**
 * struct icmp_ctx - Execution context for ICMP routines
 * @s4:		ICMP socket number
 * @s6:		ICMPv6 socket number
 */
struct icmp_ctx {
	int s4;
	int s6;
};

#endif /* ICMP_H */
