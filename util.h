void err(const char *format, ...);
void warn(const char *format, ...);
void info(const char *format, ...);
void debug(const char *format, ...);

#define CHECK_SET_MIN_MAX(basename, fd)					\
	do {								\
		if ((fd) < basename##min)				\
			basename##min = (fd);				\
		if ((fd) > basename##max)				\
			basename##max = (fd);				\
	} while (0)

#define CHECK_SET_MIN_MAX_PROTO_FD(proto, ipproto, proto_ctx, fd)	\
	do {								\
		if ((proto) == (ipproto))				\
			CHECK_SET_MIN_MAX(c->proto_ctx.fd_, (fd));	\
	} while (0)

#ifndef MIN
#define MIN(x, y)		(((x) < (y)) ? (x) : (y))
#endif
#ifndef MAX
#define MAX(x, y)		(((x) > (y)) ? (x) : (y))
#endif

#define DIV_ROUND_UP(n, d)	(((n) + (d) - 1) / (d))
#define ROUND_DOWN(x, y)	((x) & ~((y) - 1))

#define SWAP(a, b)							\
	do {								\
		typeof(a) __x = (a); (a) = (b); (b) = __x;		\
	} while (0)							\

#define STRINGIFY(x)	#x
#define STR(x)		STRINGIFY(x)

#define V4		0
#define V6		1
#define IP_VERSIONS	2

#define ARRAY_SIZE(a)		((int)(sizeof(a) / sizeof((a)[0])))

#define IN_INTERVAL(a, b, x)	((x) >= (a) && (x) <= (b))
#define FD_PROTO(x, proto)						\
	(IN_INTERVAL(c->proto.fd_min, c->proto.fd_max, (x)))

#define PORT_EPHEMERAL_MIN	((1 << 15) + (1 << 14))		/* RFC 6335 */
#define PORT_IS_EPHEMERAL(port) ((port) >= PORT_EPHEMERAL_MIN)

#define NS_FN_STACK_SIZE	(RLIMIT_STACK_VAL * 1024 / 4)
#define NS_CALL(fn, arg)						\
	do {								\
		char ns_fn_stack[NS_FN_STACK_SIZE];			\
									\
		clone((fn), ns_fn_stack + sizeof(ns_fn_stack) / 2,	\
		      CLONE_VM | CLONE_VFORK | CLONE_FILES | SIGCHLD,	\
		      (void *)(arg));					\
	} while (0)

#if __BYTE_ORDER == __BIG_ENDIAN
#define L2_BUF_ETH_IP4_INIT						\
	{								\
		.h_dest		= { 0 },				\
		.h_source	= { 0 },				\
		.h_proto	= ETH_P_IP,				\
	}
#else
#define L2_BUF_ETH_IP4_INIT						\
	{								\
		.h_dest		= { 0 },				\
		.h_source	= { 0 },				\
		.h_proto	= __bswap_constant_16(ETH_P_IP),	\
	}
#endif

#if __BYTE_ORDER == __BIG_ENDIAN
#define L2_BUF_ETH_IP6_INIT						\
	{								\
		.h_dest		= { 0 },				\
		.h_source	= { 0 },				\
		.h_proto	= ETH_P_IPV6,				\
	}
#else
#define L2_BUF_ETH_IP6_INIT						\
	{								\
		.h_dest		= { 0 },				\
		.h_source	= { 0 },				\
		.h_proto	= __bswap_constant_16(ETH_P_IPV6),	\
	}
#endif

#define L2_BUF_IP4_INIT(proto)						\
	{								\
		.version	= 4,					\
		.ihl		= 5,					\
		.tos		= 0,					\
		.tot_len	= 0,					\
		.id		= 0,					\
		.frag_off	= 0,					\
		.ttl		= 255,					\
		.protocol	= (proto),				\
		.saddr		= 0,					\
		.daddr		= 0,					\
	}

#define L2_BUF_IP6_INIT(proto)						\
	{								\
		.priority	= 0,					\
		.version	= 6,					\
		.flow_lbl	= { 0 },				\
		.payload_len	= 0,					\
		.nexthdr	= (proto),				\
		.hop_limit	= 255,					\
		.saddr		= IN6ADDR_ANY_INIT,			\
		.daddr		= IN6ADDR_ANY_INIT,			\
	}

#define RCVBUF_BIG		(2 * 1024 * 1024)
#define SNDBUF_BIG		(4 * 1024 * 1024)
#define SNDBUF_SMALL		(128 * 1024)

#include <linux/ipv6.h>
#include <net/if.h>
#include <linux/ip.h>
#include <limits.h>

enum bind_type {
	BIND_ANY = 0,
	BIND_LOOPBACK,
	BIND_LL,
	BIND_EXT,
};

struct ctx;

char *ipv6_l4hdr(struct ipv6hdr *ip6h, uint8_t *proto);
int sock_l4(struct ctx *c, int af, uint8_t proto, uint16_t port,
	    enum bind_type bind_addr, uint32_t data);
void sock_probe_mem(struct ctx *c);
int timespec_diff_ms(struct timespec *a, struct timespec *b);
void bitmap_set(uint8_t *map, int bit);
void bitmap_clear(uint8_t *map, int bit);
int bitmap_isset(uint8_t *map, int bit);
void procfs_scan_listen(char *name, uint8_t *map, uint8_t *exclude);
int ns_enter(int target_pid);
