#ifndef TCP_H
#define TCP_H

#define TCP_TIMER_INTERVAL		20 /* ms */

struct ctx;

void tcp_sock_handler(struct ctx *c, int s, uint32_t events, char *pkt_buf,
		      struct timespec *now);
int tcp_tap_handler(struct ctx *c, int af, void *addr,
		    struct tap_msg *msg, int count, struct timespec *now);
int tcp_sock_init(struct ctx *c);
void tcp_timer(struct ctx *c, struct timespec *ts);

/**
 * struct tcp_ctx - Execution context for TCP routines
 * @hash_secret:	128-bit secret for hash functions, ISN and hash table
 * @fd_min:		Lowest file descriptor number for TCP ever used
 * @fd_max:		Highest file descriptor number for TCP ever used
 * @fd_listen_min:	Lowest file descriptor number for listening sockets
 * @fd_listen_max:	Highest file descriptor number for listening sockets
 * @fd_conn_min:	Lowest file descriptor number for connected sockets
 * @fd_conn_max:	Highest file descriptor number for connected sockets
 * @timer_run:		Timestamp of most recent timer run
 */
struct tcp_ctx {
	uint64_t hash_secret[2];
	int fd_min;
	int fd_max;
	int fd_listen_min;
	int fd_listen_max;
	int fd_conn_min;
	int fd_conn_max;
	struct timespec timer_run;
};

#endif /* TCP_H */
