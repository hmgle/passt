/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (c) 2022 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 */

#ifndef PACKET_H
#define PACKET_H

/**
 * struct desc - Generic offset-based descriptor within buffer
 * @offset:	Offset of descriptor relative to buffer start, 32-bit limit
 * @len:	Length of descriptor, host order, 16-bit limit
 */
struct desc {
	uint32_t offset;
	uint16_t len;
};

/**
 * struct pool - Generic pool of packets stored in a buffer
 * @buf:	Buffer storing packet descriptors
 * @buf_size:	Total size of buffer
 * @size:	Number of usable descriptors for the pool
 * @count:	Number of used descriptors for the pool
 * @pkt:	Descriptors: see macros below
 */
struct pool {
	char *buf;
	size_t buf_size;
	size_t size;
	size_t count;
	struct desc pkt[1];
};

void packet_add_do(struct pool *p, size_t len, const char *start,
		   const char *func, const int line);
void *packet_get_do(struct pool *p, size_t index, size_t offset, size_t len,
		    size_t *left, const char *func, const int line);
void pool_flush(struct pool *p);

#define packet_add(p, len, start)					\
	packet_add_do(p, len, start, __func__, __LINE__);

#define packet_get(p, index, offset, len, left)				\
	packet_get_do(p, index, offset, len, left, __func__, __LINE__);

#define packet_get_try(p, index, offset, len, left)			\
	packet_get_do(p, index, offset, len, left, NULL, 0)

#define PACKET_POOL_DECL(_name, _size, _buf)				\
struct _name ## _t {							\
	char *buf;							\
	size_t buf_size;						\
	size_t size;							\
	size_t count;							\
	struct desc pkt[_size];						\
}

#define PACKET_POOL_INIT_NOCAST(_size, _buf, _buf_size)			\
{									\
	.buf_size = _buf_size,						\
	.buf = _buf,							\
	.size = _size,							\
}

#define PACKET_POOL(name, size, buf, buf_size)				\
	PACKET_POOL_DECL(name, size, buf) name = 			\
		PACKET_POOL_INIT_NOCAST(size, buf, buf_size)

#define PACKET_INIT(name, size, buf, buf_size)				\
	(struct name ## _t) PACKET_POOL_INIT_NOCAST(size, buf, buf_size)

#define PACKET_POOL_NOINIT(name, size, buf)				\
	PACKET_POOL_DECL(name, size, buf) name ## _storage;		\
	static struct pool *name = (struct pool *)&name ## _storage

#define PACKET_POOL_P(name, size, buf, buf_size)			\
	PACKET_POOL(name ## _storage, size, buf, buf_size);		\
	struct pool *name = (struct pool *)&name ## _storage

#endif /* PACKET_H */
