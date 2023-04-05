/* SPDX-License-Identifier: GPL-2.0-or-later
 * Copyright Red Hat
 * Author: Stefano Brivio <sbrivio@redhat.com>
 * Author: David Gibson <david@gibson.dropbear.id.au>
 */

#ifndef PORT_FWD_H
#define PORT_FWD_H

/* Number of ports for both TCP and UDP */
#define	NUM_PORTS	(1U << 16)

enum port_fwd_mode {
	FWD_SPEC = 1,
	FWD_NONE,
	FWD_AUTO,
	FWD_ALL,
};

#define PORT_BITMAP_SIZE	DIV_ROUND_UP(NUM_PORTS, 8)

/**
 * port_fwd - Describes port forwarding for one protocol and direction
 * @mode:	Overall forwarding mode (all, none, auto, specific ports)
 * @map:	Bitmap describing which ports are forwarded
 * @delta:	Offset between the original destination and mapped port number
 */
struct port_fwd {
	enum port_fwd_mode mode;
	uint8_t map[PORT_BITMAP_SIZE];
	in_port_t delta[NUM_PORTS];
};

#endif /* PORT_FWD_H */
