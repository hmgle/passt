/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright Red Hat
 * Author: Stefano Brivio <sbrivio@redhat.com>
 * Author: David Gibson <david@gibson.dropbear.id.au>
 */

#ifndef PORT_FWD_H
#define PORT_FWD_H

enum port_fwd_mode {
	FWD_SPEC = 1,
	FWD_NONE,
	FWD_AUTO,
	FWD_ALL,
};

#define PORT_BITMAP_SIZE	DIV_ROUND_UP(USHRT_MAX, 8)

#endif /* PORT_FWD_H */
