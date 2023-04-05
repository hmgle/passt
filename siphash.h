/* SPDX-License-Identifier: GPL-2.0-or-later
 * Copyright (c) 2021 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 */

#ifndef SIPHASH_H
#define SIPHASH_H

uint64_t siphash_8b(const uint8_t *in, const uint64_t *k);
uint32_t siphash_12b(const uint8_t *in, const uint64_t *k);
uint64_t siphash_20b(const uint8_t *in, const uint64_t *k);
uint32_t siphash_32b(const uint8_t *in, const uint64_t *k);
uint32_t siphash_36b(const uint8_t *in, const uint64_t *k);

#endif /* SIPHASH_H */
