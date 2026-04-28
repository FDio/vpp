/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Meter, Inc.
 */

#ifndef included_npol_manual_endian_h
#define included_npol_manual_endian_h

/*
 * vl_api_npol_ipset_member_val_t is an old-style union (no [discriminator])
 * so vppapigen refuses to autogenerate its endian helper. The wire format
 * carries no tag distinguishing the arms (address / prefix / tuple), so the
 * receiver has no portable way to know which arm to byte-swap. We pass the
 * bytes through unchanged; the longest arm (vl_api_npol_three_tuple_t) is
 * mostly an address plus a u16 port, and current callers only exchange
 * messages between hosts of matching endianness.
 *
 * TODO: convert npol_ipset_member to a discriminated union and remove this.
 */
static inline void
vl_api_npol_ipset_member_val_t_endian (vl_api_npol_ipset_member_val_t *a, bool to_net)
{
  (void) a;
  (void) to_net;
}

#endif /* included_npol_manual_endian_h */
