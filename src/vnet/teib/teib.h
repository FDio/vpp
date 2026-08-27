/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2016 Cisco and/or its affiliates.
 */

/* teib.h: next-hop resolution */

#ifndef __TEIB_H__
#define __TEIB_H__

#include <vnet/ip/ip.h>
#include <vnet/fib/fib_types.h>

/**
 * Tunnel Endpoint Information Base.
 *
 * A TEIB entry represents the mapping between a peer on an interface in the overlay
 * and a next-hop address in the underlay.
 *  i.e. there's a multipoint tunnel providing the overlay (henace a peer on
 *   that tunnel) which is reachable via 'tunnel destination' address in the
 *   underlay.
 *
 * Such overlay to underlay mappings might be providied by a protocol like NHRP
 *
 * This is the in-process consumer API. The mappings themselves are held by a
 * registered TEIB backend, which need not be part of this image; see
 * vnet/teib/teib_backend.h. All of the calls below are safe to make whether or
 * not a backend is present.
 *
 * These calls are for the main thread only.
 */

/**
 * A self contained snapshot of a TEIB entry. Consumers are handed the data
 * itself rather than a reference to the entry, so that they need nothing from
 * TEIB in order to read it.
 *
 * It holds no references, so it may be copied and kept for as long as needed.
 * Where one is passed by pointer the pointer itself is only valid for the
 * duration of the call, so keep a copy rather than the pointer. Note that a
 * kept copy is a snapshot and not a view: it does not track subsequent changes
 * to the entry, nor its removal.
 */
typedef struct teib_entry_info_t_
{
  /** overlay: the multipoint tunnel interface */
  u32 sw_if_index;
  /** underlay: the FIB in which the next-hop is resolved */
  u32 nh_fib_index;
  /** overlay: the peer's address */
  ip_address_t peer;
  /** underlay: the next-hop */
  fib_prefix_t nh;
} teib_entry_info_t;

/**
 * Look an entry up and take a snapshot of it. Returns false, leaving 'info'
 * untouched, if there is no such entry. A false return also covers the absence
 * of a TEIB backend, since a consumer has nothing else to do in either case:
 * there is no mapping to act on.
 */
extern bool teib_entry_find (u32 sw_if_index, const ip_address_t *peer, teib_entry_info_t *info);
extern bool teib_entry_find_46 (u32 sw_if_index, fib_protocol_t fproto, const ip46_address_t *peer,
				teib_entry_info_t *info);

extern void teib_entry_adj_stack (const teib_entry_info_t *info, adj_index_t ai);

typedef walk_rc_t (*teib_walk_cb_t) (const teib_entry_info_t *info, void *ctx);

/**
 * Walk the entries on one interface. A no-op if there is no TEIB backend.
 */
extern void teib_walk_itf (u32 sw_if_index, teib_walk_cb_t fn, void *ctx);

/**
 * Notifications for the creation and deletion of TEIB entries.
 *
 * A listener is called on the main thread, with a snapshot that is only valid
 * for the duration of the call; keep a copy of the value, not the pointer.
 *
 * A listener must not add or delete TEIB entries from within a callback: it is
 * called part way through the operation on the entry, so mutating the database
 * there can invalidate the caller's own state.
 */
typedef void (*teib_entry_added_t) (const teib_entry_info_t *info);
typedef void (*teib_entry_deleted_t) (const teib_entry_info_t *info);

typedef struct teib_vft_t_
{
  teib_entry_added_t nv_added;
  teib_entry_deleted_t nv_deleted;
} teib_vft_t;

/**
 * Register for notifications. For use at init time only, and independent of
 * whether a TEIB backend has registered yet.
 */
extern void teib_register (const teib_vft_t * vft);

#endif
