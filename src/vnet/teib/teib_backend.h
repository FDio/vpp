/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco and/or its affiliates.
 */

/* teib_backend.h: the provider side of the TEIB service.
 *
 * The consumer API in vnet/teib/teib.h is implemented by a backend that owns
 * the entries. This header is what such a backend implements and calls; it is
 * of no interest to a tunnel consumer.
 *
 * There is one backend at a time and it registers at init time, so neither the
 * VFT nor the listeners are locked. Backend methods and the publish calls below
 * are for the main thread only.
 */

#ifndef __TEIB_BACKEND_H__
#define __TEIB_BACKEND_H__

#include <vnet/teib/teib.h>
#include <vppinfra/error.h>

/**
 * Look up the entry for a peer on an interface and fill in a snapshot of it.
 * Returns false, leaving 'info' untouched, if there is no such entry.
 */
typedef bool (*teib_backend_entry_find_fn_t) (u32 sw_if_index, const ip_address_t *peer,
					      teib_entry_info_t *info);

/**
 * Invoke 'fn' for each entry on an interface. The predicate is handed to the
 * backend rather than applied to a full walk, so that the backend remains free
 * to index its entries by interface.
 */
typedef void (*teib_backend_walk_itf_fn_t) (u32 sw_if_index, teib_walk_cb_t fn, void *ctx);

typedef struct teib_backend_vft_t_
{
  teib_backend_entry_find_fn_t entry_find;
  teib_backend_walk_itf_fn_t walk_itf;
} teib_backend_vft_t;

/**
 * Provide the TEIB service. To be called once, at init time, and only once the
 * backend is ready to serve the methods above, since consumer calls reach it
 * from this point on.
 *
 * Returns an error if a backend is already registered or the VFT is incomplete.
 */
extern clib_error_t *teib_backend_register (const teib_backend_vft_t *vft);

/**
 * Announce a change to the listeners. The snapshot need only be valid for the
 * duration of the call.
 */
extern void teib_publish_entry_added (const teib_entry_info_t *info);
extern void teib_publish_entry_deleted (const teib_entry_info_t *info);

#endif
