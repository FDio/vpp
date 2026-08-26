/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco and/or its affiliates.
 */

/* teib_impl.h: bind the VNET-owned TEIB API to its implementation.
 *
 * The TEIB implementation owns the entries and binds itself once during VLIB
 * initialization. This is the private integration contract between the
 * implementation and VNET; tunnel consumers use vnet/teib/teib.h instead.
 */

#ifndef __TEIB_IMPL_H__
#define __TEIB_IMPL_H__

#include <vnet/teib/teib.h>
#include <vppinfra/error.h>

/** Implementation of teib_entry_add() used while TEIB is available. */
typedef int (*teib_impl_entry_add_fn_t) (u32 sw_if_index, const ip_address_t *peer, u32 nh_table_id,
					 const ip_address_t *nh);

/** Implementation of teib_entry_del() used while TEIB is available. */
typedef int (*teib_impl_entry_del_fn_t) (u32 sw_if_index, const ip_address_t *peer);

/** Implementation of teib_entry_find() used while TEIB is available. */
typedef bool (*teib_impl_entry_find_fn_t) (u32 sw_if_index, const ip_address_t *peer,
					   teib_entry_info_t *info);

/** Implementation of teib_walk_itf() used while TEIB is available. */
typedef void (*teib_impl_walk_itf_fn_t) (u32 sw_if_index, teib_walk_cb_t fn, void *ctx);

typedef struct teib_impl_vft_t_
{
  teib_impl_entry_add_fn_t entry_add;
  teib_impl_entry_del_fn_t entry_del;
  teib_impl_entry_find_fn_t entry_find;
  teib_impl_walk_itf_fn_t walk_itf;
} teib_impl_vft_t;

/**
 * Bind the TEIB implementation. Called once during init, after it is ready to
 * serve the methods above.
 *
 * Returns an error if an implementation is already bound, initialization has
 * been finalized, or the VFT is incomplete.
 */
extern clib_error_t *teib_impl_bind (const teib_impl_vft_t *vft);

/**
 * Notify listeners registered through teib_register() about an added entry.
 */
extern void teib_publish_entry_added (const teib_entry_info_t *info);

/**
 * Notify listeners registered through teib_register() about a deleted entry.
 */
extern void teib_publish_entry_deleted (const teib_entry_info_t *info);

#endif
