/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco and/or its affiliates.
 */

/* teib_vnet.c: the TEIB service as seen by its consumers.
 *
 * This holds no entries of its own: it dispatches to the registered backend and
 * fans notifications out to the listeners.
 */

#include <vnet/teib/teib_backend.h>
#include <vnet/adj/adj_midchain.h>

typedef struct teib_vnet_main_t_
{
  teib_backend_vft_t backend;
  bool backend_registered;
  teib_vft_t *listeners;
} teib_vnet_main_t;

static teib_vnet_main_t teib_vnet_main;

clib_error_t *
teib_backend_register (const teib_backend_vft_t *vft)
{
  teib_vnet_main_t *tvm = &teib_vnet_main;

  if (tvm->backend_registered)
    return (clib_error_return (0, "TEIB backend already registered"));

  if (NULL == vft || NULL == vft->entry_find || NULL == vft->walk_itf)
    return (clib_error_return (0, "invalid TEIB backend"));

  tvm->backend = *vft;
  tvm->backend_registered = true;

  return (NULL);
}

bool
teib_entry_find (u32 sw_if_index, const ip_address_t *peer, teib_entry_info_t *info)
{
  teib_vnet_main_t *tvm = &teib_vnet_main;

  if (!tvm->backend_registered)
    return (false);

  return (tvm->backend.entry_find (sw_if_index, peer, info));
}

bool
teib_entry_find_46 (u32 sw_if_index, fib_protocol_t fproto, const ip46_address_t *peer,
		    teib_entry_info_t *info)
{
  ip_address_t ip;

  ip_address_from_46 (peer, fproto, &ip);

  return (teib_entry_find (sw_if_index, &ip, info));
}

void
teib_walk_itf (u32 sw_if_index, teib_walk_cb_t fn, void *ctx)
{
  teib_vnet_main_t *tvm = &teib_vnet_main;

  if (!tvm->backend_registered)
    return;

  tvm->backend.walk_itf (sw_if_index, fn, ctx);
}

void
teib_entry_adj_stack (const teib_entry_info_t *info, adj_index_t ai)
{
  adj_midchain_delegate_stack (ai, info->nh_fib_index, &info->nh);
}

void
teib_register (const teib_vft_t *vft)
{
  vec_add1 (teib_vnet_main.listeners, *vft);
}

void
teib_publish_entry_added (const teib_entry_info_t *info)
{
  teib_vft_t *listener;

  vec_foreach (listener, teib_vnet_main.listeners)
    if (NULL != listener->nv_added)
      listener->nv_added (info);
}

void
teib_publish_entry_deleted (const teib_entry_info_t *info)
{
  teib_vft_t *listener;

  vec_foreach (listener, teib_vnet_main.listeners)
    if (NULL != listener->nv_deleted)
      listener->nv_deleted (info);
}
