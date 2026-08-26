/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco and/or its affiliates.
 */

/* teib_vnet.c: the TEIB service as seen by its consumers.
 *
 * This holds no entries of its own: it dispatches to the bound implementation
 * and fans notifications out to the listeners.
 */

#include <vnet/teib/teib_impl.h>
#include <vnet/adj/adj_midchain.h>
#include <vnet/api_errno.h>

/* The service's startup lifecycle.
 *
 * Consumers cannot tell whether TEIB is unavailable or has merely not been
 * initialised yet. The states below give them a point, teib_init_complete(),
 * by which the answer is final:
 *
 *   UNFINALIZED ---------------------.
 *       |                            |
 *       | teib_impl_bind             | no implementation
 *       v                            |
 *     BOUND -------------------------+
 *       |                            |
 *       | teib_init_complete         |
 *       v                            v
 *   AVAILABLE                  UNAVAILABLE
 *
 * UNFINALIZED is the initial (zero) value. AVAILABLE and UNAVAILABLE are
 * terminal: the implementation cannot be replaced or bound late.
 */
typedef enum
{
  TEIB_STATE_UNFINALIZED,
  TEIB_STATE_BOUND,
  TEIB_STATE_AVAILABLE,
  TEIB_STATE_UNAVAILABLE,
} teib_state_t;

typedef struct teib_vnet_main_t_
{
  teib_impl_vft_t impl;
  teib_state_t state;
  teib_vft_t *listeners;
} teib_vnet_main_t;

static teib_vnet_main_t teib_vnet_main;

/* Close the binding window and settle TEIB availability. The implementation
 * orders itself before this; consumers order themselves after it. */
static clib_error_t *
teib_init_complete (vlib_main_t *vm)
{
  if (TEIB_STATE_BOUND == teib_vnet_main.state)
    teib_vnet_main.state = TEIB_STATE_AVAILABLE;
  else if (TEIB_STATE_UNFINALIZED == teib_vnet_main.state)
    teib_vnet_main.state = TEIB_STATE_UNAVAILABLE;
  else
    return (clib_error_return (0, "invalid TEIB init state"));

  return (NULL);
}

VLIB_INIT_FUNCTION (teib_init_complete);

bool
teib_is_available (void)
{
  return (TEIB_STATE_AVAILABLE == teib_vnet_main.state);
}

clib_error_t *
teib_impl_bind (const teib_impl_vft_t *vft)
{
  teib_vnet_main_t *tvm = &teib_vnet_main;

  switch (tvm->state)
    {
    case TEIB_STATE_UNFINALIZED:
      break;
    case TEIB_STATE_BOUND:
      return (clib_error_return (0, "TEIB implementation already bound"));
    default:
      return (clib_error_return (0, "TEIB implementation binding is closed"));
    }

  if (NULL == vft || NULL == vft->entry_add || NULL == vft->entry_del || NULL == vft->entry_find ||
      NULL == vft->walk_itf)
    return (clib_error_return (0, "invalid TEIB implementation"));

  tvm->impl = *vft;
  tvm->state = TEIB_STATE_BOUND;

  return (NULL);
}

int
teib_entry_add (u32 sw_if_index, const ip_address_t *peer, u32 nh_table_id, const ip_address_t *nh)
{
  teib_vnet_main_t *tvm = &teib_vnet_main;

  if (TEIB_STATE_AVAILABLE != tvm->state)
    return (VNET_API_ERROR_FEATURE_DISABLED);

  return (tvm->impl.entry_add (sw_if_index, peer, nh_table_id, nh));
}

int
teib_entry_del (u32 sw_if_index, const ip_address_t *peer)
{
  teib_vnet_main_t *tvm = &teib_vnet_main;

  if (TEIB_STATE_AVAILABLE != tvm->state)
    return (VNET_API_ERROR_FEATURE_DISABLED);

  return (tvm->impl.entry_del (sw_if_index, peer));
}

bool
teib_entry_find (u32 sw_if_index, const ip_address_t *peer, teib_entry_info_t *info)
{
  teib_vnet_main_t *tvm = &teib_vnet_main;

  if (TEIB_STATE_AVAILABLE != tvm->state)
    return (false);

  return (tvm->impl.entry_find (sw_if_index, peer, info));
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

  if (TEIB_STATE_AVAILABLE != tvm->state)
    return;

  tvm->impl.walk_itf (sw_if_index, fn, ctx);
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
