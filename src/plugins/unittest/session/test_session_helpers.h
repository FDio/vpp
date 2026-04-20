/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco and/or its affiliates.
 */

#ifndef __included_test_session_helpers_h__
#define __included_test_session_helpers_h__

#include <vnet/ethernet/ethernet.h>
#include <vnet/fib/fib_table.h>
#include <vnet/fib/fib_types.h>
#include <vnet/interface_funcs.h>
#include <vnet/ip/ip.h>
#include <vnet/ip/ip4.h>
#include <vnet/session/application.h>
#include <vnet/session/session.h>
#include <vnet/session/transport.h>

static volatile u32 connected_session_index = ~0;
static volatile u32 connected_session_thread = ~0;
static u32 __clib_unused placeholder_accept;
static volatile u32 accepted_session_index = ~0;
static volatile u32 accepted_session_thread = ~0;
static volatile int app_session_error = 0;
static u32 __clib_unused placeholder_segment_count;

static void
placeholder_session_reset_callback (session_t *s)
{
  clib_warning ("called...");
}

static int
placeholder_session_connected_callback (u32 app_index, u32 api_context, session_t *s,
					session_error_t err)
{
  if (s)
    {
      connected_session_index = s->session_index;
      connected_session_thread = s->thread_index;
    }
  return 0;
}

static int
placeholder_add_segment_callback (u32 client_index, u64 segment_handle)
{
  placeholder_segment_count = 1;
  return 0;
}

static int
placeholder_del_segment_callback (u32 client_index, u64 segment_handle)
{
  placeholder_segment_count = 0;
  return 0;
}

static void
placeholder_session_disconnect_callback (session_t *s)
{
  if (!(s->session_index == connected_session_index &&
	s->thread_index == connected_session_thread) &&
      !(s->session_index == accepted_session_index && s->thread_index == accepted_session_thread))
    {
      clib_warning (0, "unexpected disconnect s %u thread %u", s->session_index, s->thread_index);
      app_session_error = 1;
    }

  vnet_disconnect_args_t da = {
    .handle = session_handle (s),
    .app_index = app_worker_get (s->app_wrk_index)->app_index,
  };
  vnet_disconnect_session (&da);
}

static int
placeholder_session_accept_callback (session_t *s)
{
  placeholder_accept = 1;
  accepted_session_index = s->session_index;
  accepted_session_thread = s->thread_index;
  s->session_state = SESSION_STATE_READY;
  return 0;
}

static int
placeholder_server_rx_callback (session_t *s)
{
  clib_warning ("called...");
  return -1;
}

static void
placeholder_cleanup_callback (session_t *s, session_cleanup_ntf_t ntf)
{
  if (ntf == SESSION_CLEANUP_TRANSPORT)
    return;

  if (s->session_index == connected_session_index && s->thread_index == connected_session_thread)
    {
      connected_session_index = ~0;
      connected_session_thread = ~0;
    }
  else if (s->session_index == accepted_session_index && s->thread_index == accepted_session_thread)
    {
      accepted_session_index = ~0;
      accepted_session_thread = ~0;
    }
  else
    {
      clib_warning (0, "unexpected cleanup s %u thread %u", s->session_index, s->thread_index);
      app_session_error = 1;
    }
}

static session_cb_vft_t placeholder_session_cbs = {
  .session_reset_callback = placeholder_session_reset_callback,
  .session_connected_callback = placeholder_session_connected_callback,
  .session_accept_callback = placeholder_session_accept_callback,
  .session_disconnect_callback = placeholder_session_disconnect_callback,
  .builtin_app_rx_callback = placeholder_server_rx_callback,
  .session_cleanup_callback = placeholder_cleanup_callback,
  .add_segment_callback = placeholder_add_segment_callback,
  .del_segment_callback = placeholder_del_segment_callback,
};

static inline void
session_test_reset_placeholder_state (void)
{
  connected_session_index = ~0;
  connected_session_thread = ~0;
  accepted_session_index = ~0;
  accepted_session_thread = ~0;
  placeholder_accept = 0;
  placeholder_segment_count = 0;
  app_session_error = 0;
}

static inline u32
session_test_drain_rx_fifo (session_t *s)
{
  svm_fifo_t *rx_fifo = s->rx_fifo;
  u32 n_read;
  int rv;

  n_read = svm_fifo_max_dequeue_cons (rx_fifo);
  if (!n_read)
    return 0;

  rv = svm_fifo_dequeue_drop (rx_fifo, n_read);
  if (rv > 0 && svm_fifo_needs_deq_ntf (rx_fifo, rv))
    {
      svm_fifo_clear_deq_ntf (rx_fifo);
      session_program_transport_io_evt (s->handle, SESSION_IO_EVT_RX);
    }

  return rv > 0 ? rv : 0;
}

static inline int
session_create_lookpback (u32 table_id, u32 *sw_if_index, ip4_address_t *intf_addr)
{
  u8 intf_mac[6];

  clib_memset (intf_mac, 0, sizeof (intf_mac));

  if (vnet_create_loopback_interface (sw_if_index, intf_mac, 0, 0))
    {
      clib_warning ("couldn't create loopback. stopping the test!");
      return -1;
    }

  if (table_id != 0)
    {
      ip_table_create (FIB_PROTOCOL_IP4, table_id, 0 /* is_api */, 1 /* create_mfib */, 0);
      ip_table_bind (FIB_PROTOCOL_IP4, *sw_if_index, table_id);
    }

  vnet_sw_interface_set_flags (vnet_get_main (), *sw_if_index, VNET_SW_INTERFACE_FLAG_ADMIN_UP);

  if (ip4_add_del_interface_address (vlib_get_main (), *sw_if_index, intf_addr, 24, 0))
    {
      clib_warning ("couldn't assign loopback ip %U", format_ip4_address, intf_addr);
      return -1;
    }

  return 0;
}

static inline void
session_delete_loopback (u32 sw_if_index)
{
  /* fails spectacularly  */
  /* vnet_delete_loopback_interface (sw_if_index); */

  vnet_sw_interface_set_flags (vnet_get_main (), sw_if_index, 0);
}

static inline void
session_add_del_route_via_lookup_in_table (u32 in_table_id, u32 via_table_id, ip4_address_t *ip,
					   u8 mask, u8 is_add)
{
  fib_route_path_t *rpaths = 0, *rpath;
  u32 in_fib_index, via_fib_index;

  fib_prefix_t prefix = {
    .fp_addr.ip4.as_u32 = ip->as_u32,
    .fp_len = mask,
    .fp_proto = FIB_PROTOCOL_IP4,
  };

  via_fib_index = fib_table_find (FIB_PROTOCOL_IP4, via_table_id);
  if (via_fib_index == ~0)
    {
      clib_warning ("couldn't resolve via table id to index");
      return;
    }

  in_fib_index = fib_table_find (FIB_PROTOCOL_IP4, in_table_id);
  if (in_fib_index == ~0)
    {
      clib_warning ("couldn't resolve in table id to index");
      return;
    }

  vec_add2 (rpaths, rpath, 1);
  clib_memset (rpath, 0, sizeof (*rpath));
  rpath->frp_weight = 1;
  rpath->frp_fib_index = via_fib_index;
  rpath->frp_proto = DPO_PROTO_IP4;
  rpath->frp_sw_if_index = ~0;
  rpath->frp_flags |= FIB_ROUTE_PATH_DEAG;

  if (is_add)
    fib_table_entry_path_add2 (in_fib_index, &prefix, FIB_SOURCE_CLI, FIB_ENTRY_FLAG_NONE, rpath);
  else
    fib_table_entry_path_remove2 (in_fib_index, &prefix, FIB_SOURCE_CLI, rpath);

  vec_free (rpaths);
}

#endif
