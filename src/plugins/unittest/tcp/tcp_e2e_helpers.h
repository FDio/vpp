/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco and/or its affiliates.
 */

/*
 * Shared setup/teardown for in-process TCP end-to-end unit tests.
 *
 * Builds a client and server application in two loopback-backed VRFs, connects
 * them, and resolves the client's session and transport. Because the session
 * callbacks and the connected/accepted index globals in test_session_helpers.h
 * are translation-unit static, this helper is header-only and must be included
 * from the same file as those helpers (after test_session_helpers.h).
 */

#ifndef SRC_PLUGINS_UNITTEST_TCP_TCP_E2E_HELPERS_H_
#define SRC_PLUGINS_UNITTEST_TCP_TCP_E2E_HELPERS_H_

#include <vnet/tcp/tcp.h>
#include <unittest/session/test_session_helpers.h>

typedef struct
{
  const char *name; /**< base name for the apps and namespace */
  u32 client_addr;  /**< host-order client loopback address */
  u32 server_addr;  /**< host-order server loopback address */
  u32 client_vrf;
  u32 server_vrf;
  u16 server_port;
  u16 client_port; /**< 0 -> ephemeral; use 0 to rerun in one process */
  u64 secret;
  u32 rx_fifo_size; /**< 0 -> 4 KB */
  u32 tx_fifo_size; /**< 0 -> 4 KB */
} tcp_e2e_params_t;

typedef struct
{
  u32 client_index;
  u32 server_index;
  u32 sw_if_index[2];
  ip4_address_t intf_addr[2];
  u32 client_vrf;
  u32 server_vrf;
  u64 secret;
  session_handle_t listen_handle;
  u8 *appns_id;
  u8 ns_added;
  u8 routes_added;
  /* Resolved after a successful connect. */
  session_t *client_s;
  tcp_connection_t *client_tc;
} tcp_e2e_ctx_t;

/* One barrier-synced scheduler step so datapath/timers make progress. */
static inline void
tcp_e2e_pump (vlib_main_t *vm, f64 secs)
{
  vlib_worker_thread_barrier_release (vm);
  vlib_process_suspend (vm, secs);
  vlib_worker_thread_barrier_sync (vm);
}

typedef struct
{
  session_handle_t handle;
  volatile u8 done;
} tcp_e2e_cleanup_req_t;

static inline void
tcp_e2e_session_cleanup_rpc (void *arg)
{
  tcp_e2e_cleanup_req_t *req = arg;
  session_t *s = session_get_from_handle_if_valid (req->handle);

  if (s)
    session_transport_cleanup (s);
  req->done = 1;
}

/* Unit-test teardown must not leave closing transports that can emit packets
 * after their loopback interfaces are deleted. Clean both endpoint sessions
 * on their owner threads and wait for the cleanup RPCs to complete. */
static inline int
tcp_e2e_force_session_cleanup (vlib_main_t *vm)
{
  tcp_e2e_cleanup_req_t *reqs;
  session_handle_t handles[2];
  u32 i, n_reqs = 0, n_done;

  if (connected_session_index != ~0)
    handles[n_reqs++] = session_make_handle (connected_session_index, connected_session_thread);
  if (accepted_session_index != ~0)
    handles[n_reqs++] = session_make_handle (accepted_session_index, accepted_session_thread);
  if (!n_reqs)
    return 1;

  reqs = clib_mem_alloc (n_reqs * sizeof (*reqs));
  clib_memset (reqs, 0, n_reqs * sizeof (*reqs));
  for (i = 0; i < n_reqs; i++)
    {
      reqs[i].handle = handles[i];
      session_send_rpc_evt_to_thread (session_thread_from_handle (handles[i]),
				      tcp_e2e_session_cleanup_rpc, &reqs[i]);
    }

  for (i = 0; i < 1000; i++)
    {
      for (n_done = 0; n_done < n_reqs && reqs[n_done].done; n_done++)
	;
      if (n_done == n_reqs)
	{
	  clib_mem_free (reqs);
	  return 1;
	}
      tcp_e2e_pump (vm, 1e-3);
    }

  /* The requests retain these arguments and may still complete later. */
  return 0;
}

/* Drain graph frames before deleting test interfaces. A fixed number of
 * scheduler steps is not sufficient: the process can resume with a newly
 * produced interface-output frame still pending. Require two consecutive idle
 * observations while the worker barrier is held. */
static inline int
tcp_e2e_drain_graph_frames (vlib_main_t *vm)
{
  u32 idle = 0, i, thread_index;

  for (i = 0; i < 1000 && idle < 2; i++)
    {
      tcp_e2e_pump (vm, 1e-3);

      for (thread_index = 0; thread_index < vlib_get_n_threads (); thread_index++)
	if (vec_len (vlib_get_main_by_index (thread_index)->node_main.pending_frames))
	  break;

      idle = thread_index == vlib_get_n_threads () ? idle + 1 : 0;
    }

  return idle == 2;
}

/* Return wait iterations covering at least eight RTOs, with a two-second
 * minimum. The connection RTO is expressed in TCP_TICK units. */
static inline u32
tcp_e2e_rxt_wait_iters (tcp_connection_t *tc, f64 step)
{
  f64 rto_secs = (f64) tc->rto / (f64) THZ;
  f64 budget = clib_max (8.0 * rto_secs, 2.0);
  return (u32) (budget / step) + 1;
}

/* Sum waitclose timeout counters across all TCP workers. TIME_WAIT expiration
 * is excluded because it is part of a normal active close. */
static inline u64
tcp_e2e_teardown_timeouts (void)
{
  tcp_main_t *tm = vnet_get_tcp_main ();
  u64 total = 0;
  u32 i;

  for (i = 0; i < vec_len (tm->wrk); i++)
    {
      tcp_worker_ctx_t *wrk = tcp_get_worker (i);
      total += wrk->stats.to_closewait + wrk->stats.to_closewait2 + wrk->stats.to_finwait1 +
	       wrk->stats.to_finwait2 + wrk->stats.to_lastack + wrk->stats.to_closing;
    }
  return total;
}

static inline void tcp_e2e_teardown (vlib_main_t *vm, tcp_e2e_ctx_t *ctx);

/* Bring up client+server apps over loopbacks and connect them. Fills ctx
 * incrementally so a failure can be unwound by tcp_e2e_teardown. Returns 0 on
 * success; on failure logs the failing step and returns non-zero (the caller
 * should still call tcp_e2e_teardown). */
static inline int
tcp_e2e_setup (vlib_main_t *vm, tcp_e2e_ctx_t *ctx, tcp_e2e_params_t *p)
{
  u64 options[APP_OPTIONS_N_OPTIONS];
  u32 rx_fifo = p->rx_fifo_size ? p->rx_fifo_size : (4 << 10);
  u32 tx_fifo = p->tx_fifo_size ? p->tx_fifo_size : (4 << 10);
  transport_connection_t *tc;
  u32 tries;
  int error;

  clib_memset (ctx, 0, sizeof (*ctx));
  ctx->client_index = ctx->server_index = ~0;
  ctx->sw_if_index[0] = ctx->sw_if_index[1] = ~0;
  ctx->listen_handle = SESSION_INVALID_HANDLE;
  ctx->client_vrf = p->client_vrf;
  ctx->server_vrf = p->server_vrf;
  ctx->secret = p->secret;

  session_test_reset_placeholder_state ();

  ctx->intf_addr[0].as_u32 = clib_host_to_net_u32 (p->client_addr);
  if (session_create_lookpback (p->client_vrf, &ctx->sw_if_index[0], &ctx->intf_addr[0]))
    return -1;

  ctx->intf_addr[1].as_u32 = clib_host_to_net_u32 (p->server_addr);
  if (session_create_lookpback (p->server_vrf, &ctx->sw_if_index[1], &ctx->intf_addr[1]))
    return -1;

  session_add_del_route_via_lookup_in_table (p->client_vrf, p->server_vrf, &ctx->intf_addr[1], 32,
					     1 /* is_add */);
  session_add_del_route_via_lookup_in_table (p->server_vrf, p->client_vrf, &ctx->intf_addr[0], 32,
					     1 /* is_add */);
  ctx->routes_added = 1;

  ctx->appns_id = format (0, "appns_%s_server", p->name);
  vnet_app_namespace_add_del_args_t ns_args = {
    .ns_id = ctx->appns_id,
    .secret = p->secret,
    .sw_if_index = ctx->sw_if_index[1],
    .is_add = 1,
  };
  error = vnet_app_namespace_add_del (&ns_args);
  if (error)
    {
      clib_warning ("app ns insertion failed: %d", error);
      return -1;
    }
  ctx->ns_added = 1;

  clib_memset (options, 0, sizeof (options));
  options[APP_OPTIONS_FLAGS] = APP_OPTIONS_FLAGS_IS_BUILTIN;
  options[APP_OPTIONS_FLAGS] |= APP_OPTIONS_FLAGS_USE_GLOBAL_SCOPE;
  options[APP_OPTIONS_RX_FIFO_SIZE] = rx_fifo;
  options[APP_OPTIONS_TX_FIFO_SIZE] = tx_fifo;

  vnet_app_attach_args_t attach_args = {
    .api_client_index = ~0,
    .options = options,
    .namespace_id = 0,
    .session_cb_vft = &placeholder_session_cbs,
    .name = format (0, "tcp_e2e_%s_client", p->name),
  };
  error = vnet_application_attach (&attach_args);
  vec_free (attach_args.name);
  if (error)
    {
      clib_warning ("client attach failed: %d", error);
      return -1;
    }
  ctx->client_index = attach_args.app_index;

  options[APP_OPTIONS_RX_FIFO_SIZE] = rx_fifo;
  options[APP_OPTIONS_TX_FIFO_SIZE] = tx_fifo;
  options[APP_OPTIONS_ADD_SEGMENT_SIZE] = 32 << 20;

  attach_args.name = format (0, "tcp_e2e_%s_server", p->name);
  attach_args.namespace_id = ctx->appns_id;
  attach_args.options[APP_OPTIONS_NAMESPACE_SECRET] = p->secret;
  error = vnet_application_attach (&attach_args);
  vec_free (attach_args.name);
  if (error)
    {
      clib_warning ("server attach failed: %d", error);
      return -1;
    }
  ctx->server_index = attach_args.app_index;

  session_endpoint_cfg_t server_sep = SESSION_ENDPOINT_CFG_NULL;
  server_sep.is_ip4 = 1;
  server_sep.port = p->server_port;
  vnet_listen_args_t bind_args = {
    .sep_ext = server_sep,
    .app_index = ctx->server_index,
  };
  error = vnet_listen (&bind_args);
  if (error)
    {
      clib_warning ("server bind failed: %d", error);
      return -1;
    }
  ctx->listen_handle = bind_args.handle;

  session_endpoint_cfg_t client_sep = SESSION_ENDPOINT_CFG_NULL;
  client_sep.is_ip4 = 1;
  client_sep.ip.ip4.as_u32 = ctx->intf_addr[1].as_u32;
  client_sep.port = p->server_port;
  client_sep.peer.is_ip4 = 1;
  client_sep.peer.ip.ip4.as_u32 = ctx->intf_addr[0].as_u32;
  client_sep.peer.port = p->client_port;
  client_sep.transport_proto = TRANSPORT_PROTO_TCP;

  vnet_connect_args_t connect_args = {
    .sep_ext = client_sep,
    .app_index = ctx->client_index,
  };
  error = vnet_connect (&connect_args);
  if (error)
    {
      clib_warning ("connect failed: %d", error);
      return -1;
    }

  tries = 0;
  while (connected_session_index == ~0 && ++tries < 100)
    tcp_e2e_pump (vm, 10e-3);
  while (accepted_session_index == ~0 && ++tries < 100)
    tcp_e2e_pump (vm, 10e-3);

  if (connected_session_index == ~0 || accepted_session_index == ~0)
    {
      clib_warning ("client/server session did not come up");
      return -1;
    }

  ctx->client_s = session_get (connected_session_index, connected_session_thread);
  tc = session_get_transport (ctx->client_s);
  if (!tc)
    {
      clib_warning ("client transport missing");
      return -1;
    }
  ctx->client_tc = (tcp_connection_t *) tc;
  return 0;
}

static inline void
tcp_e2e_teardown (vlib_main_t *vm, tcp_e2e_ctx_t *ctx)
{
  int sessions_cleaned = tcp_e2e_force_session_cleanup (vm);

  if (ctx->listen_handle != SESSION_INVALID_HANDLE)
    {
      vnet_unlisten_args_t ua = {
	.handle = ctx->listen_handle,
	.app_index = ctx->server_index,
      };
      (void) vnet_unlisten (&ua);
    }

  if (ctx->server_index != ~0)
    {
      vnet_app_detach_args_t da = { .app_index = ctx->server_index, .api_client_index = ~0 };
      vnet_application_detach (&da);
    }
  if (ctx->client_index != ~0)
    {
      vnet_app_detach_args_t da = { .app_index = ctx->client_index, .api_client_index = ~0 };
      vnet_application_detach (&da);
    }

  if (ctx->ns_added)
    {
      vnet_app_namespace_add_del_args_t ns_args = {
	.ns_id = ctx->appns_id,
	.secret = ctx->secret,
	.sw_if_index = ctx->sw_if_index[1],
	.is_add = 0,
      };
      (void) vnet_app_namespace_add_del (&ns_args);
    }

  vlib_process_suspend (vm, 10e-3);

  if (ctx->routes_added)
    {
      session_add_del_route_via_lookup_in_table (ctx->client_vrf, ctx->server_vrf,
						 &ctx->intf_addr[1], 32, 0 /* is_add */);
      session_add_del_route_via_lookup_in_table (ctx->server_vrf, ctx->client_vrf,
						 &ctx->intf_addr[0], 32, 0 /* is_add */);
    }

  /* Remove interface addresses and stop the loopbacks before draining. */
  for (int i = 0; i < 2; i++)
    {
      if (ctx->sw_if_index[i] == ~0)
	continue;
      (void) ip4_add_del_interface_address (vm, ctx->sw_if_index[i], &ctx->intf_addr[i], 24,
					    1 /* is_del */);
      vnet_sw_interface_set_flags (vnet_get_main (), ctx->sw_if_index[i], 0);
    }

  if (!sessions_cleaned || !tcp_e2e_drain_graph_frames (vm))
    {
      clib_warning ("graph frames did not quiesce; preserving test loopbacks");
      goto done;
    }

  for (int i = 0; i < 2; i++)
    {
      if (ctx->sw_if_index[i] == ~0)
	continue;
      (void) vnet_delete_loopback_interface (ctx->sw_if_index[i]);
    }

done:
  vec_free (ctx->appns_id);
}

#endif /* SRC_PLUGINS_UNITTEST_TCP_TCP_E2E_HELPERS_H_ */
