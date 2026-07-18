/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026
 */

#include <arpa/inet.h>
#include <errno.h>
#include <pthread.h>

#include <spdk/env.h>
#include <spdk/log.h>
#include <spdk/net.h>
#include <spdk/sock.h>
#include <spdk/string.h>
#include <spdk/thread.h>
#include <spdk/util.h>

#ifndef DEBUG
#define DEBUG		     1
#define SPDK_VPP_UNDEF_DEBUG 1
#endif
#include <spdk_internal/sock_module.h>
#ifdef SPDK_VPP_UNDEF_DEBUG
#undef DEBUG
#undef SPDK_VPP_UNDEF_DEBUG
#endif

#include <vlib/vlib.h>
#include <vlib/threads.h>
#include <vnet/session/application.h>
#include <vnet/session/application_interface.h>
#include <vnet/session/session.h>
#include <vppinfra/hash.h>

#include "spdk_plugin.h"

typedef struct spdk_vpp_sock spdk_vpp_sock_t;
typedef struct spdk_vpp_group spdk_vpp_group_t;
typedef struct spdk_vpp_tx_reservation spdk_vpp_tx_reservation_t;

struct spdk_vpp_tx_reservation
{
  spdk_vpp_sock_t *sock;
  u32 len;
  u8 committed;
  TAILQ_ENTRY (spdk_vpp_tx_reservation) link;
  SLIST_ENTRY (spdk_vpp_tx_reservation) cache_link;
};

struct spdk_vpp_sock
{
  struct spdk_sock base;
  clib_spinlock_t lock;

  session_t *session;
  session_handle_t handle;
  session_handle_t listener_handle;

  u8 connected;
  u8 closed;
  u8 is_listener;
  u8 is_ipv6;
  u8 event_queued;
  u8 flush_queued;

  spdk_sock_connect_cb_fn connect_cb_fn;
  void *connect_cb_arg;
  u32 opaque;

  char lcl_addr[INET6_ADDRSTRLEN];
  char rmt_addr[INET6_ADDRSTRLEN];
  u16 lcl_port;
  u16 rmt_port;

  spdk_vpp_group_t *group;
  TAILQ_HEAD (, spdk_vpp_sock) acceptq;
  TAILQ_HEAD (, spdk_vpp_tx_reservation) tx_reservations;
  SLIST_HEAD (, spdk_vpp_tx_reservation) tx_reservation_cache;
  u32 tx_reserved;
  u32 tx_reservation_cache_count;
  u64 tx_async_reqs;
  u64 tx_flush_calls;
  u64 tx_flush_cb_busy;
  u64 tx_no_space;
  u64 tx_enqueue_fail;
  u64 tx_partial_flush;
  u64 tx_bytes_enqueued;
  u64 tx_fifo_wraps;
  u64 tx_events_programmed;
  u64 tx_events_coalesced;
  u64 rx_calls;
  u64 rx_bytes;
  TAILQ_ENTRY (spdk_vpp_sock) accept_link;
  TAILQ_ENTRY (spdk_vpp_sock) event_link;
  TAILQ_ENTRY (spdk_vpp_sock) flush_link;
};

struct spdk_vpp_group
{
  struct spdk_sock_group_impl base;
  clib_spinlock_t lock;
  TAILQ_HEAD (, spdk_vpp_sock) events;
  TAILQ_HEAD (, spdk_vpp_sock) flush_socks;
  u32 flush_count;
  u32 listener_count;
  u32 lcore;
  u32 vpp_thread_index;
  u64 tx_reservations;
  u64 tx_reservation_bytes;
  u64 tx_commits;
  u64 tx_aborts;
  u64 tx_ooo_commits;
  u64 tx_publish_batches;
  u64 tx_events;
  u64 tx_max_reserved;
  u64 polls;
  u64 full_sweeps;
  u64 rx_sweep_ready;
  u64 tx_sweep_queued;
  TAILQ_ENTRY (spdk_vpp_group) link;
};

typedef struct
{
  u32 app_index;
  u8 attached;
  u8 locks_inited;
  u32 next_opaque;
  uword *sock_by_handle;
  uword *sock_by_opaque;
  spdk_vpp_sock_t ***sock_by_session;
  TAILQ_HEAD (, spdk_vpp_group) groups;
  u64 placement_hits;
  u64 placement_misses;
  u64 affinity_errors;
  clib_spinlock_t lock;
} spdk_vpp_main_t;

static spdk_vpp_main_t spdk_vpp_main = {
  .app_index = APP_INVALID_INDEX,
};

static int spdk_vpp_sock_close (struct spdk_sock *_sock);

static struct spdk_sock_impl_opts g_vpp_impl_opts = {
  .recv_buf_size = DEFAULT_SO_RCVBUF_SIZE,
  .send_buf_size = DEFAULT_SO_SNDBUF_SIZE,
  .enable_recv_pipe = false,
  .enable_quickack = false,
  .enable_placement_id = PLACEMENT_NONE,
  .enable_zerocopy_send_server = false,
  .enable_zerocopy_send_client = false,
  .zerocopy_threshold = 0,
  .tls_version = 0,
  .enable_ktls = false,
  .psk_key = NULL,
  .psk_identity = NULL,
};

#define __vpp_sock(s)			  ((spdk_vpp_sock_t *) (s))
#define __vpp_group(g)			  ((spdk_vpp_group_t *) (g))
#define SPDK_VPP_TX_RESERVATION_CACHE_MAX 256
#define SPDK_VPP_GROUP_SWEEP_INTERVAL	  1024

static void spdk_vpp_sock_event (spdk_vpp_sock_t *sock);

static void
spdk_vpp_main_init (void)
{
  spdk_vpp_main_t *vm = &spdk_vpp_main;

  if (vm->locks_inited)
    return;

  clib_spinlock_init (&vm->lock);
  TAILQ_INIT (&vm->groups);
  vec_validate (vm->sock_by_session, vlib_get_n_threads () - 1);
  vm->locks_inited = 1;
}

static int
spdk_vpp_sock_owner_thread (spdk_vpp_sock_t *sock, u32 *thread_index)
{
  if (sock->is_listener || sock->handle == SESSION_INVALID_HANDLE)
    return -ENOENT;

  *thread_index = session_thread_from_handle (sock->handle);
  return 0;
}

static int
spdk_vpp_sock_check_affinity (spdk_vpp_sock_t *sock)
{
  spdk_vpp_main_t *vm = &spdk_vpp_main;
  u32 owner_thread;

  if (spdk_vpp_sock_owner_thread (sock, &owner_thread))
    return 0;

  if (PREDICT_TRUE (owner_thread == vlib_get_thread_index ()))
    return 0;

  clib_spinlock_lock (&vm->lock);
  vm->affinity_errors++;
  clib_spinlock_unlock (&vm->lock);
  return -EXDEV;
}

static int
spdk_vpp_session_error_to_errno (session_error_t err)
{
  switch (err)
    {
    case SESSION_E_NONE:
      return 0;
    case SESSION_E_REFUSED:
      return -ECONNREFUSED;
    case SESSION_E_TIMEDOUT:
      return -ETIMEDOUT;
    case SESSION_E_NOIP:
    case SESSION_E_NOINTF:
      return -EHOSTUNREACH;
    default:
      return -ECONNRESET;
    }
}

static spdk_vpp_sock_t *
spdk_vpp_sock_get_by_handle (session_handle_t handle)
{
  spdk_vpp_main_t *vm = &spdk_vpp_main;
  uword *p;

  clib_spinlock_lock (&vm->lock);
  p = hash_get (vm->sock_by_handle, handle);
  clib_spinlock_unlock (&vm->lock);
  return p ? uword_to_pointer (*p, spdk_vpp_sock_t *) : 0;
}

static spdk_vpp_sock_t *
spdk_vpp_sock_get_by_session (session_t *s)
{
  spdk_vpp_main_t *vm = &spdk_vpp_main;
  spdk_vpp_sock_t **socks;

  if (PREDICT_FALSE (s->thread_index >= vec_len (vm->sock_by_session)))
    return 0;

  socks = vm->sock_by_session[s->thread_index];
  if (PREDICT_FALSE (s->session_index >= vec_len (socks)))
    return 0;

  return socks[s->session_index];
}

static void
spdk_vpp_sock_map_session (spdk_vpp_sock_t *sock, session_t *s)
{
  spdk_vpp_main_t *vm = &spdk_vpp_main;
  spdk_vpp_sock_t **socks;

  ASSERT (s->thread_index < vec_len (vm->sock_by_session));
  socks = vm->sock_by_session[s->thread_index];
  if (s->session_index >= vec_len (socks))
    vec_validate (socks, s->session_index);
  ASSERT (socks[s->session_index] == 0);
  socks[s->session_index] = sock;
  vm->sock_by_session[s->thread_index] = socks;
}

static void
spdk_vpp_sock_unmap_session (spdk_vpp_sock_t *sock)
{
  spdk_vpp_main_t *vm = &spdk_vpp_main;
  spdk_vpp_sock_t **socks;
  session_handle_tu_t handle = { .handle = sock->handle };

  if (sock->handle == SESSION_INVALID_HANDLE ||
      handle.thread_index >= vec_len (vm->sock_by_session))
    return;

  socks = vm->sock_by_session[handle.thread_index];
  if (handle.session_index < vec_len (socks) && socks[handle.session_index] == sock)
    socks[handle.session_index] = 0;
}

static spdk_vpp_sock_t *
spdk_vpp_sock_get_by_opaque (u32 opaque)
{
  spdk_vpp_main_t *vm = &spdk_vpp_main;
  uword *p;

  clib_spinlock_lock (&vm->lock);
  p = hash_get (vm->sock_by_opaque, opaque);
  clib_spinlock_unlock (&vm->lock);
  return p ? uword_to_pointer (*p, spdk_vpp_sock_t *) : 0;
}

static void
spdk_vpp_sock_map_handle (spdk_vpp_sock_t *sock, session_handle_t handle)
{
  spdk_vpp_main_t *vm = &spdk_vpp_main;

  clib_spinlock_lock (&vm->lock);
  hash_set (vm->sock_by_handle, handle, pointer_to_uword (sock));
  clib_spinlock_unlock (&vm->lock);
}

static void
spdk_vpp_sock_unmap_handle (session_handle_t handle)
{
  spdk_vpp_main_t *vm = &spdk_vpp_main;

  clib_spinlock_lock (&vm->lock);
  hash_unset (vm->sock_by_handle, handle);
  clib_spinlock_unlock (&vm->lock);
}

static u32
spdk_vpp_sock_map_opaque (spdk_vpp_sock_t *sock)
{
  spdk_vpp_main_t *vm = &spdk_vpp_main;
  u32 opaque;

  clib_spinlock_lock (&vm->lock);
  opaque = ++vm->next_opaque;
  if (opaque == 0)
    opaque = ++vm->next_opaque;
  hash_set (vm->sock_by_opaque, opaque, pointer_to_uword (sock));
  clib_spinlock_unlock (&vm->lock);

  sock->opaque = opaque;
  return opaque;
}

static void
spdk_vpp_sock_unmap_opaque (spdk_vpp_sock_t *sock)
{
  spdk_vpp_main_t *vm = &spdk_vpp_main;

  if (!sock->opaque)
    return;

  clib_spinlock_lock (&vm->lock);
  hash_unset (vm->sock_by_opaque, sock->opaque);
  clib_spinlock_unlock (&vm->lock);
  sock->opaque = 0;
}

static void
spdk_vpp_group_enqueue (spdk_vpp_group_t *group, spdk_vpp_sock_t *sock)
{
  if (!group)
    return;

  /* Data sockets and their SPDK groups are deliberately placed on the same
   * VPP worker.  Listener notifications are the only events that may cross
   * workers, so keep those on the locked path. */
  if (PREDICT_TRUE (!sock->is_listener &&
		    group->vpp_thread_index == vlib_get_thread_index ()))
    {
      if (!sock->event_queued)
	{
	  TAILQ_INSERT_TAIL (&group->events, sock, event_link);
	  sock->event_queued = 1;
	}
      return;
    }

  clib_spinlock_lock (&group->lock);
  if (!sock->event_queued)
    {
      TAILQ_INSERT_TAIL (&group->events, sock, event_link);
      sock->event_queued = 1;
    }
  clib_spinlock_unlock (&group->lock);
}

static void
spdk_vpp_group_enqueue_flush (spdk_vpp_group_t *group, spdk_vpp_sock_t *sock)
{
  if (!group)
    return;

  /* SPDK invokes writev_async and group polling on the group's bound worker.
   * The flush queue therefore has a single producer and a single consumer on
   * the same thread. */
  ASSERT (group->vpp_thread_index == vlib_get_thread_index ());
  if (!sock->flush_queued)
    {
      TAILQ_INSERT_TAIL (&group->flush_socks, sock, flush_link);
      sock->flush_queued = 1;
      group->flush_count++;
    }
}

static void
spdk_vpp_sock_event (spdk_vpp_sock_t *sock)
{
  spdk_vpp_group_t *group;

  if (PREDICT_TRUE (!sock->is_listener &&
		    session_thread_from_handle (sock->handle) == vlib_get_thread_index ()))
    {
      group = sock->group;
      spdk_vpp_group_enqueue (group, sock);
      return;
    }

  /* Publish the listener's group and event atomically with respect to group
   * removal.  Listener callbacks may arrive on any VPP worker. */
  clib_spinlock_lock (&sock->lock);
  group = sock->group;
  if (group)
    {
      clib_spinlock_lock (&group->lock);
      if (!sock->event_queued)
	{
	  TAILQ_INSERT_TAIL (&group->events, sock, event_link);
	  sock->event_queued = 1;
	}
      clib_spinlock_unlock (&group->lock);
    }
  clib_spinlock_unlock (&sock->lock);
}

static void
spdk_vpp_save_endpoints (spdk_vpp_sock_t *sock, session_t *s)
{
  transport_endpoint_t rmt = {}, lcl = {};
  int af;

  session_get_endpoint (s, &rmt, &lcl);
  sock->is_ipv6 = !lcl.is_ip4;
  af = lcl.is_ip4 ? AF_INET : AF_INET6;
  inet_ntop (af, lcl.is_ip4 ? (void *) &lcl.ip.ip4 : (void *) &lcl.ip.ip6, sock->lcl_addr,
	     sizeof (sock->lcl_addr));
  inet_ntop (af, rmt.is_ip4 ? (void *) &rmt.ip.ip4 : (void *) &rmt.ip.ip6, sock->rmt_addr,
	     sizeof (sock->rmt_addr));
  sock->lcl_port = clib_net_to_host_u16 (lcl.port);
  sock->rmt_port = clib_net_to_host_u16 (rmt.port);
}

static int
spdk_vpp_fill_sep (const char *ip, int port, session_endpoint_cfg_t *sep)
{
  ip4_address_t ip4;
  ip6_address_t ip6;

  *sep = (session_endpoint_cfg_t) SESSION_ENDPOINT_CFG_NULL;
  sep->transport_proto = TRANSPORT_PROTO_TCP;
  sep->port = clib_host_to_net_u16 ((u16) port);
  sep->sw_if_index = ENDPOINT_INVALID_INDEX;
  sep->fib_index = ENDPOINT_INVALID_INDEX;

  if (ip == NULL || ip[0] == '\0')
    {
      sep->is_ip4 = 1;
      return 0;
    }

  if (strchr (ip, ':'))
    {
      if (inet_pton (AF_INET6, ip, &ip6) != 1)
	return -EINVAL;
      sep->is_ip4 = 0;
      ip46_address_set_ip6 (&sep->ip, &ip6);
    }
  else
    {
      if (inet_pton (AF_INET, ip, &ip4) != 1)
	return -EINVAL;
      sep->is_ip4 = 1;
      ip46_address_set_ip4 (&sep->ip, &ip4);
    }

  return 0;
}

static spdk_vpp_sock_t *
spdk_vpp_sock_alloc (void)
{
  spdk_vpp_sock_t *sock = calloc (1, sizeof (*sock));

  if (!sock)
    return 0;

  TAILQ_INIT (&sock->base.queued_reqs);
  TAILQ_INIT (&sock->base.pending_reqs);
  TAILQ_INIT (&sock->acceptq);
  TAILQ_INIT (&sock->tx_reservations);
  SLIST_INIT (&sock->tx_reservation_cache);
  clib_spinlock_init (&sock->lock);
  sock->handle = SESSION_INVALID_HANDLE;
  sock->listener_handle = SESSION_INVALID_HANDLE;
  return sock;
}

static void
spdk_vpp_tx_reservation_release (spdk_vpp_tx_reservation_t *reservation, u8 cache)
{
  spdk_vpp_sock_t *sock = reservation->sock;

  reservation->len = 0;
  reservation->committed = 0;
  if (cache && !sock->closed &&
      sock->tx_reservation_cache_count < SPDK_VPP_TX_RESERVATION_CACHE_MAX)
    {
      SLIST_INSERT_HEAD (&sock->tx_reservation_cache, reservation, cache_link);
      sock->tx_reservation_cache_count++;
      return;
    }
  free (reservation);
}

static void
spdk_vpp_sock_free (spdk_vpp_sock_t *sock)
{
  spdk_vpp_tx_reservation_t *reservation;

  while ((reservation = TAILQ_FIRST (&sock->tx_reservations)) != NULL)
    {
      TAILQ_REMOVE (&sock->tx_reservations, reservation, link);
      spdk_vpp_tx_reservation_release (reservation, 0);
    }
  while ((reservation = SLIST_FIRST (&sock->tx_reservation_cache)) != NULL)
    {
      SLIST_REMOVE_HEAD (&sock->tx_reservation_cache, cache_link);
      free (reservation);
    }
  clib_spinlock_free (&sock->lock);
  free (sock);
}

static void
spdk_vpp_disconnect_handle_rpc (void *arg)
{
  session_handle_t handle = pointer_to_uword (arg);
  vnet_disconnect_args_t a = {
    .handle = handle,
    .app_index = spdk_vpp_main.app_index,
  };

  vnet_disconnect_session (&a);
}

typedef struct
{
  pthread_mutex_t lock;
  pthread_cond_t cond;
  int done;
  int rv;
  vnet_listen_args_t listen_args;
  vnet_unlisten_args_t unlisten_args;
  vnet_connect_args_t connect_args;
} spdk_vpp_rpc_op_t;

static void
spdk_vpp_rpc_done (spdk_vpp_rpc_op_t *op, int rv)
{
  pthread_mutex_lock (&op->lock);
  op->rv = rv;
  op->done = 1;
  pthread_cond_signal (&op->cond);
  pthread_mutex_unlock (&op->lock);
}

static int
spdk_vpp_rpc_wait (void (*fn) (void *), spdk_vpp_rpc_op_t *op)
{
  clib_thread_index_t thread_index = transport_cl_thread ();

  pthread_mutex_init (&op->lock, 0);
  pthread_cond_init (&op->cond, 0);

  if (vlib_get_thread_index () == thread_index)
    {
      fn (op);
    }
  else
    {
      pthread_mutex_lock (&op->lock);
      session_send_rpc_evt_to_thread_force (thread_index, fn, op);
      while (!op->done)
	pthread_cond_wait (&op->cond, &op->lock);
      pthread_mutex_unlock (&op->lock);
    }

  pthread_cond_destroy (&op->cond);
  pthread_mutex_destroy (&op->lock);
  return op->rv;
}

static void
spdk_vpp_listen_rpc (void *arg)
{
  spdk_vpp_rpc_op_t *op = arg;
  spdk_vpp_rpc_done (op, vnet_listen (&op->listen_args));
}

static void
spdk_vpp_unlisten_rpc (void *arg)
{
  spdk_vpp_rpc_op_t *op = arg;
  spdk_vpp_rpc_done (op, vnet_unlisten (&op->unlisten_args));
}

static void
spdk_vpp_connect_rpc (void *arg)
{
  spdk_vpp_rpc_op_t *op = arg;
  spdk_vpp_rpc_done (op, vnet_connect (&op->connect_args));
}

static int
spdk_vpp_app_rx_callback (session_t *s)
{
  spdk_vpp_sock_t *sock = spdk_vpp_sock_get_by_session (s);

  if (sock)
    spdk_vpp_sock_event (sock);

  return 0;
}

static int
spdk_vpp_app_tx_callback (session_t *s)
{
  (void) s;
  return 0;
}

static int
spdk_vpp_add_segment_callback (u32 app_wrk_index, u64 segment_handle)
{
  (void) app_wrk_index;
  (void) segment_handle;
  return 0;
}

static int
spdk_vpp_del_segment_callback (u32 app_wrk_index, u64 segment_handle)
{
  (void) app_wrk_index;
  (void) segment_handle;
  return 0;
}

static int
spdk_vpp_session_accept_callback (session_t *s)
{
  spdk_vpp_sock_t *listener, *sock;

  listener = spdk_vpp_sock_get_by_handle (s->listener_handle);
  if (!listener)
    return -1;

  sock = spdk_vpp_sock_alloc ();
  if (!sock)
    return -1;

  s->session_state = SESSION_STATE_READY;
  sock->session = s;
  sock->handle = session_handle (s);
  sock->listener_handle = s->listener_handle;
  sock->connected = 1;
  spdk_vpp_save_endpoints (sock, s);
  spdk_vpp_sock_map_session (sock, s);
  spdk_vpp_sock_map_handle (sock, sock->handle);

  clib_spinlock_lock (&listener->lock);
  TAILQ_INSERT_TAIL (&listener->acceptq, sock, accept_link);
  clib_spinlock_unlock (&listener->lock);

  spdk_vpp_sock_event (listener);
  return 0;
}

static int
spdk_vpp_session_connected_callback (u32 app_wrk_index, u32 opaque, session_t *s,
				     session_error_t err)
{
  spdk_vpp_sock_t *sock = spdk_vpp_sock_get_by_opaque (opaque);
  spdk_sock_connect_cb_fn cb_fn = 0;
  void *cb_arg = 0;
  int status;

  if (!sock)
    return -1;

  status = spdk_vpp_session_error_to_errno (err);

  clib_spinlock_lock (&sock->lock);
  if (!status)
    {
      s->session_state = SESSION_STATE_READY;
      sock->session = s;
      sock->handle = session_handle (s);
      sock->connected = 1;
      spdk_vpp_save_endpoints (sock, s);
      spdk_vpp_sock_map_session (sock, s);
      spdk_vpp_sock_map_handle (sock, sock->handle);
    }
  else
    {
      sock->closed = 1;
    }
  cb_fn = sock->connect_cb_fn;
  cb_arg = sock->connect_cb_arg;
  sock->connect_cb_fn = 0;
  sock->connect_cb_arg = 0;
  clib_spinlock_unlock (&sock->lock);

  if (cb_fn)
    cb_fn (cb_arg, status);
  if (!status)
    spdk_vpp_sock_event (sock);

  return 0;
}

static void
spdk_vpp_session_disconnect_callback (session_t *s)
{
  spdk_vpp_sock_t *sock = spdk_vpp_sock_get_by_session (s);

  if (!sock)
    return;

  clib_spinlock_lock (&sock->lock);
  sock->closed = 1;
  clib_spinlock_unlock (&sock->lock);
  spdk_vpp_sock_event (sock);

  spdk_vpp_disconnect_handle_rpc (uword_to_pointer (session_handle (s), void *));
}

static void
spdk_vpp_session_reset_callback (session_t *s)
{
  spdk_vpp_session_disconnect_callback (s);
}

static void
spdk_vpp_session_cleanup_callback (session_t *s, session_cleanup_ntf_t ntf)
{
  spdk_vpp_sock_t *sock = spdk_vpp_sock_get_by_session (s);

  (void) ntf;

  if (!sock)
    return;

  clib_spinlock_lock (&sock->lock);
  spdk_vpp_sock_unmap_session (sock);
  sock->session = 0;
  sock->closed = 1;
  clib_spinlock_unlock (&sock->lock);
  spdk_vpp_sock_event (sock);
}

static session_cb_vft_t spdk_vpp_session_cb_vft = {
  .session_accept_callback = spdk_vpp_session_accept_callback,
  .session_connected_callback = spdk_vpp_session_connected_callback,
  .session_disconnect_callback = spdk_vpp_session_disconnect_callback,
  .session_transport_closed_callback = spdk_vpp_session_disconnect_callback,
  .session_reset_callback = spdk_vpp_session_reset_callback,
  .session_cleanup_callback = spdk_vpp_session_cleanup_callback,
  .builtin_app_rx_callback = spdk_vpp_app_rx_callback,
  .builtin_app_tx_callback = spdk_vpp_app_tx_callback,
  .add_segment_callback = spdk_vpp_add_segment_callback,
  .del_segment_callback = spdk_vpp_del_segment_callback,
};

int
spdk_vpp_attach (void)
{
  spdk_vpp_main_t *vm = &spdk_vpp_main;
  vnet_app_attach_args_t _a = {}, *a = &_a;
  u64 options[APP_OPTIONS_N_OPTIONS] = {};
  int rv;

  spdk_vpp_main_init ();

  clib_spinlock_lock (&vm->lock);
  if (vm->attached)
    {
      clib_spinlock_unlock (&vm->lock);
      return 0;
    }
  clib_spinlock_unlock (&vm->lock);

  session_enable_disable_args_t args = { .is_en = 1,
					 .rt_engine_type = RT_BACKEND_ENGINE_RULE_TABLE };
  vlib_worker_thread_barrier_sync (vlib_get_main ());
  vnet_session_enable_disable (vlib_get_main (), &args);
  vlib_worker_thread_barrier_release (vlib_get_main ());

  a->api_client_index = APP_INVALID_INDEX;
  a->name = format (0, "spdk");
  a->session_cb_vft = &spdk_vpp_session_cb_vft;
  a->options = options;
  options[APP_OPTIONS_FLAGS] = APP_OPTIONS_FLAGS_IS_BUILTIN | APP_OPTIONS_FLAGS_USE_GLOBAL_SCOPE |
			       APP_OPTIONS_FLAGS_USE_LOCAL_SCOPE;
  options[APP_OPTIONS_SEGMENT_SIZE] = 256 << 20;
  options[APP_OPTIONS_ADD_SEGMENT_SIZE] = 256 << 20;
  options[APP_OPTIONS_RX_FIFO_SIZE] = 16 << 20;
  options[APP_OPTIONS_TX_FIFO_SIZE] = 16 << 20;
  options[APP_OPTIONS_MAX_FIFO_SIZE] = 16 << 20;
  options[APP_OPTIONS_EVT_QUEUE_SIZE] = 1 << 16;

  rv = vnet_application_attach (a);
  vec_free (a->name);
  if (rv)
    return rv;

  clib_spinlock_lock (&vm->lock);
  vm->app_index = a->app_index;
  vm->attached = 1;
  clib_spinlock_unlock (&vm->lock);
  return 0;
}

u32
spdk_vpp_app_index (void)
{
  return spdk_vpp_main.app_index;
}

static int
spdk_vpp_net_impl_init (struct spdk_sock_initialize_opts *opts)
{
  (void) opts;
  return spdk_vpp_attach ();
}

static int
spdk_vpp_sock_getaddr (struct spdk_sock *_sock, char *saddr, int slen, uint16_t *sport, char *caddr,
		       int clen, uint16_t *cport)
{
  spdk_vpp_sock_t *sock = __vpp_sock (_sock);

  clib_spinlock_lock (&sock->lock);
  if (saddr)
    spdk_strcpy_pad (saddr, sock->lcl_addr, slen, '\0');
  if (sport)
    *sport = sock->lcl_port;
  if (caddr)
    spdk_strcpy_pad (caddr, sock->rmt_addr, clen, '\0');
  if (cport)
    *cport = sock->rmt_port;
  clib_spinlock_unlock (&sock->lock);

  return 0;
}

static const char *
spdk_vpp_sock_get_interface_name (struct spdk_sock *_sock)
{
  (void) _sock;
  return "vpp";
}

static int32_t
spdk_vpp_sock_get_numa_id (struct spdk_sock *_sock)
{
  spdk_vpp_sock_t *sock = __vpp_sock (_sock);
  u32 owner_thread, lcore;

  if (!spdk_vpp_sock_owner_thread (sock, &owner_thread) &&
      !spdk_plugin_lcore_for_vpp_thread (owner_thread, &lcore))
    return spdk_env_get_numa_id (lcore);

  return spdk_env_get_numa_id (spdk_env_get_current_core ());
}

static struct spdk_sock *
spdk_vpp_sock_listen (const char *ip, int port, struct spdk_sock_opts *opts)
{
  spdk_vpp_sock_t *sock;
  spdk_vpp_rpc_op_t op = {};
  int rv;

  (void) opts;

  if (spdk_vpp_attach ())
    return 0;

  sock = spdk_vpp_sock_alloc ();
  if (!sock)
    return 0;

  sock->is_listener = 1;
  rv = spdk_vpp_fill_sep (ip, port, &op.listen_args.sep_ext);
  if (rv)
    {
      spdk_vpp_sock_free (sock);
      errno = -rv;
      return 0;
    }

  op.listen_args.app_index = spdk_vpp_main.app_index;
  rv = spdk_vpp_rpc_wait (spdk_vpp_listen_rpc, &op);
  if (rv)
    {
      spdk_vpp_sock_free (sock);
      errno = -rv;
      return 0;
    }

  sock->handle = op.listen_args.handle;
  sock->listener_handle = op.listen_args.handle;
  sock->connected = 1;
  sock->is_ipv6 = !op.listen_args.sep_ext.is_ip4;
  if (ip)
    spdk_strcpy_pad (sock->lcl_addr, ip, sizeof (sock->lcl_addr), '\0');
  else
    spdk_strcpy_pad (sock->lcl_addr, "0.0.0.0", sizeof (sock->lcl_addr), '\0');
  sock->lcl_port = port;
  spdk_vpp_sock_map_handle (sock, sock->handle);
  return &sock->base;
}

static struct spdk_sock *
spdk_vpp_sock_accept (struct spdk_sock *_sock)
{
  spdk_vpp_sock_t *listener = __vpp_sock (_sock);
  spdk_vpp_sock_t *sock;

  clib_spinlock_lock (&listener->lock);
  sock = TAILQ_FIRST (&listener->acceptq);
  if (sock)
    TAILQ_REMOVE (&listener->acceptq, sock, accept_link);
  clib_spinlock_unlock (&listener->lock);

  if (!sock)
    {
      errno = EAGAIN;
      return 0;
    }

  return &sock->base;
}

static struct spdk_sock *
spdk_vpp_sock_connect_async (const char *ip, int port, struct spdk_sock_opts *opts,
			     spdk_sock_connect_cb_fn cb_fn, void *cb_arg)
{
  spdk_vpp_sock_t *sock;
  spdk_vpp_rpc_op_t op = {};
  int rv;

  (void) opts;

  if (spdk_vpp_attach ())
    {
      errno = ENODEV;
      return 0;
    }

  sock = spdk_vpp_sock_alloc ();
  if (!sock)
    {
      errno = ENOMEM;
      return 0;
    }

  sock->connect_cb_fn = cb_fn;
  sock->connect_cb_arg = cb_arg;
  rv = spdk_vpp_fill_sep (ip, port, &op.connect_args.sep_ext);
  if (rv)
    {
      spdk_vpp_sock_free (sock);
      errno = -rv;
      return 0;
    }

  op.connect_args.app_index = spdk_vpp_main.app_index;
  op.connect_args.api_context = spdk_vpp_sock_map_opaque (sock);
  rv = spdk_vpp_rpc_wait (spdk_vpp_connect_rpc, &op);
  if (rv)
    {
      spdk_vpp_sock_unmap_opaque (sock);
      spdk_vpp_sock_free (sock);
      rv = spdk_vpp_session_error_to_errno (rv);
      errno = -rv;
      return 0;
    }

  return &sock->base;
}

static void
spdk_vpp_sync_connect_cb (void *cb_arg, int status)
{
  spdk_vpp_rpc_op_t *op = cb_arg;
  spdk_vpp_rpc_done (op, status);
}

static struct spdk_sock *
spdk_vpp_sock_connect (const char *ip, int port, struct spdk_sock_opts *opts)
{
  spdk_vpp_rpc_op_t op = {};
  struct spdk_sock *sock;
  int rv;

  pthread_mutex_init (&op.lock, 0);
  pthread_cond_init (&op.cond, 0);

  sock = spdk_vpp_sock_connect_async (ip, port, opts, spdk_vpp_sync_connect_cb, &op);
  if (!sock)
    {
      pthread_cond_destroy (&op.cond);
      pthread_mutex_destroy (&op.lock);
      return 0;
    }

  pthread_mutex_lock (&op.lock);
  while (!op.done)
    pthread_cond_wait (&op.cond, &op.lock);
  rv = op.rv;
  pthread_mutex_unlock (&op.lock);
  pthread_cond_destroy (&op.cond);
  pthread_mutex_destroy (&op.lock);

  if (rv)
    {
      spdk_vpp_sock_close (sock);
      errno = -rv;
      return 0;
    }

  return sock;
}

static int
spdk_vpp_sock_close (struct spdk_sock *_sock)
{
  spdk_vpp_sock_t *sock = __vpp_sock (_sock);
  spdk_vpp_rpc_op_t op = {};
  spdk_vpp_sock_t *accepted;

  spdk_vpp_sock_unmap_opaque (sock);

  clib_spinlock_lock (&sock->lock);
  sock->closed = 1;
  spdk_vpp_sock_unmap_session (sock);
  if (sock->handle != SESSION_INVALID_HANDLE)
    {
      if (sock->is_listener)
	{
	  op.unlisten_args.app_index = spdk_vpp_main.app_index;
	  op.unlisten_args.handle = sock->handle;
	  clib_spinlock_unlock (&sock->lock);
	  spdk_vpp_rpc_wait (spdk_vpp_unlisten_rpc, &op);
	  spdk_vpp_sock_unmap_handle (sock->handle);
	  clib_spinlock_lock (&sock->lock);
	}
      else
	{
	  session_send_rpc_evt_to_thread_force (transport_cl_thread (),
						spdk_vpp_disconnect_handle_rpc,
						uword_to_pointer (sock->handle, void *));
	  spdk_vpp_sock_unmap_handle (sock->handle);
	}
    }
  clib_spinlock_unlock (&sock->lock);

  while ((accepted = TAILQ_FIRST (&sock->acceptq)) != NULL)
    {
      TAILQ_REMOVE (&sock->acceptq, accepted, accept_link);
      spdk_vpp_sock_close (&accepted->base);
    }

  spdk_sock_abort_requests (_sock);
  spdk_vpp_sock_free (sock);
  return 0;
}

static ssize_t
spdk_vpp_sock_recv (struct spdk_sock *_sock, void *buf, size_t len)
{
  spdk_vpp_sock_t *sock = __vpp_sock (_sock);
  spdk_vpp_group_t *group = 0;
  session_t *s;
  u32 max_deq, to_read;
  u8 requeue = 0;
  int rv;

  rv = spdk_vpp_sock_check_affinity (sock);
  if (rv)
    return rv;

  clib_spinlock_lock (&sock->lock);
  if (sock->closed)
    {
      clib_spinlock_unlock (&sock->lock);
      return 0;
    }
  s = sock->handle != SESSION_INVALID_HANDLE ? session_get_from_handle_if_valid (sock->handle) : 0;
  if (!s || !s->rx_fifo)
    {
      clib_spinlock_unlock (&sock->lock);
      return -EAGAIN;
    }
  max_deq = svm_fifo_max_dequeue_cons (s->rx_fifo);
  if (!max_deq)
    {
      rv = sock->closed ? 0 : -EAGAIN;
      clib_spinlock_unlock (&sock->lock);
      return rv;
    }
  to_read = clib_min ((u32) len, max_deq);
  rv = svm_fifo_dequeue (s->rx_fifo, to_read, buf);
  if (rv > 0 && svm_fifo_needs_deq_ntf (s->rx_fifo, rv))
    {
      svm_fifo_clear_deq_ntf (s->rx_fifo);
      session_program_transport_io_evt (s->handle, SESSION_IO_EVT_RX);
    }
  if (rv > 0 && svm_fifo_max_dequeue_cons (s->rx_fifo))
    {
      group = sock->group;
      requeue = 1;
    }
  sock->rx_calls++;
  if (rv > 0)
    sock->rx_bytes += rv;
  clib_spinlock_unlock (&sock->lock);

  if (requeue)
    spdk_vpp_group_enqueue (group, sock);

  return rv;
}

static ssize_t
spdk_vpp_sock_readv (struct spdk_sock *_sock, struct iovec *iov, int iovcnt)
{
  ssize_t total = 0, rv;
  int i;

  for (i = 0; i < iovcnt; i++)
    {
      rv = spdk_vpp_sock_recv (_sock, iov[i].iov_base, iov[i].iov_len);
      if (rv < 0)
	return total ? total : rv;
      total += rv;
      if (rv != (ssize_t) iov[i].iov_len)
	break;
    }

  return total;
}

static ssize_t
spdk_vpp_sock_writev_internal (spdk_vpp_sock_t *sock, struct iovec *iov, int iovcnt)
{
  svm_fifo_seg_t segs[IOV_BATCH_SIZE];
  session_t *s;
  u32 available, n_segs = 0, tail_before;
  int i, rv;

  rv = spdk_vpp_sock_check_affinity (sock);
  if (rv)
    return rv;

  if (sock->closed)
    return -ECONNRESET;
  s = sock->handle != SESSION_INVALID_HANDLE ? session_get_from_handle_if_valid (sock->handle) : 0;
  if (!s || !s->tx_fifo)
    return -ENOTCONN;

  /* Direct C2H reservations already own the bytes starting at the current
   * FIFO tail.  Keep regular socket writes queued until those reservations
   * have been published so they cannot overwrite the reserved regions. */
  if (sock->tx_reserved)
    {
      sock->tx_no_space++;
      return -EAGAIN;
    }
  available = svm_fifo_max_enqueue_prod (s->tx_fifo);
  if (!available)
    {
      sock->tx_no_space++;
      return -EAGAIN;
    }

  iovcnt = clib_min (iovcnt, IOV_BATCH_SIZE);
  for (i = 0; i < iovcnt; i++)
    {
      if (!iov[i].iov_len)
	continue;

      if (PREDICT_FALSE (iov[i].iov_len > UINT32_MAX))
	return -EINVAL;

      segs[n_segs].data = iov[i].iov_base;
      segs[n_segs].len = clib_min ((u32) iov[i].iov_len, available);
      available -= segs[n_segs].len;
      n_segs++;
      if (!available)
	break;
    }

  if (!n_segs)
    return 0;

  /* The batch is already capped to the producer's free space.  Keep the
   * enqueue all-or-none so a failed FIFO growth never falls through to the
   * partial chunk-copy path. */
  tail_before = s->tx_fifo->shr->tail;
  rv = svm_fifo_enqueue_segments (s->tx_fifo, segs, n_segs, 0 /* all or none */);
  if (rv < 0)
    {
      sock->tx_enqueue_fail++;
      return -EAGAIN;
    }

  sock->tx_bytes_enqueued += rv;
  if (s->tx_fifo->shr->tail < tail_before)
    sock->tx_fifo_wraps++;

  if (svm_fifo_set_event (s->tx_fifo))
    {
      session_program_tx_io_evt (s->handle, SESSION_IO_EVT_TX);
      sock->tx_events_programmed++;
    }
  else
    sock->tx_events_coalesced++;

  return rv;
}

static int
spdk_vpp_sock_tx_reserve (struct spdk_sock *_sock, size_t len, struct iovec *iov, int *iovcnt,
			  void **ctx)
{
  spdk_vpp_sock_t *sock = __vpp_sock (_sock);
  spdk_vpp_tx_reservation_t *reservation;
  svm_fifo_seg_t segs[IOV_BATCH_SIZE];
  session_t *s;
  u32 available, mapped = 0;
  int capacity, i, n_segs, rv;

  if (!len || len > UINT32_MAX)
    return -E2BIG;

  rv = spdk_vpp_sock_check_affinity (sock);
  if (rv)
    return rv;

  capacity = clib_min (*iovcnt, IOV_BATCH_SIZE);
  clib_spinlock_lock (&sock->lock);
  if (sock->closed)
    {
      rv = -ECONNRESET;
      goto error;
    }
  if (!TAILQ_EMPTY (&_sock->queued_reqs))
    {
      rv = -EAGAIN;
      goto error;
    }
  if (sock->tx_reserved > UINT32_MAX - (u32) len)
    {
      rv = -E2BIG;
      goto error;
    }

  s = sock->handle != SESSION_INVALID_HANDLE ? session_get_from_handle_if_valid (sock->handle) : 0;
  if (!s || !s->tx_fifo)
    {
      rv = -ENOTCONN;
      goto error;
    }

  available = svm_fifo_max_enqueue_prod (s->tx_fifo);
  if (available < sock->tx_reserved || (u32) len > available - sock->tx_reserved)
    {
      rv = -EAGAIN;
      goto error;
    }

  n_segs =
    svm_fifo_provision_chunks_at_offset (s->tx_fifo, sock->tx_reserved, segs, capacity, (u32) len);
  if (n_segs < 0)
    {
      rv = n_segs == SVM_FIFO_EFULL ? -EAGAIN : -ENOBUFS;
      goto error;
    }

  for (i = 0; i < n_segs; i++)
    mapped += segs[i].len;
  if (mapped != len)
    {
      rv = -ENOBUFS;
      goto error;
    }

  reservation = SLIST_FIRST (&sock->tx_reservation_cache);
  if (reservation)
    {
      SLIST_REMOVE_HEAD (&sock->tx_reservation_cache, cache_link);
      ASSERT (sock->tx_reservation_cache_count > 0);
      sock->tx_reservation_cache_count--;
    }
  else
    reservation = calloc (1, sizeof (*reservation));
  if (!reservation)
    {
      rv = -ENOMEM;
      goto error;
    }

  reservation->sock = sock;
  reservation->len = (u32) len;
  reservation->committed = 0;
  for (i = 0; i < n_segs; i++)
    {
      iov[i].iov_base = segs[i].data;
      iov[i].iov_len = segs[i].len;
    }

  TAILQ_INSERT_TAIL (&sock->tx_reservations, reservation, link);
  sock->tx_reserved += (u32) len;
  if (sock->group)
    {
      sock->group->tx_reservations++;
      sock->group->tx_reservation_bytes += len;
      sock->group->tx_max_reserved = clib_max (sock->group->tx_max_reserved, sock->tx_reserved);
    }
  *iovcnt = n_segs;
  *ctx = reservation;
  clib_spinlock_unlock (&sock->lock);
  return 0;

error:
  clib_spinlock_unlock (&sock->lock);
  return rv;
}

static int
spdk_vpp_sock_tx_commit (struct spdk_sock *_sock, void *ctx)
{
  spdk_vpp_sock_t *sock = __vpp_sock (_sock);
  spdk_vpp_tx_reservation_t *reservation = ctx, *it;
  session_t *s;
  u32 published = 0;
  u8 found = 0;
  int rv;

  rv = spdk_vpp_sock_check_affinity (sock);
  if (rv)
    return rv;

  clib_spinlock_lock (&sock->lock);
  if (sock->closed)
    {
      rv = -ECONNRESET;
      goto out;
    }
  TAILQ_FOREACH (it, &sock->tx_reservations, link)
  if (it == reservation)
    {
      found = 1;
      break;
    }
  if (!found || reservation->sock != sock)
    {
      rv = -EINVAL;
      goto out;
    }

  s = sock->handle != SESSION_INVALID_HANDLE ? session_get_from_handle_if_valid (sock->handle) : 0;
  if (!s || !s->tx_fifo)
    {
      rv = -ENOTCONN;
      goto out;
    }

  if (sock->group && TAILQ_FIRST (&sock->tx_reservations) != reservation)
    sock->group->tx_ooo_commits++;
  reservation->committed = 1;
  if (sock->group)
    sock->group->tx_commits++;

  /* Reservations map FIFO storage at creation time, so only a contiguous
   * committed prefix may become visible to TCP.  This also permits bdev
   * completions to arrive out of order without exposing partially-filled
   * FIFO regions. */
  while ((it = TAILQ_FIRST (&sock->tx_reservations)) != NULL && it->committed)
    {
      u32 reservation_len = it->len;

      ASSERT (sock->tx_reserved >= reservation_len);
      svm_fifo_enqueue_nocopy (s->tx_fifo, reservation_len);
      sock->tx_reserved -= reservation_len;
      published += reservation_len;
      TAILQ_REMOVE (&sock->tx_reservations, it, link);
      spdk_vpp_tx_reservation_release (it, 1);
    }

  if (published)
    {
      if (sock->group)
	sock->group->tx_publish_batches++;
      if (svm_fifo_set_event (s->tx_fifo))
	{
	  session_program_tx_io_evt (s->handle, SESSION_IO_EVT_TX);
	  if (sock->group)
	    sock->group->tx_events++;
	}
    }
  rv = 0;

out:
  clib_spinlock_unlock (&sock->lock);
  return rv;
}

static int
spdk_vpp_sock_tx_abort (struct spdk_sock *_sock, void *ctx)
{
  spdk_vpp_sock_t *sock = __vpp_sock (_sock);
  spdk_vpp_tx_reservation_t *reservation = ctx, *it;
  u8 found = 0;
  int rv;

  rv = spdk_vpp_sock_check_affinity (sock);
  if (rv)
    return rv;

  clib_spinlock_lock (&sock->lock);
  TAILQ_FOREACH (it, &sock->tx_reservations, link)
  if (it == reservation)
    {
      found = 1;
      break;
    }
  if (!found || reservation->sock != sock)
    {
      rv = -EINVAL;
      goto out;
    }

  /* Removing anything but the newest reservation would leave a hole before
   * later FIFO mappings.  Report a hard failure so NVMe/TCP quiesces the
   * qpair instead of publishing corrupt stream data. */
  if (TAILQ_NEXT (reservation, link) != NULL)
    {
      rv = -EBUSY;
      goto out;
    }

  ASSERT (sock->tx_reserved >= reservation->len);
  sock->tx_reserved -= reservation->len;
  TAILQ_REMOVE (&sock->tx_reservations, reservation, link);
  if (sock->group)
    sock->group->tx_aborts++;
  rv = 0;

out:
  clib_spinlock_unlock (&sock->lock);
  if (rv == 0)
    spdk_vpp_tx_reservation_release (reservation, 1);
  return rv;
}

static int
spdk_vpp_sock_flush (struct spdk_sock *_sock)
{
  spdk_vpp_sock_t *sock = __vpp_sock (_sock);
  struct spdk_sock_request *req;
  struct iovec iovs[IOV_BATCH_SIZE];
  uint64_t requested;
  ssize_t rv;
  int iovcnt, rc;

  sock->tx_flush_calls++;
  if (_sock->cb_cnt > 0)
    {
      sock->tx_flush_cb_busy++;
      return -EAGAIN;
    }

  /* Complete one asynchronous request at a time.  A completion callback may
   * queue more work, so retaining a vector assembled from several requests
   * across spdk_sock_request_put() makes its ownership ambiguous. */
  while ((req = TAILQ_FIRST (&_sock->queued_reqs)) != NULL)
    {
      memset (iovs, 0, sizeof (iovs));
      requested = 0;
      iovcnt = spdk_sock_prep_req (req, iovs, 0, &requested);
      if (iovcnt == 0)
	return 0;

      clib_spinlock_lock (&sock->lock);
      rv = spdk_vpp_sock_writev_internal (sock, iovs, iovcnt);
      clib_spinlock_unlock (&sock->lock);
      if (rv < 0)
	return rv;

      req->internal.offset += rv;
      if ((uint64_t) rv < requested)
	{
	  sock->tx_partial_flush++;
	  return -EAGAIN;
	}

      spdk_sock_request_pend (_sock, req);
      rc = spdk_sock_request_put (_sock, req, 0);
      if (rc)
	return 0;
    }

  return 0;
}

static ssize_t
spdk_vpp_sock_writev (struct spdk_sock *_sock, struct iovec *iov, int iovcnt)
{
  spdk_vpp_sock_t *sock = __vpp_sock (_sock);
  ssize_t rv;
  int frc;

  frc = spdk_vpp_sock_flush (_sock);
  if (frc < 0 && frc != -EAGAIN)
    return frc;
  if (!TAILQ_EMPTY (&_sock->queued_reqs))
    return -EAGAIN;

  clib_spinlock_lock (&sock->lock);
  rv = spdk_vpp_sock_writev_internal (sock, iov, iovcnt);
  clib_spinlock_unlock (&sock->lock);
  return rv;
}

static int
spdk_vpp_sock_recv_next (struct spdk_sock *_sock, void **buf, void **ctx)
{
  (void) _sock;
  (void) buf;
  (void) ctx;
  return -ENOTSUP;
}

static void
spdk_vpp_sock_writev_async (struct spdk_sock *sock, struct spdk_sock_request *req)
{
  spdk_vpp_sock_t *vpp_sock = __vpp_sock (sock);

  vpp_sock->tx_async_reqs++;
  spdk_sock_request_queue (sock, req);
  spdk_vpp_group_enqueue_flush (vpp_sock->group, vpp_sock);
  if (sock->queued_iovcnt >= IOV_BATCH_SIZE)
    {
      int rv = spdk_vpp_sock_flush (sock);
      if (rv < 0 && rv != -EAGAIN)
	spdk_sock_abort_requests (sock);
    }
}

static int
spdk_vpp_sock_set_recvlowat (struct spdk_sock *_sock, int nbytes)
{
  (void) _sock;
  (void) nbytes;
  return 0;
}

static int
spdk_vpp_sock_set_recvbuf (struct spdk_sock *_sock, int sz)
{
  (void) _sock;
  (void) sz;
  return 0;
}

static int
spdk_vpp_sock_set_sendbuf (struct spdk_sock *_sock, int sz)
{
  (void) _sock;
  (void) sz;
  return 0;
}

static bool
spdk_vpp_sock_is_ipv6 (struct spdk_sock *_sock)
{
  return __vpp_sock (_sock)->is_ipv6;
}

static bool
spdk_vpp_sock_is_ipv4 (struct spdk_sock *_sock)
{
  return !__vpp_sock (_sock)->is_ipv6;
}

static bool
spdk_vpp_sock_is_connected (struct spdk_sock *_sock)
{
  spdk_vpp_sock_t *sock = __vpp_sock (_sock);
  return sock->connected && !sock->closed;
}

static struct spdk_sock_group_impl *
spdk_vpp_sock_group_impl_get_optimal (struct spdk_sock *_sock, struct spdk_sock_group_impl *hint)
{
  spdk_vpp_main_t *vm = &spdk_vpp_main;
  spdk_vpp_sock_t *sock = __vpp_sock (_sock);
  spdk_vpp_group_t *group, *candidate = 0;
  u32 owner_thread;

  if (spdk_vpp_sock_owner_thread (sock, &owner_thread))
    return 0;

  if (hint)
    {
      group = __vpp_group (hint);
      if (group->vpp_thread_index == owner_thread)
	{
	  clib_spinlock_lock (&vm->lock);
	  vm->placement_hits++;
	  clib_spinlock_unlock (&vm->lock);
	  return hint;
	}
    }

  clib_spinlock_lock (&vm->lock);
  TAILQ_FOREACH (group, &vm->groups, link)
  {
    if (group->vpp_thread_index != owner_thread || !group->base.group || !group->base.group->ctx)
      continue;

    if (candidate)
      {
	candidate = 0;
	break;
      }
    candidate = group;
  }

  if (candidate)
    vm->placement_hits++;
  else
    vm->placement_misses++;
  clib_spinlock_unlock (&vm->lock);

  return candidate ? &candidate->base : 0;
}

static struct spdk_sock_group_impl *
spdk_vpp_sock_group_impl_create (void)
{
  spdk_vpp_main_t *vm = &spdk_vpp_main;
  spdk_vpp_group_t *group;
  struct spdk_thread *thread;
  u32 lcore, vpp_thread_index;

  if (spdk_vpp_attach ())
    return 0;

  lcore = spdk_env_get_current_core ();
  if (lcore == SPDK_ENV_LCORE_ID_ANY ||
      spdk_plugin_vpp_thread_for_lcore (lcore, &vpp_thread_index) ||
      vpp_thread_index != vlib_get_thread_index ())
    {
      SPDK_ERRLOG ("VPP socket group created outside its mapped VPP worker\n");
      return 0;
    }

  group = calloc (1, sizeof (*group));
  if (!group)
    return 0;

  TAILQ_INIT (&group->events);
  TAILQ_INIT (&group->flush_socks);
  clib_spinlock_init (&group->lock);
  group->lcore = lcore;
  group->vpp_thread_index = vpp_thread_index;

  thread = spdk_get_thread ();
  if (thread)
    spdk_thread_bind (thread, true);

  clib_spinlock_lock (&vm->lock);
  TAILQ_INSERT_TAIL (&vm->groups, group, link);
  clib_spinlock_unlock (&vm->lock);
  return &group->base;
}

static int
spdk_vpp_sock_group_impl_add_sock (struct spdk_sock_group_impl *_group, struct spdk_sock *_sock)
{
  spdk_vpp_group_t *group = __vpp_group (_group);
  spdk_vpp_sock_t *sock = __vpp_sock (_sock);
  session_t *s;
  u32 owner_thread;

  if (!spdk_vpp_sock_owner_thread (sock, &owner_thread) && owner_thread != group->vpp_thread_index)
    {
      spdk_vpp_main_t *vm = &spdk_vpp_main;

      clib_spinlock_lock (&vm->lock);
      vm->affinity_errors++;
      clib_spinlock_unlock (&vm->lock);
      SPDK_ERRLOG ("refusing socket owned by VPP thread %u on group for thread %u\n", owner_thread,
		   group->vpp_thread_index);
      return -EXDEV;
    }

  if (sock->is_listener)
    {
      clib_spinlock_lock (&group->lock);
      group->listener_count++;
      clib_spinlock_unlock (&group->lock);
    }

  clib_spinlock_lock (&sock->lock);
  sock->group = group;
  s = sock->handle != SESSION_INVALID_HANDLE ? session_get_from_handle_if_valid (sock->handle) : 0;
  if ((sock->is_listener && !TAILQ_EMPTY (&sock->acceptq)) ||
      (!sock->is_listener && s && svm_fifo_max_dequeue_cons (s->rx_fifo)))
    spdk_vpp_group_enqueue (group, sock);
  if (!TAILQ_EMPTY (&sock->base.queued_reqs))
    spdk_vpp_group_enqueue_flush (group, sock);
  clib_spinlock_unlock (&sock->lock);

  return 0;
}

static int
spdk_vpp_sock_group_impl_remove_sock (struct spdk_sock_group_impl *_group, struct spdk_sock *_sock)
{
  spdk_vpp_group_t *group = __vpp_group (_group);
  spdk_vpp_sock_t *sock = __vpp_sock (_sock);
  spdk_vpp_sock_t *it, *next;

  if (sock->is_listener)
    clib_spinlock_lock (&sock->lock);
  clib_spinlock_lock (&group->lock);
  if (sock->flush_queued)
    {
      TAILQ_REMOVE (&group->flush_socks, sock, flush_link);
      sock->flush_queued = 0;
      ASSERT (group->flush_count > 0);
      group->flush_count--;
    }
  for (it = TAILQ_FIRST (&group->events); it; it = next)
    {
      next = TAILQ_NEXT (it, event_link);
      if (it == sock)
	{
	  TAILQ_REMOVE (&group->events, sock, event_link);
	  sock->event_queued = 0;
	  break;
	}
    }
  if (sock->is_listener)
    {
      ASSERT (group->listener_count > 0);
      group->listener_count--;
      sock->group = 0;
    }
  clib_spinlock_unlock (&group->lock);

  if (sock->is_listener)
    clib_spinlock_unlock (&sock->lock);
  else
    {
      clib_spinlock_lock (&sock->lock);
      sock->group = 0;
      clib_spinlock_unlock (&sock->lock);
    }
  spdk_sock_abort_requests (_sock);
  return 0;
}

static int
spdk_vpp_sock_group_impl_poll (struct spdk_sock_group_impl *_group, int max_events,
			       struct spdk_sock **socks)
{
  spdk_vpp_group_t *group = __vpp_group (_group);
  spdk_vpp_sock_t *sock;
  struct spdk_sock *base_sock, *next_base_sock;
  session_t *session;
  u32 flush_budget;
  u8 rx_ready;
  int count = 0, rv;

  group->polls++;

  /* Process only sockets with queued TX work on the hot path.  Bound the
   * pass to the number that was pending at entry so a socket blocked on FIFO
   * space is retried by the next poll instead of spinning in this one. */
  flush_budget = group->flush_count;
  while (flush_budget--)
    {
      sock = TAILQ_FIRST (&group->flush_socks);
      if (!sock)
	break;
      TAILQ_REMOVE (&group->flush_socks, sock, flush_link);
      sock->flush_queued = 0;
      ASSERT (group->flush_count > 0);
      group->flush_count--;

      rv = spdk_vpp_sock_flush (&sock->base);
      if (rv < 0 && rv != -EAGAIN)
	spdk_sock_abort_requests (&sock->base);
      else if (!TAILQ_EMPTY (&sock->base.queued_reqs))
	spdk_vpp_group_enqueue_flush (group, sock);
    }

  /* Callbacks and the active queues cover normal RX and TX readiness.  Keep
   * an infrequent full scan as a correctness backstop for a missed callback
   * or recursively queued request, without paying O(number of sockets) on
   * every reactor poll. */
  if ((group->polls & (SPDK_VPP_GROUP_SWEEP_INTERVAL - 1)) == 0)
    {
      group->full_sweeps++;
      base_sock = TAILQ_FIRST (&group->base.socks);
      while (base_sock)
	{
	  next_base_sock = TAILQ_NEXT (base_sock, link);
	  sock = __vpp_sock (base_sock);

	  clib_spinlock_lock (&sock->lock);
	  session = sock->handle != SESSION_INVALID_HANDLE ?
		      session_get_from_handle_if_valid (sock->handle) :
		      0;
	  rx_ready = (sock->is_listener && !TAILQ_EMPTY (&sock->acceptq)) ||
		     (!sock->is_listener && session && session->rx_fifo &&
		      svm_fifo_max_dequeue_cons (session->rx_fifo));
	  clib_spinlock_unlock (&sock->lock);
	  if (rx_ready)
	    {
	      group->rx_sweep_ready++;
	      spdk_vpp_group_enqueue (group, sock);
	    }

	  if (!TAILQ_EMPTY (&base_sock->queued_reqs))
	    {
	      group->tx_sweep_queued++;
	      spdk_vpp_group_enqueue_flush (group, sock);
	    }
	  base_sock = next_base_sock;
	}
    }

  if (PREDICT_FALSE (group->listener_count))
    clib_spinlock_lock (&group->lock);
  while (count < max_events &&
	 (sock = TAILQ_FIRST (&group->events)) != NULL)
    {
      TAILQ_REMOVE (&group->events, sock, event_link);
      sock->event_queued = 0;
      socks[count++] = &sock->base;
    }
  if (PREDICT_FALSE (group->listener_count))
    clib_spinlock_unlock (&group->lock);

  return count;
}

static int
spdk_vpp_sock_group_impl_get_interruptfd (struct spdk_sock_group_impl *_group)
{
  (void) _group;
  return -1;
}

static int
spdk_vpp_sock_group_impl_close (struct spdk_sock_group_impl *_group)
{
  spdk_vpp_main_t *vm = &spdk_vpp_main;
  spdk_vpp_group_t *group = __vpp_group (_group);

  clib_spinlock_lock (&vm->lock);
  TAILQ_REMOVE (&vm->groups, group, link);
  clib_spinlock_unlock (&vm->lock);
  clib_spinlock_free (&group->lock);
  free (group);
  return 0;
}

u8 *
format_spdk_vpp_state (u8 *s)
{
  spdk_vpp_main_t *vm = &spdk_vpp_main;
  spdk_vpp_group_t *group;
  u64 tx_reservations = 0, tx_reservation_bytes = 0, tx_commits = 0, tx_aborts = 0;
  u64 tx_ooo_commits = 0, tx_publish_batches = 0, tx_events = 0, tx_max_reserved = 0;

  spdk_vpp_main_init ();
  clib_spinlock_lock (&vm->lock);
  s = format (s, "socket backend: vpp hoststack\n");
  s = format (s, "placements: hits %llu misses %llu affinity-errors %llu\n", vm->placement_hits,
	      vm->placement_misses, vm->affinity_errors);
  TAILQ_FOREACH (group, &vm->groups, link)
  {
    tx_reservations += group->tx_reservations;
    tx_reservation_bytes += group->tx_reservation_bytes;
    tx_commits += group->tx_commits;
    tx_aborts += group->tx_aborts;
    tx_ooo_commits += group->tx_ooo_commits;
    tx_publish_batches += group->tx_publish_batches;
    tx_events += group->tx_events;
    tx_max_reserved = clib_max (tx_max_reserved, group->tx_max_reserved);
  }
  s = format (s, "direct-tx: reservations %llu bytes %llu commits %llu aborts %llu\n",
	      tx_reservations, tx_reservation_bytes, tx_commits, tx_aborts);
  s = format (s,
	      "direct-tx completion: non-creation-order %llu commit-batches %llu "
	      "events %llu max-reserved %llu\n",
	      tx_ooo_commits, tx_publish_batches, tx_events, tx_max_reserved);
  s = format (s, "socket groups:");
  TAILQ_FOREACH (group, &vm->groups, link)
  s = format (s, " vpp%u=lcore%u", group->vpp_thread_index, group->lcore);
  s = format (s, "%s\n", TAILQ_EMPTY (&vm->groups) ? " -" : "");
  TAILQ_FOREACH (group, &vm->groups, link)
  {
    struct spdk_sock *base_sock;
    spdk_vpp_sock_t *sock;
    session_t *session;
    u64 tx_async_reqs = 0, tx_flush_calls = 0, tx_flush_cb_busy = 0;
    u64 tx_no_space = 0, tx_enqueue_fail = 0, tx_partial_flush = 0;
    u64 tx_bytes_enqueued = 0, tx_fifo_wraps = 0;
    u64 tx_events_programmed = 0, tx_events_coalesced = 0;
    u64 rx_calls = 0, rx_bytes = 0;
    u32 n_socks = 0, queued_socks = 0, queued_iovs = 0;
    u32 cb_busy_socks = 0, rx_ready_socks = 0;

    TAILQ_FOREACH (base_sock, &group->base.socks, link)
    {
      sock = __vpp_sock (base_sock);
      n_socks++;
      tx_async_reqs += sock->tx_async_reqs;
      tx_flush_calls += sock->tx_flush_calls;
      tx_flush_cb_busy += sock->tx_flush_cb_busy;
      tx_no_space += sock->tx_no_space;
      tx_enqueue_fail += sock->tx_enqueue_fail;
      tx_partial_flush += sock->tx_partial_flush;
      tx_bytes_enqueued += sock->tx_bytes_enqueued;
      tx_fifo_wraps += sock->tx_fifo_wraps;
      tx_events_programmed += sock->tx_events_programmed;
      tx_events_coalesced += sock->tx_events_coalesced;
      rx_calls += sock->rx_calls;
      rx_bytes += sock->rx_bytes;
      if (!TAILQ_EMPTY (&base_sock->queued_reqs))
	{
	  queued_socks++;
	  queued_iovs += base_sock->queued_iovcnt;
	}
      if (base_sock->cb_cnt)
	cb_busy_socks++;
      session = sock->handle != SESSION_INVALID_HANDLE ?
		  session_get_from_handle_if_valid (sock->handle) :
		  0;
      if (session && session->rx_fifo && svm_fifo_max_dequeue_cons (session->rx_fifo))
	rx_ready_socks++;
    }
    s = format (s,
		"  vpp%u/lcore%u sockets %u flush-pending %u polls %llu "
		"full-sweeps %llu rx-ready %llu tx-queued %llu\n",
		group->vpp_thread_index, group->lcore, n_socks, group->flush_count, group->polls,
		group->full_sweeps, group->rx_sweep_ready, group->tx_sweep_queued);
    s = format (s,
		"    live queued-socks %u queued-iovs %u cb-busy %u "
		"rx-ready %u\n",
		queued_socks, queued_iovs, cb_busy_socks, rx_ready_socks);
    s = format (s,
		"    tx async-reqs %llu flush-calls %llu cb-eagain %llu "
		"no-space %llu enqueue-fail %llu partial %llu\n",
		tx_async_reqs, tx_flush_calls, tx_flush_cb_busy, tx_no_space, tx_enqueue_fail,
		tx_partial_flush);
    s = format (s,
		"    tx bytes %llu fifo-wraps %llu events programmed %llu "
		"coalesced %llu; rx calls %llu bytes %llu\n",
		tx_bytes_enqueued, tx_fifo_wraps, tx_events_programmed, tx_events_coalesced,
		rx_calls, rx_bytes);
  }
  clib_spinlock_unlock (&vm->lock);
  return s;
}

static int
spdk_vpp_sock_impl_get_opts (struct spdk_sock_impl_opts *opts, size_t *len)
{
  if (!opts || !len)
    return -EINVAL;

  memset (opts, 0, *len);
  memcpy (opts, &g_vpp_impl_opts, spdk_min (*len, sizeof (g_vpp_impl_opts)));
  *len = spdk_min (*len, sizeof (g_vpp_impl_opts));
  return 0;
}

static int
spdk_vpp_sock_impl_set_opts (const struct spdk_sock_impl_opts *opts, size_t len)
{
  if (!opts)
    return -EINVAL;

  memcpy (&g_vpp_impl_opts, opts, spdk_min (len, sizeof (g_vpp_impl_opts)));
  return 0;
}

#define SPDK_VPP_NET_IMPL_COMMON                                                                   \
  .init = spdk_vpp_net_impl_init, .getaddr = spdk_vpp_sock_getaddr,                                \
  .get_interface_name = spdk_vpp_sock_get_interface_name,                                          \
  .get_numa_id = spdk_vpp_sock_get_numa_id, .connect = spdk_vpp_sock_connect,                      \
  .connect_async = spdk_vpp_sock_connect_async, .listen = spdk_vpp_sock_listen,                    \
  .accept = spdk_vpp_sock_accept, .close = spdk_vpp_sock_close, .recv = spdk_vpp_sock_recv,        \
  .readv = spdk_vpp_sock_readv, .writev = spdk_vpp_sock_writev,                                    \
  .recv_next = spdk_vpp_sock_recv_next, .writev_async = spdk_vpp_sock_writev_async,                \
  .readv_async = NULL, .flush = spdk_vpp_sock_flush, .set_recvlowat = spdk_vpp_sock_set_recvlowat, \
  .set_recvbuf = spdk_vpp_sock_set_recvbuf, .set_sendbuf = spdk_vpp_sock_set_sendbuf,              \
  .is_ipv6 = spdk_vpp_sock_is_ipv6, .is_ipv4 = spdk_vpp_sock_is_ipv4,                              \
  .is_connected = spdk_vpp_sock_is_connected,                                                      \
  .group_impl_get_optimal = spdk_vpp_sock_group_impl_get_optimal,                                  \
  .group_impl_create = spdk_vpp_sock_group_impl_create,                                            \
  .group_impl_add_sock = spdk_vpp_sock_group_impl_add_sock,                                        \
  .group_impl_remove_sock = spdk_vpp_sock_group_impl_remove_sock,                                  \
  .group_impl_poll = spdk_vpp_sock_group_impl_poll,                                                \
  .group_impl_get_interruptfd = spdk_vpp_sock_group_impl_get_interruptfd,                          \
  .group_impl_close = spdk_vpp_sock_group_impl_close, .get_opts = spdk_vpp_sock_impl_get_opts,     \
  .set_opts = spdk_vpp_sock_impl_set_opts, .tx_reserve = spdk_vpp_sock_tx_reserve,                 \
  .tx_commit = spdk_vpp_sock_tx_commit, .tx_abort = spdk_vpp_sock_tx_abort

static struct spdk_net_impl g_vpp_net_impl = {
  .name = "vpp",
  SPDK_VPP_NET_IMPL_COMMON,
};

SPDK_NET_IMPL_REGISTER (vpp, &g_vpp_net_impl);
