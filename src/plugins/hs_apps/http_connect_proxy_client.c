/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2025 Cisco Systems, Inc.
 */

#include <vnet/session/application_interface.h>
#include <vnet/session/application.h>
#include <vnet/session/session.h>
#include <http/http.h>
#include <http/http_status_codes.h>
#include <vnet/tcp/tcp.h>
#include <vppinfra/tw_timer_2t_1w_2048sl.h>

#define HCPC_DEBUG 0

#if HCPC_DEBUG
#define HCPC_DBG(_fmt, _args...) clib_warning (_fmt, ##_args)
#else
#define HCPC_DBG(_fmt, _args...)
#endif

#define TCP_MSS 1460

#define HCPC_TIMER_HANDLE_INVALID ((u32) ~0)

#define foreach_hcpc_event                                                    \
  _ (PROXY_CONNECTED, "proxy-connected")                                      \
  _ (PROXY_CONNECT_REFUSED, "proxy-connect-refused")                          \
  _ (PROXY_DISCONNECTED, "proxy-disconnected")

typedef enum
{
#define _(sym, str) HCPC_EVENT_##sym,
  foreach_hcpc_event
#undef _
} hcpc_event_t;

#define foreach_hcpc_session_state                                            \
  _ (CREATED, "CREATED")                                                      \
  _ (CONNECTING, "CONNECTING")                                                \
  _ (ESTABLISHED, "ESTABLISHED")                                              \
  _ (CLOSING, "CLOSING")                                                      \
  _ (CLOSED, "CLOSED")

typedef enum
{
#define _(sym, str) HCPC_SESSION_##sym,
  foreach_hcpc_session_state
#undef _
} hcpc_session_state_t;

#define foreach_hcpc_session_flags                                            \
  _ (IS_PARENT, "is-parent")                                                  \
  _ (IS_UDP, "is-udp")                                                        \
  _ (HTTP_SHUTDOWN, "http-shutdown")                                          \
  _ (INTERCEPT_SHUTDOWN, "intercept-shutdown")

typedef enum
{
#define _(sym, str) HCPC_SESSION_F_BIT_##sym,
  foreach_hcpc_session_flags
#undef _
    HCPC_SESSION_N_F_BITS
} hcpc_session_flags_bit_t;

typedef enum
{
#define _(sym, str) HCPC_SESSION_F_##sym = 1 << HCPC_SESSION_F_BIT_##sym,
  foreach_hcpc_session_flags
#undef _
} hcpc_session_flags_t;

typedef struct
{
  session_handle_t session_handle;
  svm_fifo_t *rx_fifo;
  svm_fifo_t *tx_fifo;
} hcpc_session_side_t;

typedef struct
{
  u32 session_index;
  hcpc_session_state_t state;
  u8 flags;
  hcpc_session_side_t intercept;
  hcpc_session_side_t http;
  u32 timer_handle;
  u32 opaque;
  volatile int http_establishing;
  volatile int intercept_diconnected;
  volatile int http_disconnected;
} hcpc_session_t;

typedef struct
{
  session_endpoint_cfg_t sep;
  u32 l_index;
  session_handle_t session_handle;
} hcpc_listener_t;

#define foreach_hcpc_wrk_stat                                                 \
  _ (tunnels_opened, "tunnels opened")                                        \
  _ (udp_idle_timeouts, "udp idle timeouts")                                  \
  _ (tunnels_reset_by_client, "tunnels reset by client")                      \
  _ (tunnels_reset_by_target, "tunnels reset by target")                      \
  _ (max_streams_hit, "max streams hit")                                      \
  _ (target_unreachable, "target unreachable")                                \
  _ (client_closed_before_stream_opened, "client closed before stream "       \
					 "opened")                            \
  _ (client_closed_before_tunnel_connected,                                   \
     "client closed before tunnel connected")

typedef struct
{
#define _(name, str) u64 name;
  foreach_hcpc_wrk_stat
#undef _
} hcpc_wrk_stats_t;

typedef struct
{
  hcpc_wrk_stats_t stats;
} hcpc_worker_t;

typedef void (*hsi_intercept_proto_fn) (transport_proto_t proto, u8 is_ip4);

typedef enum
{
  HCPC_HTTP_STATE_DISCONNECTED,
  HCPC_HTTP_STATE_CONNECTING,
  HCPC_HTTP_STATE_CONNECTED,
} hcpc_http_session_state_t;

typedef struct
{
  u32 http_app_index;
  u32 listener_app_index;
  u32 ckpair_index;
  session_endpoint_cfg_t proxy_server_sep;
  http_headers_ctx_t capsule_proto_header;
  u8 *capsule_proto_header_buf;
  hcpc_listener_t *listeners;
  hcpc_session_t *sessions;
  session_handle_t http_connection_handle;
  u8 is_init;
  hcpc_http_session_state_t http_state;
  u8 hsi4_enabled;
  u8 hsi6_enabled;
  u32 sw_if_index;
  u32 fifo_size;
  u32 prealloc_fifos;
  u64 private_segment_size;
  u32 process_node_index;
  u32 udp_idle_timeout;
  clib_spinlock_t sessions_lock;
  clib_spinlock_t tw_lock;
  tw_timer_wheel_2t_1w_2048sl_t tw;
  hsi_intercept_proto_fn intercept_proto_fn;
  hcpc_worker_t *workers;
} hcpc_main_t;

hcpc_main_t hcpc_main;

#define hcpc_worker_stats_inc(_ti, _stat, _val)                               \
  hcpcm->workers[_ti].stats._stat += _val

static u8 *
format_hcpc_session_state (u8 *s, va_list *va)
{
  hcpc_session_state_t state = va_arg (*va, hcpc_session_state_t);
  u8 *t = 0;

  switch (state)
    {
#define _(sym, str)                                                           \
  case HCPC_SESSION_##sym:                                                    \
    t = (u8 *) str;                                                           \
    break;
      foreach_hcpc_session_state
#undef _
	default : return format (s, "unknown");
    }
  return format (s, "%s", t);
}

const char *hcpc_session_flags_str[] = {
#define _(sym, str) str,
  foreach_hcpc_session_flags
#undef _

};

static u8 *
format_hcpc_session_flags (u8 *s, va_list *va)
{
  hcpc_session_t *ps = va_arg (*va, hcpc_session_t *);
  int i, last = -1;

  for (i = 0; i < HCPC_SESSION_N_F_BITS; i++)
    {
      if (ps->flags & (1 << i))
	last = i;
    }

  for (i = 0; i < last; i++)
    {
      if (ps->flags & (1 << i))
	s = format (s, "%s | ", hcpc_session_flags_str[i]);
    }
  if (last >= 0)
    s = format (s, "%s", hcpc_session_flags_str[i]);

  return s;
}

static u8 *
format_hcpc_session_vars (u8 *s, va_list *va)
{
  hcpc_session_t *ps = va_arg (*va, hcpc_session_t *);

  s = format (s,
	      " http_establishing %u, http_stream_opened %u, "
	      "http_disconnected %u, intercept_disconnected %u\n",
	      ps->http_establishing,
	      ps->http.session_handle != SESSION_INVALID_HANDLE,
	      ps->http_disconnected, ps->intercept_diconnected);
  s = format (s, " flags: %U\n", format_hcpc_session_flags, ps);

  return s;
}

static void
hcpc_session_close_http (hcpc_session_t *ps)
{
  hcpc_main_t *hcpcm = &hcpc_main;
  vnet_disconnect_args_t _a = { 0 }, *a = &_a;
  session_error_t rv;

  HCPC_DBG ("session [%u]", ps->session_index);
  ASSERT (!vlib_num_workers () ||
	  CLIB_SPINLOCK_IS_LOCKED (&hcpcm->sessions_lock));

  a->handle = ps->http.session_handle;
  a->app_index = hcpcm->http_app_index;
  rv = vnet_disconnect_session (a);
  if (rv)
    clib_warning ("session %u disconnect returned: %U", ps->session_index,
		  format_session_error, rv);
  ps->http_disconnected = 1;
}

static void
hcpc_session_shutdown_http (hcpc_session_t *ps)
{
  hcpc_main_t *hcpcm = &hcpc_main;
  vnet_shutdown_args_t _a = { 0 }, *a = &_a;
  session_error_t rv;

  HCPC_DBG ("session [%u]", ps->session_index);
  ASSERT (!vlib_num_workers () ||
	  CLIB_SPINLOCK_IS_LOCKED (&hcpcm->sessions_lock));

  ps->flags |= HCPC_SESSION_F_HTTP_SHUTDOWN;
  a->handle = ps->http.session_handle;
  a->app_index = hcpcm->http_app_index;
  rv = vnet_shutdown_session (a);
  if (rv)
    clib_warning ("session %u shutdown returned: %U", ps->session_index,
		  format_session_error, rv);
}

static void
hcpc_session_close_intercept (hcpc_session_t *ps)
{
  hcpc_main_t *hcpcm = &hcpc_main;
  vnet_disconnect_args_t _a = { 0 }, *a = &_a;
  session_error_t rv;

  HCPC_DBG ("session [%u]", ps->session_index);
  ASSERT (!vlib_num_workers () ||
	  CLIB_SPINLOCK_IS_LOCKED (&hcpcm->sessions_lock));

  a->handle = ps->intercept.session_handle;
  a->app_index = hcpcm->listener_app_index;
  rv = vnet_disconnect_session (a);
  if (rv)
    clib_warning ("session %u disconnect returned: %U", ps->session_index,
		  format_session_error, rv);
  ps->intercept_diconnected = 1;
}

static void
hcpc_session_shutdown_intercept (hcpc_session_t *ps)
{
  hcpc_main_t *hcpcm = &hcpc_main;
  vnet_shutdown_args_t _a = { 0 }, *a = &_a;
  session_error_t rv;

  HCPC_DBG ("session [%u]", ps->session_index);
  ASSERT (!vlib_num_workers () ||
	  CLIB_SPINLOCK_IS_LOCKED (&hcpcm->sessions_lock));

  ps->flags |= HCPC_SESSION_F_INTERCEPT_SHUTDOWN;
  a->handle = ps->intercept.session_handle;
  a->app_index = hcpcm->listener_app_index;
  rv = vnet_shutdown_session (a);
  if (rv)
    clib_warning ("session %u shutdown returned: %U", ps->session_index,
		  format_session_error, rv);
}

static hcpc_session_t *
hcpc_session_alloc ()
{
  hcpc_main_t *hcpcm = &hcpc_main;
  hcpc_session_t *ps;

  ASSERT (!vlib_num_workers () ||
	  CLIB_SPINLOCK_IS_LOCKED (&hcpcm->sessions_lock));

  pool_get_zero (hcpcm->sessions, ps);
  ps->session_index = ps - hcpcm->sessions;
  ps->http.session_handle = SESSION_INVALID_HANDLE;
  ps->intercept.session_handle = SESSION_INVALID_HANDLE;
  ps->timer_handle = HCPC_TIMER_HANDLE_INVALID;

  return ps;
}

static void
hcpc_session_free (hcpc_session_t *ps)
{
  hcpc_main_t *hcpcm = &hcpc_main;

  HCPC_DBG ("session [%u]", ps->session_index);
  ASSERT (!vlib_num_workers () ||
	  CLIB_SPINLOCK_IS_LOCKED (&hcpcm->sessions_lock));

  if (CLIB_DEBUG)
    memset (ps, 0xB0, sizeof (*ps));
  pool_put (hcpcm->sessions, ps);
}

static hcpc_session_t *
hcpc_session_get (u32 s_index)
{
  hcpc_main_t *hcpcm = &hcpc_main;

  if (pool_is_free_index (hcpcm->sessions, s_index))
    return 0;
  return pool_elt_at_index (hcpcm->sessions, s_index);
}

static void
hcpc_timer_expired_cb (u32 *expired_timers)
{
  hcpc_main_t *hcpcm = &hcpc_main;
  int i;
  u32 ps_index;
  hcpc_session_t *ps;

  clib_spinlock_lock_if_init (&hcpcm->sessions_lock);
  for (i = 0; i < vec_len (expired_timers); i++)
    {
      ps_index = expired_timers[i] & 0x7FFFFFFF;
      ps = hcpc_session_get (ps_index);
      if (!ps)
	continue;
      HCPC_DBG ("session [%u]", ps_index);
      ASSERT (ps->flags & HCPC_SESSION_F_IS_UDP);
      ASSERT (ps->http_establishing == 0);
      ps->state = HCPC_SESSION_CLOSED;
      ps->timer_handle = HCPC_TIMER_HANDLE_INVALID;
      if (!ps->intercept_diconnected)
	hcpc_session_close_intercept (ps);
      if (!ps->http_disconnected)
	hcpc_session_close_http (ps);
    }
  clib_spinlock_unlock_if_init (&hcpc_main.sessions_lock);
  hcpc_worker_stats_inc (vlib_get_thread_index (), udp_idle_timeouts,
			 vec_len (expired_timers));
}

static inline void
hcpc_timer_start (hcpc_session_t *ps)
{
  hcpc_main_t *hcpcm = &hcpc_main;

  ASSERT (ps->timer_handle == HCPC_TIMER_HANDLE_INVALID);
  ASSERT (ps->flags & HCPC_SESSION_F_IS_UDP);
  ASSERT (!vlib_num_workers () ||
	  CLIB_SPINLOCK_IS_LOCKED (&hcpcm->sessions_lock));

  clib_spinlock_lock_if_init (&hcpcm->tw_lock);
  ps->timer_handle = tw_timer_start_2t_1w_2048sl (
    &hcpcm->tw, ps->session_index, 0, hcpcm->udp_idle_timeout);
  clib_spinlock_unlock_if_init (&hcpcm->tw_lock);
}

static inline void
hcpc_timer_stop (hcpc_session_t *ps)
{
  hcpc_main_t *hcpcm = &hcpc_main;

  ASSERT (!vlib_num_workers () ||
	  CLIB_SPINLOCK_IS_LOCKED (&hcpcm->sessions_lock));

  if (ps->timer_handle == HCPC_TIMER_HANDLE_INVALID)
    return;

  ASSERT (ps->flags & HCPC_SESSION_F_IS_UDP);

  clib_spinlock_lock_if_init (&hcpcm->tw_lock);
  tw_timer_stop_2t_1w_2048sl (&hcpcm->tw, ps->timer_handle);
  ps->timer_handle = HCPC_TIMER_HANDLE_INVALID;
  clib_spinlock_unlock_if_init (&hcpcm->tw_lock);
}

static inline void
hcpc_timer_update (hcpc_session_t *ps)
{
  hcpc_main_t *hcpcm = &hcpc_main;

  ASSERT (!vlib_num_workers () ||
	  CLIB_SPINLOCK_IS_LOCKED (&hcpcm->sessions_lock));

  if (ps->timer_handle == HCPC_TIMER_HANDLE_INVALID)
    return;

  ASSERT (ps->flags & HCPC_SESSION_F_IS_UDP);

  clib_spinlock_lock_if_init (&hcpcm->tw_lock);
  tw_timer_update_2t_1w_2048sl (&hcpcm->tw, ps->timer_handle,
				hcpcm->udp_idle_timeout);
  clib_spinlock_unlock_if_init (&hcpcm->tw_lock);
}

static void
hcpc_session_postponed_free_rpc (void *arg)
{
  uword session_index = pointer_to_uword (arg);
  hcpc_main_t *hcpcm = &hcpc_main;
  hcpc_session_t *ps;

  clib_spinlock_lock_if_init (&hcpcm->sessions_lock);

  HCPC_DBG ("session [%u]", session_index);
  ps = hcpc_session_get (session_index);
  ASSERT (ps);
  segment_manager_dealloc_fifos (ps->intercept.rx_fifo, ps->intercept.tx_fifo);
  hcpc_session_free (ps);

  clib_spinlock_unlock_if_init (&hcpc_main.sessions_lock);
}

static void
hcpc_delete_session (session_t *s, u8 is_http)
{
  hcpc_main_t *hcpcm = &hcpc_main;
  hcpc_session_t *ps;

  clib_spinlock_lock_if_init (&hcpcm->sessions_lock);

  HCPC_DBG ("session [%u] (is http %u)", s->opaque, is_http);
  ps = hcpc_session_get (s->opaque);
  ASSERT (ps);

  hcpc_timer_stop (ps);

  if (is_http)
    {
      ps->http.session_handle = SESSION_INVALID_HANDLE;
      /* http connection session doesn't have listener */
      if (ps->flags & HCPC_SESSION_F_IS_PARENT)
	{
	  ASSERT (ps->intercept.session_handle == SESSION_INVALID_HANDLE);
	  hcpc_session_free (ps);
	  clib_spinlock_unlock_if_init (&hcpc_main.sessions_lock);
	  return;
	}

      /* revert master thread index change on connect notification */
      ps->intercept.rx_fifo->master_thread_index =
	ps->intercept.tx_fifo->master_thread_index;

      /* listener already cleaned up */
      if (ps->intercept.session_handle == SESSION_INVALID_HANDLE)
	{
	  if (s->thread_index != ps->intercept.tx_fifo->master_thread_index)
	    {
	      s->rx_fifo = 0;
	      s->tx_fifo = 0;
	      session_send_rpc_evt_to_thread (
		ps->intercept.tx_fifo->master_thread_index,
		hcpc_session_postponed_free_rpc,
		uword_to_pointer (ps->session_index, void *));
	    }
	  else
	    {
	      ASSERT (s->rx_fifo->refcnt == 1);
	      hcpc_session_free (ps);
	    }
	}
    }
  else
    {
      ps->intercept.session_handle = SESSION_INVALID_HANDLE;
      /* http already cleaned up */
      if (ps->http.session_handle == SESSION_INVALID_HANDLE)
	{
	  if (!ps->http_establishing)
	    hcpc_session_free (ps);
	}
    }

  clib_spinlock_unlock_if_init (&hcpc_main.sessions_lock);
}

static void
hcpc_http_stop_listeners ()
{
  hcpc_main_t *hcpcm = &hcpc_main;
  hcpc_listener_t *l;

  pool_foreach (l, hcpcm->listeners)
    {
      if (l->session_handle != SESSION_INVALID_HANDLE)
	{
	  vnet_unlisten_args_t a = { .handle = l->session_handle,
				     .app_index = hcpcm->listener_app_index };
	  vnet_unlisten (&a);
	}
    }
}

static void
hcpc_http_connection_closed (hcpc_session_t *parent_ps)
{
  hcpc_main_t *hcpcm = &hcpc_main;
  hcpc_session_t *ps;

  hcpc_session_close_http (parent_ps);
  parent_ps->state = HCPC_SESSION_CLOSED;
  hcpcm->http_connection_handle = SESSION_INVALID_HANDLE;
  hcpcm->http_state = HCPC_HTTP_STATE_DISCONNECTED;

  pool_foreach (ps, hcpcm->sessions)
    {
      ps->state = HCPC_SESSION_CLOSED;
      ps->intercept_diconnected = 1;
      ps->http_disconnected = 1;
    }

  vlib_process_signal_event_mt (vlib_get_main (), hcpcm->process_node_index,
				HCPC_EVENT_PROXY_DISCONNECTED, 0);
}

static void
hcpc_close_session (session_t *s, u8 is_http)
{
  hcpc_main_t *hcpcm = &hcpc_main;
  hcpc_session_t *ps;

  HCPC_DBG ("session [%u] (is http %u)", s->opaque, is_http);
  clib_spinlock_lock_if_init (&hcpcm->sessions_lock);
  ps = hcpc_session_get (s->opaque);
  ASSERT (ps);

  if (is_http)
    {
      /* http connection went down */
      if (ps->flags & HCPC_SESSION_F_IS_PARENT)
	{
	  hcpc_http_connection_closed (ps);
	  clib_spinlock_unlock_if_init (&hcpc_main.sessions_lock);
	  return;
	}
      if (ps->flags & HCPC_SESSION_F_IS_UDP)
	{
	  /* udp don't have half-close */
	  ps->state = HCPC_SESSION_CLOSED;
	  hcpc_session_close_http (ps);
	  if (!(ps->intercept_diconnected))
	    {
	      ASSERT (ps->http.session_handle != SESSION_INVALID_HANDLE);
	      hcpc_session_close_intercept (ps);
	    }
	}
      else
	{
	  if (ps->intercept_diconnected)
	    {
	      /* intercept already disconnect, we can close http immediately */
	      hcpc_session_close_http (ps);
	    }
	  else
	    {
	      ASSERT (ps->http.session_handle != SESSION_INVALID_HANDLE);
	      if (ps->state == HCPC_SESSION_CLOSING)
		{
		  /* both sides start closing on same time from different
		   * threads, so http don't receive shutdown evt */
		  if (ps->flags & HCPC_SESSION_F_HTTP_SHUTDOWN)
		    {
		      ps->flags &= ~HCPC_SESSION_F_HTTP_SHUTDOWN;
		      hcpc_session_close_http (ps);
		    }
		  /* intercept start closing first, confirm close */
		  ps->state = HCPC_SESSION_CLOSED;
		  hcpc_session_close_intercept (ps);
		}
	      else
		{
		  /* shutdown intercept first, http will be closed on intercept
		   * close event */
		  ASSERT (ps->state == HCPC_SESSION_ESTABLISHED);
		  ps->state = HCPC_SESSION_CLOSING;
		  hcpc_session_shutdown_intercept (ps);
		}
	    }
	}
    }
  else
    {
      if (ps->flags & HCPC_SESSION_F_IS_UDP)
	{
	  /* udp don't have half-close */
	  ps->state = HCPC_SESSION_CLOSED;
	  hcpc_session_close_intercept (ps);
	  if (!(ps->http_disconnected) && !(ps->http_establishing))
	    {
	      if (ps->http.session_handle != SESSION_INVALID_HANDLE)
		hcpc_session_close_http (ps);
	      ps->http_disconnected = 1;
	    }
	}
      else
	{
	  if (ps->http_disconnected)
	    {
	      /* http already disconnect, we can close intercept immediately */
	      hcpc_session_close_intercept (ps);
	    }
	  else
	    {
	      if (ps->state == HCPC_SESSION_CLOSING)
		{
		  /* both sides start closing on same time from different
		   * threads, so intercept don't receive shutdown evt */
		  if (ps->flags & HCPC_SESSION_F_INTERCEPT_SHUTDOWN)
		    {
		      ps->flags &= ~HCPC_SESSION_F_INTERCEPT_SHUTDOWN;
		      hcpc_session_close_intercept (ps);
		    }
		  /* http start closing first, confirm close */
		  ps->state = HCPC_SESSION_CLOSED;
		  hcpc_session_close_http (ps);
		}
	      else
		{
		  if (ps->http_establishing)
		    {
		      /* http is still connecting */
		      hcpc_session_close_intercept (ps);
		    }
		  else
		    {
		      /* shutdown http first, intercept will be closed on http
		       * close event, unless it is already closed */
		      ps->state = HCPC_SESSION_CLOSING;
		      if (ps->http.session_handle != SESSION_INVALID_HANDLE)
			hcpc_session_shutdown_http (ps);
		    }
		}
	    }
	}
    }

  clib_spinlock_unlock_if_init (&hcpc_main.sessions_lock);
}

static void
hcpc_listen (hcpc_listener_t *l)
{
  hcpc_main_t *hcpcm = &hcpc_main;
  vnet_listen_args_t _a, *a = &_a;
  session_error_t rv;

  clib_memset (a, 0, sizeof (*a));
  a->app_index = hcpcm->listener_app_index;
  clib_memcpy (&a->sep_ext, &l->sep, sizeof (l->sep));
  /* Make sure listener is marked connected for transports like udp */
  a->sep_ext.transport_flags = TRANSPORT_CFG_F_CONNECTED;
  if ((rv = vnet_listen (a)))
    {
      clib_warning ("listen returned: %U", format_session_error, rv);
      return;
    }
  l->session_handle = a->handle;
  HCPC_DBG ("listener started %U:%u", format_ip46_address, &l->sep.ip,
	    l->sep.is_ip4, clib_net_to_host_u16 (l->sep.port));

  /* if listen all (wildcard ip and port) enable it in hsi */
  if (l->sep.port == 0)
    {
      if (l->sep.is_ip4)
	{
	  if (l->sep.ip.ip4.as_u32 != 0)
	    return;
	  hcpcm->intercept_proto_fn (l->sep.transport_proto, 1);
	}
      else
	{
	  if (!(l->sep.ip.ip6.as_u64[0] == 0 || l->sep.ip.ip6.as_u64[1] == 0))
	    return;
	  hcpcm->intercept_proto_fn (l->sep.transport_proto, 0);
	}
    }
}

void
hcpc_start_listen ()
{
  hcpc_main_t *hcpcm = &hcpc_main;
  hcpc_listener_t *l;

  pool_foreach (l, hcpcm->listeners)
    {
      hcpc_listen (l);
    }
}

#define HCPC_ARC_IP4  "ip4-unicast"
#define HCPC_ARC_IP6  "ip6-unicast"
#define HCPC_NODE_IP4 "hsi4-in"
#define HCPC_NODE_IP6 "hsi6-in"

static clib_error_t *
hcpc_enable_hsi (u8 is_ip4)
{
  hcpc_main_t *hcpcm = &hcpc_main;
  vnet_feature_registration_t *reg;
  clib_error_t *err = 0;
  int rv;

  if (is_ip4)
    {
      if (hcpcm->hsi4_enabled)
	return 0;
      reg = vnet_get_feature_reg (HCPC_ARC_IP4, HCPC_NODE_IP4);
    }
  else
    {
      if (hcpcm->hsi6_enabled)
	return 0;
      reg = vnet_get_feature_reg (HCPC_ARC_IP6, HCPC_NODE_IP6);
    }
  if (reg == 0)
    return clib_error_return (0, "hsi plugin not loaded");

  if (reg->enable_disable_cb)
    {
      if ((err = reg->enable_disable_cb (hcpcm->sw_if_index, 1)))
	return err;
    }

  if (is_ip4)
    rv = vnet_feature_enable_disable (HCPC_ARC_IP4, HCPC_NODE_IP4,
				      hcpcm->sw_if_index, 1, 0, 0);
  else
    rv = vnet_feature_enable_disable (HCPC_ARC_IP6, HCPC_NODE_IP6,
				      hcpcm->sw_if_index, 1, 0, 0);
  if (rv)
    return clib_error_return (0, "vnet feature enable failed (rv=%d)", rv);

  if (is_ip4)
    hcpcm->hsi4_enabled = 1;
  else
    hcpcm->hsi6_enabled = 1;
  return 0;
}

static clib_error_t *
hcpc_listener_add (hcpc_listener_t *l_cfg)
{
  hcpc_main_t *hcpcm = &hcpc_main;
  hcpc_listener_t *l;
  clib_error_t *err = 0;

  err = hcpc_enable_hsi (l_cfg->sep.is_ip4);
  if (err)
    return err;

  pool_get (hcpcm->listeners, l);
  *l = *l_cfg;
  l->l_index = l - hcpcm->listeners;
  l->session_handle = SESSION_INVALID_HANDLE;

  if (hcpcm->http_connection_handle != SESSION_INVALID_HANDLE)
    hcpc_listen (l);

  return 0;
}

static int
hcpc_listener_del (hcpc_listener_t *l_cfg)
{
  hcpc_main_t *hcpcm = &hcpc_main;
  hcpc_listener_t *l;
  u8 found = 0;
  session_error_t rv = 0;

  pool_foreach (l, hcpcm->listeners)
    {
      if (clib_memcmp (&l_cfg->sep, &l->sep, sizeof (l_cfg->sep)) == 0)
	{
	  found = 1;
	  break;
	}
    }

  if (!found)
    return 1;

  if (l->session_handle != SESSION_INVALID_HANDLE)
    {
      vnet_unlisten_args_t a = { .handle = l->session_handle,
				 .app_index = hcpcm->listener_app_index };
      rv = vnet_unlisten (&a);
    }

  pool_put (hcpcm->listeners, l);

  return rv;
}

static void
hcpc_open_http_stream (u32 session_index)
{
  hcpc_main_t *hcpcm = &hcpc_main;
  vnet_connect_args_t _a, *a = &_a;
  session_error_t rv;
  session_t *s;
  hcpc_session_t *ps;

  clib_memset (a, 0, sizeof (*a));
  clib_memcpy (&a->sep_ext, &hcpcm->proxy_server_sep,
	       sizeof (hcpcm->proxy_server_sep));
  a->sep_ext.parent_handle = hcpcm->http_connection_handle;
  a->app_index = hcpcm->http_app_index;
  a->api_context = session_index;

  rv = vnet_connect_stream (a);
  if (rv)
    {
      clib_warning ("session %u connect error: %U", session_index,
		    format_session_error, rv);
      clib_spinlock_lock_if_init (&hcpcm->sessions_lock);
      ps = hcpc_session_get (session_index);
      ASSERT (ps);
      ps->state = HCPC_SESSION_CLOSED;
      ps->http_disconnected = 1;
      ps->http_establishing = 0;
      if (!ps->intercept_diconnected)
	{
	  ps->intercept.rx_fifo->master_thread_index =
	    ps->intercept.tx_fifo->master_thread_index;
	  if (ps->intercept.session_handle != SESSION_INVALID_HANDLE)
	    {
	      session_reset (
		session_get_from_handle (ps->intercept.session_handle));
	      ps->intercept_diconnected = 1;
	    }
	  else
	    {
	      if (session_thread_from_handle (hcpcm->http_connection_handle) !=
		  ps->intercept.tx_fifo->master_thread_index)
		{
		  session_send_rpc_evt_to_thread (
		    ps->intercept.tx_fifo->master_thread_index,
		    hcpc_session_postponed_free_rpc,
		    uword_to_pointer (ps->session_index, void *));
		}
	      else
		hcpc_session_free (ps);
	    }
	  if (rv == SESSION_E_MAX_STREAMS_HIT)
	    hcpc_worker_stats_inc (vlib_get_thread_index (), max_streams_hit,
				   1);
	}
      clib_spinlock_unlock_if_init (&hcpcm->sessions_lock);
      return;
    }

  HCPC_DBG ("stream for session [%u] opened", session_index);
  s = session_get_from_handle (a->sh);
  clib_spinlock_lock_if_init (&hcpcm->sessions_lock);
  ps = hcpc_session_get (session_index);
  ASSERT (ps);
  ps->http.session_handle = session_handle (s);
  ps->http.rx_fifo = s->rx_fifo;
  ps->http.tx_fifo = s->tx_fifo;

  /* listener session was already closed */
  if (ps->intercept_diconnected)
    {
      hcpc_worker_stats_inc (s->thread_index,
			     client_closed_before_stream_opened, 1);
      session_reset (s);
      ps->http_establishing = 0;
      ps->http_disconnected = 1;
      clib_spinlock_unlock_if_init (&hcpcm->sessions_lock);
      return;
    }

  clib_spinlock_unlock_if_init (&hcpcm->sessions_lock);

  if (svm_fifo_max_dequeue (s->tx_fifo))
    if (svm_fifo_set_event (s->tx_fifo))
      session_program_tx_io_evt (s->handle, SESSION_IO_EVT_TX);
}

static void
hcpc_connect_http_stream_rpc (void *rpc_args)
{
  u32 session_index = pointer_to_uword (rpc_args);

  hcpc_open_http_stream (session_index);
}

static void
hcpc_connect_http_stream (u32 session_index)
{
  hcpc_main_t *hcpcm = &hcpc_main;
  u32 connects_thread, thread_index;

  connects_thread = session_thread_from_handle (hcpcm->http_connection_handle);
  thread_index = vlib_get_thread_index ();

  if (thread_index == connects_thread)
    {
      hcpc_open_http_stream (session_index);
      return;
    }

  session_send_rpc_evt_to_thread_force (
    connects_thread, hcpc_connect_http_stream_rpc,
    uword_to_pointer (session_index, void *));
}

static void
hcpc_connect_http_connection_rpc (void *rpc_args)
{
  vnet_connect_args_t *a = rpc_args;
  session_error_t rv;

  rv = vnet_connect (a);
  if (rv)
    clib_warning ("connect returned: %U", format_session_error, rv);

  session_endpoint_free_ext_cfgs (&a->sep_ext);
  vec_free (a);
}

static void
hcpc_connect_http_connection ()
{
  hcpc_main_t *hcpcm = &hcpc_main;
  vnet_connect_args_t *a = 0;
  transport_endpt_ext_cfg_t *ext_cfg;
  transport_endpt_cfg_http_t http_cfg = { 120, HTTP_UDP_TUNNEL_DGRAM, 0 };

  if (hcpcm->http_state >= HCPC_HTTP_STATE_CONNECTING)
    return;

  vec_validate (a, 0);
  clib_memset (a, 0, sizeof (a[0]));
  clib_memcpy (&a->sep_ext, &hcpcm->proxy_server_sep,
	       sizeof (hcpcm->proxy_server_sep));
  a->app_index = hcpcm->http_app_index;
  a->api_context = ~0;

  if (hcpcm->proxy_server_sep.flags & SESSION_ENDPT_CFG_F_SECURE)
    {
      ext_cfg = session_endpoint_add_ext_cfg (
	&a->sep_ext, TRANSPORT_ENDPT_EXT_CFG_CRYPTO,
	sizeof (transport_endpt_crypto_cfg_t));
      ext_cfg->crypto.ckpair_index = hcpcm->ckpair_index;
      ext_cfg->crypto.alpn_protos[0] = TLS_ALPN_PROTO_HTTP_2;
    }
  else
    http_cfg.flags |= HTTP_ENDPT_CFG_F_HTTP2_PRIOR_KNOWLEDGE;

  ext_cfg = session_endpoint_add_ext_cfg (
    &a->sep_ext, TRANSPORT_ENDPT_EXT_CFG_HTTP, sizeof (http_cfg));
  clib_memcpy (ext_cfg->data, &http_cfg, sizeof (http_cfg));
  hcpcm->http_state = HCPC_HTTP_STATE_CONNECTING;

  session_send_rpc_evt_to_thread_force (transport_cl_thread (),
					hcpc_connect_http_connection_rpc, a);
}

static int
hcpc_write_http_connect_udp_req (svm_fifo_t *f, transport_connection_t *tc)
{
  hcpc_main_t *hcpcm = &hcpc_main;
  u8 *target;
  http_msg_t msg;
  int rv;

  if (tc->is_ip4)
    target = format (0, "/.well-known/masque/udp/%U/%u/", format_ip4_address,
		     &tc->lcl_ip.ip4, clib_net_to_host_u16 (tc->lcl_port));
  else
    target = format (0, "/.well-known/masque/udp/[%U]/%u/", format_ip6_address,
		     &tc->lcl_ip.ip6, clib_net_to_host_u16 (tc->lcl_port));

  HCPC_DBG ("opening UDP tunnel %U:%u->%U:%u", format_ip46_address,
	    &tc->rmt_ip, tc->is_ip4, clib_net_to_host_u16 (tc->rmt_port),
	    format_ip46_address, &tc->lcl_ip, tc->is_ip4,
	    clib_net_to_host_u16 (tc->lcl_port));

  msg.type = HTTP_MSG_REQUEST;
  msg.method_type = HTTP_REQ_CONNECT;
  msg.data.upgrade_proto = HTTP_UPGRADE_PROTO_CONNECT_UDP;
  msg.data.target_path_offset = 0;
  msg.data.target_path_len = vec_len (target);
  msg.data.headers_offset = msg.data.target_path_len;
  msg.data.headers_len = hcpcm->capsule_proto_header.tail_offset;
  msg.data.body_len = 0;
  msg.data.type = HTTP_MSG_DATA_INLINE;
  msg.data.len = msg.data.target_path_len + msg.data.headers_len;

  svm_fifo_seg_t segs[3] = { { (u8 *) &msg, sizeof (msg) },
			     { target, msg.data.target_path_len },
			     { hcpcm->capsule_proto_header_buf,
			       msg.data.headers_len } };
  rv = svm_fifo_enqueue_segments (f, segs, 3, 0);
  vec_free (target);
  if (rv < (sizeof (msg) + msg.data.len))
    {
      clib_warning ("enqueue failed: %d", rv);
      return -1;
    }

  return 0;
}

static int
hcpc_write_http_connect_req (svm_fifo_t *f, transport_connection_t *tc)
{
  u8 *target = 0;
  http_msg_t msg;
  int rv;

  if (tc->is_ip4)
    target = format (0, "%U:%u", format_ip4_address, &tc->lcl_ip.ip4,
		     clib_net_to_host_u16 (tc->lcl_port));
  else
    target = format (0, "[%U]:%u", format_ip6_address, &tc->lcl_ip.ip6,
		     clib_net_to_host_u16 (tc->lcl_port));

  HCPC_DBG ("opening TCP tunnel %U:%u->%U:%u", format_ip46_address,
	    &tc->rmt_ip, tc->is_ip4, clib_net_to_host_u16 (tc->rmt_port),
	    format_ip46_address, &tc->lcl_ip, tc->is_ip4,
	    clib_net_to_host_u16 (tc->lcl_port));

  msg.type = HTTP_MSG_REQUEST;
  msg.method_type = HTTP_REQ_CONNECT;
  msg.data.upgrade_proto = HTTP_UPGRADE_PROTO_NA;
  msg.data.target_path_offset = 0;
  msg.data.target_path_len = vec_len (target);
  msg.data.headers_len = 0;
  msg.data.body_len = 0;
  msg.data.type = HTTP_MSG_DATA_INLINE;
  msg.data.len = msg.data.target_path_len;

  svm_fifo_seg_t segs[2] = { { (u8 *) &msg, sizeof (msg) },
			     { target, msg.data.target_path_len } };
  rv = svm_fifo_enqueue_segments (f, segs, 2, 0);
  vec_free (target);
  if (rv < (sizeof (msg) + msg.data.len))
    {
      clib_warning ("enqueue failed: %d", rv);
      return -1;
    }

  return 0;
}

static int
hcpc_read_http_connect_resp (session_t *s)
{
  hcpc_main_t *hcpcm = &hcpc_main;
  http_msg_t msg;
  int rv;

  rv = svm_fifo_dequeue (s->rx_fifo, sizeof (msg), (u8 *) &msg);
  ASSERT (rv == sizeof (msg));
  ASSERT (msg.type == HTTP_MSG_REPLY);
  /* drop everything up to body */
  svm_fifo_dequeue_drop (s->rx_fifo, msg.data.body_offset);
  HCPC_DBG ("response: %U %U", format_http_version,
	    http_session_get_version (s), format_http_status_code, msg.code);
  if (http_status_code_str[msg.code][0] != '2')
    {
      hcpc_worker_stats_inc (vlib_get_thread_index (), target_unreachable, 1);
      return -1;
    }

  hcpc_worker_stats_inc (vlib_get_thread_index (), tunnels_opened, 1);
  return 0;
}

/***************************/
/* http side vft callbacks */
/***************************/

static int
hcpc_http_session_accept_callback (session_t *s)
{
  clib_warning ("http proxy client app should not get accept events");
  return -1;
}

static int
hcpc_http_session_connected_callback (u32 app_index, u32 session_index,
				      session_t *s, session_error_t err)
{
  hcpc_main_t *hcpcm = &hcpc_main;
  hcpc_session_t *ps;

  ASSERT (hcpcm->http_connection_handle == SESSION_INVALID_HANDLE);

  if (err)
    {
      clib_warning ("connect to http proxy server failed: %U",
		    format_session_error, err);
      hcpcm->http_state = HCPC_HTTP_STATE_DISCONNECTED;
      if (err == SESSION_E_REFUSED)
	vlib_process_signal_event_mt (vlib_get_main (),
				      hcpcm->process_node_index,
				      HCPC_EVENT_PROXY_CONNECT_REFUSED, 0);
      return 0;
    }

  HCPC_DBG ("parent session connected");
  clib_spinlock_lock_if_init (&hcpcm->sessions_lock);
  ps = hcpc_session_alloc ();
  ps->http.session_handle = session_handle (s);
  ps->http.rx_fifo = s->rx_fifo;
  ps->http.tx_fifo = s->tx_fifo;
  ps->flags |= HCPC_SESSION_F_IS_PARENT;
  clib_spinlock_unlock_if_init (&hcpcm->sessions_lock);
  s->opaque = ps->session_index;
  hcpcm->http_connection_handle = session_handle (s);
  hcpcm->http_state = HCPC_HTTP_STATE_CONNECTED;
  vlib_process_signal_event_mt (vlib_get_main (), hcpcm->process_node_index,
				HCPC_EVENT_PROXY_CONNECTED, 0);
  return 0;
}

static void
hcpc_http_session_disconnect_callback (session_t *s)
{
  hcpc_close_session (s, 1);
}

static void
hcpc_http_session_transport_closed_callback (session_t *s)
{
  HCPC_DBG ("session [%u]", s->opaque);
}

static void
hcpc_http_session_reset_callback (session_t *s)
{
  hcpc_main_t *hcpcm = &hcpc_main;
  hcpc_session_t *ps;

  HCPC_DBG ("session [%u]", s->opaque);
  clib_spinlock_lock_if_init (&hcpcm->sessions_lock);
  ps = hcpc_session_get (s->opaque);
  ASSERT (ps);
  ps->state = HCPC_SESSION_CLOSED;
  hcpc_session_close_http (ps);
  if (!ps->intercept_diconnected &&
      ps->intercept.session_handle != SESSION_INVALID_HANDLE)
    {
      session_reset (session_get_from_handle (ps->intercept.session_handle));
      ps->intercept_diconnected = 1;
    }
  clib_spinlock_unlock_if_init (&hcpcm->sessions_lock);
  hcpc_worker_stats_inc (s->thread_index, tunnels_reset_by_target, 1);
}

static void
hcpc_intercept_rollback_cwnd (session_handle_t intercept_handle, u32 cwnd)
{
  session_t *s;
  transport_connection_t *tc;
  tcp_connection_t *tcp_conn;

  s = session_get_from_handle_if_valid (intercept_handle);
  if (!s)
    return;
  ASSERT (TRANSPORT_PROTO_TCP == session_get_transport_proto (s));
  tc = session_get_transport (s);
  tcp_conn = (tcp_connection_t *) tc;
  tcp_conn->cwnd = cwnd;
  transport_connection_reschedule (tc);
}

static void
hcpc_intercept_rollback_cwnd_rpc (void *arg)
{
  hcpc_main_t *hcpcm = &hcpc_main;
  hcpc_session_t *ps;

  clib_spinlock_lock_if_init (&hcpcm->sessions_lock);
  ps = hcpc_session_get (pointer_to_uword (arg));
  ASSERT (ps);
  hcpc_intercept_rollback_cwnd (ps->intercept.session_handle, ps->opaque);
  clib_spinlock_unlock_if_init (&hcpcm->sessions_lock);
}

static int
hcpc_http_rx_callback (session_t *s)
{
  hcpc_main_t *hcpcm = &hcpc_main;
  hcpc_session_t *ps;
  svm_fifo_t *listener_tx_fifo;
  session_handle_t sh;

  HCPC_DBG ("session [%u]", s->opaque);
  clib_spinlock_lock_if_init (&hcpcm->sessions_lock);
  ps = hcpc_session_get (s->opaque);
  ASSERT (ps);
  if (ps->http_establishing)
    {
      ps->http_establishing = 0;
      if (ps->intercept_diconnected || hcpc_read_http_connect_resp (s))
	{
	  ps->state = HCPC_SESSION_CLOSED;
	  session_reset (s);
	  ps->http_disconnected = 1;
	  if (!ps->intercept_diconnected)
	    {
	      if (ps->intercept.session_handle != SESSION_INVALID_HANDLE)
		session_reset (
		  session_get_from_handle (ps->intercept.session_handle));
	      ps->intercept_diconnected = 1;
	    }
	  else
	    hcpc_worker_stats_inc (s->thread_index,
				   client_closed_before_tunnel_connected, 1);
	  clib_spinlock_unlock_if_init (&hcpcm->sessions_lock);
	  return 0;
	}
      ps->state = HCPC_SESSION_ESTABLISHED;
      if (ps->flags & HCPC_SESSION_F_IS_UDP)
	hcpc_timer_start (ps);
      else
	{
	  /* rollback cwnd and reschedule tcp intercept transport */
	  if (s->thread_index !=
	      session_thread_from_handle (ps->intercept.session_handle))
	    session_send_rpc_evt_to_thread (
	      session_thread_from_handle (ps->intercept.session_handle),
	      hcpc_intercept_rollback_cwnd_rpc,
	      uword_to_pointer (ps->session_index, void *));
	  else
	    hcpc_intercept_rollback_cwnd (ps->intercept.session_handle,
					  ps->opaque);
	}

      clib_spinlock_unlock_if_init (&hcpcm->sessions_lock);

      return 0;
    }
  if (ps->intercept_diconnected)
    {
      clib_spinlock_unlock_if_init (&hcpcm->sessions_lock);
      return -1;
    }
  hcpc_timer_update (ps);
  sh = ps->intercept.session_handle;
  clib_spinlock_unlock_if_init (&hcpcm->sessions_lock);

  /* send event for intercept tx fifo */
  listener_tx_fifo = s->rx_fifo;
  ASSERT (svm_fifo_max_dequeue (listener_tx_fifo));
  if (svm_fifo_set_event (listener_tx_fifo))
    session_program_tx_io_evt (sh, SESSION_IO_EVT_TX);

  return 0;
}

static void
hcpc_intercept_force_ack (session_handle_t intercept_handle)
{
  transport_connection_t *tc;
  session_t *s;

  s = session_get_from_handle_if_valid (intercept_handle);
  if (!s || session_get_transport_proto (s) != TRANSPORT_PROTO_TCP)
    return;

  tc = session_get_transport (s);
  tcp_send_ack ((tcp_connection_t *) tc);
}

static void
hcpc_intercept_force_ack_rpc (void *arg)
{
  hcpc_main_t *hcpcm = &hcpc_main;
  hcpc_session_t *ps;

  clib_spinlock_lock_if_init (&hcpcm->sessions_lock);
  ps = hcpc_session_get (pointer_to_uword (arg));
  ASSERT (ps);
  hcpc_intercept_force_ack (ps->intercept.session_handle);
  clib_spinlock_unlock_if_init (&hcpcm->sessions_lock);
}

static int
hcpc_http_tx_callback (session_t *s)
{
  hcpc_main_t *hcpcm = &hcpc_main;
  hcpc_session_t *ps;
  u32 min_free;
  hcpc_session_state_t state;
  u32 ps_index;
  session_handle_t intercept_sh;

  HCPC_DBG ("session [%u]", s->opaque);
  min_free = clib_min (svm_fifo_size (s->tx_fifo) >> 3, 128 << 10);
  if (svm_fifo_max_enqueue (s->tx_fifo) < min_free)
    {
      svm_fifo_add_want_deq_ntf (s->tx_fifo, SVM_FIFO_WANT_DEQ_NOTIF);
      return 0;
    }

  clib_spinlock_lock_if_init (&hcpcm->sessions_lock);
  ps = hcpc_session_get (s->opaque);
  ASSERT (ps);
  state = ps->state;
  if (ps->intercept_diconnected)
    {
      clib_spinlock_unlock_if_init (&hcpcm->sessions_lock);
      return -1;
    }
  ps_index = ps->session_index;
  intercept_sh = ps->intercept.session_handle;
  clib_spinlock_unlock_if_init (&hcpcm->sessions_lock);

  if (state < HCPC_SESSION_ESTABLISHED)
    return 0;

  /* force ack on listener side to update rcv wnd */
  if (s->thread_index != session_thread_from_handle (intercept_sh))
    session_send_rpc_evt_to_thread (session_thread_from_handle (intercept_sh),
				    hcpc_intercept_force_ack_rpc,
				    uword_to_pointer (ps_index, void *));
  else
    hcpc_intercept_force_ack (intercept_sh);

  return 0;
}

static void
hcpc_http_session_cleanup_callback (session_t *s, session_cleanup_ntf_t ntf)
{
  if (ntf == SESSION_CLEANUP_TRANSPORT)
    return;

  hcpc_delete_session (s, 1);
}

static int
hcpc_http_alloc_session_fifos (session_t *s)
{
  hcpc_main_t *hcpcm = &hcpc_main;
  hcpc_session_t *ps;
  session_t *ls;
  svm_fifo_t *rx_fifo = 0, *tx_fifo = 0;
  int rv;

  HCPC_DBG ("session [%u] alloc fifos", s->opaque);
  clib_spinlock_lock_if_init (&hcpcm->sessions_lock);

  ps = hcpc_session_get (s->opaque);

  /* http connection session doesn't have listener */
  if (!ps)
    {
      HCPC_DBG ("http connection session");
      /* http connection is not mapped to any listener, alloc session fifos */
      app_worker_t *app_wrk = app_worker_get (hcpcm->http_app_index);
      segment_manager_t *sm = app_worker_get_connect_segment_manager (app_wrk);
      if ((rv = segment_manager_alloc_session_fifos (sm, s->thread_index,
						     &rx_fifo, &tx_fifo)))
	{
	  clib_spinlock_unlock_if_init (&hcpcm->sessions_lock);
	  return rv;
	}
      rx_fifo->shr->master_session_index = s->session_index;
      rx_fifo->vpp_sh = s->handle;
      s->flags &= ~SESSION_F_PROXY;
    }
  else
    {
      HCPC_DBG ("http stream session");
      if (ps->intercept_diconnected)
	{
	  clib_spinlock_unlock_if_init (&hcpcm->sessions_lock);
	  return SESSION_E_ALLOC;
	}
      ls = session_get_from_handle (ps->intercept.session_handle);
      tx_fifo = ls->rx_fifo;
      rx_fifo = ls->tx_fifo;
      ASSERT (rx_fifo->refcnt == 1);
      ASSERT (tx_fifo->refcnt == 1);
      rx_fifo->refcnt++;
      tx_fifo->refcnt++;
    }

  tx_fifo->shr->master_session_index = s->session_index;
  tx_fifo->vpp_sh = s->handle;

  clib_spinlock_unlock_if_init (&hcpcm->sessions_lock);

  s->rx_fifo = rx_fifo;
  s->tx_fifo = tx_fifo;
  return 0;
}

static session_cb_vft_t http_session_cb_vft = {
  .session_accept_callback = hcpc_http_session_accept_callback,
  .session_connected_callback = hcpc_http_session_connected_callback,
  .session_disconnect_callback = hcpc_http_session_disconnect_callback,
  .session_transport_closed_callback =
    hcpc_http_session_transport_closed_callback,
  .session_reset_callback = hcpc_http_session_reset_callback,
  .builtin_app_rx_callback = hcpc_http_rx_callback,
  .builtin_app_tx_callback = hcpc_http_tx_callback,
  .session_cleanup_callback = hcpc_http_session_cleanup_callback,
  .proxy_alloc_session_fifos = hcpc_http_alloc_session_fifos,
};

/*******************************/
/* listener side vft callbacks */
/*******************************/

static int
hcpc_intercept_accept_callback (session_t *s)
{
  hcpc_session_t *ps;
  hcpc_main_t *hcpcm = &hcpc_main;
  tcp_connection_t *tcp_conn;

  if (hcpcm->http_connection_handle == SESSION_INVALID_HANDLE)
    return -1;

  clib_spinlock_lock_if_init (&hcpcm->sessions_lock);

  ps = hcpc_session_alloc ();
  ps->state = HCPC_SESSION_CONNECTING;
  ps->intercept.session_handle = session_handle (s);
  ps->intercept.rx_fifo = s->rx_fifo;
  ps->intercept.tx_fifo = s->tx_fifo;
  ps->http_establishing = 1;
  if (session_get_transport_proto (s) == TRANSPORT_PROTO_UDP)
    ps->flags |= HCPC_SESSION_F_IS_UDP;
  else
    {
      /* set cwnd to zero temporarily, otherwise tcp on intercept side can
       * dequeue http response msg when doing ack */
      tcp_conn = (tcp_connection_t *) session_get_transport (s);
      ps->opaque = tcp_conn->cwnd;
      tcp_conn->cwnd = 0;
    }

  clib_spinlock_unlock_if_init (&hcpcm->sessions_lock);

  s->opaque = ps->session_index;
  s->session_state = SESSION_STATE_READY;

  HCPC_DBG ("going to open stream for new session [%u]", ps->session_index);
  hcpc_connect_http_stream (ps->session_index);

  return 0;
}

static int
hcpc_intercept_connected_callback (u32 app_index, u32 session_index,
				   session_t *s, session_error_t err)
{
  clib_warning ("intercept app should not get connected events");
  return -1;
}

static void
hcpc_intercept_session_disconnect_callback (session_t *s)
{
  hcpc_close_session (s, 0);
}

static void
hcpc_intercept_session_transport_closed_callback (session_t *s)
{
  HCPC_DBG ("session [%u]", s->opaque);
}

static void
hcpc_intercept_session_reset_callback (session_t *s)
{
  hcpc_main_t *hcpcm = &hcpc_main;
  hcpc_session_t *ps;

  HCPC_DBG ("session [%u]", s->opaque);
  clib_spinlock_lock_if_init (&hcpcm->sessions_lock);
  ps = hcpc_session_get (s->opaque);
  ASSERT (ps);
  ps->state = HCPC_SESSION_CLOSED;
  hcpc_session_close_intercept (ps);
  /* we want stream reset here */
  if (!ps->http_disconnected &&
      ps->http.session_handle != SESSION_INVALID_HANDLE)
    {
      session_reset (session_get_from_handle (ps->http.session_handle));
      ps->http_disconnected = 1;
    }
  clib_spinlock_unlock_if_init (&hcpcm->sessions_lock);
  hcpc_worker_stats_inc (s->thread_index, tunnels_reset_by_client, 1);
}

static int
hcpc_intercept_rx_callback (session_t *s)
{
  hcpc_main_t *hcpcm = &hcpc_main;
  hcpc_session_t *ps;
  svm_fifo_t *http_tx_fifo;
  hcpc_session_state_t state;
  session_handle_t sh;

  HCPC_DBG ("session [%u]", s->opaque);
  if (s->flags & SESSION_F_APP_CLOSED)
    return 0;
  clib_spinlock_lock_if_init (&hcpcm->sessions_lock);
  ps = hcpc_session_get (s->opaque);
  ASSERT (ps);
  state = ps->state;
  sh = ps->http.session_handle;
  if (ps->http_disconnected)
    {
      clib_spinlock_unlock_if_init (&hcpcm->sessions_lock);
      return -1;
    }
  hcpc_timer_update (ps);
  clib_spinlock_unlock_if_init (&hcpcm->sessions_lock);

  if (state < HCPC_SESSION_ESTABLISHED)
    return 0;

  /* send event for http tx fifo */
  http_tx_fifo = s->rx_fifo;
  if (svm_fifo_max_dequeue (http_tx_fifo))
    if (svm_fifo_set_event (http_tx_fifo))
      session_program_tx_io_evt (sh, SESSION_IO_EVT_TX);

  if (svm_fifo_max_enqueue (http_tx_fifo) <= TCP_MSS)
    svm_fifo_add_want_deq_ntf (http_tx_fifo, SVM_FIFO_WANT_DEQ_NOTIF);

  return 0;
}

static int
hcpc_intercept_tx_callback (session_t *s)
{
  hcpc_main_t *hcpcm = &hcpc_main;
  hcpc_session_t *ps;
  hcpc_session_state_t state;
  session_handle_t sh;

  HCPC_DBG ("session [%u]", s->opaque);
  clib_spinlock_lock_if_init (&hcpcm->sessions_lock);
  ps = hcpc_session_get (s->opaque);
  ASSERT (ps);
  state = ps->state;
  sh = ps->http.session_handle;
  if (ps->http_disconnected)
    {
      clib_spinlock_unlock_if_init (&hcpcm->sessions_lock);
      return -1;
    }
  clib_spinlock_unlock_if_init (&hcpcm->sessions_lock);

  if (state < HCPC_SESSION_ESTABLISHED)
    return 0;

  /* pass notification to http transport */
  session_program_transport_io_evt (sh, SESSION_IO_EVT_RX);
  return 0;
}

static void
hcpc_intercept_session_cleanup_callback (session_t *s,
					 session_cleanup_ntf_t ntf)
{
  if (ntf == SESSION_CLEANUP_TRANSPORT)
    return;

  hcpc_delete_session (s, 0);
}

static int
hcpc_intercept_add_segment_callback (u32 client_index, u64 segment_handle)
{
  return 0;
}

static int
hcpc_intercept_write_early_data (session_t *s)
{
  transport_proto_t tp;
  transport_connection_t *tc;
  int rv;

  tp = session_get_transport_proto (s);
  tc = session_get_transport (s);
  /* write http connect request first so it will be before tunneled data when
   * http stream is connected */
  switch (tp)
    {
    case TRANSPORT_PROTO_TCP:
      rv = hcpc_write_http_connect_req (s->rx_fifo, tc);
      break;
    case TRANSPORT_PROTO_UDP:
      rv = hcpc_write_http_connect_udp_req (s->rx_fifo, tc);
      break;
    default:
      clib_warning ("unsupported protocol %U", format_transport_proto, tp);
      return -1;
    }
  if (rv)
    return -1;

  return 0;
}

static session_cb_vft_t listener_session_cb_vft = {
  .session_accept_callback = hcpc_intercept_accept_callback,
  .session_connected_callback = hcpc_intercept_connected_callback,
  .session_disconnect_callback = hcpc_intercept_session_disconnect_callback,
  .session_transport_closed_callback =
    hcpc_intercept_session_transport_closed_callback,
  .session_reset_callback = hcpc_intercept_session_reset_callback,
  .builtin_app_rx_callback = hcpc_intercept_rx_callback,
  .builtin_app_tx_callback = hcpc_intercept_tx_callback,
  .session_cleanup_callback = hcpc_intercept_session_cleanup_callback,
  .add_segment_callback = hcpc_intercept_add_segment_callback,
  .proxy_write_early_data = hcpc_intercept_write_early_data,
};

static clib_error_t *
hcpc_attach_http_client ()
{
  hcpc_main_t *hcpcm = &hcpc_main;
  vnet_app_attach_args_t _a, *a = &_a;
  vnet_app_add_cert_key_pair_args_t _ck_pair, *ck_pair = &_ck_pair;
  u64 options[APP_OPTIONS_N_OPTIONS];
  session_error_t rv;

  clib_memset (a, 0, sizeof (*a));
  clib_memset (options, 0, sizeof (options));

  a->api_client_index = APP_INVALID_INDEX;
  a->name = format (0, "http-connect-proxy-client");
  a->session_cb_vft = &http_session_cb_vft;
  a->options = options;
  a->options[APP_OPTIONS_SEGMENT_SIZE] = hcpcm->private_segment_size;
  a->options[APP_OPTIONS_ADD_SEGMENT_SIZE] = hcpcm->private_segment_size;
  a->options[APP_OPTIONS_RX_FIFO_SIZE] = hcpcm->fifo_size;
  a->options[APP_OPTIONS_TX_FIFO_SIZE] = hcpcm->fifo_size;
  a->options[APP_OPTIONS_FLAGS] =
    APP_OPTIONS_FLAGS_IS_BUILTIN | APP_OPTIONS_FLAGS_IS_PROXY;
  a->options[APP_OPTIONS_PREALLOC_FIFO_PAIRS] = hcpcm->prealloc_fifos;
  a->options[APP_OPTIONS_TLS_ENGINE] = CRYPTO_ENGINE_OPENSSL;

  if ((rv = vnet_application_attach (a)))
    return clib_error_return (0, "attach returned: %U", format_session_error,
			      rv);

  hcpcm->http_app_index = a->app_index;
  vec_free (a->name);

  clib_memset (ck_pair, 0, sizeof (*ck_pair));
  ck_pair->cert = (u8 *) test_srv_crt_rsa;
  ck_pair->key = (u8 *) test_srv_key_rsa;
  ck_pair->cert_len = test_srv_crt_rsa_len;
  ck_pair->key_len = test_srv_key_rsa_len;
  vnet_app_add_cert_key_pair (ck_pair);
  hcpcm->ckpair_index = ck_pair->index;

  return 0;
}

static clib_error_t *
hcpc_attach_intercept_listener ()
{
  hcpc_main_t *hcpcm = &hcpc_main;
  vnet_app_attach_args_t _a, *a = &_a;
  u64 options[APP_OPTIONS_N_OPTIONS];
  session_error_t rv;

  clib_memset (a, 0, sizeof (*a));
  clib_memset (options, 0, sizeof (options));

  a->api_client_index = APP_INVALID_INDEX;
  a->name = format (0, "http-connect-proxy-client-listener");
  a->session_cb_vft = &listener_session_cb_vft;
  a->options = options;
  a->options[APP_OPTIONS_SEGMENT_SIZE] = hcpcm->private_segment_size;
  a->options[APP_OPTIONS_ADD_SEGMENT_SIZE] = hcpcm->private_segment_size;
  a->options[APP_OPTIONS_RX_FIFO_SIZE] = hcpcm->fifo_size;
  a->options[APP_OPTIONS_TX_FIFO_SIZE] = hcpcm->fifo_size;
  a->options[APP_OPTIONS_FLAGS] =
    APP_OPTIONS_FLAGS_IS_BUILTIN | APP_OPTIONS_FLAGS_IS_PROXY;
  a->options[APP_OPTIONS_PREALLOC_FIFO_PAIRS] = hcpcm->prealloc_fifos;

  if ((rv = vnet_application_attach (a)))
    return clib_error_return (0, "attach returned: %U", format_session_error,
			      rv);

  hcpcm->listener_app_index = a->app_index;
  vec_free (a->name);

  return 0;
}

static uword
hcpc_event_process (vlib_main_t *vm, vlib_node_runtime_t *rt, vlib_frame_t *f)
{
  hcpc_main_t *hcpcm = &hcpc_main;
  f64 now, timeout = 1.0;
  uword *event_data = 0;
  uword event_type;

  while (1)
    {
      vlib_process_wait_for_event_or_clock (vm, timeout);
      event_type = vlib_process_get_events (vm, (uword **) &event_data);
      switch (event_type)
	{
	case HCPC_EVENT_PROXY_CONNECTED:
	  vlib_worker_thread_barrier_sync (vm);
	  hcpc_start_listen ();
	  vlib_worker_thread_barrier_release (vm);
	  break;
	case HCPC_EVENT_PROXY_DISCONNECTED:
	  vlib_worker_thread_barrier_sync (vm);
	  hcpc_http_stop_listeners ();
	  vlib_worker_thread_barrier_release (vm);
	  hcpc_connect_http_connection ();
	  break;
	case HCPC_EVENT_PROXY_CONNECT_REFUSED:
	  /* for resets wait more time before trying */
	  timeout = 10.0;
	  break;
	case ~0:
	  /* TODO: proxy connection keep-alive */
	  if (hcpcm->http_state == HCPC_HTTP_STATE_DISCONNECTED)
	    {
	      hcpc_connect_http_connection ();
	      timeout = 1.0;
	      break;
	    }
	  /* expire timers */
	  now = vlib_time_now (vm);
	  clib_spinlock_lock_if_init (&hcpcm->tw_lock);
	  tw_timer_expire_timers_2t_1w_2048sl (&hcpcm->tw, now);
	  clib_spinlock_unlock_if_init (&hcpcm->tw_lock);
	  break;
	default:
	  HCPC_DBG ("unknown event %u", event_type);
	  break;
	}
      vec_reset_length (event_data);
    }

  return 0;
}

clib_error_t *
hcpc_enable (vlib_main_t *vm)
{
  vlib_thread_main_t *vtm = vlib_get_thread_main ();
  hcpc_main_t *hcpcm = &hcpc_main;
  hcpc_worker_t *wrk;
  clib_error_t *err = 0;
  u32 num_threads;

  hcpcm->intercept_proto_fn =
    vlib_get_plugin_symbol ("hsi_plugin.so", "hsi_intercept_proto");
  if (hcpcm->intercept_proto_fn == 0)
    return clib_error_return (0, "hsi_plugin.so not loaded");

  session_enable_disable_args_t args = { .is_en = 1,
					 .rt_engine_type =
					   RT_BACKEND_ENGINE_RULE_TABLE };
  vlib_worker_thread_barrier_sync (vm);
  vnet_session_enable_disable (vm, &args);
  vlib_worker_thread_barrier_release (vm);

  if (vlib_num_workers ())
    {
      clib_spinlock_init (&hcpcm->sessions_lock);
      clib_spinlock_init (&hcpcm->tw_lock);
    }

  num_threads = 1 + vtm->n_threads;
  vec_validate (hcpcm->workers, num_threads - 1);
  vec_foreach (wrk, hcpcm->workers)
    {
      clib_memset (&wrk->stats, 0, sizeof (wrk->stats));
    }

  err = hcpc_attach_http_client ();
  if (err)
    return err;

  err = hcpc_attach_intercept_listener ();
  if (err)
    return err;

  if (hcpcm->process_node_index == 0)
    hcpcm->process_node_index =
      vlib_process_create (vm, "hcpc-event-process", hcpc_event_process, 16);

  tw_timer_wheel_init_2t_1w_2048sl (&hcpcm->tw, hcpc_timer_expired_cb, 1.0,
				    ~0);

  return 0;
}

/*******/
/* cli */
/*******/

static clib_error_t *
hcpc_create_command_fn (vlib_main_t *vm, unformat_input_t *input,
			vlib_cli_command_t *cmd)
{
  hcpc_main_t *hcpcm = &hcpc_main;
  clib_error_t *err = 0;
  unformat_input_t _line_input, *line_input = &_line_input;
  u8 *server_uri = 0, *listener_uri = 0;
  session_error_t rv;
  hcpc_listener_t _l = {}, *l = &_l;
  u64 mem_size;
  vnet_main_t *vnm = vnet_get_main ();

  if (hcpcm->http_app_index != APP_INVALID_INDEX)
    return clib_error_return (0, "http connect proxy client already enabled");

  if (!unformat_user (input, unformat_line_input, line_input))
    return clib_error_return (0, "expected arguments");

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "server-uri %s", &server_uri))
	;
      else if (unformat (line_input, "listener %s", &listener_uri))
	;
      else if (unformat (line_input, "fifo-size %U", unformat_memory_size,
			 &mem_size))
	hcpcm->fifo_size = mem_size;
      else if (unformat (line_input, "private-segment-size %U",
			 unformat_memory_size, &mem_size))
	hcpcm->private_segment_size = mem_size;
      else if (unformat (line_input, "prealloc-fifos %d",
			 &hcpcm->prealloc_fifos))
	;
      else if (unformat (line_input, "interface %U",
			 unformat_vnet_sw_interface, vnm, &hcpcm->sw_if_index))
	;
      else if (unformat (line_input, "udp-idle-timeout %u",
			 &hcpcm->udp_idle_timeout))
	;
      else
	{
	  err = clib_error_return (0, "unknown input `%U'",
				   format_unformat_error, line_input);
	  goto done;
	}
    }

  if (hcpcm->sw_if_index == ~0)
    {
      err = clib_error_return (0, "interface not provided");
      goto done;
    }
  if (!server_uri)
    {
      err = clib_error_return (0, "server-uri not provided");
      goto done;
    }
  if (!listener_uri)
    {
      err = clib_error_return (0, "listener uri not provided");
      goto done;
    }

  if ((rv = parse_uri ((char *) server_uri, &hcpcm->proxy_server_sep)))
    {
      err = clib_error_return (0, "server-uri parse error: %U",
			       format_session_error, rv);
      goto done;
    }

  if ((rv = parse_uri ((char *) listener_uri, &l->sep)))
    {
      err = clib_error_return (0, "target uri parse error: %U",
			       format_session_error, rv);
      goto done;
    }

  err = hcpc_enable (vm);
  if (err)
    goto done;

  err = hcpc_listener_add (l);
  if (err)
    goto done;

  hcpc_connect_http_connection ();

  hcpcm->is_init = 1;

done:
  vec_free (server_uri);
  vec_free (listener_uri);
  return err;
}

VLIB_CLI_COMMAND (hcpc_create_command, static) = {
  .path = "http connect proxy client enable",
  .short_help =
    "http connect proxy client enable server-uri <http[s]://ip:port>\n"
    "interface <intfc> listener <tcp|udp://ip:port> [udp-idle-timeout <n>]\n"
    "[fifo-size <nM|G>] [private-segment-size <nM|G>] [prealloc-fifos <n>]",
  .function = hcpc_create_command_fn,
};

static clib_error_t *
hcpc_add_del_listener_command_fn (vlib_main_t *vm, unformat_input_t *input,
				  vlib_cli_command_t *cmd)
{
  hcpc_main_t *hcpcm = &hcpc_main;
  clib_error_t *err = 0;
  unformat_input_t _line_input, *line_input = &_line_input;
  u8 *listener_uri = 0;
  session_error_t rv;
  hcpc_listener_t _l = {}, *l = &_l;
  u8 is_add = 1;

  if (!hcpcm->is_init)
    return clib_error_return (0, "http connect proxy client disabled");

  if (!unformat_user (input, unformat_line_input, line_input))
    return clib_error_return (0, "expected arguments");

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "add"))
	is_add = 1;
      else if (unformat (line_input, "del"))
	is_add = 0;
      else if (unformat (line_input, "listener %s", &listener_uri))
	;
      else
	{
	  err = clib_error_return (0, "unknown input `%U'",
				   format_unformat_error, line_input);
	  goto done;
	}
    }

  if (!listener_uri)
    {
      err = clib_error_return (0, "listener uri not provided");
      goto done;
    }
  if ((rv = parse_uri ((char *) listener_uri, &l->sep)))
    {
      err = clib_error_return (0, "target uri parse error: %U",
			       format_session_error, rv);
      goto done;
    }

  if (is_add)
    {
      err = hcpc_listener_add (l);
      if (err)
	goto done;
    }
  else
    {
      rv = hcpc_listener_del (l);
      if (rv > 0)
	{
	  err = clib_error_return (0, "listener not found");
	  goto done;
	}
      else if (rv < 0)
	{
	  err = clib_error_return (0, "unlisten failed: %U",
				   format_session_error, rv);
	  goto done;
	}
    }

done:
  vec_free (listener_uri);
  return err;
}

VLIB_CLI_COMMAND (hcpc_add_del_listener_command, static) = {
  .path = "http connect proxy client listener",
  .short_help =
    "http connect proxy client listener [add|del] <tcp|udp://ip:port>",
  .function = hcpc_add_del_listener_command_fn,
};

static clib_error_t *
hcpc_show_command_fn (vlib_main_t *vm, unformat_input_t *input,
		      vlib_cli_command_t *cmd)
{
  hcpc_main_t *hcpcm = &hcpc_main;
  u8 show_listeners = 0, show_sessions = 0, show_stats = 0;
  clib_thread_index_t ti;
  hcpc_worker_t *wrk;

  if (!hcpcm->is_init)
    return clib_error_return (0, "http connect proxy client disabled");

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "listeners"))
	show_listeners = 1;
      else if (unformat (input, "sessions"))
	show_sessions = 1;
      else if (unformat (input, "stats"))
	show_stats = 1;
      else
	{
	  return clib_error_return (0, "unknown input `%U'",
				    format_unformat_error, input);
	}
    }

  vlib_cli_output (vm, "connection state: %s",
		   hcpcm->http_connection_handle == SESSION_INVALID_HANDLE ?
		     "disconnected" :
		     "connected");
  vlib_cli_output (vm, "server address: %U:%u", format_ip46_address,
		   &hcpcm->proxy_server_sep.ip, hcpcm->proxy_server_sep.is_ip4,
		   clib_net_to_host_u16 (hcpcm->proxy_server_sep.port));

  if (show_listeners)
    {
      hcpc_listener_t *l;
      pool_foreach (l, hcpcm->listeners)
	{
	  vlib_cli_output (vm, "listener [%u] %U://%U:%u", l->l_index,
			   format_transport_proto, l->sep.transport_proto,
			   format_ip46_address, &l->sep.ip, l->sep.is_ip4,
			   clib_net_to_host_u16 (l->sep.port));
	}
    }

  if (show_sessions)
    {
      hcpc_session_t *ps;
      session_t *s;
      transport_connection_t *tc;
      clib_spinlock_lock_if_init (&hcpcm->sessions_lock);
      pool_foreach (ps, hcpcm->sessions)
	{
	  if (ps->flags & HCPC_SESSION_F_IS_PARENT)
	    continue;
	  if ((ps->state > HCPC_SESSION_ESTABLISHED) ||
	      (ps->intercept.session_handle == SESSION_INVALID_HANDLE))
	    {
	      vlib_cli_output (vm, "session [%lu] %U\n%U", ps->session_index,
			       format_hcpc_session_state, ps->state,
			       format_hcpc_session_vars, ps);
	      continue;
	    }

	  s = session_get_from_handle (ps->intercept.session_handle);
	  tc = session_get_transport (s);
	  /* transport closed, we don't know yet */
	  if (!tc)
	    {
	      vlib_cli_output (
		vm, "session [%lu] INTERCEPT-TRANSPORT-CLOSED\n%U",
		ps->session_index, format_hcpc_session_vars, ps);
	      continue;
	    }

	  vlib_cli_output (
	    vm, "session [%lu] %U %U:%u->%U:%u %U\n%U", ps->session_index,
	    format_transport_proto, tc->proto, format_ip46_address,
	    &tc->rmt_ip, tc->is_ip4, clib_net_to_host_u16 (tc->rmt_port),
	    format_ip46_address, &tc->lcl_ip, tc->is_ip4,
	    clib_net_to_host_u16 (tc->lcl_port), format_hcpc_session_state,
	    ps->state, format_hcpc_session_vars, ps);
	}
      clib_spinlock_unlock_if_init (&hcpcm->sessions_lock);
    }

  if (show_stats)
    {
      for (ti = 0; ti < vec_len (hcpcm->workers); ti++)
	{
	  wrk = &hcpcm->workers[ti];
	  vlib_cli_output (vm, "Thread %u:\n", ti);
#define _(name, str)                                                          \
  if (wrk->stats.name)                                                        \
    vlib_cli_output (vm, " %lu %s", wrk->stats.name, str);
	  foreach_hcpc_wrk_stat
#undef _
	}
    }

  return 0;
}

VLIB_CLI_COMMAND (hcpc_show_command, static) = {
  .path = "show http connect proxy client",
  .short_help = "show http connect proxy [listeners] [sessions] [stats]",
  .function = hcpc_show_command_fn,
};

static clib_error_t *
hcpc_clear_stats_fn (vlib_main_t *vm, unformat_input_t *input,
		     vlib_cli_command_t *cmd)
{
  hcpc_main_t *hcpcm = &hcpc_main;
  hcpc_worker_t *wrk;
  clib_thread_index_t ti;

  if (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    return clib_error_return (0, "unknown input `%U'", format_unformat_error,
			      input);

  if (!hcpcm->is_init)
    return clib_error_return (0, "http connect proxy client disabled");

  for (ti = 0; ti < vec_len (hcpcm->workers); ti++)
    {
      wrk = &hcpcm->workers[ti];
      clib_memset (&wrk->stats, 0, sizeof (wrk->stats));
    }

  return 0;
}

VLIB_CLI_COMMAND (hcpc_clear_stats_command, static) = {
  .path = "clear http connect proxy client stats",
  .short_help = "clear http connect proxy client stats",
  .function = hcpc_clear_stats_fn,
};

clib_error_t *
hcpc_main_init (vlib_main_t *vm)
{
  hcpc_main_t *hcpcm = &hcpc_main;
  session_endpoint_cfg_t sep_null = SESSION_ENDPOINT_CFG_NULL;

  hcpcm->http_app_index = APP_INVALID_INDEX;
  hcpcm->listener_app_index = APP_INVALID_INDEX;
  hcpcm->proxy_server_sep = sep_null;
  hcpcm->http_connection_handle = SESSION_INVALID_HANDLE;
  hcpcm->fifo_size = 32 << 10;
  hcpcm->private_segment_size = 128 << 20;
  hcpcm->prealloc_fifos = 0;
  hcpcm->sw_if_index = ~0;
  hcpcm->udp_idle_timeout = 600;

  vec_validate (hcpcm->capsule_proto_header_buf, 10);
  http_init_headers_ctx (&hcpcm->capsule_proto_header,
			 hcpcm->capsule_proto_header_buf,
			 vec_len (hcpcm->capsule_proto_header_buf));
  http_add_header (&hcpcm->capsule_proto_header, HTTP_HEADER_CAPSULE_PROTOCOL,
		   http_token_lit (HTTP_BOOLEAN_TRUE));

  return 0;
}

VLIB_INIT_FUNCTION (hcpc_main_init);
