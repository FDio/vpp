/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * @file
 * @brief TCP host stack utilities
 */

#include <vnet/tcp/tcp.h>
#include <vnet/session/session.h>
#include <vnet/fib/fib.h>
#include <vnet/dpo/load_balance.h>
#include <vnet/dpo/receive_dpo.h>
#include <vnet/ip/ip6_neighbor.h>
#include <math.h>

tcp_main_t tcp_main;

static u32
tcp_connection_bind (u32 session_index, transport_endpoint_t * lcl)
{
  tcp_main_t *tm = &tcp_main;
  tcp_connection_t *listener;

  pool_get (tm->listener_pool, listener);
  memset (listener, 0, sizeof (*listener));

  listener->c_c_index = listener - tm->listener_pool;
  listener->c_lcl_port = lcl->port;

  if (lcl->is_ip4)
    {
      listener->c_lcl_ip4.as_u32 = lcl->ip.ip4.as_u32;
      listener->c_is_ip4 = 1;
    }
  else
    {
      clib_memcpy (&listener->c_lcl_ip6, &lcl->ip.ip6,
		   sizeof (ip6_address_t));

    }
  listener->c_transport_proto = TRANSPORT_PROTO_TCP;
  listener->c_s_index = session_index;
  listener->state = TCP_STATE_LISTEN;

  tcp_connection_timers_init (listener);

  TCP_EVT_DBG (TCP_EVT_BIND, listener);

  return listener->c_c_index;
}

u32
tcp_session_bind (u32 session_index, transport_endpoint_t * tep)
{
  return tcp_connection_bind (session_index, tep);
}

static void
tcp_connection_unbind (u32 listener_index)
{
  tcp_main_t *tm = vnet_get_tcp_main ();
  tcp_connection_t *tc;

  tc = pool_elt_at_index (tm->listener_pool, listener_index);

  TCP_EVT_DBG (TCP_EVT_UNBIND, tc);

  /* Poison the entry */
  if (CLIB_DEBUG > 0)
    memset (tc, 0xFA, sizeof (*tc));

  pool_put_index (tm->listener_pool, listener_index);
}

u32
tcp_session_unbind (u32 listener_index)
{
  tcp_connection_unbind (listener_index);
  return 0;
}

transport_connection_t *
tcp_session_get_listener (u32 listener_index)
{
  tcp_main_t *tm = vnet_get_tcp_main ();
  tcp_connection_t *tc;
  tc = pool_elt_at_index (tm->listener_pool, listener_index);
  return &tc->connection;
}

always_inline void
transport_endpoint_del (u32 tepi)
{
  tcp_main_t *tm = vnet_get_tcp_main ();
  clib_spinlock_lock_if_init (&tm->local_endpoints_lock);
  pool_put_index (tm->local_endpoints, tepi);
  clib_spinlock_unlock_if_init (&tm->local_endpoints_lock);
}

always_inline transport_endpoint_t *
transport_endpoint_new (void)
{
  tcp_main_t *tm = vnet_get_tcp_main ();
  transport_endpoint_t *tep;
  pool_get (tm->local_endpoints, tep);
  return tep;
}

/**
 * Cleanup half-open connection
 *
 */
void
tcp_half_open_connection_del (tcp_connection_t * tc)
{
  tcp_main_t *tm = vnet_get_tcp_main ();
  clib_spinlock_lock_if_init (&tm->half_open_lock);
  pool_put_index (tm->half_open_connections, tc->c_c_index);
  if (CLIB_DEBUG)
    memset (tc, 0xFA, sizeof (*tc));
  clib_spinlock_unlock_if_init (&tm->half_open_lock);
}

/**
 * Try to cleanup half-open connection
 *
 * If called from a thread that doesn't own tc, the call won't have any
 * effect.
 *
 * @param tc - connection to be cleaned up
 * @return non-zero if cleanup failed.
 */
int
tcp_half_open_connection_cleanup (tcp_connection_t * tc)
{
  /* Make sure this is the owning thread */
  if (tc->c_thread_index != vlib_get_thread_index ())
    return 1;
  tcp_timer_reset (tc, TCP_TIMER_ESTABLISH);
  tcp_timer_reset (tc, TCP_TIMER_RETRANSMIT_SYN);
  tcp_half_open_connection_del (tc);
  return 0;
}

tcp_connection_t *
tcp_half_open_connection_new (void)
{
  tcp_main_t *tm = vnet_get_tcp_main ();
  tcp_connection_t *tc = 0;
  ASSERT (vlib_get_thread_index () == 0);
  pool_get (tm->half_open_connections, tc);
  memset (tc, 0, sizeof (*tc));
  tc->c_c_index = tc - tm->half_open_connections;
  return tc;
}

/**
 * Cleans up connection state.
 *
 * No notifications.
 */
void
tcp_connection_cleanup (tcp_connection_t * tc)
{
  tcp_main_t *tm = &tcp_main;
  u32 tepi;
  transport_endpoint_t *tep;

  /* Cleanup local endpoint if this was an active connect */
  tepi = transport_endpoint_lookup (&tm->local_endpoints_table, &tc->c_lcl_ip,
				    clib_net_to_host_u16 (tc->c_lcl_port));
  if (tepi != TRANSPORT_ENDPOINT_INVALID_INDEX)
    {
      tep = pool_elt_at_index (tm->local_endpoints, tepi);
      transport_endpoint_table_del (&tm->local_endpoints_table, tep);
      transport_endpoint_del (tepi);
    }

  /* Check if connection is not yet fully established */
  if (tc->state == TCP_STATE_SYN_SENT)
    {
      /* Try to remove the half-open connection. If this is not the owning
       * thread, tc won't be removed. Retransmit or establish timers will
       * eventually expire and call again cleanup on the right thread. */
      tcp_half_open_connection_cleanup (tc);
    }
  else
    {
      int thread_index = tc->c_thread_index;

      /* Make sure all timers are cleared */
      tcp_connection_timers_reset (tc);

      /* Poison the entry */
      if (CLIB_DEBUG > 0)
	memset (tc, 0xFA, sizeof (*tc));
      pool_put (tm->connections[thread_index], tc);
    }
}

/**
 * Connection removal.
 *
 * This should be called only once connection enters CLOSED state. Note
 * that it notifies the session of the removal event, so if the goal is to
 * just remove the connection, call tcp_connection_cleanup instead.
 */
void
tcp_connection_del (tcp_connection_t * tc)
{
  TCP_EVT_DBG (TCP_EVT_DELETE, tc);
  stream_session_delete_notify (&tc->connection);
  tcp_connection_cleanup (tc);
}

tcp_connection_t *
tcp_connection_new (u8 thread_index)
{
  tcp_main_t *tm = vnet_get_tcp_main ();
  tcp_connection_t *tc;

  pool_get (tm->connections[thread_index], tc);
  memset (tc, 0, sizeof (*tc));
  tc->c_c_index = tc - tm->connections[thread_index];
  tc->c_thread_index = thread_index;
  return tc;
}

/** Notify session that connection has been reset.
 *
 * Switch state to closed and wait for session to call cleanup.
 */
void
tcp_connection_reset (tcp_connection_t * tc)
{
  TCP_EVT_DBG (TCP_EVT_RST_RCVD, tc);
  switch (tc->state)
    {
    case TCP_STATE_SYN_RCVD:
      /* Cleanup everything. App wasn't notified yet */
      stream_session_delete_notify (&tc->connection);
      tcp_connection_cleanup (tc);
      break;
    case TCP_STATE_SYN_SENT:
      stream_session_connect_notify (&tc->connection, 1 /* fail */ );
      tcp_connection_cleanup (tc);
      break;
    case TCP_STATE_ESTABLISHED:
    case TCP_STATE_CLOSE_WAIT:
    case TCP_STATE_FIN_WAIT_1:
    case TCP_STATE_FIN_WAIT_2:
    case TCP_STATE_CLOSING:
      tc->state = TCP_STATE_CLOSED;
      TCP_EVT_DBG (TCP_EVT_STATE_CHANGE, tc);

      /* Make sure all timers are cleared */
      tcp_connection_timers_reset (tc);
      stream_session_reset_notify (&tc->connection);

      /* Wait for cleanup from session layer but not forever */
      tcp_timer_update (tc, TCP_TIMER_WAITCLOSE, TCP_CLEANUP_TIME);
      break;
    case TCP_STATE_CLOSED:
      return;
    }
}

/**
 * Begin connection closing procedure.
 *
 * If at the end the connection is not in CLOSED state, it is not removed.
 * Instead, we rely on on TCP to advance through state machine to either
 * 1) LAST_ACK (passive close) whereby when the last ACK is received
 * tcp_connection_del is called. This notifies session of the delete and
 * calls cleanup.
 * 2) TIME_WAIT (active close) whereby after 2MSL the 2MSL timer triggers
 * and cleanup is called.
 *
 * N.B. Half-close connections are not supported
 */
void
tcp_connection_close (tcp_connection_t * tc)
{
  TCP_EVT_DBG (TCP_EVT_CLOSE, tc);

  /* Send/Program FIN if needed and switch state */
  switch (tc->state)
    {
    case TCP_STATE_SYN_SENT:
      tc->state = TCP_STATE_CLOSED;
      break;
    case TCP_STATE_SYN_RCVD:
      tcp_send_fin (tc);
      tc->state = TCP_STATE_FIN_WAIT_1;
      break;
    case TCP_STATE_ESTABLISHED:
      if (!stream_session_tx_fifo_max_dequeue (&tc->connection))
	tcp_send_fin (tc);
      else
	tc->flags |= TCP_CONN_FINPNDG;
      tc->state = TCP_STATE_FIN_WAIT_1;
      break;
    case TCP_STATE_CLOSE_WAIT:
      tcp_send_fin (tc);
      tc->state = TCP_STATE_LAST_ACK;
      break;
    case TCP_STATE_FIN_WAIT_1:
      break;
    default:
      clib_warning ("state: %u", tc->state);
    }

  TCP_EVT_DBG (TCP_EVT_STATE_CHANGE, tc);

  /* If in CLOSED and WAITCLOSE timer is not set, delete connection now */
  if (tc->timers[TCP_TIMER_WAITCLOSE] == TCP_TIMER_HANDLE_INVALID
      && tc->state == TCP_STATE_CLOSED)
    tcp_connection_del (tc);
}

void
tcp_session_close (u32 conn_index, u32 thread_index)
{
  tcp_connection_t *tc;
  tc = tcp_connection_get (conn_index, thread_index);
  tcp_connection_close (tc);
}

void
tcp_session_cleanup (u32 conn_index, u32 thread_index)
{
  tcp_connection_t *tc;
  tc = tcp_connection_get (conn_index, thread_index);

  /* Wait for the session tx events to clear */
  tc->state = TCP_STATE_CLOSED;
  TCP_EVT_DBG (TCP_EVT_STATE_CHANGE, tc);
  tcp_timer_update (tc, TCP_TIMER_WAITCLOSE, TCP_CLEANUP_TIME);
}

void *
ip_interface_get_first_ip (u32 sw_if_index, u8 is_ip4)
{
  ip_lookup_main_t *lm4 = &ip4_main.lookup_main;
  ip_lookup_main_t *lm6 = &ip6_main.lookup_main;
  ip_interface_address_t *ia = 0;

  if (is_ip4)
    {
      /* *INDENT-OFF* */
      foreach_ip_interface_address (lm4, ia, sw_if_index, 1 /* unnumbered */ ,
      ({
        return ip_interface_address_get_address (lm4, ia);
      }));
      /* *INDENT-ON* */
    }
  else
    {
      /* *INDENT-OFF* */
      foreach_ip_interface_address (lm6, ia, sw_if_index, 1 /* unnumbered */ ,
      ({
        ip6_address_t *rv;
        rv = ip_interface_address_get_address (lm6, ia);
        /* Trying to use a link-local ip6 src address is a fool's errand */
        if (!ip6_address_is_link_local_unicast (rv))
          return rv;
      }));
      /* *INDENT-ON* */
    }

  return 0;
}

#define PORT_MASK ((1 << 16)- 1)
/**
 * Allocate local port and add if successful add entry to local endpoint
 * table to mark the pair as used.
 */
int
tcp_allocate_local_port (ip46_address_t * ip)
{
  tcp_main_t *tm = vnet_get_tcp_main ();
  transport_endpoint_t *tep;
  u32 tei;
  u16 min = 1024, max = 65535;	/* XXX configurable ? */
  int tries, limit;

  limit = max - min;

  /* Only support active opens from thread 0 */
  ASSERT (vlib_get_thread_index () == 0);

  /* Search for first free slot */
  for (tries = 0; tries < limit; tries++)
    {
      u16 port = 0;

      /* Find a port in the specified range */
      while (1)
	{
	  port = random_u32 (&tm->port_allocator_seed) & PORT_MASK;
	  if (PREDICT_TRUE (port >= min && port < max))
	    break;
	}

      /* Look it up */
      tei = transport_endpoint_lookup (&tm->local_endpoints_table, ip, port);
      /* If not found, we're done */
      if (tei == TRANSPORT_ENDPOINT_INVALID_INDEX)
	{
	  clib_spinlock_lock_if_init (&tm->local_endpoints_lock);
	  tep = transport_endpoint_new ();
	  clib_memcpy (&tep->ip, ip, sizeof (*ip));
	  tep->port = port;
	  transport_endpoint_table_add (&tm->local_endpoints_table, tep,
					tep - tm->local_endpoints);
	  clib_spinlock_unlock_if_init (&tm->local_endpoints_lock);

	  return tep->port;
	}
    }
  return -1;
}

/**
 * Initialize all connection timers as invalid
 */
void
tcp_connection_timers_init (tcp_connection_t * tc)
{
  int i;

  /* Set all to invalid */
  for (i = 0; i < TCP_N_TIMERS; i++)
    {
      tc->timers[i] = TCP_TIMER_HANDLE_INVALID;
    }

  tc->rto = TCP_RTO_INIT;
}

/**
 * Stop all connection timers
 */
void
tcp_connection_timers_reset (tcp_connection_t * tc)
{
  int i;
  for (i = 0; i < TCP_N_TIMERS; i++)
    {
      tcp_timer_reset (tc, i);
    }
}

#if 0
typedef struct ip4_tcp_hdr
{
  ip4_header_t ip;
  tcp_header_t tcp;
} ip4_tcp_hdr_t;

typedef struct ip6_tcp_hdr
{
  ip6_header_t ip;
  tcp_header_t tcp;
} ip6_tcp_hdr_t;

static void
tcp_connection_select_lb_bucket (tcp_connection_t * tc, const dpo_id_t * dpo,
				 dpo_id_t * result)
{
  const dpo_id_t *choice;
  load_balance_t *lb;
  int hash;

  lb = load_balance_get (dpo->dpoi_index);
  if (tc->c_is_ip4)
    {
      ip4_tcp_hdr_t hdr;
      memset (&hdr, 0, sizeof (hdr));
      hdr.ip.protocol = IP_PROTOCOL_TCP;
      hdr.ip.address_pair.src.as_u32 = tc->c_lcl_ip.ip4.as_u32;
      hdr.ip.address_pair.dst.as_u32 = tc->c_rmt_ip.ip4.as_u32;
      hdr.tcp.src_port = tc->c_lcl_port;
      hdr.tcp.dst_port = tc->c_rmt_port;
      hash = ip4_compute_flow_hash (&hdr.ip, lb->lb_hash_config);
    }
  else
    {
      ip6_tcp_hdr_t hdr;
      memset (&hdr, 0, sizeof (hdr));
      hdr.ip.protocol = IP_PROTOCOL_TCP;
      clib_memcpy (&hdr.ip.src_address, &tc->c_lcl_ip.ip6,
		   sizeof (ip6_address_t));
      clib_memcpy (&hdr.ip.dst_address, &tc->c_rmt_ip.ip6,
		   sizeof (ip6_address_t));
      hdr.tcp.src_port = tc->c_lcl_port;
      hdr.tcp.dst_port = tc->c_rmt_port;
      hash = ip6_compute_flow_hash (&hdr.ip, lb->lb_hash_config);
    }
  choice = load_balance_get_bucket_i (lb, hash & lb->lb_n_buckets_minus_1);
  dpo_copy (result, choice);
}

fib_node_index_t
tcp_lookup_rmt_in_fib (tcp_connection_t * tc)
{
  fib_prefix_t prefix;
  u32 fib_index;

  clib_memcpy (&prefix.fp_addr, &tc->c_rmt_ip, sizeof (prefix.fp_addr));
  prefix.fp_proto = tc->c_is_ip4 ? FIB_PROTOCOL_IP4 : FIB_PROTOCOL_IP6;
  prefix.fp_len = tc->c_is_ip4 ? 32 : 128;
  fib_index = fib_table_find (prefix.fp_proto, tc->c_vrf);
  return fib_table_lookup (fib_index, &prefix);
}

static int
tcp_connection_stack_on_fib_entry (tcp_connection_t * tc)
{
  dpo_id_t choice = DPO_INVALID;
  u32 output_node_index;
  fib_entry_t *fe;

  fe = fib_entry_get (tc->c_rmt_fei);
  if (fe->fe_lb.dpoi_type != DPO_LOAD_BALANCE)
    return -1;

  tcp_connection_select_lb_bucket (tc, &fe->fe_lb, &choice);

  output_node_index =
    tc->c_is_ip4 ? tcp4_output_node.index : tcp6_output_node.index;
  dpo_stack_from_node (output_node_index, &tc->c_rmt_dpo, &choice);
  return 0;
}

/** Stack tcp connection on peer's fib entry.
 *
 * This ultimately populates the dpo the connection will use to send packets.
 */
static void
tcp_connection_fib_attach (tcp_connection_t * tc)
{
  tc->c_rmt_fei = tcp_lookup_rmt_in_fib (tc);

  ASSERT (tc->c_rmt_fei != FIB_NODE_INDEX_INVALID);

  tcp_connection_stack_on_fib_entry (tc);
}
#endif /* 0 */

/**
 * Initialize connection send variables.
 */
void
tcp_init_snd_vars (tcp_connection_t * tc)
{
  u32 time_now;

  /* Set random initial sequence */
  time_now = tcp_time_now ();
  tc->iss = random_u32 (&time_now);
  tc->snd_una = tc->iss;
  tc->snd_nxt = tc->iss + 1;
  tc->snd_una_max = tc->snd_nxt;
}

/** Initialize tcp connection variables
 *
 * Should be called after having received a msg from the peer, i.e., a SYN or
 * a SYNACK, such that connection options have already been exchanged. */
void
tcp_connection_init_vars (tcp_connection_t * tc)
{
  tcp_connection_timers_init (tc);
  tcp_init_mss (tc);
  scoreboard_init (&tc->sack_sb);
  tcp_cc_init (tc);
  if (tc->state == TCP_STATE_SYN_RCVD)
    tcp_init_snd_vars (tc);

  //  tcp_connection_fib_attach (tc);
}

int
tcp_connection_open (transport_endpoint_t * rmt)
{
  tcp_main_t *tm = vnet_get_tcp_main ();
  tcp_connection_t *tc;
  fib_prefix_t prefix;
  fib_node_index_t fei;
  u32 sw_if_index, fib_index;
  ip46_address_t lcl_addr;
  int lcl_port;

  /*
   * Find the local address and allocate port
   */
  memset (&lcl_addr, 0, sizeof (lcl_addr));

  /* Find a FIB path to the destination */
  clib_memcpy (&prefix.fp_addr, &rmt->ip, sizeof (rmt->ip));
  prefix.fp_proto = rmt->is_ip4 ? FIB_PROTOCOL_IP4 : FIB_PROTOCOL_IP6;
  prefix.fp_len = rmt->is_ip4 ? 32 : 128;

  fib_index = fib_table_find (prefix.fp_proto, rmt->vrf);
  if (fib_index == (u32) ~ 0)
    {
      clib_warning ("no fib table");
      return -1;
    }

  fei = fib_table_lookup (fib_index, &prefix);

  /* Couldn't find route to destination. Bail out. */
  if (fei == FIB_NODE_INDEX_INVALID)
    {
      clib_warning ("no route to destination");
      return -1;
    }

  sw_if_index = fib_entry_get_resolving_interface (fei);

  if (sw_if_index == (u32) ~ 0)
    {
      clib_warning ("no resolving interface for %U", format_ip46_address,
		    &rmt->ip, IP46_TYPE_IP4);
      return -1;
    }

  if (rmt->is_ip4)
    {
      ip4_address_t *ip4;
      int index;
      if (vec_len (tm->ip4_src_addresses))
	{
	  index = tm->last_v4_address_rotor++;
	  if (tm->last_v4_address_rotor >= vec_len (tm->ip4_src_addresses))
	    tm->last_v4_address_rotor = 0;
	  lcl_addr.ip4.as_u32 = tm->ip4_src_addresses[index].as_u32;
	}
      else
	{
	  ip4 = ip_interface_get_first_ip (sw_if_index, 1);
	  lcl_addr.ip4.as_u32 = ip4->as_u32;
	}
    }
  else
    {
      ip6_address_t *ip6;
      int index;

      if (vec_len (tm->ip6_src_addresses))
	{
	  index = tm->last_v6_address_rotor++;
	  if (tm->last_v6_address_rotor >= vec_len (tm->ip6_src_addresses))
	    tm->last_v6_address_rotor = 0;
	  clib_memcpy (&lcl_addr.ip6, &tm->ip6_src_addresses[index],
		       sizeof (*ip6));
	}
      else
	{
	  ip6 = ip_interface_get_first_ip (sw_if_index, 0);
	  if (ip6 == 0)
	    {
	      clib_warning ("no routable ip6 addresses on %U",
			    format_vnet_sw_if_index_name, vnet_get_main (),
			    sw_if_index);
	      return -1;
	    }

	  clib_memcpy (&lcl_addr.ip6, ip6, sizeof (*ip6));
	}
    }

  /* Allocate source port */
  lcl_port = tcp_allocate_local_port (&lcl_addr);
  if (lcl_port < 1)
    {
      clib_warning ("Failed to allocate src port");
      return -1;
    }

  /*
   * Create connection and send SYN
   */
  clib_spinlock_lock_if_init (&tm->half_open_lock);
  tc = tcp_half_open_connection_new ();
  clib_memcpy (&tc->c_rmt_ip, &rmt->ip, sizeof (ip46_address_t));
  clib_memcpy (&tc->c_lcl_ip, &lcl_addr, sizeof (ip46_address_t));
  tc->c_rmt_port = rmt->port;
  tc->c_lcl_port = clib_host_to_net_u16 (lcl_port);
  tc->c_is_ip4 = rmt->is_ip4;
  tc->c_transport_proto = TRANSPORT_PROTO_TCP;
  tc->c_vrf = rmt->vrf;
  /* The other connection vars will be initialized after SYN ACK */
  tcp_connection_timers_init (tc);

  TCP_EVT_DBG (TCP_EVT_OPEN, tc);
  tc->state = TCP_STATE_SYN_SENT;
  tcp_init_snd_vars (tc);
  tcp_send_syn (tc);
  clib_spinlock_unlock_if_init (&tm->half_open_lock);

  return tc->c_c_index;
}

int
tcp_session_open (transport_endpoint_t * tep)
{
  return tcp_connection_open (tep);
}

const char *tcp_dbg_evt_str[] = {
#define _(sym, str) str,
  foreach_tcp_dbg_evt
#undef _
};

const char *tcp_fsm_states[] = {
#define _(sym, str) str,
  foreach_tcp_fsm_state
#undef _
};

u8 *
format_tcp_state (u8 * s, va_list * args)
{
  u32 state = va_arg (*args, u32);

  if (state < TCP_N_STATES)
    s = format (s, "%s", tcp_fsm_states[state]);
  else
    s = format (s, "UNKNOWN (%d (0x%x))", state, state);
  return s;
}

const char *tcp_conn_timers[] = {
#define _(sym, str) str,
  foreach_tcp_timer
#undef _
};

u8 *
format_tcp_timers (u8 * s, va_list * args)
{
  tcp_connection_t *tc = va_arg (*args, tcp_connection_t *);
  int i, last = -1;

  for (i = 0; i < TCP_N_TIMERS; i++)
    if (tc->timers[i] != TCP_TIMER_HANDLE_INVALID)
      last = i;

  s = format (s, "[");
  for (i = 0; i < last; i++)
    {
      if (tc->timers[i] != TCP_TIMER_HANDLE_INVALID)
	s = format (s, "%s,", tcp_conn_timers[i]);
    }

  if (last >= 0)
    s = format (s, "%s]", tcp_conn_timers[i]);
  else
    s = format (s, "]");

  return s;
}

u8 *
format_tcp_congestion_status (u8 * s, va_list * args)
{
  tcp_connection_t *tc = va_arg (*args, tcp_connection_t *);
  if (tcp_in_recovery (tc))
    s = format (s, "recovery");
  else if (tcp_in_fastrecovery (tc))
    s = format (s, "fastrecovery");
  else
    s = format (s, "none");
  return s;
}

u8 *
format_tcp_vars (u8 * s, va_list * args)
{
  tcp_connection_t *tc = va_arg (*args, tcp_connection_t *);
  s = format (s, " snd_una %u snd_nxt %u snd_una_max %u",
	      tc->snd_una - tc->iss, tc->snd_nxt - tc->iss,
	      tc->snd_una_max - tc->iss);
  s = format (s, " rcv_nxt %u rcv_las %u\n",
	      tc->rcv_nxt - tc->irs, tc->rcv_las - tc->irs);
  s = format (s, " snd_wnd %u rcv_wnd %u snd_wl1 %u snd_wl2 %u\n",
	      tc->snd_wnd, tc->rcv_wnd, tc->snd_wl1 - tc->irs,
	      tc->snd_wl2 - tc->iss);
  s = format (s, " flight size %u send space %u rcv_wnd_av %d\n",
	      tcp_flight_size (tc), tcp_available_output_snd_space (tc),
	      tcp_rcv_wnd_available (tc));
  s = format (s, " cong %U ", format_tcp_congestion_status, tc);
  s = format (s, "cwnd %u ssthresh %u rtx_bytes %u bytes_acked %u\n",
	      tc->cwnd, tc->ssthresh, tc->snd_rxt_bytes, tc->bytes_acked);
  s = format (s, " prev_ssthresh %u snd_congestion %u dupack %u",
	      tc->prev_ssthresh, tc->snd_congestion - tc->iss,
	      tc->rcv_dupacks);
  s = format (s, " limited_transmit %u\n", tc->limited_transmit - tc->iss);
  s = format (s, " tsecr %u tsecr_last_ack %u\n", tc->rcv_opts.tsecr,
	      tc->tsecr_last_ack);
  s = format (s, " rto %u rto_boff %u srtt %u rttvar %u rtt_ts %u ", tc->rto,
	      tc->rto_boff, tc->srtt, tc->rttvar, tc->rtt_ts);
  s = format (s, "rtt_seq %u\n", tc->rtt_seq);
  s = format (s, " tsval_recent %u tsval_recent_age %u\n", tc->tsval_recent,
	      tcp_time_now () - tc->tsval_recent_age);
  s = format (s, " scoreboard: %U\n", format_tcp_scoreboard, &tc->sack_sb,
	      tc);
  if (vec_len (tc->snd_sacks))
    s = format (s, " sacks tx: %U\n", format_tcp_sacks, tc);

  return s;
}

u8 *
format_tcp_connection_id (u8 * s, va_list * args)
{
  tcp_connection_t *tc = va_arg (*args, tcp_connection_t *);
  if (!tc)
    return s;
  if (tc->c_is_ip4)
    {
      s = format (s, "[#%d][%s] %U:%d->%U:%d", tc->c_thread_index, "T",
		  format_ip4_address, &tc->c_lcl_ip4,
		  clib_net_to_host_u16 (tc->c_lcl_port), format_ip4_address,
		  &tc->c_rmt_ip4, clib_net_to_host_u16 (tc->c_rmt_port));
    }
  else
    {
      s = format (s, "[#%d][%s] %U:%d->%U:%d", tc->c_thread_index, "T",
		  format_ip6_address, &tc->c_lcl_ip6,
		  clib_net_to_host_u16 (tc->c_lcl_port), format_ip6_address,
		  &tc->c_rmt_ip6, clib_net_to_host_u16 (tc->c_rmt_port));
    }

  return s;
}

u8 *
format_tcp_connection (u8 * s, va_list * args)
{
  tcp_connection_t *tc = va_arg (*args, tcp_connection_t *);
  u32 verbose = va_arg (*args, u32);

  if (!tc)
    return s;
  s = format (s, "%-50U", format_tcp_connection_id, tc);
  if (verbose)
    {
      s = format (s, "%-15U", format_tcp_state, tc->state);
      if (verbose > 1)
	s = format (s, " %U\n%U", format_tcp_timers, tc, format_tcp_vars, tc);
    }

  return s;
}

u8 *
format_tcp_session (u8 * s, va_list * args)
{
  u32 tci = va_arg (*args, u32);
  u32 thread_index = va_arg (*args, u32);
  u32 verbose = va_arg (*args, u32);
  tcp_connection_t *tc;

  tc = tcp_connection_get (tci, thread_index);
  if (tc)
    s = format (s, "%U", format_tcp_connection, tc, verbose);
  else
    s = format (s, "empty\n");
  return s;
}

u8 *
format_tcp_listener_session (u8 * s, va_list * args)
{
  u32 tci = va_arg (*args, u32);
  tcp_connection_t *tc = tcp_listener_get (tci);
  return format (s, "%U", format_tcp_connection_id, tc);
}

u8 *
format_tcp_half_open_session (u8 * s, va_list * args)
{
  u32 tci = va_arg (*args, u32);
  tcp_connection_t *tc = tcp_half_open_connection_get (tci);
  return format (s, "%U", format_tcp_connection_id, tc);
}

u8 *
format_tcp_sacks (u8 * s, va_list * args)
{
  tcp_connection_t *tc = va_arg (*args, tcp_connection_t *);
  sack_block_t *sacks = tc->snd_sacks;
  sack_block_t *block;
  int i, len = 0;

  len = vec_len (sacks);
  for (i = 0; i < len - 1; i++)
    {
      block = &sacks[i];
      s = format (s, " start %u end %u\n", block->start - tc->irs,
		  block->end - tc->irs);
    }
  if (len)
    {
      block = &sacks[len - 1];
      s = format (s, " start %u end %u", block->start - tc->irs,
		  block->end - tc->irs);
    }
  return s;
}

u8 *
format_tcp_rcv_sacks (u8 * s, va_list * args)
{
  tcp_connection_t *tc = va_arg (*args, tcp_connection_t *);
  sack_block_t *sacks = tc->rcv_opts.sacks;
  sack_block_t *block;
  int i, len = 0;

  len = vec_len (sacks);
  for (i = 0; i < len - 1; i++)
    {
      block = &sacks[i];
      s = format (s, " start %u end %u\n", block->start - tc->iss,
		  block->end - tc->iss);
    }
  if (len)
    {
      block = &sacks[len - 1];
      s = format (s, " start %u end %u", block->start - tc->iss,
		  block->end - tc->iss);
    }
  return s;
}

u8 *
format_tcp_sack_hole (u8 * s, va_list * args)
{
  sack_scoreboard_hole_t *hole = va_arg (*args, sack_scoreboard_hole_t *);
  tcp_connection_t *tc = va_arg (*args, tcp_connection_t *);
  if (tc)
    s = format (s, "  [%u, %u]", hole->start - tc->iss, hole->end - tc->iss);
  else
    s = format (s, "  [%u, %u]", hole->start, hole->end);
  return s;
}

u8 *
format_tcp_scoreboard (u8 * s, va_list * args)
{
  sack_scoreboard_t *sb = va_arg (*args, sack_scoreboard_t *);
  tcp_connection_t *tc = va_arg (*args, tcp_connection_t *);
  sack_scoreboard_hole_t *hole;
  s = format (s, "sacked_bytes %u last_sacked_bytes %u lost_bytes %u\n",
	      sb->sacked_bytes, sb->last_sacked_bytes, sb->lost_bytes);
  s = format (s, " last_bytes_delivered %u high_sacked %u snd_una_adv %u\n",
	      sb->last_bytes_delivered, sb->high_sacked, sb->snd_una_adv);
  s = format (s, " cur_rxt_hole %u high_rxt %u rescue_rxt %u",
	      sb->cur_rxt_hole, sb->high_rxt, sb->rescue_rxt);

  hole = scoreboard_first_hole (sb);
  if (hole)
    s = format (s, "\n head %u tail %u holes:\n", sb->head, sb->tail);

  while (hole)
    {
      s = format (s, "%U", format_tcp_sack_hole, hole, tc);
      hole = scoreboard_next_hole (sb, hole);
    }

  return s;
}

transport_connection_t *
tcp_session_get_transport (u32 conn_index, u32 thread_index)
{
  tcp_connection_t *tc = tcp_connection_get (conn_index, thread_index);
  return &tc->connection;
}

transport_connection_t *
tcp_half_open_session_get_transport (u32 conn_index)
{
  tcp_connection_t *tc = tcp_half_open_connection_get (conn_index);
  return &tc->connection;
}

/**
 * Compute maximum segment size for session layer.
 *
 * Since the result needs to be the actual data length, it first computes
 * the tcp options to be used in the next burst and subtracts their
 * length from the connection's snd_mss.
 */
u16
tcp_session_send_mss (transport_connection_t * trans_conn)
{
  tcp_connection_t *tc = (tcp_connection_t *) trans_conn;

  /* Ensure snd_mss does accurately reflect the amount of data we can push
   * in a segment. This also makes sure that options are updated according to
   * the current state of the connection. */
  tcp_update_snd_mss (tc);

  return tc->snd_mss;
}

always_inline u32
tcp_round_snd_space (tcp_connection_t * tc, u32 snd_space)
{
  if (PREDICT_FALSE (tc->snd_wnd < tc->snd_mss))
    {
      return tc->snd_wnd <= snd_space ? tc->snd_wnd : 0;
    }

  /* If not snd_wnd constrained and we can't write at least a segment,
   * don't try at all */
  if (PREDICT_FALSE (snd_space < tc->snd_mss))
    return 0;

  /* round down to mss multiple */
  return snd_space - (snd_space % tc->snd_mss);
}

/**
 * Compute tx window session is allowed to fill.
 *
 * Takes into account available send space, snd_mss and the congestion
 * state of the connection. If possible, the value returned is a multiple
 * of snd_mss.
 *
 * @param tc tcp connection
 * @return number of bytes session is allowed to write
 */
u32
tcp_snd_space (tcp_connection_t * tc)
{
  int snd_space, snt_limited;

  if (PREDICT_TRUE (tcp_in_cong_recovery (tc) == 0))
    {
      snd_space = tcp_available_output_snd_space (tc);

      /* If we haven't gotten dupacks or if we did and have gotten sacked
       * bytes then we can still send as per Limited Transmit (RFC3042) */
      if (PREDICT_FALSE (tc->rcv_dupacks != 0
			 && (tcp_opts_sack_permitted (tc)
			     && tc->sack_sb.last_sacked_bytes == 0)))
	{
	  if (tc->rcv_dupacks == 1 && tc->limited_transmit != tc->snd_nxt)
	    tc->limited_transmit = tc->snd_nxt;
	  ASSERT (seq_leq (tc->limited_transmit, tc->snd_nxt));

	  snt_limited = tc->snd_nxt - tc->limited_transmit;
	  snd_space = clib_max (2 * tc->snd_mss - snt_limited, 0);
	}
      return tcp_round_snd_space (tc, snd_space);
    }

  if (tcp_in_recovery (tc))
    {
      tc->snd_nxt = tc->snd_una_max;
      snd_space = tcp_available_snd_wnd (tc) - tc->snd_rxt_bytes
	- (tc->snd_una_max - tc->snd_congestion);
      if (snd_space <= 0 || (tc->snd_una_max - tc->snd_una) >= tc->snd_wnd)
	return 0;
      return tcp_round_snd_space (tc, snd_space);
    }

  /* RFC 5681: When previously unsent data is available and the new value of
   * cwnd and the receiver's advertised window allow, a TCP SHOULD send 1*SMSS
   * bytes of previously unsent data. */
  if (tcp_in_fastrecovery (tc) && !tcp_fastrecovery_sent_1_smss (tc))
    {
      if (tcp_available_output_snd_space (tc) < tc->snd_mss)
	return 0;
      tcp_fastrecovery_1_smss_on (tc);
      return tc->snd_mss;
    }

  return 0;
}

u32
tcp_session_send_space (transport_connection_t * trans_conn)
{
  tcp_connection_t *tc = (tcp_connection_t *) trans_conn;
  return clib_min (tcp_snd_space (tc),
		   tc->snd_wnd - (tc->snd_nxt - tc->snd_una));
}

i32
tcp_rcv_wnd_available (tcp_connection_t * tc)
{
  return (i32) tc->rcv_wnd - (tc->rcv_nxt - tc->rcv_las);
}

u32
tcp_session_tx_fifo_offset (transport_connection_t * trans_conn)
{
  tcp_connection_t *tc = (tcp_connection_t *) trans_conn;

  ASSERT (seq_geq (tc->snd_nxt, tc->snd_una));

  /* This still works if fast retransmit is on */
  return (tc->snd_nxt - tc->snd_una);
}

/* *INDENT-OFF* */
const static transport_proto_vft_t tcp_proto = {
  .bind = tcp_session_bind,
  .unbind = tcp_session_unbind,
  .push_header = tcp_push_header,
  .get_connection = tcp_session_get_transport,
  .get_listener = tcp_session_get_listener,
  .get_half_open = tcp_half_open_session_get_transport,
  .open = tcp_session_open,
  .close = tcp_session_close,
  .cleanup = tcp_session_cleanup,
  .send_mss = tcp_session_send_mss,
  .send_space = tcp_session_send_space,
  .tx_fifo_offset = tcp_session_tx_fifo_offset,
  .format_connection = format_tcp_session,
  .format_listener = format_tcp_listener_session,
  .format_half_open = format_tcp_half_open_session,
};
/* *INDENT-ON* */

void
tcp_timer_keep_handler (u32 conn_index)
{
  u32 thread_index = vlib_get_thread_index ();
  tcp_connection_t *tc;

  tc = tcp_connection_get (conn_index, thread_index);
  tc->timers[TCP_TIMER_KEEP] = TCP_TIMER_HANDLE_INVALID;

  tcp_connection_close (tc);
}

void
tcp_timer_establish_handler (u32 conn_index)
{
  tcp_connection_t *tc;

  tc = tcp_half_open_connection_get (conn_index);
  if (tc)
    {
      ASSERT (tc->state == TCP_STATE_SYN_SENT);
      stream_session_connect_notify (&tc->connection, 1 /* fail */ );
    }
  else
    {
      tc = tcp_connection_get (conn_index, vlib_get_thread_index ());
      /* note: the connection may have already disappeared */
      if (PREDICT_FALSE (tc == 0))
	return;

      ASSERT (tc->state == TCP_STATE_SYN_RCVD);
      /* Start cleanup. App wasn't notified yet so use delete notify as
       * opposed to delete to cleanup session layer state. */
      stream_session_delete_notify (&tc->connection);
    }
  tc->timers[TCP_TIMER_ESTABLISH] = TCP_TIMER_HANDLE_INVALID;
  tcp_connection_cleanup (tc);
}

void
tcp_timer_waitclose_handler (u32 conn_index)
{
  u32 thread_index = vlib_get_thread_index ();
  tcp_connection_t *tc;

  tc = tcp_connection_get (conn_index, thread_index);
  if (!tc)
    return;
  tc->timers[TCP_TIMER_WAITCLOSE] = TCP_TIMER_HANDLE_INVALID;

  /* Session didn't come back with a close(). Send FIN either way
   * and switch to LAST_ACK. */
  if (tc->state == TCP_STATE_CLOSE_WAIT)
    {
      if (tc->flags & TCP_CONN_FINSNT)
	{
	  clib_warning ("FIN was sent and still in CLOSE WAIT. Weird!");
	}

      tcp_send_fin (tc);
      tc->state = TCP_STATE_LAST_ACK;

      /* Make sure we don't wait in LAST ACK forever */
      tcp_timer_set (tc, TCP_TIMER_WAITCLOSE, TCP_2MSL_TIME);

      /* Don't delete the connection yet */
      return;
    }

  tcp_connection_del (tc);
}

/* *INDENT-OFF* */
static timer_expiration_handler *timer_expiration_handlers[TCP_N_TIMERS] =
{
    tcp_timer_retransmit_handler,
    tcp_timer_delack_handler,
    tcp_timer_persist_handler,
    tcp_timer_keep_handler,
    tcp_timer_waitclose_handler,
    tcp_timer_retransmit_syn_handler,
    tcp_timer_establish_handler
};
/* *INDENT-ON* */

static void
tcp_expired_timers_dispatch (u32 * expired_timers)
{
  int i;
  u32 connection_index, timer_id;

  for (i = 0; i < vec_len (expired_timers); i++)
    {
      /* Get session index and timer id */
      connection_index = expired_timers[i] & 0x0FFFFFFF;
      timer_id = expired_timers[i] >> 28;

      TCP_EVT_DBG (TCP_EVT_TIMER_POP, connection_index, timer_id);

      /* Handle expiration */
      (*timer_expiration_handlers[timer_id]) (connection_index);
    }
}

void
tcp_initialize_timer_wheels (tcp_main_t * tm)
{
  tw_timer_wheel_16t_2w_512sl_t *tw;
  /* *INDENT-OFF* */
  foreach_vlib_main (({
    tw = &tm->timer_wheels[ii];
    tw_timer_wheel_init_16t_2w_512sl (tw, tcp_expired_timers_dispatch,
				      100e-3 /* timer period 100ms */ , ~0);
    tw->last_run_time = vlib_time_now (this_vlib_main);
  }));
  /* *INDENT-ON* */
}

clib_error_t *
tcp_main_enable (vlib_main_t * vm)
{
  tcp_main_t *tm = vnet_get_tcp_main ();
  ip_protocol_info_t *pi;
  ip_main_t *im = &ip_main;
  vlib_thread_main_t *vtm = vlib_get_thread_main ();
  clib_error_t *error = 0;
  u32 num_threads;
  int thread;
  tcp_connection_t *tc __attribute__ ((unused));
  u32 preallocated_connections_per_thread;

  if ((error = vlib_call_init_function (vm, ip_main_init)))
    return error;
  if ((error = vlib_call_init_function (vm, ip4_lookup_init)))
    return error;
  if ((error = vlib_call_init_function (vm, ip6_lookup_init)))
    return error;

  /*
   * Registrations
   */

  /* Register with IP */
  pi = ip_get_protocol_info (im, IP_PROTOCOL_TCP);
  if (pi == 0)
    return clib_error_return (0, "TCP protocol info AWOL");
  pi->format_header = format_tcp_header;
  pi->unformat_pg_edit = unformat_pg_tcp_header;

  ip4_register_protocol (IP_PROTOCOL_TCP, tcp4_input_node.index);
  ip6_register_protocol (IP_PROTOCOL_TCP, tcp6_input_node.index);

  /* Register as transport with session layer */
  session_register_transport (TRANSPORT_PROTO_TCP, 1, &tcp_proto);
  session_register_transport (TRANSPORT_PROTO_TCP, 0, &tcp_proto);

  /*
   * Initialize data structures
   */

  num_threads = 1 /* main thread */  + vtm->n_threads;
  vec_validate (tm->connections, num_threads - 1);

  /*
   * Preallocate connections. Assume that thread 0 won't
   * use preallocated threads when running multi-core
   */
  if (num_threads == 1)
    {
      thread = 0;
      preallocated_connections_per_thread = tm->preallocated_connections;
    }
  else
    {
      thread = 1;
      preallocated_connections_per_thread =
	tm->preallocated_connections / (num_threads - 1);
    }
  for (; thread < num_threads; thread++)
    {
      if (preallocated_connections_per_thread)
	pool_init_fixed (tm->connections[thread],
			 preallocated_connections_per_thread);
    }

  /*
   * Use a preallocated half-open connection pool?
   */
  if (tm->preallocated_half_open_connections)
    pool_init_fixed (tm->half_open_connections,
		     tm->preallocated_half_open_connections);

  /* Initialize per worker thread tx buffers (used for control messages) */
  vec_validate (tm->tx_buffers, num_threads - 1);

  /* Initialize timer wheels */
  vec_validate (tm->timer_wheels, num_threads - 1);
  tcp_initialize_timer_wheels (tm);

  /* Initialize clocks per tick for TCP timestamp. Used to compute
   * monotonically increasing timestamps. */
  tm->tstamp_ticks_per_clock = vm->clib_time.seconds_per_clock
    / TCP_TSTAMP_RESOLUTION;

  if (tm->local_endpoints_table_buckets == 0)
    tm->local_endpoints_table_buckets = 250000;
  if (tm->local_endpoints_table_memory == 0)
    tm->local_endpoints_table_memory = 512 << 20;

  clib_bihash_init_24_8 (&tm->local_endpoints_table, "local endpoint table",
			 tm->local_endpoints_table_buckets,
			 tm->local_endpoints_table_memory);

  /* Initialize [port-allocator] random number seed */
  tm->port_allocator_seed = (u32) clib_cpu_time_now ();

  if (num_threads > 1)
    {
      clib_spinlock_init (&tm->half_open_lock);
      clib_spinlock_init (&tm->local_endpoints_lock);
    }

  vec_validate (tm->tx_frames[0], num_threads - 1);
  vec_validate (tm->tx_frames[1], num_threads - 1);

  tm->bytes_per_buffer = vlib_buffer_free_list_buffer_size
    (vm, VLIB_BUFFER_DEFAULT_FREE_LIST_INDEX);

  vec_validate (tm->time_now, num_threads - 1);
  return error;
}

clib_error_t *
vnet_tcp_enable_disable (vlib_main_t * vm, u8 is_en)
{
  if (is_en)
    {
      if (tcp_main.is_enabled)
	return 0;

      return tcp_main_enable (vm);
    }
  else
    {
      tcp_main.is_enabled = 0;
    }

  return 0;
}

clib_error_t *
tcp_init (vlib_main_t * vm)
{
  tcp_main_t *tm = vnet_get_tcp_main ();
  tm->is_enabled = 0;
  tcp_api_reference ();
  return 0;
}

VLIB_INIT_FUNCTION (tcp_init);

static clib_error_t *
tcp_config_fn (vlib_main_t * vm, unformat_input_t * input)
{
  tcp_main_t *tm = vnet_get_tcp_main ();
  u64 tmp;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat
	  (input, "preallocated-connections %d",
	   &tm->preallocated_connections))
	;
      else if (unformat (input, "preallocated-half-open-connections %d",
			 &tm->preallocated_half_open_connections))
	;
      else if (unformat (input, "local-endpoints-table-memory %U",
			 unformat_memory_size, &tmp))
	{
	  if (tmp >= 0x100000000)
	    return clib_error_return (0, "memory size %llx (%lld) too large",
				      tmp, tmp);
	  tm->local_endpoints_table_memory = tmp;
	}
      else if (unformat (input, "local-endpoints-table-buckets %d",
			 &tm->local_endpoints_table_buckets))
	;


      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }
  return 0;
}

VLIB_CONFIG_FUNCTION (tcp_config_fn, "tcp");


/**
 * \brief Configure an ipv4 source address range
 * @param vm vlib_main_t pointer
 * @param start first ipv4 address in the source address range
 * @param end last ipv4 address in the source address range
 * @param table_id VRF / table ID, 0 for the default FIB
 * @return 0 if all OK, else an error indication from api_errno.h
 */

int
tcp_configure_v4_source_address_range (vlib_main_t * vm,
				       ip4_address_t * start,
				       ip4_address_t * end, u32 table_id)
{
  tcp_main_t *tm = vnet_get_tcp_main ();
  vnet_main_t *vnm = vnet_get_main ();
  u32 start_host_byte_order, end_host_byte_order;
  fib_prefix_t prefix;
  vnet_sw_interface_t *si;
  fib_node_index_t fei;
  u32 fib_index = 0;
  u32 sw_if_index;
  int rv;
  int vnet_proxy_arp_add_del (ip4_address_t * lo_addr,
			      ip4_address_t * hi_addr, u32 fib_index,
			      int is_del);

  memset (&prefix, 0, sizeof (prefix));

  fib_index = fib_table_find (FIB_PROTOCOL_IP4, table_id);

  if (fib_index == ~0)
    return VNET_API_ERROR_NO_SUCH_FIB;

  start_host_byte_order = clib_net_to_host_u32 (start->as_u32);
  end_host_byte_order = clib_net_to_host_u32 (end->as_u32);

  /* sanity check for reversed args or some such */
  if ((end_host_byte_order - start_host_byte_order) > (10 << 10))
    return VNET_API_ERROR_INVALID_ARGUMENT;

  /* Lookup the last address, to identify the interface involved */
  prefix.fp_len = 32;
  prefix.fp_proto = FIB_PROTOCOL_IP4;
  memcpy (&prefix.fp_addr.ip4, end, sizeof (ip4_address_t));

  fei = fib_table_lookup (fib_index, &prefix);

  /* Couldn't find route to destination. Bail out. */
  if (fei == FIB_NODE_INDEX_INVALID)
    return VNET_API_ERROR_NEXT_HOP_NOT_IN_FIB;

  sw_if_index = fib_entry_get_resolving_interface (fei);

  /* Enable proxy arp on the interface */
  si = vnet_get_sw_interface (vnm, sw_if_index);
  si->flags |= VNET_SW_INTERFACE_FLAG_PROXY_ARP;

  /* Configure proxy arp across the range */
  rv = vnet_proxy_arp_add_del (start, end, fib_index, 0 /* is_del */ );

  if (rv)
    return rv;

  do
    {
      dpo_id_t dpo = DPO_INVALID;

      vec_add1 (tm->ip4_src_addresses, start[0]);

      /* Add local adjacencies for the range */

      receive_dpo_add_or_lock (DPO_PROTO_IP4, ~0 /* sw_if_index */ ,
			       NULL, &dpo);
      prefix.fp_len = 32;
      prefix.fp_proto = FIB_PROTOCOL_IP4;
      prefix.fp_addr.ip4.as_u32 = start->as_u32;

      fib_table_entry_special_dpo_update (fib_index,
					  &prefix,
					  FIB_SOURCE_API,
					  FIB_ENTRY_FLAG_EXCLUSIVE, &dpo);
      dpo_reset (&dpo);

      start_host_byte_order++;
      start->as_u32 = clib_host_to_net_u32 (start_host_byte_order);
    }
  while (start_host_byte_order <= end_host_byte_order);

  return 0;
}

/**
 * \brief Configure an ipv6 source address range
 * @param vm vlib_main_t pointer
 * @param start first ipv6 address in the source address range
 * @param end last ipv6 address in the source address range
 * @param table_id VRF / table ID, 0 for the default FIB
 * @return 0 if all OK, else an error indication from api_errno.h
 */

int
tcp_configure_v6_source_address_range (vlib_main_t * vm,
				       ip6_address_t * start,
				       ip6_address_t * end, u32 table_id)
{
  tcp_main_t *tm = vnet_get_tcp_main ();
  fib_prefix_t prefix;
  u32 fib_index = 0;
  fib_node_index_t fei;
  u32 sw_if_index;

  memset (&prefix, 0, sizeof (prefix));

  fib_index = fib_table_find (FIB_PROTOCOL_IP6, table_id);

  if (fib_index == ~0)
    return VNET_API_ERROR_NO_SUCH_FIB;

  while (1)
    {
      int i;
      ip6_address_t tmp;
      dpo_id_t dpo = DPO_INVALID;

      /* Remember this address */
      vec_add1 (tm->ip6_src_addresses, start[0]);

      /* Lookup the prefix, to identify the interface involved */
      prefix.fp_len = 128;
      prefix.fp_proto = FIB_PROTOCOL_IP6;
      memcpy (&prefix.fp_addr.ip6, start, sizeof (ip6_address_t));

      fei = fib_table_lookup (fib_index, &prefix);

      /* Couldn't find route to destination. Bail out. */
      if (fei == FIB_NODE_INDEX_INVALID)
	return VNET_API_ERROR_NEXT_HOP_NOT_IN_FIB;

      sw_if_index = fib_entry_get_resolving_interface (fei);

      if (sw_if_index == (u32) ~ 0)
	return VNET_API_ERROR_NO_MATCHING_INTERFACE;

      /* Add a proxy neighbor discovery entry for this address */
      ip6_neighbor_proxy_add_del (sw_if_index, start, 0 /* is_del */ );

      /* Add a receive adjacency for this address */
      receive_dpo_add_or_lock (DPO_PROTO_IP6, ~0 /* sw_if_index */ ,
			       NULL, &dpo);

      fib_table_entry_special_dpo_update (fib_index,
					  &prefix,
					  FIB_SOURCE_API,
					  FIB_ENTRY_FLAG_EXCLUSIVE, &dpo);
      dpo_reset (&dpo);

      /* Done with the entire range? */
      if (!memcmp (start, end, sizeof (start[0])))
	break;

      /* Increment the address. DGMS. */
      tmp = start[0];
      for (i = 15; i >= 0; i--)
	{
	  tmp.as_u8[i] += 1;
	  if (tmp.as_u8[i] != 0)
	    break;
	}
      start[0] = tmp;
    }
  return 0;
}

static clib_error_t *
tcp_src_address (vlib_main_t * vm,
		 unformat_input_t * input, vlib_cli_command_t * cmd_arg)
{
  ip4_address_t v4start, v4end;
  ip6_address_t v6start, v6end;
  u32 table_id = 0;
  int v4set = 0;
  int v6set = 0;
  int rv;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%U - %U", unformat_ip4_address, &v4start,
		    unformat_ip4_address, &v4end))
	v4set = 1;
      else if (unformat (input, "%U", unformat_ip4_address, &v4start))
	{
	  memcpy (&v4end, &v4start, sizeof (v4start));
	  v4set = 1;
	}
      else if (unformat (input, "%U - %U", unformat_ip6_address, &v6start,
			 unformat_ip6_address, &v6end))
	v6set = 1;
      else if (unformat (input, "%U", unformat_ip6_address, &v6start))
	{
	  memcpy (&v6end, &v6start, sizeof (v4start));
	  v6set = 1;
	}
      else if (unformat (input, "fib-table %d", &table_id))
	;
      else
	break;
    }

  if (!v4set && !v6set)
    return clib_error_return (0, "at least one v4 or v6 address required");

  if (v4set)
    {
      rv = tcp_configure_v4_source_address_range (vm, &v4start, &v4end,
						  table_id);
      switch (rv)
	{
	case 0:
	  break;

	case VNET_API_ERROR_NO_SUCH_FIB:
	  return clib_error_return (0, "Invalid table-id %d", table_id);

	case VNET_API_ERROR_INVALID_ARGUMENT:
	  return clib_error_return (0, "Invalid address range %U - %U",
				    format_ip4_address, &v4start,
				    format_ip4_address, &v4end);
	default:
	  return clib_error_return (0, "error %d", rv);
	  break;
	}
    }
  if (v6set)
    {
      rv = tcp_configure_v6_source_address_range (vm, &v6start, &v6end,
						  table_id);
      switch (rv)
	{
	case 0:
	  break;

	case VNET_API_ERROR_NO_SUCH_FIB:
	  return clib_error_return (0, "Invalid table-id %d", table_id);

	default:
	  return clib_error_return (0, "error %d", rv);
	  break;
	}
    }
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (tcp_src_address_command, static) =
{
  .path = "tcp src-address",
  .short_help = "tcp src-address <ip-addr> [- <ip-addr>] add src address range",
  .function = tcp_src_address,
};
/* *INDENT-ON* */

static u8 *
tcp_scoreboard_dump_trace (u8 * s, sack_scoreboard_t * sb)
{
#if TCP_SCOREBOARD_TRACE

  scoreboard_trace_elt_t *block;
  int i = 0;

  if (!sb->trace)
    return s;

  s = format (s, "scoreboard trace:");
  vec_foreach (block, sb->trace)
  {
    s = format (s, "{%u, %u, %u, %u, %u}, ", block->start, block->end,
		block->ack, block->snd_una_max, block->group);
    if ((++i % 3) == 0)
      s = format (s, "\n");
  }
  return s;
#else
  return 0;
#endif
}

static clib_error_t *
tcp_show_scoreboard_trace_fn (vlib_main_t * vm, unformat_input_t * input,
			      vlib_cli_command_t * cmd_arg)
{
  transport_connection_t *tconn = 0;
  tcp_connection_t *tc;
  u8 *s = 0;
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%U", unformat_transport_connection, &tconn,
		    TRANSPORT_PROTO_TCP))
	;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }

  if (!TCP_SCOREBOARD_TRACE)
    {
      vlib_cli_output (vm, "scoreboard tracing not enabled");
      return 0;
    }

  tc = tcp_get_connection_from_transport (tconn);
  s = tcp_scoreboard_dump_trace (s, &tc->sack_sb);
  vlib_cli_output (vm, "%v", s);
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (tcp_show_scoreboard_trace_command, static) =
{
  .path = "show tcp scoreboard trace",
  .short_help = "show tcp scoreboard trace <connection>",
  .function = tcp_show_scoreboard_trace_fn,
};
/* *INDENT-ON* */

u8 *
tcp_scoreboard_replay (u8 * s, tcp_connection_t * tc, u8 verbose)
{
  int i, trace_len;
  scoreboard_trace_elt_t *trace;
  u32 next_ack, left, group, has_new_ack = 0;
  tcp_connection_t _dummy_tc, *dummy_tc = &_dummy_tc;
  sack_block_t *block;

  if (!tc)
    return s;

  memset (dummy_tc, 0, sizeof (*dummy_tc));
  tcp_connection_timers_init (dummy_tc);
  scoreboard_init (&dummy_tc->sack_sb);
  dummy_tc->rcv_opts.flags |= TCP_OPTS_FLAG_SACK;

#if TCP_SCOREBOARD_TRACE
  trace = tc->sack_sb.trace;
  trace_len = vec_len (tc->sack_sb.trace);
#else
  trace = 0;
  trace_len = 0;
#endif

  for (i = 0; i < trace_len; i++)
    {
      if (trace[i].ack != 0)
	{
	  dummy_tc->snd_una = trace[i].ack - 1448;
	  dummy_tc->snd_una_max = trace[i].ack;
	}
    }

  left = 0;
  while (left < trace_len)
    {
      group = trace[left].group;
      vec_reset_length (dummy_tc->rcv_opts.sacks);
      has_new_ack = 0;
      while (trace[left].group == group)
	{
	  if (trace[left].ack != 0)
	    {
	      if (verbose)
		s = format (s, "Adding ack %u, snd_una_max %u, segs: ",
			    trace[left].ack, trace[left].snd_una_max);
	      dummy_tc->snd_una_max = trace[left].snd_una_max;
	      next_ack = trace[left].ack;
	      has_new_ack = 1;
	    }
	  else
	    {
	      if (verbose)
		s = format (s, "[%u, %u], ", trace[left].start,
			    trace[left].end);
	      vec_add2 (dummy_tc->rcv_opts.sacks, block, 1);
	      block->start = trace[left].start;
	      block->end = trace[left].end;
	    }
	  left++;
	}

      /* Push segments */
      tcp_rcv_sacks (dummy_tc, next_ack);
      if (has_new_ack)
	dummy_tc->snd_una = next_ack + dummy_tc->sack_sb.snd_una_adv;

      if (verbose)
	s = format (s, "result: %U", format_tcp_scoreboard,
		    &dummy_tc->sack_sb);

    }
  s = format (s, "result: %U", format_tcp_scoreboard, &dummy_tc->sack_sb);

  return s;
}

static clib_error_t *
tcp_scoreboard_trace_fn (vlib_main_t * vm, unformat_input_t * input,
			 vlib_cli_command_t * cmd_arg)
{
  transport_connection_t *tconn = 0;
  tcp_connection_t *tc = 0;
  u8 *str = 0;
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%U", unformat_transport_connection, &tconn,
		    TRANSPORT_PROTO_TCP))
	;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }

  if (!TCP_SCOREBOARD_TRACE)
    {
      vlib_cli_output (vm, "scoreboard tracing not enabled");
      return 0;
    }

  tc = tcp_get_connection_from_transport (tconn);
  if (!tc)
    {
      vlib_cli_output (vm, "connection not found");
      return 0;
    }
  str = tcp_scoreboard_replay (str, tc, 1);
  vlib_cli_output (vm, "%v", str);
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (tcp_replay_scoreboard_command, static) =
{
  .path = "tcp replay scoreboard",
  .short_help = "tcp replay scoreboard <connection>",
  .function = tcp_scoreboard_trace_fn,
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
