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

typedef struct
{
  fib_protocol_t nh_proto;
  vnet_link_t link_type;
  ip46_address_t ip;
  u32 sw_if_index;
  u8 is_add;
} tcp_add_del_adj_args_t;

static void
tcp_add_del_adj_cb (tcp_add_del_adj_args_t * args)
{
  u32 ai;
  if (args->is_add)
    {
      adj_nbr_add_or_lock (args->nh_proto, args->link_type, &args->ip,
			   args->sw_if_index);
    }
  else
    {
      ai = adj_nbr_find (FIB_PROTOCOL_IP6, VNET_LINK_IP6, &args->ip,
			 args->sw_if_index);
      if (ai != ADJ_INDEX_INVALID)
	adj_unlock (ai);
    }
}

static void
tcp_add_del_adjacency (tcp_connection_t * tc, u8 is_add)
{
  tcp_add_del_adj_args_t args = {
    .nh_proto = FIB_PROTOCOL_IP6,
    .link_type = VNET_LINK_IP6,
    .ip = tc->c_rmt_ip,
    .sw_if_index = tc->sw_if_index,
    .is_add = is_add
  };
  vlib_rpc_call_main_thread (tcp_add_del_adj_cb, (u8 *) & args,
			     sizeof (args));
}

static u32
tcp_connection_bind (u32 session_index, transport_endpoint_t * lcl)
{
  tcp_main_t *tm = &tcp_main;
  tcp_connection_t *listener;
  void *iface_ip;

  pool_get (tm->listener_pool, listener);
  clib_memset (listener, 0, sizeof (*listener));

  listener->c_c_index = listener - tm->listener_pool;
  listener->c_lcl_port = lcl->port;

  /* If we are provided a sw_if_index, bind using one of its ips */
  if (ip_is_zero (&lcl->ip, 1) && lcl->sw_if_index != ENDPOINT_INVALID_INDEX)
    {
      if ((iface_ip = ip_interface_get_first_ip (lcl->sw_if_index,
						 lcl->is_ip4)))
	ip_set (&lcl->ip, iface_ip, lcl->is_ip4);
    }
  ip_copy (&listener->c_lcl_ip, &lcl->ip, lcl->is_ip4);
  listener->c_is_ip4 = lcl->is_ip4;
  listener->c_proto = TRANSPORT_PROTO_TCP;
  listener->c_s_index = session_index;
  listener->c_fib_index = lcl->fib_index;
  listener->state = TCP_STATE_LISTEN;

  tcp_connection_timers_init (listener);

  TCP_EVT_DBG (TCP_EVT_BIND, listener);

  return listener->c_c_index;
}

static u32
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
    clib_memset (tc, 0xFA, sizeof (*tc));

  pool_put_index (tm->listener_pool, listener_index);
}

static u32
tcp_session_unbind (u32 listener_index)
{
  tcp_connection_unbind (listener_index);
  return 0;
}

static transport_connection_t *
tcp_session_get_listener (u32 listener_index)
{
  tcp_main_t *tm = vnet_get_tcp_main ();
  tcp_connection_t *tc;
  tc = pool_elt_at_index (tm->listener_pool, listener_index);
  return &tc->connection;
}

/**
 * Cleanup half-open connection
 *
 */
static void
tcp_half_open_connection_del (tcp_connection_t * tc)
{
  tcp_main_t *tm = vnet_get_tcp_main ();
  clib_spinlock_lock_if_init (&tm->half_open_lock);
  pool_put_index (tm->half_open_connections, tc->c_c_index);
  if (CLIB_DEBUG)
    clib_memset (tc, 0xFA, sizeof (*tc));
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
  tcp_timer_reset (tc, TCP_TIMER_ESTABLISH_AO);
  tcp_timer_reset (tc, TCP_TIMER_RETRANSMIT_SYN);
  tcp_half_open_connection_del (tc);
  return 0;
}

static tcp_connection_t *
tcp_half_open_connection_new (void)
{
  tcp_main_t *tm = vnet_get_tcp_main ();
  tcp_connection_t *tc = 0;
  ASSERT (vlib_get_thread_index () == 0);
  pool_get (tm->half_open_connections, tc);
  clib_memset (tc, 0, sizeof (*tc));
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

  /* Cleanup local endpoint if this was an active connect */
  transport_endpoint_cleanup (TRANSPORT_PROTO_TCP, &tc->c_lcl_ip,
			      tc->c_lcl_port);

  /* Check if connection is not yet fully established */
  if (tc->state == TCP_STATE_SYN_SENT)
    {
      /* Try to remove the half-open connection. If this is not the owning
       * thread, tc won't be removed. Retransmit or establish timers will
       * eventually expire and call again cleanup on the right thread. */
      if (tcp_half_open_connection_cleanup (tc))
	tc->flags |= TCP_CONN_HALF_OPEN_DONE;
    }
  else
    {
      int thread_index = tc->c_thread_index;

      /* Make sure all timers are cleared */
      tcp_connection_timers_reset (tc);

      if (!tc->c_is_ip4 && ip6_address_is_link_local_unicast (&tc->c_rmt_ip6))
	tcp_add_del_adjacency (tc, 0);

      /* Poison the entry */
      if (CLIB_DEBUG > 0)
	clib_memset (tc, 0xFA, sizeof (*tc));
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
  session_transport_delete_notify (&tc->connection);
  tcp_connection_cleanup (tc);
}

tcp_connection_t *
tcp_connection_alloc (u8 thread_index)
{
  tcp_main_t *tm = vnet_get_tcp_main ();
  tcp_connection_t *tc;

  pool_get (tm->connections[thread_index], tc);
  clib_memset (tc, 0, sizeof (*tc));
  tc->c_c_index = tc - tm->connections[thread_index];
  tc->c_thread_index = thread_index;
  return tc;
}

void
tcp_connection_free (tcp_connection_t * tc)
{
  tcp_main_t *tm = &tcp_main;
  pool_put (tm->connections[tc->c_thread_index], tc);
  if (CLIB_DEBUG > 0)
    clib_memset (tc, 0xFA, sizeof (*tc));
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
      session_transport_delete_notify (&tc->connection);
      tcp_connection_cleanup (tc);
      break;
    case TCP_STATE_SYN_SENT:
      session_stream_connect_notify (&tc->connection, 1 /* fail */ );
      tcp_connection_cleanup (tc);
      break;
    case TCP_STATE_ESTABLISHED:
      tcp_connection_timers_reset (tc);
      /* Set the cleanup timer, in case the session layer/app don't
       * cleanly close the connection */
      tcp_timer_set (tc, TCP_TIMER_WAITCLOSE, TCP_CLOSEWAIT_TIME);
      session_transport_reset_notify (&tc->connection);
      tcp_connection_set_state (tc, TCP_STATE_CLOSED);
      break;
    case TCP_STATE_CLOSE_WAIT:
    case TCP_STATE_FIN_WAIT_1:
    case TCP_STATE_FIN_WAIT_2:
    case TCP_STATE_CLOSING:
    case TCP_STATE_LAST_ACK:
      tcp_connection_timers_reset (tc);
      tcp_timer_set (tc, TCP_TIMER_WAITCLOSE, TCP_CLOSEWAIT_TIME);
      /* Make sure we mark the session as closed. In some states we may
       * be still trying to send data */
      session_transport_closed_notify (&tc->connection);
      tcp_connection_set_state (tc, TCP_STATE_CLOSED);
      break;
    case TCP_STATE_CLOSED:
      break;
    default:
      TCP_DBG ("reset state: %u", tc->state);
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
      /* Try to cleanup. If not on the right thread, mark as half-open done.
       * Connection will be cleaned up when establish timer pops */
      tcp_connection_cleanup (tc);
      break;
    case TCP_STATE_SYN_RCVD:
      tcp_connection_timers_reset (tc);
      tcp_send_fin (tc);
      tcp_connection_set_state (tc, TCP_STATE_FIN_WAIT_1);
      tcp_timer_update (tc, TCP_TIMER_WAITCLOSE, TCP_FINWAIT1_TIME);
      break;
    case TCP_STATE_ESTABLISHED:
      if (!session_tx_fifo_max_dequeue (&tc->connection))
	tcp_send_fin (tc);
      else
	tc->flags |= TCP_CONN_FINPNDG;
      tcp_connection_set_state (tc, TCP_STATE_FIN_WAIT_1);
      /* Set a timer in case the peer stops responding. Otherwise the
       * connection will be stuck here forever. */
      ASSERT (tc->timers[TCP_TIMER_WAITCLOSE] == TCP_TIMER_HANDLE_INVALID);
      tcp_timer_set (tc, TCP_TIMER_WAITCLOSE, TCP_FINWAIT1_TIME);
      break;
    case TCP_STATE_CLOSE_WAIT:
      if (!session_tx_fifo_max_dequeue (&tc->connection))
	{
	  tcp_send_fin (tc);
	  tcp_connection_timers_reset (tc);
	  tcp_connection_set_state (tc, TCP_STATE_LAST_ACK);
	  tcp_timer_update (tc, TCP_TIMER_WAITCLOSE, TCP_2MSL_TIME);
	}
      else
	tc->flags |= TCP_CONN_FINPNDG;
      break;
    case TCP_STATE_FIN_WAIT_1:
      tcp_timer_update (tc, TCP_TIMER_WAITCLOSE, TCP_2MSL_TIME);
      break;
    case TCP_STATE_CLOSED:
      tcp_connection_timers_reset (tc);
      /* Delete connection but instead of doing it now wait until next
       * dispatch cycle to give the session layer a chance to clear
       * unhandled events */
      tcp_timer_update (tc, TCP_TIMER_WAITCLOSE, TCP_CLEANUP_TIME);
      break;
    default:
      TCP_DBG ("state: %u", tc->state);
    }
}

static void
tcp_session_close (u32 conn_index, u32 thread_index)
{
  tcp_connection_t *tc;
  tc = tcp_connection_get (conn_index, thread_index);
  tcp_connection_close (tc);
}

static void
tcp_session_cleanup (u32 conn_index, u32 thread_index)
{
  tcp_connection_t *tc;
  tc = tcp_connection_get (conn_index, thread_index);
  tcp_connection_set_state (tc, TCP_STATE_CLOSED);
  tcp_connection_cleanup (tc);
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
      clib_memset (&hdr, 0, sizeof (hdr));
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
      clib_memset (&hdr, 0, sizeof (hdr));
      hdr.ip.protocol = IP_PROTOCOL_TCP;
      clib_memcpy_fast (&hdr.ip.src_address, &tc->c_lcl_ip.ip6,
			sizeof (ip6_address_t));
      clib_memcpy_fast (&hdr.ip.dst_address, &tc->c_rmt_ip.ip6,
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

  clib_memcpy_fast (&prefix.fp_addr, &tc->c_rmt_ip, sizeof (prefix.fp_addr));
  prefix.fp_proto = tc->c_is_ip4 ? FIB_PROTOCOL_IP4 : FIB_PROTOCOL_IP6;
  prefix.fp_len = tc->c_is_ip4 ? 32 : 128;
  fib_index = fib_table_find (prefix.fp_proto, tc->c_fib_index);
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

static void
tcp_cc_init (tcp_connection_t * tc)
{
  tc->cc_algo = tcp_cc_algo_get (tcp_main.cc_algo);
  tc->cc_algo->init (tc);
}

void
tcp_cc_algo_register (tcp_cc_algorithm_type_e type,
		      const tcp_cc_algorithm_t * vft)
{
  tcp_main_t *tm = vnet_get_tcp_main ();
  vec_validate (tm->cc_algos, type);

  tm->cc_algos[type] = *vft;
}

tcp_cc_algorithm_t *
tcp_cc_algo_get (tcp_cc_algorithm_type_e type)
{
  tcp_main_t *tm = vnet_get_tcp_main ();
  return &tm->cc_algos[type];
}


/**
 * Initialize connection send variables.
 */
void
tcp_init_snd_vars (tcp_connection_t * tc)
{
  u32 time_now;

  /*
   * We use the time to randomize iss and for setting up the initial
   * timestamp. Make sure it's updated otherwise syn and ack in the
   * handshake may make it look as if time has flown in the opposite
   * direction for us.
   */
  tcp_set_time_now (tcp_get_worker (vlib_get_thread_index ()));
  time_now = tcp_time_now ();

  tc->iss = random_u32 (&time_now);
  tc->snd_una = tc->iss;
  tc->snd_nxt = tc->iss + 1;
  tc->snd_una_max = tc->snd_nxt;
  tc->srtt = 0;
}

void
tcp_enable_pacing (tcp_connection_t * tc)
{
  u32 initial_bucket, byte_rate;
  initial_bucket = 16 * tc->snd_mss;
  byte_rate = 2 << 16;
  transport_connection_tx_pacer_init (&tc->connection, byte_rate,
				      initial_bucket);
  tc->mrtt_us = (u32) ~ 0;
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

  if (!tc->c_is_ip4 && ip6_address_is_link_local_unicast (&tc->c_rmt_ip6))
    tcp_add_del_adjacency (tc, 1);

  /*  tcp_connection_fib_attach (tc); */

  if (transport_connection_is_tx_paced (&tc->connection)
      || tcp_main.tx_pacing)
    tcp_enable_pacing (tc);
}

static int
tcp_alloc_custom_local_endpoint (tcp_main_t * tm, ip46_address_t * lcl_addr,
				 u16 * lcl_port, u8 is_ip4)
{
  int index, port;
  if (is_ip4)
    {
      index = tm->last_v4_address_rotor++;
      if (tm->last_v4_address_rotor >= vec_len (tm->ip4_src_addresses))
	tm->last_v4_address_rotor = 0;
      lcl_addr->ip4.as_u32 = tm->ip4_src_addresses[index].as_u32;
    }
  else
    {
      index = tm->last_v6_address_rotor++;
      if (tm->last_v6_address_rotor >= vec_len (tm->ip6_src_addresses))
	tm->last_v6_address_rotor = 0;
      clib_memcpy_fast (&lcl_addr->ip6, &tm->ip6_src_addresses[index],
			sizeof (ip6_address_t));
    }
  port = transport_alloc_local_port (TRANSPORT_PROTO_TCP, lcl_addr);
  if (port < 1)
    {
      clib_warning ("Failed to allocate src port");
      return -1;
    }
  *lcl_port = port;
  return 0;
}

static int
tcp_session_open (transport_endpoint_cfg_t * rmt)
{
  tcp_main_t *tm = vnet_get_tcp_main ();
  tcp_connection_t *tc;
  ip46_address_t lcl_addr;
  u16 lcl_port;
  int rv;

  /*
   * Allocate local endpoint
   */
  if ((rmt->is_ip4 && vec_len (tm->ip4_src_addresses))
      || (!rmt->is_ip4 && vec_len (tm->ip6_src_addresses)))
    rv = tcp_alloc_custom_local_endpoint (tm, &lcl_addr, &lcl_port,
					  rmt->is_ip4);
  else
    rv = transport_alloc_local_endpoint (TRANSPORT_PROTO_TCP,
					 rmt, &lcl_addr, &lcl_port);

  if (rv)
    return -1;

  /*
   * Create connection and send SYN
   */
  clib_spinlock_lock_if_init (&tm->half_open_lock);
  tc = tcp_half_open_connection_new ();
  ip_copy (&tc->c_rmt_ip, &rmt->ip, rmt->is_ip4);
  ip_copy (&tc->c_lcl_ip, &lcl_addr, rmt->is_ip4);
  tc->c_rmt_port = rmt->port;
  tc->c_lcl_port = clib_host_to_net_u16 (lcl_port);
  tc->c_is_ip4 = rmt->is_ip4;
  tc->c_proto = TRANSPORT_PROTO_TCP;
  tc->c_fib_index = rmt->fib_index;
  /* The other connection vars will be initialized after SYN ACK */
  tcp_connection_timers_init (tc);

  TCP_EVT_DBG (TCP_EVT_OPEN, tc);
  tc->state = TCP_STATE_SYN_SENT;
  tcp_init_snd_vars (tc);
  tcp_send_syn (tc);
  clib_spinlock_unlock_if_init (&tm->half_open_lock);

  return tc->c_c_index;
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

const char *tcp_connection_flags_str[] = {
#define _(sym, str) str,
  foreach_tcp_connection_flag
#undef _
};

static u8 *
format_tcp_connection_flags (u8 * s, va_list * args)
{
  tcp_connection_t *tc = va_arg (*args, tcp_connection_t *);
  int i, last = -1;

  for (i = 0; i < TCP_CONN_N_FLAG_BITS; i++)
    if (tc->flags & (1 << i))
      last = i;
  for (i = 0; i < last; i++)
    {
      if (tc->flags & (1 << i))
	s = format (s, "%s, ", tcp_connection_flags_str[i]);
    }
  if (last >= 0)
    s = format (s, "%s", tcp_connection_flags_str[last]);
  return s;
}

const char *tcp_conn_timers[] = {
#define _(sym, str) str,
  foreach_tcp_timer
#undef _
};

static u8 *
format_tcp_timers (u8 * s, va_list * args)
{
  tcp_connection_t *tc = va_arg (*args, tcp_connection_t *);
  int i, last = -1;

  for (i = 0; i < TCP_N_TIMERS; i++)
    if (tc->timers[i] != TCP_TIMER_HANDLE_INVALID)
      last = i;

  for (i = 0; i < last; i++)
    {
      if (tc->timers[i] != TCP_TIMER_HANDLE_INVALID)
	s = format (s, "%s,", tcp_conn_timers[i]);
    }

  if (last >= 0)
    s = format (s, "%s", tcp_conn_timers[i]);

  return s;
}

static u8 *
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

static i32
tcp_rcv_wnd_available (tcp_connection_t * tc)
{
  return (i32) tc->rcv_wnd - (tc->rcv_nxt - tc->rcv_las);
}

static u8 *
format_tcp_congestion (u8 * s, va_list * args)
{
  tcp_connection_t *tc = va_arg (*args, tcp_connection_t *);
  u32 indent = format_get_indent (s);

  s = format (s, "%U ", format_tcp_congestion_status, tc);
  s = format (s, "cwnd %u ssthresh %u rtx_bytes %u bytes_acked %u\n",
	      tc->cwnd, tc->ssthresh, tc->snd_rxt_bytes, tc->bytes_acked);
  s = format (s, "%Ucc space %u prev_ssthresh %u snd_congestion %u"
	      " dupack %u\n", format_white_space, indent,
	      tcp_available_cc_snd_space (tc), tc->prev_ssthresh,
	      tc->snd_congestion - tc->iss, tc->rcv_dupacks);
  s = format (s, "%Utsecr %u tsecr_last_ack %u limited_transmit %u\n",
	      format_white_space, indent, tc->rcv_opts.tsecr,
	      tc->tsecr_last_ack, tc->limited_transmit - tc->iss);
  return s;
}

static u8 *
format_tcp_vars (u8 * s, va_list * args)
{
  tcp_connection_t *tc = va_arg (*args, tcp_connection_t *);
  s = format (s, " index: %u flags: %U timers: %U\n", tc->c_c_index,
	      format_tcp_connection_flags, tc, format_tcp_timers, tc);
  s = format (s, " snd_una %u snd_nxt %u snd_una_max %u",
	      tc->snd_una - tc->iss, tc->snd_nxt - tc->iss,
	      tc->snd_una_max - tc->iss);
  s = format (s, " rcv_nxt %u rcv_las %u\n",
	      tc->rcv_nxt - tc->irs, tc->rcv_las - tc->irs);
  s = format (s, " snd_wnd %u rcv_wnd %u rcv_wscale %u ",
	      tc->snd_wnd, tc->rcv_wnd, tc->rcv_wscale);
  s = format (s, "snd_wl1 %u snd_wl2 %u\n", tc->snd_wl1 - tc->irs,
	      tc->snd_wl2 - tc->iss);
  s = format (s, " flight size %u out space %u rcv_wnd_av %u\n",
	      tcp_flight_size (tc), tcp_available_output_snd_space (tc),
	      tcp_rcv_wnd_available (tc));
  s = format (s, " tsval_recent %u tsval_recent_age %u\n", tc->tsval_recent,
	      tcp_time_now () - tc->tsval_recent_age);
  s = format (s, " rto %u rto_boff %u srtt %u us %.3f rttvar %u rtt_ts %x",
	      tc->rto, tc->rto_boff, tc->srtt, tc->mrtt_us * 1000, tc->rttvar,
	      tc->rtt_ts);
  s = format (s, " rtt_seq %u\n", tc->rtt_seq - tc->iss);
  s = format (s, " cong:   %U", format_tcp_congestion, tc);

  if (tc->state >= TCP_STATE_ESTABLISHED)
    {
      s = format (s, " sboard: %U\n", format_tcp_scoreboard, &tc->sack_sb,
		  tc);
    }
  if (vec_len (tc->snd_sacks))
    s = format (s, " sacks tx: %U\n", format_tcp_sacks, tc);

  return s;
}

static u8 *
format_tcp_connection_id (u8 * s, va_list * args)
{
  tcp_connection_t *tc = va_arg (*args, tcp_connection_t *);
  if (!tc)
    return s;
  if (tc->c_is_ip4)
    {
      s = format (s, "[%d:%d][%s] %U:%d->%U:%d", tc->c_thread_index,
		  tc->c_s_index, "T", format_ip4_address, &tc->c_lcl_ip4,
		  clib_net_to_host_u16 (tc->c_lcl_port), format_ip4_address,
		  &tc->c_rmt_ip4, clib_net_to_host_u16 (tc->c_rmt_port));
    }
  else
    {
      s = format (s, "[%d:%d][%s] %U:%d->%U:%d", tc->c_thread_index,
		  tc->c_s_index, "T", format_ip6_address, &tc->c_lcl_ip6,
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
	s = format (s, "\n%U", format_tcp_vars, tc);
    }

  return s;
}

static u8 *
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

static u8 *
format_tcp_listener_session (u8 * s, va_list * args)
{
  u32 tci = va_arg (*args, u32);
  tcp_connection_t *tc = tcp_listener_get (tci);
  return format (s, "%U", format_tcp_connection_id, tc);
}

static u8 *
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

static u8 *
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
  u32 indent = format_get_indent (s);

  s = format (s, "sacked_bytes %u last_sacked_bytes %u lost_bytes %u\n",
	      sb->sacked_bytes, sb->last_sacked_bytes, sb->lost_bytes);
  s = format (s, "%Ulast_bytes_delivered %u high_sacked %u snd_una_adv %u\n",
	      format_white_space, indent, sb->last_bytes_delivered,
	      sb->high_sacked - tc->iss, sb->snd_una_adv);
  s = format (s, "%Ucur_rxt_hole %u high_rxt %u rescue_rxt %u",
	      format_white_space, indent, sb->cur_rxt_hole,
	      sb->high_rxt - tc->iss, sb->rescue_rxt - tc->iss);

  hole = scoreboard_first_hole (sb);
  if (hole)
    s = format (s, "\n%Uhead %u tail %u %u holes:\n%U", format_white_space,
		indent, sb->head, sb->tail, pool_elts (sb->holes),
		format_white_space, indent);

  while (hole)
    {
      s = format (s, "%U", format_tcp_sack_hole, hole, tc);
      hole = scoreboard_next_hole (sb, hole);
    }

  return s;
}

static transport_connection_t *
tcp_session_get_transport (u32 conn_index, u32 thread_index)
{
  tcp_connection_t *tc = tcp_connection_get (conn_index, thread_index);
  return &tc->connection;
}

static transport_connection_t *
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
static u16
tcp_session_send_mss (transport_connection_t * trans_conn)
{
  tcp_connection_t *tc = (tcp_connection_t *) trans_conn;

  /* Ensure snd_mss does accurately reflect the amount of data we can push
   * in a segment. This also makes sure that options are updated according to
   * the current state of the connection. */
  tcp_update_burst_snd_vars (tc);

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
    return snd_space < tc->cwnd ? 0 : snd_space;

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
static inline u32
tcp_snd_space_inline (tcp_connection_t * tc)
{
  int snd_space, snt_limited;

  if (PREDICT_FALSE (tcp_in_fastrecovery (tc)
		     || tc->state == TCP_STATE_CLOSED))
    return 0;

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

u32
tcp_snd_space (tcp_connection_t * tc)
{
  return tcp_snd_space_inline (tc);
}

static u32
tcp_session_send_space (transport_connection_t * trans_conn)
{
  tcp_connection_t *tc = (tcp_connection_t *) trans_conn;
  return clib_min (tcp_snd_space_inline (tc),
		   tc->snd_wnd - (tc->snd_nxt - tc->snd_una));
}

static u32
tcp_session_tx_fifo_offset (transport_connection_t * trans_conn)
{
  tcp_connection_t *tc = (tcp_connection_t *) trans_conn;

  ASSERT (seq_geq (tc->snd_nxt, tc->snd_una));

  /* This still works if fast retransmit is on */
  return (tc->snd_nxt - tc->snd_una);
}

static void
tcp_update_time (f64 now, u8 thread_index)
{
  tcp_worker_ctx_t *wrk = tcp_get_worker (thread_index);

  tcp_set_time_now (wrk);
  tw_timer_expire_timers_16t_2w_512sl (&wrk->timer_wheel, now);
  tcp_do_fastretransmits (wrk);
  tcp_send_acks (wrk);
  tcp_flush_frames_to_output (wrk);
}

static u32
tcp_session_push_header (transport_connection_t * tconn, vlib_buffer_t * b)
{
  tcp_connection_t *tc = (tcp_connection_t *) tconn;
  return tcp_push_header (tc, b);
}

static void
tcp_session_flush_data (transport_connection_t * tconn)
{
  tcp_connection_t *tc = (tcp_connection_t *) tconn;
  if (tc->flags & TCP_CONN_PSH_PENDING)
    return;
  tc->flags |= TCP_CONN_PSH_PENDING;
  tc->psh_seq = tc->snd_una_max + transport_max_tx_dequeue (tconn) - 1;
}

/* *INDENT-OFF* */
const static transport_proto_vft_t tcp_proto = {
  .enable = vnet_tcp_enable_disable,
  .bind = tcp_session_bind,
  .unbind = tcp_session_unbind,
  .push_header = tcp_session_push_header,
  .get_connection = tcp_session_get_transport,
  .get_listener = tcp_session_get_listener,
  .get_half_open = tcp_half_open_session_get_transport,
  .open = tcp_session_open,
  .close = tcp_session_close,
  .cleanup = tcp_session_cleanup,
  .send_mss = tcp_session_send_mss,
  .send_space = tcp_session_send_space,
  .update_time = tcp_update_time,
  .tx_fifo_offset = tcp_session_tx_fifo_offset,
  .flush_data = tcp_session_flush_data,
  .format_connection = format_tcp_session,
  .format_listener = format_tcp_listener_session,
  .format_half_open = format_tcp_half_open_session,
  .tx_type = TRANSPORT_TX_PEEK,
  .service_type = TRANSPORT_SERVICE_VC,
};
/* *INDENT-ON* */

void
tcp_connection_tx_pacer_update (tcp_connection_t * tc)
{
  f64 srtt;
  u64 rate;

  if (!transport_connection_is_tx_paced (&tc->connection))
    return;

  srtt = clib_min ((f64) tc->srtt * TCP_TICK, tc->mrtt_us);
  /* TODO should constrain to interface's max throughput but
   * we don't have link speeds for sw ifs ..*/
  rate = tc->cwnd / srtt;
  transport_connection_tx_pacer_update (&tc->connection, rate);
}

void
tcp_connection_tx_pacer_reset (tcp_connection_t * tc, u32 window,
			       u32 start_bucket)
{
  tcp_worker_ctx_t *wrk = tcp_get_worker (tc->c_thread_index);
  u32 byte_rate = window / ((f64) TCP_TICK * tc->srtt);
  u64 last_time = wrk->vm->clib_time.last_cpu_time;
  transport_connection_tx_pacer_reset (&tc->connection, byte_rate,
				       start_bucket, last_time);
}

static void
tcp_timer_keep_handler (u32 conn_index)
{
  u32 thread_index = vlib_get_thread_index ();
  tcp_connection_t *tc;

  tc = tcp_connection_get (conn_index, thread_index);
  tc->timers[TCP_TIMER_KEEP] = TCP_TIMER_HANDLE_INVALID;

  tcp_connection_close (tc);
}

static void
tcp_timer_establish_handler (u32 conn_index)
{
  tcp_connection_t *tc;

  tc = tcp_connection_get (conn_index, vlib_get_thread_index ());
  /* note: the connection may have already disappeared */
  if (PREDICT_FALSE (tc == 0))
    return;
  ASSERT (tc->state == TCP_STATE_SYN_RCVD);
  /* Start cleanup. App wasn't notified yet so use delete notify as
   * opposed to delete to cleanup session layer state. */
  session_transport_delete_notify (&tc->connection);
  tc->timers[TCP_TIMER_ESTABLISH] = TCP_TIMER_HANDLE_INVALID;
  tcp_connection_cleanup (tc);
}

static void
tcp_timer_establish_ao_handler (u32 conn_index)
{
  tcp_connection_t *tc;

  tc = tcp_half_open_connection_get (conn_index);
  if (!tc)
    return;

  ASSERT (tc->state == TCP_STATE_SYN_SENT);
  /* Notify app if we haven't tried to clean this up already */
  if (!(tc->flags & TCP_CONN_HALF_OPEN_DONE))
    session_stream_connect_notify (&tc->connection, 1 /* fail */ );

  tc->timers[TCP_TIMER_ESTABLISH_AO] = TCP_TIMER_HANDLE_INVALID;
  tcp_connection_cleanup (tc);
}

static void
tcp_timer_waitclose_handler (u32 conn_index)
{
  u32 thread_index = vlib_get_thread_index (), rto;
  tcp_connection_t *tc;

  tc = tcp_connection_get (conn_index, thread_index);
  if (!tc)
    return;
  tc->timers[TCP_TIMER_WAITCLOSE] = TCP_TIMER_HANDLE_INVALID;

  switch (tc->state)
    {
    case TCP_STATE_CLOSE_WAIT:
      tcp_connection_timers_reset (tc);
      session_transport_closed_notify (&tc->connection);

      if (!(tc->flags & TCP_CONN_FINPNDG))
	{
	  tcp_connection_set_state (tc, TCP_STATE_CLOSED);
	  tcp_timer_set (tc, TCP_TIMER_WAITCLOSE, TCP_CLEANUP_TIME);
	  break;
	}

      /* Session didn't come back with a close. Send FIN either way
       * and switch to LAST_ACK. */
      tcp_cong_recovery_off (tc);
      /* Make sure we don't try to send unsent data */
      tc->snd_una_max = tc->snd_nxt = tc->snd_una;
      tcp_send_fin (tc);
      tcp_connection_set_state (tc, TCP_STATE_LAST_ACK);

      /* Make sure we don't wait in LAST ACK forever */
      tcp_timer_set (tc, TCP_TIMER_WAITCLOSE, TCP_2MSL_TIME);

      /* Don't delete the connection yet */
      break;
    case TCP_STATE_FIN_WAIT_1:
      tcp_connection_timers_reset (tc);
      if (tc->flags & TCP_CONN_FINPNDG)
	{
	  /* If FIN pending send it before closing and wait as long as
	   * the rto timeout would wait. Notify session layer that transport
	   * is closed. We haven't sent everything but we did try. */
	  tcp_cong_recovery_off (tc);
	  tcp_send_fin (tc);
	  rto = clib_max (tc->rto >> tc->rto_boff, 1);
	  tcp_timer_set (tc, TCP_TIMER_WAITCLOSE,
			 clib_min (rto * TCP_TO_TIMER_TICK, TCP_2MSL_TIME));
	  session_transport_closed_notify (&tc->connection);
	}
      else
	{
	  /* We've sent the fin but no progress. Close the connection and
	   * to make sure everything is flushed, setup a cleanup timer */
	  tcp_connection_set_state (tc, TCP_STATE_CLOSED);
	  tcp_timer_set (tc, TCP_TIMER_WAITCLOSE, TCP_CLEANUP_TIME);
	}
      break;
    case TCP_STATE_LAST_ACK:
    case TCP_STATE_CLOSING:
      tcp_connection_timers_reset (tc);
      tcp_connection_set_state (tc, TCP_STATE_CLOSED);
      tcp_timer_set (tc, TCP_TIMER_WAITCLOSE, TCP_CLEANUP_TIME);
      session_transport_closed_notify (&tc->connection);
      break;
    default:
      tcp_connection_del (tc);
      break;
    }
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
    tcp_timer_establish_handler,
    tcp_timer_establish_ao_handler,
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

static void
tcp_initialize_timer_wheels (tcp_main_t * tm)
{
  tw_timer_wheel_16t_2w_512sl_t *tw;
  /* *INDENT-OFF* */
  foreach_vlib_main (({
    tw = &tm->wrk_ctx[ii].timer_wheel;
    tw_timer_wheel_init_16t_2w_512sl (tw, tcp_expired_timers_dispatch,
				      100e-3 /* timer period 100ms */ , ~0);
    tw->last_run_time = vlib_time_now (this_vlib_main);
  }));
  /* *INDENT-ON* */
}

static clib_error_t *
tcp_main_enable (vlib_main_t * vm)
{
  vlib_thread_main_t *vtm = vlib_get_thread_main ();
  u32 num_threads, n_workers, prealloc_conn_per_wrk;
  tcp_connection_t *tc __attribute__ ((unused));
  tcp_main_t *tm = vnet_get_tcp_main ();
  clib_error_t *error = 0;
  int thread;

  if ((error = vlib_call_init_function (vm, ip_main_init)))
    return error;
  if ((error = vlib_call_init_function (vm, ip4_lookup_init)))
    return error;
  if ((error = vlib_call_init_function (vm, ip6_lookup_init)))
    return error;

  /*
   * Registrations
   */

  ip4_register_protocol (IP_PROTOCOL_TCP, tcp4_input_node.index);
  ip6_register_protocol (IP_PROTOCOL_TCP, tcp6_input_node.index);

  /*
   * Initialize data structures
   */

  num_threads = 1 /* main thread */  + vtm->n_threads;
  vec_validate (tm->connections, num_threads - 1);
  vec_validate (tm->wrk_ctx, num_threads - 1);
  n_workers = num_threads == 1 ? 1 : vtm->n_threads;
  prealloc_conn_per_wrk = tm->preallocated_connections / n_workers;

  for (thread = 0; thread < num_threads; thread++)
    {
      vec_validate (tm->wrk_ctx[thread].pending_fast_rxt, 255);
      vec_validate (tm->wrk_ctx[thread].ongoing_fast_rxt, 255);
      vec_validate (tm->wrk_ctx[thread].postponed_fast_rxt, 255);
      vec_validate (tm->wrk_ctx[thread].pending_deq_acked, 255);
      vec_validate (tm->wrk_ctx[thread].pending_acks, 255);
      vec_validate (tm->wrk_ctx[thread].pending_disconnects, 255);
      vec_reset_length (tm->wrk_ctx[thread].pending_fast_rxt);
      vec_reset_length (tm->wrk_ctx[thread].ongoing_fast_rxt);
      vec_reset_length (tm->wrk_ctx[thread].postponed_fast_rxt);
      vec_reset_length (tm->wrk_ctx[thread].pending_deq_acked);
      vec_reset_length (tm->wrk_ctx[thread].pending_acks);
      vec_reset_length (tm->wrk_ctx[thread].pending_disconnects);
      tm->wrk_ctx[thread].vm = vlib_mains[thread];

      /*
       * Preallocate connections. Assume that thread 0 won't
       * use preallocated threads when running multi-core
       */
      if ((thread > 0 || num_threads == 1) && prealloc_conn_per_wrk)
	pool_init_fixed (tm->connections[thread], prealloc_conn_per_wrk);
    }

  /*
   * Use a preallocated half-open connection pool?
   */
  if (tm->preallocated_half_open_connections)
    pool_init_fixed (tm->half_open_connections,
		     tm->preallocated_half_open_connections);

  /* Initialize clocks per tick for TCP timestamp. Used to compute
   * monotonically increasing timestamps. */
  tm->tstamp_ticks_per_clock = vm->clib_time.seconds_per_clock
    / TCP_TSTAMP_RESOLUTION;

  if (num_threads > 1)
    {
      clib_spinlock_init (&tm->half_open_lock);
    }

  tcp_initialize_timer_wheels (tm);

  tm->bytes_per_buffer = VLIB_BUFFER_DATA_SIZE;

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

void
tcp_punt_unknown (vlib_main_t * vm, u8 is_ip4, u8 is_add)
{
  tcp_main_t *tm = &tcp_main;
  if (is_ip4)
    tm->punt_unknown4 = is_add;
  else
    tm->punt_unknown6 = is_add;
}

static clib_error_t *
tcp_init (vlib_main_t * vm)
{
  tcp_main_t *tm = vnet_get_tcp_main ();
  ip_main_t *im = &ip_main;
  ip_protocol_info_t *pi;

  /* Session layer, and by implication tcp, are disabled by default */
  tm->is_enabled = 0;

  /* Register with IP for header parsing */
  pi = ip_get_protocol_info (im, IP_PROTOCOL_TCP);
  if (pi == 0)
    return clib_error_return (0, "TCP protocol info AWOL");
  pi->format_header = format_tcp_header;
  pi->unformat_pg_edit = unformat_pg_tcp_header;

  /* Register as transport with session layer */
  transport_register_protocol (TRANSPORT_PROTO_TCP, &tcp_proto,
			       FIB_PROTOCOL_IP4, tcp4_output_node.index);
  transport_register_protocol (TRANSPORT_PROTO_TCP, &tcp_proto,
			       FIB_PROTOCOL_IP6, tcp6_output_node.index);

  tcp_api_reference ();
  tm->tx_pacing = 1;
  tm->cc_algo = TCP_CC_NEWRENO;
  return 0;
}

VLIB_INIT_FUNCTION (tcp_init);

uword
unformat_tcp_cc_algo (unformat_input_t * input, va_list * va)
{
  uword *result = va_arg (*va, uword *);

  if (unformat (input, "newreno"))
    *result = TCP_CC_NEWRENO;
  else if (unformat (input, "cubic"))
    *result = TCP_CC_CUBIC;
  else
    return 0;

  return 1;
}

uword
unformat_tcp_cc_algo_cfg (unformat_input_t * input, va_list * va)
{
  tcp_main_t *tm = vnet_get_tcp_main ();
  tcp_cc_algorithm_t *cc_alg;
  unformat_input_t sub_input;
  int found = 0;

  vec_foreach (cc_alg, tm->cc_algos)
  {
    if (!unformat (input, cc_alg->name))
      continue;

    if (cc_alg->unformat_cfg
	&& unformat (input, "%U", unformat_vlib_cli_sub_input, &sub_input))
      {
	if (cc_alg->unformat_cfg (&sub_input))
	  found = 1;
      }
  }
  return found;
}

static clib_error_t *
tcp_config_fn (vlib_main_t * vm, unformat_input_t * input)
{
  tcp_main_t *tm = vnet_get_tcp_main ();

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "preallocated-connections %d",
		    &tm->preallocated_connections))
	;
      else if (unformat (input, "preallocated-half-open-connections %d",
			 &tm->preallocated_half_open_connections))
	;
      else if (unformat (input, "buffer-fail-fraction %f",
			 &tm->buffer_fail_fraction))
	;
      else if (unformat (input, "max-rx-fifo %U", unformat_memory_size,
			 &tm->max_rx_fifo))
	;
      else if (unformat (input, "no-tx-pacing"))
	tm->tx_pacing = 0;
      else if (unformat (input, "cc-algo %U", unformat_tcp_cc_algo,
			 &tm->cc_algo))
	;
      else if (unformat (input, "%U", unformat_tcp_cc_algo_cfg))
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

  clib_memset (&prefix, 0, sizeof (prefix));

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

  clib_memset (&prefix, 0, sizeof (prefix));

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
	  memcpy (&v6end, &v6start, sizeof (v6start));
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

  if (!TCP_SCOREBOARD_TRACE)
    {
      s = format (s, "scoreboard tracing not enabled");
      return s;
    }

  if (!tc)
    return s;

  clib_memset (dummy_tc, 0, sizeof (*dummy_tc));
  tcp_connection_timers_init (dummy_tc);
  scoreboard_init (&dummy_tc->sack_sb);
  dummy_tc->rcv_opts.flags |= TCP_OPTS_FLAG_SACK;

#if TCP_SCOREBOARD_TRACE
  trace = tc->sack_sb.trace;
  trace_len = vec_len (tc->sack_sb.trace);
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

static clib_error_t *
show_tcp_punt_fn (vlib_main_t * vm, unformat_input_t * input,
		  vlib_cli_command_t * cmd_arg)
{
  tcp_main_t *tm = vnet_get_tcp_main ();
  if (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    return clib_error_return (0, "unknown input `%U'", format_unformat_error,
			      input);
  vlib_cli_output (vm, "IPv4 TCP punt: %s",
		   tm->punt_unknown4 ? "enabled" : "disabled");
  vlib_cli_output (vm, "IPv6 TCP punt: %s",
		   tm->punt_unknown6 ? "enabled" : "disabled");
  return 0;
}
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_tcp_punt_command, static) =
{
  .path = "show tcp punt",
  .short_help = "show tcp punt",
  .function = show_tcp_punt_fn,
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
