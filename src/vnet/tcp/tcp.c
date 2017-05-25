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

#include <vnet/tcp/tcp.h>
#include <vnet/session/session.h>
#include <vnet/fib/fib.h>
#include <math.h>

tcp_main_t tcp_main;

static u32
tcp_connection_bind (u32 session_index, ip46_address_t * ip,
		     u16 port_host_byte_order, u8 is_ip4)
{
  tcp_main_t *tm = &tcp_main;
  tcp_connection_t *listener;

  pool_get (tm->listener_pool, listener);
  memset (listener, 0, sizeof (*listener));

  listener->c_c_index = listener - tm->listener_pool;
  listener->c_lcl_port = clib_host_to_net_u16 (port_host_byte_order);

  if (is_ip4)
    {
      listener->c_lcl_ip4.as_u32 = ip->ip4.as_u32;
      listener->c_is_ip4 = 1;
      listener->c_proto = SESSION_TYPE_IP4_TCP;
    }
  else
    {
      clib_memcpy (&listener->c_lcl_ip6, &ip->ip6, sizeof (ip6_address_t));
      listener->c_proto = SESSION_TYPE_IP6_TCP;
    }

  listener->c_s_index = session_index;
  listener->state = TCP_STATE_LISTEN;

  tcp_connection_timers_init (listener);

  TCP_EVT_DBG (TCP_EVT_BIND, listener);

  return listener->c_c_index;
}

u32
tcp_session_bind_ip4 (u32 session_index, ip46_address_t * ip,
		      u16 port_host_byte_order)
{
  return tcp_connection_bind (session_index, ip, port_host_byte_order, 1);
}

u32
tcp_session_bind_ip6 (u32 session_index, ip46_address_t * ip,
		      u16 port_host_byte_order)
{
  return tcp_connection_bind (session_index, ip, port_host_byte_order, 0);
}

static void
tcp_connection_unbind (u32 listener_index)
{
  tcp_main_t *tm = vnet_get_tcp_main ();
  TCP_EVT_DBG (TCP_EVT_UNBIND,
	       pool_elt_at_index (tm->listener_pool, listener_index));
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
				    tc->c_lcl_port);

  /*XXX lock */
  if (tepi != TRANSPORT_ENDPOINT_INVALID_INDEX)
    {
      tep = pool_elt_at_index (tm->local_endpoints, tepi);
      transport_endpoint_table_del (&tm->local_endpoints_table, tep);
      pool_put (tm->local_endpoints, tep);
    }

  /* Make sure all timers are cleared */
  tcp_connection_timers_reset (tc);

  /* Check if half-open */
  if (tc->state == TCP_STATE_SYN_SENT)
    pool_put (tm->half_open_connections, tc);
  else
    pool_put (tm->connections[tc->c_thread_index], tc);
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

/** Notify session that connection has been reset.
 *
 * Switch state to closed and wait for session to call cleanup.
 */
void
tcp_connection_reset (tcp_connection_t * tc)
{
  switch (tc->state)
    {
    case TCP_STATE_SYN_RCVD:
      /* Cleanup everything. App wasn't notified yet */
      stream_session_delete_notify (&tc->connection);
      tcp_connection_cleanup (tc);
      break;
    case TCP_STATE_SYN_SENT:
    case TCP_STATE_ESTABLISHED:
    case TCP_STATE_CLOSE_WAIT:
    case TCP_STATE_FIN_WAIT_1:
    case TCP_STATE_FIN_WAIT_2:
    case TCP_STATE_CLOSING:
      tc->state = TCP_STATE_CLOSED;

      /* Make sure all timers are cleared */
      tcp_connection_timers_reset (tc);

      stream_session_reset_notify (&tc->connection);
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

  /* Send FIN if needed */
  if (tc->state == TCP_STATE_ESTABLISHED
      || tc->state == TCP_STATE_SYN_RCVD || tc->state == TCP_STATE_CLOSE_WAIT)
    tcp_send_fin (tc);

  /* Switch state */
  if (tc->state == TCP_STATE_ESTABLISHED || tc->state == TCP_STATE_SYN_RCVD)
    tc->state = TCP_STATE_FIN_WAIT_1;
  else if (tc->state == TCP_STATE_SYN_SENT)
    tc->state = TCP_STATE_CLOSED;
  else if (tc->state == TCP_STATE_CLOSE_WAIT)
    tc->state = TCP_STATE_LAST_ACK;

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
        return ip_interface_address_get_address (lm6, ia);
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
u16
tcp_allocate_local_port (tcp_main_t * tm, ip46_address_t * ip)
{
  transport_endpoint_t *tep;
  u32 time_now, tei;
  u16 min = 1024, max = 65535;	/* XXX configurable ? */
  int tries;

  tries = max - min;
  time_now = tcp_time_now ();

  /* Start at random point or max */
  pool_get (tm->local_endpoints, tep);
  clib_memcpy (&tep->ip, ip, sizeof (*ip));

  /* Search for first free slot */
  for (; tries >= 0; tries--)
    {
      u16 port = 0;

      /* Find a port in the specified range */
      while (1)
	{
	  port = random_u32 (&time_now) & PORT_MASK;
	  if (PREDICT_TRUE (port >= min && port < max))
	    break;
	}

      tep->port = port;

      /* Look it up */
      tei = transport_endpoint_lookup (&tm->local_endpoints_table, &tep->ip,
				       tep->port);
      /* If not found, we're done */
      if (tei == TRANSPORT_ENDPOINT_INVALID_INDEX)
	{
	  transport_endpoint_table_add (&tm->local_endpoints_table, tep,
					tep - tm->local_endpoints);
	  return tep->port;
	}
    }
  /* No free ports */
  pool_put (tm->local_endpoints, tep);
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
}

int
tcp_connection_open (ip46_address_t * rmt_addr, u16 rmt_port, u8 is_ip4)
{
  tcp_main_t *tm = vnet_get_tcp_main ();
  tcp_connection_t *tc;
  fib_prefix_t prefix;
  u32 fei, sw_if_index;
  ip46_address_t lcl_addr;
  u16 lcl_port;

  /*
   * Find the local address and allocate port
   */
  memset (&lcl_addr, 0, sizeof (lcl_addr));

  /* Find a FIB path to the destination */
  clib_memcpy (&prefix.fp_addr, rmt_addr, sizeof (*rmt_addr));
  prefix.fp_proto = is_ip4 ? FIB_PROTOCOL_IP4 : FIB_PROTOCOL_IP6;
  prefix.fp_len = is_ip4 ? 32 : 128;

  fei = fib_table_lookup (0, &prefix);

  /* Couldn't find route to destination. Bail out. */
  if (fei == FIB_NODE_INDEX_INVALID)
    return -1;

  sw_if_index = fib_entry_get_resolving_interface (fei);

  if (sw_if_index == (u32) ~ 0)
    return -1;

  if (is_ip4)
    {
      ip4_address_t *ip4;
      ip4 = ip_interface_get_first_ip (sw_if_index, 1);
      lcl_addr.ip4.as_u32 = ip4->as_u32;
    }
  else
    {
      ip6_address_t *ip6;
      ip6 = ip_interface_get_first_ip (sw_if_index, 0);
      clib_memcpy (&lcl_addr.ip6, ip6, sizeof (*ip6));
    }

  /* Allocate source port */
  lcl_port = tcp_allocate_local_port (tm, &lcl_addr);
  if (lcl_port < 1)
    {
      clib_warning ("Failed to allocate src port");
      return -1;
    }

  /*
   * Create connection and send SYN
   */

  pool_get (tm->half_open_connections, tc);
  memset (tc, 0, sizeof (*tc));

  clib_memcpy (&tc->c_rmt_ip, rmt_addr, sizeof (ip46_address_t));
  clib_memcpy (&tc->c_lcl_ip, &lcl_addr, sizeof (ip46_address_t));
  tc->c_rmt_port = clib_host_to_net_u16 (rmt_port);
  tc->c_lcl_port = clib_host_to_net_u16 (lcl_port);
  tc->c_c_index = tc - tm->half_open_connections;
  tc->c_is_ip4 = is_ip4;
  tc->c_proto = is_ip4 ? SESSION_TYPE_IP4_TCP : SESSION_TYPE_IP6_TCP;

  /* The other connection vars will be initialized after SYN ACK */
  tcp_connection_timers_init (tc);

  tcp_send_syn (tc);

  tc->state = TCP_STATE_SYN_SENT;

  TCP_EVT_DBG (TCP_EVT_OPEN, tc);

  return tc->c_c_index;
}

int
tcp_session_open_ip4 (ip46_address_t * addr, u16 port)
{
  return tcp_connection_open (addr, port, 1);
}

int
tcp_session_open_ip6 (ip46_address_t * addr, u16 port)
{
  return tcp_connection_open (addr, port, 0);
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
  s = format (s, " snd_una %u snd_nxt %u snd_una_max %u\n",
	      tc->snd_una - tc->iss, tc->snd_nxt - tc->iss,
	      tc->snd_una_max - tc->iss);
  s = format (s, " rcv_nxt %u rcv_las %u\n",
	      tc->rcv_nxt - tc->irs, tc->rcv_las - tc->irs);
  s = format (s, " snd_wnd %u rcv_wnd %u snd_wl1 %u snd_wl2 %u\n",
	      tc->snd_wnd, tc->rcv_wnd, tc->snd_wl1 - tc->irs,
	      tc->snd_wl2 - tc->iss);
  s = format (s, " flight size %u send space %u rcv_wnd_av %d\n",
	      tcp_flight_size (tc), tcp_available_snd_space (tc),
	      tcp_rcv_wnd_available (tc));
  s = format (s, " cong %U ", format_tcp_congestion_status, tc);
  s = format (s, "cwnd %u ssthresh %u rtx_bytes %u bytes_acked %u\n",
	      tc->cwnd, tc->ssthresh, tc->snd_rxt_bytes, tc->bytes_acked);
  s = format (s, " prev_ssthresh %u snd_congestion %u dupack %u\n",
	      tc->prev_ssthresh, tc->snd_congestion - tc->iss,
	      tc->rcv_dupacks);
  s = format (s, " rto %u rto_boff %u srtt %u rttvar %u rtt_ts %u ", tc->rto,
	      tc->rto_boff, tc->srtt, tc->rttvar, tc->rtt_ts);
  s = format (s, "rtt_seq %u\n", tc->rtt_seq);
  s = format (s, " scoreboard: %U\n", format_tcp_scoreboard, &tc->sack_sb);
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
    s = format (s, "empty");
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
  vec_foreach (block, sacks)
  {
    s = format (s, " start %u end %u\n", block->start - tc->irs,
		block->end - tc->irs);
  }
  return s;
}

u8 *
format_tcp_sack_hole (u8 * s, va_list * args)
{
  sack_scoreboard_hole_t *hole = va_arg (*args, sack_scoreboard_hole_t *);
  s = format (s, "[%u, %u]", hole->start, hole->end);
  return s;
}

u8 *
format_tcp_scoreboard (u8 * s, va_list * args)
{
  sack_scoreboard_t *sb = va_arg (*args, sack_scoreboard_t *);
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
      s = format (s, "%U", format_tcp_sack_hole, hole);
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
  if (tc->snd_wnd < tc->snd_mss)
    {
      return tc->snd_wnd <= snd_space ? tc->snd_wnd : 0;
    }

  /* If we can't write at least a segment, don't try at all */
  if (snd_space < tc->snd_mss)
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
  int snd_space;

  /* If we haven't gotten dupacks or if we did and have gotten sacked bytes
   * then we can still send */
  if (PREDICT_TRUE (tcp_in_cong_recovery (tc) == 0
		    && (tc->rcv_dupacks == 0
			|| tc->sack_sb.last_sacked_bytes)))
    {
      snd_space = tcp_available_snd_space (tc);
      return tcp_round_snd_space (tc, snd_space);
    }

  if (tcp_in_recovery (tc))
    {
      tc->snd_nxt = tc->snd_una_max;
      snd_space = tcp_available_wnd (tc) - tc->snd_rxt_bytes
	- (tc->snd_una_max - tc->snd_congestion);
      if (snd_space <= 0 || (tc->snd_una_max - tc->snd_una) >= tc->snd_wnd)
	return 0;
      return tcp_round_snd_space (tc, snd_space);
    }

  /* If in fast recovery, send 1 SMSS if wnd allows */
  if (tcp_in_fastrecovery (tc)
      && tcp_available_snd_space (tc) && !tcp_fastrecovery_sent_1_smss (tc))
    {
      tcp_fastrecovery_1_smss_on (tc);
      return tc->snd_mss;
    }

  return 0;
}

u32
tcp_session_send_space (transport_connection_t * trans_conn)
{
  tcp_connection_t *tc = (tcp_connection_t *) trans_conn;
  return tcp_snd_space (tc);
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
const static transport_proto_vft_t tcp4_proto = {
  .bind = tcp_session_bind_ip4,
  .unbind = tcp_session_unbind,
  .push_header = tcp_push_header,
  .get_connection = tcp_session_get_transport,
  .get_listener = tcp_session_get_listener,
  .get_half_open = tcp_half_open_session_get_transport,
  .open = tcp_session_open_ip4,
  .close = tcp_session_close,
  .cleanup = tcp_session_cleanup,
  .send_mss = tcp_session_send_mss,
  .send_space = tcp_session_send_space,
  .tx_fifo_offset = tcp_session_tx_fifo_offset,
  .format_connection = format_tcp_session,
  .format_listener = format_tcp_listener_session,
  .format_half_open = format_tcp_half_open_session,
};

const static transport_proto_vft_t tcp6_proto = {
  .bind = tcp_session_bind_ip6,
  .unbind = tcp_session_unbind,
  .push_header = tcp_push_header,
  .get_connection = tcp_session_get_transport,
  .get_listener = tcp_session_get_listener,
  .get_half_open = tcp_half_open_session_get_transport,
  .open = tcp_session_open_ip6,
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
  u8 sst;

  tc = tcp_half_open_connection_get (conn_index);
  tc->timers[TCP_TIMER_ESTABLISH] = TCP_TIMER_HANDLE_INVALID;

  ASSERT (tc->state == TCP_STATE_SYN_SENT);

  sst = tc->c_is_ip4 ? SESSION_TYPE_IP4_TCP : SESSION_TYPE_IP6_TCP;
  stream_session_connect_notify (&tc->connection, sst, 1 /* fail */ );

  tcp_connection_cleanup (tc);
}

void
tcp_timer_waitclose_handler (u32 conn_index)
{
  u32 thread_index = vlib_get_thread_index ();
  tcp_connection_t *tc;

  tc = tcp_connection_get (conn_index, thread_index);
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

  /* Register as transport with URI */
  session_register_transport (SESSION_TYPE_IP4_TCP, &tcp4_proto);
  session_register_transport (SESSION_TYPE_IP6_TCP, &tcp6_proto);

  /*
   * Initialize data structures
   */

  num_threads = 1 /* main thread */  + vtm->n_threads;
  vec_validate (tm->connections, num_threads - 1);

  /* Initialize per worker thread tx buffers (used for control messages) */
  vec_validate (tm->tx_buffers, num_threads - 1);

  /* Initialize timer wheels */
  vec_validate (tm->timer_wheels, num_threads - 1);
  tcp_initialize_timer_wheels (tm);

//  vec_validate (tm->delack_connections, num_threads - 1);

  /* Initialize clocks per tick for TCP timestamp. Used to compute
   * monotonically increasing timestamps. */
  tm->tstamp_ticks_per_clock = vm->clib_time.seconds_per_clock
    / TCP_TSTAMP_RESOLUTION;

  clib_bihash_init_24_8 (&tm->local_endpoints_table, "local endpoint table",
			 200000 /* $$$$ config parameter nbuckets */ ,
			 (64 << 20) /*$$$ config parameter table size */ );

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

  tm->vlib_main = vm;
  tm->vnet_main = vnet_get_main ();
  tm->is_enabled = 0;

  return 0;
}

VLIB_INIT_FUNCTION (tcp_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
