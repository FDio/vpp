/*
 * Copyright (c) 2016-2019 Cisco and/or its affiliates.
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
#include <vnet/tcp/tcp_inlines.h>
#include <vnet/session/session.h>
#include <vnet/fib/fib.h>
#include <vnet/dpo/load_balance.h>
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

static void
tcp_cc_init (tcp_connection_t * tc)
{
  tc->cc_algo->init (tc);
}

static void
tcp_cc_cleanup (tcp_connection_t * tc)
{
  if (tc->cc_algo->cleanup)
    tc->cc_algo->cleanup (tc);
}

void
tcp_cc_algo_register (tcp_cc_algorithm_type_e type,
		      const tcp_cc_algorithm_t * vft)
{
  tcp_main_t *tm = vnet_get_tcp_main ();
  vec_validate (tm->cc_algos, type);

  tm->cc_algos[type] = *vft;
  hash_set_mem (tm->cc_algo_by_name, vft->name, type);
}

tcp_cc_algorithm_t *
tcp_cc_algo_get (tcp_cc_algorithm_type_e type)
{
  tcp_main_t *tm = vnet_get_tcp_main ();
  return &tm->cc_algos[type];
}

tcp_cc_algorithm_type_e
tcp_cc_algo_new_type (const tcp_cc_algorithm_t * vft)
{
  tcp_main_t *tm = vnet_get_tcp_main ();
  tcp_cc_algo_register (++tm->cc_last_type, vft);
  return tm->cc_last_type;
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
  listener->cc_algo = tcp_cc_algo_get (tcp_cfg.cc_algo);

  tcp_connection_timers_init (listener);

  TCP_EVT (TCP_EVT_BIND, listener);

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

  TCP_EVT (TCP_EVT_UNBIND, tc);

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
tcp_half_open_connection_free (tcp_connection_t * tc)
{
  tcp_main_t *tm = vnet_get_tcp_main ();
  clib_spinlock_lock_if_init (&tm->half_open_lock);
  if (CLIB_DEBUG)
    clib_memset (tc, 0xFA, sizeof (*tc));
  pool_put (tm->half_open_connections, tc);
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
  tcp_worker_ctx_t *wrk;

  /* Make sure this is the owning thread */
  if (tc->c_thread_index != vlib_get_thread_index ())
    return 1;

  session_half_open_delete_notify (TRANSPORT_PROTO_TCP, tc->c_s_ho_handle);
  wrk = tcp_get_worker (tc->c_thread_index);
  tcp_timer_reset (&wrk->timer_wheel, tc, TCP_TIMER_RETRANSMIT_SYN);
  tcp_half_open_connection_free (tc);
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
  TCP_EVT (TCP_EVT_DELETE, tc);

  /* Cleanup local endpoint if this was an active connect */
  if (!(tc->cfg_flags & TCP_CFG_F_NO_ENDPOINT))
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
      /* Make sure all timers are cleared */
      tcp_connection_timers_reset (tc);

      if (!tc->c_is_ip4 && ip6_address_is_link_local_unicast (&tc->c_rmt_ip6))
	tcp_add_del_adjacency (tc, 0);

      tcp_cc_cleanup (tc);
      vec_free (tc->snd_sacks);
      vec_free (tc->snd_sacks_fl);
      vec_free (tc->rcv_opts.sacks);
      pool_free (tc->sack_sb.holes);

      if (tc->cfg_flags & TCP_CFG_F_RATE_SAMPLE)
	tcp_bt_cleanup (tc);

      tcp_connection_free (tc);
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
  session_transport_delete_notify (&tc->connection);
  tcp_connection_cleanup (tc);
}

tcp_connection_t *
tcp_connection_alloc (u8 thread_index)
{
  tcp_worker_ctx_t *wrk = tcp_get_worker (thread_index);
  tcp_connection_t *tc;

  pool_get (wrk->connections, tc);
  clib_memset (tc, 0, sizeof (*tc));
  tc->c_c_index = tc - wrk->connections;
  tc->c_thread_index = thread_index;
  return tc;
}

tcp_connection_t *
tcp_connection_alloc_w_base (u8 thread_index, tcp_connection_t * base)
{
  tcp_worker_ctx_t *wrk = tcp_get_worker (thread_index);
  tcp_connection_t *tc;

  pool_get (wrk->connections, tc);
  clib_memcpy_fast (tc, base, sizeof (*tc));
  tc->c_c_index = tc - wrk->connections;
  tc->c_thread_index = thread_index;
  return tc;
}

void
tcp_connection_free (tcp_connection_t * tc)
{
  tcp_worker_ctx_t *wrk = tcp_get_worker (tc->c_thread_index);
  if (CLIB_DEBUG)
    {
      clib_memset (tc, 0xFA, sizeof (*tc));
      pool_put (wrk->connections, tc);
      return;
    }
  pool_put (wrk->connections, tc);
}

void
tcp_program_cleanup (tcp_worker_ctx_t * wrk, tcp_connection_t * tc)
{
  tcp_cleanup_req_t *req;
  clib_time_type_t now;

  now = transport_time_now (tc->c_thread_index);
  clib_fifo_add2 (wrk->pending_cleanups, req);
  req->connection_index = tc->c_c_index;
  req->free_time = now + tcp_cfg.cleanup_time;
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
  tcp_worker_ctx_t *wrk = tcp_get_worker (tc->c_thread_index);

  TCP_EVT (TCP_EVT_CLOSE, tc);

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
      tcp_timer_update (&wrk->timer_wheel, tc, TCP_TIMER_WAITCLOSE,
			tcp_cfg.finwait1_time);
      break;
    case TCP_STATE_ESTABLISHED:
      /* If closing with unread data, reset the connection */
      if (transport_max_rx_dequeue (&tc->connection))
	{
	  tcp_send_reset (tc);
	  tcp_connection_timers_reset (tc);
	  tcp_connection_set_state (tc, TCP_STATE_CLOSED);
	  session_transport_closed_notify (&tc->connection);
	  tcp_program_cleanup (tcp_get_worker (tc->c_thread_index), tc);
	  tcp_worker_stats_inc (wrk, rst_unread, 1);
	  break;
	}
      if (!transport_max_tx_dequeue (&tc->connection))
	tcp_send_fin (tc);
      else
	tc->flags |= TCP_CONN_FINPNDG;
      tcp_connection_set_state (tc, TCP_STATE_FIN_WAIT_1);
      /* Set a timer in case the peer stops responding. Otherwise the
       * connection will be stuck here forever. */
      ASSERT (tc->timers[TCP_TIMER_WAITCLOSE] == TCP_TIMER_HANDLE_INVALID);
      tcp_timer_set (&wrk->timer_wheel, tc, TCP_TIMER_WAITCLOSE,
		     tcp_cfg.finwait1_time);
      break;
    case TCP_STATE_CLOSE_WAIT:
      if (!transport_max_tx_dequeue (&tc->connection))
	{
	  tcp_send_fin (tc);
	  tcp_connection_timers_reset (tc);
	  tcp_connection_set_state (tc, TCP_STATE_LAST_ACK);
	  tcp_timer_update (&wrk->timer_wheel, tc, TCP_TIMER_WAITCLOSE,
			    tcp_cfg.lastack_time);
	}
      else
	tc->flags |= TCP_CONN_FINPNDG;
      break;
    case TCP_STATE_FIN_WAIT_1:
      tcp_timer_update (&wrk->timer_wheel, tc, TCP_TIMER_WAITCLOSE,
			tcp_cfg.finwait1_time);
      break;
    case TCP_STATE_CLOSED:
      /* Cleanup should've been programmed already */
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
  if (!tc)
    return;
  tcp_connection_set_state (tc, TCP_STATE_CLOSED);
  tcp_connection_cleanup (tc);
}

static void
tcp_session_cleanup_ho (u32 conn_index)
{
  tcp_worker_ctx_t *wrk;
  tcp_connection_t *tc;

  tc = tcp_half_open_connection_get (conn_index);
  wrk = tcp_get_worker (tc->c_thread_index);
  tcp_timer_reset (&wrk->timer_wheel, tc, TCP_TIMER_RETRANSMIT_SYN);
  tcp_half_open_connection_free (tc);
}

static void
tcp_session_reset (u32 conn_index, u32 thread_index)
{
  tcp_connection_t *tc;
  tc = tcp_connection_get (conn_index, thread_index);
  tcp_send_reset (tc);
  tcp_connection_timers_reset (tc);
  tcp_cong_recovery_off (tc);
  tcp_connection_set_state (tc, TCP_STATE_CLOSED);
  session_transport_closed_notify (&tc->connection);
  tcp_program_cleanup (tcp_get_worker (thread_index), tc);
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
  tcp_worker_ctx_t *wrk = tcp_get_worker (tc->c_thread_index);
  int i;

  for (i = 0; i < TCP_N_TIMERS; i++)
    tcp_timer_reset (&wrk->timer_wheel, tc, i);
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

/**
 * Generate random iss as per rfc6528
 */
static u32
tcp_generate_random_iss (tcp_connection_t * tc)
{
  tcp_main_t *tm = &tcp_main;
  u64 tmp;

  if (tc->c_is_ip4)
    tmp = (u64) tc->c_lcl_ip.ip4.as_u32 << 32 | (u64) tc->c_rmt_ip.ip4.as_u32;
  else
    tmp = tc->c_lcl_ip.ip6.as_u64[0] ^ tc->c_lcl_ip.ip6.as_u64[1]
      ^ tc->c_rmt_ip.ip6.as_u64[0] ^ tc->c_rmt_ip.ip6.as_u64[1];

  tmp ^= tm->iss_seed.first | ((u64) tc->c_lcl_port << 16 | tc->c_rmt_port);
  tmp ^= tm->iss_seed.second;
  tmp = clib_xxhash (tmp) + clib_cpu_time_now ();
  return ((tmp >> 32) ^ (tmp & 0xffffffff));
}

/**
 * Initialize max segment size we're able to process.
 *
 * The value is constrained by the output interface's MTU and by the size
 * of the IP and TCP headers (see RFC6691). It is also what we advertise
 * to our peer.
 */
static void
tcp_init_rcv_mss (tcp_connection_t * tc)
{
  u8 ip_hdr_len;

  /* Already provided at connection init time */
  if (tc->mss)
    return;

  ip_hdr_len = tc->c_is_ip4 ? sizeof (ip4_header_t) : sizeof (ip6_header_t);
  tc->mss = tcp_cfg.default_mtu - sizeof (tcp_header_t) - ip_hdr_len;
}

static void
tcp_init_mss (tcp_connection_t * tc)
{
  u16 default_min_mss = 536;

  tcp_init_rcv_mss (tc);

  /* TODO consider PMTU discovery */
  tc->snd_mss = clib_min (tc->rcv_opts.mss, tc->mss);

  if (tc->snd_mss < 45)
    {
      /* Assume that at least the min default mss works */
      tc->snd_mss = default_min_mss;
      tc->rcv_opts.mss = default_min_mss;
    }

  /* We should have enough space for 40 bytes of options */
  ASSERT (tc->snd_mss > 45);

  /* If we use timestamp option, account for it */
  if (tcp_opts_tstamp (&tc->rcv_opts))
    tc->snd_mss -= TCP_OPTION_LEN_TIMESTAMP;
}

/**
 * Initialize connection send variables.
 */
void
tcp_init_snd_vars (tcp_connection_t * tc)
{
  /*
   * We use the time to randomize iss and for setting up the initial
   * timestamp. Make sure it's updated otherwise syn and ack in the
   * handshake may make it look as if time has flown in the opposite
   * direction for us.
   */
  tcp_set_time_now (tcp_get_worker (vlib_get_thread_index ()));

  tcp_init_rcv_mss (tc);
  tc->iss = tcp_generate_random_iss (tc);
  tc->snd_una = tc->iss;
  tc->snd_nxt = tc->iss + 1;
  tc->srtt = 0.1 * THZ;		/* 100 ms */

  if (!tcp_cfg.csum_offload)
    tc->cfg_flags |= TCP_CFG_F_NO_CSUM_OFFLOAD;
}

void
tcp_enable_pacing (tcp_connection_t * tc)
{
  u32 byte_rate;
  byte_rate = tc->cwnd / (tc->srtt * TCP_TICK);
  transport_connection_tx_pacer_init (&tc->connection, byte_rate, tc->cwnd);
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
  if (tc->state == TCP_STATE_SYN_RCVD)
    tcp_init_snd_vars (tc);

  tcp_cc_init (tc);

  if (!tc->c_is_ip4 && ip6_address_is_link_local_unicast (&tc->c_rmt_ip6))
    tcp_add_del_adjacency (tc, 1);

  /*  tcp_connection_fib_attach (tc); */

  if (transport_connection_is_tx_paced (&tc->connection)
      || tcp_cfg.enable_tx_pacing)
    tcp_enable_pacing (tc);

  if (tc->cfg_flags & TCP_CFG_F_RATE_SAMPLE)
    tcp_bt_init (tc);

  if (!tcp_cfg.allow_tso)
    tc->cfg_flags |= TCP_CFG_F_NO_TSO;

  tc->start_ts = tcp_time_now_us (tc->c_thread_index);
}

static int
tcp_alloc_custom_local_endpoint (tcp_main_t * tm, ip46_address_t * lcl_addr,
				 u16 * lcl_port, u8 is_ip4)
{
  int index, port;
  if (is_ip4)
    {
      index = tm->last_v4_addr_rotor++;
      if (tm->last_v4_addr_rotor >= vec_len (tcp_cfg.ip4_src_addrs))
	tm->last_v4_addr_rotor = 0;
      lcl_addr->ip4.as_u32 = tcp_cfg.ip4_src_addrs[index].as_u32;
    }
  else
    {
      index = tm->last_v6_addr_rotor++;
      if (tm->last_v6_addr_rotor >= vec_len (tcp_cfg.ip6_src_addrs))
	tm->last_v6_addr_rotor = 0;
      clib_memcpy_fast (&lcl_addr->ip6, &tcp_cfg.ip6_src_addrs[index],
			sizeof (ip6_address_t));
    }
  port = transport_alloc_local_port (TRANSPORT_PROTO_TCP, lcl_addr);
  if (port < 1)
    return SESSION_E_NOPORT;
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
  if ((rmt->is_ip4 && vec_len (tcp_cfg.ip4_src_addrs))
      || (!rmt->is_ip4 && vec_len (tcp_cfg.ip6_src_addrs)))
    rv = tcp_alloc_custom_local_endpoint (tm, &lcl_addr, &lcl_port,
					  rmt->is_ip4);
  else
    rv = transport_alloc_local_endpoint (TRANSPORT_PROTO_TCP,
					 rmt, &lcl_addr, &lcl_port);

  if (rv)
    {
      if (rv != SESSION_E_PORTINUSE)
	return rv;

      if (session_lookup_connection (rmt->fib_index, &lcl_addr, &rmt->ip,
				     lcl_port, rmt->port, TRANSPORT_PROTO_UDP,
				     rmt->is_ip4))
	return SESSION_E_PORTINUSE;

      /* 5-tuple is available so increase lcl endpoint refcount and proceed
       * with connection allocation */
      transport_share_local_endpoint (TRANSPORT_PROTO_UDP, &lcl_addr,
				      lcl_port);
    }

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
  tc->cc_algo = tcp_cc_algo_get (tcp_cfg.cc_algo);
  /* The other connection vars will be initialized after SYN ACK */
  tcp_connection_timers_init (tc);
  tc->mss = rmt->mss;

  TCP_EVT (TCP_EVT_OPEN, tc);
  tc->state = TCP_STATE_SYN_SENT;
  tcp_init_snd_vars (tc);
  tcp_send_syn (tc);
  clib_spinlock_unlock_if_init (&tm->half_open_lock);

  return tc->c_c_index;
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
  u32 __clib_unused thread_index = va_arg (*args, u32);
  u32 verbose = va_arg (*args, u32);
  tcp_connection_t *tc = tcp_listener_get (tci);
  s = format (s, "%-" SESSION_CLI_ID_LEN "U", format_tcp_connection_id, tc);
  if (verbose)
    s = format (s, "%-" SESSION_CLI_STATE_LEN "U", format_tcp_state,
		tc->state);
  return s;
}

static u8 *
format_tcp_half_open_session (u8 * s, va_list * args)
{
  u32 tci = va_arg (*args, u32);
  u32 __clib_unused thread_index = va_arg (*args, u32);
  tcp_connection_t *tc = tcp_half_open_connection_get (tci);
  return format (s, "%U", format_tcp_connection_id, tc);
}

static transport_connection_t *
tcp_session_get_transport (u32 conn_index, u32 thread_index)
{
  tcp_connection_t *tc = tcp_connection_get (conn_index, thread_index);
  if (PREDICT_FALSE (!tc))
    return 0;
  return &tc->connection;
}

static transport_connection_t *
tcp_half_open_session_get_transport (u32 conn_index)
{
  tcp_connection_t *tc = tcp_half_open_connection_get (conn_index);
  return &tc->connection;
}

static u16
tcp_session_cal_goal_size (tcp_connection_t * tc)
{
  u16 goal_size = tc->snd_mss;

  goal_size = tcp_cfg.max_gso_size - tc->snd_mss % tcp_cfg.max_gso_size;
  goal_size = clib_min (goal_size, tc->snd_wnd / 2);

  return goal_size > tc->snd_mss ? goal_size : tc->snd_mss;
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
  int snd_space;

  /* Fast path is disabled when recovery is on. @ref tcp_session_custom_tx
   * controls both retransmits and the sending of new data while congested
   */
  if (PREDICT_FALSE (tcp_in_cong_recovery (tc)
		     || tc->state == TCP_STATE_CLOSED))
    return 0;

  snd_space = tcp_available_output_snd_space (tc);

  /* If we got dupacks or sacked bytes but we're not yet in recovery, try
   * to force the peer to send enough dupacks to start retransmitting as
   * per Limited Transmit (RFC3042)
   */
  if (PREDICT_FALSE (tc->rcv_dupacks || tc->sack_sb.sacked_bytes))
    {
      int snt_limited, n_pkts;

      n_pkts = tcp_opts_sack_permitted (&tc->rcv_opts)
	? tc->sack_sb.reorder - 1 : 2;

      if ((seq_lt (tc->limited_transmit, tc->snd_nxt - n_pkts * tc->snd_mss)
	   || seq_gt (tc->limited_transmit, tc->snd_nxt)))
	tc->limited_transmit = tc->snd_nxt;

      ASSERT (seq_leq (tc->limited_transmit, tc->snd_nxt));

      snt_limited = tc->snd_nxt - tc->limited_transmit;
      snd_space = clib_max (n_pkts * tc->snd_mss - snt_limited, 0);
    }
  return tcp_round_snd_space (tc, snd_space);
}

u32
tcp_snd_space (tcp_connection_t * tc)
{
  return tcp_snd_space_inline (tc);
}

static int
tcp_session_send_params (transport_connection_t * trans_conn,
			 transport_send_params_t * sp)
{
  tcp_connection_t *tc = (tcp_connection_t *) trans_conn;

  /* Ensure snd_mss does accurately reflect the amount of data we can push
   * in a segment. This also makes sure that options are updated according to
   * the current state of the connection. */
  tcp_update_burst_snd_vars (tc);

  if (PREDICT_FALSE (tc->cfg_flags & TCP_CFG_F_TSO))
    sp->snd_mss = tcp_session_cal_goal_size (tc);
  else
    sp->snd_mss = tc->snd_mss;

  sp->snd_space = clib_min (tcp_snd_space_inline (tc),
			    tc->snd_wnd - (tc->snd_nxt - tc->snd_una));

  ASSERT (seq_geq (tc->snd_nxt, tc->snd_una));
  /* This still works if fast retransmit is on */
  sp->tx_offset = tc->snd_nxt - tc->snd_una;
  sp->flags = sp->snd_space ? 0 : TRANSPORT_SND_F_DESCHED;

  /* Track last byte in tx fifo as potential psh sequence */
  tc->psh_seq = tc->snd_una + sp->max_dequeue - 1;

  return 0;
}

static void
tcp_timer_waitclose_handler (tcp_connection_t * tc)
{
  tcp_worker_ctx_t *wrk = tcp_get_worker (tc->c_thread_index);

  switch (tc->state)
    {
    case TCP_STATE_CLOSE_WAIT:
      tcp_connection_timers_reset (tc);
      /* App never returned with a close */
      if (!(tc->flags & TCP_CONN_FINPNDG))
	{
	  tcp_connection_set_state (tc, TCP_STATE_CLOSED);
	  session_transport_closed_notify (&tc->connection);
	  tcp_program_cleanup (wrk, tc);
	  tcp_worker_stats_inc (wrk, to_closewait, 1);
	  break;
	}

      /* Send FIN either way and switch to LAST_ACK. */
      tcp_cong_recovery_off (tc);
      /* Make sure we don't try to send unsent data */
      tc->snd_nxt = tc->snd_una;
      tcp_send_fin (tc);
      tcp_connection_set_state (tc, TCP_STATE_LAST_ACK);
      session_transport_closed_notify (&tc->connection);

      /* Make sure we don't wait in LAST ACK forever */
      tcp_timer_set (&wrk->timer_wheel, tc, TCP_TIMER_WAITCLOSE,
		     tcp_cfg.lastack_time);
      tcp_worker_stats_inc (wrk, to_closewait2, 1);

      /* Don't delete the connection yet */
      break;
    case TCP_STATE_FIN_WAIT_1:
      tcp_connection_timers_reset (tc);
      if (tc->flags & TCP_CONN_FINPNDG)
	{
	  /* If FIN pending, we haven't sent everything, but we did try.
	   * Notify session layer that transport is closed. */
	  tcp_connection_set_state (tc, TCP_STATE_CLOSED);
	  tcp_send_reset (tc);
	  tcp_program_cleanup (wrk, tc);
	}
      else
	{
	  /* We've sent the fin but no progress. Close the connection and
	   * to make sure everything is flushed, setup a cleanup timer */
	  tcp_connection_set_state (tc, TCP_STATE_CLOSED);
	  tcp_program_cleanup (wrk, tc);
	}
      session_transport_closed_notify (&tc->connection);
      tcp_worker_stats_inc (wrk, to_finwait1, 1);
      break;
    case TCP_STATE_LAST_ACK:
      tcp_connection_timers_reset (tc);
      tcp_connection_set_state (tc, TCP_STATE_CLOSED);
      session_transport_closed_notify (&tc->connection);
      tcp_program_cleanup (wrk, tc);
      tcp_worker_stats_inc (wrk, to_lastack, 1);
      break;
    case TCP_STATE_CLOSING:
      tcp_connection_timers_reset (tc);
      tcp_connection_set_state (tc, TCP_STATE_CLOSED);
      session_transport_closed_notify (&tc->connection);
      tcp_program_cleanup (wrk, tc);
      tcp_worker_stats_inc (wrk, to_closing, 1);
      break;
    case TCP_STATE_FIN_WAIT_2:
      tcp_send_reset (tc);
      tcp_connection_timers_reset (tc);
      tcp_connection_set_state (tc, TCP_STATE_CLOSED);
      session_transport_closed_notify (&tc->connection);
      tcp_program_cleanup (wrk, tc);
      tcp_worker_stats_inc (wrk, to_finwait2, 1);
      break;
    case TCP_STATE_TIME_WAIT:
      tcp_connection_set_state (tc, TCP_STATE_CLOSED);
      tcp_program_cleanup (wrk, tc);
      break;
    default:
      clib_warning ("waitclose in state: %U", format_tcp_state, tc->state);
      break;
    }
}

/* *INDENT-OFF* */
static timer_expiration_handler *timer_expiration_handlers[TCP_N_TIMERS] =
{
    tcp_timer_retransmit_handler,
    tcp_timer_persist_handler,
    tcp_timer_waitclose_handler,
    tcp_timer_retransmit_syn_handler,
};
/* *INDENT-ON* */

static void
tcp_dispatch_pending_timers (tcp_worker_ctx_t * wrk)
{
  u32 n_timers, connection_index, timer_id, thread_index, timer_handle;
  tcp_connection_t *tc;
  int i;

  if (!(n_timers = clib_fifo_elts (wrk->pending_timers)))
    return;

  thread_index = wrk->vm->thread_index;
  for (i = 0; i < clib_min (n_timers, wrk->max_timers_per_loop); i++)
    {
      clib_fifo_sub1 (wrk->pending_timers, timer_handle);
      connection_index = timer_handle & 0x0FFFFFFF;
      timer_id = timer_handle >> 28;

      if (PREDICT_TRUE (timer_id != TCP_TIMER_RETRANSMIT_SYN))
	tc = tcp_connection_get (connection_index, thread_index);
      else
	tc = tcp_half_open_connection_get (connection_index);

      if (PREDICT_FALSE (!tc))
	continue;

      /* Skip if the timer is not pending. Probably it was reset while
       * waiting for dispatch */
      if (PREDICT_FALSE (!(tc->pending_timers & (1 << timer_id))))
	continue;

      tc->pending_timers &= ~(1 << timer_id);

      /* Skip timer if it was rearmed while pending dispatch */
      if (PREDICT_FALSE (tc->timers[timer_id] != TCP_TIMER_HANDLE_INVALID))
	continue;

      (*timer_expiration_handlers[timer_id]) (tc);
    }

  if (thread_index == 0 && clib_fifo_elts (wrk->pending_timers))
    session_queue_run_on_main_thread (wrk->vm);
}

static void
tcp_handle_cleanups (tcp_worker_ctx_t * wrk, clib_time_type_t now)
{
  u32 thread_index = wrk->vm->thread_index;
  tcp_cleanup_req_t *req;
  tcp_connection_t *tc;

  while (clib_fifo_elts (wrk->pending_cleanups))
    {
      req = clib_fifo_head (wrk->pending_cleanups);
      if (req->free_time > now)
	break;
      clib_fifo_sub2 (wrk->pending_cleanups, req);
      tc = tcp_connection_get (req->connection_index, thread_index);
      if (PREDICT_FALSE (!tc))
	continue;
      session_transport_delete_notify (&tc->connection);
      tcp_connection_cleanup (tc);
    }
}

static void
tcp_update_time (f64 now, u8 thread_index)
{
  tcp_worker_ctx_t *wrk = tcp_get_worker (thread_index);

  tcp_set_time_now (wrk);
  tcp_handle_cleanups (wrk, now);
  tcp_timer_expire_timers (&wrk->timer_wheel, now);
  tcp_dispatch_pending_timers (wrk);
}

static void
tcp_session_flush_data (transport_connection_t * tconn)
{
  /* Noop as the last segment is always sent with PSH flag on */
}

/* *INDENT-OFF* */
const static transport_proto_vft_t tcp_proto = {
  .enable = vnet_tcp_enable_disable,
  .start_listen = tcp_session_bind,
  .stop_listen = tcp_session_unbind,
  .push_header = tcp_session_push_header,
  .get_connection = tcp_session_get_transport,
  .get_listener = tcp_session_get_listener,
  .get_half_open = tcp_half_open_session_get_transport,
  .connect = tcp_session_open,
  .close = tcp_session_close,
  .cleanup = tcp_session_cleanup,
  .cleanup_ho = tcp_session_cleanup_ho,
  .reset = tcp_session_reset,
  .send_params = tcp_session_send_params,
  .update_time = tcp_update_time,
  .flush_data = tcp_session_flush_data,
  .custom_tx = tcp_session_custom_tx,
  .format_connection = format_tcp_session,
  .format_listener = format_tcp_listener_session,
  .format_half_open = format_tcp_half_open_session,
  .transport_options = {
    .name = "tcp",
    .short_name = "T",
    .tx_type = TRANSPORT_TX_PEEK,
    .service_type = TRANSPORT_SERVICE_VC,
  },
};
/* *INDENT-ON* */

void
tcp_connection_tx_pacer_update (tcp_connection_t * tc)
{
  if (!transport_connection_is_tx_paced (&tc->connection))
    return;

  f64 srtt = clib_min ((f64) tc->srtt * TCP_TICK, tc->mrtt_us);

  transport_connection_tx_pacer_update (&tc->connection,
					tcp_cc_get_pacing_rate (tc),
					srtt * CLIB_US_TIME_FREQ);
}

void
tcp_connection_tx_pacer_reset (tcp_connection_t * tc, u32 window,
			       u32 start_bucket)
{
  f64 srtt = clib_min ((f64) tc->srtt * TCP_TICK, tc->mrtt_us);
  transport_connection_tx_pacer_reset (&tc->connection,
				       tcp_cc_get_pacing_rate (tc),
				       start_bucket,
				       srtt * CLIB_US_TIME_FREQ);
}

void
tcp_reschedule (tcp_connection_t * tc)
{
  if (tcp_in_cong_recovery (tc) || tcp_snd_space_inline (tc))
    transport_connection_reschedule (&tc->connection);
}

static void
tcp_expired_timers_dispatch (u32 * expired_timers)
{
  u32 thread_index = vlib_get_thread_index (), n_left, max_per_loop;
  u32 connection_index, timer_id, n_expired, max_loops;
  tcp_worker_ctx_t *wrk;
  tcp_connection_t *tc;
  int i;

  wrk = tcp_get_worker (thread_index);
  n_expired = vec_len (expired_timers);
  tcp_worker_stats_inc (wrk, timer_expirations, n_expired);
  n_left = clib_fifo_elts (wrk->pending_timers);

  /*
   * Invalidate all timer handles before dispatching. This avoids dangling
   * index references to timer wheel pool entries that have been freed.
   */
  for (i = 0; i < n_expired; i++)
    {
      connection_index = expired_timers[i] & 0x0FFFFFFF;
      timer_id = expired_timers[i] >> 28;

      if (timer_id != TCP_TIMER_RETRANSMIT_SYN)
	tc = tcp_connection_get (connection_index, thread_index);
      else
	tc = tcp_half_open_connection_get (connection_index);

      TCP_EVT (TCP_EVT_TIMER_POP, connection_index, timer_id);

      tc->timers[timer_id] = TCP_TIMER_HANDLE_INVALID;
      tc->pending_timers |= (1 << timer_id);
    }

  clib_fifo_add (wrk->pending_timers, expired_timers, n_expired);

  max_loops = clib_max (1, 0.5 * TCP_TIMER_TICK * wrk->vm->loops_per_second);
  max_per_loop = clib_max ((n_left + n_expired) / max_loops, 10);
  max_per_loop = clib_min (max_per_loop, VLIB_FRAME_SIZE);
  wrk->max_timers_per_loop = clib_max (n_left ? wrk->max_timers_per_loop : 0,
				       max_per_loop);

  if (thread_index == 0)
    session_queue_run_on_main_thread (wrk->vm);
}

static void
tcp_initialize_iss_seed (tcp_main_t * tm)
{
  u32 default_seed = random_default_seed ();
  u64 time_now = clib_cpu_time_now ();

  tm->iss_seed.first = (u64) random_u32 (&default_seed) << 32;
  tm->iss_seed.second = random_u64 (&time_now);
}

static clib_error_t *
tcp_main_enable (vlib_main_t * vm)
{
  vlib_thread_main_t *vtm = vlib_get_thread_main ();
  u32 num_threads, n_workers, prealloc_conn_per_wrk;
  tcp_connection_t *tc __attribute__ ((unused));
  tcp_main_t *tm = vnet_get_tcp_main ();
  tcp_worker_ctx_t *wrk;
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
  vec_validate (tm->wrk_ctx, num_threads - 1);
  n_workers = num_threads == 1 ? 1 : vtm->n_threads;
  prealloc_conn_per_wrk = tcp_cfg.preallocated_connections / n_workers;

  wrk = &tm->wrk_ctx[0];
  wrk->tco_next_node[0] = vlib_node_get_next (vm, session_queue_node.index,
					      tcp4_output_node.index);
  wrk->tco_next_node[1] = vlib_node_get_next (vm, session_queue_node.index,
					      tcp6_output_node.index);

  for (thread = 0; thread < num_threads; thread++)
    {
      wrk = &tm->wrk_ctx[thread];

      vec_validate (wrk->pending_deq_acked, 255);
      vec_validate (wrk->pending_disconnects, 255);
      vec_validate (wrk->pending_resets, 255);
      vec_reset_length (wrk->pending_deq_acked);
      vec_reset_length (wrk->pending_disconnects);
      vec_reset_length (wrk->pending_resets);
      wrk->vm = vlib_mains[thread];
      wrk->max_timers_per_loop = 10;

      if (thread > 0)
	{
	  wrk->tco_next_node[0] = tm->wrk_ctx[0].tco_next_node[0];
	  wrk->tco_next_node[1] = tm->wrk_ctx[0].tco_next_node[1];
	}

      /*
       * Preallocate connections. Assume that thread 0 won't
       * use preallocated threads when running multi-core
       */
      if ((thread > 0 || num_threads == 1) && prealloc_conn_per_wrk)
	pool_init_fixed (wrk->connections, prealloc_conn_per_wrk);

      tcp_timer_initialize_wheel (&wrk->timer_wheel,
				  tcp_expired_timers_dispatch,
				  vlib_time_now (vm));
    }

  /*
   * Use a preallocated half-open connection pool?
   */
  if (tcp_cfg.preallocated_half_open_connections)
    pool_init_fixed (tm->half_open_connections,
		     tcp_cfg.preallocated_half_open_connections);

  if (num_threads > 1)
    {
      clib_spinlock_init (&tm->half_open_lock);
    }

  tcp_initialize_iss_seed (tm);

  tm->bytes_per_buffer = vlib_buffer_get_default_data_size (vm);
  tm->cc_last_type = TCP_CC_LAST;

  tm->ipl_next_node[0] = vlib_node_get_next (vm, session_queue_node.index,
					     ip4_lookup_node.index);
  tm->ipl_next_node[1] = vlib_node_get_next (vm, session_queue_node.index,
					     ip6_lookup_node.index);
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

/**
 * Initialize default values for tcp parameters
 */
static void
tcp_configuration_init (void)
{
  /* Initial wnd for SYN. Fifos are not allocated at that point so use some
   * predefined value. For SYN-ACK we still want the scale to be computed in
   * the same way */
  tcp_cfg.max_rx_fifo = 32 << 20;
  tcp_cfg.min_rx_fifo = 4 << 10;

  tcp_cfg.default_mtu = 1500;
  tcp_cfg.initial_cwnd_multiplier = 0;
  tcp_cfg.enable_tx_pacing = 1;
  tcp_cfg.allow_tso = 0;
  tcp_cfg.csum_offload = 1;
  tcp_cfg.cc_algo = TCP_CC_CUBIC;
  tcp_cfg.rwnd_min_update_ack = 1;
  tcp_cfg.max_gso_size = TCP_MAX_GSO_SZ;

  /* Time constants defined as timer tick (100us) multiples */
  tcp_cfg.closewait_time = 20000;	/* 2s */
  tcp_cfg.timewait_time = 100000;	/* 10s */
  tcp_cfg.finwait1_time = 600000;	/* 60s */
  tcp_cfg.lastack_time = 300000;	/* 30s */
  tcp_cfg.finwait2_time = 300000;	/* 30s */
  tcp_cfg.closing_time = 300000;	/* 30s */

  /* This value is seconds */
  tcp_cfg.cleanup_time = 0.1;	/* 100ms */
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

  tcp_configuration_init ();

  tm->cc_algo_by_name = hash_create_string (0, sizeof (uword));

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
