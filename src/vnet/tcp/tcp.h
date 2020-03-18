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

#ifndef _vnet_tcp_h_
#define _vnet_tcp_h_

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/session/session.h>
#include <vnet/tcp/tcp_types.h>
#include <vnet/tcp/tcp_timer.h>
#include <vnet/tcp/tcp_debug.h>
#include <vnet/tcp/tcp_sack.h>
#include <vnet/tcp/tcp_bt.h>
#include <vnet/tcp/tcp_cc.h>

typedef void (timer_expiration_handler) (tcp_connection_t * tc);

extern timer_expiration_handler tcp_timer_delack_handler;
extern timer_expiration_handler tcp_timer_retransmit_handler;
extern timer_expiration_handler tcp_timer_persist_handler;
extern timer_expiration_handler tcp_timer_retransmit_syn_handler;

typedef enum _tcp_error
{
#define tcp_error(n,s) TCP_ERROR_##n,
#include <vnet/tcp/tcp_error.def>
#undef tcp_error
  TCP_N_ERROR,
} tcp_error_t;

typedef struct _tcp_lookup_dispatch
{
  u8 next, error;
} tcp_lookup_dispatch_t;

#define foreach_tcp_wrk_stat					\
  _(timer_expirations, u64, "timer expirations")		\
  _(rxt_segs, u64, "segments retransmitted")			\
  _(tr_events, u32, "timer retransmit events")			\
  _(to_closewait, u32, "timeout close-wait")			\
  _(to_closewait2, u32, "timeout close-wait w/data")		\
  _(to_finwait1, u32, "timeout fin-wait-1")			\
  _(to_finwait2, u32, "timeout fin-wait-2")			\
  _(to_lastack, u32, "timeout last-ack")			\
  _(to_closing, u32, "timeout closing")				\
  _(tr_abort, u32, "timer retransmit abort")			\
  _(rst_unread, u32, "reset on close due to unread data")	\

typedef struct tcp_wrk_stats_
{
#define _(name, type, str) type name;
  foreach_tcp_wrk_stat
#undef _
} tcp_wrk_stats_t;

typedef struct tcp_free_req_
{
  clib_time_type_t free_time;
  u32 connection_index;
} tcp_cleanup_req_t;

typedef struct tcp_worker_ctx_
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);

  /** worker's pool of connections */
  tcp_connection_t *connections;

  /** vector of pending ack dequeues */
  u32 *pending_deq_acked;

  /** vector of pending disconnect notifications */
  u32 *pending_disconnects;

  /** vector of pending reset notifications */
  u32 *pending_resets;

  /** convenience pointer to this thread's vlib main */
  vlib_main_t *vm;

  /** worker time */
  u32 time_now;

  /* Max timers to be handled per dispatch loop */
  u32 max_timers_per_loop;

  /** tx frames for ip 4/6 lookup nodes */
  vlib_frame_t *ip_lookup_tx_frames[2];

    CLIB_CACHE_LINE_ALIGN_MARK (cacheline1);

  /** cached 'on the wire' options for bursts */
  u8 cached_opts[40];

  /** tx buffer free list */
  u32 *tx_buffers;

  /* Fifo of pending timer expirations */
  u32 *pending_timers;

  /* fifo of pending free requests */
  tcp_cleanup_req_t *pending_cleanups;

  /** worker timer wheel */
  tw_timer_wheel_16t_2w_512sl_t timer_wheel;

    CLIB_CACHE_LINE_ALIGN_MARK (cacheline2);

  tcp_wrk_stats_t stats;
} tcp_worker_ctx_t;

#define tcp_worker_stats_inc(_ti,_stat,_val) 		\
  tcp_main.wrk_ctx[_ti].stats._stat += _val

#define tcp_workerp_stats_inc(_wrk,_stat,_val) 		\
  _wrk->stats._stat += _val

typedef struct tcp_iss_seed_
{
  u64 first;
  u64 second;
} tcp_iss_seed_t;

typedef struct tcp_configuration_
{
  /** Max rx fifo size for a session (in bytes). It is used in to compute the
   *  rfc 7323 window scaling factor */
  u32 max_rx_fifo;

  /** Min rx fifo for a session (in bytes) */
  u32 min_rx_fifo;

  /** Default MTU to be used when establishing connections */
  u16 default_mtu;

  /** Initial CWND multiplier, which multiplies MSS to determine initial CWND.
   *  Set 0 to determine the initial CWND by another way */
  u16 initial_cwnd_multiplier;

  /** Enable tx pacing for new connections */
  u8 enable_tx_pacing;

  /** Allow use of TSO whenever available */
  u8 allow_tso;

  /** Set if csum offloading is enabled */
  u8 csum_offload;

  /** Default congestion control algorithm type */
  tcp_cc_algorithm_type_e cc_algo;

  /** Min rwnd, as number of snd_mss segments, for update ack to be sent after
   * a zero rwnd advertisement */
  u32 rwnd_min_update_ack;

  /** Delayed ack time (disabled) */
  u16 delack_time;

  /** Timer ticks to wait for close from app */
  u16 closewait_time;

  /** Timer ticks to wait in time-wait. Also known as 2MSL */
  u16 timewait_time;

  /** Timer ticks to wait in fin-wait1 to send fin and rcv fin-ack */
  u16 finwait1_time;

  /** Timer ticks to wait in last ack for ack */
  u16 lastack_time;

  /** Timer ticks to wait in fin-wait2 for fin */
  u16 finwait2_time;

  /** Timer ticks to wait in closing for fin ack */
  u16 closing_time;

  /** Time to wait (sec) before cleaning up the connection */
  f32 cleanup_time;

  /** Number of preallocated connections */
  u32 preallocated_connections;

  /** Number of preallocated half-open connections */
  u32 preallocated_half_open_connections;

  /** Vectors of src addresses. Optional unless one needs > 63K active-opens */
  ip4_address_t *ip4_src_addrs;
  ip6_address_t *ip6_src_addrs;

  /** Fault-injection. Debug only */
  f64 buffer_fail_fraction;
} tcp_configuration_t;

typedef struct _tcp_main
{
  /** per-worker context */
  tcp_worker_ctx_t *wrk_ctx;

  /* Pool of listeners. */
  tcp_connection_t *listener_pool;

  f64 tstamp_ticks_per_clock;

  /** vlib buffer size */
  u32 bytes_per_buffer;

  /** Dispatch table by state and flags */
  tcp_lookup_dispatch_t dispatch_table[TCP_N_STATES][64];

  clib_spinlock_t half_open_lock;

  /** Pool of half-open connections on which we've sent a SYN */
  tcp_connection_t *half_open_connections;

  /** Seed used to generate random iss */
  tcp_iss_seed_t iss_seed;

  /** Congestion control algorithms registered */
  tcp_cc_algorithm_t *cc_algos;

  /** Hash table of cc algorithms by name */
  uword *cc_algo_by_name;

  /** Last cc algo registered */
  tcp_cc_algorithm_type_e cc_last_type;

  /** Flag that indicates if stack is on or off */
  u8 is_enabled;

  /** Flag that indicates if v4 punting is enabled */
  u8 punt_unknown4;

  /** Flag that indicates if v6 punting is enabled */
  u8 punt_unknown6;

  /** Rotor for v4 source addresses */
  u32 last_v4_addr_rotor;

  /** Rotor for v6 source addresses */
  u32 last_v6_addr_rotor;

  /** Protocol configuration */
  tcp_configuration_t cfg;
} tcp_main_t;

extern tcp_main_t tcp_main;
extern vlib_node_registration_t tcp4_input_node;
extern vlib_node_registration_t tcp6_input_node;
extern vlib_node_registration_t tcp4_output_node;
extern vlib_node_registration_t tcp6_output_node;
extern vlib_node_registration_t tcp4_established_node;
extern vlib_node_registration_t tcp6_established_node;
extern vlib_node_registration_t tcp4_syn_sent_node;
extern vlib_node_registration_t tcp6_syn_sent_node;
extern vlib_node_registration_t tcp4_rcv_process_node;
extern vlib_node_registration_t tcp6_rcv_process_node;
extern vlib_node_registration_t tcp4_listen_node;
extern vlib_node_registration_t tcp6_listen_node;

#define tcp_cfg tcp_main.cfg
#define tcp_node_index(node_id, is_ip4) 				\
  ((is_ip4) ? tcp4_##node_id##_node.index : tcp6_##node_id##_node.index)

always_inline tcp_main_t *
vnet_get_tcp_main ()
{
  return &tcp_main;
}

always_inline tcp_worker_ctx_t *
tcp_get_worker (u32 thread_index)
{
  ASSERT (thread_index < vec_len (tcp_main.wrk_ctx));
  return &tcp_main.wrk_ctx[thread_index];
}

#if (VLIB_BUFFER_TRACE_TRAJECTORY)
#define tcp_trajectory_add_start(b, start)			\
{								\
    (*vlib_buffer_trace_trajectory_cb) (b, start);		\
}
#else
#define tcp_trajectory_add_start(b, start)
#endif

clib_error_t *vnet_tcp_enable_disable (vlib_main_t * vm, u8 is_en);

void tcp_punt_unknown (vlib_main_t * vm, u8 is_ip4, u8 is_add);
void tcp_connection_close (tcp_connection_t * tc);
void tcp_connection_cleanup (tcp_connection_t * tc);
void tcp_connection_del (tcp_connection_t * tc);
int tcp_half_open_connection_cleanup (tcp_connection_t * tc);
tcp_connection_t *tcp_connection_alloc (u8 thread_index);
tcp_connection_t *tcp_connection_alloc_w_base (u8 thread_index,
					       tcp_connection_t * base);
void tcp_connection_free (tcp_connection_t * tc);
int tcp_configure_v4_source_address_range (vlib_main_t * vm,
					   ip4_address_t * start,
					   ip4_address_t * end, u32 table_id);
int tcp_configure_v6_source_address_range (vlib_main_t * vm,
					   ip6_address_t * start,
					   ip6_address_t * end, u32 table_id);

void tcp_make_fin (tcp_connection_t * tc, vlib_buffer_t * b);
void tcp_make_synack (tcp_connection_t * ts, vlib_buffer_t * b);
void tcp_send_reset_w_pkt (tcp_connection_t * tc, vlib_buffer_t * pkt,
			   u32 thread_index, u8 is_ip4);
void tcp_send_reset (tcp_connection_t * tc);
void tcp_send_syn (tcp_connection_t * tc);
void tcp_send_synack (tcp_connection_t * tc);
void tcp_send_fin (tcp_connection_t * tc);
void tcp_send_ack (tcp_connection_t * tc);
void tcp_update_burst_snd_vars (tcp_connection_t * tc);
void tcp_send_window_update_ack (tcp_connection_t * tc);

void tcp_program_ack (tcp_connection_t * tc);
void tcp_program_dupack (tcp_connection_t * tc);
void tcp_program_retransmit (tcp_connection_t * tc);

u32 tcp_snd_space (tcp_connection_t * tc);
int tcp_fastrecovery_prr_snd_space (tcp_connection_t * tc);

fib_node_index_t tcp_lookup_rmt_in_fib (tcp_connection_t * tc);

u32 tcp_session_push_header (transport_connection_t * tconn,
			     vlib_buffer_t * b);
int tcp_session_custom_tx (void *conn, u32 max_burst_size);

void tcp_connection_timers_init (tcp_connection_t * tc);
void tcp_connection_timers_reset (tcp_connection_t * tc);
void tcp_init_snd_vars (tcp_connection_t * tc);
void tcp_connection_init_vars (tcp_connection_t * tc);
void tcp_connection_tx_pacer_update (tcp_connection_t * tc);
void tcp_connection_tx_pacer_reset (tcp_connection_t * tc, u32 window,
				    u32 start_bucket);
void tcp_program_cleanup (tcp_worker_ctx_t * wrk, tcp_connection_t * tc);

format_function_t format_tcp_state;
format_function_t format_tcp_flags;
format_function_t format_tcp_sacks;
format_function_t format_tcp_rcv_sacks;
format_function_t format_tcp_connection;
format_function_t format_tcp_connection_id;

always_inline void
tcp_timer_set (tcp_connection_t * tc, u8 timer_id, u32 interval)
{
  ASSERT (tc->c_thread_index == vlib_get_thread_index ());
  ASSERT (tc->timers[timer_id] == TCP_TIMER_HANDLE_INVALID);
  tc->timers[timer_id] =
    tw_timer_start_16t_2w_512sl (&tcp_main.
				 wrk_ctx[tc->c_thread_index].timer_wheel,
				 tc->c_c_index, timer_id, interval);
}

always_inline void
tcp_timer_reset (tcp_connection_t * tc, u8 timer_id)
{
  ASSERT (tc->c_thread_index == vlib_get_thread_index ());
  if (tc->timers[timer_id] == TCP_TIMER_HANDLE_INVALID)
    return;

  tw_timer_stop_16t_2w_512sl (&tcp_main.
			      wrk_ctx[tc->c_thread_index].timer_wheel,
			      tc->timers[timer_id]);
  tc->timers[timer_id] = TCP_TIMER_HANDLE_INVALID;
}

always_inline void
tcp_timer_update (tcp_connection_t * tc, u8 timer_id, u32 interval)
{
  ASSERT (tc->c_thread_index == vlib_get_thread_index ());
  if (tc->timers[timer_id] != TCP_TIMER_HANDLE_INVALID)
    tw_timer_update_16t_2w_512sl (&tcp_main.
				  wrk_ctx[tc->c_thread_index].timer_wheel,
				  tc->timers[timer_id], interval);
  else
    tc->timers[timer_id] =
      tw_timer_start_16t_2w_512sl (&tcp_main.
				   wrk_ctx[tc->c_thread_index].timer_wheel,
				   tc->c_c_index, timer_id, interval);
}

always_inline void
tcp_retransmit_timer_set (tcp_connection_t * tc)
{
  ASSERT (tc->snd_una != tc->snd_una_max);
  tcp_timer_set (tc, TCP_TIMER_RETRANSMIT,
		 clib_max (tc->rto * TCP_TO_TIMER_TICK, 1));
}

always_inline void
tcp_retransmit_timer_reset (tcp_connection_t * tc)
{
  tcp_timer_reset (tc, TCP_TIMER_RETRANSMIT);
}

always_inline void
tcp_retransmit_timer_force_update (tcp_connection_t * tc)
{
  tcp_timer_update (tc, TCP_TIMER_RETRANSMIT,
		    clib_max (tc->rto * TCP_TO_TIMER_TICK, 1));
}

always_inline void
tcp_persist_timer_set (tcp_connection_t * tc)
{
  /* Reuse RTO. It's backed off in handler */
  tcp_timer_set (tc, TCP_TIMER_PERSIST,
		 clib_max (tc->rto * TCP_TO_TIMER_TICK, 1));
}

always_inline void
tcp_persist_timer_update (tcp_connection_t * tc)
{
  u32 interval;

  if (seq_leq (tc->snd_una, tc->snd_congestion + tc->burst_acked))
    interval = 1;
  else
    interval = clib_max (tc->rto * TCP_TO_TIMER_TICK, 1);

  tcp_timer_update (tc, TCP_TIMER_PERSIST, interval);
}

always_inline void
tcp_persist_timer_reset (tcp_connection_t * tc)
{
  tcp_timer_reset (tc, TCP_TIMER_PERSIST);
}

always_inline void
tcp_retransmit_timer_update (tcp_connection_t * tc)
{
  if (tc->snd_una == tc->snd_nxt)
    {
      tcp_retransmit_timer_reset (tc);
      if (tc->snd_wnd < tc->snd_mss)
	tcp_persist_timer_update (tc);
    }
  else
    tcp_timer_update (tc, TCP_TIMER_RETRANSMIT,
		      clib_max (tc->rto * TCP_TO_TIMER_TICK, 1));
}

always_inline u8
tcp_timer_is_active (tcp_connection_t * tc, tcp_timers_e timer)
{
  return tc->timers[timer] != TCP_TIMER_HANDLE_INVALID;
}

#define tcp_validate_txf_size(_tc, _a) 					\
  ASSERT(_tc->state != TCP_STATE_ESTABLISHED 				\
	 || transport_max_tx_dequeue (&_tc->connection) >= _a)

#endif /* _vnet_tcp_h_ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
