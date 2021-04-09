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

extern timer_expiration_handler tcp_timer_retransmit_handler;
extern timer_expiration_handler tcp_timer_persist_handler;
extern timer_expiration_handler tcp_timer_retransmit_syn_handler;

typedef enum _tcp_error
{
#define tcp_error(f, n, s, d) TCP_ERROR_##f,
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
  _(no_buffer, u32, "out of buffers")				\

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

  /** Time used for high precision (us) measurements in seconds */
  f64 time_us;

  /** Time measured in @ref TCP_TSTAMP_TICK used for time stamps */
  u32 time_tstamp;

  /* Max timers to be handled per dispatch loop */
  u32 max_timers_per_loop;

  /* Fifo of pending timer expirations */
  u32 *pending_timers;

    CLIB_CACHE_LINE_ALIGN_MARK (cacheline1);

  /** cached 'on the wire' options for bursts */
  u8 cached_opts[40];

  /** tx buffer free list */
  u32 *tx_buffers;

  /* fifo of pending free requests */
  tcp_cleanup_req_t *pending_cleanups;

  /** Session layer edge indices to tcp output */
  u32 tco_next_node[2];

  /** worker timer wheel */
  tcp_timer_wheel_t timer_wheel;

    CLIB_CACHE_LINE_ALIGN_MARK (cacheline2);

  tcp_wrk_stats_t stats;
} tcp_worker_ctx_t;

#define tcp_worker_stats_inc(_wrk,_stat,_val) 		\
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

  /** Timer ticks to wait for close from app */
  u32 closewait_time;

  /** Timer ticks to wait in time-wait. Also known as 2MSL */
  u32 timewait_time;

  /** Timer ticks to wait in fin-wait1 to send fin and rcv fin-ack */
  u32 finwait1_time;

  /** Timer ticks to wait in last ack for ack */
  u32 lastack_time;

  /** Timer ticks to wait in fin-wait2 for fin */
  u32 finwait2_time;

  /** Timer ticks to wait in closing for fin ack */
  u32 closing_time;

  /** Timer ticks to wait for free buffer */
  u32 alloc_err_timeout;

  /** Time to wait (sec) before cleaning up the connection */
  f32 cleanup_time;

  /** Number of preallocated connections */
  u32 preallocated_connections;

  /** Maxium allowed GSO packet size */
  u32 max_gso_size;

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

  /** vlib buffer size */
  u32 bytes_per_buffer;

  /** Session layer edge indices to ip lookup (syns, rst) */
  u32 ipl_next_node[2];

  /** Dispatch table by state and flags */
  tcp_lookup_dispatch_t dispatch_table[TCP_N_STATES][64];

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

  /** message ID base for API */
  u16 msg_id_base;
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

tcp_connection_t *tcp_connection_alloc (u8 thread_index);
tcp_connection_t *tcp_connection_alloc_w_base (u8 thread_index,
					       tcp_connection_t **base);
void tcp_connection_free (tcp_connection_t * tc);
void tcp_connection_close (tcp_connection_t * tc);
void tcp_connection_cleanup (tcp_connection_t * tc);
void tcp_connection_del (tcp_connection_t * tc);
int tcp_half_open_connection_cleanup (tcp_connection_t * tc);

void tcp_send_reset_w_pkt (tcp_connection_t * tc, vlib_buffer_t * pkt,
			   u32 thread_index, u8 is_ip4);
void tcp_send_reset (tcp_connection_t * tc);
void tcp_send_syn (tcp_connection_t * tc);
void tcp_send_synack (tcp_connection_t * tc);
void tcp_send_fin (tcp_connection_t * tc);
void tcp_send_ack (tcp_connection_t * tc);
void tcp_send_window_update_ack (tcp_connection_t * tc);

void tcp_program_ack (tcp_connection_t * tc);
void tcp_program_dupack (tcp_connection_t * tc);
void tcp_program_retransmit (tcp_connection_t * tc);

void tcp_update_burst_snd_vars (tcp_connection_t * tc);
u32 tcp_snd_space (tcp_connection_t * tc);
int tcp_fastrecovery_prr_snd_space (tcp_connection_t * tc);
void tcp_reschedule (tcp_connection_t * tc);
fib_node_index_t tcp_lookup_rmt_in_fib (tcp_connection_t * tc);
u32 tcp_session_push_header (transport_connection_t *tconn, vlib_buffer_t **b,
			     u32 n_bufs);
int tcp_session_custom_tx (void *conn, transport_send_params_t * sp);

void tcp_connection_timers_init (tcp_connection_t * tc);
void tcp_connection_timers_reset (tcp_connection_t * tc);
void tcp_init_snd_vars (tcp_connection_t * tc);
void tcp_connection_init_vars (tcp_connection_t * tc);
void tcp_connection_tx_pacer_update (tcp_connection_t * tc);
void tcp_connection_tx_pacer_reset (tcp_connection_t * tc, u32 window,
				    u32 start_bucket);
void tcp_program_cleanup (tcp_worker_ctx_t * wrk, tcp_connection_t * tc);
void tcp_check_gso (tcp_connection_t *tc);

int tcp_buffer_make_reset (vlib_main_t *vm, vlib_buffer_t *b, u8 is_ip4);
void tcp_punt_unknown (vlib_main_t * vm, u8 is_ip4, u8 is_add);
int tcp_configure_v4_source_address_range (vlib_main_t * vm,
					   ip4_address_t * start,
					   ip4_address_t * end, u32 table_id);
int tcp_configure_v6_source_address_range (vlib_main_t * vm,
					   ip6_address_t * start,
					   ip6_address_t * end, u32 table_id);

clib_error_t *vnet_tcp_enable_disable (vlib_main_t * vm, u8 is_en);

format_function_t format_tcp_state;
format_function_t format_tcp_flags;
format_function_t format_tcp_sacks;
format_function_t format_tcp_rcv_sacks;
format_function_t format_tcp_connection;
format_function_t format_tcp_connection_id;

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
