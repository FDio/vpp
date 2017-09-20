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

#ifndef _vnet_tcp_h_
#define _vnet_tcp_h_

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/tcp/tcp_packet.h>
#include <vnet/tcp/tcp_timer.h>
#include <vnet/session/transport.h>
#include <vnet/session/session.h>
#include <vnet/tcp/tcp_debug.h>

#define TCP_TICK 0.001			/**< TCP tick period (s) */
#define THZ (u32) (1/TCP_TICK)		/**< TCP tick frequency */
#define TCP_TSTAMP_RESOLUTION TCP_TICK	/**< Time stamp resolution */
#define TCP_PAWS_IDLE 24 * 24 * 60 * 60 * THZ /**< 24 days */
#define TCP_FIB_RECHECK_PERIOD	1 * THZ	/**< Recheck every 1s */
#define TCP_MAX_OPTION_SPACE 40

#define TCP_DUPACK_THRESHOLD 	3
#define TCP_MAX_RX_FIFO_SIZE 	4 << 20
#define TCP_MIN_RX_FIFO_SIZE	4 << 10
#define TCP_IW_N_SEGMENTS 	10
#define TCP_ALWAYS_ACK		1	/**< On/off delayed acks */
#define TCP_USE_SACKS		1	/**< Disable only for testing */

/** TCP FSM state definitions as per RFC793. */
#define foreach_tcp_fsm_state   \
  _(CLOSED, "CLOSED")           \
  _(LISTEN, "LISTEN")           \
  _(SYN_SENT, "SYN_SENT")       \
  _(SYN_RCVD, "SYN_RCVD")       \
  _(ESTABLISHED, "ESTABLISHED") \
  _(CLOSE_WAIT, "CLOSE_WAIT")   \
  _(FIN_WAIT_1, "FIN_WAIT_1")   \
  _(LAST_ACK, "LAST_ACK")       \
  _(CLOSING, "CLOSING")         \
  _(FIN_WAIT_2, "FIN_WAIT_2")   \
  _(TIME_WAIT, "TIME_WAIT")

typedef enum _tcp_state
{
#define _(sym, str) TCP_STATE_##sym,
  foreach_tcp_fsm_state
#undef _
  TCP_N_STATES
} tcp_state_t;

format_function_t format_tcp_state;
format_function_t format_tcp_flags;
format_function_t format_tcp_sacks;
format_function_t format_tcp_rcv_sacks;

/** TCP timers */
#define foreach_tcp_timer               \
  _(RETRANSMIT, "RETRANSMIT")           \
  _(DELACK, "DELAYED ACK")              \
  _(PERSIST, "PERSIST")                 \
  _(KEEP, "KEEP")                       \
  _(WAITCLOSE, "WAIT CLOSE")            \
  _(RETRANSMIT_SYN, "RETRANSMIT SYN")   \
  _(ESTABLISH, "ESTABLISH")

typedef enum _tcp_timers
{
#define _(sym, str) TCP_TIMER_##sym,
  foreach_tcp_timer
#undef _
  TCP_N_TIMERS
} tcp_timers_e;

typedef void (timer_expiration_handler) (u32 index);

extern timer_expiration_handler tcp_timer_delack_handler;
extern timer_expiration_handler tcp_timer_retransmit_handler;
extern timer_expiration_handler tcp_timer_persist_handler;
extern timer_expiration_handler tcp_timer_retransmit_syn_handler;

#define TCP_TIMER_HANDLE_INVALID ((u32) ~0)

/* Timer delays as multiples of 100ms */
#define TCP_TO_TIMER_TICK       TCP_TICK*10	/* Period for converting from TCP
						 * ticks to timer units */
#define TCP_DELACK_TIME         1	/* 0.1s */
#define TCP_ESTABLISH_TIME      750	/* 75s */
#define TCP_SYN_RCVD_TIME	600	/* 60s */
#define TCP_2MSL_TIME           300	/* 30s */
#define TCP_CLOSEWAIT_TIME	20	/* 0.1s */
#define TCP_CLEANUP_TIME	5	/* 0.5s Time to wait before cleanup */
#define TCP_TIMER_PERSIST_MIN	2	/* 0.2s */

#define TCP_RTO_MAX 60 * THZ	/* Min max RTO (60s) as per RFC6298 */
#define TCP_RTO_MIN 0.2 * THZ	/* Min RTO (200ms) - lower than standard */
#define TCP_RTT_MAX 30 * THZ	/* 30s (probably too much) */
#define TCP_RTO_SYN_RETRIES 3	/* SYN retries without doubling RTO */
#define TCP_RTO_INIT 1 * THZ	/* Initial retransmit timer */

/** TCP connection flags */
#define foreach_tcp_connection_flag             \
  _(SNDACK, "Send ACK")                         \
  _(FINSNT, "FIN sent")				\
  _(SENT_RCV_WND0, "Sent 0 receive window")     \
  _(RECOVERY, "Recovery on")                    \
  _(FAST_RECOVERY, "Fast Recovery on")		\
  _(FR_1_SMSS, "Sent 1 SMSS")			\
  _(HALF_OPEN_DONE, "Half-open completed")	\
  _(FINPNDG, "FIN pending")

typedef enum _tcp_connection_flag_bits
{
#define _(sym, str) TCP_CONN_##sym##_BIT,
  foreach_tcp_connection_flag
#undef _
  TCP_CONN_N_FLAG_BITS
} tcp_connection_flag_bits_e;

typedef enum _tcp_connection_flag
{
#define _(sym, str) TCP_CONN_##sym = 1 << TCP_CONN_##sym##_BIT,
  foreach_tcp_connection_flag
#undef _
  TCP_CONN_N_FLAGS
} tcp_connection_flags_e;

/** TCP buffer flags */
#define foreach_tcp_buf_flag                            \
  _ (ACK)       /**< Sending ACK. */                    \
  _ (DUPACK)    /**< Sending DUPACK. */                 \

enum
{
#define _(f) TCP_BUF_BIT_##f,
  foreach_tcp_buf_flag
#undef _
    TCP_N_BUF_BITS,
};

enum
{
#define _(f) TCP_BUF_FLAG_##f = 1 << TCP_BUF_BIT_##f,
  foreach_tcp_buf_flag
#undef _
};

#define TCP_SCOREBOARD_TRACE (0)
#define TCP_MAX_SACK_BLOCKS 15	/**< Max number of SACK blocks stored */
#define TCP_INVALID_SACK_HOLE_INDEX ((u32)~0)

typedef struct _scoreboard_trace_elt
{
  u32 start;
  u32 end;
  u32 ack;
  u32 snd_una_max;
  u32 group;
} scoreboard_trace_elt_t;

typedef struct _sack_scoreboard_hole
{
  u32 next;		/**< Index for next entry in linked list */
  u32 prev;		/**< Index for previous entry in linked list */
  u32 start;		/**< Start sequence number */
  u32 end;		/**< End sequence number */
  u8 is_lost;		/**< Mark hole as lost */
} sack_scoreboard_hole_t;

typedef struct _sack_scoreboard
{
  sack_scoreboard_hole_t *holes;	/**< Pool of holes */
  u32 head;				/**< Index of first entry */
  u32 tail;				/**< Index of last entry */
  u32 sacked_bytes;			/**< Number of bytes sacked in sb */
  u32 last_sacked_bytes;		/**< Number of bytes last sacked */
  u32 last_bytes_delivered;		/**< Number of sack bytes delivered */
  u32 snd_una_adv;			/**< Bytes to add to snd_una */
  u32 high_sacked;			/**< Highest byte sacked (fack) */
  u32 high_rxt;				/**< Highest retransmitted sequence */
  u32 rescue_rxt;			/**< Rescue sequence number */
  u32 lost_bytes;			/**< Bytes lost as per RFC6675 */
  u32 cur_rxt_hole;			/**< Retransmitting from this hole */

#if TCP_SCOREBOARD_TRACE
  scoreboard_trace_elt_t *trace;
#endif

} sack_scoreboard_t;

#if TCP_SCOREBOARD_TRACE
#define tcp_scoreboard_trace_add(_tc, _ack) 				\
{									\
    static u64 _group = 0;						\
    sack_scoreboard_t *_sb = &_tc->sack_sb;				\
    sack_block_t *_sack, *_sacks;					\
    scoreboard_trace_elt_t *_elt;					\
    int i;								\
    _group++;								\
    _sacks = _tc->rcv_opts.sacks;					\
    for (i = 0; i < vec_len (_sacks); i++) 				\
      {									\
	_sack = &_sacks[i];						\
	vec_add2 (_sb->trace, _elt, 1);					\
	_elt->start = _sack->start;					\
	_elt->end = _sack->end;						\
	_elt->ack = _elt->end == _ack ? _ack : 0;			\
	_elt->snd_una_max = _elt->end == _ack ? _tc->snd_una_max : 0;	\
	_elt->group = _group;						\
      }									\
}
#else
#define tcp_scoreboard_trace_add(_tc, _ack)
#endif

typedef enum _tcp_cc_algorithm_type
{
  TCP_CC_NEWRENO,
} tcp_cc_algorithm_type_e;

typedef struct _tcp_cc_algorithm tcp_cc_algorithm_t;

typedef enum _tcp_cc_ack_t
{
  TCP_CC_ACK,
  TCP_CC_DUPACK,
  TCP_CC_PARTIALACK
} tcp_cc_ack_t;

typedef struct _tcp_connection
{
  transport_connection_t connection;  /**< Common transport data. First! */

  u8 state;			/**< TCP state as per tcp_state_t */
  u16 flags;			/**< Connection flags (see tcp_conn_flags_e) */
  u32 timers[TCP_N_TIMERS];	/**< Timer handles into timer wheel */

  /* TODO RFC4898 */

  /** Send sequence variables RFC793 */
  u32 snd_una;		/**< oldest unacknowledged sequence number */
  u32 snd_una_max;	/**< newest unacknowledged sequence number + 1*/
  u32 snd_wnd;		/**< send window */
  u32 snd_wl1;		/**< seq number used for last snd.wnd update */
  u32 snd_wl2;		/**< ack number used for last snd.wnd update */
  u32 snd_nxt;		/**< next seq number to be sent */
  u16 snd_mss;		/**< Effective send max seg (data) size */

  /** Receive sequence variables RFC793 */
  u32 rcv_nxt;		/**< next sequence number expected */
  u32 rcv_wnd;		/**< receive window we expect */

  u32 rcv_las;		/**< rcv_nxt at last ack sent/rcv_wnd update */
  u32 iss;		/**< initial sent sequence */
  u32 irs;		/**< initial remote sequence */

  /* Options */
  tcp_options_t rcv_opts;	/**< Rx options for connection */
  tcp_options_t snd_opts;	/**< Tx options for connection */
  u8 snd_opts_len;		/**< Tx options len */
  u8 rcv_wscale;	/**< Window scale to advertise to peer */
  u8 snd_wscale;	/**< Window scale to use when sending */
  u32 tsval_recent;	/**< Last timestamp received */
  u32 tsval_recent_age;	/**< When last updated tstamp_recent*/

  sack_block_t *snd_sacks;	/**< Vector of SACKs to send. XXX Fixed size? */
  sack_scoreboard_t sack_sb;	/**< SACK "scoreboard" that tracks holes */

  u16 rcv_dupacks;	/**< Number of DUPACKs received */
  u8 snt_dupacks;	/**< Number of DUPACKs sent in a burst */

  /* Congestion control */
  u32 cwnd;		/**< Congestion window */
  u32 ssthresh;		/**< Slow-start threshold */
  u32 prev_ssthresh;	/**< ssthresh before congestion */
  u32 prev_cwnd;	/**< ssthresh before congestion */
  u32 bytes_acked;	/**< Bytes acknowledged by current segment */
  u32 snd_rxt_bytes;	/**< Retransmitted bytes */
  u32 snd_rxt_ts;	/**< Timestamp when first packet is retransmitted */
  u32 tsecr_last_ack;	/**< Timestamp echoed to us in last healthy ACK */
  u32 snd_congestion;	/**< snd_una_max when congestion is detected */
  tcp_cc_algorithm_t *cc_algo;	/**< Congestion control algorithm */

  /* RTT and RTO */
  u32 rto;		/**< Retransmission timeout */
  u32 rto_boff;		/**< Index for RTO backoff */
  u32 srtt;		/**< Smoothed RTT */
  u32 rttvar;		/**< Smoothed mean RTT difference. Approximates variance */
  u32 rtt_ts;		/**< Timestamp for tracked ACK */
  u32 rtt_seq;		/**< Sequence number for tracked ACK */

  u16 mss;		/**< Our max seg size that includes options */
  u32 limited_transmit;	/**< snd_nxt when limited transmit starts */
  u32 last_fib_check;	/**< Last time we checked fib route for peer */
} tcp_connection_t;

struct _tcp_cc_algorithm
{
  void (*rcv_ack) (tcp_connection_t * tc);
  void (*rcv_cong_ack) (tcp_connection_t * tc, tcp_cc_ack_t ack);
  void (*congestion) (tcp_connection_t * tc);
  void (*recovered) (tcp_connection_t * tc);
  void (*init) (tcp_connection_t * tc);
};

#define tcp_fastrecovery_on(tc) (tc)->flags |= TCP_CONN_FAST_RECOVERY
#define tcp_fastrecovery_off(tc) (tc)->flags &= ~TCP_CONN_FAST_RECOVERY
#define tcp_recovery_on(tc) (tc)->flags |= TCP_CONN_RECOVERY
#define tcp_recovery_off(tc) (tc)->flags &= ~TCP_CONN_RECOVERY
#define tcp_in_fastrecovery(tc) ((tc)->flags & TCP_CONN_FAST_RECOVERY)
#define tcp_in_recovery(tc) ((tc)->flags & (TCP_CONN_RECOVERY))
#define tcp_in_slowstart(tc) (tc->cwnd < tc->ssthresh)
#define tcp_fastrecovery_sent_1_smss(tc) ((tc)->flags & TCP_CONN_FR_1_SMSS)
#define tcp_fastrecovery_1_smss_on(tc) ((tc)->flags |= TCP_CONN_FR_1_SMSS)
#define tcp_fastrecovery_1_smss_off(tc) ((tc)->flags &= ~TCP_CONN_FR_1_SMSS)

#define tcp_in_cong_recovery(tc) ((tc)->flags & 		\
	  (TCP_CONN_FAST_RECOVERY | TCP_CONN_RECOVERY))

always_inline void
tcp_cong_recovery_off (tcp_connection_t * tc)
{
  tc->flags &= ~(TCP_CONN_FAST_RECOVERY | TCP_CONN_RECOVERY);
  tcp_fastrecovery_1_smss_off (tc);
}

typedef enum
{
  TCP_IP4,
  TCP_IP6,
  TCP_N_AF,
} tcp_af_t;

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

typedef struct _tcp_main
{
  /* Per-worker thread tcp connection pools */
  tcp_connection_t **connections;

  /* Pool of listeners. */
  tcp_connection_t *listener_pool;

  /** Dispatch table by state and flags */
  tcp_lookup_dispatch_t dispatch_table[TCP_N_STATES][64];

  u8 log2_tstamp_clocks_per_tick;
  f64 tstamp_ticks_per_clock;
  u32 *time_now;

  /** per-worker tx buffer free lists */
  u32 **tx_buffers;
  /** per-worker tx frames to 4/6 output nodes */
  vlib_frame_t **tx_frames[2];

  /* Per worker-thread timer wheel for connections timers */
  tw_timer_wheel_16t_2w_512sl_t *timer_wheels;

  /* Pool of half-open connections on which we've sent a SYN */
  tcp_connection_t *half_open_connections;
  clib_spinlock_t half_open_lock;

  /* Pool of local TCP endpoints */
  transport_endpoint_t *local_endpoints;

  /* Local endpoints lookup table */
  transport_endpoint_table_t local_endpoints_table;
  clib_spinlock_t local_endpoints_lock;

  /* Congestion control algorithms registered */
  tcp_cc_algorithm_t *cc_algos;

  /* Flag that indicates if stack is on or off */
  u8 is_enabled;

  /** Number of preallocated connections */
  u32 preallocated_connections;
  u32 preallocated_half_open_connections;

  /** Transport table (preallocation) size parameters */
  u32 local_endpoints_table_memory;
  u32 local_endpoints_table_buckets;

  /** Vectors of src addresses. Optional unless one needs > 63K active-opens */
  ip4_address_t *ip4_src_addresses;
  u32 last_v4_address_rotor;
  u32 last_v6_address_rotor;
  ip6_address_t *ip6_src_addresses;

  /** Port allocator random number generator seed */
  u32 port_allocator_seed;

  /** vlib buffer size */
  u32 bytes_per_buffer;

  u8 punt_unknown4;
  u8 punt_unknown6;
} tcp_main_t;

extern tcp_main_t tcp_main;
extern vlib_node_registration_t tcp4_input_node;
extern vlib_node_registration_t tcp6_input_node;
extern vlib_node_registration_t tcp4_output_node;
extern vlib_node_registration_t tcp6_output_node;

always_inline tcp_main_t *
vnet_get_tcp_main ()
{
  return &tcp_main;
}

always_inline tcp_header_t *
tcp_buffer_hdr (vlib_buffer_t * b)
{
  ASSERT ((signed) b->current_data >= (signed) -VLIB_BUFFER_PRE_DATA_SIZE);
  return (tcp_header_t *) (b->data + b->current_data
			   + vnet_buffer (b)->tcp.hdr_offset);
}

clib_error_t *vnet_tcp_enable_disable (vlib_main_t * vm, u8 is_en);

void tcp_punt_unknown (vlib_main_t * vm, u8 is_ip4, u8 is_add);

always_inline tcp_connection_t *
tcp_connection_get (u32 conn_index, u32 thread_index)
{
  if (PREDICT_FALSE
      (pool_is_free_index (tcp_main.connections[thread_index], conn_index)))
    return 0;
  return pool_elt_at_index (tcp_main.connections[thread_index], conn_index);
}

always_inline tcp_connection_t *
tcp_connection_get_if_valid (u32 conn_index, u32 thread_index)
{
  if (tcp_main.connections[thread_index] == 0)
    return 0;
  if (pool_is_free_index (tcp_main.connections[thread_index], conn_index))
    return 0;
  return pool_elt_at_index (tcp_main.connections[thread_index], conn_index);
}

always_inline tcp_connection_t *
tcp_get_connection_from_transport (transport_connection_t * tconn)
{
  return (tcp_connection_t *) tconn;
}

void tcp_connection_close (tcp_connection_t * tc);
void tcp_connection_cleanup (tcp_connection_t * tc);
void tcp_connection_del (tcp_connection_t * tc);
int tcp_half_open_connection_cleanup (tcp_connection_t * tc);
tcp_connection_t *tcp_connection_new (u8 thread_index);
void tcp_connection_reset (tcp_connection_t * tc);
int tcp_configure_v4_source_address_range (vlib_main_t * vm,
					   ip4_address_t * start,
					   ip4_address_t * end, u32 table_id);
int tcp_configure_v6_source_address_range (vlib_main_t * vm,
					   ip6_address_t * start,
					   ip6_address_t * end, u32 table_id);
void tcp_api_reference (void);
u8 *format_tcp_connection_id (u8 * s, va_list * args);
u8 *format_tcp_connection (u8 * s, va_list * args);
u8 *format_tcp_scoreboard (u8 * s, va_list * args);

u8 *tcp_scoreboard_replay (u8 * s, tcp_connection_t * tc, u8 verbose);

always_inline tcp_connection_t *
tcp_listener_get (u32 tli)
{
  return pool_elt_at_index (tcp_main.listener_pool, tli);
}

always_inline tcp_connection_t *
tcp_half_open_connection_get (u32 conn_index)
{
  tcp_connection_t *tc = 0;
  clib_spinlock_lock_if_init (&tcp_main.half_open_lock);
  if (!pool_is_free_index (tcp_main.half_open_connections, conn_index))
    tc = pool_elt_at_index (tcp_main.half_open_connections, conn_index);
  clib_spinlock_unlock_if_init (&tcp_main.half_open_lock);
  return tc;
}

void tcp_make_ack (tcp_connection_t * ts, vlib_buffer_t * b);
void tcp_make_fin (tcp_connection_t * tc, vlib_buffer_t * b);
void tcp_make_synack (tcp_connection_t * ts, vlib_buffer_t * b);
void tcp_send_reset_w_pkt (tcp_connection_t * tc, vlib_buffer_t * pkt,
			   u8 is_ip4);
void tcp_send_reset (tcp_connection_t * tc);
void tcp_send_syn (tcp_connection_t * tc);
void tcp_send_fin (tcp_connection_t * tc);
void tcp_init_mss (tcp_connection_t * tc);
void tcp_update_snd_mss (tcp_connection_t * tc);
void tcp_update_rto (tcp_connection_t * tc);
void tcp_flush_frame_to_output (vlib_main_t * vm, u8 thread_index, u8 is_ip4);
void tcp_flush_frames_to_output (u8 thread_index);

always_inline u32
tcp_end_seq (tcp_header_t * th, u32 len)
{
  return th->seq_number + tcp_is_syn (th) + tcp_is_fin (th) + len;
}

/* Modulo arithmetic for TCP sequence numbers */
#define seq_lt(_s1, _s2) ((i32)((_s1)-(_s2)) < 0)
#define seq_leq(_s1, _s2) ((i32)((_s1)-(_s2)) <= 0)
#define seq_gt(_s1, _s2) ((i32)((_s1)-(_s2)) > 0)
#define seq_geq(_s1, _s2) ((i32)((_s1)-(_s2)) >= 0)
#define seq_max(_s1, _s2) (seq_gt((_s1), (_s2)) ? (_s1) : (_s2))

/* Modulo arithmetic for timestamps */
#define timestamp_lt(_t1, _t2) ((i32)((_t1)-(_t2)) < 0)
#define timestamp_leq(_t1, _t2) ((i32)((_t1)-(_t2)) <= 0)

/**
 * Our estimate of the number of bytes that have left the network
 */
always_inline u32
tcp_bytes_out (const tcp_connection_t * tc)
{
  if (tcp_opts_sack_permitted (&tc->rcv_opts))
    return tc->sack_sb.sacked_bytes + tc->sack_sb.lost_bytes;
  else
    return tc->rcv_dupacks * tc->snd_mss;
}

/**
 * Our estimate of the number of bytes in flight (pipe size)
 */
always_inline u32
tcp_flight_size (const tcp_connection_t * tc)
{
  int flight_size;

  flight_size = (int) (tc->snd_una_max - tc->snd_una) - tcp_bytes_out (tc)
    + tc->snd_rxt_bytes;

  if (flight_size < 0)
    {
      if (0)
	clib_warning
	  ("Negative: %u %u %u dupacks %u sacked bytes %u flags %d",
	   tc->snd_una_max - tc->snd_una, tcp_bytes_out (tc),
	   tc->snd_rxt_bytes, tc->rcv_dupacks, tc->sack_sb.sacked_bytes,
	   tc->rcv_opts.flags);
      return 0;
    }

  return flight_size;
}

/**
 * Initial cwnd as per RFC5681
 */
always_inline u32
tcp_initial_cwnd (const tcp_connection_t * tc)
{
  if (tc->snd_mss > 2190)
    return 2 * tc->snd_mss;
  else if (tc->snd_mss > 1095)
    return 3 * tc->snd_mss;
  else
    return 4 * tc->snd_mss;
}

always_inline u32
tcp_loss_wnd (const tcp_connection_t * tc)
{
  return tc->snd_mss;
}

always_inline u32
tcp_available_snd_wnd (const tcp_connection_t * tc)
{
  return clib_min (tc->cwnd, tc->snd_wnd);
}

always_inline u32
tcp_available_output_snd_space (const tcp_connection_t * tc)
{
  u32 available_wnd = tcp_available_snd_wnd (tc);
  int flight_size = (int) (tc->snd_nxt - tc->snd_una);

  if (available_wnd <= flight_size)
    return 0;

  return available_wnd - flight_size;
}

/**
 * Estimate of how many bytes we can still push into the network
 */
always_inline u32
tcp_available_snd_space (const tcp_connection_t * tc)
{
  u32 available_wnd = tcp_available_snd_wnd (tc);
  u32 flight_size = tcp_flight_size (tc);

  if (available_wnd <= flight_size)
    return 0;

  return available_wnd - flight_size;
}

always_inline u8
tcp_is_lost_fin (tcp_connection_t * tc)
{
  if ((tc->flags & TCP_CONN_FINSNT) && tc->snd_una_max - tc->snd_una == 1)
    return 1;
  return 0;
}

i32 tcp_rcv_wnd_available (tcp_connection_t * tc);
u32 tcp_snd_space (tcp_connection_t * tc);
void tcp_update_rcv_wnd (tcp_connection_t * tc);

void tcp_retransmit_first_unacked (tcp_connection_t * tc);
void tcp_fast_retransmit_no_sack (tcp_connection_t * tc);
void tcp_fast_retransmit_sack (tcp_connection_t * tc);
void tcp_fast_retransmit (tcp_connection_t * tc);
void tcp_cc_init_congestion (tcp_connection_t * tc);
int tcp_cc_recover (tcp_connection_t * tc);
void tcp_cc_fastrecovery_exit (tcp_connection_t * tc);

fib_node_index_t tcp_lookup_rmt_in_fib (tcp_connection_t * tc);

/* Made public for unit testing only */
void tcp_update_sack_list (tcp_connection_t * tc, u32 start, u32 end);

always_inline u32
tcp_time_now (void)
{
  return tcp_main.time_now[vlib_get_thread_index ()];
}

always_inline u32
tcp_set_time_now (u32 thread_index)
{
  tcp_main.time_now[thread_index] = clib_cpu_time_now ()
    * tcp_main.tstamp_ticks_per_clock;
  return tcp_main.time_now[thread_index];
}

always_inline void
tcp_update_time (f64 now, u32 thread_index)
{
  tcp_set_time_now (thread_index);
  tw_timer_expire_timers_16t_2w_512sl (&tcp_main.timer_wheels[thread_index],
				       now);
  tcp_flush_frames_to_output (thread_index);
}

u32 tcp_push_header (transport_connection_t * tconn, vlib_buffer_t * b);

u32
tcp_prepare_retransmit_segment (tcp_connection_t * tc, u32 offset,
				u32 max_bytes, vlib_buffer_t ** b);

void tcp_connection_timers_init (tcp_connection_t * tc);
void tcp_connection_timers_reset (tcp_connection_t * tc);
void tcp_init_snd_vars (tcp_connection_t * tc);
void tcp_connection_init_vars (tcp_connection_t * tc);

always_inline void
tcp_connection_force_ack (tcp_connection_t * tc, vlib_buffer_t * b)
{
  /* Reset flags, make sure ack is sent */
  tc->flags = TCP_CONN_SNDACK;
  vnet_buffer (b)->tcp.flags &= ~TCP_BUF_FLAG_DUPACK;
}

always_inline void
tcp_timer_set (tcp_connection_t * tc, u8 timer_id, u32 interval)
{
  ASSERT (tc->c_thread_index == vlib_get_thread_index ());
  ASSERT (tc->timers[timer_id] == TCP_TIMER_HANDLE_INVALID);
  tc->timers[timer_id]
    = tw_timer_start_16t_2w_512sl (&tcp_main.timer_wheels[tc->c_thread_index],
				   tc->c_c_index, timer_id, interval);
}

always_inline void
tcp_timer_reset (tcp_connection_t * tc, u8 timer_id)
{
  ASSERT (tc->c_thread_index == vlib_get_thread_index ());
  if (tc->timers[timer_id] == TCP_TIMER_HANDLE_INVALID)
    return;

  tw_timer_stop_16t_2w_512sl (&tcp_main.timer_wheels[tc->c_thread_index],
			      tc->timers[timer_id]);
  tc->timers[timer_id] = TCP_TIMER_HANDLE_INVALID;
}

always_inline void
tcp_timer_update (tcp_connection_t * tc, u8 timer_id, u32 interval)
{
  ASSERT (tc->c_thread_index == vlib_get_thread_index ());
  if (tc->timers[timer_id] != TCP_TIMER_HANDLE_INVALID)
    tw_timer_stop_16t_2w_512sl (&tcp_main.timer_wheels[tc->c_thread_index],
				tc->timers[timer_id]);
  tc->timers[timer_id] =
    tw_timer_start_16t_2w_512sl (&tcp_main.timer_wheels[tc->c_thread_index],
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
		 clib_max (tc->rto * TCP_TO_TIMER_TICK,
			   TCP_TIMER_PERSIST_MIN));
}

always_inline void
tcp_persist_timer_update (tcp_connection_t * tc)
{
  tcp_timer_update (tc, TCP_TIMER_PERSIST,
		    clib_max (tc->rto * TCP_TO_TIMER_TICK,
			      TCP_TIMER_PERSIST_MIN));
}

always_inline void
tcp_persist_timer_reset (tcp_connection_t * tc)
{
  tcp_timer_reset (tc, TCP_TIMER_PERSIST);
}

always_inline void
tcp_retransmit_timer_update (tcp_connection_t * tc)
{
  if (tc->snd_una == tc->snd_una_max)
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
	 || stream_session_tx_fifo_max_dequeue (&_tc->connection) >= _a)

void
scoreboard_remove_hole (sack_scoreboard_t * sb,
			sack_scoreboard_hole_t * hole);
void scoreboard_update_lost (tcp_connection_t * tc, sack_scoreboard_t * sb);
sack_scoreboard_hole_t *scoreboard_insert_hole (sack_scoreboard_t * sb,
						u32 prev_index, u32 start,
						u32 end);
sack_scoreboard_hole_t *scoreboard_next_rxt_hole (sack_scoreboard_t * sb,
						  sack_scoreboard_hole_t *
						  start, u8 have_sent_1_smss,
						  u8 * can_rescue,
						  u8 * snd_limited);
void scoreboard_init_high_rxt (sack_scoreboard_t * sb, u32 seq);

always_inline sack_scoreboard_hole_t *
scoreboard_get_hole (sack_scoreboard_t * sb, u32 index)
{
  if (index != TCP_INVALID_SACK_HOLE_INDEX)
    return pool_elt_at_index (sb->holes, index);
  return 0;
}

always_inline sack_scoreboard_hole_t *
scoreboard_next_hole (sack_scoreboard_t * sb, sack_scoreboard_hole_t * hole)
{
  if (hole->next != TCP_INVALID_SACK_HOLE_INDEX)
    return pool_elt_at_index (sb->holes, hole->next);
  return 0;
}

always_inline sack_scoreboard_hole_t *
scoreboard_prev_hole (sack_scoreboard_t * sb, sack_scoreboard_hole_t * hole)
{
  if (hole->prev != TCP_INVALID_SACK_HOLE_INDEX)
    return pool_elt_at_index (sb->holes, hole->prev);
  return 0;
}

always_inline sack_scoreboard_hole_t *
scoreboard_first_hole (sack_scoreboard_t * sb)
{
  if (sb->head != TCP_INVALID_SACK_HOLE_INDEX)
    return pool_elt_at_index (sb->holes, sb->head);
  return 0;
}

always_inline sack_scoreboard_hole_t *
scoreboard_last_hole (sack_scoreboard_t * sb)
{
  if (sb->tail != TCP_INVALID_SACK_HOLE_INDEX)
    return pool_elt_at_index (sb->holes, sb->tail);
  return 0;
}

always_inline void
scoreboard_clear (sack_scoreboard_t * sb)
{
  sack_scoreboard_hole_t *hole;
  while ((hole = scoreboard_first_hole (sb)))
    {
      scoreboard_remove_hole (sb, hole);
    }
  ASSERT (sb->head == sb->tail && sb->head == TCP_INVALID_SACK_HOLE_INDEX);
  ASSERT (pool_elts (sb->holes) == 0);
  sb->sacked_bytes = 0;
  sb->last_sacked_bytes = 0;
  sb->last_bytes_delivered = 0;
  sb->snd_una_adv = 0;
  sb->high_sacked = 0;
  sb->high_rxt = 0;
  sb->lost_bytes = 0;
  sb->cur_rxt_hole = TCP_INVALID_SACK_HOLE_INDEX;
}

always_inline u32
scoreboard_hole_bytes (sack_scoreboard_hole_t * hole)
{
  return hole->end - hole->start;
}

always_inline u32
scoreboard_hole_index (sack_scoreboard_t * sb, sack_scoreboard_hole_t * hole)
{
  ASSERT (!pool_is_free_index (sb->holes, hole - sb->holes));
  return hole - sb->holes;
}

always_inline void
scoreboard_init (sack_scoreboard_t * sb)
{
  sb->head = TCP_INVALID_SACK_HOLE_INDEX;
  sb->tail = TCP_INVALID_SACK_HOLE_INDEX;
  sb->cur_rxt_hole = TCP_INVALID_SACK_HOLE_INDEX;
}

void tcp_rcv_sacks (tcp_connection_t * tc, u32 ack);

always_inline void
tcp_cc_algo_register (tcp_cc_algorithm_type_e type,
		      const tcp_cc_algorithm_t * vft)
{
  tcp_main_t *tm = vnet_get_tcp_main ();
  vec_validate (tm->cc_algos, type);

  tm->cc_algos[type] = *vft;
}

always_inline tcp_cc_algorithm_t *
tcp_cc_algo_get (tcp_cc_algorithm_type_e type)
{
  tcp_main_t *tm = vnet_get_tcp_main ();
  return &tm->cc_algos[type];
}

void tcp_cc_init (tcp_connection_t * tc);

/**
 * Push TCP header to buffer
 *
 * @param vm - vlib_main
 * @param b - buffer to write the header to
 * @param sp_net - source port net order
 * @param dp_net - destination port net order
 * @param seq - sequence number net order
 * @param ack - ack number net order
 * @param tcp_hdr_opts_len - header and options length in bytes
 * @param flags - header flags
 * @param wnd - window size
 *
 * @return - pointer to start of TCP header
 */
always_inline void *
vlib_buffer_push_tcp_net_order (vlib_buffer_t * b, u16 sp, u16 dp, u32 seq,
				u32 ack, u8 tcp_hdr_opts_len, u8 flags,
				u16 wnd)
{
  tcp_header_t *th;

  th = vlib_buffer_push_uninit (b, tcp_hdr_opts_len);

  th->src_port = sp;
  th->dst_port = dp;
  th->seq_number = seq;
  th->ack_number = ack;
  th->data_offset_and_reserved = (tcp_hdr_opts_len >> 2) << 4;
  th->flags = flags;
  th->window = wnd;
  th->checksum = 0;
  th->urgent_pointer = 0;
  return th;
}

/**
 * Push TCP header to buffer
 *
 * @param b - buffer to write the header to
 * @param sp_net - source port net order
 * @param dp_net - destination port net order
 * @param seq - sequence number host order
 * @param ack - ack number host order
 * @param tcp_hdr_opts_len - header and options length in bytes
 * @param flags - header flags
 * @param wnd - window size
 *
 * @return - pointer to start of TCP header
 */
always_inline void *
vlib_buffer_push_tcp (vlib_buffer_t * b, u16 sp_net, u16 dp_net, u32 seq,
		      u32 ack, u8 tcp_hdr_opts_len, u8 flags, u16 wnd)
{
  return vlib_buffer_push_tcp_net_order (b, sp_net, dp_net,
					 clib_host_to_net_u32 (seq),
					 clib_host_to_net_u32 (ack),
					 tcp_hdr_opts_len, flags,
					 clib_host_to_net_u16 (wnd));
}

#endif /* _vnet_tcp_h_ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
