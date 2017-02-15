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
#include <vnet/uri/transport.h>
#include <vnet/uri/uri.h>

#define TCP_TICK 10e-3                  /**< TCP tick period (s) */
#define THZ 1/TCP_TICK                  /**< TCP tick frequency */
#define TCP_TSTAMP_RESOLUTION TCP_TICK  /**< Time stamp resolution */
#define TCP_PAWS_IDLE 24 * 24 * 60 * 60 * THZ /**< 24 days */
#define TCP_MAX_OPTION_SPACE 40

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
#define _(sym, str) TCP_CONNECTION_STATE_##sym,
  foreach_tcp_fsm_state
#undef _
  TCP_N_CONNECTION_STATE
} tcp_state_t;

format_function_t format_tcp_state;

/** TCP timers */
#define foreach_tcp_timer               \
  _(RETRANSMIT, "RETRANSMIT")           \
  _(DELACK, "DELAYED ACK")              \
  _(PERSIST, "PERSIST")                 \
  _(KEEP, "KEEP")                       \
  _(2MSL, "2MSL")                       \
  _(RETRANSMIT_SYN, "RETRANSMIT_SYN")

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
extern timer_expiration_handler tcp_timer_retransmit_syn_handler;

#define TCP_TIMER_HANDLE_INVALID ((u32) ~0)

/** TCP connection flags */
#define foreach_tcp_connection_flag             \
  _(DELACK, "Delay ACK")                        \
  _(SNDACK, "Send ACK")                         \
  _(BURSTACK, "Burst ACK set")                  \
  _(SENT_RCV_WND0, "Sent 0 receive window")

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

/* Timer delays as multiples of 100ms */
#define TCP_TO_TIMER_TICK       TCP_TICK*10  /* Period for converting from TCP
                                              * ticks to timer units */
#define TCP_DELACK_TIME         1       /* 0.1s */
#define TCP_ESTABLISH_TIME      750     /* 75s */

#define TCP_RTO_MAX 60 * THZ    /* Min max RTO (60s) as per RFC6298 */
#define TCP_RTT_MAX 30 * THZ    /* 30s (probably too much) */
#define TCP_RTO_SYN_RETRIES 3   /* SYN retries without doubling RTO */
#define TCP_RTO_INIT 1 * THZ    /* Initial retransmit timer */

void
tcp_update_time (f64 now, u32 thread_index);

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

#define TCP_MAX_SACK_BLOCKS 5   /**< Max number of SACK blocks stored */
#define TCP_INVALID_SACK_HOLE_INDEX ((u32)~0)

typedef struct _sack_scoreboard_hole
{
  u32 next;             /**< Index for next entry in linked list */
  u32 prev;             /**< Index for previous entry in linked list */
  u32 start;            /**< Start sequence number */
  u32 end;              /**< End sequence number */
} sack_scoreboard_hole_t;

typedef struct _sack_scoreboard
{
  sack_scoreboard_hole_t *holes;        /**< Pool of holes */
  u32 head;                             /**< Index to first entry */
} sack_scoreboard_t;

typedef struct _tcp_connection
{
  transport_connection_t connection;  /**< Common transport data. First! */

  u8 state;                     /**< TCP state as per tcp_state_t */
  u16 flags;                    /**< Connection flags (see tcp_conn_flags_e) */
  u32 timers[TCP_N_TIMERS];     /**< Timer handles into timer wheel */

  /* TODO RFC4898 */

  /** Send sequence variables RFC793 */
  u32 snd_una;          /**< oldest unacknowledged sequence number */
  u32 snd_una_max;      /**< newest unacknowledged sequence number + 1*/
  u32 snd_wnd;          /**< send window */
  u32 snd_wl1;          /**< seq number used for last snd.wnd update */
  u32 snd_wl2;          /**< ack number used for last snd.wnd update */
  u32 snd_nxt;          /**< next seq number to be sent */

  /** Receive sequence variables RFC793 */
  u32 rcv_nxt;          /**< next sequence number expected */
  u32 rcv_wnd;          /**< receive window we expect */

  u32 rcv_las;          /**< rcv_nxt at last ack sent/rcv_wnd update */
  u32 iss;              /**< initial sent sequence */
  u32 irs;              /**< initial remote sequence */

  /* Options */
  tcp_options_t opt;    /**< TCP connection options parsed */
  u8 rcv_wscale;        /**< Window scale to advertise to peer */
  u8 snd_wscale;        /**< Window scale to use when sending */
  u32 tsval_recent;     /**< Last timestamp received */
  u32 tsval_recent_age; /**< When last updated tstamp_recent*/

  sack_block_t *snd_sacks;      /**< Vector of SACKs to send. XXX Fixed size? */
  sack_scoreboard_t sack_sb;    /**< SACK "scoreboard" that tracks holes */

  u8 rcv_dupacks;       /**< Number of DUPACKs received */
  u8 snt_dupacks;       /**< Number of DUPACKs sent in a burst */

  /* RTT and RTO */
  u32 rto;              /**< Retransmission timeout */
  u32 rto_boff;         /**< Index for RTO backoff */
  u32 srtt;             /**< Smoothed RTT */
  u32 rttvar;           /**< Smoothed mean RTT difference. Approximates variance */
  u32 rtt_ts;           /**< Timestamp for tracked ACK */
  u32 rtt_seq;          /**< Sequence number for tracked ACK */

  /* XXX Everything lower may be removed */

  u16 max_segment_size;
  /* Set if connected to another tcp46_session_t */
  u32 connected_session_index;
  /* tos, ttl to use on tx */
  u8 tos;
  u8 ttl;

  /*
   * At high scale, pre-built (src,dst,src-port,dst-port)
   * headers would chew a ton of memory. Maybe worthwile for
   * a few high-throughput flows
   */
  u32 rewrite_template_index;
} tcp_connection_t;

typedef enum {
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
  tcp_lookup_dispatch_t dispatch_table[TCP_N_CONNECTION_STATE][64];

  u8 log2_tstamp_clocks_per_tick;

  /** per-worker tx buffer free lists */
  u32 **tx_buffers;

  /* Per worker-thread timer wheel for connections timers */
  tw_timer_wheel_16t_2w_512sl_t *timer_wheels;

  /* Convenience per worker-thread vector of connections to DELACK */
  u32 **delack_connections;

  /* Pool of half-open connections on which we've sent a SYN */
  tcp_connection_t *half_open_connections;

  /* Pool of local TCP endpoints */
  transport_endpoint_t *local_endpoints;

  /* Local endpoints lookup table */
  transport_endpoint_table_t local_endpoints_table;

  /* TODO decide if needed */

  /* Hash tables mapping name/protocol to protocol info index. */
  uword * dst_port_info_by_name[TCP_N_AF];
  uword * dst_port_info_by_dst_port[TCP_N_AF];

  /* convenience */
  session_manager_main_t *sm_main;
  vlib_main_t * vlib_main;
  vnet_main_t * vnet_main;
  ip4_main_t * ip4_main;
  ip6_main_t * ip6_main;
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

always_inline tcp_connection_t *
tcp_connection_get (u32 conn_index, u32 thread_index)
{
  return pool_elt_at_index(tcp_main.connections[thread_index], conn_index);
}

void
tcp_connection_close (tcp_main_t *tm, tcp_connection_t *tc);
void
tcp_connection_drop (tcp_main_t *tm, tcp_connection_t *tc);

always_inline tcp_connection_t *
tcp_listener_get (u32 tli)
{
  return pool_elt_at_index(tcp_main.listener_pool, tli);
}

always_inline tcp_connection_t *
tcp_half_open_connection_get (u32 conn_index)
{
  return pool_elt_at_index(tcp_main.half_open_connections, conn_index);
}

void
tcp_make_ack (tcp_connection_t *ts, vlib_buffer_t *b);
void
tcp_make_synack (tcp_connection_t *ts, vlib_buffer_t *b);
void
tcp_make_dupack (tcp_connection_t *ts, u8 is_ip4);
void
tcp_make_challange_ack (tcp_connection_t *ts, u8 is_ip4);
void
tcp_send_reset (vlib_buffer_t *pkt, u8 is_ip4);
void
tcp_send_syn (tcp_connection_t *tc);
void
tcp_send_fin (tcp_connection_t *tc);
u16
tcp_snd_mss (tcp_connection_t *tc);

always_inline u32
tcp_end_seq (tcp_header_t *th, u32 len)
{
  return th->seq_number + tcp_is_syn(th) + tcp_is_fin(th) + len;
}

/* Modulo arithmetic for TCP sequence numbers */
#define seq_lt(_s1, _s2) ((i32)((_s1)-(_s2)) < 0)
#define seq_leq(_s1, _s2) ((i32)((_s1)-(_s2)) <= 0)
#define seq_gt(_s1, _s2) ((i32)((_s1)-(_s2)) > 0)
#define seq_geq(_s1, _s2) ((i32)((_s1)-(_s2)) >= 0)


/* Modulo arithmetic for timestamps */
#define timestamp_lt(_t1, _t2) ((i32)((_t1)-(_t2)) < 0)
#define timestamp_leq(_t1, _t2) ((i32)((_t1)-(_t2)) <= 0)

/**
 * Compute actual receive window. Peer might have pushed more data than our
 * window since the last ack we sent, in which case, receive window is 0.
 */
always_inline u32
tcp_actual_receive_window (const tcp_connection_t *ts)
{
  i32 rcv_wnd = ts->rcv_wnd + ts->rcv_las - ts->rcv_nxt;
  if (rcv_wnd < 0)
    rcv_wnd = 0;
  return (u32) rcv_wnd;
}

always_inline u32
tcp_snd_wnd_space (tcp_connection_t *tc)
{
  return tc->snd_wnd - (tc->snd_una_max - tc->snd_una);
}

always_inline u32
tcp_time_now (void)
{
  return clib_cpu_time_now () >> tcp_main.log2_tstamp_clocks_per_tick;
}

u32
tcp_push_header_uri (transport_connection_t *tconn, vlib_buffer_t *b);

void
tcp_prepare_retransmit_segment (tcp_connection_t *tc, vlib_buffer_t *b);

always_inline void
tcp_timer_set (tcp_main_t *tm, tcp_connection_t *tc, u8 timer_id, u32 interval)
{
  tc->timers[timer_id] 
    = tw_timer_start_16t_2w_512sl (&tm->timer_wheels[tc->c_thread_index],
                                   tc->c_c_index, timer_id, interval);
}

always_inline void
tcp_timer_reset (tcp_main_t *tm, tcp_connection_t *tc, u8 timer_id)
{
  if (tc->timers[timer_id] == TCP_TIMER_HANDLE_INVALID)
    return;

  tw_timer_stop_16t_2w_512sl (&tm->timer_wheels[tc->c_thread_index], 
                               tc->timers[timer_id]);
  tc->timers[timer_id] = TCP_TIMER_HANDLE_INVALID;
}

always_inline void
tcp_timer_update (tcp_main_t *tm, tcp_connection_t *tc, u8 timer_id,
                  u32 interval)
{
  if (tc->timers[timer_id] != TCP_TIMER_HANDLE_INVALID)
    tw_timer_stop_16t_2w_512sl (&tm->timer_wheels[tc->c_thread_index],
                                 tc->timers[timer_id]);
  tc->timers[timer_id] 
    = tw_timer_start_16t_2w_512sl (&tm->timer_wheels[tc->c_thread_index],
                                    tc->c_c_index, timer_id, interval);
}

void
tcp_connection_init_vars (tcp_connection_t *tc);

always_inline u8
tcp_timer_is_active (tcp_connection_t *tc, tcp_timers_e timer)
{
  return tc->timers[timer] != TCP_TIMER_HANDLE_INVALID;
}

void
scoreboard_remove_hole (sack_scoreboard_t *sb, sack_scoreboard_hole_t *hole);

always_inline sack_scoreboard_hole_t *
scoreboard_next_hole (sack_scoreboard_t *sb, sack_scoreboard_hole_t *hole)
{
  if (hole->next != TCP_INVALID_SACK_HOLE_INDEX)
    return pool_elt_at_index (sb->holes, hole->next);
  return 0;
}

always_inline sack_scoreboard_hole_t *
scoreboard_first_hole (sack_scoreboard_t *sb)
{
  if (sb->head != TCP_INVALID_SACK_HOLE_INDEX)
    return pool_elt_at_index (sb->holes, sb->head);
  return 0;
}

always_inline void
scoreboard_clear (sack_scoreboard_t *sb)
{
  sack_scoreboard_hole_t *hole = scoreboard_first_hole (sb);
  while ((hole = scoreboard_first_hole(sb)))
    {
      scoreboard_remove_hole (sb, hole);
    }
}

#endif /* _vnet_tcp_h_ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
