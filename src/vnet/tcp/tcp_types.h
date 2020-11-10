/*
 * Copyright (c) 2020 Cisco and/or its affiliates.
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

#ifndef SRC_VNET_TCP_TCP_TYPES_H_
#define SRC_VNET_TCP_TCP_TYPES_H_

#include <vppinfra/clib.h>
#include <vppinfra/rbtree.h>
#include <vnet/tcp/tcp_packet.h>
#include <vnet/session/transport.h>

#define TCP_TICK 0.000001			/**< TCP tick period (s) */
#define THZ (u32) (1/TCP_TICK)			/**< TCP tick frequency */

#define TCP_TSTP_TICK 0.001			/**< Timestamp tick (s) */
#define TCP_TSTP_HZ (u32) (1/TCP_TSTP_TICK)	/**< Timestamp freq */
#define TCP_PAWS_IDLE (24 * 86400 * TCP_TSTP_HZ)/**< 24 days */
#define TCP_TSTP_TO_HZ (u32) (TCP_TSTP_TICK * THZ)

#define TCP_FIB_RECHECK_PERIOD	1 * THZ	/**< Recheck every 1s */
#define TCP_MAX_OPTION_SPACE 40
#define TCP_CC_DATA_SZ 24
#define TCP_RXT_MAX_BURST 10

#define TCP_DUPACK_THRESHOLD 	3
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

/** TCP timers */
#define foreach_tcp_timer               \
  _(RETRANSMIT, "RETRANSMIT")           \
  _(PERSIST, "PERSIST")                 \
  _(WAITCLOSE, "WAIT CLOSE")            \
  _(RETRANSMIT_SYN, "RETRANSMIT SYN")   \

typedef enum _tcp_timers
{
#define _(sym, str) TCP_TIMER_##sym,
  foreach_tcp_timer
#undef _
  TCP_N_TIMERS
} __clib_packed tcp_timers_e;

#define TCP_TIMER_HANDLE_INVALID ((u32) ~0)

#define TCP_TIMER_TICK		0.0001		/**< Timer tick in seconds */
#define TCP_TO_TIMER_TICK       TCP_TICK*10000	/**< Factor for converting
						     ticks to timer ticks */

#define TCP_RTO_MAX 60 * THZ	/* Min max RTO (60s) as per RFC6298 */
#define TCP_RTO_MIN 0.2 * THZ	/* Min RTO (200ms) - lower than standard */
#define TCP_RTT_MAX 30 * THZ	/* 30s (probably too much) */
#define TCP_RTO_SYN_RETRIES 3	/* SYN retries without doubling RTO */
#define TCP_RTO_INIT 1 * THZ	/* Initial retransmit timer */
#define TCP_RTO_BOFF_MAX 8	/* Max number of retries before reset */
#define TCP_ESTABLISH_TIME (60 * THZ)	/* Connection establish timeout */

/** Connection configuration flags */
#define foreach_tcp_cfg_flag 			\
  _(RATE_SAMPLE, "Rate sampling")		\
  _(NO_CSUM_OFFLOAD, "No csum offload")    	\
  _(NO_TSO, "TSO off")				\
  _(TSO, "TSO")					\
  _(NO_ENDPOINT,"No endpoint")			\

typedef enum tcp_cfg_flag_bits_
{
#define _(sym, str) TCP_CFG_F_##sym##_BIT,
  foreach_tcp_cfg_flag
#undef _
  TCP_CFG_N_FLAG_BITS
} tcp_cfg_flag_bits_e;

typedef enum tcp_cfg_flag_
{
#define _(sym, str) TCP_CFG_F_##sym = 1 << TCP_CFG_F_##sym##_BIT,
  foreach_tcp_cfg_flag
#undef _
  TCP_CFG_N_FLAGS
} tcp_cfg_flags_e;

/** TCP connection flags */
#define foreach_tcp_connection_flag             \
  _(SNDACK, "Send ACK")                         \
  _(FINSNT, "FIN sent")				\
  _(RECOVERY, "Recovery")                    	\
  _(FAST_RECOVERY, "Fast Recovery")		\
  _(DCNT_PENDING, "Disconnect pending")		\
  _(HALF_OPEN_DONE, "Half-open completed")	\
  _(FINPNDG, "FIN pending")			\
  _(RXT_PENDING, "Retransmit pending")		\
  _(FRXT_FIRST, "Retransmit first")		\
  _(DEQ_PENDING, "Dequeue pending ")		\
  _(PSH_PENDING, "PSH pending")			\
  _(FINRCVD, "FIN received")			\
  _(ZERO_RWND_SENT, "Zero RWND sent")		\

typedef enum tcp_connection_flag_bits_
{
#define _(sym, str) TCP_CONN_##sym##_BIT,
  foreach_tcp_connection_flag
#undef _
  TCP_CONN_N_FLAG_BITS
} tcp_connection_flag_bits_e;

typedef enum tcp_connection_flag_
{
#define _(sym, str) TCP_CONN_##sym = 1 << TCP_CONN_##sym##_BIT,
  foreach_tcp_connection_flag
#undef _
  TCP_CONN_N_FLAGS
} tcp_connection_flags_e;

#define TCP_SCOREBOARD_TRACE (0)
#define TCP_MAX_SACK_BLOCKS 255	/**< Max number of SACK blocks stored */
#define TCP_INVALID_SACK_HOLE_INDEX ((u32)~0)
#define TCP_MAX_SACK_REORDER 300

typedef struct _scoreboard_trace_elt
{
  u32 start;
  u32 end;
  u32 ack;
  u32 snd_nxt;
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
  u32 last_bytes_delivered;		/**< Sack bytes delivered to app */
  u32 rxt_sacked;			/**< Rxt bytes last delivered */
  u32 high_sacked;			/**< Highest byte sacked (fack) */
  u32 high_rxt;				/**< Highest retransmitted sequence */
  u32 rescue_rxt;			/**< Rescue sequence number */
  u32 lost_bytes;			/**< Bytes lost as per RFC6675 */
  u32 last_lost_bytes;			/**< Number of bytes last lost */
  u32 cur_rxt_hole;			/**< Retransmitting from this hole */
  u32 reorder;				/**< Estimate of segment reordering */
  u8 is_reneging;			/**< Flag set if peer is reneging*/

#if TCP_SCOREBOARD_TRACE
  scoreboard_trace_elt_t *trace;
#endif

} sack_scoreboard_t;

#define TCP_BTS_INVALID_INDEX	((u32)~0)

typedef enum tcp_bts_flags_
{
  TCP_BTS_IS_RXT = 1,
  TCP_BTS_IS_APP_LIMITED = 1 << 1,
  TCP_BTS_IS_SACKED = 1 << 2,
  TCP_BTS_IS_RXT_LOST = 1 << 3,
} __clib_packed tcp_bts_flags_t;

typedef struct tcp_bt_sample_
{
  u32 next;			/**< Next sample index in list */
  u32 prev;			/**< Previous sample index in list */
  u32 min_seq;			/**< Min seq number in sample */
  u32 max_seq;			/**< Max seq number. Set for rxt samples */
  u64 delivered;		/**< Total delivered bytes for sample */
  f64 delivered_time;		/**< Delivered time when sample taken */
  f64 tx_time;			/**< Transmit time for the burst */
  f64 first_tx_time;		/**< Connection first tx time at tx */
  u64 tx_in_flight;		/**< In flight at tx time */
  u64 tx_lost;			/**< Lost at tx time */
  tcp_bts_flags_t flags;	/**< Sample flag */
} tcp_bt_sample_t;

typedef struct tcp_rate_sample_
{
  u64 prior_delivered;		/**< Delivered of sample used for rate, i.e.,
				     total bytes delivered at prior_time */
  f64 prior_time;		/**< Delivered time of sample used for rate */
  f64 interval_time;		/**< Time to ack the bytes delivered */
  f64 rtt_time;			/**< RTT for sample */
  u64 tx_in_flight;		/**< In flight at (re)transmit time */
  u64 tx_lost;			/**< Lost over interval */
  u32 delivered;		/**< Bytes delivered in interval_time */
  u32 acked_and_sacked;		/**< Bytes acked + sacked now */
  u32 last_lost;		/**< Bytes lost now */
  u32 lost;			/**< Number of bytes lost over interval */
  tcp_bts_flags_t flags;	/**< Rate sample flags from bt sample */
} tcp_rate_sample_t;

typedef struct tcp_byte_tracker_
{
  tcp_bt_sample_t *samples;	/**< Pool of samples */
  rb_tree_t sample_lookup;	/**< Rbtree for sample lookup by min_seq */
  u32 head;			/**< Head of samples linked list */
  u32 tail;			/**< Tail of samples linked list */
  u32 last_ooo;			/**< Cached last ooo sample */
} tcp_byte_tracker_t;

typedef enum _tcp_cc_algorithm_type
{
  TCP_CC_NEWRENO,
  TCP_CC_CUBIC,
  TCP_CC_LAST = TCP_CC_CUBIC
} tcp_cc_algorithm_type_e;

typedef struct _tcp_cc_algorithm tcp_cc_algorithm_t;

typedef enum _tcp_cc_ack_t
{
  TCP_CC_ACK,
  TCP_CC_DUPACK,
  TCP_CC_PARTIALACK
} tcp_cc_ack_t;

typedef enum tcp_cc_event_
{
  TCP_CC_EVT_START_TX,
} tcp_cc_event_t;

/*
 * As per RFC4898 tcpEStatsStackSoftErrors
 */
typedef struct tcp_errors_
{
  u32 below_data_wnd;	/**< All data in seg is below snd_una */
  u32 above_data_wnd;	/**< Some data in segment is above snd_wnd */
  u32 below_ack_wnd;	/**< Acks for data below snd_una */
  u32 above_ack_wnd;	/**< Acks for data not sent */
} tcp_errors_t;

typedef struct _tcp_connection
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  transport_connection_t connection;  /**< Common transport data. First! */

  u8 state;			/**< TCP state as per tcp_state_t */
  u8 cfg_flags;			/**< Connection configuration flags */
  u16 flags;			/**< Connection flags (see tcp_conn_flags_e) */
  u32 timers[TCP_N_TIMERS];	/**< Timer handles into timer wheel */
  u32 pending_timers;		/**< Expired timers not yet handled */

  u64 segs_in;		/** RFC4022/4898 tcpHCInSegs/tcpEStatsPerfSegsIn */
  u64 bytes_in;		/** RFC4898 tcpEStatsPerfHCDataOctetsIn */
  u64 segs_out;		/** RFC4898 tcpEStatsPerfSegsOut */
  u64 bytes_out;	/** RFC4898 tcpEStatsPerfHCDataOctetsOut */

  /** Send sequence variables RFC793 */
  u32 snd_una;		/**< oldest unacknowledged sequence number */
  u32 snd_wnd;		/**< send window */
  u32 snd_wl1;		/**< seq number used for last snd.wnd update */
  u32 snd_wl2;		/**< ack number used for last snd.wnd update */
  u32 snd_nxt;		/**< next seq number to be sent */
  u32 psh_seq;		/**< max seq buffered that may be pushed */
  u16 snd_mss;		/**< Effective send max seg (data) size */

  u64 data_segs_in;	/** RFC4898 tcpEStatsPerfDataSegsIn */
  u64 data_segs_out;	/** RFC4898 tcpEStatsPerfDataSegsOut */

  /** Receive sequence variables RFC793 */
  u32 rcv_nxt;		/**< next sequence number expected */
  u32 rcv_wnd;		/**< receive window we expect */

  u32 rcv_las;		/**< rcv_nxt at last ack sent/rcv_wnd update */
  u32 iss;		/**< initial sent sequence */
  u32 irs;		/**< initial remote sequence */

  /* Options */
  u8 snd_opts_len;		/**< Tx options len */
  u8 rcv_wscale;		/**< Window scale to advertise to peer */
  u8 snd_wscale;		/**< Window scale to use when sending */
  u32 tsval_recent;		/**< Last timestamp received */
  u32 tsval_recent_age;		/**< When last updated tstamp_recent*/
  tcp_options_t snd_opts;	/**< Tx options for connection */
  tcp_options_t rcv_opts;	/**< Rx options for connection */

  sack_block_t *snd_sacks;	/**< Vector of SACKs to send. XXX Fixed size? */
  u8 snd_sack_pos;		/**< Position in vec of first block to send */
  sack_block_t *snd_sacks_fl;	/**< Vector for building new list */
  sack_scoreboard_t sack_sb;	/**< SACK "scoreboard" that tracks holes */

  u16 rcv_dupacks;	/**< Number of recent DUPACKs received */
  u32 dupacks_in;	/**< RFC4898 tcpEStatsStackDupAcksIn*/
  u8 pending_dupacks;	/**< Number of DUPACKs to be sent */
  u32 dupacks_out;	/**< RFC4898 tcpEStatsPathDupAcksOut */

  /* Congestion control */
  u32 cwnd;		/**< Congestion window */
  u32 cwnd_acc_bytes;	/**< Bytes accumulated for cwnd increment */
  u32 ssthresh;		/**< Slow-start threshold */
  u32 prev_ssthresh;	/**< ssthresh before congestion */
  u32 prev_cwnd;	/**< ssthresh before congestion */
  u32 bytes_acked;	/**< Bytes acknowledged by current segment */
  u32 burst_acked;	/**< Bytes acknowledged in current burst */
  u32 snd_rxt_bytes;	/**< Retransmitted bytes during current cc event */
  u32 snd_rxt_ts;	/**< Timestamp when first packet is retransmitted */
  u32 prr_delivered;	/**< RFC6937 bytes delivered during current event */
  u32 prr_start;	/**< snd_una when prr starts */
  u32 rxt_delivered;	/**< Rxt bytes delivered during current cc event */
  u32 rxt_head;		/**< snd_una last time we re rxted the head */
  u32 tsecr_last_ack;	/**< Timestamp echoed to us in last healthy ACK */
  u32 snd_congestion;	/**< snd_nxt when congestion is detected */
  u32 tx_fifo_size;	/**< Tx fifo size. Used to constrain cwnd */
  tcp_cc_algorithm_t *cc_algo;	/**< Congestion control algorithm */
  u8 cc_data[TCP_CC_DATA_SZ];	/**< Congestion control algo private data */

  u32 fr_occurences;	/**< fast-retransmit occurrences RFC4898
			     tcpEStatsStackFastRetran */
  u32 tr_occurences;	/**< timer-retransmit occurrences */
  u64 bytes_retrans;	/**< RFC4898 tcpEStatsPerfOctetsRetrans */
  u64 segs_retrans;	/**< RFC4898 tcpEStatsPerfSegsRetrans*/

  /* RTT and RTO */
  u32 rto;		/**< Retransmission timeout */
  u32 rto_boff;		/**< Index for RTO backoff */
  u32 srtt;		/**< Smoothed RTT measured in @ref TCP_TICK */
  u32 rttvar;		/**< Smoothed mean RTT difference. Approximates variance */
  u32 rtt_seq;		/**< Sequence number for tracked ACK */
  f64 rtt_ts;		/**< Timestamp for tracked ACK */
  f64 mrtt_us;		/**< High precision mrtt from tracked acks */

  u32 next_node_index;	/**< Can be used to control next node in output */
  u32 next_node_opaque;	/**< Opaque to pass to next node */
  u32 limited_transmit;	/**< snd_nxt when limited transmit starts */
  u32 sw_if_index;	/**< Interface for the connection */

  /* Delivery rate estimation */
  u64 delivered;		/**< Total bytes delivered to peer */
  u64 app_limited;		/**< Delivered when app-limited detected */
  f64 delivered_time;		/**< Time last bytes were acked */
  f64 first_tx_time;		/**< Send time for recently delivered/sent */
  u64 lost;			/**< Total bytes lost */
  tcp_byte_tracker_t *bt;	/**< Tx byte tracker */

  tcp_errors_t errors;	/**< Soft connection errors */

  f64 start_ts;		/**< Timestamp when connection initialized */
  u32 last_fib_check;	/**< Last time we checked fib route for peer */
  u16 mss;		/**< Our max seg size that includes options */
  u32 timestamp_delta;	/**< Offset for timestamp */
  u32 ipv6_flow_label;	/**< flow label for ipv6 header */

#define rst_state snd_wl1
} tcp_connection_t;

/* *INDENT-OFF* */
struct _tcp_cc_algorithm
{
  const char *name;
  uword (*unformat_cfg) (unformat_input_t * input);
  void (*init) (tcp_connection_t * tc);
  void (*cleanup) (tcp_connection_t * tc);
  void (*rcv_ack) (tcp_connection_t * tc, tcp_rate_sample_t *rs);
  void (*rcv_cong_ack) (tcp_connection_t * tc, tcp_cc_ack_t ack,
			tcp_rate_sample_t *rs);
  void (*congestion) (tcp_connection_t * tc);
  void (*loss) (tcp_connection_t * tc);
  void (*recovered) (tcp_connection_t * tc);
  void (*undo_recovery) (tcp_connection_t * tc);
  void (*event) (tcp_connection_t *tc, tcp_cc_event_t evt);
  u64 (*get_pacing_rate) (tcp_connection_t *tc);
};
/* *INDENT-ON* */

#define tcp_fastrecovery_on(tc) (tc)->flags |= TCP_CONN_FAST_RECOVERY
#define tcp_fastrecovery_off(tc) (tc)->flags &= ~TCP_CONN_FAST_RECOVERY
#define tcp_recovery_on(tc) (tc)->flags |= TCP_CONN_RECOVERY
#define tcp_recovery_off(tc) (tc)->flags &= ~TCP_CONN_RECOVERY
#define tcp_in_fastrecovery(tc) ((tc)->flags & TCP_CONN_FAST_RECOVERY)
#define tcp_in_recovery(tc) ((tc)->flags & (TCP_CONN_RECOVERY))
#define tcp_in_slowstart(tc) (tc->cwnd < tc->ssthresh)
#define tcp_disconnect_pending(tc) ((tc)->flags & TCP_CONN_DCNT_PENDING)
#define tcp_disconnect_pending_on(tc) ((tc)->flags |= TCP_CONN_DCNT_PENDING)
#define tcp_disconnect_pending_off(tc) ((tc)->flags &= ~TCP_CONN_DCNT_PENDING)
#define tcp_fastrecovery_first(tc) ((tc)->flags & TCP_CONN_FRXT_FIRST)
#define tcp_fastrecovery_first_on(tc) ((tc)->flags |= TCP_CONN_FRXT_FIRST)
#define tcp_fastrecovery_first_off(tc) ((tc)->flags &= ~TCP_CONN_FRXT_FIRST)

#define tcp_in_cong_recovery(tc) ((tc)->flags & 		\
	  (TCP_CONN_FAST_RECOVERY | TCP_CONN_RECOVERY))

always_inline void
tcp_cong_recovery_off (tcp_connection_t * tc)
{
  tc->flags &= ~(TCP_CONN_FAST_RECOVERY | TCP_CONN_RECOVERY);
  tcp_fastrecovery_first_off (tc);
}

#define tcp_csum_offload(tc) (!((tc)->cfg_flags & TCP_CFG_F_NO_CSUM_OFFLOAD))

#define tcp_zero_rwnd_sent(tc) ((tc)->flags & TCP_CONN_ZERO_RWND_SENT)
#define tcp_zero_rwnd_sent_on(tc) (tc)->flags |= TCP_CONN_ZERO_RWND_SENT
#define tcp_zero_rwnd_sent_off(tc) (tc)->flags &= ~TCP_CONN_ZERO_RWND_SENT

always_inline tcp_connection_t *
tcp_get_connection_from_transport (transport_connection_t * tconn)
{
  return (tcp_connection_t *) tconn;
}

/*
 * Define custom timer wheel geometry
 */

#undef TW_TIMER_WHEELS
#undef TW_SLOTS_PER_RING
#undef TW_RING_SHIFT
#undef TW_RING_MASK
#undef TW_TIMERS_PER_OBJECT
#undef LOG2_TW_TIMERS_PER_OBJECT
#undef TW_SUFFIX
#undef TW_OVERFLOW_VECTOR
#undef TW_FAST_WHEEL_BITMAP
#undef TW_TIMER_ALLOW_DUPLICATE_STOP
#undef TW_START_STOP_TRACE_SIZE

#define TW_TIMER_WHEELS 2
#define TW_SLOTS_PER_RING 1024
#define TW_RING_SHIFT 10
#define TW_RING_MASK (TW_SLOTS_PER_RING -1)
#define TW_TIMERS_PER_OBJECT 16
#define LOG2_TW_TIMERS_PER_OBJECT 4
#define TW_SUFFIX _tcp_twsl
#define TW_FAST_WHEEL_BITMAP 0
#define TW_TIMER_ALLOW_DUPLICATE_STOP 1

#include <vppinfra/tw_timer_template.h>

typedef tw_timer_wheel_tcp_twsl_t tcp_timer_wheel_t;

#endif /* SRC_VNET_TCP_TCP_TYPES_H_ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
