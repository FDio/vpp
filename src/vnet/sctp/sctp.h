/*
 * Copyright (c) 2017 SUSE LLC.
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
#ifndef included_vnet_sctp_h
#define included_vnet_sctp_h

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/sctp/sctp_timer.h>
#include <vnet/sctp/sctp_packet.h>
#include <vnet/session/transport.h>
#include <vnet/session/session.h>

#define SCTP_TICK 0.001			/**< TCP tick period (s) */
#define THZ (u32) (1/SCTP_TICK)		/**< TCP tick frequency */
#define SCTP_TSTAMP_RESOLUTION SCTP_TICK	/**< Time stamp resolution */
#define SCTP_PAWS_IDLE 24 * 24 * 60 * 60 * THZ /**< 24 days */
#define SCTP_FIB_RECHECK_PERIOD	1 * THZ	/**< Recheck every 1s */
#define SCTP_MAX_OPTION_SPACE 40

#define SCTP_DUPACK_THRESHOLD 	3
#define SCTP_MAX_RX_FIFO_SIZE 	4 << 20
#define SCTP_MIN_RX_FIFO_SIZE	4 << 10
#define SCTP_IW_N_SEGMENTS 	10
#define SCTP_ALWAYS_ACK		1	/**< On/off delayed acks */
#define SCTP_USE_SACKS		1	/**< Disable only for testing */

#define IP_PROTOCOL_SCTP	132

/** STCP FSM state definitions as per RFC4960. */
#define foreach_sctp_fsm_state                \
  _(CLOSED, "CLOSED")                         \
  _(INIT_SENT, "INIT_SENT")                   \
  _(INIT_ACKED, "INIT_ACKED")                 \
  _(COOKIE_WAIT, "COOKIE_WAIT")               \
  _(COOKIE_ECHOED, "COOKIE_ECHOED")           \
  _(ESTABLISHED, "ESTABLISHED")               \
  _(SHUTDOWN_PENDING, "SHUTDOWN_PENDING")     \
  _(SHUTDOWN_SENT, "SHUTDOWN_SENT")           \
  _(SHUTDOWN_RECEIVED, "SHUTDOWN_RECEIVED")   \
  _(SHUTDOWN_ACK_SENT, "SHUTDOWN_ACK_SENT")

typedef enum _sctp_state
{
#define _(sym, str) SCTP_STATE_##sym,
  foreach_sctp_fsm_state
#undef _
  SCTP_N_STATES
} sctp_state_t;

#define SCTP_TICK 0.001			/**< SCTP tick period (s) */
#define SHZ (u32) (1/SCTP_TICK)		/**< SCTP tick frequency */

/* As per RFC4960, page 83 */
#define SCTP_RTO_INIT 3 * SHZ	/* 3 seconds */
#define SCTP_RTO_MIN 1 * SHZ	/* 1 second */
#define SCTP_RTO_MAX 60 * SHZ	/* 60 seconds */
#define SCTP_RTO_BURST	4
#define SCTP_RTO_ALPHA 1/8
#define SCTP_RTO_BETA 1/4
#define SCTP_VALID_COOKIE_LIFE 60 * SHZ	/* 60 seconds */
#define SCTP_ASSOCIATION_MAX_RETRANS 10

#define SCTP_TO_TIMER_TICK       SCTP_TICK*10	/* Period for converting from SCTP_TICK */

/* SCTP timers */
#define foreach_sctp_timer              	\
  _(T1_INIT, "T1_INIT")           			\
  _(T2_SHUTDOWN, "T2_SHUTDOWN")         	\
  _(T3_RXTX, "T3_RXTX")   					\
  _(T5_SHUTDOWN_GUARD, "T5_SHUTDOWN_GUARD")

typedef enum _sctp_timers
{
#define _(sym, str) SCTP_TIMER_##sym,
  foreach_sctp_timer
#undef _
  SCTP_N_TIMERS
} sctp_timers_e;

#define SCTP_TIMER_HANDLE_INVALID ((u32) ~0)

typedef struct _sctp_lookup_dispatch
{
  u8 next, error;
} sctp_lookup_dispatch_t;

typedef struct _sctp_connection
{
  transport_connection_t connection;  /**< Common transport data. First! */

  u8 state;			/**< TCP state as per sctp_state_t */
  u16 flags;			/**< Connection flags (see tcp_conn_flags_e) */
  u32 timers[SCTP_N_TIMERS];	/**< Timer handles into timer wheel */

  /** Send sequence variables RFC4960 */
  u32 snd_una;		/**< oldest unacknowledged sequence number */
  u32 snd_una_max;	/**< newest unacknowledged sequence number + 1*/
  u32 snd_wl1;		/**< seq number used for last snd.wnd update */
  u32 snd_wl2;		/**< ack number used for last snd.wnd update */
  u32 snd_nxt;		/**< next seq number to be sent */
  u16 snd_mss;		/**< Effective send max seg (data) size */

  /** Receive sequence variables RFC4960 */
  u32 rcv_nxt;		/**< next sequence number expected */

  u32 rcv_las;		/**< rcv_nxt at last ack sent/rcv_wnd update */
  u32 iss;		/**< initial sent sequence */
  u32 irs;		/**< initial remote sequence */

  /* RTT and RTO */
  u32 rto;		/**< Retransmission timeout */
  u32 rto_boff;		/**< Index for RTO backoff */
  u32 srtt;		/**< Smoothed RTT */
  u32 rttvar;		/**< Smoothed mean RTT difference. Approximates variance */
  u32 rtt_ts;		/**< Timestamp for tracked ACK */
  u32 rtt_seq;		/**< Sequence number for tracked ACK */

} sctp_connection_t;

typedef struct _sctp_main
{
  /* Per-worker thread tcp connection pools */
  sctp_connection_t **connections;

  /* Pool of listeners. */
  sctp_connection_t *listener_pool;

	  /** Dispatch table by state and flags */
  sctp_lookup_dispatch_t dispatch_table[SCTP_N_STATES][64];

  u8 log2_tstamp_clocks_per_tick;
  f64 tstamp_ticks_per_clock;
  u32 *time_now;

	  /** per-worker tx buffer free lists */
  u32 **tx_buffers;
	  /** per-worker tx frames to tcp 4/6 output nodes */
  vlib_frame_t **tx_frames[2];
	  /** per-worker tx frames to ip 4/6 lookup nodes */
  vlib_frame_t **ip_lookup_tx_frames[2];

  /* Per worker-thread timer wheel for connections timers */
  tw_timer_wheel_16t_2w_512sl_t *timer_wheels;

  /* Pool of half-open connections on which we've sent an INIT chunk */
  sctp_connection_t *half_open_connections;
  clib_spinlock_t half_open_lock;

  /* TODO: Congestion control algorithms registered */
  /* sctp_cc_algorithm_t *cc_algos; */

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

	  /** vlib buffer size */
  u32 bytes_per_buffer;

  u8 punt_unknown4;
  u8 punt_unknown6;

} sctp_main_t;

extern sctp_main_t sctp_main;
extern vlib_node_registration_t sctp4_input_node;
extern vlib_node_registration_t sctp6_input_node;
extern vlib_node_registration_t sctp4_output_node;
extern vlib_node_registration_t sctp6_output_node;

always_inline sctp_main_t *
vnet_get_sctp_main ()
{
  return &sctp_main;
}

always_inline sctp_connection_t *
sctp_get_connection_from_transport (transport_connection_t * tconn)
{
  return (sctp_connection_t *) tconn;
}

always_inline u32
sctp_time_now (void)
{
  return sctp_main.time_now[vlib_get_thread_index ()];
}

always_inline u32
sctp_set_time_now (u32 thread_index)
{
  sctp_main.time_now[thread_index] = clib_cpu_time_now ()
    * sctp_main.tstamp_ticks_per_clock;
  return sctp_main.time_now[thread_index];
}

always_inline void
sctp_timer_set (sctp_connection_t * tc, u8 timer_id, u32 interval)
{
  ASSERT (tc->c_thread_index == vlib_get_thread_index ());
  ASSERT (tc->timers[timer_id] == SCTP_TIMER_HANDLE_INVALID);
  tc->timers[timer_id]
    = tw_timer_start_16t_2w_512sl (&sctp_main.timer_wheels[tc->c_thread_index],
				   tc->c_c_index, timer_id, interval);
}

u32
sctp_push_header (transport_connection_t * tconn, vlib_buffer_t * b);

void
sctp_send_init (sctp_connection_t * tc);

#endif

/**
 * Push SCTP header to buffer
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
vlib_buffer_push_sctp_net_order (vlib_buffer_t * b, u16 sp, u16 dp, u32 seq,
				u32 ack, u8 sctp_hdr_len)
{
  sctp_header_t *th;

  th = vlib_buffer_push_uninit (b, sctp_hdr_len);

  th->src_port = sp;
  th->dst_port = dp;
  th->checksum = 0;
  th->verification_tag = 0;

  return th;
}

/**
 * Push SCTP header to buffer
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
vlib_buffer_push_sctp (vlib_buffer_t * b, u16 sp_net, u16 dp_net, u32 seq,
		      u32 ack, u8 sctp_hdr_len)
{
  return vlib_buffer_push_sctp_net_order (b, sp_net, dp_net,
					 clib_host_to_net_u32 (seq),
					 clib_host_to_net_u32 (ack),
					 sctp_hdr_len);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
