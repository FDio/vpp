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

/* SCTP timers */
#define foreach_sctp_timer              	\
  _(T1_INIT, "T1_INIT")           			\
  _(T1_COOKIE, "T1_COOKIE")        			\
  _(T2_SHUTDOWN, "T2_SHUTDOWN")         	\
  _(T3_RXTX, "T3_RXTX")   					\
  _(T4_HEARTBEAT, "T4_HB")					\
  _(T5_SHUTDOWN_GUARD, "T5_SHUTDOWN_GUARD")

typedef enum _sctp_timers
{
#define _(sym, str) SCTP_TIMER_##sym,
  foreach_sctp_timer
#undef _
  SCTP_N_TIMERS
} sctp_timers_e;

#define SCTP_TIMER_HANDLE_INVALID ((u32) ~0)

always_inline char *
sctp_timer_to_string (u8 timer_id)
{
  switch (timer_id)
    {
    case SCTP_TIMER_T1_INIT:
      return "SCTP_TIMER_T1_INIT";
    case SCTP_TIMER_T1_COOKIE:
      return "SCTP_TIMER_T1_COOKIE";
    case SCTP_TIMER_T2_SHUTDOWN:
      return "SCTP_TIMER_T2_SHUTDOWN";
    case SCTP_TIMER_T3_RXTX:
      return "SCTP_TIMER_T3_RXTX";
    case SCTP_TIMER_T4_HEARTBEAT:
      return "SCTP_TIMER_T4_HEARTBEAT";
    case SCTP_TIMER_T5_SHUTDOWN_GUARD:
      return "SCTP_TIMER_T5_SHUTDOWN_GUARD";
    }
  return NULL;
}

typedef enum _sctp_error
{
#define sctp_error(n,s) SCTP_ERROR_##n,
#include <vnet/sctp/sctp_error.def>
#undef sctp_error
  SCTP_N_ERROR,
} sctp_error_t;

#define NO_FLAG 0

#define IS_T_BIT_SET(var) ((var) & (1))
#define IS_E_BIT_SET(var) ((var) & (1))
#define IS_B_BIT_SET(var) ((var) & (1<<1))
#define IS_U_BIT_SET(var) ((var) & (1<<2))

#define MAX_SCTP_CONNECTIONS 8
#define SCTP_PRIMARY_PATH_IDX 0

#if (VLIB_BUFFER_TRACE_TRAJECTORY)
#define sctp_trajectory_add_start(b, start)			\
{								\
    (*vlib_buffer_trace_trajectory_cb) (b, start);		\
}
#else
#define sctp_trajectory_add_start(b, start)
#endif

enum _sctp_subconn_state
{
  SCTP_SUBCONN_STATE_DOWN = 0,
  SCTP_SUBCONN_STATE_UP,
  SCTP_SUBCONN_STATE_ALLOW_HB,
  SCTP_SUBCONN_AWAITING_SACK,
  SCTP_SUBCONN_SACK_RECEIVED
};

#define SCTP_INITIAL_SSHTRESH 65535
typedef struct _sctp_sub_connection
{
  transport_connection_t connection;	      /**< Common transport data. First! */

  u8 subconn_idx; /**< This indicates the position of this sub-connection in the super-set container of connections pool */
  u32 error_count; /**< The current error count for this destination. */
  u32 error_threshold; /**< Current error threshold for this destination,
				i.e. what value marks the destination down if error count reaches this value. */
  u32 cwnd; /**< Congestion control window (cwnd, in bytes), which is adjusted by
      the sender based on observed network conditions. */
  u32 ssthresh;	/**< Slow-start threshold (in bytes), which is used by the
      sender to distinguish slow-start and congestion avoidance phases. */

  u64 rtt_ts;	/**< USED to hold the timestamp of when the packet has been sent */

  u32 RTO; /**< The current retransmission timeout value. */
  u64 SRTT; /**< The current smoothed round-trip time. */
  f64 RTTVAR; /**< The current RTT variation. */

  u32 partially_acked_bytes; /**< The tracking method for increase of cwnd when in
  	  	  	  	  congestion avoidance mode (see Section 7.2.2).*/

  u8 state; /**< The current state of this destination, i.e., DOWN, UP, ALLOW-HB, NO-HEARTBEAT, etc. */

  u16 PMTU; /**< The current known path MTU. */

  u32 timers[SCTP_N_TIMERS]; /**< A timer used by each destination. */

  u8 RTO_pending; /**< A flag used to track if one of the DATA chunks sent to
  	  	  	  	  this address is currently being used to compute an RTT.
  	  	  	  	  If this flag is 0, the next DATA chunk sent to this destination
  	  	  	  	  should be used to compute an RTT and this flag should be set.
  	  	  	  	  Every time the RTT calculation completes (i.e., the DATA chunk is SACK'd),
  	  	  	  	  clear this flag. */

  u64 last_seen; /**< The time to which this destination was last sent a packet to.
  	  	  	  	  This can be used to determine if a HEARTBEAT is needed. */

  u64 last_data_ts; /**< Used to hold the timestamp value of last time we sent a DATA chunk */

  u8 unacknowledged_hb;	/**< Used to track how many unacknowledged heartbeats we had;
  	  	  	  	  If more than SCTP_PATH_MAX_RETRANS then connection is considered unreachable. */

  u8 is_retransmitting;	/**< A flag (0 = no, 1 = yes) indicating whether the connection is retransmitting a previous packet */

  u8 enqueue_state; /**< if set to 1 indicates that DATA is still being handled hence cannot shutdown this connection yet */

} sctp_sub_connection_t;

typedef struct
{
  u32 a_rwnd; /**< Maximum segment size advertised */

} sctp_options_t;

/* Useful macros to deal with the out_of_order_map (array of bit) */
#define SET_BIT(A,k)     ( A[(k/32)] |= (1 << (k%32)) )
#define CLEAR_BIT(A,k)   ( A[(k/32)] &= ~(1 << (k%32)) )
#define TEST_BIT(A,k)    ( A[(k/32)] & (1 << (k%32)) )

always_inline void
_bytes_swap (void *pv, size_t n)
{
  char *p = pv;
  size_t lo, hi;
  for (lo = 0, hi = n - 1; hi > lo; lo++, hi--)
    {
      char tmp = p[lo];
      p[lo] = p[hi];
      p[hi] = tmp;
    }
}

#define ENDIANESS_SWAP(x) _bytes_swap(&x, sizeof(x));

#define MAX_INFLIGHT_PACKETS	128
#define MAX_ENQUEABLE_SACKS 2

/* This parameter indicates to the receiver how much increment in
 * milliseconds the sender wishes the receiver to add to its default
 * cookie life-span.
 */
#define SUGGESTED_COOKIE_LIFE_SPAN_INCREMENT 1000

typedef struct _sctp_user_configuration
{
  u8 never_delay_sack;
  u8 never_bundle;

} sctp_user_configuration_t;

typedef struct _sctp_connection
{
  /** Required for pool_get_aligned */
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);

  sctp_sub_connection_t sub_conn[MAX_SCTP_CONNECTIONS];	/**< Common transport data. First! */
  sctp_user_configuration_t conn_config; /**< Allows tuning of some SCTP behaviors */

  u8 state;			/**< SCTP state as per sctp_state_t */
  u16 flags;		/**< Chunk flag (see sctp_chunks_common_hdr_t) */

  u32 local_tag;	/**< INIT_TAG generated locally */
  u32 remote_tag;	/**< INIT_TAG generated by the remote peer */

  u32 local_initial_tsn; /**< Initial TSN generated locally */
  u32 remote_initial_tsn; /**< Initial TSN generated by the remote-peer */

  u32 peer_cookie_life_span_increment;

  u32 overall_err_count; /**< The overall association error count. */
  u32 overall_err_treshold; /**< The threshold for this association that if the Overall Error Count
  	  	  	  	  reaches will cause this association to be torn down. */

  u8 init_retransmit_err; /**< Error counter for the INIT transmission phase */

  u32 peer_rwnd; /**< Current calculated value of the peer's rwnd. */

  u32 next_tsn;	/**< The next TSN number to be assigned to a new DATA chunk.
                 This is sent in the INIT or INIT ACK chunk to the peer
                 and incremented each time a DATA chunk is assigned a
                 TSN (normally just prior to transmit or during
                 fragmentation). */

  u32 last_unacked_tsn;	/** < Last TSN number still unacked */
  u32 next_tsn_expected; /**< The next TSN number expected to be received. */

  u32 last_rcvd_tsn; /**< This is the last TSN received in sequence. This value
     	 	 	 is set initially by taking the peer's initial TSN,
                 received in the INIT or INIT ACK chunk, and
                 subtracting one from it. */

  u32 out_of_order_map[MAX_INFLIGHT_PACKETS]; /**< An array of bits or bytes indicating which out-of-order
				TSNs have been received (relative to the Last Rcvd TSN).
				If no gaps exist, i.e., no out-of-order packets have been received,
				this array will be set to all zero. */

  u8 ack_state;	/**< This flag indicates if the next received packet is set to be responded to with a SACK.
  	  	  	  	This is initialized to 0. When a packet is received it is incremented.
  	  	  	  	If this value reaches 2 or more, a SACK is sent and the value is reset to 0.
  	  	  	  	Note: This is used only when no DATA chunks are received out-of-order.
  	  	  	  	When DATA chunks are out-of-order, SACKs are not delayed (see Section 6). */

  u8 smallest_PMTU_idx;	/** The index of the sub-connection with the smallest PMTU discovered across all peer's transport addresses. */

  u8 overall_sending_status; /**< 0 indicates first fragment of a user message
  	  	  	  	  	  	  	  	  1 indicates normal stream
  	  	  	  	  	  	  	  	  2 indicates last fragment of a user message */

  u8 forming_association_changed; /**< This is a flag indicating whether the original association has been modified during
  	  	  	  	  the life-span of the association itself. For instance, a new sub-connection might have been added. */

  sctp_state_cookie_param_t cookie_param; /**< Temporary location to save cookie information; it can be used to
  	  	  	  	  when timeout expires and sending again a COOKIE is require. */

} sctp_connection_t;

typedef void (sctp_timer_expiration_handler) (u32 conn_index, u32 timer_id);

sctp_connection_t *sctp_connection_new (u8 thread_index);

u8
sctp_sub_connection_add_ip4 (vlib_main_t * vm,
			     ip4_address_t * lcl_addr,
			     ip4_address_t * rmt_addr);

u8
sctp_sub_connection_add_ip6 (vlib_main_t * vm,
			     ip6_address_t * lcl_addr,
			     ip6_address_t * rmt_addr);

u8
sctp_sub_connection_del_ip4 (ip4_address_t * lcl_addr,
			     ip4_address_t * rmt_addr);

u8
sctp_sub_connection_del_ip6 (ip6_address_t * lcl_addr,
			     ip6_address_t * rmt_addr);

u8 sctp_configure (sctp_user_configuration_t config);

void sctp_connection_close (sctp_connection_t * sctp_conn);
void sctp_connection_cleanup (sctp_connection_t * sctp_conn);
void sctp_connection_del (sctp_connection_t * sctp_conn);

u32 sctp_push_header (transport_connection_t * tconn, vlib_buffer_t * b);
void sctp_send_init (sctp_connection_t * sctp_conn);
void sctp_send_cookie_echo (sctp_connection_t * sctp_conn);
void sctp_send_shutdown (sctp_connection_t * sctp_conn);
void sctp_send_shutdown_ack (sctp_connection_t * sctp_conn, u8 idx,
			     vlib_buffer_t * b);
void sctp_send_shutdown_complete (sctp_connection_t * sctp_conn, u8 idx,
				  vlib_buffer_t * b0);
void sctp_send_heartbeat (sctp_connection_t * sctp_conn);
void sctp_data_retransmit (sctp_connection_t * sctp_conn);
void sctp_flush_frame_to_output (vlib_main_t * vm, u8 thread_index,
				 u8 is_ip4);
void sctp_flush_frames_to_output (u8 thread_index);
void sctp_punt_unknown (vlib_main_t * vm, u8 is_ip4, u8 is_add);

format_function_t format_sctp_state;

u8 *format_sctp_connection_id (u8 * s, va_list * args);
u8 *format_sctp_connection (u8 * s, va_list * args);
u8 *format_sctp_scoreboard (u8 * s, va_list * args);
u8 *format_sctp_header (u8 * s, va_list * args);
u8 *format_sctp_tx_trace (u8 * s, va_list * args);

clib_error_t *sctp_init (vlib_main_t * vm);
void sctp_connection_timers_init (sctp_connection_t * sctp_conn);
void sctp_connection_timers_reset (sctp_connection_t * sctp_conn);
void sctp_init_snd_vars (sctp_connection_t * sctp_conn);
void sctp_init_mss (sctp_connection_t * sctp_conn);

void sctp_prepare_initack_chunk (sctp_connection_t * sctp_conn, u8 idx,
				 vlib_buffer_t * b, ip4_address_t * ip4_addr,
				 u8 add_ip4, ip6_address_t * ip6_addr,
				 u8 add_ip6);
void sctp_prepare_initack_chunk_for_collision (sctp_connection_t * sctp_conn,
					       u8 idx, vlib_buffer_t * b,
					       ip4_address_t * ip4_addr,
					       ip6_address_t * ip6_addr);
void sctp_prepare_abort_for_collision (sctp_connection_t * sctp_conn, u8 idx,
				       vlib_buffer_t * b,
				       ip4_address_t * ip4_addr,
				       ip6_address_t * ip6_addr);
void sctp_prepare_operation_error (sctp_connection_t * sctp_conn, u8 idx,
				   vlib_buffer_t * b, u8 err_cause);
void sctp_prepare_cookie_echo_chunk (sctp_connection_t * sctp_conn, u8 idx,
				     vlib_buffer_t * b, u8 reuse_buffer);
void sctp_prepare_cookie_ack_chunk (sctp_connection_t * sctp_conn, u8 idx,
				    vlib_buffer_t * b);
void sctp_prepare_sack_chunk (sctp_connection_t * sctp_conn, u8 idx,
			      vlib_buffer_t * b);
void sctp_prepare_heartbeat_ack_chunk (sctp_connection_t * sctp_conn, u8 idx,
				       vlib_buffer_t * b);

u16 sctp_check_outstanding_data_chunks (sctp_connection_t * sctp_conn);

void sctp_api_reference (void);

#define IP_PROTOCOL_SCTP	132

/** SSCTP FSM state definitions as per RFC4960. */
#define foreach_sctp_fsm_state                \
  _(CLOSED, "CLOSED")                         \
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

always_inline char *
sctp_state_to_string (u8 state)
{
  switch (state)
    {
    case SCTP_STATE_CLOSED:
      return "SCTP_STATE_CLOSED";
    case SCTP_STATE_COOKIE_WAIT:
      return "SCTP_STATE_COOKIE_WAIT";
    case SCTP_STATE_COOKIE_ECHOED:
      return "SCTP_STATE_COOKIE_ECHOED";
    case SCTP_STATE_ESTABLISHED:
      return "SCTP_STATE_ESTABLISHED";
    case SCTP_STATE_SHUTDOWN_PENDING:
      return "SCTP_STATE_SHUTDOWN_PENDING";
    case SCTP_STATE_SHUTDOWN_SENT:
      return "SCTP_STATE_SHUTDOWN_SENT";
    case SCTP_STATE_SHUTDOWN_RECEIVED:
      return "SCTP_STATE_SHUTDOWN_RECEIVED";
    case SCTP_STATE_SHUTDOWN_ACK_SENT:
      return "SCTP_STATE_SHUTDOWN_ACK_SENT";
    }
  return NULL;
}

always_inline char *
sctp_chunk_to_string (u8 type)
{
  switch (type)
    {
    case DATA:
      return "DATA";
    case INIT:
      return "INIT";
    case INIT_ACK:
      return "INIT_ACK";
    case SACK:
      return "SACK";
    case HEARTBEAT:
      return "HEARTBEAT";
    case HEARTBEAT_ACK:
      return "HEARTBEAT_ACK";
    case ABORT:
      return "ABORT";
    case SHUTDOWN:
      return "SHUTDOWN";
    case SHUTDOWN_ACK:
      return "SHUTDOWN_ACK";
    case OPERATION_ERROR:
      return "OPERATION_ERROR";
    case COOKIE_ECHO:
      return "COOKIE_ECHO";
    case COOKIE_ACK:
      return "COOKIE_ACK";
    case ECNE:
      return "ECNE";
    case CWR:
      return "CWR";
    case SHUTDOWN_COMPLETE:
      return "SHUTDOWN_COMPLETE";
    }
  return NULL;
}

always_inline char *
sctp_optparam_type_to_string (u8 type)
{
  switch (type)
    {
    case SCTP_IPV4_ADDRESS_TYPE:
      return "SCTP_IPV4_ADDRESS_TYPE";
    case SCTP_IPV6_ADDRESS_TYPE:
      return "SCTP_IPV6_ADDRESS_TYPE";
    case SCTP_STATE_COOKIE_TYPE:
      return "SCTP_STATE_COOKIE_TYPE";
    case SCTP_UNRECOGNIZED_TYPE:
      return "SCTP_UNRECOGNIZED_TYPE";
    case SCTP_COOKIE_PRESERVATIVE_TYPE:
      return "SCTP_COOKIE_PRESERVATIVE_TYPE";
    case SCTP_HOSTNAME_ADDRESS_TYPE:
      return "SCTP_HOSTNAME_ADDRESS_TYPE";
    case SCTP_SUPPORTED_ADDRESS_TYPES:
      return "SCTP_SUPPORTED_ADDRESS_TYPES";
    }
  return NULL;
}

#define SCTP_TICK 0.001			/**< SCTP tick period (s) */
#define SHZ (u32) (1/SCTP_TICK)		/**< SCTP tick frequency */
#define SCTP_TSTAMP_RESOLUTION SCTP_TICK	/**< Time stamp resolution */

/* As per RFC4960, page 83 */
#define SCTP_RTO_INIT 3 * SHZ	/* 3 seconds */
#define SCTP_RTO_MIN 1 * SHZ	/* 1 second */
#define SCTP_RTO_MAX 60 * SHZ	/* 60 seconds */
#define SCTP_RTO_BURST 4
#define SCTP_RTO_ALPHA 1/8
#define SCTP_RTO_BETA 1/4
#define SCTP_VALID_COOKIE_LIFE 60 * SHZ	/* 60 seconds */
#define SCTP_ASSOCIATION_MAX_RETRANS 10	// the overall connection
#define SCTP_PATH_MAX_RETRANS 5	// number of attempts per destination address
#define SCTP_MAX_INIT_RETRANS 8	// number of attempts
#define SCTP_HB_INTERVAL 30 * SHZ
#define SCTP_HB_MAX_BURST 1
#define SCTP_DATA_IDLE_INTERVAL 15 * SHZ	/* 15 seconds; the time-interval after which the connetion is considered IDLE */
#define SCTP_TO_TIMER_TICK       SCTP_TICK*10	/* Period for converting from SCTP_TICK */

#define SCTP_CONN_RECOVERY 1 << 1
#define SCTP_FAST_RECOVERY 1 << 2

typedef struct _sctp_lookup_dispatch
{
  u8 next, error;
} sctp_lookup_dispatch_t;

typedef struct _sctp_main
{
  /* Per-worker thread SCTP connection pools */
  sctp_connection_t **connections;

  /* Pool of listeners. */
  sctp_connection_t *listener_pool;

	  /** Dispatch table by state and flags */
  sctp_lookup_dispatch_t dispatch_table[SCTP_N_STATES][64];

  u8 log2_tstamp_clocks_per_tick;
  f64 tstamp_ticks_per_clock;
  u64 *time_now;

	  /** per-worker tx buffer free lists */
  u32 **tx_buffers;
	  /** per-worker tx frames to SCTP 4/6 output nodes */
  vlib_frame_t **tx_frames[2];
	  /** per-worker tx frames to ip 4/6 lookup nodes */
  vlib_frame_t **ip_lookup_tx_frames[2];

  /* Per worker-thread timer wheel for connections timers */
  tw_timer_wheel_16t_2w_512sl_t *timer_wheels;

  /* Pool of half-open connections on which we've sent a SYN */
  sctp_connection_t *half_open_connections;
  clib_spinlock_t half_open_lock;

  /* TODO: Congestion control algorithms registered */
  /* sctp_cc_algorithm_t *cc_algos; */

  /* Flag that indicates if stack is on or off */
  u8 is_enabled;

	  /** Number of preallocated connections */
  u32 preallocated_connections;

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

always_inline sctp_header_t *
sctp_buffer_hdr (vlib_buffer_t * b)
{
  ASSERT ((signed) b->current_data >= (signed) -VLIB_BUFFER_PRE_DATA_SIZE);
  return (sctp_header_t *) (b->data + b->current_data
			    + vnet_buffer (b)->sctp.hdr_offset);
}

clib_error_t *vnet_sctp_enable_disable (vlib_main_t * vm, u8 is_en);

always_inline sctp_connection_t *
sctp_half_open_connection_get (u32 conn_index)
{
  sctp_connection_t *tc = 0;
  clib_spinlock_lock_if_init (&sctp_main.half_open_lock);
  if (!pool_is_free_index (sctp_main.half_open_connections, conn_index))
    tc = pool_elt_at_index (sctp_main.half_open_connections, conn_index);
  tc->sub_conn[SCTP_PRIMARY_PATH_IDX].subconn_idx = SCTP_PRIMARY_PATH_IDX;
  clib_spinlock_unlock_if_init (&sctp_main.half_open_lock);
  return tc;
}

/**
 * Cleanup half-open connection
 *
 */
always_inline void
sctp_half_open_connection_del (sctp_connection_t * tc)
{
  sctp_main_t *sctp_main = vnet_get_sctp_main ();
  clib_spinlock_lock_if_init (&sctp_main->half_open_lock);
  pool_put_index (sctp_main->half_open_connections,
		  tc->sub_conn[SCTP_PRIMARY_PATH_IDX].c_c_index);
  if (CLIB_DEBUG)
    memset (tc, 0xFA, sizeof (*tc));
  clib_spinlock_unlock_if_init (&sctp_main->half_open_lock);
}

always_inline u64
sctp_set_time_now (u32 thread_index)
{
  sctp_main.time_now[thread_index] = clib_cpu_time_now ()
    * sctp_main.tstamp_ticks_per_clock;
  return sctp_main.time_now[thread_index];
}

always_inline void
sctp_timer_set (sctp_connection_t * tc, u8 conn_idx, u8 timer_id,
		u32 interval)
{
  ASSERT (tc->sub_conn[conn_idx].connection.thread_index ==
	  vlib_get_thread_index ());
  ASSERT (tc->sub_conn[conn_idx].timers[timer_id] ==
	  SCTP_TIMER_HANDLE_INVALID);

  sctp_sub_connection_t *sub = &tc->sub_conn[conn_idx];
  sub->timers[timer_id] =
    tw_timer_start_16t_2w_512sl (&sctp_main.timer_wheels[sub->c_thread_index],
				 sub->c_c_index, timer_id, interval);
}

always_inline void
sctp_timer_reset (sctp_connection_t * tc, u8 conn_idx, u8 timer_id)
{
  ASSERT (tc->sub_conn[conn_idx].c_thread_index == vlib_get_thread_index ());
  if (tc->sub_conn[conn_idx].timers[timer_id] == SCTP_TIMER_HANDLE_INVALID)
    return;

  sctp_sub_connection_t *sub = &tc->sub_conn[conn_idx];

  tw_timer_stop_16t_2w_512sl (&sctp_main.timer_wheels[sub->c_thread_index],
			      sub->timers[timer_id]);
  sub->timers[timer_id] = SCTP_TIMER_HANDLE_INVALID;
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
always_inline int
sctp_half_open_connection_cleanup (sctp_connection_t * tc)
{
  /* Make sure this is the owning thread */
  if (tc->sub_conn[SCTP_PRIMARY_PATH_IDX].c_thread_index !=
      vlib_get_thread_index ())
    return 1;
  sctp_timer_reset (tc, SCTP_PRIMARY_PATH_IDX, SCTP_TIMER_T1_INIT);
  sctp_half_open_connection_del (tc);
  return 0;
}

always_inline u32
sctp_header_bytes ()
{
  return sizeof (sctp_header_t);
}

always_inline sctp_connection_t *
sctp_get_connection_from_transport (transport_connection_t * tconn)
{
  ASSERT (tconn != NULL);

  sctp_sub_connection_t *sub = (sctp_sub_connection_t *) tconn;
#if SCTP_ADV_DEBUG
  if (sub == NULL)
    SCTP_ADV_DBG ("sub == NULL");
  if (sub->parent == NULL)
    SCTP_ADV_DBG ("sub->parent == NULL");
#endif
  if (sub->subconn_idx > 0)
    return (sctp_connection_t *) sub -
      (sizeof (sctp_sub_connection_t) * (sub->subconn_idx - 1));

  return (sctp_connection_t *) sub;
}

always_inline u64
sctp_time_now (void)
{
  return sctp_main.time_now[vlib_get_thread_index ()];
}

#define ABS(x) ((x) > 0) ? (x) : -(x);

always_inline void
sctp_calculate_rto (sctp_connection_t * sctp_conn, u8 conn_idx)
{
  /* See RFC4960, 6.3.1.  RTO Calculation */
  u64 RTO = 0;
  f64 RTTVAR = 0;
  u64 now = sctp_time_now ();
  u64 prev_ts = sctp_conn->sub_conn[conn_idx].rtt_ts;
  u64 R = prev_ts - now;

  if (sctp_conn->sub_conn[conn_idx].RTO == 0)	// C1: Let's initialize our RTO
    {
      sctp_conn->sub_conn[conn_idx].RTO = SCTP_RTO_MIN;
      return;
    }

  if (sctp_conn->sub_conn[conn_idx].RTO == SCTP_RTO_MIN && sctp_conn->sub_conn[conn_idx].SRTT == 0)	// C2: First RTT calculation
    {
      sctp_conn->sub_conn[conn_idx].SRTT = R;
      RTTVAR = R / 2;

      if (RTTVAR == 0)
	RTTVAR = 100e-3;	/* 100 ms */

      sctp_conn->sub_conn[conn_idx].RTTVAR = RTTVAR;
    }
  else				// C3: RTT already exists; let's recalculate
    {
      RTTVAR = (1 - SCTP_RTO_BETA) * sctp_conn->sub_conn[conn_idx].RTTVAR +
	SCTP_RTO_BETA * ABS (sctp_conn->sub_conn[conn_idx].SRTT - R);

      if (RTTVAR == 0)
	RTTVAR = 100e-3;	/* 100 ms */

      sctp_conn->sub_conn[conn_idx].RTTVAR = RTTVAR;

      sctp_conn->sub_conn[conn_idx].SRTT =
	(1 - SCTP_RTO_ALPHA) * sctp_conn->sub_conn[conn_idx].SRTT +
	SCTP_RTO_ALPHA * R;
    }

  RTO =
    sctp_conn->sub_conn[conn_idx].SRTT +
    4 * sctp_conn->sub_conn[conn_idx].RTTVAR;
  if (RTO < SCTP_RTO_MIN)	// C6
    RTO = SCTP_RTO_MIN;

  if (RTO > SCTP_RTO_MAX)	// C7
    RTO = SCTP_RTO_MAX;

  sctp_conn->sub_conn[conn_idx].RTO = RTO;
}

always_inline void
sctp_timer_update (sctp_connection_t * tc, u8 conn_idx, u8 timer_id,
		   u32 interval)
{
  ASSERT (tc->sub_conn[conn_idx].connection.thread_index ==
	  vlib_get_thread_index ());
  sctp_sub_connection_t *sub = &tc->sub_conn[conn_idx];

  if (tc->sub_conn[conn_idx].timers[timer_id] != SCTP_TIMER_HANDLE_INVALID)
    tw_timer_stop_16t_2w_512sl (&sctp_main.timer_wheels[sub->c_thread_index],
				sub->timers[timer_id]);

  tc->sub_conn[conn_idx].timers[timer_id] =
    tw_timer_start_16t_2w_512sl (&sctp_main.timer_wheels[sub->c_thread_index],
				 sub->c_c_index, timer_id, interval);
}

always_inline sctp_connection_t *
sctp_listener_get (u32 tli)
{
  return pool_elt_at_index (sctp_main.listener_pool, tli);
}

#endif

always_inline sctp_connection_t *
sctp_connection_get (u32 conn_index, u32 thread_index)
{
  if (PREDICT_FALSE
      (pool_is_free_index (sctp_main.connections[thread_index], conn_index)))
    return 0;
  return pool_elt_at_index (sctp_main.connections[thread_index], conn_index);
}

#define SELECT_MAX_RETRIES 8

always_inline u8
sctp_data_subconn_select (sctp_connection_t * sctp_conn)
{
  u32 sub = SCTP_PRIMARY_PATH_IDX;
  u8 i, cwnd = sctp_conn->sub_conn[SCTP_PRIMARY_PATH_IDX].cwnd;
  for (i = 1; i < MAX_SCTP_CONNECTIONS; i++)
    {
      if (sctp_conn->sub_conn[i].state == SCTP_SUBCONN_STATE_DOWN)
	continue;

      if (sctp_conn->sub_conn[i].cwnd > cwnd)
	{
	  sub = i;
	  cwnd = sctp_conn->sub_conn[i].cwnd;
	}
    }
  return sub;
}

always_inline u8
sctp_sub_conn_id_via_ip6h (sctp_connection_t * sctp_conn, ip6_header_t * ip6h)
{
  u8 i;

  for (i = 0; i < MAX_SCTP_CONNECTIONS; i++)
    {
      if (sctp_conn->sub_conn[i].connection.lcl_ip.ip6.as_u64[0] ==
	  ip6h->dst_address.as_u64[0] &&
	  sctp_conn->sub_conn[i].connection.lcl_ip.ip6.as_u64[1] ==
	  ip6h->dst_address.as_u64[1] &&
	  sctp_conn->sub_conn[i].connection.rmt_ip.ip6.as_u64[0] ==
	  ip6h->src_address.as_u64[0] &&
	  sctp_conn->sub_conn[i].connection.rmt_ip.ip6.as_u64[1] ==
	  ip6h->src_address.as_u64[1])
	return i;
    }
  clib_warning ("Did not find a sub-connection; defaulting to %u",
		SCTP_PRIMARY_PATH_IDX);
  return SCTP_PRIMARY_PATH_IDX;
}

always_inline u8
sctp_sub_conn_id_via_ip4h (sctp_connection_t * sctp_conn, ip4_header_t * ip4h)
{
  u8 i;

  for (i = 0; i < MAX_SCTP_CONNECTIONS; i++)
    {
      if (sctp_conn->sub_conn[i].connection.lcl_ip.ip4.as_u32 ==
	  ip4h->dst_address.as_u32
	  && sctp_conn->sub_conn[i].connection.rmt_ip.ip4.as_u32 ==
	  ip4h->src_address.as_u32)
	return i;
    }
  clib_warning ("Did not find a sub-connection; defaulting to %u",
		SCTP_PRIMARY_PATH_IDX);
  return SCTP_PRIMARY_PATH_IDX;
}

/**
 * Push SCTP header to buffer
 *
 * @param vm - vlib_main
 * @param b - buffer to write the header to
 * @param sp_net - source port net order
 * @param dp_net - destination port net order
 * @param sctp_hdr_opts_len - header and options length in bytes
 *
 * @return - pointer to start of SCTP header
 */
always_inline void *
vlib_buffer_push_sctp_net_order (vlib_buffer_t * b, u16 sp, u16 dp,
				 u8 sctp_hdr_opts_len)
{
  sctp_full_hdr_t *full_hdr;

  full_hdr = vlib_buffer_push_uninit (b, sctp_hdr_opts_len);

  full_hdr->hdr.src_port = sp;
  full_hdr->hdr.dst_port = dp;
  full_hdr->hdr.checksum = 0;
  return full_hdr;
}

/**
 * Push SCTP header to buffer
 *
 * @param b - buffer to write the header to
 * @param sp_net - source port net order
 * @param dp_net - destination port net order
 * @param sctp_hdr_opts_len - header and options length in bytes
 *
 * @return - pointer to start of SCTP header
 */
always_inline void *
vlib_buffer_push_sctp (vlib_buffer_t * b, u16 sp_net, u16 dp_net,
		       u8 sctp_hdr_opts_len)
{
  return vlib_buffer_push_sctp_net_order (b, sp_net, dp_net,
					  sctp_hdr_opts_len);
}

always_inline u8
sctp_next_avail_subconn (sctp_connection_t * sctp_conn)
{
  u8 i;

  for (i = 0; i < MAX_SCTP_CONNECTIONS; i++)
    {
      if (sctp_conn->sub_conn[i].state == SCTP_SUBCONN_STATE_DOWN)
	return i;
    }
  return MAX_SCTP_CONNECTIONS;
}

always_inline void
update_smallest_pmtu_idx (sctp_connection_t * sctp_conn)
{
  u8 i;
  u8 smallest_pmtu_index = SCTP_PRIMARY_PATH_IDX;

  for (i = 1; i < MAX_SCTP_CONNECTIONS; i++)
    {
      if (sctp_conn->sub_conn[i].state != SCTP_SUBCONN_STATE_DOWN)
	{
	  if (sctp_conn->sub_conn[i].PMTU <
	      sctp_conn->sub_conn[smallest_pmtu_index].PMTU)
	    smallest_pmtu_index = i;
	}
    }

  sctp_conn->smallest_PMTU_idx = smallest_pmtu_index;
}

/* As per RFC4960; section 7.2.1: Slow-Start */
always_inline void
sctp_init_cwnd (sctp_connection_t * sctp_conn)
{
  u8 i;
  for (i = 0; i < MAX_SCTP_CONNECTIONS; i++)
    {
      /* Section 7.2.1; point (1) */
      sctp_conn->sub_conn[i].cwnd =
	clib_min (4 * sctp_conn->sub_conn[i].PMTU,
		  clib_max (2 * sctp_conn->sub_conn[i].PMTU, 4380));

      /* Section 7.2.1; point (3) */
      sctp_conn->sub_conn[i].ssthresh = SCTP_INITIAL_SSHTRESH;

      /* Section 7.2.2; point (1) */
      sctp_conn->sub_conn[i].partially_acked_bytes = 0;
    }
}

always_inline u8
sctp_in_cong_recovery (sctp_connection_t * sctp_conn, u8 idx)
{
  return 0;
}

always_inline u8
cwnd_fully_utilized (sctp_connection_t * sctp_conn, u8 idx)
{
  if (sctp_conn->sub_conn[idx].cwnd == 0)
    return 1;
  return 0;
}

/* As per RFC4960; section 7.2.1: Slow-Start */
always_inline void
update_cwnd (sctp_connection_t * sctp_conn)
{
  u8 i;
  u32 inflight = sctp_conn->next_tsn - sctp_conn->last_unacked_tsn;

  for (i = 0; i < MAX_SCTP_CONNECTIONS; i++)
    {
      /* Section 7.2.1; point (2) */
      if (sctp_conn->sub_conn[i].is_retransmitting)
	{
	  sctp_conn->sub_conn[i].cwnd = 1 * sctp_conn->sub_conn[i].PMTU;
	  continue;
	}

      /* Section 7.2.2; point (4) */
      if (sctp_conn->sub_conn[i].last_data_ts >
	  sctp_time_now () + SCTP_DATA_IDLE_INTERVAL)
	{
	  sctp_conn->sub_conn[i].cwnd =
	    clib_max (sctp_conn->sub_conn[i].cwnd / 2,
		      4 * sctp_conn->sub_conn[i].PMTU);
	  continue;
	}

      /* Section 7.2.1; point (5) */
      if (sctp_conn->sub_conn[i].cwnd <= sctp_conn->sub_conn[i].ssthresh)
	{
	  if (!cwnd_fully_utilized (sctp_conn, i))
	    continue;

	  if (sctp_in_cong_recovery (sctp_conn, i))
	    continue;

	  sctp_conn->sub_conn[i].cwnd =
	    clib_min (sctp_conn->sub_conn[i].PMTU, 1);
	}

      /* Section 6.1; point (D) */
      if ((inflight + SCTP_RTO_BURST * sctp_conn->sub_conn[i].PMTU) <
	  sctp_conn->sub_conn[i].cwnd)
	sctp_conn->sub_conn[i].cwnd =
	  inflight + SCTP_RTO_BURST * sctp_conn->sub_conn[i].PMTU;
    }
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
