/*
 * Copyright (c) 2011-2016 Cisco and/or its affiliates.
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
 * @brief BFD global declarations
 */
#ifndef __included_bfd_main_h__
#define __included_bfd_main_h__

#include <vnet/vnet.h>
#include <vnet/bfd/bfd_protocol.h>
#include <vnet/bfd/bfd_udp.h>
#include <vlib/log.h>
#include <vppinfra/os.h>
#include <vppinfra/tw_timer_1t_3w_1024sl_ov.h>

#define foreach_bfd_mode(F) \
  F (asynchronous)          \
  F (demand)

typedef enum
{
#define F(x) BFD_MODE_##x,
  foreach_bfd_mode (F)
#undef F
} bfd_mode_e;

typedef struct
{
  /** global configuration key ID */
  u32 conf_key_id;

  /** keeps track of how many sessions reference this key */
  u32 use_count;

  /**
   * key data directly usable for bfd purposes - already padded with zeroes
   * (so we don't need the actual length)
   */
  u8 key[20];

  /** authentication type for this key */
  bfd_auth_type_e auth_type;
} bfd_auth_key_t;

#define foreach_bfd_poll_state(F) \
  F (NOT_NEEDED)                  \
  F (NEEDED)                      \
  F (IN_PROGRESS)                 \
  F (IN_PROGRESS_AND_QUEUED)

typedef enum
{
#define F(x) BFD_POLL_##x,
  foreach_bfd_poll_state (F)
#undef F
} bfd_poll_state_e;

/**
 * hop types
 */
#define foreach_bfd_hop(F)                     \
  F (SINGLE, "single")                         \
  F (MULTI,  "multi")                          \

typedef enum
{
#define F(sym, str) BFD_HOP_TYPE_##sym,
  foreach_bfd_hop (F)
#undef F
} bfd_hop_type_e;

typedef struct bfd_session_s
{
  /** index in bfd_main.sessions pool */
  u32 bs_idx;

  /** session state */
  bfd_state_e local_state;

  /** remote session state */
  bfd_state_e remote_state;

  /** BFD hop type */
  bfd_hop_type_e hop_type;

  /** local diagnostics */
  bfd_diag_code_e local_diag;

  /** remote diagnostics */
  bfd_diag_code_e remote_diag;

  /** local discriminator */
  u32 local_discr;

  /** remote discriminator */
  u32 remote_discr;

  /** configured desired min tx interval (microseconds) */
  u32 config_desired_min_tx_usec;

  /** configured desired min tx interval (nsec) */
  u64 config_desired_min_tx_nsec;

  /** effective desired min tx interval (nsec) */
  u64 effective_desired_min_tx_nsec;

  /** configured required min rx interval (microseconds) */
  u32 config_required_min_rx_usec;

  /** configured required min rx interval (nsec) */
  u64 config_required_min_rx_nsec;

  /** effective required min rx interval (nsec) */
  u64 effective_required_min_rx_nsec;

  /** remote min rx interval (microseconds) */
  u64 remote_min_rx_usec;

  /** remote min rx interval (nsec) */
  u64 remote_min_rx_nsec;

  /** remote min echo rx interval (microseconds) */
  u64 remote_min_echo_rx_usec;

  /** remote min echo rx interval (nsec) */
  u64 remote_min_echo_rx_nsec;

  /** remote desired min tx interval (nsec) */
  u64 remote_desired_min_tx_nsec;

  /** configured detect multiplier */
  u8 local_detect_mult;

  /** 1 if remote system sets demand mode, 0 otherwise */
  u8 remote_demand;

  /** remote detect multiplier */
  u8 remote_detect_mult;

  /** 1 is echo function is active, 0 otherwise */
  u8 echo;

  /** next event time in nsec for this session (0 if no event) */
  u64 event_time_nsec;

  /** timing wheel internal id used to manipulate timer (if set) */
  u32 tw_id;

  /** transmit interval */
  u64 transmit_interval_nsec;

  /** next time at which to transmit a packet */
  u64 tx_timeout_nsec;

  /** timestamp of last packet transmitted */
  u64 last_tx_nsec;

  /** timestamp of last packet received */
  u64 last_rx_nsec;

  /** transmit interval for echo packets */
  u64 echo_transmit_interval_nsec;

  /** next time at which to transmit echo packet */
  u64 echo_tx_timeout_nsec;

  /** timestamp of last echo packet transmitted */
  u64 echo_last_tx_nsec;

  /** timestamp of last echo packet received */
  u64 echo_last_rx_nsec;

  /** secret used for calculating/checking checksum of echo packets */
  u32 echo_secret;

  /** detection time */
  u64 detection_time_nsec;

  /** state info regarding poll sequence */
  bfd_poll_state_e poll_state;

  /**
   * helper for delayed poll sequence - marks either start of running poll
   * sequence or timeout, after which we can start the next poll sequnce
   */
  u64 poll_state_start_or_timeout_nsec;

  /** authentication information */
  struct
  {
    /** current key in use */
    bfd_auth_key_t *curr_key;

    /**
     * set to next key to use if delayed switch is enabled - in that case
     * the key is switched when first incoming packet is signed with next_key
     */
    bfd_auth_key_t *next_key;

    /** sequence number incremented occasionally or always (if meticulous) */
    u32 local_seq_number;

    /** remote sequence number */
    u32 remote_seq_number;

    /** set to 1 if remote sequence number is known */
    u8 remote_seq_number_known;

    /** current key ID sent out in bfd packet */
    u8 curr_bfd_key_id;

    /** key ID to use when switched to next_key */
    u8 next_bfd_key_id;

    /**
     * set to 1 if delayed action is pending, which might be activation
     * of authentication, change of key or deactivation
     */
    u8 is_delayed;
  } auth;

  /** transport type for this session */
  bfd_transport_e transport;

  /** union of transport-specific data */
  union
  {
    bfd_udp_session_t udp;
  };
} bfd_session_t;

/**
 * listener events
 */
#define foreach_bfd_listen_event(F)            \
  F (CREATE, "sesion-created")                 \
  F (UPDATE, "session-updated")                \
  F (DELETE, "session-deleted")

typedef enum
{
#define F(sym, str) BFD_LISTEN_EVENT_##sym,
  foreach_bfd_listen_event (F)
#undef F
} bfd_listen_event_e;

/**
 * session nitification call back function type
 */
typedef void (*bfd_notify_fn_t) (bfd_listen_event_e, const bfd_session_t *);

typedef struct
{
  /** lock to protect data structures */
  clib_spinlock_t lock;
  int lock_recursion_count;
  uword owner_thread_index;

  /** Number of event wakeup RPCs in flight. Should be 0 or 1 */
  int bfd_process_wakeup_events_in_flight;

  /** The timestamp of last wakeup event being sent */
  u64 bfd_process_wakeup_event_start_nsec;

  /** The time it took the last wakeup event to make it to handling */
  u64 bfd_process_wakeup_event_delay_nsec;

  /** When the bfd process is supposed to wake up next */
  u64 bfd_process_next_wakeup_nsec;

  /** pool of bfd sessions context data */
  bfd_session_t *sessions;

  /** timing wheel for scheduling timeouts */
    TWT (tw_timer_wheel) wheel;

  /** hashmap - bfd session by discriminator */
  u32 *session_by_disc;

  /** background process node index */
  u32 bfd_process_node_index;

  /** convenience variables */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;

  /** how many nanoseconds is one timing wheel tick */
  u64 nsec_per_tw_tick;

  /** default desired min tx in nsec */
  u64 default_desired_min_tx_nsec;

  /** minimum required min rx while echo function is active - nsec */
  u64 min_required_min_rx_while_echo_nsec;

  /** for generating random numbers */
  u32 random_seed;

  /** pool of authentication keys */
  bfd_auth_key_t *auth_keys;

  /** hashmap - index in pool auth_keys by conf_key_id */
  u32 *auth_key_by_conf_key_id;

  /** vector of callback notification functions */
  bfd_notify_fn_t *listeners;

  /** log class */
  vlib_log_class_t log_class;
} bfd_main_t;

extern bfd_main_t bfd_main;

/** Packet counters */
#define foreach_bfd_error(F)               \
  F (NONE, "good bfd packets (processed)") \
  F (BAD, "invalid bfd packets")           \
  F (DISABLED, "bfd packets received on disabled interfaces")

typedef enum
{
#define F(sym, str) BFD_ERROR_##sym,
  foreach_bfd_error (F)
#undef F
    BFD_N_ERROR,
} bfd_error_t;

/** bfd packet trace capture */
typedef struct
{
  u32 len;
  u8 data[400];
} bfd_input_trace_t;

typedef enum
{
  BFD_EVENT_RESCHEDULE = 1,
  BFD_EVENT_NEW_SESSION,
  BFD_EVENT_CONFIG_CHANGED,
} bfd_process_event_e;

/* *INDENT-OFF* */
/** echo packet structure */
typedef CLIB_PACKED (struct {
  /** local discriminator */
  u32 discriminator;
  /** expire time of this packet - nsec */
  u64 expire_time_nsec;
  /** checksum - based on discriminator, local secret and expire time */
  u64 checksum;
}) bfd_echo_pkt_t;
/* *INDENT-ON* */

static inline void
bfd_lock (bfd_main_t * bm)
{
  uword my_thread_index = __os_thread_index;

  if (bm->owner_thread_index == my_thread_index
      && bm->lock_recursion_count > 0)
    {
      bm->lock_recursion_count++;
      return;
    }

  clib_spinlock_lock_if_init (&bm->lock);
  bm->lock_recursion_count = 1;
  bm->owner_thread_index = my_thread_index;
}

static inline void
bfd_unlock (bfd_main_t * bm)
{
  uword my_thread_index = __os_thread_index;
  ASSERT (bm->owner_thread_index == my_thread_index);

  if (bm->lock_recursion_count > 1)
    {
      bm->lock_recursion_count--;
      return;
    }
  bm->lock_recursion_count = 0;
  bm->owner_thread_index = ~0;
  clib_spinlock_unlock_if_init (&bm->lock);
}

static inline void
bfd_lock_check (bfd_main_t * bm)
{
  if (PREDICT_FALSE (bm->lock_recursion_count < 1))
    clib_warning ("lock check failure");
}

u8 *bfd_input_format_trace (u8 * s, va_list * args);
bfd_session_t *bfd_get_session (bfd_main_t * bm, bfd_transport_e t);
void bfd_put_session (bfd_main_t * bm, bfd_session_t * bs);
bfd_session_t *bfd_find_session_by_idx (bfd_main_t * bm, uword bs_idx);
bfd_session_t *bfd_find_session_by_disc (bfd_main_t * bm, u32 disc);
void bfd_session_start (bfd_main_t * bm, bfd_session_t * bs);
void bfd_consume_pkt (vlib_main_t * vm, bfd_main_t * bm,
		      const bfd_pkt_t * bfd, u32 bs_idx);
int bfd_consume_echo_pkt (vlib_main_t * vm, bfd_main_t * bm,
			  vlib_buffer_t * b);
int bfd_verify_pkt_common (const bfd_pkt_t * pkt);
int bfd_verify_pkt_auth (vlib_main_t * vm, const bfd_pkt_t * pkt,
			 u16 pkt_size, bfd_session_t * bs);
void bfd_event (bfd_main_t * bm, bfd_session_t * bs);
void bfd_init_final_control_frame (vlib_main_t * vm, vlib_buffer_t * b,
				   bfd_main_t * bm, bfd_session_t * bs,
				   int is_local);
u8 *format_bfd_session (u8 * s, va_list * args);
u8 *format_bfd_session_brief (u8 * s, va_list * args);
u8 *format_bfd_auth_key (u8 * s, va_list * args);
void bfd_session_set_flags (vlib_main_t * vm, bfd_session_t * bs,
			    u8 admin_up_down);
unsigned bfd_auth_type_supported (bfd_auth_type_e auth_type);
vnet_api_error_t bfd_auth_activate (bfd_session_t * bs, u32 conf_key_id,
				    u8 bfd_key_id, u8 is_delayed);
vnet_api_error_t bfd_auth_deactivate (bfd_session_t * bs, u8 is_delayed);
vnet_api_error_t bfd_session_set_params (bfd_main_t * bm, bfd_session_t * bs,
					 u32 desired_min_tx_usec,
					 u32 required_min_rx_usec,
					 u8 detect_mult);

u32 bfd_nsec_to_usec (u64 nsec);
const char *bfd_poll_state_string (bfd_poll_state_e state);

#define USEC_PER_MS (1000LL)
#define MSEC_PER_SEC (1000LL)
#define NSEC_PER_USEC (1000LL)
#define USEC_PER_SEC (MSEC_PER_SEC * USEC_PER_MS)
#define NSEC_PER_SEC (NSEC_PER_USEC * USEC_PER_SEC)
#define SEC_PER_NSEC ((f64)1/NSEC_PER_SEC)

/** timing wheel tick-rate, 1ms should be good enough */
#define BFD_TW_TPS (MSEC_PER_SEC)

/** default, slow transmission interval for BFD packets, per spec at least 1s */
#define BFD_DEFAULT_DESIRED_MIN_TX_USEC USEC_PER_SEC

/**
 * minimum required min rx set locally when echo function is used, per spec
 * should be set to at least 1s
 */
#define BFD_REQUIRED_MIN_RX_USEC_WHILE_ECHO USEC_PER_SEC

/**
 * Register a callback function to receive session notifications.
 */
void bfd_register_listener (bfd_notify_fn_t fn);

#endif /* __included_bfd_main_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
