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

#include <vppinfra/timing_wheel.h>
#include <vnet/vnet.h>
#include <vnet/bfd/bfd_protocol.h>
#include <vnet/bfd/bfd_udp.h>

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

  /** configured desired min tx interval (clocks) */
  u64 config_desired_min_tx_clocks;

  /** effective desired min tx interval (clocks) */
  u64 effective_desired_min_tx_clocks;

  /** configured required min rx interval (microseconds) */
  u32 config_required_min_rx_usec;

  /** configured required min rx interval (clocks) */
  u64 config_required_min_rx_clocks;

  /** effective required min rx interval (clocks) */
  u64 effective_required_min_rx_clocks;

  /** remote min rx interval (microseconds) */
  u64 remote_min_rx_usec;

  /** remote min rx interval (clocks) */
  u64 remote_min_rx_clocks;

  /** remote min echo rx interval (microseconds) */
  u64 remote_min_echo_rx_usec;

  /** remote min echo rx interval (clocks) */
  u64 remote_min_echo_rx_clocks;

  /** remote desired min tx interval (clocks) */
  u64 remote_desired_min_tx_clocks;

  /** configured detect multiplier */
  u8 local_detect_mult;

  /** 1 if remote system sets demand mode, 0 otherwise */
  u8 remote_demand;

  /** remote detect multiplier */
  u8 remote_detect_mult;

  /** 1 is echo function is active, 0 otherwise */
  u8 echo;

  /** set to value of timer in timing wheel, 0 if never set */
  u64 wheel_time_clocks;

  /** transmit interval */
  u64 transmit_interval_clocks;

  /** next time at which to transmit a packet */
  u64 tx_timeout_clocks;

  /** timestamp of last packet transmitted */
  u64 last_tx_clocks;

  /** timestamp of last packet received */
  u64 last_rx_clocks;

  /** transmit interval for echo packets */
  u64 echo_transmit_interval_clocks;

  /** next time at which to transmit echo packet */
  u64 echo_tx_timeout_clocks;

  /** timestamp of last echo packet transmitted */
  u64 echo_last_tx_clocks;

  /** timestamp of last echo packet received */
  u64 echo_last_rx_clocks;

  /** secret used for calculating/checking checksum of echo packets */
  u32 echo_secret;

  /** detection time */
  u64 detection_time_clocks;

  /** state info regarding poll sequence */
  bfd_poll_state_e poll_state;

  /**
   * helper for delayed poll sequence - marks either start of running poll
   * sequence or timeout, after which we can start the next poll sequnce
   */
  u64 poll_state_start_or_timeout_clocks;

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
  /** pool of bfd sessions context data */
  bfd_session_t *sessions;

  /** timing wheel for scheduling timeouts */
  timing_wheel_t wheel;

  /** timing wheel inaccuracy, in clocks */
  u64 wheel_inaccuracy;

  /** hashmap - bfd session by discriminator */
  u32 *session_by_disc;

  /** background process node index */
  u32 bfd_process_node_index;

  /** convenience variables */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;

  /** cpu clocks per second */
  f64 cpu_cps;

  /** default desired min tx in clocks */
  u64 default_desired_min_tx_clocks;

  /** minimum required min rx while echo function is active - clocks */
  u64 min_required_min_rx_while_echo_clocks;

  /** for generating random numbers */
  u32 random_seed;

  /** pool of authentication keys */
  bfd_auth_key_t *auth_keys;

  /** hashmap - index in pool auth_keys by conf_key_id */
  u32 *auth_key_by_conf_key_id;

  /** A vector of callback notification functions */
  bfd_notify_fn_t *listeners;
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

enum
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
  /** expire time of this packet - clocks */
  u64 expire_time_clocks;
  /** checksum - based on discriminator, local secret and expire time */
  u64 checksum;
}) bfd_echo_pkt_t;
/* *INDENT-ON* */

u8 *bfd_input_format_trace (u8 * s, va_list * args);
bfd_session_t *bfd_get_session (bfd_main_t * bm, bfd_transport_e t);
void bfd_put_session (bfd_main_t * bm, bfd_session_t * bs);
bfd_session_t *bfd_find_session_by_idx (bfd_main_t * bm, uword bs_idx);
bfd_session_t *bfd_find_session_by_disc (bfd_main_t * bm, u32 disc);
void bfd_session_start (bfd_main_t * bm, bfd_session_t * bs);
void bfd_consume_pkt (bfd_main_t * bm, const bfd_pkt_t * bfd, u32 bs_idx);
int bfd_consume_echo_pkt (bfd_main_t * bm, vlib_buffer_t * b);
int bfd_verify_pkt_common (const bfd_pkt_t * pkt);
int bfd_verify_pkt_auth (const bfd_pkt_t * pkt, u16 pkt_size,
			 bfd_session_t * bs);
void bfd_event (bfd_main_t * bm, bfd_session_t * bs);
void bfd_init_final_control_frame (vlib_main_t * vm, vlib_buffer_t * b,
				   bfd_main_t * bm, bfd_session_t * bs,
				   int is_local);
u8 *format_bfd_session (u8 * s, va_list * args);
u8 *format_bfd_auth_key (u8 * s, va_list * args);
void bfd_session_set_flags (bfd_session_t * bs, u8 admin_up_down);
unsigned bfd_auth_type_supported (bfd_auth_type_e auth_type);
vnet_api_error_t bfd_auth_activate (bfd_session_t * bs, u32 conf_key_id,
				    u8 bfd_key_id, u8 is_delayed);
vnet_api_error_t bfd_auth_deactivate (bfd_session_t * bs, u8 is_delayed);
vnet_api_error_t bfd_session_set_params (bfd_main_t * bm, bfd_session_t * bs,
					 u32 desired_min_tx_usec,
					 u32 required_min_rx_usec,
					 u8 detect_mult);

u32 bfd_clocks_to_usec (const bfd_main_t * bm, u64 clocks);
const char *bfd_poll_state_string (bfd_poll_state_e state);

#define USEC_PER_MS 1000LL
#define USEC_PER_SECOND (1000 * USEC_PER_MS)

/** default, slow transmission interval for BFD packets, per spec at least 1s */
#define BFD_DEFAULT_DESIRED_MIN_TX_USEC USEC_PER_SECOND

/**
 * minimum required min rx set locally when echo function is used, per spec
 * should be set to at least 1s
 */
#define BFD_REQUIRED_MIN_RX_USEC_WHILE_ECHO USEC_PER_SECOND

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
