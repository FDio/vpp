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

#define foreach_bfd_transport(F) \
  F (UDP4, "ip4-rewrite") \
  F (UDP6, "ip6-rewrite")

typedef enum
{
#define F(t, n) BFD_TRANSPORT_##t,
  foreach_bfd_transport (F)
#undef F
} bfd_transport_t;

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
  /* index in bfd_main.sessions pool */
  u32 bs_idx;

  /* session state */
  bfd_state_e local_state;

  /* local diagnostics */
  bfd_diag_code_e local_diag;

  /* remote session state */
  bfd_state_e remote_state;

  /* local discriminator */
  u32 local_discr;

  /* remote discriminator */
  u32 remote_discr;

  /* configured desired min tx interval (microseconds) */
  u32 config_desired_min_tx_us;

  /* desired min tx interval (microseconds) */
  u32 desired_min_tx_us;

  /* desired min tx interval (clocks) */
  u64 desired_min_tx_clocks;

  /* required min rx interval (microseconds) */
  u32 required_min_rx_us;

  /* required min echo rx interval (microseconds) */
  u32 required_min_echo_rx_us;

  /* remote min rx interval (microseconds) */
  u32 remote_min_rx_us;

  /* remote min rx interval (clocks) */
  u64 remote_min_rx_clocks;

  /* remote desired min tx interval (microseconds) */
  u32 remote_desired_min_tx_us;

  /* 1 if in demand mode, 0 otherwise */
  u8 local_demand;

  /* 1 if remote system sets demand mode, 0 otherwise */
  u8 remote_demand;

  /* local detect multiplier */
  u8 local_detect_mult;

  /* remote detect multiplier */
  u8 remote_detect_mult;

  /* set to value of timer in timing wheel, 0 if never set */
  u64 wheel_time_clocks;

  /* transmit interval */
  u64 transmit_interval_clocks;

  /* next time at which to transmit a packet */
  u64 tx_timeout_clocks;

  /* timestamp of last packet transmitted */
  u64 last_tx_clocks;

  /* timestamp of last packet received */
  u64 last_rx_clocks;

  /* detection time */
  u64 detection_time_clocks;

  /* transport type for this session */
  bfd_transport_t transport;

  union
  {
    bfd_udp_session_t udp;
  };
} bfd_session_t;

typedef struct
{
  u32 client_index;
  u32 client_pid;
} event_subscriber_t;

typedef struct
{
  /* pool of bfd sessions context data */
  bfd_session_t *sessions;

  /* timing wheel for scheduling timeouts */
  timing_wheel_t wheel;

  /* timing wheel inaccuracy, in clocks */
  u64 wheel_inaccuracy;

  /* hashmap - bfd session by discriminator */
  u32 *session_by_disc;

  /* background process node index */
  u32 bfd_process_node_index;

  /* convenience variables */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;

  /* cpu clocks per second */
  f64 cpu_cps;

  /* for generating random numbers */
  u32 random_seed;

} bfd_main_t;

extern bfd_main_t bfd_main;

/* Packet counters */
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

/* bfd packet trace capture */
typedef struct
{
  u32 len;
  u8 data[400];
} bfd_input_trace_t;

enum
{
  BFD_EVENT_RESCHEDULE = 1,
  BFD_EVENT_NEW_SESSION,
} bfd_process_event_e;

u8 *bfd_input_format_trace (u8 * s, va_list * args);

bfd_session_t *bfd_get_session (bfd_main_t * bm, bfd_transport_t t);
void bfd_put_session (bfd_main_t * bm, bfd_session_t * bs);
bfd_session_t *bfd_find_session_by_idx (bfd_main_t * bm, uword bs_idx);
bfd_session_t *bfd_find_session_by_disc (bfd_main_t * bm, u32 disc);
void bfd_session_start (bfd_main_t * bm, bfd_session_t * bs);
void bfd_consume_pkt (bfd_main_t * bm, const bfd_pkt_t * bfd, u32 bs_idx);
int bfd_verify_pkt_common (const bfd_pkt_t * pkt);
int bfd_verify_pkt_session (const bfd_pkt_t * pkt, u16 pkt_size,
			    const bfd_session_t * bs);
void bfd_event (bfd_main_t * bm, bfd_session_t * bs);
void bfd_send_final (vlib_main_t * vm, vlib_buffer_t * b, bfd_session_t * bs);
u8 *format_bfd_session (u8 * s, va_list * args);


#define USEC_PER_MS 1000LL
#define USEC_PER_SECOND (1000 * USEC_PER_MS)

/* default, slow transmission interval for BFD packets, per spec at least 1s */
#define BFD_DEFAULT_DESIRED_MIN_TX_US USEC_PER_SECOND

#endif /* __included_bfd_main_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
