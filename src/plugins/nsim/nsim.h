
/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) <current-year> <your-organization>
 */

/* nsim.h - skeleton vpp engine plug-in header file */

#ifndef __included_nsim_h__
#define __included_nsim_h__

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>

#include <vppinfra/hash.h>
#include <vppinfra/error.h>

#define NSIM_MAX_TX_BURST 32	/**< max packets in a tx burst */

typedef struct
{
  f64 tx_time;
  u32 rx_sw_if_index;
  u32 tx_sw_if_index;
  u32 output_next_index;
  u32 buffer_index;
  u32 pad;			/* pad to 32-bytes */
} nsim_wheel_entry_t;

typedef struct
{
  u32 wheel_size;
  u32 cursize;
  u32 head;
  u32 tail;
  /* Departure time of the most recently enqueued packet. Used by the queued
   * (bufferbloat) model to serialize packets at the bottleneck rate. */
  f64 last_tx_time;
  nsim_wheel_entry_t *entries;
    CLIB_CACHE_LINE_ALIGN_MARK (pad);
} nsim_wheel_t;

typedef struct nsim_node_ctx
{
  vnet_feature_config_main_t *fcm;
  f64 expires;
  f64 now;
  u32 *drop;
  u8 *action;
  u32 n_buffered;
  u32 n_loss;
  u32 n_reordered;
} nsim_node_ctx_t;

#define foreach_nsm_action			\
  _(DROP, "Packet loss")			\
  _(REORDER, "Packet reorder")

enum nsm_action_bit
{
#define _(sym, str) NSIM_ACTION_##sym##_BIT,
  foreach_nsm_action
#undef _
};

typedef enum nsm_action
{
#define _(sym, str) NSIM_ACTION_##sym = 1 << NSIM_ACTION_##sym##_BIT,
  foreach_nsm_action
#undef _
} nsm_action_e;

/* Loss models. Included after NSIM_ACTION_* so the datapath-inline appliers can
 * set the DROP action bit. */
#include <nsim/nsim_loss.h>
/* Time-varying bottleneck-rate models (only used by the queued model). */
#include <nsim/nsim_rate.h>

typedef struct
{
  /* API message ID base */
  u16 msg_id_base;

  /* output feature arc index */
  u16 arc_index;

  /* Two interfaces, cross-connected with delay */
  u32 sw_if_index0, sw_if_index1;
  u32 output_next_index0, output_next_index1;

  /* N interfaces, using the output feature */
  u32 *output_next_index_by_sw_if_index;

  /* Random seed for loss-rate simulation */
  u32 seed;

  /* Per-thread scheduler wheels */
  nsim_wheel_t **wheel_by_thread;
  /* Per-thread side wheels for late-reordered packets if reorder_fraction > 0 */
  nsim_wheel_t **reorder_wheel_by_thread;

  /* Config parameters */
  f64 delay;
  f64 bandwidth;
  /* Active packet-loss model (uniform/burst/one-shot/targeted). See
   * nsim_loss.h. A single model is active at a time. */
  nsim_loss_model_t loss;
  /* Reorder is an impairment orthogonal to the loss model; it composes with any
   * of them. Fraction of packets delayed out of order. */
  f64 reorder_fraction;
  /* Max extra delay (seconds) applied to a reordered packet, on top of the base delay */
  f64 reorder_delay;
  /* Bottleneck buffer, in seconds of bandwidth. When non-zero, nsim models a
   * rate-limited server with a FIFO buffer of this depth (queued/bufferbloat
   * model) instead of the default fixed-delay line. */
  f64 buffer_time;
  /* Per-packet serialization time at the bottleneck (packet_size/bandwidth),
   * cached for the datapath. Only used when buffer_time > 0. */
  f64 serialization_time;
  /* Optional time-varying bottleneck rate (queued model only). When active it
   * modulates serialization_time per departure; type NONE => constant rate. */
  nsim_rate_model_t rate;
  u32 packet_size;
  u32 wheel_slots_per_wrk;
  u32 poll_main_thread;

  u64 mmap_size;

  /* Wheels are configured */
  int is_configured;

  /* convenience */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;
} nsim_main_t;

extern nsim_main_t nsim_main;

extern vlib_node_registration_t nsim_node;
extern vlib_node_registration_t nsim_input_node;

#endif /* __included_nsim_h__ */
