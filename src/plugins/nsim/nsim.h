
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
  u32 *reord;
  u16 *reord_nexts;
  u32 *fwd;
  u16 *fwd_nexts;
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

  /* Config parameters */
  f64 delay;
  f64 bandwidth;
  f64 drop_fraction;
  f64 reorder_fraction;
  /* Bursty (correlated) loss model. When burst_prob > 0, loss arrives in
   * TIME-BOUNDED bursts: with probability burst_prob per packet a burst starts
   * that drops every packet for the next burst_dur seconds, then clears. Making
   * the burst duration-based (not packet-count-based) is deliberate: a real
   * buffer-overflow burst clears in well under an RTT, so a retransmit sent ~1
   * RTT later survives (matching real captures where a segment is retransmitted
   * only a few times) -- a packet-count burst on a flow that has collapsed to a
   * few segs/RTT would instead span many RTTs and re-drop the retransmit and
   * its retries, manufacturing a false RTO-backoff cascade. burst_until is the
   * wall-clock time the current burst ends (0 => not bursting). burst_prob == 0
   * => model disabled, uniform drop_fraction used instead. */
  f64 burst_prob;
  f64 burst_dur;
  f64 burst_until;
  /* One-shot loss event. drop_once_at seconds after the first datapath packet,
   * drop everything for a drop_once_dur-second window (once), then disable.
   * Models a single slow-start-overshoot buffer overflow (real captures: one
   * big burst loss, then a long clean reconvergence) without the chronic
   * per-RTT tail-drop a static buffer produces once the flow parks above it.
   * drop_once_dur == 0 => disabled. drop_once_start is stamped on the first
   * datapath packet so the trigger is relative to traffic, not config time. */
  f64 drop_once_at;
  f64 drop_once_dur;
  u8 drop_once_done;
  f64 drop_once_start;
  u32 drop_once_count;
  /* Bottleneck buffer, in seconds of bandwidth. When non-zero, nsim models a
   * rate-limited server with a FIFO buffer of this depth (queued/bufferbloat
   * model) instead of the default fixed-delay line. */
  f64 buffer_time;
  /* Per-packet serialization time at the bottleneck (packet_size/bandwidth),
   * cached for the datapath. Only used when buffer_time > 0. */
  f64 serialization_time;
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
