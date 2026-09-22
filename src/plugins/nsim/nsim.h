
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
#include <nsim/nsim_model.h>

#define NSIM_MAX_TX_BURST 32	/**< max packets in a tx burst */

typedef struct
{
  f64 tx_time;
  u32 rx_sw_if_index;
  u32 tx_sw_if_index;
  u32 output_next_index;
  u32 buffer_index;
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

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  nsim_wheel_t *wheel;
  nsim_wheel_t *reorder_wheel;

  /* Serialization completions for packets admitted to the bottleneck queue.
   * This queue releases buffer capacity at service completion, independently
   * of propagation, batching and reorder holding time. */
  f64 *service_departures;
  u32 service_head;
  u32 service_tail;
  u32 service_cursize;
  u32 storage_cursize;
  u32 max_service_cursize;
  u32 max_storage_cursize;
  f64 max_service_backlog;

  /* Loss and link-model state is private to the worker. Independent random
   * streams ensure that enabling one impairment cannot perturb another. */
  nsim_loss_model_t loss;
  nsim_model_state_t model;
  u32 loss_seed;
  u32 reorder_seed;
  u32 reorder_delay_seed;
  u64 packets;
  u64 drops;
  u64 queue_drops;
  u64 reordered;
  u64 transmitted;
} nsim_worker_t;

STATIC_ASSERT (sizeof (nsim_worker_t) % CLIB_CACHE_LINE_BYTES == 0,
	       "nsim worker state must not share cache lines");

typedef struct
{
  /* API message ID base */
  u16 msg_id_base;

  /* Two interfaces, cross-connected with delay */
  u32 sw_if_index0, sw_if_index1;
  u32 output_next_index0, output_next_index1;

  /* N interfaces, using the output feature */
  u32 *output_next_index_by_sw_if_index;

  /* Base seed used to derive independent per-worker model streams. */
  u32 seed;

  /* Per-thread scheduler and mutable model state. A configured bandwidth and
   * buffer apply independently to each worker; aggregate shared-link shaping
   * is not modeled. */
  nsim_worker_t *workers;

  /* Config parameters */
  f64 delay;
  f64 bandwidth;
  /* Loss model template copied into each worker on configuration. */
  nsim_loss_model_t loss_config;
  /* Reorder is an impairment orthogonal to the loss model; it composes with any
   * of them. Fraction of packets delayed out of order. */
  f64 reorder_fraction;
  /* Max extra delay (seconds) applied to a reordered packet, on top of the base delay */
  f64 reorder_delay;
  /* Immutable queued-link model shared by all workers. */
  nsim_model_config_t model;
  u32 packet_size;
  u32 queue_slots_per_wrk;
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

unformat_function_t unformat_nsim_delay;
unformat_function_t unformat_nsim_bandwidth;

extern vlib_node_registration_t nsim_node;
extern vlib_node_registration_t nsim_input_node;

#endif /* __included_nsim_h__ */
