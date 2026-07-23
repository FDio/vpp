/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco and/or its affiliates.
 */

#ifndef __included_nsim_loss_h__
#define __included_nsim_loss_h__

/*
 * nsim packet-loss models.
 *
 * A single loss model is active at a time, selected by nsim_loss_type_t. Models
 * fall in two families:
 *  - statistical: content-blind, decide via RNG / wall-clock (uniform, burst,
 *    one-shot). No packet inspection.
 *  - stateful: content-aware, track flow/sequence state to drop a specific
 *    segment and its retransmits (targeted). Requires TCP inspection.
 *
 * The datapath appliers here are header-inline so they specialize into each
 * CPU-march variant of the nsim node; control-plane construction/reset/format
 * live in nsim_loss.c.
 */

#include <vppinfra/clib.h>
#include <vppinfra/random.h>
#include <vlib/buffer.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/tcp/tcp_packet.h>

typedef enum nsim_loss_type_
{
  NSIM_LOSS_NONE = 0,
  NSIM_LOSS_UNIFORM,	/**< statistical: independent per-packet drop prob */
  NSIM_LOSS_BURST,	/**< statistical: time-correlated burst loss */
  NSIM_LOSS_ONCE,	/**< statistical: single timed drop window */
  NSIM_LOSS_TARGET_SEQ, /**< stateful: a segment + its retransmits */
  NSIM_LOSS_N_TYPES,
} nsim_loss_type_t;

/* Minimum TCP payload for the targeted classifier to treat a flow as the bulk
 * transfer (bytes). Above any realistic app control message, below a full MSS. */
#define NSIM_LOSS_MIN_SEG 512

typedef struct nsim_loss_model_
{
  nsim_loss_type_t type;
  /* Derived at config time from type; kept here so the datapath and the
   * inspection gate don't re-switch on type. */
  u8 stateful;	    /**< keeps cross-packet state */
  u8 needs_inspect; /**< parses packet headers (sets nsim inspect gate) */

  union
  {
    /* Statistical: independent per-packet drop. */
    struct
    {
      f64 fraction;
    } uniform;

    /* Statistical: with prob per packet, enter a bad state that drops every
     * packet for duration seconds (wall-clock), then clears. `until` is live
     * state: the time the current burst ends (0 => not bursting). Duration-based
     * (not packet-count) so a retransmit sent ~1 RTT later survives. */
    struct
    {
      f64 prob;
      f64 duration;
      f64 until;
    } burst;

    /* Statistical: `at` seconds after the first datapath packet, drop
     * everything for `duration` seconds (once), then disable. `start` is stamped
     * on the first packet; `done` latches; `count` tallies dropped packets. */
    struct
    {
      f64 at;
      f64 duration;
      f64 start;
      u8 done;
      u32 count;
    } once;

    /* Stateful: drop the data segment covering byte `offset` into the first
     * full-size (>= NSIM_LOSS_MIN_SEG) flow seen, plus its next `rxt`
     * retransmits, then disable. `isn`/`target` are learned once; `remaining`
     * counts retransmit drops left; `armed` is set until the original drops. */
    struct
    {
      u32 offset;
      u32 rxt;
      u32 isn;
      u32 target;
      u32 remaining;
      u8 armed;
    } target_seq;
  };
} nsim_loss_model_t;

/* Parse an IPv4/TCP data segment on the output path. Returns 1 and fills seq
 * (host order) and seg_len (TCP payload bytes) for a TCP packet carrying data;
 * returns 0 for non-IPv4, non-TCP, or pure-ACK/control segments. Buffer is at
 * the ethernet header on the interface-output arc. */
static_always_inline int
nsim_loss_parse_tcp_data (vlib_buffer_t *b, u32 *seq, u32 *seg_len)
{
  ethernet_header_t *eth = vlib_buffer_get_current (b);
  ip4_header_t *ip;
  tcp_header_t *tcp;
  u16 ip_len, tcp_hlen;

  if (eth->type != clib_host_to_net_u16 (ETHERNET_TYPE_IP4))
    return 0;
  ip = (ip4_header_t *) (eth + 1);
  if (ip->protocol != IP_PROTOCOL_TCP)
    return 0;

  ip_len = clib_net_to_host_u16 (ip->length);
  tcp = (tcp_header_t *) ip4_next_header (ip);
  tcp_hlen = tcp_header_bytes (tcp);
  *seq = clib_net_to_host_u32 (tcp->seq_number);
  *seg_len = ip_len - ip4_header_bytes (ip) - tcp_hlen;
  return *seg_len > 0;
}

/* Targeted-segment match: 1 if this packet is the target segment or one of its
 * to-be-dropped retransmits. Advances model state. */
static_always_inline int
nsim_loss_target_seq_match (nsim_loss_model_t *m, vlib_buffer_t *b)
{
  u32 seq, seg_len, end;

  if (!nsim_loss_parse_tcp_data (b, &seq, &seg_len))
    return 0;

  /* Lock onto the bulk flow on the first full-size segment, skipping small
   * control/handshake payloads (e.g. an app control connection). */
  if (m->target_seq.isn == 0)
    {
      if (seg_len < NSIM_LOSS_MIN_SEG)
	return 0;
      m->target_seq.isn = seq;
      m->target_seq.target = seq + m->target_seq.offset;
    }

  end = seq + seg_len;
  /* Does this segment cover the target byte? (seq-wrap safe) */
  if (!(seq_leq (seq, m->target_seq.target) && seq_lt (m->target_seq.target, end)))
    return 0;

  if (m->target_seq.armed)
    {
      m->target_seq.armed = 0; /* original transmission */
      return 1;
    }
  if (m->target_seq.remaining)
    {
      m->target_seq.remaining--; /* a retransmit of the dropped target */
      return 1;
    }
  return 0;
}

/* Apply the active loss model to a frame's worth of packets, setting the DROP
 * action bit. `seed` is the nsim RNG state, `now` the frame timestamp. */
static_always_inline void
nsim_loss_apply (nsim_loss_model_t *m, u32 *seed, f64 now, vlib_buffer_t **b, u8 *action, u32 n)
{
  u32 i;

  switch (m->type)
    {
    case NSIM_LOSS_UNIFORM:
      for (i = 0; i < n; i++)
	if (random_f64 (seed) <= m->uniform.fraction)
	  action[i] |= NSIM_ACTION_DROP;
      break;

    case NSIM_LOSS_BURST:
      for (i = 0; i < n; i++)
	{
	  if (now < m->burst.until)
	    action[i] |= NSIM_ACTION_DROP;
	  else if (random_f64 (seed) <= m->burst.prob)
	    {
	      m->burst.until = now + m->burst.duration;
	      action[i] |= NSIM_ACTION_DROP;
	    }
	}
      break;

    case NSIM_LOSS_ONCE:
      if (!m->once.done)
	{
	  f64 elapsed;
	  if (m->once.start == 0.0)
	    m->once.start = now;
	  elapsed = now - m->once.start;
	  if (elapsed >= m->once.at && elapsed < m->once.at + m->once.duration)
	    for (i = 0; i < n; i++)
	      {
		action[i] |= NSIM_ACTION_DROP;
		m->once.count++;
	      }
	  else if (elapsed >= m->once.at + m->once.duration)
	    m->once.done = 1;
	}
      break;

    case NSIM_LOSS_TARGET_SEQ:
      for (i = 0; i < n; i++)
	if (nsim_loss_target_seq_match (m, b[i]))
	  action[i] |= NSIM_ACTION_DROP;
      break;

    default:
      break;
    }
}

format_function_t format_nsim_loss_model;
void nsim_loss_model_uniform (nsim_loss_model_t *m, f64 fraction);
void nsim_loss_model_burst (nsim_loss_model_t *m, f64 prob, f64 duration);
void nsim_loss_model_once (nsim_loss_model_t *m, f64 at, f64 duration);
void nsim_loss_model_target_seq (nsim_loss_model_t *m, u32 offset, u32 rxt);
void nsim_loss_model_reset (nsim_loss_model_t *m);

#endif /* __included_nsim_loss_h__ */
