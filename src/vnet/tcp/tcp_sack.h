/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2020 Cisco and/or its affiliates.
 */

#ifndef SRC_VNET_TCP_TCP_SACK_H_
#define SRC_VNET_TCP_TCP_SACK_H_

#include <vnet/tcp/tcp_types.h>

always_inline u32
scoreboard_hole_index (sack_scoreboard_t * sb, sack_scoreboard_hole_t * hole)
{
  ASSERT (!pool_is_free_index (sb->holes, hole - sb->holes));
  return hole - sb->holes;
}

always_inline u32
scoreboard_hole_bytes (sack_scoreboard_hole_t * hole)
{
  return hole->end - hole->start;
}

always_inline sack_scoreboard_hole_t *
scoreboard_get_hole (sack_scoreboard_t * sb, u32 index)
{
  if (index != TCP_INVALID_SACK_HOLE_INDEX)
    return pool_elt_at_index (sb->holes, index);
  return 0;
}

always_inline sack_scoreboard_hole_t *
scoreboard_next_hole (sack_scoreboard_t * sb, sack_scoreboard_hole_t * hole)
{
  if (hole->next != TCP_INVALID_SACK_HOLE_INDEX)
    return pool_elt_at_index (sb->holes, hole->next);
  return 0;
}

always_inline sack_scoreboard_hole_t *
scoreboard_prev_hole (sack_scoreboard_t * sb, sack_scoreboard_hole_t * hole)
{
  if (hole->prev != TCP_INVALID_SACK_HOLE_INDEX)
    return pool_elt_at_index (sb->holes, hole->prev);
  return 0;
}

always_inline sack_scoreboard_hole_t *
scoreboard_first_hole (sack_scoreboard_t * sb)
{
  if (sb->head != TCP_INVALID_SACK_HOLE_INDEX)
    return pool_elt_at_index (sb->holes, sb->head);
  return 0;
}

always_inline sack_scoreboard_hole_t *
scoreboard_last_hole (sack_scoreboard_t * sb)
{
  if (sb->tail != TCP_INVALID_SACK_HOLE_INDEX)
    return pool_elt_at_index (sb->holes, sb->tail);
  return 0;
}

#if TCP_SCOREBOARD_TRACE
#define tcp_scoreboard_trace_add(_tc, _ack)                                                        \
  {                                                                                                \
    static u64 _group = 0;                                                                         \
    sack_scoreboard_t *_sb = &_tc->sack_sb;                                                        \
    sack_block_t *_sack, *_sacks;                                                                  \
    scoreboard_trace_elt_t *_elt;                                                                  \
    int i;                                                                                         \
    _group++;                                                                                      \
    _sacks = _tc->rcv_opts.sacks;                                                                  \
    if (seq_gt (_ack, _tc->snd_una))                                                               \
      {                                                                                            \
	vec_add2 (_sb->trace, _elt, 1);                                                            \
	_elt->start = _tc->snd_una;                                                                \
	_elt->end = _ack;                                                                          \
	_elt->ack = _ack;                                                                          \
	_elt->snd_nxt = _tc->snd_nxt;                                                              \
	_elt->group = _group;                                                                      \
      }                                                                                            \
    for (i = 0; i < vec_len (_sacks); i++)                                                         \
      {                                                                                            \
	_sack = &_sacks[i];                                                                        \
	vec_add2 (_sb->trace, _elt, 1);                                                            \
	_elt->start = _sack->start;                                                                \
	_elt->end = _sack->end;                                                                    \
	_elt->ack = 0;                                                                             \
	_elt->snd_nxt = 0;                                                                         \
	_elt->group = _group;                                                                      \
      }                                                                                            \
  }

#define tcp_sack_trace(_tc, _ack)                                                                  \
  do                                                                                               \
    {                                                                                              \
      if (!((_tc)->cfg_flags & TCP_CFG_F_BYTE_TRACKER))                                            \
	tcp_scoreboard_trace_add (_tc, _ack);                                                      \
    }                                                                                              \
  while (0)
#else
#define tcp_scoreboard_trace_add(_tc, _ack)
#define tcp_sack_trace(_tc, _ack)
#endif

__clib_export sack_scoreboard_hole_t *scoreboard_next_rxt_hole (sack_scoreboard_t *sb,
								sack_scoreboard_hole_t *start,
								u8 have_sent_1_smss, u8 *can_rescue,
								u8 *snd_limited);
__clib_export void scoreboard_clear (sack_scoreboard_t *sb);
__clib_export void scoreboard_init (sack_scoreboard_t *sb);

__clib_export format_function_t format_tcp_scoreboard;

/** Most out-of-order arrivals kept for dupacks. A burst sends at most
 * TRANSPORT_PACER_MAX_BURST_PKTS dupacks, so more are not worth memory */
#define TCP_SACK_HIST_MAX 64

/** Dupack burst, each dupack stands for the next arrival in the history */
typedef struct tcp_sack_burst_
{
  u32 next;					 /**< Arrivals reported, with this dupack */
  u32 n_recent;					 /**< Blocks in recent, ~0 if not built */
  sack_block_t recent[TCP_OPTS_MAX_SACK_BLOCKS]; /**< Most recent blocks of those */
} tcp_sack_burst_t;

/** Report [start, end), received again (RFC 2883), if reporting is enabled */
__clib_export void tcp_dsack_report (tcp_connection_t *tc, u32 start, u32 end);
/*
 * Sack blocks come from the history of out-of-order arrivals, so acks report
 * them as RFC 2018 asks: the block that holds the arrival an ack stands for
 * first, then the most recent other blocks
 */
/** Drop the blocks in-order data delivered. If fewer than fit in an ack are
 * left, add the lowest of o, the rx fifo's out-of-order data */
void tcp_sack_delivered (tcp_connection_t *tc, ooo_segments_t *o);
/** Fill blks with the most recent blocks */
__clib_export u32 tcp_make_sacks (tcp_connection_t *tc, sack_block_t *blks);
/** Start a dupack burst with the first arrival no dupack reported */
__clib_export void tcp_sack_burst_init (tcp_connection_t *tc, tcp_sack_burst_t *b);
/** Keep the arrivals the burst did not report, and the most recent blocks,
 * which later acks repeat */
__clib_export void tcp_sack_burst_save (tcp_connection_t *tc, tcp_sack_burst_t *b);
/** Fill blks for a dupack of a burst: the oldest pending dsack, if any, and
 * the block that contains it, then the block of the next arrival and the
 * most recent ones before it. Dupacks after the last arrival repeat its
 * blocks. Each dsack is reported once, so call once the ack has a buffer.
 * b is not used if there is no out-of-order data. */
__clib_export u32 tcp_make_dupack_sacks (tcp_connection_t *tc, tcp_sack_burst_t *b,
					 sack_block_t *blks);
__clib_export void tcp_dsack_recovery_clear (tcp_connection_t *tc);
__clib_export void tcp_dsack_recovery_init (tcp_connection_t *tc);
__clib_export void tcp_track_rxt (tcp_connection_t *tc, u32 start, u32 end);
__clib_export void tcp_rcv_dsack (tcp_connection_t *tc, u32 ack, tcp_ack_ctx_t *ac);
__clib_export void tcp_ack_handle_full_feedback (tcp_connection_t *tc, u32 packet_ack, u32 ack,
						 tcp_ack_ctx_t *ac);

static_always_inline void
tcp_ack_handle_feedback (tcp_connection_t *tc, u32 packet_ack, tcp_ack_ctx_t *ac)
{
  sack_scoreboard_t *sb = &tc->sack_sb;
  u32 ack = seq_max (packet_ack, tc->snd_una);
  u8 has_ack_state, has_byte_tracker, needs_full_feedback;

  ac->bytes_acked = ack - tc->snd_una;
  has_ack_state = (sb->sacked_bytes != 0) | (sb->head != TCP_INVALID_SACK_HOLE_INDEX);
  has_byte_tracker = (tc->cfg_flags & TCP_CFG_F_BYTE_TRACKER) != 0;
  needs_full_feedback = (tcp_opts_sack (&tc->rcv_opts) != 0) |
			((ac->bytes_acked != 0) & (has_byte_tracker | has_ack_state));

  if (PREDICT_FALSE (needs_full_feedback))
    {
      tcp_ack_handle_full_feedback (tc, packet_ack, ack, ac);
      return;
    }

  ac->acked_and_sacked = ac->bytes_acked;
}

static inline u8
tcp_dsack_report_enabled (tcp_connection_t *tc)
{
  return tcp_opts_sack_permitted (&tc->rcv_opts) && !(tc->sack_sb.flags & TCP_DSACK_UNDO_DISABLED);
}

/** Pending dsacks */
static inline u8
tcp_dsack_is_pending (tcp_connection_t *tc)
{
  return vec_len (tc->snd_dsacks) != 0;
}

/** Rx fifo has out-of-order data to report */
static inline u8
tcp_sack_has_blocks (tcp_connection_t *tc)
{
  return tc->snd_sack_newest.start != tc->snd_sack_newest.end;
}

static inline void
tcp_sack_clear_blocks (tcp_connection_t *tc)
{
  tc->snd_sack_newest.end = tc->snd_sack_newest.start;
  vec_free (tc->snd_sack_hist);
  tc->snd_sack_pending = 0;
}

/** a holds all of b */
static inline u8
tcp_sack_block_contains (sack_block_t a, sack_block_t b)
{
  return seq_leq (a.start, b.start) && seq_leq (b.end, a.end);
}

/*
 * The history of arrivals is snd_sack_hist, oldest first, then the newest
 * block. The last snd_sack_pending were not reported yet
 */

/** Arrivals in the history */
static inline u32
tcp_sack_hist_len (tcp_connection_t *tc)
{
  return vec_len (tc->snd_sack_hist) + tcp_sack_has_blocks (tc);
}

/** Arrival i of the history */
static inline sack_block_t
tcp_sack_hist_at (tcp_connection_t *tc, u32 i)
{
  return i < vec_len (tc->snd_sack_hist) ? tc->snd_sack_hist[i] : tc->snd_sack_newest;
}

/** Arrivals no dupack reported yet */
static inline u32
tcp_sack_n_pending (tcp_connection_t *tc)
{
  return tc->snd_sack_pending;
}

void tcp_sack_add_older (tcp_connection_t *tc);

/** Record blk, the block that now holds an out-of-order arrival. Blocks only
 * grow, so one that holds the newest block is the arrival that grew it */
static inline void
tcp_sack_add (tcp_connection_t *tc, sack_block_t blk)
{
  if (PREDICT_FALSE (tcp_sack_has_blocks (tc) &&
		     !tcp_sack_block_contains (blk, tc->snd_sack_newest)))
    tcp_sack_add_older (tc);
  /* The newest is reported again, for this arrival */
  else if (!tc->snd_sack_pending)
    tc->snd_sack_pending = 1;
  tc->snd_sack_newest = blk;
}

__clib_export void tcp_sack_init_rxt (tcp_connection_t *tc, u32 snd_una);
/** Bytes from snd_una to the first sacked byte, at most max_bytes. Reneged
 * sacks at the head do not limit it. */
__clib_export u32 tcp_sack_rxt_head_bytes (tcp_connection_t *tc, u32 max_bytes);
__clib_export void tcp_sack_recompute_loss (tcp_connection_t *tc);
__clib_export void tcp_sack_rxt_mark_lost (tcp_connection_t *tc);
__clib_export u8 tcp_sack_handle_reneging (tcp_connection_t *tc);
u8 tcp_sack_is_sane_post_recovery (tcp_connection_t *tc);
__clib_export u8 *tcp_scoreboard_replay (u8 *s, tcp_connection_t *tc, u8 verbose);

#endif /* SRC_VNET_TCP_TCP_SACK_H_ */
