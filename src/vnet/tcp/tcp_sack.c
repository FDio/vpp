/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2020 Cisco and/or its affiliates.
 */

#include <vnet/tcp/tcp_sack.h>

static void
scoreboard_remove_hole (sack_scoreboard_t * sb, sack_scoreboard_hole_t * hole)
{
  sack_scoreboard_hole_t *next, *prev;

  if (hole->next != TCP_INVALID_SACK_HOLE_INDEX)
    {
      next = pool_elt_at_index (sb->holes, hole->next);
      next->prev = hole->prev;
    }
  else
    {
      sb->tail = hole->prev;
    }

  if (hole->prev != TCP_INVALID_SACK_HOLE_INDEX)
    {
      prev = pool_elt_at_index (sb->holes, hole->prev);
      prev->next = hole->next;
    }
  else
    {
      sb->head = hole->next;
    }

  if (scoreboard_hole_index (sb, hole) == sb->cur_rxt_hole)
    sb->cur_rxt_hole = TCP_INVALID_SACK_HOLE_INDEX;

  /* Poison the entry */
  if (CLIB_DEBUG > 0)
    clib_memset (hole, 0xfe, sizeof (*hole));

  pool_put (sb->holes, hole);
}

static sack_scoreboard_hole_t *
scoreboard_insert_hole (sack_scoreboard_t * sb, u32 prev_index,
			u32 start, u32 end)
{
  sack_scoreboard_hole_t *hole, *next, *prev;
  u32 hole_index;

  pool_get (sb->holes, hole);
  clib_memset (hole, 0, sizeof (*hole));

  hole->start = start;
  hole->end = end;
  hole_index = scoreboard_hole_index (sb, hole);

  prev = scoreboard_get_hole (sb, prev_index);
  if (prev)
    {
      hole->prev = prev_index;
      hole->next = prev->next;

      if ((next = scoreboard_next_hole (sb, hole)))
	next->prev = hole_index;
      else
	sb->tail = hole_index;

      prev->next = hole_index;
    }
  else
    {
      sb->head = hole_index;
      hole->prev = TCP_INVALID_SACK_HOLE_INDEX;
      hole->next = TCP_INVALID_SACK_HOLE_INDEX;
    }

  return hole;
}

typedef enum
{
  TCP_SB_SACK_OOO,
  TCP_SB_SACK_RXT,
  TCP_SB_SACK_RXT_RESCUED,
} tcp_sb_sack_mode_e;

always_inline void
scoreboard_update_sacked (sack_scoreboard_t *sb, u32 start, u32 end, tcp_sb_sack_mode_e mode,
			  u16 snd_mss)
{
  /* A newly sacked segment below the sack frontier arrived out of order. Use it to grow the reorder
   * estimate when its late arrival is unambiguous reordering. Segments below high_rxt (or after
   * rescue has fired) are excluded because they're ambiguous */
  if (seq_lt (start, sb->high_sacked) &&
      (mode == TCP_SB_SACK_OOO || (mode == TCP_SB_SACK_RXT && seq_geq (start, sb->high_rxt))))
    {
      u32 reord = (sb->high_sacked - start + snd_mss - 1) / snd_mss;
      reord = clib_min (reord, TCP_MAX_SACK_REORDER);
      sb->reorder = clib_max (sb->reorder, reord);
    }

  if (mode == TCP_SB_SACK_OOO)
    return;

  if (seq_geq (start, sb->high_rxt))
    return;

  sb->rxt_sacked +=
    seq_lt (end, sb->high_rxt) ? (end - start) : (sb->high_rxt - start);
}

always_inline u32
scoreboard_update_loss (sack_scoreboard_t *sb, u32 ack, u32 snd_mss, u8 clear_lost)
{
  sack_scoreboard_hole_t *hole, *left, *right;
  u32 sacked = 0, blks = 0;

  if (clear_lost)
    {
      hole = scoreboard_first_hole (sb);
      while (hole)
	{
	  hole->is_lost = 0;
	  hole = scoreboard_next_hole (sb, hole);
	}
    }

  sb->last_lost_bytes = 0;
  sb->lost_bytes = 0;

  right = scoreboard_last_hole (sb);
  if (!right)
    return seq_gt (sb->high_sacked, ack) ? sb->high_sacked - ack : 0;

  if (seq_gt (sb->high_sacked, right->end))
    {
      sacked = sb->high_sacked - right->end;
      blks = 1;
    }

  /* As per RFC 6675 a sequence number is lost if:
   *   DupThresh discontiguous SACKed sequences have arrived above
   *   'SeqNum' or more than (DupThresh - 1) * SMSS bytes with sequence
   *   numbers greater than 'SeqNum' have been SACKed.
   * To avoid spurious retransmits, use reordering estimate instead of
   * DupThresh to detect loss.
   */
  while (sacked <= (sb->reorder - 1) * snd_mss && blks < sb->reorder)
    {
      if (right->is_lost)
	sb->lost_bytes += scoreboard_hole_bytes (right);

      left = scoreboard_prev_hole (sb, right);
      if (!left)
	{
	  ASSERT (right->start == ack || sb->is_reneging);
	  sacked += right->start - ack;
	  right = 0;
	  break;
	}

      sacked += right->start - left->end;
      blks++;
      right = left;
    }

  /* right is first lost */
  while (right)
    {
      sb->lost_bytes += scoreboard_hole_bytes (right);
      sb->last_lost_bytes += right->is_lost ? 0 : (right->end - right->start);
      right->is_lost = 1;
      left = scoreboard_prev_hole (sb, right);
      if (!left)
	{
	  ASSERT (right->start == ack || sb->is_reneging);
	  sacked += right->start - ack;
	  break;
	}
      sacked += right->start - left->end;
      right = left;
    }

  return sacked;
}

always_inline void
scoreboard_update_bytes (sack_scoreboard_t *sb, u32 ack, u32 snd_mss)
{
  u32 old_sacked = sb->sacked_bytes;

  sb->sacked_bytes = scoreboard_update_loss (sb, ack, snd_mss, 0);
  sb->last_sacked_bytes = sb->sacked_bytes - (old_sacked - sb->last_bytes_delivered);
}

void
scoreboard_recompute_sack_loss (sack_scoreboard_t *sb, u32 ack, u32 snd_mss)
{
  u32 last_lost_bytes = sb->last_lost_bytes;
  u32 sacked;

  /* Discard loss classification inherited from an rto and infer it again
   * solely from the SACK scoreboard. Keep per-ack accounting unchanged. */
  sacked = scoreboard_update_loss (sb, ack, snd_mss, 1);
  ASSERT (sacked == sb->sacked_bytes);
  sb->last_lost_bytes = last_lost_bytes;
}

/**
 * Figure out the next hole to retransmit
 *
 * Follows logic proposed in RFC6675 Sec. 4, NextSeg()
 */
sack_scoreboard_hole_t *
scoreboard_next_rxt_hole (sack_scoreboard_t * sb,
			  sack_scoreboard_hole_t * start,
			  u8 have_unsent, u8 * can_rescue, u8 * snd_limited)
{
  sack_scoreboard_hole_t *hole = 0;

  hole = start ? start : scoreboard_first_hole (sb);
  while (hole && seq_leq (hole->end, sb->high_rxt) && hole->is_lost)
    hole = scoreboard_next_hole (sb, hole);

  /* Nothing, return */
  if (!hole)
    {
      sb->cur_rxt_hole = TCP_INVALID_SACK_HOLE_INDEX;
      return 0;
    }

  /* Rule (1): if higher than rxt, less than high_sacked and lost */
  if (hole->is_lost && seq_lt (hole->start, sb->high_sacked))
    {
      sb->cur_rxt_hole = scoreboard_hole_index (sb, hole);
    }
  else
    {
      /* Rule (2): available unsent data */
      if (have_unsent)
	{
	  sb->cur_rxt_hole = TCP_INVALID_SACK_HOLE_INDEX;
	  return 0;
	}
      /* Rule (3): if hole not lost */
      else if (seq_lt (hole->start, sb->high_sacked))
	{
	  /* And we didn't already retransmit it */
	  if (seq_leq (hole->end, sb->high_rxt))
	    {
	      sb->cur_rxt_hole = TCP_INVALID_SACK_HOLE_INDEX;
	      return 0;
	    }
	  *snd_limited = 0;
	  sb->cur_rxt_hole = scoreboard_hole_index (sb, hole);
	}
      /* Rule (4): if hole beyond high_sacked */
      else
	{
	  ASSERT (seq_geq (hole->start, sb->high_sacked));
	  *snd_limited = 1;
	  *can_rescue = 1;
	  /* HighRxt MUST NOT be updated */
	  return 0;
	}
    }

  if (hole && seq_lt (sb->high_rxt, hole->start))
    sb->high_rxt = hole->start;

  return hole;
}

void
scoreboard_init_rxt (sack_scoreboard_t * sb, u32 snd_una)
{
  sack_scoreboard_hole_t *hole;
  hole = scoreboard_first_hole (sb);
  if (hole)
    {
      snd_una = seq_gt (snd_una, hole->start) ? snd_una : hole->start;
      sb->cur_rxt_hole = sb->head;
    }
  sb->high_rxt = snd_una;
  sb->rescue_rxt = snd_una - 1;
}

void
scoreboard_rxt_mark_lost (sack_scoreboard_t *sb, u32 snd_una, u32 snd_nxt)
{
  sack_scoreboard_hole_t *hole;

  hole = scoreboard_first_hole (sb);
  if (!hole)
    {
      hole = scoreboard_insert_hole (sb, TCP_INVALID_SACK_HOLE_INDEX, snd_una,
				     snd_nxt);
      sb->tail = scoreboard_hole_index (sb, hole);
      sb->high_sacked = snd_una;
    }

  if (hole->is_lost)
    return;

  hole->is_lost = 1;
  sb->lost_bytes += scoreboard_hole_bytes (hole);
}

void
scoreboard_init (sack_scoreboard_t * sb)
{
  sb->head = TCP_INVALID_SACK_HOLE_INDEX;
  sb->tail = TCP_INVALID_SACK_HOLE_INDEX;
  sb->cur_rxt_hole = TCP_INVALID_SACK_HOLE_INDEX;
  sb->reorder = TCP_DUPACK_THRESHOLD;
}

void
scoreboard_clear (sack_scoreboard_t * sb)
{
  sack_scoreboard_hole_t *hole;
  while ((hole = scoreboard_first_hole (sb)))
    {
      scoreboard_remove_hole (sb, hole);
    }
  ASSERT (sb->head == sb->tail && sb->head == TCP_INVALID_SACK_HOLE_INDEX);
  ASSERT (pool_elts (sb->holes) == 0);
  sb->sacked_bytes = 0;
  sb->last_sacked_bytes = 0;
  sb->last_bytes_delivered = 0;
  sb->lost_bytes = 0;
  sb->last_lost_bytes = 0;
  sb->cur_rxt_hole = TCP_INVALID_SACK_HOLE_INDEX;
  sb->is_reneging = 0;
  /* reorder is a learned path property, not episode state, so it is NOT reset here */
}

void
scoreboard_clear_reneging (sack_scoreboard_t * sb, u32 start, u32 end)
{
  sack_scoreboard_hole_t *last_hole;

  scoreboard_clear (sb);
  /* Reneging retracts data the peer previously sacked: the reorder estimate
   * that led here is suspect, so fall back to the dupack floor (as on rto). */
  sb->reorder = TCP_DUPACK_THRESHOLD;
  last_hole = scoreboard_insert_hole (sb, TCP_INVALID_SACK_HOLE_INDEX,
				      start, end);
  last_hole->is_lost = 1;
  sb->tail = scoreboard_hole_index (sb, last_hole);
  sb->high_sacked = start;
  scoreboard_init_rxt (sb, start);
}

/**
 * Test that scoreboard is sane after recovery
 */
u8
tcp_scoreboard_is_sane_post_recovery (tcp_connection_t *tc)
{
  sack_scoreboard_hole_t *hole = scoreboard_first_hole (&tc->sack_sb);

  /* Empty scoreboard is always sane */
  if (!hole)
    return 1;

  /* Hole must be within the outstanding send range. Loss detected above the
   * recovery point is left behind as a fresh congestion event for the next
   * recovery, but it can never fall outside [snd_una, snd_nxt]. */
  if (seq_lt (hole->start, tc->snd_una) || seq_gt (hole->end, tc->snd_nxt))
    return 0;

  /* A hole may only reach snd_nxt if it is lost. A non-lost hole at snd_nxt
   * has nothing sacked above it, so recovery exit would have cleared it;
   * seeing one means is_lost/lost_bytes accounting drifted. */
  if (hole->end == tc->snd_nxt && !hole->is_lost)
    return 0;

  return 1;
}

void
tcp_dsack_recovery_start (tcp_connection_t *tc)
{
  vec_free (tc->dsack_rxt);
  tc->dsack_flags &= TCP_DSACK_UNDO_DISABLED;
  tc->dsack_recovery_ack = 0;
}

void
tcp_dsack_recovery_done (tcp_connection_t *tc)
{
  vec_free (tc->dsack_rxt);
  tc->dsack_flags &= TCP_DSACK_UNDO_DISABLED;
  tc->dsack_recovery_ack = 0;
}

void
tcp_dsack_recovery_save (tcp_connection_t *tc)
{
  if (tcp_dsack_has_history (tc))
    tc->dsack_recovery_ack = tc->snd_una;
}

/* Once an episode is ineligible for undo, retain only the union of its
 * retransmitted ranges so a later D-SACK is not mistaken for network
 * duplication. */
static void
tcp_dsack_track_range_union (tcp_connection_t *tc, u32 start, u32 end)
{
  tcp_dsack_rxt_t rxt = { .start = start, .end = end };
  u32 i = 0;

  while (i < vec_len (tc->dsack_rxt))
    {
      if (seq_lt (rxt.end, tc->dsack_rxt[i].start))
	break;
      if (seq_gt (rxt.start, tc->dsack_rxt[i].end))
	{
	  i++;
	  continue;
	}

      rxt.start = seq_lt (tc->dsack_rxt[i].start, rxt.start) ? tc->dsack_rxt[i].start : rxt.start;
      rxt.end = seq_max (rxt.end, tc->dsack_rxt[i].end);
      vec_delete (tc->dsack_rxt, 1, i);
    }

  vec_insert_elts (tc->dsack_rxt, &rxt, 1, i);
}

void
tcp_dsack_track_retransmit (tcp_connection_t *tc, u32 start, u32 end)
{
  tcp_dsack_rxt_t rxt = { .start = start, .end = end };
  u32 i;

  ASSERT (tcp_opts_sack_permitted (&tc->rcv_opts));
  ASSERT (tcp_in_cong_recovery (tc));
  ASSERT (seq_lt (start, end));

  if (tcp_dsack_undo_disabled (tc))
    return;

  if (tcp_dsack_ineligible (tc))
    {
      tcp_dsack_track_range_union (tc, start, end);
      return;
    }

  /* HighRxt keeps normal RFC 6675 retransmissions disjoint. An overlap means
   * at least one byte was retransmitted more than once (RFC 3708 A.3). */
  for (i = 0; i < vec_len (tc->dsack_rxt); i++)
    if (seq_lt (start, tc->dsack_rxt[i].end) && seq_gt (end, tc->dsack_rxt[i].start))
      {
	tcp_dsack_ineligible_on (tc);
	tcp_dsack_track_range_union (tc, start, end);
	return;
      }

  for (i = 0; i < vec_len (tc->dsack_rxt); i++)
    if (seq_lt (start, tc->dsack_rxt[i].start))
      {
	vec_insert_elts (tc->dsack_rxt, &rxt, 1, i);
	return;
      }

  vec_add1 (tc->dsack_rxt, rxt);
}

/* Mark the intersection of [start,end) with retained retransmissions.
 * Splitting makes repeated and overlapping D-SACK reports idempotent.
 * Returns all bytes matched, including bytes marked by an earlier D-SACK. */
static u32
tcp_dsack_mark_duplicate (tcp_connection_t *tc, u32 start, u32 end)
{
  tcp_dsack_rxt_t cur, parts[2];
  u32 overlap_start, overlap_end, matched = 0, i = 0;

  while (i < vec_len (tc->dsack_rxt))
    {
      cur = tc->dsack_rxt[i];
      if (seq_leq (end, cur.start))
	break;
      if (seq_geq (start, cur.end))
	{
	  i++;
	  continue;
	}

      overlap_start = seq_gt (start, cur.start) ? start : cur.start;
      overlap_end = seq_lt (end, cur.end) ? end : cur.end;
      matched += overlap_end - overlap_start;

      if (overlap_start == cur.start && overlap_end == cur.end)
	{
	  tc->dsack_rxt[i].flags |= TCP_DSACK_RXT_DUPLICATE;
	  i++;
	}
      else if (overlap_start == cur.start)
	{
	  parts[0] = cur;
	  parts[0].start = overlap_end;
	  tc->dsack_rxt[i].end = overlap_end;
	  tc->dsack_rxt[i].flags |= TCP_DSACK_RXT_DUPLICATE;
	  vec_insert_elts (tc->dsack_rxt, parts, 1, i + 1);
	  i += 2;
	}
      else if (overlap_end == cur.end)
	{
	  parts[0] = cur;
	  parts[0].start = overlap_start;
	  parts[0].flags |= TCP_DSACK_RXT_DUPLICATE;
	  tc->dsack_rxt[i].end = overlap_start;
	  vec_insert_elts (tc->dsack_rxt, parts, 1, i + 1);
	  i += 2;
	}
      else
	{
	  parts[0] = cur;
	  parts[0].start = overlap_start;
	  parts[0].end = overlap_end;
	  parts[0].flags |= TCP_DSACK_RXT_DUPLICATE;
	  parts[1] = cur;
	  parts[1].start = overlap_end;
	  tc->dsack_rxt[i].end = overlap_start;
	  vec_insert_elts (tc->dsack_rxt, parts, 2, i + 1);
	  i += 3;
	}
    }

  return matched;
}

static_always_inline u8
tcp_sack_detect_dsack (tcp_connection_t *tc, u32 ack, sack_block_t *dsack)
{
  sack_block_t *sacks = tc->rcv_opts.sacks;

  ASSERT (vec_len (sacks));

  if (PREDICT_FALSE (!seq_lt (sacks[0].start, sacks[0].end)))
    return 0;

  /* RFC 2883: compare against the ACK in this packet, never snd_una. */
  if (seq_leq (sacks[0].end, ack))
    {
      *dsack = sacks[0];
      return 1;
    }

  if (vec_len (sacks) > 1 && seq_gt (sacks[0].start, ack) &&
      seq_leq (sacks[1].start, sacks[0].start) && seq_geq (sacks[1].end, sacks[0].end))
    {
      *dsack = sacks[0];
      return 1;
    }

  return 0;
}

static u8
tcp_sack_extract_dsack (tcp_connection_t *tc, u32 ack, sack_block_t *dsack)
{
  ASSERT (tcp_opts_sack (&tc->rcv_opts) && vec_len (tc->rcv_opts.sacks));

  if (!tcp_sack_detect_dsack (tc, ack, dsack))
    return 0;

  vec_del1 (tc->rcv_opts.sacks, 0);
  tc->rcv_opts.n_sack_blocks -= tc->rcv_opts.n_sack_blocks != 0;
  return 1;
}

static u8
tcp_dsack_update (tcp_connection_t *tc, u32 packet_ack, const sack_block_t *dsack,
		  u8 had_sack_history)
{
  tcp_dsack_rxt_t *rxt;
  u32 cum_ack, matched;

  if (!tcp_dsack_has_history (tc))
    {
      if (dsack)
	tcp_dsack_undo_disabled_on (tc);
      return 0;
    }

  cum_ack = seq_max (tc->snd_una, packet_ack);

  /* Keep one ACK of trailing history for a late D-SACK. */
  if (!tcp_in_cong_recovery (tc) && !dsack)
    {
      if (seq_gt (cum_ack, tc->dsack_recovery_ack))
	tcp_dsack_recovery_done (tc);
      return 0;
    }

  if (dsack)
    {
      /* RFC 3708 A.1: an empty SACK history and a D-SACK beginning at
       * snd_una is indistinguishable from loss of the whole ACK window. */
      if (!had_sack_history && dsack->start == tc->snd_una)
	tcp_dsack_ineligible_on (tc);
      else
	{
	  matched = tcp_dsack_mark_duplicate (tc, dsack->start, dsack->end);
	  if (matched != dsack->end - dsack->start)
	    {
	      tcp_dsack_undo_disabled_on (tc);
	      tcp_dsack_ineligible_on (tc);
	    }
	}
    }

  if (tc->sack_sb.is_reneging)
    tcp_dsack_ineligible_on (tc);

  if (tc->dsack_flags & (TCP_DSACK_INELIGIBLE | TCP_DSACK_UNDO_DISABLED) ||
      seq_lt (cum_ack, tc->snd_congestion))
    return 0;

  vec_foreach (rxt, tc->dsack_rxt)
    if (!(rxt->flags & TCP_DSACK_RXT_DUPLICATE))
      return 0;

  return 1;
}

void
tcp_rcv_dsack (tcp_connection_t *tc, u32 ack, tcp_rate_sample_t *rs)
{
  sack_block_t dsack;

  if (tcp_opts_sack (&tc->rcv_opts) && vec_len (tc->rcv_opts.sacks) &&
      tcp_sack_extract_dsack (tc, ack, &dsack))
    {
      rs->ack_flags |= TCP_ACK_F_DSACK;
      rs->ack_flags |= tcp_dsack_update (tc, ack, &dsack, tc->sack_sb.sacked_bytes != 0) *
		       TCP_ACK_F_DSACK_SPURIOUS;
    }
}

void
tcp_rcv_sacks (tcp_connection_t *tc, u32 ack, tcp_rate_sample_t *rs)
{
  sack_scoreboard_hole_t *hole, *next_hole;
  sack_scoreboard_t *sb = &tc->sack_sb;
  sack_block_t dsack, *blk, *rcv_sacks;
  u32 blk_index = 0, i, j, high_sacked, packet_ack = ack;
  u8 had_sack_history, has_dsack, has_sack, has_scoreboard, needs_update;
  tcp_sb_sack_mode_e mode;

  sb->last_sacked_bytes = 0;
  sb->last_bytes_delivered = 0;
  sb->rxt_sacked = 0;

  has_sack = tcp_opts_sack (&tc->rcv_opts);
  had_sack_history = sb->sacked_bytes != 0;
  has_scoreboard = had_sack_history || sb->head != TCP_INVALID_SACK_HOLE_INDEX;
  needs_update = tcp_dsack_has_history (tc) & seq_gt (packet_ack, tc->snd_una);

  if (PREDICT_TRUE (!(has_sack | has_scoreboard | needs_update)))
    return;

  has_dsack = has_sack && tcp_sack_extract_dsack (tc, packet_ack, &dsack);
  rs->ack_flags |= has_dsack * TCP_ACK_F_DSACK;
  has_sack &= vec_len (tc->rcv_opts.sacks) != 0;
  needs_update |= has_dsack;

  if (!(has_sack | has_scoreboard))
    goto done;

  mode = !tcp_in_cong_recovery (tc)	       ? TCP_SB_SACK_OOO :
	 seq_geq (sb->rescue_rxt, tc->snd_una) ? TCP_SB_SACK_RXT_RESCUED :
						 TCP_SB_SACK_RXT;

  /* The dsack check needs the ack from the wire. The scoreboard treats
   * an old ack as snd_una */
  ack = seq_max (packet_ack, tc->snd_una);

  /* Remove invalid blocks */
  blk = tc->rcv_opts.sacks;
  while (blk < vec_end (tc->rcv_opts.sacks))
    {
      if (seq_lt (blk->start, blk->end)
	  && seq_gt (blk->start, tc->snd_una)
	  && seq_gt (blk->start, ack)
	  && seq_lt (blk->start, tc->snd_nxt)
	  && seq_leq (blk->end, tc->snd_nxt))
	{
	  blk++;
	  continue;
	}
      vec_del1 (tc->rcv_opts.sacks, blk - tc->rcv_opts.sacks);
    }

  /* Add block for cumulative ack */
  if (seq_gt (ack, tc->snd_una))
    {
      vec_add2 (tc->rcv_opts.sacks, blk, 1);
      blk->start = tc->snd_una;
      blk->end = ack;
    }

  if (vec_len (tc->rcv_opts.sacks) == 0)
    goto done;

  tcp_scoreboard_trace_add (tc, ack);

  high_sacked = (sb->sacked_bytes || sb->is_reneging) ? sb->high_sacked : tc->snd_una;

  /* Make sure blocks are ordered */
  rcv_sacks = tc->rcv_opts.sacks;
  for (i = 0; i < vec_len (rcv_sacks); i++)
    {
      for (j = i + 1; j < vec_len (rcv_sacks); j++)
	if (seq_lt (rcv_sacks[j].start, rcv_sacks[i].start))
	  {
	    sack_block_t tmp = rcv_sacks[i];
	    rcv_sacks[i] = rcv_sacks[j];
	    rcv_sacks[j] = tmp;
	  }
      /* Last block's end is not guaranteed to be highest */
      high_sacked = seq_max (high_sacked, rcv_sacks[i].end);
    }

  if (sb->head == TCP_INVALID_SACK_HOLE_INDEX)
    {
      /* Handle reneging as a special case */
      if (PREDICT_FALSE (sb->is_reneging))
	{
	  /* No holes, only sacked bytes */
	  if (seq_leq (tc->snd_nxt, sb->high_sacked))
	    {
	      /* No progress made so return */
	      if (seq_leq (ack, tc->snd_una))
		goto done;

	      /* Update sacked bytes delivered and return */
	      sb->last_bytes_delivered = ack - tc->snd_una;
	      sb->sacked_bytes -= sb->last_bytes_delivered;
	      sb->is_reneging = seq_lt (ack, sb->high_sacked);
	      goto done;
	    }

	  /* New hole above high sacked. Add it and process normally */
	  hole = scoreboard_insert_hole (sb, TCP_INVALID_SACK_HOLE_INDEX,
					 sb->high_sacked, tc->snd_nxt);
	  sb->tail = scoreboard_hole_index (sb, hole);
	}
      /* Not reneging and no holes. Insert the first that covers all
       * outstanding bytes */
      else
	{
	  hole = scoreboard_insert_hole (sb, TCP_INVALID_SACK_HOLE_INDEX,
					 tc->snd_una, tc->snd_nxt);
	  sb->tail = scoreboard_hole_index (sb, hole);
	  sb->high_sacked = tc->snd_una;
	}
    }
  else
    {
      /* If we have holes but snd_nxt is beyond the last hole, update
       * last hole end or add new hole after high sacked */
      hole = scoreboard_last_hole (sb);
      if (seq_gt (tc->snd_nxt, hole->end))
	{
	  if (seq_geq (hole->start, sb->high_sacked))
	    {
	      hole->end = tc->snd_nxt;
	    }
	  /* New hole after high sacked block */
	  else if (seq_lt (sb->high_sacked, tc->snd_nxt))
	    {
	      scoreboard_insert_hole (sb, sb->tail, sb->high_sacked,
				      tc->snd_nxt);
	    }
	}
    }

  /* Walk the holes with the SACK blocks */
  hole = pool_elt_at_index (sb->holes, sb->head);

  if (PREDICT_FALSE (sb->is_reneging))
    {
      sb->last_bytes_delivered += clib_min (hole->start - tc->snd_una,
					    ack - tc->snd_una);
      sb->is_reneging = seq_lt (ack, hole->start);
    }

  while (hole && blk_index < vec_len (rcv_sacks))
    {
      blk = &rcv_sacks[blk_index];
      if (seq_leq (blk->start, hole->start))
	{
	  /* Block covers hole. Remove hole */
	  if (seq_geq (blk->end, hole->end))
	    {
	      next_hole = scoreboard_next_hole (sb, hole);

	      /* If covered by ack, compute delivered bytes */
	      if (blk->end == ack)
		{
		  u32 sacked = next_hole ? next_hole->start :
		    seq_max (sb->high_sacked, hole->end);
		  if (PREDICT_FALSE (seq_lt (ack, sacked)))
		    {
		      sb->last_bytes_delivered += ack - hole->end;
		      sb->is_reneging = 1;
		    }
		  else
		    {
		      sb->last_bytes_delivered += sacked - hole->end;
		      sb->is_reneging = 0;
		    }
		}
	      scoreboard_update_sacked (sb, hole->start, hole->end, mode, tc->snd_mss);
	      scoreboard_remove_hole (sb, hole);
	      hole = next_hole;
	    }
	  /* Partial 'head' overlap */
	  else
	    {
	      if (seq_gt (blk->end, hole->start))
		{
		  scoreboard_update_sacked (sb, hole->start, blk->end, mode, tc->snd_mss);
		  hole->start = blk->end;
		}
	      blk_index++;
	    }
	}
      else
	{
	  /* Hole must be split */
	  if (seq_lt (blk->end, hole->end))
	    {
	      u32 hole_index = scoreboard_hole_index (sb, hole);
	      next_hole = scoreboard_insert_hole (sb, hole_index, blk->end,
						  hole->end);
	      /* Pool might've moved */
	      hole = scoreboard_get_hole (sb, hole_index);
	      hole->end = blk->start;
	      next_hole->is_lost = hole->is_lost;

	      scoreboard_update_sacked (sb, blk->start, blk->end, mode, tc->snd_mss);

	      blk_index++;
	      ASSERT (hole->next == scoreboard_hole_index (sb, next_hole));
	    }
	  else if (seq_lt (blk->start, hole->end))
	    {
	      scoreboard_update_sacked (sb, blk->start, hole->end, mode, tc->snd_mss);
	      hole->end = blk->start;
	    }
	  hole = scoreboard_next_hole (sb, hole);
	}
    }

  sb->high_sacked = high_sacked;
  scoreboard_update_bytes (sb, ack, tc->snd_mss);

  ASSERT (sb->last_sacked_bytes <= sb->sacked_bytes || tcp_in_recovery (tc));
  ASSERT (sb->sacked_bytes == 0 || tcp_in_recovery (tc)
	  || sb->sacked_bytes <= tc->snd_nxt - seq_max (tc->snd_una, ack));
  ASSERT (sb->last_sacked_bytes + sb->lost_bytes <= tc->snd_nxt
	  - seq_max (tc->snd_una, ack) || tcp_in_recovery (tc));
  ASSERT (sb->head == TCP_INVALID_SACK_HOLE_INDEX || tcp_in_recovery (tc)
	  || sb->is_reneging || sb->holes[sb->head].start == ack);
  ASSERT (sb->last_lost_bytes <= sb->lost_bytes);
  ASSERT ((ack - tc->snd_una) + sb->last_sacked_bytes
	  - sb->last_bytes_delivered >= sb->rxt_sacked);
  ASSERT ((ack - tc->snd_una) >= tc->sack_sb.last_bytes_delivered
	  || (tc->flags & TCP_CONN_FINSNT));

  TCP_EVT (TCP_EVT_CC_SCOREBOARD, tc);

done:
  if (PREDICT_FALSE (needs_update))
    rs->ack_flags |= tcp_dsack_update (tc, packet_ack, has_dsack ? &dsack : 0, had_sack_history) *
		     TCP_ACK_F_DSACK_SPURIOUS;
}

static u8
tcp_sack_vector_is_sane (sack_block_t * sacks)
{
  int i;
  for (i = 1; i < vec_len (sacks); i++)
    {
      if (sacks[i - 1].end == sacks[i].start)
	return 0;
    }
  return 1;
}

/**
 * Build SACK list as per RFC2018.
 *
 * Makes sure the first block contains the segment that generated the current
 * ACK and the following ones are the ones most recently reported in SACK
 * blocks.
 *
 * @param tc TCP connection for which the SACK list is updated
 * @param start Start sequence number of the newest SACK block
 * @param end End sequence of the newest SACK block
 */
void
tcp_update_sack_list (tcp_connection_t * tc, u32 start, u32 end)
{
  sack_block_t *new_list = tc->snd_sacks_fl, *block = 0;
  int i;

  /* If the first segment is ooo add it to the list. Last write might've moved
   * rcv_nxt over the first segment. */
  if (seq_lt (tc->rcv_nxt, start))
    {
      vec_add2 (new_list, block, 1);
      block->start = start;
      block->end = end;
    }

  /* Find the blocks still worth keeping. */
  for (i = 0; i < vec_len (tc->snd_sacks); i++)
    {
      /* Discard if rcv_nxt advanced beyond current block */
      if (seq_leq (tc->snd_sacks[i].start, tc->rcv_nxt))
	continue;

      /* Merge or drop if segment overlapped by the new segment */
      if (block && (seq_geq (tc->snd_sacks[i].end, new_list[0].start)
		    && seq_leq (tc->snd_sacks[i].start, new_list[0].end)))
	{
	  if (seq_lt (tc->snd_sacks[i].start, new_list[0].start))
	    new_list[0].start = tc->snd_sacks[i].start;
	  if (seq_lt (new_list[0].end, tc->snd_sacks[i].end))
	    new_list[0].end = tc->snd_sacks[i].end;
	  continue;
	}

      /* Save to new SACK list if we have space. */
      if (vec_len (new_list) < TCP_MAX_SACK_BLOCKS)
	vec_add1 (new_list, tc->snd_sacks[i]);
    }

  ASSERT (vec_len (new_list) <= TCP_MAX_SACK_BLOCKS);

  /* Replace old vector with new one */
  vec_reset_length (tc->snd_sacks);
  tc->snd_sacks_fl = tc->snd_sacks;
  tc->snd_sacks = new_list;

  /* Segments should not 'touch' */
  ASSERT (tcp_sack_vector_is_sane (tc->snd_sacks));
}

u32
tcp_sack_list_bytes (tcp_connection_t * tc)
{
  u32 bytes = 0, i;
  for (i = 0; i < vec_len (tc->snd_sacks); i++)
    bytes += tc->snd_sacks[i].end - tc->snd_sacks[i].start;
  return bytes;
}
