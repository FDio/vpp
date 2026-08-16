/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2020 Cisco and/or its affiliates.
 */

#include <vnet/tcp/tcp_sack.h>
#include <vnet/tcp/tcp_bt.h>

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
scoreboard_update_sacked (sack_scoreboard_t *sb, tcp_rate_sample_t *rs, u32 start, u32 end,
			  tcp_sb_sack_mode_e mode, u16 snd_mss)
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

  rs->rxt_sacked += seq_lt (end, sb->high_rxt) ? (end - start) : (sb->high_rxt - start);
}

always_inline u32
scoreboard_update_loss (sack_scoreboard_t *sb, u32 ack, u32 snd_mss, u8 clear_lost, u32 *last_lost)
{
  sack_scoreboard_hole_t *hole, *left, *right;
  u32 sacked = 0, blks = 0, newly_lost = 0;

  if (clear_lost)
    {
      hole = scoreboard_first_hole (sb);
      while (hole)
	{
	  hole->is_lost = 0;
	  hole = scoreboard_next_hole (sb, hole);
	}
    }

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
      if (!right->is_lost)
	newly_lost += right->end - right->start;
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

  if (last_lost)
    *last_lost = newly_lost;
  return sacked;
}

always_inline void
scoreboard_update_bytes (sack_scoreboard_t *sb, tcp_rate_sample_t *rs, u32 ack, u32 snd_mss)
{
  u32 old_sacked = sb->sacked_bytes;

  sb->sacked_bytes = scoreboard_update_loss (sb, ack, snd_mss, 0, &rs->last_lost);
  rs->last_sacked_bytes = sb->sacked_bytes - (old_sacked - rs->last_bytes_delivered);
}

static void
scoreboard_recompute_sack_loss (sack_scoreboard_t *sb, u32 ack, u32 snd_mss)
{
  u32 sacked;

  /* Discard loss classification inherited from an rto and infer it again
   * solely from the SACK scoreboard. Reclassification is not newly detected
   * loss for the current ACK, so discard the delta. */
  sacked = scoreboard_update_loss (sb, ack, snd_mss, 1, 0);
  ASSERT (sacked == sb->sacked_bytes);
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

static void
scoreboard_init_rxt (sack_scoreboard_t *sb, u32 snd_una)
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

static void
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
  sb->lost_bytes = 0;
  sb->cur_rxt_hole = TCP_INVALID_SACK_HOLE_INDEX;
  sb->is_reneging = 0;
  /* reorder is a learned path property, not episode state, so it is NOT reset here */
}

static void
scoreboard_clear_reneging (sack_scoreboard_t *sb, u32 start, u32 end)
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
static u8
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
tcp_sack_init_rxt (tcp_connection_t *tc, u32 snd_una)
{
  if (PREDICT_FALSE (tc->cfg_flags & TCP_CFG_F_BYTE_TRACKER))
    tcp_bt_init_rxt (tc, snd_una);
  else
    scoreboard_init_rxt (&tc->sack_sb, snd_una);
}

void
tcp_sack_recompute_loss (tcp_connection_t *tc)
{
  if (PREDICT_FALSE (tc->cfg_flags & TCP_CFG_F_BYTE_TRACKER))
    tcp_bt_recompute_sack_loss (tc);
  else
    scoreboard_recompute_sack_loss (&tc->sack_sb, tc->snd_una, tc->snd_mss);
}

void
tcp_sack_rxt_mark_lost (tcp_connection_t *tc)
{
  if (PREDICT_FALSE (tc->cfg_flags & TCP_CFG_F_BYTE_TRACKER))
    tcp_bt_rxt_mark_lost (tc);
  else
    scoreboard_rxt_mark_lost (&tc->sack_sb, tc->snd_una, tc->snd_nxt);
}

u8
tcp_sack_handle_reneging (tcp_connection_t *tc)
{
  sack_scoreboard_t *sb = &tc->sack_sb;
  sack_scoreboard_hole_t *hole;

  if (PREDICT_FALSE (tc->cfg_flags & TCP_CFG_F_BYTE_TRACKER))
    return tcp_bt_handle_sack_reneging (tc);

  hole = scoreboard_first_hole (sb);
  if (!sb->is_reneging && (!hole || hole->start == tc->snd_una))
    return 0;

  scoreboard_clear_reneging (sb, tc->snd_una, tc->snd_nxt);
  return 1;
}

static u8
tcp_sack_is_sane_post_recovery (tcp_connection_t *tc)
{
  return (tc->cfg_flags & TCP_CFG_F_BYTE_TRACKER) ? tcp_bt_is_sane_post_recovery (tc) :
						    tcp_scoreboard_is_sane_post_recovery (tc);
}

static_always_inline tcp_dsack_rxt_t *
tcp_dsack_rxt_header (tcp_connection_t *tc)
{
  ASSERT ((tc->dsack_flags & TCP_DSACK_RXT_ACTIVE) && tc->dsack_rxt);
  return pool_elt_at_index (tc->dsack_rxt, 0);
}

static_always_inline tcp_dsack_rxt_t *
tcp_dsack_rxt_get (tcp_connection_t *tc, u32 index)
{
  ASSERT (index != TCP_DSACK_RXT_INVALID_INDEX);
  return pool_elt_at_index (tc->dsack_rxt, index);
}

static_always_inline u32
tcp_dsack_rxt_count (tcp_connection_t *tc)
{
  ASSERT (tc->dsack_flags & TCP_DSACK_RXT_ACTIVE);
  return pool_elts (tc->dsack_rxt) - 1;
}

static_always_inline u32
tcp_dsack_get_history_start (tcp_connection_t *tc)
{
  if (tc->dsack_flags & TCP_DSACK_RXT_ACTIVE)
    return tcp_dsack_rxt_header (tc)->history_start;
  return tc->dsack_history_start;
}

static void
tcp_dsack_rxt_release (tcp_connection_t *tc, u32 history_start)
{
  ASSERT (tc->dsack_flags & TCP_DSACK_RXT_ACTIVE);
  pool_free (tc->dsack_rxt);
  tc->dsack_history_start = history_start;
  tc->dsack_flags &= ~TCP_DSACK_RXT_ACTIVE;
}

void
tcp_dsack_cleanup (tcp_connection_t *tc)
{
  ASSERT (!(tc->cfg_flags & TCP_CFG_F_BYTE_TRACKER));
  if (tc->dsack_flags & TCP_DSACK_RXT_ACTIVE)
    pool_free (tc->dsack_rxt);
  tc->dsack_rxt = 0;
  tc->dsack_pending_bytes = 0;
  tc->dsack_flags &= TCP_DSACK_UNDO_DISABLED;
}

/* Retire exact ranges as the cumulative ACK advances past them. Aggregate
 * accounting retains the D-SACK evidence still required. */
static void
tcp_dsack_retire (tcp_connection_t *tc, u32 ack)
{
  tcp_dsack_rxt_t *hdr, *rxt;
  u32 history_start, index, next;

  ASSERT (tc->dsack_flags & TCP_DSACK_RXT_ACTIVE);
  hdr = tcp_dsack_rxt_header (tc);
  index = hdr->head;
  rxt = tcp_dsack_rxt_get (tc, index);
  if (seq_leq (ack, rxt->start))
    return;

  history_start = hdr->history_start;
  while (index != TCP_DSACK_RXT_INVALID_INDEX)
    {
      rxt = tcp_dsack_rxt_get (tc, index);
      if (seq_gt (rxt->end, ack))
	break;
      next = rxt->next;
      pool_put_index (tc->dsack_rxt, index);
      index = next;
    }

  if (index == TCP_DSACK_RXT_INVALID_INDEX)
    {
      tcp_dsack_rxt_release (tc, tcp_dsack_has_history (tc) ? history_start : 0);
      return;
    }

  hdr->head = index;
  rxt = tcp_dsack_rxt_get (tc, index);
  if (seq_lt (rxt->start, ack))
    rxt->start = ack;
}

/* Clear recovery-local D-SACK state while preserving active retransmissions
 * and a connection-wide decision to disable undo. */
void
tcp_dsack_recovery_clear (tcp_connection_t *tc)
{
  if (PREDICT_FALSE (tc->cfg_flags & TCP_CFG_F_BYTE_TRACKER))
    {
      tcp_bt_dsack_recovery_clear (tc);
      return;
    }

  tc->dsack_pending_bytes = 0;
  if (tc->dsack_flags & TCP_DSACK_UNDO_DISABLED)
    tcp_dsack_cleanup (tc);
  else
    {
      if (!(tc->dsack_flags & TCP_DSACK_RXT_ACTIVE))
	tc->dsack_history_start = 0;
      tc->dsack_flags &= TCP_DSACK_RXT_ACTIVE;
    }
}

void
tcp_dsack_recovery_init (tcp_connection_t *tc)
{
  tcp_dsack_rxt_t *hdr, *rxt;
  u32 index;

  tcp_dsack_recovery_clear (tc);
  if (PREDICT_FALSE (tc->cfg_flags & TCP_CFG_F_BYTE_TRACKER))
    {
      tcp_bt_dsack_recovery_init (tc);
      return;
    }

  if (!(tc->dsack_flags & TCP_DSACK_RXT_ACTIVE))
    return;

  tcp_dsack_retire (tc, tc->snd_una);
  if (!(tc->dsack_flags & TCP_DSACK_RXT_ACTIVE))
    return;

  hdr = tcp_dsack_rxt_header (tc);
  hdr->history_start = tc->snd_una;
  index = hdr->head;
  while (index != TCP_DSACK_RXT_INVALID_INDEX)
    {
      rxt = tcp_dsack_rxt_get (tc, index);
      tc->dsack_pending_bytes += rxt->end - rxt->start;
      index = rxt->next;
    }
  if (tc->dsack_pending_bytes)
    tc->dsack_flags |= TCP_DSACK_HISTORY;
}

void
tcp_sack_recovery_exit (tcp_connection_t *tc, tcp_ack_flag_t spurious_flags)
{
  sack_scoreboard_hole_t *hole;

  if (spurious_flags)
    tcp_sack_recompute_loss (tc);

  if (!(tc->cfg_flags & TCP_CFG_F_BYTE_TRACKER))
    {
      hole = scoreboard_first_hole (&tc->sack_sb);
      if (hole && seq_leq (tc->sack_sb.high_sacked, hole->end) && !tc->sack_sb.lost_bytes)
	scoreboard_clear (&tc->sack_sb);
    }

  if (spurious_flags)
    {
      if ((spurious_flags & TCP_ACK_F_DSACK_SPURIOUS) || !tcp_dsack_has_history (tc))
	tcp_dsack_recovery_clear (tc);
      else
	/* Retain enough history to recognize the later D-SACK without
	 * misclassifying it as network duplication, but never undo twice. */
	tc->dsack_flags |= TCP_DSACK_INELIGIBLE;
    }
  else if ((tc->dsack_flags & TCP_DSACK_UNDO_DISABLED) || !tcp_dsack_has_history (tc))
    tcp_dsack_recovery_clear (tc);

  ASSERT (tcp_sack_is_sane_post_recovery (tc));
}

/* Prepare to add retained ranges. On overflow, discard range history and make
 * the current recovery episode ineligible for D-SACK undo. */
static_always_inline u8
tcp_dsack_rxt_prepare_add (tcp_connection_t *tc)
{
  u32 history_start;

  if (tcp_dsack_rxt_count (tc) < TCP_MAX_DSACK_RXT_RANGES)
    return 1;

  history_start = tcp_dsack_get_history_start (tc);
  tcp_dsack_rxt_release (tc, history_start);
  tc->dsack_flags |= TCP_DSACK_INELIGIBLE | TCP_DSACK_RXT_OVERFLOW | TCP_DSACK_HISTORY;
  return 0;
}

static_always_inline u32
tcp_dsack_rxt_alloc (tcp_connection_t *tc, tcp_dsack_rxt_t rxt, u32 next)
{
  tcp_dsack_rxt_t *new_rxt;
  u32 index;

  pool_get (tc->dsack_rxt, new_rxt);
  index = new_rxt - tc->dsack_rxt;
  *new_rxt = rxt;
  new_rxt->next = next;
  return index;
}

static_always_inline void
tcp_dsack_rxt_append (tcp_connection_t *tc, tcp_dsack_rxt_t rxt)
{
  tcp_dsack_rxt_t *hdr;
  u32 index, tail;

  hdr = tcp_dsack_rxt_header (tc);
  tail = hdr->tail;
  index = tcp_dsack_rxt_alloc (tc, rxt, TCP_DSACK_RXT_INVALID_INDEX);
  hdr = tcp_dsack_rxt_header (tc);
  if (tail == TCP_DSACK_RXT_INVALID_INDEX)
    hdr->head = index;
  else
    tcp_dsack_rxt_get (tc, tail)->next = index;
  hdr->tail = index;
}

static_always_inline void
tcp_dsack_rxt_insert (tcp_connection_t *tc, tcp_dsack_rxt_t rxt, u32 prev, u32 next)
{
  tcp_dsack_rxt_t *hdr;
  u32 index;

  index = tcp_dsack_rxt_alloc (tc, rxt, next);
  hdr = tcp_dsack_rxt_header (tc);
  if (prev == TCP_DSACK_RXT_INVALID_INDEX)
    hdr->head = index;
  else
    tcp_dsack_rxt_get (tc, prev)->next = index;
  if (next == TCP_DSACK_RXT_INVALID_INDEX)
    hdr->tail = index;
}

/* Add retransmitted coverage as a sorted, disjoint union. Returns true when
 * the new transmission overlaps a copy already in flight. */
static u8
tcp_dsack_track_range_union (tcp_connection_t *tc, u32 start, u32 end)
{
  tcp_dsack_rxt_t rxt = { .start = start, .end = end };
  tcp_dsack_rxt_t *hdr, *cur, *last;
  u8 overlap = 0;
  u32 current, next, prev = TCP_DSACK_RXT_INVALID_INDEX;

  if (!(tc->dsack_flags & TCP_DSACK_RXT_ACTIVE))
    {
      u32 history_start = tcp_dsack_has_history (tc) ? tc->dsack_history_start : tc->snd_una;

      tc->dsack_rxt = 0;
      pool_get (tc->dsack_rxt, hdr);
      ASSERT (hdr == tc->dsack_rxt);
      hdr->head = TCP_DSACK_RXT_INVALID_INDEX;
      hdr->tail = TCP_DSACK_RXT_INVALID_INDEX;
      hdr->history_start = history_start;
      tc->dsack_flags |= TCP_DSACK_RXT_ACTIVE;
      tcp_dsack_rxt_append (tc, rxt);
      return 0;
    }

  hdr = tcp_dsack_rxt_header (tc);
  last = tcp_dsack_rxt_get (tc, hdr->tail);
  if (seq_geq (start, last->end))
    {
      if (start == last->end)
	last->end = end;
      else if (tcp_dsack_rxt_prepare_add (tc))
	tcp_dsack_rxt_append (tc, rxt);
      return 0;
    }

  current = hdr->head;
  while (current != TCP_DSACK_RXT_INVALID_INDEX)
    {
      cur = tcp_dsack_rxt_get (tc, current);
      if (seq_lt (rxt.end, cur->start))
	break;
      if (seq_gt (rxt.start, cur->end))
	{
	  prev = current;
	  current = cur->next;
	  continue;
	}

      overlap |= seq_lt (rxt.start, cur->end) && seq_gt (rxt.end, cur->start);
      rxt.start = seq_min (cur->start, rxt.start);
      rxt.end = seq_max (rxt.end, cur->end);
      next = cur->next;
      pool_put_index (tc->dsack_rxt, current);
      current = next;
    }

  if (!tcp_dsack_rxt_prepare_add (tc))
    return overlap;

  tcp_dsack_rxt_insert (tc, rxt, prev, current);
  return overlap;
}

void
tcp_dsack_track_retransmit (tcp_connection_t *tc, u32 start, u32 end)
{
  u32 tracked = end - start;

  ASSERT (tcp_opts_sack_permitted (&tc->rcv_opts));
  ASSERT (tcp_in_cong_recovery (tc));
  ASSERT (seq_lt (start, end));

  if (tc->dsack_flags & (TCP_DSACK_UNDO_DISABLED | TCP_DSACK_RXT_OVERFLOW))
    return;

  if (tcp_dsack_track_range_union (tc, start, end))
    tc->dsack_flags |= TCP_DSACK_INELIGIBLE;
  ASSERT (tc->dsack_pending_bytes <= (u32) ~0 - tracked);
  tc->dsack_pending_bytes += tracked;
  tc->dsack_flags |= TCP_DSACK_HISTORY;
}

/* Match the intersection of [start,end) with retained retransmissions. */
static u32
tcp_dsack_mark_duplicate (tcp_connection_t *tc, u32 start, u32 end)
{
  tcp_dsack_rxt_t *rxt;
  u32 active_start = start, matched = 0;
  u32 index, overlap_start, overlap_end;

  if (PREDICT_FALSE (tc->cfg_flags & TCP_CFG_F_BYTE_TRACKER))
    return tcp_bt_dsack_mark_duplicate (tc, start, end);

  if (seq_lt (active_start, tc->snd_una))
    {
      overlap_end = seq_min (end, tc->snd_una);
      overlap_start = seq_max (active_start, tcp_dsack_get_history_start (tc));
      if (seq_lt (overlap_start, overlap_end))
	{
	  matched += overlap_end - overlap_start;
	}
      active_start = overlap_end;
    }

  if ((tc->dsack_flags & TCP_DSACK_RXT_ACTIVE) && seq_lt (active_start, end))
    {
      index = tcp_dsack_rxt_header (tc)->head;
      while (index != TCP_DSACK_RXT_INVALID_INDEX)
	{
	  rxt = tcp_dsack_rxt_get (tc, index);
	  if (seq_leq (end, rxt->start))
	    break;
	  if (seq_geq (active_start, rxt->end))
	    {
	      index = rxt->next;
	      continue;
	    }

	  overlap_start = seq_max (active_start, rxt->start);
	  overlap_end = seq_min (end, rxt->end);
	  ASSERT (seq_lt (overlap_start, overlap_end));
	  matched += overlap_end - overlap_start;
	  index = rxt->next;
	}
    }

  return matched;
}

static u8
tcp_dsack_all_duplicate (tcp_connection_t *tc)
{
  return tcp_dsack_has_history (tc) && !tc->dsack_pending_bytes;
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

  /* Ignore ranges that alias unsent sequence space, cross the cumulative ACK, or are larger than
   * any receive window advertised by the peer. */
  u32 snd_una = seq_max (ack, tc->snd_una);
  if (PREDICT_FALSE (seq_gt (dsack->end, tc->snd_nxt) || seq_geq (dsack->start, tc->snd_nxt) ||
		     (seq_leq (dsack->start, snd_una) && seq_gt (dsack->end, snd_una)) ||
		     dsack->end - dsack->start > tc->snd_wnd_max))
    return 0;

  vec_del1 (tc->rcv_opts.sacks, 0);
  tc->rcv_opts.n_sack_blocks -= tc->rcv_opts.n_sack_blocks != 0;
  return 1;
}

static u8
tcp_dsack_update (tcp_connection_t *tc, const sack_block_t *dsack, u8 had_sack_history)
{
  u32 matched;

  ASSERT (dsack != 0);

  if (!tcp_dsack_has_history (tc))
    {
      /* With bounded retransmit history, conservatively treat a D-SACK
       * without retained history as network duplication (RFC 3708 A.4). */
      tc->dsack_flags |= TCP_DSACK_UNDO_DISABLED;
      tcp_dsack_recovery_clear (tc);
      return 0;
    }

  /* Tracking overflow makes only this recovery episode ineligible. D-SACKs
   * cannot be matched after its history is discarded, but that is not
   * evidence that D-SACK undo should be disabled for the connection. */
  if (tc->dsack_flags & TCP_DSACK_RXT_OVERFLOW)
    return 0;

  /* RFC 3708 A.1: an empty SACK history and a D-SACK beginning at
   * snd_una is indistinguishable from loss of the whole ACK window. */
  if (!had_sack_history && dsack->start == tc->snd_una)
    tc->dsack_flags |= TCP_DSACK_INELIGIBLE;
  else
    {
      matched = tcp_dsack_mark_duplicate (tc, dsack->start, dsack->end);
      if (tc->dsack_flags & TCP_DSACK_RXT_OVERFLOW)
	return 0;
      if (matched != dsack->end - dsack->start)
	{
	  tc->dsack_flags |= TCP_DSACK_UNDO_DISABLED;
	  tcp_dsack_recovery_clear (tc);
	  return 0;
	}
      if (matched > tc->dsack_pending_bytes)
	{
	  tc->dsack_flags |= TCP_DSACK_INELIGIBLE;
	  return 0;
	}
      tc->dsack_pending_bytes -= matched;
    }

  return 1;
}

static tcp_ack_flag_t
tcp_dsack_finalize (tcp_connection_t *tc)
{

  if (tc->sack_sb.is_reneging)
    tc->dsack_flags |= TCP_DSACK_INELIGIBLE;

  if (tc->dsack_flags & (TCP_DSACK_INELIGIBLE | TCP_DSACK_UNDO_DISABLED))
    return 0;

  return tcp_dsack_all_duplicate (tc) ? TCP_ACK_F_DSACK_SPURIOUS : 0;
}

void
tcp_rcv_dsack (tcp_connection_t *tc, u32 ack, tcp_rate_sample_t *rs)
{
  sack_block_t dsack;

  if (tcp_opts_sack (&tc->rcv_opts) && vec_len (tc->rcv_opts.sacks) &&
      tcp_sack_extract_dsack (tc, ack, &dsack))
    {
      rs->ack_flags |= TCP_ACK_F_DSACK;
      if (tcp_dsack_update (tc, &dsack, tc->sack_sb.sacked_bytes != 0))
	rs->ack_flags |= tcp_dsack_finalize (tc);
    }
}

static void
tcp_scoreboard_apply_sacks (tcp_connection_t *tc, u32 ack, u32 high_sacked, tcp_sb_sack_mode_e mode,
			    tcp_rate_sample_t *rs)
{
  sack_scoreboard_hole_t *hole, *next_hole;
  sack_scoreboard_t *sb = &tc->sack_sb;
  sack_block_t *blk, *rcv_sacks = tc->rcv_opts.sacks;
  u32 blk_index = 0;

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
		return;

	      /* Update sacked bytes delivered and return */
	      rs->last_bytes_delivered = ack - tc->snd_una;
	      sb->sacked_bytes -= rs->last_bytes_delivered;
	      sb->is_reneging = seq_lt (ack, sb->high_sacked);
	      return;
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
      rs->last_bytes_delivered += clib_min (hole->start - tc->snd_una, ack - tc->snd_una);
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
		  u32 sacked = next_hole ? next_hole->start : seq_max (sb->high_sacked, hole->end);
		  if (PREDICT_FALSE (seq_lt (ack, sacked)))
		    {
		      rs->last_bytes_delivered += ack - hole->end;
		      sb->is_reneging = 1;
		    }
		  else
		    {
		      rs->last_bytes_delivered += sacked - hole->end;
		      sb->is_reneging = 0;
		    }
		}
	      scoreboard_update_sacked (sb, rs, hole->start, hole->end, mode, tc->snd_mss);
	      scoreboard_remove_hole (sb, hole);
	      hole = next_hole;
	    }
	  /* Partial 'head' overlap */
	  else
	    {
	      if (seq_gt (blk->end, hole->start))
		{
		  scoreboard_update_sacked (sb, rs, hole->start, blk->end, mode, tc->snd_mss);
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
	      next_hole = scoreboard_insert_hole (sb, hole_index, blk->end, hole->end);
	      /* Pool might've moved */
	      hole = scoreboard_get_hole (sb, hole_index);
	      hole->end = blk->start;
	      next_hole->is_lost = hole->is_lost;

	      scoreboard_update_sacked (sb, rs, blk->start, blk->end, mode, tc->snd_mss);

	      blk_index++;
	      ASSERT (hole->next == scoreboard_hole_index (sb, next_hole));
	    }
	  else if (seq_lt (blk->start, hole->end))
	    {
	      scoreboard_update_sacked (sb, rs, blk->start, hole->end, mode, tc->snd_mss);
	      hole->end = blk->start;
	    }
	  hole = scoreboard_next_hole (sb, hole);
	}
    }

  sb->high_sacked = high_sacked;
  scoreboard_update_bytes (sb, rs, ack, tc->snd_mss);

  ASSERT (rs->last_sacked_bytes <= sb->sacked_bytes || tcp_in_recovery (tc));
  ASSERT (sb->sacked_bytes == 0 || tcp_in_recovery (tc) ||
	  sb->sacked_bytes <= tc->snd_nxt - seq_max (tc->snd_una, ack));
  ASSERT (rs->last_sacked_bytes + sb->lost_bytes <= tc->snd_nxt - seq_max (tc->snd_una, ack) ||
	  tcp_in_recovery (tc));
  ASSERT (sb->head == TCP_INVALID_SACK_HOLE_INDEX || tcp_in_recovery (tc) || sb->is_reneging ||
	  sb->holes[sb->head].start == ack);
  ASSERT (rs->last_lost <= sb->lost_bytes);
  ASSERT ((ack - tc->snd_una) + rs->last_sacked_bytes - rs->last_bytes_delivered >= rs->rxt_sacked);
  ASSERT ((ack - tc->snd_una) >= rs->last_bytes_delivered || (tc->flags & TCP_CONN_FINSNT));

  TCP_EVT (TCP_EVT_CC_SCOREBOARD, tc, rs);
}

void
tcp_rcv_sacks (tcp_connection_t *tc, u32 ack, tcp_rate_sample_t *rs)
{
  sack_scoreboard_t *sb = &tc->sack_sb;
  sack_block_t dsack, *blk, *rcv_sacks;
  u32 i, j, high_sacked, packet_ack = ack;
  u8 finalize_dsack, had_sack_history, has_dsack, has_sack, has_scoreboard;
  u8 may_retire_dsack;

  has_sack = tcp_opts_sack (&tc->rcv_opts) != 0;
  had_sack_history = sb->sacked_bytes != 0;
  has_scoreboard = had_sack_history || sb->head != TCP_INVALID_SACK_HOLE_INDEX;
  may_retire_dsack = seq_gt (packet_ack, tc->snd_una) && (tc->dsack_flags & TCP_DSACK_RXT_ACTIVE);

  if (PREDICT_TRUE (!(has_sack | has_scoreboard | may_retire_dsack)))
    return;

  has_dsack = has_sack && tcp_sack_extract_dsack (tc, packet_ack, &dsack);
  rs->ack_flags |= has_dsack * TCP_ACK_F_DSACK;
  has_sack &= vec_len (tc->rcv_opts.sacks) != 0;
  /* Record dsack evidence first, but decide undo only after ack/sack
   * processing has resolved reneging. */
  finalize_dsack = has_dsack && tcp_dsack_update (tc, &dsack, had_sack_history);

  if (!(has_sack | has_scoreboard))
    goto done;

  /* The dsack check needs the ack from the wire. The scoreboard treats
   * an old ack as snd_una */
  ack = seq_max (packet_ack, tc->snd_una);

  /* Remove invalid blocks */
  blk = tc->rcv_opts.sacks;
  while (blk < vec_end (tc->rcv_opts.sacks))
    {
      if (seq_lt (blk->start, blk->end) && seq_gt (blk->start, tc->snd_una) &&
	  seq_gt (blk->start, ack) && seq_lt (blk->start, tc->snd_nxt) &&
	  seq_leq (blk->end, tc->snd_nxt))
	{
	  blk++;
	  continue;
	}
      vec_del1 (tc->rcv_opts.sacks, blk - tc->rcv_opts.sacks);
    }

  has_sack = vec_len (tc->rcv_opts.sacks) != 0;

  /* Add block for cumulative ack */
  if (seq_gt (ack, tc->snd_una))
    {
      vec_add2 (tc->rcv_opts.sacks, blk, 1);
      blk->start = tc->snd_una;
      blk->end = ack;
    }

  if (vec_len (tc->rcv_opts.sacks) == 0)
    goto done;

  if (!(tc->cfg_flags & TCP_CFG_F_BYTE_TRACKER))
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

  if (PREDICT_FALSE (tc->cfg_flags & TCP_CFG_F_BYTE_TRACKER))
    tcp_bt_apply_sacks (tc, ack, high_sacked, has_sack, rs);
  else
    {
      tcp_sb_sack_mode_e mode = !tcp_in_cong_recovery (tc)	      ? TCP_SB_SACK_OOO :
				seq_geq (sb->rescue_rxt, tc->snd_una) ? TCP_SB_SACK_RXT_RESCUED :
									TCP_SB_SACK_RXT;
      tcp_scoreboard_apply_sacks (tc, ack, high_sacked, mode, rs);
    }

done:
  if (PREDICT_FALSE (finalize_dsack | may_retire_dsack))
    {
      if (finalize_dsack)
	rs->ack_flags |= tcp_dsack_finalize (tc);
      if (may_retire_dsack && (tc->dsack_flags & TCP_DSACK_RXT_ACTIVE))
	tcp_dsack_retire (tc, packet_ack);
    }
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
