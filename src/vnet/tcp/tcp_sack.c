/*
 * Copyright (c) 2020 Cisco and/or its affiliates.
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

always_inline void
scoreboard_update_sacked_rxt (sack_scoreboard_t * sb, u32 start, u32 end,
			      u8 has_rxt)
{
  if (!has_rxt || seq_geq (start, sb->high_rxt))
    return;

  sb->rxt_sacked +=
    seq_lt (end, sb->high_rxt) ? (end - start) : (sb->high_rxt - start);
}

always_inline void
scoreboard_update_bytes (sack_scoreboard_t * sb, u32 ack, u32 snd_mss)
{
  sack_scoreboard_hole_t *left, *right;
  u32 sacked = 0, blks = 0, old_sacked;

  old_sacked = sb->sacked_bytes;

  sb->last_lost_bytes = 0;
  sb->lost_bytes = 0;
  sb->sacked_bytes = 0;

  right = scoreboard_last_hole (sb);
  if (!right)
    {
      sb->sacked_bytes = sb->high_sacked - ack;
      sb->last_sacked_bytes = sb->sacked_bytes
	- (old_sacked - sb->last_bytes_delivered);
      return;
    }

  if (seq_gt (sb->high_sacked, right->end))
    {
      sacked = sb->high_sacked - right->end;
      blks = 1;
    }

  while (sacked < (TCP_DUPACK_THRESHOLD - 1) * snd_mss
	 && blks < TCP_DUPACK_THRESHOLD)
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

  sb->sacked_bytes = sacked;
  sb->last_sacked_bytes = sacked - (old_sacked - sb->last_bytes_delivered);
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
scoreboard_init (sack_scoreboard_t * sb)
{
  sb->head = TCP_INVALID_SACK_HOLE_INDEX;
  sb->tail = TCP_INVALID_SACK_HOLE_INDEX;
  sb->cur_rxt_hole = TCP_INVALID_SACK_HOLE_INDEX;
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
}

void
scoreboard_clear_reneging (sack_scoreboard_t * sb, u32 start, u32 end)
{
  sack_scoreboard_hole_t *last_hole;

  scoreboard_clear (sb);
  last_hole = scoreboard_insert_hole (sb, TCP_INVALID_SACK_HOLE_INDEX,
				      start, end);
  last_hole->is_lost = 1;
  sb->tail = scoreboard_hole_index (sb, last_hole);
  sb->high_sacked = start;
  scoreboard_init_rxt (sb, start);
}

/**
 * Test that scoreboard is sane after recovery
 *
 * Returns 1 if scoreboard is empty or if first hole beyond
 * snd_una.
 */
u8
tcp_scoreboard_is_sane_post_recovery (tcp_connection_t * tc)
{
  sack_scoreboard_hole_t *hole;
  hole = scoreboard_first_hole (&tc->sack_sb);
  return (!hole || (seq_geq (hole->start, tc->snd_una)
		    && seq_lt (hole->end, tc->snd_nxt)));
}

void
tcp_rcv_sacks (tcp_connection_t * tc, u32 ack)
{
  sack_scoreboard_hole_t *hole, *next_hole;
  sack_scoreboard_t *sb = &tc->sack_sb;
  sack_block_t *blk, *rcv_sacks;
  u32 blk_index = 0, i, j;
  u8 has_rxt;

  sb->last_sacked_bytes = 0;
  sb->last_bytes_delivered = 0;
  sb->rxt_sacked = 0;

  if (!tcp_opts_sack (&tc->rcv_opts) && !sb->sacked_bytes
      && sb->head == TCP_INVALID_SACK_HOLE_INDEX)
    return;

  has_rxt = tcp_in_cong_recovery (tc);

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
    return;

  tcp_scoreboard_trace_add (tc, ack);

  /* Make sure blocks are ordered */
  rcv_sacks = tc->rcv_opts.sacks;
  for (i = 0; i < vec_len (rcv_sacks); i++)
    for (j = i + 1; j < vec_len (rcv_sacks); j++)
      if (seq_lt (rcv_sacks[j].start, rcv_sacks[i].start))
	{
	  sack_block_t tmp = rcv_sacks[i];
	  rcv_sacks[i] = rcv_sacks[j];
	  rcv_sacks[j] = tmp;
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
		return;

	      /* Update sacked bytes delivered and return */
	      sb->last_bytes_delivered = ack - tc->snd_una;
	      sb->sacked_bytes -= sb->last_bytes_delivered;
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
	}
      sb->high_sacked = rcv_sacks[vec_len (rcv_sacks) - 1].end;
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

      /* Keep track of max byte sacked for when the last hole
       * is acked */
      sb->high_sacked = seq_max (rcv_sacks[vec_len (rcv_sacks) - 1].end,
				 sb->high_sacked);
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
		  u32 sacked = next_hole ? next_hole->start : sb->high_sacked;
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
	      scoreboard_update_sacked_rxt (sb, hole->start, hole->end,
					    has_rxt);
	      scoreboard_remove_hole (sb, hole);
	      hole = next_hole;
	    }
	  /* Partial 'head' overlap */
	  else
	    {
	      if (seq_gt (blk->end, hole->start))
		{
		  scoreboard_update_sacked_rxt (sb, hole->start, blk->end,
						has_rxt);
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

	      scoreboard_update_sacked_rxt (sb, blk->start, blk->end,
					    has_rxt);

	      blk_index++;
	      ASSERT (hole->next == scoreboard_hole_index (sb, next_hole));
	    }
	  else if (seq_lt (blk->start, hole->end))
	    {
	      scoreboard_update_sacked_rxt (sb, blk->start, hole->end,
					    has_rxt);
	      hole->end = blk->start;
	    }
	  hole = scoreboard_next_hole (sb, hole);
	}
    }

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

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
