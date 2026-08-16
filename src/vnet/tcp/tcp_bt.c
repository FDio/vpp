/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Cisco and/or its affiliates.
 */

/*
 * TCP byte tracker that can generate delivery rate estimates. Based on
 * draft-cheng-iccrg-delivery-rate-estimation-00
 */

#include <vnet/tcp/tcp_bt.h>
#include <vnet/tcp/tcp.h>
#include <vnet/tcp/tcp_inlines.h>

static tcp_bt_sample_t *
bt_get_sample (tcp_byte_tracker_t * bt, u32 bts_index)
{
  if (pool_is_free_index (bt->samples, bts_index))
    return 0;
  return pool_elt_at_index (bt->samples, bts_index);
}

static tcp_bt_sample_t *
bt_next_sample (tcp_byte_tracker_t * bt, tcp_bt_sample_t * bts)
{
  return bt_get_sample (bt, bts->next);
}

static tcp_bt_sample_t *
bt_prev_sample (tcp_byte_tracker_t * bt, tcp_bt_sample_t * bts)
{
  return bt_get_sample (bt, bts->prev);
}

static u32
bt_sample_index (tcp_byte_tracker_t * bt, tcp_bt_sample_t * bts)
{
  if (!bts)
    return TCP_BTS_INVALID_INDEX;
  return bts - bt->samples;
}

static inline int
bt_seq_lt (u32 a, u32 b)
{
  return seq_lt (a, b);
}

static tcp_bt_sample_t *
bt_alloc_sample (tcp_byte_tracker_t * bt, u32 min_seq, u32 max_seq)
{
  tcp_bt_sample_t *bts;

  pool_get_zero (bt->samples, bts);
  bts->next = bts->prev = TCP_BTS_INVALID_INDEX;
  bts->min_seq = min_seq;
  bts->max_seq = max_seq;
  rb_tree_add_custom (&bt->sample_lookup, bts->min_seq, bts - bt->samples,
		      bt_seq_lt);
  return bts;
}

static void
bt_free_sample (tcp_byte_tracker_t *bt, tcp_bt_sample_t *bts)
{
  if (bt->last_ooo == bt_sample_index (bt, bts))
    bt->last_ooo = TCP_BTS_INVALID_INDEX;
  if (bt->cur_rxt == bt_sample_index (bt, bts))
    bt->cur_rxt = TCP_BTS_INVALID_INDEX;

  if (bts->prev != TCP_BTS_INVALID_INDEX)
    {
      tcp_bt_sample_t *prev = bt_prev_sample (bt, bts);
      prev->next = bts->next;
    }
  else
    bt->head = bts->next;

  if (bts->next != TCP_BTS_INVALID_INDEX)
    {
      tcp_bt_sample_t *next = bt_next_sample (bt, bts);
      next->prev = bts->prev;
    }
  else
    bt->tail = bts->prev;

  rb_tree_del_custom (&bt->sample_lookup, bts->min_seq, bt_seq_lt);
  if (CLIB_DEBUG)
    memset (bts, 0xfc, sizeof (*bts));
  pool_put (bt->samples, bts);
}

static tcp_bt_sample_t *
bt_split_sample (tcp_byte_tracker_t * bt, tcp_bt_sample_t * bts, u32 seq)
{
  tcp_bt_sample_t *ns, *next;
  u32 bts_index;

  bts_index = bt_sample_index (bt, bts);

  ASSERT (seq_leq (bts->min_seq, seq) && seq_lt (seq, bts->max_seq));

  ns = bt_alloc_sample (bt, seq, bts->max_seq);
  bts = bt_get_sample (bt, bts_index);

  *ns = *bts;
  ns->min_seq = seq;
  bts->max_seq = seq;

  next = bt_next_sample (bt, bts);
  if (next)
    next->prev = bt_sample_index (bt, ns);
  else
    bt->tail = bt_sample_index (bt, ns);

  bts->next = bt_sample_index (bt, ns);
  ns->prev = bt_sample_index (bt, bts);

  return ns;
}

static tcp_bt_sample_t *
bt_merge_sample (tcp_byte_tracker_t * bt, tcp_bt_sample_t * prev,
		 tcp_bt_sample_t * cur)
{
  ASSERT (prev->max_seq == cur->min_seq);
  prev->max_seq = cur->max_seq;
  if (bt_sample_index (bt, cur) == bt->tail)
    bt->tail = bt_sample_index (bt, prev);
  bt_free_sample (bt, cur);
  return prev;
}

static_always_inline u8
bt_sacked_samples_can_merge (tcp_bt_sample_t *left, tcp_bt_sample_t *right)
{
  return left->flags == right->flags;
}

static tcp_bt_sample_t *
bt_lookup_seq (tcp_byte_tracker_t * bt, u32 seq)
{
  rb_tree_t *rt = &bt->sample_lookup;
  rb_node_t *cur, *prev;
  tcp_bt_sample_t *bts;

  cur = rb_node (rt, rb_tree_root (rt));
  if (rb_node_is_tnil (rt, cur))
    return 0;

  while (seq != cur->key)
    {
      prev = cur;
      if (seq_lt (seq, cur->key))
	cur = rb_node_left (rt, cur);
      else
	cur = rb_node_right (rt, cur);

      if (rb_node_is_tnil (rt, cur))
	{
	  /* Hit tnil as a left child. Find predecessor */
	  if (seq_lt (seq, prev->key))
	    {
	      cur = rb_tree_predecessor (rt, prev);
	      if (rb_node_is_tnil (rt, cur))
		return 0;
	      bts = bt_get_sample (bt, cur->opaque);
	    }
	  /* Hit tnil as a right child */
	  else
	    {
	      bts = bt_get_sample (bt, prev->opaque);
	    }

	  if (seq_geq (seq, bts->min_seq))
	    return bts;

	  return 0;
	}
    }

  if (!rb_node_is_tnil (rt, cur))
    return bt_get_sample (bt, cur->opaque);

  return 0;
}

static void
bt_update_sample (tcp_byte_tracker_t * bt, tcp_bt_sample_t * bts, u32 seq)
{
  rb_tree_del_custom (&bt->sample_lookup, bts->min_seq, bt_seq_lt);
  bts->min_seq = seq;
  rb_tree_add_custom (&bt->sample_lookup, bts->min_seq,
		      bt_sample_index (bt, bts), bt_seq_lt);
}

static tcp_bt_sample_t *
bt_fix_overlapped (tcp_byte_tracker_t * bt, tcp_bt_sample_t * start,
		   u32 seq, u8 is_end)
{
  tcp_bt_sample_t *cur, *next;

  cur = start;
  while (cur && seq_leq (cur->max_seq, seq))
    {
      next = bt_next_sample (bt, cur);
      bt_free_sample (bt, cur);
      cur = next;
    }

  if (cur && seq_lt (cur->min_seq, seq))
    bt_update_sample (bt, cur, seq);

  return cur;
}

int
tcp_bt_is_sane (tcp_byte_tracker_t * bt)
{
  tcp_bt_sample_t *bts, *tmp;

  if (pool_elts (bt->samples) != pool_elts (bt->sample_lookup.nodes) - 1)
    return 0;

  if (bt->head == TCP_BTS_INVALID_INDEX)
    {
      if (bt->tail != TCP_BTS_INVALID_INDEX)
	return 0;
      if (pool_elts (bt->samples) != 0)
	return 0;
      return 1;
    }

  bts = bt_get_sample (bt, bt->tail);
  if (!bts)
    return 0;

  bts = bt_get_sample (bt, bt->head);
  if (!bts || bts->prev != TCP_BTS_INVALID_INDEX)
    return 0;

  while (bts)
    {
      tmp = bt_lookup_seq (bt, bts->min_seq);
      if (!tmp || tmp != bts)
	return 0;
      tmp = bt_next_sample (bt, bts);
      if (tmp)
	{
	  if (tmp->prev != bt_sample_index (bt, bts))
	    {
	      clib_warning ("next %u thinks prev is %u should be %u", bts->next, tmp->prev,
			    bt_sample_index (bt, bts));
	      return 0;
	    }
	  if (!seq_lt (bts->min_seq, tmp->min_seq))
	    return 0;
	}
      else
	{
	  if (bt->tail != bt_sample_index (bt, bts))
	    return 0;
	  if (bts->next != TCP_BTS_INVALID_INDEX)
	    return 0;
	}
      bts = tmp;
    }

  return 1;
}

static tcp_bt_sample_t *
tcp_bt_alloc_tx_sample (tcp_connection_t * tc, u32 min_seq, u32 max_seq)
{
  tcp_bt_sample_t *bts;
  bts = bt_alloc_sample (tc->bt, min_seq, max_seq);
  bts->delivered = tc->delivered;
  bts->delivered_time = tc->delivered_time;
  bts->tx_time = tcp_time_now_us (tc->c_thread_index);
  bts->first_tx_time = tc->first_tx_time;
  bts->flags |= tc->app_limited ? TCP_BTS_IS_APP_LIMITED : 0;
  bts->tx_in_flight = tcp_flight_size (tc);
  bts->tx_lost = tc->lost;
  return bts;
}

void
tcp_bt_check_app_limited (tcp_connection_t * tc)
{
  u32 available_bytes, flight_size;

  available_bytes = transport_max_tx_dequeue (&tc->connection);
  flight_size = tcp_flight_size (tc);

  /* Not enough bytes to fill the cwnd */
  if (available_bytes + flight_size + tc->snd_mss < tc->cwnd
      /* Bytes considered lost have been retransmitted */
      && tc->sack_sb.lost_bytes <= tc->snd_rxt_bytes)
    tc->app_limited = tc->delivered + flight_size ? : 1;
}

void
tcp_bt_track_tx (tcp_connection_t * tc, u32 len)
{
  tcp_byte_tracker_t *bt = tc->bt;
  tcp_bt_sample_t *bts, *tail;
  tcp_bts_flags_t tx_flags = tc->app_limited ? TCP_BTS_IS_APP_LIMITED : 0;
  u32 bts_index;

  tail = bt_get_sample (bt, bt->tail);
  if (tail && tail->max_seq == tc->snd_nxt && tail->flags == tx_flags &&
      tail->tx_time == tcp_time_now_us (tc->c_thread_index))
    {
      tail->max_seq += len;
      return;
    }

  if (tc->snd_una == tc->snd_nxt)
    {
      tc->delivered_time = tcp_time_now_us (tc->c_thread_index);
      tc->first_tx_time = tc->delivered_time;
    }

  bts = tcp_bt_alloc_tx_sample (tc, tc->snd_nxt, tc->snd_nxt + len);
  bts_index = bt_sample_index (bt, bts);
  tail = bt_get_sample (bt, bt->tail);
  if (tail)
    {
      tail->next = bts_index;
      bts->prev = bt->tail;
      bt->tail = bts_index;
    }
  else
    {
      bt->tail = bt->head = bts_index;
    }
}

static_always_inline tcp_bts_flags_t
bt_rxt_flags (tcp_connection_t *tc, tcp_bt_sample_t *bts)
{
  tcp_bts_flags_t flags = TCP_BTS_IS_RXT;

  flags |= bts->flags & (TCP_BTS_IS_LOST | TCP_BTS_IS_DELIVERED);
  flags |= (bts->flags & TCP_BTS_IS_RXT) ? TCP_BTS_IS_RXT_LOST : 0;
  flags |= tc->app_limited ? TCP_BTS_IS_APP_LIMITED : 0;
  return flags;
}

static_always_inline u32
bt_rxt_range_end (tcp_connection_t *tc, tcp_bt_sample_t *bts, u32 end, tcp_bts_flags_t rxt_flags)
{
  tcp_byte_tracker_t *bt = tc->bt;
  tcp_bt_sample_t *scan;

  scan = bt_next_sample (bt, bts);
  while (scan && seq_lt (scan->min_seq, end))
    {
      if ((scan->flags & TCP_BTS_IS_SACKED) || bt_rxt_flags (tc, scan) != rxt_flags)
	return scan->min_seq;
      scan = bt_next_sample (bt, scan);
    }
  return end;
}

/* Record one contiguous unsacked retransmit range whose source samples all
 * map to rxt_flags. */
static void
bt_track_rxt_range (tcp_connection_t *tc, tcp_bt_sample_t *start_bts, u32 start, u32 end,
		    tcp_bts_flags_t rxt_flags)
{
  tcp_byte_tracker_t *bt = tc->bt;
  sack_scoreboard_t *sb = &tc->sack_sb;
  tcp_bt_sample_t *bts, *next, *cur, *prev, *nbts;
  u32 bts_index, cur_index, next_index, prev_index, max_seq;
  u8 was_cur_rxt, is_end = end == tc->snd_nxt;

  /* The caller already resolved the sample while partitioning the retransmit,
   * so do not repeat the rb-tree lookup here. */
  bts = start_bts;
  ASSERT (bts != 0 && bt_rxt_flags (tc, bts) == rxt_flags && seq_geq (start, bts->min_seq));
  was_cur_rxt = bt_sample_index (bt, bts) == bt->cur_rxt;

  /* Only bytes below snd_una leave the tracker and need to be discounted. */
  if (seq_lt (bts->min_seq, tc->snd_una))
    {
      if (rxt_flags & TCP_BTS_IS_LOST)
	{
	  u32 retired = tc->snd_una - bts->min_seq;

	  ASSERT (sb->lost_bytes >= retired);
	  sb->lost_bytes -= retired;
	}
      bt_update_sample (bt, bts, tc->snd_una);
    }

  /* Head overlap */
  if (bts->min_seq == start)
    {
      prev_index = bts->prev;
      next = bt_fix_overlapped (bt, bts, end, is_end);
      /* bts might no longer be valid from here */
      next_index = bt_sample_index (bt, next);

      cur = tcp_bt_alloc_tx_sample (tc, start, end);
      cur->flags = rxt_flags;
      cur->next = next_index;
      cur->prev = prev_index;

      cur_index = bt_sample_index (bt, cur);

      if (next_index != TCP_BTS_INVALID_INDEX)
	{
	  next = bt_get_sample (bt, next_index);
	  next->prev = cur_index;
	}
      else
	{
	  bt->tail = cur_index;
	}

      if (prev_index != TCP_BTS_INVALID_INDEX)
	{
	  prev = bt_get_sample (bt, prev_index);
	  prev->next = cur_index;
	}
      else
	{
	  bt->head = cur_index;
	}

      bt->last_ooo = cur_index;
      if (was_cur_rxt)
	bt->cur_rxt = cur_index;
      return;
    }

  bts_index = bt_sample_index (bt, bts);
  next = bt_next_sample (bt, bts);
  if (next)
    bt_fix_overlapped (bt, next, end, is_end);

  max_seq = bts->max_seq;
  ASSERT (seq_lt (start, max_seq));

  /* Have to split or tail overlap */
  cur = tcp_bt_alloc_tx_sample (tc, start, end);
  cur->flags = rxt_flags;
  cur->prev = bts_index;
  cur_index = bt_sample_index (bt, cur);

  /* Split. Allocate another sample */
  if (seq_lt (end, max_seq))
    {
      nbts = tcp_bt_alloc_tx_sample (tc, end, bts->max_seq);
      cur = bt_get_sample (bt, cur_index);
      bts = bt_get_sample (bt, bts_index);

      *nbts = *bts;
      nbts->min_seq = end;

      if (nbts->next != TCP_BTS_INVALID_INDEX)
	{
	  next = bt_get_sample (bt, nbts->next);
	  next->prev = bt_sample_index (bt, nbts);
	}
      else
	bt->tail = bt_sample_index (bt, nbts);

      bts->next = nbts->prev = cur_index;
      cur->next = bt_sample_index (bt, nbts);

      bts->max_seq = start;
    }
  /* Tail completely overlapped */
  else
    {
      bts = bt_get_sample (bt, bts_index);
      bts->max_seq = start;

      if (bts->next != TCP_BTS_INVALID_INDEX)
	{
	  next = bt_get_sample (bt, bts->next);
	  next->prev = cur_index;
	}
      else
	bt->tail = cur_index;

      cur->next = bts->next;
      bts->next = cur_index;
    }

  bt->last_ooo = cur_index;
  if (was_cur_rxt)
    bt->cur_rxt = cur_index;
}

static_always_inline tcp_bt_sample_t *
bt_rxt_extend_candidate (tcp_connection_t *tc, u32 start, tcp_bt_sample_t **next)
{
  tcp_byte_tracker_t *bt = tc->bt;
  tcp_bt_sample_t *bts, *last;
  tcp_bts_flags_t rxt_flags;

  last = bt_get_sample (bt, bt->last_ooo);
  if (!last || last->max_seq != start)
    return 0;

  bts = bt_next_sample (bt, last);
  if (!bts || bts->min_seq != start || (bts->flags & TCP_BTS_IS_SACKED))
    return 0;

  rxt_flags = bt_rxt_flags (tc, bts);
  if (last->flags != rxt_flags || last->tx_time != tcp_time_now_us (tc->c_thread_index))
    return 0;

  *next = bts;
  return last;
}

static_always_inline void
bt_extend_rxt_sample (tcp_connection_t *tc, tcp_bt_sample_t *last, tcp_bt_sample_t *next, u32 end)
{
  last->max_seq = end;
  bt_fix_overlapped (tc->bt, next, end, end == tc->snd_nxt);
}

static_always_inline u8
bt_try_extend_rxt_sample (tcp_connection_t *tc, u32 start, u32 end)
{
  tcp_bt_sample_t *last, *next;

  last = bt_rxt_extend_candidate (tc, start, &next);
  if (!last || seq_gt (end, next->max_seq))
    return 0;

  bt_extend_rxt_sample (tc, last, next, end);
  return 1;
}

static u32
bt_track_rxt_ranges (tcp_connection_t *tc, u32 start, u32 end)
{
  tcp_byte_tracker_t *bt = tc->bt;
  tcp_bt_sample_t *bts, *last, *next;
  tcp_bts_flags_t rxt_flags;
  u32 range_end, tracked = 0;

  /* A retransmit can cross one or more ranges the peer already sacked. Record every unsacked
   * sub-range sent so retransmit delivery and rtt ambiguity remain byte exact. */
  while (seq_lt (start, end))
    {
      bts = bt_lookup_seq (bt, start);
      ASSERT (bts != 0 && seq_geq (start, bts->min_seq) && seq_lt (start, bts->max_seq));

      if (bts->flags & TCP_BTS_IS_SACKED)
	{
	  start = seq_min (bts->max_seq, end);
	  continue;
	}

      rxt_flags = bt_rxt_flags (tc, bts);
      range_end = bt_rxt_range_end (tc, bts, end, rxt_flags);

      ASSERT (seq_lt (start, range_end));

      /* range_end is already known to be homogeneous, so extending through
       * multiple compatible source samples needs no second boundary scan. */
      last = bt_rxt_extend_candidate (tc, start, &next);
      if (last && next == bts)
	bt_extend_rxt_sample (tc, last, bts, range_end);
      else
	bt_track_rxt_range (tc, bts, start, range_end, rxt_flags);
      tracked += range_end - start;
      start = range_end;
    }

  return tracked;
}

void
tcp_bt_track_rxt (tcp_connection_t *tc, u32 start, u32 end)
{
  u32 tracked;
  u8 track_dsack = tcp_opts_sack_permitted (&tc->rcv_opts) &&
		   !(tc->sack_sb.flags & TCP_DSACK_UNDO_DISABLED) && tcp_in_cong_recovery (tc);

  ASSERT (seq_lt (start, end));

  /* Consecutive homogeneous retransmits can extend the last sample without
   * an rb-tree lookup or a new allocation. */
  if (bt_try_extend_rxt_sample (tc, start, end))
    tracked = end - start;
  else
    tracked = bt_track_rxt_ranges (tc, start, end);

  if (track_dsack && tracked)
    {
      if (!(tc->sack_sb.flags & TCP_DSACK_HISTORY))
	{
	  tc->dsack_history_start = tc->snd_una;
	  tc->sack_sb.flags |= TCP_DSACK_HISTORY;
	}
      ASSERT (tc->dsack_pending_bytes <= (u32) ~0 - tracked);
      tc->dsack_pending_bytes += tracked;
    }
}

static void
tcp_bt_sample_to_rate_sample (tcp_connection_t *tc, tcp_bt_sample_t *bts, tcp_rate_sample_t *rs,
			      f64 now)
{
  if (bts->flags & TCP_BTS_IS_DELIVERED)
    return;

  if (rs->prior_delivered && rs->prior_delivered >= bts->delivered)
    return;

  rs->prior_delivered = bts->delivered;
  rs->prior_time = bts->delivered_time;
  rs->interval_time = bts->tx_time - bts->first_tx_time;
  rs->rtt_time = now - bts->tx_time;
  rs->flags = bts->flags;
  rs->tx_in_flight = bts->tx_in_flight;
  rs->tx_lost = bts->tx_lost;
  tc->first_tx_time = bts->tx_time;
}

static void
tcp_bt_update_reorder (tcp_connection_t *tc, tcp_bts_flags_t flags, u32 start, u32 high_sacked)
{
  sack_scoreboard_t *sb = &tc->sack_sb;
  u32 reord;

  if (!seq_lt (start, high_sacked))
    return;

  if (tcp_in_cong_recovery (tc) && (flags & TCP_BTS_IS_RXT))
    return;

  reord = (high_sacked - start + tc->snd_mss - 1) / tc->snd_mss;
  reord = clib_min (reord, TCP_MAX_SACK_REORDER);
  sb->reorder = clib_max (sb->reorder, reord);
}

static_always_inline void
tcp_bt_update_rxt_delivered (tcp_connection_t *tc, tcp_rate_sample_t *rs, tcp_bts_flags_t flags,
			     u32 start, u32 end)
{
  u32 high_rxt = tc->sack_sb.high_rxt;

  if (!(flags & TCP_BTS_IS_RXT) || !tcp_in_cong_recovery (tc) || seq_geq (start, high_rxt))
    return;

  rs->rxt_sacked += seq_min (end, high_rxt) - start;
}

static void
tcp_bt_walk_samples (tcp_connection_t *tc, u32 ack, tcp_rate_sample_t *rs, f64 now, u32 high_sacked,
		     u8 account)
{
  tcp_byte_tracker_t *bt = tc->bt;
  tcp_bt_sample_t *next, *cur;

  cur = bt_get_sample (bt, bt->head);
  while (cur && seq_leq (cur->max_seq, ack))
    {
      next = bt_next_sample (bt, cur);
      if (account)
	{
	  u32 len = cur->max_seq - cur->min_seq;
	  if (!(cur->flags & TCP_BTS_IS_SACKED))
	    {
	      tcp_bt_update_reorder (tc, cur->flags, cur->min_seq, high_sacked);
	      tcp_bt_update_rxt_delivered (tc, rs, cur->flags, cur->min_seq, cur->max_seq);
	      if (cur->flags & TCP_BTS_IS_DELIVERED)
		rs->last_bytes_delivered += len;
	    }
	  else
	    {
	      rs->last_bytes_delivered += len;
	      tc->sack_sb.sacked_bytes -= len;
	    }
	  if (cur->flags & TCP_BTS_IS_LOST)
	    tc->sack_sb.lost_bytes -= len;
	}
      tcp_bt_sample_to_rate_sample (tc, cur, rs, now);
      bt_free_sample (bt, cur);
      cur = next;
    }

  if (cur && seq_lt (cur->min_seq, ack))
    {
      u32 len = ack - cur->min_seq;
      tcp_bt_sample_t *acked = cur;
      if (account)
	{
	  if (!(acked->flags & TCP_BTS_IS_SACKED))
	    {
	      tcp_bt_update_reorder (tc, acked->flags, acked->min_seq, high_sacked);
	      tcp_bt_update_rxt_delivered (tc, rs, acked->flags, acked->min_seq, ack);
	      if (acked->flags & TCP_BTS_IS_DELIVERED)
		rs->last_bytes_delivered += len;
	    }
	  else
	    {
	      rs->last_bytes_delivered += len;
	      tc->sack_sb.sacked_bytes -= len;
	    }
	  if (acked->flags & TCP_BTS_IS_LOST)
	    tc->sack_sb.lost_bytes -= len;
	}
      tcp_bt_sample_to_rate_sample (tc, acked, rs, now);
      bt_update_sample (bt, cur, ack);
    }
}

static void
tcp_bt_walk_samples_ooo (tcp_connection_t *tc, tcp_rate_sample_t *rs, f64 now, u32 ack,
			 u32 high_sacked)
{
  sack_block_t *blks = tc->rcv_opts.sacks, *blk;
  tcp_byte_tracker_t *bt = tc->bt;
  tcp_bt_sample_t *cur, *prev, *next;
  int i;

  for (i = 0; i < vec_len (blks); i++)
    {
      blk = &blks[i];

      /* The prefix walk already retired cumulative ack coverage. */
      if (seq_leq (blk->end, ack))
	continue;

      cur = bt_lookup_seq (bt, blk->start);
      if (!cur)
	continue;

      ASSERT (seq_geq (blk->start, cur->min_seq)
	      && seq_lt (blk->start, cur->max_seq));

      /* Split current if block starts in new sack coverage. Second part will be consumed */
      if (PREDICT_FALSE (cur->min_seq != blk->start) && !(cur->flags & TCP_BTS_IS_SACKED))
	{
	  cur = bt_split_sample (bt, cur, blk->start);
	  prev = bt_prev_sample (bt, cur);
	}
      else
	prev = bt_prev_sample (bt, cur);

      while (cur && seq_leq (cur->max_seq, blk->end))
	{
	  if (!(cur->flags & TCP_BTS_IS_SACKED))
	    {
	      u32 len = cur->max_seq - cur->min_seq;
	      tcp_bt_update_reorder (tc, cur->flags, cur->min_seq, high_sacked);
	      tc->sack_sb.sacked_bytes += len;
	      rs->last_sacked_bytes += len;
	      if (cur->flags & TCP_BTS_IS_DELIVERED)
		rs->last_bytes_delivered += len;
	      if (cur->flags & TCP_BTS_IS_LOST)
		tc->sack_sb.lost_bytes -= len;
	      tcp_bt_update_rxt_delivered (tc, rs, cur->flags, cur->min_seq, cur->max_seq);
	      tcp_bt_sample_to_rate_sample (tc, cur, rs, now);
	      cur->flags &= ~TCP_BTS_IS_LOST;
	      cur->flags |= TCP_BTS_IS_SACKED | TCP_BTS_IS_DELIVERED;
	      if (prev && (prev->flags & TCP_BTS_IS_SACKED) &&
		  bt_sacked_samples_can_merge (prev, cur))
		cur = bt_merge_sample (bt, prev, cur);

	      next = bt_next_sample (bt, cur);
	      if (next && (next->flags & TCP_BTS_IS_SACKED) &&
		  bt_sacked_samples_can_merge (cur, next))
		{
		  cur = bt_merge_sample (bt, cur, next);
		  next = bt_next_sample (bt, cur);
		}
	    }
	  else
	    next = bt_next_sample (bt, cur);

	  prev = cur;
	  cur = next;
	}

      if (cur && seq_lt (cur->min_seq, blk->end))
	{
	  if (cur->flags & TCP_BTS_IS_SACKED)
	    continue;

	  u32 len = blk->end - cur->min_seq;
	  tcp_bt_update_reorder (tc, cur->flags, cur->min_seq, high_sacked);
	  tc->sack_sb.sacked_bytes += len;
	  rs->last_sacked_bytes += len;
	  if (cur->flags & TCP_BTS_IS_DELIVERED)
	    rs->last_bytes_delivered += len;
	  if (cur->flags & TCP_BTS_IS_LOST)
	    tc->sack_sb.lost_bytes -= len;
	  tcp_bt_update_rxt_delivered (tc, rs, cur->flags, cur->min_seq, blk->end);
	  tcp_bt_sample_to_rate_sample (tc, cur, rs, now);
	  next = bt_split_sample (bt, cur, blk->end);
	  cur = bt_prev_sample (bt, next);
	  cur->flags &= ~TCP_BTS_IS_LOST;
	  cur->flags |= TCP_BTS_IS_SACKED | TCP_BTS_IS_DELIVERED;

	  prev = bt_prev_sample (bt, cur);
	  if (prev && (prev->flags & TCP_BTS_IS_SACKED) && bt_sacked_samples_can_merge (prev, cur))
	    {
	      bt_merge_sample (bt, prev, cur);
	    }
	}
    }
}

static_always_inline u32
tcp_bt_data_acked (tcp_connection_t *tc, tcp_rate_sample_t *rs)
{
  u32 ack_end, data_end, prev_una;

  if (PREDICT_TRUE (!(tc->flags & TCP_CONN_FINSNT)))
    return rs->bytes_acked;

  data_end = tc->snd_nxt - 1;
  prev_una = tc->snd_una - rs->bytes_acked;
  ack_end = seq_lt (tc->snd_una, data_end) ? tc->snd_una : data_end;
  return seq_gt (ack_end, prev_una) ? ack_end - prev_una : 0;
}

/* Advance the RFC 6675 loss boundary after new SACK coverage. Samples below
 * sack_loss_high were already classified on an earlier ACK, so only the
 * evidence above the next candidate and the newly exposed interval need to
 * be walked. RTO loss does not advance this boundary. */
static void
tcp_bt_update_sack_loss (tcp_connection_t *tc, tcp_rate_sample_t *rs)
{
  tcp_byte_tracker_t *bt = tc->bt;
  tcp_bt_sample_t *cur;
  sack_scoreboard_t *sb = &tc->sack_sb;
  u32 sacked = 0, newly_lost = 0, blocks = 0, old_loss_high;
  u32 loss_thresh = (sb->reorder - 1) * tc->snd_mss;
  u8 in_sacked = 0;

  ASSERT (seq_gt (sb->high_sacked, tc->snd_una));
  cur = bt_lookup_seq (bt, sb->high_sacked - 1);
  ASSERT (cur && seq_lt (sb->high_sacked - 1, cur->max_seq));
  while (cur && seq_gt (cur->max_seq, bt->sack_loss_high))
    {
      if (cur->flags & TCP_BTS_IS_SACKED)
	{
	  sacked += cur->max_seq - cur->min_seq;
	  if (!in_sacked)
	    blocks++;
	  in_sacked = 1;
	}
      else
	{
	  in_sacked = 0;
	  if (sacked > loss_thresh || blocks >= sb->reorder)
	    break;
	}

      cur = bt_prev_sample (bt, cur);
    }

  if (!cur || seq_leq (cur->max_seq, bt->sack_loss_high))
    return;

  old_loss_high = bt->sack_loss_high;
  bt->sack_loss_high = cur->max_seq;
  while (cur && seq_gt (cur->max_seq, old_loss_high))
    {
      if (!(cur->flags & (TCP_BTS_IS_SACKED | TCP_BTS_IS_LOST)))
	{
	  cur->flags |= TCP_BTS_IS_LOST;
	  newly_lost += cur->max_seq - cur->min_seq;
	}
      cur = bt_prev_sample (bt, cur);
    }

  sb->lost_bytes += newly_lost;
  if (rs)
    rs->last_lost += newly_lost;
}

void
tcp_bt_apply_sacks (tcp_connection_t *tc, u32 ack, u32 high_sacked, u8 has_sack,
		    tcp_rate_sample_t *rs)
{
  tcp_byte_tracker_t *bt = tc->bt;
  sack_scoreboard_t *sb = &tc->sack_sb;
  tcp_bt_sample_t *head;
  u32 old_high_sacked;
  f64 now;

  rs->ack_flags |= TCP_ACK_F_BT_PROCESSED;
  now = tcp_time_now_us (tc->c_thread_index);
  old_high_sacked =
    (sb->sacked_bytes || tcp_scoreboard_is_reneging (sb)) ? sb->high_sacked : tc->snd_una;

  if (seq_gt (ack, tc->snd_una))
    {
      tcp_bt_walk_samples (tc, ack, rs, now, old_high_sacked, 1 /* account */);
      bt->sack_loss_high = seq_max (bt->sack_loss_high, ack);
    }

  sb->high_sacked = high_sacked;
  if (PREDICT_FALSE (has_sack))
    {
      /* SACK processing can split ranges or change their loss classification. */
      bt->cur_rxt_end = sb->high_rxt;
      tcp_bt_walk_samples_ooo (tc, rs, now, ack, old_high_sacked);
      /* Prefix retirement keeps both aggregates exact. Without new sack
       * coverage, no remaining range can acquire a new loss classification. */
      if (rs->last_sacked_bytes)
	tcp_bt_update_sack_loss (tc, rs);
    }

  /* A cumulative-only ACK already updated the aggregates while retiring its
   * prefix. Only the head is needed to detect that prior SACK state reneged. */
  head = bt_get_sample (bt, bt->head);
  tcp_scoreboard_set_reneging (sb, head && (head->flags & TCP_BTS_IS_SACKED));
}

void
tcp_bt_recompute_sack_loss (tcp_connection_t *tc)
{
  tcp_byte_tracker_t *bt = tc->bt;
  tcp_bt_sample_t *cur;
  sack_scoreboard_t *sb = &tc->sack_sb;
  u32 sacked = 0;

  bt->cur_rxt_end = sb->high_rxt;
  bt->sack_loss_high = tc->snd_una;
  cur = bt_get_sample (bt, bt->head);
  while (cur)
    {
      cur->flags &= ~TCP_BTS_IS_LOST;
      if (cur->flags & TCP_BTS_IS_SACKED)
	sacked += cur->max_seq - cur->min_seq;
      cur = bt_next_sample (bt, cur);
    }

  ASSERT (sacked == sb->sacked_bytes);
  sb->lost_bytes = 0;
  if (sacked)
    tcp_bt_update_sack_loss (tc, 0);
}

void
tcp_bt_init_rxt (tcp_connection_t *tc, u32 snd_una)
{
  tcp_byte_tracker_t *bt = tc->bt;
  tcp_bt_sample_t *cur;

  cur = bt_get_sample (bt, bt->head);
  while (cur && (cur->flags & TCP_BTS_IS_SACKED))
    cur = bt_next_sample (bt, cur);
  if (cur)
    {
      snd_una = seq_max (snd_una, cur->min_seq);
      bt->cur_rxt = bt_sample_index (bt, cur);
    }
  else
    bt->cur_rxt = TCP_BTS_INVALID_INDEX;

  tc->sack_sb.high_rxt = snd_una;
  bt->cur_rxt_end = snd_una;
  tc->sack_sb.rescue_rxt = snd_una - 1;
}

void
tcp_bt_rxt_mark_lost (tcp_connection_t *tc)
{
  tcp_byte_tracker_t *bt = tc->bt;
  tcp_bt_sample_t *cur;
  sack_scoreboard_t *sb = &tc->sack_sb;

  bt->cur_rxt_end = sb->high_rxt;

  cur = bt_get_sample (bt, bt->head);
  while (cur && (cur->flags & TCP_BTS_IS_SACKED))
    cur = bt_next_sample (bt, cur);

  while (cur && !(cur->flags & TCP_BTS_IS_SACKED))
    {
      if (!(cur->flags & TCP_BTS_IS_LOST))
	{
	  cur->flags |= TCP_BTS_IS_LOST;
	  sb->lost_bytes += cur->max_seq - cur->min_seq;
	}
      cur = bt_next_sample (bt, cur);
    }
}

u8
tcp_bt_handle_sack_reneging (tcp_connection_t *tc)
{
  tcp_byte_tracker_t *bt = tc->bt;
  tcp_bt_sample_t *cur;
  sack_scoreboard_t *sb = &tc->sack_sb;
  u32 lost = 0;

  cur = bt_get_sample (bt, bt->head);
  if (!tcp_scoreboard_is_reneging (sb) && (!cur || !(cur->flags & TCP_BTS_IS_SACKED)))
    return 0;

  while (cur)
    {
      cur->flags &= ~TCP_BTS_IS_SACKED;
      cur->flags |= TCP_BTS_IS_LOST;
      lost += cur->max_seq - cur->min_seq;
      cur = bt_next_sample (bt, cur);
    }

  sb->sacked_bytes = 0;
  sb->lost_bytes = lost;
  sb->high_sacked = tc->snd_una;
  tcp_scoreboard_set_reneging (sb, 0);
  sb->reorder = TCP_DUPACK_THRESHOLD;
  bt->sack_loss_high = tc->snd_una;
  tcp_bt_init_rxt (tc, tc->snd_una);
  return 1;
}

u8
tcp_bt_is_sane_post_recovery (tcp_connection_t *tc)
{
  tcp_byte_tracker_t *bt = tc->bt;
  tcp_bt_sample_t *cur;
  u32 lost = 0, sacked = 0;

  cur = bt_get_sample (bt, bt->head);
  if (cur && seq_lt (cur->min_seq, tc->snd_una))
    return 0;

  while (cur)
    {
      u32 len = cur->max_seq - cur->min_seq;
      if (seq_gt (cur->max_seq, tc->snd_nxt))
	return 0;
      if (seq_lt (cur->min_seq, bt->sack_loss_high) &&
	  !(cur->flags & (TCP_BTS_IS_SACKED | TCP_BTS_IS_LOST)))
	return 0;
      if (cur->flags & TCP_BTS_IS_SACKED)
	sacked += len;
      else if (cur->flags & TCP_BTS_IS_LOST)
	lost += len;
      cur = bt_next_sample (bt, cur);
    }

  return sacked == tc->sack_sb.sacked_bytes && lost == tc->sack_sb.lost_bytes;
}

static u8
bt_next_rxt_range (tcp_byte_tracker_t *bt, tcp_bt_sample_t *cur, tcp_rxt_range_t *range,
		   tcp_bt_sample_t **range_start, tcp_bt_sample_t **next_range)
{
  tcp_bt_sample_t *next;
  tcp_bts_flags_t lost;

  while (cur && (cur->flags & TCP_BTS_IS_SACKED))
    cur = bt_next_sample (bt, cur);
  if (!cur)
    {
      *range_start = 0;
      *next_range = 0;
      return 0;
    }

  *range_start = cur;
  lost = cur->flags & TCP_BTS_IS_LOST;
  range->start = cur->min_seq;
  range->end = cur->max_seq;
  range->is_lost = !!lost;

  next = bt_next_sample (bt, cur);
  while (next && (next->flags & (TCP_BTS_IS_SACKED | TCP_BTS_IS_LOST)) == lost)
    {
      range->end = next->max_seq;
      next = bt_next_sample (bt, next);
    }
  *next_range = next;
  return 1;
}

u8
tcp_bt_next_rxt_range (tcp_connection_t *tc, u8 have_unsent, u8 *can_rescue, u8 *snd_limited,
		       tcp_rxt_range_t *range)
{
  tcp_byte_tracker_t *bt = tc->bt;
  sack_scoreboard_t *sb = &tc->sack_sb;
  tcp_bt_sample_t *cur, *next, *range_start;

  cur = bt_get_sample (bt, bt->cur_rxt);
  /* Range and loss-classification mutations invalidate cur_rxt_end by
   * resetting it to high_rxt. A greater value therefore denotes a valid
   * cached range end. */
  if (cur && seq_gt (bt->cur_rxt_end, sb->high_rxt))
    {
      range->start = cur->min_seq;
      range->end = bt->cur_rxt_end;
      range->is_lost = !!(cur->flags & TCP_BTS_IS_LOST);
    }
  else
    {
      if (!cur)
	cur = bt_get_sample (bt, bt->head);
      while (cur)
	{
	  if (!bt_next_rxt_range (bt, cur, range, &range_start, &next))
	    {
	      bt->cur_rxt = TCP_BTS_INVALID_INDEX;
	      bt->cur_rxt_end = sb->high_rxt;
	      return 0;
	    }
	  cur = range_start;
	  /* Rule (1) only considers lost ranges with data above HighRxt. */
	  if (!range->is_lost || seq_gt (range->end, sb->high_rxt))
	    break;
	  cur = next;
	}
    }

  if (!cur)
    {
      bt->cur_rxt = TCP_BTS_INVALID_INDEX;
      bt->cur_rxt_end = sb->high_rxt;
      return 0;
    }
  /* Apply the RFC 6675 Section 4 NextSeg rules to the range derived from
   * byte-tracker samples. Rule (1), a lost range below HighACK, takes
   * precedence. If it does not apply, evaluate Rules (2)-(4). */
  if (!(range->is_lost && seq_lt (range->start, sb->high_sacked)))
    {
      /* Rule (2): prefer available unsent data. */
      if (have_unsent)
	{
	  bt->cur_rxt = TCP_BTS_INVALID_INDEX;
	  bt->cur_rxt_end = sb->high_rxt;
	  return 0;
	}

      /* Rule (3): retransmit an unsacked range below HighACK that has data
       * above HighRxt. */
      if (seq_lt (range->start, sb->high_sacked))
	{
	  if (seq_leq (range->end, sb->high_rxt))
	    {
	      bt->cur_rxt = TCP_BTS_INVALID_INDEX;
	      bt->cur_rxt_end = sb->high_rxt;
	      return 0;
	    }
	  *snd_limited = 0;
	}
      /* Rule (4): request a rescue retransmission for the range at or above
       * HighACK. HighRxt MUST NOT be updated. */
      else
	{
	  ASSERT (seq_geq (range->start, sb->high_sacked));
	  *snd_limited = 1;
	  *can_rescue = 1;
	  return 0;
	}
    }

  /* Rules (1) and (3) only reach here with data above HighRxt. */
  bt->cur_rxt = bt_sample_index (bt, cur);
  bt->cur_rxt_end = range->end;
  if (seq_lt (sb->high_rxt, range->start))
    sb->high_rxt = range->start;
  range->start = sb->high_rxt;
  ASSERT (seq_lt (range->start, range->end));
  return 1;
}

u8
tcp_bt_last_rxt_range (tcp_connection_t *tc, tcp_rxt_range_t *range)
{
  tcp_byte_tracker_t *bt = tc->bt;
  tcp_bt_sample_t *cur, *prev;
  tcp_bts_flags_t lost;

  cur = bt_get_sample (bt, bt->tail);
  while (cur && (cur->flags & TCP_BTS_IS_SACKED))
    cur = bt_prev_sample (bt, cur);
  if (!cur)
    return 0;

  lost = cur->flags & TCP_BTS_IS_LOST;
  range->start = cur->min_seq;
  range->end = cur->max_seq;
  range->is_lost = !!lost;

  prev = bt_prev_sample (bt, cur);
  while (prev && (prev->flags & (TCP_BTS_IS_SACKED | TCP_BTS_IS_LOST)) == lost)
    {
      range->start = prev->min_seq;
      prev = bt_prev_sample (bt, prev);
    }
  return 1;
}

u32
tcp_bt_dsack_mark_duplicate (tcp_connection_t *tc, u32 start, u32 end)
{
  tcp_byte_tracker_t *bt = tc->bt;
  tcp_bt_sample_t *bts = 0;
  u32 matched = 0;
  u32 active_start = start, overlap_start, overlap_end;

  /* ACKed samples are no longer retained. Match their D-SACK evidence
   * against the recovery boundary and account it with the aggregate. */
  if (seq_lt (active_start, tc->snd_una))
    {
      overlap_end = seq_min (end, tc->snd_una);
      overlap_start = seq_max (active_start, tc->dsack_history_start);
      if (seq_lt (overlap_start, overlap_end))
	{
	  matched += overlap_end - overlap_start;
	}
      active_start = overlap_end;
    }

  if (seq_lt (active_start, end))
    bts = bt_lookup_seq (bt, active_start);

  while (bts && seq_lt (bts->min_seq, end))
    {
      overlap_start = seq_max (active_start, bts->min_seq);
      overlap_end = seq_min (end, bts->max_seq);

      if (seq_lt (overlap_start, overlap_end) && (bts->flags & TCP_BTS_IS_RXT))
	{
	  matched += overlap_end - overlap_start;
	}
      bts = bt_next_sample (bt, bts);
    }

  return matched;
}

void
tcp_bt_dsack_recovery_init (tcp_connection_t *tc)
{
  tcp_byte_tracker_t *bt = tc->bt;
  tcp_bt_sample_t *bts;
  u32 start;

  if (!tcp_opts_sack_permitted (&tc->rcv_opts) || (tc->sack_sb.flags & TCP_DSACK_UNDO_DISABLED))
    return;

  bts = bt_get_sample (bt, bt->head);
  while (bts)
    {
      if ((bts->flags & (TCP_BTS_IS_RXT | TCP_BTS_IS_SACKED | TCP_BTS_IS_DELIVERED)) ==
	  TCP_BTS_IS_RXT)
	{
	  start = seq_max (bts->min_seq, tc->snd_una);
	  if (seq_lt (start, bts->max_seq))
	    tc->dsack_pending_bytes += bts->max_seq - start;
	}
      bts = bt_next_sample (bt, bts);
    }

  if (tc->dsack_pending_bytes)
    {
      tc->dsack_history_start = tc->snd_una;
      tc->sack_sb.flags |= TCP_DSACK_HISTORY;
    }
}

void
tcp_bt_dsack_recovery_clear (tcp_connection_t *tc)
{
  tc->dsack_rxt = 0;
  tc->dsack_pending_bytes = 0;
  tc->sack_sb.flags &= TCP_SCOREBOARD_F_RENEGING | TCP_DSACK_UNDO_DISABLED;
}

static void
tcp_bt_process_ack (tcp_connection_t *tc, tcp_rate_sample_t *rs, u32 data_acked)
{
  tcp_byte_tracker_t *bt = tc->bt;
  sack_scoreboard_t *sb = &tc->sack_sb;
  tcp_bt_sample_t *head;
  u32 old_high_sacked, prev_una;
  u8 account;
  f64 now;

  account = tcp_opts_sack_permitted (&tc->rcv_opts) != 0;
  if (!(data_acked || (account && rs->bytes_acked)))
    return;

  now = tcp_time_now_us (tc->c_thread_index);
  prev_una = tc->snd_una - rs->bytes_acked;
  old_high_sacked =
    (sb->sacked_bytes || tcp_scoreboard_is_reneging (sb)) ? sb->high_sacked : prev_una;

  tcp_bt_walk_samples (tc, tc->snd_una, rs, now, old_high_sacked, account);
  if (account)
    {
      bt->sack_loss_high = seq_max (bt->sack_loss_high, tc->snd_una);
      sb->high_sacked = seq_max (old_high_sacked, tc->snd_una);
      head = bt_get_sample (bt, bt->head);
      tcp_scoreboard_set_reneging (sb, head && (head->flags & TCP_BTS_IS_SACKED));
    }
}

void
tcp_bt_sample_delivery_rate (tcp_connection_t * tc, tcp_rate_sample_t * rs)
{
  u32 delivered, data_acked;
  f64 now;

  /* Deferred accounting and delivery use the same ACK state. */
  data_acked = tcp_bt_data_acked (tc, rs);

  /* If SACK processing did not walk the tracker, process the cumulative ACK
   * here after snd_una and bytes_acked have been updated. */
  if (!(rs->ack_flags & TCP_ACK_F_BT_PROCESSED))
    tcp_bt_process_ack (tc, rs, data_acked);

  tc->lost += rs->last_lost;

  delivered = data_acked + rs->last_sacked_bytes;
  delivered -= rs->last_bytes_delivered;

  if (!delivered)
    goto done;

  now = tcp_time_now_us (tc->c_thread_index);
  tc->delivered += delivered;
  tc->delivered_time = now;

  if (tc->app_limited && tc->delivered > tc->app_limited)
    tc->app_limited = 0;

  rs->interval_time = clib_max ((tc->delivered_time - rs->prior_time),
				rs->interval_time);
  rs->delivered = tc->delivered - rs->prior_delivered;

done:
  rs->acked_and_sacked = delivered;
  rs->lost = tc->lost - rs->tx_lost;
}

void
tcp_bt_flush_samples (tcp_connection_t * tc)
{
  tcp_byte_tracker_t *bt = tc->bt;
  tcp_bt_sample_t *bts, *next;

  ASSERT (pool_elts (bt->samples) != 0);

  bts = bt_get_sample (bt, bt->head);
  while (bts)
    {
      next = bt_next_sample (bt, bts);
      bt_free_sample (bt, bts);
      bts = next;
    }
  tcp_bt_dsack_recovery_clear (tc);
}

void
tcp_bt_cleanup (tcp_connection_t * tc)
{
  tcp_byte_tracker_t *bt = tc->bt;

  tc->dsack_rxt = 0;
  tc->dsack_pending_bytes = 0;
  tc->sack_sb.flags &= TCP_SCOREBOARD_F_RENEGING | TCP_DSACK_UNDO_DISABLED;
  rb_tree_free_nodes (&bt->sample_lookup);
  pool_free (bt->samples);
  clib_mem_free (bt);
  tc->bt = 0;
  tc->cfg_flags &= ~TCP_CFG_F_BYTE_TRACKER;
}

void
tcp_bt_init (tcp_connection_t * tc)
{
  tcp_byte_tracker_t *bt;

  bt = clib_mem_alloc (sizeof (tcp_byte_tracker_t));
  clib_memset (bt, 0, sizeof (tcp_byte_tracker_t));

  rb_tree_init (&bt->sample_lookup);
  bt->head = bt->tail = TCP_BTS_INVALID_INDEX;
  bt->last_ooo = TCP_BTS_INVALID_INDEX;
  bt->cur_rxt = TCP_BTS_INVALID_INDEX;
  bt->cur_rxt_end = tc->snd_una;
  bt->sack_loss_high = tc->snd_una;
  tc->sack_sb.high_sacked = tc->snd_una;
  tc->bt = bt;
  tc->cfg_flags |= TCP_CFG_F_BYTE_TRACKER;
}

int
tcp_bt_enable (tcp_connection_t *tc, u8 enable)
{
  bool is_enabled = tc->cfg_flags & TCP_CFG_F_BYTE_TRACKER;

  if (!!enable == is_enabled)
    return 0;
  if (tc->snd_una != tc->snd_nxt)
    return -1;

  if (enable)
    {
      tcp_dsack_cleanup (tc);
      tcp_bt_init (tc);
    }
  else
    tcp_bt_cleanup (tc);
  return 0;
}

u8 *
format_tcp_bt_sample (u8 * s, va_list * args)
{
  tcp_connection_t *tc = va_arg (*args, tcp_connection_t *);
  tcp_bt_sample_t *bts = va_arg (*args, tcp_bt_sample_t *);
  f64 now = tcp_time_now_us (tc->c_thread_index);
  s = format (s, "[%u, %u] d %u dt %.3f txt %.3f ftxt %.3f flags 0x%x",
	      bts->min_seq - tc->iss, bts->max_seq - tc->iss, bts->delivered,
	      now - bts->delivered_time, now - bts->tx_time,
	      now - bts->first_tx_time, bts->flags);
  return s;
}

u8 *
format_tcp_bt (u8 * s, va_list * args)
{
  tcp_connection_t *tc = va_arg (*args, tcp_connection_t *);
  tcp_byte_tracker_t *bt = tc->bt;
  tcp_bt_sample_t *bts;

  bts = bt_get_sample (bt, bt->head);
  while (bts)
    {
      s = format (s, "%U\n", format_tcp_bt_sample, tc, bts);
      bts = bt_next_sample (bt, bts);
    }

  return s;
}

u8 *
format_tcp_bt_stats (u8 *s, va_list *args)
{
  tcp_connection_t *tc = va_arg (*args, tcp_connection_t *);
  tcp_byte_tracker_t *bt = tc->bt;
  u32 indent = format_get_indent (s);

  s = format (s, "delivered %lu lost %lu app-limited %s\n", tc->delivered, tc->lost,
	      tc->app_limited ? "yes" : "no");
  s = format (s, "%Usamples active %u", format_white_space, indent, pool_elts (bt->samples));
  return s;
}
