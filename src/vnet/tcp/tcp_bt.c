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
#include <vnet/tcp/tcp_rack.h>

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
bt_unlink_sample (tcp_byte_tracker_t *bt, tcp_bt_sample_t *bts)
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
}

static void
bt_free_sample (tcp_byte_tracker_t *bt, tcp_bt_sample_t *bts)
{
  bt_unlink_sample (bt, bts);
  bt->dsack_fragments -= !!(bts->flags & TCP_BTS_DSACK_TRACKED);
  if (CLIB_DEBUG)
    memset (bts, 0xfc, sizeof (*bts));
  pool_put (bt->samples, bts);
}

static void
bt_retire_sample (tcp_byte_tracker_t *bt, tcp_bt_sample_t *bts)
{
  tcp_bt_sample_t *tail;
  u32 bts_index = bt_sample_index (bt, bts);

  bt_unlink_sample (bt, bts);
  bts->next = TCP_BTS_INVALID_INDEX;
  bts->prev = bt->dsack_tail;

  tail = bt_get_sample (bt, bt->dsack_tail);
  if (tail)
    tail->next = bts_index;
  else
    bt->dsack_head = bts_index;
  bt->dsack_tail = bts_index;
}

static void
bt_free_retired_sample (tcp_byte_tracker_t *bt, tcp_bt_sample_t *bts)
{
  tcp_bt_sample_t *next, *prev;

  next = bt_get_sample (bt, bts->next);
  prev = bt_get_sample (bt, bts->prev);
  if (next)
    next->prev = bts->prev;
  else
    bt->dsack_tail = bts->prev;
  if (prev)
    prev->next = bts->next;
  else
    bt->dsack_head = bts->next;

  bt->dsack_fragments -= !!(bts->flags & TCP_BTS_DSACK_TRACKED);
  if (CLIB_DEBUG)
    memset (bts, 0xfc, sizeof (*bts));
  pool_put (bt->samples, bts);
}

static void
bt_free_retired_samples (tcp_byte_tracker_t *bt)
{
  tcp_bt_sample_t *cur, *next;

  cur = bt_get_sample (bt, bt->dsack_head);
  while (cur)
    {
      next = bt_get_sample (bt, cur->next);
      bt_free_retired_sample (bt, cur);
      cur = next;
    }
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
  bt->dsack_fragments += !!(ns->flags & TCP_BTS_DSACK_TRACKED);

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
  u32 active = 0, retired = 0, dsack_fragments = 0;

  if (bt->head == TCP_BTS_INVALID_INDEX)
    {
      if (bt->tail != TCP_BTS_INVALID_INDEX)
	return 0;
    }
  else
    {
      bts = bt_get_sample (bt, bt->tail);
      if (!bts)
	return 0;

      bts = bt_get_sample (bt, bt->head);
      if (!bts || bts->prev != TCP_BTS_INVALID_INDEX)
	return 0;

      while (bts)
	{
	  active++;
	  dsack_fragments += !!(bts->flags & TCP_BTS_DSACK_TRACKED);
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
    }

  bts = bt_get_sample (bt, bt->dsack_head);
  if (bts && bts->prev != TCP_BTS_INVALID_INDEX)
    return 0;
  while (bts)
    {
      retired++;
      dsack_fragments++;
      if (!(bts->flags & TCP_BTS_DSACK_TRACKED))
	return 0;
      tmp = bt_get_sample (bt, bts->next);
      if (tmp && tmp->prev != bt_sample_index (bt, bts))
	return 0;
      if (!tmp && bt->dsack_tail != bt_sample_index (bt, bts))
	return 0;
      bts = tmp;
    }

  if (active != pool_elts (bt->sample_lookup.nodes) - 1)
    return 0;
  if (active + retired != pool_elts (bt->samples))
    return 0;
  if (dsack_fragments != bt->dsack_fragments)
    return 0;

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

static void
bt_dsack_clear_ranges (tcp_connection_t *tc)
{
  tcp_byte_tracker_t *bt = tc->bt;
  tcp_bt_sample_t *cur;

  cur = bt_get_sample (bt, bt->head);
  while (cur)
    {
      cur->flags &= ~(TCP_BTS_DSACK_TRACKED | TCP_BTS_DSACK_DUPLICATE);
      cur = bt_next_sample (bt, cur);
    }
  bt_free_retired_samples (bt);
  bt->dsack_rxt_bytes = 0;
  bt->dsack_dup_bytes = 0;
  bt->dsack_rxt_ranges = 0;
  bt->dsack_fragments = 0;
  bt->dsack_high = 0;
}

static void
bt_dsack_abandon_history (tcp_connection_t *tc)
{
  bt_dsack_clear_ranges (tc);
  tc->dsack_flags |= TCP_DSACK_INELIGIBLE | TCP_DSACK_RXT_OVERFLOW;
}

static_always_inline u8
bt_dsack_can_split (tcp_connection_t *tc, u32 n_splits)
{
  if (tc->bt->dsack_fragments <= TCP_MAX_DSACK_RXT_RANGES - n_splits)
    return 1;

  bt_dsack_abandon_history (tc);
  return 0;
}

static u8
bt_dsack_track_retransmit (tcp_connection_t *tc, u32 start, u32 end, u8 overlaps)
{
  tcp_byte_tracker_t *bt = tc->bt;

  if (tc->dsack_flags & TCP_DSACK_RXT_OVERFLOW)
    return 0;

  if (overlaps)
    tc->dsack_flags |= TCP_DSACK_INELIGIBLE;

  if (!bt->dsack_rxt_bytes || start != bt->dsack_high)
    {
      if (bt->dsack_rxt_ranges == TCP_MAX_DSACK_RXT_RANGES ||
	  bt->dsack_fragments == TCP_MAX_DSACK_RXT_RANGES)
	{
	  bt_dsack_abandon_history (tc);
	  return 0;
	}
      bt->dsack_rxt_ranges++;
    }

  if (!overlaps)
    bt->dsack_rxt_bytes += end - start;
  bt->dsack_high = end;
  return 1;
}

static_always_inline void
bt_dsack_track_sample (tcp_byte_tracker_t *bt, tcp_bt_sample_t *bts)
{
  if (!(bts->flags & TCP_BTS_DSACK_TRACKED))
    {
      bts->flags |= TCP_BTS_DSACK_TRACKED;
      bt->dsack_fragments++;
    }
}

static u32
tcp_bt_rxt_bytes_in_range (tcp_connection_t *tc, u32 start, u32 end)
{
  tcp_byte_tracker_t *bt = tc->bt;
  tcp_bt_sample_t *bts;
  u32 sample_start, sample_end, bytes = 0;

  bts = bt_lookup_seq (bt, start);
  while (bts && seq_lt (bts->min_seq, end))
    {
      if ((bts->flags & TCP_BTS_IS_RXT) && !(bts->flags & (TCP_BTS_RACK_LOST | TCP_BTS_IS_SACKED)))
	{
	  sample_start = seq_gt (bts->min_seq, start) ? bts->min_seq : start;
	  sample_end = seq_lt (bts->max_seq, end) ? bts->max_seq : end;
	  if (seq_lt (sample_start, sample_end))
	    bytes += sample_end - sample_start;
	}
      bts = bt_next_sample (bt, bts);
    }

  return bytes;
}

void
tcp_bt_rack_sync_rxt_delivery (tcp_connection_t *tc)
{
  tcp_rack_state_t *rack = tcp_rack_get_state (tc);

  ASSERT (tc->bt);
  ASSERT (rack->rxt_in_flight <= tc->snd_rxt_bytes);
  tc->rxt_delivered = tc->snd_rxt_bytes - rack->rxt_in_flight;
}

static_always_inline void
tcp_bt_account_rxt_departed (tcp_connection_t *tc, u32 departed)
{
  if (!departed || !tcp_in_cong_recovery (tc))
    return;

  ASSERT (tc->rxt_delivered + departed <= tc->snd_rxt_bytes);
  tc->rxt_delivered += departed;
}

u32
tcp_bt_rack_sample_mark_lost (tcp_connection_t *tc, tcp_bt_sample_t *bts)
{
  tcp_rack_state_t *rack = tcp_rack_get_state (tc);
  u32 departed = 0;

  if (bts->flags & TCP_BTS_RACK_LOST)
    return 0;

  if ((bts->flags & TCP_BTS_IS_RXT) && !(bts->flags & TCP_BTS_IS_SACKED))
    {
      departed = bts->max_seq - bts->min_seq;
      ASSERT (departed <= rack->rxt_in_flight);
      rack->rxt_in_flight -= departed;
    }
  bts->flags |= TCP_BTS_IS_LOST | TCP_BTS_RACK_LOST;

  tcp_bt_account_rxt_departed (tc, departed);

  return departed;
}

u32
tcp_bt_track_rxt (tcp_connection_t *tc, u32 start, u32 end)
{
  tcp_byte_tracker_t *bt = tc->bt;
  tcp_rack_state_t *rack = tcp_rack_get_state (tc);
  tcp_bt_sample_t *bts, *next, *cur, *prev, *nbts, *scan;
  u32 bts_index, cur_index, next_index, prev_index, max_seq, replaced = 0;
  u8 is_end = end == tc->snd_nxt;
  u8 track_dsack = tcp_opts_sack_permitted (&tc->rcv_opts) &&
		   !(tc->dsack_flags & TCP_DSACK_UNDO_DISABLED) && tcp_in_cong_recovery (tc);
  u8 dsack_overlap = 0, was_cur_rxt;
  tcp_bts_flags_t bts_flags, merge_flags;

  replaced = tcp_bt_rxt_bytes_in_range (tc, start, end);
  ASSERT (replaced <= rack->rxt_in_flight);
  rack->rxt_in_flight -= replaced;
  rack->rxt_in_flight += end - start;

  /* Contiguous blocks retransmitted at the same time */
  bts = bt_get_sample (bt, bt->last_ooo);
  next = bts ? bt_next_sample (bt, bts) : 0;
  merge_flags = TCP_BTS_IS_RXT;
  if (next)
    {
      merge_flags |= next->flags & (TCP_BTS_IS_LOST | TCP_BTS_IS_DELIVERED);
      merge_flags |= (next->flags & TCP_BTS_IS_RXT) ? TCP_BTS_IS_RXT_LOST : 0;
    }
  merge_flags |= tc->app_limited ? TCP_BTS_IS_APP_LIMITED : 0;
  merge_flags |= track_dsack ? TCP_BTS_DSACK_TRACKED : 0;
  if (bts && next && bts->max_seq == start && bts->flags == merge_flags &&
      bts->tx_time == tcp_time_now_us (tc->c_thread_index))
    {
      bts->max_seq = end;
      if (track_dsack && bt_dsack_track_retransmit (tc, start, end, 0 /* overlaps */))
	{
	  bt_dsack_track_sample (bt, bts);
	}
      if (next)
	bt_fix_overlapped (bt, next, end, is_end);

      tcp_bt_account_rxt_departed (tc, replaced);
      return replaced;
    }

  /* Find original tx sample and cache flags in case the sample
   * is freed or the pool moves */
  bts = bt_lookup_seq (bt, start);
  ASSERT (bts != 0 && seq_geq (start, bts->min_seq));
  was_cur_rxt = bt_sample_index (bt, bts) == bt->cur_rxt;
  bts_flags = bts->flags;

  if (track_dsack)
    {
      scan = bts;
      while (scan && seq_lt (scan->min_seq, end))
	{
	  dsack_overlap |= !!(scan->flags & TCP_BTS_DSACK_TRACKED);
	  scan = bt_next_sample (bt, scan);
	}
      track_dsack = bt_dsack_track_retransmit (tc, start, end, dsack_overlap);
    }

  /* Head in the past */
  if (seq_lt (bts->min_seq, tc->snd_una))
    bt_update_sample (bt, bts, tc->snd_una);

  /* Head overlap */
  if (bts->min_seq == start)
    {
      prev_index = bts->prev;
      next = bt_fix_overlapped (bt, bts, end, is_end);
      /* bts might no longer be valid from here */
      next_index = bt_sample_index (bt, next);

      cur = tcp_bt_alloc_tx_sample (tc, start, end);
      cur->flags |= TCP_BTS_IS_RXT;
      if (bts_flags & TCP_BTS_IS_RXT)
	cur->flags |= TCP_BTS_IS_RXT_LOST;
      cur->flags |= bts_flags & (TCP_BTS_IS_LOST | TCP_BTS_IS_DELIVERED);
      if (track_dsack)
	bt_dsack_track_sample (bt, cur);
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
      tcp_bt_account_rxt_departed (tc, replaced);
      return replaced;
    }

  bts_index = bt_sample_index (bt, bts);
  next = bt_next_sample (bt, bts);
  if (next)
    bt_fix_overlapped (bt, next, end, is_end);

  max_seq = bts->max_seq;
  ASSERT (seq_lt (start, max_seq));

  /* Have to split or tail overlap */
  cur = tcp_bt_alloc_tx_sample (tc, start, end);
  cur->flags |= TCP_BTS_IS_RXT;
  if (bts_flags & TCP_BTS_IS_RXT)
    cur->flags |= TCP_BTS_IS_RXT_LOST;
  cur->flags |= bts_flags & (TCP_BTS_IS_LOST | TCP_BTS_IS_DELIVERED);
  if (track_dsack)
    bt_dsack_track_sample (bt, cur);
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
      bt->dsack_fragments += !!(nbts->flags & TCP_BTS_DSACK_TRACKED);

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
      bt->last_ooo = cur_index;
      if (was_cur_rxt)
	bt->cur_rxt = cur_index;
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

      bt->last_ooo = cur_index;
      if (was_cur_rxt)
	bt->cur_rxt = cur_index;
    }

  if (PREDICT_FALSE (bt->dsack_fragments > TCP_MAX_DSACK_RXT_RANGES))
    bt_dsack_abandon_history (tc);
  tcp_bt_account_rxt_departed (tc, replaced);
  return replaced;
}

void
tcp_bt_walk_range (tcp_connection_t *tc, u32 start, u32 end, tcp_bt_walk_fn_t fn, void *opaque)
{
  tcp_byte_tracker_t *bt = tc->bt;
  tcp_bt_sample_t *bts, *next;

  if (!bt || !seq_lt (start, end))
    return;

  bts = bt_lookup_seq (bt, start);
  while (bts && seq_lt (bts->min_seq, end))
    {
      next = bt_next_sample (bt, bts);
      if (seq_gt (bts->max_seq, start))
	fn (tc, bts, opaque);
      bts = next;
    }
}

void
tcp_bt_split_at (tcp_connection_t *tc, u32 seq)
{
  tcp_bt_sample_t *bts;

  if (!tc->bt)
    return;

  bts = bt_lookup_seq (tc->bt, seq);
  if (bts && seq_gt (seq, bts->min_seq) && seq_lt (seq, bts->max_seq))
    bt_split_sample (tc->bt, bts, seq);
}

void
tcp_bt_rxt_rewind (tcp_connection_t *tc, u32 seq)
{
  tcp_bt_sample_t *bts;

  ASSERT (tc->bt);
  bts = bt_lookup_seq (tc->bt, seq);
  ASSERT (bts && seq_geq (seq, bts->min_seq) && seq_lt (seq, bts->max_seq));

  if (seq_lt (seq, tc->sack_sb.high_rxt))
    tc->sack_sb.high_rxt = seq;
  tc->bt->cur_rxt = bt_sample_index (tc->bt, bts);
}

static void
tcp_bt_sample_to_rate_sample (tcp_connection_t *tc, tcp_bt_sample_t *bts, u32 delivered_end,
			      tcp_rate_sample_t *rs, f64 now)
{
  if (bts->flags & TCP_BTS_IS_DELIVERED)
    return;

  tcp_rack_sample_acked (tc, bts, delivered_end);

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

static void tcp_bt_update_reorder (tcp_connection_t *tc, u32 start, u32 high_sacked);

static_always_inline void
tcp_bt_update_rxt_delivered (tcp_connection_t *tc, tcp_rate_sample_t *rs, tcp_bts_flags_t flags,
			     u32 start, u32 end)
{
  tcp_rack_state_t *rack;
  u32 departed;

  if (!(flags & TCP_BTS_IS_RXT) || (flags & (TCP_BTS_RACK_LOST | TCP_BTS_IS_SACKED)))
    return;

  departed = end - start;
  rack = tcp_rack_get_state (tc);
  ASSERT (departed <= rack->rxt_in_flight);
  rack->rxt_in_flight -= departed;
  rs->rxt_sacked += departed;
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
	    tcp_bt_update_reorder (tc, cur->min_seq, high_sacked);
	  if (cur->flags & TCP_BTS_IS_SACKED)
	    {
	      rs->last_bytes_delivered += len;
	      tc->sack_sb.sacked_bytes -= len;
	    }
	  if (cur->flags & TCP_BTS_IS_LOST)
	    tc->sack_sb.lost_bytes -= len;
	}
      tcp_bt_update_rxt_delivered (tc, rs, cur->flags, cur->min_seq, cur->max_seq);
      tcp_bt_sample_to_rate_sample (tc, cur, cur->max_seq, rs, now);
      if (account && (cur->flags & TCP_BTS_DSACK_TRACKED))
	bt_retire_sample (bt, cur);
      else
	bt_free_sample (bt, cur);
      cur = next;
    }

  if (cur && seq_lt (cur->min_seq, ack))
    {
      u32 len = ack - cur->min_seq;
      tcp_bt_sample_t *acked = cur;

      if (account && (cur->flags & TCP_BTS_DSACK_TRACKED))
	{
	  cur = bt_split_sample (bt, cur, ack);
	  acked = bt_prev_sample (bt, cur);
	}
      if (account)
	{
	  if (!(acked->flags & TCP_BTS_IS_SACKED))
	    tcp_bt_update_reorder (tc, acked->min_seq, high_sacked);
	  if (acked->flags & TCP_BTS_IS_SACKED)
	    {
	      rs->last_bytes_delivered += len;
	      tc->sack_sb.sacked_bytes -= len;
	    }
	  if (acked->flags & TCP_BTS_IS_LOST)
	    tc->sack_sb.lost_bytes -= len;
	}
      tcp_bt_update_rxt_delivered (tc, rs, acked->flags, acked->min_seq, ack);
      tcp_bt_sample_to_rate_sample (tc, acked, ack, rs, now);
      if (acked != cur)
	bt_retire_sample (bt, acked);
      else
	bt_update_sample (bt, cur, ack);
    }
}

static void
tcp_bt_walk_samples_ooo (tcp_connection_t *tc, tcp_rate_sample_t *rs, f64 now, u32 high_sacked,
			 u8 account)
{
  sack_block_t *blks = tc->rcv_opts.sacks, *blk;
  tcp_byte_tracker_t *bt = tc->bt;
  tcp_bt_sample_t *cur, *prev, *next;
  int i;

  for (i = 0; i < vec_len (blks); i++)
    {
      blk = &blks[i];

      /* Ignore blocks that are already covered by snd_una */
      if (seq_lt (blk->end, tc->snd_una))
	continue;

      cur = bt_lookup_seq (bt, blk->start);
      if (!cur)
	continue;

      ASSERT (seq_geq (blk->start, cur->min_seq)
	      && seq_lt (blk->start, cur->max_seq));

      /* Current should be split. Second part will be consumed */
      if (PREDICT_FALSE (cur->min_seq != blk->start))
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
	      if (account)
		{
		  u32 len = cur->max_seq - cur->min_seq;
		  tcp_bt_update_reorder (tc, cur->min_seq, high_sacked);
		  tc->sack_sb.sacked_bytes += len;
		  rs->last_sacked_bytes += len;
		  if (cur->flags & TCP_BTS_IS_LOST)
		    tc->sack_sb.lost_bytes -= len;
		}
	      tcp_bt_update_rxt_delivered (tc, rs, cur->flags, cur->min_seq, cur->max_seq);
	      tcp_bt_sample_to_rate_sample (tc, cur, cur->max_seq, rs, now);
	      cur->flags &= ~TCP_BTS_IS_LOST;
	      cur->flags |= TCP_BTS_IS_SACKED | TCP_BTS_IS_DELIVERED;
	      if (prev && (prev->flags & TCP_BTS_IS_SACKED) &&
		  bt_sacked_samples_can_merge (prev, cur))
		{
		  cur = bt_merge_sample (bt, prev, cur);
		  next = bt_next_sample (bt, cur);
		}
	      else
		{
		  next = bt_next_sample (bt, cur);
		  if (next && (next->flags & TCP_BTS_IS_SACKED) &&
		      bt_sacked_samples_can_merge (cur, next))
		    {
		      cur = bt_merge_sample (bt, cur, next);
		      next = bt_next_sample (bt, cur);
		    }
		}
	    }
	  else
	    next = bt_next_sample (bt, cur);

	  prev = cur;
	  cur = next;
	}

      if (cur && seq_lt (cur->min_seq, blk->end))
	{
	  if (!account)
	    {
	      tcp_bt_update_rxt_delivered (tc, rs, cur->flags, cur->min_seq, blk->end);
	      tcp_bt_sample_to_rate_sample (tc, cur, blk->end, rs, now);
	      prev = bt_prev_sample (bt, cur);
	      if (prev && (prev->flags & TCP_BTS_IS_SACKED) &&
		  bt_sacked_samples_can_merge (prev, cur))
		{
		  prev->max_seq = blk->end;
		  bt_update_sample (bt, cur, blk->end);
		}
	      else
		{
		  next = bt_split_sample (bt, cur, blk->end);
		  cur = bt_prev_sample (bt, next);
		  cur->flags &= ~TCP_BTS_IS_LOST;
		  cur->flags |= TCP_BTS_IS_SACKED | TCP_BTS_IS_DELIVERED;
		}
	      continue;
	    }

	  if (cur->flags & TCP_BTS_IS_SACKED)
	    continue;

	  u32 len = blk->end - cur->min_seq;
	  tcp_bt_update_reorder (tc, cur->min_seq, high_sacked);
	  tc->sack_sb.sacked_bytes += len;
	  rs->last_sacked_bytes += len;
	  if (cur->flags & TCP_BTS_IS_LOST)
	    tc->sack_sb.lost_bytes -= len;
	  tcp_bt_update_rxt_delivered (tc, rs, cur->flags, cur->min_seq, blk->end);
	  tcp_bt_sample_to_rate_sample (tc, cur, blk->end, rs, now);
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

static void
tcp_bt_update_sack_loss (tcp_connection_t *tc, tcp_rate_sample_t *rs, u8 clear_lost)
{
  tcp_byte_tracker_t *bt = tc->bt;
  tcp_bt_sample_t *cur;
  sack_scoreboard_t *sb = &tc->sack_sb;
  u32 sacked = 0, lost = 0, newly_lost = 0, blocks = 0;
  u32 loss_thresh = (sb->reorder - 1) * tc->snd_mss;
  u8 in_sacked = 0;

  cur = bt_get_sample (bt, bt->tail);
  while (cur)
    {
      u32 len = cur->max_seq - cur->min_seq;

      if (clear_lost)
	cur->flags &= ~TCP_BTS_IS_LOST;

      if (cur->flags & TCP_BTS_IS_SACKED)
	{
	  sacked += len;
	  if (!in_sacked)
	    blocks++;
	  in_sacked = 1;
	}
      else
	{
	  in_sacked = 0;
	  if (seq_lt (cur->min_seq, sb->high_sacked) &&
	      (sacked > loss_thresh || blocks >= sb->reorder) && !(cur->flags & TCP_BTS_IS_LOST))
	    {
	      cur->flags |= TCP_BTS_IS_LOST;
	      newly_lost += len;
	    }
	  if (cur->flags & TCP_BTS_IS_LOST)
	    lost += len;
	}

      cur = bt_prev_sample (bt, cur);
    }

  ASSERT (sacked == sb->sacked_bytes);
  sb->lost_bytes = lost;
  if (rs)
    rs->last_lost += newly_lost;
}

static void
tcp_bt_update_reorder (tcp_connection_t *tc, u32 start, u32 high_sacked)
{
  sack_scoreboard_t *sb = &tc->sack_sb;
  u32 reord;

  if (!seq_lt (start, high_sacked))
    return;

  if (tcp_in_cong_recovery (tc) &&
      (seq_geq (sb->rescue_rxt, tc->snd_una) || seq_lt (start, sb->high_rxt)))
    return;

  reord = (high_sacked - start + tc->snd_mss - 1) / tc->snd_mss;
  reord = clib_min (reord, TCP_MAX_SACK_REORDER);
  sb->reorder = clib_max (sb->reorder, reord);
}

void
tcp_bt_apply_sacks (tcp_connection_t *tc, u32 ack, u32 high_sacked, tcp_rate_sample_t *rs)
{
  sack_scoreboard_t *sb = &tc->sack_sb;
  u32 old_high_sacked;
  f64 now;

  now = tcp_time_now_us (tc->c_thread_index);
  old_high_sacked = (sb->sacked_bytes || sb->is_reneging) ? sb->high_sacked : tc->snd_una;

  if (seq_gt (ack, tc->snd_una))
    tcp_bt_walk_samples (tc, ack, rs, now, old_high_sacked, 1 /* account */);

  tcp_bt_walk_samples_ooo (tc, rs, now, old_high_sacked, 1 /* account */);
  if (PREDICT_FALSE (tc->bt->dsack_fragments > TCP_MAX_DSACK_RXT_RANGES))
    bt_dsack_abandon_history (tc);
  sb->high_sacked = high_sacked;
  tcp_bt_update_sack_loss (tc, rs, 0 /* clear_lost */);

  if (bt_get_sample (tc->bt, tc->bt->head))
    sb->is_reneging = !!(bt_get_sample (tc->bt, tc->bt->head)->flags & TCP_BTS_IS_SACKED);
  else
    sb->is_reneging = 0;

  rs->bt_processed = 1;
}

void
tcp_bt_recompute_sack_loss (tcp_connection_t *tc)
{
  tcp_bt_update_sack_loss (tc, 0, 1 /* clear_lost */);
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
  tc->sack_sb.rescue_rxt = snd_una - 1;
}

void
tcp_bt_rxt_mark_lost (tcp_connection_t *tc)
{
  tcp_byte_tracker_t *bt = tc->bt;
  tcp_bt_sample_t *cur;
  sack_scoreboard_t *sb = &tc->sack_sb;

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
  if (!sb->is_reneging && (!cur || !(cur->flags & TCP_BTS_IS_SACKED)))
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
  sb->is_reneging = 0;
  sb->reorder = TCP_DUPACK_THRESHOLD;
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
		   tcp_bt_sample_t **next_range)
{
  tcp_bt_sample_t *next;
  tcp_bts_flags_t lost;

  while (cur && (cur->flags & TCP_BTS_IS_SACKED))
    cur = bt_next_sample (bt, cur);
  if (!cur)
    {
      *next_range = 0;
      return 0;
    }

  lost = cur->flags & TCP_BTS_IS_LOST;
  range->start = cur->min_seq;
  range->end = cur->max_seq;
  range->is_lost = !!lost;

  next = bt_next_sample (bt, cur);
  while (next && !(next->flags & TCP_BTS_IS_SACKED) && !!(next->flags & TCP_BTS_IS_LOST) == !!lost)
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
  tcp_bt_sample_t *cur, *next;

  cur = bt_get_sample (bt, bt->cur_rxt);
  if (!cur)
    cur = bt_get_sample (bt, bt->head);
  while (cur)
    {
      if (!bt_next_rxt_range (bt, cur, range, &next))
	{
	  bt->cur_rxt = TCP_BTS_INVALID_INDEX;
	  return 0;
	}
      if (!range->is_lost || seq_gt (range->end, sb->high_rxt))
	break;
      cur = next;
    }

  if (!cur)
    {
      bt->cur_rxt = TCP_BTS_INVALID_INDEX;
      return 0;
    }

  if (range->is_lost && seq_lt (range->start, sb->high_sacked))
    ;
  else if (have_unsent)
    {
      bt->cur_rxt = TCP_BTS_INVALID_INDEX;
      return 0;
    }
  else if (seq_lt (range->start, sb->high_sacked))
    {
      if (seq_leq (range->end, sb->high_rxt))
	{
	  bt->cur_rxt = TCP_BTS_INVALID_INDEX;
	  return 0;
	}
      *snd_limited = 0;
    }
  else
    {
      *snd_limited = 1;
      *can_rescue = 1;
      return 0;
    }

  bt->cur_rxt = bt_sample_index (bt, cur);
  if (seq_lt (sb->high_rxt, range->start))
    sb->high_rxt = range->start;
  range->start = sb->high_rxt;
  return seq_lt (range->start, range->end);
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
  while (prev && !(prev->flags & TCP_BTS_IS_SACKED) && !!(prev->flags & TCP_BTS_IS_LOST) == !!lost)
    {
      range->start = prev->min_seq;
      prev = bt_prev_sample (bt, prev);
    }
  return 1;
}

static u32
bt_dsack_mark_active (tcp_connection_t *tc, u32 start, u32 end)
{
  tcp_byte_tracker_t *bt = tc->bt;
  tcp_bt_sample_t *cur, *next;
  u32 overlap_start, overlap_end, matched = 0, n_splits;

  cur = bt_lookup_seq (bt, start);
  if (!cur)
    cur = bt_get_sample (bt, bt->head);
  if (cur && seq_geq (start, cur->max_seq))
    cur = bt_next_sample (bt, cur);

  while (cur && seq_lt (cur->min_seq, end))
    {
      next = bt_next_sample (bt, cur);
      if (!(cur->flags & TCP_BTS_DSACK_TRACKED))
	{
	  cur = next;
	  continue;
	}

      overlap_start = seq_max (start, cur->min_seq);
      overlap_end = seq_lt (end, cur->max_seq) ? end : cur->max_seq;
      if (!seq_lt (overlap_start, overlap_end))
	{
	  cur = next;
	  continue;
	}

      n_splits = seq_gt (overlap_start, cur->min_seq) + seq_lt (overlap_end, cur->max_seq);
      if (!bt_dsack_can_split (tc, n_splits))
	return matched;

      if (seq_gt (overlap_start, cur->min_seq))
	cur = bt_split_sample (bt, cur, overlap_start);
      if (seq_lt (overlap_end, cur->max_seq))
	next = bt_split_sample (bt, cur, overlap_end);
      else
	next = bt_next_sample (bt, cur);

      matched += overlap_end - overlap_start;
      if (!(cur->flags & TCP_BTS_DSACK_DUPLICATE))
	{
	  cur->flags |= TCP_BTS_DSACK_DUPLICATE;
	  bt->dsack_dup_bytes += overlap_end - overlap_start;
	}
      cur = next;
    }

  return matched;
}

static tcp_bt_sample_t *
bt_split_retired_sample (tcp_byte_tracker_t *bt, tcp_bt_sample_t *cur, u32 seq)
{
  tcp_bt_sample_t *next, *right;
  u32 cur_index = bt_sample_index (bt, cur);

  ASSERT (seq_lt (cur->min_seq, seq) && seq_lt (seq, cur->max_seq));

  pool_get_zero (bt->samples, right);
  cur = bt_get_sample (bt, cur_index);
  *right = *cur;
  right->min_seq = seq;
  cur->max_seq = seq;
  bt->dsack_fragments++;

  next = bt_get_sample (bt, right->next);
  if (next)
    next->prev = bt_sample_index (bt, right);
  else
    bt->dsack_tail = bt_sample_index (bt, right);
  cur->next = bt_sample_index (bt, right);
  right->prev = cur_index;
  return right;
}

static u32
bt_dsack_mark_retired (tcp_connection_t *tc, u32 start, u32 end)
{
  tcp_byte_tracker_t *bt = tc->bt;
  tcp_bt_sample_t *cur, *next;
  u32 overlap_start, overlap_end, matched = 0, n_splits;

  cur = bt_get_sample (bt, bt->dsack_head);
  while (cur && seq_leq (cur->max_seq, start))
    cur = bt_get_sample (bt, cur->next);

  while (cur && seq_lt (cur->min_seq, end))
    {
      next = bt_get_sample (bt, cur->next);
      overlap_start = seq_max (start, cur->min_seq);
      overlap_end = seq_lt (end, cur->max_seq) ? end : cur->max_seq;
      if (!seq_lt (overlap_start, overlap_end))
	{
	  cur = next;
	  continue;
	}

      n_splits = seq_gt (overlap_start, cur->min_seq) + seq_lt (overlap_end, cur->max_seq);
      if (!bt_dsack_can_split (tc, n_splits))
	return matched;

      if (seq_gt (overlap_start, cur->min_seq))
	cur = bt_split_retired_sample (bt, cur, overlap_start);
      if (seq_lt (overlap_end, cur->max_seq))
	next = bt_split_retired_sample (bt, cur, overlap_end);
      else
	next = bt_get_sample (bt, cur->next);

      matched += overlap_end - overlap_start;
      if (!(cur->flags & TCP_BTS_DSACK_DUPLICATE))
	{
	  cur->flags |= TCP_BTS_DSACK_DUPLICATE;
	  bt->dsack_dup_bytes += overlap_end - overlap_start;
	}
      cur = next;
    }

  return matched;
}

void
tcp_bt_dsack_recovery_start (tcp_connection_t *tc)
{
  bt_dsack_clear_ranges (tc);
  tc->dsack_flags &= TCP_DSACK_UNDO_DISABLED;
  tc->dsack_recovery_ack = 0;
}

void
tcp_bt_dsack_recovery_done (tcp_connection_t *tc)
{
  bt_dsack_clear_ranges (tc);
  tc->dsack_flags &= TCP_DSACK_UNDO_DISABLED;
  tc->dsack_recovery_ack = 0;
}

u8
tcp_bt_dsack_has_history (tcp_connection_t *tc)
{
  return tc->bt->dsack_rxt_bytes != 0 || (tc->dsack_flags & TCP_DSACK_RXT_OVERFLOW);
}

tcp_ack_flag_t
tcp_bt_dsack_update (tcp_connection_t *tc, u32 packet_ack, const sack_block_t *dsack,
		     u8 had_sack_history)
{
  tcp_byte_tracker_t *bt = tc->bt;
  u32 matched;

  if (!tcp_bt_dsack_has_history (tc))
    {
      if (dsack)
	{
	  tc->dsack_flags |= TCP_DSACK_UNDO_DISABLED;
	  tcp_bt_dsack_recovery_done (tc);
	}
      return 0;
    }

  if (!tcp_in_cong_recovery (tc) && !dsack)
    {
      u32 new_snd_una = seq_max (tc->snd_una, packet_ack);
      if (seq_gt (new_snd_una, tc->dsack_recovery_ack))
	tcp_bt_dsack_recovery_done (tc);
      return 0;
    }

  if (tc->dsack_flags & TCP_DSACK_RXT_OVERFLOW)
    return 0;

  if (dsack)
    {
      if (!had_sack_history && dsack->start == tc->snd_una)
	tc->dsack_flags |= TCP_DSACK_INELIGIBLE;
      else
	{
	  matched = bt_dsack_mark_active (tc, dsack->start, dsack->end);
	  if (tc->dsack_flags & TCP_DSACK_RXT_OVERFLOW)
	    return 0;
	  matched += bt_dsack_mark_retired (tc, dsack->start, dsack->end);
	  if (tc->dsack_flags & TCP_DSACK_RXT_OVERFLOW)
	    return 0;
	  if (matched != dsack->end - dsack->start)
	    {
	      tc->dsack_flags |= TCP_DSACK_UNDO_DISABLED;
	      tcp_bt_dsack_recovery_done (tc);
	      return 0;
	    }
	}
    }

  if (tc->sack_sb.is_reneging)
    tc->dsack_flags |= TCP_DSACK_INELIGIBLE;

  if (tc->dsack_flags & (TCP_DSACK_INELIGIBLE | TCP_DSACK_UNDO_DISABLED))
    return 0;

  return bt->dsack_dup_bytes == bt->dsack_rxt_bytes ? TCP_ACK_F_DSACK_SPURIOUS : 0;
}

void
tcp_bt_sample_delivery_rate (tcp_connection_t * tc, tcp_rate_sample_t * rs)
{
  u32 delivered, data_acked;
  f64 now;

  tc->lost += rs->last_lost;

  data_acked = tcp_bt_data_acked (tc, rs);
  delivered = data_acked + rs->last_sacked_bytes;
  delivered -= rs->last_bytes_delivered;
  if (tc->bt->head == TCP_BTS_INVALID_INDEX)
    goto done;

  now = tcp_time_now_us (tc->c_thread_index);

  if (!delivered)
    {
      if (data_acked && !rs->bt_processed)
	tcp_bt_walk_samples (tc, tc->snd_una, rs, now, tc->sack_sb.high_sacked, 0 /* account */);
      goto done;
    }

  tc->delivered += delivered;
  tc->delivered_time = now;

  if (tc->app_limited && tc->delivered > tc->app_limited)
    tc->app_limited = 0;

  if (data_acked && !rs->bt_processed)
    tcp_bt_walk_samples (tc, tc->snd_una, rs, now, tc->sack_sb.high_sacked, 0 /* account */);

  if (rs->last_sacked_bytes && !rs->bt_processed)
    tcp_bt_walk_samples_ooo (tc, rs, now, tc->sack_sb.high_sacked, 0 /* account */);

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
  bt_free_retired_samples (bt);
}

void
tcp_bt_cleanup (tcp_connection_t * tc)
{
  tcp_byte_tracker_t *bt = tc->bt;

  rb_tree_free_nodes (&bt->sample_lookup);
  pool_free (bt->samples);
  clib_mem_free (bt);
  tc->bt = 0;
  tc->cfg_flags &= ~TCP_CFG_F_RATE_SAMPLE;
}

void
tcp_bt_init_opaque (tcp_connection_t *tc, uword opaque_size)
{
  tcp_byte_tracker_t *bt;
  uword alloc_size = sizeof (*bt) + opaque_size;

  bt = clib_mem_alloc (alloc_size);
  clib_memset (bt, 0, alloc_size);

  rb_tree_init (&bt->sample_lookup);
  bt->head = bt->tail = TCP_BTS_INVALID_INDEX;
  bt->last_ooo = TCP_BTS_INVALID_INDEX;
  bt->cur_rxt = TCP_BTS_INVALID_INDEX;
  bt->dsack_head = bt->dsack_tail = TCP_BTS_INVALID_INDEX;
  tc->bt = bt;
  tc->cfg_flags |= TCP_CFG_F_RATE_SAMPLE;
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
  u32 active, retired;

  active = pool_elts (bt->sample_lookup.nodes) - 1;
  retired = pool_elts (bt->samples) - active;

  s = format (s, "delivered %lu lost %lu app-limited %s\n", tc->delivered, tc->lost,
	      tc->app_limited ? "yes" : "no");
  s = format (s, "%Usamples active %u retired %u\n", format_white_space, indent, active, retired);
  s = format (s, "%Udsack rxt-bytes %u dup-bytes %u ranges %u fragments %u", format_white_space,
	      indent, bt->dsack_rxt_bytes, bt->dsack_dup_bytes, bt->dsack_rxt_ranges,
	      bt->dsack_fragments);
  return s;
}
