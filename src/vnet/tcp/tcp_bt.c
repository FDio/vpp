/*
 * Copyright (c) 2019 Cisco and/or its affiliates.
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
 *
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
bt_free_sample (tcp_byte_tracker_t * bt, tcp_bt_sample_t * bts)
{
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

static tcp_bt_sample_t *
bt_lookup_seq (tcp_byte_tracker_t * bt, u32 seq)
{
  rb_tree_t *rt = &bt->sample_lookup;
  rb_node_t *cur, *prev;
  tcp_bt_sample_t *bts;

  cur = rb_node (rt, rt->root);
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
      if (!tmp)
	return 0;
      if (tmp != bts)
	return 0;
      tmp = bt_next_sample (bt, bts);
      if (tmp)
	{
	  if (tmp->prev != bt_sample_index (bt, bts))
	    {
	      clib_warning ("next %u thinks prev is %u should be %u",
			    bts->next, tmp->prev, bt_sample_index (bt, bts));
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
  u32 bts_index;

  tail = bt_get_sample (bt, bt->tail);
  if (tail && tail->max_seq == tc->snd_nxt
      && !(tail->flags & TCP_BTS_IS_SACKED)
      && tail->tx_time == tcp_time_now_us (tc->c_thread_index))
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

void
tcp_bt_track_rxt (tcp_connection_t * tc, u32 start, u32 end)
{
  tcp_byte_tracker_t *bt = tc->bt;
  tcp_bt_sample_t *bts, *next, *cur, *prev, *nbts;
  u32 bts_index, cur_index, next_index, prev_index, max_seq;
  u8 is_end = end == tc->snd_nxt;
  tcp_bts_flags_t bts_flags;

  /* Contiguous blocks retransmitted at the same time */
  bts = bt_get_sample (bt, bt->last_ooo);
  if (bts && bts->max_seq == start
      && bts->tx_time == tcp_time_now_us (tc->c_thread_index))
    {
      bts->max_seq = end;
      next = bt_next_sample (bt, bts);
      if (next)
	bt_fix_overlapped (bt, next, end, is_end);

      return;
    }

  /* Find original tx sample and cache flags in case the sample
   * is freed or the pool moves */
  bts = bt_lookup_seq (bt, start);
  bts_flags = bts->flags;

  ASSERT (bts != 0 && seq_geq (start, bts->min_seq));

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
  cur->flags |= TCP_BTS_IS_RXT;
  if (bts_flags & TCP_BTS_IS_RXT)
    cur->flags |= TCP_BTS_IS_RXT_LOST;
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
      bt->last_ooo = cur_index;
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
    }
}

static void
tcp_bt_sample_to_rate_sample (tcp_connection_t * tc, tcp_bt_sample_t * bts,
			      tcp_rate_sample_t * rs)
{
  if (bts->flags & TCP_BTS_IS_SACKED)
    return;

  if (rs->prior_delivered && rs->prior_delivered >= bts->delivered)
    return;

  rs->prior_delivered = bts->delivered;
  rs->prior_time = bts->delivered_time;
  rs->interval_time = bts->tx_time - bts->first_tx_time;
  rs->rtt_time = tc->delivered_time - bts->tx_time;
  rs->flags = bts->flags;
  rs->tx_in_flight = bts->tx_in_flight;
  rs->tx_lost = bts->tx_lost;
  tc->first_tx_time = bts->tx_time;
}

static void
tcp_bt_walk_samples (tcp_connection_t * tc, tcp_rate_sample_t * rs)
{
  tcp_byte_tracker_t *bt = tc->bt;
  tcp_bt_sample_t *next, *cur;

  cur = bt_get_sample (bt, bt->head);
  while (cur && seq_leq (cur->max_seq, tc->snd_una))
    {
      next = bt_next_sample (bt, cur);
      tcp_bt_sample_to_rate_sample (tc, cur, rs);
      bt_free_sample (bt, cur);
      cur = next;
    }

  if (cur && seq_lt (cur->min_seq, tc->snd_una))
    {
      bt_update_sample (bt, cur, tc->snd_una);
      tcp_bt_sample_to_rate_sample (tc, cur, rs);
    }
}

static void
tcp_bt_walk_samples_ooo (tcp_connection_t * tc, tcp_rate_sample_t * rs)
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
	      tcp_bt_sample_to_rate_sample (tc, cur, rs);
	      cur->flags |= TCP_BTS_IS_SACKED;
	      if (prev && (prev->flags & TCP_BTS_IS_SACKED))
		{
		  cur = bt_merge_sample (bt, prev, cur);
		  next = bt_next_sample (bt, cur);
		}
	      else
		{
		  next = bt_next_sample (bt, cur);
		  if (next && (next->flags & TCP_BTS_IS_SACKED))
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
	  tcp_bt_sample_to_rate_sample (tc, cur, rs);
	  prev = bt_prev_sample (bt, cur);
	  /* Extend previous to include the newly sacked bytes */
	  if (prev && (prev->flags & TCP_BTS_IS_SACKED))
	    {
	      prev->max_seq = blk->end;
	      bt_update_sample (bt, cur, blk->end);
	    }
	  /* Split sample into two. First part is consumed */
	  else
	    {
	      next = bt_split_sample (bt, cur, blk->end);
	      cur = bt_prev_sample (bt, next);
	      cur->flags |= TCP_BTS_IS_SACKED;
	    }
	}
    }
}

void
tcp_bt_sample_delivery_rate (tcp_connection_t * tc, tcp_rate_sample_t * rs)
{
  u32 delivered;

  if (PREDICT_FALSE (tc->flags & TCP_CONN_FINSNT))
    return;

  tc->lost += tc->sack_sb.last_lost_bytes;

  delivered = tc->bytes_acked + tc->sack_sb.last_sacked_bytes;
  /* Do not count bytes that were previously sacked again */
  delivered -= tc->sack_sb.last_bytes_delivered;
  if (!delivered || tc->bt->head == TCP_BTS_INVALID_INDEX)
    return;

  tc->delivered += delivered;
  tc->delivered_time = tcp_time_now_us (tc->c_thread_index);

  if (tc->app_limited && tc->delivered > tc->app_limited)
    tc->app_limited = 0;

  if (tc->bytes_acked)
    tcp_bt_walk_samples (tc, rs);

  if (tc->sack_sb.last_sacked_bytes)
    tcp_bt_walk_samples_ooo (tc, rs);

  rs->interval_time = clib_max ((tc->delivered_time - rs->prior_time),
				rs->interval_time);
  rs->delivered = tc->delivered - rs->prior_delivered;
  rs->acked_and_sacked = delivered;
  rs->last_lost = tc->sack_sb.last_lost_bytes;
  rs->lost = tc->lost - rs->tx_lost;
}

void
tcp_bt_flush_samples (tcp_connection_t * tc)
{
  tcp_byte_tracker_t *bt = tc->bt;
  tcp_bt_sample_t *bts;
  u32 *samples = 0, *si;

  if (pool_elts (bt->samples) == 0)
    return;

  vec_validate (samples, pool_elts (bt->samples) - 1);
  vec_reset_length (samples);

  pool_foreach (bts, bt->samples)  {
    vec_add1 (samples, bts - bt->samples);
  }

  vec_foreach (si, samples)
  {
    bts = bt_get_sample (bt, *si);
    bt_free_sample (bt, bts);
  }

  vec_free (samples);
}

void
tcp_bt_cleanup (tcp_connection_t * tc)
{
  tcp_byte_tracker_t *bt = tc->bt;

  rb_tree_free_nodes (&bt->sample_lookup);
  pool_free (bt->samples);
  clib_mem_free (bt);
  tc->bt = 0;
}

void
tcp_bt_init (tcp_connection_t * tc)
{
  tcp_byte_tracker_t *bt;

  bt = clib_mem_alloc (sizeof (tcp_byte_tracker_t));
  clib_memset (bt, 0, sizeof (tcp_byte_tracker_t));

  rb_tree_init (&bt->sample_lookup);
  bt->head = bt->tail = TCP_BTS_INVALID_INDEX;
  tc->bt = bt;
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

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
