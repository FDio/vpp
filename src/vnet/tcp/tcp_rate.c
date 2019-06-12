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
 * TCP byte tracker that can generate generate delivery rate estimates. Based
 * on draft-cheng-iccrg-delivery-rate-estimation-00
 */

#include <vnet/tcp/tcp.h>

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
bt_alloc_sample (tcp_byte_tracker_t * bt, u32 min_seq)
{
  tcp_bt_sample_t *bts;

  pool_get_zero (bt->samples, bts);
  bts->next = bts->prev = TCP_BTS_INVALID_INDEX;
  bts->min_seq = min_seq;
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
bt_update_sample (tcp_byte_tracker_t * bt, tcp_bt_sample_t * bts,
			      u32 seq)
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
  while ((next = bt_next_sample (bt, cur))
	 && seq_lt (next->min_seq, seq))
    {
      bt_free_sample (bt, cur);
      cur = next;
    }

  if (next)
    {
      bt_free_sample (bt, cur);
      return next;
    }

  /* Overlapping current entirely */
  if (is_end)
    {
      bt_free_sample (bt, cur);
      return 0;
    }

  /* Overlapping head of current but not all */
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
			    bts->next, tmp->prev,
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
tcp_bt_alloc_tx_sample (tcp_connection_t * tc, u32 min_seq)
{
  tcp_bt_sample_t *bts;
  bts = bt_alloc_sample (tc->tx_tracker, min_seq);
  bts->delivered = tc->delivered;
  bts->delivered_time = tc->delivered_time;
  bts->tx_rate = transport_connection_tx_pacer_rate (&tc->connection);
  bts->flags |= tc->app_limited ? TCP_BS_IS_APP_LIMITED : 0;
  return bts;
}

void
tcp_bt_track_tx (tcp_connection_t * tc)
{
  tcp_byte_tracker_t *tt = tc->tx_tracker;
  tcp_bt_sample_t *bts, *tail;
  u32 bts_index;

  if (!tcp_flight_size (tc))
    tc->delivered_time = tcp_time_now_us (tc->c_thread_index);

  bts = bt_lookup_seq (tt, tc->snd_nxt);
  if (bts)
    {
      if (bts->min_seq == tc->snd_nxt)
	clib_warning ("OVERLAP %u", bts->min_seq);

      if (bt_next_sample (tt, bts))
	{
	  clib_warning ("has next so again overlap %u", bts->min_seq);
	  os_panic ();
	}
    }

  bts = tcp_bt_alloc_tx_sample (tc, tc->snd_nxt);
  bts_index = bt_sample_index (tt, bts);
  tail = bt_get_sample (tt, tt->tail);
  if (tail)
    {
      tail->next = bts_index;
      bts->prev = tt->tail;
      tt->tail = bts_index;
    }
  else
    {
      tt->tail = tt->head = bts_index;
    }
}

void
tcp_bt_track_rxt (tcp_connection_t * tc, u32 start, u32 end)
{
  tcp_byte_tracker_t *tt = tc->tx_tracker;
  tcp_bt_sample_t *bts, *next, *cur, *prev, *nbts;
  u32 bts_index, cur_index, next_index, prev_index, min_seq;
  u8 is_end = end == tc->snd_nxt;

  bts = bt_get_sample (tt, tt->last_ooo);
  if (bts && bts->max_seq == start)
    {
      bts->max_seq = end;
      next = bt_next_sample (tt, bts);
      if (next)
	bt_fix_overlapped (tt, next, end, is_end);

      return;
    }

  /* Find original tx sample */
  bts = bt_lookup_seq (tt, start);

  ASSERT (bts != 0 && seq_geq (start, bts->min_seq));

  /* Head in the past */
  if (seq_lt (bts->min_seq, tc->snd_una))
    bt_update_sample (tt, bts, tc->snd_una);

  /* Head overlap */
  if (bts->min_seq == start)
    {
      prev_index = bts->prev;
      next = bt_fix_overlapped (tt, bts, end, is_end);
      next_index = bt_sample_index (tt, next);

      if (next && next->min_seq == start)
	os_panic ();

      cur = tcp_bt_alloc_tx_sample (tc, start);
      cur->max_seq = end;
      cur->flags |= TCP_BS_IS_RXT;
      cur->next = next_index;
      cur->prev = prev_index;

      cur_index = bt_sample_index (tt, cur);

      if (next_index != TCP_BTS_INVALID_INDEX)
	{
	  next = bt_get_sample (tt, next_index);
	  next->prev = cur_index;
	}
      else
	{
	  tt->tail = cur_index;
	}

      if (prev_index != TCP_BTS_INVALID_INDEX)
	{
	  prev = bt_get_sample (tt, prev_index);
	  prev->next = cur_index;
	}
      else
	{
	  tt->head = cur_index;
	}

      tt->last_ooo = cur_index;
      return;
    }

  bts_index = bt_sample_index (tt, bts);
  next = bt_next_sample (tt, bts);
  if (next)
    next = bt_fix_overlapped (tt, next, end, is_end);

  min_seq = next ? next->min_seq : tc->snd_nxt;
  ASSERT (seq_lt (start, min_seq));

  /* Have to split or tail overlap */
  cur = tcp_bt_alloc_tx_sample (tc, start);
  cur->max_seq = end;
  cur->flags |= TCP_BS_IS_RXT;
  cur->prev = bts_index;
  cur_index = bt_sample_index (tt, cur);

  /* Split. Allocate another sample */
  if (seq_lt (end, min_seq))
    {
      nbts = tcp_bt_alloc_tx_sample (tc, end);
      cur = bt_get_sample (tt, cur_index);
      bts = bt_get_sample (tt, bts_index);

      if (bts->next != TCP_BTS_INVALID_INDEX)
	{
	  next = bt_get_sample (tt, bts->next);
	  if (next->prev != bts_index)
	    {
	      clib_warning ("THIS!");
	      os_panic ();
	    }
	}

      *nbts = *bts;
      nbts->min_seq = end;
      if (nbts->next != TCP_BTS_INVALID_INDEX)
	{
	  next = bt_get_sample (tt, nbts->next);
	  next->prev = bt_sample_index (tt, nbts);
	}
      else
	tt->tail = bt_sample_index (tt, nbts);

      bts->next = nbts->prev = cur_index;
      cur->next = bt_sample_index (tt, nbts);

      tt->last_ooo = cur_index;
    }
  /* Tail completely overlapped */
  else
    {
      bts = bt_get_sample (tt, bts_index);

      if (bts->next != TCP_BTS_INVALID_INDEX)
	{
	  next = bt_get_sample (tt, bts->next);
	  next->prev = cur_index;
	}
      else
	tt->tail = cur_index;

      cur->next = bts->next;
      bts->next = cur_index;

      tt->last_ooo = cur_index;
    }
}

static void
tcp_bt_sample_to_rate_sample (tcp_connection_t * tc, tcp_bt_sample_t * bts,
			      tcp_rate_sample_t * rs)
{
  if (rs->sample_delivered && rs->sample_delivered >= bts->delivered)
    return;

  rs->sample_delivered = bts->delivered;
  rs->delivered = tc->delivered - bts->delivered;
  rs->ack_time = tc->delivered_time - bts->delivered_time;
  rs->tx_rate = bts->tx_rate;
  rs->flags = bts->flags;
}

static void
tcp_bt_tracker_walk_samples (tcp_connection_t * tc, tcp_rate_sample_t * rs)
{
  tcp_byte_tracker_t *tt = tc->tx_tracker;
  tcp_bt_sample_t *next, *cur;

  cur = bt_get_sample (tt, tt->head);
  tcp_bt_sample_to_rate_sample (tc, cur, rs);
  while ((next = bt_get_sample (tt, cur->next))
	 && seq_lt (next->min_seq, tc->snd_una))
    {
      bt_free_sample (tt, cur);
      tcp_bt_sample_to_rate_sample (tc, next, rs);
      cur = next;
    }

  ASSERT (seq_lt (cur->min_seq, tc->snd_una));

  /* All samples acked */
  if (tc->snd_una == tc->snd_nxt)
    {
      ASSERT (pool_elts (tt->samples) == 1);
      bt_free_sample (tt, cur);
      return;
    }

  /* Current sample completely consumed */
  if (next && next->min_seq == tc->snd_una)
    {
      bt_free_sample (tt, cur);
      cur = next;
    }
}

static void
tcp_bt_tracker_walk_samples_ooo (tcp_connection_t * tc,
				 tcp_rate_sample_t * rs)
{
  sack_block_t *blks = tc->rcv_opts.sacks, *blk;
  tcp_byte_tracker_t *tt = tc->tx_tracker;
  tcp_bt_sample_t *next, *cur;
  int i;

  for (i = 0; i < vec_len (blks); i++)
    {
      blk = &blks[i];

      /* Ignore blocks that are already covered by snd_una */
      if (seq_lt (blk->end, tc->snd_una))
	continue;

      cur = bt_lookup_seq (tt, blk->start);
      if (!cur)
	continue;

      tcp_bt_sample_to_rate_sample (tc, cur, rs);

      /* Current shouldn't be removed */
      if (cur->min_seq != blk->start)
	{
	  cur = bt_next_sample (tt, cur);
	  if (!cur)
	    continue;
	}

      while ((next = bt_get_sample (tt, cur->next))
	     && seq_lt (next->min_seq, blk->end))
	{
	  bt_free_sample (tt, cur);
	  tcp_bt_sample_to_rate_sample (tc, next, rs);
	  cur = next;
	}

      /* Current consumed entirely */
      if (next && next->min_seq == blk->end)
	bt_free_sample (tt, cur);
    }
}

void
tcp_bt_sample_delivery_rate (tcp_connection_t * tc, tcp_rate_sample_t * rs)
{
  u32 delivered;

  if (PREDICT_FALSE (tc->flags & TCP_CONN_FINSNT))
    return;

  delivered = tc->bytes_acked + tc->sack_sb.last_sacked_bytes;
  if (!delivered || tc->tx_tracker->head == TCP_BTS_INVALID_INDEX)
    return;

  /* Do not count bytes that were previously sacked again */
  tc->delivered += delivered - tc->sack_sb.last_bytes_delivered;
  tc->delivered_time = tcp_time_now_us (tc->c_thread_index);

  if (tc->app_limited && tc->delivered > tc->app_limited)
    tc->app_limited = 0;

  if (tc->bytes_acked)
    tcp_bt_tracker_walk_samples (tc, rs);

  if (tc->sack_sb.last_sacked_bytes)
    tcp_bt_tracker_walk_samples_ooo (tc, rs);
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
tcp_bt_flush_samples (tcp_connection_t * tc)
{
  tcp_byte_tracker_t *tt = tc->tx_tracker;
  tcp_bt_sample_t *bts;
  u32 *samples = 0, *si;

  /* *INDENT-OFF* */
  pool_foreach (bts, tt->samples, ({
    vec_add1 (samples, bts - tt->samples);
  }));
  /* *INDENT-ON* */

  vec_foreach (si, samples)
  {
    bts = bt_get_sample (tt, *si);
    bt_free_sample (tt, bts);
  }

  vec_free (samples);
}

void
tcp_bt_cleanup (tcp_connection_t * tc)
{
  tcp_byte_tracker_t *tt = tc->tx_tracker;

  rb_tree_free_nodes (&tt->sample_lookup);
  pool_free (tt->samples);
  clib_mem_free (tt);
  tc->tx_tracker = 0;
}

void
tcp_bt_init (tcp_connection_t * tc)
{
  tcp_byte_tracker_t *tt;

  tt = clib_mem_alloc (sizeof (tcp_byte_tracker_t));
  clib_memset (tt, 0, sizeof (tcp_byte_tracker_t));

  rb_tree_init (&tt->sample_lookup);
  tt->head = tt->tail = TCP_BTS_INVALID_INDEX;
  tc->tx_tracker = tt;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
