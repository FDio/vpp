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
 * Based on draft-cheng-iccrg-delivery-rate-estimation-00
 */

#include <vnet/tcp/tcp.h>

static tcp_tx_sample_t *
tcp_tx_tracker_get_sample (tcp_tx_tracker_t * tt, u32 txs_index)
{
  if (pool_is_free_index (tt->samples, txs_index))
    return 0;
  return pool_elt_at_index (tt->samples, txs_index);
}

static tcp_tx_sample_t *
tcp_tx_tracker_next_sample (tcp_tx_tracker_t * tt, tcp_tx_sample_t * txs)
{
  return tcp_tx_tracker_get_sample (tt, txs->next);
}

static tcp_tx_sample_t *
tcp_tx_tracker_prev_sample (tcp_tx_tracker_t * tt, tcp_tx_sample_t * txs)
{
  return tcp_tx_tracker_get_sample (tt, txs->prev);
}

static u32
tcp_tx_tracker_sample_index (tcp_tx_tracker_t * tt, tcp_tx_sample_t * txs)
{
  if (!txs)
    return TCP_TXS_INVALID_INDEX;
  return txs - tt->samples;
}

static inline int
tt_seq_lt (u32 a, u32 b)
{
  return seq_lt (a, b);
}

static tcp_tx_sample_t *
tcp_tx_tracker_alloc_sample (tcp_tx_tracker_t * tt, u32 min_seq)
{
  tcp_tx_sample_t *txs;

  pool_get_zero (tt->samples, txs);
  txs->next = txs->prev = TCP_TXS_INVALID_INDEX;
  txs->min_seq = min_seq;
  rb_tree_add_custom (&tt->sample_lookup, txs->min_seq, txs - tt->samples,
		      tt_seq_lt);
  return txs;
}

static volatile u32 n_index;
static volatile u8 is_left;

static tcp_tx_sample_t *
tcp_tx_tracker_lookup_seq (tcp_tx_tracker_t * tt, u32 seq)
{
  rb_tree_t *rt = &tt->sample_lookup;
  rb_node_t *cur, *prev;
  tcp_tx_sample_t *txs;

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
	  n_index = prev - rt->nodes;
	  /* Hit tnil as a left child. Find predecessor */
	  if (seq_lt (seq, prev->key))
	    {
	      cur = rb_tree_predecessor (rt, prev);
	      if (rb_node_is_tnil (rt, cur))
		return 0;
	      txs = tcp_tx_tracker_get_sample (tt, cur->opaque);
	      is_left = 1;
	    }
	  /* Hit tnil as a right child */
	  else
	    {
	      txs = tcp_tx_tracker_get_sample (tt, prev->opaque);
	      is_left = 0;
	    }

	  if (seq_geq (seq, txs->min_seq))
	    return txs;

	  return 0;
	}
    }

  if (!rb_node_is_tnil (rt, cur))
    return tcp_tx_tracker_get_sample (tt, cur->opaque);

  return 0;
}

int
tcp_tx_tracker_is_sane (tcp_tx_tracker_t * tt)
{
  tcp_tx_sample_t *txs, *tmp;

  if (pool_elts (tt->samples) != pool_elts (tt->sample_lookup.nodes) - 1)
    return 0;

  if (tt->head == TCP_TXS_INVALID_INDEX)
    {
      if (tt->tail != TCP_TXS_INVALID_INDEX)
	return 0;
      if (pool_elts (tt->samples) != 0)
	return 0;
      return 1;
    }

  txs = tcp_tx_tracker_get_sample (tt, tt->tail);
  if (!txs)
    return 0;

  txs = tcp_tx_tracker_get_sample (tt, tt->head);
  if (!txs || txs->prev != TCP_TXS_INVALID_INDEX)
    return 0;

  while (txs)
    {
      tmp = tcp_tx_tracker_lookup_seq (tt, txs->min_seq);
      if (!tmp)
	return 0;
      if (tmp != txs)
	return 0;
      tmp = tcp_tx_tracker_next_sample (tt, txs);
      if (tmp)
	{
	  if (tmp->prev != tcp_tx_tracker_sample_index (tt, txs))
	    {
	      clib_warning ("next %u thinks prev is %u should be %u",
			    txs->next, tmp->prev,
			    tcp_tx_tracker_sample_index (tt, txs));
	      return 0;
	    }
	  if (!seq_lt (txs->min_seq, tmp->min_seq))
	    return 0;
	}
      else
	{
	  if (tt->tail != tcp_tx_tracker_sample_index (tt, txs))
	    return 0;
	  if (txs->next != TCP_TXS_INVALID_INDEX)
	    return 0;
	}
      txs = tmp;
    }
  return 1;
}

void
tcp_tx_tracker_validate (tcp_tx_tracker_t * tt)
{
  if (!tcp_tx_tracker_is_sane (tt))
    os_panic ();
}

static volatile u32 removing;

static void
tcp_tx_tracker_free_sample (tcp_tx_tracker_t * tt, tcp_tx_sample_t * txs)
{
  if (txs->prev != TCP_TXS_INVALID_INDEX)
    {
      tcp_tx_sample_t *prev = tcp_tx_tracker_prev_sample (tt, txs);
      prev->next = txs->next;
    }
  else
    tt->head = txs->next;

  if (txs->next != TCP_TXS_INVALID_INDEX)
    {
      tcp_tx_sample_t *next = tcp_tx_tracker_next_sample (tt, txs);
      next->prev = txs->prev;
    }
  else
    tt->tail = txs->prev;

  removing = txs->min_seq;

  rb_tree_del_custom (&tt->sample_lookup, txs->min_seq, tt_seq_lt);
//  if (CLIB_DEBUG)
  memset (txs, 0xfc, sizeof (*txs));
  pool_put (tt->samples, txs);

  tcp_tx_tracker_validate (tt);
}

static tcp_tx_sample_t *
tcp_alloc_tx_sample (tcp_connection_t * tc, u32 min_seq)
{
  tcp_tx_sample_t *txs;
  txs = tcp_tx_tracker_alloc_sample (tc->tx_tracker, min_seq);
  txs->delivered = tc->delivered;
  txs->delivered_time = tc->delivered_time;
  txs->tx_rate = transport_connection_tx_pacer_rate (&tc->connection);
  return txs;
}

void
tcp_track_tx (tcp_connection_t * tc)
{
  tcp_tx_tracker_t *tt = tc->tx_tracker;
  tcp_tx_sample_t *txs, *tail;
  u32 txs_index;

  if (!tcp_flight_size (tc))
    tc->delivered_time = tcp_time_now_us (tc->c_thread_index);

  txs = tcp_tx_tracker_lookup_seq (tt, tc->snd_nxt);
  if (txs)
    {
      if (txs->min_seq == tc->snd_nxt)
	clib_warning ("OVERLAP %u", txs->min_seq);

      if (tcp_tx_tracker_next_sample (tt, txs))
	{
	  clib_warning ("has next so again overlap %u", txs->min_seq);
	  os_panic ();
	}
    }

  txs = tcp_alloc_tx_sample (tc, tc->snd_nxt);
  txs_index = tcp_tx_tracker_sample_index (tt, txs);
  tail = tcp_tx_tracker_get_sample (tt, tt->tail);
  if (tail)
    {
      tail->next = txs_index;
      txs->prev = tt->tail;
      tt->tail = txs_index;
    }
  else
    {
      tt->tail = tt->head = txs_index;
    }
  tcp_tx_tracker_validate (tt);
}

static void
tcp_tx_tracker_update_sample (tcp_tx_tracker_t * tt, tcp_tx_sample_t * txs,
			      u32 seq)
{
  rb_tree_del_custom (&tt->sample_lookup, txs->min_seq, tt_seq_lt);
  txs->min_seq = seq;
  rb_tree_add_custom (&tt->sample_lookup, txs->min_seq,
		      tcp_tx_tracker_sample_index (tt, txs), tt_seq_lt);
}

static tcp_tx_sample_t *
tcp_tx_tracker_fix_overlapped (tcp_tx_tracker_t * tt, tcp_tx_sample_t * start,
			       u32 seq, u8 is_end)
{
  tcp_tx_sample_t *cur, *next;

  cur = start;
  while ((next = tcp_tx_tracker_next_sample (tt, cur))
	 && seq_lt (next->min_seq, seq))
    {
      tcp_tx_tracker_free_sample (tt, cur);
      cur = next;
    }

  tcp_tx_tracker_validate (tt);

  if (next)
    {
      tcp_tx_tracker_free_sample (tt, cur);
      tcp_tx_tracker_validate (tt);
      return next;
    }

  /* Overlapping current entirely */
  if (is_end)
    {
      tcp_tx_tracker_free_sample (tt, cur);
      tcp_tx_tracker_validate (tt);
      return 0;
    }

  /* Overlapping head of current but not all */
  tcp_tx_tracker_update_sample (tt, cur, seq);
  tcp_tx_tracker_validate (tt);
  return cur;
}

static volatile u32 pi, ci, ni, nti, pni, is_first;

void
tcp_track_rxt (tcp_connection_t * tc, u32 start, u32 end)
{
  tcp_tx_tracker_t *tt = tc->tx_tracker;
  tcp_tx_sample_t *txs, *next, *cur, *prev, *ntxs;
  u32 txs_index, cur_index, next_index, prev_index, min_seq;
  u8 is_end = end == tc->snd_nxt;

  txs = tcp_tx_tracker_get_sample (tt, tt->last_ooo);
  if (txs && txs->max_seq == start)
    {
      txs->max_seq = end;
      next = tcp_tx_tracker_next_sample (tt, txs);
      if (next)
	tcp_tx_tracker_fix_overlapped (tt, next, end, is_end);

      tcp_tx_tracker_validate (tt);
      return;
    }

  /* Find original tx sample */
  txs = tcp_tx_tracker_lookup_seq (tt, start);

  ASSERT (txs != 0 && seq_geq (start, txs->min_seq));

  if (!(txs != 0 && seq_geq (start, txs->min_seq)))
    os_panic ();

  /* Head in the past */
  if (seq_lt (txs->min_seq, tc->snd_una))
    tcp_tx_tracker_update_sample (tt, txs, tc->snd_una);

  /* Head overlap */
  if (txs->min_seq == start)
    {
      prev_index = txs->prev;
      next = tcp_tx_tracker_fix_overlapped (tt, txs, end, is_end);
      next_index = tcp_tx_tracker_sample_index (tt, next);

      if (next && next->min_seq == start)
	os_panic ();

      cur = tcp_alloc_tx_sample (tc, start);
      cur->max_seq = end;
      cur->is_rxt = 1;
      cur->next = next_index;
      cur->prev = prev_index;

      cur_index = tcp_tx_tracker_sample_index (tt, cur);

      if (next_index != TCP_TXS_INVALID_INDEX)
	{
	  next = tcp_tx_tracker_get_sample (tt, next_index);
	  next->prev = cur_index;
	}
      else
	{
	  tt->tail = cur_index;
	}

      if (prev_index != TCP_TXS_INVALID_INDEX)
	{
	  prev = tcp_tx_tracker_get_sample (tt, prev_index);
	  prev->next = cur_index;
	}
      else
	{
	  tt->head = cur_index;
	}

      tt->last_ooo = cur_index;

      tcp_tx_tracker_validate (tt);

      return;
    }

  txs_index = tcp_tx_tracker_sample_index (tt, txs);
  next = tcp_tx_tracker_next_sample (tt, txs);
  if (next)
    next = tcp_tx_tracker_fix_overlapped (tt, next, end, is_end);

  if (pool_is_free_index (tt->samples, txs_index))
    os_panic ();
  if (txs->next != TCP_TXS_INVALID_INDEX
      && pool_is_free_index (tt->samples, txs->next))
    os_panic ();
  ni = tcp_tx_tracker_sample_index (tt, next);

  min_seq = next ? next->min_seq : tc->snd_nxt;
  ASSERT (seq_lt (start, min_seq));

  /* Have to split or tail overlap */
  cur = tcp_alloc_tx_sample (tc, start);
  cur->max_seq = end;
  cur->is_rxt = 1;
  cur->prev = txs_index;
  cur_index = tcp_tx_tracker_sample_index (tt, cur);

  pi = txs_index;
  ci = cur_index;

  is_first = 0;

  /* Split. Allocate another sample */
  if (seq_lt (end, min_seq))
    {
      is_first = 1;

      ntxs = tcp_alloc_tx_sample (tc, end);
      cur = tcp_tx_tracker_get_sample (tt, cur_index);
      txs = tcp_tx_tracker_get_sample (tt, txs_index);

      if (txs->next != TCP_TXS_INVALID_INDEX)
	{
	  next = tcp_tx_tracker_get_sample (tt, txs->next);
	  if (next->prev != txs_index)
	    {
	      clib_warning ("THIS!");
	      os_panic ();
	    }
	}

      pni = txs->next;

      *ntxs = *txs;
      ntxs->min_seq = end;
      if (ntxs->next != TCP_TXS_INVALID_INDEX)
	{
	  next = tcp_tx_tracker_get_sample (tt, ntxs->next);
	  next->prev = tcp_tx_tracker_sample_index (tt, ntxs);
	}
      else
	tt->tail = tcp_tx_tracker_sample_index (tt, ntxs);

      txs->next = ntxs->prev = cur_index;
      nti = cur->next = tcp_tx_tracker_sample_index (tt, ntxs);

      tt->last_ooo = cur_index;

      tcp_tx_tracker_validate (tt);
    }
  /* Tail completely overlapped */
  else
    {
      txs = tcp_tx_tracker_get_sample (tt, txs_index);

      if (txs->next != TCP_TXS_INVALID_INDEX)
	{
	  next = tcp_tx_tracker_get_sample (tt, txs->next);
	  next->prev = cur_index;
	}
      else
	tt->tail = cur_index;

      cur->next = txs->next;
      txs->next = cur_index;

      tt->last_ooo = cur_index;

      tcp_tx_tracker_validate (tt);
    }
}

static void
tcp_tx_sample_to_rate_sample (tcp_connection_t * tc, tcp_tx_sample_t * txs,
			      tcp_rate_sample_t * rs)
{
  if (rs->sample_delivered && rs->sample_delivered >= txs->delivered)
    return;

  rs->sample_delivered = txs->delivered;
  rs->delivered = tc->delivered - txs->delivered;
  rs->ack_time = tc->delivered_time - txs->delivered_time;
  rs->tx_rate = txs->tx_rate;
  rs->is_rxt = txs->is_rxt;
}

static void
tcp_tx_tracker_walk_samples (tcp_connection_t * tc, tcp_rate_sample_t * rs)
{
  tcp_tx_tracker_t *tt = tc->tx_tracker;
  tcp_tx_sample_t *next, *cur;

  cur = tcp_tx_tracker_get_sample (tt, tt->head);
  tcp_tx_sample_to_rate_sample (tc, cur, rs);
  while ((next = tcp_tx_tracker_get_sample (tt, cur->next))
	 && seq_lt (next->min_seq, tc->snd_una))
    {
      tcp_tx_tracker_free_sample (tt, cur);
      tcp_tx_sample_to_rate_sample (tc, next, rs);
      cur = next;
    }

  ASSERT (seq_lt (cur->min_seq, tc->snd_una));

  /* All samples acked */
  if (tc->snd_una == tc->snd_nxt)
    {
      ASSERT (pool_elts (tt->samples) == 1);
      tcp_tx_tracker_free_sample (tt, cur);
      tcp_tx_tracker_validate (tt);
      return;
    }

  /* Current sample completely consumed */
  if (next && next->min_seq == tc->snd_una)
    {
      tcp_tx_tracker_free_sample (tt, cur);
      cur = next;
    }

  tcp_tx_tracker_validate (tt);
}

static void
tcp_tx_tracker_walk_samples_ooo (tcp_connection_t * tc,
				 tcp_rate_sample_t * rs)
{
  sack_block_t *blks = tc->rcv_opts.sacks, *blk;
  tcp_tx_tracker_t *tt = tc->tx_tracker;
  tcp_tx_sample_t *next, *cur;
  int i;

  for (i = 0; i < vec_len (blks); i++)
    {
      blk = &blks[i];

      /* Ignore blocks that are already covered by snd_una */
      if (seq_lt (blk->end, tc->snd_una))
	continue;

      cur = tcp_tx_tracker_lookup_seq (tt, blk->start);
      if (!cur)
	continue;

      tcp_tx_sample_to_rate_sample (tc, cur, rs);

      /* Current shouldn't be removed */
      if (cur->min_seq != blk->start)
	{
	  cur = tcp_tx_tracker_next_sample (tt, cur);
	  if (!cur)
	    continue;
	}

      while ((next = tcp_tx_tracker_get_sample (tt, cur->next))
	     && seq_lt (next->min_seq, blk->end))
	{
	  tcp_tx_tracker_free_sample (tt, cur);
	  tcp_tx_sample_to_rate_sample (tc, next, rs);
	  cur = next;
	}

      /* Current consumed entirely */
      if (next && next->min_seq == blk->end)
	tcp_tx_tracker_free_sample (tt, cur);

      tcp_tx_tracker_validate (tt);
    }
}

void
tcp_sample_delivery_rate (tcp_connection_t * tc, tcp_rate_sample_t * rs)
{
  u32 delivered;

  if (PREDICT_FALSE (tc->flags & TCP_CONN_FINSNT))
    return;

  delivered = tc->bytes_acked + tc->sack_sb.last_sacked_bytes;
  if (!delivered || tc->tx_tracker->head == TCP_TXS_INVALID_INDEX)
    return;

  /* Do not count bytes that were previously sacked again */
  tc->delivered += delivered - tc->sack_sb.last_bytes_delivered;
  tc->delivered_time = tcp_time_now_us (tc->c_thread_index);

  if (tc->bytes_acked)
    tcp_tx_tracker_walk_samples (tc, rs);

  if (tc->sack_sb.last_sacked_bytes)
    tcp_tx_tracker_walk_samples_ooo (tc, rs);

  if (0)
    {
      static f64 last_time = 0;
      static u64 max_rate = 0;

      if (tc->delivered_time > last_time + 0.5)
	{
	  u64 rate = (u64) rs->delivered / rs->ack_time;

	  last_time = tc->delivered_time;
	  max_rate = clib_max (max_rate, rate);
	  clib_warning ("bytes %u rate %lu max %lu snd rate %lu",
			rs->delivered, rate, max_rate, rs->tx_rate);
	}
    }

}

void
tcp_tx_tracker_init (tcp_connection_t * tc)
{
  tcp_tx_tracker_t *tt;

  tt = clib_mem_alloc (sizeof (tcp_tx_tracker_t));
  clib_memset (tt, 0, sizeof (tcp_tx_tracker_t));

  rb_tree_init (&tt->sample_lookup);
  tt->head = tt->tail = TCP_TXS_INVALID_INDEX;
  tc->tx_tracker = tt;
}

void
tcp_tx_tracker_flush_samples (tcp_connection_t * tc)
{
  tcp_tx_tracker_t *tt = tc->tx_tracker;
  tcp_tx_sample_t *txs;
  u32 *samples = 0, *si;

  /* *INDENT-OFF* */
  pool_foreach (txs, tt->samples, ({
    vec_add1 (samples, txs - tt->samples);
  }));
  /* *INDENT-ON* */

  vec_foreach (si, samples)
  {
    txs = tcp_tx_tracker_get_sample (tt, *si);
    tcp_tx_tracker_free_sample (tt, txs);
  }

  vec_free (samples);
}

void
tcp_tx_tracker_cleanup (tcp_connection_t * tc)
{
  tcp_tx_tracker_t *tt = tc->tx_tracker;

  rb_tree_free_nodes (&tt->sample_lookup);
  pool_free (tt->samples);
  clib_mem_free (tt);
  tc->tx_tracker = 0;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
