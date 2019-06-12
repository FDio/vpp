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

static void
tcp_tx_tracker_free_sample (tcp_tx_tracker_t * tt, tcp_tx_sample_t * txs)
{
  rb_tree_del_custom (&tt->sample_lookup, txs->min_seq, tt_seq_lt);
  pool_put (tt->samples, txs);
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
}

static tcp_tx_sample_t *
tcp_tx_tracker_fix_overlapped (tcp_tx_tracker_t * tt, tcp_tx_sample_t * start,
			       u32 seq, u8 is_end)
{
  tcp_tx_sample_t *prev, *cur, *next;

  prev = tcp_tx_tracker_prev_sample (tt, start);
  cur = start;
  while ((next = tcp_tx_tracker_next_sample (tt, cur))
	 && seq_geq (seq, next->min_seq))
    {
      if (prev)
	{
	  prev->next = tcp_tx_tracker_sample_index (tt, next);
	  next->prev = tcp_tx_tracker_sample_index (tt, prev);
	}
      tcp_tx_tracker_free_sample (tt, cur);
      cur = next;
    }

  /* Not overlapping next */
  if (seq_leq (seq, cur->min_seq))
    return cur;

  /* Overlapping head of last but not all */
  if (!is_end)
    {
      rb_tree_del_custom (&tt->sample_lookup, cur->min_seq, tt_seq_lt);
      cur->min_seq = seq;
      rb_tree_add_custom (&tt->sample_lookup, seq,
			  tcp_tx_tracker_sample_index (tt, cur), tt_seq_lt);
      return cur;
    }

  /* Completely overlapping last */
  tt->tail = cur->prev;
  tcp_tx_tracker_free_sample (tt, cur);

  return 0;
}

void
tcp_track_rxt (tcp_connection_t * tc, u32 start, u32 end)
{
  tcp_tx_tracker_t *tt = tc->tx_tracker;
  tcp_tx_sample_t *txs, *next, *cur, *prev, *ntxs;
  u32 txs_index, cur_index, next_index, min_seq;
  u8 is_end = end == tc->snd_nxt;

  txs = tcp_tx_tracker_get_sample (tt, tt->last_ooo);
  if (txs && txs->max_seq == start)
    {
      txs->max_seq = end;
      next = tcp_tx_tracker_next_sample (tt, txs);
      if (next)
	tcp_tx_tracker_fix_overlapped (tt, next, end, is_end);

      return;
    }

  /* Find original tx sample */
  txs = tcp_tx_tracker_lookup_seq (tt, start);
  ASSERT (txs != 0 && !txs->is_rxt && seq_geq (start, txs->min_seq));

  /* Head overlap */
  if (txs->min_seq == start)
    {
      next = tcp_tx_tracker_fix_overlapped (tt, txs, end, is_end);
      next_index = tcp_tx_tracker_sample_index (tt, next);

      cur = tcp_alloc_tx_sample (tc, start);
      cur->max_seq = end;
      cur->is_rxt = 1;

      next = tcp_tx_tracker_get_sample (tt, next_index);
      prev = tcp_tx_tracker_prev_sample (tt, next);

      cur->next = next_index;
      cur->prev = next->prev;
      next->prev = prev->next = tcp_tx_tracker_sample_index (tt, cur);
      tt->last_ooo = next->prev;
      return;
    }

  txs_index = tcp_tx_tracker_sample_index (tt, txs);
  next = tcp_tx_tracker_next_sample (tt, txs);
  if (next)
    next = tcp_tx_tracker_fix_overlapped (tt, next, end, is_end);

  min_seq = next ? next->min_seq : tc->snd_nxt;
  ASSERT (seq_lt (start, min_seq));

  /* Have to split or tail overlap */
  cur = tcp_alloc_tx_sample (tc, start);
  cur->max_seq = end;
  cur->is_rxt = 1;
  cur->prev = txs_index;
  cur_index = tcp_tx_tracker_sample_index (tt, cur);

  /* Split. Allocate another sample */
  if (seq_lt (end, min_seq))
    {
      ntxs = tcp_alloc_tx_sample (tc, start);
      cur = tcp_tx_tracker_get_sample (tt, cur_index);
      txs = tcp_tx_tracker_get_sample (tt, txs_index);

      clib_memcpy (ntxs, txs, sizeof (*txs));
      ntxs->min_seq = end;
      txs->next = ntxs->prev = cur_index;
      cur->next = tcp_tx_tracker_sample_index (tt, ntxs);
      tt->last_ooo = cur_index;
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

      cur->next = txs->next;
      txs->next = cur_index;

      tt->last_ooo = cur_index;
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
}

static void
tcp_tx_tracker_walk_samples (tcp_connection_t * tc, tcp_rate_sample_t * rs)
{
  tcp_tx_tracker_t *tt = tc->tx_tracker;
  tcp_tx_sample_t *cur, *prev;

  prev = tcp_tx_tracker_get_sample (tt, tt->head);
  tcp_tx_sample_to_rate_sample (tc, prev, rs);
  while ((cur = tcp_tx_tracker_get_sample (tt, prev->next)))
    {
      if (seq_gt (cur->min_seq, tc->snd_una))
	break;

      tcp_tx_tracker_free_sample (tt, prev);
      tcp_tx_sample_to_rate_sample (tc, cur, rs);
      prev = cur;
    }

  ASSERT (seq_leq (prev->min_seq, tc->snd_una));

  if (tc->snd_una == tc->snd_nxt)
    {
      tcp_tx_tracker_free_sample (tt, prev);
      tt->head = tt->tail = TCP_TXS_INVALID_INDEX;
      return;
    }
  tt->head = tcp_tx_tracker_sample_index (tt, prev);
}

static void
tcp_tx_tracker_walk_samples_ooo (tcp_connection_t * tc,
				 tcp_rate_sample_t * rs)
{
  sack_block_t *blks = tc->rcv_opts.sacks, *blk;
  tcp_tx_tracker_t *tt = tc->tx_tracker;
  tcp_tx_sample_t *cur, *prev;
  int i;

  for (i = 0; i < vec_len (blks); i++)
    {
      blk = &blks[i];

      prev = tcp_tx_tracker_lookup_seq (tt, blk->start);
      if (!prev)
	continue;

      tcp_tx_sample_to_rate_sample (tc, prev, rs);
      while ((cur = tcp_tx_tracker_get_sample (tt, prev->next)))
	{
	  if (seq_leq (blk->end, cur->min_seq))
	    break;

	  tcp_tx_tracker_free_sample (tt, prev);
	  tcp_tx_sample_to_rate_sample (tc, cur, rs);
	  prev = cur;
	}
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

  tc->delivered_time = tcp_time_now_us (tc->c_thread_index);
  tc->delivered += delivered;

  if (tc->bytes_acked)
    tcp_tx_tracker_walk_samples (tc, rs);

  if (tc->sack_sb.last_sacked_bytes)
    tcp_tx_tracker_walk_samples_ooo (tc, rs);
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
