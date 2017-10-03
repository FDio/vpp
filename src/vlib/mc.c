/*
 * mc.c: vlib reliable sequenced multicast distributed applications
 *
 * Copyright (c) 2010 Cisco and/or its affiliates.
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

#include <vlib/vlib.h>

/*
 * 1 to enable msg id training wheels, which are useful for tracking
 * down catchup and/or partitioned network problems
 */
#define MSG_ID_DEBUG 0

static format_function_t format_mc_stream_state;

static u32
elog_id_for_peer_id (mc_main_t * m, u64 peer_id)
{
  uword *p, r;
  mhash_t *h = &m->elog_id_by_peer_id;

  if (!m->elog_id_by_peer_id.hash)
    mhash_init (h, sizeof (uword), sizeof (mc_peer_id_t));

  p = mhash_get (h, &peer_id);
  if (p)
    return p[0];
  r = elog_string (m->elog_main, "%U", m->transport.format_peer_id, peer_id);
  mhash_set (h, &peer_id, r, /* old_value */ 0);
  return r;
}

static u32
elog_id_for_msg_name (mc_main_t * m, char *msg_name)
{
  uword *p, r;
  uword *h = m->elog_id_by_msg_name;
  u8 *name_copy;

  if (!h)
    h = m->elog_id_by_msg_name = hash_create_string (0, sizeof (uword));

  p = hash_get_mem (h, msg_name);
  if (p)
    return p[0];
  r = elog_string (m->elog_main, "%s", msg_name);

  name_copy = format (0, "%s%c", msg_name, 0);

  hash_set_mem (h, name_copy, r);
  m->elog_id_by_msg_name = h;

  return r;
}

static void
elog_tx_msg (mc_main_t * m, u32 stream_id, u32 local_sequence,
	     u32 retry_count)
{
  if (MC_EVENT_LOGGING > 0)
    {
      /* *INDENT-OFF* */
      ELOG_TYPE_DECLARE (e) =
        {
          .format = "tx-msg: stream %d local seq %d attempt %d",
          .format_args = "i4i4i4",
        };
      /* *INDENT-ON* */
      struct
      {
	u32 stream_id, local_sequence, retry_count;
      } *ed;
      ed = ELOG_DATA (m->elog_main, e);
      ed->stream_id = stream_id;
      ed->local_sequence = local_sequence;
      ed->retry_count = retry_count;
    }
}

/*
 * seq_cmp
 * correctly compare two unsigned sequence numbers.
 * This function works so long as x and y are within 2**(n-1) of each
 * other, where n = bits(x, y).
 *
 * Magic decoder ring:
 * seq_cmp == 0 => x and y are equal
 * seq_cmp < 0 => x is "in the past" with respect to y
 * seq_cmp > 0 => x is "in the future" with respect to y
 */
always_inline i32
mc_seq_cmp (u32 x, u32 y)
{
  return (i32) x - (i32) y;
}

void *
mc_get_vlib_buffer (vlib_main_t * vm, u32 n_bytes, u32 * bi_return)
{
  u32 n_alloc, bi;
  vlib_buffer_t *b;

  n_alloc = vlib_buffer_alloc (vm, &bi, 1);
  ASSERT (n_alloc == 1);

  b = vlib_get_buffer (vm, bi);
  b->current_length = n_bytes;
  *bi_return = bi;
  return (void *) b->data;
}

static void
delete_peer_with_index (mc_main_t * mcm, mc_stream_t * s,
			uword index, int notify_application)
{
  mc_stream_peer_t *p = pool_elt_at_index (s->peers, index);
  ASSERT (p != 0);
  if (s->config.peer_died && notify_application)
    s->config.peer_died (mcm, s, p->id);

  s->all_peer_bitmap = clib_bitmap_andnoti (s->all_peer_bitmap, p - s->peers);

  if (MC_EVENT_LOGGING > 0)
    {
      /* *INDENT-OFF* */
      ELOG_TYPE_DECLARE (e) =
        {
          .format = "delete peer %s from all_peer_bitmap",
          .format_args = "T4",
        };
      /* *INDENT-ON* */
      struct
      {
	u32 peer;
      } *ed = 0;

      ed = ELOG_DATA (mcm->elog_main, e);
      ed->peer = elog_id_for_peer_id (mcm, p->id.as_u64);
    }
  /* Do not delete the pool / hash table entries, or we lose sequence number state */
}

static mc_stream_peer_t *
get_or_create_peer_with_id (mc_main_t * mcm,
			    mc_stream_t * s, mc_peer_id_t id, int *created)
{
  uword *q = mhash_get (&s->peer_index_by_id, &id);
  mc_stream_peer_t *p;

  if (q)
    {
      p = pool_elt_at_index (s->peers, q[0]);
      goto done;
    }

  pool_get (s->peers, p);
  memset (p, 0, sizeof (p[0]));
  p->id = id;
  p->last_sequence_received = ~0;
  mhash_set (&s->peer_index_by_id, &id, p - s->peers, /* old_value */ 0);
  if (created)
    *created = 1;

done:
  if (MC_EVENT_LOGGING > 0)
    {
      /* *INDENT-OFF* */
      ELOG_TYPE_DECLARE (e) =
        {
          .format = "get_or_create %s peer %s stream %d seq %d",
          .format_args = "t4T4i4i4",
          .n_enum_strings = 2,
          .enum_strings = {
            "old", "new",
          },
        };
      /* *INDENT-ON* */
      struct
      {
	u32 is_new, peer, stream_index, rx_sequence;
      } *ed = 0;

      ed = ELOG_DATA (mcm->elog_main, e);
      ed->is_new = q ? 0 : 1;
      ed->peer = elog_id_for_peer_id (mcm, p->id.as_u64);
      ed->stream_index = s->index;
      ed->rx_sequence = p->last_sequence_received;
    }
  /* $$$$ Enable or reenable this peer */
  s->all_peer_bitmap = clib_bitmap_ori (s->all_peer_bitmap, p - s->peers);
  return p;
}

static void
maybe_send_window_open_event (vlib_main_t * vm, mc_stream_t * stream)
{
  vlib_one_time_waiting_process_t *p;

  if (pool_elts (stream->retry_pool) >= stream->config.window_size)
    return;

  vec_foreach (p, stream->procs_waiting_for_open_window)
    vlib_signal_one_time_waiting_process (vm, p);

  if (stream->procs_waiting_for_open_window)
    _vec_len (stream->procs_waiting_for_open_window) = 0;
}

static void
mc_retry_free (mc_main_t * mcm, mc_stream_t * s, mc_retry_t * r)
{
  mc_retry_t record, *retp;

  if (r->unacked_by_peer_bitmap)
    _vec_len (r->unacked_by_peer_bitmap) = 0;

  if (clib_fifo_elts (s->retired_fifo) >= 2 * s->config.window_size)
    {
      clib_fifo_sub1 (s->retired_fifo, record);
      vlib_buffer_free_one (mcm->vlib_main, record.buffer_index);
    }

  clib_fifo_add2 (s->retired_fifo, retp);

  retp->buffer_index = r->buffer_index;
  retp->local_sequence = r->local_sequence;

  r->buffer_index = ~0;		/* poison buffer index in this retry */
}

static void
mc_resend_retired (mc_main_t * mcm, mc_stream_t * s, u32 local_sequence)
{
  mc_retry_t *retry;

  if (MC_EVENT_LOGGING > 0)
    {
      /* *INDENT-OFF* */
      ELOG_TYPE_DECLARE (e) =
        {
          .format = "resend-retired: search for local seq %d",
          .format_args = "i4",
        };
      /* *INDENT-ON* */
      struct
      {
	u32 local_sequence;
      } *ed;
      ed = ELOG_DATA (mcm->elog_main, e);
      ed->local_sequence = local_sequence;
    }

  /* *INDENT-OFF* */
  clib_fifo_foreach (retry, s->retired_fifo,
  ({
    if (retry->local_sequence == local_sequence)
      {
        elog_tx_msg (mcm, s->index, retry-> local_sequence, -13);
        mcm->transport.tx_buffer (mcm->transport.opaque,
                                  MC_TRANSPORT_USER_REQUEST_TO_RELAY,
                                  retry->buffer_index);
        return;
      }
  }));
  /* *INDENT-ON* */

  if (MC_EVENT_LOGGING > 0)
    {
      /* *INDENT-OFF* */
      ELOG_TYPE_DECLARE (e) =
        {
          .format = "resend-retired: FAILED search for local seq %d",
          .format_args = "i4",
        };
      /* *INDENT-ON* */
      struct
      {
	u32 local_sequence;
      } *ed;
      ed = ELOG_DATA (mcm->elog_main, e);
      ed->local_sequence = local_sequence;
    }
}

static uword *
delete_retry_fifo_elt (mc_main_t * mcm,
		       mc_stream_t * stream,
		       mc_retry_t * r, uword * dead_peer_bitmap)
{
  mc_stream_peer_t *p;

  /* *INDENT-OFF* */
  pool_foreach (p, stream->peers, ({
    uword pi = p - stream->peers;
    uword is_alive = 0 == clib_bitmap_get (r->unacked_by_peer_bitmap, pi);

    if (! is_alive)
      dead_peer_bitmap = clib_bitmap_ori (dead_peer_bitmap, pi);

    if (MC_EVENT_LOGGING > 0)
      {
        ELOG_TYPE_DECLARE (e) = {
          .format = "delete_retry_fifo_elt: peer %s is %s",
          .format_args = "T4t4",
          .n_enum_strings = 2,
          .enum_strings = { "alive", "dead", },
        };
        struct { u32 peer, is_alive; } * ed;
        ed = ELOG_DATA (mcm->elog_main, e);
        ed->peer = elog_id_for_peer_id (mcm, p->id.as_u64);
        ed->is_alive = is_alive;
      }
  }));
  /* *INDENT-ON* */

  hash_unset (stream->retry_index_by_local_sequence, r->local_sequence);
  mc_retry_free (mcm, stream, r);

  return dead_peer_bitmap;
}

always_inline mc_retry_t *
prev_retry (mc_stream_t * s, mc_retry_t * r)
{
  return (r->prev_index != ~0
	  ? pool_elt_at_index (s->retry_pool, r->prev_index) : 0);
}

always_inline mc_retry_t *
next_retry (mc_stream_t * s, mc_retry_t * r)
{
  return (r->next_index != ~0
	  ? pool_elt_at_index (s->retry_pool, r->next_index) : 0);
}

always_inline void
remove_retry_from_pool (mc_stream_t * s, mc_retry_t * r)
{
  mc_retry_t *p = prev_retry (s, r);
  mc_retry_t *n = next_retry (s, r);

  if (p)
    p->next_index = r->next_index;
  else
    s->retry_head_index = r->next_index;
  if (n)
    n->prev_index = r->prev_index;
  else
    s->retry_tail_index = r->prev_index;

  pool_put_index (s->retry_pool, r - s->retry_pool);
}

static void
check_retry (mc_main_t * mcm, mc_stream_t * s)
{
  mc_retry_t *r;
  vlib_main_t *vm = mcm->vlib_main;
  f64 now = vlib_time_now (vm);
  uword *dead_peer_bitmap = 0;
  u32 ri, ri_next;

  for (ri = s->retry_head_index; ri != ~0; ri = ri_next)
    {
      r = pool_elt_at_index (s->retry_pool, ri);
      ri_next = r->next_index;

      if (now < r->sent_at + s->config.retry_interval)
	continue;

      r->n_retries += 1;
      if (r->n_retries > s->config.retry_limit)
	{
	  dead_peer_bitmap =
	    delete_retry_fifo_elt (mcm, s, r, dead_peer_bitmap);
	  remove_retry_from_pool (s, r);
	}
      else
	{
	  if (MC_EVENT_LOGGING > 0)
	    {
	      mc_stream_peer_t *p;

              /* *INDENT-OFF* */
	      ELOG_TYPE_DECLARE (t) =
                {
                  .format = "resend local seq %d attempt %d",
                  .format_args = "i4i4",
                };
              /* *INDENT-ON* */

              /* *INDENT-OFF* */
	      pool_foreach (p, s->peers, ({
		if (clib_bitmap_get (r->unacked_by_peer_bitmap, p - s->peers))
		  {
		    ELOG_TYPE_DECLARE (ev) = {
		      .format = "resend: needed by peer %s local seq %d",
		      .format_args = "T4i4",
		    };
		    struct { u32 peer, rx_sequence; } * ed;
		    ed = ELOG_DATA (mcm->elog_main, ev);
		    ed->peer = elog_id_for_peer_id (mcm, p->id.as_u64);
		    ed->rx_sequence = r->local_sequence;
		  }
	      }));
              /* *INDENT-ON* */

	      struct
	      {
		u32 sequence;
		u32 trail;
	      } *ed;
	      ed = ELOG_DATA (mcm->elog_main, t);
	      ed->sequence = r->local_sequence;
	      ed->trail = r->n_retries;
	    }

	  r->sent_at = vlib_time_now (vm);
	  s->stats.n_retries += 1;

	  elog_tx_msg (mcm, s->index, r->local_sequence, r->n_retries);

	  mcm->transport.tx_buffer
	    (mcm->transport.opaque,
	     MC_TRANSPORT_USER_REQUEST_TO_RELAY, r->buffer_index);
	}
    }

  maybe_send_window_open_event (mcm->vlib_main, s);

  /* Delete any dead peers we've found. */
  if (!clib_bitmap_is_zero (dead_peer_bitmap))
    {
      uword i;

      /* *INDENT-OFF* */
      clib_bitmap_foreach (i, dead_peer_bitmap, ({
	delete_peer_with_index (mcm, s, i, /* notify_application */ 1);

	/* Delete any references to just deleted peer in retry pool. */
	pool_foreach (r, s->retry_pool, ({
	  r->unacked_by_peer_bitmap =
	    clib_bitmap_andnoti (r->unacked_by_peer_bitmap, i);
	}));
      }));
/* *INDENT-ON* */
      clib_bitmap_free (dead_peer_bitmap);
    }
}

always_inline mc_main_t *
mc_node_get_main (vlib_node_runtime_t * node)
{
  mc_main_t **p = (void *) node->runtime_data;
  return p[0];
}

static uword
mc_retry_process (vlib_main_t * vm,
		  vlib_node_runtime_t * node, vlib_frame_t * f)
{
  mc_main_t *mcm = mc_node_get_main (node);
  mc_stream_t *s;

  while (1)
    {
      vlib_process_suspend (vm, 1.0);
      vec_foreach (s, mcm->stream_vector)
      {
	if (s->state != MC_STREAM_STATE_invalid)
	  check_retry (mcm, s);
      }
    }
  return 0;			/* not likely */
}

static void
send_join_or_leave_request (mc_main_t * mcm, u32 stream_index, u32 is_join)
{
  vlib_main_t *vm = mcm->vlib_main;
  mc_msg_join_or_leave_request_t *mp;
  u32 bi;

  mp = mc_get_vlib_buffer (vm, sizeof (mp[0]), &bi);
  memset (mp, 0, sizeof (*mp));
  mp->type = MC_MSG_TYPE_join_or_leave_request;
  mp->peer_id = mcm->transport.our_ack_peer_id;
  mp->stream_index = stream_index;
  mp->is_join = is_join;

  mc_byte_swap_msg_join_or_leave_request (mp);

  /*
   * These msgs are unnumbered, unordered so send on the from-relay
   * channel.
   */
  mcm->transport.tx_buffer (mcm->transport.opaque, MC_TRANSPORT_JOIN, bi);
}

static uword
mc_join_ager_process (vlib_main_t * vm,
		      vlib_node_runtime_t * node, vlib_frame_t * f)
{
  mc_main_t *mcm = mc_node_get_main (node);

  while (1)
    {
      if (mcm->joins_in_progress)
	{
	  mc_stream_t *s;
	  vlib_one_time_waiting_process_t *p;
	  f64 now = vlib_time_now (vm);

	  vec_foreach (s, mcm->stream_vector)
	  {
	    if (s->state != MC_STREAM_STATE_join_in_progress)
	      continue;

	    if (now > s->join_timeout)
	      {
		s->state = MC_STREAM_STATE_ready;

		if (MC_EVENT_LOGGING > 0)
		  {
                    /* *INDENT-OFF* */
		    ELOG_TYPE_DECLARE (e) =
                      {
                        .format = "stream %d join timeout",
                      };
                    /* *INDENT-ON* */
		    ELOG (mcm->elog_main, e, s->index);
		  }
		/* Make sure that this app instance exists as a stream peer,
		   or we may answer a catchup request with a NULL
		   all_peer_bitmap... */
		(void) get_or_create_peer_with_id
		  (mcm, s, mcm->transport.our_ack_peer_id, /* created */ 0);

		vec_foreach (p, s->procs_waiting_for_join_done)
		  vlib_signal_one_time_waiting_process (vm, p);
		if (s->procs_waiting_for_join_done)
		  _vec_len (s->procs_waiting_for_join_done) = 0;

		mcm->joins_in_progress--;
		ASSERT (mcm->joins_in_progress >= 0);
	      }
	    else
	      {
		/* Resent join request which may have been lost. */
		send_join_or_leave_request (mcm, s->index, 1 /* is_join */ );

		/* We're *not* alone, retry for as long as it takes */
		if (mcm->relay_state == MC_RELAY_STATE_SLAVE)
		  s->join_timeout = vlib_time_now (vm) + 2.0;


		if (MC_EVENT_LOGGING > 0)
		  {
                    /* *INDENT-OFF* */
		    ELOG_TYPE_DECLARE (e) =
                      {
                        .format = "stream %d resend join request",
                      };
                    /* *INDENT-ON* */
		    ELOG (mcm->elog_main, e, s->index);
		  }
	      }
	  }
	}

      vlib_process_suspend (vm, .5);
    }

  return 0;			/* not likely */
}

static void
serialize_mc_register_stream_name (serialize_main_t * m, va_list * va)
{
  char *name = va_arg (*va, char *);
  serialize_cstring (m, name);
}

static void
elog_stream_name (char *buf, int n_buf_bytes, char *v)
{
  clib_memcpy (buf, v, clib_min (n_buf_bytes - 1, vec_len (v)));
  buf[n_buf_bytes - 1] = 0;
}

static void
unserialize_mc_register_stream_name (serialize_main_t * m, va_list * va)
{
  mc_main_t *mcm = va_arg (*va, mc_main_t *);
  char *name;
  mc_stream_t *s;
  uword *p;

  unserialize_cstring (m, &name);

  if ((p = hash_get_mem (mcm->stream_index_by_name, name)))
    {
      if (MC_EVENT_LOGGING > 0)
	{
          /* *INDENT-OFF* */
	  ELOG_TYPE_DECLARE (e) =
            {
              .format = "stream index %d already named %s",
              .format_args = "i4s16",
            };
          /* *INDENT-ON* */
	  struct
	  {
	    u32 stream_index;
	    char name[16];
	  } *ed;
	  ed = ELOG_DATA (mcm->elog_main, e);
	  ed->stream_index = p[0];
	  elog_stream_name (ed->name, sizeof (ed->name), name);
	}

      vec_free (name);
      return;
    }

  vec_add2 (mcm->stream_vector, s, 1);
  mc_stream_init (s);
  s->state = MC_STREAM_STATE_name_known;
  s->index = s - mcm->stream_vector;
  s->config.name = name;

  if (MC_EVENT_LOGGING > 0)
    {
      /* *INDENT-OFF* */
      ELOG_TYPE_DECLARE (e) =
        {
          .format = "stream index %d named %s",
          .format_args = "i4s16",
        };
      /* *INDENT-ON* */
      struct
      {
	u32 stream_index;
	char name[16];
      } *ed;
      ed = ELOG_DATA (mcm->elog_main, e);
      ed->stream_index = s->index;
      elog_stream_name (ed->name, sizeof (ed->name), name);
    }

  hash_set_mem (mcm->stream_index_by_name, name, s->index);

  p = hash_get (mcm->procs_waiting_for_stream_name_by_name, name);
  if (p)
    {
      vlib_one_time_waiting_process_t *wp, **w;
      w = pool_elt_at_index (mcm->procs_waiting_for_stream_name_pool, p[0]);
      vec_foreach (wp, w[0])
	vlib_signal_one_time_waiting_process (mcm->vlib_main, wp);
      pool_put (mcm->procs_waiting_for_stream_name_pool, w);
      hash_unset_mem (mcm->procs_waiting_for_stream_name_by_name, name);
    }
}

/* *INDENT-OFF* */
MC_SERIALIZE_MSG (mc_register_stream_name_msg, static) =
{
  .name = "mc_register_stream_name",
  .serialize = serialize_mc_register_stream_name,
  .unserialize = unserialize_mc_register_stream_name,
};
/* *INDENT-ON* */

void
mc_rx_buffer_unserialize (mc_main_t * mcm,
			  mc_stream_t * stream,
			  mc_peer_id_t peer_id, u32 buffer_index)
{
  return mc_unserialize (mcm, stream, buffer_index);
}

static u8 *
mc_internal_catchup_snapshot (mc_main_t * mcm,
			      u8 * data_vector,
			      u32 last_global_sequence_processed)
{
  serialize_main_t m;

  /* Append serialized data to data vector. */
  serialize_open_vector (&m, data_vector);
  m.stream.current_buffer_index = vec_len (data_vector);

  serialize (&m, serialize_mc_main, mcm);
  return serialize_close_vector (&m);
}

static void
mc_internal_catchup (mc_main_t * mcm, u8 * data, u32 n_data_bytes)
{
  serialize_main_t s;

  unserialize_open_data (&s, data, n_data_bytes);

  unserialize (&s, unserialize_mc_main, mcm);
}

/* Overridden from the application layer, not actually used here */
void mc_stream_join_process_hold (void) __attribute__ ((weak));
void
mc_stream_join_process_hold (void)
{
}

static u32
mc_stream_join_helper (mc_main_t * mcm,
		       mc_stream_config_t * config, u32 is_internal)
{
  mc_stream_t *s;
  vlib_main_t *vm = mcm->vlib_main;

  s = 0;
  if (!is_internal)
    {
      uword *p;

      /* Already have a stream with given name? */
      if ((s = mc_stream_by_name (mcm, config->name)))
	{
	  /* Already joined and ready? */
	  if (s->state == MC_STREAM_STATE_ready)
	    return s->index;
	}

      /* First join MC internal stream. */
      if (!mcm->stream_vector
	  || (mcm->stream_vector[MC_STREAM_INDEX_INTERNAL].state
	      == MC_STREAM_STATE_invalid))
	{
	  static mc_stream_config_t c = {
	    .name = "mc-internal",
	    .rx_buffer = mc_rx_buffer_unserialize,
	    .catchup = mc_internal_catchup,
	    .catchup_snapshot = mc_internal_catchup_snapshot,
	  };

	  c.save_snapshot = config->save_snapshot;

	  mc_stream_join_helper (mcm, &c, /* is_internal */ 1);
	}

      /* If stream is still unknown register this name and wait for
         sequenced message to name stream.  This way all peers agree
         on stream name to index mappings. */
      s = mc_stream_by_name (mcm, config->name);
      if (!s)
	{
	  vlib_one_time_waiting_process_t *wp, **w;
	  u8 *name_copy = format (0, "%s", config->name);

	  mc_serialize_stream (mcm,
			       MC_STREAM_INDEX_INTERNAL,
			       &mc_register_stream_name_msg, config->name);

	  /* Wait for this stream to be named. */
	  p =
	    hash_get_mem (mcm->procs_waiting_for_stream_name_by_name,
			  name_copy);
	  if (p)
	    w =
	      pool_elt_at_index (mcm->procs_waiting_for_stream_name_pool,
				 p[0]);
	  else
	    {
	      pool_get (mcm->procs_waiting_for_stream_name_pool, w);
	      if (!mcm->procs_waiting_for_stream_name_by_name)
		mcm->procs_waiting_for_stream_name_by_name = hash_create_string ( /* elts */ 0,	/* value size */
										 sizeof
										 (uword));
	      hash_set_mem (mcm->procs_waiting_for_stream_name_by_name,
			    name_copy,
			    w - mcm->procs_waiting_for_stream_name_pool);
	      w[0] = 0;
	    }

	  vec_add2 (w[0], wp, 1);
	  vlib_current_process_wait_for_one_time_event (vm, wp);
	  vec_free (name_copy);
	}

      /* Name should be known now. */
      s = mc_stream_by_name (mcm, config->name);
      ASSERT (s != 0);
      ASSERT (s->state == MC_STREAM_STATE_name_known);
    }

  if (!s)
    {
      vec_add2 (mcm->stream_vector, s, 1);
      mc_stream_init (s);
      s->index = s - mcm->stream_vector;
    }

  {
    /* Save name since we could have already used it as hash key. */
    char *name_save = s->config.name;

    s->config = config[0];

    if (name_save)
      s->config.name = name_save;
  }

  if (s->config.window_size == 0)
    s->config.window_size = 8;

  if (s->config.retry_interval == 0.0)
    s->config.retry_interval = 1.0;

  /* Sanity. */
  ASSERT (s->config.retry_interval < 30);

  if (s->config.retry_limit == 0)
    s->config.retry_limit = 7;

  s->state = MC_STREAM_STATE_join_in_progress;
  if (!s->peer_index_by_id.hash)
    mhash_init (&s->peer_index_by_id, sizeof (uword), sizeof (mc_peer_id_t));

  /* If we don't hear from someone in 5 seconds, we're alone */
  s->join_timeout = vlib_time_now (vm) + 5.0;
  mcm->joins_in_progress++;

  if (MC_EVENT_LOGGING > 0)
    {
      /* *INDENT-OFF* */
      ELOG_TYPE_DECLARE (e) =
      {
        .format = "stream index %d join request %s",
        .format_args = "i4s16",
      };
      /* *INDENT-ON* */
      struct
      {
	u32 stream_index;
	char name[16];
      } *ed;
      ed = ELOG_DATA (mcm->elog_main, e);
      ed->stream_index = s->index;
      elog_stream_name (ed->name, sizeof (ed->name), s->config.name);
    }

  send_join_or_leave_request (mcm, s->index, 1 /* join */ );

  vlib_current_process_wait_for_one_time_event_vector
    (vm, &s->procs_waiting_for_join_done);

  if (MC_EVENT_LOGGING)
    {
      ELOG_TYPE (e, "join complete stream %d");
      ELOG (mcm->elog_main, e, s->index);
    }

  return s->index;
}

u32
mc_stream_join (mc_main_t * mcm, mc_stream_config_t * config)
{
  return mc_stream_join_helper (mcm, config, /* is_internal */ 0);
}

void
mc_stream_leave (mc_main_t * mcm, u32 stream_index)
{
  mc_stream_t *s = mc_stream_by_index (mcm, stream_index);

  if (!s)
    return;

  if (MC_EVENT_LOGGING)
    {
      /* *INDENT-OFF* */
      ELOG_TYPE_DECLARE (t) =
        {
          .format = "leave-stream: %d",.format_args = "i4",
        };
      /* *INDENT-ON* */
      struct
      {
	u32 index;
      } *ed;
      ed = ELOG_DATA (mcm->elog_main, t);
      ed->index = stream_index;
    }

  send_join_or_leave_request (mcm, stream_index, 0 /* is_join */ );
  mc_stream_free (s);
  s->state = MC_STREAM_STATE_name_known;
}

void
mc_msg_join_or_leave_request_handler (mc_main_t * mcm,
				      mc_msg_join_or_leave_request_t * req,
				      u32 buffer_index)
{
  mc_stream_t *s;
  mc_msg_join_reply_t *rep;
  u32 bi;

  mc_byte_swap_msg_join_or_leave_request (req);

  s = mc_stream_by_index (mcm, req->stream_index);
  if (!s || s->state != MC_STREAM_STATE_ready)
    return;

  /* If the peer is joining, create it */
  if (req->is_join)
    {
      mc_stream_t *this_s;

      /* We're not in a position to catch up a peer until all
         stream joins are complete. */
      if (0)
	{
	  /* XXX This is hard to test so we've. */
	  vec_foreach (this_s, mcm->stream_vector)
	  {
	    if (this_s->state != MC_STREAM_STATE_ready
		&& this_s->state != MC_STREAM_STATE_name_known)
	      return;
	  }
	}
      else if (mcm->joins_in_progress > 0)
	return;

      (void) get_or_create_peer_with_id (mcm, s, req->peer_id,
					 /* created */ 0);

      rep = mc_get_vlib_buffer (mcm->vlib_main, sizeof (rep[0]), &bi);
      memset (rep, 0, sizeof (rep[0]));
      rep->type = MC_MSG_TYPE_join_reply;
      rep->stream_index = req->stream_index;

      mc_byte_swap_msg_join_reply (rep);
      /* These two are already in network byte order... */
      rep->peer_id = mcm->transport.our_ack_peer_id;
      rep->catchup_peer_id = mcm->transport.our_catchup_peer_id;

      mcm->transport.tx_buffer (mcm->transport.opaque, MC_TRANSPORT_JOIN, bi);
    }
  else
    {
      if (s->config.peer_died)
	s->config.peer_died (mcm, s, req->peer_id);
    }
}

void
mc_msg_join_reply_handler (mc_main_t * mcm,
			   mc_msg_join_reply_t * mp, u32 buffer_index)
{
  mc_stream_t *s;

  mc_byte_swap_msg_join_reply (mp);

  s = mc_stream_by_index (mcm, mp->stream_index);

  if (!s || s->state != MC_STREAM_STATE_join_in_progress)
    return;

  /* Switch to catchup state; next join reply
     for this stream will be ignored. */
  s->state = MC_STREAM_STATE_catchup;

  mcm->joins_in_progress--;
  mcm->transport.catchup_request_fun (mcm->transport.opaque,
				      mp->stream_index, mp->catchup_peer_id);
}

void
mc_wait_for_stream_ready (mc_main_t * m, char *stream_name)
{
  mc_stream_t *s;

  while (1)
    {
      s = mc_stream_by_name (m, stream_name);
      if (s)
	break;
      vlib_process_suspend (m->vlib_main, .1);
    }

  /* It's OK to send a message in catchup and ready states. */
  if (s->state == MC_STREAM_STATE_catchup
      || s->state == MC_STREAM_STATE_ready)
    return;

  /* Otherwise we are waiting for a join to finish. */
  vlib_current_process_wait_for_one_time_event_vector
    (m->vlib_main, &s->procs_waiting_for_join_done);
}

u32
mc_stream_send (mc_main_t * mcm, u32 stream_index, u32 buffer_index)
{
  mc_stream_t *s = mc_stream_by_index (mcm, stream_index);
  vlib_main_t *vm = mcm->vlib_main;
  mc_retry_t *r;
  mc_msg_user_request_t *mp;
  vlib_buffer_t *b = vlib_get_buffer (vm, buffer_index);
  u32 ri;

  if (!s)
    return 0;

  if (s->state != MC_STREAM_STATE_ready)
    vlib_current_process_wait_for_one_time_event_vector
      (vm, &s->procs_waiting_for_join_done);

  while (pool_elts (s->retry_pool) >= s->config.window_size)
    {
      vlib_current_process_wait_for_one_time_event_vector
	(vm, &s->procs_waiting_for_open_window);
    }

  pool_get (s->retry_pool, r);
  ri = r - s->retry_pool;

  r->prev_index = s->retry_tail_index;
  r->next_index = ~0;
  s->retry_tail_index = ri;

  if (r->prev_index == ~0)
    s->retry_head_index = ri;
  else
    {
      mc_retry_t *p = pool_elt_at_index (s->retry_pool, r->prev_index);
      p->next_index = ri;
    }

  vlib_buffer_advance (b, -sizeof (mp[0]));
  mp = vlib_buffer_get_current (b);

  mp->peer_id = mcm->transport.our_ack_peer_id;
  /* mp->transport.global_sequence set by relay agent. */
  mp->global_sequence = 0xdeadbeef;
  mp->stream_index = s->index;
  mp->local_sequence = s->our_local_sequence++;
  mp->n_data_bytes =
    vlib_buffer_index_length_in_chain (vm, buffer_index) - sizeof (mp[0]);

  r->buffer_index = buffer_index;
  r->local_sequence = mp->local_sequence;
  r->sent_at = vlib_time_now (vm);
  r->n_retries = 0;

  /* Retry will be freed when all currently known peers have acked. */
  vec_validate (r->unacked_by_peer_bitmap, vec_len (s->all_peer_bitmap) - 1);
  vec_copy (r->unacked_by_peer_bitmap, s->all_peer_bitmap);

  hash_set (s->retry_index_by_local_sequence, r->local_sequence,
	    r - s->retry_pool);

  elog_tx_msg (mcm, s->index, mp->local_sequence, r->n_retries);

  mc_byte_swap_msg_user_request (mp);

  mcm->transport.tx_buffer (mcm->transport.opaque,
			    MC_TRANSPORT_USER_REQUEST_TO_RELAY, buffer_index);

  s->user_requests_sent++;

  /* return amount of window remaining */
  return s->config.window_size - pool_elts (s->retry_pool);
}

void
mc_msg_user_request_handler (mc_main_t * mcm, mc_msg_user_request_t * mp,
			     u32 buffer_index)
{
  vlib_main_t *vm = mcm->vlib_main;
  mc_stream_t *s;
  mc_stream_peer_t *peer;
  i32 seq_cmp_result;
  static int once = 0;

  mc_byte_swap_msg_user_request (mp);

  s = mc_stream_by_index (mcm, mp->stream_index);

  /* Not signed up for this stream? Turf-o-matic */
  if (!s || s->state != MC_STREAM_STATE_ready)
    {
      vlib_buffer_free_one (vm, buffer_index);
      return;
    }

  /* Find peer, including ourselves. */
  peer = get_or_create_peer_with_id (mcm, s, mp->peer_id,
				     /* created */ 0);

  seq_cmp_result = mc_seq_cmp (mp->local_sequence,
			       peer->last_sequence_received + 1);

  if (MC_EVENT_LOGGING > 0)
    {
      /* *INDENT-OFF* */
      ELOG_TYPE_DECLARE (e) =
        {
          .format = "rx-msg: peer %s stream %d rx seq %d seq_cmp %d",
          .format_args = "T4i4i4i4",
        };
      /* *INDENT-ON* */
      struct
      {
	u32 peer, stream_index, rx_sequence;
	i32 seq_cmp_result;
      } *ed;
      ed = ELOG_DATA (mcm->elog_main, e);
      ed->peer = elog_id_for_peer_id (mcm, peer->id.as_u64);
      ed->stream_index = mp->stream_index;
      ed->rx_sequence = mp->local_sequence;
      ed->seq_cmp_result = seq_cmp_result;
    }

  if (0 && mp->stream_index == 1 && once == 0)
    {
      once = 1;
      ELOG_TYPE (e, "FAKE lost msg on stream 1");
      ELOG (mcm->elog_main, e, 0);
      return;
    }

  peer->last_sequence_received += seq_cmp_result == 0;
  s->user_requests_received++;

  if (seq_cmp_result > 0)
    peer->stats.n_msgs_from_future += 1;

  /* Send ack even if msg from future */
  if (1)
    {
      mc_msg_user_ack_t *rp;
      u32 bi;

      rp = mc_get_vlib_buffer (vm, sizeof (rp[0]), &bi);
      rp->peer_id = mcm->transport.our_ack_peer_id;
      rp->stream_index = s->index;
      rp->local_sequence = mp->local_sequence;
      rp->seq_cmp_result = seq_cmp_result;

      if (MC_EVENT_LOGGING > 0)
	{
          /* *INDENT-OFF* */
	  ELOG_TYPE_DECLARE (e) =
            {
              .format = "tx-ack: stream %d local seq %d",
              .format_args = "i4i4",
            };
          /* *INDENT-ON* */
	  struct
	  {
	    u32 stream_index;
	    u32 local_sequence;
	  } *ed;
	  ed = ELOG_DATA (mcm->elog_main, e);
	  ed->stream_index = rp->stream_index;
	  ed->local_sequence = rp->local_sequence;
	}

      mc_byte_swap_msg_user_ack (rp);

      mcm->transport.tx_ack (mcm->transport.opaque, mp->peer_id, bi);
      /* Msg from past? If so, free the buffer... */
      if (seq_cmp_result < 0)
	{
	  vlib_buffer_free_one (vm, buffer_index);
	  peer->stats.n_msgs_from_past += 1;
	}
    }

  if (seq_cmp_result == 0)
    {
      vlib_buffer_t *b = vlib_get_buffer (vm, buffer_index);
      switch (s->state)
	{
	case MC_STREAM_STATE_ready:
	  vlib_buffer_advance (b, sizeof (mp[0]));
	  s->config.rx_buffer (mcm, s, mp->peer_id, buffer_index);

	  /* Stream vector can change address via rx callback for mc-internal
	     stream. */
	  s = mc_stream_by_index (mcm, mp->stream_index);
	  ASSERT (s != 0);
	  s->last_global_sequence_processed = mp->global_sequence;
	  break;

	case MC_STREAM_STATE_catchup:
	  clib_fifo_add1 (s->catchup_fifo, buffer_index);
	  break;

	default:
	  clib_warning ("stream in unknown state %U",
			format_mc_stream_state, s->state);
	  break;
	}
    }
}

void
mc_msg_user_ack_handler (mc_main_t * mcm, mc_msg_user_ack_t * mp,
			 u32 buffer_index)
{
  vlib_main_t *vm = mcm->vlib_main;
  uword *p;
  mc_stream_t *s;
  mc_stream_peer_t *peer;
  mc_retry_t *r;
  int peer_created = 0;

  mc_byte_swap_msg_user_ack (mp);

  s = mc_stream_by_index (mcm, mp->stream_index);

  if (MC_EVENT_LOGGING > 0)
    {
      /* *INDENT-OFF* */
      ELOG_TYPE_DECLARE (t) =
        {
          .format = "rx-ack: local seq %d peer %s seq_cmp_result %d",
          .format_args = "i4T4i4",
        };
      /* *INDENT-ON* */

      struct
      {
	u32 local_sequence;
	u32 peer;
	i32 seq_cmp_result;
      } *ed;
      ed = ELOG_DATA (mcm->elog_main, t);
      ed->local_sequence = mp->local_sequence;
      ed->peer = elog_id_for_peer_id (mcm, mp->peer_id.as_u64);
      ed->seq_cmp_result = mp->seq_cmp_result;
    }

  /* Unknown stream? */
  if (!s)
    return;

  /* Find the peer which just ack'ed. */
  peer = get_or_create_peer_with_id (mcm, s, mp->peer_id,
				     /* created */ &peer_created);

  /*
   * Peer reports message from the future. If it's not in the retry
   * fifo, look for a retired message.
   */
  if (mp->seq_cmp_result > 0)
    {
      p = hash_get (s->retry_index_by_local_sequence, mp->local_sequence -
		    mp->seq_cmp_result);
      if (p == 0)
	mc_resend_retired (mcm, s, mp->local_sequence - mp->seq_cmp_result);

      /* Normal retry should fix it... */
      return;
    }

  /*
   * Pointer to the indicated retry fifo entry.
   * Worth hashing because we could use a window size of 100 or 1000.
   */
  p = hash_get (s->retry_index_by_local_sequence, mp->local_sequence);

  /*
   * Is this a duplicate ACK, received after we've retired the
   * fifo entry. This can happen when learning about new
   * peers.
   */
  if (p == 0)
    {
      if (MC_EVENT_LOGGING > 0)
	{
          /* *INDENT-OFF* */
	  ELOG_TYPE_DECLARE (t) =
            {
              .format = "ack: for seq %d from peer %s no fifo elt",
              .format_args = "i4T4",
            };
          /* *INDENT-ON* */

	  struct
	  {
	    u32 seq;
	    u32 peer;
	  } *ed;
	  ed = ELOG_DATA (mcm->elog_main, t);
	  ed->seq = mp->local_sequence;
	  ed->peer = elog_id_for_peer_id (mcm, mp->peer_id.as_u64);
	}

      return;
    }

  r = pool_elt_at_index (s->retry_pool, p[0]);

  /* Make sure that this new peer ACKs our msgs from now on */
  if (peer_created)
    {
      mc_retry_t *later_retry = next_retry (s, r);

      while (later_retry)
	{
	  later_retry->unacked_by_peer_bitmap =
	    clib_bitmap_ori (later_retry->unacked_by_peer_bitmap,
			     peer - s->peers);
	  later_retry = next_retry (s, later_retry);
	}
    }

  ASSERT (mp->local_sequence == r->local_sequence);

  /* If we weren't expecting to hear from this peer */
  if (!peer_created &&
      !clib_bitmap_get (r->unacked_by_peer_bitmap, peer - s->peers))
    {
      if (MC_EVENT_LOGGING > 0)
	{
          /* *INDENT-OFF* */
	  ELOG_TYPE_DECLARE (t) =
            {
              .format = "dup-ack: for seq %d from peer %s",
              .format_args = "i4T4",
            };
          /* *INDENT-ON* */
	  struct
	  {
	    u32 seq;
	    u32 peer;
	  } *ed;
	  ed = ELOG_DATA (mcm->elog_main, t);
	  ed->seq = r->local_sequence;
	  ed->peer = elog_id_for_peer_id (mcm, peer->id.as_u64);
	}
      if (!clib_bitmap_is_zero (r->unacked_by_peer_bitmap))
	return;
    }

  if (MC_EVENT_LOGGING > 0)
    {
      /* *INDENT-OFF* */
      ELOG_TYPE_DECLARE (t) =
        {
          .format = "ack: for seq %d from peer %s",
          .format_args = "i4T4",
        };
      /* *INDENT-ON* */
      struct
      {
	u32 seq;
	u32 peer;
      } *ed;
      ed = ELOG_DATA (mcm->elog_main, t);
      ed->seq = mp->local_sequence;
      ed->peer = elog_id_for_peer_id (mcm, peer->id.as_u64);
    }

  r->unacked_by_peer_bitmap =
    clib_bitmap_andnoti (r->unacked_by_peer_bitmap, peer - s->peers);

  /* Not all clients have ack'ed */
  if (!clib_bitmap_is_zero (r->unacked_by_peer_bitmap))
    {
      return;
    }
  if (MC_EVENT_LOGGING > 0)
    {
      /* *INDENT-OFF* */
      ELOG_TYPE_DECLARE (t) =
        {
          .format = "ack: retire fifo elt loc seq %d after %d acks",
          .format_args = "i4i4",
        };
      /* *INDENT-ON* */
      struct
      {
	u32 seq;
	u32 npeers;
      } *ed;
      ed = ELOG_DATA (mcm->elog_main, t);
      ed->seq = r->local_sequence;
      ed->npeers = pool_elts (s->peers);
    }

  hash_unset (s->retry_index_by_local_sequence, mp->local_sequence);
  mc_retry_free (mcm, s, r);
  remove_retry_from_pool (s, r);
  maybe_send_window_open_event (vm, s);
}

#define EVENT_MC_SEND_CATCHUP_DATA 0

static uword
mc_catchup_process (vlib_main_t * vm,
		    vlib_node_runtime_t * node, vlib_frame_t * f)
{
  mc_main_t *mcm = mc_node_get_main (node);
  uword *event_data = 0;
  mc_catchup_process_arg_t *args;
  int i;

  while (1)
    {
      if (event_data)
	_vec_len (event_data) = 0;
      vlib_process_wait_for_event_with_type (vm, &event_data,
					     EVENT_MC_SEND_CATCHUP_DATA);

      for (i = 0; i < vec_len (event_data); i++)
	{
	  args = pool_elt_at_index (mcm->catchup_process_args, event_data[i]);

	  mcm->transport.catchup_send_fun (mcm->transport.opaque,
					   args->catchup_opaque,
					   args->catchup_snapshot);

	  /* Send function will free snapshot data vector. */
	  pool_put (mcm->catchup_process_args, args);
	}
    }

  return 0;			/* not likely */
}

static void
serialize_mc_stream (serialize_main_t * m, va_list * va)
{
  mc_stream_t *s = va_arg (*va, mc_stream_t *);
  mc_stream_peer_t *p;

  serialize_integer (m, pool_elts (s->peers), sizeof (u32));
  /* *INDENT-OFF* */
  pool_foreach (p, s->peers, ({
    u8 * x = serialize_get (m, sizeof (p->id));
    clib_memcpy (x, p->id.as_u8, sizeof (p->id));
    serialize_integer (m, p->last_sequence_received,
                       sizeof (p->last_sequence_received));
  }));
/* *INDENT-ON* */
  serialize_bitmap (m, s->all_peer_bitmap);
}

void
unserialize_mc_stream (serialize_main_t * m, va_list * va)
{
  mc_stream_t *s = va_arg (*va, mc_stream_t *);
  u32 i, n_peers;
  mc_stream_peer_t *p;

  unserialize_integer (m, &n_peers, sizeof (u32));
  mhash_init (&s->peer_index_by_id, sizeof (uword), sizeof (mc_peer_id_t));
  for (i = 0; i < n_peers; i++)
    {
      u8 *x;
      pool_get (s->peers, p);
      x = unserialize_get (m, sizeof (p->id));
      clib_memcpy (p->id.as_u8, x, sizeof (p->id));
      unserialize_integer (m, &p->last_sequence_received,
			   sizeof (p->last_sequence_received));
      mhash_set (&s->peer_index_by_id, &p->id, p - s->peers,	/* old_value */
		 0);
    }
  s->all_peer_bitmap = unserialize_bitmap (m);

  /* This is really bad. */
  if (!s->all_peer_bitmap)
    clib_warning ("BUG: stream %s all_peer_bitmap NULL", s->config.name);
}

void
mc_msg_catchup_request_handler (mc_main_t * mcm,
				mc_msg_catchup_request_t * req,
				u32 catchup_opaque)
{
  vlib_main_t *vm = mcm->vlib_main;
  mc_stream_t *s;
  mc_catchup_process_arg_t *args;

  mc_byte_swap_msg_catchup_request (req);

  s = mc_stream_by_index (mcm, req->stream_index);
  if (!s || s->state != MC_STREAM_STATE_ready)
    return;

  if (MC_EVENT_LOGGING > 0)
    {
      /* *INDENT-OFF* */
      ELOG_TYPE_DECLARE (t) =
        {
          .format = "catchup-request: from %s stream %d",
          .format_args = "T4i4",
        };
      /* *INDENT-ON* */
      struct
      {
	u32 peer, stream;
      } *ed;
      ed = ELOG_DATA (mcm->elog_main, t);
      ed->peer = elog_id_for_peer_id (mcm, req->peer_id.as_u64);
      ed->stream = req->stream_index;
    }

  /*
   * The application has to snapshoot its data structures right
   * here, right now. If we process any messages after
   * noting the last global sequence we've processed, the client
   * won't be able to accurately reconstruct our data structures.
   *
   * Once the data structures are e.g. vec_dup()'ed, we
   * send the resulting messages from a separate process, to
   * make sure that we don't cause a bunch of message retransmissions
   */
  pool_get (mcm->catchup_process_args, args);

  args->stream_index = s - mcm->stream_vector;
  args->catchup_opaque = catchup_opaque;
  args->catchup_snapshot = 0;

  /* Construct catchup reply and snapshot state for stream to send as
     catchup reply payload. */
  {
    mc_msg_catchup_reply_t *rep;
    serialize_main_t m;

    vec_resize (args->catchup_snapshot, sizeof (rep[0]));

    rep = (void *) args->catchup_snapshot;

    rep->peer_id = req->peer_id;
    rep->stream_index = req->stream_index;
    rep->last_global_sequence_included = s->last_global_sequence_processed;

    /* Setup for serialize to append to catchup snapshot. */
    serialize_open_vector (&m, args->catchup_snapshot);
    m.stream.current_buffer_index = vec_len (m.stream.buffer);

    serialize (&m, serialize_mc_stream, s);

    args->catchup_snapshot = serialize_close_vector (&m);

    /* Actually copy internal state */
    args->catchup_snapshot = s->config.catchup_snapshot
      (mcm, args->catchup_snapshot, rep->last_global_sequence_included);

    rep = (void *) args->catchup_snapshot;
    rep->n_data_bytes = vec_len (args->catchup_snapshot) - sizeof (rep[0]);

    mc_byte_swap_msg_catchup_reply (rep);
  }

  /* now go send it... */
  vlib_process_signal_event (vm, mcm->catchup_process,
			     EVENT_MC_SEND_CATCHUP_DATA,
			     args - mcm->catchup_process_args);
}

#define EVENT_MC_UNSERIALIZE_BUFFER 0
#define EVENT_MC_UNSERIALIZE_CATCHUP 1

void
mc_msg_catchup_reply_handler (mc_main_t * mcm, mc_msg_catchup_reply_t * mp,
			      u32 catchup_opaque)
{
  vlib_process_signal_event (mcm->vlib_main,
			     mcm->unserialize_process,
			     EVENT_MC_UNSERIALIZE_CATCHUP,
			     pointer_to_uword (mp));
}

static void
perform_catchup (mc_main_t * mcm, mc_msg_catchup_reply_t * mp)
{
  mc_stream_t *s;
  i32 seq_cmp_result;

  mc_byte_swap_msg_catchup_reply (mp);

  s = mc_stream_by_index (mcm, mp->stream_index);

  /* Never heard of this stream or already caught up. */
  if (!s || s->state == MC_STREAM_STATE_ready)
    return;

  {
    serialize_main_t m;
    mc_stream_peer_t *p;
    u32 n_stream_bytes;

    /* For offline sim replay: save the entire catchup snapshot... */
    if (s->config.save_snapshot)
      s->config.save_snapshot (mcm, /* is_catchup */ 1, mp->data,
			       mp->n_data_bytes);

    unserialize_open_data (&m, mp->data, mp->n_data_bytes);
    unserialize (&m, unserialize_mc_stream, s);

    /* Make sure we start numbering our messages as expected */
    /* *INDENT-OFF* */
    pool_foreach (p, s->peers, ({
      if (p->id.as_u64 == mcm->transport.our_ack_peer_id.as_u64)
        s->our_local_sequence = p->last_sequence_received + 1;
    }));
/* *INDENT-ON* */

    n_stream_bytes = m.stream.current_buffer_index;

    /* No need to unserialize close; nothing to free. */

    /* After serialized stream is user's catchup data. */
    s->config.catchup (mcm, mp->data + n_stream_bytes,
		       mp->n_data_bytes - n_stream_bytes);
  }

  /* Vector could have been moved by catchup.
     This can only happen for mc-internal stream. */
  s = mc_stream_by_index (mcm, mp->stream_index);

  s->last_global_sequence_processed = mp->last_global_sequence_included;

  while (clib_fifo_elts (s->catchup_fifo))
    {
      mc_msg_user_request_t *gp;
      u32 bi;
      vlib_buffer_t *b;

      clib_fifo_sub1 (s->catchup_fifo, bi);

      b = vlib_get_buffer (mcm->vlib_main, bi);
      gp = vlib_buffer_get_current (b);

      /* Make sure we're replaying "new" news */
      seq_cmp_result = mc_seq_cmp (gp->global_sequence,
				   mp->last_global_sequence_included);

      if (seq_cmp_result > 0)
	{
	  vlib_buffer_advance (b, sizeof (gp[0]));
	  s->config.rx_buffer (mcm, s, gp->peer_id, bi);
	  s->last_global_sequence_processed = gp->global_sequence;

	  if (MC_EVENT_LOGGING)
	    {
              /* *INDENT-OFF* */
	      ELOG_TYPE_DECLARE (t) =
                {
                  .format = "catchup replay local sequence 0x%x",
                  .format_args = "i4",
                };
              /* *INDENT-ON* */
	      struct
	      {
		u32 local_sequence;
	      } *ed;
	      ed = ELOG_DATA (mcm->elog_main, t);
	      ed->local_sequence = gp->local_sequence;
	    }
	}
      else
	{
	  if (MC_EVENT_LOGGING)
	    {
              /* *INDENT-OFF* */
	      ELOG_TYPE_DECLARE (t) =
                {
                  .format = "catchup discard local sequence 0x%x",
                  .format_args = "i4",
                };
              /* *INDENT-ON* */
	      struct
	      {
		u32 local_sequence;
	      } *ed;
	      ed = ELOG_DATA (mcm->elog_main, t);
	      ed->local_sequence = gp->local_sequence;
	    }

	  vlib_buffer_free_one (mcm->vlib_main, bi);
	}
    }

  s->state = MC_STREAM_STATE_ready;

  /* Now that we are caught up wake up joining process. */
  {
    vlib_one_time_waiting_process_t *wp;
    vec_foreach (wp, s->procs_waiting_for_join_done)
      vlib_signal_one_time_waiting_process (mcm->vlib_main, wp);
    if (s->procs_waiting_for_join_done)
      _vec_len (s->procs_waiting_for_join_done) = 0;
  }
}

static void
this_node_maybe_master (mc_main_t * mcm)
{
  vlib_main_t *vm = mcm->vlib_main;
  mc_msg_master_assert_t *mp;
  uword event_type;
  int timeouts = 0;
  int is_master = mcm->relay_state == MC_RELAY_STATE_MASTER;
  clib_error_t *error;
  f64 now, time_last_master_assert = -1;
  u32 bi;

  while (1)
    {
      if (!mcm->we_can_be_relay_master)
	{
	  mcm->relay_state = MC_RELAY_STATE_SLAVE;
	  if (MC_EVENT_LOGGING)
	    {
	      ELOG_TYPE (e, "become slave (config)");
	      ELOG (mcm->elog_main, e, 0);
	    }
	  return;
	}

      now = vlib_time_now (vm);
      if (now >= time_last_master_assert + 1)
	{
	  time_last_master_assert = now;
	  mp = mc_get_vlib_buffer (mcm->vlib_main, sizeof (mp[0]), &bi);

	  mp->peer_id = mcm->transport.our_ack_peer_id;
	  mp->global_sequence = mcm->relay_global_sequence;

	  /*
	   * these messages clog the event log, set MC_EVENT_LOGGING higher
	   * if you want them
	   */
	  if (MC_EVENT_LOGGING > 1)
	    {
              /* *INDENT-OFF* */
	      ELOG_TYPE_DECLARE (e) =
                {
                  .format = "tx-massert: peer %s global seq %u",
                  .format_args = "T4i4",
                };
              /* *INDENT-ON* */
	      struct
	      {
		u32 peer, global_sequence;
	      } *ed;
	      ed = ELOG_DATA (mcm->elog_main, e);
	      ed->peer = elog_id_for_peer_id (mcm, mp->peer_id.as_u64);
	      ed->global_sequence = mp->global_sequence;
	    }

	  mc_byte_swap_msg_master_assert (mp);

	  error =
	    mcm->transport.tx_buffer (mcm->transport.opaque,
				      MC_TRANSPORT_MASTERSHIP, bi);
	  if (error)
	    clib_error_report (error);
	}

      vlib_process_wait_for_event_or_clock (vm, 1.0);
      event_type = vlib_process_get_events (vm, /* no event data */ 0);

      switch (event_type)
	{
	case ~0:
	  if (!is_master && timeouts++ > 2)
	    {
	      mcm->relay_state = MC_RELAY_STATE_MASTER;
	      mcm->relay_master_peer_id =
		mcm->transport.our_ack_peer_id.as_u64;
	      if (MC_EVENT_LOGGING)
		{
		  ELOG_TYPE (e, "become master (was maybe_master)");
		  ELOG (mcm->elog_main, e, 0);
		}
	      return;
	    }
	  break;

	case MC_RELAY_STATE_SLAVE:
	  mcm->relay_state = MC_RELAY_STATE_SLAVE;
	  if (MC_EVENT_LOGGING && mcm->relay_state != MC_RELAY_STATE_SLAVE)
	    {
	      ELOG_TYPE (e, "become slave (was maybe_master)");
	      ELOG (mcm->elog_main, e, 0);
	    }
	  return;
	}
    }
}

static void
this_node_slave (mc_main_t * mcm)
{
  vlib_main_t *vm = mcm->vlib_main;
  uword event_type;
  int timeouts = 0;

  if (MC_EVENT_LOGGING)
    {
      ELOG_TYPE (e, "become slave");
      ELOG (mcm->elog_main, e, 0);
    }

  while (1)
    {
      vlib_process_wait_for_event_or_clock (vm, 1.0);
      event_type = vlib_process_get_events (vm, /* no event data */ 0);

      switch (event_type)
	{
	case ~0:
	  if (timeouts++ > 2)
	    {
	      mcm->relay_state = MC_RELAY_STATE_NEGOTIATE;
	      mcm->relay_master_peer_id = ~0ULL;
	      if (MC_EVENT_LOGGING)
		{
		  ELOG_TYPE (e, "timeouts; negoitate mastership");
		  ELOG (mcm->elog_main, e, 0);
		}
	      return;
	    }
	  break;

	case MC_RELAY_STATE_SLAVE:
	  mcm->relay_state = MC_RELAY_STATE_SLAVE;
	  timeouts = 0;
	  break;
	}
    }
}

static uword
mc_mastership_process (vlib_main_t * vm,
		       vlib_node_runtime_t * node, vlib_frame_t * f)
{
  mc_main_t *mcm = mc_node_get_main (node);

  while (1)
    {
      switch (mcm->relay_state)
	{
	case MC_RELAY_STATE_NEGOTIATE:
	case MC_RELAY_STATE_MASTER:
	  this_node_maybe_master (mcm);
	  break;

	case MC_RELAY_STATE_SLAVE:
	  this_node_slave (mcm);
	  break;
	}
    }
  return 0;			/* not likely */
}

void
mc_enable_disable_mastership (mc_main_t * mcm, int we_can_be_master)
{
  if (we_can_be_master != mcm->we_can_be_relay_master)
    {
      mcm->we_can_be_relay_master = we_can_be_master;
      vlib_process_signal_event (mcm->vlib_main,
				 mcm->mastership_process,
				 MC_RELAY_STATE_NEGOTIATE, 0);
    }
}

void
mc_msg_master_assert_handler (mc_main_t * mcm, mc_msg_master_assert_t * mp,
			      u32 buffer_index)
{
  mc_peer_id_t his_peer_id, our_peer_id;
  i32 seq_cmp_result;
  u8 signal_slave = 0;
  u8 update_global_sequence = 0;

  mc_byte_swap_msg_master_assert (mp);

  his_peer_id = mp->peer_id;
  our_peer_id = mcm->transport.our_ack_peer_id;

  /* compare the incoming global sequence with ours */
  seq_cmp_result = mc_seq_cmp (mp->global_sequence,
			       mcm->relay_global_sequence);

  /* If the sender has a lower peer id and the sender's sequence >=
     our global sequence, we become a slave.  Otherwise we are master. */
  if (mc_peer_id_compare (his_peer_id, our_peer_id) < 0
      && seq_cmp_result >= 0)
    {
      vlib_process_signal_event (mcm->vlib_main,
				 mcm->mastership_process,
				 MC_RELAY_STATE_SLAVE, 0);
      signal_slave = 1;
    }

  /* Update our global sequence. */
  if (seq_cmp_result > 0)
    {
      mcm->relay_global_sequence = mp->global_sequence;
      update_global_sequence = 1;
    }

  {
    uword *q = mhash_get (&mcm->mastership_peer_index_by_id, &his_peer_id);
    mc_mastership_peer_t *p;

    if (q)
      p = vec_elt_at_index (mcm->mastership_peers, q[0]);
    else
      {
	vec_add2 (mcm->mastership_peers, p, 1);
	p->peer_id = his_peer_id;
	mhash_set (&mcm->mastership_peer_index_by_id, &p->peer_id,
		   p - mcm->mastership_peers,
		   /* old_value */ 0);
      }
    p->time_last_master_assert_received = vlib_time_now (mcm->vlib_main);
  }

  /*
   * these messages clog the event log, set MC_EVENT_LOGGING higher
   * if you want them.
   */
  if (MC_EVENT_LOGGING > 1)
    {
      /* *INDENT-OFF* */
      ELOG_TYPE_DECLARE (e) =
        {
          .format = "rx-massert: peer %s global seq %u upd %d slave %d",
          .format_args = "T4i4i1i1",
        };
      /* *INDENT-ON* */

      struct
      {
	u32 peer;
	u32 global_sequence;
	u8 update_sequence;
	u8 slave;
      } *ed;
      ed = ELOG_DATA (mcm->elog_main, e);
      ed->peer = elog_id_for_peer_id (mcm, his_peer_id.as_u64);
      ed->global_sequence = mp->global_sequence;
      ed->update_sequence = update_global_sequence;
      ed->slave = signal_slave;
    }
}

static void
mc_serialize_init (mc_main_t * mcm)
{
  mc_serialize_msg_t *m;
  vlib_main_t *vm = vlib_get_main ();

  mcm->global_msg_index_by_name
    = hash_create_string ( /* elts */ 0, sizeof (uword));

  m = vm->mc_msg_registrations;

  while (m)
    {
      m->global_index = vec_len (mcm->global_msgs);
      hash_set_mem (mcm->global_msg_index_by_name, m->name, m->global_index);
      vec_add1 (mcm->global_msgs, m);
      m = m->next_registration;
    }
}

clib_error_t *
mc_serialize_va (mc_main_t * mc,
		 u32 stream_index,
		 u32 multiple_messages_per_vlib_buffer,
		 mc_serialize_msg_t * msg, va_list * va)
{
  mc_stream_t *s;
  clib_error_t *error;
  serialize_main_t *m = &mc->serialize_mains[VLIB_TX];
  vlib_serialize_buffer_main_t *sbm = &mc->serialize_buffer_mains[VLIB_TX];
  u32 bi, n_before, n_after, n_total, n_this_msg;
  u32 si, gi;

  if (!sbm->vlib_main)
    {
      sbm->tx.max_n_data_bytes_per_chain = 4096;
      sbm->tx.free_list_index = VLIB_BUFFER_DEFAULT_FREE_LIST_INDEX;
    }

  if (sbm->first_buffer == 0)
    serialize_open_vlib_buffer (m, mc->vlib_main, sbm);

  n_before = serialize_vlib_buffer_n_bytes (m);

  s = mc_stream_by_index (mc, stream_index);
  gi = msg->global_index;
  ASSERT (msg == vec_elt (mc->global_msgs, gi));

  si = ~0;
  if (gi < vec_len (s->stream_msg_index_by_global_index))
    si = s->stream_msg_index_by_global_index[gi];

  serialize_likely_small_unsigned_integer (m, si);

  /* For first time message is sent, use name to identify message. */
  if (si == ~0 || MSG_ID_DEBUG)
    serialize_cstring (m, msg->name);

  if (MSG_ID_DEBUG && MC_EVENT_LOGGING > 0)
    {
      /* *INDENT-OFF* */
      ELOG_TYPE_DECLARE (e) =
        {
          .format = "serialize-msg: %s index %d",
          .format_args = "T4i4",
        };
      /* *INDENT-ON* */
      struct
      {
	u32 c[2];
      } *ed;
      ed = ELOG_DATA (mc->elog_main, e);
      ed->c[0] = elog_id_for_msg_name (mc, msg->name);
      ed->c[1] = si;
    }

  error = va_serialize (m, va);

  n_after = serialize_vlib_buffer_n_bytes (m);
  n_this_msg = n_after - n_before;
  n_total = n_after + sizeof (mc_msg_user_request_t);

  /* For max message size ignore first message where string name is sent. */
  if (si != ~0)
    msg->max_n_bytes_serialized =
      clib_max (msg->max_n_bytes_serialized, n_this_msg);

  if (!multiple_messages_per_vlib_buffer
      || si == ~0
      || n_total + msg->max_n_bytes_serialized >
      mc->transport.max_packet_size)
    {
      bi = serialize_close_vlib_buffer (m);
      sbm->first_buffer = 0;
      if (!error)
	mc_stream_send (mc, stream_index, bi);
      else if (bi != ~0)
	vlib_buffer_free_one (mc->vlib_main, bi);
    }

  return error;
}

clib_error_t *
mc_serialize_internal (mc_main_t * mc,
		       u32 stream_index,
		       u32 multiple_messages_per_vlib_buffer,
		       mc_serialize_msg_t * msg, ...)
{
  vlib_main_t *vm = mc->vlib_main;
  va_list va;
  clib_error_t *error;

  if (stream_index == ~0)
    {
      if (vm->mc_main && vm->mc_stream_index == ~0)
	vlib_current_process_wait_for_one_time_event_vector
	  (vm, &vm->procs_waiting_for_mc_stream_join);
      stream_index = vm->mc_stream_index;
    }

  va_start (va, msg);
  error = mc_serialize_va (mc, stream_index,
			   multiple_messages_per_vlib_buffer, msg, &va);
  va_end (va);
  return error;
}

uword
mc_unserialize_message (mc_main_t * mcm,
			mc_stream_t * s, serialize_main_t * m)
{
  mc_serialize_stream_msg_t *sm;
  u32 gi, si;

  si = unserialize_likely_small_unsigned_integer (m);

  if (!(si == ~0 || MSG_ID_DEBUG))
    {
      sm = vec_elt_at_index (s->stream_msgs, si);
      gi = sm->global_index;
    }
  else
    {
      char *name;

      unserialize_cstring (m, &name);

      if (MSG_ID_DEBUG && MC_EVENT_LOGGING > 0)
	{
          /* *INDENT-OFF* */
	  ELOG_TYPE_DECLARE (e) =
            {
              .format = "unserialize-msg: %s rx index %d",
              .format_args = "T4i4",
            };
          /* *INDENT-ON* */
	  struct
	  {
	    u32 c[2];
	  } *ed;
	  ed = ELOG_DATA (mcm->elog_main, e);
	  ed->c[0] = elog_id_for_msg_name (mcm, name);
	  ed->c[1] = si;
	}

      {
	uword *p = hash_get_mem (mcm->global_msg_index_by_name, name);
	gi = p ? p[0] : ~0;
      }

      /* Unknown message? */
      if (gi == ~0)
	{
	  vec_free (name);
	  goto done;
	}

      vec_validate_init_empty (s->stream_msg_index_by_global_index, gi, ~0);
      si = s->stream_msg_index_by_global_index[gi];

      /* Stream local index unknown?  Create it. */
      if (si == ~0)
	{
	  vec_add2 (s->stream_msgs, sm, 1);

	  si = sm - s->stream_msgs;
	  sm->global_index = gi;
	  s->stream_msg_index_by_global_index[gi] = si;

	  if (MC_EVENT_LOGGING > 0)
	    {
              /* *INDENT-OFF* */
	      ELOG_TYPE_DECLARE (e) =
                {
                  .format = "msg-bind: stream %d %s to index %d",
                  .format_args = "i4T4i4",
                };
              /* *INDENT-ON* */
	      struct
	      {
		u32 c[3];
	      } *ed;
	      ed = ELOG_DATA (mcm->elog_main, e);
	      ed->c[0] = s->index;
	      ed->c[1] = elog_id_for_msg_name (mcm, name);
	      ed->c[2] = si;
	    }
	}
      else
	{
	  sm = vec_elt_at_index (s->stream_msgs, si);
	  if (gi != sm->global_index && MC_EVENT_LOGGING > 0)
	    {
              /* *INDENT-OFF* */
	      ELOG_TYPE_DECLARE (e) =
                {
                  .format = "msg-id-ERROR: %s index %d expected %d",
                  .format_args = "T4i4i4",
                };
              /* *INDENT-ON* */
	      struct
	      {
		u32 c[3];
	      } *ed;
	      ed = ELOG_DATA (mcm->elog_main, e);
	      ed->c[0] = elog_id_for_msg_name (mcm, name);
	      ed->c[1] = si;
	      ed->c[2] = ~0;
	      if (sm->global_index <
		  vec_len (s->stream_msg_index_by_global_index))
		ed->c[2] =
		  s->stream_msg_index_by_global_index[sm->global_index];
	    }
	}

      vec_free (name);
    }

  if (gi != ~0)
    {
      mc_serialize_msg_t *msg;
      msg = vec_elt (mcm->global_msgs, gi);
      unserialize (m, msg->unserialize, mcm);
    }

done:
  return gi != ~0;
}

void
mc_unserialize_internal (mc_main_t * mcm, u32 stream_and_buffer_index)
{
  vlib_main_t *vm = mcm->vlib_main;
  serialize_main_t *m = &mcm->serialize_mains[VLIB_RX];
  vlib_serialize_buffer_main_t *sbm = &mcm->serialize_buffer_mains[VLIB_RX];
  mc_stream_and_buffer_t *sb;
  mc_stream_t *stream;
  u32 buffer_index;

  sb =
    pool_elt_at_index (mcm->mc_unserialize_stream_and_buffers,
		       stream_and_buffer_index);
  buffer_index = sb->buffer_index;
  stream = vec_elt_at_index (mcm->stream_vector, sb->stream_index);
  pool_put (mcm->mc_unserialize_stream_and_buffers, sb);

  if (stream->config.save_snapshot)
    {
      u32 n_bytes = vlib_buffer_index_length_in_chain (vm, buffer_index);
      static u8 *contents;
      vec_reset_length (contents);
      vec_validate (contents, n_bytes - 1);
      vlib_buffer_contents (vm, buffer_index, contents);
      stream->config.save_snapshot (mcm, /* is_catchup */ 0, contents,
				    n_bytes);
    }

  ASSERT (vlib_in_process_context (vm));

  unserialize_open_vlib_buffer (m, vm, sbm);

  clib_fifo_add1 (sbm->rx.buffer_fifo, buffer_index);

  while (unserialize_vlib_buffer_n_bytes (m) > 0)
    mc_unserialize_message (mcm, stream, m);

  /* Frees buffer. */
  unserialize_close_vlib_buffer (m);
}

void
mc_unserialize (mc_main_t * mcm, mc_stream_t * s, u32 buffer_index)
{
  vlib_main_t *vm = mcm->vlib_main;
  mc_stream_and_buffer_t *sb;
  pool_get (mcm->mc_unserialize_stream_and_buffers, sb);
  sb->stream_index = s->index;
  sb->buffer_index = buffer_index;
  vlib_process_signal_event (vm, mcm->unserialize_process,
			     EVENT_MC_UNSERIALIZE_BUFFER,
			     sb - mcm->mc_unserialize_stream_and_buffers);
}

static uword
mc_unserialize_process (vlib_main_t * vm,
			vlib_node_runtime_t * node, vlib_frame_t * f)
{
  mc_main_t *mcm = mc_node_get_main (node);
  uword event_type, *event_data = 0;
  int i;

  while (1)
    {
      if (event_data)
	_vec_len (event_data) = 0;

      vlib_process_wait_for_event (vm);
      event_type = vlib_process_get_events (vm, &event_data);
      switch (event_type)
	{
	case EVENT_MC_UNSERIALIZE_BUFFER:
	  for (i = 0; i < vec_len (event_data); i++)
	    mc_unserialize_internal (mcm, event_data[i]);
	  break;

	case EVENT_MC_UNSERIALIZE_CATCHUP:
	  for (i = 0; i < vec_len (event_data); i++)
	    {
	      u8 *mp = uword_to_pointer (event_data[i], u8 *);
	      perform_catchup (mcm, (void *) mp);
	      vec_free (mp);
	    }
	  break;

	default:
	  break;
	}
    }

  return 0;			/* not likely */
}

void
serialize_mc_main (serialize_main_t * m, va_list * va)
{
  mc_main_t *mcm = va_arg (*va, mc_main_t *);
  mc_stream_t *s;
  mc_serialize_stream_msg_t *sm;
  mc_serialize_msg_t *msg;

  serialize_integer (m, vec_len (mcm->stream_vector), sizeof (u32));
  vec_foreach (s, mcm->stream_vector)
  {
    /* Stream name. */
    serialize_cstring (m, s->config.name);

    /* Serialize global names for all sent messages. */
    serialize_integer (m, vec_len (s->stream_msgs), sizeof (u32));
    vec_foreach (sm, s->stream_msgs)
    {
      msg = vec_elt (mcm->global_msgs, sm->global_index);
      serialize_cstring (m, msg->name);
    }
  }
}

void
unserialize_mc_main (serialize_main_t * m, va_list * va)
{
  mc_main_t *mcm = va_arg (*va, mc_main_t *);
  u32 i, n_streams, n_stream_msgs;
  char *name;
  mc_stream_t *s;
  mc_serialize_stream_msg_t *sm;

  unserialize_integer (m, &n_streams, sizeof (u32));
  for (i = 0; i < n_streams; i++)
    {
      unserialize_cstring (m, &name);
      if (i != MC_STREAM_INDEX_INTERNAL && !mc_stream_by_name (mcm, name))
	{
	  vec_validate (mcm->stream_vector, i);
	  s = vec_elt_at_index (mcm->stream_vector, i);
	  mc_stream_init (s);
	  s->index = s - mcm->stream_vector;
	  s->config.name = name;
	  s->state = MC_STREAM_STATE_name_known;
	  hash_set_mem (mcm->stream_index_by_name, s->config.name, s->index);
	}
      else
	vec_free (name);

      s = vec_elt_at_index (mcm->stream_vector, i);

      vec_free (s->stream_msgs);
      vec_free (s->stream_msg_index_by_global_index);

      unserialize_integer (m, &n_stream_msgs, sizeof (u32));
      vec_resize (s->stream_msgs, n_stream_msgs);
      vec_foreach (sm, s->stream_msgs)
      {
	uword *p;
	u32 si, gi;

	unserialize_cstring (m, &name);
	p = hash_get (mcm->global_msg_index_by_name, name);
	gi = p ? p[0] : ~0;
	si = sm - s->stream_msgs;

	if (MC_EVENT_LOGGING > 0)
	  {
            /* *INDENT-OFF* */
	    ELOG_TYPE_DECLARE (e) =
              {
                .format = "catchup-bind: %s to %d global index %d stream %d",
                .format_args = "T4i4i4i4",
              };
            /* *INDENT-ON* */

	    struct
	    {
	      u32 c[4];
	    } *ed;
	    ed = ELOG_DATA (mcm->elog_main, e);
	    ed->c[0] = elog_id_for_msg_name (mcm, name);
	    ed->c[1] = si;
	    ed->c[2] = gi;
	    ed->c[3] = s->index;
	  }

	vec_free (name);

	sm->global_index = gi;
	if (gi != ~0)
	  {
	    vec_validate_init_empty (s->stream_msg_index_by_global_index,
				     gi, ~0);
	    s->stream_msg_index_by_global_index[gi] = si;
	  }
      }
    }
}

void
mc_main_init (mc_main_t * mcm, char *tag)
{
  vlib_main_t *vm = vlib_get_main ();

  mcm->vlib_main = vm;
  mcm->elog_main = &vm->elog_main;

  mcm->relay_master_peer_id = ~0ULL;
  mcm->relay_state = MC_RELAY_STATE_NEGOTIATE;

  mcm->stream_index_by_name
    = hash_create_string ( /* elts */ 0, /* value size */ sizeof (uword));

  {
    vlib_node_registration_t r;

    memset (&r, 0, sizeof (r));

    r.type = VLIB_NODE_TYPE_PROCESS;

    /* Point runtime data to main instance. */
    r.runtime_data = &mcm;
    r.runtime_data_bytes = sizeof (&mcm);

    r.name = (char *) format (0, "mc-mastership-%s", tag);
    r.function = mc_mastership_process;
    mcm->mastership_process = vlib_register_node (vm, &r);

    r.name = (char *) format (0, "mc-join-ager-%s", tag);
    r.function = mc_join_ager_process;
    mcm->join_ager_process = vlib_register_node (vm, &r);

    r.name = (char *) format (0, "mc-retry-%s", tag);
    r.function = mc_retry_process;
    mcm->retry_process = vlib_register_node (vm, &r);

    r.name = (char *) format (0, "mc-catchup-%s", tag);
    r.function = mc_catchup_process;
    mcm->catchup_process = vlib_register_node (vm, &r);

    r.name = (char *) format (0, "mc-unserialize-%s", tag);
    r.function = mc_unserialize_process;
    mcm->unserialize_process = vlib_register_node (vm, &r);
  }

  if (MC_EVENT_LOGGING > 0)
    mhash_init (&mcm->elog_id_by_peer_id, sizeof (uword),
		sizeof (mc_peer_id_t));

  mhash_init (&mcm->mastership_peer_index_by_id, sizeof (uword),
	      sizeof (mc_peer_id_t));
  mc_serialize_init (mcm);
}

static u8 *
format_mc_relay_state (u8 * s, va_list * args)
{
  mc_relay_state_t state = va_arg (*args, mc_relay_state_t);
  char *t = 0;
  switch (state)
    {
    case MC_RELAY_STATE_NEGOTIATE:
      t = "negotiate";
      break;
    case MC_RELAY_STATE_MASTER:
      t = "master";
      break;
    case MC_RELAY_STATE_SLAVE:
      t = "slave";
      break;
    default:
      return format (s, "unknown 0x%x", state);
    }

  return format (s, "%s", t);
}

static u8 *
format_mc_stream_state (u8 * s, va_list * args)
{
  mc_stream_state_t state = va_arg (*args, mc_stream_state_t);
  char *t = 0;
  switch (state)
    {
#define _(f) case MC_STREAM_STATE_##f: t = #f; break;
      foreach_mc_stream_state
#undef _
    default:
      return format (s, "unknown 0x%x", state);
    }

  return format (s, "%s", t);
}

static int
mc_peer_comp (void *a1, void *a2)
{
  mc_stream_peer_t *p1 = a1;
  mc_stream_peer_t *p2 = a2;

  return mc_peer_id_compare (p1->id, p2->id);
}

u8 *
format_mc_main (u8 * s, va_list * args)
{
  mc_main_t *mcm = va_arg (*args, mc_main_t *);
  mc_stream_t *t;
  mc_stream_peer_t *p, *ps;
  u32 indent = format_get_indent (s);

  s = format (s, "MC state %U, %d streams joined, global sequence 0x%x",
	      format_mc_relay_state, mcm->relay_state,
	      vec_len (mcm->stream_vector), mcm->relay_global_sequence);

  {
    mc_mastership_peer_t *mp;
    f64 now = vlib_time_now (mcm->vlib_main);
    s = format (s, "\n%UMost recent mastership peers:",
		format_white_space, indent + 2);
    vec_foreach (mp, mcm->mastership_peers)
    {
      s = format (s, "\n%U%-30U%.4e",
		  format_white_space, indent + 4,
		  mcm->transport.format_peer_id, mp->peer_id,
		  now - mp->time_last_master_assert_received);
    }
  }

  vec_foreach (t, mcm->stream_vector)
  {
    s = format (s, "\n%Ustream `%s' index %d",
		format_white_space, indent + 2, t->config.name, t->index);

    s = format (s, "\n%Ustate %U",
		format_white_space, indent + 4,
		format_mc_stream_state, t->state);

    s =
      format (s,
	      "\n%Uretries: interval %.0f sec, limit %d, pool elts %d, %Ld sent",
	      format_white_space, indent + 4, t->config.retry_interval,
	      t->config.retry_limit, pool_elts (t->retry_pool),
	      t->stats.n_retries - t->stats_last_clear.n_retries);

    s = format (s, "\n%U%Ld/%Ld user requests sent/received",
		format_white_space, indent + 4,
		t->user_requests_sent, t->user_requests_received);

    s = format (s, "\n%U%d peers, local/global sequence 0x%x/0x%x",
		format_white_space, indent + 4,
		pool_elts (t->peers),
		t->our_local_sequence, t->last_global_sequence_processed);

    ps = 0;
    /* *INDENT-OFF* */
    pool_foreach (p, t->peers,
    ({
      if (clib_bitmap_get (t->all_peer_bitmap, p - t->peers))
        vec_add1 (ps, p[0]);
    }));
    /* *INDENT-ON* */
    vec_sort_with_function (ps, mc_peer_comp);
    s = format (s, "\n%U%=30s%10s%16s%16s",
		format_white_space, indent + 6,
		"Peer", "Last seq", "Retries", "Future");

    vec_foreach (p, ps)
    {
      s = format (s, "\n%U%-30U0x%08x%16Ld%16Ld%s",
		  format_white_space, indent + 6,
		  mcm->transport.format_peer_id, p->id.as_u64,
		  p->last_sequence_received,
		  p->stats.n_msgs_from_past -
		  p->stats_last_clear.n_msgs_from_past,
		  p->stats.n_msgs_from_future -
		  p->stats_last_clear.n_msgs_from_future,
		  (mcm->transport.our_ack_peer_id.as_u64 ==
		   p->id.as_u64 ? " (self)" : ""));
    }
    vec_free (ps);
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
