/*
 *------------------------------------------------------------------
 * api_shared.c - API message handling, common code for both clients
 * and the vlib process itself.
 *
 *
 * Copyright (c) 2009 Cisco and/or its affiliates.
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
 *------------------------------------------------------------------
 */

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <vppinfra/format.h>
#include <vppinfra/byte_order.h>
#include <vppinfra/error.h>
#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vlibapi/api.h>
#include <vppinfra/elog.h>
#include <vppinfra/callback.h>

/* *INDENT-OFF* */
static api_main_t api_global_main = {
  .region_name = "/unset",
  .api_uid = -1,
  .api_gid = -1,
};
/* *INDENT-ON* */

/* Please use vlibapi_get_main() to access my_api_main */
__thread api_main_t *my_api_main = &api_global_main;

void
vl_msg_api_set_global_main (void *am_arg)
{
  ASSERT (am_arg);
  my_api_main = (api_main_t *) am_arg;
}

void
vl_msg_api_increment_missing_client_counter (void)
{
  api_main_t *am = vlibapi_get_main ();
  am->missing_clients++;
}

int
vl_msg_api_rx_trace_enabled (api_main_t * am)
{
  return (am->rx_trace && am->rx_trace->enabled);
}

int
vl_msg_api_tx_trace_enabled (api_main_t * am)
{
  return (am->tx_trace && am->tx_trace->enabled);
}

/*
 * vl_msg_api_trace
 */
void
vl_msg_api_trace (api_main_t * am, vl_api_trace_t * tp, void *msg)
{
  u8 **this_trace;
  u8 **old_trace;
  u8 *msg_copy;
  u32 length;
  u16 msg_id = clib_net_to_host_u16 (*((u16 *) msg));
  vl_api_msg_data_t *m = vl_api_get_msg_data (am, msg_id);
  msgbuf_t *header = (msgbuf_t *) (((u8 *) msg) - offsetof (msgbuf_t, data));

  if (!m || !m->trace_enable)
    return;

  msg_copy = 0;

  if (tp->nitems == 0)
    {
      clib_warning ("tp->nitems is 0");
      return;
    }

  if (vec_len (tp->traces) < tp->nitems)
    {
      vec_add1 (tp->traces, 0);
      this_trace = tp->traces + vec_len (tp->traces) - 1;
    }
  else
    {
      tp->wrapped = 1;
      old_trace = tp->traces + tp->curindex++;
      if (tp->curindex == tp->nitems)
	tp->curindex = 0;
      /* Reuse the trace record, may save some memory allocator traffic */
      msg_copy = *old_trace;
      vec_reset_length (msg_copy);
      this_trace = old_trace;
    }

  length = clib_net_to_host_u32 (header->data_len);

  vec_validate (msg_copy, length - 1);
  clib_memcpy_fast (msg_copy, msg, length);
  *this_trace = msg_copy;
}

int
vl_msg_api_trace_onoff (api_main_t * am, vl_api_trace_which_t which,
			int onoff)
{
  vl_api_trace_t *tp;
  int rv;

  switch (which)
    {
    case VL_API_TRACE_TX:
      tp = am->tx_trace;
      if (tp == 0)
	{
	  vl_msg_api_trace_configure (am, which, 1024);
	  tp = am->tx_trace;
	}
      break;

    case VL_API_TRACE_RX:
      tp = am->rx_trace;
      if (tp == 0)
	{
	  vl_msg_api_trace_configure (am, which, 1024);
	  tp = am->rx_trace;
	}
      break;

    default:
      /* duh? */
      return -1;
    }

  /* Configured? */
  if (tp == 0 || tp->nitems == 0)
    return -1;

  rv = tp->enabled;
  tp->enabled = onoff;

  return rv;
}

int
vl_msg_api_trace_free (api_main_t * am, vl_api_trace_which_t which)
{
  vl_api_trace_t *tp;
  int i;

  switch (which)
    {
    case VL_API_TRACE_TX:
      tp = am->tx_trace;
      break;

    case VL_API_TRACE_RX:
      tp = am->rx_trace;
      break;

    default:
      /* duh? */
      return -1;
    }

  /* Configured? */
  if (!tp || tp->nitems == 0)
    return -1;

  tp->curindex = 0;
  tp->wrapped = 0;

  for (i = 0; i < vec_len (tp->traces); i++)
    {
      vec_free (tp->traces[i]);
    }
  vec_free (tp->traces);

  return 0;
}

u8 *
vl_api_serialize_message_table (api_main_t * am, u8 * vector)
{
  serialize_main_t _sm, *sm = &_sm;
  hash_pair_t *hp;
  u32 nmsg = hash_elts (am->msg_index_by_name_and_crc);

  serialize_open_vector (sm, vector);

  /* serialize the count */
  serialize_integer (sm, nmsg, sizeof (u32));

  /* *INDENT-OFF* */
  hash_foreach_pair (hp, am->msg_index_by_name_and_crc,
  ({
    serialize_likely_small_unsigned_integer (sm, hp->value[0]);
    serialize_cstring (sm, (char *) hp->key);
  }));
  /* *INDENT-ON* */

  return serialize_close_vector (sm);
}

static int
vl_msg_api_trace_write_one (api_main_t *am, u8 *msg, FILE *fp)
{
  static u8 *tmpmem = 0;
  int tlen, slen;

  u32 msg_length = vec_len (msg);
  vec_validate (tmpmem, msg_length - 1);
  clib_memcpy_fast (tmpmem, msg, msg_length);
  u16 id = clib_net_to_host_u16 (*((u16 *) msg));
  vl_api_msg_data_t *m = vl_api_get_msg_data (am, id);

  if (m && m->endian_handler)
    {
      m->endian_handler (tmpmem);
    }

  if (m && m->tojson_handler)
    {
      cJSON *o = m->tojson_handler (tmpmem);
      char *s = cJSON_Print (o);
      slen = strlen (s);
      tlen = fwrite (s, 1, slen, fp);
      cJSON_free (s);
      cJSON_Delete (o);
      // vec_free (tmpmem);
      if (tlen != slen)
	{
	  fformat (stderr, "writing to file error\n");
	  return -11;
	}
    }
  else
    fformat (stderr, "  [no registered tojson fn]\n");

  return 0;
}

#define vl_msg_fwrite(_s, _f) fwrite (_s, 1, sizeof (_s) - 1, _f)

typedef struct
{
  FILE *fp;
  u32 n_traces;
  u32 i;
} vl_msg_write_json_args_t;

static int
vl_msg_write_json_fn (u8 *msg, void *ctx)
{
  vl_msg_write_json_args_t *arg = ctx;
  FILE *fp = arg->fp;
  api_main_t *am = vlibapi_get_main ();
  int rc = vl_msg_api_trace_write_one (am, msg, fp);
  if (rc < 0)
    return rc;

  if (arg->i < arg->n_traces - 1)
    vl_msg_fwrite (",\n", fp);
  arg->i++;
  return 0;
}

static int
vl_msg_api_trace_write_json (api_main_t *am, vl_api_trace_t *tp, FILE *fp)
{
  vl_msg_write_json_args_t args;
  clib_memset (&args, 0, sizeof (args));
  args.fp = fp;
  args.n_traces = vec_len (tp->traces);
  vl_msg_fwrite ("[\n", fp);

  int rv = vl_msg_traverse_trace (tp, vl_msg_write_json_fn, &args);
  if (rv < 0)
    return rv;

  vl_msg_fwrite ("]", fp);
  return 0;
}

int
vl_msg_traverse_trace (vl_api_trace_t *tp, vl_msg_traverse_trace_fn fn,
		       void *ctx)
{
  int i;
  u8 *msg;
  int rv = 0;

  /* No-wrap case */
  if (tp->wrapped == 0)
    {
      for (i = 0; i < vec_len (tp->traces); i++)
	{
	  /*sa_ignore NO_NULL_CHK */
	  msg = tp->traces[i];
	  if (!msg)
	    continue;

	  rv = fn (msg, ctx);
	  if (rv < 0)
	    return rv;
	}
    }
  else
    {
      /* Wrap case: write oldest -> end of buffer */
      for (i = tp->curindex; i < vec_len (tp->traces); i++)
	{
	  msg = tp->traces[i];
	  if (!msg)
	    continue;

	  rv = fn (msg, ctx);
	  if (rv < 0)
	    return rv;
	}
      /* write beginning of buffer -> oldest-1 */
      for (i = 0; i < tp->curindex; i++)
	{
	  /*sa_ignore NO_NULL_CHK */
	  msg = tp->traces[i];
	  if (!msg)
	    continue;

	  rv = fn (msg, ctx);
	  if (rv < 0)
	    return rv;
	}
    }
  return 0;
}

static int
vl_api_msg_write_fn (u8 *msg, void *ctx)
{
  FILE *fp = ctx;
  u32 msg_length = clib_host_to_net_u32 (vec_len (msg));
  if (fwrite (&msg_length, 1, sizeof (msg_length), fp) != sizeof (msg_length))
    {
      return (-14);
    }
  if (fwrite (msg, 1, vec_len (msg), fp) != vec_len (msg))
    {
      return (-14);
    }
  return 0;
}

int
vl_msg_api_trace_save (api_main_t *am, vl_api_trace_which_t which, FILE *fp,
		       u8 is_json)
{
  vl_api_trace_t *tp;
  vl_api_trace_file_header_t fh;

  switch (which)
    {
    case VL_API_TRACE_TX:
      tp = am->tx_trace;
      break;

    case VL_API_TRACE_RX:
      tp = am->rx_trace;
      break;

    default:
      /* duh? */
      return -1;
    }

  /* Configured, data present? */
  if (tp == 0 || tp->nitems == 0 || vec_len (tp->traces) == 0)
    return -1;

  /* "Dare to be stupid" check */
  if (fp == 0)
    {
      return -2;
    }

  if (is_json)
    return vl_msg_api_trace_write_json (am, tp, fp);

  /* Write the file header */
  fh.wrapped = tp->wrapped;
  fh.nitems = clib_host_to_net_u32 (vec_len (tp->traces));

  u8 *m = vl_api_serialize_message_table (am, 0);
  fh.msgtbl_size = clib_host_to_net_u32 (vec_len (m));

  if (fwrite (&fh, sizeof (fh), 1, fp) != 1)
    {
      return (-10);
    }

  /* Write the message table */
  if (fwrite (m, vec_len (m), 1, fp) != 1)
    {
      return (-14);
    }
  vec_free (m);

  return vl_msg_traverse_trace (tp, vl_api_msg_write_fn, fp);
}

int
vl_msg_api_trace_configure (api_main_t * am, vl_api_trace_which_t which,
			    u32 nitems)
{
  vl_api_trace_t *tp;
  int was_on = 0;

  switch (which)
    {
    case VL_API_TRACE_TX:
      tp = am->tx_trace;
      if (tp == 0)
	{
	  vec_validate (am->tx_trace, 0);
	  tp = am->tx_trace;
	}
      break;

    case VL_API_TRACE_RX:
      tp = am->rx_trace;
      if (tp == 0)
	{
	  vec_validate (am->rx_trace, 0);
	  tp = am->rx_trace;
	}

      break;

    default:
      return -1;

    }

  if (tp->enabled)
    {
      was_on = vl_msg_api_trace_onoff (am, which, 0);
    }
  if (tp->traces)
    {
      vl_msg_api_trace_free (am, which);
    }

  clib_memset (tp, 0, sizeof (*tp));

  if (clib_arch_is_big_endian)
    {
      tp->endian = VL_API_BIG_ENDIAN;
    }
  else
    {
      tp->endian = VL_API_LITTLE_ENDIAN;
    }

  tp->nitems = nitems;
  if (was_on)
    {
      (void) vl_msg_api_trace_onoff (am, which, was_on);
    }
  return 0;
}

void
vl_msg_api_barrier_sync (void)
{
}

void
vl_msg_api_barrier_release (void)
{
}

always_inline void
msg_handler_internal (api_main_t *am, void *the_msg, uword msg_len,
		      int trace_it, int do_it, int free_it)
{
  u16 id = clib_net_to_host_u16 (*((u16 *) the_msg));
  vl_api_msg_data_t *m = vl_api_get_msg_data (am, id);

  if (PREDICT_FALSE (am->elog_trace_api_messages))
    {
      /* *INDENT-OFF* */
      ELOG_TYPE_DECLARE (e) =
        {
          .format = "api-msg: %s",
          .format_args = "T4",
        };
      /* *INDENT-ON* */
      struct
      {
	u32 c;
      } *ed;
      ed = ELOG_DATA (am->elog_main, e);
      if (m && m->name)
	ed->c = elog_string (am->elog_main, (char *) m->name);
      else
	ed->c = elog_string (am->elog_main, "BOGUS");
    }

  if (m && m->handler)
    {
      if (am->msg_print_flag)
	{
	  fformat (stdout, "[%d]: %s\n", id, m->name);
	  fformat (stdout, "%U", format_vl_api_msg_text, am, id, the_msg);
	}

      uword calc_size = 0;
      ASSERT (NULL != m->calc_size_func);
      if (m->calc_size_func)
	{
	  calc_size = m->calc_size_func (the_msg);
	  if (calc_size > msg_len)
	    {
	      clib_warning (
		"Truncated message '%s' (id %u) received, calculated size "
		"%lu is bigger than actual size %llu, message dropped.",
		m->name, id, calc_size, msg_len);
	    }
	}
      else
	{
	  clib_warning ("Message '%s' (id %u) has NULL calc_size_func, cannot "
			"verify message size is correct",
			m->name, id);
	}

      /* don't trace message if it's truncated, otherwise output api message
       * trace output will access memory beyond message boundary.
       * e.g. VLA length field set to 1M elements, but VLA empty */
      if (trace_it && calc_size <= msg_len)
	vl_msg_api_trace (am, am->rx_trace, the_msg);

      /* don't process message if it's truncated, otherwise byte swaps
       * and stuff could corrupt memory even beyond message if it's malicious
       * e.g. VLA length field set to 1M elements, but VLA empty */
      if (do_it && calc_size <= msg_len)
	{

	  if (!m->is_mp_safe)
	    {
	      vl_msg_api_barrier_trace_context (am->msg_names[id]);
	      vl_msg_api_barrier_sync ();
	    }

	  if (m->is_autoendian)
	    m->endian_handler (the_msg);

	  if (PREDICT_FALSE (vec_len (am->perf_counter_cbs) != 0))
	    clib_call_callbacks (am->perf_counter_cbs, am, id,
				 0 /* before */ );

	  m->handler (the_msg);

	  if (PREDICT_FALSE (vec_len (am->perf_counter_cbs) != 0))
	    clib_call_callbacks (am->perf_counter_cbs, am, id,
				 1 /* after */ );

	  if (!m->is_mp_safe)
	    vl_msg_api_barrier_release ();
	}
    }
  else
    {
      clib_warning ("no handler for msg id %d", id);
    }

  if (free_it)
    vl_msg_api_free (the_msg);

  if (PREDICT_FALSE (am->elog_trace_api_messages))
    {
      /* *INDENT-OFF* */
      ELOG_TYPE_DECLARE (e) =
        {
          .format = "api-msg-done(%s): %s",
          .format_args = "t4T4",
          .n_enum_strings = 2,
          .enum_strings =
          {
            "barrier",
            "mp-safe",
          }
        };
      /* *INDENT-ON* */

      struct
      {
	u32 barrier;
	u32 c;
      } *ed;
      ed = ELOG_DATA (am->elog_main, e);
      if (m && m->name)
	{
	  ed->c = elog_string (am->elog_main, (char *) m->name);
	  ed->barrier = !m->is_mp_safe;
	}
      else
	{
	  ed->c = elog_string (am->elog_main, "BOGUS");
	  ed->barrier = 0;
	}
    }
}

void
vl_msg_api_handler (void *the_msg, uword msg_len)
{
  api_main_t *am = vlibapi_get_main ();

  msg_handler_internal (am, the_msg, msg_len,
			(am->rx_trace && am->rx_trace->enabled) /* trace_it */,
			1 /* do_it */, 1 /* free_it */);
}

void
vl_msg_api_handler_no_free (void *the_msg, uword msg_len)
{
  api_main_t *am = vlibapi_get_main ();
  msg_handler_internal (am, the_msg, msg_len,
			(am->rx_trace && am->rx_trace->enabled) /* trace_it */,
			1 /* do_it */, 0 /* free_it */);
}

void
vl_msg_api_handler_no_trace_no_free (void *the_msg, uword msg_len)
{
  api_main_t *am = vlibapi_get_main ();
  msg_handler_internal (am, the_msg, msg_len, 0 /* trace_it */, 1 /* do_it */,
			0 /* free_it */);
}

/*
 * Add a trace record to the API message trace buffer, if
 * API message tracing is enabled. Handy for adding sufficient
 * data to the trace to reproduce autonomous state, as opposed to
 * state downloaded via control-plane API messages. Example: the NAT
 * application creates database entries based on packet traffic, not
 * control-plane messages.
 *
 */
void
vl_msg_api_trace_only (void *the_msg, uword msg_len)
{
  api_main_t *am = vlibapi_get_main ();

  msg_handler_internal (am, the_msg, msg_len,
			(am->rx_trace && am->rx_trace->enabled) /* trace_it */,
			0 /* do_it */, 0 /* free_it */);
}

void
vl_msg_api_cleanup_handler (void *the_msg)
{
  api_main_t *am = vlibapi_get_main ();
  u16 id = clib_net_to_host_u16 (*((u16 *) the_msg));
  vl_api_msg_data_t *m = vl_api_get_msg_data (am, id);

  if (PREDICT_FALSE (!m))
    {
      clib_warning ("_vl_msg_id too large: %d\n", id);
      return;
    }

  if (m->cleanup_handler)
    m->cleanup_handler (the_msg);

  vl_msg_api_free (the_msg);
}

/*
 * vl_msg_api_replay_handler
 */
void
vl_msg_api_replay_handler (void *the_msg)
{
  api_main_t *am = vlibapi_get_main ();
  u16 id = clib_net_to_host_u16 (*((u16 *) the_msg));
  vl_api_msg_data_t *m = vl_api_get_msg_data (am, id);

  if (PREDICT_FALSE (!m))
    {
      clib_warning ("_vl_msg_id too large: %d\n", id);
      return;
    }
  /* do NOT trace the message... */
  if (m->handler)
    m->handler (the_msg);
  /* do NOT free the message buffer... */
}

u32
vl_msg_api_get_msg_length (void *msg_arg)
{
  return vl_msg_api_get_msg_length_inline (msg_arg);
}

/*
 * vl_msg_api_socket_handler
 */
void
vl_msg_api_socket_handler (void *the_msg, uword msg_len)
{
  api_main_t *am = vlibapi_get_main ();

  msg_handler_internal (am, the_msg, msg_len,
			(am->rx_trace && am->rx_trace->enabled) /* trace_it */,
			1 /* do_it */, 0 /* free_it */);
}

void
vl_msg_api_config (vl_msg_api_msg_config_t * c)
{
  api_main_t *am = vlibapi_get_main ();
  vl_api_msg_data_t *m;

  /*
   * This happens during the java core tests if the message
   * dictionary is missing newly added xxx_reply_t messages.
   * Should never happen, but since I shot myself in the foot once
   * this way, I thought I'd make it easy to debug if I ever do
   * it again... (;-)...
   */
  if (c->id == 0)
    {
      if (c->name)
	clib_warning ("Trying to register %s with a NULL msg id!", c->name);
      else
	clib_warning ("Trying to register a NULL msg with a NULL msg id!");
      clib_warning ("Did you forget to call setup_message_id_table?");
      return;
    }

  vec_validate (am->msg_data, c->id);
  m = vl_api_get_msg_data (am, c->id);

  if (m->handler && m->handler != c->handler)
    clib_warning ("BUG: re-registering 'vl_api_%s_t_handler'."
		  "Handler was %llx, replaced by %llx",
		  c->name, m->handler, c->handler);

  m->name = c->name;
  m->handler = c->handler;
  m->cleanup_handler = c->cleanup;
  m->endian_handler = c->endian;
  m->format_fn = c->format_fn;
  m->tojson_handler = c->tojson;
  m->fromjson_handler = c->fromjson;
  m->calc_size_func = c->calc_size;
  m->bounce = c->message_bounce;
  m->is_mp_safe = c->is_mp_safe;
  m->is_autoendian = c->is_autoendian;

  m->trace_size = c->size;
  m->trace_enable = c->traced;
  m->replay_allowed = c->replay;

  if (!am->msg_id_by_name)
    am->msg_id_by_name = hash_create_string (0, sizeof (uword));

  hash_set_mem (am->msg_id_by_name, c->name, c->id);
}

void
vl_msg_api_clean_handlers (int msg_id)
{
  vl_msg_api_msg_config_t cfg;
  vl_msg_api_msg_config_t *c = &cfg;

  clib_memset (c, 0, sizeof (*c));

  c->id = msg_id;
  vl_msg_api_config (c);
}

void
vl_msg_api_set_cleanup_handler (int msg_id, void *fp)
{
  api_main_t *am = vlibapi_get_main ();
  vl_api_msg_data_t *m = vl_api_get_msg_data (am, msg_id);
  ASSERT (msg_id > 0);

  m->cleanup_handler = fp;
}

void
vl_msg_api_queue_handler (svm_queue_t * q)
{
  uword msg;

  while (!svm_queue_sub (q, (u8 *) &msg, SVM_Q_WAIT, 0))
    {
      VL_MSG_API_UNPOISON ((u8 *) msg);
      msgbuf_t *msgbuf = (msgbuf_t *) ((u8 *) msg - offsetof (msgbuf_t, data));
      vl_msg_api_handler ((void *) msg, ntohl (msgbuf->data_len));
    }
}

u32
vl_msg_api_max_length (void *mp)
{
  msgbuf_t *mb;
  u32 data_len = ~0;

  /* Work out the maximum sane message length, and return it */
  if (PREDICT_TRUE (mp != 0))
    {
      mb = (msgbuf_t *) (((u8 *) mp) - offsetof (msgbuf_t, data));
      data_len = clib_net_to_host_u32 (mb->data_len);
    }
  return data_len;
}

vl_api_trace_t *
vl_msg_api_trace_get (api_main_t * am, vl_api_trace_which_t which)
{
  switch (which)
    {
    case VL_API_TRACE_RX:
      return am->rx_trace;
    case VL_API_TRACE_TX:
      return am->tx_trace;
    default:
      return 0;
    }
}

static u8 post_mortem_dump_enabled;

void
vl_msg_api_post_mortem_dump_enable_disable (int enable)
{
  post_mortem_dump_enabled = enable;
}

void
vl_msg_api_post_mortem_dump (void)
{
  api_main_t *am = vlibapi_get_main ();
  FILE *fp;
  char filename[64];
  int rv;

  if (post_mortem_dump_enabled == 0)
    return;

  snprintf (filename, sizeof (filename), "/tmp/api_post_mortem.%d",
	    getpid ());

  fp = fopen (filename, "w");
  if (fp == NULL)
    {
      rv = write (2, "Couldn't create ", 16);
      rv = write (2, filename, strlen (filename));
      rv = write (2, "\n", 1);
      return;
    }
  rv = vl_msg_api_trace_save (am, VL_API_TRACE_RX, fp, 0);
  fclose (fp);
  if (rv < 0)
    {
      rv = write (2, "Failed to save post-mortem API trace to ", 40);
      rv = write (2, filename, strlen (filename));
      rv = write (2, "\n", 1);
    }

}

/* Layered message handling support */

void
vl_msg_api_set_first_available_msg_id (u16 first_avail)
{
  api_main_t *am = vlibapi_get_main ();

  am->first_available_msg_id = first_avail;
}

u16
vl_msg_api_get_msg_ids (const char *name, int n)
{
  api_main_t *am = vlibapi_get_main ();
  u8 *name_copy;
  vl_api_msg_range_t *rp;
  uword *p;
  u16 rv;

  if (am->msg_range_by_name == 0)
    am->msg_range_by_name = hash_create_string (0, sizeof (uword));

  name_copy = format (0, "%s%c", name, 0);

  p = hash_get_mem (am->msg_range_by_name, name_copy);
  if (p)
    {
      clib_warning ("WARNING: duplicate message range registration for '%s'",
		    name_copy);
      vec_free (name_copy);
      return ((u16) ~ 0);
    }

  if (n < 0 || n > 1024)
    {
      clib_warning
	("WARNING: bad number of message-IDs (%d) requested by '%s'",
	 n, name_copy);
      vec_free (name_copy);
      return ((u16) ~ 0);
    }

  vec_add2 (am->msg_ranges, rp, 1);

  rv = rp->first_msg_id = am->first_available_msg_id;
  am->first_available_msg_id += n;
  rp->last_msg_id = am->first_available_msg_id - 1;
  rp->name = name_copy;

  hash_set_mem (am->msg_range_by_name, name_copy, rp - am->msg_ranges);

  return rv;
}

void
vl_msg_api_add_msg_name_crc (api_main_t * am, const char *string, u32 id)
{
  uword *p;

  if (am->msg_index_by_name_and_crc == 0)
    am->msg_index_by_name_and_crc = hash_create_string (0, sizeof (uword));

  p = hash_get_mem (am->msg_index_by_name_and_crc, string);
  if (p)
    {
      clib_warning ("attempt to redefine '%s' ignored...", string);
      return;
    }

  hash_set_mem (am->msg_index_by_name_and_crc, string, id);
}

void
vl_msg_api_add_version (api_main_t * am, const char *string,
			u32 major, u32 minor, u32 patch)
{
  api_version_t version = {.major = major,.minor = minor,.patch = patch };
  ASSERT (strlen (string) < 64);
  strncpy (version.name, string, 64 - 1);
  vec_add1 (am->api_version_list, version);
}

u32
vl_msg_api_get_msg_index (u8 * name_and_crc)
{
  api_main_t *am = vlibapi_get_main ();
  uword *p;

  if (am->msg_index_by_name_and_crc)
    {
      p = hash_get_mem (am->msg_index_by_name_and_crc, name_and_crc);
      if (p)
	return p[0];
    }
  return ~0;
}

void *
vl_msg_push_heap_w_region (svm_region_t * vlib_rp)
{
  pthread_mutex_lock (&vlib_rp->mutex);
  return svm_push_data_heap (vlib_rp);
}

void *
vl_msg_push_heap (void)
{
  api_main_t *am = vlibapi_get_main ();
  return vl_msg_push_heap_w_region (am->vlib_rp);
}

void
vl_msg_pop_heap_w_region (svm_region_t * vlib_rp, void *oldheap)
{
  svm_pop_heap (oldheap);
  pthread_mutex_unlock (&vlib_rp->mutex);
}

void
vl_msg_pop_heap (void *oldheap)
{
  api_main_t *am = vlibapi_get_main ();
  vl_msg_pop_heap_w_region (am->vlib_rp, oldheap);
}

/* Must be nul terminated */
int
vl_api_c_string_to_api_string (const char *buf, vl_api_string_t * str)
{
  /* copy without nul terminator */
  u32 len = strlen (buf);
  if (len > 0)
    clib_memcpy_fast (str->buf, buf, len);
  str->length = htonl (len);
  return len + sizeof (u32);
}

/* Must NOT be nul terminated */
int
vl_api_vec_to_api_string (const u8 * vec, vl_api_string_t * str)
{
  u32 len = vec_len (vec);
  clib_memcpy (str->buf, vec, len);
  str->length = htonl (len);
  return len + sizeof (u32);
}

u32
vl_api_string_len (vl_api_string_t * astr)
{
  return clib_net_to_host_u32 (astr->length);
}

u8 *
vl_api_format_string (u8 * s, va_list * args)
{
  vl_api_string_t *a = va_arg (*args, vl_api_string_t *);
  vec_add (s, a->buf, clib_net_to_host_u32 (a->length));
  return s;
}

/*
 * Returns a new vector. Remember to free it after use.
 * NOT nul terminated.
 */
u8 *
vl_api_from_api_to_new_vec (void *mp, vl_api_string_t * astr)
{
  u8 *v = 0;

  if (vl_msg_api_max_length (mp) < clib_net_to_host_u32 (astr->length))
    return format (0, "Invalid astr->length %u > max (%u)%c",
		   clib_net_to_host_u32 (astr->length),
		   vl_msg_api_max_length (mp), 0);
  vec_add (v, astr->buf, clib_net_to_host_u32 (astr->length));
  return v;
}

/*
 * Returns a new vector. Remember to free it after use.
 * Nul terminated.
 */
char *
vl_api_from_api_to_new_c_string (vl_api_string_t * astr)
{
  char *v = 0;
  if (clib_net_to_host_u32 (astr->length) > 0)
    {
      vec_add (v, astr->buf, clib_net_to_host_u32 (astr->length));
      vec_add1 (v, 0);
    }
  return v;
}

void
vl_api_set_elog_main (elog_main_t * m)
{
  api_main_t *am = vlibapi_get_main ();
  am->elog_main = m;
}

int
vl_api_set_elog_trace_api_messages (int enable)
{
  int rv;
  api_main_t *am = vlibapi_get_main ();

  rv = am->elog_trace_api_messages;
  am->elog_trace_api_messages = enable;
  return rv;
}

int
vl_api_get_elog_trace_api_messages (void)
{
  api_main_t *am = vlibapi_get_main ();

  return am->elog_trace_api_messages;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
