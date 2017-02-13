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
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <vppinfra/format.h>
#include <vppinfra/byte_order.h>
#include <vppinfra/error.h>
#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vlibapi/api.h>
#include <vppinfra/elog.h>

api_main_t api_main;

void vl_msg_api_barrier_sync (void) __attribute__ ((weak));
void
vl_msg_api_barrier_sync (void)
{
}

void vl_msg_api_barrier_release (void) __attribute__ ((weak));
void
vl_msg_api_barrier_release (void)
{
}

void
vl_msg_api_increment_missing_client_counter (void)
{
  api_main_t *am = &api_main;
  am->missing_clients++;
}

typedef enum
{
  DUMP,
  CUSTOM_DUMP,
  REPLAY,
  INITIALIZERS,
} vl_api_replay_t;

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
  trace_cfg_t *cfgp;
  u16 msg_id = ntohs (*((u16 *) msg));
  msgbuf_t *header = (msgbuf_t *) (((u8 *) msg) - offsetof (msgbuf_t, data));

  cfgp = am->api_trace_cfg + msg_id;

  if (!cfgp || !cfgp->trace_enable)
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
      vec_free (*old_trace);
      this_trace = old_trace;
    }

  length = clib_net_to_host_u32 (header->data_len);

  vec_validate (msg_copy, length - 1);
  clib_memcpy (msg_copy, msg, length);
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

int
vl_msg_api_trace_save (api_main_t * am, vl_api_trace_which_t which, FILE * fp)
{
  vl_api_trace_t *tp;
  vl_api_trace_file_header_t fh;
  int i;
  u8 *msg;

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

  /* Write the file header */
  fh.nitems = vec_len (tp->traces);
  fh.endian = tp->endian;
  fh.wrapped = tp->wrapped;

  if (fwrite (&fh, sizeof (fh), 1, fp) != 1)
    {
      return (-10);
    }

  /* No-wrap case */
  if (tp->wrapped == 0)
    {
      /*
       * Note: vec_len return 0 when fed a NULL pointer.
       * Unfortunately, the static analysis tool doesn't
       * figure it out, hence the suppressed warnings.
       * What a great use of my time.
       */
      for (i = 0; i < vec_len (tp->traces); i++)
	{
	  u32 msg_length;
	  /*sa_ignore NO_NULL_CHK */
	  msg = tp->traces[i];
	  /*
	   * This retarded check required to pass
	   * [sic] SA-checking.
	   */
	  if (!msg)
	    continue;

	  msg_length = clib_host_to_net_u32 (vec_len (msg));
	  if (fwrite (&msg_length, 1, sizeof (msg_length), fp)
	      != sizeof (msg_length))
	    {
	      return (-14);
	    }
	  if (fwrite (msg, 1, vec_len (msg), fp) != vec_len (msg))
	    {
	      return (-11);
	    }
	}
    }
  else
    {
      /* Wrap case: write oldest -> end of buffer */
      for (i = tp->curindex; i < vec_len (tp->traces); i++)
	{
	  u32 msg_length;
	  msg = tp->traces[i];
	  /*
	   * This retarded check required to pass
	   * [sic] SA-checking
	   */
	  if (!msg)
	    continue;

	  msg_length = clib_host_to_net_u32 (vec_len (msg));
	  if (fwrite (&msg_length, 1, sizeof (msg_length), fp)
	      != sizeof (msg_length))
	    {
	      return (-14);
	    }

	  if (fwrite (msg, 1, vec_len (msg), fp) != vec_len (msg))
	    {
	      return (-12);
	    }
	}
      /* write beginning of buffer -> oldest-1 */
      for (i = 0; i < tp->curindex; i++)
	{
	  u32 msg_length;
	  /*sa_ignore NO_NULL_CHK */
	  msg = tp->traces[i];
	  /*
	   * This retarded check required to pass
	   * [sic] SA-checking
	   */
	  if (!msg)
	    continue;

	  msg_length = clib_host_to_net_u32 (vec_len (msg));
	  if (fwrite (&msg_length, 1, sizeof (msg_length), fp)
	      != sizeof (msg_length))
	    {
	      return (-14);
	    }

	  if (fwrite (msg, 1, vec_len (msg), fp) != vec_len (msg))
	    {
	      return (-13);
	    }
	}
    }
  return 0;
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

  memset (tp, 0, sizeof (*tp));

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

always_inline void
msg_handler_internal (api_main_t * am,
		      void *the_msg, int trace_it, int do_it, int free_it)
{
  u16 id = ntohs (*((u16 *) the_msg));
  u8 *(*print_fp) (void *, void *);

  if (id < vec_len (am->msg_handlers) && am->msg_handlers[id])
    {
      if (trace_it)
	vl_msg_api_trace (am, am->rx_trace, the_msg);

      if (am->msg_print_flag)
	{
	  fformat (stdout, "[%d]: %s\n", id, am->msg_names[id]);
	  print_fp = (void *) am->msg_print_handlers[id];
	  if (print_fp == 0)
	    {
	      fformat (stdout, "  [no registered print fn]\n");
	    }
	  else
	    {
	      (*print_fp) (the_msg, stdout);
	    }
	}

      if (do_it)
	{
	  if (!am->is_mp_safe[id])
	    vl_msg_api_barrier_sync ();
	  (*am->msg_handlers[id]) (the_msg);
	  if (!am->is_mp_safe[id])
	    vl_msg_api_barrier_release ();
	}
    }
  else
    {
      clib_warning ("no handler for msg id %d", id);
    }

  if (free_it)
    vl_msg_api_free (the_msg);
}

/* set to 1 if you want before/after message handler event logging */
#define ELOG_API_MESSAGE_HANDLERS 0

#if ELOG_API_MESSAGE_HANDLERS > 0
static u32
elog_id_for_msg_name (vlib_main_t * vm, char *msg_name)
{
  uword *p, r;
  static uword *h;
  u8 *name_copy;

  if (!h)
    h = hash_create_string (0, sizeof (uword));

  p = hash_get_mem (h, msg_name);
  if (p)
    return p[0];
  r = elog_string (&vm->elog_main, "%s", msg_name);

  name_copy = format (0, "%s%c", msg_name, 0);

  hash_set_mem (h, name_copy, r);

  return r;
}
#endif

/* This is only to be called from a vlib/vnet app */
void
vl_msg_api_handler_with_vm_node (api_main_t * am,
				 void *the_msg, vlib_main_t * vm,
				 vlib_node_runtime_t * node)
{
  u16 id = ntohs (*((u16 *) the_msg));
  u8 *(*handler) (void *, void *, void *);

#if ELOG_API_MESSAGE_HANDLERS > 0
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
    ed = ELOG_DATA (&vm->elog_main, e);
    if (id < vec_len (am->msg_names))
      ed->c = elog_id_for_msg_name (vm, am->msg_names[id]);
    else
      ed->c = elog_id_for_msg_name (vm, "BOGUS");
  }
#endif

  if (id < vec_len (am->msg_handlers) && am->msg_handlers[id])
    {
      handler = (void *) am->msg_handlers[id];

      if (am->rx_trace && am->rx_trace->enabled)
	vl_msg_api_trace (am, am->rx_trace, the_msg);

      if (!am->is_mp_safe[id])
	vl_msg_api_barrier_sync ();
      (*handler) (the_msg, vm, node);
      if (!am->is_mp_safe[id])
	vl_msg_api_barrier_release ();
    }
  else
    {
      clib_warning ("no handler for msg id %d", id);
    }

  /*
   * Special-case, so we can e.g. bounce messages off the vnet
   * main thread without copying them...
   */
  if (!(am->message_bounce[id]))
    vl_msg_api_free (the_msg);

#if ELOG_API_MESSAGE_HANDLERS > 0
  {
  /* *INDENT-OFF* */
  ELOG_TYPE_DECLARE (e) = {
    .format = "api-msg-done: %s",
    .format_args = "T4",
  };
  /* *INDENT-ON* */

    struct
    {
      u32 c;
    } *ed;
    ed = ELOG_DATA (&vm->elog_main, e);
    if (id < vec_len (am->msg_names))
      ed->c = elog_id_for_msg_name (vm, am->msg_names[id]);
    else
      ed->c = elog_id_for_msg_name (vm, "BOGUS");
  }
#endif
}

void
vl_msg_api_handler (void *the_msg)
{
  api_main_t *am = &api_main;

  msg_handler_internal (am, the_msg,
			(am->rx_trace
			 && am->rx_trace->enabled) /* trace_it */ ,
			1 /* do_it */ , 1 /* free_it */ );
}

void
vl_msg_api_handler_no_free (void *the_msg)
{
  api_main_t *am = &api_main;
  msg_handler_internal (am, the_msg,
			(am->rx_trace
			 && am->rx_trace->enabled) /* trace_it */ ,
			1 /* do_it */ , 0 /* free_it */ );
}

void
vl_msg_api_handler_no_trace_no_free (void *the_msg)
{
  api_main_t *am = &api_main;
  msg_handler_internal (am, the_msg, 0 /* trace_it */ , 1 /* do_it */ ,
			0 /* free_it */ );
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
vl_msg_api_trace_only (void *the_msg)
{
  api_main_t *am = &api_main;

  msg_handler_internal (am, the_msg,
			(am->rx_trace
			 && am->rx_trace->enabled) /* trace_it */ ,
			0 /* do_it */ , 0 /* free_it */ );
}

void
vl_msg_api_cleanup_handler (void *the_msg)
{
  api_main_t *am = &api_main;
  u16 id = ntohs (*((u16 *) the_msg));

  if (PREDICT_FALSE (id >= vec_len (am->msg_cleanup_handlers)))
    {
      clib_warning ("_vl_msg_id too large: %d\n", id);
      return;
    }
  if (am->msg_cleanup_handlers[id])
    (*am->msg_cleanup_handlers[id]) (the_msg);

  vl_msg_api_free (the_msg);
}

/*
 * vl_msg_api_replay_handler
 */
void
vl_msg_api_replay_handler (void *the_msg)
{
  api_main_t *am = &api_main;

  u16 id = ntohs (*((u16 *) the_msg));

  if (PREDICT_FALSE (id >= vec_len (am->msg_handlers)))
    {
      clib_warning ("_vl_msg_id too large: %d\n", id);
      return;
    }
  /* do NOT trace the message... */
  if (am->msg_handlers[id])
    (*am->msg_handlers[id]) (the_msg);
  /* do NOT free the message buffer... */
}

/*
 * vl_msg_api_socket_handler
 */
void
vl_msg_api_socket_handler (void *the_msg)
{
  api_main_t *am = &api_main;

  msg_handler_internal (am, the_msg,
			(am->rx_trace
			 && am->rx_trace->enabled) /* trace_it */ ,
			1 /* do_it */ , 0 /* free_it */ );
}

#define foreach_msg_api_vector                  \
_(msg_names)                                    \
_(msg_handlers)                                 \
_(msg_cleanup_handlers)                         \
_(msg_endian_handlers)                          \
_(msg_print_handlers)                           \
_(api_trace_cfg)				\
_(message_bounce)				\
_(is_mp_safe)

void
vl_msg_api_config (vl_msg_api_msg_config_t * c)
{
  api_main_t *am = &api_main;

  ASSERT (c->id > 0);

#define _(a) vec_validate (am->a, c->id);
  foreach_msg_api_vector;
#undef _

  am->msg_names[c->id] = c->name;
  am->msg_handlers[c->id] = c->handler;
  am->msg_cleanup_handlers[c->id] = c->cleanup;
  am->msg_endian_handlers[c->id] = c->endian;
  am->msg_print_handlers[c->id] = c->print;
  am->message_bounce[c->id] = c->message_bounce;
  am->is_mp_safe[c->id] = c->is_mp_safe;

  am->api_trace_cfg[c->id].size = c->size;
  am->api_trace_cfg[c->id].trace_enable = c->traced;
  am->api_trace_cfg[c->id].replay_enable = c->replay;
}

/*
 * vl_msg_api_set_handlers
 * preserve the old API for a while
 */
void
vl_msg_api_set_handlers (int id, char *name, void *handler, void *cleanup,
			 void *endian, void *print, int size, int traced)
{
  vl_msg_api_msg_config_t cfg;
  vl_msg_api_msg_config_t *c = &cfg;

  memset (c, 0, sizeof (*c));

  c->id = id;
  c->name = name;
  c->handler = handler;
  c->cleanup = cleanup;
  c->endian = endian;
  c->print = print;
  c->traced = traced;
  c->replay = 1;
  c->message_bounce = 0;
  c->is_mp_safe = 0;
  vl_msg_api_config (c);
}

void
vl_msg_api_set_cleanup_handler (int msg_id, void *fp)
{
  api_main_t *am = &api_main;
  ASSERT (msg_id > 0);

  vec_validate (am->msg_cleanup_handlers, msg_id);
  am->msg_cleanup_handlers[msg_id] = fp;
}

void
vl_msg_api_queue_handler (unix_shared_memory_queue_t * q)
{
  uword msg;

  while (!unix_shared_memory_queue_sub (q, (u8 *) & msg, 0))
    vl_msg_api_handler ((void *) msg);
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

void
vl_noop_handler (void *mp)
{
}

clib_error_t *
vl_api_init (vlib_main_t * vm)
{
  static u8 once;
  api_main_t *am = &api_main;

  if (once)
    return 0;

  once = 1;

  am->region_name = "/unset";
  /*
   * Eventually passed to fchown, -1 => "current user"
   * instead of 0 => "root". A very fine disctinction at best.
   */
  if (am->api_uid == 0)
    am->api_uid = -1;
  if (am->api_gid == 0)
    am->api_gid = -1;

  return (0);
}

void vl_msg_api_custom_dump_configure (api_main_t * am)
  __attribute__ ((weak));
void
vl_msg_api_custom_dump_configure (api_main_t * am)
{
}

VLIB_INIT_FUNCTION (vl_api_init);

static void
vl_msg_api_process_file (vlib_main_t * vm, u8 * filename,
			 u32 first_index, u32 last_index,
			 vl_api_replay_t which)
{
  vl_api_trace_file_header_t *hp;
  int i, fd;
  struct stat statb;
  size_t file_size;
  u8 *msg;
  u8 endian_swap_needed = 0;
  api_main_t *am = &api_main;
  u8 *tmpbuf = 0;
  u32 nitems;
  void **saved_print_handlers = 0;

  fd = open ((char *) filename, O_RDONLY);

  if (fd < 0)
    {
      vlib_cli_output (vm, "Couldn't open %s\n", filename);
      return;
    }

  if (fstat (fd, &statb) < 0)
    {
      vlib_cli_output (vm, "Couldn't stat %s\n", filename);
      close (fd);
      return;
    }

  if (!(statb.st_mode & S_IFREG) || (statb.st_size < sizeof (*hp)))
    {
      vlib_cli_output (vm, "File not plausible: %s\n", filename);
      close (fd);
      return;
    }

  file_size = statb.st_size;
  file_size = (file_size + 4095) & ~(4096);

  hp = mmap (0, file_size, PROT_READ, MAP_PRIVATE, fd, 0);

  if (hp == (vl_api_trace_file_header_t *) MAP_FAILED)
    {
      vlib_cli_output (vm, "mmap failed: %s\n", filename);
      close (fd);
      return;
    }
  close (fd);

  if ((clib_arch_is_little_endian && hp->endian == VL_API_BIG_ENDIAN)
      || (clib_arch_is_big_endian && hp->endian == VL_API_LITTLE_ENDIAN))
    endian_swap_needed = 1;

  if (endian_swap_needed)
    nitems = ntohl (hp->nitems);
  else
    nitems = hp->nitems;

  if (last_index == (u32) ~ 0)
    {
      last_index = nitems - 1;
    }

  if (first_index >= nitems || last_index >= nitems)
    {
      vlib_cli_output (vm, "Range (%d, %d) outside file range (0, %d)\n",
		       first_index, last_index, nitems - 1);
      munmap (hp, file_size);
      return;
    }
  if (hp->wrapped)
    vlib_cli_output (vm,
		     "Note: wrapped/incomplete trace, results may vary\n");

  if (which == CUSTOM_DUMP)
    {
      saved_print_handlers = (void **) vec_dup (am->msg_print_handlers);
      vl_msg_api_custom_dump_configure (am);
    }


  msg = (u8 *) (hp + 1);

  for (i = 0; i < first_index; i++)
    {
      trace_cfg_t *cfgp;
      int size;
      u16 msg_id;

      size = clib_host_to_net_u32 (*(u32 *) msg);
      msg += sizeof (u32);

      if (clib_arch_is_little_endian)
	msg_id = ntohs (*((u16 *) msg));
      else
	msg_id = *((u16 *) msg);

      cfgp = am->api_trace_cfg + msg_id;
      if (!cfgp)
	{
	  vlib_cli_output (vm, "Ugh: msg id %d no trace config\n", msg_id);
	  munmap (hp, file_size);
	  return;
	}
      msg += size;
    }

  for (; i <= last_index; i++)
    {
      trace_cfg_t *cfgp;
      u16 *msg_idp;
      u16 msg_id;
      int size;

      if (which == DUMP)
	vlib_cli_output (vm, "---------- trace %d -----------\n", i);

      size = clib_host_to_net_u32 (*(u32 *) msg);
      msg += sizeof (u32);

      if (clib_arch_is_little_endian)
	msg_id = ntohs (*((u16 *) msg));
      else
	msg_id = *((u16 *) msg);

      cfgp = am->api_trace_cfg + msg_id;
      if (!cfgp)
	{
	  vlib_cli_output (vm, "Ugh: msg id %d no trace config\n", msg_id);
	  munmap (hp, file_size);
	  vec_free (tmpbuf);
	  return;
	}

      /* Copy the buffer (from the read-only mmap'ed file) */
      vec_validate (tmpbuf, size - 1 + sizeof (uword));
      clib_memcpy (tmpbuf + sizeof (uword), msg, size);
      memset (tmpbuf, 0xf, sizeof (uword));

      /*
       * Endian swap if needed. All msg data is supposed to be
       * in network byte order. All msg handlers are supposed to
       * know that. The generic message dumpers don't know that.
       * One could fix apigen, I suppose.
       */
      if ((which == DUMP && clib_arch_is_little_endian) || endian_swap_needed)
	{
	  void (*endian_fp) (void *);
	  if (msg_id >= vec_len (am->msg_endian_handlers)
	      || (am->msg_endian_handlers[msg_id] == 0))
	    {
	      vlib_cli_output (vm, "Ugh: msg id %d no endian swap\n", msg_id);
	      munmap (hp, file_size);
	      vec_free (tmpbuf);
	      return;
	    }
	  endian_fp = am->msg_endian_handlers[msg_id];
	  (*endian_fp) (tmpbuf + sizeof (uword));
	}

      /* msg_id always in network byte order */
      if (clib_arch_is_little_endian)
	{
	  msg_idp = (u16 *) (tmpbuf + sizeof (uword));
	  *msg_idp = msg_id;
	}

      switch (which)
	{
	case CUSTOM_DUMP:
	case DUMP:
	  if (msg_id < vec_len (am->msg_print_handlers) &&
	      am->msg_print_handlers[msg_id])
	    {
	      u8 *(*print_fp) (void *, void *);

	      print_fp = (void *) am->msg_print_handlers[msg_id];
	      (*print_fp) (tmpbuf + sizeof (uword), vm);
	    }
	  else
	    {
	      vlib_cli_output (vm, "Skipping msg id %d: no print fcn\n",
			       msg_id);
	      break;
	    }
	  break;

	case INITIALIZERS:
	  if (msg_id < vec_len (am->msg_print_handlers) &&
	      am->msg_print_handlers[msg_id])
	    {
	      u8 *s;
	      int j;
	      u8 *(*print_fp) (void *, void *);

	      print_fp = (void *) am->msg_print_handlers[msg_id];

	      vlib_cli_output (vm, "/*");

	      (*print_fp) (tmpbuf + sizeof (uword), vm);
	      vlib_cli_output (vm, "*/\n");

	      s = format (0, "static u8 * vl_api_%s_%d[%d] = {",
			  am->msg_names[msg_id], i,
			  am->api_trace_cfg[msg_id].size);

	      for (j = 0; j < am->api_trace_cfg[msg_id].size; j++)
		{
		  if ((j & 7) == 0)
		    s = format (s, "\n    ");
		  s = format (s, "0x%02x,", tmpbuf[sizeof (uword) + j]);
		}
	      s = format (s, "\n};\n%c", 0);
	      vlib_cli_output (vm, (char *) s);
	      vec_free (s);
	    }
	  break;

	case REPLAY:
	  if (msg_id < vec_len (am->msg_print_handlers) &&
	      am->msg_print_handlers[msg_id] && cfgp->replay_enable)
	    {
	      void (*handler) (void *);

	      handler = (void *) am->msg_handlers[msg_id];

	      if (!am->is_mp_safe[msg_id])
		vl_msg_api_barrier_sync ();
	      (*handler) (tmpbuf + sizeof (uword));
	      if (!am->is_mp_safe[msg_id])
		vl_msg_api_barrier_release ();
	    }
	  else
	    {
	      if (cfgp->replay_enable)
		vlib_cli_output (vm, "Skipping msg id %d: no handler\n",
				 msg_id);
	      break;
	    }
	  break;
	}

      _vec_len (tmpbuf) = 0;
      msg += size;
    }

  if (saved_print_handlers)
    {
      clib_memcpy (am->msg_print_handlers, saved_print_handlers,
		   vec_len (am->msg_print_handlers) * sizeof (void *));
      vec_free (saved_print_handlers);
    }

  munmap (hp, file_size);
  vec_free (tmpbuf);
}

u8 *
format_vl_msg_api_trace_status (u8 * s, va_list * args)
{
  api_main_t *am = va_arg (*args, api_main_t *);
  vl_api_trace_which_t which = va_arg (*args, vl_api_trace_which_t);
  vl_api_trace_t *tp;
  char *trace_name;

  switch (which)
    {
    case VL_API_TRACE_TX:
      tp = am->tx_trace;
      trace_name = "TX trace";
      break;

    case VL_API_TRACE_RX:
      tp = am->rx_trace;
      trace_name = "RX trace";
      break;

    default:
      abort ();
    }

  if (tp == 0)
    {
      s = format (s, "%s: not yet configured.\n", trace_name);
      return s;
    }

  s = format (s, "%s: used %d of %d items, %s enabled, %s wrapped\n",
	      trace_name, vec_len (tp->traces), tp->nitems,
	      tp->enabled ? "is" : "is not", tp->wrapped ? "has" : "has not");
  return s;
}

static u8 post_mortem_dump_enabled;

static clib_error_t *
api_trace_command_fn (vlib_main_t * vm,
		      unformat_input_t * input, vlib_cli_command_t * cmd)
{
  u32 nitems = 256 << 10;
  api_main_t *am = &api_main;
  vl_api_trace_which_t which = VL_API_TRACE_RX;
  u8 *filename;
  u32 first = 0;
  u32 last = (u32) ~ 0;
  FILE *fp;
  int rv;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "on") || unformat (input, "enable"))
	{
	  if (unformat (input, "nitems %d", &nitems))
	    ;
	  vl_msg_api_trace_configure (am, which, nitems);
	  vl_msg_api_trace_onoff (am, which, 1 /* on */ );
	}
      else if (unformat (input, "off"))
	{
	  vl_msg_api_trace_onoff (am, which, 0);
	}
      else if (unformat (input, "save %s", &filename))
	{
	  u8 *chroot_filename;
	  if (strstr ((char *) filename, "..")
	      || index ((char *) filename, '/'))
	    {
	      vlib_cli_output (vm, "illegal characters in filename '%s'",
			       filename);
	      return 0;
	    }

	  chroot_filename = format (0, "/tmp/%s%c", filename, 0);

	  vec_free (filename);

	  fp = fopen ((char *) chroot_filename, "w");
	  if (fp == NULL)
	    {
	      vlib_cli_output (vm, "Couldn't create %s\n", chroot_filename);
	      return 0;
	    }
	  rv = vl_msg_api_trace_save (am, which, fp);
	  fclose (fp);
	  if (rv == -1)
	    vlib_cli_output (vm, "API Trace data not present\n");
	  else if (rv == -2)
	    vlib_cli_output (vm, "File for writing is closed\n");
	  else if (rv == -10)
	    vlib_cli_output (vm, "Error while writing header to file\n");
	  else if (rv == -11)
	    vlib_cli_output (vm, "Error while writing trace to file\n");
	  else if (rv == -12)
	    vlib_cli_output (vm,
			     "Error while writing end of buffer trace to file\n");
	  else if (rv == -13)
	    vlib_cli_output (vm,
			     "Error while writing start of buffer trace to file\n");
	  else if (rv < 0)
	    vlib_cli_output (vm, "Unkown error while saving: %d", rv);
	  else
	    vlib_cli_output (vm, "API trace saved to %s\n", chroot_filename);
	  vec_free (chroot_filename);
	}
      else if (unformat (input, "dump %s", &filename))
	{
	  vl_msg_api_process_file (vm, filename, first, last, DUMP);
	}
      else if (unformat (input, "custom-dump %s", &filename))
	{
	  vl_msg_api_process_file (vm, filename, first, last, CUSTOM_DUMP);
	}
      else if (unformat (input, "replay %s", &filename))
	{
	  vl_msg_api_process_file (vm, filename, first, last, REPLAY);
	}
      else if (unformat (input, "initializers %s", &filename))
	{
	  vl_msg_api_process_file (vm, filename, first, last, INITIALIZERS);
	}
      else if (unformat (input, "tx"))
	{
	  which = VL_API_TRACE_TX;
	}
      else if (unformat (input, "first %d", &first))
	{
	  ;
	}
      else if (unformat (input, "last %d", &last))
	{
	  ;
	}
      else if (unformat (input, "status"))
	{
	  vlib_cli_output (vm, "%U", format_vl_msg_api_trace_status,
			   am, which);
	}
      else if (unformat (input, "free"))
	{
	  vl_msg_api_trace_onoff (am, which, 0);
	  vl_msg_api_trace_free (am, which);
	}
      else if (unformat (input, "post-mortem-on"))
	post_mortem_dump_enabled = 1;
      else if (unformat (input, "post-mortem-off"))
	post_mortem_dump_enabled = 0;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (api_trace_command, static) = {
    .path = "api trace",
    .short_help =
    "api trace [on|off][dump|save|replay <file>][status][free][post-mortem-on]",
    .function = api_trace_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
api_config_fn (vlib_main_t * vm, unformat_input_t * input)
{
  u32 nitems = 256 << 10;
  vl_api_trace_which_t which = VL_API_TRACE_RX;
  api_main_t *am = &api_main;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "on") || unformat (input, "enable"))
	{
	  if (unformat (input, "nitems %d", &nitems))
	    ;
	  vl_msg_api_trace_configure (am, which, nitems);
	  vl_msg_api_trace_onoff (am, which, 1 /* on */ );
	  post_mortem_dump_enabled = 1;
	}
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }
  return 0;
}

VLIB_CONFIG_FUNCTION (api_config_fn, "api-trace");

void
vl_msg_api_post_mortem_dump (void)
{
  api_main_t *am = &api_main;
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
  rv = vl_msg_api_trace_save (am, VL_API_TRACE_RX, fp);
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
vl_msg_api_register_pd_handler (void *fp, u16 msg_id_host_byte_order)
{
  api_main_t *am = &api_main;

  /* Mild idiot proofing */
  if (msg_id_host_byte_order > 10000)
    clib_warning ("msg_id_host_byte_order endian issue? %d arg vs %d",
		  msg_id_host_byte_order,
		  clib_net_to_host_u16 (msg_id_host_byte_order));
  vec_validate (am->pd_msg_handlers, msg_id_host_byte_order);
  am->pd_msg_handlers[msg_id_host_byte_order] = fp;
}

int
vl_msg_api_pd_handler (void *mp, int rv)
{
  api_main_t *am = &api_main;
  int (*fp) (void *, int);
  u16 msg_id;

  if (clib_arch_is_little_endian)
    msg_id = clib_net_to_host_u16 (*((u16 *) mp));
  else
    msg_id = *((u16 *) mp);

  if (msg_id >= vec_len (am->pd_msg_handlers)
      || am->pd_msg_handlers[msg_id] == 0)
    return rv;

  fp = am->pd_msg_handlers[msg_id];
  rv = (*fp) (mp, rv);
  return rv;
}

void
vl_msg_api_set_first_available_msg_id (u16 first_avail)
{
  api_main_t *am = &api_main;

  am->first_available_msg_id = first_avail;
}

u16
vl_msg_api_get_msg_ids (char *name, int n)
{
  api_main_t *am = &api_main;
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
vl_msg_api_add_msg_name_crc (api_main_t * am, char *string, u32 id)
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


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
