/*
 *------------------------------------------------------------------
 * Copyright (c) 2018 Cisco and/or its affiliates.
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

#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>

static clib_error_t *
vl_api_show_histogram_command (vlib_main_t * vm,
			       unformat_input_t * input,
			       vlib_cli_command_t * cli_cmd)
{
  u64 total_counts = 0;
  int i;

  for (i = 0; i < SLEEP_N_BUCKETS; i++)
    {
      total_counts += vector_rate_histogram[i];
    }

  if (total_counts == 0)
    {
      vlib_cli_output (vm, "No control-plane activity.");
      return 0;
    }

#define _(n)                                                    \
    do {                                                        \
        f64 percent;                                            \
        percent = ((f64) vector_rate_histogram[SLEEP_##n##_US]) \
            / (f64) total_counts;                               \
        percent *= 100.0;                                       \
        vlib_cli_output (vm, "Sleep %3d us: %llu, %.2f%%",n,    \
                         vector_rate_histogram[SLEEP_##n##_US], \
                         percent);                              \
    } while (0);
  foreach_histogram_bucket;
#undef _

  return 0;
}

/*?
 * Display the binary api sleep-time histogram
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (cli_show_api_histogram_command, static) =
{
  .path = "show api histogram",
  .short_help = "show api histogram",
  .function = vl_api_show_histogram_command,
};
/* *INDENT-ON* */

static clib_error_t *
vl_api_clear_histogram_command (vlib_main_t * vm,
				unformat_input_t * input,
				vlib_cli_command_t * cli_cmd)
{
  int i;

  for (i = 0; i < SLEEP_N_BUCKETS; i++)
    vector_rate_histogram[i] = 0;
  return 0;
}

/*?
 * Clear the binary api sleep-time histogram
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (cli_clear_api_histogram_command, static) =
{
  .path = "clear api histogram",
  .short_help = "clear api histogram",
  .function = vl_api_clear_histogram_command,
};
/* *INDENT-ON* */

static clib_error_t *
vl_api_client_command (vlib_main_t * vm,
		       unformat_input_t * input, vlib_cli_command_t * cli_cmd)
{
  vl_api_registration_t **regpp, *regp;
  svm_queue_t *q;
  char *health;
  api_main_t *am = vlibapi_get_main ();
  u32 *confused_indices = 0;

  if (!pool_elts (am->vl_clients))
    goto socket_clients;
  vlib_cli_output (vm, "Shared memory clients");
  vlib_cli_output (vm, "%20s %8s %14s %18s %s",
		   "Name", "PID", "Queue Length", "Queue VA", "Health");

  /* *INDENT-OFF* */
  pool_foreach (regpp, am->vl_clients)
   {
    regp = *regpp;

    if (regp)
      {
        if (regp->unanswered_pings > 0)
          health = "questionable";
        else
          health = "OK";

        q = regp->vl_input_queue;

        vlib_cli_output (vm, "%20s %8d %14d 0x%016llx %s\n",
                         regp->name, q->consumer_pid, q->cursize,
                         q, health);
      }
    else
      {
        clib_warning ("NULL client registration index %d",
                      regpp - am->vl_clients);
        vec_add1 (confused_indices, regpp - am->vl_clients);
      }
  }
  /* *INDENT-ON* */

  /* This should "never happen," but if it does, fix it... */
  if (PREDICT_FALSE (vec_len (confused_indices) > 0))
    {
      int i;
      for (i = 0; i < vec_len (confused_indices); i++)
	{
	  pool_put_index (am->vl_clients, confused_indices[i]);
	}
    }
  vec_free (confused_indices);

  if (am->missing_clients)
    vlib_cli_output (vm, "%u messages with missing clients",
		     am->missing_clients);
socket_clients:
  vl_sock_api_dump_clients (vm, am);

  return 0;
}

static clib_error_t *
vl_api_status_command (vlib_main_t * vm,
		       unformat_input_t * input, vlib_cli_command_t * cli_cmd)
{
  api_main_t *am = vlibapi_get_main ();

  /* check if rx_trace and tx_trace are not null pointers */
  if (am->rx_trace == 0)
    {
      vlib_cli_output (vm, "RX Trace disabled\n");
    }
  else
    {
      if (am->rx_trace->enabled == 0)
	vlib_cli_output (vm, "RX Trace disabled\n");
      else
	vlib_cli_output (vm, "RX Trace enabled\n");
    }

  if (am->tx_trace == 0)
    {
      vlib_cli_output (vm, "TX Trace disabled\n");
    }
  else
    {
      if (am->tx_trace->enabled == 0)
	vlib_cli_output (vm, "TX Trace disabled\n");
      else
	vlib_cli_output (vm, "TX Trace enabled\n");
    }

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (cli_show_api_command, static) =
{
  .path = "show api",
  .short_help = "Show API information",
};
/* *INDENT-ON* */

/*?
 * Display current api client connections
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (cli_show_api_clients_command, static) =
{
  .path = "show api clients",
  .short_help = "Client information",
  .function = vl_api_client_command,
};
/* *INDENT-ON* */

/*?
 * Display the current api message tracing status
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (cli_show_api_status_command, static) =
{
  .path = "show api trace-status",
  .short_help = "Display API trace status",
  .function = vl_api_status_command,
};
/* *INDENT-ON* */

static clib_error_t *
vl_api_message_table_command (vlib_main_t * vm,
			      unformat_input_t * input,
			      vlib_cli_command_t * cli_cmd)
{
  api_main_t *am = vlibapi_get_main ();
  int i;
  int verbose = 0;

  if (unformat (input, "verbose"))
    verbose = 1;


  if (verbose == 0)
    vlib_cli_output (vm, "%-4s %s", "ID", "Name");
  else
    vlib_cli_output (vm, "%-4s %-40s %6s %7s", "ID", "Name", "Bounce",
		     "MP-safe");

  for (i = 1; i < vec_len (am->msg_names); i++)
    {
      if (verbose == 0)
	{
	  vlib_cli_output (vm, "%-4d %s", i,
			   am->msg_names[i] ? am->msg_names[i] :
			   "  [no handler]");
	}
      else
	{
	  vlib_cli_output (vm, "%-4d %-40s %6d %7d", i,
			   am->msg_names[i] ? am->msg_names[i] :
			   "  [no handler]", am->message_bounce[i],
			   am->is_mp_safe[i]);
	}
    }

  return 0;
}

/*?
 * Display the current api message decode tables
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (cli_show_api_message_table_command, static) =
{
  .path = "show api message-table",
  .short_help = "Message Table",
  .function = vl_api_message_table_command,
};
/* *INDENT-ON* */

static int
range_compare (vl_api_msg_range_t * a0, vl_api_msg_range_t * a1)
{
  int len0, len1, clen;

  len0 = vec_len (a0->name);
  len1 = vec_len (a1->name);
  clen = len0 < len1 ? len0 : len1;
  return (strncmp ((char *) a0->name, (char *) a1->name, clen));
}

static u8 *
format_api_msg_range (u8 * s, va_list * args)
{
  vl_api_msg_range_t *rp = va_arg (*args, vl_api_msg_range_t *);

  if (rp == 0)
    s = format (s, "%-50s%9s%9s", "Name", "First-ID", "Last-ID");
  else
    s = format (s, "%-50s%9d%9d", rp->name, rp->first_msg_id,
		rp->last_msg_id);

  return s;
}

static clib_error_t *
vl_api_show_plugin_command (vlib_main_t * vm,
			    unformat_input_t * input,
			    vlib_cli_command_t * cli_cmd)
{
  api_main_t *am = vlibapi_get_main ();
  vl_api_msg_range_t *rp = 0;
  int i;

  if (vec_len (am->msg_ranges) == 0)
    {
      vlib_cli_output (vm, "No plugin API message ranges configured...");
      return 0;
    }

  rp = vec_dup (am->msg_ranges);

  vec_sort_with_function (rp, range_compare);

  vlib_cli_output (vm, "Plugin API message ID ranges...\n");
  vlib_cli_output (vm, "%U", format_api_msg_range, 0 /* header */ );

  for (i = 0; i < vec_len (rp); i++)
    vlib_cli_output (vm, "%U", format_api_msg_range, rp + i);

  vec_free (rp);

  return 0;
}

/*?
 * Display the plugin binary API message range table
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (cli_show_api_plugin_command, static) =
{
  .path = "show api plugin",
  .short_help = "show api plugin",
  .function = vl_api_show_plugin_command,
};
/* *INDENT-ON* */

typedef enum
{
  DUMP,
  CUSTOM_DUMP,
  REPLAY,
  INITIALIZERS,
} vl_api_replay_t;

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

void vl_msg_api_custom_dump_configure (api_main_t * am)
  __attribute__ ((weak));
void
vl_msg_api_custom_dump_configure (api_main_t * am)
{
}

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
  api_main_t *am = vlibapi_get_main ();
  u8 *tmpbuf = 0;
  u32 nitems, nitems_msgtbl;
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
  file_size = (file_size + 4095) & ~(4095);

  hp = mmap (0, file_size, PROT_READ, MAP_PRIVATE, fd, 0);

  if (hp == (vl_api_trace_file_header_t *) MAP_FAILED)
    {
      vlib_cli_output (vm, "mmap failed: %s\n", filename);
      close (fd);
      return;
    }
  close (fd);

  CLIB_MEM_UNPOISON (hp, file_size);

  nitems = ntohl (hp->nitems);

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

  u16 *msgid_vec = 0;
  serialize_main_t _sm, *sm = &_sm;
  u32 msgtbl_size = ntohl (hp->msgtbl_size);
  u8 *name_and_crc;

  unserialize_open_data (sm, msg, msgtbl_size);
  unserialize_integer (sm, &nitems_msgtbl, sizeof (u32));

  for (i = 0; i < nitems_msgtbl; i++)
    {
      u16 msg_index = unserialize_likely_small_unsigned_integer (sm);
      unserialize_cstring (sm, (char **) &name_and_crc);
      u16 msg_index2 = vl_msg_api_get_msg_index (name_and_crc);
      vec_validate (msgid_vec, msg_index);
      msgid_vec[msg_index] = msg_index2;
    }

  msg += msgtbl_size;

  for (i = 0; i < first_index; i++)
    {
      trace_cfg_t *cfgp;
      int size;
      u16 msg_id;

      size = clib_host_to_net_u32 (*(u32 *) msg);
      msg += sizeof (u32);

      msg_id = ntohs (*((u16 *) msg));
      if (msg_id < vec_len (msgid_vec))
	msg_id = msgid_vec[msg_id];
      cfgp = am->api_trace_cfg + msg_id;
      if (!cfgp)
	{
	  vlib_cli_output (vm, "Ugh: msg id %d no trace config\n", msg_id);
	  munmap (hp, file_size);
	  return;
	}
      msg += size;
    }

  if (which == REPLAY)
    am->replay_in_progress = 1;

  for (; i <= last_index; i++)
    {
      trace_cfg_t *cfgp;
      u16 msg_id;
      int size;

      if (which == DUMP)
	vlib_cli_output (vm, "---------- trace %d -----------\n", i);

      size = clib_host_to_net_u32 (*(u32 *) msg);
      msg += sizeof (u32);

      msg_id = ntohs (*((u16 *) msg));
      if (msg_id < vec_len (msgid_vec))
	{
	  msg_id = msgid_vec[msg_id];
	}

      cfgp = am->api_trace_cfg + msg_id;
      if (!cfgp)
	{
	  vlib_cli_output (vm, "Ugh: msg id %d no trace config\n", msg_id);
	  munmap (hp, file_size);
	  vec_free (tmpbuf);
	  am->replay_in_progress = 0;
	  return;
	}

      /* Copy the buffer (from the read-only mmap'ed file) */
      vec_validate (tmpbuf, size - 1 + sizeof (uword));
      clib_memcpy (tmpbuf + sizeof (uword), msg, size);
      clib_memset (tmpbuf, 0xf, sizeof (uword));

      /*
       * Endian swap if needed. All msg data is supposed to be in
       * network byte order.
       */
      if (((which == DUMP || which == CUSTOM_DUMP)
	   && clib_arch_is_little_endian))
	{
	  void (*endian_fp) (void *);
	  if (msg_id >= vec_len (am->msg_endian_handlers)
	      || (am->msg_endian_handlers[msg_id] == 0))
	    {
	      vlib_cli_output (vm, "Ugh: msg id %d no endian swap\n", msg_id);
	      munmap (hp, file_size);
	      vec_free (tmpbuf);
	      am->replay_in_progress = 0;
	      return;
	    }
	  endian_fp = am->msg_endian_handlers[msg_id];
	  (*endian_fp) (tmpbuf + sizeof (uword));
	}

      /* msg_id always in network byte order */
      if (clib_arch_is_little_endian)
	{
	  u16 *msg_idp = (u16 *) (tmpbuf + sizeof (uword));
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
	      void (*handler) (void *, vlib_main_t *);

	      handler = (void *) am->msg_handlers[msg_id];

	      if (!am->is_mp_safe[msg_id])
		vl_msg_api_barrier_sync ();
	      (*handler) (tmpbuf + sizeof (uword), vm);
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
  am->replay_in_progress = 0;
}

/** api_trace_command_fn - control the binary API trace / replay feature

    Note: this command MUST be marked thread-safe. Replay with
    multiple worker threads depends in many cases on worker thread
    graph replica maintenance. If we (implicitly) assert a worker
    thread barrier at the debug CLI level, all graph replica changes
    are deferred until the replay operation completes. If an interface
    is deleted, the wheels fall off.
 */

static clib_error_t *
api_trace_command_fn (vlib_main_t * vm,
		      unformat_input_t * input, vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u32 nitems = 256 << 10;
  api_main_t *am = vlibapi_get_main ();
  vl_api_trace_which_t which = VL_API_TRACE_RX;
  u8 *filename = 0;
  u8 *chroot_filename = 0;
  u32 first = 0;
  u32 last = (u32) ~ 0;
  FILE *fp;
  int rv;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "on") || unformat (line_input, "enable"))
	{
	  if (unformat (line_input, "nitems %d", &nitems))
	    ;
	  vlib_worker_thread_barrier_sync (vm);
	  vl_msg_api_trace_configure (am, which, nitems);
	  vl_msg_api_trace_onoff (am, which, 1 /* on */ );
	  vlib_worker_thread_barrier_release (vm);
	}
      else if (unformat (line_input, "off"))
	{
	  vlib_worker_thread_barrier_sync (vm);
	  vl_msg_api_trace_onoff (am, which, 0);
	  vlib_worker_thread_barrier_release (vm);
	}
      else if (unformat (line_input, "save %s", &filename))
	{
	  if (strstr ((char *) filename, "..")
	      || index ((char *) filename, '/'))
	    {
	      vlib_cli_output (vm, "illegal characters in filename '%s'",
			       filename);
	      goto out;
	    }

	  chroot_filename = format (0, "/tmp/%s%c", filename, 0);

	  vec_free (filename);

	  fp = fopen ((char *) chroot_filename, "w");
	  if (fp == NULL)
	    {
	      vlib_cli_output (vm, "Couldn't create %s\n", chroot_filename);
	      goto out;
	    }
	  vlib_worker_thread_barrier_sync (vm);
	  rv = vl_msg_api_trace_save (am, which, fp);
	  vlib_worker_thread_barrier_release (vm);
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
	    vlib_cli_output (vm, "Unknown error while saving: %d", rv);
	  else
	    vlib_cli_output (vm, "API trace saved to %s\n", chroot_filename);
	  goto out;
	}
      else if (unformat (line_input, "dump %s", &filename))
	{
	  vl_msg_api_process_file (vm, filename, first, last, DUMP);
	}
      else if (unformat (line_input, "custom-dump %s", &filename))
	{
	  vl_msg_api_process_file (vm, filename, first, last, CUSTOM_DUMP);
	}
      else if (unformat (line_input, "replay %s", &filename))
	{
	  vl_msg_api_process_file (vm, filename, first, last, REPLAY);
	}
      else if (unformat (line_input, "initializers %s", &filename))
	{
	  vl_msg_api_process_file (vm, filename, first, last, INITIALIZERS);
	}
      else if (unformat (line_input, "tx"))
	{
	  which = VL_API_TRACE_TX;
	}
      else if (unformat (line_input, "first %d", &first))
	{
	  ;
	}
      else if (unformat (line_input, "last %d", &last))
	{
	  ;
	}
      else if (unformat (line_input, "status"))
	{
	  vlib_cli_output (vm, "%U", format_vl_msg_api_trace_status,
			   am, which);
	}
      else if (unformat (line_input, "free"))
	{
	  vlib_worker_thread_barrier_sync (vm);
	  vl_msg_api_trace_onoff (am, which, 0);
	  vl_msg_api_trace_free (am, which);
	  vlib_worker_thread_barrier_release (vm);
	}
      else if (unformat (line_input, "post-mortem-on"))
	vl_msg_api_post_mortem_dump_enable_disable (1 /* enable */ );
      else if (unformat (line_input, "post-mortem-off"))
	vl_msg_api_post_mortem_dump_enable_disable (0 /* enable */ );
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }
out:
  vec_free (filename);
  vec_free (chroot_filename);
  unformat_free (line_input);
  return 0;
}

/*?
 * Display, replay, or save a binary API trace
?*/

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (api_trace_command, static) =
{
  .path = "api trace",
  .short_help = "api trace [on|off][first <n>][last <n>][status][free]"
                "[post-mortem-on][dump|custom-dump|save|replay <file>]",
  .function = api_trace_command_fn,
  .is_mp_safe = 1,
};
/* *INDENT-ON* */

static clib_error_t *
vl_api_trace_command (vlib_main_t * vm,
		      unformat_input_t * input, vlib_cli_command_t * cli_cmd)
{
  u32 nitems = 1024;
  vl_api_trace_which_t which = VL_API_TRACE_RX;
  api_main_t *am = vlibapi_get_main ();

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "rx nitems %u", &nitems) || unformat (input, "rx"))
	goto configure;
      else if (unformat (input, "tx nitems %u", &nitems)
	       || unformat (input, "tx"))
	{
	  which = VL_API_TRACE_RX;
	  goto configure;
	}
      else if (unformat (input, "on rx"))
	{
	  vl_msg_api_trace_onoff (am, VL_API_TRACE_RX, 1);
	}
      else if (unformat (input, "on tx"))
	{
	  vl_msg_api_trace_onoff (am, VL_API_TRACE_TX, 1);
	}
      else if (unformat (input, "on"))
	{
	  vl_msg_api_trace_onoff (am, VL_API_TRACE_RX, 1);
	}
      else if (unformat (input, "off"))
	{
	  vl_msg_api_trace_onoff (am, VL_API_TRACE_RX, 0);
	  vl_msg_api_trace_onoff (am, VL_API_TRACE_TX, 0);
	}
      else if (unformat (input, "free"))
	{
	  vl_msg_api_trace_onoff (am, VL_API_TRACE_RX, 0);
	  vl_msg_api_trace_onoff (am, VL_API_TRACE_TX, 0);
	  vl_msg_api_trace_free (am, VL_API_TRACE_RX);
	  vl_msg_api_trace_free (am, VL_API_TRACE_TX);
	}
      else if (unformat (input, "debug on"))
	{
	  am->msg_print_flag = 1;
	}
      else if (unformat (input, "debug off"))
	{
	  am->msg_print_flag = 0;
	}
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }
  return 0;

configure:
  if (vl_msg_api_trace_configure (am, which, nitems))
    {
      vlib_cli_output (vm, "warning: trace configure error (%d, %d)",
		       which, nitems);
    }

  return 0;
}

/*?
 * Control the binary API trace mechanism
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (trace, static) =
{
  .path = "set api-trace",
  .short_help = "API trace [on][on tx][on rx][off][free][debug on][debug off]",
  .function = vl_api_trace_command,
};
/* *INDENT-ON* */

static clib_error_t *
api_trace_config_fn (vlib_main_t * vm, unformat_input_t * input)
{
  u32 nitems = 256 << 10;
  vl_api_trace_which_t which = VL_API_TRACE_RX;
  api_main_t *am = vlibapi_get_main ();

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "on") || unformat (input, "enable"))
	{
	  if (unformat (input, "nitems %d", &nitems))
	    ;
	  vl_msg_api_trace_configure (am, which, nitems);
	  vl_msg_api_trace_onoff (am, which, 1 /* on */ );
	  vl_msg_api_post_mortem_dump_enable_disable (1 /* enable */ );
	}
      else if (unformat (input, "save-api-table %s",
			 &am->save_msg_table_filename))
	;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }
  return 0;
}

/*?
 * This module has three configuration parameters:
 * "on" or "enable" - enables binary api tracing
 * "nitems <nnn>" - sets the size of the circular buffer to <nnn>
 * "save-api-table <filename>" - dumps the API message table to /tmp/<filename>
?*/
VLIB_CONFIG_FUNCTION (api_trace_config_fn, "api-trace");

static clib_error_t *
api_queue_config_fn (vlib_main_t * vm, unformat_input_t * input)
{
  api_main_t *am = vlibapi_get_main ();
  u32 nitems;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "length %d", &nitems) ||
	  (unformat (input, "len %d", &nitems)))
	{
	  if (nitems >= 1024)
	    am->vlib_input_queue_length = nitems;
	  else
	    clib_warning ("vlib input queue length %d too small, ignored",
			  nitems);
	}
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }
  return 0;
}

VLIB_CONFIG_FUNCTION (api_queue_config_fn, "api-queue");

static u8 *
extract_name (u8 * s)
{
  u8 *rv;

  rv = vec_dup (s);

  while (vec_len (rv) && rv[vec_len (rv)] != '_')
    _vec_len (rv)--;

  rv[vec_len (rv)] = 0;

  return rv;
}

static u8 *
extract_crc (u8 * s)
{
  int i;
  u8 *rv;

  rv = vec_dup (s);

  for (i = vec_len (rv) - 1; i >= 0; i--)
    {
      if (rv[i] == '_')
	{
	  vec_delete (rv, i + 1, 0);
	  break;
	}
    }
  return rv;
}

typedef struct
{
  u8 *name_and_crc;
  u8 *name;
  u8 *crc;
  u32 msg_index;
  int which;
} msg_table_unserialize_t;

static int
table_id_cmp (void *a1, void *a2)
{
  msg_table_unserialize_t *n1 = a1;
  msg_table_unserialize_t *n2 = a2;

  return (n1->msg_index - n2->msg_index);
}

static int
table_name_and_crc_cmp (void *a1, void *a2)
{
  msg_table_unserialize_t *n1 = a1;
  msg_table_unserialize_t *n2 = a2;

  return strcmp ((char *) n1->name_and_crc, (char *) n2->name_and_crc);
}

typedef struct
{
  char *name;
  u32 new_crc;
  u32 old_crc;
} msgcrc_fixup_entry_t;

static msgcrc_fixup_entry_t crc_fixup_dict[] = {
  { "abf_policy_add_del", 0xc6131197, 0xee66f93e },
  { "abf_policy_details", 0xb7487fa4, 0x6769e504 },
  { "acl_add_replace", 0xee5c2f18, 0x1cabdeab },
  { "acl_details", 0x95babae0, 0x7a97f21c },
  { "macip_acl_add", 0xce6fbad0, 0xd648fd0a },
  { "macip_acl_add_replace", 0x2a461dd4, 0xe34402a7 },
  { "macip_acl_details", 0x27135b59, 0x57c7482f },
  { "dhcp_proxy_config", 0x4058a689, 0x6767230e },
  { "dhcp_client_config", 0x1af013ea, 0x959b80a3 },
  { "dhcp_compl_event", 0x554a44e5, 0xe908fd1d },
  { "dhcp_client_details", 0x3c5cd28a, 0xacd82f5a },
  { "dhcp_proxy_details", 0xdcbaf540, 0xce16f044 },
  { "dhcp6_send_client_message", 0xf8222476, 0xf6f14ef0 },
  { "dhcp6_pd_send_client_message", 0x3739fd8d, 0x64badb8 },
  { "dhcp6_reply_event", 0x85b7b17e, 0x9f3af9e5 },
  { "dhcp6_pd_reply_event", 0x5e878029, 0xcb3e462b },
  { "ip6_add_del_address_using_prefix", 0x3982f30a, 0x9b3d11e0 },
  { "gbp_bridge_domain_add", 0x918e8c01, 0x8454bfdf },
  { "gbp_bridge_domain_details", 0x51d51be9, 0x2acd15f9 },
  { "gbp_route_domain_add", 0x204c79e1, 0x2d0afe38 },
  { "gbp_route_domain_details", 0xa78bfbca, 0x8ab11375 },
  { "gbp_endpoint_add", 0x7b3af7de, 0x9ce16d5a },
  { "gbp_endpoint_details", 0x8dd8fbd3, 0x8aecb60 },
  { "gbp_endpoint_group_add", 0x301ddf15, 0x8e0f4054 },
  { "gbp_endpoint_group_details", 0xab71d723, 0x8f38292c },
  { "gbp_subnet_add_del", 0xa8803c80, 0x888aca35 },
  { "gbp_subnet_details", 0xcbc5ca18, 0x4ed84156 },
  { "gbp_contract_add_del", 0xaa8d652d, 0x553e275b },
  { "gbp_contract_details", 0x65dec325, 0x2a18db6e },
  { "gbp_ext_itf_add_del", 0x7606d0e1, 0x12ed5700 },
  { "gbp_ext_itf_details", 0x519c3d3c, 0x408a45c0 },
  { "gtpu_add_del_tunnel", 0xca983a2b, 0x9a9c0426 },
  { "gtpu_tunnel_update_tteid", 0x79f33816, 0x8a2db108 },
  { "gtpu_tunnel_details", 0x27f434ae, 0x4535cf95 },
  { "igmp_listen", 0x19a49f1e, 0x3f93a51a },
  { "igmp_details", 0x38f09929, 0x52f12a89 },
  { "igmp_event", 0x85fe93ec, 0xd7696eaf },
  { "igmp_group_prefix_set", 0x5b14a5ce, 0xd4f20ac5 },
  { "igmp_group_prefix_details", 0x259ccd81, 0xc3b3c526 },
  { "ikev2_set_responder", 0xb9aa4d4e, 0xf0d3dc80 },
  { "vxlan_gpe_ioam_export_enable_disable", 0xd4c76d3a, 0xe4d4ebfa },
  { "ioam_export_ip6_enable_disable", 0xd4c76d3a, 0xe4d4ebfa },
  { "vxlan_gpe_ioam_vni_enable", 0xfbb5fb1, 0x997161fb },
  { "vxlan_gpe_ioam_vni_disable", 0xfbb5fb1, 0x997161fb },
  { "vxlan_gpe_ioam_transit_enable", 0x3d3ec657, 0x553f5b7b },
  { "vxlan_gpe_ioam_transit_disable", 0x3d3ec657, 0x553f5b7b },
  { "udp_ping_add_del", 0xfa2628fc, 0xc692b188 },
  { "l3xc_update", 0xe96aabdf, 0x787b1d3 },
  { "l3xc_details", 0xbc5bf852, 0xd4f69627 },
  { "sw_interface_lacp_details", 0xd9a83d2f, 0x745ae0ba },
  { "lb_conf", 0x56cd3261, 0x22ddb739 },
  { "lb_add_del_vip", 0x6fa569c7, 0xd15b7ddc },
  { "lb_add_del_as", 0x35d72500, 0x78628987 },
  { "lb_vip_dump", 0x56110cb7, 0xc7bcb124 },
  { "lb_vip_details", 0x1329ec9b, 0x8f39bed },
  { "lb_as_details", 0x8d24c29e, 0x9c39f60e },
  { "mactime_add_del_range", 0xcb56e877, 0x101858ef },
  { "mactime_details", 0xda25b13a, 0x44921c06 },
  { "map_add_domain", 0x249f195c, 0x7a5a18c9 },
  { "map_domain_details", 0x796edb50, 0xfc1859dd },
  { "map_param_add_del_pre_resolve", 0xdae5af03, 0x17008c66 },
  { "map_param_get_reply", 0x26272c90, 0x28092156 },
  { "memif_details", 0xda34feb9, 0xd0382c4c },
  { "dslite_add_del_pool_addr_range", 0xde2a5b02, 0xc448457a },
  { "dslite_set_aftr_addr", 0x78b50fdf, 0x1e955f8d },
  { "dslite_get_aftr_addr_reply", 0x8e23608e, 0x38e30db1 },
  { "dslite_set_b4_addr", 0x78b50fdf, 0x1e955f8d },
  { "dslite_get_b4_addr_reply", 0x8e23608e, 0x38e30db1 },
  { "nat44_add_del_address_range", 0x6f2b8055, 0xd4c7568c },
  { "nat44_address_details", 0xd1beac1, 0x45410ac4 },
  { "nat44_add_del_static_mapping", 0x5ae5f03e, 0xe165e83b },
  { "nat44_static_mapping_details", 0x6cb40b2, 0x1a433ef7 },
  { "nat44_add_del_identity_mapping", 0x2faaa22, 0x8e12743f },
  { "nat44_identity_mapping_details", 0x2a52a030, 0x36d21351 },
  { "nat44_add_del_interface_addr", 0x4aed50c0, 0xfc835325 },
  { "nat44_interface_addr_details", 0xe4aca9ca, 0x3e687514 },
  { "nat44_user_session_details", 0x2cf6e16d, 0x1965fd69 },
  { "nat44_add_del_lb_static_mapping", 0x4f68ee9d, 0x53b24611 },
  { "nat44_lb_static_mapping_add_del_local", 0x7ca47547, 0x2910a151 },
  { "nat44_lb_static_mapping_details", 0xed5ce876, 0x2267b9e8 },
  { "nat44_del_session", 0x15a5bf8c, 0x4c49c387 },
  { "nat_det_add_del_map", 0x1150a190, 0x112fde05 },
  { "nat_det_map_details", 0xad91dc83, 0x88000ee1 },
  { "nat_det_close_session_out", 0xf6b259d1, 0xc1b6cbfb },
  { "nat_det_close_session_in", 0x3c68e073, 0xa10ef64 },
  { "nat64_add_del_pool_addr_range", 0xa3b944e3, 0x21234ef3 },
  { "nat64_add_del_static_bib", 0x1c404de5, 0x90fae58a },
  { "nat64_bib_details", 0x43bc3ddf, 0x62c8541d },
  { "nat64_st_details", 0xdd3361ed, 0xc770d620 },
  { "nat66_add_del_static_mapping", 0x3ed88f71, 0xfb64e50b },
  { "nat66_static_mapping_details", 0xdf39654b, 0x5c568448 },
  { "nsh_add_del_map", 0xa0f42b0, 0x898d857d },
  { "nsh_map_details", 0x2fefcf49, 0xb34ac8a1 },
  { "nsim_cross_connect_enable_disable", 0x9c3ead86, 0x16f70bdf },
  { "pppoe_add_del_session", 0xf6fd759e, 0x46ace853 },
  { "pppoe_session_details", 0x4b8e8a4a, 0x332bc742 },
  { "stn_add_del_rule", 0x224c6edd, 0x53f751e6 },
  { "stn_rules_details", 0xa51935a6, 0xb0f6606c },
  { "svs_route_add_del", 0xe49bc63c, 0xd39e31fc },
  { "svs_details", 0x6282cd55, 0xb8523d64 },
  { "vmxnet3_details", 0x6a1a5498, 0x829ba055 },
  { "vrrp_vr_add_del", 0xc5cf15aa, 0x6dc4b881 },
  { "vrrp_vr_details", 0x46edcebd, 0x412fa71 },
  { "vrrp_vr_set_peers", 0x20bec71f, 0xbaa2e52b },
  { "vrrp_vr_peer_details", 0x3d99c108, 0xabd9145e },
  { "vrrp_vr_track_if_add_del", 0xd67df299, 0x337f4ba4 },
  { "vrrp_vr_track_if_details", 0x73c36f81, 0x99bcca9c },
  { "proxy_arp_add_del", 0x1823c3e7, 0x85486cbd },
  { "proxy_arp_details", 0x5b948673, 0x9228c150 },
  { "bfd_udp_get_echo_source_reply", 0xe3d736a1, 0x1e00cfce },
  { "bfd_udp_add", 0x939cd26a, 0x7a6d1185 },
  { "bfd_udp_mod", 0x913df085, 0x783a3ff6 },
  { "bfd_udp_del", 0xdcb13a89, 0x8096514d },
  { "bfd_udp_session_details", 0x9fb2f2d, 0x60653c02 },
  { "bfd_udp_session_set_flags", 0x4b4bdfd, 0xcf313851 },
  { "bfd_udp_auth_activate", 0x21fd1bdb, 0x493ee0ec },
  { "bfd_udp_auth_deactivate", 0x9a05e2e0, 0x99978c32 },
  { "bier_route_add_del", 0xfd02f3ea, 0xf29edca0 },
  { "bier_route_details", 0x4008caee, 0x39ee6a56 },
  { "bier_disp_entry_add_del", 0x9eb80cb4, 0x648323eb },
  { "bier_disp_entry_details", 0x84c218f1, 0xe5b039a9 },
  { "bond_create", 0xf1dbd4ff, 0x48883c7e },
  { "bond_enslave", 0xe7d14948, 0x76ecfa7 },
  { "sw_interface_bond_details", 0xbb7c929b, 0xf5ef2106 },
  { "pipe_create_reply", 0xb7ce310c, 0xd4c2c2b3 },
  { "pipe_details", 0xc52b799d, 0x43ac107a },
  { "tap_create_v2", 0x2d0d6570, 0x445835fd },
  { "sw_interface_tap_v2_details", 0x1e2b2a47, 0xe53c16de },
  { "sw_interface_vhost_user_details", 0xcee1e53, 0x98530df1 },
  { "virtio_pci_create", 0x1944f8db, 0xa9f1370c },
  { "sw_interface_virtio_pci_details", 0x6ca9c167, 0x16187f3a },
  { "p2p_ethernet_add", 0x36a1a6dc, 0xeeb8e717 },
  { "p2p_ethernet_del", 0x62f81c8c, 0xb62c386 },
  { "geneve_add_del_tunnel", 0x99445831, 0x976693b5 },
  { "geneve_tunnel_details", 0x6b16eb24, 0xe27e2748 },
  { "gre_tunnel_add_del", 0xa27d7f17, 0x6efc9c22 },
  { "gre_tunnel_details", 0x24435433, 0x3bfbf1 },
  { "sw_interface_set_flags", 0xf5aec1b8, 0x6a2b491a },
  { "sw_interface_event", 0x2d3d95a7, 0xf709f78d },
  { "sw_interface_details", 0x6c221fc7, 0x17b69fa2 },
  { "sw_interface_add_del_address", 0x5463d73b, 0x5803d5c4 },
  { "sw_interface_set_unnumbered", 0x154a6439, 0x938ef33b },
  { "sw_interface_set_mac_address", 0xc536e7eb, 0x6aca746a },
  { "sw_interface_set_rx_mode", 0xb04d1cfe, 0x780f5cee },
  { "sw_interface_rx_placement_details", 0x9e44a7ce, 0xf6d7d024 },
  { "create_subif", 0x790ca755, 0xcb371063 },
  { "ip_neighbor_add_del", 0x607c257, 0x105518b6 },
  { "ip_neighbor_dump", 0xd817a484, 0xcd831298 },
  { "ip_neighbor_details", 0xe29d79f0, 0x870e80b9 },
  { "want_ip_neighbor_events", 0x73e70a86, 0x1a312870 },
  { "ip_neighbor_event", 0xbdb092b2, 0x83933131 },
  { "ip_route_add_del", 0xb8ecfe0d, 0xc1ff832d },
  { "ip_route_details", 0xbda8f315, 0xd1ffaae1 },
  { "ip_route_lookup", 0x710d6471, 0xe2986185 },
  { "ip_route_lookup_reply", 0x5d8febcb, 0xae99de8e },
  { "ip_mroute_add_del", 0x85d762f3, 0xf6627d17 },
  { "ip_mroute_details", 0x99341a45, 0xc1cb4b44 },
  { "ip_address_details", 0xee29b797, 0xb1199745 },
  { "ip_unnumbered_details", 0xcc59bd42, 0xaa12a483 },
  { "mfib_signal_details", 0x6f4a4cfb, 0x64398a9a },
  { "ip_punt_redirect", 0x6580f635, 0xa9a5592c },
  { "ip_punt_redirect_details", 0x2cef63e7, 0x3924f5d3 },
  { "ip_container_proxy_add_del", 0x7df1dff1, 0x91189f40 },
  { "ip_container_proxy_details", 0xa8085523, 0xee460e8 },
  { "ip_source_and_port_range_check_add_del", 0x92a067e3, 0x8bfc76f2 },
  { "sw_interface_ip6_set_link_local_address", 0x1c10f15f, 0x2931d9fa },
  { "ip_reassembly_enable_disable", 0xeb77968d, 0x885c85a6 },
  { "set_punt", 0xaa83d523, 0x83799618 },
  { "punt_socket_register", 0x95268cbf, 0xc8cd10fa },
  { "punt_socket_details", 0xde575080, 0x1de0ce75 },
  { "punt_socket_deregister", 0x98fc9102, 0x98a444f4 },
  { "sw_interface_ip6nd_ra_prefix", 0x82cc1b28, 0xe098785f },
  { "ip6nd_proxy_add_del", 0xc2e4a686, 0x3fdf6659 },
  { "ip6nd_proxy_details", 0x30b9ff4a, 0xd35be8ff },
  { "ip6_ra_event", 0x364c1c5, 0x47e8cfbe },
  { "set_ipfix_exporter", 0x5530c8a0, 0x69284e07 },
  { "ipfix_exporter_details", 0xdedbfe4, 0x11e07413 },
  { "ipip_add_tunnel", 0x2ac399f5, 0xa9decfcd },
  { "ipip_6rd_add_tunnel", 0xb9ec1863, 0x56e93cc0 },
  { "ipip_tunnel_details", 0xd31cb34e, 0x53236d75 },
  { "ipsec_spd_entry_add_del", 0x338b7411, 0x9f384b8d },
  { "ipsec_spd_details", 0x5813d7a2, 0xf2222790 },
  { "ipsec_sad_entry_add_del", 0xab64b5c6, 0xb8def364 },
  { "ipsec_tunnel_protect_update", 0x30d5f133, 0x143f155d },
  { "ipsec_tunnel_protect_del", 0xcd239930, 0xddd2ba36 },
  { "ipsec_tunnel_protect_details", 0x21663a50, 0xac6c823b },
  { "ipsec_tunnel_if_add_del", 0x20e353fa, 0x2b135e68 },
  { "ipsec_sa_details", 0x345d14a7, 0xb30c7f41 },
  { "l2_xconnect_details", 0x472b6b67, 0xc8aa6b37 },
  { "l2_fib_table_details", 0xa44ef6b8, 0xe8d2fc72 },
  { "l2fib_add_del", 0xeddda487, 0xf29d796c },
  { "l2_macs_event", 0x44b8fd64, 0x2eadfc8b },
  { "bridge_domain_details", 0xfa506fd, 0x979f549d },
  { "l2_interface_pbb_tag_rewrite", 0x38e802a8, 0x612efa5a },
  { "l2_patch_add_del", 0xa1f6a6f3, 0x522f3445 },
  { "sw_interface_set_l2_xconnect", 0x4fa28a85, 0x1aaa2dbb },
  { "sw_interface_set_l2_bridge", 0xd0678b13, 0x2e483cd0 },
  { "bd_ip_mac_add_del", 0x257c869, 0x5f2b84e2 },
  { "bd_ip_mac_details", 0x545af86a, 0xa52f8044 },
  { "l2_arp_term_event", 0x6963e07a, 0x85ff71ea },
  { "l2tpv3_create_tunnel", 0x15bed0c2, 0x596892cb },
  { "sw_if_l2tpv3_tunnel_details", 0x50b88993, 0x1dab5c7e },
  { "lisp_add_del_local_eid", 0x4e5a83a2, 0x21f573bd },
  { "lisp_add_del_map_server", 0xce19e32d, 0x6598ea7c },
  { "lisp_add_del_map_resolver", 0xce19e32d, 0x6598ea7c },
  { "lisp_use_petr", 0xd87dbad9, 0x9e141831 },
  { "show_lisp_use_petr_reply", 0x22b9a4b0, 0xdcad8a81 },
  { "lisp_add_del_remote_mapping", 0x6d5c789e, 0xfae8ed77 },
  { "lisp_add_del_adjacency", 0x2ce0e6f6, 0xcf5edb61 },
  { "lisp_locator_details", 0x2c620ffe, 0xc0c4c2a7 },
  { "lisp_eid_table_details", 0x1c29f792, 0x4bc32e3a },
  { "lisp_eid_table_dump", 0x629468b5, 0xb959b73b },
  { "lisp_adjacencies_get_reply", 0x807257bf, 0x3f97bcdd },
  { "lisp_map_resolver_details", 0x3e78fc57, 0x82a09deb },
  { "lisp_map_server_details", 0x3e78fc57, 0x82a09deb },
  { "one_add_del_local_eid", 0x4e5a83a2, 0x21f573bd },
  { "one_add_del_map_server", 0xce19e32d, 0x6598ea7c },
  { "one_add_del_map_resolver", 0xce19e32d, 0x6598ea7c },
  { "one_use_petr", 0xd87dbad9, 0x9e141831 },
  { "show_one_use_petr_reply", 0x84a03528, 0x10e744a6 },
  { "one_add_del_remote_mapping", 0x6d5c789e, 0xfae8ed77 },
  { "one_add_del_l2_arp_entry", 0x1aa5e8b3, 0x33209078 },
  { "one_l2_arp_entries_get_reply", 0xb0dd200f, 0xb0a47bbe },
  { "one_add_del_ndp_entry", 0xf8a287c, 0xd1629a2f },
  { "one_ndp_entries_get_reply", 0x70719b1a, 0xbd34161 },
  { "one_add_del_adjacency", 0x9e830312, 0xe48e7afe },
  { "one_locator_details", 0x2c620ffe, 0xc0c4c2a7 },
  { "one_eid_table_details", 0x1c29f792, 0x4bc32e3a },
  { "one_eid_table_dump", 0xbd190269, 0x95151038 },
  { "one_adjacencies_get_reply", 0x85bab89, 0xa8ed89a5 },
  { "one_map_resolver_details", 0x3e78fc57, 0x82a09deb },
  { "one_map_server_details", 0x3e78fc57, 0x82a09deb },
  { "one_stats_details", 0x2eb74678, 0xff6ef238 },
  { "gpe_add_del_fwd_entry", 0xf0847644, 0xde6df50f },
  { "gpe_fwd_entries_get_reply", 0xc4844876, 0xf9f53f1b },
  { "gpe_fwd_entry_path_details", 0x483df51a, 0xee80b19a },
  { "gpe_add_del_native_fwd_rpath", 0x43fc8b54, 0x812da2f2 },
  { "gpe_native_fwd_rpaths_get_reply", 0x7a1ca5a2, 0x79d54eb9 },
  { "sw_interface_set_lldp", 0x57afbcd4, 0xd646ae0f },
  { "mpls_ip_bind_unbind", 0xc7533b32, 0x48249a27 },
  { "mpls_tunnel_add_del", 0x44350ac1, 0xe57ce61d },
  { "mpls_tunnel_details", 0x57118ae3, 0xf3c0928e },
  { "mpls_route_add_del", 0x8e1d1e07, 0x343cff54 },
  { "mpls_route_details", 0x9b5043dc, 0xd0ac384c },
  { "policer_add_del", 0x2b31dd38, 0xcb948f6e },
  { "policer_details", 0x72d0e248, 0xa43f781a },
  { "qos_store_enable_disable", 0xf3abcc8b, 0x3507235e },
  { "qos_store_details", 0x3ee0aad7, 0x38a6d48 },
  { "qos_record_enable_disable", 0x2f1a4a38, 0x25b33f88 },
  { "qos_record_details", 0xa425d4d3, 0x4956ccdd },
  { "session_rule_add_del", 0xe4895422, 0xe31f9443 },
  { "session_rules_details", 0x28d71830, 0x304b91f0 },
  { "sw_interface_span_enable_disable", 0x23ddd96b, 0xacc8fea1 },
  { "sw_interface_span_details", 0x8a20e79f, 0x55643fc },
  { "sr_mpls_steering_add_del", 0x64acff63, 0x7d1b0a0b },
  { "sr_mpls_policy_assign_endpoint_color", 0xe7eb978, 0x5e1c5c13 },
  { "sr_localsid_add_del", 0x5a36c324, 0x26fa3309 },
  { "sr_policy_add", 0x44ac92e8, 0xec79ee6a },
  { "sr_policy_mod", 0xb97bb56e, 0xe531a102 },
  { "sr_steering_add_del", 0xe46b0a0f, 0x3711dace },
  { "sr_localsids_details", 0x2e9221b9, 0x6a6c0265 },
  { "sr_policies_details", 0xdb6ff2a1, 0x7ec2d93 },
  { "sr_steering_pol_details", 0xd41258c9, 0x1c1ee786 },
  { "syslog_set_sender", 0xb8011d0b, 0xbb641285 },
  { "syslog_get_sender_reply", 0x424cfa4e, 0xd3da60ac },
  { "tcp_configure_src_addresses", 0x67eede0d, 0x4b02b946 },
  { "teib_entry_add_del", 0x8016cfd2, 0x5aa0a538 },
  { "teib_details", 0x981ee1a1, 0xe3b6a503 },
  { "udp_encap_add", 0xf74a60b1, 0x61d5fc48 },
  { "udp_encap_details", 0x8cfb9c76, 0x87c82821 },
  { "vxlan_gbp_tunnel_add_del", 0x6c743427, 0x8c819166 },
  { "vxlan_gbp_tunnel_details", 0x66e94a89, 0x1da24016 },
  { "vxlan_gpe_add_del_tunnel", 0xa645b2b0, 0x7c6da6ae },
  { "vxlan_gpe_tunnel_details", 0x968fc8b, 0x57712346 },
  { "vxlan_add_del_tunnel", 0xc09dc80, 0xa35dc8f5 },
  { "vxlan_tunnel_details", 0xc3916cb1, 0xe782f70f },
  { "vxlan_offload_rx", 0x9cc95087, 0x89a1564b },
  { "log_details", 0x3d61cc0, 0x255827a1 },
};

static clib_error_t *
dump_api_table_file_command_fn (vlib_main_t * vm,
				unformat_input_t * input,
				vlib_cli_command_t * cmd)
{
  u8 *filename = 0;
  api_main_t *am = vlibapi_get_main ();
  serialize_main_t _sm, *sm = &_sm;
  clib_error_t *error;
  u32 nmsgs;
  u32 msg_index;
  u8 *name_and_crc;
  int compare_current = 0;
  int numeric_sort = 0;
  msg_table_unserialize_t *table = 0, *item;
  u32 i;
  u32 ndifferences = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "file %s", &filename))
	;
      else if (unformat (input, "compare-current")
	       || unformat (input, "compare"))
	compare_current = 1;
      else if (unformat (input, "numeric"))
	numeric_sort = 1;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }

  if (numeric_sort && compare_current)
    return clib_error_return
      (0, "Comparison and numeric sorting are incompatible");

  if (filename == 0)
    return clib_error_return (0, "File not specified");

  /* Load the serialized message table from the table dump */

  error = unserialize_open_clib_file (sm, (char *) filename);

  if (error)
    return error;

  unserialize_integer (sm, &nmsgs, sizeof (u32));

  for (i = 0; i < nmsgs; i++)
    {
      msg_index = unserialize_likely_small_unsigned_integer (sm);
      unserialize_cstring (sm, (char **) &name_and_crc);
      vec_add2 (table, item, 1);
      item->msg_index = msg_index;
      item->name_and_crc = name_and_crc;
      item->name = extract_name (name_and_crc);
      item->crc = extract_crc (name_and_crc);
      item->which = 0;		/* file */
    }
  unserialize_close (sm);

  /* Compare with the current image? */
  if (compare_current)
    {
      /* Append the current message table */
      u8 *tblv = vl_api_serialize_message_table (am, 0);

      serialize_open_vector (sm, tblv);
      unserialize_integer (sm, &nmsgs, sizeof (u32));

      for (i = 0; i < nmsgs; i++)
	{
	  msg_index = unserialize_likely_small_unsigned_integer (sm);
	  unserialize_cstring (sm, (char **) &name_and_crc);

	  vec_add2 (table, item, 1);
	  item->msg_index = msg_index;
	  item->name_and_crc = name_and_crc;
	  item->name = extract_name (name_and_crc);
	  item->crc = extract_crc (name_and_crc);
	  item->which = 1;	/* current_image */
	}
      vec_free (tblv);
    }

  /* Sort the table. */
  if (numeric_sort)
    vec_sort_with_function (table, table_id_cmp);
  else
    vec_sort_with_function (table, table_name_and_crc_cmp);

  if (compare_current)
    {
      u8 *dashes = 0;
      ndifferences = 0;

      /*
       * In this case, the recovered table will have two entries per
       * API message. So, if entries i and i+1 match, the message definitions
       * are identical. Otherwise, the crc is different, or a message is
       * present in only one of the tables.
       */
      vlib_cli_output (vm, "%-60s | %s", "Message Name", "Result");
      vec_validate_init_empty (dashes, 60, '-');
      vec_terminate_c_string (dashes);
      vlib_cli_output (vm, "%60s-|-%s", dashes, "-----------------");
      vec_free (dashes);
      for (i = 0; i < vec_len (table);)
	{
	  /* Last message lonely? */
	  if (i == vec_len (table) - 1)
	    {
	      ndifferences++;
	      goto last_unique;
	    }

	  /* Identical pair? */
	  if (!strncmp
	      ((char *) table[i].name_and_crc,
	       (char *) table[i + 1].name_and_crc,
	       vec_len (table[i].name_and_crc)))
	    {
	      i += 2;
	      continue;
	    }

	  ndifferences++;

	  /* Only in one of two tables? */
	  if (i + 1 == vec_len (table)
	      || strcmp ((char *) table[i].name, (char *) table[i + 1].name))
	    {
	    last_unique:
	      vlib_cli_output (vm, "%-60s | only in %s",
			       table[i].name, table[i].which ?
			       "image" : "file");
	      i++;
	      continue;
	    }
	  /* In both tables, but with different signatures */
	  {
	    int k;
	    int count = sizeof (crc_fixup_dict) / sizeof (crc_fixup_dict[0]);
	    for (k = 0; k < count; k++)
	      {
		if (!strcmp (crc_fixup_dict[k].name, (char *) table[i].name))
		  {
		    break;
		  }
	      }
	    if (k < count)
	      {
		u8 *name_and_new_crc = format (0, "%s_%08x%c", table[i].name,
					       crc_fixup_dict[k].new_crc, 0);
		u8 *name_and_old_crc = format (0, "%s_%08x%c", table[i].name,
					       crc_fixup_dict[k].old_crc, 0);

		if ((!strcmp ((char *) name_and_new_crc,
			      (char *) table[i].name_and_crc) &&
		     !strcmp ((char *) name_and_old_crc,
			      (char *) table[i + 1].name_and_crc)) ||
		    (!strcmp ((char *) name_and_new_crc,
			      (char *) table[i + 1].name_and_crc) &&
		     !strcmp ((char *) name_and_old_crc,
			      (char *) table[i].name_and_crc)))
		  {
		    vlib_cli_output (vm, "%-60s | message CRC32 fix",
				     table[i].name);
		  }
		else
		  {
		    vlib_cli_output (vm, "%-60s | definition changed",
				     table[i].name);
		  }

		vec_free (name_and_new_crc);
		vec_free (name_and_old_crc);
	      }
	    else
	      {
		vlib_cli_output (vm, "%-60s | definition changed",
				 table[i].name);
	      }
	  }

	  i += 2;
	}
      if (ndifferences == 0)
	vlib_cli_output (vm, "No api message signature differences found.");
      else
	vlib_cli_output (vm, "\nFound %u api message signature differences",
			 ndifferences);
      goto cleanup;
    }

  /* Dump the table, sorted as shown above */
  vlib_cli_output (vm, "%=60s %=8s %=10s", "Message name", "MsgID", "CRC");

  for (i = 0; i < vec_len (table); i++)
    {
      item = table + i;
      vlib_cli_output (vm, "%-60s %8u %10s", item->name,
		       item->msg_index, item->crc);
    }

cleanup:
  for (i = 0; i < vec_len (table); i++)
    {
      vec_free (table[i].name_and_crc);
      vec_free (table[i].name);
      vec_free (table[i].crc);
    }

  vec_free (table);

  return 0;
}

/*?
 * Displays a serialized API message decode table, sorted by message name
 *
 * @cliexpar
 * @cliexstart{show api dump file <filename>}
 *                                                Message name    MsgID        CRC
 * accept_session                                                    407   8e2a127e
 * accept_session_reply                                              408   67d8c22a
 * add_node_next                                                     549   e4202993
 * add_node_next_reply                                               550   e89d6eed
 * etc.
 * @cliexend
?*/

/*?
 * Compares a serialized API message decode table with the current image
 *
 * @cliexpar
 * @cliexstart{show api dump file <filename> compare}
 * ip_add_del_route                                             definition changed
 * ip_table_add_del                                             definition changed
 * l2_macs_event                                                only in image
 * vnet_ip4_fib_counters                                        only in file
 * vnet_ip4_nbr_counters                                        only in file
 * @cliexend
?*/

/*?
 * Display a serialized API message decode table, compare a saved
 * decode table with the current image, to establish API differences.
 *
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (dump_api_table_file, static) =
{
  .path = "show api dump",
  .short_help = "show api dump file <filename> [numeric | compare-current]",
  .function = dump_api_table_file_command_fn,
};

/* *INDENT-ON* */
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
