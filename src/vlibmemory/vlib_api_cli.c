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
  api_main_t *am = &api_main;
  u32 *confused_indices = 0;

  if (!pool_elts (am->vl_clients))
    goto socket_clients;
  vlib_cli_output (vm, "Shared memory clients");
  vlib_cli_output (vm, "%20s %8s %14s %18s %s",
		   "Name", "PID", "Queue Length", "Queue VA", "Health");

  /* *INDENT-OFF* */
  pool_foreach (regpp, am->vl_clients,
  ({
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
  }));
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
  api_main_t *am = &api_main;

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
  api_main_t *am = &api_main;
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
  api_main_t *am = &api_main;
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

  if (which == REPLAY)
    am->replay_in_progress = 1;

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
	  am->replay_in_progress = 0;
	  return;
	}

      /* Copy the buffer (from the read-only mmap'ed file) */
      vec_validate (tmpbuf, size - 1 + sizeof (uword));
      clib_memcpy (tmpbuf + sizeof (uword), msg, size);
      clib_memset (tmpbuf, 0xf, sizeof (uword));

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
	      am->replay_in_progress = 0;
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
	    vlib_cli_output (vm, "Unknown error while saving: %d", rv);
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
	vl_msg_api_post_mortem_dump_enable_disable (1 /* enable */ );
      else if (unformat (input, "post-mortem-off"))
	vl_msg_api_post_mortem_dump_enable_disable (0 /* enable */ );
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }
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
};
/* *INDENT-ON* */

static clib_error_t *
vl_api_trace_command (vlib_main_t * vm,
		      unformat_input_t * input, vlib_cli_command_t * cli_cmd)
{
  u32 nitems = 1024;
  vl_api_trace_which_t which = VL_API_TRACE_RX;
  api_main_t *am = &api_main;

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
  .path = "set api-trace [on][on tx][on rx][off][free][debug on][debug off]",
  .short_help = "API trace",
  .function = vl_api_trace_command,
};
/* *INDENT-ON* */

static clib_error_t *
api_trace_config_fn (vlib_main_t * vm, unformat_input_t * input)
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
  api_main_t *am = &api_main;
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

static clib_error_t *
dump_api_table_file_command_fn (vlib_main_t * vm,
				unformat_input_t * input,
				vlib_cli_command_t * cmd)
{
  u8 *filename = 0;
  api_main_t *am = &api_main;
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
  serialize_close (sm);

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
      ndifferences = 0;

      /*
       * In this case, the recovered table will have two entries per
       * API message. So, if entries i and i+1 match, the message definitions
       * are identical. Otherwise, the crc is different, or a message is
       * present in only one of the tables.
       */
      vlib_cli_output (vm, "%=60s %s", "Message Name", "Result");

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
	  if (strncmp ((char *) table[i].name, (char *) table[i + 1].name,
		       vec_len (table[i].name)))
	    {
	    last_unique:
	      vlib_cli_output (vm, "%-60s only in %s",
			       table[i].name, table[i].which ?
			       "image" : "file");
	      i++;
	      continue;
	    }
	  /* In both tables, but with different signatures */
	  vlib_cli_output (vm, "%-60s definition changed", table[i].name);
	  i += 2;
	}
      if (ndifferences == 0)
	vlib_cli_output (vm, "No api message signature differences found.");
      else
	vlib_cli_output (vm, "Found %u api message signature differences",
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
