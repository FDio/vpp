/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2018 Cisco and/or its affiliates.
 */

#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vlibapi/api_desc.h>
#include <vppinfra/format_table.h>

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
VLIB_CLI_COMMAND (cli_show_api_histogram_command, static) =
{
  .path = "show api histogram",
  .short_help = "show api histogram",
  .function = vl_api_show_histogram_command,
};

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
VLIB_CLI_COMMAND (cli_clear_api_histogram_command, static) =
{
  .path = "clear api histogram",
  .short_help = "clear api histogram",
  .function = vl_api_clear_histogram_command,
};

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

VLIB_CLI_COMMAND (cli_show_api_command, static) =
{
  .path = "show api",
  .short_help = "Show API information",
};

/*?
 * Display current api client connections
?*/
VLIB_CLI_COMMAND (cli_show_api_clients_command, static) =
{
  .path = "show api clients",
  .short_help = "Client information",
  .function = vl_api_client_command,
};

/*?
 * Display the current api message tracing status
?*/
VLIB_CLI_COMMAND (cli_show_api_status_command, static) =
{
  .path = "show api trace-status",
  .short_help = "Display API trace status",
  .function = vl_api_status_command,
};

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

  for (i = 1; i < vec_len (am->msg_data); i++)
    {
      vl_api_msg_data_t *m = vl_api_get_msg_data (am, i);
      if (verbose == 0)
	{
	  vlib_cli_output (vm, "%-4d %s", i,
			   m->name ? m->name : "  [no handler]");
	}
      else
	{
	  vlib_cli_output (vm, "%-4d %-40s %6d %7d", i,
			   m->name ? m->name : "  [no handler]", m->bounce,
			   m->is_mp_safe);
	}
    }

  return 0;
}

/*?
 * Display the current api message decode tables
?*/
VLIB_CLI_COMMAND (cli_show_api_message_table_command, static) =
{
  .path = "show api message-table",
  .short_help = "Message Table",
  .function = vl_api_message_table_command,
};

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
VLIB_CLI_COMMAND (cli_show_api_plugin_command, static) =
{
  .path = "show api plugin",
  .short_help = "show api plugin",
  .function = vl_api_show_plugin_command,
};

typedef enum
{
  DUMP,
  DUMP_JSON,
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

static void
vl_msg_api_process_file (vlib_main_t * vm, u8 * filename,
			 u32 first_index, u32 last_index,
			 vl_api_replay_t which)
{
  vl_api_trace_file_header_t *hp;
  int i, fd;
  u16 *msgid_vec = 0;
  struct stat statb;
  size_t file_size;
  u8 *msg;
  api_main_t *am = vlibapi_get_main ();
  u8 *tmpbuf = 0;
  u32 nitems, nitems_msgtbl;

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

  clib_mem_unpoison (hp, file_size);

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

  size_t file_size_left = file_size;

#define assert_size(size_left, s)                                             \
  do                                                                          \
    {                                                                         \
      if ((s) >= size_left)                                                   \
	{                                                                     \
	  vlib_cli_output (vm, "corrupted file");                             \
	  munmap (hp, file_size);                                             \
	  vec_free (msgid_vec);                                               \
	  return;                                                             \
	}                                                                     \
      size_left -= s;                                                         \
    }                                                                         \
  while (0);

  assert_size (file_size_left, sizeof (hp[0]));
  msg = (u8 *) (hp + 1);

  serialize_main_t _sm, *sm = &_sm;
  u32 msgtbl_size = ntohl (hp->msgtbl_size);
  u8 *name_and_crc;

  assert_size (file_size_left, msgtbl_size);

  unserialize_open_data (sm, msg, msgtbl_size);
  unserialize_integer (sm, &nitems_msgtbl, sizeof (u32));

  for (i = 0; i < nitems_msgtbl; i++)
    {
      u16 msg_index = unserialize_likely_small_unsigned_integer (sm);
      unserialize_cstring (sm, (char **) &name_and_crc);
      u32 msg_index2 = vl_msg_api_get_msg_index (name_and_crc);
      ASSERT (~0 == msg_index2 || msg_index2 <= 65535);
      if (~0 == msg_index2)
	vlib_cli_output (vm, "warning: can't find msg index for id %d\n",
			 msg_index);
      vec_validate (msgid_vec, msg_index);
      msgid_vec[msg_index] = msg_index2;
    }

  msg += msgtbl_size;

  for (i = 0; i < first_index; i++)
    {
      int size;
      u16 msg_id;

      assert_size (file_size_left, sizeof (u32));
      size = clib_host_to_net_u32 (*(u32 *) msg);
      msg += sizeof (u32);

      assert_size (file_size_left, clib_max (size, sizeof (u16)));
      msg_id = ntohs (*((u16 *) msg));
      if (msg_id >= vec_len (msgid_vec) ||
	  msgid_vec[msg_id] >= vec_len (am->msg_data))
	vlib_cli_output (vm, "warning: unknown msg id %d for msg number %d\n",
			 msg_id, i);

      msg += size;
    }

  if (which == REPLAY)
    am->replay_in_progress = 1;

  for (; i <= last_index; i++)
    {
      vl_api_msg_data_t *m;
      u16 msg_id;
      int size;

      if (which == DUMP)
	vlib_cli_output (vm, "---------- trace %d -----------\n", i);

      assert_size (file_size_left, sizeof (u32));
      size = clib_host_to_net_u32 (*(u32 *) msg);
      msg += sizeof (u32);

      assert_size (file_size_left, clib_max (size, sizeof (u16)));
      msg_id = ntohs (*((u16 *) msg));

      if (msg_id >= vec_len (msgid_vec) ||
	  msgid_vec[msg_id] >= vec_len (am->msg_data))
	{
	  vlib_cli_output (
	    vm, "warning: unknown msg id %d for msg number %d, skipping\n",
	    msg_id, i);
	  msg += size;
	  continue;
	}

      msg_id = msgid_vec[msg_id];
      m = vl_api_get_msg_data (am, msg_id);

      /* Copy the buffer (from the read-only mmap'ed file) */
      vec_validate (tmpbuf, size - 1 + sizeof (uword));
      clib_memcpy (tmpbuf + sizeof (uword), msg, size);
      clib_memset (tmpbuf, 0xf, sizeof (uword));

      /*
       * Endian swap if needed. All msg data is supposed to be in
       * network byte order.
       */
      if (((which == DUMP || which == DUMP_JSON) &&
	   clib_arch_is_little_endian))
	{
	  if (m && m->endian_handler == 0)
	    {
	      vlib_cli_output (vm, "Ugh: msg id %d no endian swap\n", msg_id);
	      munmap (hp, file_size);
	      vec_free (tmpbuf);
	      am->replay_in_progress = 0;
	      return;
	    }
	  if (m)
	    {
	      m->endian_handler (tmpbuf + sizeof (uword), 1 /* to network */);
	    }
	}

      /* msg_id always in network byte order */
      if (clib_arch_is_little_endian)
	{
	  u16 *msg_idp = (u16 *) (tmpbuf + sizeof (uword));
	  *msg_idp = msg_id;
	}

      switch (which)
	{
	case DUMP_JSON:
	  vlib_cli_output (vm, "%U", format_vl_api_msg_json, am, msg_id,
			   tmpbuf + sizeof (uword));
	  break;

	case DUMP:
	  vlib_cli_output (vm, "%U", format_vl_api_msg_text, am, msg_id,
			   tmpbuf + sizeof (uword));
	  break;

	case INITIALIZERS:
	  if (m)
	    {
	      u8 *s;
	      int j;

	      vlib_cli_output (vm, "/*%U*/", format_vl_api_msg_text, am,
			       msg_id, tmpbuf + sizeof (uword));

	      vlib_cli_output (vm, "*/\n");

	      s = format (0, "static u8 * vl_api_%s_%d[%d] = {", m->name, i,
			  m->trace_size);

	      for (j = 0; j < m->trace_size; j++)
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
	  if (m && m->handler && m->replay_allowed)
	    {
	      if (!m->is_mp_safe)
		vl_msg_api_barrier_sync ();
	      m->handler (tmpbuf + sizeof (uword));
	      if (!m->is_mp_safe)
		vl_msg_api_barrier_release ();
	    }
	  else
	    {
	      if (m && m->replay_allowed)
		vlib_cli_output (vm, "Skipping msg id %d: no handler\n",
				 msg_id);
	      break;
	    }
	  break;
	}

      vec_set_len (tmpbuf, 0);
      msg += size;
    }

  munmap (hp, file_size);
  vec_free (tmpbuf);
  vec_free (msgid_vec);
  am->replay_in_progress = 0;
}

static int
file_exists (u8 *fname)
{
  FILE *fp = 0;
  fp = fopen ((char *) fname, "r");
  if (fp)
    {
      fclose (fp);
      return 1;
    }
  return 0;
}

typedef struct
{
  vlib_main_t *vm;
  u8 is_json;
} vl_msg_print_args;

static int
vl_msg_print_trace (u8 *msg, void *ctx)
{
  vl_msg_print_args *a = ctx;
  api_main_t *am = vlibapi_get_main ();
  u16 msg_id = ntohs (*((u16 *) msg));
  vl_api_msg_data_t *m = vl_api_get_msg_data (am, msg_id);
  u8 is_json = a->is_json;
  u8 *tmpbuf = 0;

  if (!m)
    {
      vlib_cli_output (a->vm, "Unknown msg id %d\n", msg_id);
      return 0;
    }

  if (clib_arch_is_little_endian && (m->endian_handler != NULL))
    {
      u32 msg_length = vec_len (msg);
      vec_validate (tmpbuf, msg_length - 1);
      clib_memcpy_fast (tmpbuf, msg, msg_length);
      msg = tmpbuf;

      m->endian_handler (tmpbuf, 0 /* from network */);
    }

  vlib_cli_output (a->vm, "%U\n",
		   is_json ? format_vl_api_msg_json : format_vl_api_msg_text,
		   am, msg_id, msg);

  vec_free (tmpbuf);
  return 0;
}

static int
vl_msg_api_dump_trace (vlib_main_t *vm, vl_api_trace_which_t which, u8 is_json)
{
  api_main_t *am = vlibapi_get_main ();
  vl_api_trace_t *tp;

  switch (which)
    {
    case VL_API_TRACE_TX:
      tp = am->tx_trace;
      break;
    case VL_API_TRACE_RX:
      tp = am->rx_trace;
      break;
    default:
      return -1;
    }

  if (tp == 0 || tp->nitems == 0 || vec_len (tp->traces) == 0)
    return -1;

  vl_msg_print_args args;
  clib_memset (&args, 0, sizeof (args));
  args.is_json = is_json;
  args.vm = vm;
  vl_msg_traverse_trace (tp, vl_msg_print_trace, &args);

  return 0;
}

static char *
vl_msg_read_file (FILE *f)
{
  const size_t bufsize = 1024;
  char *buf[bufsize], *v = 0;
  size_t n;

  while ((n = fread (buf, 1, bufsize, f)))
    vec_add (v, buf, n);

  /* most callers expect a NULL-terminated C-string */
  if (v)
    vec_add1 (v, 0);

  return v;
}

static u16
vl_msg_find_id_by_name_and_crc (vlib_main_t *vm, api_main_t *am, char *name)
{
  uword *p;
  p = hash_get_mem (am->msg_index_by_name_and_crc, name);
  if (!p)
    return (u16) ~0;

  return p[0];
}

static u16
vl_msg_find_id_by_name (vlib_main_t *vm, api_main_t *am, char *name)
{
  uword *p;

  if (!am->msg_id_by_name)
    {
      vlib_cli_output (vm, "message id table not yet initialized!\n");
      return (u16) ~0;
    }

  p = hash_get_mem (am->msg_id_by_name, name);
  if (!p)
    return (u16) ~0;

  return p[0];
}

static int
vl_msg_exec_json_command (vlib_main_t *vm, clib_json_text_t *j, int o)
{
  api_main_t *am = vlibapi_get_main ();
  u16 msg_id;
  int rv = -1, name_idx, crc_idx;
  vl_api_msg_data_t *m;
  const vl_api_desc_type_t *d;
  u8 *msg = 0, *name, *crc, *name_crc;
  u8 proc_warning = 0;

  name_idx = clib_json_find_object_value_by_name (j, o, "_msgname");
  if (name_idx < 0 || !clib_json_value_is_string (j, name_idx))
    {
      vlib_cli_output (vm, "Missing '_msgname' element!\n");
      return rv;
    }
  name = pool_elt_at_index (j->values, name_idx)->string;

  crc_idx = clib_json_find_object_value_by_name (j, o, "_crc");
  if (crc_idx < 0 || !clib_json_value_is_string (j, crc_idx))
    {
      vlib_cli_output (vm, "Missing '_crc' element!\n");
      return rv;
    }
  crc = pool_elt_at_index (j->values, crc_idx)->string;

  name_crc = format (0, "%v_%v%c", name, crc, 0);
  msg_id = vl_msg_find_id_by_name_and_crc (vm, am, (char *) name_crc);
  vec_free (name_crc);

  if (msg_id == (u16) ~0)
    {
      u8 *n = format (0, "%v%c", name, 0);

      msg_id = vl_msg_find_id_by_name (vm, am, (char *) n);
      vec_free (n);
      if (msg_id == (u16) ~0)
	{
	  vlib_cli_output (vm, "unknown msg id %d!\n", msg_id);
	  return rv;
	}

      proc_warning = 1;
    }

  m = vl_api_get_msg_data (am, msg_id);

  if (m->replay_allowed)
    {
      if (proc_warning)
	vlib_cli_output (vm, "warning: msg %d has different signature\n");

      d = vl_api_desc_find_msg (am, msg_id);
      if (!d)
	{
	  vlib_cli_output (vm, "missing fromjson convert function! id %d\n", msg_id);
	  return rv;
	}

      msg = vl_api_desc_msg_from_json (d, j, o);
      if (!msg)
	{
	  vlib_cli_output (vm, "failed to convert JSON (msg id %d)!\n", msg_id);
	  return rv;
	}

      if (clib_arch_is_little_endian && m->endian_handler)
	m->endian_handler (msg, 1 /* to network */);

      if (!m->handler)
	{
	  vlib_cli_output (vm, "no handler for msg id %d!\n", msg_id);
	  goto end;
	}

      if (!m->is_mp_safe)
	vl_msg_api_barrier_sync ();

      m->handler (msg);

      if (!m->is_mp_safe)
	vl_msg_api_barrier_release ();
    }

  rv = 0;
end:
  vec_free (msg);
  return rv;
}

static void
vl_msg_replay_json (vlib_main_t *vm, u8 *filename)
{
  api_main_t *am = vlibapi_get_main ();
  clib_json_text_t j;
  clib_error_t *err;
  int rv = 0;
  FILE *f = fopen ((char *) filename, "r");
  char *buf;

  if (!f)
    {
      vlib_cli_output (vm, "failed to open %s!\n", filename);
      return;
    }

  buf = vl_msg_read_file (f);
  fclose (f);

  /* the buffer is nul terminated */
  err = clib_json_init_from_string (&j, buf, vec_len (buf) ? vec_len (buf) - 1 : 0);
  vec_free (buf);
  if (err)
    {
      vlib_cli_output (vm, "%s: Failed parsing JSON input: %U\n", filename, format_clib_error, err);
      clib_error_free (err);
      return;
    }

  if (clib_json_value_is_array (&j, j.root_value))
    {
      int *e;

      am->replay_in_progress = 1;
      vec_foreach (e, pool_elt_at_index (j.values, j.root_value)->array_val_indices)
	{
	  rv = vl_msg_exec_json_command (vm, &j, *e);
	  if (rv < 0)
	    {
	      am->replay_in_progress = 0;
	      break;
	    }
	}
    }
  else
    rv = vl_msg_exec_json_command (vm, &j, j.root_value);

  if (rv < 0)
    vlib_cli_output (vm, "error during replaying API trace");

  clib_json_free (&j);
}

static void
vl_msg_dump_file_json (vlib_main_t *vm, u8 *filename)
{
  FILE *f = fopen ((char *) filename, "r");
  char *buf;

  if (!f)
    {
      vlib_cli_output (vm, "failed to open %s!\n", filename);
      return;
    }

  buf = vl_msg_read_file (f);
  fclose (f);

  if (!buf)
    {
      vlib_cli_output (vm, "no content in %s!\n", filename);
      return;
    }

  vlib_cli_output (vm, buf);
  vec_free (buf);
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
      else if (unformat (line_input, "save-json %s", &filename))
	{
	  if (strstr ((char *) filename, "..") ||
	      index ((char *) filename, '/'))
	    {
	      vlib_cli_output (vm, "illegal characters in filename '%s'",
			       filename);
	      goto out;
	    }

	  chroot_filename = format (0, "/tmp/%s%c", filename, 0);

	  vec_free (filename);

	  if (file_exists (chroot_filename))
	    {
	      vlib_cli_output (vm, "file exists: %s\n", chroot_filename);
	      goto out;
	    }

	  fp = fopen ((char *) chroot_filename, "w");
	  if (fp == NULL)
	    {
	      vlib_cli_output (vm, "Couldn't create %s\n", chroot_filename);
	      goto out;
	    }
	  vlib_worker_thread_barrier_sync (vm);
	  rv = vl_msg_api_trace_save (am, which, fp, 1);
	  if (rv == -1)
	    vlib_cli_output (vm, "API Trace data not present\n");
	  else if (rv < 0)
	    vlib_cli_output (vm, "failed to save api trace\n");
	  else
	    vlib_cli_output (vm, "API trace saved to %s\n", chroot_filename);
	  vlib_worker_thread_barrier_release (vm);
	  fclose (fp);
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

	  if (file_exists (chroot_filename))
	    {
	      vlib_cli_output (vm, "file exists: %s\n", chroot_filename);
	      goto out;
	    }

	  fp = fopen ((char *) chroot_filename, "w");
	  if (fp == NULL)
	    {
	      vlib_cli_output (vm, "Couldn't create %s\n", chroot_filename);
	      goto out;
	    }
	  vlib_worker_thread_barrier_sync (vm);
	  rv = vl_msg_api_trace_save (am, which, fp, 0);
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
      else if (unformat (line_input, "tojson %s", &filename))
	{
	  vl_msg_api_process_file (vm, filename, first, last, DUMP_JSON);
	}
      else if (unformat (line_input, "dump-file-json %s", &filename))
	{
	  vl_msg_dump_file_json (vm, filename);
	}
      else if (unformat (line_input, "dump-file %s", &filename))
	{
	  vl_msg_api_process_file (vm, filename, first, last, DUMP);
	}
      else if (unformat (line_input, "dump-json"))
	{
	  vl_msg_api_dump_trace (vm, which, 1);
	}
      else if (unformat (line_input, "dump"))
	{
	  vl_msg_api_dump_trace (vm, which, 0);
	}
      else if (unformat (line_input, "replay-json %s", &filename))
	{
	  vl_msg_replay_json (vm, filename);
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

VLIB_CLI_COMMAND (api_trace_command, static) = {
  .path = "api trace",
  .short_help = "api trace [tx][on|off][first <n>][last <n>][status][free]"
		"[post-mortem-on][dump|dump-file|dump-json|save|tojson|save-"
		"json|replay <file>|replay-json <file>][nitems <n>]"
		"[initializers <file>]",
  .function = api_trace_command_fn,
  .is_mp_safe = 1,
};

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
    vec_dec_len (rv, 1);

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
	  vlib_cli_output (vm, "%-60s | definition changed", table[i].name);
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
VLIB_CLI_COMMAND (dump_api_table_file, static) = {
  .path = "show api dump",
  .short_help = "show api dump file <filename> [numeric | compare-current]",
  .function = dump_api_table_file_command_fn,
};

/* ---- show api descriptor */

static const char *desc_field_kinds[] = {
  [VL_API_DK_U8] = "u8",       [VL_API_DK_I8] = "i8",	       [VL_API_DK_U16] = "u16",
  [VL_API_DK_I16] = "i16",     [VL_API_DK_U32] = "u32",	       [VL_API_DK_I32] = "i32",
  [VL_API_DK_U64] = "u64",     [VL_API_DK_I64] = "i64",	       [VL_API_DK_F64] = "f64",
  [VL_API_DK_BOOL] = "bool",   [VL_API_DK_STRING] = "string",  [VL_API_DK_FSTRING] = "fixed string",
  [VL_API_DK_ENUM] = "enum",   [VL_API_DK_ENUMFLAG] = "flags", [VL_API_DK_STRUCT] = "struct",
  [VL_API_DK_UNION] = "union", [VL_API_DK_NAMED] = "alias",
};

static const char *desc_type_kinds[] = {
  [VL_API_DT_MESSAGE] = "message", [VL_API_DT_TYPEDEF] = "type",   [VL_API_DT_UNION] = "union",
  [VL_API_DT_ENUM] = "enum",	   [VL_API_DT_ENUMFLAG] = "flags", [VL_API_DT_ALIAS] = "alias",
};

/* The messages, or the types, of all the files, once for each name. The lists
 * are made again when there are more files. */
static const vl_api_desc_type_t *
desc_nth_name (api_main_t *am, int messages, u32 n)
{
  static const vl_api_desc_type_t **names[2];
  static u32 n_files;

  if (n_files != vec_len (am->desc_files))
    {
      uword *seen[2] = { hash_create_string (0, sizeof (uword)),
			 hash_create_string (0, sizeof (uword)) };

      vec_reset_length (names[0]);
      vec_reset_length (names[1]);

      for (u32 i = 0; i < vec_len (am->desc_files); i++)
	{
	  const vl_api_desc_file_t *f = am->desc_files[i];

	  for (u32 k = 0; k < f->n_msgs + f->n_types; k++)
	    {
	      const vl_api_desc_type_t *t = k < f->n_msgs ? f->msgs[k] : f->types[k - f->n_msgs];
	      int w = k < f->n_msgs;

	      if (hash_get_mem (seen[w], t->name))
		continue;

	      hash_set_mem (seen[w], t->name, 1);
	      vec_add1 (names[w], t);
	    }
	}

      hash_free (seen[0]);
      hash_free (seen[1]);
      n_files = vec_len (am->desc_files);
    }

  return n < vec_len (names[!!messages]) ? names[!!messages][n] : 0;
}

static const char *
desc_next_message (const cli_arg_t *a __clib_unused, u32 *iter, u32 *value, const char **help)
{
  const vl_api_desc_type_t *t = desc_nth_name (vlibapi_get_main (), 1, *iter);

  if (!t)
    return 0;

  *value = (*iter)++;
  if (help)
    *help = "message";
  return t->name;
}

static const char *
desc_next_type (const cli_arg_t *a __clib_unused, u32 *iter, u32 *value, const char **help)
{
  const vl_api_desc_type_t *t = desc_nth_name (vlibapi_get_main (), 0, *iter);

  if (!t)
    return 0;

  *value = (*iter)++;
  if (help)
    *help = desc_type_kinds[t->kind];
  return t->name;
}

CLIB_CLI_TYPE (cli_type_api_message) = {
  .name = "message",
  .help = "the name of an API message",
  .next_name = desc_next_message,
  .parse = cli_names_parse,
  .complete = cli_names_complete,
};

CLIB_CLI_TYPE (cli_type_api_type) = {
  .name = "type",
  .help = "the name of an API type, enum, flags or alias",
  .next_name = desc_next_type,
  .parse = cli_names_parse,
  .complete = cli_names_complete,
};

static const char *
desc_next_module (const cli_arg_t *a __clib_unused, u32 *iter, u32 *value, const char **help)
{
  api_main_t *am = vlibapi_get_main ();

  if (*iter >= vec_len (am->desc_files))
    return 0;

  *value = *iter;
  if (help)
    *help = "API file";
  return am->desc_files[(*iter)++]->module;
}

CLIB_CLI_TYPE (cli_type_api_module) = {
  .name = "module",
  .help = "the name of an API file",
  .next_name = desc_next_module,
  .parse = cli_names_parse,
  .complete = cli_names_complete,
};

static u8 *
format_desc_flags (u8 *s, va_list *args)
{
  u32 flags = va_arg (*args, u32);
  u32 n = 0;

  if (flags & VL_API_DTF_MANUAL_PRINT)
    s = format (s, "%smanual_print", n++ ? "," : "");

  if (flags & VL_API_DTF_MANUAL_ENDIAN)
    s = format (s, "%smanual_endian", n++ ? "," : "");

  if (flags & VL_API_DTF_VLA)
    s = format (s, "%svla", n++ ? "," : "");

  if (flags & VL_API_DTF_DONT_TRACE)
    s = format (s, "%sdont_trace", n++ ? "," : "");

  if (flags & VL_API_DTF_AUTOENDIAN)
    s = format (s, "%sautoendian", n++ ? "," : "");

  return s;
}

static u8 *
format_desc_field_flags (u8 *s, va_list *args)
{
  const vl_api_desc_type_t *t = va_arg (*args, const vl_api_desc_type_t *);
  const vl_api_desc_field_t *f = va_arg (*args, const vl_api_desc_field_t *);

  if (f->flags & VL_API_DF_VLA)
    return format (s, "vla[%s]", vl_api_desc_len_field_name (t, f));

  if (f->flags & VL_API_DF_MODERN_VLA)
    return format (s, "vla");

  if (f->flags & VL_API_DF_ARRAY)
    return format (s, "[%u]", f->length);

  if (f->flags & VL_API_DF_LENGTH)
    return format (s, "length");

  return s;
}

/* the id the message is registered with, ~0 if it is not */
static u32
desc_msg_id (api_main_t *am, const vl_api_desc_type_t *t)
{
  for (u32 i = 0; i < vec_len (am->desc_by_msg_id); i++)
    if (am->desc_by_msg_id[i] == t)
      return i;

  return ~0;
}

static clib_error_t *
show_api_descriptor_files (vlib_main_t *vm, cli_ctx_t *ctx, api_main_t *am)
{
  static const cli_column_t cols[] = {
    { "module", "Module" }, { "crc", "CRC" }, { "messages", "Messages" }, { "types", "Types" }, {},
  };
  clib_json_text_t j;

  if (!cli_is_structured (ctx))
    {
      table_t table = {};

      table_add_hdr_col (&table, 0);
      table_add_hdr_row (&table, 4, "Module", "CRC", "Messages", "Types");
      table_set_cell_align (&table, -1, -1, TTAA_LEFT);
      table_set_cell_align (&table, -1, 0, TTAA_LEFT);
      table_set_cell_align (&table, -1, 1, TTAA_RIGHT);
      table_set_cell_align (&table, -1, 2, TTAA_RIGHT);

      for (u32 i = 0; i < vec_len (am->desc_files); i++)
	{
	  const vl_api_desc_file_t *f = am->desc_files[i];

	  table_format_cell (&table, i, -1, "%s", f->module);
	  table_format_cell (&table, i, 0, "0x%x", f->file_crc);
	  table_format_cell (&table, i, 1, "%u", f->n_msgs);
	  table_format_cell (&table, i, 2, "%u", f->n_types);
	  table_set_cell_align (&table, i, 0, TTAA_LEFT);
	}

      vlib_cli_output (vm, "%U", format_table, &table);
      table_free (&table);
      return 0;
    }

  clib_json_init (&j);
  clib_json_add_array (&j, 0);

  for (u32 i = 0; i < vec_len (am->desc_files); i++)
    {
      const vl_api_desc_file_t *f = am->desc_files[i];

      clib_json_add_object (&j, 0);
      clib_json_add_string (&j, "module", "%s", f->module);
      clib_json_add_string (&j, "crc", "0x%x", f->file_crc);
      clib_json_add_number (&j, "messages", f->n_msgs);
      clib_json_add_number (&j, "types", f->n_types);
      clib_json_parent (&j);
    }

  return cli_emit_table (ctx, &j, cols);
}

static clib_error_t *
show_api_descriptor_type (vlib_main_t *vm, cli_ctx_t *ctx, api_main_t *am,
			  const vl_api_desc_type_t *t)
{
  u32 id = t->kind == VL_API_DT_MESSAGE ? desc_msg_id (am, t) : ~0;
  u8 *flags = format (0, "%U", format_desc_flags, t->flags);
  clib_error_t *err = 0;

  if (cli_is_json (ctx))
    {
      static const cli_column_t cols[] = {
	{ "name", "Name" },
	{ "kind", "Kind" },
	{ "id", "ID" },
	{ "crc", "CRC" },
	{ "size", "Size" },
	{ "flags", "Flags" },
	{},
      };
      clib_json_text_t j;

      clib_json_init (&j);
      clib_json_add_object (&j, 0);
      clib_json_add_string (&j, "name", "%s", t->name);
      clib_json_add_string (&j, "kind", "%s", desc_type_kinds[t->kind]);

      if (id != ~0)
	clib_json_add_number (&j, "id", id);

      if (t->kind == VL_API_DT_MESSAGE)
	clib_json_add_string (&j, "crc", "%08x", t->crc);

      clib_json_add_number (&j, "size", t->size);
      clib_json_add_string (&j, "flags", "%v", flags);

      if (t->kind == VL_API_DT_ENUM || t->kind == VL_API_DT_ENUMFLAG)
	{
	  clib_json_add_array (&j, "values");

	  for (u32 i = 0; i < t->n_fields; i++)
	    {
	      clib_json_add_object (&j, 0);
	      clib_json_add_string (&j, "name", "%s", t->values[i].name);
	      clib_json_add_number (&j, "value", t->values[i].value);
	      clib_json_parent (&j);
	    }

	  clib_json_parent (&j);
	}
      else if (t->kind == VL_API_DT_ALIAS)
	{
	  clib_json_add_string (&j, "alias", "%s", t->alias_type);
	  clib_json_add_number (&j, "length", t->alias_length);
	}
      else
	{
	  clib_json_add_array (&j, "fields");

	  for (u32 i = 0; i < t->n_fields; i++)
	    {
	      const vl_api_desc_field_t *f = &t->fields[i];

	      clib_json_add_object (&j, 0);
	      clib_json_add_string (&j, "name", "%s", f->name);
	      clib_json_add_string (&j, "type", "%U", format_vl_api_desc_field_type, f);
	      clib_json_add_string (&j, "kind", "%s", desc_field_kinds[f->kind]);
	      clib_json_add_number (&j, "offset", f->offset);
	      clib_json_add_number (&j, "size", f->size);
	      clib_json_add_string (&j, "array", "%U", format_desc_field_flags, t, f);

	      if (f->description)
		clib_json_add_string (&j, "description", "%s", f->description);

	      clib_json_parent (&j);
	    }

	  clib_json_parent (&j);
	}

      err = cli_emit_object (ctx, &j, cols);
      vec_free (flags);
      return err;
    }

  vlib_cli_output (vm, "%s %s", desc_type_kinds[t->kind], t->name);

  if (t->brief)
    vlib_cli_output (vm, "  %s", t->brief);

  if (id != ~0)
    vlib_cli_output (vm, "  id %u, crc %08x", id, t->crc);

  vlib_cli_output (vm, "  size %u%s%v", t->size, vec_len (flags) ? ", " : "", flags);

  if (t->kind == VL_API_DT_ALIAS)
    vlib_cli_output (vm, "  alias of %s", t->alias_type);
  else if (t->kind == VL_API_DT_ENUM || t->kind == VL_API_DT_ENUMFLAG)
    {
      table_t table = {};

      table_add_hdr_col (&table, 0);
      table_add_hdr_row (&table, 2, "Name", "Value");
      table_set_cell_align (&table, -1, -1, TTAA_LEFT);
      table_set_cell_align (&table, -1, 0, TTAA_RIGHT);

      for (u32 i = 0; i < t->n_fields; i++)
	{
	  table_format_cell (&table, i, -1, "%s", t->values[i].name);
	  table_format_cell (&table, i, 0, "%lld", t->values[i].value);
	}

      vlib_cli_output (vm, "%U", format_table, &table);
      table_free (&table);
    }
  else
    {
      table_t table = {};

      table_add_hdr_col (&table, 0);
      table_add_hdr_row (&table, 7, "Field", "Type", "Kind", "Offset", "Size", "Array",
			 "Description");

      /* the headers are aligned as the columns are */
      table_set_cell_align (&table, -1, -1, TTAA_LEFT);
      table_set_cell_align (&table, -1, 0, TTAA_LEFT);
      table_set_cell_align (&table, -1, 1, TTAA_LEFT);
      table_set_cell_align (&table, -1, 2, TTAA_RIGHT);
      table_set_cell_align (&table, -1, 3, TTAA_RIGHT);
      table_set_cell_align (&table, -1, 4, TTAA_LEFT);
      table_set_cell_align (&table, -1, 5, TTAA_LEFT);

      for (u32 i = 0; i < t->n_fields; i++)
	{
	  const vl_api_desc_field_t *f = &t->fields[i];

	  table_format_cell (&table, i, -1, "%s", f->name);
	  table_format_cell (&table, i, 0, "%U", format_vl_api_desc_field_type, f);
	  table_format_cell (&table, i, 1, "%s", desc_field_kinds[f->kind]);
	  table_format_cell (&table, i, 2, "%u", f->offset);
	  table_format_cell (&table, i, 3, "%u", f->size);
	  table_format_cell (&table, i, 4, "%U", format_desc_field_flags, t, f);

	  if (f->description)
	    table_format_cell (&table, i, 5, "%s", f->description);

	  table_set_cell_align (&table, i, 0, TTAA_LEFT);
	  table_set_cell_align (&table, i, 1, TTAA_LEFT);
	  table_set_cell_align (&table, i, 4, TTAA_LEFT);
	  table_set_cell_align (&table, i, 5, TTAA_LEFT);
	}

      vlib_cli_output (vm, "%U", format_table, &table);
      table_free (&table);
    }

  vec_free (flags);
  return 0;
}

static clib_error_t *
show_api_descriptor_module (vlib_main_t *vm, cli_ctx_t *ctx, api_main_t *am,
			    const vl_api_desc_file_t *f)
{
  clib_json_text_t j;
  table_t table = {};
  u32 row = 0, n_types = 0;
  int json = cli_is_json (ctx);

  if (json)
    {
      clib_json_init (&j);
      clib_json_add_object (&j, 0);
      clib_json_add_string (&j, "module", "%s", f->module);
      clib_json_add_string (&j, "crc", "0x%x", f->file_crc);
      clib_json_add_array (&j, "entries");
    }

  table_add_hdr_col (&table, 0);
  table_add_hdr_row (&table, 6, "Name", "Kind", "ID", "CRC", "Size", "Reply");
  table_set_cell_align (&table, -1, -1, TTAA_LEFT);
  table_set_cell_align (&table, -1, 0, TTAA_LEFT);
  table_set_cell_align (&table, -1, 1, TTAA_RIGHT);
  table_set_cell_align (&table, -1, 2, TTAA_RIGHT);
  table_set_cell_align (&table, -1, 3, TTAA_RIGHT);
  table_set_cell_align (&table, -1, 4, TTAA_LEFT);

  /* the messages, then the types of the file, not the ones which it imports */
  for (u32 i = 0; i < f->n_msgs + f->n_types; i++)
    {
      const vl_api_desc_type_t *t = i < f->n_msgs ? f->msgs[i] : f->types[i - f->n_msgs];
      int is_msg = t->kind == VL_API_DT_MESSAGE;
      u32 id = is_msg ? desc_msg_id (am, t) : ~0;
      const char *reply =
	is_msg && (t->flags & VL_API_DTF_SERVICE) ? (t->reply ? t->reply->name : "null") : 0;

      if (t->imported)
	continue;

      if (!is_msg)
	n_types++;

      if (json)
	{
	  clib_json_add_object (&j, 0);
	  clib_json_add_string (&j, "name", "%s", t->name);
	  clib_json_add_string (&j, "kind", "%s", desc_type_kinds[t->kind]);
	  if (id != ~0)
	    clib_json_add_number (&j, "id", id);
	  if (is_msg)
	    clib_json_add_string (&j, "crc", "%08x", t->crc);
	  clib_json_add_number (&j, "size", t->size);
	  if (reply)
	    clib_json_add_string (&j, "reply", "%s", reply);
	  clib_json_parent (&j);
	  continue;
	}

      table_format_cell (&table, row, -1, "%s", t->name);
      table_format_cell (&table, row, 0, "%s", desc_type_kinds[t->kind]);
      if (id != ~0)
	table_format_cell (&table, row, 1, "%u", id);
      if (is_msg)
	table_format_cell (&table, row, 2, "%08x", t->crc);
      table_format_cell (&table, row, 3, "%u", t->size);
      if (reply)
	table_format_cell (&table, row, 4, "%s", reply);
      table_set_cell_align (&table, row, 0, TTAA_LEFT);
      table_set_cell_align (&table, row, 4, TTAA_LEFT);
      row++;
    }

  if (json)
    {
      static const cli_column_t cols[] = {
	{ "module", "Module" },
	{ "crc", "CRC" },
	{},
      };

      clib_json_parent (&j);
      table_free (&table);
      return cli_emit_object (ctx, &j, cols);
    }

  vlib_cli_output (vm, "module %s, crc 0x%x, %u messages, %u types\n", f->module, f->file_crc,
		   f->n_msgs, n_types);
  vlib_cli_output (vm, "%U", format_table, &table);
  table_free (&table);
  return 0;
}

static clib_error_t *
show_api_descriptor_command_fn (vlib_main_t *vm, cli_ctx_t *ctx)
{
  api_main_t *am = vlibapi_get_main ();
  cli_value_t *v;
  const vl_api_desc_type_t *t;

  if ((v = cli_get (ctx, "module")))
    return show_api_descriptor_module (vm, ctx, am, am->desc_files[v->index]);

  if ((v = cli_get (ctx, "message")))
    t = desc_nth_name (am, 1, v->index);
  else if ((v = cli_get (ctx, "type")))
    t = desc_nth_name (am, 0, v->index);
  else
    return show_api_descriptor_files (vm, ctx, am);

  if (!t)
    return clib_error_return (0, "unknown name");

  return show_api_descriptor_type (vm, ctx, am, t);
}

/*?
 * Display the API descriptors: the files, or the description of a message
 * or a type, with the layout of its fields.
?*/
VLIB_CLI_COMMAND (show_api_descriptor_command, static) = {
  .path = "show api descriptor",
  .short_help = "Display the API descriptors of the files, of a file, a message or a type",
  .args = CLI_ARGS (CLI_ONEOF (
    "what", CLI_F_OPTIONAL, CLI_KEYWORD ("module", cli_type_api_module, .help = "an API file"),
    CLI_KEYWORD ("message", cli_type_api_message, .help = "an API message"),
    CLI_KEYWORD ("type", cli_type_api_type, .help = "an API type, enum, flags or alias"))),
  .handler = show_api_descriptor_command_fn,
  .is_mp_safe = 1,
};
