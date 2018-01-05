/*
 *------------------------------------------------------------------
 * vlib_api.c VLIB API implementation
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

#include <fcntl.h>
#include <pthread.h>
#include <vppinfra/vec.h>
#include <vppinfra/hash.h>
#include <vppinfra/pool.h>
#include <vppinfra/format.h>
#include <vppinfra/byte_order.h>
#include <vppinfra/elog.h>
#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>

/**
 * @file
 * @brief Binary API messaging via shared memory
 * Low-level, primary provisioning interface
 */
/*? %%clicmd:group_label Binary API CLI %% ?*/
/*? %%syscfg:group_label Binary API configuration %% ?*/

#define TRACE_VLIB_MEMORY_QUEUE 0

#include <vlibmemory/vl_memory_msg_enum.h>	/* enumerate all vlib messages */

#define vl_typedefs		/* define message structures */
#include <vlibmemory/vl_memory_api_h.h>
#undef vl_typedefs

/* instantiate all the print functions we know about */
#define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)
#define vl_printfun
#include <vlibmemory/vl_memory_api_h.h>
#undef vl_printfun

static inline void *
vl_api_trace_plugin_msg_ids_t_print (vl_api_trace_plugin_msg_ids_t * a,
				     void *handle)
{
  vl_print (handle, "vl_api_trace_plugin_msg_ids: %s first %u last %u\n",
	    a->plugin_name,
	    clib_host_to_net_u16 (a->first_msg_id),
	    clib_host_to_net_u16 (a->last_msg_id));
  return handle;
}

/* instantiate all the endian swap functions we know about */
#define vl_endianfun
#include <vlibmemory/vl_memory_api_h.h>
#undef vl_endianfun

extern void vl_socket_api_send (vl_api_registration_t * rp, u8 * elem);

void
vl_api_send_msg (vl_api_registration_t * rp, u8 * elem)
{
  if (PREDICT_FALSE (rp->registration_type > REGISTRATION_TYPE_SHMEM))
    {
      vl_socket_api_send (rp, elem);
    }
  else
    {
      vl_msg_api_send_shmem (rp->vl_input_queue, (u8 *) & elem);
    }
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

static void
vl_api_get_first_msg_id_t_handler (vl_api_get_first_msg_id_t * mp)
{
  vl_api_get_first_msg_id_reply_t *rmp;
  vl_api_registration_t *regp;
  uword *p;
  api_main_t *am = &api_main;
  vl_api_msg_range_t *rp;
  u8 name[64];
  u16 first_msg_id = ~0;
  int rv = -7;			/* VNET_API_ERROR_INVALID_VALUE */

  regp = vl_api_client_index_to_registration (mp->client_index);
  if (!regp)
    return;

  if (am->msg_range_by_name == 0)
    goto out;

  strncpy ((char *) name, (char *) mp->name, ARRAY_LEN (name) - 1);

  p = hash_get_mem (am->msg_range_by_name, name);
  if (p == 0)
    goto out;

  rp = vec_elt_at_index (am->msg_ranges, p[0]);
  first_msg_id = rp->first_msg_id;
  rv = 0;

out:
  rmp = vl_msg_api_alloc (sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (VL_API_GET_FIRST_MSG_ID_REPLY);
  rmp->context = mp->context;
  rmp->retval = ntohl (rv);
  rmp->first_msg_id = ntohs (first_msg_id);
  vl_api_send_msg (regp, (u8 *) rmp);
}

void
vl_api_api_versions_t_handler (vl_api_api_versions_t * mp)
{
  api_main_t *am = &api_main;
  vl_api_api_versions_reply_t *rmp;
  svm_queue_t *q;
  u32 nmsg = vec_len (am->api_version_list);
  int msg_size = sizeof (*rmp) + sizeof (rmp->api_versions[0]) * nmsg;
  int i;

  q = vl_api_client_index_to_input_queue (mp->client_index);
  if (q == 0)
    return;

  rmp = vl_msg_api_alloc (msg_size);
  memset (rmp, 0, msg_size);
  rmp->_vl_msg_id = ntohs (VL_API_API_VERSIONS_REPLY);

  /* fill in the message */
  rmp->context = mp->context;
  rmp->count = htonl (nmsg);

  for (i = 0; i < nmsg; ++i)
    {
      api_version_t *vl = &am->api_version_list[i];
      rmp->api_versions[i].major = htonl (vl->major);
      rmp->api_versions[i].minor = htonl (vl->minor);
      rmp->api_versions[i].patch = htonl (vl->patch);
      strncpy ((char *) rmp->api_versions[i].name, vl->name, 64 - 1);
    }

  vl_msg_api_send_shmem (q, (u8 *) & rmp);
}

#define foreach_vlib_api_msg                            \
_(GET_FIRST_MSG_ID, get_first_msg_id)                   \
_(API_VERSIONS, api_versions)

/*
 * vl_api_init
 */
static int
vlib_api_init (void)
{
  vl_msg_api_msg_config_t cfg;
  vl_msg_api_msg_config_t *c = &cfg;

  memset (c, 0, sizeof (*c));

#define _(N,n) do {                                             \
    c->id = VL_API_##N;                                         \
    c->name = #n;                                               \
    c->handler = vl_api_##n##_t_handler;                        \
    c->cleanup = vl_noop_handler;                               \
    c->endian = vl_api_##n##_t_endian;                          \
    c->print = vl_api_##n##_t_print;                            \
    c->size = sizeof(vl_api_##n##_t);                           \
    c->traced = 1; /* trace, so these msgs print */             \
    c->replay = 0; /* don't replay client create/delete msgs */ \
    c->message_bounce = 0; /* don't bounce this message */	\
    vl_msg_api_config(c);} while (0);

  foreach_vlib_api_msg;
#undef _

  return 0;
}

#define foreach_histogram_bucket                \
_(400)                                          \
_(200)                                          \
_(100)                                          \
_(10)

typedef enum
{
#define _(n) SLEEP_##n##_US,
  foreach_histogram_bucket
#undef _
    SLEEP_N_BUCKETS,
} histogram_index_t;

static u64 vector_rate_histogram[SLEEP_N_BUCKETS];

/*
 * Callback to send ourselves a plugin numbering-space trace msg
 */
static void
send_one_plugin_msg_ids_msg (u8 * name, u16 first_msg_id, u16 last_msg_id)
{
  vl_api_trace_plugin_msg_ids_t *mp;
  api_main_t *am = &api_main;
  vl_shmem_hdr_t *shmem_hdr = am->shmem_hdr;
  svm_queue_t *q;

  mp = vl_msg_api_alloc_as_if_client (sizeof (*mp));
  memset (mp, 0, sizeof (*mp));

  mp->_vl_msg_id = clib_host_to_net_u16 (VL_API_TRACE_PLUGIN_MSG_IDS);
  strncpy ((char *) mp->plugin_name, (char *) name,
	   sizeof (mp->plugin_name) - 1);
  mp->first_msg_id = clib_host_to_net_u16 (first_msg_id);
  mp->last_msg_id = clib_host_to_net_u16 (last_msg_id);

  q = shmem_hdr->vl_input_queue;

  vl_msg_api_send_shmem (q, (u8 *) & mp);
}

int
vl_api_call_reaper_functions (u32 client_index)
{
  clib_error_t *error = 0;
  _vl_msg_api_function_list_elt_t *i;

  i = api_main.reaper_function_registrations;
  while (i)
    {
      error = i->f (client_index);
      if (error)
	clib_error_report (error);
      i = i->next_init_function;
    }
  return 0;
}

void
vl_api_save_msg_table ()
{
  u8 *serialized_message_table;
  api_main_t *am = &api_main;
  u8 *chroot_file;
  int fd, rv;

  /*
   * Snapshoot the api message table.
   */
  if (strstr ((char *) am->save_msg_table_filename, "..")
	  || index ((char *) am->save_msg_table_filename, '/'))
	{
	  clib_warning ("illegal save-message-table filename '%s'",
			am->save_msg_table_filename);
	  return;
	}

  chroot_file = format (0, "/tmp/%s%c", am->save_msg_table_filename, 0);

  fd = creat ((char *) chroot_file, 0644);

  if (fd < 0)
	{
	  clib_unix_warning ("creat");
	  return;
	}

  serialized_message_table = vl_api_serialize_message_table (am, 0);

  rv = write (fd, serialized_message_table,
		  vec_len (serialized_message_table));

  if (rv != vec_len (serialized_message_table))
	clib_unix_warning ("write");

  rv = close (fd);
  if (rv < 0)
	clib_unix_warning ("close");

  vec_free (chroot_file);
  vec_free (serialized_message_table);
}

static uword
vl_api_clnt_process (vlib_main_t * vm, vlib_node_runtime_t * node,
                    vlib_frame_t * f)
{
  vl_shmem_hdr_t *shm;
  svm_queue_t *q;
  clib_error_t *e;
  int rv;
  api_main_t *am = &api_main;
  f64 dead_client_scan_time;
  f64 sleep_time, start_time;
  f64 vector_rate;
  clib_error_t *socksvr_api_init (vlib_main_t * vm);
  clib_error_t *error;
  int i;
  vl_socket_args_for_process_t *a;
  uword event_type;
  uword *event_data = 0;
  int private_segment_rotor = 0;
  f64 now;

  if ((rv = memory_api_init (am->region_name)) < 0)
    {
      clib_warning ("memory_api_init returned %d, quitting...", rv);
      return 0;
    }

  if ((error = socksvr_api_init (vm)))
    {
      clib_error_report (error);
      clib_warning ("socksvr_api_init failed, quitting...");
      return 0;
    }

  if ((rv = vlib_api_init ()) < 0)
    {
      clib_warning ("vlib_api_init returned %d, quitting...", rv);
      return 0;
    }

  shm = am->shmem_hdr;
  q = shm->vl_input_queue;

  e = vlib_call_init_exit_functions
    (vm, vm->api_init_function_registrations, 1 /* call_once */ );
  if (e)
    clib_error_report (e);

  sleep_time = 10.0;
  dead_client_scan_time = vlib_time_now (vm) + 10.0;

  /*
   * Send plugin message range messages for each plugin we loaded
   */
  for (i = 0; i < vec_len (am->msg_ranges); i++)
    {
      vl_api_msg_range_t *rp = am->msg_ranges + i;
      send_one_plugin_msg_ids_msg (rp->name, rp->first_msg_id,
				   rp->last_msg_id);
    }

  /*
   * Save the api message table snapshot, if configured
   */
  if (am->save_msg_table_filename)
    vl_api_save_msg_table (am);

  /* $$$ pay attention to frame size, control CPU usage */
  while (1)
    {
      /*
       * There's a reason for checking the queue before
       * sleeping. If the vlib application crashes, it's entirely
       * possible for a client to enqueue a connect request
       * during the process restart interval.
       *
       * Unless some force of physics causes the new incarnation
       * of the application to process the request, the client will
       * sit and wait for Godot...
       */
      vector_rate = vlib_last_vector_length_per_node (vm);
      start_time = vlib_time_now (vm);
      while (1)
	{
	  if (vl_mem_api_handle_msg_main (vm, node))
	    {
	      vm->api_queue_nonempty = 0;
	      VL_MEM_API_LOG_Q_LEN ("q-underflow: len %d", 0);
	      sleep_time = 20.0;
	      break;
	    }

	  /* Allow no more than 10us without a pause */
	  if (vlib_time_now (vm) > start_time + 10e-6)
	    {
	      int index = SLEEP_400_US;
	      if (vector_rate > 40.0)
		sleep_time = 400e-6;
	      else if (vector_rate > 20.0)
		{
		  index = SLEEP_200_US;
		  sleep_time = 200e-6;
		}
	      else if (vector_rate >= 1.0)
		{
		  index = SLEEP_100_US;
		  sleep_time = 100e-6;
		}
	      else
		{
		  index = SLEEP_10_US;
		  sleep_time = 10e-6;
		}
	      vector_rate_histogram[index] += 1;
	      break;
	    }
	}

      /*
       * see if we have any private api shared-memory segments
       * If so, push required context variables, and process
       * a message.
       */
      if (PREDICT_FALSE (vec_len (am->vlib_private_rps)))
	{
	  vl_mem_api_handle_msg_private (vm, node, private_segment_rotor++);
	  if (private_segment_rotor >= vec_len (am->vlib_private_rps))
	    private_segment_rotor = 0;
	}

      vlib_process_wait_for_event_or_clock (vm, sleep_time);
      vec_reset_length (event_data);
      event_type = vlib_process_get_events (vm, &event_data);
      now = vlib_time_now (vm);

      switch (event_type)
	{
	case QUEUE_SIGNAL_EVENT:
	  vm->queue_signal_pending = 0;
	  VL_MEM_API_LOG_Q_LEN("q-awake: len %d", q->cursize);

	  break;
	case SOCKET_READ_EVENT:
	  for (i = 0; i < vec_len (event_data); i++)
	    {
	      a = pool_elt_at_index (socket_main.process_args, event_data[i]);
	      vl_socket_process_api_msg (a->clib_file, a->regp,
					 (i8 *) a->data);
	      vec_free (a->data);
	      pool_put (socket_main.process_args, a);
	    }
	  break;

	  /* Timeout... */
	case -1:
	  break;

	default:
	  clib_warning ("unknown event type %d", event_type);
	  break;
	}

      if (now > dead_client_scan_time)
	{
	  vl_mem_api_dead_client_scan (am, shm, now);
	  dead_client_scan_time = vlib_time_now (vm) + 10.0;
	}
    }

  return 0;
}
/* *INDENT-OFF* */
VLIB_REGISTER_NODE (vl_api_clnt_node) =
{
  .function = vl_api_clnt_process,
  .type = VLIB_NODE_TYPE_PROCESS,
  .name = "api-rx-from-ring",
  .state = VLIB_NODE_STATE_DISABLED,
};
/* *INDENT-ON* */

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

void
vl_enable_disable_memory_api (vlib_main_t * vm, int enable)
{
  vlib_node_set_state (vm, vl_api_clnt_node.index,
		       (enable
			? VLIB_NODE_STATE_POLLING
			: VLIB_NODE_STATE_DISABLED));
}

static uword
api_rx_from_node (vlib_main_t * vm,
		  vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  uword n_packets = frame->n_vectors;
  uword n_left_from;
  u32 *from;
  static u8 *long_msg;

  vec_validate (long_msg, 4095);
  n_left_from = frame->n_vectors;
  from = vlib_frame_args (frame);

  while (n_left_from > 0)
    {
      u32 bi0;
      vlib_buffer_t *b0;
      void *msg;
      uword msg_len;

      bi0 = from[0];
      b0 = vlib_get_buffer (vm, bi0);
      from += 1;
      n_left_from -= 1;

      msg = b0->data + b0->current_data;
      msg_len = b0->current_length;
      if (b0->flags & VLIB_BUFFER_NEXT_PRESENT)
	{
	  ASSERT (long_msg != 0);
	  _vec_len (long_msg) = 0;
	  vec_add (long_msg, msg, msg_len);
	  while (b0->flags & VLIB_BUFFER_NEXT_PRESENT)
	    {
	      b0 = vlib_get_buffer (vm, b0->next_buffer);
	      msg = b0->data + b0->current_data;
	      msg_len = b0->current_length;
	      vec_add (long_msg, msg, msg_len);
	    }
	  msg = long_msg;
	}
      vl_msg_api_handler_no_trace_no_free (msg);
    }

  /* Free what we've been given. */
  vlib_buffer_free (vm, vlib_frame_args (frame), n_packets);

  return n_packets;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (api_rx_from_node_node,static) = {
    .function = api_rx_from_node,
    .type = VLIB_NODE_TYPE_INTERNAL,
    .vector_size = 4,
    .name = "api-rx-from-node",
};
/* *INDENT-ON* */

void dump_socket_clients (vlib_main_t * vm, api_main_t * am)
  __attribute__ ((weak));

void
dump_socket_clients (vlib_main_t * vm, api_main_t * am)
{
}

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
  dump_socket_clients (vm, am);

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

static void
vl_api_rpc_call_t_handler (vl_api_rpc_call_t * mp)
{
  vl_api_rpc_call_reply_t *rmp;
  int (*fp) (void *);
  i32 rv = 0;
  vlib_main_t *vm = vlib_get_main ();

  if (mp->function == 0)
    {
      rv = -1;
      clib_warning ("rpc NULL function pointer");
    }

  else
    {
      if (mp->need_barrier_sync)
	vlib_worker_thread_barrier_sync (vm);

      fp = uword_to_pointer (mp->function, int (*)(void *));
      rv = fp (mp->data);

      if (mp->need_barrier_sync)
	vlib_worker_thread_barrier_release (vm);
    }

  if (mp->send_reply)
    {
      svm_queue_t *q = vl_api_client_index_to_input_queue (mp->client_index);
      if (q)
	{
	  rmp = vl_msg_api_alloc_as_if_client (sizeof (*rmp));
	  rmp->_vl_msg_id = ntohs (VL_API_RPC_CALL_REPLY);
	  rmp->context = mp->context;
	  rmp->retval = rv;
	  vl_msg_api_send_shmem (q, (u8 *) & rmp);
	}
    }
  if (mp->multicast)
    {
      clib_warning ("multicast not yet implemented...");
    }
}

static void
vl_api_rpc_call_reply_t_handler (vl_api_rpc_call_reply_t * mp)
{
  clib_warning ("unimplemented");
}

void
vl_api_send_pending_rpc_requests (vlib_main_t * vm)
{
  api_main_t *am = &api_main;
  vl_shmem_hdr_t *shmem_hdr = am->shmem_hdr;
  svm_queue_t *q;
  int i;

  /*
   * Use the "normal" control-plane mechanism for the main thread.
   * Well, almost. if the main input queue is full, we cannot
   * block. Otherwise, we can expect a barrier sync timeout.
   */
  q = shmem_hdr->vl_input_queue;

  for (i = 0; i < vec_len (vm->pending_rpc_requests); i++)
    {
      while (pthread_mutex_trylock (&q->mutex))
	vlib_worker_thread_barrier_check ();

      while (PREDICT_FALSE (svm_queue_is_full (q)))
	{
	  pthread_mutex_unlock (&q->mutex);
	  vlib_worker_thread_barrier_check ();
	  while (pthread_mutex_trylock (&q->mutex))
	    vlib_worker_thread_barrier_check ();
	}

      vl_msg_api_send_shmem_nolock (q, (u8 *) (vm->pending_rpc_requests + i));

      pthread_mutex_unlock (&q->mutex);
    }
  _vec_len (vm->pending_rpc_requests) = 0;
}

always_inline void
vl_api_rpc_call_main_thread_inline (void *fp, u8 * data, u32 data_length,
				    u8 force_rpc)
{
  vl_api_rpc_call_t *mp;
  vlib_main_t *vm = vlib_get_main ();

  /* Main thread and not a forced RPC: call the function directly */
  if ((force_rpc == 0) && (vlib_get_thread_index () == 0))
    {
      void (*call_fp) (void *);

      vlib_worker_thread_barrier_sync (vm);

      call_fp = fp;
      call_fp (data);

      vlib_worker_thread_barrier_release (vm);
      return;
    }

  /* Otherwise, actually do an RPC */
  mp = vl_msg_api_alloc_as_if_client (sizeof (*mp) + data_length);

  memset (mp, 0, sizeof (*mp));
  clib_memcpy (mp->data, data, data_length);
  mp->_vl_msg_id = ntohs (VL_API_RPC_CALL);
  mp->function = pointer_to_uword (fp);
  mp->need_barrier_sync = 1;

  vec_add1 (vm->pending_rpc_requests, (uword) mp);
}

/*
 * Check if called from worker threads.
 * If so, make rpc call of fp through shmem.
 * Otherwise, call fp directly
 */
void
vl_api_rpc_call_main_thread (void *fp, u8 * data, u32 data_length)
{
  vl_api_rpc_call_main_thread_inline (fp, data, data_length,	/*force_rpc */
				      0);
}

/*
 * Always make rpc call of fp through shmem, useful for calling from threads
 * not setup as worker threads, such as DPDK callback thread
 */
void
vl_api_force_rpc_call_main_thread (void *fp, u8 * data, u32 data_length)
{
  vl_api_rpc_call_main_thread_inline (fp, data, data_length,	/*force_rpc */
				      1);
}

static void
vl_api_trace_plugin_msg_ids_t_handler (vl_api_trace_plugin_msg_ids_t * mp)
{
  api_main_t *am = &api_main;
  vl_api_msg_range_t *rp;
  uword *p;

  /* Noop (except for tracing) during normal operation */
  if (am->replay_in_progress == 0)
    return;

  p = hash_get_mem (am->msg_range_by_name, mp->plugin_name);
  if (p == 0)
    {
      clib_warning ("WARNING: traced plugin '%s' not in current image",
		    mp->plugin_name);
      return;
    }

  rp = vec_elt_at_index (am->msg_ranges, p[0]);
  if (rp->first_msg_id != clib_net_to_host_u16 (mp->first_msg_id))
    {
      clib_warning ("WARNING: traced plugin '%s' first message id %d not %d",
		    mp->plugin_name, clib_net_to_host_u16 (mp->first_msg_id),
		    rp->first_msg_id);
    }

  if (rp->last_msg_id != clib_net_to_host_u16 (mp->last_msg_id))
    {
      clib_warning ("WARNING: traced plugin '%s' last message id %d not %d",
		    mp->plugin_name, clib_net_to_host_u16 (mp->last_msg_id),
		    rp->last_msg_id);
    }
}

#define foreach_rpc_api_msg                     \
_(RPC_CALL,rpc_call)                            \
_(RPC_CALL_REPLY,rpc_call_reply)

#define foreach_plugin_trace_msg		\
_(TRACE_PLUGIN_MSG_IDS,trace_plugin_msg_ids)

/*
 * Set the rpc callback at our earliest possible convenience.
 * This avoids ordering issues between thread_init() -> start_workers and
 * an init function which we could define here. If we ever intend to use
 * vlib all by itself, we can't create a link-time dependency on
 * an init function here and a typical "call foo_init first"
 * guitar lick.
 */

extern void *rpc_call_main_thread_cb_fn;

static clib_error_t *
rpc_api_hookup (vlib_main_t * vm)
{
  api_main_t *am = &api_main;
#define _(N,n)                                                  \
    vl_msg_api_set_handlers(VL_API_##N, #n,                     \
                           vl_api_##n##_t_handler,              \
                           vl_noop_handler,                     \
                           vl_noop_handler,			\
                           vl_api_##n##_t_print,                \
                           sizeof(vl_api_##n##_t), 0 /* do not trace */);
  foreach_rpc_api_msg;
#undef _

#define _(N,n)                                                  \
    vl_msg_api_set_handlers(VL_API_##N, #n,                     \
                           vl_api_##n##_t_handler,              \
                           vl_noop_handler,                     \
                           vl_noop_handler,			\
                           vl_api_##n##_t_print,                \
                           sizeof(vl_api_##n##_t), 1 /* do trace */);
  foreach_plugin_trace_msg;
#undef _

  /* No reason to halt the parade to create a trace record... */
  am->is_mp_safe[VL_API_TRACE_PLUGIN_MSG_IDS] = 1;
  rpc_call_main_thread_cb_fn = vl_api_rpc_call_main_thread;
  return 0;
}

VLIB_API_INIT_FUNCTION (rpc_api_hookup);

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
