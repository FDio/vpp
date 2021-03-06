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

static void
vl_api_get_first_msg_id_t_handler (vl_api_get_first_msg_id_t * mp)
{
  vl_api_get_first_msg_id_reply_t *rmp;
  vl_api_registration_t *regp;
  uword *p;
  api_main_t *am = vlibapi_get_main ();
  vl_api_msg_range_t *rp;
  u8 name[64];
  u16 first_msg_id = ~0;
  int rv = -7;			/* VNET_API_ERROR_INVALID_VALUE */

  regp = vl_api_client_index_to_registration (mp->client_index);
  if (!regp)
    return;

  if (am->msg_range_by_name == 0)
    goto out;
  strncpy ((char *) name, (char *) mp->name, ARRAY_LEN (name));
  name[ARRAY_LEN (name) - 1] = '\0';
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
  api_main_t *am = vlibapi_get_main ();
  vl_api_api_versions_reply_t *rmp;
  vl_api_registration_t *reg;
  u32 nmsg = vec_len (am->api_version_list);
  int msg_size = sizeof (*rmp) + sizeof (rmp->api_versions[0]) * nmsg;
  int i;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  rmp = vl_msg_api_alloc (msg_size);
  clib_memset (rmp, 0, msg_size);
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
      strncpy ((char *) rmp->api_versions[i].name, vl->name,
	       ARRAY_LEN (rmp->api_versions[i].name));
      rmp->api_versions[i].name[ARRAY_LEN (rmp->api_versions[i].name) - 1] =
	'\0';
    }

  vl_api_send_msg (reg, (u8 *) rmp);
}

#define foreach_vlib_api_msg				\
_(GET_FIRST_MSG_ID, get_first_msg_id)			\
_(API_VERSIONS, api_versions)

/*
 * vl_api_init
 */
static int
vlib_api_init (void)
{
  vl_msg_api_msg_config_t cfg;
  vl_msg_api_msg_config_t *c = &cfg;

  clib_memset (c, 0, sizeof (*c));

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

u64 vector_rate_histogram[SLEEP_N_BUCKETS];

/*
 * Callback to send ourselves a plugin numbering-space trace msg
 */
static void
send_one_plugin_msg_ids_msg (u8 * name, u16 first_msg_id, u16 last_msg_id)
{
  vl_api_trace_plugin_msg_ids_t *mp;
  api_main_t *am = vlibapi_get_main ();
  vl_shmem_hdr_t *shmem_hdr = am->shmem_hdr;
  svm_queue_t *q;

  mp = vl_msg_api_alloc_as_if_client (sizeof (*mp));
  clib_memset (mp, 0, sizeof (*mp));

  mp->_vl_msg_id = clib_host_to_net_u16 (VL_API_TRACE_PLUGIN_MSG_IDS);
  strncpy ((char *) mp->plugin_name, (char *) name,
	   sizeof (mp->plugin_name) - 1);
  mp->first_msg_id = clib_host_to_net_u16 (first_msg_id);
  mp->last_msg_id = clib_host_to_net_u16 (last_msg_id);

  q = shmem_hdr->vl_input_queue;

  vl_msg_api_send_shmem (q, (u8 *) & mp);
}

void
vl_api_save_msg_table (void)
{
  u8 *serialized_message_table;
  api_main_t *am = vlibapi_get_main ();
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

clib_error_t *vat_builtin_main_init (vlib_main_t * vm) __attribute__ ((weak));
clib_error_t *
vat_builtin_main_init (vlib_main_t * vm)
{
  return 0;
}

static uword
vl_api_clnt_process (vlib_main_t * vm, vlib_node_runtime_t * node,
		     vlib_frame_t * f)
{
  vlib_global_main_t *vgm = vlib_get_global_main ();
  int private_segment_rotor = 0, i, rv;
  vl_socket_args_for_process_t *a;
  vl_shmem_hdr_t *shm;
  svm_queue_t *q;
  clib_error_t *e;
  api_main_t *am = vlibapi_get_main ();
  f64 dead_client_scan_time;
  f64 sleep_time, start_time;
  f64 vector_rate;
  clib_error_t *error;
  uword event_type;
  uword *event_data = 0;
  f64 now;

  if ((error = vl_sock_api_init (vm)))
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

  e = vlib_call_init_exit_functions (vm, &vgm->api_init_function_registrations,
				     1 /* call_once */, 1 /* is_global */);
  if (e)
    clib_error_report (e);

  e = vat_builtin_main_init (vm);
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
    vl_api_save_msg_table ();

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
      vector_rate = (f64) vlib_last_vectors_per_main_loop (vm);
      start_time = vlib_time_now (vm);
      while (1)
	{
	  if (vl_mem_api_handle_rpc (vm, node)
	      || vl_mem_api_handle_msg_main (vm, node))
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
	  if (private_segment_rotor >= vec_len (am->vlib_private_rps))
	    private_segment_rotor = 0;
	  vl_mem_api_handle_msg_private (vm, node, private_segment_rotor++);
	}

      vlib_process_wait_for_event_or_clock (vm, sleep_time);
      vec_reset_length (event_data);
      event_type = vlib_process_get_events (vm, &event_data);
      now = vlib_time_now (vm);

      switch (event_type)
	{
	case QUEUE_SIGNAL_EVENT:
	  vm->queue_signal_pending = 0;
	  VL_MEM_API_LOG_Q_LEN ("q-awake: len %d", q->cursize);

	  break;
	case SOCKET_READ_EVENT:
	  for (i = 0; i < vec_len (event_data); i++)
	    {
	      vl_api_registration_t *regp;

	      a = pool_elt_at_index (socket_main.process_args, event_data[i]);
	      regp = vl_socket_get_registration (a->reg_index);
	      if (regp)
		{
		  vl_socket_process_api_msg (regp, (i8 *) a->data);
		  a = pool_elt_at_index (socket_main.process_args,
					 event_data[i]);
		}
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
  .process_log2_n_stack_bytes = 18,
};
/* *INDENT-ON* */

void
vl_mem_api_enable_disable (vlib_main_t * vm, int enable)
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
  from = vlib_frame_vector_args (frame);

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
  vlib_buffer_free (vm, vlib_frame_vector_args (frame), n_packets);

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
  vlib_main_t *vm_global = vlib_mains[0];

  ASSERT (vm != vm_global);

  clib_spinlock_lock_if_init (&vm_global->pending_rpc_lock);
  vec_append (vm_global->pending_rpc_requests, vm->pending_rpc_requests);
  vec_reset_length (vm->pending_rpc_requests);
  clib_spinlock_unlock_if_init (&vm_global->pending_rpc_lock);
}

always_inline void
vl_api_rpc_call_main_thread_inline (void *fp, u8 * data, u32 data_length,
				    u8 force_rpc)
{
  vl_api_rpc_call_t *mp;
  vlib_main_t *vm_global = vlib_mains[0];
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

  clib_memset (mp, 0, sizeof (*mp));
  clib_memcpy_fast (mp->data, data, data_length);
  mp->_vl_msg_id = ntohs (VL_API_RPC_CALL);
  mp->function = pointer_to_uword (fp);
  mp->need_barrier_sync = 1;

  /* Add to the pending vector. Thread 0 requires locking. */
  if (vm == vm_global)
    clib_spinlock_lock_if_init (&vm_global->pending_rpc_lock);
  vec_add1 (vm->pending_rpc_requests, (uword) mp);
  if (vm == vm_global)
    clib_spinlock_unlock_if_init (&vm_global->pending_rpc_lock);
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
  api_main_t *am = vlibapi_get_main ();
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
  api_main_t *am = vlibapi_get_main ();
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

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
