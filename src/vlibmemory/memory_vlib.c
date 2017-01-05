/*
 *------------------------------------------------------------------
 * memory_vlib.c
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
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <signal.h>
#include <pthread.h>
#include <vppinfra/vec.h>
#include <vppinfra/hash.h>
#include <vppinfra/pool.h>
#include <vppinfra/format.h>
#include <vppinfra/byte_order.h>
#include <vppinfra/elog.h>
#include <stdarg.h>
#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>

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
vl_api_memclnt_create_t_print (vl_api_memclnt_create_t * a, void *handle)
{
  vl_print (handle, "vl_api_memclnt_create_t:\n");
  vl_print (handle, "name: %s\n", a->name);
  vl_print (handle, "input_queue: 0x%wx\n", a->input_queue);
  vl_print (handle, "context: %u\n", (unsigned) a->context);
  vl_print (handle, "ctx_quota: %ld\n", (long) a->ctx_quota);
  return handle;
}

static inline void *
vl_api_memclnt_delete_t_print (vl_api_memclnt_delete_t * a, void *handle)
{
  vl_print (handle, "vl_api_memclnt_delete_t:\n");
  vl_print (handle, "index: %u\n", (unsigned) a->index);
  vl_print (handle, "handle: 0x%wx\n", a->handle);
  return handle;
}

/* instantiate all the endian swap functions we know about */
#define vl_endianfun
#include <vlibmemory/vl_memory_api_h.h>
#undef vl_endianfun

void vl_socket_api_send (vl_api_registration_t * rp, u8 * elem)
  __attribute__ ((weak));

void
vl_socket_api_send (vl_api_registration_t * rp, u8 * elem)
{
  static int count;

  if (count++ < 5)
    clib_warning ("need to link against -lvlibsocket, msg not sent!");
}

void
vl_msg_api_send (vl_api_registration_t * rp, u8 * elem)
{
  if (PREDICT_FALSE (rp->registration_type > REGISTRATION_TYPE_SHMEM))
    {
      vl_socket_api_send (rp, elem);
    }
  else
    {
      vl_msg_api_send_shmem (rp->vl_input_queue, elem);
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

  hash_foreach_pair (hp, am->msg_index_by_name_and_crc, (
							  {
							  serialize_likely_small_unsigned_integer
							  (sm, hp->value[0]);
							  serialize_cstring
							  (sm,
							   (char *) hp->key);
							  }));

  return serialize_close_vector (sm);
}

/*
 * vl_api_memclnt_create_t_handler
 */
void
vl_api_memclnt_create_t_handler (vl_api_memclnt_create_t * mp)
{
  vl_api_registration_t **regpp;
  vl_api_registration_t *regp;
  vl_api_memclnt_create_reply_t *rp;
  svm_region_t *svm;
  unix_shared_memory_queue_t *q;
  int rv = 0;
  void *oldheap;
  api_main_t *am = &api_main;
  u8 *serialized_message_table = 0;

  /*
   * This is tortured. Maintain a vlib-address-space private
   * pool of client registrations. We use the shared-memory virtual
   * address of client structure as a handle, to allow direct
   * manipulation of context quota vbls from the client library.
   *
   * This scheme causes trouble w/ API message trace replay, since
   * some random VA from clib_mem_alloc() certainly won't
   * occur in the Linux sim. The (very) few places
   * that care need to use the pool index.
   *
   * Putting the registration object(s) into a pool in shared memory and
   * using the pool index as a handle seems like a great idea.
   * Unfortunately, each and every reference to that pool would need
   * to be protected by a mutex:
   *
   *     Client                      VLIB
   *     ------                      ----
   *     convert pool index to
   *     pointer.
   *     <deschedule>
   *                                 expand pool
   *                                 <deschedule>
   *     kaboom!
   */

  pool_get (am->vl_clients, regpp);

  svm = am->vlib_rp;

  if (am->serialized_message_table_in_shmem == 0)
    serialized_message_table = vl_api_serialize_message_table (am, 0);

  pthread_mutex_lock (&svm->mutex);
  oldheap = svm_push_data_heap (svm);
  *regpp = clib_mem_alloc (sizeof (vl_api_registration_t));

  regp = *regpp;
  memset (regp, 0, sizeof (*regp));
  regp->registration_type = REGISTRATION_TYPE_SHMEM;
  regp->vl_api_registration_pool_index = regpp - am->vl_clients;

  q = regp->vl_input_queue = (unix_shared_memory_queue_t *) (uword)
    mp->input_queue;

  regp->name = format (0, "%s", mp->name);
  vec_add1 (regp->name, 0);
  if (serialized_message_table)
    am->serialized_message_table_in_shmem =
      vec_dup (serialized_message_table);

  pthread_mutex_unlock (&svm->mutex);
  svm_pop_heap (oldheap);

  vec_free (serialized_message_table);

  rp = vl_msg_api_alloc (sizeof (*rp));
  rp->_vl_msg_id = ntohs (VL_API_MEMCLNT_CREATE_REPLY);
  rp->handle = (uword) regp;
  rp->index = vl_msg_api_handle_from_index_and_epoch
    (regp->vl_api_registration_pool_index,
     am->shmem_hdr->application_restarts);
  rp->context = mp->context;
  rp->response = ntohl (rv);
  rp->message_table = (u64) am->serialized_message_table_in_shmem;

  vl_msg_api_send_shmem (q, (u8 *) & rp);
}

/* Application callback to clean up leftover registrations from this client */
int vl_api_memclnt_delete_callback (u32 client_index) __attribute__ ((weak));

int
vl_api_memclnt_delete_callback (u32 client_index)
{
  return 0;
}

/*
 * vl_api_memclnt_delete_t_handler
 */
void
vl_api_memclnt_delete_t_handler (vl_api_memclnt_delete_t * mp)
{
  vl_api_registration_t **regpp;
  vl_api_registration_t *regp;
  vl_api_memclnt_delete_reply_t *rp;
  svm_region_t *svm;
  void *oldheap;
  api_main_t *am = &api_main;
  u32 handle, client_index, epoch;

  handle = mp->index;

  if (vl_api_memclnt_delete_callback (handle))
    return;

  epoch = vl_msg_api_handle_get_epoch (handle);
  client_index = vl_msg_api_handle_get_index (handle);

  if (epoch != (am->shmem_hdr->application_restarts & VL_API_EPOCH_MASK))
    {
      clib_warning
	("Stale clnt delete index %d old epoch %d cur epoch %d",
	 client_index, epoch,
	 (am->shmem_hdr->application_restarts & VL_API_EPOCH_MASK));
      return;
    }

  regpp = am->vl_clients + client_index;

  if (!pool_is_free (am->vl_clients, regpp))
    {
      regp = *regpp;
      svm = am->vlib_rp;

      /* $$$ check the input queue for e.g. punted sf's */

      rp = vl_msg_api_alloc (sizeof (*rp));
      rp->_vl_msg_id = ntohs (VL_API_MEMCLNT_DELETE_REPLY);
      rp->handle = mp->handle;
      rp->response = 1;

      vl_msg_api_send_shmem (regp->vl_input_queue, (u8 *) & rp);

      if (client_index != regp->vl_api_registration_pool_index)
	{
	  clib_warning ("mismatch client_index %d pool_index %d",
			client_index, regp->vl_api_registration_pool_index);
	  vl_msg_api_free (rp);
	  return;
	}

      /* No dangling references, please */
      *regpp = 0;

      pool_put_index (am->vl_clients, regp->vl_api_registration_pool_index);

      pthread_mutex_lock (&svm->mutex);
      oldheap = svm_push_data_heap (svm);
      /* Poison the old registration */
      memset (regp, 0xF1, sizeof (*regp));
      clib_mem_free (regp);
      pthread_mutex_unlock (&svm->mutex);
      svm_pop_heap (oldheap);
    }
  else
    {
      clib_warning ("unknown client ID %d", mp->index);
    }
}

void
vl_api_get_first_msg_id_t_handler (vl_api_get_first_msg_id_t * mp)
{
  vl_api_get_first_msg_id_reply_t *rmp;
  unix_shared_memory_queue_t *q;
  uword *p;
  api_main_t *am = &api_main;
  vl_api_msg_range_t *rp;
  u8 name[64];
  u16 first_msg_id = ~0;
  int rv = -7;			/* VNET_API_ERROR_INVALID_VALUE */

  q = vl_api_client_index_to_input_queue (mp->client_index);
  if (!q)
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
  vl_msg_api_send_shmem (q, (u8 *) & rmp);
}

#define foreach_vlib_api_msg                    \
_(MEMCLNT_CREATE, memclnt_create)               \
_(MEMCLNT_DELETE, memclnt_delete)               \
_(GET_FIRST_MSG_ID, get_first_msg_id)

/*
 * vl_api_init
 */
static int
memory_api_init (char *region_name)
{
  int rv;
  vl_msg_api_msg_config_t cfg;
  vl_msg_api_msg_config_t *c = &cfg;

  memset (c, 0, sizeof (*c));

  if ((rv = vl_map_shmem (region_name, 1 /* is_vlib */ )) < 0)
    return rv;

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

static void memclnt_queue_callback (vlib_main_t * vm);

static uword
memclnt_process (vlib_main_t * vm,
		 vlib_node_runtime_t * node, vlib_frame_t * f)
{
  uword mp;
  vl_shmem_hdr_t *shm;
  unix_shared_memory_queue_t *q;
  clib_error_t *e;
  int rv;
  api_main_t *am = &api_main;
  f64 dead_client_scan_time;
  f64 sleep_time, start_time;
  f64 vector_rate;

  vlib_set_queue_signal_callback (vm, memclnt_queue_callback);

  if ((rv = memory_api_init (am->region_name)) < 0)
    {
      clib_warning ("memory_api_init returned %d, wait for godot...", rv);
      vlib_process_suspend (vm, 1e70);
    }

  shm = am->shmem_hdr;
  ASSERT (shm);
  q = shm->vl_input_queue;
  ASSERT (q);

  e = vlib_call_init_exit_functions
    (vm, vm->api_init_function_registrations, 1 /* call_once */ );
  if (e)
    clib_error_report (e);

  sleep_time = 20.0;
  dead_client_scan_time = vlib_time_now (vm) + 20.0;

  /* $$$ pay attention to frame size, control CPU usage */
  while (1)
    {
      uword event_type __attribute__ ((unused));
      i8 *headp;
      int need_broadcast;

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
	  pthread_mutex_lock (&q->mutex);
	  if (q->cursize == 0)
	    {
	      vm->api_queue_nonempty = 0;
	      pthread_mutex_unlock (&q->mutex);

	      if (TRACE_VLIB_MEMORY_QUEUE)
		{
                  /* *INDENT-OFF* */
                  ELOG_TYPE_DECLARE (e) =
                    {
                      .format = "q-underflow: len %d",
                      .format_args = "i4",
                    };
                  /* *INDENT-ON* */
		  struct
		  {
		    u32 len;
		  } *ed;
		  ed = ELOG_DATA (&vm->elog_main, e);
		  ed->len = 0;
		}
	      sleep_time = 20.0;
	      break;
	    }

	  headp = (i8 *) (q->data + sizeof (uword) * q->head);
	  clib_memcpy (&mp, headp, sizeof (uword));

	  q->head++;
	  need_broadcast = (q->cursize == q->maxsize / 2);
	  q->cursize--;

	  if (PREDICT_FALSE (q->head == q->maxsize))
	    q->head = 0;
	  pthread_mutex_unlock (&q->mutex);
	  if (need_broadcast)
	    (void) pthread_cond_broadcast (&q->condvar);

	  vl_msg_api_handler_with_vm_node (am, (void *) mp, vm, node);

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

      event_type = vlib_process_wait_for_event_or_clock (vm, sleep_time);
      vm->queue_signal_pending = 0;
      vlib_process_get_events (vm, 0 /* event_data */ );

      if (vlib_time_now (vm) > dead_client_scan_time)
	{
	  vl_api_registration_t **regpp;
	  vl_api_registration_t *regp;
	  unix_shared_memory_queue_t *q;
	  static u32 *dead_indices;
	  static u32 *confused_indices;

	  vec_reset_length (dead_indices);
	  vec_reset_length (confused_indices);

          /* *INDENT-OFF* */
          pool_foreach (regpp, am->vl_clients,
          ({
            regp = *regpp;
            if (regp)
              {
                q = regp->vl_input_queue;
                if (kill (q->consumer_pid, 0) < 0)
                  {
                    vec_add1(dead_indices, regpp - am->vl_clients);
                  }
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

	  if (PREDICT_FALSE (vec_len (dead_indices) > 0))
	    {
	      int i;
	      svm_region_t *svm;
	      void *oldheap;

	      /* Allow the application to clean up its registrations */
	      for (i = 0; i < vec_len (dead_indices); i++)
		{
		  regpp = pool_elt_at_index (am->vl_clients, dead_indices[i]);
		  if (regpp)
		    {
		      u32 handle;

		      handle = vl_msg_api_handle_from_index_and_epoch
			(dead_indices[i], shm->application_restarts);
		      (void) vl_api_memclnt_delete_callback (handle);
		    }
		}

	      svm = am->vlib_rp;
	      pthread_mutex_lock (&svm->mutex);
	      oldheap = svm_push_data_heap (svm);

	      for (i = 0; i < vec_len (dead_indices); i++)
		{
		  regpp = pool_elt_at_index (am->vl_clients, dead_indices[i]);
		  if (regpp)
		    {
		      /* Poison the old registration */
		      memset (*regpp, 0xF3, sizeof (**regpp));
		      clib_mem_free (*regpp);
		      /* no dangling references, please */
		      *regpp = 0;
		    }
		  else
		    {
		      svm_pop_heap (oldheap);
		      clib_warning ("Duplicate free, client index %d",
				    regpp - am->vl_clients);
		      oldheap = svm_push_data_heap (svm);
		    }
		}

	      svm_client_scan_this_region_nolock (am->vlib_rp);

	      pthread_mutex_unlock (&svm->mutex);
	      svm_pop_heap (oldheap);
	      for (i = 0; i < vec_len (dead_indices); i++)
		pool_put_index (am->vl_clients, dead_indices[i]);
	    }

	  dead_client_scan_time = vlib_time_now (vm) + 20.0;
	}

      if (TRACE_VLIB_MEMORY_QUEUE)
	{
          /* *INDENT-OFF* */
          ELOG_TYPE_DECLARE (e) = {
            .format = "q-awake: len %d",
            .format_args = "i4",
          };
          /* *INDENT-ON* */
	  struct
	  {
	    u32 len;
	  } *ed;
	  ed = ELOG_DATA (&vm->elog_main, e);
	  ed->len = q->cursize;
	}
    }

  return 0;
}

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

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (cli_show_api_histogram_command, static) = {
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

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (cli_clear_api_histogram_command, static) = {
    .path = "clear api histogram",
    .short_help = "clear api histogram",
    .function = vl_api_clear_histogram_command,
};
/* *INDENT-ON* */


/* *INDENT-OFF* */
VLIB_REGISTER_NODE (memclnt_node,static) = {
    .function = memclnt_process,
    .type = VLIB_NODE_TYPE_PROCESS,
    .name = "api-rx-from-ring",
    .state = VLIB_NODE_STATE_DISABLED,
};
/* *INDENT-ON* */

static void
memclnt_queue_callback (vlib_main_t * vm)
{
  static volatile int *cursizep;

  if (PREDICT_FALSE (cursizep == 0))
    {
      api_main_t *am = &api_main;
      vl_shmem_hdr_t *shmem_hdr = am->shmem_hdr;
      unix_shared_memory_queue_t *q;

      if (shmem_hdr == 0)
	return;

      q = shmem_hdr->vl_input_queue;
      if (q == 0)
	return;
      cursizep = &q->cursize;
    }

  if (*cursizep >= 1)
    {
      vm->queue_signal_pending = 1;
      vm->api_queue_nonempty = 1;
      vlib_process_signal_event (vm, memclnt_node.index,
				 /* event_type */ 0, /* event_data */ 0);
    }
}

void
vl_enable_disable_memory_api (vlib_main_t * vm, int enable)
{
  vlib_node_set_state (vm, memclnt_node.index,
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

static clib_error_t *
setup_memclnt_exit (vlib_main_t * vm)
{
  atexit (vl_unmap_shmem);
  return 0;
}

VLIB_INIT_FUNCTION (setup_memclnt_exit);


static clib_error_t *
vl_api_ring_command (vlib_main_t * vm,
		     unformat_input_t * input, vlib_cli_command_t * cli_cmd)
{
  int i;
  ring_alloc_t *ap;
  vl_shmem_hdr_t *shmem_hdr;
  api_main_t *am = &api_main;

  shmem_hdr = am->shmem_hdr;

  if (shmem_hdr == 0)
    {
      vlib_cli_output (vm, "Shared memory segment not initialized...\n");
      return 0;
    }

  vlib_cli_output (vm, "%8s %8s %8s %8s %8s\n",
		   "Owner", "Size", "Nitems", "Hits", "Misses");

  ap = shmem_hdr->vl_rings;

  for (i = 0; i < vec_len (shmem_hdr->vl_rings); i++)
    {
      vlib_cli_output (vm, "%8s %8d %8d %8d %8d\n",
		       "vlib", ap->size, ap->nitems, ap->hits, ap->misses);
      ap++;
    }

  ap = shmem_hdr->client_rings;

  for (i = 0; i < vec_len (shmem_hdr->client_rings); i++)
    {
      vlib_cli_output (vm, "%8s %8d %8d %8d %8d\n",
		       "clnt", ap->size, ap->nitems, ap->hits, ap->misses);
      ap++;
    }

  vlib_cli_output (vm, "%d ring miss fallback allocations\n",
		   am->ring_misses);

  vlib_cli_output (vm, "%d application restarts, %d reclaimed msgs\n",
		   shmem_hdr->application_restarts,
		   shmem_hdr->restart_reclaims);
  return 0;
}

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
  unix_shared_memory_queue_t *q;
  char *health;
  api_main_t *am = &api_main;
  u32 *confused_indices = 0;

  if (!pool_elts (am->vl_clients))
    goto socket_clients;
  vlib_cli_output (vm, "Shared memory clients");
  vlib_cli_output (vm, "%16s %8s %14s %18s %s",
		   "Name", "PID", "Queue Length", "Queue VA", "Health");

  /* *INDENT-OFF* */
  pool_foreach (regpp, am->vl_clients,
  ({
    regp = *regpp;

    if (regp)
      {
        q = regp->vl_input_queue;
        if (kill (q->consumer_pid, 0) < 0)
          {
            health = "DEAD";
          }
        else
          {
            health = "alive";
          }
        vlib_cli_output (vm, "%16s %8d %14d 0x%016llx %s\n",
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

  // check if rx_trace and tx_trace are not null pointers

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
VLIB_CLI_COMMAND (cli_show_api_command, static) = {
    .path = "show api",
    .short_help = "Show API information",
};
/* *INDENT-ON* */

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (cli_show_api_ring_command, static) = {
    .path = "show api ring-stats",
    .short_help = "Message ring statistics",
    .function = vl_api_ring_command,
};
/* *INDENT-ON* */

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (cli_show_api_clients_command, static) = {
    .path = "show api clients",
    .short_help = "Client information",
    .function = vl_api_client_command,
};
/* *INDENT-ON* */

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (cli_show_api_status_command, static) = {
    .path = "show api status",
    .short_help = "Show API trace status",
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

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (cli_show_api_message_table_command, static) = {
    .path = "show api message-table",
    .short_help = "Message Table",
    .function = vl_api_message_table_command,
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

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (trace, static) = {
    .path = "set api-trace",
    .short_help = "API trace",
    .function = vl_api_trace_command,
};
/* *INDENT-ON* */

clib_error_t *
vlibmemory_init (vlib_main_t * vm)
{
  api_main_t *am = &api_main;
  svm_map_region_args_t _a, *a = &_a;

  memset (a, 0, sizeof (*a));
  a->root_path = am->root_path;
  a->name = SVM_GLOBAL_REGION_NAME;
  a->baseva = (am->global_baseva != 0) ?
    am->global_baseva : SVM_GLOBAL_REGION_BASEVA;
  a->size = (am->global_size != 0) ? am->global_size : SVM_GLOBAL_REGION_SIZE;
  a->flags = SVM_FLAGS_NODATA;
  a->uid = am->api_uid;
  a->gid = am->api_gid;
  a->pvt_heap_size =
    (am->global_pvt_heap_size !=
     0) ? am->global_pvt_heap_size : SVM_PVT_MHEAP_SIZE;

  svm_region_init_args (a);
  return 0;
}

VLIB_INIT_FUNCTION (vlibmemory_init);

void
vl_set_memory_region_name (char *name)
{
  api_main_t *am = &api_main;

  am->region_name = name;
}

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
    s = format (s, "%-20s%9s%9s", "Name", "First-ID", "Last-ID");
  else
    s = format (s, "%-20s%9d%9d", rp->name, rp->first_msg_id,
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

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (cli_show_api_plugin_command, static) = {
    .path = "show api plugin",
    .short_help = "show api plugin",
    .function = vl_api_show_plugin_command,
};
/* *INDENT-ON* */

static void
vl_api_rpc_call_t_handler (vl_api_rpc_call_t * mp)
{
  vl_api_rpc_reply_t *rmp;
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
      unix_shared_memory_queue_t *q =
	vl_api_client_index_to_input_queue (mp->client_index);
      if (q)
	{
	  rmp = vl_msg_api_alloc_as_if_client (sizeof (*rmp));
	  rmp->_vl_msg_id = ntohs (VL_API_RPC_REPLY);
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
vl_api_rpc_reply_t_handler (vl_api_rpc_reply_t * mp)
{
  clib_warning ("unimplemented");
}

void
vl_api_rpc_call_main_thread (void *fp, u8 * data, u32 data_length)
{
  vl_api_rpc_call_t *mp;
  api_main_t *am = &api_main;
  vl_shmem_hdr_t *shmem_hdr = am->shmem_hdr;
  unix_shared_memory_queue_t *q;

  /* Main thread: call the function directly */
  if (os_get_cpu_number () == 0)
    {
      vlib_main_t *vm = vlib_get_main ();
      void (*call_fp) (void *);

      vlib_worker_thread_barrier_sync (vm);

      call_fp = fp;
      call_fp (data);

      vlib_worker_thread_barrier_release (vm);
      return;
    }

  /* Any other thread, actually do an RPC call... */
  mp = vl_msg_api_alloc_as_if_client (sizeof (*mp) + data_length);

  memset (mp, 0, sizeof (*mp));
  clib_memcpy (mp->data, data, data_length);
  mp->_vl_msg_id = ntohs (VL_API_RPC_CALL);
  mp->function = pointer_to_uword (fp);
  mp->need_barrier_sync = 1;

  /*
   * Use the "normal" control-plane mechanism for the main thread.
   * Well, almost. if the main input queue is full, we cannot
   * block. Otherwise, we can expect a barrier sync timeout.
   */
  q = shmem_hdr->vl_input_queue;

  while (pthread_mutex_trylock (&q->mutex))
    vlib_worker_thread_barrier_check ();

  while (PREDICT_FALSE (unix_shared_memory_queue_is_full (q)))
    {
      pthread_mutex_unlock (&q->mutex);
      vlib_worker_thread_barrier_check ();
      while (pthread_mutex_trylock (&q->mutex))
	vlib_worker_thread_barrier_check ();
    }

  vl_msg_api_send_shmem_nolock (q, (u8 *) & mp);

  pthread_mutex_unlock (&q->mutex);
}

#define foreach_rpc_api_msg                     \
_(RPC_CALL,rpc_call)                            \
_(RPC_REPLY,rpc_reply)

static clib_error_t *
rpc_api_hookup (vlib_main_t * vm)
{
#define _(N,n)                                                  \
    vl_msg_api_set_handlers(VL_API_##N, #n,                     \
                           vl_api_##n##_t_handler,              \
                           vl_noop_handler,                     \
                           vl_noop_handler,			\
                           vl_api_##n##_t_print,                \
                           sizeof(vl_api_##n##_t), 0 /* do not trace */);
  foreach_rpc_api_msg;
#undef _
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
