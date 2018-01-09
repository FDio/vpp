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
#include <signal.h>

#include <vlib/vlib.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vlibmemory/memory_api.h>

#include <vlibmemory/vl_memory_msg_enum.h>	/* enumerate all vlib messages */

#define vl_typedefs		/* define message structures */
#include <vlibmemory/vl_memory_api_h.h>
#undef vl_typedefs

/* instantiate all the print functions we know about */
#define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)
#define vl_printfun
#include <vlibmemory/vl_memory_api_h.h>
#undef vl_printfun

/* instantiate all the endian swap functions we know about */
#define vl_endianfun
#include <vlibmemory/vl_memory_api_h.h>
#undef vl_endianfun

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

volatile int **vl_api_queue_cursizes;

static void
memclnt_queue_callback (vlib_main_t * vm)
{
  int i;
  api_main_t *am = &api_main;

  if (PREDICT_FALSE (vec_len (vl_api_queue_cursizes) !=
		     1 + vec_len (am->vlib_private_rps)))
    {
      vl_shmem_hdr_t *shmem_hdr = am->shmem_hdr;
      svm_queue_t *q;

      if (shmem_hdr == 0)
	return;

      q = shmem_hdr->vl_input_queue;
      if (q == 0)
	return;

      vec_add1 (vl_api_queue_cursizes, &q->cursize);

      for (i = 0; i < vec_len (am->vlib_private_rps); i++)
	{
	  svm_region_t *vlib_rp = am->vlib_private_rps[i];

	  shmem_hdr = (void *) vlib_rp->user_ctx;
	  q = shmem_hdr->vl_input_queue;
	  vec_add1 (vl_api_queue_cursizes, &q->cursize);
	}
    }

  for (i = 0; i < vec_len (vl_api_queue_cursizes); i++)
    {
      if (*vl_api_queue_cursizes[i])
	{
	  vm->queue_signal_pending = 1;
	  vm->api_queue_nonempty = 1;
	  vlib_process_signal_event (vm, vl_api_clnt_node.index,
				     /* event_type */ QUEUE_SIGNAL_EVENT,
				     /* event_data */ 0);
	  break;
	}
    }
}

/*
 * vl_api_memclnt_create_internal
 */
u32
vl_api_memclnt_create_internal (char *name, svm_queue_t * q)
{
  vl_api_registration_t **regpp;
  vl_api_registration_t *regp;
  svm_region_t *svm;
  void *oldheap;
  api_main_t *am = &api_main;

  ASSERT (vlib_get_thread_index () == 0);
  pool_get (am->vl_clients, regpp);

  svm = am->vlib_rp;

  pthread_mutex_lock (&svm->mutex);
  oldheap = svm_push_data_heap (svm);
  *regpp = clib_mem_alloc (sizeof (vl_api_registration_t));

  regp = *regpp;
  memset (regp, 0, sizeof (*regp));
  regp->registration_type = REGISTRATION_TYPE_SHMEM;
  regp->vl_api_registration_pool_index = regpp - am->vl_clients;
  regp->vlib_rp = svm;
  regp->shmem_hdr = am->shmem_hdr;

  regp->vl_input_queue = q;
  regp->name = format (0, "%s%c", name, 0);

  pthread_mutex_unlock (&svm->mutex);
  svm_pop_heap (oldheap);
  return vl_msg_api_handle_from_index_and_epoch
    (regp->vl_api_registration_pool_index,
     am->shmem_hdr->application_restarts);
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
  svm_queue_t *q;
  int rv = 0;
  void *oldheap;
  api_main_t *am = &api_main;

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

  pthread_mutex_lock (&svm->mutex);
  oldheap = svm_push_data_heap (svm);
  *regpp = clib_mem_alloc (sizeof (vl_api_registration_t));

  regp = *regpp;
  memset (regp, 0, sizeof (*regp));
  regp->registration_type = REGISTRATION_TYPE_SHMEM;
  regp->vl_api_registration_pool_index = regpp - am->vl_clients;
  regp->vlib_rp = svm;
  regp->shmem_hdr = am->shmem_hdr;

  q = regp->vl_input_queue = (svm_queue_t *) (uword) mp->input_queue;

  regp->name = format (0, "%s", mp->name);
  vec_add1 (regp->name, 0);

  if (am->serialized_message_table_in_shmem == 0)
    am->serialized_message_table_in_shmem =
      vl_api_serialize_message_table (am, 0);

  pthread_mutex_unlock (&svm->mutex);
  svm_pop_heap (oldheap);

  rp = vl_msg_api_alloc (sizeof (*rp));
  rp->_vl_msg_id = ntohs (VL_API_MEMCLNT_CREATE_REPLY);
  rp->handle = (uword) regp;
  rp->index = vl_msg_api_handle_from_index_and_epoch
    (regp->vl_api_registration_pool_index,
     am->shmem_hdr->application_restarts);
  rp->context = mp->context;
  rp->response = ntohl (rv);
  rp->message_table =
    pointer_to_uword (am->serialized_message_table_in_shmem);

  vl_msg_api_send_shmem (q, (u8 *) & rp);
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

  if (vl_api_call_reaper_functions (handle))
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
      int i;
      regp = *regpp;
      svm = am->vlib_rp;
      int private_registration = 0;

      /*
       * Note: the API message handling path will set am->vlib_rp
       * as appropriate for pairwise / private memory segments
       */
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

      /* For horizontal scaling, add a hash table... */
      for (i = 0; i < vec_len (am->vlib_private_rps); i++)
	{
	  /* Is this a pairwise / private API segment? */
	  if (am->vlib_private_rps[i] == svm)
	    {
	      /* Note: account for the memfd header page */
	      u64 virtual_base = svm->virtual_base - MMAP_PAGESIZE;
	      u64 virtual_size = svm->virtual_size + MMAP_PAGESIZE;

	      /*
	       * Kill the registration pool element before we make
	       * the index vanish forever
	       */
	      pool_put_index (am->vl_clients,
			      regp->vl_api_registration_pool_index);

	      vec_delete (am->vlib_private_rps, 1, i);
	      /* Kill it, accounting for the memfd header page */
	      if (munmap ((void *) virtual_base, virtual_size) < 0)
		clib_unix_warning ("munmap");
	      /* Reset the queue-length-address cache */
	      vec_reset_length (vl_api_queue_cursizes);
	      private_registration = 1;
	      break;
	    }
	}

      /* No dangling references, please */
      *regpp = 0;

      if (private_registration == 0)
	{
	  pool_put_index (am->vl_clients,
			  regp->vl_api_registration_pool_index);
	  pthread_mutex_lock (&svm->mutex);
	  oldheap = svm_push_data_heap (svm);
	  /* Poison the old registration */
	  memset (regp, 0xF1, sizeof (*regp));
	  clib_mem_free (regp);
	  pthread_mutex_unlock (&svm->mutex);
	  svm_pop_heap (oldheap);
	  /*
	   * These messages must be freed manually, since they're set up
	   * as "bounce" messages. In the private_registration == 1 case,
	   * we kill the shared-memory segment which contains the message
	   * with munmap.
	   */
	  vl_msg_api_free (mp);
	}
    }
  else
    {
      clib_warning ("unknown client ID %d", mp->index);
    }
}

/**
 * client answered a ping, stave off the grim reaper...
 */
void
  vl_api_memclnt_keepalive_reply_t_handler
  (vl_api_memclnt_keepalive_reply_t * mp)
{
  vl_api_registration_t *regp;
  vlib_main_t *vm = vlib_get_main ();

  regp = vl_api_client_index_to_registration (mp->context);
  if (regp)
    {
      regp->last_heard = vlib_time_now (vm);
      regp->unanswered_pings = 0;
    }
  else
    clib_warning ("BUG: anonymous memclnt_keepalive_reply");
}

/**
 * We can send ourselves these messages if someone uses the
 * builtin binary api test tool...
 */
static void
vl_api_memclnt_keepalive_t_handler (vl_api_memclnt_keepalive_t * mp)
{
  vl_api_memclnt_keepalive_reply_t *rmp;
  api_main_t *am;
  vl_shmem_hdr_t *shmem_hdr;

  am = &api_main;
  shmem_hdr = am->shmem_hdr;

  rmp = vl_msg_api_alloc_as_if_client (sizeof (*rmp));
  memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (VL_API_MEMCLNT_KEEPALIVE_REPLY);
  rmp->context = mp->context;
  vl_msg_api_send_shmem (shmem_hdr->vl_input_queue, (u8 *) & rmp);
}

#define foreach_vlib_api_msg                            \
_(MEMCLNT_CREATE, memclnt_create)                       \
_(MEMCLNT_DELETE, memclnt_delete)                       \
_(MEMCLNT_KEEPALIVE, memclnt_keepalive)                 \
_(MEMCLNT_KEEPALIVE_REPLY, memclnt_keepalive_reply)	\

/*
 * memory_api_init
 */
int
vl_mem_api_init (const char *region_name)
{
  int rv;
  api_main_t *am = &api_main;
  vl_msg_api_msg_config_t cfg;
  vl_msg_api_msg_config_t *c = &cfg;
  vl_shmem_hdr_t *shm;
  vlib_main_t *vm = vlib_get_main ();

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

  /*
   * special-case freeing of memclnt_delete messages, so we can
   * simply munmap pairwise / private API segments...
   */
  am->message_bounce[VL_API_MEMCLNT_DELETE] = 1;
  am->is_mp_safe[VL_API_MEMCLNT_KEEPALIVE_REPLY] = 1;

  vlib_set_queue_signal_callback (vm, memclnt_queue_callback);

  shm = am->shmem_hdr;
  ASSERT (shm && shm->vl_input_queue);

  /* Make a note so we can always find the primary region easily */
  am->vlib_primary_rp = am->vlib_rp;

  return 0;
}

static void
send_memclnt_keepalive (vl_api_registration_t * regp, f64 now)
{
  vl_api_memclnt_keepalive_t *mp;
  svm_queue_t *q;
  api_main_t *am = &api_main;
  svm_region_t *save_vlib_rp = am->vlib_rp;
  vl_shmem_hdr_t *save_shmem_hdr = am->shmem_hdr;

  q = regp->vl_input_queue;

  /*
   * If the queue head is moving, assume that the client is processing
   * messages and skip the ping. This heuristic may fail if the queue
   * is in the same position as last time, net of wrapping; in which
   * case, the client will receive a keepalive.
   */
  if (regp->last_queue_head != q->head)
    {
      regp->last_heard = now;
      regp->unanswered_pings = 0;
      regp->last_queue_head = q->head;
      return;
    }

  /*
   * push/pop shared memory segment, so this routine
   * will work with "normal" as well as "private segment"
   * memory clients..
   */

  am->vlib_rp = regp->vlib_rp;
  am->shmem_hdr = regp->shmem_hdr;

  mp = vl_msg_api_alloc (sizeof (*mp));
  memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = clib_host_to_net_u16 (VL_API_MEMCLNT_KEEPALIVE);
  mp->context = mp->client_index =
    vl_msg_api_handle_from_index_and_epoch
    (regp->vl_api_registration_pool_index,
     am->shmem_hdr->application_restarts);

  regp->unanswered_pings++;

  /* Failure-to-send due to a stuffed queue is absolutely expected */
  if (svm_queue_add (q, (u8 *) & mp, 1 /* nowait */ ))
    vl_msg_api_free (mp);

  am->vlib_rp = save_vlib_rp;
  am->shmem_hdr = save_shmem_hdr;
}

void
vl_mem_api_dead_client_scan (api_main_t * am, vl_shmem_hdr_t * shm, f64 now)
{
  vl_api_registration_t **regpp;
  vl_api_registration_t *regp;
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
        /* If we haven't heard from this client recently... */
        if (regp->last_heard < (now - 10.0))
          {
            if (regp->unanswered_pings == 2)
              {
                svm_queue_t *q;
                q = regp->vl_input_queue;
                if (kill (q->consumer_pid, 0) >=0)
                  {
                    clib_warning ("REAPER: lazy binary API client '%s'",
                                  regp->name);
                    regp->unanswered_pings = 0;
                    regp->last_heard = now;
                  }
                else
                  {
                    clib_warning ("REAPER: binary API client '%s' died",
                                  regp->name);
                    vec_add1(dead_indices, regpp - am->vl_clients);
                  }
              }
            else
              send_memclnt_keepalive (regp, now);
          }
        else
          regp->unanswered_pings = 0;
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
	      (void) vl_api_call_reaper_functions (handle);
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
	      /* Is this a pairwise SVM segment? */
	      if ((*regpp)->vlib_rp != svm)
		{
		  int i;
		  svm_region_t *dead_rp = (*regpp)->vlib_rp;
		  /* Note: account for the memfd header page */
		  u64 virtual_base = dead_rp->virtual_base - MMAP_PAGESIZE;
		  u64 virtual_size = dead_rp->virtual_size + MMAP_PAGESIZE;

		  /* For horizontal scaling, add a hash table... */
		  for (i = 0; i < vec_len (am->vlib_private_rps); i++)
		    if (am->vlib_private_rps[i] == dead_rp)
		      {
			vec_delete (am->vlib_private_rps, 1, i);
			goto found;
		      }
		  clib_warning ("private rp %llx AWOL", dead_rp);

		found:
		  /* Kill it, accounting for the memfd header page */
		  if (munmap ((void *) virtual_base, virtual_size) < 0)
		    clib_unix_warning ("munmap");
		  /* Reset the queue-length-address cache */
		  vec_reset_length (vl_api_queue_cursizes);
		}
	      else
		{
		  /* Poison the old registration */
		  memset (*regpp, 0xF3, sizeof (**regpp));
		  clib_mem_free (*regpp);
		}
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
}

static inline int
void_mem_api_handle_msg_i (api_main_t * am, vlib_main_t * vm,
			   vlib_node_runtime_t * node, svm_queue_t * q)
{
  uword mp;
  if (!svm_queue_sub2 (q, (u8 *) & mp))
    {
      vl_msg_api_handler_with_vm_node (am, (void *) mp, vm, node);
      return 0;
    }
  return -1;
}

int
vl_mem_api_handle_msg_main (vlib_main_t * vm, vlib_node_runtime_t * node)
{
  api_main_t *am = &api_main;
  return void_mem_api_handle_msg_i (am, vm, node,
				    am->shmem_hdr->vl_input_queue);
}

int
vl_mem_api_handle_msg_private (vlib_main_t * vm, vlib_node_runtime_t * node,
			       u32 reg_index)
{
  api_main_t *am = &api_main;
  vl_shmem_hdr_t *save_shmem_hdr = am->shmem_hdr;
  svm_region_t *vlib_rp, *save_vlib_rp = am->vlib_rp;
  svm_queue_t *q;
  int rv;

  vlib_rp = am->vlib_rp = am->vlib_private_rps[reg_index];

  am->shmem_hdr = (void *) vlib_rp->user_ctx;
  q = am->shmem_hdr->vl_input_queue;

  rv = void_mem_api_handle_msg_i (am, vm, node, q);

  am->shmem_hdr = save_shmem_hdr;
  am->vlib_rp = save_vlib_rp;

  return rv;
}

vl_api_registration_t *
vl_mem_api_client_index_to_registration (u32 handle)
{
  vl_api_registration_t **regpp;
  vl_api_registration_t *regp;
  api_main_t *am = &api_main;
  u32 index;

  index = vl_msg_api_handle_get_index (handle);
  if ((am->shmem_hdr->application_restarts & VL_API_EPOCH_MASK)
      != vl_msg_api_handle_get_epoch (handle))
    {
      vl_msg_api_increment_missing_client_counter ();
      return 0;
    }

  regpp = am->vl_clients + index;

  if (pool_is_free (am->vl_clients, regpp))
    {
      vl_msg_api_increment_missing_client_counter ();
      return 0;
    }
  regp = *regpp;
  return (regp);
}

svm_queue_t *
vl_api_client_index_to_input_queue (u32 index)
{
  vl_api_registration_t *regp;
  api_main_t *am = &api_main;

  /* Special case: vlib trying to send itself a message */
  if (index == (u32) ~ 0)
    return (am->shmem_hdr->vl_input_queue);

  regp = vl_mem_api_client_index_to_registration (index);
  if (!regp)
    return 0;
  return (regp->vl_input_queue);
}

static clib_error_t *
setup_memclnt_exit (vlib_main_t * vm)
{
  atexit (vl_unmap_shmem);
  return 0;
}

VLIB_INIT_FUNCTION (setup_memclnt_exit);

u8 *
format_api_message_rings (u8 * s, va_list * args)
{
  api_main_t *am = va_arg (*args, api_main_t *);
  vl_shmem_hdr_t *shmem_hdr = va_arg (*args, vl_shmem_hdr_t *);
  int main_segment = va_arg (*args, int);
  ring_alloc_t *ap;
  int i;

  if (shmem_hdr == 0)
    return format (s, "%8s %8s %8s %8s %8s\n",
		   "Owner", "Size", "Nitems", "Hits", "Misses");

  ap = shmem_hdr->vl_rings;

  for (i = 0; i < vec_len (shmem_hdr->vl_rings); i++)
    {
      s = format (s, "%8s %8d %8d %8d %8d\n",
		  "vlib", ap->size, ap->nitems, ap->hits, ap->misses);
      ap++;
    }

  ap = shmem_hdr->client_rings;

  for (i = 0; i < vec_len (shmem_hdr->client_rings); i++)
    {
      s = format (s, "%8s %8d %8d %8d %8d\n",
		  "clnt", ap->size, ap->nitems, ap->hits, ap->misses);
      ap++;
    }

  if (main_segment)
    {
      s = format (s, "%d ring miss fallback allocations\n", am->ring_misses);
      s = format
	(s,
	 "%d application restarts, %d reclaimed msgs, %d garbage collects\n",
	 shmem_hdr->application_restarts, shmem_hdr->restart_reclaims,
	 shmem_hdr->garbage_collects);
    }
  return s;
}

static clib_error_t *
vl_api_ring_command (vlib_main_t * vm,
		     unformat_input_t * input, vlib_cli_command_t * cli_cmd)
{
  int i;
  vl_shmem_hdr_t *shmem_hdr;
  api_main_t *am = &api_main;

  /* First, dump the primary region rings.. */

  if (am->vlib_primary_rp == 0 || am->vlib_primary_rp->user_ctx == 0)
    {
      vlib_cli_output (vm, "Shared memory segment not initialized...\n");
      return 0;
    }

  shmem_hdr = (void *) am->vlib_primary_rp->user_ctx;

  vlib_cli_output (vm, "Main API segment rings:");

  vlib_cli_output (vm, "%U", format_api_message_rings, am,
		   0 /* print header */ , 0 /* notused */ );

  vlib_cli_output (vm, "%U", format_api_message_rings, am,
		   shmem_hdr, 1 /* main segment */ );

  for (i = 0; i < vec_len (am->vlib_private_rps); i++)
    {
      svm_region_t *vlib_rp = am->vlib_private_rps[i];
      shmem_hdr = (void *) vlib_rp->user_ctx;
      vl_api_registration_t **regpp;
      vl_api_registration_t *regp = 0;

      /* For horizontal scaling, add a hash table... */
      /* *INDENT-OFF* */
      pool_foreach (regpp, am->vl_clients,
      ({
        regp = *regpp;
        if (regp && regp->vlib_rp == vlib_rp)
          {
            vlib_cli_output (vm, "%s segment rings:", regp->name);
            goto found;
          }
      }));
      vlib_cli_output (vm, "regp %llx not found?", regp);
      continue;
      /* *INDENT-ON* */
    found:
      vlib_cli_output (vm, "%U", format_api_message_rings, am,
		       0 /* print header */ , 0 /* notused */ );
      vlib_cli_output (vm, "%U", format_api_message_rings, am,
		       shmem_hdr, 0 /* main segment */ );
    }

  return 0;
}

/*?
 * Display binary api message allocation ring statistics
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (cli_show_api_ring_command, static) =
{
  .path = "show api ring-stats",
  .short_help = "Message ring statistics",
  .function = vl_api_ring_command,
};
/* *INDENT-ON* */

clib_error_t *
vlibmemory_init (vlib_main_t * vm)
{
  api_main_t *am = &api_main;
  svm_map_region_args_t _a, *a = &_a;
  clib_error_t *error;

  memset (a, 0, sizeof (*a));
  a->root_path = am->root_path;
  a->name = SVM_GLOBAL_REGION_NAME;
  a->baseva = (am->global_baseva != 0) ?
    am->global_baseva : +svm_get_global_region_base_va ();
  a->size = (am->global_size != 0) ? am->global_size : SVM_GLOBAL_REGION_SIZE;
  a->flags = SVM_FLAGS_NODATA;
  a->uid = am->api_uid;
  a->gid = am->api_gid;
  a->pvt_heap_size =
    (am->global_pvt_heap_size !=
     0) ? am->global_pvt_heap_size : SVM_PVT_MHEAP_SIZE;

  svm_region_init_args (a);

  error = vlib_call_init_function (vm, vlibsocket_init);

  return error;
}

VLIB_INIT_FUNCTION (vlibmemory_init);

void
vl_set_memory_region_name (const char *name)
{
  api_main_t *am = &api_main;
  am->region_name = name;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
