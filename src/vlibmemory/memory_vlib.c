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
#include <sys/stat.h>
#include <fcntl.h>
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
vl_msg_api_send (vl_api_registration_t * rp, u8 * elem)
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

/*
 * vl_api_memclnt_create_internal
 */

u32
vl_api_memclnt_create_internal (char *name, unix_shared_memory_queue_t * q)
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
  unix_shared_memory_queue_t *q;
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

  q = regp->vl_input_queue = (unix_shared_memory_queue_t *) (uword)
    mp->input_queue;

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

static int
call_reaper_functions (u32 client_index)
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

  if (call_reaper_functions (handle))
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

void
vl_api_api_versions_t_handler (vl_api_api_versions_t * mp)
{
  api_main_t *am = &api_main;
  vl_api_api_versions_reply_t *rmp;
  unix_shared_memory_queue_t *q;
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
_(MEMCLNT_CREATE, memclnt_create)                       \
_(MEMCLNT_DELETE, memclnt_delete)                       \
_(GET_FIRST_MSG_ID, get_first_msg_id)                   \
_(MEMCLNT_KEEPALIVE, memclnt_keepalive)                 \
_(MEMCLNT_KEEPALIVE_REPLY, memclnt_keepalive_reply)	\
_(API_VERSIONS, api_versions)

/*
 * vl_api_init
 */
static int
memory_api_init (const char *region_name)
{
  int rv;
  api_main_t *am = &api_main;
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

  /*
   * special-case freeing of memclnt_delete messages, so we can
   * simply munmap pairwise / private API segments...
   */
  am->message_bounce[VL_API_MEMCLNT_DELETE] = 1;
  am->is_mp_safe[VL_API_MEMCLNT_KEEPALIVE_REPLY] = 1;

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

/*
 * Callback to send ourselves a plugin numbering-space trace msg
 */
static void
send_one_plugin_msg_ids_msg (u8 * name, u16 first_msg_id, u16 last_msg_id)
{
  vl_api_trace_plugin_msg_ids_t *mp;
  api_main_t *am = &api_main;
  vl_shmem_hdr_t *shmem_hdr = am->shmem_hdr;
  unix_shared_memory_queue_t *q;

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

static void
send_memclnt_keepalive (vl_api_registration_t * regp, f64 now)
{
  vl_api_memclnt_keepalive_t *mp;
  unix_shared_memory_queue_t *q;
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
  if (unix_shared_memory_queue_add (q, (u8 *) & mp, 1 /* nowait */ ))
    vl_msg_api_free (mp);

  am->vlib_rp = save_vlib_rp;
  am->shmem_hdr = save_shmem_hdr;
}

static void
dead_client_scan (api_main_t * am, vl_shmem_hdr_t * shm, f64 now)
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
                unix_shared_memory_queue_t *q;
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
	      (void) call_reaper_functions (handle);
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
  clib_error_t *socksvr_api_init (vlib_main_t * vm);
  clib_error_t *error;
  int i;
  vl_socket_args_for_process_t *a;
  uword event_type;
  uword *event_data = 0;
  int private_segment_rotor = 0;
  svm_region_t *vlib_rp;
  f64 now;

  vlib_set_queue_signal_callback (vm, memclnt_queue_callback);

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

  shm = am->shmem_hdr;
  ASSERT (shm);
  q = shm->vl_input_queue;
  ASSERT (q);
  /* Make a note so we can always find the primary region easily */
  am->vlib_primary_rp = am->vlib_rp;

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
    {
      int fd, rv;
      u8 *chroot_file;
      u8 *serialized_message_table;

      /*
       * Snapshoot the api message table.
       */
      if (strstr ((char *) am->save_msg_table_filename, "..")
	  || index ((char *) am->save_msg_table_filename, '/'))
	{
	  clib_warning ("illegal save-message-table filename '%s'",
			am->save_msg_table_filename);
	  goto skip_save;
	}

      chroot_file = format (0, "/tmp/%s%c", am->save_msg_table_filename, 0);

      fd = creat ((char *) chroot_file, 0644);

      if (fd < 0)
	{
	  clib_unix_warning ("creat");
	  goto skip_save;
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

skip_save:

  /* $$$ pay attention to frame size, control CPU usage */
  while (1)
    {
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

      /*
       * see if we have any private api shared-memory segments
       * If so, push required context variables, and process
       * a message.
       */
      if (PREDICT_FALSE (vec_len (am->vlib_private_rps)))
	{
	  unix_shared_memory_queue_t *save_vlib_input_queue = q;
	  vl_shmem_hdr_t *save_shmem_hdr = am->shmem_hdr;
	  svm_region_t *save_vlib_rp = am->vlib_rp;

	  vlib_rp = am->vlib_rp = am->vlib_private_rps[private_segment_rotor];

	  am->shmem_hdr = (void *) vlib_rp->user_ctx;
	  q = am->shmem_hdr->vl_input_queue;

	  pthread_mutex_lock (&q->mutex);
	  if (q->cursize > 0)
	    {
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

	      pthread_mutex_unlock (&q->mutex);

	      vl_msg_api_handler_with_vm_node (am, (void *) mp, vm, node);
	    }
	  else
	    pthread_mutex_unlock (&q->mutex);

	  q = save_vlib_input_queue;
	  am->shmem_hdr = save_shmem_hdr;
	  am->vlib_rp = save_vlib_rp;

	  private_segment_rotor++;
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
	  break;

	case SOCKET_READ_EVENT:
	  for (i = 0; i < vec_len (event_data); i++)
	    {
	      a = pool_elt_at_index (socket_main.process_args, event_data[i]);
	      vl_api_socket_process_msg (a->clib_file, a->regp,
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
	  dead_client_scan (am, shm, now);
	  dead_client_scan_time = vlib_time_now (vm) + 10.0;
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
/* *INDENT-OFF* */
VLIB_REGISTER_NODE (memclnt_node) =
{
  .function = memclnt_process,
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
      unix_shared_memory_queue_t *q;

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
	  vlib_process_signal_event (vm, memclnt_node.index,
				     /* event_type */ QUEUE_SIGNAL_EVENT,
				     /* event_data */ 0);
	  break;
	}
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
        if (regp->unanswered_pings > 0)
          health = "questionable";
        else
          health = "OK";

        q = regp->vl_input_queue;

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
VLIB_CLI_COMMAND (cli_show_api_command, static) =
{
  .path = "show api",
  .short_help = "Show API information",
};
/* *INDENT-ON* */

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
    am->global_baseva : SVM_GLOBAL_REGION_BASEVA;
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
      unix_shared_memory_queue_t *q =
	vl_api_client_index_to_input_queue (mp->client_index);
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

always_inline void
vl_api_rpc_call_main_thread_inline (void *fp, u8 * data, u32 data_length,
				    u8 force_rpc)
{
  vl_api_rpc_call_t *mp;
  api_main_t *am = &api_main;
  vl_shmem_hdr_t *shmem_hdr = am->shmem_hdr;
  unix_shared_memory_queue_t *q;

  /* Main thread: call the function directly */
  if ((force_rpc == 0) && (vlib_get_thread_index () == 0))
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
VLIB_CONFIG_FUNCTION (api_config_fn, "api-trace");

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
