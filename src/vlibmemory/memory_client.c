/*
 *------------------------------------------------------------------
 * memory_client.c - API message handling, client code.
 *
 * Copyright (c) 2010 Cisco and/or its affiliates.
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
#include <setjmp.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <signal.h>
#include <pthread.h>
#include <unistd.h>
#include <time.h>
#include <fcntl.h>
#include <string.h>
#include <vppinfra/clib.h>
#include <vppinfra/vec.h>
#include <vppinfra/hash.h>
#include <vppinfra/bitmap.h>
#include <vppinfra/fifo.h>
#include <vppinfra/time.h>
#include <vppinfra/mheap.h>
#include <vppinfra/heap.h>
#include <vppinfra/pool.h>
#include <vppinfra/format.h>

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vlibmemory/api.h>

#include <vlibmemory/vl_memory_msg_enum.h>

#define vl_typedefs		/* define message structures */
#include <vlibmemory/vl_memory_api_h.h>
#undef vl_typedefs

#define vl_endianfun		/* define message structures */
#include <vlibmemory/vl_memory_api_h.h>
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...) clib_warning (__VA_ARGS__)
#define vl_printfun
#include <vlibmemory/vl_memory_api_h.h>
#undef vl_printfun

typedef struct
{
  u8 rx_thread_jmpbuf_valid;
  u8 connected_to_vlib;
  jmp_buf rx_thread_jmpbuf;
  pthread_t rx_thread_handle;
  /* Plugin message base lookup scheme */
  volatile u8 first_msg_id_reply_ready;
  u16 first_msg_id_reply;
} memory_client_main_t;

memory_client_main_t memory_client_main;

static void *
rx_thread_fn (void *arg)
{
  unix_shared_memory_queue_t *q;
  memory_client_main_t *mm = &memory_client_main;
  api_main_t *am = &api_main;

  q = am->vl_input_queue;

  /* So we can make the rx thread terminate cleanly */
  if (setjmp (mm->rx_thread_jmpbuf) == 0)
    {
      mm->rx_thread_jmpbuf_valid = 1;
      while (1)
	{
	  vl_msg_api_queue_handler (q);
	}
    }
  pthread_exit (0);
}

static void
vl_api_rx_thread_exit_t_handler (vl_api_rx_thread_exit_t * mp)
{
  memory_client_main_t *mm = &memory_client_main;
  vl_msg_api_free (mp);
  longjmp (mm->rx_thread_jmpbuf, 1);
}

static void
vl_api_memclnt_create_reply_t_handler (vl_api_memclnt_create_reply_t * mp)
{
  serialize_main_t _sm, *sm = &_sm;
  api_main_t *am = &api_main;
  u8 *tblv;
  u32 nmsgs;
  int i;
  u8 *name_and_crc;
  u32 msg_index;

  am->my_client_index = mp->index;
  am->my_registration = (vl_api_registration_t *) (uword) mp->handle;

  /* Clean out any previous hash table (unlikely) */
  if (am->msg_index_by_name_and_crc)
    {
      int i;
      u8 **keys = 0;
      hash_pair_t *hp;
      /* *INDENT-OFF* */
      hash_foreach_pair (hp, am->msg_index_by_name_and_crc,
      ({
        vec_add1 (keys, (u8 *) hp->key);
      }));
      /* *INDENT-ON* */
      for (i = 0; i < vec_len (keys); i++)
	vec_free (keys[i]);
      vec_free (keys);
    }

  am->msg_index_by_name_and_crc = hash_create_string (0, sizeof (uword));

  /* Recreate the vnet-side API message handler table */
  tblv = uword_to_pointer (mp->message_table, u8 *);
  serialize_open_vector (sm, tblv);
  unserialize_integer (sm, &nmsgs, sizeof (u32));

  for (i = 0; i < nmsgs; i++)
    {
      msg_index = unserialize_likely_small_unsigned_integer (sm);
      unserialize_cstring (sm, (char **) &name_and_crc);
      hash_set_mem (am->msg_index_by_name_and_crc, name_and_crc, msg_index);
    }
}

static void
noop_handler (void *notused)
{
}

int
vl_client_connect (const char *name, int ctx_quota, int input_queue_size)
{
  svm_region_t *svm;
  vl_api_memclnt_create_t *mp;
  vl_api_memclnt_create_reply_t *rp;
  unix_shared_memory_queue_t *vl_input_queue;
  vl_shmem_hdr_t *shmem_hdr;
  int rv = 0;
  void *oldheap;
  api_main_t *am = &api_main;

  if (am->my_registration)
    {
      clib_warning ("client %s already connected...", name);
      return -1;
    }

  if (am->vlib_rp == 0)
    {
      clib_warning ("am->vlib_rp NULL");
      return -1;
    }

  svm = am->vlib_rp;
  shmem_hdr = am->shmem_hdr;

  if (shmem_hdr == 0 || shmem_hdr->vl_input_queue == 0)
    {
      clib_warning ("shmem_hdr / input queue NULL");
      return -1;
    }

  pthread_mutex_lock (&svm->mutex);
  oldheap = svm_push_data_heap (svm);
  vl_input_queue =
    unix_shared_memory_queue_init (input_queue_size, sizeof (uword),
				   getpid (), 0);
  pthread_mutex_unlock (&svm->mutex);
  svm_pop_heap (oldheap);

  am->my_client_index = ~0;
  am->my_registration = 0;
  am->vl_input_queue = vl_input_queue;

  mp = vl_msg_api_alloc (sizeof (vl_api_memclnt_create_t));
  memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = ntohs (VL_API_MEMCLNT_CREATE);
  mp->ctx_quota = ctx_quota;
  mp->input_queue = (uword) vl_input_queue;
  strncpy ((char *) mp->name, name, sizeof (mp->name) - 1);

  vl_msg_api_send_shmem (shmem_hdr->vl_input_queue, (u8 *) & mp);

  while (1)
    {
      int qstatus;
      struct timespec ts, tsrem;
      int i;

      /* Wait up to 10 seconds */
      for (i = 0; i < 1000; i++)
	{
	  qstatus = unix_shared_memory_queue_sub (vl_input_queue, (u8 *) & rp,
						  1 /* nowait */ );
	  if (qstatus == 0)
	    goto read_one_msg;
	  ts.tv_sec = 0;
	  ts.tv_nsec = 10000 * 1000;	/* 10 ms */
	  while (nanosleep (&ts, &tsrem) < 0)
	    ts = tsrem;
	}
      /* Timeout... */
      clib_warning ("memclnt_create_reply timeout");
      return -1;

    read_one_msg:
      if (ntohs (rp->_vl_msg_id) != VL_API_MEMCLNT_CREATE_REPLY)
	{
	  clib_warning ("unexpected reply: id %d", ntohs (rp->_vl_msg_id));
	  continue;
	}
      rv = clib_net_to_host_u32 (rp->response);

      vl_msg_api_handler ((void *) rp);
      break;
    }
  return (rv);
}

static void
vl_api_memclnt_delete_reply_t_handler (vl_api_memclnt_delete_reply_t * mp)
{
  void *oldheap;
  api_main_t *am = &api_main;

  pthread_mutex_lock (&am->vlib_rp->mutex);
  oldheap = svm_push_data_heap (am->vlib_rp);
  unix_shared_memory_queue_free (am->vl_input_queue);
  pthread_mutex_unlock (&am->vlib_rp->mutex);
  svm_pop_heap (oldheap);

  am->my_client_index = ~0;
  am->my_registration = 0;
  am->vl_input_queue = 0;
}

void
vl_client_disconnect (void)
{
  vl_api_memclnt_delete_t *mp;
  vl_api_memclnt_delete_reply_t *rp;
  unix_shared_memory_queue_t *vl_input_queue;
  vl_shmem_hdr_t *shmem_hdr;
  time_t begin;
  api_main_t *am = &api_main;

  ASSERT (am->vlib_rp);
  shmem_hdr = am->shmem_hdr;
  ASSERT (shmem_hdr && shmem_hdr->vl_input_queue);

  vl_input_queue = am->vl_input_queue;

  mp = vl_msg_api_alloc (sizeof (vl_api_memclnt_delete_t));
  memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = ntohs (VL_API_MEMCLNT_DELETE);
  mp->index = am->my_client_index;
  mp->handle = (uword) am->my_registration;

  vl_msg_api_send_shmem (shmem_hdr->vl_input_queue, (u8 *) & mp);

  /*
   * Have to be careful here, in case the client is disconnecting
   * because e.g. the vlib process died, or is unresponsive.
   */

  begin = time (0);
  while (1)
    {
      time_t now;

      now = time (0);

      if (now >= (begin + 2))
	{
	  clib_warning ("peer unresponsive, give up");
	  am->my_client_index = ~0;
	  am->my_registration = 0;
	  am->shmem_hdr = 0;
	  break;
	}
      if (unix_shared_memory_queue_sub (vl_input_queue, (u8 *) & rp, 1) < 0)
	continue;

      /* drain the queue */
      if (ntohs (rp->_vl_msg_id) != VL_API_MEMCLNT_DELETE_REPLY)
	{
	  vl_msg_api_handler ((void *) rp);
	  continue;
	}
      vl_msg_api_handler ((void *) rp);
      break;
    }
}

#define foreach_api_msg                         \
_(RX_THREAD_EXIT, rx_thread_exit)               \
_(MEMCLNT_CREATE_REPLY, memclnt_create_reply)   \
_(MEMCLNT_DELETE_REPLY, memclnt_delete_reply)


void
vl_client_install_client_message_handlers (void)
{

#define _(N,n)                                                  \
    vl_msg_api_set_handlers(VL_API_##N, #n,                     \
                            vl_api_##n##_t_handler,             \
                            noop_handler,                       \
                            vl_api_##n##_t_endian,              \
                            vl_api_##n##_t_print,               \
                            sizeof(vl_api_##n##_t), 1);
  foreach_api_msg;
#undef _
}


int
vl_client_api_map (const char *region_name)
{
  int rv;

  if ((rv = vl_map_shmem (region_name, 0 /* is_vlib */ )) < 0)
    return rv;

  return 0;
}

void
vl_client_api_unmap (void)
{
  vl_unmap_shmem ();
}

static int
connect_to_vlib_internal (const char *svm_name,
			  const char *client_name,
			  int rx_queue_size, int want_pthread, int do_map)
{
  int rv = 0;
  memory_client_main_t *mm = &memory_client_main;

  if (do_map && (rv = vl_client_api_map (svm_name)))
    {
      clib_warning ("vl_client_api map rv %d", rv);
      return rv;
    }

  if (vl_client_connect (client_name, 0 /* punt quota */ ,
			 rx_queue_size /* input queue */ ) < 0)
    {
      vl_client_api_unmap ();
      return -1;
    }

  /* Start the rx queue thread */

  if (want_pthread)
    {
      rv = pthread_create (&mm->rx_thread_handle,
			   NULL /*attr */ , rx_thread_fn, 0);
      if (rv)
	clib_warning ("pthread_create returned %d", rv);
    }

  mm->connected_to_vlib = 1;
  return 0;
}

int
vl_client_connect_to_vlib (const char *svm_name,
			   const char *client_name, int rx_queue_size)
{
  return connect_to_vlib_internal (svm_name, client_name, rx_queue_size,
				   1 /* want pthread */ ,
				   1 /* do map */ );
}

int
vl_client_connect_to_vlib_no_rx_pthread (const char *svm_name,
					 const char *client_name,
					 int rx_queue_size)
{
  return connect_to_vlib_internal (svm_name, client_name, rx_queue_size,
				   0 /* want pthread */ ,
				   1 /* do map */ );
}

int
vl_client_connect_to_vlib_no_map (const char *svm_name,
				  const char *client_name, int rx_queue_size)
{
  return connect_to_vlib_internal (svm_name, client_name, rx_queue_size,
				   1 /* want pthread */ ,
				   0 /* dont map */ );
}

void
vl_client_disconnect_from_vlib (void)
{
  memory_client_main_t *mm = &memory_client_main;
  api_main_t *am = &api_main;
  uword junk;

  if (mm->rx_thread_jmpbuf_valid)
    {
      vl_api_rx_thread_exit_t *ep;
      ep = vl_msg_api_alloc (sizeof (*ep));
      ep->_vl_msg_id = ntohs (VL_API_RX_THREAD_EXIT);
      vl_msg_api_send_shmem (am->vl_input_queue, (u8 *) & ep);
      pthread_join (mm->rx_thread_handle, (void **) &junk);
    }
  if (mm->connected_to_vlib)
    {
      vl_client_disconnect ();
      vl_client_api_unmap ();
    }
  memset (mm, 0, sizeof (*mm));
}

static void vl_api_get_first_msg_id_reply_t_handler
  (vl_api_get_first_msg_id_reply_t * mp)
{
  memory_client_main_t *mm = &memory_client_main;
  i32 retval = ntohl (mp->retval);

  mm->first_msg_id_reply = (retval >= 0) ? ntohs (mp->first_msg_id) : ~0;
  mm->first_msg_id_reply_ready = 1;
}

u16
vl_client_get_first_plugin_msg_id (const char *plugin_name)
{
  vl_api_get_first_msg_id_t *mp;
  api_main_t *am = &api_main;
  memory_client_main_t *mm = &memory_client_main;
  f64 timeout;
  void *old_handler;
  clib_time_t clib_time;
  u16 rv = ~0;

  if (strlen (plugin_name) + 1 > sizeof (mp->name))
    return (rv);

  memset (&clib_time, 0, sizeof (clib_time));
  clib_time_init (&clib_time);

  /* Push this plugin's first_msg_id_reply handler */
  old_handler = am->msg_handlers[VL_API_GET_FIRST_MSG_ID_REPLY];
  am->msg_handlers[VL_API_GET_FIRST_MSG_ID_REPLY] = (void *)
    vl_api_get_first_msg_id_reply_t_handler;

  /* Ask the data-plane for the message-ID base of the indicated plugin */
  mm->first_msg_id_reply_ready = 0;

  mp = vl_msg_api_alloc (sizeof (*mp));
  memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = ntohs (VL_API_GET_FIRST_MSG_ID);
  mp->client_index = am->my_client_index;
  strncpy ((char *) mp->name, plugin_name, sizeof (mp->name) - 1);

  vl_msg_api_send_shmem (am->shmem_hdr->vl_input_queue, (u8 *) & mp);

  /* Synchronously wait for the answer */
  do
    {
      timeout = clib_time_now (&clib_time) + 1.0;

      while (clib_time_now (&clib_time) < timeout)
	{
	  if (mm->first_msg_id_reply_ready == 1)
	    {
	      rv = mm->first_msg_id_reply;
	      goto result;
	    }
	}
      /* Restore old handler */
      am->msg_handlers[VL_API_GET_FIRST_MSG_ID_REPLY] = old_handler;

      return rv;
    }
  while (0);

result:

  /* Restore the old handler */
  am->msg_handlers[VL_API_GET_FIRST_MSG_ID_REPLY] = old_handler;

  if (rv == (u16) ~ 0)
    clib_warning ("plugin '%s' not registered", plugin_name);

  return rv;
}

void
vlib_node_sync_stats (vlib_main_t * vm, vlib_node_t * n)
{
  clib_warning ("STUB called...");
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
