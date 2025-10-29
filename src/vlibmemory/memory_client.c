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

#include <setjmp.h>

#include <svm/svm.h>
#include <svm/ssvm.h>
#include <vppinfra/serialize.h>
#include <vppinfra/hash.h>
#include <vlibmemory/memory_client.h>
#include <vlibapi/api_common.h>

/* A hack. vl_client_get_first_plugin_msg_id depends on it */
#include <vlibmemory/socket_client.h>

#include <vlibmemory/vl_memory_msg_enum.h>

#define vl_typedefs		/* define message structures */
#include <vlibmemory/vl_memory_api_h.h>
#undef vl_typedefs

#define vl_endianfun		/* define message structures */
#include <vlibmemory/vl_memory_api_h.h>
#undef vl_endianfun

#define vl_calcsizefun
#include <vlibmemory/vl_memory_api_h.h>
#undef vl_calcsizefun

/* instantiate all the print functions we know about */
#define vl_printfun
#include <vlibmemory/vl_memory_api_h.h>
#undef vl_printfun

memory_client_main_t memory_client_main;
__thread memory_client_main_t *my_memory_client_main = &memory_client_main;

typedef struct rx_thread_fn_arg
{
  api_main_t *am;
  memory_client_main_t *mm;
} rx_thread_fn_arg_t;

static void *
rx_thread_fn (void *arg)
{
  rx_thread_fn_arg_t *a = (rx_thread_fn_arg_t *) arg;
  memory_client_main_t *mm;
  svm_queue_t *q;

  vlibapi_set_main (a->am);
  vlibapi_set_memory_client_main (a->mm);
  free (a);

  mm = vlibapi_get_memory_client_main ();
  q = vlibapi_get_main ()->vl_input_queue;

  /* So we can make the rx thread terminate cleanly */
  if (setjmp (mm->rx_thread_jmpbuf) == 0)
    {
      mm->rx_thread_jmpbuf_valid = 1;
      while (1)
	vl_msg_api_queue_handler (q);
    }
  pthread_exit (0);
}

static void
vl_api_rx_thread_exit_t_handler (vl_api_rx_thread_exit_t * mp)
{
  memory_client_main_t *mm = vlibapi_get_memory_client_main ();
  if (mm->rx_thread_jmpbuf_valid)
    longjmp (mm->rx_thread_jmpbuf, 1);
}

static void
vl_api_name_and_crc_free (void)
{
  api_main_t *am = vlibapi_get_main ();
  int i;
  u8 **keys = 0;
  hash_pair_t *hp;

  if (!am->msg_index_by_name_and_crc)
    return;

  hash_foreach_pair (hp, am->msg_index_by_name_and_crc,
      ({
        vec_add1 (keys, (u8 *) hp->key);
      }));
  for (i = 0; i < vec_len (keys); i++)
    vec_free (keys[i]);
  vec_free (keys);
  hash_free (am->msg_index_by_name_and_crc);
}

__clib_nosanitize_addr static void
VL_API_VEC_UNPOISON (const void *v)
{
  const vec_header_t *vh = &((vec_header_t *) v)[-1];
  clib_mem_unpoison (vh, sizeof (*vh) + vec_len (v));
}

static void
vl_api_memclnt_create_reply_t_handler (vl_api_memclnt_create_reply_t * mp)
{
  serialize_main_t _sm, *sm = &_sm;
  api_main_t *am = vlibapi_get_main ();
  u8 *tblv;
  u32 nmsgs;
  int i;
  u8 *name_and_crc;
  u32 msg_index;

  am->my_client_index = mp->index;
  am->my_registration = (vl_api_registration_t *) (uword) mp->handle;

  /* Clean out any previous hash table (unlikely) */
  vl_api_name_and_crc_free ();

  am->msg_index_by_name_and_crc = hash_create_string (0, sizeof (uword));

  /* Recreate the vnet-side API message handler table */
  tblv = uword_to_pointer (mp->message_table, u8 *);
  unserialize_open_data (sm, tblv, vec_len (tblv));
  unserialize_integer (sm, &nmsgs, sizeof (u32));

  VL_API_VEC_UNPOISON (tblv);

  for (i = 0; i < nmsgs; i++)
    {
      msg_index = unserialize_likely_small_unsigned_integer (sm);
      unserialize_cstring (sm, (char **) &name_and_crc);
      hash_set_mem (am->msg_index_by_name_and_crc, name_and_crc, msg_index);
    }
}

void vl_msg_api_send_shmem (svm_queue_t * q, u8 * elem);
int
vl_client_connect (const char *name, int ctx_quota, int input_queue_size)
{
  vl_api_memclnt_create_t *mp;
  vl_api_memclnt_create_reply_t *rp;
  svm_queue_t *vl_input_queue;
  vl_shmem_hdr_t *shmem_hdr;
  int rv = 0;
  void *oldheap;
  api_main_t *am = vlibapi_get_main ();

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

  shmem_hdr = am->shmem_hdr;

  if (shmem_hdr == 0 || shmem_hdr->vl_input_queue == 0)
    {
      clib_warning ("shmem_hdr / input queue NULL");
      return -1;
    }

  clib_mem_unpoison (shmem_hdr, sizeof (*shmem_hdr));
  VL_MSG_API_SVM_QUEUE_UNPOISON (shmem_hdr->vl_input_queue);

  oldheap = vl_msg_push_heap ();
  vl_input_queue = svm_queue_alloc_and_init (input_queue_size, sizeof (uword),
					     getpid ());
  vl_msg_pop_heap (oldheap);

  am->my_client_index = ~0;
  am->my_registration = 0;
  am->vl_input_queue = vl_input_queue;

  mp = vl_msg_api_alloc (sizeof (vl_api_memclnt_create_t));
  clib_memset (mp, 0, sizeof (*mp));
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
	  qstatus = svm_queue_sub (vl_input_queue, (u8 *) & rp,
				   SVM_Q_NOWAIT, 0);
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
      VL_MSG_API_UNPOISON (rp);
      if (ntohs (rp->_vl_msg_id) != VL_API_MEMCLNT_CREATE_REPLY)
	{
	  clib_warning ("unexpected reply: id %d", ntohs (rp->_vl_msg_id));
	  continue;
	}
      rv = clib_net_to_host_u32 (rp->response);

      msgbuf_t *msgbuf = (msgbuf_t *) ((u8 *) rp - offsetof (msgbuf_t, data));
      vl_msg_api_handler ((void *) rp, ntohl (msgbuf->data_len));
      break;
    }
  return (rv);
}

static void
vl_api_memclnt_delete_reply_t_handler (vl_api_memclnt_delete_reply_t * mp)
{
  void *oldheap;
  api_main_t *am = vlibapi_get_main ();

  oldheap = vl_msg_push_heap ();
  svm_queue_free (am->vl_input_queue);
  vl_msg_pop_heap (oldheap);

  am->my_client_index = ~0;
  am->my_registration = 0;
  am->vl_input_queue = 0;
}

void
vl_client_send_disconnect (u8 do_cleanup)
{
  vl_api_memclnt_delete_t *mp;
  vl_shmem_hdr_t *shmem_hdr;
  api_main_t *am = vlibapi_get_main ();

  ASSERT (am->vlib_rp);
  shmem_hdr = am->shmem_hdr;
  ASSERT (shmem_hdr && shmem_hdr->vl_input_queue);

  mp = vl_msg_api_alloc (sizeof (vl_api_memclnt_delete_t));
  clib_memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = ntohs (VL_API_MEMCLNT_DELETE);
  mp->index = am->my_client_index;
  mp->handle = (uword) am->my_registration;
  mp->do_cleanup = do_cleanup;

  vl_msg_api_send_shmem (shmem_hdr->vl_input_queue, (u8 *) & mp);
}

int
vl_client_disconnect (void)
{
  vl_api_memclnt_delete_reply_t *rp;
  svm_queue_t *vl_input_queue;
  api_main_t *am = vlibapi_get_main ();
  time_t begin;
  msgbuf_t *msgbuf;

  vl_input_queue = am->vl_input_queue;
  vl_client_send_disconnect (0 /* wait for reply */ );

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
	  return -1;
	}
      if (svm_queue_sub (vl_input_queue, (u8 *) & rp, SVM_Q_NOWAIT, 0) < 0)
	continue;

      VL_MSG_API_UNPOISON (rp);

      /* drain the queue */
      if (ntohs (rp->_vl_msg_id) != VL_API_MEMCLNT_DELETE_REPLY)
	{
	  clib_warning ("queue drain: %d", ntohs (rp->_vl_msg_id));
	  msgbuf = (msgbuf_t *) ((u8 *) rp - offsetof (msgbuf_t, data));
	  vl_msg_api_handler ((void *) rp, ntohl (msgbuf->data_len));
	  continue;
	}
      msgbuf = (msgbuf_t *) ((u8 *) rp - offsetof (msgbuf_t, data));
      vl_msg_api_handler ((void *) rp, ntohl (msgbuf->data_len));
      break;
    }

  vl_api_name_and_crc_free ();
  return 0;
}

/**
 * Stave off the binary API dead client reaper
 * Only sent to inactive clients
 */
static void
vl_api_memclnt_keepalive_t_handler (vl_api_memclnt_keepalive_t * mp)
{
  vl_api_memclnt_keepalive_reply_t *rmp;
  api_main_t *am;
  vl_shmem_hdr_t *shmem_hdr;

  am = vlibapi_get_main ();
  shmem_hdr = am->shmem_hdr;

  rmp = vl_msg_api_alloc_as_if_client (sizeof (*rmp));
  clib_memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (VL_API_MEMCLNT_KEEPALIVE_REPLY);
  rmp->context = mp->context;
  vl_msg_api_send_shmem (shmem_hdr->vl_input_queue, (u8 *) & rmp);
}

#define foreach_api_msg                         \
_(RX_THREAD_EXIT, rx_thread_exit)               \
_(MEMCLNT_CREATE_REPLY, memclnt_create_reply)   \
_(MEMCLNT_DELETE_REPLY, memclnt_delete_reply)	\
_(MEMCLNT_KEEPALIVE, memclnt_keepalive)

void
vl_client_install_client_message_handlers (void)
{
  api_main_t *am = vlibapi_get_main ();
#define _(N, n)                                                               \
  vl_msg_api_config (&(vl_msg_api_msg_config_t){                              \
    .id = VL_API_##N,                                                         \
    .name = #n,                                                               \
    .handler = vl_api_##n##_t_handler,                                        \
    .endian = vl_api_##n##_t_endian,                                          \
    .format_fn = vl_api_##n##_t_format,                                       \
    .size = sizeof (vl_api_##n##_t),                                          \
    .traced = 0,                                                              \
    .tojson = vl_api_##n##_t_tojson,                                          \
    .fromjson = vl_api_##n##_t_fromjson,                                      \
    .calc_size = vl_api_##n##_t_calc_size,                                    \
  });                                                                         \
  am->msg_data[VL_API_##N].replay_allowed = 0;
  foreach_api_msg;
#undef _
}

int
vl_client_api_map (const char *region_name)
{
  int rv;

  if ((rv = vl_map_shmem (region_name, 0 /* is_vlib */ )) < 0)
    return rv;

  vl_client_install_client_message_handlers ();
  return 0;
}

void
vl_client_api_unmap (void)
{
  vl_unmap_shmem_client ();
}

u8
vl_mem_client_is_connected (void)
{
  return (my_memory_client_main->connected_to_vlib != 0);
}

static int
vl_rx_thread_init_attr (pthread_attr_t *attr)
{
  pthread_t thread = pthread_self ();
  int rv, policy, priority;
  struct sched_param param;

  /* If current thread has real-time scheduling policy, try to set a higher
   * priority to rx-thread to avoid deadlocks whereby current thread spins
   * waiting for api replies while rx-thread cannot preempt current thread
   * to process replies */
  rv = pthread_getschedparam (thread, &policy, &param);
  if (rv != 0)
    {
      clib_warning ("pthread_getschedparam returned %d", rv);
      return -1;
    }
  priority = param.sched_priority;
  if ((policy == SCHED_FIFO) && (priority < 99))
    {
      pthread_attr_setschedpolicy (attr, SCHED_FIFO);
      param.sched_priority = priority + 1;
      pthread_attr_setschedparam (attr, &param);
      pthread_attr_setinheritsched (attr, PTHREAD_EXPLICIT_SCHED);
    }
  return 0;
}

static int
connect_to_vlib_internal (const char *svm_name,
			  const char *client_name,
			  int rx_queue_size, void *(*thread_fn) (void *),
			  void *thread_fn_arg, int do_map)
{
  int rv = 0;
  memory_client_main_t *mm = vlibapi_get_memory_client_main ();
  api_main_t *am = vlibapi_get_main ();
  pthread_attr_t attr;

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

  if (thread_fn)
    {
      am->rx_thread_handle = 0;
      if (thread_fn == rx_thread_fn)
	{
	  rx_thread_fn_arg_t *arg;
	  arg = malloc (sizeof (*arg));
	  arg->am = vlibapi_get_main ();
	  arg->mm = vlibapi_get_memory_client_main ();
	  thread_fn_arg = (void *) arg;
	}

      rv = pthread_attr_init (&attr);
      if (rv != 0)
	{
	  clib_warning ("pthread_attr_init returned %d", rv);
	  return -1;
	}
      if (vl_rx_thread_init_attr (&attr))
	return -1;

      rv = pthread_create (&mm->rx_thread_handle, &attr, thread_fn,
			   thread_fn_arg);
      if (rv)
	{
	  clib_warning ("pthread_create returned %d", rv);
	  return -1;
	}
      am->rx_thread_handle = mm->rx_thread_handle;
      pthread_attr_destroy (&attr);
    }

  mm->connected_to_vlib = 1;
  return 0;
}

int
vl_client_connect_to_vlib (const char *svm_name,
			   const char *client_name, int rx_queue_size)
{
  return connect_to_vlib_internal (svm_name, client_name, rx_queue_size,
				   rx_thread_fn, 0 /* thread fn arg */ ,
				   1 /* do map */ );
}

int
vl_client_connect_to_vlib_no_rx_pthread (const char *svm_name,
					 const char *client_name,
					 int rx_queue_size)
{
  return connect_to_vlib_internal (svm_name, client_name, rx_queue_size,
				   0 /* no rx_thread_fn */ ,
				   0 /* no thread fn arg */ ,
				   1 /* do map */ );
}

int
vl_client_connect_to_vlib_no_map (const char *svm_name,
				  const char *client_name, int rx_queue_size)
{
  return connect_to_vlib_internal (svm_name, client_name, rx_queue_size,
				   rx_thread_fn, 0 /* no thread fn arg */ ,
				   0 /* dont map */ );
}

int
vl_client_connect_to_vlib_no_rx_pthread_no_map (const char *svm_name,
						const char *client_name,
						int rx_queue_size)
{
  return connect_to_vlib_internal (svm_name, client_name, rx_queue_size,
				   0 /* no thread_fn */ ,
				   0 /* no thread fn arg */ ,
				   0 /* dont map */ );
}

int
vl_client_connect_to_vlib_thread_fn (const char *svm_name,
				     const char *client_name,
				     int rx_queue_size,
				     void *(*thread_fn) (void *), void *arg)
{
  return connect_to_vlib_internal (svm_name, client_name, rx_queue_size,
				   thread_fn, arg, 1 /* do map */ );
}

void
vl_client_stop_rx_thread (svm_queue_t *vl_input_queue)
{
  vl_api_rx_thread_exit_t *ep;
  ep = vl_msg_api_alloc (sizeof (*ep));
  ep->_vl_msg_id = ntohs (VL_API_RX_THREAD_EXIT);
  vl_msg_api_send_shmem (vl_input_queue, (u8 *) &ep);
}

static void
disconnect_from_vlib_internal (u8 do_unmap)
{
  memory_client_main_t *mm = vlibapi_get_memory_client_main ();
  api_main_t *am = vlibapi_get_main ();
  uword junk;

  if (mm->rx_thread_jmpbuf_valid)
    {
      vl_client_stop_rx_thread (am->vl_input_queue);
      pthread_join (mm->rx_thread_handle, (void **) &junk);
    }
  if (mm->connected_to_vlib)
    {
      vl_client_disconnect ();
      if (do_unmap)
	vl_client_api_unmap ();
    }
  clib_memset (mm, 0, sizeof (*mm));
}

void
vl_client_disconnect_from_vlib (void)
{
  disconnect_from_vlib_internal (1);
}

void
vl_client_disconnect_from_vlib_no_unmap (void)
{
  disconnect_from_vlib_internal (0);
}

static void vl_api_get_first_msg_id_reply_t_handler
  (vl_api_get_first_msg_id_reply_t * mp)
{
  memory_client_main_t *mm = vlibapi_get_memory_client_main ();
  i32 retval = ntohl (mp->retval);

  mm->first_msg_id_reply = (retval >= 0) ? ntohs (mp->first_msg_id) : ~0;
  mm->first_msg_id_reply_ready = 1;
}

u16
vl_client_get_first_plugin_msg_id (const char *plugin_name)
{
  vl_api_get_first_msg_id_t *mp;
  api_main_t *am = vlibapi_get_main ();
  memory_client_main_t *mm = vlibapi_get_memory_client_main ();
  vl_api_msg_data_t *m =
    vl_api_get_msg_data (am, VL_API_GET_FIRST_MSG_ID_REPLY);
  f64 timeout;
  void *old_handler;
  clib_time_t clib_time;
  u16 rv = ~0;

  if (strlen (plugin_name) + 1 > sizeof (mp->name))
    return (rv);

  clib_memset (&clib_time, 0, sizeof (clib_time));
  clib_time_init (&clib_time);

  /* Push this plugin's first_msg_id_reply handler */
  old_handler = m->handler;
  m->handler = (void *) vl_api_get_first_msg_id_reply_t_handler;
  if (!m->calc_size_func)
    {
      m->calc_size_func =
	(uword (*) (void *)) vl_api_get_first_msg_id_reply_t_calc_size;
    }

  /* Ask the data-plane for the message-ID base of the indicated plugin */
  mm->first_msg_id_reply_ready = 0;

  /* Not using shm client */
  if (!am->my_registration)
    {
      mp = vl_socket_client_msg_alloc (sizeof (*mp));
      clib_memset (mp, 0, sizeof (*mp));
      mp->_vl_msg_id = ntohs (VL_API_GET_FIRST_MSG_ID);
      mp->client_index = am->my_client_index;
      strncpy ((char *) mp->name, plugin_name, sizeof (mp->name) - 1);

      if (vl_socket_client_write () <= 0)
	goto sock_err;
      if (vl_socket_client_read (1))
	goto sock_err;

      if (mm->first_msg_id_reply_ready == 1)
	{
	  rv = mm->first_msg_id_reply;
	  goto result;
	}

    sock_err:
      /* Restore old handler */
      m->handler = old_handler;

      return -1;
    }
  else
    {
      mp = vl_msg_api_alloc (sizeof (*mp));
      clib_memset (mp, 0, sizeof (*mp));
      mp->_vl_msg_id = ntohs (VL_API_GET_FIRST_MSG_ID);
      mp->client_index = am->my_client_index;
      strncpy ((char *) mp->name, plugin_name, sizeof (mp->name) - 1);

      vl_msg_api_send_shmem (am->shmem_hdr->vl_input_queue, (u8 *) & mp);

      /* Synchronously wait for the answer */
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
      m->handler = old_handler;

      return rv;
    }

result:

  /* Restore the old handler */
  m->handler = old_handler;

  if (rv == (u16) ~ 0)
    clib_warning ("plugin '%s' not registered", plugin_name);

  return rv;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
