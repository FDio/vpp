/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
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
 */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <netdb.h>
#include <signal.h>
#include <stdbool.h>
#include <vnet/vnet.h>
#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>

#include <vpp/api/vpe_msg_enum.h>

#include "vppapiclient.h"

bool timeout_cancelled;
bool timeout_in_progress;
bool rx_thread_done;

/*
 * Asynchronous mode:
 *  Client registers a callback. All messages are sent to the callback.
 * Synchronous mode:
 *  Client calls blocking read().
 *  Clients are expected to collate events on a queue.
 *  vac_write() -> suspends RX thread
 *  vac_read() -> resumes RX thread
 */

#define vl_typedefs             /* define message structures */
#include <vpp/api/vpe_all_api_h.h>
#undef vl_typedefs

#define vl_endianfun             /* define message structures */
#include <vpp/api/vpe_all_api_h.h>
#undef vl_endianfun

vlib_main_t **vlib_mains;

typedef struct {
  u8 connected_to_vlib;
  pthread_t rx_thread_handle;
  pthread_t timeout_thread_handle;
  pthread_mutex_t queue_lock;
  pthread_cond_t suspend_cv;
  pthread_cond_t resume_cv;
  pthread_mutex_t timeout_lock;
  u8 timeout_loop;
  pthread_cond_t timeout_cv;
  pthread_cond_t timeout_cancel_cv;
  pthread_cond_t terminate_cv;
} vac_main_t;

vac_main_t vac_main;
vac_callback_t vac_callback;
u16 read_timeout = 0;
bool rx_is_running = false;
bool timeout_thread_cancelled = false;

/* Only ever allocate one heap */
bool mem_initialized = false;

static void
init (void)
{
  vac_main_t *pm = &vac_main;
  clib_memset(pm, 0, sizeof(*pm));
  pthread_mutex_init(&pm->queue_lock, NULL);
  pthread_cond_init(&pm->suspend_cv, NULL);
  pthread_cond_init(&pm->resume_cv, NULL);
  pthread_mutex_init(&pm->timeout_lock, NULL);
  pm->timeout_loop = 1;
  pthread_cond_init(&pm->timeout_cv, NULL);
  pthread_cond_init(&pm->timeout_cancel_cv, NULL);
  pthread_cond_init(&pm->terminate_cv, NULL);
}

static void
cleanup (void)
{
  vac_main_t *pm = &vac_main;
  pthread_mutex_destroy(&pm->queue_lock);
  pthread_cond_destroy(&pm->suspend_cv);
  pthread_cond_destroy(&pm->resume_cv);
  pthread_mutex_destroy(&pm->timeout_lock);
  pthread_cond_destroy(&pm->timeout_cv);
  pthread_cond_destroy(&pm->timeout_cancel_cv);
  pthread_cond_destroy(&pm->terminate_cv);
  clib_memset(pm, 0, sizeof(*pm));
}

/*
 * Satisfy external references when -lvlib is not available.
 */
void vlib_cli_output (struct vlib_main_t * vm, char * fmt, ...)
{
  clib_warning ("vlib_cli_output called...");
}

void
vac_free (void * msg)
{
  vl_msg_api_free (msg);
}

static void
vac_api_handler (void *msg)
{
  u16 id = ntohs(*((u16 *)msg));
  msgbuf_t *msgbuf = (msgbuf_t *)(((u8 *)msg) - offsetof(msgbuf_t, data));
  int l = ntohl(msgbuf->data_len);
  if (l == 0)
    clib_warning("Message ID %d has wrong length: %d\n", id, l);

  /* Call Python callback */
  ASSERT(vac_callback);
  (vac_callback)(msg, l);
  vac_free(msg);
}

static void *
vac_rx_thread_fn (void *arg)
{
  svm_queue_t *q;
  vl_api_memclnt_keepalive_t *mp;
  vl_api_memclnt_keepalive_reply_t *rmp;
  vac_main_t *pm = &vac_main;
  api_main_t *am = vlibapi_get_main();
  vl_shmem_hdr_t *shmem_hdr;
  uword msg;

  q = am->vl_input_queue;

  while (1)
    while (!svm_queue_sub(q, (u8 *)&msg, SVM_Q_WAIT, 0))
      {
        VL_MSG_API_UNPOISON((void *)msg);
	u16 id = ntohs(*((u16 *)msg));
	switch (id) {
	case VL_API_RX_THREAD_EXIT:
	  vl_msg_api_free((void *) msg);
	  /* signal waiting threads that this thread is about to terminate */
	  pthread_mutex_lock(&pm->queue_lock);
	  rx_thread_done = true;
	  pthread_cond_signal(&pm->terminate_cv);
	  pthread_mutex_unlock(&pm->queue_lock);
	  pthread_exit(0);
	  return 0;
	  break;

	case VL_API_MEMCLNT_RX_THREAD_SUSPEND:
	  vl_msg_api_free((void * )msg);
	  /* Suspend thread and signal reader */
	  pthread_mutex_lock(&pm->queue_lock);
	  pthread_cond_signal(&pm->suspend_cv);
	  /* Wait for the resume signal */
	  pthread_cond_wait (&pm->resume_cv, &pm->queue_lock);
	  pthread_mutex_unlock(&pm->queue_lock);
	  break;

	case VL_API_MEMCLNT_READ_TIMEOUT:
	  clib_warning("Received read timeout in async thread\n");
	  vl_msg_api_free((void *) msg);
	  break;

        case VL_API_MEMCLNT_KEEPALIVE:
          mp = (void *)msg;
          rmp = vl_msg_api_alloc (sizeof (*rmp));
          clib_memset (rmp, 0, sizeof (*rmp));
          rmp->_vl_msg_id = ntohs(VL_API_MEMCLNT_KEEPALIVE_REPLY);
          rmp->context = mp->context;
          shmem_hdr = am->shmem_hdr;
          vl_msg_api_send_shmem(shmem_hdr->vl_input_queue, (u8 *)&rmp);
          vl_msg_api_free((void *) msg);
	  break;

	default:
	  vac_api_handler((void *)msg);
	}
      }
}

static void *
vac_timeout_thread_fn (void *arg)
{
  vl_api_memclnt_read_timeout_t *ep;
  vac_main_t *pm = &vac_main;
  api_main_t *am = vlibapi_get_main();
  struct timespec ts;
  struct timeval tv;
  int rv;

  while (pm->timeout_loop)
    {
      /* Wait for poke */
      pthread_mutex_lock(&pm->timeout_lock);
      while (!timeout_in_progress)
	pthread_cond_wait (&pm->timeout_cv, &pm->timeout_lock);

      /* Starting timer */
      gettimeofday(&tv, NULL);
      ts.tv_sec = tv.tv_sec + read_timeout;
      ts.tv_nsec = 0;

      if (!timeout_cancelled) {
	rv = pthread_cond_timedwait (&pm->timeout_cancel_cv,
				     &pm->timeout_lock, &ts);
	if (rv == ETIMEDOUT && !timeout_thread_cancelled) {
	  ep = vl_msg_api_alloc (sizeof (*ep));
	  ep->_vl_msg_id = ntohs(VL_API_MEMCLNT_READ_TIMEOUT);
	  vl_msg_api_send_shmem(am->vl_input_queue, (u8 *)&ep);
	}
      }

      pthread_mutex_unlock(&pm->timeout_lock);
    }
  pthread_exit(0);
}

void
vac_rx_suspend (void)
{
  api_main_t *am = vlibapi_get_main();
  vac_main_t *pm = &vac_main;
  vl_api_memclnt_rx_thread_suspend_t *ep;

  if (!pm->rx_thread_handle) return;
  pthread_mutex_lock(&pm->queue_lock);
  if (rx_is_running)
    {
      ep = vl_msg_api_alloc (sizeof (*ep));
      ep->_vl_msg_id = ntohs(VL_API_MEMCLNT_RX_THREAD_SUSPEND);
      vl_msg_api_send_shmem(am->vl_input_queue, (u8 *)&ep);
      /* Wait for RX thread to tell us it has suspended */
      pthread_cond_wait(&pm->suspend_cv, &pm->queue_lock);
      rx_is_running = false;
    }
  pthread_mutex_unlock(&pm->queue_lock);
}

void
vac_rx_resume (void)
{
  vac_main_t *pm = &vac_main;
  if (!pm->rx_thread_handle) return;
  pthread_mutex_lock(&pm->queue_lock);
  if (rx_is_running) goto unlock;
  pthread_cond_signal(&pm->resume_cv);
  rx_is_running = true;
 unlock:
  pthread_mutex_unlock(&pm->queue_lock);
}

static uword *
vac_msg_table_get_hash (void)
{
  api_main_t *am = vlibapi_get_main();
  return (am->msg_index_by_name_and_crc);
}

int
vac_msg_table_size(void)
{
  api_main_t *am = vlibapi_get_main();
  return hash_elts(am->msg_index_by_name_and_crc);
}

int
vac_connect (char * name, char * chroot_prefix, vac_callback_t cb,
             int rx_qlen)
{
  rx_thread_done = false;
  int rv = 0;
  vac_main_t *pm = &vac_main;

  assert (clib_mem_get_heap ());
  init();
  if (chroot_prefix != NULL)
    vl_set_memory_root_path (chroot_prefix);

  if ((rv = vl_client_api_map("/vpe-api"))) {
    clib_warning ("vl_client_api_map returned %d", rv);
    return rv;
  }

  if (vl_client_connect(name, 0, rx_qlen) < 0) {
    vl_client_api_unmap();
    return (-1);
  }

  if (cb) {
    /* Start the rx queue thread */
    rv = pthread_create(&pm->rx_thread_handle, NULL, vac_rx_thread_fn, 0);
    if (rv) {
      clib_warning("pthread_create returned %d", rv);
      vl_client_api_unmap();
      return (-1);
    }
    vac_callback = cb;
    rx_is_running = true;
  }

  /* Start read timeout thread */
  rv = pthread_create(&pm->timeout_thread_handle, NULL,
		      vac_timeout_thread_fn, 0);
  if (rv) {
    clib_warning("pthread_create returned %d", rv);
    vl_client_api_unmap();
    return (-1);
  }

  pm->connected_to_vlib = 1;

  return (0);
}
static void
set_timeout (unsigned short timeout)
{
  vac_main_t *pm = &vac_main;
  pthread_mutex_lock(&pm->timeout_lock);
  read_timeout = timeout;
  timeout_in_progress = true;
  timeout_cancelled = false;
  pthread_cond_signal(&pm->timeout_cv);
  pthread_mutex_unlock(&pm->timeout_lock);
}

static void
unset_timeout (void)
{
  vac_main_t *pm = &vac_main;
  pthread_mutex_lock(&pm->timeout_lock);
  timeout_in_progress = false;
  timeout_cancelled = true;
  pthread_cond_signal(&pm->timeout_cancel_cv);
  pthread_mutex_unlock(&pm->timeout_lock);
}

int
vac_disconnect (void)
{
  api_main_t *am = vlibapi_get_main();
  vac_main_t *pm = &vac_main;
  uword junk;
  int rv = 0;

  if (!pm->connected_to_vlib) return 0;

  if (pm->rx_thread_handle) {
    vl_api_rx_thread_exit_t *ep;
    ep = vl_msg_api_alloc (sizeof (*ep));
    ep->_vl_msg_id = ntohs(VL_API_RX_THREAD_EXIT);
    vl_msg_api_send_shmem(am->vl_input_queue, (u8 *)&ep);

    /* wait (with timeout) until RX thread has finished */
    struct timespec ts;
    struct timeval tv;
    gettimeofday(&tv, NULL);
    ts.tv_sec = tv.tv_sec + 5;
    ts.tv_nsec = 0;

    pthread_mutex_lock(&pm->queue_lock);
    if (rx_thread_done == false)
      rv = pthread_cond_timedwait(&pm->terminate_cv, &pm->queue_lock, &ts);
    pthread_mutex_unlock(&pm->queue_lock);

    /* now join so we wait until thread has -really- finished */
    if (rv == ETIMEDOUT)
      pthread_cancel(pm->rx_thread_handle);
    else
      pthread_join(pm->rx_thread_handle, (void **) &junk);
  }
  if (pm->timeout_thread_handle) {
    /* cancel, wake then join the timeout thread */
    pm->timeout_loop = 0;
    timeout_thread_cancelled = true;
    set_timeout(0);
    pthread_join(pm->timeout_thread_handle, (void **) &junk);
  }

  vl_client_disconnect();
  vl_client_api_unmap();
  //vac_callback = 0;

  cleanup();

  return (0);
}

int
vac_read (char **p, int *l, u16 timeout)
{
  svm_queue_t *q;
  api_main_t *am = vlibapi_get_main();
  vac_main_t *pm = &vac_main;
  vl_api_memclnt_keepalive_t *mp;
  vl_api_memclnt_keepalive_reply_t *rmp;
  uword msg;
  msgbuf_t *msgbuf;
  int rv;
  vl_shmem_hdr_t *shmem_hdr;

  /* svm_queue_sub(below) returns {-1, -2} */
  if (!pm->connected_to_vlib)
    return VAC_NOT_CONNECTED;

  *l = 0;

  /* svm_queue_sub(below) returns {-1, -2} */
  if (am->our_pid == 0)
    return (VAC_SHM_NOT_READY);

  /* Poke timeout thread */
  if (timeout)
    set_timeout(timeout);

  q = am->vl_input_queue;

 again:
  rv = svm_queue_sub(q, (u8 *)&msg, SVM_Q_WAIT, 0);

  if (rv == 0) {
    VL_MSG_API_UNPOISON((void *)msg);
    u16 msg_id = ntohs(*((u16 *)msg));
    switch (msg_id) {
    case VL_API_RX_THREAD_EXIT:
      vl_msg_api_free((void *) msg);
      goto error;
    case VL_API_MEMCLNT_RX_THREAD_SUSPEND:
      goto error;
    case VL_API_MEMCLNT_READ_TIMEOUT:
      goto error;
    case VL_API_MEMCLNT_KEEPALIVE:
      /* Handle an alive-check ping from vpp. */
      mp = (void *)msg;
      rmp = vl_msg_api_alloc (sizeof (*rmp));
      clib_memset (rmp, 0, sizeof (*rmp));
      rmp->_vl_msg_id = ntohs(VL_API_MEMCLNT_KEEPALIVE_REPLY);
      rmp->context = mp->context;
      shmem_hdr = am->shmem_hdr;
      vl_msg_api_send_shmem(shmem_hdr->vl_input_queue, (u8 *)&rmp);
      vl_msg_api_free((void *) msg);
      /*
       * Python code is blissfully unaware of these pings, so
       * act as if it never happened...
       */
      goto again;

    default:
      msgbuf = (msgbuf_t *)(((u8 *)msg) - offsetof(msgbuf_t, data));
      *l = ntohl(msgbuf->data_len);
      if (*l == 0) {
	fprintf(stderr, "Unregistered API message: %d\n", msg_id);
	goto error;
      }
    }
    *p = (char *)msg;


  } else {
    fprintf(stderr, "Read failed with %d\n", rv);
  }
  /* Let timeout notification thread know we're done */
  if (timeout)
    unset_timeout();

  return (rv);

 error:
  if (timeout)
    unset_timeout();
  vl_msg_api_free((void *) msg);
  /* Client might forget to resume RX thread on failure */
  vac_rx_resume ();
  return VAC_TIMEOUT;
}

/*
 * XXX: Makes the assumption that client_index is the first member
 */
typedef VL_API_PACKED(struct _vl_api_header {
  u16 _vl_msg_id;
  u32 client_index;
}) vl_api_header_t;

static u32
vac_client_index (void)
{
  return (vlibapi_get_main()->my_client_index);
}

int
vac_write (char *p, int l)
{
  int rv = -1;
  api_main_t *am = vlibapi_get_main();
  vl_api_header_t *mp = vl_msg_api_alloc(l);
  svm_queue_t *q;
  vac_main_t *pm = &vac_main;

  if (!pm->connected_to_vlib)
    return VAC_NOT_CONNECTED;
  if (!mp) return (-1);

  memcpy(mp, p, l);
  mp->client_index = vac_client_index();
  q = am->shmem_hdr->vl_input_queue;
  rv = svm_queue_add(q, (u8 *)&mp, 0);
  if (rv != 0) {
    fprintf(stderr, "vpe_api_write fails: %d\n", rv);
    /* Clear message */
    vac_free(mp);
  }
  return (rv);
}

int
vac_get_msg_index (char * name)
{
  return vl_msg_api_get_msg_index ((u8 *)name);
}

int
vac_msg_table_max_index(void)
{
  int max = 0;
  hash_pair_t *hp;
  uword *h = vac_msg_table_get_hash();
  hash_foreach_pair (hp, h,
  ({
    if (hp->value[0] > max)
      max = hp->value[0];
  }));

  return max;
}

void
vac_set_error_handler (vac_error_callback_t cb)
{
  assert (clib_mem_get_heap ());
  if (cb) clib_error_register_handler (cb, 0);
}

/*
 * Required if application doesn't use a VPP heap.
 */
void
vac_mem_init (size_t size)
{
  if (mem_initialized)
    return;
  if (size == 0)
    clib_mem_init (0, 1 << 30);  // default
  else
    clib_mem_init (0, size);
  mem_initialized = true;
}
