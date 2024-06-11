/*
 *------------------------------------------------------------------
 * Copyright (c) 2017 Cisco and/or its affiliates.
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

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <stddef.h>
#include <assert.h>

#include <vpp-api/vapi/vapi_dbg.h>
#include <vpp-api/vapi/vapi.h>
#include <vpp-api/vapi/vapi_internal.h>
#include <vppinfra/types.h>
#include <vppinfra/pool.h>
#include <vlib/vlib.h>
#include <vlibapi/api_common.h>
#include <vlibmemory/memory_client.h>
#include <vlibmemory/memory_api.h>
#include <vlibmemory/api.h>

#include <vapi/memclnt.api.vapi.h>
#include <vapi/vlib.api.vapi.h>

#include <vlibmemory/vl_memory_msg_enum.h>

#define vl_typedefs /* define message structures */
#include <vlibmemory/vl_memory_api_h.h>
#undef vl_typedefs

/* we need to use control pings for some stuff and because we're forced to put
 * the code in headers, we need a way to be able to grab the ids of these
 * messages - so declare them here as extern */
vapi_msg_id_t vapi_msg_id_control_ping = 0;
vapi_msg_id_t vapi_msg_id_control_ping_reply = 0;

DEFINE_VAPI_MSG_IDS_MEMCLNT_API_JSON;
DEFINE_VAPI_MSG_IDS_VLIB_API_JSON;

struct
{
  size_t count;
  vapi_message_desc_t **msgs;
  size_t max_len_name_with_crc;
} __vapi_metadata;

typedef struct
{
  u32 context;
  vapi_cb_t callback;
  void *callback_ctx;
  vapi_msg_id_t response_id;
  enum vapi_request_type type;
} vapi_req_t;

static const u32 context_counter_mask = (1 << 31);

typedef struct
{
  vapi_error_e (*cb) (vapi_ctx_t ctx, void *callback_ctx, vapi_msg_id_t id,
		      void *payload);
  void *ctx;
} vapi_generic_cb_with_ctx;

typedef struct
{
  vapi_error_e (*cb) (vapi_ctx_t ctx, void *callback_ctx, void *payload);
  void *ctx;
} vapi_event_cb_with_ctx;

struct vapi_ctx_s
{
  vapi_mode_e mode;
  int requests_size;		/* size of the requests array (circular queue) */
  int requests_start;		/* index of first request */
  int requests_count;		/* number of used slots */
  vapi_req_t *requests;
  u32 context_counter;
  vapi_generic_cb_with_ctx generic_cb;
  vapi_event_cb_with_ctx *event_cbs;
  u16 *vapi_msg_id_t_to_vl_msg_id;
  u16 vl_msg_id_max;
  vapi_msg_id_t *vl_msg_id_to_vapi_msg_t;
  bool connected;
  bool handle_keepalives;
  pthread_mutex_t requests_mutex;
  bool use_uds;

  svm_queue_t *vl_input_queue;
  clib_socket_t client_socket;
  clib_time_t time;
  u32 my_client_index;
  /** client message index hash table */
  uword *msg_index_by_name_and_crc;
};

u32
vapi_gen_req_context (vapi_ctx_t ctx)
{
  ++ctx->context_counter;
  ctx->context_counter %= context_counter_mask;
  return ctx->context_counter | context_counter_mask;
}

size_t
vapi_get_request_count (vapi_ctx_t ctx)
{
  return ctx->requests_count;
}

bool
vapi_requests_full (vapi_ctx_t ctx)
{
  return (ctx->requests_count == ctx->requests_size);
}

bool
vapi_requests_empty (vapi_ctx_t ctx)
{
  return (0 == ctx->requests_count);
}

static int
vapi_requests_end (vapi_ctx_t ctx)
{
  return (ctx->requests_start + ctx->requests_count) % ctx->requests_size;
}

void
vapi_store_request (vapi_ctx_t ctx, u32 context, vapi_msg_id_t response_id,
		    enum vapi_request_type request_type, vapi_cb_t callback,
		    void *callback_ctx)
{
  assert (!vapi_requests_full (ctx));
  /* if the mutex is not held, bad things will happen */
  assert (0 != pthread_mutex_trylock (&ctx->requests_mutex));
  const int requests_end = vapi_requests_end (ctx);
  vapi_req_t *slot = &ctx->requests[requests_end];
  slot->type = request_type;
  slot->response_id = response_id;
  slot->context = context;
  slot->callback = callback;
  slot->callback_ctx = callback_ctx;
  VAPI_DBG ("stored@%d: context:%x (start is @%d)", requests_end, context,
	    ctx->requests_start);
  ++ctx->requests_count;
  assert (!vapi_requests_empty (ctx));
}

#if VAPI_DEBUG_ALLOC
struct to_be_freed_s;
struct to_be_freed_s
{
  void *v;
  struct to_be_freed_s *next;
};

static struct to_be_freed_s *to_be_freed = NULL;

void
vapi_add_to_be_freed (void *v)
{
  struct to_be_freed_s *prev = NULL;
  struct to_be_freed_s *tmp;
  tmp = to_be_freed;
  while (tmp && tmp->v)
    {
      prev = tmp;
      tmp = tmp->next;
    }
  if (!tmp)
    {
      if (!prev)
	{
	  tmp = to_be_freed = calloc (1, sizeof (*to_be_freed));
	}
      else
	{
	  tmp = prev->next = calloc (1, sizeof (*to_be_freed));
	}
    }
  VAPI_DBG ("To be freed %p", v);
  tmp->v = v;
}

void
vapi_trace_free (void *v)
{
  struct to_be_freed_s *tmp = to_be_freed;
  while (tmp && tmp->v != v)
    {
      tmp = tmp->next;
    }
  if (tmp && tmp->v == v)
    {
      VAPI_DBG ("Freed %p", v);
      tmp->v = NULL;
    }
  else
    {
      VAPI_ERR ("Trying to free untracked pointer %p", v);
      abort ();
    }
}

void
vapi_to_be_freed_validate ()
{
  struct to_be_freed_s *tmp = to_be_freed;
  while (tmp)
    {
      if (tmp->v)
	{
	  VAPI_ERR ("Unfreed msg %p!", tmp->v);
	}
      tmp = tmp->next;
    }
}

#endif

static void *
vapi_shm_msg_alloc (vapi_ctx_t ctx, size_t size)
{
  if (!ctx->connected)
    {
      return NULL;
    }
  void *rv = vl_msg_api_alloc_as_if_client_or_null (size);
  if (rv)
    {
      clib_memset (rv, 0, size);
    }
  return rv;
}

static void *
vapi_sock_msg_alloc (size_t size)
{
  u8 *rv = 0;
  vec_validate_init_empty (rv, size - 1, 0);
  return rv;
}

void *
vapi_msg_alloc (vapi_ctx_t ctx, size_t size)
{
  if (ctx->use_uds)
    return vapi_sock_msg_alloc (size);

  return vapi_shm_msg_alloc (ctx, size);
}

void
vapi_msg_free (vapi_ctx_t ctx, void *msg)
{
  if (!ctx->connected)
    {
      return;
    }

#if VAPI_DEBUG_ALLOC
  vapi_trace_free (msg);
#endif

  if (ctx->use_uds)
    {
      vec_free (msg);
    }
  else
    {
      vl_msg_api_free (msg);
    }
}

vapi_msg_id_t
vapi_lookup_vapi_msg_id_t (vapi_ctx_t ctx, u16 vl_msg_id)
{
  if (vl_msg_id <= ctx->vl_msg_id_max)
    {
      return ctx->vl_msg_id_to_vapi_msg_t[vl_msg_id];
    }
  return VAPI_INVALID_MSG_ID;
}

vapi_error_e
vapi_ctx_alloc (vapi_ctx_t * result)
{
  vapi_ctx_t ctx = calloc (1, sizeof (struct vapi_ctx_s));
  if (!ctx)
    {
      return VAPI_ENOMEM;
    }
  ctx->context_counter = 0;
  ctx->vapi_msg_id_t_to_vl_msg_id =
    malloc (__vapi_metadata.count *
	    sizeof (*ctx->vapi_msg_id_t_to_vl_msg_id));
  if (!ctx->vapi_msg_id_t_to_vl_msg_id)
    {
      goto fail;
    }
  clib_memset (ctx->vapi_msg_id_t_to_vl_msg_id, ~0,
	       __vapi_metadata.count *
	       sizeof (*ctx->vapi_msg_id_t_to_vl_msg_id));
  ctx->event_cbs = calloc (__vapi_metadata.count, sizeof (*ctx->event_cbs));
  if (!ctx->event_cbs)
    {
      goto fail;
    }
  pthread_mutex_init (&ctx->requests_mutex, NULL);
  *result = ctx;
  clib_time_init (&ctx->time);
  return VAPI_OK;
fail:
  vapi_ctx_free (ctx);
  return VAPI_ENOMEM;
}

void
vapi_ctx_free (vapi_ctx_t ctx)
{
  assert (!ctx->connected);
  free (ctx->requests);
  free (ctx->vapi_msg_id_t_to_vl_msg_id);
  free (ctx->event_cbs);
  free (ctx->vl_msg_id_to_vapi_msg_t);
  pthread_mutex_destroy (&ctx->requests_mutex);
  free (ctx);
}

bool
vapi_is_msg_available (vapi_ctx_t ctx, vapi_msg_id_t id)
{
  return vapi_lookup_vl_msg_id (ctx, id) != UINT16_MAX;
}

/* Cut and paste to avoid adding dependency to client library */
__clib_nosanitize_addr static void
VL_API_VEC_UNPOISON (const void *v)
{
  const vec_header_t *vh = &((vec_header_t *) v)[-1];
  clib_mem_unpoison (vh, sizeof (*vh) + vec_len (v));
}

static void
vapi_api_name_and_crc_free (vapi_ctx_t ctx)
{
  int i;
  u8 **keys = 0;
  hash_pair_t *hp;

  if (!ctx->msg_index_by_name_and_crc)
    return;
  hash_foreach_pair (hp, ctx->msg_index_by_name_and_crc,
		     ({ vec_add1 (keys, (u8 *) hp->key); }));
  for (i = 0; i < vec_len (keys); i++)
    vec_free (keys[i]);
  vec_free (keys);
  hash_free (ctx->msg_index_by_name_and_crc);
}

static vapi_error_e
vapi_sock_get_errno (int err)
{
  switch (err)
    {
    case ENOTSOCK:
      return VAPI_ENOTSOCK;
    case EACCES:
      return VAPI_EACCES;
    case ECONNRESET:
      return VAPI_ECONNRESET;
    default:
      break;
    }
  return VAPI_ESOCK_FAILURE;
}

static vapi_error_e
vapi_sock_send (vapi_ctx_t ctx, u8 *msg)
{
  size_t n;
  struct msghdr hdr;

  const size_t len = vec_len (msg);
  const size_t total_len = len + sizeof (msgbuf_t);

  msgbuf_t msgbuf1 = {
    .q = 0,
    .gc_mark_timestamp = 0,
    .data_len = htonl (len),
  };

  struct iovec bufs[2] = {
    [0] = { .iov_base = &msgbuf1, .iov_len = sizeof (msgbuf1) },
    [1] = { .iov_base = msg, .iov_len = len },
  };

  clib_memset (&hdr, 0, sizeof (hdr));
  hdr.msg_iov = bufs;
  hdr.msg_iovlen = 2;

  n = sendmsg (ctx->client_socket.fd, &hdr, 0);
  if (n < 0)
    {
      return vapi_sock_get_errno (errno);
    }

  if (n < total_len)
    {
      return VAPI_EAGAIN;
    }

  vec_free (msg);

  return VAPI_OK;
}

static vapi_error_e
vapi_sock_send2 (vapi_ctx_t ctx, u8 *msg1, u8 *msg2)
{
  size_t n;
  struct msghdr hdr;

  const size_t len1 = vec_len (msg1);
  const size_t len2 = vec_len (msg2);
  const size_t total_len = len1 + len2 + 2 * sizeof (msgbuf_t);

  msgbuf_t msgbuf1 = {
    .q = 0,
    .gc_mark_timestamp = 0,
    .data_len = htonl (len1),
  };

  msgbuf_t msgbuf2 = {
    .q = 0,
    .gc_mark_timestamp = 0,
    .data_len = htonl (len2),
  };

  struct iovec bufs[4] = {
    [0] = { .iov_base = &msgbuf1, .iov_len = sizeof (msgbuf1) },
    [1] = { .iov_base = msg1, .iov_len = len1 },
    [2] = { .iov_base = &msgbuf2, .iov_len = sizeof (msgbuf2) },
    [3] = { .iov_base = msg2, .iov_len = len2 },
  };

  clib_memset (&hdr, 0, sizeof (hdr));
  hdr.msg_iov = bufs;
  hdr.msg_iovlen = 4;

  n = sendmsg (ctx->client_socket.fd, &hdr, 0);
  if (n < 0)
    {
      return vapi_sock_get_errno (errno);
    }

  if (n < total_len)
    {
      return VAPI_EAGAIN;
    }

  vec_free (msg1);
  vec_free (msg2);

  return VAPI_OK;
}

static vapi_error_e
vapi_sock_recv_internal (vapi_ctx_t ctx, u8 **vec_msg, u32 timeout)
{
  clib_socket_t *sock = &ctx->client_socket;
  u32 data_len = 0, msg_size;
  msgbuf_t *mbp = 0;
  ssize_t n, current_rx_index;
  f64 deadline;
  vapi_error_e rv = VAPI_EAGAIN;

  if (ctx->client_socket.fd == 0)
    return VAPI_ENOTSOCK;

  deadline = clib_time_now (&ctx->time) + timeout;

  while (1)
    {
      current_rx_index = vec_len (sock->rx_buffer);
      while (current_rx_index < sizeof (*mbp))
	{
	  vec_validate (sock->rx_buffer, sizeof (*mbp) - 1);
	  n = recv (sock->fd, sock->rx_buffer + current_rx_index,
		    sizeof (*mbp) - current_rx_index, MSG_DONTWAIT);
	  if (n < 0)
	    {
	      if (errno == EAGAIN && clib_time_now (&ctx->time) >= deadline)
		return VAPI_EAGAIN;

	      if (errno == EAGAIN)
		continue;

	      clib_unix_warning ("socket_read");
	      vec_set_len (sock->rx_buffer, current_rx_index);
	      return vapi_sock_get_errno (errno);
	    }
	  current_rx_index += n;
	}
      vec_set_len (sock->rx_buffer, current_rx_index);

      mbp = (msgbuf_t *) (sock->rx_buffer);
      data_len = ntohl (mbp->data_len);
      current_rx_index = vec_len (sock->rx_buffer);
      vec_validate (sock->rx_buffer, current_rx_index + data_len);
      mbp = (msgbuf_t *) (sock->rx_buffer);
      msg_size = data_len + sizeof (*mbp);

      while (current_rx_index < msg_size)
	{
	  n = recv (sock->fd, sock->rx_buffer + current_rx_index,
		    msg_size - current_rx_index, MSG_DONTWAIT);
	  if (n < 0)
	    {
	      if (errno == EAGAIN && clib_time_now (&ctx->time) >= deadline)
		return VAPI_EAGAIN;

	      if (errno == EAGAIN)
		continue;

	      clib_unix_warning ("socket_read");
	      vec_set_len (sock->rx_buffer, current_rx_index);
	      return vapi_sock_get_errno (errno);
	    }
	  current_rx_index += n;
	}
      vec_set_len (sock->rx_buffer, current_rx_index);

      if (vec_len (sock->rx_buffer) >= data_len + sizeof (*mbp))
	{
	  if (data_len)
	    {
	      vec_add (*vec_msg, mbp->data, data_len);
	      rv = VAPI_OK;
	    }
	  else
	    {
	      *vec_msg = 0;
	    }

	  if (vec_len (sock->rx_buffer) == data_len + sizeof (*mbp))
	    vec_set_len (sock->rx_buffer, 0);
	  else
	    vec_delete (sock->rx_buffer, data_len + sizeof (*mbp), 0);
	  mbp = 0;

	  /* Quit if we're out of data, and not expecting a ping reply */
	  if (vec_len (sock->rx_buffer) == 0)
	    break;
	}
    }
  return rv;
}

static void
vapi_memclnt_create_v2_reply_t_handler (vapi_ctx_t ctx,
					vl_api_memclnt_create_v2_reply_t *mp)
{
  serialize_main_t _sm, *sm = &_sm;
  u8 *tblv;
  u32 nmsgs;
  int i;
  u8 *name_and_crc;
  u32 msg_index;

  ctx->my_client_index = mp->index;

  /* Clean out any previous hash table (unlikely) */
  vapi_api_name_and_crc_free (ctx);

  ctx->msg_index_by_name_and_crc = hash_create_string (0, sizeof (uword));

  /* Recreate the vnet-side API message handler table */
  tblv = uword_to_pointer (mp->message_table, u8 *);
  unserialize_open_data (sm, tblv, vec_len (tblv));
  unserialize_integer (sm, &nmsgs, sizeof (u32));

  VL_API_VEC_UNPOISON (tblv);

  for (i = 0; i < nmsgs; i++)
    {
      msg_index = unserialize_likely_small_unsigned_integer (sm);
      unserialize_cstring (sm, (char **) &name_and_crc);
      hash_set_mem (ctx->msg_index_by_name_and_crc, name_and_crc, msg_index);
    }
}

static void
vapi_sockclnt_create_reply_t_handler (vapi_ctx_t ctx,
				      vl_api_sockclnt_create_reply_t *mp)
{
  int i;
  u8 *name_and_crc;

  ctx->my_client_index = mp->index;

  /* Clean out any previous hash table (unlikely) */
  vapi_api_name_and_crc_free (ctx);

  ctx->msg_index_by_name_and_crc = hash_create_string (0, sizeof (uword));

  for (i = 0; i < be16toh (mp->count); i++)
    {
      name_and_crc = format (0, "%s%c", mp->message_table[i].name, 0);
      hash_set_mem (ctx->msg_index_by_name_and_crc, name_and_crc,
		    be16toh (mp->message_table[i].index));
    }
}

static void
vapi_memclnt_delete_reply_t_handler (vapi_ctx_t ctx,
				     vl_api_memclnt_delete_reply_t *mp)
{
  void *oldheap;
  oldheap = vl_msg_push_heap ();
  svm_queue_free (ctx->vl_input_queue);
  vl_msg_pop_heap (oldheap);

  ctx->my_client_index = ~0;
  ctx->vl_input_queue = 0;
}

static void
vapi_sockclnt_delete_reply_t_handler (vapi_ctx_t ctx,
				      vl_api_sockclnt_delete_reply_t *mp)
{
  ctx->my_client_index = ~0;
  ctx->vl_input_queue = 0;
}

static int
vapi_shm_client_connect (vapi_ctx_t ctx, const char *name, int ctx_quota,
			 int input_queue_size, bool keepalive)
{
  vl_api_memclnt_create_v2_t *mp;
  vl_api_memclnt_create_v2_reply_t *rp;
  svm_queue_t *vl_input_queue;
  vl_shmem_hdr_t *shmem_hdr;
  int rv = 0;
  void *oldheap;
  api_main_t *am = vlibapi_get_main ();

  shmem_hdr = am->shmem_hdr;

  if (shmem_hdr == 0 || shmem_hdr->vl_input_queue == 0)
    {
      clib_warning ("shmem_hdr / input queue NULL");
      return VAPI_ECON_FAIL;
    }

  clib_mem_unpoison (shmem_hdr, sizeof (*shmem_hdr));
  VL_MSG_API_SVM_QUEUE_UNPOISON (shmem_hdr->vl_input_queue);

  oldheap = vl_msg_push_heap ();
  vl_input_queue =
    svm_queue_alloc_and_init (input_queue_size, sizeof (uword), getpid ());
  vl_msg_pop_heap (oldheap);

  ctx->my_client_index = ~0;
  ctx->vl_input_queue = vl_input_queue;

  mp = vl_msg_api_alloc_as_if_client (sizeof (vl_api_memclnt_create_v2_t));
  clib_memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = ntohs (VL_API_MEMCLNT_CREATE_V2);
  mp->ctx_quota = ctx_quota;
  mp->input_queue = (uword) vl_input_queue;
  strncpy ((char *) mp->name, name, sizeof (mp->name) - 1);
  mp->keepalive = keepalive;

  vl_msg_api_send_shmem (shmem_hdr->vl_input_queue, (u8 *) &mp);

  while (1)
    {
      int qstatus;
      struct timespec ts, tsrem;
      int i;

      /* Wait up to 10 seconds */
      for (i = 0; i < 1000; i++)
	{
	  qstatus =
	    svm_queue_sub (vl_input_queue, (u8 *) &rp, SVM_Q_NOWAIT, 0);
	  if (qstatus == 0)
	    goto read_one_msg;
	  ts.tv_sec = 0;
	  ts.tv_nsec = 10000 * 1000; /* 10 ms */
	  while (nanosleep (&ts, &tsrem) < 0)
	    ts = tsrem;
	}
      /* Timeout... */
      return VAPI_ECON_FAIL;

    read_one_msg:
      VL_MSG_API_UNPOISON (rp);
      if (ntohs (rp->_vl_msg_id) != VL_API_MEMCLNT_CREATE_V2_REPLY)
	{
	  clib_warning ("unexpected reply: id %d", ntohs (rp->_vl_msg_id));
	  continue;
	}
      rv = clib_net_to_host_u32 (rp->response);
      vapi_memclnt_create_v2_reply_t_handler (ctx, rp);
      break;
    }
  return (rv);
}

static int
vapi_sock_client_connect (vapi_ctx_t ctx, char *path, const char *name)
{
  clib_error_t *error;
  clib_socket_t *sock;
  vl_api_sockclnt_create_t *mp;
  vl_api_sockclnt_create_reply_t *rp;
  int rv = 0;
  u8 *msg = 0;

  ctx->my_client_index = ~0;

  if (ctx->client_socket.fd)
    return VAPI_EINVAL;

  if (name == 0)
    return VAPI_EINVAL;

  sock = &ctx->client_socket;
  sock->config = path ? path : API_SOCKET_FILE;
  sock->flags = CLIB_SOCKET_F_IS_CLIENT;

  if ((error = clib_socket_init (sock)))
    {
      clib_error_report (error);
      return VAPI_ECON_FAIL;
    }

  mp = vapi_sock_msg_alloc (sizeof (vl_api_sockclnt_create_t));
  mp->_vl_msg_id = ntohs (VL_API_SOCKCLNT_CREATE);
  strncpy ((char *) mp->name, name, sizeof (mp->name) - 1);

  if (vapi_sock_send (ctx, (void *) mp) != VAPI_OK)
    {
      return VAPI_ECON_FAIL;
    }

  while (1)
    {
      int qstatus;
      struct timespec ts, tsrem;
      int i;

      /* Wait up to 10 seconds */
      for (i = 0; i < 1000; i++)
	{
	  qstatus = vapi_sock_recv_internal (ctx, &msg, 0);

	  if (qstatus == 0)
	    goto read_one_msg;
	  ts.tv_sec = 0;
	  ts.tv_nsec = 10000 * 1000; /* 10 ms */
	  while (nanosleep (&ts, &tsrem) < 0)
	    ts = tsrem;
	}
      /* Timeout... */
      return -1;

    read_one_msg:
      if (vec_len (msg) == 0)
	continue;

      rp = (void *) msg;
      if (ntohs (rp->_vl_msg_id) != VL_API_SOCKCLNT_CREATE_REPLY)
	{
	  clib_warning ("unexpected reply: id %d", ntohs (rp->_vl_msg_id));
	  continue;
	}
      rv = clib_net_to_host_u32 (rp->response);
      vapi_sockclnt_create_reply_t_handler (ctx, rp);
      break;
    }
  return (rv);
}

static void
vapi_shm_client_send_disconnect (vapi_ctx_t ctx, u8 do_cleanup)
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
  mp->index = ctx->my_client_index;
  mp->do_cleanup = do_cleanup;

  vl_msg_api_send_shmem (shmem_hdr->vl_input_queue, (u8 *) &mp);
}

static vapi_error_e
vapi_sock_client_send_disconnect (vapi_ctx_t ctx)
{
  vl_api_sockclnt_delete_t *mp;

  mp = vapi_msg_alloc (ctx, sizeof (vl_api_sockclnt_delete_t));
  clib_memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = ntohs (VL_API_SOCKCLNT_DELETE);
  mp->client_index = ctx->my_client_index;

  return vapi_sock_send (ctx, (void *) mp);
}

static int
vapi_shm_client_disconnect (vapi_ctx_t ctx)
{
  vl_api_memclnt_delete_reply_t *rp;
  svm_queue_t *vl_input_queue;
  time_t begin;
  msgbuf_t *msgbuf;

  vl_input_queue = ctx->vl_input_queue;
  vapi_shm_client_send_disconnect (ctx, 0 /* wait for reply */);

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
	  ctx->my_client_index = ~0;
	  return VAPI_ENORESP;
	}
      if (svm_queue_sub (vl_input_queue, (u8 *) &rp, SVM_Q_NOWAIT, 0) < 0)
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

  vapi_api_name_and_crc_free (ctx);
  return 0;
}

static vapi_error_e
vapi_sock_client_disconnect (vapi_ctx_t ctx)
{
  vl_api_sockclnt_delete_reply_t *rp;
  u8 *msg = 0;
  msgbuf_t *msgbuf;
  int rv;
  f64 deadline;

  deadline = clib_time_now (&ctx->time) + 2;

  do
    {
      rv = vapi_sock_client_send_disconnect (ctx);
    }
  while (clib_time_now (&ctx->time) < deadline && rv != VAPI_OK);

  while (1)
    {
      if (clib_time_now (&ctx->time) >= deadline)
	{
	  clib_warning ("peer unresponsive, give up");
	  ctx->my_client_index = ~0;
	  return VAPI_ENORESP;
	}

      if (vapi_sock_recv_internal (ctx, &msg, 0) != VAPI_OK)
	continue;

      msgbuf = (void *) msg;
      rp = (void *) msgbuf->data;
      /* drain the queue */
      if (ntohs (rp->_vl_msg_id) != VL_API_SOCKCLNT_DELETE_REPLY)
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

  clib_socket_close (&ctx->client_socket);
  vapi_api_name_and_crc_free (ctx);
  return VAPI_OK;
}

int
vapi_client_disconnect (vapi_ctx_t ctx)
{
  if (ctx->use_uds)
    {
      return vapi_sock_client_disconnect (ctx);
    }
  return vapi_shm_client_disconnect (ctx);
}

u32
vapi_api_get_msg_index (vapi_ctx_t ctx, u8 *name_and_crc)
{
  uword *p;

  if (ctx->msg_index_by_name_and_crc)
    {
      p = hash_get_mem (ctx->msg_index_by_name_and_crc, name_and_crc);
      if (p)
	return p[0];
    }
  return ~0;
}

vapi_error_e
vapi_connect_ex (vapi_ctx_t ctx, const char *name, const char *path,
		 int max_outstanding_requests, int response_queue_size,
		 vapi_mode_e mode, bool handle_keepalives, bool use_uds)
{
  int rv;

  if (response_queue_size <= 0 || max_outstanding_requests <= 0)
    {
      return VAPI_EINVAL;
    }

  if (!clib_mem_get_per_cpu_heap () && !clib_mem_init (0, 1024L * 1024 * 32))
    {
      return VAPI_ENOMEM;
    }

  ctx->requests_size = max_outstanding_requests;
  const size_t size = ctx->requests_size * sizeof (*ctx->requests);
  void *tmp = realloc (ctx->requests, size);
  if (!tmp)
    {
      return VAPI_ENOMEM;
    }
  ctx->requests = tmp;
  clib_memset (ctx->requests, 0, size);
  /* coverity[MISSING_LOCK] - 177211 requests_mutex is not needed here */
  ctx->requests_start = ctx->requests_count = 0;
  ctx->use_uds = use_uds;

  if (use_uds)
    {
      if (vapi_sock_client_connect (ctx, (char *) path, name) < 0)
	{
	  return VAPI_ECON_FAIL;
	}
    }
  else
    {
      if (path)
	{
	  VAPI_DBG ("set memory root path `%s'", path);
	  vl_set_memory_root_path ((char *) path);
	}
      static char api_map[] = "/vpe-api";
      VAPI_DBG ("client api map `%s'", api_map);
      if ((rv = vl_map_shmem (api_map, 0 /* is_vlib */)) < 0)
	{
	  return VAPI_EMAP_FAIL;
	}
      VAPI_DBG ("connect client `%s'", name);
      if (vapi_shm_client_connect (ctx, (char *) name, 0, response_queue_size,
				   true) < 0)
	{
	  vl_client_api_unmap ();
	  return VAPI_ECON_FAIL;
	}
#if VAPI_DEBUG_CONNECT
  VAPI_DBG ("start probing messages");
#endif
    }

  int i;
  for (i = 0; i < __vapi_metadata.count; ++i)
    {
      vapi_message_desc_t *m = __vapi_metadata.msgs[i];
      u8 scratch[m->name_with_crc_len + 1];
      memcpy (scratch, m->name_with_crc, m->name_with_crc_len + 1);
      u32 id = vapi_api_get_msg_index (ctx, scratch);

      if (VAPI_INVALID_MSG_ID != id)
	{
	  if (id > UINT16_MAX)
	    {
	      VAPI_ERR ("Returned vl_msg_id `%u' > UINT16MAX `%u'!", id,
			UINT16_MAX);
	      rv = VAPI_EINVAL;
	      goto fail;
	    }
	  if (id > ctx->vl_msg_id_max)
	    {
	      vapi_msg_id_t *tmp =
		realloc (ctx->vl_msg_id_to_vapi_msg_t,
			 sizeof (*ctx->vl_msg_id_to_vapi_msg_t) * (id + 1));
	      if (!tmp)
		{
		  rv = VAPI_ENOMEM;
		  goto fail;
		}
	      ctx->vl_msg_id_to_vapi_msg_t = tmp;
	      ctx->vl_msg_id_max = id;
	    }
	  ctx->vl_msg_id_to_vapi_msg_t[id] = m->id;
	  ctx->vapi_msg_id_t_to_vl_msg_id[m->id] = id;
#if VAPI_DEBUG_CONNECT
	  VAPI_DBG ("Message `%s' has vl_msg_id `%u'", m->name_with_crc,
		    (unsigned) id);
#endif
	}
      else
	{
	  ctx->vapi_msg_id_t_to_vl_msg_id[m->id] = UINT16_MAX;
	  VAPI_DBG ("Message `%s' not available", m->name_with_crc);
	}
    }
#if VAPI_DEBUG_CONNECT
  VAPI_DBG ("finished probing messages");
#endif
  if (!vapi_is_msg_available (ctx, vapi_msg_id_control_ping) ||
      !vapi_is_msg_available (ctx, vapi_msg_id_control_ping_reply))
    {
      VAPI_ERR (
	"control ping or control ping reply not available, cannot connect");
      rv = VAPI_EINCOMPATIBLE;
      goto fail;
    }
  ctx->mode = mode;
  ctx->connected = true;
  if (vapi_is_msg_available (ctx, vapi_msg_id_memclnt_keepalive))
    {
      ctx->handle_keepalives = handle_keepalives;
    }
  else
    {
      ctx->handle_keepalives = false;
    }
  return VAPI_OK;
fail:
  vapi_client_disconnect (ctx);
  vl_client_api_unmap ();
  return rv;
}

vapi_error_e
vapi_connect (vapi_ctx_t ctx, const char *name, const char *chroot_prefix,
	      int max_outstanding_requests, int response_queue_size,
	      vapi_mode_e mode, bool handle_keepalives)
{
  return vapi_connect_ex (ctx, name, chroot_prefix, max_outstanding_requests,
			  response_queue_size, mode, handle_keepalives, false);
}

/*
 * API client running in the same process as VPP
 */
vapi_error_e
vapi_connect_from_vpp (vapi_ctx_t ctx, const char *name,
		       int max_outstanding_requests, int response_queue_size,
		       vapi_mode_e mode, bool handle_keepalives)
{
  int rv;

  if (ctx->use_uds)
    {
      return VAPI_ENOTSUP;
    }

  if (response_queue_size <= 0 || max_outstanding_requests <= 0)
    {
      return VAPI_EINVAL;
    }

  ctx->requests_size = max_outstanding_requests;
  const size_t size = ctx->requests_size * sizeof (*ctx->requests);
  void *tmp = realloc (ctx->requests, size);
  if (!tmp)
    {
      return VAPI_ENOMEM;
    }
  ctx->requests = tmp;
  clib_memset (ctx->requests, 0, size);
  /* coverity[MISSING_LOCK] - 177211 requests_mutex is not needed here */
  ctx->requests_start = ctx->requests_count = 0;

  VAPI_DBG ("connect client `%s'", name);
  if (vapi_shm_client_connect (ctx, (char *) name, 0, response_queue_size,
			       handle_keepalives) < 0)
    {
      return VAPI_ECON_FAIL;
    }

  int i;
  for (i = 0; i < __vapi_metadata.count; ++i)
    {
      vapi_message_desc_t *m = __vapi_metadata.msgs[i];
      u8 scratch[m->name_with_crc_len + 1];
      memcpy (scratch, m->name_with_crc, m->name_with_crc_len + 1);
      u32 id = vapi_api_get_msg_index (ctx, scratch);
      if (VAPI_INVALID_MSG_ID != id)
	{
	  if (id > UINT16_MAX)
	    {
	      VAPI_ERR ("Returned vl_msg_id `%u' > UINT16MAX `%u'!", id,
			UINT16_MAX);
	      rv = VAPI_EINVAL;
	      goto fail;
	    }
	  if (id > ctx->vl_msg_id_max)
	    {
	      vapi_msg_id_t *tmp =
		realloc (ctx->vl_msg_id_to_vapi_msg_t,
			 sizeof (*ctx->vl_msg_id_to_vapi_msg_t) * (id + 1));
	      if (!tmp)
		{
		  rv = VAPI_ENOMEM;
		  goto fail;
		}
	      ctx->vl_msg_id_to_vapi_msg_t = tmp;
	      ctx->vl_msg_id_max = id;
	    }
	  ctx->vl_msg_id_to_vapi_msg_t[id] = m->id;
	  ctx->vapi_msg_id_t_to_vl_msg_id[m->id] = id;
	}
      else
	{
	  ctx->vapi_msg_id_t_to_vl_msg_id[m->id] = UINT16_MAX;
	  VAPI_DBG ("Message `%s' not available", m->name_with_crc);
	}
    }
  if (!vapi_is_msg_available (ctx, vapi_msg_id_control_ping) ||
      !vapi_is_msg_available (ctx, vapi_msg_id_control_ping_reply))
    {
      VAPI_ERR (
	"control ping or control ping reply not available, cannot connect");
      rv = VAPI_EINCOMPATIBLE;
      goto fail;
    }
  ctx->mode = mode;
  ctx->connected = true;
  if (vapi_is_msg_available (ctx, vapi_msg_id_memclnt_keepalive))
    {
      ctx->handle_keepalives = handle_keepalives;
    }
  else
    {
      ctx->handle_keepalives = false;
    }
  return VAPI_OK;
fail:
  vapi_client_disconnect (ctx);
  return rv;
}

vapi_error_e
vapi_disconnect_from_vpp (vapi_ctx_t ctx)
{
  if (!ctx->connected)
    {
      return VAPI_EINVAL;
    }

  if (ctx->use_uds)
    {
      return VAPI_ENOTSUP;
    }

  vl_api_memclnt_delete_reply_t *rp;
  svm_queue_t *vl_input_queue;
  time_t begin;
  vl_input_queue = ctx->vl_input_queue;
  vapi_shm_client_send_disconnect (ctx, 0 /* wait for reply */);

  /*
   * Have to be careful here, in case the client is disconnecting
   * because e.g. the vlib process died, or is unresponsive.
   */
  begin = time (0);
  vapi_error_e rv = VAPI_OK;
  while (1)
    {
      time_t now;

      now = time (0);

      if (now >= (begin + 2))
	{
	  clib_warning ("peer unresponsive, give up");
	  ctx->my_client_index = ~0;
	  rv = VAPI_ENORESP;
	  goto fail;
	}
      if (svm_queue_sub (vl_input_queue, (u8 *) &rp, SVM_Q_NOWAIT, 0) < 0)
	continue;

      VL_MSG_API_UNPOISON (rp);

      /* drain the queue */
      if (ntohs (rp->_vl_msg_id) != VL_API_MEMCLNT_DELETE_REPLY)
	{
	  clib_warning ("queue drain: %d", ntohs (rp->_vl_msg_id));
	  vl_msg_api_free (rp);
	  continue;
	}
      vapi_memclnt_delete_reply_t_handler (
	ctx, (void *) rp /*, ntohl (msgbuf->data_len)*/);
      break;
    }
fail:
  vapi_api_name_and_crc_free (ctx);

  ctx->connected = false;
  return rv;
}

static vapi_error_e
vapi_shm_disconnect (vapi_ctx_t ctx)
{
  vl_api_memclnt_delete_reply_t *rp;
  svm_queue_t *vl_input_queue;
  time_t begin;
  vl_input_queue = ctx->vl_input_queue;
  vapi_shm_client_send_disconnect (ctx, 0 /* wait for reply */);

  /*
   * Have to be careful here, in case the client is disconnecting
   * because e.g. the vlib process died, or is unresponsive.
   */
  begin = time (0);
  vapi_error_e rv = VAPI_OK;
  while (1)
    {
      time_t now;

      now = time (0);

      if (now >= (begin + 2))
	{
	  clib_warning ("peer unresponsive, give up");
	  ctx->my_client_index = ~0;
	  rv = VAPI_ENORESP;
	  goto fail;
	}
      if (svm_queue_sub (vl_input_queue, (u8 *) &rp, SVM_Q_NOWAIT, 0) < 0)
	continue;

      VL_MSG_API_UNPOISON (rp);

      /* drain the queue */
      if (ntohs (rp->_vl_msg_id) != VL_API_MEMCLNT_DELETE_REPLY)
	{
	  clib_warning ("queue drain: %d", ntohs (rp->_vl_msg_id));
	  vl_msg_api_free (rp);
	  continue;
	}
      vapi_memclnt_delete_reply_t_handler (
	ctx, (void *) rp /*, ntohl (msgbuf->data_len)*/);
      break;
    }
fail:
  vapi_api_name_and_crc_free (ctx);

  vl_client_api_unmap ();
#if VAPI_DEBUG_ALLOC
  vapi_to_be_freed_validate ();
#endif
  ctx->connected = false;
  return rv;
}

static vapi_error_e
vapi_sock_disconnect (vapi_ctx_t ctx)
{
  vl_api_sockclnt_delete_reply_t *rp;
  time_t begin;
  u8 *msg = 0;

  vapi_sock_client_send_disconnect (ctx);

  begin = time (0);
  vapi_error_e rv = VAPI_OK;
  while (1)
    {
      time_t now;

      now = time (0);

      if (now >= (begin + 2))
	{
	  clib_warning ("peer unresponsive, give up");
	  ctx->my_client_index = ~0;
	  rv = VAPI_ENORESP;
	  goto fail;
	}
      if (vapi_sock_recv_internal (ctx, &msg, 0) < 0)
	continue;

      if (vec_len (msg) == 0)
	continue;

      rp = (void *) msg;

      /* drain the queue */
      if (ntohs (rp->_vl_msg_id) != VL_API_SOCKCLNT_DELETE_REPLY)
	{
	  clib_warning ("queue drain: %d", ntohs (rp->_vl_msg_id));
	  continue;
	}
      vapi_sockclnt_delete_reply_t_handler (
	ctx, (void *) rp /*, ntohl (msgbuf->data_len)*/);
      break;
    }
fail:
  clib_socket_close (&ctx->client_socket);
  vapi_api_name_and_crc_free (ctx);

  ctx->connected = false;
  return rv;
}

vapi_error_e
vapi_disconnect (vapi_ctx_t ctx)
{
  if (!ctx->connected)
    {
      return VAPI_EINVAL;
    }

  if (ctx->use_uds)
    {
      return vapi_sock_disconnect (ctx);
    }
  return vapi_shm_disconnect (ctx);
}

vapi_error_e
vapi_get_fd (vapi_ctx_t ctx, int *fd)
{
  if (ctx->use_uds && fd)
    {
      *fd = ctx->client_socket.fd;
      return VAPI_OK;
    }
  return VAPI_ENOTSUP;
}

#if VAPI_DEBUG
static void
vapi_debug_log (vapi_ctx_t ctx, void *msg, const char *fun)
{
  unsigned msgid = be16toh (*(u16 *) msg);
  if (msgid <= ctx->vl_msg_id_max)
    {
      vapi_msg_id_t id = ctx->vl_msg_id_to_vapi_msg_t[msgid];
      if (id < __vapi_metadata.count)
	{
	  VAPI_DBG ("%s msg@%p:%u[%s]", fun, msg, msgid,
		    __vapi_metadata.msgs[id]->name);
	}
      else
	{
	  VAPI_DBG ("%s msg@%p:%u[UNKNOWN]", fun, msg, msgid);
	}
    }
  else
    {
      VAPI_DBG ("%s msg@%p:%u[UNKNOWN]", fun, msg, msgid);
    }
}
#endif

static vapi_error_e
vapi_shm_send (vapi_ctx_t ctx, void *msg)
{
  int rv = VAPI_OK;
  int tmp;
  svm_queue_t *q = vlibapi_get_main ()->shmem_hdr->vl_input_queue;
#if VAPI_DEBUG
  vapi_debug_log (ctx, msg, "send");
#endif
  tmp =
    svm_queue_add (q, (u8 *) &msg, VAPI_MODE_BLOCKING == ctx->mode ? 0 : 1);
  if (tmp < 0)
    {
      rv = VAPI_EAGAIN;
    }
  else
    VL_MSG_API_POISON (msg);

  return rv;
}

vapi_error_e
vapi_send (vapi_ctx_t ctx, void *msg)
{
  vapi_error_e rv = VAPI_OK;
  if (!ctx || !msg || !ctx->connected)
    {
      rv = VAPI_EINVAL;
      goto out;
    }

  if (ctx->use_uds)
    {
      rv = vapi_sock_send (ctx, msg);
    }
  else
    {
      rv = vapi_shm_send (ctx, msg);
    }

out:
  VAPI_DBG ("vapi_send() rv = %d", rv);
  return rv;
}

static vapi_error_e
vapi_shm_send2 (vapi_ctx_t ctx, void *msg1, void *msg2)
{
  vapi_error_e rv = VAPI_OK;
  svm_queue_t *q = vlibapi_get_main ()->shmem_hdr->vl_input_queue;
#if VAPI_DEBUG
  vapi_debug_log (ctx, msg1, "send2");
  vapi_debug_log (ctx, msg2, "send2");
#endif
  int tmp = svm_queue_add2 (q, (u8 *) &msg1, (u8 *) &msg2,
			    VAPI_MODE_BLOCKING == ctx->mode ? 0 : 1);
  if (tmp < 0)
    {
      rv = VAPI_EAGAIN;
    }
  else
    VL_MSG_API_POISON (msg1);

  return rv;
}

vapi_error_e
vapi_send2 (vapi_ctx_t ctx, void *msg1, void *msg2)
{
  vapi_error_e rv = VAPI_OK;
  if (!ctx || !msg1 || !msg2 || !ctx->connected)
    {
      rv = VAPI_EINVAL;
      goto out;
    }

  if (ctx->use_uds)
    {
      rv = vapi_sock_send2 (ctx, msg1, msg2);
    }
  else
    {
      rv = vapi_shm_send2 (ctx, msg1, msg2);
    }

out:
  VAPI_DBG ("vapi_send() rv = %d", rv);
  return rv;
}

static vapi_error_e
vapi_shm_recv (vapi_ctx_t ctx, void **msg, size_t *msg_size,
	       svm_q_conditional_wait_t cond, u32 time)
{
  vapi_error_e rv = VAPI_OK;
  uword data;

  svm_queue_t *q = ctx->vl_input_queue;

  VAPI_DBG ("doing shm queue sub");

  int tmp = svm_queue_sub (q, (u8 *) & data, cond, time);

  if (tmp != 0)
    {
      return VAPI_EAGAIN;
    }

      VL_MSG_API_UNPOISON ((void *) data);
#if VAPI_DEBUG_ALLOC
      vapi_add_to_be_freed ((void *) data);
#endif
      msgbuf_t *msgbuf =
	(msgbuf_t *) ((u8 *) data - offsetof (msgbuf_t, data));
      if (!msgbuf->data_len)
	{
	  vapi_msg_free (ctx, (u8 *) data);
	  return VAPI_EAGAIN;
	}
      *msg = (u8 *) data;
      *msg_size = ntohl (msgbuf->data_len);

#if VAPI_DEBUG
      vapi_debug_log (ctx, msg, "recv");
#endif

      return rv;
}

static vapi_error_e
vapi_sock_recv (vapi_ctx_t ctx, void **msg, size_t *msg_size, u32 time)
{
  vapi_error_e rv = VAPI_OK;
  u8 *data = 0;
  if (time == 0 && ctx->mode == VAPI_MODE_BLOCKING)
    time = 1;

  rv = vapi_sock_recv_internal (ctx, &data, time);

  if (rv != VAPI_OK)
    {
      return rv;
    }

  *msg = data;
  *msg_size = vec_len (data);

#if VAPI_DEBUG
  vapi_debug_log (ctx, msg, "recv");
#endif

  return rv;
}

vapi_error_e
vapi_recv (vapi_ctx_t ctx, void **msg, size_t *msg_size,
	   svm_q_conditional_wait_t cond, u32 time)
{
  if (!ctx || !ctx->connected || !msg || !msg_size)
    {
      return VAPI_EINVAL;
    }
  vapi_error_e rv = VAPI_OK;

again:
  if (ctx->use_uds)
    {
      rv = vapi_sock_recv (ctx, msg, msg_size, time);
    }
  else
    {
      rv = vapi_shm_recv (ctx, msg, msg_size, cond, time);
    }

  if (rv != VAPI_OK)
    return rv;

  if (ctx->handle_keepalives)
    {
      unsigned msgid = be16toh (*(u16 *) *msg);
      if (msgid == vapi_lookup_vl_msg_id (ctx, vapi_msg_id_memclnt_keepalive))
	{
	  vapi_msg_memclnt_keepalive_reply *reply = NULL;
	  do
	    {
	      reply = vapi_msg_alloc (ctx, sizeof (*reply));
	    }
	  while (!reply);
	  reply->header.context = vapi_get_client_index (ctx);
	  reply->header._vl_msg_id =
	    vapi_lookup_vl_msg_id (ctx, vapi_msg_id_memclnt_keepalive_reply);
	  reply->payload.retval = 0;
	  vapi_msg_memclnt_keepalive_reply_hton (reply);
	  while (VAPI_EAGAIN == vapi_send (ctx, reply))
	    ;
	  vapi_msg_free (ctx, *msg);
	  goto again;
	}
    }

  return rv;
}

vapi_error_e
vapi_wait (vapi_ctx_t ctx)
{
  if (ctx->use_uds)
    return VAPI_ENOTSUP;

  svm_queue_lock (ctx->vl_input_queue);
  svm_queue_wait (ctx->vl_input_queue);
  svm_queue_unlock (ctx->vl_input_queue);

  return VAPI_OK;
}

static vapi_error_e
vapi_dispatch_response (vapi_ctx_t ctx, vapi_msg_id_t id,
			u32 context, void *msg)
{
  int mrv;
  if (0 != (mrv = pthread_mutex_lock (&ctx->requests_mutex)))
    {
      VAPI_DBG ("pthread_mutex_lock() failed, rv=%d:%s", mrv, strerror (mrv));
      return VAPI_MUTEX_FAILURE;
    }
  int tmp = ctx->requests_start;
  const int requests_end = vapi_requests_end (ctx);
  while (ctx->requests[tmp].context != context && tmp != requests_end)
    {
      ++tmp;
      if (tmp == ctx->requests_size)
	{
	  tmp = 0;
	}
    }
  VAPI_DBG ("dispatch, search from %d, %s at %d", ctx->requests_start,
	    ctx->requests[tmp].context == context ? "matched" : "stopped",
	    tmp);
  vapi_error_e rv = VAPI_OK;
  if (ctx->requests[tmp].context == context)
    {
      while (ctx->requests_start != tmp)
	{
	  VAPI_ERR ("No response to req with context=%u",
		    (unsigned) ctx->requests[tmp].context);
	  ctx->requests[ctx->requests_start].callback (ctx, ctx->requests
						       [ctx->
							requests_start].callback_ctx,
						       VAPI_ENORESP, true,
						       NULL);
	  clib_memset (&ctx->requests[ctx->requests_start], 0,
		       sizeof (ctx->requests[ctx->requests_start]));
	  ++ctx->requests_start;
	  --ctx->requests_count;
	  if (ctx->requests_start == ctx->requests_size)
	    {
	      ctx->requests_start = 0;
	    }
	}
      // now ctx->requests_start == tmp
      int payload_offset = vapi_get_payload_offset (id);
      void *payload = ((u8 *) msg) + payload_offset;
      bool is_last = true;
      switch (ctx->requests[tmp].type)
	{
	case VAPI_REQUEST_STREAM:
	  if (ctx->requests[tmp].response_id == id)
	    {
	      is_last = false;
	    }
	  else
	    {
	      VAPI_DBG ("Stream response ID doesn't match current ID, move to "
			"next ID");
	      clib_memset (&ctx->requests[tmp], 0,
			   sizeof (ctx->requests[tmp]));
	      ++ctx->requests_start;
	      --ctx->requests_count;
	      if (ctx->requests_start == ctx->requests_size)
		{
		  ctx->requests_start = 0;
		}
	      tmp = ctx->requests_start;
	      if (ctx->requests[tmp].context != context)
		{
		  VAPI_ERR ("Unexpected context %u, expected context %u!",
			    ctx->requests[tmp].context, context);
		}
	    }
	  break;
	case VAPI_REQUEST_DUMP:
	  if (vapi_msg_id_control_ping_reply == id)
	    {
	      payload = NULL;
	    }
	  else
	    {
	      is_last = false;
	    }
	  break;
	case VAPI_REQUEST_REG:
	  break;
	}
      if (payload_offset != -1)
	{
	  rv = ctx->requests[tmp].callback (
	    ctx, ctx->requests[tmp].callback_ctx, VAPI_OK, is_last, payload);
	}
      else
	{
	  /* this is a message without payload, so bend the callback a little
	   */
	  rv =
	    ((vapi_error_e (*)(vapi_ctx_t, void *, vapi_error_e, bool))
	     ctx->requests[tmp].callback) (ctx,
					   ctx->requests[tmp].callback_ctx,
					   VAPI_OK, is_last);
	}
      if (is_last)
	{
	  clib_memset (&ctx->requests[ctx->requests_start], 0,
		       sizeof (ctx->requests[ctx->requests_start]));
	  ++ctx->requests_start;
	  --ctx->requests_count;
	  if (ctx->requests_start == ctx->requests_size)
	    {
	      ctx->requests_start = 0;
	    }
	}
      VAPI_DBG ("after dispatch, req start = %d, end = %d, count = %d",
		ctx->requests_start, requests_end, ctx->requests_count);
    }
  if (0 != (mrv = pthread_mutex_unlock (&ctx->requests_mutex)))
    {
      VAPI_DBG ("pthread_mutex_unlock() failed, rv=%d:%s", mrv,
		strerror (mrv));
      abort ();			/* this really shouldn't happen */
    }
  return rv;
}

static vapi_error_e
vapi_dispatch_event (vapi_ctx_t ctx, vapi_msg_id_t id, void *msg)
{
  if (ctx->event_cbs[id].cb)
    {
      return ctx->event_cbs[id].cb (ctx, ctx->event_cbs[id].ctx, msg);
    }
  else if (ctx->generic_cb.cb)
    {
      return ctx->generic_cb.cb (ctx, ctx->generic_cb.ctx, id, msg);
    }
  else
    {
      VAPI_DBG
	("No handler/generic handler for msg id %u[%s], message ignored",
	 (unsigned) id, __vapi_metadata.msgs[id]->name);
    }
  return VAPI_OK;
}

bool
vapi_msg_is_with_context (vapi_msg_id_t id)
{
  assert (id <= __vapi_metadata.count);
  return __vapi_metadata.msgs[id]->has_context;
}

static int
vapi_verify_msg_size (vapi_msg_id_t id, void *buf, uword buf_size)
{
  assert (id < __vapi_metadata.count);
  return __vapi_metadata.msgs[id]->verify_msg_size (buf, buf_size);
}

vapi_error_e
vapi_dispatch_one_timedwait (vapi_ctx_t ctx, u32 wait_time)
{
  VAPI_DBG ("vapi_dispatch_one()");
  void *msg;
  uword size;
  svm_q_conditional_wait_t cond =
    vapi_is_nonblocking (ctx) ? (wait_time ? SVM_Q_TIMEDWAIT : SVM_Q_NOWAIT) :
				      SVM_Q_WAIT;
  vapi_error_e rv = vapi_recv (ctx, &msg, &size, cond, wait_time);
  if (VAPI_OK != rv)
    {
      VAPI_DBG ("vapi_recv failed with rv=%d", rv);
      return rv;
    }
  u16 vpp_id = be16toh (*(u16 *) msg);
  if (vpp_id > ctx->vl_msg_id_max)
    {
      VAPI_ERR ("Unknown msg ID received, id `%u', out of range <0,%u>",
		(unsigned) vpp_id, (unsigned) ctx->vl_msg_id_max);
      vapi_msg_free (ctx, msg);
      return VAPI_EINVAL;
    }
  if (VAPI_INVALID_MSG_ID == (unsigned) ctx->vl_msg_id_to_vapi_msg_t[vpp_id])
    {
      VAPI_ERR ("Unknown msg ID received, id `%u' marked as not supported",
		(unsigned) vpp_id);
      vapi_msg_free (ctx, msg);
      return VAPI_EINVAL;
    }
  const vapi_msg_id_t id = ctx->vl_msg_id_to_vapi_msg_t[vpp_id];
  vapi_get_swap_to_host_func (id) (msg);
  if (vapi_verify_msg_size (id, msg, size))
    {
      vapi_msg_free (ctx, msg);
      return VAPI_EINVAL;
    }
  u32 context;
  if (vapi_msg_is_with_context (id))
    {
      context = *(u32 *) (((u8 *) msg) + vapi_get_context_offset (id));
      /* is this a message originating from VAPI? */
      VAPI_DBG ("dispatch, context is %x", context);
      if (context & context_counter_mask)
	{
	  rv = vapi_dispatch_response (ctx, id, context, msg);
	  goto done;
	}
    }
  rv = vapi_dispatch_event (ctx, id, msg);

done:
  vapi_msg_free (ctx, msg);
  return rv;
}

vapi_error_e
vapi_dispatch_one (vapi_ctx_t ctx)
{
  return vapi_dispatch_one_timedwait (ctx, 0);
}

vapi_error_e
vapi_dispatch (vapi_ctx_t ctx)
{
  vapi_error_e rv = VAPI_OK;
  while (!vapi_requests_empty (ctx))
    {
      rv = vapi_dispatch_one (ctx);
      if (VAPI_OK != rv)
	{
	  return rv;
	}
    }
  return rv;
}

void
vapi_set_event_cb (vapi_ctx_t ctx, vapi_msg_id_t id,
		   vapi_event_cb callback, void *callback_ctx)
{
  vapi_event_cb_with_ctx *c = &ctx->event_cbs[id];
  c->cb = callback;
  c->ctx = callback_ctx;
}

void
vapi_clear_event_cb (vapi_ctx_t ctx, vapi_msg_id_t id)
{
  vapi_set_event_cb (ctx, id, NULL, NULL);
}

void
vapi_set_generic_event_cb (vapi_ctx_t ctx, vapi_generic_event_cb callback,
			   void *callback_ctx)
{
  ctx->generic_cb.cb = callback;
  ctx->generic_cb.ctx = callback_ctx;
}

void
vapi_clear_generic_event_cb (vapi_ctx_t ctx)
{
  ctx->generic_cb.cb = NULL;
  ctx->generic_cb.ctx = NULL;
}

u16
vapi_lookup_vl_msg_id (vapi_ctx_t ctx, vapi_msg_id_t id)
{
  assert (id < __vapi_metadata.count);
  return ctx->vapi_msg_id_t_to_vl_msg_id[id];
}

int
vapi_get_client_index (vapi_ctx_t ctx)
{
  return ctx->my_client_index;
}

bool
vapi_is_nonblocking (vapi_ctx_t ctx)
{
  return (VAPI_MODE_NONBLOCKING == ctx->mode);
}

size_t
vapi_get_max_request_count (vapi_ctx_t ctx)
{
  return ctx->requests_size - 1;
}

int
vapi_get_payload_offset (vapi_msg_id_t id)
{
  assert (id < __vapi_metadata.count);
  return __vapi_metadata.msgs[id]->payload_offset;
}

void (*vapi_get_swap_to_host_func (vapi_msg_id_t id)) (void *msg)
{
  assert (id < __vapi_metadata.count);
  return __vapi_metadata.msgs[id]->swap_to_host;
}

void (*vapi_get_swap_to_be_func (vapi_msg_id_t id)) (void *msg)
{
  assert (id < __vapi_metadata.count);
  return __vapi_metadata.msgs[id]->swap_to_be;
}

size_t
vapi_get_context_offset (vapi_msg_id_t id)
{
  assert (id < __vapi_metadata.count);
  return __vapi_metadata.msgs[id]->context_offset;
}

vapi_msg_id_t
vapi_register_msg (vapi_message_desc_t * msg)
{
  int i = 0;
  for (i = 0; i < __vapi_metadata.count; ++i)
    {
      if (!strcmp
	  (msg->name_with_crc, __vapi_metadata.msgs[i]->name_with_crc))
	{
	  /* this happens if somebody is linking together several objects while
	   * using the static inline headers, just fill in the already
	   * assigned id here so that all the objects are in sync */
	  msg->id = __vapi_metadata.msgs[i]->id;
	  return msg->id;
	}
    }
  vapi_msg_id_t id = __vapi_metadata.count;
  ++__vapi_metadata.count;
  __vapi_metadata.msgs =
    realloc (__vapi_metadata.msgs,
	     sizeof (*__vapi_metadata.msgs) * __vapi_metadata.count);
  __vapi_metadata.msgs[id] = msg;
  size_t s = strlen (msg->name_with_crc);
  if (s > __vapi_metadata.max_len_name_with_crc)
    {
      __vapi_metadata.max_len_name_with_crc = s;
    }
  msg->id = id;
  return id;
}

vapi_error_e
vapi_producer_lock (vapi_ctx_t ctx)
{
  int mrv;
  if (0 != (mrv = pthread_mutex_lock (&ctx->requests_mutex)))
    {
      VAPI_DBG ("pthread_mutex_lock() failed, rv=%d:%s", mrv, strerror (mrv));
      (void) mrv;		/* avoid warning if the above debug is not enabled */
      return VAPI_MUTEX_FAILURE;
    }
  return VAPI_OK;
}

vapi_error_e
vapi_producer_unlock (vapi_ctx_t ctx)
{
  int mrv;
  if (0 != (mrv = pthread_mutex_unlock (&ctx->requests_mutex)))
    {
      VAPI_DBG ("pthread_mutex_unlock() failed, rv=%d:%s", mrv,
		strerror (mrv));
      (void) mrv;		/* avoid warning if the above debug is not enabled */
      return VAPI_MUTEX_FAILURE;
    }
  return VAPI_OK;
}

size_t
vapi_get_message_count ()
{
  return __vapi_metadata.count;
}

const char *
vapi_get_msg_name (vapi_msg_id_t id)
{
  return __vapi_metadata.msgs[id]->name;
}

void
vapi_stop_rx_thread (vapi_ctx_t ctx)
{
  if (!ctx || !ctx->connected || !ctx->vl_input_queue)
    {
      return;
    }

  vl_client_stop_rx_thread (ctx->vl_input_queue);
}
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
