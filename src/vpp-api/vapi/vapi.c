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
#include <vlibapi/api_common.h>
#include <vlibmemory/api_common.h>

/* we need to use control pings for some stuff and because we're forced to put
 * the code in headers, we need a way to be able to grab the ids of these
 * messages - so declare them here as extern */
vapi_msg_id_t vapi_msg_id_control_ping = 0;
vapi_msg_id_t vapi_msg_id_control_ping_reply = 0;

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
  bool is_dump;
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
  pthread_mutex_t requests_mutex;
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

static bool
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
vapi_store_request (vapi_ctx_t ctx, u32 context, bool is_dump,
		    vapi_cb_t callback, void *callback_ctx)
{
  assert (!vapi_requests_full (ctx));
  /* if the mutex is not held, bad things will happen */
  assert (0 != pthread_mutex_trylock (&ctx->requests_mutex));
  const int requests_end = vapi_requests_end (ctx);
  vapi_req_t *slot = &ctx->requests[requests_end];
  slot->is_dump = is_dump;
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

void *
vapi_msg_alloc (vapi_ctx_t ctx, size_t size)
{
  if (!ctx->connected)
    {
      return NULL;
    }
  void *rv = vl_msg_api_alloc_or_null (size);
  return rv;
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
  vl_msg_api_free (msg);
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
  ctx->event_cbs = calloc (__vapi_metadata.count, sizeof (*ctx->event_cbs));
  if (!ctx->event_cbs)
    {
      goto fail;
    }
  pthread_mutex_init (&ctx->requests_mutex, NULL);
  *result = ctx;
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

vapi_error_e
vapi_connect (vapi_ctx_t ctx, const char *name,
	      const char *chroot_prefix,
	      int max_outstanding_requests,
	      int response_queue_size, vapi_mode_e mode)
{
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
  memset (ctx->requests, 0, size);
  ctx->requests_start = ctx->requests_count = 0;
  if (chroot_prefix)
    {
      VAPI_DBG ("set memory root path `%s'", chroot_prefix);
      vl_set_memory_root_path ((char *) chroot_prefix);
    }
  static char api_map[] = "/vpe-api";
  VAPI_DBG ("client api map `%s'", api_map);
  if ((vl_client_api_map (api_map)) < 0)
    {
      return VAPI_EMAP_FAIL;
    }
  VAPI_DBG ("connect client `%s'", name);
  if (vl_client_connect ((char *) name, 0, response_queue_size) < 0)
    {
      vl_client_api_unmap ();
      return VAPI_ECON_FAIL;
    }
#if VAPI_DEBUG_CONNECT
  VAPI_DBG ("start probing messages");
#endif
  int rv;
  int i;
  for (i = 0; i < __vapi_metadata.count; ++i)
    {
      vapi_message_desc_t *m = __vapi_metadata.msgs[i];
      u8 scratch[m->name_with_crc_len + 1];
      memcpy (scratch, m->name_with_crc, m->name_with_crc_len + 1);
      u32 id = vl_api_get_msg_index (scratch);
      if (~0 != id)
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
	      vapi_msg_id_t *tmp = realloc (ctx->vl_msg_id_to_vapi_msg_t,
					    sizeof
					    (*ctx->vl_msg_id_to_vapi_msg_t) *
					    (id + 1));
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
      VAPI_ERR
	("control ping or control ping reply not available, cannot connect");
      rv = VAPI_EINCOMPATIBLE;
      goto fail;
    }
  ctx->mode = mode;
  ctx->connected = true;
  return VAPI_OK;
fail:
  vl_client_disconnect ();
  vl_client_api_unmap ();
  return rv;
}

vapi_error_e
vapi_disconnect (vapi_ctx_t ctx)
{
  if (!ctx->connected)
    {
      return VAPI_EINVAL;
    }
  vl_client_disconnect ();
  vl_client_api_unmap ();
#if VAPI_DEBUG_ALLOC
  vapi_to_be_freed_validate ();
#endif
  ctx->connected = false;
  return VAPI_OK;
}

vapi_error_e
vapi_get_fd (vapi_ctx_t ctx, int *fd)
{
  return VAPI_ENOTSUP;
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
  int tmp;
  unix_shared_memory_queue_t *q = api_main.shmem_hdr->vl_input_queue;
#if VAPI_DEBUG
  unsigned msgid = be16toh (*(u16 *) msg);
  if (msgid <= ctx->vl_msg_id_max)
    {
      vapi_msg_id_t id = ctx->vl_msg_id_to_vapi_msg_t[msgid];
      if (id < __vapi_metadata.count)
	{
	  VAPI_DBG ("send msg %u[%s]", msgid, __vapi_metadata.msgs[id]->name);
	}
      else
	{
	  VAPI_DBG ("send msg %u[UNKNOWN]", msgid);
	}
    }
  else
    {
      VAPI_DBG ("send msg %u[UNKNOWN]", msgid);
    }
#endif
  tmp = unix_shared_memory_queue_add (q, (u8 *) & msg,
				      VAPI_MODE_BLOCKING ==
				      ctx->mode ? 0 : 1);
  if (tmp < 0)
    {
      rv = VAPI_EAGAIN;
    }
out:
  VAPI_DBG ("vapi_send() rv = %d", rv);
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
  unix_shared_memory_queue_t *q = api_main.shmem_hdr->vl_input_queue;
#if VAPI_DEBUG
  unsigned msgid1 = be16toh (*(u16 *) msg1);
  unsigned msgid2 = be16toh (*(u16 *) msg2);
  const char *name1 = "UNKNOWN";
  const char *name2 = "UNKNOWN";
  if (msgid1 <= ctx->vl_msg_id_max)
    {
      vapi_msg_id_t id = ctx->vl_msg_id_to_vapi_msg_t[msgid1];
      if (id < __vapi_metadata.count)
	{
	  name1 = __vapi_metadata.msgs[id]->name;
	}
    }
  if (msgid2 <= ctx->vl_msg_id_max)
    {
      vapi_msg_id_t id = ctx->vl_msg_id_to_vapi_msg_t[msgid2];
      if (id < __vapi_metadata.count)
	{
	  name2 = __vapi_metadata.msgs[id]->name;
	}
    }
  VAPI_DBG ("send two: %u[%s], %u[%s]", msgid1, name1, msgid2, name2);
#endif
  int tmp = unix_shared_memory_queue_add2 (q, (u8 *) & msg1, (u8 *) & msg2,
					   VAPI_MODE_BLOCKING ==
					   ctx->mode ? 0 : 1);
  if (tmp < 0)
    {
      rv = VAPI_EAGAIN;
    }
out:
  VAPI_DBG ("vapi_send() rv = %d", rv);
  return rv;
}

vapi_error_e
vapi_recv (vapi_ctx_t ctx, void **msg, size_t * msg_size)
{
  if (!ctx || !ctx->connected || !msg || !msg_size)
    {
      return VAPI_EINVAL;
    }
  vapi_error_e rv = VAPI_OK;
  api_main_t *am = &api_main;
  uword data;

  if (am->our_pid == 0)
    {
      return VAPI_EINVAL;
    }

  unix_shared_memory_queue_t *q = am->vl_input_queue;
  VAPI_DBG ("doing shm queue sub");
  int tmp = unix_shared_memory_queue_sub (q, (u8 *) & data, 0);
  if (tmp == 0)
    {
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
      VAPI_DBG ("recv msg %p", *msg);
    }
  else
    {
      rv = VAPI_EAGAIN;
    }
  return rv;
}

vapi_error_e
vapi_wait (vapi_ctx_t ctx, vapi_wait_mode_e mode)
{
  /* FIXME */
  return VAPI_ENOTSUP;
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
	  ctx->requests[ctx->requests_start].callback (ctx,
						       ctx->requests
						       [ctx->
							requests_start].callback_ctx,
						       VAPI_ENORESP, true,
						       NULL);
	  memset (&ctx->requests[ctx->requests_start], 0,
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
      if (ctx->requests[tmp].is_dump)
	{
	  if (vapi_msg_id_control_ping_reply == id)
	    {
	      payload = NULL;
	    }
	  else
	    {
	      is_last = false;
	    }
	}
      if (payload_offset != -1)
	{
	  rv =
	    ctx->requests[tmp].callback (ctx, ctx->requests[tmp].callback_ctx,
					 VAPI_OK, is_last, payload);
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
	  memset (&ctx->requests[ctx->requests_start], 0,
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

static bool
vapi_msg_is_with_context (vapi_msg_id_t id)
{
  assert (id <= __vapi_metadata.count);
  return __vapi_metadata.msgs[id]->has_context;
}

vapi_error_e
vapi_dispatch_one (vapi_ctx_t ctx)
{
  VAPI_DBG ("vapi_dispatch_one()");
  void *msg;
  size_t size;
  vapi_error_e rv = vapi_recv (ctx, &msg, &size);
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
  if (~0 == (unsigned) ctx->vl_msg_id_to_vapi_msg_t[vpp_id])
    {
      VAPI_ERR ("Unknown msg ID received, id `%u' marked as not supported",
		(unsigned) vpp_id);
      vapi_msg_free (ctx, msg);
      return VAPI_EINVAL;
    }
  const vapi_msg_id_t id = ctx->vl_msg_id_to_vapi_msg_t[vpp_id];
  const size_t expect_size = vapi_get_message_size (id);
  if (size < expect_size)
    {
      VAPI_ERR
	("Invalid msg received, unexpected size `%zu' < expected min `%zu'",
	 size, expect_size);
      vapi_msg_free (ctx, msg);
      return VAPI_EINVAL;
    }
  u32 context;
  vapi_get_swap_to_host_func (id) (msg);
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
  return api_main.my_client_index;
}

bool
vapi_is_nonblocking (vapi_ctx_t ctx)
{
  return (VAPI_MODE_NONBLOCKING == ctx->mode);
}

bool vapi_requests_full (vapi_ctx_t ctx);

size_t vapi_get_request_count (vapi_ctx_t ctx);

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
vapi_get_message_size (vapi_msg_id_t id)
{
  assert (id < __vapi_metadata.count);
  return __vapi_metadata.msgs[id]->size;
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

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
