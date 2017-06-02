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
#include <vpe.api.vapi.h>

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
  vapi_error_e (*cb) (vapi_ctx_t *ctx, void *callback_ctx, vapi_msg_id_t id,
                      void *payload);
  void *ctx;
} vapi_generic_cb_with_ctx;

typedef struct
{
  vapi_error_e (*cb) (vapi_ctx_t *ctx, void *callback_ctx, void *payload);
  void *ctx;
} vapi_event_cb_with_ctx;

struct vapi_ctx_s
{
  vapi_mode_e mode;
  int requests_size;
  int requests_start;
  int requests_end;
  vapi_req_t *requests;
  u32 context_counter;
  vapi_generic_cb_with_ctx generic_cb;
  vapi_event_cb_with_ctx *event_cbs;
  u16 *vapi_msg_id_t_to_vl_msg_id;
  u16 vl_msg_id_max;
  vapi_msg_id_t *vl_msg_id_to_vapi_msg_t;
  bool connected;
};

u32 vapi_gen_req_context (vapi_ctx_t *ctx)
{
  ++ctx->context_counter;
  if (ctx->context_counter == context_counter_mask)
    {
      ctx->context_counter = 0;
    }
  return ctx->context_counter & context_counter_mask;
}

size_t vapi_get_request_count (vapi_ctx_t *ctx)
{
  if (ctx->requests_start <= ctx->requests_end)
    {
      return ctx->requests_end - ctx->requests_start;
    }
  return ctx->requests_size - (ctx->requests_start - ctx->requests_end) - 1;
}

bool vapi_requests_full (vapi_ctx_t *ctx)
{
  return (ctx->requests_start == 0 &&
          ctx->requests_end == ctx->requests_size) ||
         (ctx->requests_end + 1 == ctx->requests_start);
}

static bool vapi_requests_empty (vapi_ctx_t *ctx)
{
  return ctx->requests_end == ctx->requests_start;
}

void vapi_store_request (vapi_ctx_t *ctx, u32 context, bool is_dump,
                         vapi_cb_t callback, void *callback_ctx)
{
  assert (!vapi_requests_full (ctx));
  vapi_req_t *slot = &ctx->requests[ctx->requests_end];
  slot->is_dump = is_dump;
  slot->context = context;
  slot->callback = callback;
  slot->callback_ctx = callback_ctx;
  ++ctx->requests_end;
}

vapi_error_e vapi_send_control_ping (vapi_ctx_t *ctx,
                                     vapi_msg_control_ping *msg, u32 context)
{
  vapi_msg_init_control_ping (ctx, msg);
  vapi_msg_control_ping *ping = msg;
  ping->header.context = context;
  vapi_vapi_payload_control_ping_swap_to_be (&ping->payload);
  return vapi_send (ctx, ping);
}

#if VAPI_DEBUG_ALLOC
struct to_be_freed_s;
struct to_be_freed_s
{
  void *v;
  struct to_be_freed_s *next;
};

static struct to_be_freed_s *to_be_freed = NULL;

void vapi_add_to_be_freed (void *v)
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

void vapi_trace_free (void *v)
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

void vapi_to_be_freed_validate ()
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

void *vapi_msg_alloc (vapi_ctx_t *ctx, size_t size)
{
  if (!ctx->connected)
    {
      return NULL;
    }
  void *rv = vl_msg_api_alloc_or_null (size);
  return rv;
}

void vapi_msg_free (vapi_ctx_t *ctx, void *msg)
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

vapi_ctx_t *vapi_ctx_alloc ()
{
  vapi_ctx_t *ctx = calloc (1, sizeof (vapi_ctx_t));
  if (!ctx)
    {
      return NULL;
    }
  ctx->context_counter = context_counter_mask;
  ctx->vapi_msg_id_t_to_vl_msg_id = malloc (
      __vapi_metadata.count * sizeof (*ctx->vapi_msg_id_t_to_vl_msg_id));
  if (!ctx->vapi_msg_id_t_to_vl_msg_id)
    {
      goto fail;
    }
  ctx->event_cbs = calloc (__vapi_metadata.count, sizeof (*ctx->event_cbs));
  if (!ctx->event_cbs)
    {
      goto fail;
    }
  return ctx;
fail:
  vapi_ctx_free (ctx);
  return NULL;
}

void vapi_ctx_free (vapi_ctx_t *ctx)
{
  free (ctx->requests);
  free (ctx->vapi_msg_id_t_to_vl_msg_id);
  free (ctx->event_cbs);
  free (ctx->vl_msg_id_to_vapi_msg_t);
  free (ctx);
}

bool vapi_is_msg_available (vapi_ctx_t *ctx, vapi_msg_id_t id)
{
  return false;
}

vapi_error_e vapi_connect (vapi_ctx_t *ctx, const char *name,
                           const char *chroot_prefix, int max_queued_requests,
                           vapi_mode_e mode)
{
  if (max_queued_requests < 0)
    {
      return VAPI_EINVAL;
    }
  const size_t size = max_queued_requests * sizeof (*ctx->requests);
  void *tmp = realloc (ctx->requests, size);
  if (!tmp)
    {
      return VAPI_ENOMEM;
    }
  ctx->requests = tmp;
  memset (ctx->requests, 0, size);
  ctx->requests_size = max_queued_requests;
  ctx->requests_start = ctx->requests_end = 0;
  if (chroot_prefix)
    {
      VAPI_DBG ("set memory root path `%s'", chroot_prefix);
      vl_set_memory_root_path ((char *)chroot_prefix);
    }
  static char api_map[] = "/vpe-api";
  VAPI_DBG ("client api map `%s'", api_map);
  if ((vl_client_api_map (api_map)) < 0)
    {
      return VAPI_EMAP_FAIL;
    }
  VAPI_DBG ("connect client `%s'", name);
  if (vl_client_connect ((char *)name, 0, max_queued_requests) < 0)
    {
      vl_client_api_unmap ();
      return VAPI_ECON_FAIL;
    }
#if VAPI_DEBUG_CONNECT
  VAPI_DBG ("start probing messages");
#endif
  int rv;
  for (int i = 0; i < __vapi_metadata.count; ++i)
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
          VAPI_DBG ("Message `%s' has vl_msg_id `%u'", m->name_with_crc,
                    (unsigned)id);
        }
      else
        {
          VAPI_DBG ("Message `%s' not available", m->name_with_crc);
        }
    }
#if VAPI_DEBUG_CONNECT
  VAPI_DBG ("finished probing messages");
#endif
  ctx->mode = mode;
  ctx->connected = true;
  return VAPI_OK;
fail:
  vl_client_disconnect ();
  vl_client_api_unmap ();
  return rv;
}

vapi_error_e vapi_disconnect (vapi_ctx_t *ctx)
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
  return VAPI_OK;
}

vapi_error_e vapi_get_fd (vapi_ctx_t *ctx, int *fd) { return VAPI_ENOTSUP; }

vapi_error_e vapi_send (vapi_ctx_t *ctx, void *msg)
{
  if (!ctx || !ctx->connected || !msg)
    {
      return VAPI_EINVAL;
    }
  unix_shared_memory_queue_t *q = api_main.shmem_hdr->vl_input_queue;
#if VAPI_DEBUG
  unsigned msgid = be16toh (*(u16 *)msg);
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
  int rv = unix_shared_memory_queue_add (
      q, (u8 *)&msg, VAPI_MODE_BLOCKING == ctx->mode ? 0 : 1);
  if (rv < 0)
    {
      return VAPI_EAGAIN;
    }
  return VAPI_OK;
}

vapi_error_e vapi_recv (vapi_ctx_t *ctx, void **msg, size_t *msg_size)
{
  if (!ctx || !ctx->connected || !msg || !msg_size)
    {
      return VAPI_EINVAL;
    }
  api_main_t *am = &api_main;
  uword data;

  if (am->our_pid == 0)
    return VAPI_EINVAL;

  unix_shared_memory_queue_t *q = am->vl_input_queue;
  VAPI_DBG ("doing shm queue sub");
  int rv = unix_shared_memory_queue_sub (q, (u8 *)&data, 0);
  if (rv == 0)
    {
#if VAPI_DEBUG_ALLOC
      vapi_add_to_be_freed ((void *)data);
#endif
      msgbuf_t *msgbuf = (msgbuf_t *)((u8 *)data - offsetof (msgbuf_t, data));
      if (!msgbuf->data_len)
        {
          vapi_msg_free (ctx, (u8 *)data);
          return VAPI_EAGAIN;
        }
      *msg = (u8 *)data;
      *msg_size = ntohl (msgbuf->data_len);
      VAPI_DBG ("recv msg %p", *msg);
      return VAPI_OK;
    }
  return VAPI_EAGAIN;
}

vapi_error_e vapi_wait (vapi_ctx_t *ctx, vapi_wait_mode_e mode)
{
  /* FIXME */
  return VAPI_ENOTSUP;
}

static vapi_error_e vapi_dispatch_response (vapi_ctx_t *ctx, vapi_msg_id_t id,
                                            u32 context, void *msg)
{
  int tmp = ctx->requests_start;
  while (ctx->requests[tmp].context != context && tmp != ctx->requests_end)
    {
      ++tmp;
      if (tmp == ctx->requests_size)
        {
          tmp = 0;
        }
    }
  if (ctx->requests[tmp].context == context)
    {
      while (ctx->requests_start != tmp)
        {
          VAPI_ERR ("No response to req with context=%u",
                    (unsigned)ctx->requests[tmp].context);
          ctx->requests[ctx->requests_start].callback (
              ctx, ctx->requests[ctx->requests_start].callback_ctx,
              VAPI_ENORESP, true, NULL);
          memset (&ctx->requests[ctx->requests_start], 0,
                  sizeof (ctx->requests[ctx->requests_start]));
          ++ctx->requests_start;
          if (ctx->requests_start == ctx->requests_size)
            {
              ctx->requests_start = 0;
            }
        }
      // now ctx->requests_start == tmp
      void *payload = ((u8 *)msg) + vapi_get_payload_offset (id);
      vapi_get_swap_to_host_func (id) (payload);
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
      ctx->requests[tmp].callback (ctx, ctx->requests[tmp].callback_ctx,
                                   VAPI_OK, is_last, payload);
      if (is_last)
        {
          memset (&ctx->requests[ctx->requests_start], 0,
                  sizeof (ctx->requests[ctx->requests_start]));
          ++ctx->requests_start;
          if (ctx->requests_start == ctx->requests_size)
            {
              ctx->requests_start = 0;
            }
          // also remove our control ping
          if (!payload && vapi_msg_id_control_ping_reply == id)
            {
              if (!vapi_requests_empty (ctx) &&
                  ctx->requests[ctx->requests_start].context == context)
                {
                  memset (&ctx->requests[ctx->requests_start], 0,
                          sizeof (ctx->requests[ctx->requests_start]));
                  ++ctx->requests_start;
                  if (ctx->requests_start == ctx->requests_size)
                    {
                      ctx->requests_start = 0;
                    }
                }
            }
        }
    }
  return VAPI_OK;
}

static vapi_error_e vapi_dispatch_event (vapi_ctx_t *ctx, vapi_msg_id_t id,
                                         void *msg)
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
      VAPI_DBG (
          "No handler/generic handler for msg id %u[%s], message ignored",
          (unsigned)id, __vapi_metadata.msgs[id]->name);
    }
  return VAPI_OK;
}

static bool vapi_msg_is_with_context (vapi_msg_id_t id)
{
  assert (id <= __vapi_metadata.count);
  return __vapi_metadata.msgs[id]->has_context;
}

vapi_error_e vapi_dispatch_one (vapi_ctx_t *ctx)
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
  u16 vpp_id = be16toh (*(u16 *)msg);
  if (vpp_id >= ctx->vl_msg_id_max)
    {
      VAPI_ERR ("Unknown msg ID received, id `%u', out of range <0,%u>",
                (unsigned)vpp_id, (unsigned)ctx->vl_msg_id_max);
      vapi_msg_free (ctx, msg);
      return VAPI_EINVAL;
    }
  if (~0 == (unsigned)ctx->vl_msg_id_to_vapi_msg_t[vpp_id])
    {
      VAPI_ERR ("Unknown msg ID received, id `%u' marked as not supported",
                (unsigned)vpp_id);
      vapi_msg_free (ctx, msg);
      return VAPI_EINVAL;
    }
  const vapi_msg_id_t id = ctx->vl_msg_id_to_vapi_msg_t[vpp_id];
  const size_t expect_size = vapi_get_message_size (id);
  if (size < expect_size)
    {
      VAPI_ERR (
          "Invalid msg received, unexpected size `%zu' < expected min `%zu'",
          size, expect_size);
      vapi_msg_free (ctx, msg);
      return VAPI_EINVAL;
    }
  u32 context;
  if (vapi_msg_is_with_context (id))
    {
      context = *(u32 *)(((u8 *)msg) + vapi_get_context_offset (id));
      /* is this a message originating from VAPI? */
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

vapi_error_e vapi_dispatch (vapi_ctx_t *ctx)
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

void vapi_set_event_cb (vapi_ctx_t *ctx, vapi_msg_id_t id,
                        vapi_generic_event_cb callback, void *callback_ctx)
{
  vapi_event_cb_with_ctx *c = &ctx->event_cbs[id];
  c->cb = callback;
  c->ctx = callback_ctx;
}

void vapi_clear_event_cb (vapi_ctx_t *ctx, vapi_msg_id_t id)
{
  vapi_set_event_cb (ctx, id, NULL, NULL);
}

u16 vapi_lookup_vl_msg_id (vapi_ctx_t *ctx, vapi_msg_id_t id)
{
  assert (id < __vapi_metadata.count);
  return ctx->vapi_msg_id_t_to_vl_msg_id[id];
}

int vapi_get_client_index (vapi_ctx_t *ctx)
{
  return api_main.my_client_index;
}

bool vapi_is_nonblocking (vapi_ctx_t *ctx)
{
  return (VAPI_MODE_NONBLOCKING == ctx->mode);
}

bool vapi_requests_full (vapi_ctx_t *ctx);
size_t vapi_get_request_count (vapi_ctx_t *ctx);
size_t vapi_get_max_request_count (vapi_ctx_t *ctx)
{
  return ctx->requests_size;
}

void vapi_store_request (vapi_ctx_t *ctx, u32 context, bool is_dump,
                         vapi_cb_t callback, void *callback_ctx);
vapi_error_e vapi_send_control_ping (vapi_ctx_t *ctx,
                                     vapi_msg_control_ping *msg, u32 context);

size_t vapi_get_payload_offset (vapi_msg_id_t id)
{
  assert (id < __vapi_metadata.count);
  return __vapi_metadata.msgs[id]->payload_offset;
}

void (*vapi_get_swap_to_host_func (vapi_msg_id_t id)) (void *payload)
{
  assert (id < __vapi_metadata.count);
  return __vapi_metadata.msgs[id]->swap_to_host;
}

void (*vapi_get_swap_to_be_func (vapi_msg_id_t id)) (void *payload)
{
  assert (id < __vapi_metadata.count);
  return __vapi_metadata.msgs[id]->swap_to_be;
}

size_t vapi_get_message_size (vapi_msg_id_t id)
{
  assert (id < __vapi_metadata.count);
  return __vapi_metadata.msgs[id]->size;
}

size_t vapi_get_context_offset (vapi_msg_id_t id)
{
  assert (id < __vapi_metadata.count);
  return __vapi_metadata.msgs[id]->context_offset;
}

vapi_msg_id_t vapi_register_msg (vapi_message_desc_t *msg)
{
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
