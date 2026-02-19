/* SPDX-License-Identifier: GPL-2.0-only
 * Copyright (C) 2025 Cisco and/or its affiliates.
 */

#define _GNU_SOURCE
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdarg.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <errno.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>

#include <daq_dlt.h>
#include <daq.h>

#include "daq_vpp.h"

daq_vpp_main_t daq_vpp_main = {
  .socket_name = DAQ_VPP_DEFAULT_SOCKET_PATH,
  .socket_fd = -1,
  .default_msg_pool_size = 256,
};

static inline uint64_t
daq_vpp_trace_now_nsec (void)
{
  struct timespec ts;
  clock_gettime (CLOCK_MONOTONIC_COARSE, &ts);
  return (uint64_t) ts.tv_sec * 1000000000ull + (uint64_t) ts.tv_nsec;
}

static const char *
daq_vpp_trace_event_to_string (daq_vpp_trace_event_t ev)
{
  switch (ev)
    {
    case DAQ_VPP_TRACE_EV_INSTANTIATE:
      return "INSTANTIATE";
    case DAQ_VPP_TRACE_EV_MSG_RECV_ENTER:
      return "MSG_RECV_ENTER";
    case DAQ_VPP_TRACE_EV_MSG_RECV_ONE_ENTER:
      return "MSG_RECV_ONE_ENTER";
    case DAQ_VPP_TRACE_EV_FILL_MSG:
      return "FILL_MSG";
    case DAQ_VPP_TRACE_EV_MSG_RECV_ONE_RET:
      return "MSG_RECV_ONE_RET";
    case DAQ_VPP_TRACE_EV_MSG_RECV_RET:
      return "MSG_RECV_RET";
    case DAQ_VPP_TRACE_EV_MSG_FINALIZE:
      return "MSG_FINALIZE";
    case DAQ_VPP_TRACE_EV_INJECT_ENTER:
      return "INJECT_ENTER";
    case DAQ_VPP_TRACE_EV_INJECT_NO_EMPTY_BUF:
      return "INJECT_NO_EMPTY_BUF";
    case DAQ_VPP_TRACE_EV_INJECT_DONE:
      return "INJECT_DONE";
    default:
      return "UNKNOWN";
    }
}

int
daq_vpp_trace_ring_init (daq_vpp_ctx_t *ctx)
{
  daq_vpp_main_t *vdm = &daq_vpp_main;

  if (!vdm->trace_ring_enable)
    return DAQ_SUCCESS;
  if (vdm->trace_ring)
    return DAQ_SUCCESS;
  if (vdm->trace_ring_size == 0)
    vdm->trace_ring_size = DAQ_VPP_TRACE_RING_DEFAULT_SIZE;
  if ((vdm->trace_ring_size & (vdm->trace_ring_size - 1)) != 0)
    return daq_vpp_err (ctx, "trace ring size must be power-of-two");

  vdm->trace_ring = calloc (vdm->trace_ring_size, sizeof (daq_vpp_trace_entry_t));
  if (!vdm->trace_ring)
    return daq_vpp_err (ctx, "trace ring allocation failed");

  vdm->trace_ring_seq = 0;
  return DAQ_SUCCESS;
}

void
daq_vpp_trace_ring_free (void)
{
  daq_vpp_main_t *vdm = &daq_vpp_main;

  if (vdm->trace_ring)
    free (vdm->trace_ring);
  vdm->trace_ring = 0;
  vdm->trace_ring_seq = 0;
}

void
daq_vpp_trace_ring_add (daq_vpp_ctx_t *ctx, daq_vpp_qpair_t *qp, daq_vpp_trace_event_t ev,
			uint32_t arg0, uint32_t arg1)
{
  daq_vpp_main_t *vdm = &daq_vpp_main;
  daq_vpp_trace_entry_t *e;
  uint64_t seq;
  uint64_t token;

  if (!vdm->trace_ring_enable || vdm->trace_ring == 0)
    return;

  seq = __atomic_fetch_add (&vdm->trace_ring_seq, 1, __ATOMIC_RELAXED);
  token = seq + 1;
  e = &vdm->trace_ring[seq & (vdm->trace_ring_size - 1)];

  e->ts_nsec = daq_vpp_trace_now_nsec ();
  e->event = ev;
  e->instance_id = ctx ? ctx->instance_id : 0;
  e->qpair_thread_id = qp ? qp->qpair_id.thread_id : UINT16_MAX;
  e->qpair_queue_id = qp ? qp->qpair_id.queue_id : UINT16_MAX;
  e->arg0 = arg0;
  e->arg1 = arg1;
  __atomic_store_n (&e->seq, token, __ATOMIC_RELEASE);
}

void
daq_vpp_trace_ring_dump (FILE *f, uint32_t max_entries)
{
  daq_vpp_main_t *vdm = &daq_vpp_main;
  uint64_t total, start;
  uint64_t n;

  if (vdm->trace_ring == 0 || vdm->trace_ring_size == 0)
    return;

  total = __atomic_load_n (&vdm->trace_ring_seq, __ATOMIC_ACQUIRE);
  if (total == 0)
    return;

  n = total < vdm->trace_ring_size ? total : vdm->trace_ring_size;
  if (max_entries && n > max_entries)
    n = max_entries;
  start = total - n;

  fprintf (f, "daq_vpp: trace-ring dump (total=%llu, showing-last=%llu, size=%u)\n",
	   (unsigned long long) total, (unsigned long long) n, vdm->trace_ring_size);
  for (uint64_t i = 0; i < n; i++)
    {
      uint64_t seq = start + i;
      uint64_t token = seq + 1;
      daq_vpp_trace_entry_t *e = &vdm->trace_ring[seq & (vdm->trace_ring_size - 1)];

      if (__atomic_load_n (&e->seq, __ATOMIC_ACQUIRE) != token)
	continue;

      fprintf (f, "  #%llu t=%llu ev=%s inst=%u qp=%u.%u a0=%u a1=%u\n", (unsigned long long) seq,
	       (unsigned long long) e->ts_nsec, daq_vpp_trace_event_to_string (e->event),
	       e->instance_id, e->qpair_thread_id, e->qpair_queue_id, e->arg0, e->arg1);
    }
}

int
daq_vpp_err (daq_vpp_ctx_t *ctx, char *fmt, ...)
{
  char buffer[256];
  va_list va;

  va_start (va, fmt);
  vsnprintf (buffer, sizeof (buffer), fmt, va);
  va_end (va);
  if (daq_vpp_main.trace_ring_enable && daq_vpp_main.trace_ring_dump_on_err)
    {
      fprintf (stderr, "daq_vpp: error: %s\n", buffer);
      daq_vpp_trace_ring_dump (stderr, 256);
    }

  daq_vpp_main.daq_base_api.set_errbuf (ctx->modinst, "%s", buffer);
  return DAQ_ERROR;
}

static inline __attribute__ ((always_inline)) void
daq_vpp_prefetch_read (void *p)
{
  __builtin_prefetch (p, 0 /* read */, 3 /* closest to the cpu */);
}

static int
daq_vpp_module_load (const DAQ_BaseAPI_t *base_api)
{
  daq_vpp_main_t *vdm = &daq_vpp_main;
  if (base_api->api_version != DAQ_BASE_API_VERSION ||
      base_api->api_size != sizeof (DAQ_BaseAPI_t))
    return DAQ_ERROR;

  vdm->daq_base_api = *base_api;

  return DAQ_SUCCESS;
}

static int
daq_vpp_module_unload (void)
{
  daq_vpp_trace_ring_free ();
  return DAQ_SUCCESS;
}

static void
daq_vpp_destroy (void *handle)
{
  daq_vpp_main_t *vdm = &daq_vpp_main;
  daq_vpp_ctx_t *ctx = (daq_vpp_ctx_t *) handle;
  uint16_t instance_id = ctx->instance_id;

  DEBUG ("destroying instance %u", instance_id);
  free (ctx->qpairs);
  if (ctx->epoll_fd != -1)
    close (ctx->epoll_fd);
  free (ctx);

  if (--vdm->n_instances == 0)
    {
      /* free inputs and their qpairs */
      if (vdm->inputs)
	{
	  for (daq_vpp_input_index_t ii = 0; ii < vdm->n_inputs; ii++)
	    {
	      daq_vpp_input_t *in = vdm->inputs[ii];
	      for (daq_vpp_qpair_index_t qi = 0; qi < in->num_qpairs; qi++)
		{
		  daq_vpp_qpair_t *qp = in->qpairs + qi;
		  close (qp->enq_fd);
		  close (qp->deq_fd);
		}
	      if (in->shm_base)
		munmap (in->shm_base, in->shm_size);
	    }
	  free (vdm->inputs);
	}

      /* free buffer pools */
      if (vdm->bpools)
	{
	  for (daq_vpp_buffer_pool_index_t bpi = 0; bpi < vdm->num_bpools;
	       bpi++)
	    {
	      daq_vpp_buffer_pool_t *bp = vdm->bpools + bpi;
	      munmap (bp->base, bp->size);
	      close (bp->fd);
	    }
	  free (vdm->bpools);
	}
    }
  DEBUG ("destroyed instance %u", instance_id);
}

daq_vpp_qpair_t *
daq_vpp_find_qpair (daq_vpp_input_t *in, daq_vpp_qpair_id_t id)
{
  for (uint16_t i = 0; i < in->num_qpairs; i++)
    {
      if (in->qpairs[i].qpair_id.thread_id == id.thread_id &&
	  in->qpairs[i].qpair_id.queue_id == id.queue_id)
	return in->qpairs + i;
    }
  return 0;
}

static int
daq_vpp_add_qpair_to_instance (daq_vpp_ctx_t *ctx, daq_vpp_qpair_t *qp)
{
  struct epoll_event ev = { .events = EPOLLIN, .data.ptr = qp };

  if (qp->used_by_instance)
    return daq_vpp_err (ctx, "%s: qpair %u.%u already used by instance %u",
			__func__, qp->qpair_id.thread_id,
			qp->qpair_id.queue_id, qp->used_by_instance);

  if (epoll_ctl (ctx->epoll_fd, EPOLL_CTL_ADD, qp->enq_fd, &ev) == -1)
    return daq_vpp_err (ctx, "%s: failed to add dequeue fd to epoll instance",
			__func__);

  qp->used_by_instance = ctx->instance_id;
  ctx->qpairs = reallocarray (ctx->qpairs, ctx->num_qpairs + 1,
			      sizeof (daq_vpp_qpair_t *));
  ctx->qpairs[ctx->num_qpairs++] = qp;

  DEBUG ("qpair %u.%u added to instance %u", qp->qpair_id.thread_id,
	 qp->qpair_id.queue_id, ctx->instance_id);
  return DAQ_SUCCESS;
}

static int
daq_vpp_parse_qpair_ids (daq_vpp_ctx_t *ctx, char *s, daq_vpp_qpair_id_t **qip,
			 uint16_t *n_qpair_ids_ptr)
{
  daq_vpp_qpair_id_t *v = 0;
  uint16_t n_qpair_ids = 0;

  if (*s != ':')
    return 0;

  const char *p = s + 1;
  uint16_t a = 0, b = 0, parsing_b = 0;

  for (; *p != '\0'; ++p)
    {
      switch (*p)
	{
	case '.':
	  parsing_b = 1;
	  break;
	case ',':
	  v = reallocarray (v, n_qpair_ids + 1, sizeof (daq_vpp_qpair_id_t));
	  v[n_qpair_ids++] =
	    (daq_vpp_qpair_id_t){ .thread_id = a, .queue_id = b };

	  a = b = 0;
	  parsing_b = 0;
	  break;
	case '0' ... '9':
	  if (!parsing_b)
	    a = a * 10 + (*p - '0');
	  else
	    b = b * 10 + (*p - '0');
	  break;
	default:
	  if (v)
	    free (v);
	  return daq_vpp_err (ctx, "unable to parse '%s'", p);
	}
    }

  v = reallocarray (v, n_qpair_ids + 1, sizeof (daq_vpp_qpair_id_t));
  v[n_qpair_ids++] = (daq_vpp_qpair_id_t){ .thread_id = a, .queue_id = b };

  *qip = v;
  *n_qpair_ids_ptr = n_qpair_ids;
  return DAQ_SUCCESS;
}

static int
daq_vpp_instantiate (DAQ_ModuleConfig_h modcfg, DAQ_ModuleInstance_h modinst,
		     void **ctxt_ptr)
{
  daq_vpp_main_t *vdm = &daq_vpp_main;
  int rv;
  daq_vpp_input_t *in;
  daq_vpp_ctx_t *ctx = 0, *oldctx;
  unsigned n_instances, instance_id;
  char name[DAQ_VPP_MAX_INST_NAME_LEN], *end_of_name;
  unsigned input_name_len;
  const char *input_name;
  daq_vpp_qpair_id_t *qpair_ids = 0;
  uint16_t n_qpair_ids = 0;
  uint32_t msg_pool_size;

  n_instances = vdm->daq_base_api.config_get_total_instances (modcfg);
  instance_id = vdm->daq_base_api.config_get_instance_id (modcfg);
  input_name = vdm->daq_base_api.config_get_input (modcfg);

  vdm->n_instances++;

  end_of_name = strchrnul (input_name, ':');
  input_name_len = end_of_name - input_name;
  ctx = calloc (1, sizeof (daq_vpp_ctx_t));
  ctx->modinst = modinst;
  ctx->timeout = (int) vdm->daq_base_api.config_get_timeout (modcfg);
  ctx->instance_id = instance_id;

  if (input_name_len >= DAQ_VPP_MAX_INST_NAME_LEN)
    return daq_vpp_err (ctx, "input name '%s' too long", input_name);

  strncpy (name, input_name, input_name_len);
  name[input_name_len] = 0;

  if (!vdm->config_parsed)
    {
      rv = daq_vpp_parse_config (ctx, modcfg);
      if (rv != DAQ_SUCCESS)
	goto err;
      vdm->config_parsed = 1;
    }

  rv = daq_vpp_parse_qpair_ids (ctx, end_of_name, &qpair_ids, &n_qpair_ids);
  if (rv != DAQ_SUCCESS)
    goto err;

  DEBUG ("creating instance %u out of %u with input %s", instance_id,
	 n_instances, name);

  daq_vpp_trace_ring_add (ctx, 0, DAQ_VPP_TRACE_EV_INSTANTIATE, n_instances, instance_id);

  msg_pool_size = vdm->daq_base_api.config_get_msg_pool_size (modcfg);
  msg_pool_size = msg_pool_size ? msg_pool_size : vdm->default_msg_pool_size;

  oldctx = ctx;
  ctx = realloc (ctx, sizeof (daq_vpp_ctx_t) +
			msg_pool_size * sizeof (daq_vpp_msg_pool_entry_t));
  if (ctx == 0)
    {
      free (oldctx);
      rv = daq_vpp_err (ctx, "failed to realloc");
      goto err;
    }

  if (!vdm->connected)
    {
      rv = daq_vpp_connect (ctx, n_instances,
			    vdm->daq_base_api.config_get_mode (modcfg));

      if (rv != DAQ_SUCCESS)
	goto err;
      vdm->connected = 1;
    }

  rv = daq_vpp_find_or_add_input (ctx, name, &in);
  if (rv != DAQ_SUCCESS)
    goto err;

  ctx->modinst = modinst;

  ctx->epoll_fd = epoll_create (1);
  if (ctx->epoll_fd < 0)
    {
      rv = daq_vpp_err (ctx, "failed to create epoll instance");
      goto err;
    }

  ctx->wakeup_fd = eventfd (0, EFD_NONBLOCK);
  if (ctx->wakeup_fd < 0)
    {
      rv = daq_vpp_err (ctx, "failed to create epoll instance");
      goto err;
    }

  rv = epoll_ctl (ctx->epoll_fd, EPOLL_CTL_ADD, ctx->wakeup_fd,
		  &(struct epoll_event){ .events = EPOLLIN });
  if (rv == -1)
    {
      rv = daq_vpp_err (ctx, "failed to add dequeue fd to epoll instance");
      goto err;
    }

  /* monitor sock_fd from first instance only, to be notified that remote
   * dissapears */
  if (ctx->instance_id == 1)
    {
      rv = epoll_ctl (
	ctx->epoll_fd, EPOLL_CTL_ADD, vdm->socket_fd,
	&(struct epoll_event){ .events = EPOLLIN, .data.ptr = (void *) 1 });
      if (rv == -1)
	{
	  rv = daq_vpp_err (ctx, "failed to add dequeue fd to epoll instance");
	  goto err;
	}
    }

  /* assign qpair to ths instance */
  if (n_qpair_ids)
    {
      for (uint32_t i = 0; i < n_qpair_ids; i++)
	{
	  daq_vpp_qpair_t *qp;
	  qp = daq_vpp_find_qpair (in, qpair_ids[i]);
	  if (!qp)
	    {
	      rv = daq_vpp_err (ctx, "cannot find qpair %u.%u",
				qpair_ids[i].thread_id, qpair_ids[i].queue_id,
				ctx->instance_id);
	      goto err;
	    }
	  rv = daq_vpp_add_qpair_to_instance (ctx, qp);
	  if (rv != DAQ_SUCCESS)
	    goto err;
	}
      free (qpair_ids);
      qpair_ids = 0;
    }
  else
    /* add all qpairs to this instance */
    for (daq_vpp_qpair_index_t i = 0; i < in->num_qpairs; i++)
      {
	rv = daq_vpp_add_qpair_to_instance (ctx, in->qpairs + i);
	if (rv != DAQ_SUCCESS)
	  goto err;
      }

  /* init msg pool */
  daq_vpp_msg_pool_entry_t *freelist_next = 0;
  for (uint32_t i = 0; i < msg_pool_size; i++)
    {
      daq_vpp_msg_pool_entry_t *pe = ctx->msg_pool + i;
      pe->pkthdr = (DAQ_PktHdr_t){
	.egress_index = DAQ_PKTHDR_UNKNOWN,
	.ingress_group = DAQ_PKTHDR_UNKNOWN,
	.egress_group = DAQ_PKTHDR_UNKNOWN,
      };
      pe->msg = (DAQ_Msg_t){
	.type = DAQ_MSG_TYPE_PACKET,
	.hdr_len = sizeof (DAQ_PktHdr_t),
	.hdr = &ctx->msg_pool[i].pkthdr,
	.priv = pe,
      };
      pe->freelist_next = freelist_next;
      freelist_next = pe;
    }
  ctx->msg_pool_freelist = freelist_next;
  ctx->msg_pool_info.available = msg_pool_size;
  ctx->msg_pool_info.size = msg_pool_size;
  ctx->msg_pool_info.mem_size =
    msg_pool_size * sizeof (daq_vpp_msg_pool_entry_t);

  *ctxt_ptr = ctx;

  if (instance_id == n_instances)
    {
      /* run checks on last instance */
      for (daq_vpp_input_index_t ii = 0; ii < vdm->n_inputs; ii++)
	{
	  daq_vpp_input_t *in = vdm->inputs[ii];
	  for (daq_vpp_qpair_index_t qi = 0; qi < in->num_qpairs; qi++)
	    {
	      daq_vpp_qpair_t *qp = in->qpairs + qi;
	      if (qp->used_by_instance == 0)
		fprintf (
		  stderr,
		  "WARNING: input %s:%u.%u is not assigned to any instance\n",
		  in->name, qp->qpair_id.thread_id, qp->qpair_id.queue_id);
	    }
	}
    }

  return DAQ_SUCCESS;

err:
  if (qpair_ids)
    free (qpair_ids);
  daq_vpp_destroy (ctx);
  return rv;
}

static int
daq_vpp_start (void __unused *handle)
{
  return DAQ_SUCCESS;
}

static int
daq_vpp_interrupt (void *handle)
{
  daq_vpp_ctx_t *ctx = (daq_vpp_ctx_t *) handle;
  ssize_t __unused rv;

  ctx->interrupted = 1;
  rv = write (ctx->wakeup_fd, &(uint64_t){ 1 }, sizeof (uint64_t));

  return DAQ_SUCCESS;
}

static int
daq_vpp_inject (void *handle, DAQ_MsgType type, const void *hdr,
		const uint8_t *data, uint32_t data_len)
{
  daq_vpp_ctx_t __unused *ctx = (daq_vpp_ctx_t *) handle;
  daq_vpp_main_t __unused *vdm = &daq_vpp_main;
  DAQ_PktHdr_t *pkthdr = (DAQ_PktHdr_t *) hdr;

  DEBUG_DUMP_MSG2 (pkthdr, type, data, data_len);

  return DAQ_ERROR_NOTSUP;
}

static int
daq_vpp_inject_relative (void *handle, DAQ_Msg_h msg, const uint8_t *data,
			 uint32_t data_len, int reverse)
{
  daq_vpp_ctx_t *ctx = (daq_vpp_ctx_t *) handle;
  daq_vpp_main_t *vdm = &daq_vpp_main;
  daq_vpp_msg_pool_entry_t *pe = msg->priv;
  daq_vpp_qpair_t *qp = pe->qpair;
  daq_vpp_head_tail_t head, tail, mask = qp->empty_buf_queue_size - 1;
  daq_vpp_qpair_header_t *h = qp->hdr;
  uint8_t *buf_data;
  daq_vpp_empty_buf_desc_t *empty_buf_desc;

  daq_vpp_trace_ring_add (ctx, qp, DAQ_VPP_TRACE_EV_INJECT_ENTER, pe->index, data_len);

  DEBUG_DUMP_MSG (msg);
  DEBUG2 ("%s", daq_vpp_inject_direction (reverse));
  DEBUG_DUMP_DATA_HEX (data, data_len);

  /*
   * check the injection direction against the packet direction
   * if direction is not the supported one, return error
   */
  switch (reverse)
    {
    case DAQ_DIR_FORWARD:
      break;
    case DAQ_DIR_REVERSE:
      break;
    case DAQ_DIR_BOTH:
      break;
    default:
      return daq_vpp_err (ctx, "invalid direction %d", reverse);
    }

  head = __atomic_load_n (&qp->hdr->deq.empty_buf_head, __ATOMIC_ACQUIRE);
  tail = __atomic_load_n (&qp->hdr->deq.empty_buf_tail, __ATOMIC_RELAXED);

  if (head == tail)
    {
      DEBUG2 ("no empty buffer available to inject packet");
      daq_vpp_trace_ring_add (ctx, qp, DAQ_VPP_TRACE_EV_INJECT_NO_EMPTY_BUF,
			      (uint32_t) (head - tail), data_len);
      return daq_vpp_err (ctx, "no empty buffer available to inject packet");
    }
  empty_buf_desc = &qp->empty_buf_ring[tail & mask];
  buf_data =
    vdm->bpools[empty_buf_desc->buffer_pool].base + empty_buf_desc->offset;

  if (empty_buf_desc->length < data_len)
    {
      DEBUG ("descriptor %lu buffer too small (%u < %u)", tail & mask, empty_buf_desc->length,
	     data_len);
      return daq_vpp_err (ctx, "descriptor %u buffer too small (%u < %u)", tail & mask,
			  empty_buf_desc->length, data_len);
    }

  memcpy (buf_data, data, data_len);
  empty_buf_desc->length = data_len;
  empty_buf_desc->ref_buffer_desc_index = pe->index;
  empty_buf_desc->direction = reverse;

  tail = tail + 1;
  __atomic_store_n (&h->deq.empty_buf_tail, tail, __ATOMIC_RELEASE);
  daq_vpp_trace_ring_add (ctx, qp, DAQ_VPP_TRACE_EV_INJECT_DONE, pe->index, (uint32_t) tail);

  if (!__atomic_exchange_n (&qp->hdr->deq.interrupt_pending, 1,
			    __ATOMIC_RELAXED))
    {
      ssize_t __unused rv;
      rv = write (qp->deq_fd, &(uint64_t){ 1 }, sizeof (uint64_t));
    }
  return DAQ_SUCCESS;
}

const DAQ_Msg_t *
daq_vpp_fill_msg (daq_vpp_ctx_t *ctx, daq_vpp_qpair_t *qp, uint32_t desc_index,
		  struct timeval tv)
{
  daq_vpp_main_t *vdm = &daq_vpp_main;
  daq_vpp_msg_pool_entry_t *pe;
  daq_vpp_desc_t *d;
  uint8_t *data;

  d = qp->hdr->descs + desc_index;
  data = vdm->bpools[d->buffer_pool].base + d->offset;

  daq_vpp_prefetch_read (data);
  pe = ctx->msg_pool_freelist;
  ctx->msg_pool_freelist = pe->freelist_next;
  daq_vpp_prefetch_read (pe->freelist_next);
  pe->qpair = qp;
  pe->index = desc_index;
  pe->pkthdr.ts = tv;
  pe->pkthdr.pktlen = d->length;
  pe->pkthdr.address_space_id = d->metadata.address_space_id;
  pe->pkthdr.flow_id = d->metadata.flow_id;
  pe->pkthdr.flags = d->metadata.flags;
  pe->pkthdr.ingress_index = d->metadata.ingress_index;
  pe->msg.data = data;
  pe->msg.data_len = d->length;

  daq_vpp_trace_ring_add (ctx, qp, DAQ_VPP_TRACE_EV_FILL_MSG, desc_index, d->length);

  DEBUG_DUMP_MSG (&pe->msg);
  return &pe->msg;
}

uint32_t
daq_vpp_msg_receive_one (daq_vpp_ctx_t *ctx, daq_vpp_qpair_t *qp,
			 const DAQ_Msg_t *msgs[], unsigned max_recv)
{
  uint32_t n_recv, n_left, desc_index, next_desc_index;
  daq_vpp_head_tail_t head, tail, mask = qp->queue_size - 1;
  struct timeval tv;

  if (max_recv == 0)
    return 0;

  tail = qp->tail;
  head = __atomic_load_n (&qp->hdr->enq.head, __ATOMIC_ACQUIRE);
  n_recv = head - tail;
  daq_vpp_trace_ring_add (ctx, qp, DAQ_VPP_TRACE_EV_MSG_RECV_ONE_ENTER, n_recv, max_recv);
  if (n_recv == 0)
    return 0;

  if (n_recv > max_recv)
    n_recv = max_recv;

  next_desc_index = qp->enq_ring[tail++ & mask];

  gettimeofday (&tv, NULL);
  for (n_left = n_recv; n_left > 1; n_left--, msgs++)
    {
      desc_index = next_desc_index;

      msgs[0] = daq_vpp_fill_msg (ctx, qp, desc_index, tv);
      next_desc_index = qp->enq_ring[tail++ & mask];
    }

  /* last packet */
  msgs[0] = daq_vpp_fill_msg (ctx, qp, next_desc_index, tv);

  qp->tail = tail;
  daq_vpp_trace_ring_add (ctx, qp, DAQ_VPP_TRACE_EV_MSG_RECV_ONE_RET, n_recv, (uint32_t) qp->tail);
  return n_recv;
}

static inline void
daq_vpp_flush_eventfd (int fd)
{
  uint64_t ctr;
  ssize_t __unused size = read (fd, &ctr, sizeof (ctr));
}

static unsigned
daq_vpp_msg_receive (void *handle, unsigned max_recv, const DAQ_Msg_t *msgs[],
		     DAQ_RecvStatus *rstatp)
{
  daq_vpp_main_t *dvm = &daq_vpp_main;
  daq_vpp_ctx_t *ctx = (daq_vpp_ctx_t *) handle;
  struct epoll_event epoll_events[32];
  uint32_t n_recv = 0;
  int32_t n_events;
  DAQ_RecvStatus rstat = DAQ_RSTAT_OK;

  daq_vpp_trace_ring_add (ctx, 0, DAQ_VPP_TRACE_EV_MSG_RECV_ENTER, max_recv,
			  ctx->msg_pool_info.available);

  if (ctx->interrupted)
    {
      rstat = DAQ_RSTAT_INTERRUPTED;
      ctx->interrupted = 0;
      goto done;
    }

  if (dvm->hangup)
    {
      daq_vpp_err (ctx, "hangup received");
      rstat = DAQ_RSTAT_ERROR;
      goto done;
    }

  if (ctx->msg_pool_info.available < max_recv)
    max_recv = ctx->msg_pool_info.available;

  if (ctx->num_qpairs == 1)
    {
      daq_vpp_qpair_t *qp = ctx->qpairs[0];
      uint32_t n;

      n = daq_vpp_msg_receive_one (ctx, qp, msgs, max_recv);
      if (n)
	{
	  msgs += n;
	  n_recv += n;
	}
    }
  else
    {
      /* first, we visit all qpairs. If we find any work there then we can give
       * it back immediatelly. To avoid bias towards qpair 0 we remeber what
       * next qpair */
      uint16_t num_qpairs = ctx->num_qpairs;
      uint16_t next_qp = ctx->next_qpair;
      for (uint32_t n, left = num_qpairs; left; left--)
	{
	  daq_vpp_qpair_t *qp = ctx->qpairs[next_qp];

	  n = daq_vpp_msg_receive_one (ctx, qp, msgs, max_recv - n_recv);
	  if (n)
	    {
	      msgs += n;
	      n_recv += n;
	    }

	  /* next */
	  next_qp = next_qp + 1 < num_qpairs ? next_qp + 1 : 0;
	}
      ctx->next_qpair =
	ctx->next_qpair + 1 < num_qpairs ? ctx->next_qpair + 1 : 0;
    }

  if (n_recv)
    goto done;

  n_events = epoll_wait (ctx->epoll_fd, epoll_events, ARRAY_LEN (epoll_events),
			 ctx->timeout);

  if (n_events < 1)
    {
      if (n_events == 0 || errno == EINTR)
	rstat = DAQ_RSTAT_TIMEOUT;
      else
	rstat = DAQ_RSTAT_ERROR;
      goto done;
    }

  for (struct epoll_event *e = epoll_events; e - epoll_events < n_events; e++)
    {
      if (e->events & EPOLLERR)
	{
	  daq_vpp_err (ctx, "socket error");
	  rstat = DAQ_RSTAT_ERROR;
	}
      else if (e->events & EPOLLHUP)
	{
	  daq_vpp_err (ctx, "hangup received");
	  dvm->hangup = 1;
	  rstat = DAQ_RSTAT_EOF;
	}
      else if (e->events & EPOLLIN)
	{
	  if (e->data.ptr == 0)
	    {
	      rstat = DAQ_RSTAT_INTERRUPTED;
	      ctx->interrupted = 0;
	      daq_vpp_flush_eventfd (ctx->wakeup_fd);
	    }
	  else if (e->data.ptr == (void *) 1)
	    {
	      rstat = DAQ_RSTAT_ERROR;
	      daq_vpp_flush_eventfd (ctx->wakeup_fd);
	    }
	}
    }

  if (rstat != DAQ_RSTAT_OK)
    goto done;

  for (struct epoll_event *e = epoll_events; e - epoll_events < n_events; e++)
    if (e->data.ptr > (void *) 1)
      {
	daq_vpp_qpair_t *qp = e->data.ptr;
	uint32_t n;

	__atomic_store_n (&qp->hdr->enq.interrupt_pending, 0,
			  __ATOMIC_RELAXED);

	n = daq_vpp_msg_receive_one (ctx, qp, msgs, max_recv - n_recv);
	if (n)
	  {
	    msgs += n;
	    n_recv += n;
	  }
	daq_vpp_flush_eventfd (qp->enq_fd);
      }

done:
  if (n_recv)
    ctx->msg_pool_info.available -= n_recv;
  *rstatp = rstat;
  daq_vpp_trace_ring_add (ctx, 0, DAQ_VPP_TRACE_EV_MSG_RECV_RET, n_recv, (uint32_t) rstat);
  return n_recv;
}

static int
daq_vpp_msg_finalize (void *handle, const DAQ_Msg_t *msg, DAQ_Verdict verdict)
{
  daq_vpp_ctx_t *ctx = (daq_vpp_ctx_t *) handle;
  daq_vpp_msg_pool_entry_t *pe = msg->priv;
  daq_vpp_qpair_t *qp = pe->qpair;
  daq_vpp_head_tail_t head, mask;
  daq_vpp_qpair_header_t *h = qp->hdr;
  daq_vpp_desc_t *d;

  daq_vpp_trace_ring_add (ctx, qp, DAQ_VPP_TRACE_EV_MSG_FINALIZE, pe->index, verdict);

  DEBUG_DUMP_MSG (msg);

  if (ctx->msg_pool_info.available == ctx->msg_pool_info.size)
    {
      DEBUG2 ("all messages are already finalized");
      return DAQ_SUCCESS;
    }

  if (verdict >= MAX_DAQ_VERDICT)
    {
      DEBUG2 ("verdict %d out of range, setting to PASS", verdict);
      verdict = DAQ_VERDICT_PASS;
    }
  ctx->stats.verdicts[verdict]++;

  mask = qp->queue_size - 1;
  head = __atomic_load_n (&h->deq.head, __ATOMIC_ACQUIRE);
  d = h->descs + pe->index;

  d->metadata.verdict = (daq_vpp_verdict_t) verdict;
  qp->deq_ring[head & mask] = pe->index;
  head = head + 1;
  __atomic_store_n (&h->deq.head, head, __ATOMIC_RELEASE);

  /* put back to freelist */
  pe->freelist_next = ctx->msg_pool_freelist;
  ctx->msg_pool_freelist = pe;
  ctx->msg_pool_info.available++;

  if (!__atomic_exchange_n (&qp->hdr->deq.interrupt_pending, 1,
			    __ATOMIC_RELAXED))
    {
      ssize_t __unused rv;
      rv = write (qp->deq_fd, &(uint64_t){ 1 }, sizeof (uint64_t));
    }

  return DAQ_SUCCESS;
}

static int
daq_vpp_get_msg_pool_info (void *handle, DAQ_MsgPoolInfo_t *info)
{
  daq_vpp_ctx_t *ctx = (daq_vpp_ctx_t *) handle;
  DEBUG ("getting msg pool info");
  *info = ctx->msg_pool_info;
  return DAQ_SUCCESS;
}

static int
daq_vpp_get_stats (void __unused *handle, DAQ_Stats_t *stats)
{
  daq_vpp_ctx_t *ctx = (daq_vpp_ctx_t *) handle;
  DEBUG ("getting stats");
  *stats = ctx->stats;
  return DAQ_SUCCESS;
}

static void
daq_vpp_reset_stats (void *handle)
{
  daq_vpp_ctx_t *ctx = (daq_vpp_ctx_t *) handle;
  DEBUG ("resetting stats");
  ctx->stats = (DAQ_Stats_t){};
}

static uint32_t
daq_vpp_get_capabilities (void __unused *handle)
{
  return DAQ_CAPA_BLOCK |	 /* can block packets */
	 DAQ_CAPA_INJECT |	 /* can inject packets */
	 DAQ_CAPA_UNPRIV_START | /* can start without root privileges */
	 DAQ_CAPA_INTERRUPT |	 /* can be interrupted */
	 DAQ_CAPA_DEVICE_INDEX; /* can consistently fill the device index field
				   in DAQ_PktHdr */
}

static int
daq_vpp_get_datalink_type (void __unused *handle)
{
  return DLT_IPV4;
}

static const char *
daq_vpp_ioctl_cmd_to_str (DAQ_IoctlCmd cmd)
{
#define IOCTL_CMD_STR(cmd)                                                    \
  case cmd:                                                                   \
    return #cmd;

  switch (cmd)
    {
      IOCTL_CMD_STR (DIOCTL_GET_DEVICE_INDEX)
      IOCTL_CMD_STR (DIOCTL_SET_FLOW_OPAQUE)
      IOCTL_CMD_STR (DIOCTL_SET_FLOW_HA_STATE)
      IOCTL_CMD_STR (DIOCTL_GET_FLOW_HA_STATE)
      IOCTL_CMD_STR (DIOCTL_SET_FLOW_QOS_ID)
      IOCTL_CMD_STR (DIOCTL_SET_PACKET_TRACE_DATA)
      IOCTL_CMD_STR (DIOCTL_SET_PACKET_VERDICT_REASON)
      IOCTL_CMD_STR (DIOCTL_SET_FLOW_PRESERVE)
      IOCTL_CMD_STR (DIOCTL_GET_FLOW_TCP_SCRUBBED_SYN)
      IOCTL_CMD_STR (DIOCTL_GET_FLOW_TCP_SCRUBBED_SYN_ACK)
      IOCTL_CMD_STR (DIOCTL_CREATE_EXPECTED_FLOW)
      IOCTL_CMD_STR (DIOCTL_DIRECT_INJECT_PAYLOAD)
      IOCTL_CMD_STR (DIOCTL_DIRECT_INJECT_RESET)
      IOCTL_CMD_STR (DIOCTL_GET_PRIV_DATA_LEN)
      IOCTL_CMD_STR (DIOCTL_GET_CPU_PROFILE_DATA)
      IOCTL_CMD_STR (DIOCTL_GET_SNORT_LATENCY_DATA)
      IOCTL_CMD_STR (DIOCTL_SET_INJECT_DROP)
    default:
      return "UNKNOWN";
    }
}

static int
daq_vpp_ioctl (void *handle, DAQ_IoctlCmd cmd, void *arg, size_t arglen)
{
  daq_vpp_main_t *vdm = &daq_vpp_main;
  daq_vpp_ctx_t *ctx = (daq_vpp_ctx_t *) handle;
  DIOCTL_QueryDeviceIndex *qdi = (DIOCTL_QueryDeviceIndex *) arg;

  DEBUG2 ("ioctl cmd %s", daq_vpp_ioctl_cmd_to_str (cmd));

  switch (cmd)
    {
    case DIOCTL_GET_DEVICE_INDEX:
      {
	char name[DAQ_VPP_MAX_INST_NAME_LEN], *colon;

	if (arglen != sizeof (DIOCTL_QueryDeviceIndex))
	  return DAQ_ERROR_NOTSUP;

	if (qdi->device == 0)
	  {
	    daq_vpp_err (ctx, "no device name in IOCTL_GET_DEVICE_INDEX");
	    return DAQ_ERROR_INVAL;
	  }
	snprintf (name, sizeof (name), "%s", qdi->device);
	colon = strchr (name, ':');
	if (colon)
	  colon[0] = 0;

	for (daq_vpp_input_index_t ii = 0; ii < vdm->n_inputs; ii++)
	  if (strcmp (name, vdm->inputs[ii]->name) == 0)
	    {
	      qdi->index = ii + 1;
	      return DAQ_SUCCESS;
	    }

	return DAQ_ERROR_NODEV;
      }
    case DIOCTL_GET_PRIV_DATA_LEN:
      {
	DIOCTL_GetPrivDataLen *gpl = (DIOCTL_GetPrivDataLen *) arg;

	if (arglen != sizeof (DIOCTL_GetPrivDataLen))
	  return DAQ_ERROR_NOTSUP;
	if (gpl->msg->priv != NULL)
	  gpl->priv_data_len = sizeof (daq_vpp_msg_pool_entry_t);
	else
	  gpl->priv_data_len = 0;

	DEBUG2 ("ioctl cmd %s %u", daq_vpp_ioctl_cmd_to_str (cmd),
		gpl->priv_data_len);
	return DAQ_SUCCESS;
      }
    case DIOCTL_DIRECT_INJECT_PAYLOAD:
    case DIOCTL_DIRECT_INJECT_RESET:
    case DIOCTL_SET_INJECT_DROP:
      DEBUG2 ("%s is a no-op", daq_vpp_ioctl_cmd_to_str (cmd));

    default:
      /* not supported yet */
      return DAQ_ERROR_NOTSUP;
    }

  return DAQ_ERROR_NOTSUP;
}

DAQ_SO_PUBLIC
const DAQ_ModuleAPI_t DAQ_MODULE_DATA = {
  .name = "vpp",
  .api_version = DAQ_MODULE_API_VERSION,
  .api_size = sizeof (DAQ_ModuleAPI_t),
  .module_version = DAQ_VPP_VERSION,
  .type =
    DAQ_TYPE_INTF_CAPABLE | DAQ_TYPE_MULTI_INSTANCE | DAQ_TYPE_INLINE_CAPABLE,
  .load = daq_vpp_module_load,
  .unload = daq_vpp_module_unload,
  .get_variable_descs = daq_vpp_get_variable_descs,
  .instantiate = daq_vpp_instantiate,
  .destroy = daq_vpp_destroy,
  .start = daq_vpp_start,
  .inject = daq_vpp_inject,
  .inject_relative = daq_vpp_inject_relative,
  .interrupt = daq_vpp_interrupt,
  .ioctl = daq_vpp_ioctl,
  .get_stats = daq_vpp_get_stats,
  .reset_stats = daq_vpp_reset_stats,
  .get_snaplen = NULL,
  .get_datalink_type = daq_vpp_get_datalink_type,
  .msg_receive = daq_vpp_msg_receive,
  .msg_finalize = daq_vpp_msg_finalize,
  .get_msg_pool_info = daq_vpp_get_msg_pool_info,
  .get_capabilities = daq_vpp_get_capabilities,
};
