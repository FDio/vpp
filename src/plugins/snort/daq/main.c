/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2025 Cisco Systems, Inc.
 */

#define _GNU_SOURCE
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdarg.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <errno.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>

#include <daq_dlt.h>
#include <daq_module_api.h>

#include "daq_vpp.h"

daq_vpp_main_t daq_vpp_main = {
  .socket_name = DAQ_VPP_DEFAULT_SOCKET_PATH,
  .socket_fd = -1,
  .msg_pool_size = 256,
};

int
daq_vpp_err (daq_vpp_ctx_t *ctx, char *fmt, ...)
{
  char buffer[256];
  va_list va;

  va_start (va, fmt);
  vsnprintf (buffer, sizeof (buffer), fmt, va);
  va_end (va);

  daq_vpp_main.daq_base_api.set_errbuf (ctx->modinst, "%s", buffer);
  return DAQ_ERROR;
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
  return DAQ_SUCCESS;
}

static void
daq_vpp_destroy (void *handle)
{
  daq_vpp_main_t *vdm = &daq_vpp_main;
  daq_vpp_ctx_t *ctx = (daq_vpp_ctx_t *) handle;
  DEBUG ("instance_id %u", ctx->instance_id);

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
  daq_vpp_qpair_id_t *qpair_ids;
  uint16_t n_qpair_ids;

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

  rv = daq_vpp_parse_qpair_ids (ctx, end_of_name, &qpair_ids, &n_qpair_ids);
  if (rv != DAQ_SUCCESS)
    goto err;

  if (!vdm->config_parsed)
    {
      rv = daq_vpp_parse_config (ctx, modcfg);
      if (rv != DAQ_SUCCESS)
	goto err;
      vdm->config_parsed = 1;
    }

  DEBUG ("creating instance %u/%u with input %s", instance_id, n_instances,
	 name);

  oldctx = ctx;
  ctx =
    realloc (ctx, sizeof (daq_vpp_ctx_t) +
		    vdm->msg_pool_size * sizeof (daq_vpp_msg_pool_entry_t));
  if (ctx == 0)
    {
      free (oldctx);
      rv = daq_vpp_err (ctx, "failed to realloc");
      goto err;
    }

  if (!vdm->connected)
    {
      rv = daq_vpp_connect (ctx, n_instances);

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
  ctx->msg_pool_info.available = vdm->msg_pool_size;
  ctx->msg_pool_info.size = vdm->msg_pool_size;

  daq_vpp_msg_pool_entry_t *freelist_next = 0;
  for (uint32_t i = 0; i < ctx->msg_pool_info.size; i++)
    {
      daq_vpp_msg_pool_entry_t *pe = ctx->msg_pool + i;
      pe->pkthdr = (DAQ_PktHdr_t){
	.ingress_group = DAQ_PKTHDR_UNKNOWN,
	.egress_group = DAQ_PKTHDR_UNKNOWN,
      };
      pe->msg = (DAQ_Msg_t){
	.owner = modinst,
	.type = DAQ_MSG_TYPE_PACKET,
	.hdr_len = sizeof (DAQ_PktHdr_t),
	.hdr = &ctx->msg_pool[i].pkthdr,
      };
      pe->freelist_next = freelist_next;
      freelist_next = pe;
    }
  ctx->msg_pool_freelist = freelist_next;

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
  daq_vpp_ctx_t *ctx = (daq_vpp_ctx_t *) handle;
  DEBUG ("instance_id %u", ctx->instance_id);
  return DAQ_SUCCESS;
}

static int
daq_vpp_interrupt (void *handle)
{
  daq_vpp_ctx_t *ctx = (daq_vpp_ctx_t *) handle;
  ssize_t __unused rv;
  DEBUG ("instance_id %u", ctx->instance_id);

  ctx->interrupted = 1;
  rv = write (ctx->wakeup_fd, &(uint64_t){ 1 }, sizeof (uint64_t));

  return DAQ_SUCCESS;
}

uint32_t
daq_vpp_msg_receive_one (daq_vpp_ctx_t *ctx, daq_vpp_qpair_t *qp,
			 const DAQ_Msg_t *msgs[], unsigned max_recv)
{
  daq_vpp_main_t *vdm = &daq_vpp_main;
  uint32_t n_recv, n_left;
  uint32_t head, next, mask = qp->queue_size - 1;
  struct timeval tv;

  if (max_recv == 0)
    return 0;

  next = qp->next_desc;
  head = __atomic_load_n (qp->enq_head, __ATOMIC_ACQUIRE);
  n_recv = n_left = head - next;

  if (n_left > max_recv)
    {
      n_left = n_recv = max_recv;
    }

  gettimeofday (&tv, NULL);
  while (n_left--)
    {
      uint32_t desc_index = qp->enq_ring[next & mask];
      daq_vpp_desc_t *d = qp->descs + desc_index;
      daq_vpp_msg_pool_entry_t *dd = ctx->msg_pool_freelist;
      ctx->msg_pool_freelist = dd->freelist_next;
      dd->qpair = qp;
      dd->pkthdr.ts.tv_sec = tv.tv_sec;
      dd->pkthdr.ts.tv_usec = tv.tv_usec;
      dd->pkthdr.pktlen = d->length;
      dd->pkthdr.address_space_id = d->address_space_id;
      dd->msg.data = vdm->bpools[d->buffer_pool].base + d->offset;
      dd->msg.data_len = d->length;
      next = next + 1;

      msgs[0] = &dd->msg;
      msgs++;
    }

  qp->next_desc = next;

  return n_recv;
}

static inline void
daq_vpp_flush_eventfd (int fd)
{
  uint64_t ctr;
  ssize_t __unused size = read (fd, &ctr, sizeof (ctr));
}

static unsigned
daq_vpp_msg_receive (void *handle, const unsigned max_recv,
		     const DAQ_Msg_t *msgs[], DAQ_RecvStatus *rstatp)
{
  daq_vpp_main_t *dvm = &daq_vpp_main;
  daq_vpp_ctx_t *ctx = (daq_vpp_ctx_t *) handle;
  struct epoll_event epoll_events[32];
  uint32_t n, n_recv = 0;
  int32_t n_events;
  DAQ_RecvStatus rstat = DAQ_RSTAT_OK;

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

  /* first, we visit all qpairs. If we find any work there then we can give
   * it back immediatelly. To avoid bias towards qpair 0 we remeber what
   * next qpair */
  for (uint32_t left = ctx->num_qpairs; left; left--)
    {
      daq_vpp_qpair_t *qp = ctx->qpairs[ctx->next_qpair_to_poll];

      n = daq_vpp_msg_receive_one (ctx, qp, msgs, max_recv - n_recv);
      if (n)
	{
	  msgs += n;
	  n_recv += n;
	}

      /* next */
      ctx->next_qpair_to_poll++;
      if (ctx->next_qpair_to_poll == ctx->num_qpairs)
	ctx->next_qpair_to_poll = 0;
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
    {
      daq_vpp_qpair_t *qp = e->data.ptr;

      if (e->data.ptr > (void *) 1)
	continue;

      n = daq_vpp_msg_receive_one (ctx, qp, msgs, max_recv - n_recv);
      if (n)
	{
	  msgs += n;
	  n_recv += n;
	}
      daq_vpp_flush_eventfd (qp->enq_fd);
    }

done:
  *rstatp = rstat;
  return n_recv;
}

static int
daq_vpp_msg_finalize (void *handle, const DAQ_Msg_t *msg, DAQ_Verdict verdict)
{
  daq_vpp_main_t *vdm = &daq_vpp_main;
  daq_vpp_ctx_t *ctx = (daq_vpp_ctx_t *) handle;
  daq_vpp_msg_pool_entry_t *pe = msg->priv;
  daq_vpp_qpair_t *qp = pe->qpair;
  daq_vpp_desc_index_t head, mask;
  daq_vpp_desc_t *d;

  const daq_vpp_action_t translation_table[MAX_DAQ_VERDICT] = {
    [DAQ_VERDICT_PASS] = DAQ_VPP_ACTION_FORWARD,
    [DAQ_VERDICT_BLOCK] = DAQ_VPP_ACTION_DROP,
    [DAQ_VERDICT_REPLACE] = DAQ_VPP_ACTION_FORWARD,
    [DAQ_VERDICT_WHITELIST] = DAQ_VPP_ACTION_FORWARD,
    [DAQ_VERDICT_BLACKLIST] = DAQ_VPP_ACTION_DROP,
    [DAQ_VERDICT_IGNORE] = DAQ_VPP_ACTION_FORWARD
  };

  if (verdict >= MAX_DAQ_VERDICT)
    verdict = DAQ_VERDICT_PASS;
  ctx->stats.verdicts[verdict]++;

  mask = qp->queue_size - 1;
  head = __atomic_load_n (qp->deq_head, __ATOMIC_RELAXED);
  d = qp->descs + pe->index;

  d->action = translation_table[verdict];
  qp->deq_ring[head & mask] = pe->index;
  head = head + 1;
  __atomic_store_n (qp->deq_head, head, __ATOMIC_RELEASE);

  if (vdm->input_mode == DAQ_VPP_INPUT_MODE_INTERRUPT)
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
  DEBUG ("instance_id %u", ctx->instance_id);
  *info = ctx->msg_pool_info;
  return DAQ_SUCCESS;
}

static int
daq_vpp_get_stats (void __unused *handle, DAQ_Stats_t *stats)
{
  daq_vpp_ctx_t *ctx = (daq_vpp_ctx_t *) handle;
  DEBUG ("instance_id %u", ctx->instance_id);
  *stats = ctx->stats;
  return DAQ_SUCCESS;
}

static void
daq_vpp_reset_stats (void *handle)
{
  daq_vpp_ctx_t *ctx = (daq_vpp_ctx_t *) handle;
  DEBUG ("instance_id %u", ctx->instance_id);
  ctx->stats = (DAQ_Stats_t){};
}

static uint32_t
daq_vpp_get_capabilities (void __unused *handle)
{
  daq_vpp_ctx_t *ctx = (daq_vpp_ctx_t *) handle;
  DEBUG ("instance_id %u", ctx->instance_id);
  return DAQ_CAPA_BLOCK | DAQ_CAPA_UNPRIV_START | DAQ_CAPA_INTERRUPT;
}

static int
daq_vpp_get_datalink_type (void __unused *handle)
{
  daq_vpp_ctx_t *ctx = (daq_vpp_ctx_t *) handle;
  DEBUG ("instance_id %u", ctx->instance_id);
  return DLT_IPV4;
}

DAQ_SO_PUBLIC
const DAQ_ModuleAPI_t DAQ_MODULE_DATA = {
  .name = "vpp",
  .api_version = DAQ_MODULE_API_VERSION,
  .api_size = sizeof (DAQ_ModuleAPI_t),
  .module_version = DAQ_VPP_VERSION,
  .type =
    DAQ_TYPE_INTF_CAPABLE | DAQ_TYPE_INLINE_CAPABLE | DAQ_TYPE_MULTI_INSTANCE,
  .load = daq_vpp_module_load,
  .unload = daq_vpp_module_unload,
  .get_variable_descs = daq_vpp_get_variable_descs,
  .instantiate = daq_vpp_instantiate,
  .destroy = daq_vpp_destroy,
  .start = daq_vpp_start,
  .interrupt = daq_vpp_interrupt,
  .get_stats = daq_vpp_get_stats,
  .reset_stats = daq_vpp_reset_stats,
  .get_snaplen = NULL,
  .get_datalink_type = daq_vpp_get_datalink_type,
  .msg_receive = daq_vpp_msg_receive,
  .msg_finalize = daq_vpp_msg_finalize,
  .get_msg_pool_info = daq_vpp_get_msg_pool_info,
  .get_capabilities = daq_vpp_get_capabilities,
};
