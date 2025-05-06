/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2021 Cisco Systems, Inc.
 */

#define _GNU_SOURCE
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <errno.h>
#include <sys/epoll.h>

#include <daq_dlt.h>
#include <daq_module_api.h>

#include "daq_vpp.h"
#include "daq_vpp_internal.h"

daq_vpp_main_t daq_vpp_main = {
  .socket_name = DAQ_VPP_DEFAULT_SOCKET_PATH,
  .socket_fd = -1,
  .msg_pool_size = 256,
};

static inline int
daq_vpp_qpair_lock (daq_vpp_qpair_t *p)
{
  uint8_t free = 0;
  while (!__atomic_compare_exchange_n (&p->lock, &free, 1, 0, __ATOMIC_ACQUIRE,
				       __ATOMIC_RELAXED))
    {
      while (__atomic_load_n (&p->lock, __ATOMIC_RELAXED))
	VPP_DAQ_PAUSE ();
      free = 0;
    }
  return 0;
}

static inline void
daq_vpp_qpair_unlock (daq_vpp_qpair_t *p)
{
  __atomic_store_n (&p->lock, 0, __ATOMIC_RELEASE);
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
  daq_vpp_main_t *vdm = &daq_vpp_main;
  vdm->daq_base_api = (DAQ_BaseAPI_t){};
  if (vdm->bpools)
    {
      for (int i = 0; i < vdm->num_bpools; i++)
	{
	  daq_vpp_buffer_pool_t *bp = vdm->bpools + i;
	  if (bp->fd != -1)
	    close (bp->fd);
	  if (bp->base && bp->base != MAP_FAILED)
	    munmap (bp->base, bp->size);
	}
      free (vdm->bpools);
    }
  return DAQ_SUCCESS;
}

static void
daq_vpp_destroy (void *handle)
{
#if 0
  daq_vpp_ctx_t *vc = (daq_vpp_ctx_t *) handle;

  if (vc->qpairs)
    {
      for (int i = 0; i < vc->num_qpairs; i++)
	{
	  daq_vpp_qpair_t *qp = vc->qpairs + i;
	  if (qp->enq_fd != -1)
	    close (qp->enq_fd);
	  if (qp->deq_fd != -1)
	    close (qp->deq_fd);
	  if (qp->desc_data)
	    free (qp->desc_data);
	}
      free (vc->qpairs);
    }

  if (vc->epoll_fd != -1)
    close (vc->epoll_fd);
  free (vc);
#endif
}

#define ERR(r, fmt, ...)                                                    \
  {                                                                          \
    SET_ERROR (modinst, "%s: " fmt, __func__, ##__VA_ARGS__);                \
    rv = r;                                                               \
    goto err;                                                                \
 }

static int
daq_vpp_instantiate (DAQ_ModuleConfig_h modcfg, DAQ_ModuleInstance_h modinst,
		     void **ctxt_ptr)
{
  daq_vpp_main_t *vdm = &daq_vpp_main;
  daq_vpp_rv_t rv = 0;
  daq_vpp_input_t *in;
  daq_vpp_ctx_t *ctx = 0;
  unsigned n_instances;
  char name[DAQ_VPP_MAX_INST_NAME_LEN + 6], *p;
  long qpair = -1;

  snprintf (name, sizeof (name), "%s",
	    vdm->daq_base_api.config_get_input (modcfg));

  p = strchrnul (name, ':');
  if (*p == ':')
    {
      char *endptr;
      *p = '\0';
      qpair = strtol (p + 1, &endptr, 10);
      if (*endptr)
	ERR (DAQ_ERROR_INVAL, "invalid input name'%s'", name);
    }
  if (p - name >= DAQ_VPP_MAX_INST_NAME_LEN)
    ERR (DAQ_ERROR_INVAL, "input name '%s' too long", name);

  n_instances = vdm->daq_base_api.config_get_total_instances (modcfg);

  daq_vpp_parse_config (modcfg);

  DEBUG ("instance %u/%u input %s qpair %ld",
	 vdm->daq_base_api.config_get_instance_id (modcfg),
	 vdm->daq_base_api.config_get_total_instances (modcfg), name, qpair);

  ctx = calloc (1, sizeof (daq_vpp_ctx_t) +
		     vdm->msg_pool_size * sizeof (daq_vpp_msg_pool_entry_t));
  ctx->modinst = modinst;
  ctx->instance_id = vdm->daq_base_api.config_get_instance_id (modcfg);

  if (!vdm->connected)
    {
      rv = daq_vpp_connect (n_instances);

      if (rv)
	goto err;
    }

  rv = daq_vpp_find_or_add_input (name, &in);
  if (rv)
    goto err;

  ctx->modinst = modinst;
  ctx->epoll_fd = -1;

#if 0
  vc->intf_count = 1;

  if (vdm->debug)
    {
      printf ("[%s]\n", input);
      printf ("  Number of queue pairs: %u\n", vc->num_qpairs);
    }

  if ((vc->epoll_fd = epoll_create (1)) == -1)
    ERR (DAQ_ERROR_NODEV,
	 "couldn't create epoll fd for the new VPP context");

  /* receive queue pairs */
  for (int i = 0; i < vc->num_qpairs; i++)
    {
      ev.data.u32 = i;

      if (epoll_ctl (vc->epoll_fd, EPOLL_CTL_ADD, qp->enq_fd, &ev) == -1)
	ERR (DAQ_ERROR_NODEV,
	     "failed to dequeue fd to epoll instance for the new VPP context");

      qsz = qp->queue_size;

      qp->desc_data = calloc (qsz, sizeof (daq_vpp_desc_data_t));
      if (!qp->desc_data)
	ERR (DAQ_ERROR_NOMEM,
	     "couldn't allocate memory for the new VPP context");


      DEBUG ("Queue pair %u:\n", i);
      DEBUG ("  Size: %u\n", qp->queue_size);
      DEBUG ("  Enqueue fd: %u\n", qp->enq_fd);
      DEBUG ("  Dequeue fd: %u\n", qp->deq_fd);
    }

      for (daq_vpp_desc_index_t i = 0; i < qp->queue_size; i++)
	{
	  daq_vpp_desc_data_t *dd = qp->desc_data + i;
	  DAQ_PktHdr_t *pkthdr = &dd->pkthdr;
	  DAQ_Msg_t *msg = &dd->msg;

	  dd->index = i;
	  dd->qpair_index = i;
	  msg->priv = dd;
	}
#endif

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

  return DAQ_SUCCESS;
err:
  if (rv != DAQ_VPP_OK)
    daq_vpp_main.daq_base_api.set_errbuf (modinst, "%s",
					  daq_vpp_rv_string (rv));
  if (ctx)
    free (ctx);
  return DAQ_ERROR;
}

static int
daq_vpp_start (void __unused *handle)
{
  return DAQ_SUCCESS;
}

static int
daq_vpp_interrupt (void *handle)
{
  daq_vpp_ctx_t *vc = (daq_vpp_ctx_t *) handle;

  vc->interrupted = true;

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

  daq_vpp_qpair_lock (qp);
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
  daq_vpp_qpair_unlock (qp);

  return n_recv;
}

static unsigned
daq_vpp_msg_receive (void *handle, const unsigned max_recv,
		     const DAQ_Msg_t *msgs[], DAQ_RecvStatus *rstat)
{
  daq_vpp_main_t *vdm = &daq_vpp_main;
  daq_vpp_ctx_t *ctx = (daq_vpp_ctx_t *) handle;
  daq_vpp_input_t *in = ctx->input;
  uint32_t n_qpairs_left = in->num_qpairs;
  struct epoll_event epoll_events[32];
  uint32_t n, n_recv = 0;
  int32_t n_events;

  /* If the receive has been interrupted, break out of loop and return. */
  if (ctx->interrupted)
    {
      ctx->interrupted = false;
      *rstat = DAQ_RSTAT_INTERRUPTED;
      return 0;
    }

  /* first, we visit all qpairs. If we find any work there then we can give
   * it back immediatelly. To avoid bias towards qpair 0 we remeber what
   * next qpair */
  while (n_qpairs_left)
    {
      daq_vpp_qpair_t *qp = in->qpairs + in->next_qpair;

      n = daq_vpp_msg_receive_one (ctx, qp, msgs, max_recv - n_recv);
      if (n)
	{
	  msgs += n;
	  n_recv += n;
	}

      /* next */
      in->next_qpair++;
      if (in->next_qpair == in->num_qpairs)
	in->next_qpair = 0;
      n_qpairs_left--;
    }

  if (vdm->input_mode == DAQ_VPP_INPUT_MODE_POLLING)
    {
      *rstat = DAQ_RSTAT_OK;
      return n_recv;
    }

  if (n_recv)
    {
      *rstat = DAQ_RSTAT_OK;
      return n_recv;
    }

  n_events =
    epoll_wait (ctx->epoll_fd, epoll_events, ARRAY_LEN (epoll_events), 1000);

  if (n_events == 0)
    {
      *rstat = DAQ_RSTAT_TIMEOUT;
      return 0;
    }
  if (n_events < 0)
    {
      *rstat = errno == EINTR ? DAQ_RSTAT_TIMEOUT : DAQ_RSTAT_ERROR;
      return 0;
    }

  for (int i = 0; i < n_events; i++)
    {
      uint64_t ctr;
      daq_vpp_qpair_t *qp = in->qpairs + epoll_events[i].data.u32;

      n = daq_vpp_msg_receive_one (ctx, qp, msgs, max_recv - n_recv);
      if (n)
	{
	  msgs += n;
	  n_recv += n;
	}
      ssize_t __unused size = read (qp->enq_fd, &ctr, sizeof (ctr));
    }

  *rstat = DAQ_RSTAT_OK;
  return n_recv;
}

static int
daq_vpp_msg_finalize (void *handle, const DAQ_Msg_t *msg, DAQ_Verdict verdict)
{
  daq_vpp_main_t *vdm = &daq_vpp_main;
  daq_vpp_ctx_t *ctx = (daq_vpp_ctx_t *) handle;
  daq_vpp_msg_pool_entry_t *pe = msg->priv;
  daq_vpp_qpair_t *qp = pe->qpair;
  daq_vpp_desc_t *d;
  uint32_t mask;
  daq_vpp_desc_index_t head;
  int retv = DAQ_SUCCESS;

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

  daq_vpp_qpair_lock (qp);
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

  daq_vpp_qpair_unlock (qp);
  return retv;
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
  return DAQ_CAPA_BLOCK | DAQ_CAPA_UNPRIV_START;
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
