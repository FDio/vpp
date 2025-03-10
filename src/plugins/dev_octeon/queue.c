/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vnet/dev/counters.h>
#include <dev_octeon/octeon.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>

VLIB_REGISTER_LOG_CLASS (oct_log, static) = {
  .class_name = "octeon",
  .subclass_name = "queue",
};

static vnet_dev_rv_t
oct_roc_err (vnet_dev_t *dev, int rv, char *fmt, ...)
{
  u8 *s = 0;
  va_list va;

  va_start (va, fmt);
  s = va_format (s, fmt, &va);
  va_end (va);

  log_err (dev, "%v - ROC error %s (%d)", s, roc_error_msg_get (rv), rv);

  vec_free (s);
  return VNET_DEV_ERR_INTERNAL;
}

vnet_dev_rv_t
oct_rx_queue_alloc (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq)
{
  vnet_dev_port_t *port = rxq->port;
  vnet_dev_t *dev = port->dev;

  log_debug (dev, "rx_queue_alloc: queue %u alocated", rxq->queue_id);
  return VNET_DEV_OK;
}

void
oct_rx_queue_free (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq)
{
  vnet_dev_port_t *port = rxq->port;
  vnet_dev_t *dev = port->dev;

  log_debug (dev, "rx_queue_free: queue %u", rxq->queue_id);
}

vnet_dev_rv_t
oct_tx_queue_alloc (vlib_main_t *vm, vnet_dev_tx_queue_t *txq)
{
  oct_txq_t *ctq = vnet_dev_get_tx_queue_data (txq);
  vnet_dev_port_t *port = txq->port;
  vnet_dev_t *dev = port->dev;
  u32 sz = sizeof (void *) * ROC_CN10K_NPA_BATCH_ALLOC_MAX_PTRS;
  vnet_dev_rv_t rv;

  log_debug (dev, "tx_queue_alloc: queue %u alocated", txq->queue_id);

  rv = vnet_dev_dma_mem_alloc (vm, dev, sz, 128, (void **) &ctq->ba_buffer);

  if (rv != VNET_DEV_OK)
    return rv;

  clib_memset_u64 (ctq->ba_buffer, OCT_BATCH_ALLOC_IOVA0_MASK,
		   ROC_CN10K_NPA_BATCH_ALLOC_MAX_PTRS);

  return rv;
}

void
oct_tx_queue_free (vlib_main_t *vm, vnet_dev_tx_queue_t *txq)
{
  oct_txq_t *ctq = vnet_dev_get_tx_queue_data (txq);
  vnet_dev_port_t *port = txq->port;
  vnet_dev_t *dev = port->dev;

  log_debug (dev, "tx_queue_free: queue %u", txq->queue_id);

  vnet_dev_dma_mem_free (vm, dev, ctq->ba_buffer);
}

vnet_dev_rv_t
oct_rxq_init (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq)
{
  oct_rxq_t *crq = vnet_dev_get_rx_queue_data (rxq);
  vnet_dev_t *dev = rxq->port->dev;
  oct_device_t *cd = vnet_dev_get_data (dev);
  vlib_buffer_pool_t *bp =
    vlib_get_buffer_pool (vm, vnet_dev_get_rx_queue_buffer_pool_index (rxq));
  struct roc_nix *nix = cd->nix;
  int rrv;

  struct npa_aura_s aura = {};
  struct npa_pool_s npapool = { .nat_align = 1 };

  if ((rrv = roc_npa_pool_create (&crq->aura_handle, bp->alloc_size, rxq->size,
				  &aura, &npapool, 0)))
    {
      oct_rxq_deinit (vm, rxq);
      return oct_roc_err (dev, rrv, "roc_npa_pool_create() failed");
    }

  crq->npa_pool_initialized = 1;
  log_notice (dev, "NPA pool created, aura_handle = 0x%lx", crq->aura_handle);

  crq->cq = (struct roc_nix_cq){
    .nb_desc = rxq->size,
    .qid = rxq->queue_id,
  };

  if ((rrv = roc_nix_cq_init (nix, &crq->cq)))
    {
      oct_rxq_deinit (vm, rxq);
      return oct_roc_err (dev, rrv,
			  "roc_nix_cq_init(qid = %u, nb_desc = %u) failed",
			  crq->cq.nb_desc, crq->cq.nb_desc);
    }

  crq->cq_initialized = 1;
  log_debug (dev, "CQ %u initialised (qmask 0x%x wdata 0x%lx)", crq->cq.qid,
	     crq->cq.qmask, crq->cq.wdata);

  crq->hdr_off = vm->buffer_main->ext_hdr_size;

  crq->rq = (struct roc_nix_rq){
    .qid = rxq->queue_id,
    .cqid = crq->cq.qid,
    .aura_handle = crq->aura_handle,
    .first_skip = crq->hdr_off + sizeof (vlib_buffer_t),
    .later_skip = crq->hdr_off + sizeof (vlib_buffer_t),
    .lpb_size = bp->data_size + crq->hdr_off + sizeof (vlib_buffer_t),
    .flow_tag_width = 32,
  };

  if ((rrv = roc_nix_rq_init (nix, &crq->rq, 1 /* disable */)))
    {
      oct_rxq_deinit (vm, rxq);
      return oct_roc_err (dev, rrv, "roc_nix_rq_init(qid = %u) failed",
			  crq->rq.qid);
    }

  crq->rq_initialized = 1;
  crq->lmt_base_addr = roc_idev_lmt_base_addr_get ();
  crq->aura_batch_free_ioaddr =
    (roc_npa_aura_handle_to_base (crq->aura_handle) +
     NPA_LF_AURA_BATCH_FREE0) |
    (0x7 << 4);

  log_debug (dev, "RQ %u initialised", crq->cq.qid);

  return VNET_DEV_OK;
}

static_always_inline vlib_buffer_t *
oct_seg_to_bp (void *p)
{
  return (vlib_buffer_t *) p - 1;
}

static void
oct_multi_seg_free (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq,
		    oct_nix_rx_cqe_desc_t *d)
{
  vlib_buffer_t *t;
  u8 s0 = d->sg0.segs, s1;

  t = oct_seg_to_bp (d->segs0[1]);
  vlib_buffer_free_one (vm, vlib_get_buffer_index (vm, t));

  if (s0 == 2)
    return;
  t = oct_seg_to_bp (d->segs0[2]);
  vlib_buffer_free_one (vm, vlib_get_buffer_index (vm, t));

  if (d->sg1.subdc != NIX_SUBDC_SG)
    return;

  s1 = d->sg1.segs;
  if (s1 == 0)
    return;

  t = oct_seg_to_bp (d->segs1[0]);
  vlib_buffer_free_one (vm, vlib_get_buffer_index (vm, t));

  if (s1 == 1)
    return;
  t = oct_seg_to_bp (d->segs1[1]);
  vlib_buffer_free_one (vm, vlib_get_buffer_index (vm, t));

  if (s1 == 2)
    return;
  t = oct_seg_to_bp (d->segs1[2]);
  vlib_buffer_free_one (vm, vlib_get_buffer_index (vm, t));
}

int
oct_drain_queue (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq)
{
  oct_rxq_t *crq = vnet_dev_get_rx_queue_data (rxq);
  oct_nix_rx_cqe_desc_t *descs = crq->cq.desc_base;
  oct_nix_lf_cq_op_status_t status;
  u32 cq_size = crq->cq.nb_desc;
  u32 cq_mask = crq->cq.qmask;
  vlib_buffer_t *b;
  u32 i, head, n_desc, n, f_cnt = 0;

  /* Free all CQ entries */
  while (1)
    {
      /* get head and tail from NIX_LF_CQ_OP_STATUS */
      status.as_u64 = roc_atomic64_add_sync (crq->cq.wdata, crq->cq.status);
      if (status.cq_err || status.op_err)
	return f_cnt;

      head = status.head;
      n_desc = (status.tail - head) & cq_mask;

      if (n_desc == 0)
	return f_cnt;

      n = clib_min (cq_size - head, n_desc);
      for (i = head; i < n; i++)
	{
	  b = oct_seg_to_bp (descs[i].segs0[0]);
	  vlib_buffer_free_one (vm, vlib_get_buffer_index (vm, b));
	  if (descs[i].sg0.segs > 1)
	    oct_multi_seg_free (vm, rxq, &descs[i]);
	}
      f_cnt += n;
      plt_write64 ((crq->cq.wdata | n), crq->cq.door);
      plt_wmb ();
    }

  return f_cnt;
}

void
oct_rxq_deinit (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq)
{
  oct_rxq_t *crq = vnet_dev_get_rx_queue_data (rxq);
  vnet_dev_t *dev = rxq->port->dev;
  int rrv;

  if (crq->rq_initialized)
    {
      rrv = roc_nix_rq_fini (&crq->rq);
      if (rrv)
	oct_roc_err (dev, rrv, "roc_nix_rq_fini() failed");
      crq->rq_initialized = 0;
    }

  if (crq->cq_initialized)
    {
      oct_drain_queue (vm, rxq);
      rrv = roc_nix_cq_fini (&crq->cq);
      if (rrv)
	oct_roc_err (dev, rrv, "roc_nix_cq_fini() failed");
      crq->cq_initialized = 0;
    }

  if (crq->npa_pool_initialized)
    {
      rrv = roc_npa_pool_destroy (crq->aura_handle);
      if (rrv)
	oct_roc_err (dev, rrv, "roc_npa_pool_destroy() failed");
      crq->npa_pool_initialized = 0;
    }
}

vnet_dev_rv_t
oct_txq_init (vlib_main_t *vm, vnet_dev_tx_queue_t *txq)
{
  oct_txq_t *ctq = vnet_dev_get_tx_queue_data (txq);
  vnet_dev_t *dev = txq->port->dev;
  oct_device_t *cd = vnet_dev_get_data (dev);
  struct roc_nix *nix = cd->nix;
  struct npa_aura_s aura = {};
  struct npa_pool_s npapool = { .nat_align = 1 };
  int rrv;
  vlib_buffer_pool_t *bp = vlib_get_buffer_pool (vm, 0);

  if ((rrv = roc_npa_pool_create (
	 &ctq->aura_handle, bp->alloc_size,
	 txq->size * 6 /* worst case - two SG with 3 segs each = 6 */, &aura,
	 &npapool, 0)))
    {
      oct_txq_deinit (vm, txq);
      return oct_roc_err (dev, rrv, "roc_npa_pool_create() failed");
    }

  ctq->npa_pool_initialized = 1;
  log_notice (dev, "NPA pool created, aura_handle = 0x%lx", ctq->aura_handle);

  ctq->sq = (struct roc_nix_sq){
    .nb_desc = txq->size,
    .qid = txq->queue_id,
    .max_sqe_sz = NIX_MAXSQESZ_W16,
  };

  if ((rrv = roc_nix_sq_init (nix, &ctq->sq)))
    {
      oct_txq_deinit (vm, txq);
      return oct_roc_err (
	dev, rrv,
	"roc_nix_sq_init(qid = %u, nb_desc = %u, max_sqe_sz = %u) failed",
	ctq->sq.nb_desc, ctq->sq.max_sqe_sz);
    }

  ctq->sq_initialized = 1;
  log_debug (dev, "SQ initialised, qid %u, nb_desc %u, max_sqe_sz %u",
	     ctq->sq.qid, ctq->sq.nb_desc, ctq->sq.max_sqe_sz);

  ctq->hdr_off = vm->buffer_main->ext_hdr_size;

  if (ctq->sq.lmt_addr == 0)
    ctq->sq.lmt_addr = (void *) nix->lmt_base;
  ctq->io_addr = ctq->sq.io_addr & ~0x7fULL;
  ctq->lmt_addr = ctq->sq.lmt_addr;

  return VNET_DEV_OK;
}

void
oct_txq_deinit (vlib_main_t *vm, vnet_dev_tx_queue_t *txq)
{
  oct_txq_t *ctq = vnet_dev_get_tx_queue_data (txq);
  vnet_dev_t *dev = txq->port->dev;
  int rrv;

  if (ctq->sq_initialized)
    {
      rrv = roc_nix_sq_fini (&ctq->sq);
      if (rrv)
	oct_roc_err (dev, rrv, "roc_nix_sq_fini() failed");
      ctq->sq_initialized = 0;
    }

  if (ctq->npa_pool_initialized)
    {
      rrv = roc_npa_pool_destroy (ctq->aura_handle);
      if (rrv)
	oct_roc_err (dev, rrv, "roc_npa_pool_destroy() failed");
      ctq->npa_pool_initialized = 0;
    }
}

u8 *
format_oct_rxq_info (u8 *s, va_list *args)
{
  vnet_dev_format_args_t *a = va_arg (*args, vnet_dev_format_args_t *);
  vnet_dev_rx_queue_t *rxq = va_arg (*args, vnet_dev_rx_queue_t *);
  oct_rxq_t *crq = vnet_dev_get_rx_queue_data (rxq);
  u32 indent = format_get_indent (s);

  if (a->debug)
    {
      s = format (s, "n_enq %u cq_nb_desc %u", crq->n_enq, crq->cq.nb_desc);
      s = format (s, "\n%Uaura: id 0x%x count %u limit %u avail %u",
		  format_white_space, indent,
		  roc_npa_aura_handle_to_aura (crq->aura_handle),
		  roc_npa_aura_op_cnt_get (crq->aura_handle),
		  roc_npa_aura_op_limit_get (crq->aura_handle),
		  roc_npa_aura_op_available (crq->aura_handle));
    }
  return s;
}

u8 *
format_oct_txq_info (u8 *s, va_list *args)
{
  vnet_dev_format_args_t *a = va_arg (*args, vnet_dev_format_args_t *);
  vnet_dev_tx_queue_t *txq = va_arg (*args, vnet_dev_tx_queue_t *);
  oct_txq_t *ctq = vnet_dev_get_tx_queue_data (txq);
  u32 indent = format_get_indent (s);

  if (a->debug)
    {
      s = format (s, "n_enq %u sq_nb_desc %u io_addr %p lmt_addr %p",
		  ctq->n_enq, ctq->sq.nb_desc, ctq->io_addr, ctq->lmt_addr);
      s = format (s, "\n%Uaura: id 0x%x count %u limit %u avail %u",
		  format_white_space, indent,
		  roc_npa_aura_handle_to_aura (ctq->aura_handle),
		  roc_npa_aura_op_cnt_get (ctq->aura_handle),
		  roc_npa_aura_op_limit_get (ctq->aura_handle),
		  roc_npa_aura_op_available (ctq->aura_handle));
    }

  return s;
}
