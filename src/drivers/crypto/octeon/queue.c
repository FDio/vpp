/*
 * Copyright (c) 2024 Marvell.
 * SPDX-License-Identifier: Apache-2.0
 * https://spdx.org/licenses/Apache-2.0.html
 * Copyright (c) 2026 Cisco and/or its affiliates.
 */

#include <vnet/dev/dev.h>
#include <octeon_common.h>
#include <crypto.h>

VLIB_REGISTER_LOG_CLASS (oct_log, static) = {
  .class_name = "octeon",
  .subclass_name = "crypto-queue",
};

void
oct_crypto_queue_deinit (vlib_main_t *vm, vnet_dev_crypto_queue_t *cq)
{
  oct_crypto_queue_t *q = vnet_dev_get_crypto_queue_data (cq);

  if (q->lf)
    {
      roc_cpt_iq_disable (q->lf);
      roc_cpt_lf_fini (q->lf);
      oct_plt_init_param.oct_plt_free (q->lf);
      q->lf = 0;
    }

  if (q->meta)
    oct_plt_init_param.oct_plt_free (q->meta);
  vec_free (q->frames);
  q->meta = 0;
}

vnet_dev_rv_t
oct_crypto_queue_init (vlib_main_t *vm, vnet_dev_crypto_queue_t *cq)
{
  oct_crypto_queue_t *q = vnet_dev_get_crypto_queue_data (cq);
  vnet_dev_t *dev = cq->dev;
  oct_crypto_device_t *cd = vnet_dev_get_data (dev);
  struct roc_cpt *roc_cpt = cd->roc_cpt;
  vnet_dev_rv_t rv;
  int rrv;

  q->n_desc = cq->size;

  q->lf = oct_plt_init_param.oct_plt_zmalloc (sizeof (struct roc_cpt_lf), ROC_ALIGN);
  if (q->lf == 0)
    return VNET_DEV_ERR_DMA_MEM_ALLOC_FAIL;

  q->lf->lf_id = cq->index;
  q->lf->nb_desc = q->n_desc;
  if ((rrv = roc_cpt_lf_init (roc_cpt, q->lf)) < 0)
    {
      rv = cnx_return_roc_err (dev, rrv, "roc_cpt_lf_init");
      oct_plt_init_param.oct_plt_free (q->lf);
      q->lf = 0;
      return rv;
    }

  roc_cpt_iq_enable (q->lf);

  if ((rrv = roc_cpt_lmtline_init (roc_cpt, &q->lmtline, q->lf->lf_id, false)) < 0)
    {
      oct_crypto_queue_deinit (vm, cq);
      return cnx_return_roc_err (dev, rrv, "roc_cpt_lmtline_init");
    }

  vec_validate_aligned (q->frames, q->n_desc - 1, CLIB_CACHE_LINE_BYTES);

  q->meta = oct_plt_init_param.oct_plt_zmalloc (q->n_desc * sizeof (oct_crypto_meta_t), ROC_ALIGN);
  if (q->meta == 0)
    {
      log_err (dev, "Failed to allocate crypto scatter gather memory");
      oct_crypto_queue_deinit (vm, cq);
      return VNET_DEV_ERR_DMA_MEM_ALLOC_FAIL;
    }

  return VNET_DEV_OK;
}

/* hardware writes results into the queue memory */
void
oct_crypto_queue_stop (vlib_main_t *vm, vnet_dev_crypto_queue_t *cq)
{
  oct_crypto_queue_t *q = vnet_dev_get_crypto_queue_data (cq);
  f64 timeout = vlib_time_now (vm) + 1.0;
  u16 mask = q->n_desc - 1;

  while (q->frame_head != q->frame_tail)
    {
      cpt_res_t r = {
	.u64[0] = __atomic_load_n (&q->meta[q->deq_next & mask].res.u64[0], __ATOMIC_RELAXED),
      };

      if (r.cn10k.compcode != CPT_COMP_NOT_DONE)
	{
	  if (q->deq_left == 0)
	    q->deq_left = q->frames[q->frame_head & mask]->n_vectors;
	  q->deq_next++;
	  if (--q->deq_left == 0)
	    {
	      q->elt_head = q->deq_next;
	      q->frame_head++;
	    }
	  continue;
	}

      if (vlib_time_now (vm) > timeout)
	{
	  log_err (cq->dev, "timeout waiting for %u crypto frames",
		   (u16) (q->frame_tail - q->frame_head));
	  break;
	}
      CLIB_PAUSE ();
    }
}
