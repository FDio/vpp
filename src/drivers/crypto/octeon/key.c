/*
 * Copyright (c) 2024 Marvell.
 * SPDX-License-Identifier: Apache-2.0
 * https://spdx.org/licenses/Apache-2.0.html
 * Copyright (c) 2026 Cisco and/or its affiliates.
 */

#include <vnet/dev/dev.h>
#include <vnet/dev/counters.h>
#include <vnet/devices/devices.h>
#include <octeon_common.h>
#include <crypto.h>

VLIB_REGISTER_LOG_CLASS (oct_log, static) = {
  .class_name = "octeon",
  .subclass_name = "crypto",
};

static vnet_dev_crypto_engine_t *
oct_crypto_ctx_engine (vnet_crypto_ctx_t *ctx)
{
  return vnet_dev_crypto_get_engine (
    vnet_crypto_ctx_get_engine (ctx, VNET_CRYPTO_HANDLER_TYPE_ASYNC));
}

static void
oct_crypto_key_free (vnet_crypto_ctx_t *ctx, oct_crypto_key_t *ckey)
{
  vlib_main_t *vm = vlib_get_main ();

  if (ckey->flush_on_free)
    {
      vnet_dev_crypto_queue_t *cq =
	vnet_dev_crypto_get_thread_queue (oct_crypto_ctx_engine (ctx), 0);

      if (cq)
	{
	  oct_crypto_queue_t *q = vnet_dev_get_crypto_queue_data (cq);

	  roc_cpt_lf_ctx_flush (q->lf, ckey->enc_ctx, true);
	  roc_cpt_lf_ctx_flush (q->lf, ckey->dec_ctx, true);
	}
    }

  vnet_dev_dma_slab_free (vm, 0, ckey->enc_ctx);
  vnet_dev_dma_slab_free (vm, 0, ckey->dec_ctx);
}

void
oct_crypto_key_change_handler (vnet_crypto_ctx_t *ctx, vnet_crypto_key_change_args_t *args)
{
  oct_crypto_key_t *ckey = (oct_crypto_key_t *) args->key_data;
  vlib_main_t *vm = vlib_get_main ();
  u32 sz = sizeof (struct roc_se_ctx);
  vnet_dev_crypto_engine_t *e;
  vnet_dev_crypto_queue_t *cq;
  oct_crypto_device_t *cd;
  vnet_dev_t *dev = 0;

  ASSERT (args->handler_type == VNET_CRYPTO_HANDLER_TYPE_ASYNC);

  if (args->action == VNET_CRYPTO_KEY_DATA_REMOVE)
    {
      if (ckey->enc_ctx)
	oct_crypto_key_free (ctx, ckey);
      return;
    }

  ASSERT (args->action == VNET_CRYPTO_KEY_DATA_ADD);

  if (ckey->enc_ctx || (e = oct_crypto_ctx_engine (ctx)) == 0)
    return;

  /* without a device the enqueue handler fails the operations */
  for (u32 ti = 0; ti < vlib_get_n_threads () && dev == 0; ti++)
    if ((cq = vnet_dev_crypto_get_thread_queue (e, ti)))
      dev = cq->dev;

  if (dev == 0)
    return;

  cd = vnet_dev_get_data (dev);
  ckey->enc_ctx = vnet_dev_dma_slab_alloc (vm, dev, sz, ROC_ALIGN);
  ckey->dec_ctx = vnet_dev_dma_slab_alloc (vm, dev, sz, ROC_ALIGN);
  if (ckey->enc_ctx == 0 || ckey->dec_ctx == 0)
    {
      log_err (dev, "Failed to allocate crypto session memory");
      if (ckey->enc_ctx)
	vnet_dev_dma_slab_free (vm, 0, ckey->enc_ctx);
      if (ckey->dec_ctx)
	vnet_dev_dma_slab_free (vm, 0, ckey->dec_ctx);
      *ckey = (oct_crypto_key_t) {};
      return;
    }

  ckey->flush_on_free = cd->hw_ctx_cache;

  if (oct_crypto_session_init (vm, ckey, ctx, cd))
    {
      log_err (dev, "Failed to initialize crypto session");
      oct_crypto_key_free (ctx, ckey);
      *ckey = (oct_crypto_key_t) {};
    }
}
