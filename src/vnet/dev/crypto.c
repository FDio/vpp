/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vnet/dev/counters.h>
#include <vnet/dev/log.h>

VLIB_REGISTER_LOG_CLASS (dev_log, static) = {
  .class_name = "dev",
  .subclass_name = "crypto",
};

static vnet_dev_counter_t crypto_queue_counters[] = {
#define _(n, s, u) VNET_DEV_CTR_VENDOR (0, NA, u, s),
  foreach_vnet_dev_crypto_queue_counter
#undef _
};

static void
vnet_dev_crypto_register_engine (vlib_main_t *vm, vnet_dev_driver_t *drv)
{
  vnet_dev_crypto_ops_t *ops = &drv->registration->crypto.ops;
  vnet_dev_driver_registration_t *r = drv->registration;
  vnet_crypto_engine_id_t engine;

  engine = vnet_crypto_register_engine (vm, r->crypto.engine_name, r->crypto.priority,
					r->crypto.engine_desc);

  if (ops->dequeue)
    vnet_crypto_register_dequeue_handler (vm, engine, ops->dequeue);

  if (ops->get_enqueue_handler)
    for (u32 alg = 1; alg < VNET_CRYPTO_N_ALGS; alg++)
      for (u32 type = 0; type < VNET_CRYPTO_OP_N_TYPES; type++)
	{
	  vnet_crypto_frame_enq_fn_t *fn = ops->get_enqueue_handler (alg, type);
	  if (fn)
	    vnet_crypto_register_enqueue_handler_by_alg (vm, engine, alg, type, fn);
	}

  if (ops->key_change)
    vnet_crypto_register_key_change_handler (vm, engine, ops->key_change, ops->key_data_sz);

  drv->crypto_engine = engine;
  drv->crypto_engine_registered = 1;
  vec_validate (drv->crypto_thread_queues, vlib_get_n_threads () - 1);
  log_debug (0, "crypto engine '%s' registered", r->crypto.engine_name);
}

static void
vnet_dev_crypto_queue_free (vlib_main_t *vm, vnet_dev_crypto_queue_t *cq)
{
  vnet_dev_driver_t *drv = vec_elt_at_index (vnet_dev_main.drivers, cq->dev->driver_index);
  vnet_dev_crypto_ops_t *ops = &drv->registration->crypto.ops;

  if (cq->started && ops->stop)
    ops->stop (vm, cq);
  cq->started = 0;

  if (cq->initialized && ops->deinit)
    ops->deinit (vm, cq);
  cq->initialized = 0;

  if (cq->counter_main)
    vnet_dev_counters_free (vm, cq->counter_main);
  clib_bitmap_free (cq->assigned_threads);
  clib_mem_free (cq);
}

/* Called with the worker threads at the barrier. */
static void
vnet_dev_crypto_queues_remove (vlib_main_t *vm, vnet_dev_t *dev)
{
  vnet_dev_driver_t *drv = vec_elt_at_index (vnet_dev_main.drivers, dev->driver_index);
  uword ti;

  vec_foreach_pointer (cq, dev->crypto_queues)
    {
      clib_bitmap_foreach (ti, cq->assigned_threads)
	{
	  vnet_dev_crypto_queue_t **tq = drv->crypto_thread_queues[ti];
	  for (u32 i = 0; i < vec_len (tq); i++)
	    if (tq[i] == cq)
	      {
		vec_del1 (drv->crypto_thread_queues[ti], i);
		break;
	      }
	}
    }

  vec_foreach_pointer (cq, dev->crypto_queues)
    vnet_dev_crypto_queue_free (vm, cq);

  vec_free (dev->crypto_queues);
}

vnet_dev_rv_t
vnet_dev_crypto_init (vlib_main_t *vm, vnet_dev_t *dev)
{
  vnet_dev_driver_t *drv = vec_elt_at_index (vnet_dev_main.drivers, dev->driver_index);
  vnet_dev_driver_registration_t *r = drv->registration;
  vnet_dev_crypto_ops_t *ops = &r->crypto.ops;
  u32 n_threads = vlib_get_n_threads ();
  u32 n_queues = clib_min (clib_max (dev->max_crypto_queues, 1), n_threads);
  vnet_dev_rv_t rv = VNET_DEV_OK;

  if (r->crypto.engine_name == 0)
    return VNET_DEV_OK;

  if (dev->crypto_queue_size == 0)
    {
      log_err (dev, "driver did not set crypto_queue_size");
      return VNET_DEV_ERR_INVALID_VALUE;
    }

  if (drv->crypto_engine_registered == 0)
    vnet_dev_crypto_register_engine (vm, drv);

  vlib_worker_thread_barrier_sync (vm);

  for (u32 i = 0; i < n_queues; i++)
    {
      vnet_dev_crypto_queue_t *cq;

      cq = vnet_dev_alloc_with_data (sizeof (*cq), r->crypto.queue_data_sz);
      cq->dev = dev;
      cq->index = i;
      cq->size = dev->crypto_queue_size;
      cq->lock_needed = n_queues < n_threads;
      cq->counter_main =
	vnet_dev_counters_alloc (vm, crypto_queue_counters, ARRAY_LEN (crypto_queue_counters),
				 "%s crypto queue %u counters", dev->device_id, i);
      vec_add1 (dev->crypto_queues, cq);

      if (ops->init && (rv = ops->init (vm, cq)) != VNET_DEV_OK)
	{
	  log_err (dev, "crypto queue %u init failed [rv %d]", i, rv);
	  goto done;
	}
      cq->initialized = 1;

      if (ops->start && (rv = ops->start (vm, cq)) != VNET_DEV_OK)
	{
	  log_err (dev, "crypto queue %u start failed [rv %d]", i, rv);
	  goto done;
	}
      cq->started = 1;
    }

  for (u32 ti = 0; ti < n_threads; ti++)
    {
      vnet_dev_crypto_queue_t *cq = dev->crypto_queues[ti % n_queues];
      cq->assigned_threads = clib_bitmap_set (cq->assigned_threads, ti, 1);
      vec_add1 (drv->crypto_thread_queues[ti], cq);
    }

  log_debug (dev, "%u crypto queues created, size %u", n_queues, dev->crypto_queue_size);

done:
  if (rv != VNET_DEV_OK)
    vnet_dev_crypto_queues_remove (vm, dev);
  vlib_worker_thread_barrier_release (vm);
  return rv;
}

void
vnet_dev_crypto_deinit (vlib_main_t *vm, vnet_dev_t *dev)
{
  if (vec_len (dev->crypto_queues) == 0)
    return;

  /* no worker may be inside an enqueue or dequeue handler while the queues
   * are stopped and freed */
  vlib_worker_thread_barrier_sync (vm);
  vnet_dev_crypto_queues_remove (vm, dev);
  vlib_worker_thread_barrier_release (vm);
}
