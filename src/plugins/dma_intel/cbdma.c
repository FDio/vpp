/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2022 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>
#include <vlib/pci/pci.h>
#include <vlib/dma/dma.h>
#include <vppinfra/heap.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>
#include <dma_intel/dma_intel.h>

VLIB_REGISTER_LOG_CLASS (intel_dma_log, static) = {
  .class_name = "intel_dma",
  .subclass_name = "cbdma",
};

static vlib_dma_batch_t *
intel_cbdma_batch_new (vlib_main_t *vm, struct vlib_dma_config_data *cd)
{
  intel_dma_main_t *idm = &intel_dma_main;
  intel_cbdma_config_t *icc;
  intel_cbdma_batch_t *b;

  icc = vec_elt_at_index (idm->cbdma_config_heap,
			  cd->private_data + vm->thread_index);

  if (vec_len (icc->freelist) > 0)
    {
      b = vec_pop (icc->freelist);
    }
  else
    {
      b = vlib_physmem_alloc (vm, icc->alloc_size);
      vlib_pci_map_dma (vm, icc->batch_template.ch->pci_handle, b);
      /* FIXME error handling */
      *b = icc->batch_template;

      /* fill all descriptors with static data */
      for (int i = 0; i < icc->max_transfers; i++)
	b->descs[i] = (intel_cbdma_desc_t){ .next = &b->descs[i + 1] };
    }

  return &b->batch;
}

extern vlib_node_registration_t intel_cbdma_node;

int
intel_cbdma_batch_submit (vlib_main_t *vm, struct vlib_dma_batch *vb)
{
  intel_dma_main_t *idm = &intel_dma_main;
  intel_cbdma_batch_t *b = (intel_cbdma_batch_t *) vb;
  intel_cbdma_channel_t *ch = b->ch;
  u16 next;

  if (ch->n_threads > 1)
    {
      /* channel is used by multiple threads so we need to lock it */
      u8 expected = 0;
      while (!__atomic_compare_exchange_n (&ch->lock, &expected,
					   /* desired */ 1, /* weak */ 0,
					   __ATOMIC_ACQUIRE, __ATOMIC_RELAXED))
	{
	  while (__atomic_load_n (&ch->lock, __ATOMIC_RELAXED))
	    CLIB_PAUSE ();
	  expected = 0;
	}
    }

  next = ch->next;
  ch->comp_descs[next].next = b->descs;
  ch->next = next = (next + 1) & ch->mask;
  b->descs[vb->n_enq] = (intel_cbdma_desc_t){
    .dst = &b->completion,
    .op_type = 3,
    .src = (void *) -1,
    .fence = 1,
    .next = &ch->comp_descs[next],
  };

  ch->dmacount += vb->n_enq + 2;
  //__atomic_store_n(&ch->regs->dmacount, ch->dmacount, __ATOMIC_RELEASE);

  if (ch->n_threads > 1)
    __atomic_store_n (&ch->lock, 0, __ATOMIC_RELEASE);

  fformat (stdout, "\n%U\n", format_cbdma_descs, &b->descs[0], vb->n_enq + 1);

  vec_add1 (idm->cbdma_threads[vm->thread_index].pending_batches, b);
  vlib_node_set_interrupt_pending (vm, intel_cbdma_node.index);
  b->completion  = 1;
  return 1;
}

static int
intel_cbdma_config_add_fn (vlib_main_t *vm, vlib_dma_config_data_t *cd)
{
  intel_dma_main_t *idm = &intel_dma_main;
  intel_cbdma_config_t *icc;
  u32 index, n_threads = vlib_get_n_threads ();

  vlib_dma_config_t supported_cfg = {
    .barrier_before_last = 1,
  };

  if (cd->cfg.features & ~supported_cfg.features)
    {
      log_debug ("unsupported feature requested");
      return 0;
    }

  if (cd->cfg.max_transfer_size > 2 << 20)
    {
      log_debug ("transfer size (%u) too big", cd->cfg.max_transfer_size);
      return 0;
    }

  vec_validate (idm->cbdma_config_heap_handle_by_config_index,
		cd->config_index);
  index = heap_alloc_aligned (
    idm->cbdma_config_heap, n_threads, CLIB_CACHE_LINE_BYTES,
    idm->cbdma_config_heap_handle_by_config_index[cd->config_index]);

  cd->batch_new_fn = intel_cbdma_batch_new;
  cd->private_data = index;

  for (u32 thread = 0; thread < n_threads; thread++)
    {
      intel_cbdma_batch_t *icb;
      vlib_dma_batch_t *b;
      icc = vec_elt_at_index (idm->cbdma_config_heap, index + thread);

      /* size of physmem allocation for this config */
      icc->max_transfers = cd->cfg.max_transfers;
      icc->alloc_size = sizeof (intel_cbdma_batch_t) +
			sizeof (intel_cbdma_desc_t) * (icc->max_transfers + 1);
      /* fill batch template */
      icb = &icc->batch_template;
      icb->ch = idm->cbdma_threads[vm->thread_index].ch;
      icb->config_heap_index = index + thread;
      b = &icb->batch;
      b->stride = sizeof (intel_cbdma_desc_t);
      b->src_ptr_off = STRUCT_OFFSET_OF (intel_cbdma_batch_t, descs[0].src);
      b->dst_ptr_off = STRUCT_OFFSET_OF (intel_cbdma_batch_t, descs[0].dst);
      b->size_off = STRUCT_OFFSET_OF (intel_cbdma_batch_t, descs[0].size);
      b->submit_fn = intel_cbdma_batch_submit;
    }

  log_debug ("config %u added", cd->private_data);

  return 1;
}

static void
intel_cbdma_config_del_fn (vlib_main_t *vm, vlib_dma_config_data_t *cd)
{
  intel_dma_main_t *idm = &intel_dma_main;
  heap_dealloc (
    idm->cbdma_config_heap,
    idm->cbdma_config_heap_handle_by_config_index[cd->config_index]);
  log_debug ("config %u removed", cd->private_data);
}

vlib_dma_backend_t intel_cbdma_backend = {
  .name = "Intel CBDMA",
  .config_add_fn = intel_cbdma_config_add_fn,
  .config_del_fn = intel_cbdma_config_del_fn,
};

static uword
intel_cbdma_node_fn (vlib_main_t *vm, vlib_node_runtime_t *node,
			  vlib_frame_t *frame)
{
  intel_dma_main_t *idm = &intel_dma_main;
  intel_cbdma_thread_t *t = vec_elt_at_index (idm->cbdma_threads, vm->thread_index);
  u32 n_pending, n = 0;
  fformat (stderr, "%s: thread %u\n", __func__, vm->thread_index);

  n_pending = vec_len (t->pending_batches);

  for (u32 i = 0; i < n_pending; i++)
    {
      intel_cbdma_batch_t *b = t->pending_batches[i];
      if (b->completion)
	{
	  intel_cbdma_desc_t *d = b->descs + b->batch.n_enq;
	  /* restore last descriptor fields */
	  d->desc_control = 0;
	  d->next = d + 1;
	  b->completion = 0;
	  b->batch.n_enq = 0;

	  /* add to freelist */
	  vec_add1 (idm->cbdma_config_heap[b->config_heap_index].freelist, b);
	}
      else
	t->pending_batches[n++] = b;
    }

  vec_set_len (t->pending_batches, n);

  if (n)
    vlib_node_set_interrupt_pending (vm, intel_cbdma_node.index);

  return n_pending - n;
}

VLIB_REGISTER_NODE (intel_cbdma_node) = {
  .function = intel_cbdma_node_fn,
  .name = "intel-cbdma",
  .type = VLIB_NODE_TYPE_INPUT, /* FIXME should be VLIB_NODE_TYPE_PRE_INPUT */
  .state = VLIB_NODE_STATE_INTERRUPT, /*FIXME should be disabled on startup */
  .vector_size = 4,
};

