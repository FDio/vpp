/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2022 Cisco Systems, Inc.
 * Copyright (c) 2022 Intel and/or its affiliates.
 */

#include <vlib/vlib.h>
#include <vlib/pci/pci.h>
#include <vlib/dma/dma.h>
#include <vppinfra/heap.h>
#include <vppinfra/atomics.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>
#include <dma_intel/dsa_intel.h>

extern vlib_node_registration_t intel_dsa_node;

VLIB_REGISTER_LOG_CLASS (intel_dsa_log, static) = {
  .class_name = "intel_dsa",
  .subclass_name = "dsa",
};

static void
intel_dsa_channel_lock (intel_dsa_channel_t *ch)
{
  u8 expected = 0;
  if (ch->n_threads < 2)
    return;

  /* channel is used by multiple threads so we need to lock it */
  while (!__atomic_compare_exchange_n (&ch->lock, &expected,
				       /* desired */ 1, /* weak */ 0,
				       __ATOMIC_ACQUIRE, __ATOMIC_RELAXED))
    {
      while (__atomic_load_n (&ch->lock, __ATOMIC_RELAXED))
	CLIB_PAUSE ();
      expected = 0;
    }
}

static void
intel_dsa_channel_unlock (intel_dsa_channel_t *ch)
{
  if (ch->n_threads < 2)
    return;

  __atomic_store_n (&ch->lock, 0, __ATOMIC_RELEASE);
}

static vlib_dma_batch_t *
intel_dsa_batch_new (vlib_main_t *vm, struct vlib_dma_config_data *cd)
{
  intel_dsa_main_t *idm = &intel_dsa_main;
  intel_dsa_config_t *idc;
  intel_dsa_batch_t *b;

  idc = vec_elt_at_index (idm->dsa_config_heap,
			  cd->private_data + vm->thread_index);

  if (vec_len (idc->freelist) > 0)
    b = vec_pop (idc->freelist);
  else
    {
      clib_spinlock_lock (&idm->lock);
      b = vlib_physmem_alloc (vm, idc->alloc_size);
      clib_spinlock_unlock (&idm->lock);
      /* if no free space in physmem, force quit */
      ASSERT (b != NULL);
      *b = idc->batch_template;
      b->max_transfers = idc->max_transfers;

      u32 def_flags = (INTEL_DSA_OP_MEMMOVE << INTEL_DSA_OP_SHIFT) |
		      INTEL_DSA_FLAG_CACHE_CONTROL;
      if (b->ch->block_on_fault)
	def_flags |= INTEL_DSA_FLAG_BLOCK_ON_FAULT;
      for (int i = 0; i < idc->max_transfers; i++)
	{
	  intel_dsa_desc_t *dsa_desc = b->descs + i;
	  dsa_desc->op_flags = def_flags;
	}
    }

  return &b->batch;
}

#if defined(__x86_64__) || defined(i386)
static_always_inline void
__movdir64b (volatile void *dst, const void *src)
{
  asm volatile(".byte 0x66, 0x0f, 0x38, 0xf8, 0x02"
	       :
	       : "a"(dst), "d"(src)
	       : "memory");
}
#endif

static_always_inline void
intel_dsa_batch_fallback (vlib_main_t *vm, intel_dsa_batch_t *b,
			  intel_dsa_channel_t *ch)
{
  for (u16 i = 0; i < b->batch.n_enq; i++)
    {
      intel_dsa_desc_t *desc = &b->descs[i];
      clib_memcpy_fast (desc->dst, desc->src, desc->size);
    }
  b->status = INTEL_DSA_STATUS_CPU_SUCCESS;
  ch->submitted++;
  return;
}

int
intel_dsa_batch_submit (vlib_main_t *vm, struct vlib_dma_batch *vb)
{
  intel_dsa_main_t *idm = &intel_dsa_main;
  intel_dsa_batch_t *b = (intel_dsa_batch_t *) vb;
  intel_dsa_channel_t *ch = b->ch;
  if (PREDICT_FALSE (vb->n_enq == 0))
    {
      vec_add1 (idm->dsa_config_heap[b->config_heap_index].freelist, b);
      return 0;
    }

  intel_dsa_channel_lock (ch);
  if (ch->n_enq >= ch->size)
    {
      if (!b->sw_fallback)
	{
	  intel_dsa_channel_unlock (ch);
	  return 0;
	}
      /* skip channel limitation if first pending finished */
      intel_dsa_batch_t *lb = NULL;
      u32 n_pendings =
	vec_len (idm->dsa_threads[vm->thread_index].pending_batches);
      if (n_pendings)
	lb =
	  idm->dsa_threads[vm->thread_index].pending_batches[n_pendings - 1];

      if (!lb || lb->status != INTEL_DSA_STATUS_SUCCESS)
	{
	  intel_dsa_batch_fallback (vm, b, ch);
	  goto done;
	}
    }

  b->status = INTEL_DSA_STATUS_BUSY;
  if (PREDICT_FALSE (vb->n_enq == 1))
    {
      intel_dsa_desc_t *desc = &b->descs[0];
      desc->completion = (u64) &b->completion_cl;
      desc->op_flags |= INTEL_DSA_FLAG_COMPLETION_ADDR_VALID |
			INTEL_DSA_FLAG_REQUEST_COMPLETION;
#if defined(__x86_64__) || defined(i386)
      _mm_sfence (); /* fence before writing desc to device */
      __movdir64b (ch->portal, (void *) desc);
#endif
    }
  else
    {
      intel_dsa_desc_t *batch_desc = &b->descs[b->max_transfers];
      batch_desc->op_flags = (INTEL_DSA_OP_BATCH << INTEL_DSA_OP_SHIFT) |
			     INTEL_DSA_FLAG_COMPLETION_ADDR_VALID |
			     INTEL_DSA_FLAG_REQUEST_COMPLETION;
      batch_desc->desc_addr = (void *) (b->descs);
      batch_desc->size = vb->n_enq;
      batch_desc->completion = (u64) &b->completion_cl;
#if defined(__x86_64__) || defined(i386)
      _mm_sfence (); /* fence before writing desc to device */
      __movdir64b (ch->portal, (void *) batch_desc);
#endif
    }

  ch->submitted++;
  ch->n_enq++;

done:
  intel_dsa_channel_unlock (ch);
  vec_add1 (idm->dsa_threads[vm->thread_index].pending_batches, b);
  vlib_node_set_interrupt_pending (vm, intel_dsa_node.index);
  return 1;
}

static int
intel_dsa_check_channel (intel_dsa_channel_t *ch, vlib_dma_config_data_t *cd)
{
  if (!ch)
    {
      dsa_log_error ("no available dsa channel");
      return 1;
    }
  vlib_dma_config_t supported_cfg = {
    .barrier_before_last = 1,
    .sw_fallback = 1,
  };

  if (cd->cfg.features & ~supported_cfg.features)
    {
      dsa_log_error ("unsupported feature requested");
      return 1;
    }

  if (cd->cfg.max_transfers > ch->max_transfers)
    {
      dsa_log_error ("transfer number (%u) too big", cd->cfg.max_transfers);
      return 1;
    }

  if (cd->cfg.max_transfer_size > ch->max_transfer_size)
    {
      dsa_log_error ("transfer size (%u) too big", cd->cfg.max_transfer_size);
      return 1;
    }
  return 0;
}

static_always_inline void
intel_dsa_alloc_dma_batch (vlib_main_t *vm, intel_dsa_config_t *idc)
{
  intel_dsa_batch_t *b;
  b = vlib_physmem_alloc (vm, idc->alloc_size);
  /* if no free space in physmem, force quit */
  ASSERT (b != NULL);
  *b = idc->batch_template;
  b->max_transfers = idc->max_transfers;

  u32 def_flags = (INTEL_DSA_OP_MEMMOVE << INTEL_DSA_OP_SHIFT) |
		  INTEL_DSA_FLAG_CACHE_CONTROL;
  if (b->ch->block_on_fault)
    def_flags |= INTEL_DSA_FLAG_BLOCK_ON_FAULT;

  for (int i = 0; i < idc->max_transfers; i++)
    {
      intel_dsa_desc_t *dsa_desc = b->descs + i;
      dsa_desc->op_flags = def_flags;
    }
  vec_add1 (idc->freelist, b);
}

static int
intel_dsa_config_add_fn (vlib_main_t *vm, vlib_dma_config_data_t *cd)
{
  intel_dsa_main_t *idm = &intel_dsa_main;
  intel_dsa_config_t *idc;
  u32 index, n_threads = vlib_get_n_threads ();

  vec_validate (idm->dsa_config_heap_handle_by_config_index, cd->config_index);
  index = heap_alloc_aligned (
    idm->dsa_config_heap, n_threads, CLIB_CACHE_LINE_BYTES,
    idm->dsa_config_heap_handle_by_config_index[cd->config_index]);

  cd->batch_new_fn = intel_dsa_batch_new;
  cd->private_data = index;

  for (u32 thread = 0; thread < n_threads; thread++)
    {
      intel_dsa_batch_t *idb;
      vlib_dma_batch_t *b;
      idc = vec_elt_at_index (idm->dsa_config_heap, index + thread);

      /* size of physmem allocation for this config */
      idc->max_transfers = cd->cfg.max_transfers;
      idc->alloc_size = sizeof (intel_dsa_batch_t) +
			sizeof (intel_dsa_desc_t) * (idc->max_transfers + 1);
      /* fill batch template */
      idb = &idc->batch_template;
      idb->ch = idm->dsa_threads[thread].ch;
      if (intel_dsa_check_channel (idb->ch, cd))
	return 0;

      dsa_log_debug ("config %d in thread %d using channel %u/%u",
		     cd->config_index, thread, idb->ch->did, idb->ch->qid);
      idb->config_heap_index = index + thread;
      idb->config_index = cd->config_index;
      idb->batch.callback_fn = cd->cfg.callback_fn;
      idb->features = cd->cfg.features;
      b = &idb->batch;
      b->stride = sizeof (intel_dsa_desc_t);
      b->src_ptr_off = STRUCT_OFFSET_OF (intel_dsa_batch_t, descs[0].src);
      b->dst_ptr_off = STRUCT_OFFSET_OF (intel_dsa_batch_t, descs[0].dst);
      b->size_off = STRUCT_OFFSET_OF (intel_dsa_batch_t, descs[0].size);
      b->submit_fn = intel_dsa_batch_submit;
      dsa_log_debug (
	"config %d in thread %d stride %d src/dst/size offset %d-%d-%d",
	cd->config_index, thread, b->stride, b->src_ptr_off, b->dst_ptr_off,
	b->size_off);

      /* allocate dma batch in advance */
      for (u32 index = 0; index < cd->cfg.max_inflight; index++)
	intel_dsa_alloc_dma_batch (vm, idc);
    }

  dsa_log_info ("config %u added", cd->private_data);

  return 1;
}

static void
intel_dsa_config_del_fn (vlib_main_t *vm, vlib_dma_config_data_t *cd)
{
  intel_dsa_main_t *idm = &intel_dsa_main;
  intel_dsa_thread_t *t =
    vec_elt_at_index (idm->dsa_threads, vm->thread_index);
  u32 n_pending, n_threads, config_heap_index, n = 0;
  n_threads = vlib_get_n_threads ();

  if (!t->pending_batches)
    goto free_heap;

  n_pending = vec_len (t->pending_batches);
  intel_dsa_batch_t *b;

  /* clean pending list and free list */
  for (u32 i = 0; i < n_pending; i++)
    {
      b = t->pending_batches[i];
      if (b->config_index == cd->config_index)
	{
	  vec_add1 (idm->dsa_config_heap[b->config_heap_index].freelist, b);
	  if (b->status == INTEL_DSA_STATUS_SUCCESS ||
	      b->status == INTEL_DSA_STATUS_BUSY)
	    b->ch->n_enq--;
	}
      else
	t->pending_batches[n++] = b;
    }

  vec_set_len (t->pending_batches, n);

free_heap:
  for (u32 thread = 0; thread < n_threads; thread++)
    {
      config_heap_index = cd->private_data + thread;
      while (vec_len (idm->dsa_config_heap[config_heap_index].freelist) > 0)
	{
	  b = vec_pop (idm->dsa_config_heap[config_heap_index].freelist);
	  vlib_physmem_free (vm, b);
	}
    }

  heap_dealloc (idm->dsa_config_heap,
		idm->dsa_config_heap_handle_by_config_index[cd->config_index]);

  dsa_log_debug ("config %u removed", cd->private_data);
}

static uword
intel_dsa_node_fn (vlib_main_t *vm, vlib_node_runtime_t *node,
		   vlib_frame_t *frame)
{
  intel_dsa_main_t *idm = &intel_dsa_main;
  intel_dsa_thread_t *t =
    vec_elt_at_index (idm->dsa_threads, vm->thread_index);
  u32 n_pending = 0, n = 0;
  u8 glitch = 0;

  if (!t->pending_batches)
    return 0;

  n_pending = vec_len (t->pending_batches);

  for (u32 i = 0; i < n_pending; i++)
    {
      intel_dsa_batch_t *b = t->pending_batches[i];
      intel_dsa_channel_t *ch = b->ch;

      if ((b->status == INTEL_DSA_STATUS_SUCCESS ||
	   b->status == INTEL_DSA_STATUS_CPU_SUCCESS) &&
	  !glitch)
	{
	  /* callback */
	  if (b->batch.callback_fn)
	    b->batch.callback_fn (vm, &b->batch);

	  /* restore last descriptor fields */
	  if (b->batch.n_enq == 1)
	    {
	      b->descs[0].completion = 0;
	      b->descs[0].op_flags =
		(INTEL_DSA_OP_MEMMOVE << INTEL_DSA_OP_SHIFT) |
		INTEL_DSA_FLAG_CACHE_CONTROL;
	      if (b->ch->block_on_fault)
		b->descs[0].op_flags |= INTEL_DSA_FLAG_BLOCK_ON_FAULT;
	    }
	  /* add to freelist */
	  vec_add1 (idm->dsa_config_heap[b->config_heap_index].freelist, b);

	  intel_dsa_channel_lock (ch);
	  if (b->status == INTEL_DSA_STATUS_SUCCESS)
	    {
	      ch->n_enq--;
	      ch->completed++;
	    }
	  else
	    ch->sw_fallback++;
	  intel_dsa_channel_unlock (ch);

	  b->batch.n_enq = 0;
	  b->status = INTEL_DSA_STATUS_IDLE;
	}
      else if (b->status == INTEL_DSA_STATUS_BUSY)
	{
	  glitch = 1 & b->barrier_before_last;
	  t->pending_batches[n++] = b;
	}
      else if (!glitch)
	{
	  /* fallback to software if exception happened */
	  intel_dsa_batch_fallback (vm, b, ch);
	  glitch = 1 & b->barrier_before_last;
	}
      else
	{
	  t->pending_batches[n++] = b;
	}
    }
  vec_set_len (t->pending_batches, n);

  if (n)
    {
      vlib_node_set_interrupt_pending (vm, intel_dsa_node.index);
    }

  return n_pending - n;
}

u8 *
format_dsa_info (u8 *s, va_list *args)
{
  intel_dsa_main_t *idm = &intel_dsa_main;
  vlib_main_t *vm = va_arg (*args, vlib_main_t *);
  intel_dsa_channel_t *ch;
  ch = idm->dsa_threads[vm->thread_index].ch;
  s = format (s, "thread %d dma %u/%u request %-16lld hw %-16lld cpu %-16lld",
	      vm->thread_index, ch->did, ch->qid, ch->submitted, ch->completed,
	      ch->sw_fallback);
  return s;
}

VLIB_REGISTER_NODE (intel_dsa_node) = {
  .function = intel_dsa_node_fn,
  .name = "intel-dsa",
  .type = VLIB_NODE_TYPE_INPUT,
  .state = VLIB_NODE_STATE_INTERRUPT,
  .vector_size = 4,
};

vlib_dma_backend_t intel_dsa_backend = {
  .name = "Intel DSA",
  .config_add_fn = intel_dsa_config_add_fn,
  .config_del_fn = intel_dsa_config_del_fn,
  .info_fn = format_dsa_info,
};
