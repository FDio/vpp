/*
 *------------------------------------------------------------------
 * Copyright (c) 2016 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *------------------------------------------------------------------
 */

#define _GNU_SOURCE
#include <stdint.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/uio.h>

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vnet/ethernet/ethernet.h>

#include <memif/memif.h>
#include <memif/private.h>

#define foreach_memif_tx_func_error                                           \
  _ (NO_FREE_SLOTS, no_free_slots, ERROR, "no free tx slots")                 \
  _ (ROLLBACK, rollback, ERROR, "no enough space in tx buffers")

typedef enum
{
#define _(f, n, s, d) MEMIF_TX_ERROR_##f,
  foreach_memif_tx_func_error
#undef _
    MEMIF_TX_N_ERROR,
} memif_tx_func_error_t;

static vlib_error_desc_t memif_tx_func_error_counters[] = {
#define _(f, n, s, d) { #n, d, VL_COUNTER_SEVERITY_##s },
  foreach_memif_tx_func_error
#undef _
};

#ifndef CLIB_MARCH_VARIANT
u8 *
format_memif_device_name (u8 * s, va_list * args)
{
  u32 dev_instance = va_arg (*args, u32);
  memif_main_t *mm = &memif_main;
  memif_if_t *mif = pool_elt_at_index (mm->interfaces, dev_instance);
  memif_socket_file_t *msf;

  msf = pool_elt_at_index (mm->socket_files, mif->socket_file_index);
  s = format (s, "memif%lu/%lu", msf->socket_id, mif->id);
  return s;
}
#endif

static u8 *
format_memif_device (u8 * s, va_list * args)
{
  u32 dev_instance = va_arg (*args, u32);
  int verbose = va_arg (*args, int);
  u32 indent = format_get_indent (s);

  s = format (s, "MEMIF interface");
  if (verbose)
    {
      s = format (s, "\n%U instance %u", format_white_space, indent + 2,
		  dev_instance);
    }
  return s;
}

static u8 *
format_memif_tx_trace (u8 * s, va_list * args)
{
  s = format (s, "Unimplemented...");
  return s;
}

static_always_inline void
memif_add_copy_op (memif_per_thread_data_t * ptd, void *data, u32 len,
		   u16 buffer_offset, u16 buffer_vec_index)
{
  memif_copy_op_t *co;
  vec_add2_aligned (ptd->copy_ops, co, 1, CLIB_CACHE_LINE_BYTES);
  co->data = data;
  co->data_len = len;
  co->buffer_offset = buffer_offset;
  co->buffer_vec_index = buffer_vec_index;
}

static_always_inline uword
memif_interface_tx_inline (vlib_main_t *vm, vlib_node_runtime_t *node,
			   u32 *buffers, memif_if_t *mif,
			   memif_ring_type_t type, memif_queue_t *mq,
			   memif_per_thread_data_t *ptd, u32 n_left)
{
  memif_ring_t *ring;
  u32 n_copy_op;
  u16 ring_size, mask, slot, free_slots;
  int n_retries = 5;
  vlib_buffer_t *b0, *b1, *b2, *b3;
  memif_copy_op_t *co;
  memif_region_index_t last_region = ~0;
  void *last_region_shm = 0;
  u16 head, tail;

  ring = mq->ring;
  ring_size = 1 << mq->log2_ring_size;
  mask = ring_size - 1;

retry:

  if (type == MEMIF_RING_S2M)
    {
      slot = head = ring->head;
      tail = __atomic_load_n (&ring->tail, __ATOMIC_ACQUIRE);
      mq->last_tail += tail - mq->last_tail;
      free_slots = ring_size - head + mq->last_tail;
    }
  else
    {
      slot = tail = ring->tail;
      head = __atomic_load_n (&ring->head, __ATOMIC_ACQUIRE);
      mq->last_tail += tail - mq->last_tail;
      free_slots = head - tail;
    }

  while (n_left && free_slots)
    {
      memif_desc_t *d0;
      void *mb0;
      i32 src_off;
      u32 bi0, dst_off, src_left, dst_left, bytes_to_copy;
      u32 saved_ptd_copy_ops_len = _vec_len (ptd->copy_ops);
      u32 saved_ptd_buffers_len = _vec_len (ptd->buffers);
      u16 saved_slot = slot;

      clib_prefetch_load (&ring->desc[(slot + 8) & mask]);

      d0 = &ring->desc[slot & mask];
      if (PREDICT_FALSE (last_region != d0->region))
	{
	  last_region_shm = mif->regions[d0->region].shm;
	  last_region = d0->region;
	}
      mb0 = last_region_shm + d0->offset;

      dst_off = 0;

      /* slave is the producer, so it should be able to reset buffer length */
      dst_left = (type == MEMIF_RING_S2M) ? mif->run.buffer_size : d0->length;

      if (PREDICT_TRUE (n_left >= 4))
	vlib_prefetch_buffer_header (vlib_get_buffer (vm, buffers[3]), LOAD);
      bi0 = buffers[0];

    next_in_chain:

      b0 = vlib_get_buffer (vm, bi0);
      src_off = b0->current_data;
      src_left = b0->current_length;

      while (src_left)
	{
	  if (PREDICT_FALSE (dst_left == 0))
	    {
	      if (free_slots)
		{
		  d0->length = dst_off;
		  d0->flags = MEMIF_DESC_FLAG_NEXT;
		  d0 = &ring->desc[slot & mask];
		  dst_off = 0;
		  dst_left =
		    (type ==
		     MEMIF_RING_S2M) ? mif->run.buffer_size : d0->length;

		  if (PREDICT_FALSE (last_region != d0->region))
		    {
		      last_region_shm = mif->regions[d0->region].shm;
		      last_region = d0->region;
		    }
		  mb0 = last_region_shm + d0->offset;
		}
	      else
		{
		  /* we need to rollback vectors before bailing out */
		  vec_set_len (ptd->buffers, saved_ptd_buffers_len);
		  vec_set_len (ptd->copy_ops, saved_ptd_copy_ops_len);
		  vlib_error_count (vm, node->node_index,
				    MEMIF_TX_ERROR_ROLLBACK, 1);
		  slot = saved_slot;
		  goto no_free_slots;
		}
	    }
	  bytes_to_copy = clib_min (src_left, dst_left);
	  memif_add_copy_op (ptd, mb0 + dst_off, bytes_to_copy, src_off,
			     vec_len (ptd->buffers));
	  vec_add1_aligned (ptd->buffers, bi0, CLIB_CACHE_LINE_BYTES);
	  src_off += bytes_to_copy;
	  dst_off += bytes_to_copy;
	  src_left -= bytes_to_copy;
	  dst_left -= bytes_to_copy;
	}

      if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_NEXT_PRESENT))
	{
	  bi0 = b0->next_buffer;
	  slot++;
	  free_slots--;
	  goto next_in_chain;
	}

      d0->length = dst_off;
      d0->flags = 0;

      free_slots -= 1;
      slot += 1;

      buffers++;
      n_left--;
    }
no_free_slots:

  /* copy data */
  n_copy_op = vec_len (ptd->copy_ops);
  co = ptd->copy_ops;
  while (n_copy_op >= 8)
    {
      clib_prefetch_load (co[4].data);
      clib_prefetch_load (co[5].data);
      clib_prefetch_load (co[6].data);
      clib_prefetch_load (co[7].data);

      b0 = vlib_get_buffer (vm, ptd->buffers[co[0].buffer_vec_index]);
      b1 = vlib_get_buffer (vm, ptd->buffers[co[1].buffer_vec_index]);
      b2 = vlib_get_buffer (vm, ptd->buffers[co[2].buffer_vec_index]);
      b3 = vlib_get_buffer (vm, ptd->buffers[co[3].buffer_vec_index]);

      clib_memcpy_fast (co[0].data, b0->data + co[0].buffer_offset,
			co[0].data_len);
      clib_memcpy_fast (co[1].data, b1->data + co[1].buffer_offset,
			co[1].data_len);
      clib_memcpy_fast (co[2].data, b2->data + co[2].buffer_offset,
			co[2].data_len);
      clib_memcpy_fast (co[3].data, b3->data + co[3].buffer_offset,
			co[3].data_len);

      co += 4;
      n_copy_op -= 4;
    }
  while (n_copy_op)
    {
      b0 = vlib_get_buffer (vm, ptd->buffers[co[0].buffer_vec_index]);
      clib_memcpy_fast (co[0].data, b0->data + co[0].buffer_offset,
			co[0].data_len);
      co += 1;
      n_copy_op -= 1;
    }

  vec_reset_length (ptd->copy_ops);
  vec_reset_length (ptd->buffers);

  if (type == MEMIF_RING_S2M)
    __atomic_store_n (&ring->head, slot, __ATOMIC_RELEASE);
  else
    __atomic_store_n (&ring->tail, slot, __ATOMIC_RELEASE);

  if (n_left && n_retries--)
    goto retry;

  return n_left;
}

static_always_inline uword
memif_interface_tx_zc_inline (vlib_main_t *vm, vlib_node_runtime_t *node,
			      u32 *buffers, memif_if_t *mif, memif_queue_t *mq,
			      memif_per_thread_data_t *ptd, u32 n_left)
{
  memif_ring_t *ring = mq->ring;
  u16 slot, free_slots, n_free;
  u16 ring_size = 1 << mq->log2_ring_size;
  u16 mask = ring_size - 1;
  int n_retries = 5;
  vlib_buffer_t *b0;
  u16 head, tail;

retry:
  tail = __atomic_load_n (&ring->tail, __ATOMIC_ACQUIRE);
  slot = head = ring->head;

  n_free = tail - mq->last_tail;
  if (n_free >= 16)
    {
      vlib_buffer_free_from_ring_no_next (vm, mq->buffers,
					  mq->last_tail & mask,
					  ring_size, n_free);
      mq->last_tail += n_free;
    }

  free_slots = ring_size - head + mq->last_tail;

  while (n_left && free_slots)
    {
      u16 s0;
      u16 slots_in_packet = 1;
      memif_desc_t *d0;
      u32 bi0;

      clib_prefetch_store (&ring->desc[(slot + 8) & mask]);

      if (PREDICT_TRUE (n_left >= 4))
	vlib_prefetch_buffer_header (vlib_get_buffer (vm, buffers[3]), LOAD);

      bi0 = buffers[0];

    next_in_chain:
      s0 = slot & mask;
      d0 = &ring->desc[s0];
      mq->buffers[s0] = bi0;
      b0 = vlib_get_buffer (vm, bi0);

      d0->region = b0->buffer_pool_index + 1;
      d0->offset = (void *) b0->data + b0->current_data -
	mif->regions[d0->region].shm;
      d0->length = b0->current_length;

      free_slots--;
      slot++;

      if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_NEXT_PRESENT))
	{
	  if (PREDICT_FALSE (free_slots == 0))
	    {
	      /* revert to last fully processed packet */
	      free_slots += slots_in_packet;
	      slot -= slots_in_packet;
	      goto no_free_slots;
	    }

	  d0->flags = MEMIF_DESC_FLAG_NEXT;
	  bi0 = b0->next_buffer;

	  /* next */
	  slots_in_packet++;
	  goto next_in_chain;
	}

      d0->flags = 0;

      /* next from */
      buffers++;
      n_left--;
    }
no_free_slots:

  __atomic_store_n (&ring->head, slot, __ATOMIC_RELEASE);

  if (n_left && n_retries--)
    goto retry;

  return n_left;
}

CLIB_MARCH_FN (memif_tx_dma_completion_cb, void, vlib_main_t *vm,
	       vlib_dma_batch_t *b)
{
  memif_main_t *mm = &memif_main;
  memif_if_t *mif = vec_elt_at_index (mm->interfaces, b->cookie >> 16);
  memif_queue_t *mq = vec_elt_at_index (mif->tx_queues, b->cookie & 0xffff);
  memif_dma_data_t *dma_data = mq->dma_data + mq->dma_data_head;
  memif_per_thread_data_t *ptd = &dma_data->data;

  vlib_buffer_free (vm, ptd->buffers, vec_len (ptd->buffers));
  dma_data->state = DMA_DATA_STATE_COMPLETED;
  vec_reset_length (ptd->buffers);
  vec_reset_length (ptd->copy_ops);

  __atomic_store_n (&mq->ring->tail, dma_data->dma_tail, __ATOMIC_RELEASE);

  mq->dma_data_head++;
  if (mq->dma_data_head == mq->dma_data_size)
    mq->dma_data_head = 0;
  mq->dma_data_full = 0;
}

#ifndef CLIB_MARCH_VARIANT
void
memif_tx_dma_completion_cb (vlib_main_t *vm, vlib_dma_batch_t *b)
{
  return CLIB_MARCH_FN_SELECT (memif_tx_dma_completion_cb) (vm, b);
}
#endif

static_always_inline uword
memif_interface_tx_dma_inline (vlib_main_t *vm, vlib_node_runtime_t *node,
			       u32 *buffers, memif_if_t *mif,
			       memif_ring_type_t type, memif_queue_t *mq,
			       u32 n_left)
{
  memif_ring_t *ring;
  u32 n_copy_op;
  u16 ring_size, mask, slot, free_slots;
  int n_retries = 5, fallback = 0;
  vlib_buffer_t *b0, *b1, *b2, *b3;
  memif_copy_op_t *co;
  memif_region_index_t last_region = ~0;
  void *last_region_shm = 0;
  u16 head, tail;
  memif_dma_data_t *dma_data;
  memif_per_thread_data_t *ptd;

  ring = mq->ring;
  ring_size = 1 << mq->log2_ring_size;
  mask = ring_size - 1;

  dma_data = mq->dma_data + mq->dma_data_tail;
  ptd = &dma_data->data;

  /* do software fallback if dma ring is full */
  u16 dma_mask = mq->dma_data_size - 1;
  if ((((mq->dma_data_tail + 1) & dma_mask) == mq->dma_data_head) ||
      ((mq->dma_data_head == dma_mask) && (mq->dma_data_tail == 0)))
    {
      if (!mq->dma_data_full)
	mq->dma_data_full = 1;
      else
	fallback = 1;
    }

  vlib_dma_batch_t *b = NULL;
  if (PREDICT_TRUE (!fallback))
    b = vlib_dma_batch_new (vm, mif->dma_tx_config);

retry:

  slot = tail = mq->dma_tail;
  head = __atomic_load_n (&ring->head, __ATOMIC_ACQUIRE);
  mq->last_tail += tail - mq->last_tail;
  free_slots = head - mq->dma_tail;

  while (n_left && free_slots)
    {
      memif_desc_t *d0;
      void *mb0;
      i32 src_off;
      u32 bi0, dst_off, src_left, dst_left, bytes_to_copy;
      u32 saved_ptd_copy_ops_len = _vec_len (ptd->copy_ops);
      u32 saved_ptd_buffers_len = _vec_len (ptd->buffers);
      u16 saved_slot = slot;

      clib_prefetch_load (&ring->desc[(slot + 8) & mask]);

      d0 = &ring->desc[slot & mask];
      if (PREDICT_FALSE (last_region != d0->region))
	{
	  last_region_shm = mif->regions[d0->region].shm;
	  last_region = d0->region;
	}
      mb0 = last_region_shm + d0->offset;

      dst_off = 0;

      /* slave is the producer, so it should be able to reset buffer length */
      dst_left = d0->length;

      if (PREDICT_TRUE (n_left >= 4))
	vlib_prefetch_buffer_header (vlib_get_buffer (vm, buffers[3]), LOAD);
      bi0 = buffers[0];

    next_in_chain:

      b0 = vlib_get_buffer (vm, bi0);
      src_off = b0->current_data;
      src_left = b0->current_length;

      while (src_left)
	{
	  if (PREDICT_FALSE (dst_left == 0))
	    {
	      if (free_slots)
		{
		  d0->length = dst_off;
		  d0->flags = MEMIF_DESC_FLAG_NEXT;
		  d0 = &ring->desc[slot & mask];
		  dst_off = 0;
		  dst_left = (type == MEMIF_RING_S2M) ? mif->run.buffer_size :
							      d0->length;

		  if (PREDICT_FALSE (last_region != d0->region))
		    {
		      last_region_shm = mif->regions[d0->region].shm;
		      last_region = d0->region;
		    }
		  mb0 = last_region_shm + d0->offset;
		}
	      else
		{
		  /* we need to rollback vectors before bailing out */
		  vec_set_len (ptd->buffers, saved_ptd_buffers_len);
		  vec_set_len (ptd->copy_ops, saved_ptd_copy_ops_len);
		  vlib_error_count (vm, node->node_index,
				    MEMIF_TX_ERROR_ROLLBACK, 1);
		  slot = saved_slot;
		  goto no_free_slots;
		}
	    }
	  bytes_to_copy = clib_min (src_left, dst_left);
	  memif_add_copy_op (ptd, mb0 + dst_off, bytes_to_copy, src_off,
			     vec_len (ptd->buffers));
	  src_off += bytes_to_copy;
	  dst_off += bytes_to_copy;
	  src_left -= bytes_to_copy;
	  dst_left -= bytes_to_copy;
	}

      if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_NEXT_PRESENT))
	{
	  slot++;
	  free_slots--;
	  bi0 = b0->next_buffer;
	  goto next_in_chain;
	}

      vec_add1_aligned (ptd->buffers, buffers[0], CLIB_CACHE_LINE_BYTES);
      d0->length = dst_off;
      d0->flags = 0;

      free_slots -= 1;
      slot += 1;

      buffers++;
      n_left--;
    }
no_free_slots:

  /* copy data */
  n_copy_op = vec_len (ptd->copy_ops);
  co = ptd->copy_ops;
  while (n_copy_op >= 8)
    {
      clib_prefetch_load (co[4].data);
      clib_prefetch_load (co[5].data);
      clib_prefetch_load (co[6].data);
      clib_prefetch_load (co[7].data);

      b0 = vlib_get_buffer (vm, ptd->buffers[co[0].buffer_vec_index]);
      b1 = vlib_get_buffer (vm, ptd->buffers[co[1].buffer_vec_index]);
      b2 = vlib_get_buffer (vm, ptd->buffers[co[2].buffer_vec_index]);
      b3 = vlib_get_buffer (vm, ptd->buffers[co[3].buffer_vec_index]);

      if (PREDICT_TRUE (!fallback))
	{
	  vlib_dma_batch_add (vm, b, co[0].data,
			      b0->data + co[0].buffer_offset, co[0].data_len);
	  vlib_dma_batch_add (vm, b, co[1].data,
			      b1->data + co[1].buffer_offset, co[1].data_len);
	  vlib_dma_batch_add (vm, b, co[2].data,
			      b2->data + co[2].buffer_offset, co[2].data_len);
	  vlib_dma_batch_add (vm, b, co[3].data,
			      b3->data + co[3].buffer_offset, co[3].data_len);
	}
      else
	{
	  clib_memcpy_fast (co[0].data, b0->data + co[0].buffer_offset,
			    co[0].data_len);
	  clib_memcpy_fast (co[1].data, b1->data + co[1].buffer_offset,
			    co[1].data_len);
	  clib_memcpy_fast (co[2].data, b2->data + co[2].buffer_offset,
			    co[2].data_len);
	  clib_memcpy_fast (co[3].data, b3->data + co[3].buffer_offset,
			    co[3].data_len);
	}

      co += 4;
      n_copy_op -= 4;
    }
  while (n_copy_op)
    {
      b0 = vlib_get_buffer (vm, ptd->buffers[co[0].buffer_vec_index]);
      if (PREDICT_TRUE (!fallback))
	vlib_dma_batch_add (vm, b, co[0].data, b0->data + co[0].buffer_offset,
			    co[0].data_len);
      else
	clib_memcpy_fast (co[0].data, b0->data + co[0].buffer_offset,
			  co[0].data_len);
      co += 1;
      n_copy_op -= 1;
    }

  dma_data->dma_tail = slot;
  mq->dma_tail = slot;
  vec_reset_length (ptd->copy_ops);

  if (n_left && n_retries--)
    goto retry;

  if (PREDICT_TRUE (!fallback))
    {
      vlib_dma_batch_set_cookie (vm, b,
				 (mif->id << 16) | (mq - mif->tx_queues));
      vlib_dma_batch_submit (vm, b);
      dma_data->state = DMA_DATA_STATE_SUBMITTED;

      /* use current dma info if no callback from dma node */
      if (b->n_enq)
	{
	  mq->dma_data_tail++;
	  if (mq->dma_data_tail == mq->dma_data_size)
	    mq->dma_data_tail = 0;
	}
    }
  else if (fallback && dma_data->state == DMA_DATA_STATE_COMPLETED)
    {
      /* when dma has been completed, update ring state immediately */
      vlib_buffer_free (vm, ptd->buffers, vec_len (ptd->buffers));
      vec_reset_length (ptd->buffers);
      __atomic_store_n (&mq->ring->tail, slot, __ATOMIC_RELEASE);
    }

  return n_left;
}

VNET_DEVICE_CLASS_TX_FN (memif_device_class) (vlib_main_t * vm,
					      vlib_node_runtime_t * node,
					      vlib_frame_t * frame)
{
  memif_main_t *nm = &memif_main;
  vnet_interface_output_runtime_t *rund = (void *) node->runtime_data;
  memif_if_t *mif = pool_elt_at_index (nm->interfaces, rund->dev_instance);
  vnet_hw_if_tx_frame_t *tf = vlib_frame_scalar_args (frame);
  memif_queue_t *mq;
  u32 qid = tf->queue_id;
  u32 *from, thread_index = vm->thread_index;
  memif_per_thread_data_t *ptd = vec_elt_at_index (memif_main.per_thread_data,
						   thread_index);
  uword n_left;

  ASSERT (vec_len (mif->tx_queues) > qid);
  mq = vec_elt_at_index (mif->tx_queues, qid);

  if (tf->shared_queue)
    clib_spinlock_lock (&mq->lockp);

  from = vlib_frame_vector_args (frame);
  n_left = frame->n_vectors;
  if (mif->flags & MEMIF_IF_FLAG_ZERO_COPY)
    n_left =
      memif_interface_tx_zc_inline (vm, node, from, mif, mq, ptd, n_left);
  else if (mif->flags & MEMIF_IF_FLAG_IS_SLAVE)
    n_left = memif_interface_tx_inline (vm, node, from, mif, MEMIF_RING_S2M,
					mq, ptd, n_left);
  else
    {
      if ((mif->flags & MEMIF_IF_FLAG_USE_DMA) && (mif->dma_tx_config >= 0))
	n_left = memif_interface_tx_dma_inline (vm, node, from, mif,
						MEMIF_RING_M2S, mq, n_left);
      else
	n_left = memif_interface_tx_inline (vm, node, from, mif,
					    MEMIF_RING_M2S, mq, ptd, n_left);
    }

  if (tf->shared_queue)
    clib_spinlock_unlock (&mq->lockp);

  if (n_left)
    {
      vlib_error_count (vm, node->node_index, MEMIF_TX_ERROR_NO_FREE_SLOTS,
			n_left);
    }

  if ((mq->ring->flags & MEMIF_RING_FLAG_MASK_INT) == 0 && mq->int_fd > -1)
    {
      u64 b = 1;
      int __clib_unused r = write (mq->int_fd, &b, sizeof (b));
      mq->int_count++;
    }

  if ((mif->flags & MEMIF_IF_FLAG_USE_DMA) && (mif->dma_tx_config >= 0))
    {
      if (n_left)
	vlib_buffer_free (vm, from + frame->n_vectors - n_left, n_left);
    }
  else if ((mif->flags & MEMIF_IF_FLAG_ZERO_COPY) == 0)
    vlib_buffer_free (vm, from, frame->n_vectors);
  else if (n_left)
    vlib_buffer_free (vm, from + frame->n_vectors - n_left, n_left);

  return frame->n_vectors - n_left;
}

static void
memif_set_interface_next_node (vnet_main_t * vnm, u32 hw_if_index,
			       u32 node_index)
{
  memif_main_t *apm = &memif_main;
  vnet_hw_interface_t *hw = vnet_get_hw_interface (vnm, hw_if_index);
  memif_if_t *mif = pool_elt_at_index (apm->interfaces, hw->dev_instance);

  /* Shut off redirection */
  if (node_index == ~0)
    {
      mif->per_interface_next_index = node_index;
      return;
    }

  mif->per_interface_next_index =
    vlib_node_add_next (vlib_get_main (), memif_input_node.index, node_index);
}

static void
memif_clear_hw_interface_counters (u32 instance)
{
  /* Nothing for now */
}

static clib_error_t *
memif_interface_rx_mode_change (vnet_main_t * vnm, u32 hw_if_index, u32 qid,
				vnet_hw_if_rx_mode mode)
{
  memif_main_t *mm = &memif_main;
  vnet_hw_interface_t *hw = vnet_get_hw_interface (vnm, hw_if_index);
  memif_if_t *mif = pool_elt_at_index (mm->interfaces, hw->dev_instance);
  memif_queue_t *mq = vec_elt_at_index (mif->rx_queues, qid);

  if (mode == VNET_HW_IF_RX_MODE_POLLING)
    mq->ring->flags |= MEMIF_RING_FLAG_MASK_INT;
  else
    mq->ring->flags &= ~MEMIF_RING_FLAG_MASK_INT;

  return 0;
}

static clib_error_t *
memif_subif_add_del_function (vnet_main_t * vnm,
			      u32 hw_if_index,
			      struct vnet_sw_interface_t *st, int is_add)
{
  /* Nothing for now */
  return 0;
}

/* *INDENT-OFF* */
VNET_DEVICE_CLASS (memif_device_class) = {
  .name = "memif",
  .format_device_name = format_memif_device_name,
  .format_device = format_memif_device,
  .format_tx_trace = format_memif_tx_trace,
  .tx_function_n_errors = MEMIF_TX_N_ERROR,
  .tx_function_error_counters = memif_tx_func_error_counters,
  .rx_redirect_to_node = memif_set_interface_next_node,
  .clear_counters = memif_clear_hw_interface_counters,
  .admin_up_down_function = memif_interface_admin_up_down,
  .subif_add_del_function = memif_subif_add_del_function,
  .rx_mode_change_function = memif_interface_rx_mode_change,
};

/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
