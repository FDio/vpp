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

#define foreach_memif_tx_func_error	       \
_(NO_FREE_SLOTS, "no free tx slots")           \
_(ROLLBACK, "no enough space in tx buffers")

typedef enum
{
#define _(f,s) MEMIF_TX_ERROR_##f,
  foreach_memif_tx_func_error
#undef _
    MEMIF_TX_N_ERROR,
} memif_tx_func_error_t;

static __clib_unused char *memif_tx_func_error_strings[] = {
#define _(n,s) s,
  foreach_memif_tx_func_error
#undef _
};

#ifndef CLIB_MULTIARCH_VARIANT
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

static __clib_unused u8 *
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

static __clib_unused u8 *
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
memif_interface_tx_inline (vlib_main_t * vm, vlib_node_runtime_t * node,
			   vlib_frame_t * frame, memif_if_t * mif,
			   memif_ring_type_t type)
{
  u8 qid;
  memif_ring_t *ring;
  u32 *buffers = vlib_frame_args (frame);
  u32 n_left = frame->n_vectors;
  u16 ring_size, mask, slot, free_slots;
  u32 thread_index = vlib_get_thread_index ();
  memif_per_thread_data_t *ptd = vec_elt_at_index (memif_main.per_thread_data,
						   thread_index);
  u8 tx_queues = vec_len (mif->tx_queues);
  memif_queue_t *mq;
  int n_retries = 5;
  vlib_buffer_t *b0, *b1, *b2, *b3;
  memif_copy_op_t *co;

  if (tx_queues < vec_len (vlib_mains))
    {
      ASSERT (tx_queues > 0);
      qid = thread_index % tx_queues;
      clib_spinlock_lock_if_init (&mif->lockp);
    }
  else
    qid = thread_index;

  mq = vec_elt_at_index (mif->tx_queues, qid);
  ring = mq->ring;
  ring_size = 1 << mq->log2_ring_size;
  mask = ring_size - 1;

retry:

  free_slots = ring->tail - mq->last_tail;
  mq->last_tail += free_slots;
  slot = (type == MEMIF_RING_S2M) ? ring->head : ring->tail;

  if (type == MEMIF_RING_S2M)
    free_slots = ring_size - ring->head + mq->last_tail;
  else
    free_slots = ring->head - ring->tail;

  while (n_left && free_slots)
    {
      memif_desc_t *d0;
      void *mb0;
      i32 src_off;
      u32 bi0, dst_off, src_left, dst_left, bytes_to_copy;
      u32 saved_ptd_copy_ops_len = _vec_len (ptd->copy_ops);
      u32 saved_ptd_buffers_len = _vec_len (ptd->buffers);
      u16 saved_slot = slot;

      CLIB_PREFETCH (&ring->desc[(slot + 2) & mask], CLIB_CACHE_LINE_BYTES,
		     LOAD);

      d0 = &ring->desc[slot & mask];
      mb0 = mif->regions[d0->region].shm + d0->offset;

      dst_off = 0;
      dst_left = d0->buffer_length;
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
		  slot++;
		  free_slots--;
		  d0->length = d0->buffer_length;
		  d0->flags = MEMIF_DESC_FLAG_NEXT;
		  d0 = &ring->desc[slot & mask];
		  dst_off = 0;
		  dst_left = d0->buffer_length;
		  mb0 = mif->regions[d0->region].shm + d0->offset;
		}
	      else
		{
		  /* we need to rollback vectors before bailing out */
		  _vec_len (ptd->buffers) = saved_ptd_buffers_len;
		  _vec_len (ptd->copy_ops) = saved_ptd_copy_ops_len;
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
  n_left = vec_len (ptd->copy_ops);
  co = ptd->copy_ops;
  while (n_left >= 8)
    {
      CLIB_PREFETCH (co[4].data, CLIB_CACHE_LINE_BYTES, LOAD);
      CLIB_PREFETCH (co[5].data, CLIB_CACHE_LINE_BYTES, LOAD);
      CLIB_PREFETCH (co[6].data, CLIB_CACHE_LINE_BYTES, LOAD);
      CLIB_PREFETCH (co[7].data, CLIB_CACHE_LINE_BYTES, LOAD);

      b0 = vlib_get_buffer (vm, ptd->buffers[co[0].buffer_vec_index]);
      b1 = vlib_get_buffer (vm, ptd->buffers[co[1].buffer_vec_index]);
      b2 = vlib_get_buffer (vm, ptd->buffers[co[2].buffer_vec_index]);
      b3 = vlib_get_buffer (vm, ptd->buffers[co[3].buffer_vec_index]);

      clib_memcpy (co[0].data, b0->data + co[0].buffer_offset,
		   co[0].data_len);
      clib_memcpy (co[1].data, b1->data + co[1].buffer_offset,
		   co[1].data_len);
      clib_memcpy (co[2].data, b2->data + co[2].buffer_offset,
		   co[2].data_len);
      clib_memcpy (co[3].data, b3->data + co[3].buffer_offset,
		   co[3].data_len);

      co += 4;
      n_left -= 4;
    }
  while (n_left)
    {
      b0 = vlib_get_buffer (vm, ptd->buffers[co[0].buffer_vec_index]);
      clib_memcpy (co[0].data, b0->data + co[0].buffer_offset,
		   co[0].data_len);
      co += 1;
      n_left -= 1;
    }

  vec_reset_length (ptd->copy_ops);
  vec_reset_length (ptd->buffers);

  CLIB_MEMORY_STORE_BARRIER ();
  if (type == MEMIF_RING_S2M)
    ring->head = slot;
  else
    ring->tail = slot;


  if (n_left && n_retries--)
    goto retry;

  clib_spinlock_unlock_if_init (&mif->lockp);

  if (n_left)
    {
      vlib_error_count (vm, node->node_index, MEMIF_TX_ERROR_NO_FREE_SLOTS,
			n_left);
    }

  if ((ring->flags & MEMIF_RING_FLAG_MASK_INT) == 0 && mq->int_fd > -1)
    {
      u64 b = 1;
      CLIB_UNUSED (int r) = write (mq->int_fd, &b, sizeof (b));
      mq->int_count++;
    }

  vlib_buffer_free (vm, vlib_frame_args (frame), frame->n_vectors);

  return frame->n_vectors;
}

uword
CLIB_MULTIARCH_FN (memif_interface_tx) (vlib_main_t * vm,
					vlib_node_runtime_t * node,
					vlib_frame_t * frame)
{
  memif_main_t *nm = &memif_main;
  vnet_interface_output_runtime_t *rund = (void *) node->runtime_data;
  memif_if_t *mif = pool_elt_at_index (nm->interfaces, rund->dev_instance);

  if (mif->flags & MEMIF_IF_FLAG_IS_SLAVE)
    return memif_interface_tx_inline (vm, node, frame, mif, MEMIF_RING_S2M);
  else
    return memif_interface_tx_inline (vm, node, frame, mif, MEMIF_RING_M2S);
}

static __clib_unused void
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

static __clib_unused void
memif_clear_hw_interface_counters (u32 instance)
{
  /* Nothing for now */
}

static __clib_unused clib_error_t *
memif_interface_rx_mode_change (vnet_main_t * vnm, u32 hw_if_index, u32 qid,
				vnet_hw_interface_rx_mode mode)
{
  memif_main_t *mm = &memif_main;
  vnet_hw_interface_t *hw = vnet_get_hw_interface (vnm, hw_if_index);
  memif_if_t *mif = pool_elt_at_index (mm->interfaces, hw->dev_instance);
  memif_queue_t *mq = vec_elt_at_index (mif->rx_queues, qid);

  if (mode == VNET_HW_INTERFACE_RX_MODE_POLLING)
    mq->ring->flags |= MEMIF_RING_FLAG_MASK_INT;
  else
    mq->ring->flags &= ~MEMIF_RING_FLAG_MASK_INT;

  return 0;
}

static __clib_unused clib_error_t *
memif_interface_admin_up_down (vnet_main_t * vnm, u32 hw_if_index, u32 flags)
{
  memif_main_t *mm = &memif_main;
  vnet_hw_interface_t *hw = vnet_get_hw_interface (vnm, hw_if_index);
  memif_if_t *mif = pool_elt_at_index (mm->interfaces, hw->dev_instance);
  static clib_error_t *error = 0;

  if (flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP)
    mif->flags |= MEMIF_IF_FLAG_ADMIN_UP;
  else
    mif->flags &= ~MEMIF_IF_FLAG_ADMIN_UP;

  return error;
}

static __clib_unused clib_error_t *
memif_subif_add_del_function (vnet_main_t * vnm,
			      u32 hw_if_index,
			      struct vnet_sw_interface_t *st, int is_add)
{
  /* Nothing for now */
  return 0;
}

#ifndef CLIB_MULTIARCH_VARIANT
/* *INDENT-OFF* */
VNET_DEVICE_CLASS (memif_device_class) = {
  .name = "memif",
  .tx_function = memif_interface_tx,
  .format_device_name = format_memif_device_name,
  .format_device = format_memif_device,
  .format_tx_trace = format_memif_tx_trace,
  .tx_function_n_errors = MEMIF_TX_N_ERROR,
  .tx_function_error_strings = memif_tx_func_error_strings,
  .rx_redirect_to_node = memif_set_interface_next_node,
  .clear_counters = memif_clear_hw_interface_counters,
  .admin_up_down_function = memif_interface_admin_up_down,
  .subif_add_del_function = memif_subif_add_del_function,
  .rx_mode_change_function = memif_interface_rx_mode_change,
};

#if __x86_64__
vlib_node_function_t __clib_weak memif_interface_tx_avx512;
vlib_node_function_t __clib_weak memif_interface_tx_avx2;
static void __clib_constructor
dpdk_interface_tx_multiarch_select (void)
{
  if (memif_interface_tx_avx512 && clib_cpu_supports_avx512f ())
    memif_device_class.tx_function = memif_interface_tx_avx512;
  else if (memif_interface_tx_avx2 && clib_cpu_supports_avx2 ())
    memif_device_class.tx_function = memif_interface_tx_avx2;
}
#endif
#endif

/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
