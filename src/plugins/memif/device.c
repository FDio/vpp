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
_(TRUNC_PACKET, "packet > buffer size -- truncated in tx ring") \
_(PENDING_MSGS, "pending msgs in tx ring") \
_(NO_TX_QUEUES, "no tx queues")

typedef enum
{
#define _(f,s) MEMIF_TX_ERROR_##f,
  foreach_memif_tx_func_error
#undef _
    MEMIF_TX_N_ERROR,
} memif_tx_func_error_t;

static char *memif_tx_func_error_strings[] = {
#define _(n,s) s,
  foreach_memif_tx_func_error
#undef _
};

u8 *
format_memif_device_name (u8 * s, va_list * args)
{
  u32 dev_instance = va_arg (*args, u32);
  memif_main_t *mm = &memif_main;
  memif_if_t *mif = pool_elt_at_index (mm->interfaces, dev_instance);

  s = format (s, "memif%lu/%lu", mif->socket_file_index, mif->id);
  return s;
}

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
memif_prefetch_buffer_and_data (vlib_main_t * vm, u32 bi)
{
  vlib_buffer_t *b = vlib_get_buffer (vm, bi);
  vlib_prefetch_buffer_header (b, LOAD);
  CLIB_PREFETCH (b->data, CLIB_CACHE_LINE_BYTES, LOAD);
}

/**
 * @brief Copy buffer to tx ring
 *
 * @param * vm (in)
 * @param * node (in)
 * @param * mif (in) pointer to memif interface
 * @param bi (in) vlib buffer index
 * @param * ring (in) pointer to memif ring
 * @param * head (in/out) ring head
 * @param mask (in) ring size - 1
 */
static_always_inline void
memif_copy_buffer_to_tx_ring (vlib_main_t * vm, vlib_node_runtime_t * node,
			      memif_if_t * mif, u32 bi, memif_ring_t * ring,
			      u16 * head, u16 mask)
{
  vlib_buffer_t *b0;
  void *mb0;
  u32 total = 0, len;
  u16 slot = (*head) & mask;

  mb0 = memif_get_buffer (mif, ring, slot);
  ring->desc[slot].flags = 0;
  do
    {
      b0 = vlib_get_buffer (vm, bi);
      len = b0->current_length;
      if (PREDICT_FALSE (ring->desc[slot].buffer_length < (total + len)))
	{
	  if (PREDICT_TRUE (total))
	    {
	      ring->desc[slot].length = total;
	      total = 0;
	      ring->desc[slot].flags |= MEMIF_DESC_FLAG_NEXT;
	      (*head)++;
	      slot = (*head) & mask;
	      mb0 = memif_get_buffer (mif, ring, slot);
	      ring->desc[slot].flags = 0;
	    }
	}
      if (PREDICT_TRUE (ring->desc[slot].buffer_length >= (total + len)))
	{
	  clib_memcpy (mb0 + total, vlib_buffer_get_current (b0),
		       CLIB_CACHE_LINE_BYTES);
	  if (len > CLIB_CACHE_LINE_BYTES)
	    clib_memcpy (mb0 + CLIB_CACHE_LINE_BYTES + total,
			 vlib_buffer_get_current (b0) + CLIB_CACHE_LINE_BYTES,
			 len - CLIB_CACHE_LINE_BYTES);
	  total += len;
	}
      else
	{
	  vlib_error_count (vm, node->node_index, MEMIF_TX_ERROR_TRUNC_PACKET,
			    1);
	  break;
	}
    }
  while ((bi = (b0->flags & VLIB_BUFFER_NEXT_PRESENT) ? b0->next_buffer : 0));

  if (PREDICT_TRUE (total))
    {
      ring->desc[slot].length = total;
      (*head)++;
    }
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
  u16 ring_size, mask;
  u16 head, tail;
  u16 free_slots;
  u32 thread_index = vlib_get_thread_index ();
  u8 tx_queues = vec_len (mif->tx_queues);
  memif_queue_t *mq;

  if (PREDICT_FALSE (tx_queues == 0))
    {
      vlib_error_count (vm, node->node_index, MEMIF_TX_ERROR_NO_TX_QUEUES,
			n_left);
      goto error;
    }

  if (tx_queues < vec_len (vlib_mains))
    {
      qid = thread_index % tx_queues;
      clib_spinlock_lock_if_init (&mif->lockp);
    }
  else
    {
      qid = thread_index;
    }
  mq = vec_elt_at_index (mif->tx_queues, qid);
  ring = mq->ring;
  ring_size = 1 << mq->log2_ring_size;
  mask = ring_size - 1;

  /* free consumed buffers */

  head = ring->head;
  tail = ring->tail;

  free_slots = ring_size - head + tail;

  while (n_left > 5 && free_slots > 1)
    {
      CLIB_PREFETCH (memif_get_buffer (mif, ring, (head + 2) & mask),
		     CLIB_CACHE_LINE_BYTES, STORE);
      CLIB_PREFETCH (memif_get_buffer (mif, ring, (head + 3) & mask),
		     CLIB_CACHE_LINE_BYTES, STORE);
      CLIB_PREFETCH (&ring->desc[(head + 4) & mask], CLIB_CACHE_LINE_BYTES,
		     STORE);
      CLIB_PREFETCH (&ring->desc[(head + 5) & mask], CLIB_CACHE_LINE_BYTES,
		     STORE);
      memif_prefetch_buffer_and_data (vm, buffers[2]);
      memif_prefetch_buffer_and_data (vm, buffers[3]);

      memif_copy_buffer_to_tx_ring (vm, node, mif, buffers[0], ring, &head,
				    mask);
      memif_copy_buffer_to_tx_ring (vm, node, mif, buffers[1], ring, &head,
				    mask);

      buffers += 2;
      n_left -= 2;
      free_slots -= 2;
    }

  while (n_left && free_slots)
    {
      memif_copy_buffer_to_tx_ring (vm, node, mif, buffers[0], ring, &head,
				    mask);
      buffers++;
      n_left--;
      free_slots--;
    }

  CLIB_MEMORY_STORE_BARRIER ();
  ring->head = head;

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

error:
  vlib_buffer_free (vm, vlib_frame_args (frame), frame->n_vectors);

  return frame->n_vectors;
}

static uword
memif_interface_tx (vlib_main_t * vm,
		    vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  memif_main_t *nm = &memif_main;
  vnet_interface_output_runtime_t *rund = (void *) node->runtime_data;
  memif_if_t *mif = pool_elt_at_index (nm->interfaces, rund->dev_instance);

  if (mif->flags & MEMIF_IF_FLAG_IS_SLAVE)
    return memif_interface_tx_inline (vm, node, frame, mif, MEMIF_RING_S2M);
  else
    return memif_interface_tx_inline (vm, node, frame, mif, MEMIF_RING_M2S);
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

static clib_error_t *
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

VLIB_DEVICE_TX_FUNCTION_MULTIARCH(memif_device_class,
				  memif_interface_tx)
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
