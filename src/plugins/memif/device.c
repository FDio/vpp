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

#define foreach_memif_tx_func_error	       \
_(NO_FREE_SLOTS, "no free tx slots")           \
_(PENDING_MSGS, "pending msgs in tx ring")

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


static u8 *
format_memif_device_name (u8 * s, va_list * args)
{
  u32 i = va_arg (*args, u32);

  s = format (s, "memif%u", i);
  return s;
}

static u8 *
format_memif_device (u8 * s, va_list * args)
{
  u32 dev_instance = va_arg (*args, u32);
  int verbose = va_arg (*args, int);
  uword indent = format_get_indent (s);

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

static_always_inline uword
memif_interface_tx_inline (vlib_main_t * vm, vlib_node_runtime_t * node,
			   vlib_frame_t * frame, memif_if_t * mif,
			   memif_ring_type_t type)
{
  u8 rid = 0;
  memif_ring_t *ring = memif_get_ring (mif, type, rid);
  u32 *buffers = vlib_frame_args (frame);
  u32 n_left = frame->n_vectors;
  u16 ring_size = 1 << mif->log2_ring_size;
  u16 mask = ring_size - 1;
  u16 head, tail;
  u16 free_slots;

  clib_spinlock_lock_if_init (&mif->lockp);

  /* free consumed buffers */

  head = ring->head;
  tail = ring->tail;

  if (tail > head)
    free_slots = tail - head;
  else
    free_slots = ring_size - head + tail;

  while (n_left > 5 && free_slots > 1)
    {
      if (PREDICT_TRUE (head + 5 < ring_size))
	{
	  CLIB_PREFETCH (memif_get_buffer (mif, ring, head + 2),
			 CLIB_CACHE_LINE_BYTES, STORE);
	  CLIB_PREFETCH (memif_get_buffer (mif, ring, head + 3),
			 CLIB_CACHE_LINE_BYTES, STORE);
	  CLIB_PREFETCH (&ring->desc[head + 4], CLIB_CACHE_LINE_BYTES, STORE);
	  CLIB_PREFETCH (&ring->desc[head + 5], CLIB_CACHE_LINE_BYTES, STORE);
	}
      else
	{
	  CLIB_PREFETCH (memif_get_buffer (mif, ring, (head + 2) % mask),
			 CLIB_CACHE_LINE_BYTES, STORE);
	  CLIB_PREFETCH (memif_get_buffer (mif, ring, (head + 3) % mask),
			 CLIB_CACHE_LINE_BYTES, STORE);
	  CLIB_PREFETCH (&ring->desc[(head + 4) % mask],
			 CLIB_CACHE_LINE_BYTES, STORE);
	  CLIB_PREFETCH (&ring->desc[(head + 5) % mask],
			 CLIB_CACHE_LINE_BYTES, STORE);
	}

      memif_prefetch_buffer_and_data (vm, buffers[2]);
      memif_prefetch_buffer_and_data (vm, buffers[3]);

      vlib_buffer_t *b0 = vlib_get_buffer (vm, buffers[0]);
      vlib_buffer_t *b1 = vlib_get_buffer (vm, buffers[1]);

      void *mb0 = memif_get_buffer (mif, ring, head);
      clib_memcpy (mb0, vlib_buffer_get_current (b0), CLIB_CACHE_LINE_BYTES);
      ring->desc[head].length = b0->current_length;
      head = (head + 1) & mask;

      void *mb1 = memif_get_buffer (mif, ring, head);
      clib_memcpy (mb1, vlib_buffer_get_current (b1), CLIB_CACHE_LINE_BYTES);
      ring->desc[head].length = b1->current_length;
      head = (head + 1) & mask;

      if (b0->current_length > CLIB_CACHE_LINE_BYTES)
	{
	  clib_memcpy (mb0 + CLIB_CACHE_LINE_BYTES,
		       vlib_buffer_get_current (b0) + CLIB_CACHE_LINE_BYTES,
		       b0->current_length - CLIB_CACHE_LINE_BYTES);
	}
      if (b1->current_length > CLIB_CACHE_LINE_BYTES)
	{
	  clib_memcpy (mb1 + CLIB_CACHE_LINE_BYTES,
		       vlib_buffer_get_current (b1) + CLIB_CACHE_LINE_BYTES,
		       b1->current_length - CLIB_CACHE_LINE_BYTES);
	}


      buffers += 2;
      n_left -= 2;
      free_slots -= 2;
    }

  while (n_left && free_slots)
    {
      vlib_buffer_t *b0 = vlib_get_buffer (vm, buffers[0]);
      void *mb0 = memif_get_buffer (mif, ring, head);
      clib_memcpy (mb0, vlib_buffer_get_current (b0), CLIB_CACHE_LINE_BYTES);

      if (b0->current_length > CLIB_CACHE_LINE_BYTES)
	{
	  clib_memcpy (mb0 + CLIB_CACHE_LINE_BYTES,
		       vlib_buffer_get_current (b0) + CLIB_CACHE_LINE_BYTES,
		       b0->current_length - CLIB_CACHE_LINE_BYTES);
	}
      ring->desc[head].length = b0->current_length;
      head = (head + 1) & mask;

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
      vlib_buffer_free (vm, buffers, n_left);
    }

  vlib_buffer_free (vm, vlib_frame_args (frame), frame->n_vectors);
  if (mif->interrupt_line.fd > 0)
    {
      u8 b = rid;
      CLIB_UNUSED (int r) = write (mif->interrupt_line.fd, &b, sizeof (b));
    }

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
memif_interface_admin_up_down (vnet_main_t * vnm, u32 hw_if_index, u32 flags)
{
  memif_main_t *apm = &memif_main;
  vlib_main_t *vm = vlib_get_main ();
  memif_msg_t msg = { 0 };
  vnet_hw_interface_t *hw = vnet_get_hw_interface (vnm, hw_if_index);
  memif_if_t *mif = pool_elt_at_index (apm->interfaces, hw->dev_instance);
  static clib_error_t *error = 0;

  if (flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP)
    mif->flags |= MEMIF_IF_FLAG_ADMIN_UP;
  else
    {
      mif->flags &= ~MEMIF_IF_FLAG_ADMIN_UP;
      if (!(mif->flags & MEMIF_IF_FLAG_DELETING)
	  && mif->connection.index != ~0)
	{
	  msg.version = MEMIF_VERSION;
	  msg.type = MEMIF_MSG_TYPE_DISCONNECT;
	  if (send (mif->connection.fd, &msg, sizeof (msg), 0) < 0)
	    {
	      clib_unix_warning ("Failed to send disconnect request");
	      error = clib_error_return_unix (0, "send fd %d",
					      mif->connection.fd);
	      memif_disconnect (vm, mif);
	    }
	}
    }

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
