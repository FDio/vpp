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

#include <stdint.h>
#include <net/if.h>
#include <sys/ioctl.h>

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vnet/ethernet/ethernet.h>

#include <vnet/devices/memif/memif.h>

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

static uword
memif_interface_tx (vlib_main_t * vm,
		    vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  u8 rid = 0;
  memif_main_t *nm = &memif_main;
  vnet_interface_output_runtime_t *rund = (void *) node->runtime_data;
  memif_if_t *nif = pool_elt_at_index (nm->interfaces, rund->dev_instance);
  memif_ring_t *ring = memif_get_s2m_ring (nif, rid);
  memif_ring_data_t *rd = vec_elt_at_index (nif->s2m_ring_data, rid);
  u32 *buffers = vlib_frame_args (frame);
  u32 n_left = frame->n_vectors;
  u16 ring_size = 1 << nif->log2_ring_size;
  u16 mask = ring_size - 1;
  u16 head, tail;
  u16 free_slots;

  clib_warning ("sending %u packets", n_left);

  if (PREDICT_FALSE (nif->lockp != 0))
    {
      while (__sync_lock_test_and_set (nif->lockp, 1))
	;
    }

  /* free consumed buffers */
  tail = ring->tail;
  while (tail != rd->last_tail)
    {
      u32 bi0;
      bi0 = rd->buffers[rd->last_tail];
      clib_warning ("bi %u freed from slot %u", bi0, rd->last_tail);
      vlib_buffer_free (vm, &bi0, 1);	//FIXME
      rd->last_tail = (rd->last_tail + 1) & mask;
    }

  head = ring->head;

  if (ring->tail > ring->head)
    free_slots = ring_size - ring->head - ring->tail;
  else
    free_slots = ring_size - ring->head + ring->tail;

  while (n_left && free_slots)
    {
      u32 bi0 = buffers[0];
      vlib_buffer_t *b0 = vlib_get_buffer (vm, bi0);
      ring->desc[head].addr = pointer_to_uword (vlib_buffer_get_current (b0));
      ring->desc[head].length = b0->current_length;
      rd->buffers[head] = bi0;
      clib_warning ("bi %u added to slot %u", bi0, head);
      buffers++;
      n_left--;
      free_slots--;
      head = (head + 1) & mask;
    }
  CLIB_MEMORY_BARRIER ();
  ring->head = head;

  if (PREDICT_FALSE (nif->lockp != 0))
    *nif->lockp = 0;

  if (n_left)
    {
      vlib_error_count (vm, node->node_index,
			(n_left ==
			 frame->n_vectors ? MEMIF_TX_ERROR_PENDING_MSGS :
			 MEMIF_TX_ERROR_NO_FREE_SLOTS), n_left);
      vlib_buffer_free (vm, buffers, n_left);
    }
  return frame->n_vectors;
}

static void
memif_set_interface_next_node (vnet_main_t * vnm, u32 hw_if_index,
			       u32 node_index)
{
  memif_main_t *apm = &memif_main;
  vnet_hw_interface_t *hw = vnet_get_hw_interface (vnm, hw_if_index);
  memif_if_t *nif = pool_elt_at_index (apm->interfaces, hw->dev_instance);

  /* Shut off redirection */
  if (node_index == ~0)
    {
      nif->per_interface_next_index = node_index;
      return;
    }

  nif->per_interface_next_index =
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
  vnet_hw_interface_t *hw = vnet_get_hw_interface (vnm, hw_if_index);
  memif_if_t *nif = pool_elt_at_index (apm->interfaces, hw->dev_instance);
  u32 hw_flags;

  if (flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP)
    nif->flags |= MEMIF_IF_FLAG_ADMIN_UP;
  else
    nif->flags &= ~MEMIF_IF_FLAG_ADMIN_UP;

  if (nif->flags & MEMIF_IF_FLAG_ADMIN_UP)
    hw_flags = VNET_HW_INTERFACE_FLAG_LINK_UP;
  else
    hw_flags = 0;

  vnet_hw_interface_set_flags (vnm, hw_if_index, hw_flags);

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
