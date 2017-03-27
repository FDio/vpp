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

#include <vnet/devices/netmap/net_netmap.h>
#include <vnet/devices/netmap/netmap.h>

#define foreach_netmap_tx_func_error	       \
_(NO_FREE_SLOTS, "no free tx slots")           \
_(PENDING_MSGS, "pending msgs in tx ring")

typedef enum
{
#define _(f,s) NETMAP_TX_ERROR_##f,
  foreach_netmap_tx_func_error
#undef _
    NETMAP_TX_N_ERROR,
} netmap_tx_func_error_t;

static char *netmap_tx_func_error_strings[] = {
#define _(n,s) s,
  foreach_netmap_tx_func_error
#undef _
};


static u8 *
format_netmap_device_name (u8 * s, va_list * args)
{
  u32 i = va_arg (*args, u32);
  netmap_main_t *apm = &netmap_main;
  netmap_if_t *nif = pool_elt_at_index (apm->interfaces, i);

  s = format (s, "netmap-%s", nif->host_if_name);
  return s;
}

static u8 *
format_netmap_device (u8 * s, va_list * args)
{
  u32 dev_instance = va_arg (*args, u32);
  int verbose = va_arg (*args, int);
  netmap_main_t *nm = &netmap_main;
  netmap_if_t *nif = vec_elt_at_index (nm->interfaces, dev_instance);
  uword indent = format_get_indent (s);

  s = format (s, "NETMAP interface");
  if (verbose)
    {
      s = format (s, "\n%U version %d flags 0x%x"
		  "\n%U region %u memsize 0x%x offset 0x%x"
		  "\n%U tx_slots %u rx_slots %u tx_rings %u rx_rings %u",
		  format_white_space, indent + 2,
		  nif->req->nr_version,
		  nif->req->nr_flags,
		  format_white_space, indent + 2,
		  nif->mem_region,
		  nif->req->nr_memsize,
		  nif->req->nr_offset,
		  format_white_space, indent + 2,
		  nif->req->nr_tx_slots,
		  nif->req->nr_rx_slots,
		  nif->req->nr_tx_rings, nif->req->nr_rx_rings);
    }
  return s;
}

static u8 *
format_netmap_tx_trace (u8 * s, va_list * args)
{
  s = format (s, "Unimplemented...");
  return s;
}

static uword
netmap_interface_tx (vlib_main_t * vm,
		     vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  netmap_main_t *nm = &netmap_main;
  u32 *buffers = vlib_frame_args (frame);
  u32 n_left = frame->n_vectors;
  f64 const time_constant = 1e3;
  vnet_interface_output_runtime_t *rd = (void *) node->runtime_data;
  netmap_if_t *nif = pool_elt_at_index (nm->interfaces, rd->dev_instance);
  int cur_ring;

  clib_spinlock_lock_if_init (&nif->lockp);

  cur_ring = nif->first_tx_ring;

  while (n_left && cur_ring <= nif->last_tx_ring)
    {
      struct netmap_ring *ring = NETMAP_TXRING (nif->nifp, cur_ring);
      int n_free_slots = nm_ring_space (ring);
      uint cur = ring->cur;

      if (nm_tx_pending (ring))
	{
	  if (ioctl (nif->fd, NIOCTXSYNC, NULL) < 0)
	    clib_unix_warning ("NIOCTXSYNC");
	  clib_cpu_time_wait (time_constant);

	  if (nm_tx_pending (ring) && !n_free_slots)
	    {
	      cur_ring++;
	      continue;
	    }
	}

      while (n_left && n_free_slots)
	{
	  vlib_buffer_t *b0 = 0;
	  u32 bi = buffers[0];
	  u32 len;
	  u32 offset = 0;
	  buffers++;

	  struct netmap_slot *slot = &ring->slot[cur];

	  do
	    {
	      b0 = vlib_get_buffer (vm, bi);
	      len = b0->current_length;
	      /* memcpy */
	      clib_memcpy ((u8 *) NETMAP_BUF (ring, slot->buf_idx) + offset,
			   vlib_buffer_get_current (b0), len);
	      offset += len;
	    }
	  while ((bi = b0->next_buffer));

	  slot->len = offset;
	  cur = (cur + 1) % ring->num_slots;
	  n_free_slots--;
	  n_left--;
	}
      CLIB_MEMORY_BARRIER ();
      ring->head = ring->cur = cur;
    }

  if (n_left < frame->n_vectors)
    ioctl (nif->fd, NIOCTXSYNC, NULL);

  clib_spinlock_unlock_if_init (&nif->lockp);

  if (n_left)
    vlib_error_count (vm, node->node_index,
		      (n_left ==
		       frame->n_vectors ? NETMAP_TX_ERROR_PENDING_MSGS :
		       NETMAP_TX_ERROR_NO_FREE_SLOTS), n_left);

  vlib_buffer_free (vm, vlib_frame_args (frame), frame->n_vectors);
  return frame->n_vectors;
}

static void
netmap_set_interface_next_node (vnet_main_t * vnm, u32 hw_if_index,
				u32 node_index)
{
  netmap_main_t *apm = &netmap_main;
  vnet_hw_interface_t *hw = vnet_get_hw_interface (vnm, hw_if_index);
  netmap_if_t *nif = pool_elt_at_index (apm->interfaces, hw->dev_instance);

  /* Shut off redirection */
  if (node_index == ~0)
    {
      nif->per_interface_next_index = node_index;
      return;
    }

  nif->per_interface_next_index =
    vlib_node_add_next (vlib_get_main (), netmap_input_node.index,
			node_index);
}

static void
netmap_clear_hw_interface_counters (u32 instance)
{
  /* Nothing for now */
}

static clib_error_t *
netmap_interface_admin_up_down (vnet_main_t * vnm, u32 hw_if_index, u32 flags)
{
  netmap_main_t *apm = &netmap_main;
  vnet_hw_interface_t *hw = vnet_get_hw_interface (vnm, hw_if_index);
  netmap_if_t *nif = pool_elt_at_index (apm->interfaces, hw->dev_instance);
  u32 hw_flags;

  nif->is_admin_up = (flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP) != 0;

  if (nif->is_admin_up)
    hw_flags = VNET_HW_INTERFACE_FLAG_LINK_UP;
  else
    hw_flags = 0;

  vnet_hw_interface_set_flags (vnm, hw_if_index, hw_flags);

  return 0;
}

static clib_error_t *
netmap_subif_add_del_function (vnet_main_t * vnm,
			       u32 hw_if_index,
			       struct vnet_sw_interface_t *st, int is_add)
{
  /* Nothing for now */
  return 0;
}

/* *INDENT-OFF* */
VNET_DEVICE_CLASS (netmap_device_class) = {
  .name = "netmap",
  .tx_function = netmap_interface_tx,
  .format_device_name = format_netmap_device_name,
  .format_device = format_netmap_device,
  .format_tx_trace = format_netmap_tx_trace,
  .tx_function_n_errors = NETMAP_TX_N_ERROR,
  .tx_function_error_strings = netmap_tx_func_error_strings,
  .rx_redirect_to_node = netmap_set_interface_next_node,
  .clear_counters = netmap_clear_hw_interface_counters,
  .admin_up_down_function = netmap_interface_admin_up_down,
  .subif_add_del_function = netmap_subif_add_del_function,
};

VLIB_DEVICE_TX_FUNCTION_MULTIARCH(netmap_device_class,
				  netmap_interface_tx)
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
