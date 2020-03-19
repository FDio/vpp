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

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/devices/virtio/virtio.h>

#define foreach_virtio_tx_func_error	       \
_(NO_FREE_SLOTS, "no free tx slots")           \
_(TRUNC_PACKET, "packet > buffer size -- truncated in tx ring") \
_(PENDING_MSGS, "pending msgs in tx ring") \
_(NO_TX_QUEUES, "no tx queues") \
_(OUT_OF_ORDER, "out-of-order buffers in used ring")

typedef enum
{
#define _(f,s) VIRTIO_TX_ERROR_##f,
  foreach_virtio_tx_func_error
#undef _
    VIRTIO_TX_N_ERROR,
} virtio_tx_func_error_t;

static char *virtio_tx_func_error_strings[] = {
#define _(n,s) s,
  foreach_virtio_tx_func_error
#undef _
};

#ifndef CLIB_MARCH_VARIANT
u8 *
format_virtio_device_name (u8 * s, va_list * args)
{
  u32 dev_instance = va_arg (*args, u32);
  virtio_main_t *mm = &virtio_main;
  virtio_if_t *vif = pool_elt_at_index (mm->interfaces, dev_instance);

  if (vif->type == VIRTIO_IF_TYPE_TAP)
    s = format (s, "tap%u", vif->id);
  else if (vif->type == VIRTIO_IF_TYPE_PCI)
    s = format (s, "virtio-%x/%x/%x/%x", vif->pci_addr.domain,
		vif->pci_addr.bus, vif->pci_addr.slot,
		vif->pci_addr.function);
  else
    s = format (s, "virtio-%lu", vif->dev_instance);

  return s;
}
#endif /* CLIB_MARCH_VARIANT */

static u8 *
format_virtio_device (u8 * s, va_list * args)
{
  u32 dev_instance = va_arg (*args, u32);
  int verbose = va_arg (*args, int);
  u32 indent = format_get_indent (s);

  s = format (s, "VIRTIO interface");
  if (verbose)
    {
      s = format (s, "\n%U instance %u", format_white_space, indent + 2,
		  dev_instance);
    }
  return s;
}

static u8 *
format_virtio_tx_trace (u8 * s, va_list * args)
{
  s = format (s, "Unimplemented...");
  return s;
}

static_always_inline void
virtio_memset_ring_u32 (u32 * ring, u32 start, u32 ring_size, u32 n_buffers)
{
  ASSERT (n_buffers <= ring_size);

  if (PREDICT_TRUE (start + n_buffers <= ring_size))
    {
      clib_memset_u32 (ring + start, ~0, n_buffers);
    }
  else
    {
      clib_memset_u32 (ring + start, ~0, ring_size - start);
      clib_memset_u32 (ring, ~0, n_buffers - (ring_size - start));
    }
}

static_always_inline void
virtio_free_used_device_desc (vlib_main_t * vm, virtio_vring_t * vring,
			      uword node_index)
{
  u16 used = vring->desc_in_use;
  u16 sz = vring->size;
  u16 mask = sz - 1;
  u16 last = vring->last_used_idx;
  u16 n_left = vring->used->idx - last;
  u16 out_of_order_count = 0;

  if (n_left == 0)
    return;

  while (n_left)
    {
      struct vring_used_elem *e = &vring->used->ring[last & mask];
      u16 slot, n_buffers;
      slot = n_buffers = e->id;

      while (e->id == (n_buffers & mask))
	{
	  n_left--;
	  last++;
	  n_buffers++;
	  if (n_left == 0)
	    break;
	  e = &vring->used->ring[last & mask];
	}
      vlib_buffer_free_from_ring (vm, vring->buffers, slot,
				  sz, (n_buffers - slot));
      virtio_memset_ring_u32 (vring->buffers, slot, sz, (n_buffers - slot));
      used -= (n_buffers - slot);

      if (n_left > 0)
	{
	  vlib_buffer_free (vm, &vring->buffers[e->id], 1);
	  vring->buffers[e->id] = ~0;
	  used--;
	  last++;
	  n_left--;
	  out_of_order_count++;
	  vring->flags |= VRING_TX_OUT_OF_ORDER;
	}
    }

  /*
   * Some vhost-backends give buffers back in out-of-order fashion in used ring.
   * It impacts the overall virtio-performance.
   */
  if (out_of_order_count)
    vlib_error_count (vm, node_index, VIRTIO_TX_ERROR_OUT_OF_ORDER,
		      out_of_order_count);

  vring->desc_in_use = used;
  vring->last_used_idx = last;
}

static_always_inline u16
add_buffer_to_slot (vlib_main_t * vm, virtio_if_t * vif,
		    virtio_vring_t * vring, u32 bi, u16 avail, u16 next,
		    u16 mask, int do_gso)
{
  u16 n_added = 0;
  int hdr_sz = vif->virtio_net_hdr_sz;
  struct vring_desc *d;
  d = &vring->desc[next];
  vlib_buffer_t *b = vlib_get_buffer (vm, bi);
  struct virtio_net_hdr_v1 *hdr = vlib_buffer_get_current (b) - hdr_sz;

  clib_memset (hdr, 0, hdr_sz);
  if (do_gso && (b->flags & VNET_BUFFER_F_GSO))
    {
      if (b->flags & VNET_BUFFER_F_IS_IP4)
	{
	  hdr->gso_type = VIRTIO_NET_HDR_GSO_TCPV4;
	  hdr->gso_size = vnet_buffer2 (b)->gso_size;
	  hdr->flags = VIRTIO_NET_HDR_F_NEEDS_CSUM;
	  hdr->csum_start = vnet_buffer (b)->l4_hdr_offset;	// 0x22;
	  hdr->csum_offset = 0x10;
	}
      else
	{
	  hdr->gso_type = VIRTIO_NET_HDR_GSO_TCPV6;
	  hdr->gso_size = vnet_buffer2 (b)->gso_size;
	  hdr->flags = VIRTIO_NET_HDR_F_NEEDS_CSUM;
	  hdr->csum_start = vnet_buffer (b)->l4_hdr_offset;	// 0x36;
	  hdr->csum_offset = 0x10;
	}
    }

  if (PREDICT_TRUE ((b->flags & VLIB_BUFFER_NEXT_PRESENT) == 0))
    {
      d->addr =
	((vif->type == VIRTIO_IF_TYPE_PCI) ? vlib_buffer_get_current_pa (vm,
									 b) :
	 pointer_to_uword (vlib_buffer_get_current (b))) - hdr_sz;
      d->len = b->current_length + hdr_sz;
      d->flags = 0;
    }
  else
    {
      /*
       * We are using single vlib_buffer_t for indirect descriptor(s)
       * chain. Single descriptor is 16 bytes and vlib_buffer_t
       * has 2048 bytes space. So maximum long chain can have 128
       * (=2048/16) indirect descriptors.
       * It can easily support 65535 bytes of Jumbo frames with
       * each data buffer size of 512 bytes minimum.
       */
      u32 indirect_buffer = 0;
      if (PREDICT_FALSE (vlib_buffer_alloc (vm, &indirect_buffer, 1) == 0))
	return n_added;

      vlib_buffer_t *indirect_desc = vlib_get_buffer (vm, indirect_buffer);
      indirect_desc->current_data = 0;
      indirect_desc->flags |= VLIB_BUFFER_NEXT_PRESENT;
      indirect_desc->next_buffer = bi;
      bi = indirect_buffer;

      struct vring_desc *id =
	(struct vring_desc *) vlib_buffer_get_current (indirect_desc);
      u32 count = 1;
      if (vif->type == VIRTIO_IF_TYPE_PCI)
	{
	  d->addr = vlib_physmem_get_pa (vm, id);
	  id->addr = vlib_buffer_get_current_pa (vm, b) - hdr_sz;

	  /*
	   * If VIRTIO_F_ANY_LAYOUT is not negotiated, then virtio_net_hdr
	   * should be presented in separate descriptor and data will start
	   * from next descriptor.
	   */
	  if (PREDICT_TRUE
	      (vif->features & VIRTIO_FEATURE (VIRTIO_F_ANY_LAYOUT)))
	    id->len = b->current_length + hdr_sz;
	  else
	    {
	      id->len = hdr_sz;
	      id->flags = VRING_DESC_F_NEXT;
	      id->next = count;
	      count++;
	      id++;
	      id->addr = vlib_buffer_get_current_pa (vm, b);
	      id->len = b->current_length;
	    }
	  while (b->flags & VLIB_BUFFER_NEXT_PRESENT)
	    {
	      id->flags = VRING_DESC_F_NEXT;
	      id->next = count;
	      count++;
	      id++;
	      b = vlib_get_buffer (vm, b->next_buffer);
	      id->addr = vlib_buffer_get_current_pa (vm, b);
	      id->len = b->current_length;
	    }
	}
      else			/* VIRTIO_IF_TYPE_TAP */
	{
	  d->addr = pointer_to_uword (id);
	  /* first buffer in chain */
	  id->addr = pointer_to_uword (vlib_buffer_get_current (b)) - hdr_sz;
	  id->len = b->current_length + hdr_sz;

	  while (b->flags & VLIB_BUFFER_NEXT_PRESENT)
	    {
	      id->flags = VRING_DESC_F_NEXT;
	      id->next = count;
	      count++;
	      id++;
	      b = vlib_get_buffer (vm, b->next_buffer);
	      id->addr = pointer_to_uword (vlib_buffer_get_current (b));
	      id->len = b->current_length;
	    }
	}
      id->flags = 0;
      id->next = 0;
      d->len = count * sizeof (struct vring_desc);
      d->flags = VRING_DESC_F_INDIRECT;
    }
  vring->buffers[next] = bi;
  vring->avail->ring[avail & mask] = next;
  n_added++;
  return n_added;
}

static_always_inline u32
virtio_find_free_desc (virtio_vring_t * vring, u16 size, u16 mask,
		       u16 req, u16 next, u32 * first_free_desc_index,
		       u16 * free_desc_count)
{
  u16 start = 0;
  /* next is used as hint: from where to start looking */
  for (u16 i = 0; i < size; i++, next++)
    {
      if (vring->buffers[next & mask] == ~0)
	{
	  if (*first_free_desc_index == ~0)
	    {
	      *first_free_desc_index = (next & mask);
	      start = i;
	      (*free_desc_count)++;
	      req--;
	      if (req == 0)
		break;
	    }
	  else
	    {
	      if (start + *free_desc_count == i)
		{
		  (*free_desc_count)++;
		  req--;
		  if (req == 0)
		    break;
		}
	      else
		break;
	    }
	}
    }
  return *first_free_desc_index;
}

static_always_inline uword
virtio_interface_tx_inline (vlib_main_t * vm, vlib_node_runtime_t * node,
			    vlib_frame_t * frame, virtio_if_t * vif,
			    int do_gso)
{
  u16 n_left = frame->n_vectors;
  virtio_vring_t *vring;
  u16 qid = vm->thread_index % vif->num_txqs;
  vring = vec_elt_at_index (vif->txq_vrings, qid);
  u16 used, next, avail;
  u16 sz = vring->size;
  u16 mask = sz - 1;
  u16 retry_count = 2;
  u32 *buffers = vlib_frame_vector_args (frame);

  clib_spinlock_lock_if_init (&vring->lockp);

  if ((vring->used->flags & VIRTIO_RING_FLAG_MASK_INT) == 0 &&
      (vring->last_kick_avail_idx != vring->avail->idx))
    virtio_kick (vm, vring, vif);

retry:
  /* free consumed buffers */
  virtio_free_used_device_desc (vm, vring, node->node_index);

  used = vring->desc_in_use;
  next = vring->desc_next;
  avail = vring->avail->idx;

  u16 free_desc_count = 0;

  if (PREDICT_FALSE (vring->flags & VRING_TX_OUT_OF_ORDER))
    {
      u32 first_free_desc_index = ~0;

      virtio_find_free_desc (vring, sz, mask, n_left, next,
			     &first_free_desc_index, &free_desc_count);

      if (free_desc_count)
	next = first_free_desc_index;
    }
  else
    free_desc_count = sz - used;

  while (n_left && free_desc_count)
    {
      u16 n_added = 0;
      n_added =
	add_buffer_to_slot (vm, vif, vring, buffers[0], avail, next, mask,
			    do_gso);
      if (!n_added)
	break;
      avail += n_added;
      next = (next + n_added) & mask;
      used += n_added;
      buffers++;
      n_left--;
      free_desc_count--;
    }

  if (n_left != frame->n_vectors)
    {
      CLIB_MEMORY_STORE_BARRIER ();
      vring->avail->idx = avail;
      vring->desc_next = next;
      vring->desc_in_use = used;
      if ((vring->used->flags & VIRTIO_RING_FLAG_MASK_INT) == 0)
	virtio_kick (vm, vring, vif);
    }

  if (n_left)
    {
      if (retry_count--)
	goto retry;

      vlib_error_count (vm, node->node_index, VIRTIO_TX_ERROR_NO_FREE_SLOTS,
			n_left);
      vlib_buffer_free (vm, buffers, n_left);
    }

  clib_spinlock_unlock_if_init (&vring->lockp);

  return frame->n_vectors - n_left;
}

VNET_DEVICE_CLASS_TX_FN (virtio_device_class) (vlib_main_t * vm,
					       vlib_node_runtime_t * node,
					       vlib_frame_t * frame)
{
  virtio_main_t *nm = &virtio_main;
  vnet_interface_output_runtime_t *rund = (void *) node->runtime_data;
  virtio_if_t *vif = pool_elt_at_index (nm->interfaces, rund->dev_instance);
  vnet_main_t *vnm = vnet_get_main ();

  if (vnm->interface_main.gso_interface_count > 0)
    return virtio_interface_tx_inline (vm, node, frame, vif, 1 /* do_gso */ );
  else
    return virtio_interface_tx_inline (vm, node, frame, vif,
				       0 /* no do_gso */ );
}

static void
virtio_set_interface_next_node (vnet_main_t * vnm, u32 hw_if_index,
				u32 node_index)
{
  virtio_main_t *apm = &virtio_main;
  vnet_hw_interface_t *hw = vnet_get_hw_interface (vnm, hw_if_index);
  virtio_if_t *vif = pool_elt_at_index (apm->interfaces, hw->dev_instance);

  /* Shut off redirection */
  if (node_index == ~0)
    {
      vif->per_interface_next_index = node_index;
      return;
    }

  vif->per_interface_next_index =
    vlib_node_add_next (vlib_get_main (), virtio_input_node.index,
			node_index);
}

static void
virtio_clear_hw_interface_counters (u32 instance)
{
  /* Nothing for now */
}

static clib_error_t *
virtio_interface_rx_mode_change (vnet_main_t * vnm, u32 hw_if_index, u32 qid,
				 vnet_hw_interface_rx_mode mode)
{
  virtio_main_t *mm = &virtio_main;
  vnet_hw_interface_t *hw = vnet_get_hw_interface (vnm, hw_if_index);
  virtio_if_t *vif = pool_elt_at_index (mm->interfaces, hw->dev_instance);
  virtio_vring_t *vring = vec_elt_at_index (vif->rxq_vrings, qid);

  if (vif->type == VIRTIO_IF_TYPE_PCI && !(vif->support_int_mode))
    {
      vring->avail->flags |= VIRTIO_RING_FLAG_MASK_INT;
      return clib_error_return (0, "interrupt mode is not supported");
    }

  if (mode == VNET_HW_INTERFACE_RX_MODE_POLLING)
    vring->avail->flags |= VIRTIO_RING_FLAG_MASK_INT;
  else
    vring->avail->flags &= ~VIRTIO_RING_FLAG_MASK_INT;

  return 0;
}

static clib_error_t *
virtio_interface_admin_up_down (vnet_main_t * vnm, u32 hw_if_index, u32 flags)
{
  virtio_main_t *mm = &virtio_main;
  vnet_hw_interface_t *hw = vnet_get_hw_interface (vnm, hw_if_index);
  virtio_if_t *vif = pool_elt_at_index (mm->interfaces, hw->dev_instance);

  if (flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP)
    {
      vif->flags |= VIRTIO_IF_FLAG_ADMIN_UP;
      vnet_hw_interface_set_flags (vnm, vif->hw_if_index,
				   VNET_HW_INTERFACE_FLAG_LINK_UP);
    }
  else
    {
      vif->flags &= ~VIRTIO_IF_FLAG_ADMIN_UP;
      vnet_hw_interface_set_flags (vnm, vif->hw_if_index, 0);
    }
  return 0;
}

static clib_error_t *
virtio_subif_add_del_function (vnet_main_t * vnm,
			       u32 hw_if_index,
			       struct vnet_sw_interface_t *st, int is_add)
{
  /* Nothing for now */
  return 0;
}

/* *INDENT-OFF* */
VNET_DEVICE_CLASS (virtio_device_class) = {
  .name = "virtio",
  .format_device_name = format_virtio_device_name,
  .format_device = format_virtio_device,
  .format_tx_trace = format_virtio_tx_trace,
  .tx_function_n_errors = VIRTIO_TX_N_ERROR,
  .tx_function_error_strings = virtio_tx_func_error_strings,
  .rx_redirect_to_node = virtio_set_interface_next_node,
  .clear_counters = virtio_clear_hw_interface_counters,
  .admin_up_down_function = virtio_interface_admin_up_down,
  .subif_add_del_function = virtio_subif_add_del_function,
  .rx_mode_change_function = virtio_interface_rx_mode_change,
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
