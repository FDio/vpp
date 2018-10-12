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
#include <linux/virtio_net.h>
#include <linux/vhost.h>

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
_(NO_TX_QUEUES, "no tx queues")

typedef enum
{
#define _(f,s) TAP_TX_ERROR_##f,
  foreach_virtio_tx_func_error
#undef _
    TAP_TX_N_ERROR,
} virtio_tx_func_error_t;

static char *virtio_tx_func_error_strings[] = {
#define _(n,s) s,
  foreach_virtio_tx_func_error
#undef _
};

u8 *
format_virtio_device_name (u8 * s, va_list * args)
{
  u32 dev_instance = va_arg (*args, u32);
  virtio_main_t *mm = &virtio_main;
  virtio_if_t *vif = pool_elt_at_index (mm->interfaces, dev_instance);

  if (vif->type == VIRTIO_IF_TYPE_TAP)
    {
      s = format (s, "tap%u", vif->id);
    }
  else
    s = format (s, "virtio%lu", vif->dev_instance);

  return s;
}

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

inline void
virtio_free_used_desc (vlib_main_t * vm, virtio_vring_t * vring)
{
  u16 used = vring->desc_in_use;
  u16 sz = vring->size;
  u16 mask = sz - 1;
  u16 last = vring->last_used_idx;
  u16 n_left = vring->used->idx - last;

  if (n_left == 0)
    return;

  while (n_left)
    {
      struct vring_used_elem *e = &vring->used->ring[last & mask];
      u16 slot = e->id;
      struct vring_desc *d = &vring->desc[slot];

      if (PREDICT_FALSE (d->flags & VRING_DESC_F_INDIRECT))
	{
	  d = uword_to_pointer (d->addr, struct vring_desc *);
	  vec_free (d);
	}

      vlib_buffer_free (vm, &vring->buffers[slot], 1);
      used--;
      last++;
      n_left--;
    }
  vring->desc_in_use = used;
  vring->last_used_idx = last;
}

static_always_inline u16
add_buffer_to_slot (vlib_main_t * vm, virtio_vring_t * vring, u32 bi,
		    u16 avail, u16 next, u16 mask, int do_gso)
{
  u16 n_added = 0;
  const int hdr_sz = sizeof (struct virtio_net_hdr_v1);
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
      d->addr = pointer_to_uword (vlib_buffer_get_current (b)) - hdr_sz;
      d->len = b->current_length + hdr_sz;
      d->flags = 0;
    }
  else
    {
      struct vring_desc *id, *descs = 0;

      /* first buffer in chain */
      vec_add2_aligned (descs, id, 1, CLIB_CACHE_LINE_BYTES);
      id->addr = pointer_to_uword (vlib_buffer_get_current (b)) - hdr_sz;
      id->len = b->current_length + hdr_sz;

      while (b->flags & VLIB_BUFFER_NEXT_PRESENT)
	{
	  id->flags = VRING_DESC_F_NEXT;
	  id->next = vec_len (descs);
	  vec_add2_aligned (descs, id, 1, CLIB_CACHE_LINE_BYTES);
	  b = vlib_get_buffer (vm, b->next_buffer);
	  id->addr = pointer_to_uword (vlib_buffer_get_current (b));
	  id->len = b->current_length;
	}

      d->addr = pointer_to_uword (descs);
      d->len = vec_len (descs) * sizeof (struct vring_desc);
      d->flags = VRING_DESC_F_INDIRECT;
    }
  vring->buffers[next] = bi;
  vring->avail->ring[avail & mask] = next;
  n_added++;
  return n_added;
}

static_always_inline uword
virtio_interface_tx_inline (vlib_main_t * vm, vlib_node_runtime_t * node,
			    vlib_frame_t * frame, virtio_if_t * vif,
			    int do_gso)
{
  u8 qid = 0;
  u16 n_left = frame->n_vectors;
  virtio_vring_t *vring = vec_elt_at_index (vif->vrings, (qid << 1) + 1);
  u16 used, next, avail;
  u16 sz = vring->size;
  u16 mask = sz - 1;
  u32 *buffers = vlib_frame_vector_args (frame);

  clib_spinlock_lock_if_init (&vif->lockp);

  if ((vring->used->flags & VIRTIO_RING_FLAG_MASK_INT) == 0 &&
      vring->last_kick_avail_idx != vring->avail->idx)
    virtio_kick (vring);

  /* free consumed buffers */
  virtio_free_used_desc (vm, vring);

  used = vring->desc_in_use;
  next = vring->desc_next;
  avail = vring->avail->idx;

  while (n_left && used < sz)
    {
      u16 n_added;
      n_added =
	add_buffer_to_slot (vm, vring, buffers[0], avail, next, mask, do_gso);
      avail += n_added;
      next = (next + n_added) & mask;
      used += n_added;
      buffers++;
      n_left--;
    }

  if (n_left != frame->n_vectors)
    {
      CLIB_MEMORY_STORE_BARRIER ();
      vring->avail->idx = avail;
      vring->desc_next = next;
      vring->desc_in_use = used;
      if ((vring->used->flags & VIRTIO_RING_FLAG_MASK_INT) == 0)
	virtio_kick (vring);
    }


  if (n_left)
    {
      vlib_error_count (vm, node->node_index, TAP_TX_ERROR_NO_FREE_SLOTS,
			n_left);
      vlib_buffer_free (vm, buffers, n_left);
    }

  clib_spinlock_unlock_if_init (&vif->lockp);

  return frame->n_vectors - n_left;
}

static uword
virtio_interface_tx (vlib_main_t * vm,
		     vlib_node_runtime_t * node, vlib_frame_t * frame)
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
  virtio_vring_t *vring = vec_elt_at_index (vif->vrings, qid);

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
    vif->flags |= VIRTIO_IF_FLAG_ADMIN_UP;
  else
    vif->flags &= ~VIRTIO_IF_FLAG_ADMIN_UP;

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
  .tx_function = virtio_interface_tx,
  .format_device_name = format_virtio_device_name,
  .format_device = format_virtio_device,
  .format_tx_trace = format_virtio_tx_trace,
  .tx_function_n_errors = TAP_TX_N_ERROR,
  .tx_function_error_strings = virtio_tx_func_error_strings,
  .rx_redirect_to_node = virtio_set_interface_next_node,
  .clear_counters = virtio_clear_hw_interface_counters,
  .admin_up_down_function = virtio_interface_admin_up_down,
  .subif_add_del_function = virtio_subif_add_del_function,
  .rx_mode_change_function = virtio_interface_rx_mode_change,
};

VLIB_DEVICE_TX_FUNCTION_MULTIARCH(virtio_device_class,
				  virtio_interface_tx)
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
