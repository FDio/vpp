/*
 *------------------------------------------------------------------
 * Copyright (c) 2017 Cisco and/or its affiliates.
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
#include <net/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <sys/eventfd.h>

#include <vlib/vlib.h>
#include <vlib/pci/pci.h>
#include <vlib/unix/unix.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/devices/virtio/virtio.h>
#include <vnet/devices/virtio/pci.h>
#include <vnet/interface/rx_queue_funcs.h>
#include <vnet/interface/tx_queue_funcs.h>

virtio_main_t virtio_main;

#define _IOCTL(fd,a,...) \
  if (ioctl (fd, a, __VA_ARGS__) < 0) \
    { \
      err = clib_error_return_unix (0, "ioctl(" #a ")"); \
      goto error; \
    }

static clib_error_t *
call_read_ready (clib_file_t * uf)
{
  vnet_main_t *vnm = vnet_get_main ();
  u64 b;

  CLIB_UNUSED (ssize_t size) = read (uf->file_descriptor, &b, sizeof (b));
  vnet_hw_if_rx_queue_set_int_pending (vnm, uf->private_data);

  return 0;
}


clib_error_t *
virtio_vring_init (vlib_main_t * vm, virtio_if_t * vif, u16 idx, u16 sz)
{
  virtio_vring_t *vring;
  int i;

  if (!is_pow2 (sz))
    return clib_error_return (0, "ring size must be power of 2");

  if (sz > 32768)
    return clib_error_return (0, "ring size must be 32768 or lower");

  if (sz == 0)
    sz = 256;

  if (idx % 2)
    {
      vec_validate_aligned (vif->txq_vrings, TX_QUEUE_ACCESS (idx),
			    CLIB_CACHE_LINE_BYTES);
      vring = vec_elt_at_index (vif->txq_vrings, TX_QUEUE_ACCESS (idx));
    }
  else
    {
      vec_validate_aligned (vif->rxq_vrings, RX_QUEUE_ACCESS (idx),
			    CLIB_CACHE_LINE_BYTES);
      vring = vec_elt_at_index (vif->rxq_vrings, RX_QUEUE_ACCESS (idx));
    }
  i = sizeof (vring_desc_t) * sz;
  i = round_pow2 (i, CLIB_CACHE_LINE_BYTES);
  vring->desc = clib_mem_alloc_aligned (i, CLIB_CACHE_LINE_BYTES);
  clib_memset (vring->desc, 0, i);

  i = sizeof (vring_avail_t) + sz * sizeof (vring->avail->ring[0]);
  i = round_pow2 (i, CLIB_CACHE_LINE_BYTES);
  vring->avail = clib_mem_alloc_aligned (i, CLIB_CACHE_LINE_BYTES);
  clib_memset (vring->avail, 0, i);
  // tell kernel that we don't need interrupt
  vring->avail->flags = VRING_AVAIL_F_NO_INTERRUPT;

  i = sizeof (vring_used_t) + sz * sizeof (vring_used_elem_t);
  i = round_pow2 (i, CLIB_CACHE_LINE_BYTES);
  vring->used = clib_mem_alloc_aligned (i, CLIB_CACHE_LINE_BYTES);
  clib_memset (vring->used, 0, i);

  vring->queue_id = idx;
  ASSERT (vring->buffers == 0);
  vec_validate_aligned (vring->buffers, sz, CLIB_CACHE_LINE_BYTES);

  if (idx & 1)
    {
      clib_memset_u32 (vring->buffers, ~0, sz);
      // tx path: suppress the interrupts from kernel
      vring->call_fd = -1;
    }
  else
    vring->call_fd = eventfd (0, EFD_NONBLOCK | EFD_CLOEXEC);

  vring->size = sz;
  vring->kick_fd = eventfd (0, EFD_NONBLOCK | EFD_CLOEXEC);
  virtio_log_debug (vif, "vring %u size %u call_fd %d kick_fd %d", idx,
		    vring->size, vring->call_fd, vring->kick_fd);

  return 0;
}

inline void
virtio_free_buffers (vlib_main_t * vm, virtio_vring_t * vring)
{
  u16 used = vring->desc_in_use;
  u16 last = vring->last_used_idx;
  u16 mask = vring->size - 1;

  while (used)
    {
      vlib_buffer_free (vm, &vring->buffers[last & mask], 1);
      last++;
      used--;
    }
}

clib_error_t *
virtio_vring_free_rx (vlib_main_t * vm, virtio_if_t * vif, u32 idx)
{
  virtio_vring_t *vring =
    vec_elt_at_index (vif->rxq_vrings, RX_QUEUE_ACCESS (idx));

  clib_file_del_by_index (&file_main, vring->call_file_index);
  close (vring->kick_fd);
  close (vring->call_fd);
  if (vring->used)
    {
      virtio_free_buffers (vm, vring);
      clib_mem_free (vring->used);
    }
  if (vring->desc)
    clib_mem_free (vring->desc);
  if (vring->avail)
    clib_mem_free (vring->avail);
  vec_free (vring->buffers);
  return 0;
}

clib_error_t *
virtio_vring_free_tx (vlib_main_t * vm, virtio_if_t * vif, u32 idx)
{
  virtio_vring_t *vring =
    vec_elt_at_index (vif->txq_vrings, TX_QUEUE_ACCESS (idx));

  close (vring->kick_fd);
  if (vring->used)
    {
      virtio_free_buffers (vm, vring);
      clib_mem_free (vring->used);
    }
  if (vring->desc)
    clib_mem_free (vring->desc);
  if (vring->avail)
    clib_mem_free (vring->avail);
  vec_free (vring->buffers);
  gro_flow_table_free (vring->flow_table);
  virtio_vring_buffering_free (vm, vring->buffering);
  clib_spinlock_free (&vring->lockp);
  return 0;
}

void
virtio_set_packet_coalesce (virtio_if_t * vif)
{
  vnet_main_t *vnm = vnet_get_main ();
  vnet_hw_interface_t *hw = vnet_get_hw_interface (vnm, vif->hw_if_index);
  virtio_vring_t *vring;
  vif->packet_coalesce = 1;
  vec_foreach (vring, vif->txq_vrings)
  {
    gro_flow_table_init (&vring->flow_table,
			 vif->type & (VIRTIO_IF_TYPE_TAP |
				      VIRTIO_IF_TYPE_PCI), hw->tx_node_index);
  }
}

clib_error_t *
virtio_set_packet_buffering (virtio_if_t * vif, u16 buffering_size)
{
  vnet_main_t *vnm = vnet_get_main ();
  vnet_hw_interface_t *hw = vnet_get_hw_interface (vnm, vif->hw_if_index);
  virtio_vring_t *vring;
  clib_error_t *error = 0;
  vif->packet_buffering = 1;

  vec_foreach (vring, vif->txq_vrings)
  {
    if ((error =
	 virtio_vring_buffering_init (&vring->buffering, hw->tx_node_index,
				      buffering_size)))
      {
	break;
      }
  }

  return error;
}

void
virtio_vring_set_rx_queues (vlib_main_t *vm, virtio_if_t *vif)
{
  vnet_main_t *vnm = vnet_get_main ();
  virtio_vring_t *vring;

  vnet_hw_if_set_input_node (vnm, vif->hw_if_index, virtio_input_node.index);

  vec_foreach (vring, vif->rxq_vrings)
    {
      vring->queue_index = vnet_hw_if_register_rx_queue (
	vnm, vif->hw_if_index, RX_QUEUE_ACCESS (vring->queue_id),
	VNET_HW_IF_RXQ_THREAD_ANY);
      vring->buffer_pool_index = vlib_buffer_pool_get_default_for_numa (
	vm, vnet_hw_if_get_rx_queue_numa_node (vnm, vring->queue_index));
      if (vif->type == VIRTIO_IF_TYPE_TAP || vif->type == VIRTIO_IF_TYPE_TUN)
	{

	  clib_file_t f = {
	    .read_function = call_read_ready,
	    .flags = UNIX_FILE_EVENT_EDGE_TRIGGERED,
	    .file_descriptor = vring->call_fd,
	    .private_data = vring->queue_index,
	    .description = format (0, "%U vring %u", format_virtio_device_name,
				   vif->dev_instance, vring->queue_id),
	  };

	  vring->call_file_index = clib_file_add (&file_main, &f);
	  vnet_hw_if_set_rx_queue_file_index (vnm, vring->queue_index,
					      vring->call_file_index);
	}
    }
  vnet_hw_if_update_runtime_data (vnm, vif->hw_if_index);
}

void
virtio_vring_set_tx_queues (vlib_main_t *vm, virtio_if_t *vif)
{
  vnet_main_t *vnm = vnet_get_main ();
  virtio_vring_t *vring;
  u32 *queue_ids = 0;
  u32 *flags = 0;
  u32 i = 0;

  ASSERT (vif->num_txqs > 0);
  vec_validate (flags, vif->num_txqs - 1);
  vec_foreach (vring, vif->txq_vrings)
    {
      vec_add1 (queue_ids, TX_QUEUE_ACCESS (vring->queue_id));
    }
  vnet_hw_if_register_tx_queues (vnm, vif->hw_if_index, queue_ids, flags);
  vec_foreach_index (i, vif->txq_vrings)
    {
      switch (flags[i])
	{
	case VNET_HW_IF_TXQ_UNIQUE:
	  vif->txq_vrings[i].flags |= VRING_TX_QUEUE_UNIQUE;
	  break;
	case VNET_HW_IF_TXQ_SHARED:
	  vif->txq_vrings[i].flags |= VRING_TX_QUEUE_SHARED;
	  clib_spinlock_init (&vif->txq_vrings[i].lockp);
	  break;
	}
    }

  vec_free (flags);
  vec_free (queue_ids);
}

inline void
virtio_set_net_hdr_size (virtio_if_t * vif)
{
  if (vif->features & VIRTIO_FEATURE (VIRTIO_NET_F_MRG_RXBUF) ||
      vif->features & VIRTIO_FEATURE (VIRTIO_F_VERSION_1))
    vif->virtio_net_hdr_sz = sizeof (virtio_net_hdr_v1_t);
  else
    vif->virtio_net_hdr_sz = sizeof (virtio_net_hdr_t);
}

inline void
virtio_show (vlib_main_t * vm, u32 * hw_if_indices, u8 show_descr, u32 type)
{
  u32 i, j, hw_if_index;
  virtio_if_t *vif;
  vnet_main_t *vnm = &vnet_main;
  virtio_main_t *mm = &virtio_main;
  virtio_vring_t *vring;
  struct feat_struct
  {
    u8 bit;
    char *str;
  };
  struct feat_struct *feat_entry;

  static struct feat_struct feat_array[] = {
#define _(s,b) { .str = #s, .bit = b, },
    foreach_virtio_net_features
#undef _
    {.str = NULL}
  };

  struct feat_struct *flag_entry;
  static struct feat_struct flags_array[] = {
#define _(b,e,s) { .bit = b, .str = s, },
    foreach_virtio_if_flag
#undef _
    {.str = NULL}
  };

  if (!hw_if_indices)
    return;

  for (hw_if_index = 0; hw_if_index < vec_len (hw_if_indices); hw_if_index++)
    {
      vnet_hw_interface_t *hi =
	vnet_get_hw_interface (vnm, hw_if_indices[hw_if_index]);
      vif = pool_elt_at_index (mm->interfaces, hi->dev_instance);
      if (vif->type != type)
	continue;
      vlib_cli_output (vm, "Interface: %U (ifindex %d)",
		       format_vnet_hw_if_index_name, vnm,
		       hw_if_indices[hw_if_index], vif->hw_if_index);
      if (type == VIRTIO_IF_TYPE_PCI)
	{
	  vlib_cli_output (vm, "  PCI Address: %U", format_vlib_pci_addr,
			   &vif->pci_addr);
	}
      if (type & (VIRTIO_IF_TYPE_TAP | VIRTIO_IF_TYPE_TUN))
	{
	  u8 *str = 0;
	  if (vif->host_if_name)
	    vlib_cli_output (vm, "  name \"%s\"", vif->host_if_name);
	  if (vif->net_ns)
	    vlib_cli_output (vm, "  host-ns \"%s\"", vif->net_ns);
	  if (vif->host_mtu_size)
	    vlib_cli_output (vm, "  host-mtu-size \"%d\"",
			     vif->host_mtu_size);
	  if (type == VIRTIO_IF_TYPE_TAP)
	    vlib_cli_output (vm, "  host-mac-addr: %U",
			     format_ethernet_address, vif->host_mac_addr);
	  vlib_cli_output (vm, "  host-carrier-up: %u", vif->host_carrier_up);

	  vec_foreach_index (i, vif->vhost_fds)
	    str = format (str, " %d", vif->vhost_fds[i]);
	  vlib_cli_output (vm, "  vhost-fds%v", str);
	  vec_free (str);
	  vec_foreach_index (i, vif->tap_fds)
	    str = format (str, " %d", vif->tap_fds[i]);
	  vlib_cli_output (vm, "  tap-fds%v", str);
	  vec_free (str);
	}
      vlib_cli_output (vm, "  gso-enabled %d", vif->gso_enabled);
      vlib_cli_output (vm, "  csum-enabled %d", vif->csum_offload_enabled);
      vlib_cli_output (vm, "  packet-coalesce %d", vif->packet_coalesce);
      vlib_cli_output (vm, "  packet-buffering %d", vif->packet_buffering);
      if (type & (VIRTIO_IF_TYPE_TAP | VIRTIO_IF_TYPE_PCI))
	vlib_cli_output (vm, "  Mac Address: %U", format_ethernet_address,
			 vif->mac_addr);
      vlib_cli_output (vm, "  Device instance: %u", vif->dev_instance);
      vlib_cli_output (vm, "  flags 0x%x", vif->flags);
      flag_entry = (struct feat_struct *) &flags_array;
      while (flag_entry->str)
	{
	  if (vif->flags & (1ULL << flag_entry->bit))
	    vlib_cli_output (vm, "    %s (%d)", flag_entry->str,
			     flag_entry->bit);
	  flag_entry++;
	}
      if (type == VIRTIO_IF_TYPE_PCI)
	{
	  device_status (vm, vif);
	}
      vlib_cli_output (vm, "  features 0x%lx", vif->features);
      feat_entry = (struct feat_struct *) &feat_array;
      while (feat_entry->str)
	{
	  if (vif->features & (1ULL << feat_entry->bit))
	    vlib_cli_output (vm, "    %s (%d)", feat_entry->str,
			     feat_entry->bit);
	  feat_entry++;
	}
      vlib_cli_output (vm, "  remote-features 0x%lx", vif->remote_features);
      feat_entry = (struct feat_struct *) &feat_array;
      while (feat_entry->str)
	{
	  if (vif->remote_features & (1ULL << feat_entry->bit))
	    vlib_cli_output (vm, "    %s (%d)", feat_entry->str,
			     feat_entry->bit);
	  feat_entry++;
	}
      vlib_cli_output (vm, "  Number of RX Virtqueue  %u", vif->num_rxqs);
      vlib_cli_output (vm, "  Number of TX Virtqueue  %u", vif->num_txqs);
      if (vif->cxq_vring != NULL
	  && vif->features & VIRTIO_FEATURE (VIRTIO_NET_F_CTRL_VQ))
	vlib_cli_output (vm, "  Number of CTRL Virtqueue 1");
      vec_foreach_index (i, vif->rxq_vrings)
      {
	vring = vec_elt_at_index (vif->rxq_vrings, i);
	vlib_cli_output (vm, "  Virtqueue (RX) %d", vring->queue_id);
	vlib_cli_output (vm,
			 "    qsz %d, last_used_idx %d, desc_next %d, desc_in_use %d",
			 vring->size, vring->last_used_idx, vring->desc_next,
			 vring->desc_in_use);
	if (vif->is_packed)
	  {
	    vlib_cli_output (vm,
			     "    driver_event.flags 0x%x driver_event.off_wrap %d device_event.flags 0x%x device_event.off_wrap %d",
			     vring->driver_event->flags,
			     vring->driver_event->off_wrap,
			     vring->device_event->flags,
			     vring->device_event->off_wrap);
	    vlib_cli_output (vm,
			     "    avail wrap counter %d, used wrap counter %d",
			     vring->avail_wrap_counter,
			     vring->used_wrap_counter);
	  }
	else
	  vlib_cli_output (vm,
			   "    avail.flags 0x%x avail.idx %d used.flags 0x%x used.idx %d",
			   vring->avail->flags, vring->avail->idx,
			   vring->used->flags, vring->used->idx);
	if (type & (VIRTIO_IF_TYPE_TAP | VIRTIO_IF_TYPE_TUN))
	  {
	    vlib_cli_output (vm, "    kickfd %d, callfd %d", vring->kick_fd,
			     vring->call_fd);
	  }
	if (show_descr)
	  {
	    vlib_cli_output (vm, "\n  descriptor table:\n");
	    vlib_cli_output (vm,
			     "   id          addr         len  flags  next/id      user_addr\n");
	    vlib_cli_output (vm,
			     "  ===== ================== ===== ====== ======= ==================\n");
	    for (j = 0; j < vring->size; j++)
	      {
		if (vif->is_packed)
		  {
		    vring_packed_desc_t *desc = &vring->packed_desc[j];
		    vlib_cli_output (vm,
				     "  %-5d 0x%016lx %-5d 0x%04x %-8d 0x%016lx\n",
				     j, desc->addr,
				     desc->len,
				     desc->flags, desc->id, desc->addr);
		  }
		else
		  {
		    vring_desc_t *desc = &vring->desc[j];
		    vlib_cli_output (vm,
				     "  %-5d 0x%016lx %-5d 0x%04x %-8d 0x%016lx\n",
				     j, desc->addr,
				     desc->len,
				     desc->flags, desc->next, desc->addr);
		  }
	      }
	  }
      }
      vec_foreach_index (i, vif->txq_vrings)
      {
	vring = vec_elt_at_index (vif->txq_vrings, i);
	vlib_cli_output (vm, "  Virtqueue (TX) %d", vring->queue_id);
	vlib_cli_output (vm,
			 "    qsz %d, last_used_idx %d, desc_next %d, desc_in_use %d",
			 vring->size, vring->last_used_idx, vring->desc_next,
			 vring->desc_in_use);
	if (vif->is_packed)
	  {
	    vlib_cli_output (vm,
			     "    driver_event.flags 0x%x driver_event.off_wrap %d device_event.flags 0x%x device_event.off_wrap %d",
			     vring->driver_event->flags,
			     vring->driver_event->off_wrap,
			     vring->device_event->flags,
			     vring->device_event->off_wrap);
	    vlib_cli_output (vm,
			     "    avail wrap counter %d, used wrap counter %d",
			     vring->avail_wrap_counter,
			     vring->used_wrap_counter);
	  }
	else
	  vlib_cli_output (vm,
			   "    avail.flags 0x%x avail.idx %d used.flags 0x%x used.idx %d",
			   vring->avail->flags, vring->avail->idx,
			   vring->used->flags, vring->used->idx);
	if (type & (VIRTIO_IF_TYPE_TAP | VIRTIO_IF_TYPE_TUN))
	  {
	    vlib_cli_output (vm, "    kickfd %d, callfd %d", vring->kick_fd,
			     vring->call_fd);
	  }
	if (vring->flow_table)
	  {
	    vlib_cli_output (vm, "    %U", gro_flow_table_format,
			     vring->flow_table);
	  }
	if (vif->packet_buffering)
	  {
	    vlib_cli_output (vm, "    %U", virtio_vring_buffering_format,
			     vring->buffering);
	  }
	if (show_descr)
	  {
	    vlib_cli_output (vm, "\n  descriptor table:\n");
	    vlib_cli_output (vm,
			     "   id          addr         len  flags  next/id      user_addr\n");
	    vlib_cli_output (vm,
			     "  ===== ================== ===== ====== ======== ==================\n");
	    for (j = 0; j < vring->size; j++)
	      {
		if (vif->is_packed)
		  {
		    vring_packed_desc_t *desc = &vring->packed_desc[j];
		    vlib_cli_output (vm,
				     "  %-5d 0x%016lx %-5d 0x%04x %-8d 0x%016lx\n",
				     j, desc->addr,
				     desc->len,
				     desc->flags, desc->id, desc->addr);
		  }
		else
		  {
		    vring_desc_t *desc = &vring->desc[j];
		    vlib_cli_output (vm,
				     "  %-5d 0x%016lx %-5d 0x%04x %-8d 0x%016lx\n",
				     j, desc->addr,
				     desc->len,
				     desc->flags, desc->next, desc->addr);
		  }
	      }
	  }
      }
      if (vif->cxq_vring != NULL
	  && vif->features & VIRTIO_FEATURE (VIRTIO_NET_F_CTRL_VQ))
	{
	  vring = vif->cxq_vring;
	  vlib_cli_output (vm, "  Virtqueue (CTRL) %d", vring->queue_id);
	  vlib_cli_output (vm,
			   "    qsz %d, last_used_idx %d, desc_next %d, desc_in_use %d",
			   vring->size, vring->last_used_idx,
			   vring->desc_next, vring->desc_in_use);
	  if (vif->is_packed)
	    {
	      vlib_cli_output (vm,
			       "    driver_event.flags 0x%x driver_event.off_wrap %d device_event.flags 0x%x device_event.off_wrap %d",
			       vring->driver_event->flags,
			       vring->driver_event->off_wrap,
			       vring->device_event->flags,
			       vring->device_event->off_wrap);
	      vlib_cli_output (vm,
			       "    avail wrap counter %d, used wrap counter %d",
			       vring->avail_wrap_counter,
			       vring->used_wrap_counter);
	    }
	  else
	    {
	      vlib_cli_output (vm,
			       "    avail.flags 0x%x avail.idx %d used.flags 0x%x used.idx %d",
			       vring->avail->flags, vring->avail->idx,
			       vring->used->flags, vring->used->idx);
	    }
	  if (type & (VIRTIO_IF_TYPE_TAP | VIRTIO_IF_TYPE_TUN))
	    {
	      vlib_cli_output (vm, "    kickfd %d, callfd %d", vring->kick_fd,
			       vring->call_fd);
	    }
	  if (show_descr)
	    {
	      vlib_cli_output (vm, "\n  descriptor table:\n");
	      vlib_cli_output (vm,
			       "   id          addr         len  flags  next/id      user_addr\n");
	      vlib_cli_output (vm,
			       "  ===== ================== ===== ====== ======== ==================\n");
	      for (j = 0; j < vring->size; j++)
		{
		  if (vif->is_packed)
		    {
		      vring_packed_desc_t *desc = &vring->packed_desc[j];
		      vlib_cli_output (vm,
				       "  %-5d 0x%016lx %-5d 0x%04x %-8d 0x%016lx\n",
				       j, desc->addr,
				       desc->len,
				       desc->flags, desc->id, desc->addr);
		    }
		  else
		    {
		      vring_desc_t *desc = &vring->desc[j];
		      vlib_cli_output (vm,
				       "  %-5d 0x%016lx %-5d 0x%04x %-8d 0x%016lx\n",
				       j, desc->addr,
				       desc->len,
				       desc->flags, desc->next, desc->addr);
		    }
		}
	    }
	}

    }

}

static clib_error_t *
virtio_init (vlib_main_t * vm)
{
  virtio_main_t *vim = &virtio_main;
  clib_error_t *error = 0;

  vim->log_default = vlib_log_register_class ("virtio", 0);
  vlib_log_debug (vim->log_default, "initialized");

  return error;
}

VLIB_INIT_FUNCTION (virtio_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
