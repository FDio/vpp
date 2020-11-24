/*
 * Copyright (c) 2018 Cisco and/or its affiliates.
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
 */

#include <fcntl.h>
#include <sys/ioctl.h>

#include <vppinfra/types.h>
#include <vlib/vlib.h>
#include <vlib/pci/pci.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/devices/virtio/virtio.h>
#include <vnet/devices/virtio/pci.h>

#define PCI_VENDOR_ID_VIRTIO				0x1af4
#define PCI_DEVICE_ID_VIRTIO_NIC			0x1000
/* Doesn't support modern device */
#define PCI_DEVICE_ID_VIRTIO_NIC_MODERN			0x1041

#define PCI_CAPABILITY_LIST     0x34
#define PCI_CAP_ID_VNDR         0x09
#define PCI_CAP_ID_MSIX         0x11

#define PCI_MSIX_ENABLE 0x8000

static pci_device_id_t virtio_pci_device_ids[] = {
  {
   .vendor_id = PCI_VENDOR_ID_VIRTIO,
   .device_id = PCI_DEVICE_ID_VIRTIO_NIC},
  {
   .vendor_id = PCI_VENDOR_ID_VIRTIO,
   .device_id = PCI_DEVICE_ID_VIRTIO_NIC_MODERN},
  {0},
};

static u32
virtio_pci_flag_change (vnet_main_t * vnm, vnet_hw_interface_t * hw,
			u32 flags)
{
  return 0;
}

static clib_error_t *
virtio_pci_get_max_virtqueue_pairs (vlib_main_t * vm, virtio_if_t * vif)
{
  clib_error_t *error = 0;
  u16 max_queue_pairs = 1;

  if (vif->features & VIRTIO_FEATURE (VIRTIO_NET_F_MQ))
    {
      max_queue_pairs = vif->virtio_pci_func->get_max_queue_pairs (vm, vif);
    }

  virtio_log_debug (vif, "max queue pair is %x", max_queue_pairs);
  if (max_queue_pairs < 1 || max_queue_pairs > 0x8000)
    return clib_error_return (error, "max queue pair is %x,"
			      " should be in range [1, 0x8000]",
			      max_queue_pairs);

  vif->max_queue_pairs = max_queue_pairs;
  return error;
}

static void
virtio_pci_set_mac (vlib_main_t * vm, virtio_if_t * vif)
{
  if (vif->features & VIRTIO_FEATURE (VIRTIO_NET_F_MAC))
    vif->virtio_pci_func->set_mac (vm, vif);
}

static u32
virtio_pci_get_mac (vlib_main_t * vm, virtio_if_t * vif)
{
  if (vif->features & VIRTIO_FEATURE (VIRTIO_NET_F_MAC))
    {
      vif->virtio_pci_func->get_mac (vm, vif);
      return 0;
    }
  return 1;
}

static u16
virtio_pci_is_link_up (vlib_main_t * vm, virtio_if_t * vif)
{
  /*
   * Minimal driver: assumes link is up
   */
  u16 status = 1;
  if (vif->features & VIRTIO_FEATURE (VIRTIO_NET_F_STATUS))
    status = vif->virtio_pci_func->get_device_status (vm, vif);
  return status;
}

static void
virtio_pci_irq_queue_handler (vlib_main_t * vm, vlib_pci_dev_handle_t h,
			      u16 line)
{
  vnet_main_t *vnm = vnet_get_main ();
  virtio_main_t *vim = &virtio_main;
  uword pd = vlib_pci_get_private_data (vm, h);
  virtio_if_t *vif = pool_elt_at_index (vim->interfaces, pd);
  line--;
  u16 qid = line;

  vnet_device_input_set_interrupt_pending (vnm, vif->hw_if_index, qid);
}

static void
virtio_pci_irq_config_handler (vlib_main_t * vm, vlib_pci_dev_handle_t h,
			       u16 line)
{
  vnet_main_t *vnm = vnet_get_main ();
  virtio_main_t *vim = &virtio_main;
  uword pd = vlib_pci_get_private_data (vm, h);
  virtio_if_t *vif = pool_elt_at_index (vim->interfaces, pd);

  if (virtio_pci_is_link_up (vm, vif) & VIRTIO_NET_S_LINK_UP)
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
}

static void
virtio_pci_irq_handler (vlib_main_t * vm, vlib_pci_dev_handle_t h)
{
  virtio_main_t *vim = &virtio_main;
  uword pd = vlib_pci_get_private_data (vm, h);
  virtio_if_t *vif = pool_elt_at_index (vim->interfaces, pd);
  u8 isr = 0;
  u16 line = 0;

  isr = vif->virtio_pci_func->get_isr (vm, vif);

  /*
   * If the lower bit is set: look through the used rings of
   * all virtqueues for the device, to see if any progress has
   * been made by the device which requires servicing.
   */
  if (isr & VIRTIO_PCI_ISR_INTR)
    {
      for (; line < vif->num_rxqs; line++)
	virtio_pci_irq_queue_handler (vm, h, (line + 1));
    }

  if (isr & VIRTIO_PCI_ISR_CONFIG)
    virtio_pci_irq_config_handler (vm, h, line);
}

inline void
device_status (vlib_main_t * vm, virtio_if_t * vif)
{
  struct status_struct
  {
    u8 bit;
    char *str;
  };
  struct status_struct *status_entry;
  static struct status_struct status_array[] = {
#define _(s,b) { .str = #s, .bit = b, },
    foreach_virtio_config_status_flags
#undef _
    {.str = NULL}
  };

  vlib_cli_output (vm, "  status 0x%x", vif->status);

  status_entry = (struct status_struct *) &status_array;
  while (status_entry->str)
    {
      if (vif->status & status_entry->bit)
	vlib_cli_output (vm, "    %s (%x)", status_entry->str,
			 status_entry->bit);
      status_entry++;
    }
}

static int
virtio_pci_send_ctrl_msg_packed (vlib_main_t * vm, virtio_if_t * vif,
				 virtio_ctrl_msg_t * data, u32 len)
{
  virtio_vring_t *vring = vif->cxq_vring;
  virtio_net_ctrl_ack_t status = VIRTIO_NET_ERR;
  virtio_ctrl_msg_t result;
  u32 buffer_index;
  vlib_buffer_t *b;
  u16 used, next;
  u16 sz = vring->size;
  u16 flags = 0, first_desc_flags = 0;

  used = vring->desc_in_use;
  next = vring->desc_next;
  vring_packed_desc_t *d = &vring->packed_desc[next];

  if (vlib_buffer_alloc (vm, &buffer_index, 1))
    b = vlib_get_buffer (vm, buffer_index);
  else
    return VIRTIO_NET_ERR;
  /*
   * current_data may not be initialized with 0 and may contain
   * previous offset.
   */
  b->current_data = 0;
  clib_memcpy (vlib_buffer_get_current (b), data, sizeof (virtio_ctrl_msg_t));

  first_desc_flags = VRING_DESC_F_NEXT;
  if (vring->avail_wrap_counter)
    {
      first_desc_flags |= VRING_DESC_F_AVAIL;
      first_desc_flags &= ~VRING_DESC_F_USED;
    }
  else
    {
      first_desc_flags &= ~VRING_DESC_F_AVAIL;
      first_desc_flags |= VRING_DESC_F_USED;
    }
  d->addr = vlib_buffer_get_current_pa (vm, b);
  d->len = sizeof (virtio_net_ctrl_hdr_t);
  d->id = next;

  next++;
  if (next >= sz)
    {
      next = 0;
      vring->avail_wrap_counter ^= 1;
    }
  used++;

  d = &vring->packed_desc[next];
  flags = VRING_DESC_F_NEXT;
  if (vring->avail_wrap_counter)
    {
      flags |= VRING_DESC_F_AVAIL;
      flags &= ~VRING_DESC_F_USED;
    }
  else
    {
      flags &= ~VRING_DESC_F_AVAIL;
      flags |= VRING_DESC_F_USED;
    }
  d->addr = vlib_buffer_get_current_pa (vm, b) +
    STRUCT_OFFSET_OF (virtio_ctrl_msg_t, data);
  d->len = len;
  d->id = next;
  d->flags = flags;

  next++;
  if (next >= sz)
    {
      next = 0;
      vring->avail_wrap_counter ^= 1;
    }
  used++;

  d = &vring->packed_desc[next];
  flags = VRING_DESC_F_WRITE;
  if (vring->avail_wrap_counter)
    {
      flags |= VRING_DESC_F_AVAIL;
      flags &= ~VRING_DESC_F_USED;
    }
  else
    {
      flags &= ~VRING_DESC_F_AVAIL;
      flags |= VRING_DESC_F_USED;
    }
  d->addr = vlib_buffer_get_current_pa (vm, b) +
    STRUCT_OFFSET_OF (virtio_ctrl_msg_t, status);
  d->len = sizeof (data->status);
  d->id = next;
  d->flags = flags;

  next++;
  if (next >= sz)
    {
      next = 0;
      vring->avail_wrap_counter ^= 1;
    }
  used++;

  CLIB_MEMORY_STORE_BARRIER ();
  vring->packed_desc[vring->desc_next].flags = first_desc_flags;
  vring->desc_next = next;
  vring->desc_in_use = used;
  CLIB_MEMORY_BARRIER ();
  if (vring->device_event->flags != VRING_EVENT_F_DISABLE)
    {
      virtio_kick (vm, vring, vif);
    }

  u16 last = vring->last_used_idx;
  d = &vring->packed_desc[last];
  do
    {
      flags = d->flags;
    }
  while ((flags & VRING_DESC_F_AVAIL) != (vring->used_wrap_counter << 7)
	 || (flags & VRING_DESC_F_USED) != (vring->used_wrap_counter << 15));

  last += 3;
  if (last >= vring->size)
    {
      last = last - vring->size;
      vring->used_wrap_counter ^= 1;
    }
  vring->desc_in_use -= 3;
  vring->last_used_idx = last;

  CLIB_MEMORY_BARRIER ();
  clib_memcpy (&result, vlib_buffer_get_current (b),
	       sizeof (virtio_ctrl_msg_t));
  virtio_log_debug (vif, "ctrl-queue: status %u", result.status);
  status = result.status;
  vlib_buffer_free (vm, &buffer_index, 1);
  return status;
}

static int
virtio_pci_send_ctrl_msg_split (vlib_main_t * vm, virtio_if_t * vif,
				virtio_ctrl_msg_t * data, u32 len)
{
  virtio_vring_t *vring = vif->cxq_vring;
  virtio_net_ctrl_ack_t status = VIRTIO_NET_ERR;
  virtio_ctrl_msg_t result;
  u32 buffer_index;
  vlib_buffer_t *b;
  u16 used, next, avail;
  u16 sz = vring->size;
  u16 mask = sz - 1;

  used = vring->desc_in_use;
  next = vring->desc_next;
  avail = vring->avail->idx;
  vring_desc_t *d = &vring->desc[next];

  if (vlib_buffer_alloc (vm, &buffer_index, 1))
    b = vlib_get_buffer (vm, buffer_index);
  else
    return VIRTIO_NET_ERR;
  /*
   * current_data may not be initialized with 0 and may contain
   * previous offset.
   */
  b->current_data = 0;
  clib_memcpy (vlib_buffer_get_current (b), data, sizeof (virtio_ctrl_msg_t));
  d->flags = VRING_DESC_F_NEXT;
  d->addr = vlib_buffer_get_current_pa (vm, b);
  d->len = sizeof (virtio_net_ctrl_hdr_t);
  vring->avail->ring[avail & mask] = next;
  avail++;
  next = (next + 1) & mask;
  d->next = next;
  used++;

  d = &vring->desc[next];
  d->flags = VRING_DESC_F_NEXT;
  d->addr = vlib_buffer_get_current_pa (vm, b) +
    STRUCT_OFFSET_OF (virtio_ctrl_msg_t, data);
  d->len = len;
  next = (next + 1) & mask;
  d->next = next;
  used++;

  d = &vring->desc[next];
  d->flags = VRING_DESC_F_WRITE;
  d->addr = vlib_buffer_get_current_pa (vm, b) +
    STRUCT_OFFSET_OF (virtio_ctrl_msg_t, status);
  d->len = sizeof (data->status);
  next = (next + 1) & mask;
  used++;

  CLIB_MEMORY_STORE_BARRIER ();
  vring->avail->idx = avail;
  vring->desc_next = next;
  vring->desc_in_use = used;

  if ((vring->used->flags & VIRTIO_RING_FLAG_MASK_INT) == 0)
    {
      virtio_kick (vm, vring, vif);
    }

  u16 last = vring->last_used_idx, n_left = 0;
  n_left = vring->used->idx - last;

  while (n_left)
    {
      vring_used_elem_t *e = &vring->used->ring[last & mask];
      u16 slot = e->id;

      d = &vring->desc[slot];
      while (d->flags & VRING_DESC_F_NEXT)
	{
	  used--;
	  slot = d->next;
	  d = &vring->desc[slot];
	}
      used--;
      last++;
      n_left--;
    }
  vring->desc_in_use = used;
  vring->last_used_idx = last;

  CLIB_MEMORY_BARRIER ();
  clib_memcpy (&result, vlib_buffer_get_current (b),
	       sizeof (virtio_ctrl_msg_t));
  virtio_log_debug (vif, "ctrl-queue: status %u", result.status);
  status = result.status;
  vlib_buffer_free (vm, &buffer_index, 1);
  return status;
}

static int
virtio_pci_send_ctrl_msg (vlib_main_t * vm, virtio_if_t * vif,
			  virtio_ctrl_msg_t * data, u32 len)
{
  if (vif->is_packed)
    return virtio_pci_send_ctrl_msg_packed (vm, vif, data, len);
  else
    return virtio_pci_send_ctrl_msg_split (vm, vif, data, len);
}

static int
virtio_pci_disable_offload (vlib_main_t * vm, virtio_if_t * vif)
{
  virtio_ctrl_msg_t offload_hdr;
  virtio_net_ctrl_ack_t status = VIRTIO_NET_ERR;

  offload_hdr.ctrl.class = VIRTIO_NET_CTRL_GUEST_OFFLOADS;
  offload_hdr.ctrl.cmd = VIRTIO_NET_CTRL_GUEST_OFFLOADS_SET;
  offload_hdr.status = VIRTIO_NET_ERR;
  u64 offloads = 0ULL;
  clib_memcpy (offload_hdr.data, &offloads, sizeof (offloads));

  status =
    virtio_pci_send_ctrl_msg (vm, vif, &offload_hdr, sizeof (offloads));
  virtio_log_debug (vif, "disable offloads");
  vif->remote_features = vif->virtio_pci_func->get_device_features (vm, vif);
  vif->virtio_pci_func->get_driver_features (vm, vif);
  return status;
}

static int
virtio_pci_enable_checksum_offload (vlib_main_t * vm, virtio_if_t * vif)
{
  virtio_ctrl_msg_t csum_offload_hdr;
  virtio_net_ctrl_ack_t status = VIRTIO_NET_ERR;

  csum_offload_hdr.ctrl.class = VIRTIO_NET_CTRL_GUEST_OFFLOADS;
  csum_offload_hdr.ctrl.cmd = VIRTIO_NET_CTRL_GUEST_OFFLOADS_SET;
  csum_offload_hdr.status = VIRTIO_NET_ERR;
  u64 offloads = 0ULL;
  offloads |= VIRTIO_FEATURE (VIRTIO_NET_F_GUEST_CSUM);
  clib_memcpy (csum_offload_hdr.data, &offloads, sizeof (offloads));

  status =
    virtio_pci_send_ctrl_msg (vm, vif, &csum_offload_hdr, sizeof (offloads));
  virtio_log_debug (vif, "enable checksum offload");
  vif->remote_features = vif->virtio_pci_func->get_device_features (vm, vif);
  vif->features = vif->virtio_pci_func->get_driver_features (vm, vif);
  return status;
}

static int
virtio_pci_enable_gso (vlib_main_t * vm, virtio_if_t * vif)
{
  virtio_ctrl_msg_t gso_hdr;
  virtio_net_ctrl_ack_t status = VIRTIO_NET_ERR;

  gso_hdr.ctrl.class = VIRTIO_NET_CTRL_GUEST_OFFLOADS;
  gso_hdr.ctrl.cmd = VIRTIO_NET_CTRL_GUEST_OFFLOADS_SET;
  gso_hdr.status = VIRTIO_NET_ERR;
  u64 offloads = VIRTIO_FEATURE (VIRTIO_NET_F_GUEST_CSUM)
    | VIRTIO_FEATURE (VIRTIO_NET_F_GUEST_TSO4)
    | VIRTIO_FEATURE (VIRTIO_NET_F_GUEST_TSO6);
  clib_memcpy (gso_hdr.data, &offloads, sizeof (offloads));

  status = virtio_pci_send_ctrl_msg (vm, vif, &gso_hdr, sizeof (offloads));
  virtio_log_debug (vif, "enable gso");
  vif->remote_features = vif->virtio_pci_func->get_device_features (vm, vif);
  vif->virtio_pci_func->get_driver_features (vm, vif);
  return status;
}

static int
virtio_pci_offloads (vlib_main_t * vm, virtio_if_t * vif, int gso_enabled,
		     int csum_offload_enabled)
{
  vnet_main_t *vnm = vnet_get_main ();
  vnet_hw_interface_t *hw = vnet_get_hw_interface (vnm, vif->hw_if_index);

  if ((vif->features & VIRTIO_FEATURE (VIRTIO_NET_F_CTRL_VQ)) &&
      (vif->features & VIRTIO_FEATURE (VIRTIO_NET_F_CTRL_GUEST_OFFLOADS)))
    {
      if (gso_enabled
	  && (vif->features & (VIRTIO_FEATURE (VIRTIO_NET_F_HOST_TSO4) |
			       VIRTIO_FEATURE (VIRTIO_NET_F_HOST_TSO6))))
	{
	  if (virtio_pci_enable_gso (vm, vif))
	    {
	      virtio_log_warning (vif, "gso is not enabled");
	    }
	  else
	    {
	      vif->gso_enabled = 1;
	      vif->csum_offload_enabled = 0;
	      hw->caps |=
		VNET_HW_INTERFACE_CAP_SUPPORTS_TCP_GSO |
		VNET_HW_INTERFACE_CAP_SUPPORTS_TX_TCP_CKSUM |
		VNET_HW_INTERFACE_CAP_SUPPORTS_TX_UDP_CKSUM;
	    }
	}
      else if (csum_offload_enabled
	       && (vif->features & VIRTIO_FEATURE (VIRTIO_NET_F_CSUM)))
	{
	  if (virtio_pci_enable_checksum_offload (vm, vif))
	    {
	      virtio_log_warning (vif, "checksum offload is not enabled");
	    }
	  else
	    {
	      vif->csum_offload_enabled = 1;
	      vif->gso_enabled = 0;
	      hw->caps &= ~VNET_HW_INTERFACE_CAP_SUPPORTS_TCP_GSO;
	      hw->caps |=
		VNET_HW_INTERFACE_CAP_SUPPORTS_TX_TCP_CKSUM |
		VNET_HW_INTERFACE_CAP_SUPPORTS_TX_UDP_CKSUM;
	    }
	}
      else
	{
	  if (virtio_pci_disable_offload (vm, vif))
	    {
	      virtio_log_warning (vif, "offloads are not disabled");
	    }
	  else
	    {
	      vif->csum_offload_enabled = 0;
	      vif->gso_enabled = 0;
	      hw->caps &=
		~(VNET_HW_INTERFACE_OFFLOAD_FLAG_SUPPORTS_L4_TX_CKSUM |
		  VNET_HW_INTERFACE_CAP_SUPPORTS_TCP_GSO);
	    }
	}
    }

  return 0;
}

static int
virtio_pci_enable_multiqueue (vlib_main_t * vm, virtio_if_t * vif,
			      u16 num_queues)
{
  virtio_ctrl_msg_t mq_hdr;
  virtio_net_ctrl_ack_t status = VIRTIO_NET_ERR;

  mq_hdr.ctrl.class = VIRTIO_NET_CTRL_MQ;
  mq_hdr.ctrl.cmd = VIRTIO_NET_CTRL_MQ_VQ_PAIRS_SET;
  mq_hdr.status = VIRTIO_NET_ERR;
  clib_memcpy (mq_hdr.data, &num_queues, sizeof (num_queues));

  status = virtio_pci_send_ctrl_msg (vm, vif, &mq_hdr, sizeof (num_queues));
  virtio_log_debug (vif, "multi-queue enable %u queues", num_queues);
  return status;
}

static u8
virtio_pci_queue_size_valid (u16 qsz)
{
  if (qsz < 64 || qsz > 4096)
    return 0;
  if ((qsz % 64) != 0)
    return 0;
  return 1;
}

clib_error_t *
virtio_pci_control_vring_packed_init (vlib_main_t * vm, virtio_if_t * vif,
				      u16 queue_num)
{
  clib_error_t *error = 0;
  u16 queue_size = 0;
  virtio_vring_t *vring;
  u32 i = 0;
  void *ptr = NULL;

  queue_size = vif->virtio_pci_func->get_queue_size (vm, vif, queue_num);

  if (queue_size > 32768)
    return clib_error_return (0, "ring size must be 32768 or lower");

  if (queue_size == 0)
    queue_size = 256;

  vec_validate_aligned (vif->cxq_vring, 0, CLIB_CACHE_LINE_BYTES);
  vring = vec_elt_at_index (vif->cxq_vring, 0);

  i =
    (((queue_size * sizeof (vring_packed_desc_t)) +
      sizeof (vring_desc_event_t) + VIRTIO_PCI_VRING_ALIGN -
      1) & ~(VIRTIO_PCI_VRING_ALIGN - 1)) + sizeof (vring_desc_event_t);

  ptr =
    vlib_physmem_alloc_aligned_on_numa (vm, i, VIRTIO_PCI_VRING_ALIGN,
					vif->numa_node);
  if (!ptr)
    return vlib_physmem_last_error (vm);
  clib_memset (ptr, 0, i);

  vring->packed_desc = ptr;

  vring->driver_event = ptr + (queue_size * sizeof (vring_packed_desc_t));
  vring->driver_event->off_wrap = 0;
  vring->driver_event->flags = VRING_EVENT_F_DISABLE;

  vring->device_event =
    ptr +
    (((queue_size * sizeof (vring_packed_desc_t)) +
      sizeof (vring_desc_event_t) + VIRTIO_PCI_VRING_ALIGN -
      1) & ~(VIRTIO_PCI_VRING_ALIGN - 1));
  vring->device_event->off_wrap = 0;
  vring->device_event->flags = 0;

  vring->queue_id = queue_num;
  vring->size = queue_size;
  vring->avail_wrap_counter = 1;
  vring->used_wrap_counter = 1;

  ASSERT (vring->buffers == 0);

  virtio_log_debug (vif, "control-queue: number %u, size %u", queue_num,
		    queue_size);
  vif->virtio_pci_func->setup_queue (vm, vif, queue_num, (void *) vring);
  vring->queue_notify_offset =
    vif->notify_off_multiplier *
    vif->virtio_pci_func->get_queue_notify_off (vm, vif, queue_num);
  virtio_log_debug (vif, "queue-notify-offset: number %u, offset %u",
		    queue_num, vring->queue_notify_offset);
  return error;
}

clib_error_t *
virtio_pci_control_vring_split_init (vlib_main_t * vm, virtio_if_t * vif,
				     u16 queue_num)
{
  clib_error_t *error = 0;
  u16 queue_size = 0;
  virtio_vring_t *vring;
  vring_t vr;
  u32 i = 0;
  void *ptr = NULL;

  queue_size = vif->virtio_pci_func->get_queue_size (vm, vif, queue_num);
  if (!virtio_pci_queue_size_valid (queue_size))
    clib_warning ("queue size is not valid");

  if (!is_pow2 (queue_size))
    return clib_error_return (0, "ring size must be power of 2");

  if (queue_size > 32768)
    return clib_error_return (0, "ring size must be 32768 or lower");

  if (queue_size == 0)
    queue_size = 256;

  vec_validate_aligned (vif->cxq_vring, 0, CLIB_CACHE_LINE_BYTES);
  vring = vec_elt_at_index (vif->cxq_vring, 0);
  i = vring_size (queue_size, VIRTIO_PCI_VRING_ALIGN);
  i = round_pow2 (i, VIRTIO_PCI_VRING_ALIGN);
  ptr =
    vlib_physmem_alloc_aligned_on_numa (vm, i, VIRTIO_PCI_VRING_ALIGN,
					vif->numa_node);
  if (!ptr)
    return vlib_physmem_last_error (vm);
  clib_memset (ptr, 0, i);
  vring_init (&vr, queue_size, ptr, VIRTIO_PCI_VRING_ALIGN);
  vring->desc = vr.desc;
  vring->avail = vr.avail;
  vring->used = vr.used;
  vring->queue_id = queue_num;
  vring->avail->flags = VIRTIO_RING_FLAG_MASK_INT;

  ASSERT (vring->buffers == 0);

  vring->size = queue_size;
  virtio_log_debug (vif, "control-queue: number %u, size %u", queue_num,
		    queue_size);
  vif->virtio_pci_func->setup_queue (vm, vif, queue_num, ptr);
  vring->queue_notify_offset =
    vif->notify_off_multiplier *
    vif->virtio_pci_func->get_queue_notify_off (vm, vif, queue_num);
  virtio_log_debug (vif, "queue-notify-offset: number %u, offset %u",
		    queue_num, vring->queue_notify_offset);

  return error;
}

clib_error_t *
virtio_pci_control_vring_init (vlib_main_t * vm, virtio_if_t * vif,
			       u16 queue_num)
{
  if (vif->is_packed)
    return virtio_pci_control_vring_packed_init (vm, vif, queue_num);
  else
    return virtio_pci_control_vring_split_init (vm, vif, queue_num);
}

clib_error_t *
virtio_pci_vring_split_init (vlib_main_t * vm, virtio_if_t * vif,
			     u16 queue_num)
{
  vlib_thread_main_t *vtm = vlib_get_thread_main ();
  clib_error_t *error = 0;
  u16 queue_size = 0;
  virtio_vring_t *vring;
  vring_t vr;
  u32 i = 0;
  void *ptr = NULL;

  queue_size = vif->virtio_pci_func->get_queue_size (vm, vif, queue_num);
  if (!virtio_pci_queue_size_valid (queue_size))
    clib_warning ("queue size is not valid");

  if (!is_pow2 (queue_size))
    return clib_error_return (0, "ring size must be power of 2");

  if (queue_size > 32768)
    return clib_error_return (0, "ring size must be 32768 or lower");

  if (queue_size == 0)
    queue_size = 256;

  if (queue_num % 2)
    {
      vec_validate_aligned (vif->txq_vrings, TX_QUEUE_ACCESS (queue_num),
			    CLIB_CACHE_LINE_BYTES);
      vring = vec_elt_at_index (vif->txq_vrings, TX_QUEUE_ACCESS (queue_num));
      if (vif->max_queue_pairs < vtm->n_vlib_mains)
	clib_spinlock_init (&vring->lockp);
    }
  else
    {
      vec_validate_aligned (vif->rxq_vrings, RX_QUEUE_ACCESS (queue_num),
			    CLIB_CACHE_LINE_BYTES);
      vring = vec_elt_at_index (vif->rxq_vrings, RX_QUEUE_ACCESS (queue_num));
    }
  i = vring_size (queue_size, VIRTIO_PCI_VRING_ALIGN);
  i = round_pow2 (i, VIRTIO_PCI_VRING_ALIGN);
  ptr =
    vlib_physmem_alloc_aligned_on_numa (vm, i, VIRTIO_PCI_VRING_ALIGN,
					vif->numa_node);
  if (!ptr)
    return vlib_physmem_last_error (vm);
  clib_memset (ptr, 0, i);
  vring_init (&vr, queue_size, ptr, VIRTIO_PCI_VRING_ALIGN);
  vring->desc = vr.desc;
  vring->avail = vr.avail;
  vring->used = vr.used;
  vring->queue_id = queue_num;
  vring->avail->flags = VIRTIO_RING_FLAG_MASK_INT;
  vring->flow_table = 0;

  ASSERT (vring->buffers == 0);
  vec_validate_aligned (vring->buffers, queue_size, CLIB_CACHE_LINE_BYTES);
  if (queue_num % 2)
    {
      virtio_log_debug (vif, "tx-queue: number %u, size %u", queue_num,
			queue_size);
      clib_memset_u32 (vring->buffers, ~0, queue_size);
    }
  else
    {
      virtio_log_debug (vif, "rx-queue: number %u, size %u", queue_num,
			queue_size);
    }
  vring->size = queue_size;
  if (vif->virtio_pci_func->setup_queue (vm, vif, queue_num, ptr))
    return clib_error_return (0, "error in queue address setup");

  vring->queue_notify_offset =
    vif->notify_off_multiplier *
    vif->virtio_pci_func->get_queue_notify_off (vm, vif, queue_num);
  virtio_log_debug (vif, "queue-notify-offset: number %u, offset %u",
		    queue_num, vring->queue_notify_offset);
  return error;
}

clib_error_t *
virtio_pci_vring_packed_init (vlib_main_t * vm, virtio_if_t * vif,
			      u16 queue_num)
{
  vlib_thread_main_t *vtm = vlib_get_thread_main ();
  clib_error_t *error = 0;
  u16 queue_size = 0;
  virtio_vring_t *vring;
  u32 i = 0;
  void *ptr = NULL;

  queue_size = vif->virtio_pci_func->get_queue_size (vm, vif, queue_num);

  if (queue_size > 32768)
    return clib_error_return (0, "ring size must be 32768 or lower");

  if (queue_size == 0)
    queue_size = 256;

  if (queue_num % 2)
    {
      vec_validate_aligned (vif->txq_vrings, TX_QUEUE_ACCESS (queue_num),
			    CLIB_CACHE_LINE_BYTES);
      vring = vec_elt_at_index (vif->txq_vrings, TX_QUEUE_ACCESS (queue_num));
      if (vif->max_queue_pairs < vtm->n_vlib_mains)
	clib_spinlock_init (&vring->lockp);
    }
  else
    {
      vec_validate_aligned (vif->rxq_vrings, RX_QUEUE_ACCESS (queue_num),
			    CLIB_CACHE_LINE_BYTES);
      vring = vec_elt_at_index (vif->rxq_vrings, RX_QUEUE_ACCESS (queue_num));
    }

  i =
    (((queue_size * sizeof (vring_packed_desc_t)) +
      sizeof (vring_desc_event_t) + VIRTIO_PCI_VRING_ALIGN -
      1) & ~(VIRTIO_PCI_VRING_ALIGN - 1)) + sizeof (vring_desc_event_t);

  ptr =
    vlib_physmem_alloc_aligned_on_numa (vm, i, VIRTIO_PCI_VRING_ALIGN,
					vif->numa_node);
  if (!ptr)
    return vlib_physmem_last_error (vm);

  clib_memset (ptr, 0, i);
  vring->packed_desc = ptr;

  vring->driver_event = ptr + (queue_size * sizeof (vring_packed_desc_t));
  vring->driver_event->off_wrap = 0;
  vring->driver_event->flags = VRING_EVENT_F_DISABLE;

  vring->device_event =
    ptr +
    (((queue_size * sizeof (vring_packed_desc_t)) +
      sizeof (vring_desc_event_t) + VIRTIO_PCI_VRING_ALIGN -
      1) & ~(VIRTIO_PCI_VRING_ALIGN - 1));
  vring->device_event->off_wrap = 0;
  vring->device_event->flags = 0;

  vring->queue_id = queue_num;

  vring->avail_wrap_counter = 1;
  vring->used_wrap_counter = 1;

  ASSERT (vring->buffers == 0);
  vec_validate_aligned (vring->buffers, queue_size, CLIB_CACHE_LINE_BYTES);
  if (queue_num % 2)
    {
      virtio_log_debug (vif, "tx-queue: number %u, size %u", queue_num,
			queue_size);
      clib_memset_u32 (vring->buffers, ~0, queue_size);
    }
  else
    {
      virtio_log_debug (vif, "rx-queue: number %u, size %u", queue_num,
			queue_size);
    }
  vring->size = queue_size;
  if (vif->virtio_pci_func->setup_queue (vm, vif, queue_num, (void *) vring))
    return clib_error_return (0, "error in queue address setup");

  vring->queue_notify_offset =
    vif->notify_off_multiplier *
    vif->virtio_pci_func->get_queue_notify_off (vm, vif, queue_num);
  virtio_log_debug (vif, "queue-notify-offset: number %u, offset %u",
		    queue_num, vring->queue_notify_offset);

  return error;
}

clib_error_t *
virtio_pci_vring_init (vlib_main_t * vm, virtio_if_t * vif, u16 queue_num)
{
  if (vif->is_packed)
    return virtio_pci_vring_packed_init (vm, vif, queue_num);
  else
    return virtio_pci_vring_split_init (vm, vif, queue_num);
}

static void
virtio_negotiate_features (vlib_main_t * vm, virtio_if_t * vif,
			   u64 req_features)
{
  /*
   * if features are not requested
   * default: all supported features
   */
  u64 supported_features = VIRTIO_FEATURE (VIRTIO_NET_F_CSUM)
    | VIRTIO_FEATURE (VIRTIO_NET_F_GUEST_CSUM)
    | VIRTIO_FEATURE (VIRTIO_NET_F_CTRL_GUEST_OFFLOADS)
    | VIRTIO_FEATURE (VIRTIO_NET_F_MTU)
    | VIRTIO_FEATURE (VIRTIO_NET_F_MAC)
    | VIRTIO_FEATURE (VIRTIO_NET_F_GSO)
    | VIRTIO_FEATURE (VIRTIO_NET_F_GUEST_TSO4)
    | VIRTIO_FEATURE (VIRTIO_NET_F_GUEST_TSO6)
    | VIRTIO_FEATURE (VIRTIO_NET_F_GUEST_UFO)
    | VIRTIO_FEATURE (VIRTIO_NET_F_HOST_TSO4)
    | VIRTIO_FEATURE (VIRTIO_NET_F_HOST_TSO6)
    | VIRTIO_FEATURE (VIRTIO_NET_F_HOST_UFO)
    | VIRTIO_FEATURE (VIRTIO_NET_F_MRG_RXBUF)
    | VIRTIO_FEATURE (VIRTIO_NET_F_STATUS)
    | VIRTIO_FEATURE (VIRTIO_NET_F_CTRL_VQ)
    | VIRTIO_FEATURE (VIRTIO_NET_F_MQ)
    | VIRTIO_FEATURE (VIRTIO_F_NOTIFY_ON_EMPTY)
    | VIRTIO_FEATURE (VIRTIO_F_ANY_LAYOUT)
    | VIRTIO_FEATURE (VIRTIO_RING_F_INDIRECT_DESC);

  if (vif->is_modern)
    supported_features |= VIRTIO_FEATURE (VIRTIO_F_VERSION_1);

  if (vif->is_packed)
    {
      supported_features |=
	(VIRTIO_FEATURE (VIRTIO_F_RING_PACKED) |
	 VIRTIO_FEATURE (VIRTIO_F_IN_ORDER));
    }

  if (req_features == 0)
    {
      req_features = supported_features;
    }

  vif->features = req_features & vif->remote_features & supported_features;

  if (vif->features & VIRTIO_FEATURE (VIRTIO_NET_F_MTU))
    {
      u16 mtu = 0;
      mtu = vif->virtio_pci_func->get_mtu (vm, vif);

      if (mtu < 64)
	vif->features &= ~VIRTIO_FEATURE (VIRTIO_NET_F_MTU);
    }

  if ((vif->features & (VIRTIO_FEATURE (VIRTIO_F_RING_PACKED))) == 0)
    vif->is_packed = 0;

  vif->virtio_pci_func->set_driver_features (vm, vif, vif->features);
  vif->features = vif->virtio_pci_func->get_driver_features (vm, vif);
}

void
virtio_pci_read_device_feature (vlib_main_t * vm, virtio_if_t * vif)
{
  vif->remote_features = vif->virtio_pci_func->get_device_features (vm, vif);
}

int
virtio_pci_reset_device (vlib_main_t * vm, virtio_if_t * vif)
{
  u8 status = 0;

  /*
   * Reset the device
   */
  status = vif->virtio_pci_func->device_reset (vm, vif);

  /*
   * Set the Acknowledge status bit
   */
  vif->virtio_pci_func->set_status (vm, vif, VIRTIO_CONFIG_STATUS_ACK);

  /*
   * Set the Driver status bit
   */
  vif->virtio_pci_func->set_status (vm, vif, VIRTIO_CONFIG_STATUS_DRIVER);

  /*
   * Read the status and verify it
   */
  status = vif->virtio_pci_func->get_status (vm, vif);
  if ((status & VIRTIO_CONFIG_STATUS_ACK)
      && (status & VIRTIO_CONFIG_STATUS_DRIVER))
    vif->status = status;
  else
    return -1;

  return 0;
}

clib_error_t *
virtio_pci_read_caps (vlib_main_t * vm, virtio_if_t * vif, void **bar)
{
  clib_error_t *error = 0;
  virtio_pci_cap_t cap;
  u8 pos, common_cfg = 0, notify = 0, dev_cfg = 0, isr = 0, pci_cfg = 0;
  vlib_pci_dev_handle_t h = vif->pci_dev_handle;

  if ((error = vlib_pci_read_config_u8 (vm, h, PCI_CAPABILITY_LIST, &pos)))
    {
      virtio_log_error (vif, "error in reading capabilty list position");
      return clib_error_return (error,
				"error in reading capabilty list position");
    }
  while (pos)
    {
      if ((error =
	   vlib_pci_read_write_config (vm, h, VLIB_READ, pos, &cap,
				       sizeof (cap))))
	{
	  virtio_log_error (vif, "%s [%2x]",
			    "error in reading the capability at", pos);
	  return clib_error_return (error,
				    "error in reading the capability at [%2x]",
				    pos);
	}

      if (cap.cap_vndr == PCI_CAP_ID_MSIX)
	{
	  u16 flags, table_size, table_size_mask = 0x07FF;

	  if ((error =
	       vlib_pci_read_write_config (vm, h, VLIB_READ, pos + 2, &flags,
					   sizeof (flags))))
	    return clib_error_return (error,
				      "error in reading the capability at [%2x]",
				      pos + 2);

	  table_size = flags & table_size_mask;
	  virtio_log_debug (vif, "flags:0x%x %s 0x%x", flags,
			    "msix interrupt vector table-size", table_size);

	  if (flags & PCI_MSIX_ENABLE)
	    {
	      virtio_log_debug (vif, "msix interrupt enabled");
	      vif->msix_enabled = VIRTIO_MSIX_ENABLED;
	      vif->msix_table_size = table_size;
	    }
	  else
	    {
	      virtio_log_debug (vif, "msix interrupt disabled");
	      vif->msix_enabled = VIRTIO_MSIX_DISABLED;
	      vif->msix_table_size = 0;
	    }
	}

      if (cap.cap_vndr != PCI_CAP_ID_VNDR)
	{
	  virtio_log_debug (vif, "[%2x] %s %2x ", pos,
			    "skipping non VNDR cap id:", cap.cap_vndr);
	  goto next;
	}

      virtio_log_debug (vif,
			"[%4x] cfg type: %u, bar: %u, offset: %04x, len: %u",
			pos, cap.cfg_type, cap.bar, cap.offset, cap.length);

      if (cap.bar >= 0 && cap.bar <= 5)
	{
	  vif->bar = bar[cap.bar];
	  vif->bar_id = cap.bar;
	}
      else
	return clib_error_return (error, "invalid bar %u", cap.bar);

      switch (cap.cfg_type)
	{
	case VIRTIO_PCI_CAP_COMMON_CFG:
	  vif->common_offset = cap.offset;
	  common_cfg = 1;
	  break;
	case VIRTIO_PCI_CAP_NOTIFY_CFG:
	  if ((error =
	       vlib_pci_read_write_config (vm, h, VLIB_READ,
					   pos + sizeof (cap),
					   &vif->notify_off_multiplier,
					   sizeof
					   (vif->notify_off_multiplier))))
	    {
	      virtio_log_error (vif, "notify off multiplier is not given");
	    }
	  else
	    {
	      virtio_log_debug (vif, "notify off multiplier is %u",
				vif->notify_off_multiplier);
	      vif->notify_offset = cap.offset;
	      notify = 1;
	    }
	  break;
	case VIRTIO_PCI_CAP_DEVICE_CFG:
	  vif->device_offset = cap.offset;
	  dev_cfg = 1;
	  break;
	case VIRTIO_PCI_CAP_ISR_CFG:
	  vif->isr_offset = cap.offset;
	  isr = 1;
	  break;
	case VIRTIO_PCI_CAP_PCI_CFG:
	  if (cap.bar == 0)
	    pci_cfg = 1;
	  break;
	}
    next:
      pos = cap.cap_next;
    }

  if (common_cfg == 0 || notify == 0 || dev_cfg == 0 || isr == 0)
    {
      vif->virtio_pci_func = &virtio_pci_legacy_func;
      vif->notify_off_multiplier = 0;
      virtio_log_debug (vif, "legacy virtio pci device found");
      return error;
    }

  vif->is_modern = 1;
  vif->virtio_pci_func = &virtio_pci_modern_func;

  if (!pci_cfg)
    {
      virtio_log_debug (vif, "modern virtio pci device found");
    }
  else
    {
      virtio_log_debug (vif, "transitional virtio pci device found");
    }

  return error;
}

static clib_error_t *
virtio_pci_device_init (vlib_main_t * vm, virtio_if_t * vif,
			virtio_pci_create_if_args_t * args, void **bar)
{
  clib_error_t *error = 0;
  vlib_thread_main_t *vtm = vlib_get_thread_main ();
  u8 status = 0;

  if ((error = virtio_pci_read_caps (vm, vif, bar)))
    {
      args->rv = VNET_API_ERROR_UNSUPPORTED;
      virtio_log_error (vif, "Device is not supported");
      return clib_error_return (error, "Device is not supported");
    }

  if (virtio_pci_reset_device (vm, vif) < 0)
    {
      args->rv = VNET_API_ERROR_INIT_FAILED;
      virtio_log_error (vif, "Failed to reset the device");
      return clib_error_return (error, "Failed to reset the device");
    }
  /*
   * read device features and negotiate (user) requested features
   */
  virtio_pci_read_device_feature (vm, vif);
  if ((vif->remote_features & VIRTIO_FEATURE (VIRTIO_RING_F_INDIRECT_DESC)) ==
      0)
    {
      virtio_log_warning (vif, "error encountered: vhost-net backend doesn't "
			  "support VIRTIO_RING_F_INDIRECT_DESC features");
    }
  if ((vif->remote_features & VIRTIO_FEATURE (VIRTIO_NET_F_MRG_RXBUF)) == 0)
    {
      virtio_log_warning (vif, "error encountered: vhost-net backend doesn't "
			  "support VIRTIO_NET_F_MRG_RXBUF features");
    }
  virtio_negotiate_features (vm, vif, args->features);

  /*
   * After FEATURE_OK, driver should not accept new feature bits
   */
  vif->virtio_pci_func->set_status (vm, vif,
				    VIRTIO_CONFIG_STATUS_FEATURES_OK);
  status = vif->virtio_pci_func->get_status (vm, vif);
  if (!(status & VIRTIO_CONFIG_STATUS_FEATURES_OK))
    {
      args->rv = VNET_API_ERROR_UNSUPPORTED;
      virtio_log_error (vif,
			"error encountered: Device doesn't support requested features");
      return clib_error_return (error,
				"Device doesn't support requested features");
    }
  vif->status = status;

  /*
   * get or set the mac address
   */
  if (virtio_pci_get_mac (vm, vif))
    {
      f64 now = vlib_time_now (vm);
      u32 rnd;
      rnd = (u32) (now * 1e6);
      rnd = random_u32 (&rnd);

      memcpy (vif->mac_addr + 2, &rnd, sizeof (rnd));
      vif->mac_addr[0] = 2;
      vif->mac_addr[1] = 0xfe;
      virtio_pci_set_mac (vm, vif);
    }

  virtio_set_net_hdr_size (vif);

  /*
   * Initialize the virtqueues
   */
  if ((error = virtio_pci_get_max_virtqueue_pairs (vm, vif)))
    {
      args->rv = VNET_API_ERROR_EXCEEDED_NUMBER_OF_RANGES_CAPACITY;
      goto err;
    }

  if (vif->msix_enabled == VIRTIO_MSIX_ENABLED)
    {
      if (vif->msix_table_size <= vif->max_queue_pairs)
	{
	  virtio_log_error (vif,
			    "error MSIX lines (%u) <= Number of RXQs (%u)",
			    vif->msix_table_size, vif->max_queue_pairs);
	  return clib_error_return (error,
				    "error MSIX lines (%u) <= Number of RXQs (%u)",
				    vif->msix_table_size,
				    vif->max_queue_pairs);
	}
    }

  for (int i = 0; i < vif->max_queue_pairs; i++)
    {
      if ((error = virtio_pci_vring_init (vm, vif, RX_QUEUE (i))))
	{
	  args->rv = VNET_API_ERROR_INIT_FAILED;
	  virtio_log_error (vif, "%s (%u) %s", "error in rxq-queue",
			    RX_QUEUE (i), "initialization");
	  error =
	    clib_error_return (error, "%s (%u) %s", "error in rxq-queue",
			       RX_QUEUE (i), "initialization");
	  goto err;
	}
      else
	{
	  vif->num_rxqs++;
	}

      if (i >= vtm->n_vlib_mains)
	{
	  /*
	   * There is 1:1 mapping between tx queue and vpp worker thread.
	   * tx queue 0 is bind with thread index 0, tx queue 1 on thread
	   * index 1 and so on.
	   * Multiple worker threads can poll same tx queue when number of
	   * workers are more than tx queues. In this case, 1:N mapping
	   * between tx queue and vpp worker thread.
	   */
	  virtio_log_debug (vif, "%s %u, %s", "tx-queue: number",
			    TX_QUEUE (i),
			    "no VPP worker thread is available");
	  continue;
	}

      if ((error = virtio_pci_vring_init (vm, vif, TX_QUEUE (i))))
	{
	  args->rv = VNET_API_ERROR_INIT_FAILED;
	  virtio_log_error (vif, "%s (%u) %s", "error in txq-queue",
			    TX_QUEUE (i), "initialization");
	  error =
	    clib_error_return (error, "%s (%u) %s", "error in txq-queue",
			       TX_QUEUE (i), "initialization");
	  goto err;
	}
      else
	{
	  vif->num_txqs++;
	}
    }

  if (vif->features & VIRTIO_FEATURE (VIRTIO_NET_F_CTRL_VQ))
    {
      if ((error =
	   virtio_pci_control_vring_init (vm, vif, vif->max_queue_pairs * 2)))
	{
	  virtio_log_warning (vif, "%s (%u) %s", "error in control-queue",
			      vif->max_queue_pairs * 2, "initialization");
	  if (vif->features & VIRTIO_FEATURE (VIRTIO_NET_F_MQ))
	    vif->features &= ~VIRTIO_FEATURE (VIRTIO_NET_F_MQ);
	}
    }
  else
    {
      virtio_log_debug (vif, "control queue is not available");
      vif->cxq_vring = NULL;
    }

  /*
   * set the msix interrupts
   */
  if (vif->msix_enabled == VIRTIO_MSIX_ENABLED)
    {
      int i, j;
      if (vif->virtio_pci_func->set_config_irq (vm, vif, 0) ==
	  VIRTIO_MSI_NO_VECTOR)
	{
	  virtio_log_warning (vif, "config vector 0 is not set");
	}
      else
	{
	  virtio_log_debug (vif, "config msix vector is set at 0");
	}
      for (i = 0, j = 1; i < vif->max_queue_pairs; i++, j++)
	{
	  if (vif->virtio_pci_func->set_queue_irq (vm, vif, j,
						   RX_QUEUE (i)) ==
	      VIRTIO_MSI_NO_VECTOR)
	    {
	      virtio_log_warning (vif, "queue (%u) vector is not set at %u",
				  RX_QUEUE (i), j);
	    }
	  else
	    {
	      virtio_log_debug (vif, "%s (%u) %s %u", "queue",
				RX_QUEUE (i), "msix vector is set at", j);
	    }
	}
    }

  /*
   * set the driver status OK
   */
  vif->virtio_pci_func->set_status (vm, vif, VIRTIO_CONFIG_STATUS_DRIVER_OK);
  vif->status = vif->virtio_pci_func->get_status (vm, vif);
err:
  return error;
}

void
virtio_pci_create_if (vlib_main_t * vm, virtio_pci_create_if_args_t * args)
{
  vnet_main_t *vnm = vnet_get_main ();
  virtio_main_t *vim = &virtio_main;
  virtio_if_t *vif;
  vlib_pci_dev_handle_t h;
  clib_error_t *error = 0;
  u32 interrupt_count = 0;

  /* *INDENT-OFF* */
  pool_foreach (vif, vim->interfaces, ({
    if (vif->pci_addr.as_u32 == args->addr)
      {
	args->rv = VNET_API_ERROR_ADDRESS_IN_USE;
	args->error =
	  clib_error_return (error, "PCI address in use");
	  vlib_log (VLIB_LOG_LEVEL_ERR, vim->log_default, "%U: %s",
                format_vlib_pci_addr, &args->addr,
                " PCI address in use");
	return;
      }
  }));
  /* *INDENT-ON* */

  pool_get (vim->interfaces, vif);
  vif->dev_instance = vif - vim->interfaces;
  vif->per_interface_next_index = ~0;
  vif->pci_addr.as_u32 = args->addr;
  if (args->virtio_flags & VIRTIO_FLAG_PACKED)
    vif->is_packed = 1;

  if ((error =
       vlib_pci_device_open (vm, (vlib_pci_addr_t *) & vif->pci_addr,
			     virtio_pci_device_ids, &h)))
    {
      args->rv = VNET_API_ERROR_INVALID_INTERFACE;
      args->error =
	clib_error_return (error, "pci-addr %U", format_vlib_pci_addr,
			   &vif->pci_addr);
      vlib_log (VLIB_LOG_LEVEL_ERR, vim->log_default, "%U: %s",
		format_vlib_pci_addr, &vif->pci_addr,
		"error encountered on pci device open");
      pool_put (vim->interfaces, vif);
      return;
    }
  vif->pci_dev_handle = h;
  vlib_pci_set_private_data (vm, h, vif->dev_instance);
  vif->numa_node = vlib_pci_get_numa_node (vm, h);
  vif->type = VIRTIO_IF_TYPE_PCI;

  if ((error = vlib_pci_bus_master_enable (vm, h)))
    {
      virtio_log_error (vif, "error encountered on pci bus master enable");
      goto error;
    }

  void *bar[6];
  for (u32 i = 0; i <= 5; i++)
    {

      if ((error = vlib_pci_map_region (vm, h, i, &bar[i])))
	{
	  virtio_log_debug (vif, "no pci map region for bar %u", i);
	}
      else
	{
	  virtio_log_debug (vif, "pci map region for bar %u at %p", i,
			    bar[i]);
	}
    }

  if ((error = vlib_pci_io_region (vm, h, 0)))
    {
      virtio_log_error (vif, "error encountered on pci io region");
      goto error;
    }

  interrupt_count = vlib_pci_get_num_msix_interrupts (vm, h);
  if (interrupt_count > 1)
    {
      if ((error = vlib_pci_register_msix_handler (vm, h, 0, 1,
						   &virtio_pci_irq_config_handler)))
	{
	  args->rv = VNET_API_ERROR_INVALID_REGISTRATION;
	  virtio_log_error (vif,
			    "error encountered on pci register msix handler 0");
	  goto error;
	}

      if ((error =
	   vlib_pci_register_msix_handler (vm, h, 1, (interrupt_count - 1),
					   &virtio_pci_irq_queue_handler)))
	{
	  args->rv = VNET_API_ERROR_INVALID_REGISTRATION;
	  virtio_log_error (vif,
			    "error encountered on pci register msix handler 1");
	  goto error;
	}

      if ((error = vlib_pci_enable_msix_irq (vm, h, 0, interrupt_count)))
	{
	  virtio_log_error (vif, "error encountered on pci enable msix irq");
	  goto error;
	}
      vif->support_int_mode = 1;
      virtio_log_debug (vif, "device supports msix interrupts");
    }
  else if (interrupt_count == 1)
    {
      /*
       * if msix table-size is 1, fall back to intX.
       */
      if ((error =
	   vlib_pci_register_intx_handler (vm, h, &virtio_pci_irq_handler)))
	{
	  virtio_log_error (vif,
			    "error encountered on pci register interrupt handler");
	  goto error;
	}
      vif->support_int_mode = 1;
      virtio_log_debug (vif, "pci register interrupt handler");
    }
  else
    {
      /*
       * WARN: intX is showing some weird behaviour.
       * Please don't use interrupt mode with UIO driver.
       */
      vif->support_int_mode = 0;
      virtio_log_debug (vif, "driver is configured in poll mode only");
    }

  if ((error = vlib_pci_intr_enable (vm, h)))
    {
      virtio_log_error (vif, "error encountered on pci interrupt enable");
      goto error;
    }

  if ((error = virtio_pci_device_init (vm, vif, args, bar)))
    {
      virtio_log_error (vif, "error encountered on device init");
      goto error;
    }

  /* create interface */
  error = ethernet_register_interface (vnm, virtio_device_class.index,
				       vif->dev_instance, vif->mac_addr,
				       &vif->hw_if_index,
				       virtio_pci_flag_change);

  if (error)
    {
      args->rv = VNET_API_ERROR_INVALID_REGISTRATION;
      virtio_log_error (vif,
			"error encountered on ethernet register interface");
      goto error;
    }

  vnet_sw_interface_t *sw = vnet_get_hw_sw_interface (vnm, vif->hw_if_index);
  vif->sw_if_index = sw->sw_if_index;
  args->sw_if_index = sw->sw_if_index;

  vnet_hw_interface_t *hw = vnet_get_hw_interface (vnm, vif->hw_if_index);
  hw->caps |= VNET_HW_INTERFACE_CAP_SUPPORTS_INT_MODE;

  if (args->virtio_flags & VIRTIO_FLAG_BUFFERING)
    {
      error = virtio_set_packet_buffering (vif, args->buffering_size);
      if (error)
	{
	  args->rv = VNET_API_ERROR_INIT_FAILED;
	  virtio_log_error (vif,
			    "error encountered during packet buffering init");
	  goto error;
	}
    }

  vnet_hw_interface_set_input_node (vnm, vif->hw_if_index,
				    virtio_input_node.index);
  u32 i = 0;
  vec_foreach_index (i, vif->rxq_vrings)
  {
    vnet_hw_interface_assign_rx_thread (vnm, vif->hw_if_index, i, ~0);
    virtio_vring_set_numa_node (vm, vif, RX_QUEUE (i));
    /* Set default rx mode to POLLING */
    vnet_hw_interface_set_rx_mode (vnm, vif->hw_if_index, i,
				   VNET_HW_IF_RX_MODE_POLLING);
  }
  if (virtio_pci_is_link_up (vm, vif) & VIRTIO_NET_S_LINK_UP)
    {
      vif->flags |= VIRTIO_IF_FLAG_ADMIN_UP;
      vnet_hw_interface_set_flags (vnm, vif->hw_if_index,
				   VNET_HW_INTERFACE_FLAG_LINK_UP);
    }
  else
    vnet_hw_interface_set_flags (vnm, vif->hw_if_index, 0);

  virtio_pci_offloads (vm, vif, args->gso_enabled,
		       args->checksum_offload_enabled);

  if ((vif->features & VIRTIO_FEATURE (VIRTIO_NET_F_CTRL_VQ)) &&
      (vif->features & VIRTIO_FEATURE (VIRTIO_NET_F_MQ)))
    {
      if (virtio_pci_enable_multiqueue (vm, vif, vif->max_queue_pairs))
	virtio_log_warning (vif, "multiqueue is not set");
    }
  return;

error:
  virtio_pci_delete_if (vm, vif);
  if (args->rv == 0)
    args->rv = VNET_API_ERROR_INVALID_INTERFACE;
  args->error = error;
}

int
virtio_pci_delete_if (vlib_main_t * vm, virtio_if_t * vif)
{
  vnet_main_t *vnm = vnet_get_main ();
  virtio_main_t *vim = &virtio_main;
  u32 i = 0;

  if (vif->type != VIRTIO_IF_TYPE_PCI)
    return VNET_API_ERROR_INVALID_INTERFACE;

  vlib_pci_intr_disable (vm, vif->pci_dev_handle);

  for (i = 0; i < vif->max_queue_pairs; i++)
    {
      vif->virtio_pci_func->del_queue (vm, vif, RX_QUEUE (i));
      vif->virtio_pci_func->del_queue (vm, vif, TX_QUEUE (i));
    }

  if (vif->features & VIRTIO_FEATURE (VIRTIO_NET_F_CTRL_VQ))
    vif->virtio_pci_func->del_queue (vm, vif, vif->max_queue_pairs * 2);

  if (vif->virtio_pci_func)
    vif->virtio_pci_func->device_reset (vm, vif);

  if (vif->hw_if_index)
    {
      vnet_hw_interface_set_flags (vnm, vif->hw_if_index, 0);
      vec_foreach_index (i, vif->rxq_vrings)
      {
	vnet_hw_interface_unassign_rx_thread (vnm, vif->hw_if_index, i);
      }
      ethernet_delete_interface (vnm, vif->hw_if_index);
    }

  vlib_pci_device_close (vm, vif->pci_dev_handle);

  vec_foreach_index (i, vif->rxq_vrings)
  {
    virtio_vring_t *vring = vec_elt_at_index (vif->rxq_vrings, i);
    if (vring->used)
      {
	virtio_free_buffers (vm, vring);
      }
    vec_free (vring->buffers);
    vlib_physmem_free (vm, vring->desc);
  }

  vec_foreach_index (i, vif->txq_vrings)
  {
    virtio_vring_t *vring = vec_elt_at_index (vif->txq_vrings, i);
    if (vring->used)
      {
	virtio_free_buffers (vm, vring);
      }
    vec_free (vring->buffers);
    gro_flow_table_free (vring->flow_table);
    virtio_vring_buffering_free (vm, vring->buffering);
    clib_spinlock_free (&vring->lockp);
    vlib_physmem_free (vm, vring->desc);
  }

  if (vif->cxq_vring != NULL)
    {
      u16 last = vif->cxq_vring->last_used_idx;
      u16 n_left = vif->cxq_vring->used->idx - last;
      while (n_left)
	{
	  last++;
	  n_left--;
	}

      vif->cxq_vring->last_used_idx = last;
      vlib_physmem_free (vm, vif->cxq_vring->desc);
    }

  vec_free (vif->rxq_vrings);
  vec_free (vif->txq_vrings);
  vec_free (vif->cxq_vring);

  clib_error_free (vif->error);
  memset (vif, 0, sizeof (*vif));
  pool_put (vim->interfaces, vif);

  return 0;
}

int
virtio_pci_enable_disable_offloads (vlib_main_t * vm, virtio_if_t * vif,
				    int gso_enabled,
				    int checksum_offload_enabled,
				    int offloads_disabled)
{
  if (vif->type != VIRTIO_IF_TYPE_PCI)
    return VNET_API_ERROR_INVALID_INTERFACE;

  if (gso_enabled)
    virtio_pci_offloads (vm, vif, 1, 0);
  else if (checksum_offload_enabled)
    virtio_pci_offloads (vm, vif, 0, 1);
  else if (offloads_disabled)
    virtio_pci_offloads (vm, vif, 0, 0);

  return 0;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
