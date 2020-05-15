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

#define PCI_CONFIG_SIZE(vif) ((vif->msix_enabled == VIRTIO_MSIX_ENABLED) ? \
  24 : 20)

static pci_device_id_t virtio_pci_device_ids[] = {
  {
   .vendor_id = PCI_VENDOR_ID_VIRTIO,
   .device_id = PCI_DEVICE_ID_VIRTIO_NIC},
  {
   .vendor_id = PCI_VENDOR_ID_VIRTIO,
   .device_id = PCI_DEVICE_ID_VIRTIO_NIC_MODERN},
  {0},
};

static void
virtio_pci_legacy_read_config (vlib_main_t * vm, virtio_if_t * vif, void *dst,
			       int len, u32 addr)
{
  u32 size = 0;
  vlib_pci_dev_handle_t h = vif->pci_dev_handle;

  while (len > 0)
    {
      if (len >= 4)
	{
	  size = 4;
	  vlib_pci_read_io_u32 (vm, h, PCI_CONFIG_SIZE (vif) + addr, dst);
	}
      else if (len >= 2)
	{
	  size = 2;
	  vlib_pci_read_io_u16 (vm, h, PCI_CONFIG_SIZE (vif) + addr, dst);
	}
      else
	{
	  size = 1;
	  vlib_pci_read_io_u8 (vm, h, PCI_CONFIG_SIZE (vif) + addr, dst);
	}
      dst = (u8 *) dst + size;
      addr += size;
      len -= size;
    }
}

static void
virtio_pci_legacy_write_config (vlib_main_t * vm, virtio_if_t * vif,
				void *src, int len, u32 addr)
{
  u32 size = 0;
  vlib_pci_dev_handle_t h = vif->pci_dev_handle;

  while (len > 0)
    {
      if (len >= 4)
	{
	  size = 4;
	  vlib_pci_write_io_u32 (vm, h, PCI_CONFIG_SIZE (vif) + addr, src);
	}
      else if (len >= 2)
	{
	  size = 2;
	  vlib_pci_write_io_u16 (vm, h, PCI_CONFIG_SIZE (vif) + addr, src);
	}
      else
	{
	  size = 1;
	  vlib_pci_write_io_u8 (vm, h, PCI_CONFIG_SIZE (vif) + addr, src);
	}
      src = (u8 *) src + size;
      addr += size;
      len -= size;
    }
}

static u64
virtio_pci_legacy_get_host_features (vlib_main_t * vm, virtio_if_t * vif)
{
  u32 features;
  vlib_pci_read_io_u32 (vm, vif->pci_dev_handle, VIRTIO_PCI_HOST_FEATURES,
			&features);
  return features;
}

static u32
virtio_pci_legacy_get_guest_features (vlib_main_t * vm, virtio_if_t * vif)
{
  u32 feature = 0;
  vlib_pci_read_io_u32 (vm, vif->pci_dev_handle, VIRTIO_PCI_GUEST_FEATURES,
			&feature);
  vif->features = feature;
  return feature;
}

static u32
virtio_pci_legacy_set_guest_features (vlib_main_t * vm, virtio_if_t * vif,
				      u64 features)
{
  if ((features >> 32) != 0)
    {
      clib_warning ("only 32 bit features are allowed for legacy virtio!");
    }
  u32 feature = 0, guest_features = (u32) features;
  vlib_pci_write_io_u32 (vm, vif->pci_dev_handle, VIRTIO_PCI_GUEST_FEATURES,
			 &guest_features);
  vlib_pci_read_io_u32 (vm, vif->pci_dev_handle, VIRTIO_PCI_GUEST_FEATURES,
			&feature);
  return feature;
}

static u8
virtio_pci_legacy_get_status (vlib_main_t * vm, virtio_if_t * vif)
{
  u8 status = 0;
  vlib_pci_read_io_u8 (vm, vif->pci_dev_handle, VIRTIO_PCI_STATUS, &status);
  return status;
}

static void
virtio_pci_legacy_set_status (vlib_main_t * vm, virtio_if_t * vif, u8 status)
{
  if (status != VIRTIO_CONFIG_STATUS_RESET)
    status |= virtio_pci_legacy_get_status (vm, vif);
  vlib_pci_write_io_u8 (vm, vif->pci_dev_handle, VIRTIO_PCI_STATUS, &status);
}

static u8
virtio_pci_legacy_reset (vlib_main_t * vm, virtio_if_t * vif)
{
  virtio_pci_legacy_set_status (vm, vif, VIRTIO_CONFIG_STATUS_RESET);
  return virtio_pci_legacy_get_status (vm, vif);
}

static u8
virtio_pci_legacy_get_isr (vlib_main_t * vm, virtio_if_t * vif)
{
  u8 isr = 0;
  vlib_pci_read_io_u8 (vm, vif->pci_dev_handle, VIRTIO_PCI_ISR, &isr);
  return isr;
}

static u16
virtio_pci_legacy_get_queue_num (vlib_main_t * vm, virtio_if_t * vif,
				 u16 queue_id)
{
  u16 queue_num = 0;
  vlib_pci_write_io_u16 (vm, vif->pci_dev_handle, VIRTIO_PCI_QUEUE_SEL,
			 &queue_id);
  vlib_pci_read_io_u16 (vm, vif->pci_dev_handle, VIRTIO_PCI_QUEUE_NUM,
			&queue_num);
  return queue_num;
}

static int
virtio_pci_legacy_setup_queue (vlib_main_t * vm, virtio_if_t * vif,
			       u16 queue_id, void *p)
{
  u64 addr = vlib_physmem_get_pa (vm, p) >> VIRTIO_PCI_QUEUE_ADDR_SHIFT;
  u32 addr2 = 0;
  vlib_pci_write_io_u16 (vm, vif->pci_dev_handle, VIRTIO_PCI_QUEUE_SEL,
			 &queue_id);
  vlib_pci_write_io_u32 (vm, vif->pci_dev_handle, VIRTIO_PCI_QUEUE_PFN,
			 (u32 *) & addr);
  vlib_pci_read_io_u32 (vm, vif->pci_dev_handle, VIRTIO_PCI_QUEUE_PFN,
			&addr2);
  if ((u32) addr == addr2)
    return 0;
  return 1;
}

static void
virtio_pci_legacy_del_queue (vlib_main_t * vm, virtio_if_t * vif,
			     u16 queue_id)
{
  u32 src = 0;
  vlib_pci_write_io_u16 (vm, vif->pci_dev_handle, VIRTIO_PCI_QUEUE_SEL,
			 &queue_id);
  vlib_pci_write_io_u32 (vm, vif->pci_dev_handle, VIRTIO_PCI_QUEUE_PFN, &src);
}

inline void
virtio_pci_legacy_notify_queue (vlib_main_t * vm, virtio_if_t * vif,
				u16 queue_id)
{
  vlib_pci_write_io_u16 (vm, vif->pci_dev_handle, VIRTIO_PCI_QUEUE_NOTIFY,
			 &queue_id);
}

/* Enable one vector (0) for Link State Intrerrupt */
static u16
virtio_pci_legacy_set_config_irq (vlib_main_t * vm, virtio_if_t * vif,
				  u16 vec)
{
  vlib_pci_write_io_u16 (vm, vif->pci_dev_handle, VIRTIO_MSI_CONFIG_VECTOR,
			 &vec);
  vlib_pci_read_io_u16 (vm, vif->pci_dev_handle, VIRTIO_MSI_CONFIG_VECTOR,
			&vec);
  return vec;
}

static u16
virtio_pci_legacy_set_queue_irq (vlib_main_t * vm, virtio_if_t * vif, u16 vec,
				 u16 queue_id)
{
  vlib_pci_write_io_u16 (vm, vif->pci_dev_handle, VIRTIO_PCI_QUEUE_SEL,
			 &queue_id);
  vlib_pci_write_io_u16 (vm, vif->pci_dev_handle, VIRTIO_MSI_QUEUE_VECTOR,
			 &vec);
  vlib_pci_read_io_u16 (vm, vif->pci_dev_handle, VIRTIO_MSI_QUEUE_VECTOR,
			&vec);
  return vec;
}

static u32
virtio_pci_flag_change (vnet_main_t * vnm, vnet_hw_interface_t * hw,
			u32 flags)
{
  return 0;
}

static clib_error_t *
virtio_pci_get_max_virtqueue_pairs (vlib_main_t * vm, virtio_if_t * vif)
{
  virtio_net_config_t config;
  clib_error_t *error = 0;
  u16 max_queue_pairs = 1;

  if (vif->features & VIRTIO_FEATURE (VIRTIO_NET_F_MQ))
    {
      virtio_pci_legacy_read_config (vm, vif, &config.max_virtqueue_pairs,
				     sizeof (config.max_virtqueue_pairs),
				     STRUCT_OFFSET_OF (virtio_net_config_t,
						       max_virtqueue_pairs));
      max_queue_pairs = config.max_virtqueue_pairs;
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
  virtio_pci_legacy_write_config (vm, vif, vif->mac_addr,
				  sizeof (vif->mac_addr), 0);
}

static u32
virtio_pci_get_mac (vlib_main_t * vm, virtio_if_t * vif)
{
  if (vif->features & VIRTIO_FEATURE (VIRTIO_NET_F_MAC))
    {
      virtio_pci_legacy_read_config (vm, vif, vif->mac_addr,
				     sizeof (vif->mac_addr), 0);
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
    virtio_pci_legacy_read_config (vm, vif, &status, sizeof (status),	/* mac */
				   STRUCT_OFFSET_OF (virtio_net_config_t,
						     status));
  return status;
}

static void
virtio_pci_irq_0_handler (vlib_main_t * vm, vlib_pci_dev_handle_t h, u16 line)
{
  vnet_main_t *vnm = vnet_get_main ();
  virtio_main_t *vim = &virtio_main;
  uword pd = vlib_pci_get_private_data (vm, h);
  virtio_if_t *vif = pool_elt_at_index (vim->interfaces, pd);
  u16 qid = line;

  vnet_device_input_set_interrupt_pending (vnm, vif->hw_if_index, qid);
}

static void
virtio_pci_irq_1_handler (vlib_main_t * vm, vlib_pci_dev_handle_t h, u16 line)
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

  isr = virtio_pci_legacy_get_isr (vm, vif);

  /*
   * If the lower bit is set: look through the used rings of
   * all virtqueues for the device, to see if any progress has
   * been made by the device which requires servicing.
   */
  if (isr & VIRTIO_PCI_ISR_INTR)
    virtio_pci_irq_0_handler (vm, h, line);

  if (isr & VIRTIO_PCI_ISR_CONFIG)
    virtio_pci_irq_1_handler (vm, h, line);
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

inline void
debug_device_config_space (vlib_main_t * vm, virtio_if_t * vif)
{
  u32 data_u32;
  u16 data_u16;
  u8 data_u8;
  vlib_pci_read_io_u32 (vm, vif->pci_dev_handle, VIRTIO_PCI_HOST_FEATURES,
			&data_u32);
  vlib_cli_output (vm, "remote features 0x%lx", data_u32);
  vlib_pci_read_io_u32 (vm, vif->pci_dev_handle, VIRTIO_PCI_GUEST_FEATURES,
			&data_u32);
  vlib_cli_output (vm, "guest features 0x%lx", data_u32);
  vlib_pci_read_io_u32 (vm, vif->pci_dev_handle, VIRTIO_PCI_QUEUE_PFN,
			&data_u32);
  vlib_cli_output (vm, "queue address 0x%lx", data_u32);
  vlib_pci_read_io_u16 (vm, vif->pci_dev_handle, VIRTIO_PCI_QUEUE_NUM,
			&data_u16);
  vlib_cli_output (vm, "queue size 0x%x", data_u16);
  vlib_pci_read_io_u16 (vm, vif->pci_dev_handle, VIRTIO_PCI_QUEUE_SEL,
			&data_u16);
  vlib_cli_output (vm, "queue select 0x%x", data_u16);
  vlib_pci_read_io_u16 (vm, vif->pci_dev_handle, VIRTIO_PCI_QUEUE_NOTIFY,
			&data_u16);
  vlib_cli_output (vm, "queue notify 0x%x", data_u16);
  vlib_pci_read_io_u8 (vm, vif->pci_dev_handle, VIRTIO_PCI_STATUS, &data_u8);
  vlib_cli_output (vm, "status 0x%x", data_u8);
  vlib_pci_read_io_u8 (vm, vif->pci_dev_handle, VIRTIO_PCI_ISR, &data_u8);
  vlib_cli_output (vm, "isr 0x%x", data_u8);

  if (vif->msix_enabled == VIRTIO_MSIX_ENABLED)
    {
      vlib_pci_read_io_u16 (vm, vif->pci_dev_handle, VIRTIO_MSI_CONFIG_VECTOR,
			    &data_u16);
      vlib_cli_output (vm, "config vector 0x%x", data_u16);
      u16 queue_id = 0;
      vlib_pci_write_io_u16 (vm, vif->pci_dev_handle, VIRTIO_PCI_QUEUE_SEL,
			     &queue_id);
      vlib_pci_read_io_u16 (vm, vif->pci_dev_handle, VIRTIO_MSI_QUEUE_VECTOR,
			    &data_u16);
      vlib_cli_output (vm, "queue vector for queue (0) 0x%x", data_u16);
    }

  u8 mac[6];
  virtio_pci_legacy_read_config (vm, vif, mac, sizeof (mac), 0);
  vlib_cli_output (vm, "mac %U", format_ethernet_address, mac);
  virtio_pci_legacy_read_config (vm, vif, &data_u16, sizeof (u16),	/* offset to status */
				 6);
  vlib_cli_output (vm, "link up/down status 0x%x", data_u16);
  virtio_pci_legacy_read_config (vm, vif, &data_u16, sizeof (u16),
				 /* offset to max_virtqueue */ 8);
  vlib_cli_output (vm, "num of virtqueue 0x%x", data_u16);
  virtio_pci_legacy_read_config (vm, vif, &data_u16, sizeof (u16),	/* offset to mtu */
				 10);
  vlib_cli_output (vm, "mtu 0x%x", data_u16);

  u32 i = PCI_CONFIG_SIZE (vif) + 12, a = 4;
  i += a;
  i &= ~a;
  for (; i < 64; i += 4)
    {
      u32 data = 0;
      vlib_pci_read_io_u32 (vm, vif->pci_dev_handle, i, &data);
      vlib_cli_output (vm, "0x%lx", data);
    }
}

struct virtio_ctrl_msg
{
  struct virtio_net_ctrl_hdr ctrl;
  virtio_net_ctrl_ack status;
  u8 data[1024];
};

static int
virtio_pci_send_ctrl_msg (vlib_main_t * vm, virtio_if_t * vif,
			  struct virtio_ctrl_msg *data, u32 len)
{
  virtio_vring_t *vring = vif->cxq_vring;
  virtio_net_ctrl_ack status = VIRTIO_NET_ERR;
  struct virtio_ctrl_msg result;
  u32 buffer_index;
  vlib_buffer_t *b;
  u16 used, next, avail;
  u16 sz = vring->size;
  u16 mask = sz - 1;

  used = vring->desc_in_use;
  next = vring->desc_next;
  avail = vring->avail->idx;
  struct vring_desc *d = &vring->desc[next];

  if (vlib_buffer_alloc (vm, &buffer_index, 1))
    b = vlib_get_buffer (vm, buffer_index);
  else
    return VIRTIO_NET_ERR;
  /*
   * current_data may not be initialized with 0 and may contain
   * previous offset.
   */
  b->current_data = 0;
  clib_memcpy (vlib_buffer_get_current (b), data,
	       sizeof (struct virtio_ctrl_msg));
  d->flags = VRING_DESC_F_NEXT;
  d->addr = vlib_buffer_get_current_pa (vm, b);
  d->len = sizeof (struct virtio_net_ctrl_hdr);
  vring->avail->ring[avail & mask] = next;
  avail++;
  next = (next + 1) & mask;
  d->next = next;
  used++;

  d = &vring->desc[next];
  d->flags = VRING_DESC_F_NEXT;
  d->addr = vlib_buffer_get_current_pa (vm, b) +
    STRUCT_OFFSET_OF (struct virtio_ctrl_msg, data);
  d->len = len;
  next = (next + 1) & mask;
  d->next = next;
  used++;

  d = &vring->desc[next];
  d->flags = VRING_DESC_F_WRITE;
  d->addr = vlib_buffer_get_current_pa (vm, b) +
    STRUCT_OFFSET_OF (struct virtio_ctrl_msg, status);
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
      struct vring_used_elem *e = &vring->used->ring[last & mask];
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
	       sizeof (struct virtio_ctrl_msg));
  virtio_log_debug (vif, "ctrl-queue: status %u", result.status);
  status = result.status;
  vlib_buffer_free (vm, &buffer_index, 1);
  return status;
}

static int
virtio_pci_disable_offload (vlib_main_t * vm, virtio_if_t * vif)
{
  struct virtio_ctrl_msg offload_hdr;
  virtio_net_ctrl_ack status = VIRTIO_NET_ERR;

  offload_hdr.ctrl.class = VIRTIO_NET_CTRL_GUEST_OFFLOADS;
  offload_hdr.ctrl.cmd = VIRTIO_NET_CTRL_GUEST_OFFLOADS_SET;
  offload_hdr.status = VIRTIO_NET_ERR;
  u64 offloads = 0ULL;
  clib_memcpy (offload_hdr.data, &offloads, sizeof (offloads));

  status =
    virtio_pci_send_ctrl_msg (vm, vif, &offload_hdr, sizeof (offloads));
  virtio_log_debug (vif, "disable offloads");
  vif->remote_features = virtio_pci_legacy_get_host_features (vm, vif);
  virtio_pci_legacy_get_guest_features (vm, vif);
  return status;
}

static int
virtio_pci_enable_checksum_offload (vlib_main_t * vm, virtio_if_t * vif)
{
  struct virtio_ctrl_msg csum_offload_hdr;
  virtio_net_ctrl_ack status = VIRTIO_NET_ERR;

  csum_offload_hdr.ctrl.class = VIRTIO_NET_CTRL_GUEST_OFFLOADS;
  csum_offload_hdr.ctrl.cmd = VIRTIO_NET_CTRL_GUEST_OFFLOADS_SET;
  csum_offload_hdr.status = VIRTIO_NET_ERR;
  u64 offloads = 0ULL;
  offloads |= VIRTIO_FEATURE (VIRTIO_NET_F_GUEST_CSUM);
  clib_memcpy (csum_offload_hdr.data, &offloads, sizeof (offloads));

  status =
    virtio_pci_send_ctrl_msg (vm, vif, &csum_offload_hdr, sizeof (offloads));
  virtio_log_debug (vif, "enable checksum offload");
  vif->remote_features = virtio_pci_legacy_get_host_features (vm, vif);
  virtio_pci_legacy_get_guest_features (vm, vif);
  return status;
}

static int
virtio_pci_enable_gso (vlib_main_t * vm, virtio_if_t * vif)
{
  struct virtio_ctrl_msg gso_hdr;
  virtio_net_ctrl_ack status = VIRTIO_NET_ERR;

  gso_hdr.ctrl.class = VIRTIO_NET_CTRL_GUEST_OFFLOADS;
  gso_hdr.ctrl.cmd = VIRTIO_NET_CTRL_GUEST_OFFLOADS_SET;
  gso_hdr.status = VIRTIO_NET_ERR;
  u64 offloads = VIRTIO_FEATURE (VIRTIO_NET_F_GUEST_CSUM)
    | VIRTIO_FEATURE (VIRTIO_NET_F_GUEST_TSO4)
    | VIRTIO_FEATURE (VIRTIO_NET_F_GUEST_TSO6);
  clib_memcpy (gso_hdr.data, &offloads, sizeof (offloads));

  status = virtio_pci_send_ctrl_msg (vm, vif, &gso_hdr, sizeof (offloads));
  virtio_log_debug (vif, "enable gso");
  vif->remote_features = virtio_pci_legacy_get_host_features (vm, vif);
  virtio_pci_legacy_get_guest_features (vm, vif);
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
	      hw->flags |= VNET_HW_INTERFACE_FLAG_SUPPORTS_GSO |
		VNET_HW_INTERFACE_FLAG_SUPPORTS_TX_L4_CKSUM_OFFLOAD;
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
	      hw->flags &= ~VNET_HW_INTERFACE_FLAG_SUPPORTS_GSO;
	      hw->flags |=
		VNET_HW_INTERFACE_FLAG_SUPPORTS_TX_L4_CKSUM_OFFLOAD;
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
	      hw->flags &= ~(VNET_HW_INTERFACE_FLAG_SUPPORTS_GSO |
			     VNET_HW_INTERFACE_FLAG_SUPPORTS_TX_L4_CKSUM_OFFLOAD);
	    }
	}
    }

  return 0;
}

static int
virtio_pci_enable_multiqueue (vlib_main_t * vm, virtio_if_t * vif,
			      u16 num_queues)
{
  struct virtio_ctrl_msg mq_hdr;
  virtio_net_ctrl_ack status = VIRTIO_NET_ERR;

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
virtio_pci_control_vring_init (vlib_main_t * vm, virtio_if_t * vif,
			       u16 queue_num)
{
  clib_error_t *error = 0;
  u16 queue_size = 0;
  virtio_vring_t *vring;
  struct vring vr;
  u32 i = 0;
  void *ptr = NULL;

  queue_size = virtio_pci_legacy_get_queue_num (vm, vif, queue_num);
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
  virtio_pci_legacy_setup_queue (vm, vif, queue_num, ptr);
  vring->kick_fd = -1;

  return error;
}

clib_error_t *
virtio_pci_vring_init (vlib_main_t * vm, virtio_if_t * vif, u16 queue_num)
{
  clib_error_t *error = 0;
  u16 queue_size = 0;
  virtio_vring_t *vring;
  struct vring vr;
  u32 i = 0;
  void *ptr = NULL;

  queue_size = virtio_pci_legacy_get_queue_num (vm, vif, queue_num);
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
  if (virtio_pci_legacy_setup_queue (vm, vif, queue_num, ptr))
    return clib_error_return (0, "error in queue address setup");

  vring->kick_fd = -1;
  return error;
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

  if (req_features == 0)
    {
      req_features = supported_features;
    }

  vif->features = req_features & vif->remote_features & supported_features;

  if (vif->features & VIRTIO_FEATURE (VIRTIO_NET_F_MTU))
    {
      virtio_net_config_t config;
      virtio_pci_legacy_read_config (vm, vif, &config.mtu,
				     sizeof (config.mtu),
				     STRUCT_OFFSET_OF (virtio_net_config_t,
						       mtu));
      if (config.mtu < 64)
	vif->features &= ~VIRTIO_FEATURE (VIRTIO_NET_F_MTU);
    }

  vif->features =
    virtio_pci_legacy_set_guest_features (vm, vif, vif->features);
}

void
virtio_pci_read_device_feature (vlib_main_t * vm, virtio_if_t * vif)
{
  vif->remote_features = virtio_pci_legacy_get_host_features (vm, vif);
}

int
virtio_pci_reset_device (vlib_main_t * vm, virtio_if_t * vif)
{
  u8 status = 0;

  /*
   * Reset the device
   */
  status = virtio_pci_legacy_reset (vm, vif);

  /*
   * Set the Acknowledge status bit
   */
  virtio_pci_legacy_set_status (vm, vif, VIRTIO_CONFIG_STATUS_ACK);

  /*
   * Set the Driver status bit
   */
  virtio_pci_legacy_set_status (vm, vif, VIRTIO_CONFIG_STATUS_DRIVER);

  /*
   * Read the status and verify it
   */
  status = virtio_pci_legacy_get_status (vm, vif);
  if (!
      ((status & VIRTIO_CONFIG_STATUS_ACK)
       && (status & VIRTIO_CONFIG_STATUS_DRIVER)))
    return -1;
  vif->status = status;

  return 0;
}

clib_error_t *
virtio_pci_read_caps (vlib_main_t * vm, virtio_if_t * vif)
{
  clib_error_t *error = 0;
  struct virtio_pci_cap cap;
  u8 pos, common_cfg = 0, notify_base = 0, dev_cfg = 0, isr = 0, pci_cfg = 0;
  vlib_pci_dev_handle_t h = vif->pci_dev_handle;

  if ((error = vlib_pci_read_config_u8 (vm, h, PCI_CAPABILITY_LIST, &pos)))
    {
      virtio_log_error (vif, "error in reading capabilty list position");
      clib_error_return (error, "error in reading capabilty list position");
    }
  while (pos)
    {
      if ((error =
	   vlib_pci_read_write_config (vm, h, VLIB_READ, pos, &cap,
				       sizeof (cap))))
	{
	  virtio_log_error (vif, "%s [%2x]",
			    "error in reading the capability at", pos);
	  clib_error_return (error,
			     "error in reading the capability at [%2x]", pos);
	}

      if (cap.cap_vndr == PCI_CAP_ID_MSIX)
	{
	  u16 flags, table_size, table_size_mask = 0x07FF;

	  if ((error =
	       vlib_pci_read_write_config (vm, h, VLIB_READ, pos + 2, &flags,
					   sizeof (flags))))
	    clib_error_return (error,
			       "error in reading the capability at [%2x]",
			       pos + 2);

	  table_size = flags & table_size_mask;
	  virtio_log_debug (vif, "flags:0x%x %s 0x%x", flags,
			    "msix interrupt vector table-size", table_size);

	  if (flags & PCI_MSIX_ENABLE)
	    {
	      virtio_log_debug (vif, "msix interrupt enabled");
	      vif->msix_enabled = VIRTIO_MSIX_ENABLED;
	    }
	  else
	    {
	      virtio_log_debug (vif, "msix interrupt disabled");
	      vif->msix_enabled = VIRTIO_MSIX_DISABLED;
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
      switch (cap.cfg_type)
	{
	case VIRTIO_PCI_CAP_COMMON_CFG:
	  common_cfg = 1;
	  break;
	case VIRTIO_PCI_CAP_NOTIFY_CFG:
	  notify_base = 1;
	  break;
	case VIRTIO_PCI_CAP_DEVICE_CFG:
	  dev_cfg = 1;
	  break;
	case VIRTIO_PCI_CAP_ISR_CFG:
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

  if (common_cfg == 0 || notify_base == 0 || dev_cfg == 0 || isr == 0)
    {
      virtio_log_debug (vif, "legacy virtio pci device found");
      return error;
    }

  if (!pci_cfg)
    clib_error_return (error, "modern virtio pci device found");

  virtio_log_debug (vif, "transitional virtio pci device found");
  return error;
}

static clib_error_t *
virtio_pci_device_init (vlib_main_t * vm, virtio_if_t * vif,
			virtio_pci_create_if_args_t * args)
{
  clib_error_t *error = 0;
  vlib_thread_main_t *vtm = vlib_get_thread_main ();
  u8 status = 0;

  if ((error = virtio_pci_read_caps (vm, vif)))
    {
      args->rv = VNET_API_ERROR_UNSUPPORTED;
      virtio_log_error (vif, "Device is not supported");
      clib_error_return (error, "Device is not supported");
    }

  if (virtio_pci_reset_device (vm, vif) < 0)
    {
      args->rv = VNET_API_ERROR_INIT_FAILED;
      virtio_log_error (vif, "Failed to reset the device");
      clib_error_return (error, "Failed to reset the device");
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
  virtio_pci_legacy_set_status (vm, vif, VIRTIO_CONFIG_STATUS_FEATURES_OK);
  status = virtio_pci_legacy_get_status (vm, vif);
  if (!(status & VIRTIO_CONFIG_STATUS_FEATURES_OK))
    {
      args->rv = VNET_API_ERROR_UNSUPPORTED;
      virtio_log_error (vif,
			"error encountered: Device doesn't support requested features");
      clib_error_return (error, "Device doesn't support requested features");
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

  for (int i = 0; i < vif->max_queue_pairs; i++)
    {
      if ((error = virtio_pci_vring_init (vm, vif, RX_QUEUE (i))))
	{
	  args->rv = VNET_API_ERROR_INIT_FAILED;
	  virtio_log_error (vif, "%s (%u) %s", "error in rxq-queue",
			    RX_QUEUE (i), "initialization");
	  clib_error_return (error, "%s (%u) %s", "error in rxq-queue",
			     RX_QUEUE (i), "initialization");
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
	  clib_error_return (error, "%s (%u) %s", "error in txq-queue",
			     TX_QUEUE (i), "initialization");
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
      if (virtio_pci_legacy_set_config_irq (vm, vif, 1) ==
	  VIRTIO_MSI_NO_VECTOR)
	virtio_log_warning (vif, "config vector 1 is not set");
      if (virtio_pci_legacy_set_queue_irq (vm, vif, 0, 0) ==
	  VIRTIO_MSI_NO_VECTOR)
	virtio_log_warning (vif, "queue vector 0 is not set");
    }

  /*
   * set the driver status OK
   */
  virtio_pci_legacy_set_status (vm, vif, VIRTIO_CONFIG_STATUS_DRIVER_OK);
  vif->status = virtio_pci_legacy_get_status (vm, vif);
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

  if ((error = vlib_pci_io_region (vm, h, 0)))
    {
      virtio_log_error (vif, "error encountered on pci io region");
      goto error;
    }

  if (vlib_pci_get_num_msix_interrupts (vm, h) > 1)
    {
      if ((error = vlib_pci_register_msix_handler (vm, h, 0, 1,
						   &virtio_pci_irq_0_handler)))
	{
	  args->rv = VNET_API_ERROR_INVALID_REGISTRATION;
	  virtio_log_error (vif,
			    "error encountered on pci register msix handler 0");
	  goto error;
	}
      if ((error = vlib_pci_register_msix_handler (vm, h, 1, 1,
						   &virtio_pci_irq_1_handler)))
	{
	  args->rv = VNET_API_ERROR_INVALID_REGISTRATION;
	  virtio_log_error (vif,
			    "error encountered on pci register msix handler 1");
	  goto error;
	}

      if ((error = vlib_pci_enable_msix_irq (vm, h, 0, 2)))
	{
	  virtio_log_error (vif, "error encountered on pci enable msix irq");
	  goto error;
	}
      vif->support_int_mode = 1;
      virtio_log_debug (vif, "device supports msix interrupts");
    }
  else if (vlib_pci_get_num_msix_interrupts (vm, h) == 1)
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

  if ((error = virtio_pci_device_init (vm, vif, args)))
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
  hw->flags |= VNET_HW_INTERFACE_FLAG_SUPPORTS_INT_MODE;
  vnet_hw_interface_set_input_node (vnm, vif->hw_if_index,
				    virtio_input_node.index);
  u32 i = 0;
  vec_foreach_index (i, vif->rxq_vrings)
  {
    vnet_hw_interface_assign_rx_thread (vnm, vif->hw_if_index, i, ~0);
    virtio_vring_set_numa_node (vm, vif, RX_QUEUE (i));
    /* Set default rx mode to POLLING */
    vnet_hw_interface_set_rx_mode (vnm, vif->hw_if_index, i,
				   VNET_HW_INTERFACE_RX_MODE_POLLING);
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
      virtio_pci_legacy_del_queue (vm, vif, RX_QUEUE (i));
      virtio_pci_legacy_del_queue (vm, vif, TX_QUEUE (i));
    }

  if (vif->features & VIRTIO_FEATURE (VIRTIO_NET_F_CTRL_VQ))
    virtio_pci_legacy_del_queue (vm, vif, vif->max_queue_pairs * 2);

  virtio_pci_legacy_reset (vm, vif);

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
    if (vring->kick_fd != -1)
      close (vring->kick_fd);
    if (vring->used)
      {
	virtio_free_rx_buffers (vm, vring);
      }
    vec_free (vring->buffers);
    vlib_physmem_free (vm, vring->desc);
  }

  vec_foreach_index (i, vif->txq_vrings)
  {
    virtio_vring_t *vring = vec_elt_at_index (vif->txq_vrings, i);
    if (vring->kick_fd != -1)
      close (vring->kick_fd);
    if (vring->used)
      {
	virtio_free_used_desc (vm, vring);
      }
    vec_free (vring->buffers);
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
