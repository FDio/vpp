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

#include <vlib/vlib.h>
#include <vlib/pci/pci.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/devices/virtio/virtio.h>
#include <vnet/devices/virtio/virtio_pci_legacy.h>
#include <vnet/devices/virtio/pci.h>

#define PCI_CONFIG_SIZE(vif) ((vif->msix_enabled == VIRTIO_MSIX_ENABLED) ? \
  24 : 20)

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
  u32 host_features;
  vlib_pci_read_io_u32 (vm, vif->pci_dev_handle, VIRTIO_PCI_HOST_FEATURES,
			&host_features);
  return host_features;
}

static u64
virtio_pci_legacy_get_guest_features (vlib_main_t * vm, virtio_if_t * vif)
{
  u32 guest_features = 0;
  vlib_pci_read_io_u32 (vm, vif->pci_dev_handle, VIRTIO_PCI_GUEST_FEATURES,
			&guest_features);
  vif->features = guest_features;
  return guest_features;
}

static void
virtio_pci_legacy_set_guest_features (vlib_main_t * vm, virtio_if_t * vif,
				      u64 guest_features)
{
  if ((guest_features >> 32) != 0)
    {
      clib_warning ("only 32 bit features are allowed for legacy virtio!");
    }
  u32 features = 0;
  u32 gf = (u32) guest_features;

  vlib_pci_write_io_u32 (vm, vif->pci_dev_handle, VIRTIO_PCI_GUEST_FEATURES,
			 &gf);
  vlib_pci_read_io_u32 (vm, vif->pci_dev_handle, VIRTIO_PCI_GUEST_FEATURES,
			&features);
  if (features != (u32) guest_features)
    {
      clib_warning ("legacy set guest features failed!");
    }
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

static void
virtio_pci_legacy_set_queue_num (vlib_main_t * vm, virtio_if_t * vif,
				 u16 queue_id, u16 queue_size)
{
  /* do nothing */
}

static u8
virtio_pci_legacy_setup_queue (vlib_main_t * vm, virtio_if_t * vif,
			       u16 queue_id, void *p)
{
  u64 addr = vlib_physmem_get_pa (vm, p) >> VIRTIO_PCI_QUEUE_ADDR_SHIFT;
  u32 addr2 = 0, a = (u32) addr;
  vlib_pci_write_io_u16 (vm, vif->pci_dev_handle, VIRTIO_PCI_QUEUE_SEL,
			 &queue_id);
  vlib_pci_write_io_u32 (vm, vif->pci_dev_handle, VIRTIO_PCI_QUEUE_PFN, &a);
  vlib_pci_read_io_u32 (vm, vif->pci_dev_handle, VIRTIO_PCI_QUEUE_PFN,
			&addr2);
  if (addr == addr2)
    return 0;

  clib_warning ("legacy queue setup failed!");
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

static u16
virtio_pci_legacy_get_queue_notify_off (vlib_main_t * vm, virtio_if_t * vif,
					u16 queue_id)
{
  return 0;
}

inline void
virtio_pci_legacy_notify_queue (vlib_main_t * vm, virtio_if_t * vif,
				u16 queue_id, u16 queue_notify_off)
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

static void
virtio_pci_legacy_get_mac (vlib_main_t * vm, virtio_if_t * vif)
{
  virtio_pci_legacy_read_config (vm, vif, vif->mac_addr,
				 sizeof (vif->mac_addr), 0);
}

static void
virtio_pci_legacy_set_mac (vlib_main_t * vm, virtio_if_t * vif)
{
  virtio_pci_legacy_write_config (vm, vif, vif->mac_addr,
				  sizeof (vif->mac_addr), 0);
}

static u16
virtio_pci_legacy_get_device_status (vlib_main_t * vm, virtio_if_t * vif)
{
  u16 status = 0;
  virtio_pci_legacy_read_config (vm, vif, &status,
				 sizeof (status),
				 STRUCT_OFFSET_OF
				 (virtio_net_config_t, status));
  return status;
}

static u16
virtio_pci_legacy_get_max_queue_pairs (vlib_main_t * vm, virtio_if_t * vif)
{
  virtio_net_config_t config;
  virtio_pci_legacy_read_config (vm, vif, &config.max_virtqueue_pairs,
				 sizeof (config.max_virtqueue_pairs),
				 STRUCT_OFFSET_OF
				 (virtio_net_config_t, max_virtqueue_pairs));
  return config.max_virtqueue_pairs;
}

static u16
virtio_pci_legacy_get_mtu (vlib_main_t * vm, virtio_if_t * vif)
{
  virtio_net_config_t config;
  virtio_pci_legacy_read_config (vm, vif, &config.mtu,
				 sizeof (config.mtu),
				 STRUCT_OFFSET_OF (virtio_net_config_t, mtu));
  return config.mtu;
}


static void
virtio_pci_legacy_device_debug_config_space (vlib_main_t * vm,
					     virtio_if_t * vif)
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

const virtio_pci_func_t virtio_pci_legacy_func = {
  .read_config = virtio_pci_legacy_read_config,
  .write_config = virtio_pci_legacy_write_config,
  .get_device_features = virtio_pci_legacy_get_host_features,
  .get_driver_features = virtio_pci_legacy_get_guest_features,
  .set_driver_features = virtio_pci_legacy_set_guest_features,
  .get_status = virtio_pci_legacy_get_status,
  .set_status = virtio_pci_legacy_set_status,
  .device_reset = virtio_pci_legacy_reset,
  .get_isr = virtio_pci_legacy_get_isr,
  .get_queue_size = virtio_pci_legacy_get_queue_num,
  .set_queue_size = virtio_pci_legacy_set_queue_num,
  .setup_queue = virtio_pci_legacy_setup_queue,
  .del_queue = virtio_pci_legacy_del_queue,
  .get_queue_notify_off = virtio_pci_legacy_get_queue_notify_off,
  .notify_queue = virtio_pci_legacy_notify_queue,
  .set_config_irq = virtio_pci_legacy_set_config_irq,
  .set_queue_irq = virtio_pci_legacy_set_queue_irq,
  .get_mac = virtio_pci_legacy_get_mac,
  .set_mac = virtio_pci_legacy_set_mac,
  .get_device_status = virtio_pci_legacy_get_device_status,
  .get_max_queue_pairs = virtio_pci_legacy_get_max_queue_pairs,
  .get_mtu = virtio_pci_legacy_get_mtu,
  .device_debug_config_space = virtio_pci_legacy_device_debug_config_space,
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
