/*
 * Copyright (c) 2020 Cisco and/or its affiliates.
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
#include <vnet/devices/virtio/virtio_pci_modern.h>
#include <vnet/devices/virtio/pci.h>


static u64
virtio_pci_modern_get_device_features (vlib_main_t * vm, virtio_if_t * vif)
{
  u64 features_lo, features_hi;
  virtio_pci_reg_write_u32 (vif, VIRTIO_DEVICE_FEATURE_SELECT_OFFSET (vif),
			    VIRTIO_FEATURE_SELECT_LO);
  features_lo =
    virtio_pci_reg_read_u32 (vif, VIRTIO_DEVICE_FEATURE_OFFSET (vif));
  virtio_pci_reg_write_u32 (vif, VIRTIO_DEVICE_FEATURE_SELECT_OFFSET (vif),
			    VIRTIO_FEATURE_SELECT_HI);
  features_hi =
    virtio_pci_reg_read_u32 (vif, VIRTIO_DEVICE_FEATURE_OFFSET (vif));
  u64 features = ((features_hi << 32) | features_lo);
  return features;
}

static u64
virtio_pci_modern_get_driver_features (vlib_main_t * vm, virtio_if_t * vif)
{
  u64 features_lo, features_hi;
  virtio_pci_reg_write_u32 (vif, VIRTIO_DRIVER_FEATURE_SELECT_OFFSET (vif),
			    VIRTIO_FEATURE_SELECT_LO);
  features_lo =
    virtio_pci_reg_read_u32 (vif, VIRTIO_DRIVER_FEATURE_OFFSET (vif));
  virtio_pci_reg_write_u32 (vif, VIRTIO_DRIVER_FEATURE_SELECT_OFFSET (vif),
			    VIRTIO_FEATURE_SELECT_HI);
  features_hi =
    virtio_pci_reg_read_u32 (vif, VIRTIO_DRIVER_FEATURE_OFFSET (vif));

  vif->features = ((features_hi << 32) | features_lo);
  return vif->features;
}

static void
virtio_pci_modern_set_driver_features (vlib_main_t * vm, virtio_if_t * vif,
				       u64 features)
{
  u32 features_lo = (u32) features, features_hi = (u32) (features >> 32);
  virtio_pci_reg_write_u32 (vif, VIRTIO_DRIVER_FEATURE_SELECT_OFFSET (vif),
			    VIRTIO_FEATURE_SELECT_LO);
  virtio_pci_reg_write_u32 (vif, VIRTIO_DRIVER_FEATURE_OFFSET (vif),
			    features_lo);
  virtio_pci_reg_write_u32 (vif, VIRTIO_DRIVER_FEATURE_SELECT_OFFSET (vif),
			    VIRTIO_FEATURE_SELECT_HI);
  virtio_pci_reg_write_u32 (vif, VIRTIO_DRIVER_FEATURE_OFFSET (vif),
			    features_hi);

  if (features != virtio_pci_modern_get_driver_features (vm, vif))
    {
      clib_warning ("modern set guest features failed!");
    }
}

static u16
virtio_pci_modern_get_msix_config (virtio_if_t * vif)
{
  u16 msix_config;
  msix_config =
    virtio_pci_reg_read_u16 (vif, VIRTIO_MSIX_CONFIG_VECTOR_OFFSET (vif));
  return msix_config;
}

static u16
virtio_pci_modern_set_msix_config (vlib_main_t * vm, virtio_if_t * vif,
				   u16 msix_config)
{
  virtio_pci_reg_write_u16 (vif, VIRTIO_MSIX_CONFIG_VECTOR_OFFSET (vif),
			    msix_config);
  return virtio_pci_modern_get_msix_config (vif);
}

static u16
virtio_pci_modern_get_num_queues (virtio_if_t * vif)
{
  u16 num_queues = 0;
  num_queues = virtio_pci_reg_read_u16 (vif, VIRTIO_NUM_QUEUES_OFFSET (vif));
  return num_queues;
}

static u8
virtio_pci_modern_get_status (vlib_main_t * vm, virtio_if_t * vif)
{
  u8 status = 0;
  status = virtio_pci_reg_read_u8 (vif, VIRTIO_DEVICE_STATUS_OFFSET (vif));
  return status;
}

static void
virtio_pci_modern_set_status (vlib_main_t * vm, virtio_if_t * vif, u8 status)
{
  if (status != VIRTIO_CONFIG_STATUS_RESET)
    status |= virtio_pci_modern_get_status (vm, vif);
  virtio_pci_reg_write_u8 (vif, VIRTIO_DEVICE_STATUS_OFFSET (vif), status);
}

static u8
virtio_pci_modern_reset (vlib_main_t * vm, virtio_if_t * vif)
{
  virtio_pci_modern_set_status (vm, vif, VIRTIO_CONFIG_STATUS_RESET);
  return virtio_pci_modern_get_status (vm, vif);
}

static u8
virtio_pci_modern_get_config_generation (virtio_if_t * vif)
{
  u8 config_generation = 0;
  config_generation =
    virtio_pci_reg_read_u8 (vif, VIRTIO_CONFIG_GENERATION_OFFSET (vif));
  return config_generation;
}

static void
virtio_pci_modern_set_queue_select (virtio_if_t * vif, u16 queue_select)
{
  virtio_pci_reg_write_u16 (vif, VIRTIO_QUEUE_SELECT_OFFSET (vif),
			    queue_select);
}

static u16
virtio_pci_modern_get_queue_size (vlib_main_t * vm, virtio_if_t * vif,
				  u16 queue_id)
{
  u16 queue_size = 0;
  virtio_pci_modern_set_queue_select (vif, queue_id);
  queue_size = virtio_pci_reg_read_u16 (vif, VIRTIO_QUEUE_SIZE_OFFSET (vif));
  return queue_size;
}

static void
virtio_pci_modern_set_queue_size (vlib_main_t * vm, virtio_if_t * vif,
				  u16 queue_id, u16 queue_size)
{
  if (!is_pow2 (queue_size))
    {
      return;
    }

  if (virtio_pci_modern_get_queue_size (vm, vif, queue_id) > queue_size)
    virtio_pci_reg_write_u16 (vif, VIRTIO_QUEUE_SIZE_OFFSET (vif),
			      queue_size);
}

static u16
virtio_pci_modern_get_queue_msix_vector (virtio_if_t * vif)
{
  u16 queue_msix_vector = 0;
  queue_msix_vector =
    virtio_pci_reg_read_u16 (vif, VIRTIO_QUEUE_MSIX_VECTOR_OFFSET (vif));
  return queue_msix_vector;
}

static u16
virtio_pci_modern_set_queue_msix_vector (vlib_main_t * vm, virtio_if_t * vif,
					 u16 queue_msix_vector, u16 queue_id)
{
  virtio_pci_modern_set_queue_select (vif, queue_id);
  virtio_pci_reg_write_u16 (vif, VIRTIO_QUEUE_MSIX_VECTOR_OFFSET (vif),
			    queue_msix_vector);
  return virtio_pci_modern_get_queue_msix_vector (vif);
}

static u16
virtio_pci_modern_get_queue_enable (virtio_if_t * vif, u16 queue_id)
{
  u16 queue_enable = 0;
  virtio_pci_modern_set_queue_select (vif, queue_id);
  queue_enable =
    virtio_pci_reg_read_u16 (vif, VIRTIO_QUEUE_ENABLE_OFFSET (vif));
  return queue_enable;
}

static void
virtio_pci_modern_set_queue_enable (virtio_if_t * vif, u16 queue_id,
				    u16 queue_enable)
{
  virtio_pci_modern_set_queue_select (vif, queue_id);
  virtio_pci_reg_write_u16 (vif, VIRTIO_QUEUE_ENABLE_OFFSET (vif),
			    queue_enable);
}

static u16
virtio_pci_modern_get_queue_notify_off (vlib_main_t * vm, virtio_if_t * vif,
					u16 queue_id)
{
  u16 queue_notify_off = 0;
  virtio_pci_modern_set_queue_select (vif, queue_id);
  queue_notify_off =
    virtio_pci_reg_read_u16 (vif, VIRTIO_QUEUE_NOTIFY_OFF_OFFSET (vif));
  return queue_notify_off;
}

static u64
virtio_pci_modern_get_queue_desc (virtio_if_t * vif)
{
  u64 queue_desc = 0;
  queue_desc = virtio_pci_reg_read_u64 (vif, VIRTIO_QUEUE_DESC_OFFSET (vif));
  return queue_desc;
}

static void
virtio_pci_modern_set_queue_desc (virtio_if_t * vif, u64 queue_desc)
{
  virtio_pci_reg_write_u64 (vif, VIRTIO_QUEUE_DESC_OFFSET (vif), queue_desc);
}

static u64
virtio_pci_modern_get_queue_driver (virtio_if_t * vif)
{
  u64 queue_driver = 0;
  queue_driver =
    virtio_pci_reg_read_u64 (vif, VIRTIO_QUEUE_DRIVER_OFFSET (vif));
  return queue_driver;
}

static void
virtio_pci_modern_set_queue_driver (virtio_if_t * vif, u64 queue_driver)
{
  virtio_pci_reg_write_u64 (vif, VIRTIO_QUEUE_DRIVER_OFFSET (vif),
			    queue_driver);
}

static u64
virtio_pci_modern_get_queue_device (virtio_if_t * vif)
{
  u64 queue_device = 0;
  queue_device =
    virtio_pci_reg_read_u64 (vif, VIRTIO_QUEUE_DEVICE_OFFSET (vif));
  return queue_device;
}

static void
virtio_pci_modern_set_queue_device (virtio_if_t * vif, u64 queue_device)
{
  virtio_pci_reg_write_u64 (vif, VIRTIO_QUEUE_DEVICE_OFFSET (vif),
			    queue_device);
}

static u8
virtio_pci_modern_setup_queue (vlib_main_t * vm, virtio_if_t * vif,
			       u16 queue_id, void *p)
{
  vring_t vr;
  u16 queue_size = 0;

  virtio_pci_modern_set_queue_select (vif, queue_id);
  queue_size = virtio_pci_modern_get_queue_size (vm, vif, queue_id);
  vring_init (&vr, queue_size, p, VIRTIO_PCI_VRING_ALIGN);

  u64 desc = vlib_physmem_get_pa (vm, vr.desc);
  virtio_pci_modern_set_queue_desc (vif, desc);
  if (desc != virtio_pci_modern_get_queue_desc (vif))
    return 1;

  u64 avail = vlib_physmem_get_pa (vm, vr.avail);
  virtio_pci_modern_set_queue_driver (vif, avail);
  if (avail != virtio_pci_modern_get_queue_driver (vif))
    return 1;

  u64 used = vlib_physmem_get_pa (vm, vr.used);
  virtio_pci_modern_set_queue_device (vif, used);
  if (used != virtio_pci_modern_get_queue_device (vif))
    return 1;

  virtio_pci_modern_set_queue_enable (vif, queue_id, 1);

  if (virtio_pci_modern_get_queue_enable (vif, queue_id))
    return 0;

  return 1;
}

static void
virtio_pci_modern_del_queue (vlib_main_t * vm, virtio_if_t * vif,
			     u16 queue_id)
{
  virtio_pci_modern_set_queue_select (vif, queue_id);
  virtio_pci_modern_set_queue_enable (vif, queue_id, 0);
  virtio_pci_modern_set_queue_desc (vif, 0);
  virtio_pci_modern_set_queue_driver (vif, 0);
  virtio_pci_modern_set_queue_device (vif, 0);
}

static void
virtio_pci_modern_get_device_mac (vlib_main_t * vm, virtio_if_t * vif)
{
  vif->mac_addr32 = virtio_pci_reg_read_u32 (vif, VIRTIO_MAC_OFFSET (vif));
  vif->mac_addr16 =
    virtio_pci_reg_read_u16 (vif, VIRTIO_MAC_OFFSET (vif) + 4);
}

static void
virtio_pci_modern_set_device_mac (vlib_main_t * vm, virtio_if_t * vif)
{
  virtio_pci_reg_write_u32 (vif, VIRTIO_MAC_OFFSET (vif), vif->mac_addr32);
  virtio_pci_reg_write_u16 (vif, VIRTIO_MAC_OFFSET (vif) + 4,
			    vif->mac_addr16);
}

static u16
virtio_pci_modern_get_device_status (vlib_main_t * vm, virtio_if_t * vif)
{
  u16 status = 0;
  status = virtio_pci_reg_read_u16 (vif, VIRTIO_STATUS_OFFSET (vif));
  return status;
}

static u16
virtio_pci_modern_get_max_virtqueue_pairs (vlib_main_t * vm,
					   virtio_if_t * vif)
{
  u16 max_virtqueue_pairs = 0;
  max_virtqueue_pairs =
    virtio_pci_reg_read_u16 (vif, VIRTIO_MAX_VIRTQUEUE_PAIRS_OFFSET (vif));
  u16 supported_queues = virtio_pci_modern_get_num_queues (vif);
  virtio_log_debug (vif, "max-virtqueue-pairs %u, supported-queues %u",
		    max_virtqueue_pairs, supported_queues);
  return max_virtqueue_pairs;
}

static u16
virtio_pci_modern_get_device_mtu (vlib_main_t * vm, virtio_if_t * vif)
{
  u16 mtu = 0;
  mtu = virtio_pci_reg_read_u16 (vif, VIRTIO_MTU_OFFSET (vif));
  return mtu;
}

static void
virtio_pci_modern_read_config (vlib_main_t * vm, virtio_if_t * vif, void *dst,
			       int len, u32 addr)
{
  u8 config_count;
  do
    {
      config_count = virtio_pci_modern_get_config_generation (vif);
      virtio_pci_modern_get_device_mac (vm, vif);
      u16 status = virtio_pci_modern_get_device_status (vm, vif);
      u16 max_queue_pairs =
	virtio_pci_modern_get_max_virtqueue_pairs (vm, vif);
      u16 mtu = virtio_pci_modern_get_device_mtu (vm, vif);
      virtio_log_debug (vif, "status %u, max_queue_pairs %u, mtu %u", status,
			max_queue_pairs, mtu);
    }
  while (config_count != virtio_pci_modern_get_config_generation (vif));
}

static void
virtio_pci_modern_write_config (vlib_main_t * vm, virtio_if_t * vif,
				void *src, int len, u32 addr)
{
  // do nothing
}

static u8
virtio_pci_modern_get_isr (vlib_main_t * vm, virtio_if_t * vif)
{
  return virtio_pci_reg_read_u8 (vif, VIRTIO_ISR_OFFSET (vif));
}

inline void
virtio_pci_modern_notify_queue (vlib_main_t * vm, virtio_if_t * vif,
				u16 queue_id, u16 queue_notify_off)
{
  virtio_pci_reg_write_u16 (vif,
			    VIRTIO_NOTIFICATION_OFFSET (vif) +
			    queue_notify_off, queue_id);
}

static void
virtio_pci_modern_device_debug_config_space (vlib_main_t * vm,
					     virtio_if_t * vif)
{
  // do nothing for now
}

const virtio_pci_func_t virtio_pci_modern_func = {
  .read_config = virtio_pci_modern_read_config,
  .write_config = virtio_pci_modern_write_config,
  .get_device_features = virtio_pci_modern_get_device_features,
  .get_driver_features = virtio_pci_modern_get_driver_features,
  .set_driver_features = virtio_pci_modern_set_driver_features,
  .get_status = virtio_pci_modern_get_status,
  .set_status = virtio_pci_modern_set_status,
  .device_reset = virtio_pci_modern_reset,
  .get_isr = virtio_pci_modern_get_isr,
  .get_queue_size = virtio_pci_modern_get_queue_size,
  .set_queue_size = virtio_pci_modern_set_queue_size,
  .setup_queue = virtio_pci_modern_setup_queue,
  .del_queue = virtio_pci_modern_del_queue,
  .get_queue_notify_off = virtio_pci_modern_get_queue_notify_off,
  .notify_queue = virtio_pci_modern_notify_queue,
  .set_config_irq = virtio_pci_modern_set_msix_config,
  .set_queue_irq = virtio_pci_modern_set_queue_msix_vector,
  .get_mac = virtio_pci_modern_get_device_mac,
  .set_mac = virtio_pci_modern_set_device_mac,
  .get_device_status = virtio_pci_modern_get_device_status,
  .get_max_queue_pairs = virtio_pci_modern_get_max_virtqueue_pairs,
  .get_mtu = virtio_pci_modern_get_device_mtu,
  .device_debug_config_space = virtio_pci_modern_device_debug_config_space,
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
