/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2020-2025 Cisco and/or its affiliates.
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

u64
virtio_pci_get_device_features (vlib_main_t *vm, virtio_if_t *vif)
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

u64
virtio_pci_get_driver_features (vlib_main_t *vm, virtio_if_t *vif)
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

void
virtio_pci_set_driver_features (vlib_main_t *vm, virtio_if_t *vif,
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

  if (features != virtio_pci_get_driver_features (vm, vif))
    {
      clib_warning ("modern set guest features failed!");
    }
}

static u16
virtio_pci_get_msix_config (virtio_if_t *vif)
{
  u16 msix_config;
  msix_config =
    virtio_pci_reg_read_u16 (vif, VIRTIO_MSIX_CONFIG_VECTOR_OFFSET (vif));
  return msix_config;
}

u16
virtio_pci_set_config_irq (vlib_main_t *vm, virtio_if_t *vif, u16 msix_config)
{
  virtio_pci_reg_write_u16 (vif, VIRTIO_MSIX_CONFIG_VECTOR_OFFSET (vif),
			    msix_config);
  return virtio_pci_get_msix_config (vif);
}

static u16
virtio_pci_get_num_queues (virtio_if_t *vif)
{
  u16 num_queues = 0;
  num_queues = virtio_pci_reg_read_u16 (vif, VIRTIO_NUM_QUEUES_OFFSET (vif));
  return num_queues;
}

u8
virtio_pci_get_status (vlib_main_t *vm, virtio_if_t *vif)
{
  u8 status = 0;
  status = virtio_pci_reg_read_u8 (vif, VIRTIO_DEVICE_STATUS_OFFSET (vif));
  return status;
}

void
virtio_pci_set_status (vlib_main_t *vm, virtio_if_t *vif, u8 status)
{
  if (status != VIRTIO_CONFIG_STATUS_RESET)
    status |= virtio_pci_get_status (vm, vif);
  virtio_pci_reg_write_u8 (vif, VIRTIO_DEVICE_STATUS_OFFSET (vif), status);
}

u8
virtio_pci_device_reset (vlib_main_t *vm, virtio_if_t *vif)
{
  virtio_pci_set_status (vm, vif, VIRTIO_CONFIG_STATUS_RESET);
  return virtio_pci_get_status (vm, vif);
}

static u8
virtio_pci_get_config_generation (virtio_if_t *vif)
{
  u8 config_generation = 0;
  config_generation =
    virtio_pci_reg_read_u8 (vif, VIRTIO_CONFIG_GENERATION_OFFSET (vif));
  return config_generation;
}

static void
virtio_pci_set_queue_select (virtio_if_t *vif, u16 queue_select)
{
  virtio_pci_reg_write_u16 (vif, VIRTIO_QUEUE_SELECT_OFFSET (vif),
			    queue_select);
}

u16
virtio_pci_get_queue_size (vlib_main_t *vm, virtio_if_t *vif, u16 queue_id)
{
  u16 queue_size = 0;
  virtio_pci_set_queue_select (vif, queue_id);
  queue_size = virtio_pci_reg_read_u16 (vif, VIRTIO_QUEUE_SIZE_OFFSET (vif));
  return queue_size;
}

void
virtio_pci_set_queue_size (vlib_main_t *vm, virtio_if_t *vif, u16 queue_id,
			   u16 queue_size)
{
  if (!is_pow2 (queue_size))
    {
      return;
    }

  virtio_pci_reg_write_u16 (vif, VIRTIO_QUEUE_SIZE_OFFSET (vif), queue_size);
}

static u16
virtio_pci_get_queue_msix_vector (virtio_if_t *vif)
{
  u16 queue_msix_vector = 0;
  queue_msix_vector =
    virtio_pci_reg_read_u16 (vif, VIRTIO_QUEUE_MSIX_VECTOR_OFFSET (vif));
  return queue_msix_vector;
}

u16
virtio_pci_set_queue_irq (vlib_main_t *vm, virtio_if_t *vif,
			  u16 queue_msix_vector, u16 queue_id)
{
  virtio_pci_set_queue_select (vif, queue_id);
  virtio_pci_reg_write_u16 (vif, VIRTIO_QUEUE_MSIX_VECTOR_OFFSET (vif),
			    queue_msix_vector);
  return virtio_pci_get_queue_msix_vector (vif);
}

static u16
virtio_pci_get_queue_enable (virtio_if_t *vif, u16 queue_id)
{
  u16 queue_enable = 0;
  virtio_pci_set_queue_select (vif, queue_id);
  queue_enable =
    virtio_pci_reg_read_u16 (vif, VIRTIO_QUEUE_ENABLE_OFFSET (vif));
  return queue_enable;
}

static void
virtio_pci_set_queue_enable (virtio_if_t *vif, u16 queue_id, u16 queue_enable)
{
  virtio_pci_set_queue_select (vif, queue_id);
  virtio_pci_reg_write_u16 (vif, VIRTIO_QUEUE_ENABLE_OFFSET (vif),
			    queue_enable);
}

u16
virtio_pci_get_queue_notify_off (vlib_main_t *vm, virtio_if_t *vif,
				 u16 queue_id)
{
  u16 queue_notify_off = 0;
  virtio_pci_set_queue_select (vif, queue_id);
  queue_notify_off =
    virtio_pci_reg_read_u16 (vif, VIRTIO_QUEUE_NOTIFY_OFF_OFFSET (vif));
  return queue_notify_off;
}

static u64
virtio_pci_get_queue_desc (virtio_if_t *vif)
{
  u64 queue_desc = 0;
  queue_desc = virtio_pci_reg_read_u64 (vif, VIRTIO_QUEUE_DESC_OFFSET (vif));
  return queue_desc;
}

static void
virtio_pci_set_queue_desc (virtio_if_t *vif, u64 queue_desc)
{
  virtio_pci_reg_write_u64 (vif, VIRTIO_QUEUE_DESC_OFFSET (vif), queue_desc);
}

static u64
virtio_pci_get_queue_driver (virtio_if_t *vif)
{
  u64 queue_driver = 0;
  queue_driver =
    virtio_pci_reg_read_u64 (vif, VIRTIO_QUEUE_DRIVER_OFFSET (vif));
  return queue_driver;
}

static void
virtio_pci_set_queue_driver (virtio_if_t *vif, u64 queue_driver)
{
  virtio_pci_reg_write_u64 (vif, VIRTIO_QUEUE_DRIVER_OFFSET (vif),
			    queue_driver);
}

static u64
virtio_pci_get_queue_device (virtio_if_t *vif)
{
  u64 queue_device = 0;
  queue_device =
    virtio_pci_reg_read_u64 (vif, VIRTIO_QUEUE_DEVICE_OFFSET (vif));
  return queue_device;
}

static void
virtio_pci_set_queue_device (virtio_if_t *vif, u64 queue_device)
{
  virtio_pci_reg_write_u64 (vif, VIRTIO_QUEUE_DEVICE_OFFSET (vif),
			    queue_device);
}

u8
virtio_pci_setup_queue (vlib_main_t *vm, virtio_if_t *vif, u16 queue_id,
			vnet_virtio_vring_t *vring)
{
  u64 desc, avail, used;

  virtio_pci_set_queue_select (vif, queue_id);

  if (vif->is_packed)
    {
      desc = vlib_physmem_get_pa (vm, vring->packed_desc);
      avail = vlib_physmem_get_pa (vm, vring->driver_event);
      used = vlib_physmem_get_pa (vm, vring->device_event);
    }
  else
    {
      desc = vlib_physmem_get_pa (vm, vring->desc);
      avail = vlib_physmem_get_pa (vm, vring->avail);
      used = vlib_physmem_get_pa (vm, vring->used);
    }

  virtio_pci_set_queue_desc (vif, desc);
  if (desc != virtio_pci_get_queue_desc (vif))
    return 1;

  virtio_pci_set_queue_driver (vif, avail);
  if (avail != virtio_pci_get_queue_driver (vif))
    return 1;

  virtio_pci_set_queue_device (vif, used);
  if (used != virtio_pci_get_queue_device (vif))
    return 1;

  virtio_pci_set_queue_enable (vif, queue_id, 1);

  if (virtio_pci_get_queue_enable (vif, queue_id))
    return 0;

  return 1;
}

void
virtio_pci_del_queue (vlib_main_t *vm, virtio_if_t *vif, u16 queue_id)
{
  virtio_pci_set_queue_select (vif, queue_id);
  virtio_pci_set_queue_enable (vif, queue_id, 0);
  virtio_pci_set_queue_desc (vif, 0);
  virtio_pci_set_queue_driver (vif, 0);
  virtio_pci_set_queue_device (vif, 0);
}

u32
virtio_pci_get_mac (vlib_main_t *vm, virtio_if_t *vif)
{
  vif->mac_addr32 = virtio_pci_reg_read_u32 (vif, VIRTIO_MAC_OFFSET (vif));
  vif->mac_addr16 = virtio_pci_reg_read_u16 (vif, VIRTIO_MAC_OFFSET (vif) + 4);
  return 0;
}

void
virtio_pci_set_mac (vlib_main_t *vm, virtio_if_t *vif)
{
  virtio_pci_reg_write_u32 (vif, VIRTIO_MAC_OFFSET (vif), vif->mac_addr32);
  virtio_pci_reg_write_u16 (vif, VIRTIO_MAC_OFFSET (vif) + 4, vif->mac_addr16);
}

u16
virtio_pci_get_device_status (vlib_main_t *vm, virtio_if_t *vif)
{
  u16 status = 0;
  status = virtio_pci_reg_read_u16 (vif, VIRTIO_STATUS_OFFSET (vif));
  return status;
}

u16
virtio_pci_get_max_virtqueue_pairs (vlib_main_t *vm, virtio_if_t *vif)
{
  u16 max_virtqueue_pairs = 0;
  max_virtqueue_pairs =
    virtio_pci_reg_read_u16 (vif, VIRTIO_MAX_VIRTQUEUE_PAIRS_OFFSET (vif));
  u16 supported_queues = virtio_pci_get_num_queues (vif);
  virtio_log_debug (vif, "max-virtqueue-pairs %u, supported-queues %u",
		    max_virtqueue_pairs, supported_queues);
  return max_virtqueue_pairs;
}

u16
virtio_pci_get_mtu (vlib_main_t *vm, virtio_if_t *vif)
{
  u16 mtu = 0;
  mtu = virtio_pci_reg_read_u16 (vif, VIRTIO_MTU_OFFSET (vif));
  return mtu;
}

void
virtio_pci_read_config (vlib_main_t *vm, virtio_if_t *vif, void *dst, int len,
			u32 addr)
{
  u8 config_count;
  do
    {
      config_count = virtio_pci_get_config_generation (vif);
      virtio_pci_get_mac (vm, vif);
      u16 status = virtio_pci_get_device_status (vm, vif);
      u16 max_queue_pairs = virtio_pci_get_max_virtqueue_pairs (vm, vif);
      u16 mtu = virtio_pci_get_mtu (vm, vif);
      virtio_log_debug (vif, "status %u, max_queue_pairs %u, mtu %u", status,
			max_queue_pairs, mtu);
    }
  while (config_count != virtio_pci_get_config_generation (vif));
}

void
virtio_pci_write_config (vlib_main_t *vm, virtio_if_t *vif, void *src, int len,
			 u32 addr)
{
  // do nothing
}

u8
virtio_pci_get_isr (vlib_main_t *vm, virtio_if_t *vif)
{
  return virtio_pci_reg_read_u8 (vif, VIRTIO_ISR_OFFSET (vif));
}

void
virtio_pci_notify_queue (vlib_main_t *vm, virtio_if_t *vif, u16 queue_id,
			 u16 queue_notify_off)
{
  virtio_pci_reg_write_u16 (
    vif, VIRTIO_NOTIFICATION_OFFSET (vif) + queue_notify_off, queue_id);
}
