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

#include <vnet/devices/virtio/virtio.h>
#include <vnet/devices/virtio/pci.h>


#define VIRTIO_FEATURE_SELECT_HI 1
#define VIRTIO_FEATURE_SELECT_LO 0


#define VIRTIO_DEVICE_FEATURE_SELECT_OFFSET(v) (v->common_offset + STRUCT_OFFSET_OF (virtio_pci_common_cfg_t, device_feature_select))
#define VIRTIO_DEVICE_FEATURE_OFFSET(v) (v->common_offset + STRUCT_OFFSET_OF (virtio_pci_common_cfg_t, device_feature))
#define VIRTIO_DRIVER_FEATURE_SELECT_OFFSET(v) (v->common_offset + STRUCT_OFFSET_OF (virtio_pci_common_cfg_t, driver_feature_select))
#define VIRTIO_DRIVER_FEATURE_OFFSET(v) (v->common_offset + STRUCT_OFFSET_OF (virtio_pci_common_cfg_t, driver_feature))
#define VIRTIO_MSIX_CONFIG_VECTOR_OFFSET(v) (v->common_offset + STRUCT_OFFSET_OF (virtio_pci_common_cfg_t, msix_config))
#define VIRTIO_NUM_QUEUES_OFFSET(v) (v->common_offset + STRUCT_OFFSET_OF (virtio_pci_common_cfg_t, num_queues))
#define VIRTIO_DEVICE_STATUS_OFFSET(v) (v->common_offset + STRUCT_OFFSET_OF (virtio_pci_common_cfg_t, device_status))
#define VIRTIO_CONFIG_GENERATION_OFFSET(v) (v->common_offset + STRUCT_OFFSET_OF (virtio_pci_common_cfg_t, config_generation))
#define VIRTIO_QUEUE_SELECT_OFFSET(v) (v->common_offset + STRUCT_OFFSET_OF (virtio_pci_common_cfg_t, queue_select))
#define VIRTIO_QUEUE_SIZE_OFFSET(v) (v->common_offset + STRUCT_OFFSET_OF (virtio_pci_common_cfg_t, queue_size))
#define VIRTIO_QUEUE_MSIX_VECTOR_OFFSET(v) (v->common_offset + STRUCT_OFFSET_OF (virtio_pci_common_cfg_t, queue_msix_vector))
#define VIRTIO_QUEUE_ENABLE_OFFSET(v) (v->common_offset + STRUCT_OFFSET_OF (virtio_pci_common_cfg_t, queue_enable))
#define VIRTIO_QUEUE_NOTIFY_OFF_OFFSET(v) (v->common_offset + STRUCT_OFFSET_OF (virtio_pci_common_cfg_t, queue_notify_off))
#define VIRTIO_QUEUE_DESC_OFFSET(v) (v->common_offset + STRUCT_OFFSET_OF (virtio_pci_common_cfg_t, queue_desc))
#define VIRTIO_QUEUE_DRIVER_OFFSET(v) (v->common_offset + STRUCT_OFFSET_OF (virtio_pci_common_cfg_t, queue_driver))
#define VIRTIO_QUEUE_DEVICE_OFFSET(v) (v->common_offset + STRUCT_OFFSET_OF (virtio_pci_common_cfg_t, queue_device))

#define VIRTIO_MAC_OFFSET(v) (v->device_offset + STRUCT_OFFSET_OF (virtio_net_config_t, mac))
#define VIRTIO_STATUS_OFFSET(v) (v->device_offset + STRUCT_OFFSET_OF (virtio_net_config_t, status))
#define VIRTIO_MAX_VIRTQUEUE_PAIRS_OFFSET(v) (v->device_offset + STRUCT_OFFSET_OF (virtio_net_config_t, max_virtqueue_pairs))
#define VIRTIO_MTU_OFFSET(v) (v->device_offset + STRUCT_OFFSET_OF (virtio_net_config_t, mtu))

#define VIRTIO_ISR_OFFSET(v) (v->isr_offset)

static_always_inline void
virtio_pci_reg_write_inline (virtio_if_t * vif, u32 addr, u32 val)
{
  *(volatile u32 *) ((u8 *) vif->bar + addr) = val;
}

static_always_inline void
virtio_pci_reg_write (virtio_if_t * vif, u32 addr, u32 val)
{
  virtio_log_debug (vif, "reg wr addr 0x%x val 0x%x", addr, val);
  virtio_pci_reg_write_inline (vif, addr, val);
}

static_always_inline u32
virtio_pci_reg_read (virtio_if_t * vif, u32 addr)
{
  u32 val;

  val = *(volatile u32 *) (vif->bar + addr);
  virtio_log_debug (vif, "reg rd addr 0x%x val 0x%x", addr, val);

  return val;
}

#define _(t)                                                         \
static_always_inline t                                               \
virtio_pci_reg_read_##t (virtio_if_t * vif, u32 offset)              \
{                                                                    \
  t val;                                                             \
  val = *(volatile t *) (vif->bar + offset);		             \
  virtio_log_debug (vif, "reg rd addr 0x%x val 0x%x", offset, val);  \
  return val;                                                        \
}

_(u64);
_(u32);
_(u16);
_(u8);

#undef _

#define _(t)                                                         \
static_always_inline void                                            \
virtio_pci_reg_write_##t (virtio_if_t * vif, u32 offset, t val)      \
{                                                                    \
  *(volatile t *) ((u8 *) vif->bar + offset) = val;	             \
  virtio_log_debug (vif, "reg rd addr 0x%x val 0x%x", offset, val);  \
}

_(u64);
_(u32);
_(u16);
_(u8);

#undef _

static u64
virtio_pci_modern_get_device_features (virtio_if_t * vif)
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
virtio_pci_modern_get_driver_features (virtio_if_t * vif)
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

static u64
virtio_pci_modern_set_driver_features (virtio_if_t * vif, u64 features)
{
  if ((features >> 32) != 0)
    {
      clib_warning ("only 32 bit features are allowed for modern virtio!");
    }

  u32 features_lo = (u32) features, features_hi = (u32) (features >> 32);
  virtio_pci_reg_write_u32 (vif, VIRTIO_DRIVER_FEATURE_SELECT_OFFSET (vif),
			    VIRTIO_FEATURE_SELECT_LO);
  virtio_pci_reg_write_u32 (vif, VIRTIO_DRIVER_FEATURE_OFFSET (vif),
			    features_lo);
  virtio_pci_reg_write_u32 (vif, VIRTIO_DRIVER_FEATURE_SELECT_OFFSET (vif),
			    VIRTIO_FEATURE_SELECT_HI);
  virtio_pci_reg_write_u32 (vif, VIRTIO_DRIVER_FEATURE_OFFSET (vif),
			    features_hi);

  virtio_pci_modern_get_driver_features (vif);
  return vif->features;
}

static u16
virtio_pci_modern_get_msix_config (virtio_if_t * vif)
{
  u16 msix_config;
  msix_config =
    virtio_pci_reg_read_u16 (vif, VIRTIO_MSIX_CONFIG_VECTOR_OFFSET (vif));
  return msix_config;
}

static void
virtio_pci_modern_set_msix_config (virtio_if_t * vif, u16 msix_config)
{
  virtio_pci_reg_write_u16 (vif, VIRTIO_MSIX_CONFIG_VECTOR_OFFSET (vif),
			    msix_config);
}

static u16
virtio_pci_modern_get_num_queues (virtio_if_t * vif)
{
  u16 num_queues = 0;
  num_queues = virtio_pci_reg_read_u16 (vif, VIRTIO_NUM_QUEUES_OFFSET (vif));
  return num_queues;
}

static u8
virtio_pci_modern_get_status (virtio_if_t * vif)
{
  u8 status = 0;
  status = virtio_pci_reg_read_u8 (vif, VIRTIO_DEVICE_STATUS_OFFSET (vif));
  return status;
}

static void
virtio_pci_modern_set_status (virtio_if_t * vif, u8 status)
{
  if (status != VIRTIO_CONFIG_STATUS_RESET)
    status |= virtio_pci_modern_get_status (vif);
  virtio_pci_reg_write_u8 (vif, VIRTIO_DEVICE_STATUS_OFFSET (vif), status);
}

static u8
virtio_pci_modern_reset (virtio_if_t * vif)
{
  virtio_pci_modern_set_status (vif, VIRTIO_CONFIG_STATUS_RESET);
  return virtio_pci_modern_get_status (vif);
}

static u8
virtio_pci_modern_get_config_generation (virtio_if_t * vif)
{
  u8 config_generation = 0;
  config_generation =
    virtio_pci_reg_read_u8 (vif, VIRTIO_CONFIG_GENERATION_OFFSET (vif));
  return config_generation;
}

/*static u8
virtio_pci_modern_get_isr (vlib_main_t * vm, virtio_if_t * vif)
{
  u8 isr = 0;
  vlib_pci_read_io_u8 (vm, vif->pci_dev_handle, VIRTIO_PCI_ISR, &isr);
  return isr;
}
*/

static u16
virtio_pci_modern_get_queue_select (virtio_if_t * vif)
{
  u16 queue_num = 0;
  queue_num = virtio_pci_reg_read_u16 (vif, VIRTIO_QUEUE_SELECT_OFFSET (vif));
  return queue_num;
}

static void
virtio_pci_modern_set_queue_select (virtio_if_t * vif, u16 queue_select)
{
  virtio_pci_reg_write_u16 (vif, VIRTIO_QUEUE_SELECT_OFFSET (vif),
			    queue_select);
}

static u16
virtio_pci_modern_get_queue_size (virtio_if_t * vif, u16 queue_id)
{
  u16 queue_size = 0;
  virtio_pci_modern_set_queue_select (vif, queue_id);
  queue_size = virtio_pci_reg_read_u16 (vif, VIRTIO_QUEUE_SIZE_OFFSET (vif));
  return queue_size;
}

static void
virtio_pci_modern_set_queue_size (virtio_if_t * vif, u16 queue_id,
				  u16 queue_size)
{
  if (vif->features & VIRTIO_F_RING_PACKED)
    {
      if (queue_size == 0)
	return;
    }
  else if (!is_pow2 (queue_size))
    {
      return;
    }

  if (virtio_pci_modern_get_queue_size (vif, queue_id) > queue_size)
    virtio_pci_reg_write_u16 (vif, VIRTIO_QUEUE_SIZE_OFFSET (vif),
			      queue_size);
}

static u16
virtio_pci_modern_get_queue_msix_vector (virtio_if_t * vif, u16 queue_id)
{
  u16 queue_msix_vector = 0;
  virtio_pci_modern_set_queue_select (vif, queue_id);
  queue_msix_vector =
    virtio_pci_reg_read_u16 (vif, VIRTIO_QUEUE_MSIX_VECTOR_OFFSET (vif));
  return queue_msix_vector;
}

static void
virtio_pci_modern_set_queue_msix_vector (virtio_if_t * vif, u16 queue_id,
					 u16 queue_msix_vector)
{
  virtio_pci_modern_set_queue_select (vif, queue_id);
  virtio_pci_reg_write_u16 (vif, VIRTIO_QUEUE_MSIX_VECTOR_OFFSET (vif),
			    queue_msix_vector);
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
virtio_pci_modern_get_queue_notify_off (virtio_if_t * vif, u16 queue_id)
{
  u16 queue_notify_off = 0;
  virtio_pci_modern_set_queue_select (vif, queue_id);
  queue_notify_off =
    virtio_pci_reg_read_u16 (vif, VIRTIO_QUEUE_NOTIFY_OFF_OFFSET (vif));
  return queue_notify_off;
}

static u64
virtio_pci_modern_get_queue_desc (virtio_if_t * vif, u16 queue_id)
{
  u64 queue_desc = 0;
  virtio_pci_modern_set_queue_select (vif, queue_id);
  queue_desc = virtio_pci_reg_read_u64 (vif, VIRTIO_QUEUE_DESC_OFFSET (vif));
  return queue_desc;
}

static void
virtio_pci_modern_set_queue_desc (virtio_if_t * vif, u16 queue_id,
				  u64 queue_desc)
{
  virtio_pci_modern_set_queue_select (vif, queue_id);
  virtio_pci_reg_write_u64 (vif, VIRTIO_QUEUE_DESC_OFFSET (vif), queue_desc);
}

static u64
virtio_pci_modern_get_queue_driver (virtio_if_t * vif, u16 queue_id)
{
  u64 queue_driver = 0;
  virtio_pci_modern_set_queue_select (vif, queue_id);
  queue_driver =
    virtio_pci_reg_read_u64 (vif, VIRTIO_QUEUE_DRIVER_OFFSET (vif));
  return queue_driver;
}

static void
virtio_pci_modern_set_queue_driver (virtio_if_t * vif, u16 queue_id,
				    u64 queue_driver)
{
  virtio_pci_modern_set_queue_select (vif, queue_id);
  virtio_pci_reg_write_u64 (vif, VIRTIO_QUEUE_DRIVER_OFFSET (vif),
			    queue_driver);
}

static u64
virtio_pci_modern_get_queue_device (virtio_if_t * vif, u16 queue_id)
{
  u64 queue_device = 0;
  virtio_pci_modern_set_queue_select (vif, queue_id);
  queue_device =
    virtio_pci_reg_read_u64 (vif, VIRTIO_QUEUE_DEVICE_OFFSET (vif));
  return queue_device;
}

static void
virtio_pci_modern_set_queue_device (virtio_if_t * vif, u16 queue_id,
				    u64 queue_device)
{
  virtio_pci_modern_set_queue_select (vif, queue_id);
  virtio_pci_reg_write_u64 (vif, VIRTIO_QUEUE_DEVICE_OFFSET (vif),
			    queue_device);
}

static u16
virtio_pci_modern_device_status (virtio_if_t * vif)
{
  u16 status = 0;
  status = virtio_pci_reg_read_u16 (vif, VIRTIO_STATUS_OFFSET (vif));
  return status;
}

static u16
virtio_pci_modern_max_virtqueue_pairs (virtio_if_t * vif)
{
  u16 max_virtqueue_pairs = 0;
  max_virtqueue_pairs =
    virtio_pci_reg_read_u16 (vif, VIRTIO_MAX_VIRTQUEUE_PAIRS_OFFSET (vif));
  return max_virtqueue_pairs;
}

static u16
virtio_pci_modern_device_mtu (virtio_if_t * vif)
{
  u16 mtu = 0;
  mtu = virtio_pci_reg_read_u16 (vif, VIRTIO_MTU_OFFSET (vif));
  return mtu;
}

static void
virtio_pci_modern_device_mac (virtio_if_t * vif)
{
  *((u32 *) vif->mac_addr) =
    virtio_pci_reg_read_u32 (vif, VIRTIO_MAC_OFFSET (vif));
  *((u16 *) (vif->mac_addr + 4)) =
    virtio_pci_reg_read_u16 (vif, VIRTIO_MAC_OFFSET (vif) + 4);
}

static void
virtio_pci_modern_set_device_mac (virtio_if_t * vif)
{
  virtio_pci_reg_write_u32 (vif, VIRTIO_MAC_OFFSET (vif),
			    *((u32 *) vif->mac_addr));
  virtio_pci_reg_write_u16 (vif, VIRTIO_MAC_OFFSET (vif) + 4,
			    *((u16 *) (vif->mac_addr + 4)));
}

static u8
virtio_pci_modern_get_isr (virtio_if_t * vif)
{
  return virtio_pci_reg_read_u8 (vif, VIRTIO_ISR_OFFSET (vif));
}

clib_error_t *virtio_pci_device_init_modern (vlib_main_t * vm,
					     virtio_if_t * vif,
					     virtio_pci_create_if_args_t *
					     args);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
