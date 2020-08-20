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

/* common configuration */
#define VIRTIO_FEATURE_SELECT_HI 1
#define VIRTIO_FEATURE_SELECT_LO 0

#define VIRTIO_DEVICE_FEATURE_SELECT_OFFSET(v)                    \
   (v->common_offset + STRUCT_OFFSET_OF (virtio_pci_common_cfg_t, \
					 device_feature_select))
#define VIRTIO_DEVICE_FEATURE_OFFSET(v)                           \
   (v->common_offset + STRUCT_OFFSET_OF (virtio_pci_common_cfg_t, \
					        device_feature))
#define VIRTIO_DRIVER_FEATURE_SELECT_OFFSET(v)                    \
   (v->common_offset + STRUCT_OFFSET_OF (virtio_pci_common_cfg_t, \
					 driver_feature_select))
#define VIRTIO_DRIVER_FEATURE_OFFSET(v)                           \
   (v->common_offset + STRUCT_OFFSET_OF (virtio_pci_common_cfg_t, \
					        driver_feature))
#define VIRTIO_MSIX_CONFIG_VECTOR_OFFSET(v)                       \
   (v->common_offset + STRUCT_OFFSET_OF (virtio_pci_common_cfg_t, \
					           msix_config))
#define VIRTIO_NUM_QUEUES_OFFSET(v)                               \
   (v->common_offset + STRUCT_OFFSET_OF (virtio_pci_common_cfg_t, \
					            num_queues))
#define VIRTIO_DEVICE_STATUS_OFFSET(v)                            \
   (v->common_offset + STRUCT_OFFSET_OF (virtio_pci_common_cfg_t, \
					         device_status))
#define VIRTIO_CONFIG_GENERATION_OFFSET(v)                        \
   (v->common_offset + STRUCT_OFFSET_OF (virtio_pci_common_cfg_t, \
					     config_generation))
#define VIRTIO_QUEUE_SELECT_OFFSET(v)                             \
   (v->common_offset + STRUCT_OFFSET_OF (virtio_pci_common_cfg_t, \
					          queue_select))
#define VIRTIO_QUEUE_SIZE_OFFSET(v)                               \
   (v->common_offset + STRUCT_OFFSET_OF (virtio_pci_common_cfg_t, \
					            queue_size))
#define VIRTIO_QUEUE_MSIX_VECTOR_OFFSET(v)                        \
   (v->common_offset + STRUCT_OFFSET_OF (virtio_pci_common_cfg_t, \
					     queue_msix_vector))
#define VIRTIO_QUEUE_ENABLE_OFFSET(v)                             \
   (v->common_offset + STRUCT_OFFSET_OF (virtio_pci_common_cfg_t, \
					          queue_enable))
#define VIRTIO_QUEUE_NOTIFY_OFF_OFFSET(v)                         \
   (v->common_offset + STRUCT_OFFSET_OF (virtio_pci_common_cfg_t, \
					      queue_notify_off))
#define VIRTIO_QUEUE_DESC_OFFSET(v)                               \
   (v->common_offset + STRUCT_OFFSET_OF (virtio_pci_common_cfg_t, \
					            queue_desc))
#define VIRTIO_QUEUE_DRIVER_OFFSET(v)                             \
   (v->common_offset + STRUCT_OFFSET_OF (virtio_pci_common_cfg_t, \
					          queue_driver))
#define VIRTIO_QUEUE_DEVICE_OFFSET(v)                             \
   (v->common_offset + STRUCT_OFFSET_OF (virtio_pci_common_cfg_t, \
					          queue_device))
/* device configuration */
#define VIRTIO_MAC_OFFSET(v)                                      \
   (v->device_offset + STRUCT_OFFSET_OF (virtio_net_config_t,     \
					                   mac))
#define VIRTIO_STATUS_OFFSET(v)                                   \
   (v->device_offset + STRUCT_OFFSET_OF (virtio_net_config_t,     \
					                status))
#define VIRTIO_MAX_VIRTQUEUE_PAIRS_OFFSET(v)                      \
   (v->device_offset + STRUCT_OFFSET_OF (virtio_net_config_t,     \
					   max_virtqueue_pairs))
#define VIRTIO_MTU_OFFSET(v)                                      \
   (v->device_offset + STRUCT_OFFSET_OF (virtio_net_config_t,     \
					                   mtu))
/* interrupt service routine */
#define VIRTIO_ISR_OFFSET(v) (v->isr_offset)
/* notification */
#define VIRTIO_NOTIFICATION_OFFSET(v) (v->notify_offset)

#define _(t)                                                         \
static_always_inline t                                               \
virtio_pci_reg_read_##t (virtio_if_t * vif, u32 offset)              \
{                                                                    \
  t val;                                                             \
  val = *(volatile t *) (vif->bar + offset);		             \
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
}

_(u64);
_(u32);
_(u16);
_(u8);

#undef _

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
