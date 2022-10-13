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

#ifndef __included_virtio_pci_h__
#define __included_virtio_pci_h__

/* VirtIO ABI version, this must match exactly. */
#define VIRTIO_PCI_ABI_VERSION 0

/* VirtIO device IDs. */
#define VIRTIO_ID_NETWORK  0x01

/*
 * Vector value used to disable MSI for queue.
 * define in include/linux/virtio_pci.h
 */
#define VIRTIO_MSI_NO_VECTOR 0xFFFF

/* The bit of the ISR which indicates a device has an interrupt. */
#define VIRTIO_PCI_ISR_INTR   0x1
/* The bit of the ISR which indicates a device configuration change. */
#define VIRTIO_PCI_ISR_CONFIG 0x2

/* Status byte for guest to report progress. */
#define foreach_virtio_config_status_flags	\
  _ (VIRTIO_CONFIG_STATUS_RESET, 0x00)		\
  _ (VIRTIO_CONFIG_STATUS_ACK, 0x01)		\
  _ (VIRTIO_CONFIG_STATUS_DRIVER, 0x02)		\
  _ (VIRTIO_CONFIG_STATUS_DRIVER_OK, 0x04)	\
  _ (VIRTIO_CONFIG_STATUS_FEATURES_OK, 0x08)	\
  _ (VIRTIO_CONFIG_STATUS_DEVICE_NEEDS_RESET, 0x40) \
  _ (VIRTIO_CONFIG_STATUS_FAILED, 0x80)

typedef enum
{
#define _(a, b) a = b,
  foreach_virtio_config_status_flags
#undef _
} virtio_config_status_flags_t;


#define VIRTIO_NET_S_LINK_UP    1	/* Link is up */
#define VIRTIO_NET_S_ANNOUNCE   2	/* Announcement is needed */

#define VIRTIO_NET_OK     0
#define VIRTIO_NET_ERR    1

/* If multiqueue is provided by host, then we support it. */
#define VIRTIO_NET_CTRL_MQ   4
#define VIRTIO_NET_CTRL_MQ_VQ_PAIRS_SET        0
#define VIRTIO_NET_CTRL_MQ_VQ_PAIRS_MIN        1
#define VIRTIO_NET_CTRL_MQ_VQ_PAIRS_MAX        0x8000

/*
 * Control network offloads
 * Reconfigures the network offloads that Guest can handle.
 * Available with the VIRTIO_NET_F_CTRL_GUEST_OFFLOADS feature bit.
 * Command data format matches the feature bit mask exactly.
 * See VIRTIO_NET_F_GUEST_* for the list of offloads
 * that can be enabled/disabled.
 */
#define VIRTIO_NET_CTRL_GUEST_OFFLOADS 5
#define VIRTIO_NET_CTRL_GUEST_OFFLOADS_SET 0

/* Common configuration */
#define VIRTIO_PCI_CAP_COMMON_CFG       1
/* Notifications */
#define VIRTIO_PCI_CAP_NOTIFY_CFG       2
/* ISR Status */
#define VIRTIO_PCI_CAP_ISR_CFG          3
/* Device specific configuration */
#define VIRTIO_PCI_CAP_DEVICE_CFG       4
/* PCI configuration access */
#define VIRTIO_PCI_CAP_PCI_CFG          5

#define VIRTIO_PCI_QUEUE_ADDR_SHIFT 12

#define VNET_VIRTIO_PCI_VRING_ALIGN 4096

typedef enum
{
  VIRTIO_MSIX_NONE = 0,
  VIRTIO_MSIX_DISABLED = 1,
  VIRTIO_MSIX_ENABLED = 2
} virtio_msix_status_t;

/* This is the PCI capability header: */
typedef struct
{
  u8 cap_vndr;			/* Generic PCI field: PCI_CAP_ID_VNDR */
  u8 cap_next;			/* Generic PCI field: next ptr. */
  u8 cap_len;			/* Generic PCI field: capability length */
  u8 cfg_type;			/* Identifies the structure. */
  u8 bar;			/* Where to find it. */
  u8 padding[3];		/* Pad to full dword. */
  u32 offset;			/* Offset within bar. */
  u32 length;			/* Length of the structure, in bytes. */
} virtio_pci_cap_t;

typedef struct
{
  virtio_pci_cap_t cap;
  u32 notify_off_multiplier;	/* Multiplier for queue_notify_off. */
} virtio_pci_notify_cap_t;

/* Fields in VIRTIO_PCI_CAP_COMMON_CFG: */
typedef struct
{
  /* About the whole device. */
  u32 device_feature_select;	/* read-write */
  u32 device_feature;		/* read-only */
  u32 driver_feature_select;	/* read-write */
  u32 driver_feature;		/* read-write */
  u16 msix_config;		/* read-write */
  u16 num_queues;		/* read-only */
  u8 device_status;		/* read-write */
  u8 config_generation;		/* read-only */

  /* About a specific virtqueue. */
  u16 queue_select;		/* read-write */
  u16 queue_size;		/* read-write, power of 2. */
  u16 queue_msix_vector;	/* read-write */
  u16 queue_enable;		/* read-write */
  u16 queue_notify_off;		/* read-only */
  u64 queue_desc;		/* read-write */
  u64 queue_driver;		/* read-write */
  u64 queue_device;		/* read-write */
} virtio_pci_common_cfg_t;

typedef struct
{
  u8 mac[6];
  u16 status;
  u16 max_virtqueue_pairs;
  u16 mtu;
} virtio_net_config_t;

/*
 * Control virtqueue data structures
 *
 * The control virtqueue expects a header in the first sg entry
 * and an ack/status response in the last entry.  Data for the
 * command goes in between.
 */
/* *INDENT-OFF* */
typedef CLIB_PACKED (struct
{
  u8 class;
  u8 cmd;
}) virtio_net_ctrl_hdr_t;
/* *INDENT-ON* */

typedef u8 virtio_net_ctrl_ack_t;

typedef struct
{
  virtio_net_ctrl_hdr_t ctrl;
  virtio_net_ctrl_ack_t status;
  u8 data[1024];
} virtio_ctrl_msg_t;

typedef struct _virtio_pci_func
{
  void (*read_config) (vlib_main_t * vm, virtio_if_t * vif, void *dst,
		       int len, u32 addr);
  void (*write_config) (vlib_main_t * vm, virtio_if_t * vif, void *src,
			int len, u32 addr);

    u64 (*get_device_features) (vlib_main_t * vm, virtio_if_t * vif);
    u64 (*get_driver_features) (vlib_main_t * vm, virtio_if_t * vif);
  void (*set_driver_features) (vlib_main_t * vm, virtio_if_t * vif,
			       u64 features);

    u8 (*get_status) (vlib_main_t * vm, virtio_if_t * vif);
  void (*set_status) (vlib_main_t * vm, virtio_if_t * vif, u8 status);
    u8 (*device_reset) (vlib_main_t * vm, virtio_if_t * vif);

    u8 (*get_isr) (vlib_main_t * vm, virtio_if_t * vif);

    u16 (*get_queue_size) (vlib_main_t * vm, virtio_if_t * vif, u16 queue_id);
  void (*set_queue_size) (vlib_main_t * vm, virtio_if_t * vif, u16 queue_id,
			  u16 queue_size);
  u8 (*setup_queue) (vlib_main_t *vm, virtio_if_t *vif, u16 queue_id,
		     vnet_virtio_vring_t *vring);
  void (*del_queue) (vlib_main_t * vm, virtio_if_t * vif, u16 queue_id);
    u16 (*get_queue_notify_off) (vlib_main_t * vm, virtio_if_t * vif,
				 u16 queue_id);
  void (*notify_queue) (vlib_main_t * vm, virtio_if_t * vif, u16 queue_id,
			u16 queue_notify_offset);

    u16 (*set_config_irq) (vlib_main_t * vm, virtio_if_t * vif, u16 vec);
    u16 (*set_queue_irq) (vlib_main_t * vm, virtio_if_t * vif, u16 vec,
			  u16 queue_id);

  void (*get_mac) (vlib_main_t * vm, virtio_if_t * vif);
  void (*set_mac) (vlib_main_t * vm, virtio_if_t * vif);
    u16 (*get_device_status) (vlib_main_t * vm, virtio_if_t * vif);
    u16 (*get_max_queue_pairs) (vlib_main_t * vm, virtio_if_t * vif);
    u16 (*get_mtu) (vlib_main_t * vm, virtio_if_t * vif);
  void (*device_debug_config_space) (vlib_main_t * vm, virtio_if_t * vif);
} virtio_pci_func_t;

#define foreach_virtio_flags  \
  _ (GSO, 0)                  \
  _ (CSUM_OFFLOAD, 1)         \
  _ (GRO_COALESCE, 2)         \
  _ (PACKED, 3)               \
  _ (IN_ORDER, 4)	      \
  _ (BUFFERING, 5)

typedef enum
{
#define _(a, b) VIRTIO_FLAG_##a = (1 << b),
  foreach_virtio_flags
#undef _
} virtio_flag_t;

typedef enum
{
  VIRTIO_BIND_NONE = 0,
  VIRTIO_BIND_DEFAULT = 1,
  VIRTIO_BIND_FORCE = 2,
} __clib_packed virtio_bind_t;

typedef struct
{
  u32 addr;
  /* return */
  i32 rv;
  u32 sw_if_index;
  u8 mac_addr_set;
  u8 mac_addr[6];
  u64 features;
  u8 gso_enabled;
  u8 checksum_offload_enabled;
  virtio_bind_t bind;
  u32 buffering_size;
  u32 virtio_flags;
  clib_error_t *error;
} virtio_pci_create_if_args_t;

extern const virtio_pci_func_t virtio_pci_legacy_func;
extern const virtio_pci_func_t virtio_pci_modern_func;

extern void device_status (vlib_main_t * vm, virtio_if_t * vif);
void virtio_pci_create_if (vlib_main_t * vm,
			   virtio_pci_create_if_args_t * args);
int virtio_pci_delete_if (vlib_main_t * vm, virtio_if_t * ad);
int virtio_pci_enable_disable_offloads (vlib_main_t * vm, virtio_if_t * vif,
					int gso_enabled,
					int checksum_offload_enabled,
					int offloads_disabled);
#endif /* __included_virtio_pci_h__ */
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
