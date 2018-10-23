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

/*
 * VirtIO Header, located in BAR 0.
 */
#define VIRTIO_PCI_HOST_FEATURES  0	/* host's supported features (32bit, RO) */
#define VIRTIO_PCI_GUEST_FEATURES 4	/* guest's supported features (32, RW) */
#define VIRTIO_PCI_QUEUE_PFN      8	/* physical address of VQ (32, RW) */
#define VIRTIO_PCI_QUEUE_NUM      12	/* number of ring entries (16, RO) */
#define VIRTIO_PCI_QUEUE_SEL      14	/* current VQ selection (16, RW) */
#define VIRTIO_PCI_QUEUE_NOTIFY   16	/* notify host regarding VQ (16, RW) */
#define VIRTIO_PCI_STATUS         18	/* device status register (8, RW) */
#define VIRTIO_PCI_ISR            19	/* interrupt status register, reading
					 * also clears the register (8, RO) */
/* Only if MSIX is enabled: */
#define VIRTIO_MSI_CONFIG_VECTOR  20	/* configuration change vector (16, RW) */
#define VIRTIO_MSI_QUEUE_VECTOR   22	/* vector for selected VQ notifications
					   (16, RW) */

/* The bit of the ISR which indicates a device has an interrupt. */
#define VIRTIO_PCI_ISR_INTR   0x1
/* The bit of the ISR which indicates a device configuration change. */
#define VIRTIO_PCI_ISR_CONFIG 0x2
/* Vector value used to disable MSI for queue. */

/* VirtIO device IDs. */
#define VIRTIO_ID_NETWORK  0x01

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

#define foreach_virtio_net_feature_flags      \
  _ (VIRTIO_NET_F_CSUM, 0)      /* Host handles pkts w/ partial csum */ \
  _ (VIRTIO_NET_F_GUEST_CSUM, 1) /* Guest handles pkts w/ partial csum */ \
  _ (VIRTIO_NET_F_CTRL_GUEST_OFFLOADS, 2) /* Dynamic offload configuration. */ \
  _ (VIRTIO_NET_F_MTU, 3)       /* Initial MTU advice. */ \
  _ (VIRTIO_NET_F_MAC, 5)       /* Host has given MAC address. */ \
  _ (VIRTIO_NET_F_GSO, 6)       /* Host handles pkts w/ any GSO. */ \
  _ (VIRTIO_NET_F_GUEST_TSO4, 7)        /* Guest can handle TSOv4 in. */ \
  _ (VIRTIO_NET_F_GUEST_TSO6, 8)        /* Guest can handle TSOv6 in. */ \
  _ (VIRTIO_NET_F_GUEST_ECN, 9) /* Guest can handle TSO[6] w/ ECN in. */ \
  _ (VIRTIO_NET_F_GUEST_UFO, 10)        /* Guest can handle UFO in. */ \
  _ (VIRTIO_NET_F_HOST_TSO4, 11)        /* Host can handle TSOv4 in. */ \
  _ (VIRTIO_NET_F_HOST_TSO6, 12)        /* Host can handle TSOv6 in. */ \
  _ (VIRTIO_NET_F_HOST_ECN, 13) /* Host can handle TSO[6] w/ ECN in. */ \
  _ (VIRTIO_NET_F_HOST_UFO, 14) /* Host can handle UFO in. */ \
  _ (VIRTIO_NET_F_MRG_RXBUF, 15)        /* Host can merge receive buffers. */ \
  _ (VIRTIO_NET_F_STATUS, 16)   /* virtio_net_config.status available */ \
  _ (VIRTIO_NET_F_CTRL_VQ, 17)  /* Control channel available */ \
  _ (VIRTIO_NET_F_CTRL_RX, 18)  /* Control channel RX mode support */ \
  _ (VIRTIO_NET_F_CTRL_VLAN, 19)        /* Control channel VLAN filtering */ \
  _ (VIRTIO_NET_F_CTRL_RX_EXTRA, 20)    /* Extra RX mode control support */ \
  _ (VIRTIO_NET_F_GUEST_ANNOUNCE, 21)   /* Guest can announce device on the network */ \
  _ (VIRTIO_NET_F_MQ, 22)               /* Device supports Receive Flow Steering */ \
  _ (VIRTIO_NET_F_CTRL_MAC_ADDR, 23)    /* Set MAC address */ \
  _ (VIRTIO_F_NOTIFY_ON_EMPTY, 24) \
  _ (VHOST_F_LOG_ALL, 26)      /* Log all write descriptors */ \
  _ (VIRTIO_F_ANY_LAYOUT, 27)  /* Can the device handle any descripor layout */ \
  _ (VIRTIO_RING_F_INDIRECT_DESC, 28)   /* Support indirect buffer descriptors */ \
  _ (VIRTIO_RING_F_EVENT_IDX, 29)       /* The Guest publishes the used index for which it expects an interrupt \
 * at the end of the avail ring. Host should ignore the avail->flags field. */ \
/* The Host publishes the avail index for which it expects a kick \
 * at the end of the used ring. Guest should ignore the used->flags field. */ \
  _ (VHOST_USER_F_PROTOCOL_FEATURES, 30)

#define VIRTIO_NET_F_MTU 3
#define VIRTIO_NET_S_LINK_UP    1	/* Link is up */
#define VIRTIO_NET_S_ANNOUNCE   2	/* Announcement is needed */

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

#define VIRTIO_PCI_VRING_ALIGN 4096

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
  struct virtio_pci_cap cap;
  u32 notify_off_multiplier;	/* Multiplier for queue_notify_off. */
} virtio_pci_notify_cap_t;

/* Fields in VIRTIO_PCI_CAP_COMMON_CFG: */
typedef struct
{
  /* About the whole device. */
  u32 device_feature_select;	/* read-write */
  u32 device_feature;		/* read-only */
  u32 guest_feature_select;	/* read-write */
  u32 guest_feature;		/* read-write */
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
  u32 queue_desc_lo;		/* read-write */
  u32 queue_desc_hi;		/* read-write */
  u32 queue_avail_lo;		/* read-write */
  u32 queue_avail_hi;		/* read-write */
  u32 queue_used_lo;		/* read-write */
  u32 queue_used_hi;		/* read-write */
} virtio_pci_common_cfg_t;

typedef struct
{
  u64 addr;
  u32 len;
  u16 flags;
  u16 next;
} vring_desc_t;

typedef struct
{
  u16 flags;
  u16 idx;
  u16 ring[0];
  /*  u16 used_event; */
} vring_avail_t;

typedef struct
{
  u32 id;
  u32 len;
} vring_used_elem_t;

typedef struct
{
  u16 flags;
  u16 idx;
  vring_used_elem_t ring[0];
  /* u16 avail_event; */
} vring_used_t;

typedef struct
{
  u32 addr;
  u16 rxq_size;
  u16 txq_size;
  /* return */
  i32 rv;
  u32 sw_if_index;
  u8 mac_addr_set;
  u8 mac_addr[6];
  u64 features;
  clib_error_t *error;
} virtio_pci_create_if_args_t;

extern void debug_device_config_space (vlib_main_t * vm, virtio_if_t * vif);
extern void device_status (vlib_main_t * vm, virtio_if_t * vif);
void virtio_pci_create_if (vlib_main_t * vm,
			   virtio_pci_create_if_args_t * args);
int virtio_pci_delete_if (vlib_main_t * vm, virtio_if_t * ad);

#endif /* __included_virtio_pci_h__ */
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
