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
#define VIRTIO_MSI_NO_VECTOR 0xFFFF

/* VirtIO device IDs. */
#define VIRTIO_ID_NETWORK  0x01
//#define VIRTIO_ID_BLOCK    0x02
//#define VIRTIO_ID_CONSOLE  0x03
//#define VIRTIO_ID_ENTROPY  0x04
//#define VIRTIO_ID_BALLOON  0x05
//#define VIRTIO_ID_IOMEMORY 0x06
//#define VIRTIO_ID_9P       0x09

/* Status byte for guest to report progress. */
#define VIRTIO_CONFIG_STATUS_RESET     0x00
#define VIRTIO_CONFIG_STATUS_ACK       0x01
#define VIRTIO_CONFIG_STATUS_DRIVER    0x02
#define VIRTIO_CONFIG_STATUS_DRIVER_OK 0x04
#define VIRTIO_CONFIG_STATUS_FEATURES_OK 0x08
#define VIRTIO_CONFIG_STATUS_DEVICE_NEEDS_RESET 0x40
#define VIRTIO_CONFIG_STATUS_FAILED    0x80

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

/*typedef enum
{
#define _(a, b) a = (1 << b),
  foreach_virtio_net_feature_flags
#undef _
} foreach_virtio_net_features_t;

#define VIRTIO_F_VERSION_1 (1 << 32)
*/
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
struct virtio_pci_cap
{
  u8 cap_vndr;			/* Generic PCI field: PCI_CAP_ID_VNDR */
  u8 cap_next;			/* Generic PCI field: next ptr. */
  u8 cap_len;			/* Generic PCI field: capability length */
  u8 cfg_type;			/* Identifies the structure. */
  u8 bar;			/* Where to find it. */
  u8 padding[3];		/* Pad to full dword. */
  u32 offset;			/* Offset within bar. */
  u32 length;			/* Length of the structure, in bytes. */
};

struct virtio_pci_notify_cap
{
  struct virtio_pci_cap cap;
  u32 notify_off_multiplier;	/* Multiplier for queue_notify_off. */
};

/* Fields in VIRTIO_PCI_CAP_COMMON_CFG: */
struct virtio_pci_common_cfg
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
};

/*
#define foreach_virtio_pci_tx_func_error	       \
  _(ERROR_PACKETS, "error packets") \
  _(LINK_DOWN, "link down") \
  _(NO_FREE_SLOTS, "no free tx slots")

typedef enum
{
#define _(f,s) VMXNET3_TX_ERROR_##f,
  foreach_virtio_pci_tx_func_error
#undef _
    VMXNET3_TX_N_ERROR,
} virtio_pci_tx_func_error_t;

#define foreach_virtio_pci_rxmode_flags \
  _(0, UCAST, "unicast") \
  _(1, MCAST, "multicast")		   \
  _(2, BCAST, "broadcast") \
  _(3, ALL_MULTI, "all multicast") \
  _(4, PROMISC, "promiscuous")

enum
{
#define _(a, b, c) VMXNET3_RXMODE_##b = (1 << a),
  foreach_virtio_pci_rxmode_flags
#undef _
};
*/
/* BAR 0 */
//#define VMXNET3_REG_IMR     0x0000    /* Interrupt Mask Register */
//#define VMXNET3_REG_TXPROD  0x0600    /* Tx Producer Index */
//#define VMXNET3_REG_RXPROD  0x0800    /* Rx Producer Index for ring 1 */
//#define VMXNET3_REG_RXPROD2 0x0A00    /* Rx Producer Index for ring 2 */


/* BAR 1 */
//#define VMXNET3_REG_VRRS 0x0000       /* VMXNET3 Revision Report Selection */
//#define VMXNET3_REG_UVRS 0x0008       /* UPT Version Report Selection */
//#define VMXNET3_REG_DSAL 0x0010       /* Driver Shared Address Low */
//#define VMXNET3_REG_DSAH 0x0018       /* Driver Shared Address High */
//#define VMXNET3_REG_CMD  0x0020       /* Command */
//#define VMXNET3_REG_MACL 0x0028       /* MAC Address Low */
//#define VMXNET3_REG_MACH 0x0030       /* MAC Address High */
//#define VMXNET3_REG_ICR  0x0038       /* Interrupt Cause Register */
//#define VMXNET3_REG_ECR  0x0040       /* Event Cause Register */
/*
#define VMXNET3_VLAN_LEN 4
#define VMXNET3_FCS_LEN  4
#define VMXNET3_MTU (1514 + VMXNET3_VLAN_LEN + VMXNET3_FCS_LEN)
*/
//#define VMXNET3_RXF_BTYPE (1 << 14)   /* rx body buffer type */
//#define VMXNET3_RXF_GEN   (1 << 31)   /* rx generation */
//#define VMXNET3_RXCF_IP6  (1 << 20)   /* rx ip6 packet */
//#define VMXNET3_RXCF_IP4  (1 << 21)   /* rx ip4 packet */
//#define VMXNET3_RXCF_GEN  (1 << 31)   /* rx completion generation */
//#define VMXNET3_RXC_INDEX (0xFFF)     /* rx completion index mask */

//#define VMXNET3_TXF_GEN  (1 << 14)    /* tx generation */
//#define VMXNET3_TXF_EOP  (1 << 12)    /* tx end of packet */
//#define VMXNET3_TXF_CQ   (1 << 13)    /* tx completion request */
//#define VMXNET3_TXCF_GEN (1 << 31)    /* tx completion generation */
//#define VMXNET3_TXC_INDEX (0xFFF)     /* tx completion index mask */
/*
#define VMXNET3_RX_RING_SIZE 2
#define VMXNET3_INPUT_REFILL_THRESHOLD 32
#define VMXNET3_NUM_TX_DESC 1024
#define VMXNET3_NUM_TX_COMP VMXNET3_NUM_TX_DESC
#define VMXNET3_NUM_RX_DESC 1024
#define VMXNET3_NUM_RX_COMP VMXNET3_NUM_RX_DESC

#define VMXNET3_VERSION_MAGIC 0x69505845
#define VMXNET3_SHARED_MAGIC  0xbabefee1
#define VMXNET3_VERSION_SELECT     1
#define VMXNET3_UPT_VERSION_SELECT 1
#define VMXNET3_MAX_INTRS          25
#define VMXNET3_IC_DISABLE_ALL     0x1

#define VMXNET3_GOS_BITS_32     (1 << 0)
#define VMXNET3_GOS_BITS_64     (2 << 0)
#define VMXNET3_GOS_TYPE_LINUX  (1 << 2)
#define VMXNET3_RXCL_LEN_MASK   (0x3FFF)	// 14 bits
#define VMXNET3_RXCL_ERROR      (1 << 14)
#define VMXNET3_RXCI_EOP        (1 << 14)
#define VMXNET3_RXCI_SOP        (1 << 15)

#define foreach_virtio_pci_device_flags \
  _(0, INITIALIZED, "initialized") \
  _(1, ERROR, "error")		   \
  _(2, ADMIN_UP, "admin-up") \
  _(3, IOVA, "iova") \
  _(4, LINK_UP, "link-up") \
  _(5, SHARED_TXQ_LOCK, "shared-txq-lock") \
  _(6, ELOG, "elog")

enum
{
#define _(a, b, c) VMXNET3_DEVICE_F_##b = (1 << a),
  foreach_virtio_pci_device_flags
#undef _
};

#define foreach_virtio_pci_set_cmds \
  _(0, ACTIVATE_DEV, "activate device") \
  _(1, QUIESCE_DEV, "quiesce device") \
  _(2, RESET_DEV, "reset device") \
  _(3, UPDATE_RX_MODE, "update rx mode") \
  _(4, UPDATE_MAC_FILTERS, "update mac filters") \
  _(5, UPDATE_VLAN_FILTERS, "update vlan filters") \
  _(6, UPDATE_RSSIDT, "update rss idt") \
  _(7, UPDATE_IML, "update iml") \
  _(8, UPDATE_PMCFG, "update pm cfg") \
  _(9, UPDATE_FEATURE, "update feature") \
  _(10, STOP_EMULATION, "stop emulation") \
  _(11, LOAD_PLUGIN, "load plugin") \
  _(12, ACTIVATE_VF, "activate vf") \
  _(13, RESERVED3, "reserved 3") \
  _(14, RESERVED4, "reservced 4") \
  _(15, REGISTER_MEMREGS, "register mem regs")

enum
{
#define _(a, b, c) VMXNET3_CMD_##b = (a + 0xCAFE0000),
  foreach_virtio_pci_set_cmds
#undef _
};

#define foreach_virtio_pci_get_cmds \
  _(0, GET_QUEUE_STATUS, "get queue status") \
  _(1, GET_STATS, "get stats") \
  _(2, GET_LINK, "get link") \
  _(3, GET_PERM_MAC_LO, "get perm mac lo") \
  _(4, GET_PERM_MAC_HI, "get perm mac hi") \
  _(5, GET_DID_LO, "get did lo") \
  _(6, GET_DID_HI, "get did hi") \
  _(7, GET_DEV_EXTRA_INFO, "get dev extra info") \
  _(8, GET_CONF_INTR, "get conf intr") \
  _(9, GET_ADAPTIVE_RING_INFO, "get adaptive ring info") \
  _(10, GET_TXDATA_DESC_SIZE, "gte txdata desc size") \
  _(11, RESERVED5, "reserved5")

enum
{
#define _(a, b, c) VMXNET3_CMD_##b = (a + 0xF00D0000),
  foreach_virtio_pci_get_cmds
#undef _
};

typedef CLIB_PACKED (struct
		     {
		     u32 version; u32 guest_info; u32 version_support;
		     u32 upt_version_support; u64 upt_features;
		     u64 driver_data_address; u64 queue_desc_address;
		     u32 driver_data_len; u32 queue_desc_len;
		     u32 mtu;
		     u16 max_num_rx_sg; u8 num_tx_queues; u8 num_rx_queues;
		     u32 pad[4];
		     }) virtio_pci_misc_config;

typedef CLIB_PACKED (struct
		     {
		     u8 mask_mode;
		     u8 num_intrs;
		     u8 event_intr_index;
		     u8 moderation_level[VMXNET3_MAX_INTRS]; u32 control;
		     u32 pad[2];
		     }) virtio_pci_interrupt_config;

typedef CLIB_PACKED (struct
		     {
		     u32 mode;
		     u16 multicast_len;
		     u16 pad; u64 multicast_address; u8 vlan_filter[512];
		     }) virtio_pci_rx_filter_config;

typedef CLIB_PACKED (struct
		     {
		     u32 version; u32 length;
		     u64 address;
		     }) virtio_pci_variable_config;

typedef CLIB_PACKED (struct
		     {
		     u32 magic;
		     u32 pad;
		     virtio_pci_misc_config misc;
		     virtio_pci_interrupt_config interrupt;
		     virtio_pci_rx_filter_config rx_filter;
		     virtio_pci_variable_config rss;
		     virtio_pci_variable_config pattern;
		     virtio_pci_variable_config plugin; u32 ecr;
		     u32 pad1[5];
		     }) virtio_pci_shared;

typedef CLIB_PACKED (struct
		     {
		     u8 stopped;
		     u8 pad[3];
		     u32 error;
		     }) virtio_pci_queue_status;

typedef CLIB_PACKED (struct
		     {
		     u32 num_deferred; u32 threshold;
		     u64 pad;
		     }) virtio_pci_tx_queue_control;

typedef CLIB_PACKED (struct
		     {
		     u64 desc_address;
		     u64 data_address;
		     u64 comp_address; u64 driver_data_address; u64 pad;
		     u32 num_desc;
		     u32 num_data;
		     u32 num_comp; u32 driver_data_len; u8 intr_index;
		     u8 pad1[7];
		     }) virtio_pci_tx_queue_config;

typedef CLIB_PACKED (struct
		     {
		     u64 tso_pkts;
		     u64 tso_bytes;
		     u64 ucast_pkts; u64 ucast_bytes; u64 mcast_pkts;
		     u64 mcast_bytes;
		     u64 bcast_pkts; u64 bcast_bytes; u64 error_pkts;
		     u64 discard_pkts;
		     }) virtio_pci_tx_stats;

typedef CLIB_PACKED (struct
		     {
		     virtio_pci_tx_queue_control ctrl;
		     virtio_pci_tx_queue_config cfg;
		     virtio_pci_queue_status status; virtio_pci_tx_stats stats;
		     u8 pad[88];
		     }) virtio_pci_tx_queue;

typedef CLIB_PACKED (struct
		     {
		     u8 update_prod; u8 pad[7];
		     u64 pad1;
		     }) virtio_pci_rx_queue_control;

typedef CLIB_PACKED (struct
		     {
		     u64 desc_address[2];
		     u64 comp_address; u64 driver_data_address; u64 pad;
		     u32 num_desc[2];
		     u32 num_comp; u32 driver_data_len; u8 intr_index;
		     u8 pad1[7];
		     }) virtio_pci_rx_queue_config;

typedef CLIB_PACKED (struct
		     {
		     u64 lro_pkts;
		     u64 lro_bytes;
		     u64 ucast_pkts; u64 ucast_bytes; u64 mcast_pkts;
		     u64 mcast_bytes;
		     u64 bcast_pkts; u64 bcast_bytes; u64 nobuf_pkts;
		     u64 error_pkts;
		     }) virtio_pci_rx_stats;

typedef CLIB_PACKED (struct
		     {
		     virtio_pci_rx_queue_control ctrl;
		     virtio_pci_rx_queue_config cfg;
		     virtio_pci_queue_status status; virtio_pci_rx_stats stats;
		     u8 pad[88];
		     }) virtio_pci_rx_queue;

typedef CLIB_PACKED (struct
		     {
		     virtio_pci_tx_queue tx; virtio_pci_rx_queue rx;
		     }) virtio_pci_queues;

*
 * flags:
 *   buffer length   -- bits 0-13
 *   buffer type     -- bit  14
 *   descriptor type -- bit  15
 *   reserved        -- bits 16-30
 *   generation      -- bit  31
 *
typedef CLIB_PACKED (struct
		     {
		     u64 address;
		     u32 flags;
		     u32 pad;
		     }) virtio_pci_rx_desc;

*
 * index:
 *   RX desc index           -- bits 0-11
 *   ext1                    -- bits 12-13
 *   end of packet           -- bit  14
 *   start of packet         -- bit  15
 *   ring ID                 -- bits 16-25
 *   RSS hash type           -- bits 26-29
 *   checksum not calculated -- bit  30
 *   ext2                    -- bit  31
 *
 * rss: RSS hash value
 *
 * len:
 *   data length             -- bits 0-13
 *   error                   -- bit  14
 *   tag is stripped         -- bit  15
 *   tag stripped            -- bits 16-31
 *
 * flags:
 *   checksum                -- bits 0 - 15
 *   tcp/udp checksum correct-- bit  16
 *   udp packet              -- bit  17
 *   tcp packet              -- bit  18
 *   ip checksum correct     -- bit  19
 *   ipv6                    -- bit  20
 *   ipv4                    -- bit  21
 *   ip fragment             -- bit  22
 *   frame crc correct       -- bit  23
 *   completion type         -- bits 24-30
 *   generation              -- bit  31
 *
typedef CLIB_PACKED (struct
		     {
		     u32 index; u32 rss;
		     u32 len;
		     u32 flags;
		     }) virtio_pci_rx_comp;

*
 * index:
 *   TX desc index           -- bits 0-11
 *   ext1                    -- bits 12-31
 *
 * flags:
 *   reserved                -- bits 0-23
 *   completion type         -- bits 24-30
 *   generation              -- bit  31
 *
typedef CLIB_PACKED (struct
		     {
		     u32 index;
		     u32 pad[2];
		     u32 flags;
		     }) virtio_pci_tx_comp;

*
 * flags[0]:
 *   length                  -- bits 0-13
 *   generation              -- bit  14
 *   reserved                -- bit  15
 *   descriptor type         -- bit  16
 *   ext1                    -- bit  17
 *   MSS, checksum offset    -- bits 18-31
 * flags[1]:
 *   header length           -- bits 0-9
 *   offload mode            -- bits 10-11
 *   end of packet           -- bit  12
 *   completion request      -- bit  13
 *   ext2                    -- bit  14
 *   vlan tag insertion      -- bit  15
 *   tag to insert           -- bits 16-31
 *
typedef CLIB_PACKED (struct
		     {
		     u64 address;
		     u32 flags[2];
		     }) virtio_pci_tx_desc;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  u32 *bufs;
  u32 gen;
  u16 fill;
  u16 rid;
  u16 produce;
  u16 consume;
} virtio_pci_rx_ring;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  u64 next;
  u32 gen;
} virtio_pci_rx_comp_ring;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  u16 size;
  u8 int_mode;
  virtio_pci_rx_ring rx_ring[VMXNET3_RX_RING_SIZE];
  virtio_pci_rx_desc *rx_desc[VMXNET3_RX_RING_SIZE];
  virtio_pci_rx_comp *rx_comp;
  virtio_pci_rx_comp_ring rx_comp_ring;
} virtio_pci_rxq_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  u32 *bufs;
  u32 gen;
  u16 produce;
  u16 consume;
} virtio_pci_tx_ring;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  u64 next;
  u32 gen;
} virtio_pci_tx_comp_ring;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  u16 size;
  clib_spinlock_t lock;

  virtio_pci_tx_desc *tx_desc;
  virtio_pci_tx_comp *tx_comp;
  virtio_pci_tx_ring tx_ring;
  virtio_pci_tx_comp_ring tx_comp_ring;
} virtio_pci_txq_t;

typedef CLIB_PACKED (struct
		     {
		     virtio_pci_queues queues; virtio_pci_shared shared;
		     }) virtio_pci_dma;
*/

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

#define VIRTIO_NUM_RX_DESC 256
#define VIRTIO_NUM_TX_DESC 256
typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  u32 flags;
  u32 per_interface_next_index;

  u32 dev_instance;
  u32 sw_if_index;
  u32 hw_if_index;
  vlib_pci_dev_handle_t pci_dev_handle;
  vlib_pci_addr_t pci_addr;
  void *bar[2];

  /* queues */
  virtio_vring_t *vrings;

//  virtio_pci_rxq_t *rxqs;
//  virtio_pci_txq_t *txqs;

  u16 num_tx_queues;
  u16 num_rx_queues;
  u16 num_intrs;

  u8 version;
  u8 mac_addr[6];

  virtio_if_type_t type;

  /* error */
  clib_error_t *error;

//  virtio_pci_dma *dma;

  u32 link_speed;
} virtio_pci_device_t;

typedef struct
{
  u16 msg_id_base;
} virtio_pci_main_t;

extern virtio_pci_main_t virtio_pci_main;

typedef struct
{
  vlib_pci_addr_t addr;
  u32 enable_elog;
  u16 rxq_size;
  u16 txq_size;
  /* return */
  i32 rv;
  u32 sw_if_index;
  u64 features;
  clib_error_t *error;
} virtio_pci_create_if_args_t;

void virtio_pci_create_if (vlib_main_t * vm,
			   virtio_pci_create_if_args_t * args);
void virtio_pci_delete_if (vlib_main_t * vm, virtio_if_t * ad);
/*
static_always_inline void
virtio_pci_reg_write (virtio_if_t * vd, u8 bar, u32 addr, u32 val)
{
  *(volatile u32 *) ((u8 *) vd->bar[bar] + addr) = val;
}

static_always_inline u32
virtio_pci_reg_read (virtio_if_t * vd, u8 bar, u32 addr)
{
  return *(volatile u32 *) (vd->bar[bar] + addr);
}
*/
/*
typedef struct
{
  u32 next_index;
  u32 hw_if_index;
  vlib_buffer_t buffer;
} virtio_pci_input_trace_t;

void virtio_pci_create_if (vlib_main_t * vm, virtio_pci_create_if_args_t * args);
void virtio_pci_delete_if (vlib_main_t * vm, virtio_pci_device_t * ad);

extern clib_error_t *virtio_pci_plugin_api_hookup (vlib_main_t * vm);
extern vlib_node_registration_t virtio_pci_input_node;
extern vnet_device_class_t virtio_pci_device_class;
*/
/* format.c */
/*
format_function_t format_virtio_pci_device;
format_function_t format_virtio_pci_device_name;
format_function_t format_virtio_pci_input_trace;

static_always_inline void
virtio_pci_reg_write (virtio_pci_device_t * vd, u8 bar, u32 addr, u32 val)
{
  *(volatile u32 *) ((u8 *) vd->bar[bar] + addr) = val;
}

static_always_inline u32
virtio_pci_reg_read (virtio_pci_device_t * vd, u8 bar, u32 addr)
{
  return *(volatile u32 *) (vd->bar[bar] + addr);
}

static_always_inline uword
virtio_pci_dma_addr (vlib_main_t * vm, virtio_pci_device_t * vd, void *p)
{
  virtio_pci_main_t *vmxm = &virtio_pci_main;

  return (vd->flags & VMXNET3_DEVICE_F_IOVA) ? pointer_to_uword (p) :
    vlib_physmem_virtual_to_physical (vm, vmxm->physmem_region, p);
}

static_always_inline void
virtio_pci_rx_ring_advance_produce (virtio_pci_rxq_t * rxq, virtio_pci_rx_ring * ring)
{
  ring->produce++;
  if (PREDICT_FALSE (ring->produce == rxq->size))
    {
      ring->produce = 0;
      ring->gen ^= VMXNET3_RXF_GEN;
    }
}

static_always_inline clib_error_t *
virtio_pci_rxq_refill_ring0 (vlib_main_t * vm, virtio_pci_device_t * vd,
			  virtio_pci_rxq_t * rxq)
{
  virtio_pci_rx_desc *rxd;
  u16 n_refill, n_alloc;
  virtio_pci_rx_ring *ring;

  ring = &rxq->rx_ring[0];
  n_refill = rxq->size - ring->fill;

  if (PREDICT_TRUE (n_refill <= VMXNET3_INPUT_REFILL_THRESHOLD))
    return 0;

  n_alloc =
    vlib_buffer_alloc_to_ring (vm, ring->bufs, ring->produce, rxq->size,
			       n_refill);
  if (PREDICT_FALSE (n_alloc != n_refill))
    {
      if (n_alloc)
	vlib_buffer_free_from_ring (vm, ring->bufs, ring->produce, rxq->size,
				    n_alloc);
      return clib_error_return (0, "buffer alloc failed");
    }

  while (n_alloc)
    {
      rxd = &rxq->rx_desc[0][ring->produce];
      rxd->address =
	vlib_get_buffer_data_physical_address (vm, ring->bufs[ring->produce]);
      rxd->flags = ring->gen | VLIB_BUFFER_DATA_SIZE;

      virtio_pci_rx_ring_advance_produce (rxq, ring);
      ring->fill++;
      n_alloc--;
    }

  virtio_pci_reg_write (vd, 0, VMXNET3_REG_RXPROD, ring->produce);

  return 0;
}

static_always_inline clib_error_t *
virtio_pci_rxq_refill_ring1 (vlib_main_t * vm, virtio_pci_device_t * vd,
			  virtio_pci_rxq_t * rxq)
{
  virtio_pci_rx_desc *rxd;
  u16 n_refill, n_alloc;
  virtio_pci_rx_ring *ring;

  ring = &rxq->rx_ring[1];
  n_refill = rxq->size - ring->fill;

  if (PREDICT_TRUE (n_refill <= VMXNET3_INPUT_REFILL_THRESHOLD))
    return 0;

  n_alloc =
    vlib_buffer_alloc_to_ring (vm, ring->bufs, ring->produce, rxq->size,
			       n_refill);
  if (PREDICT_FALSE (n_alloc != n_refill))
    {
      if (n_alloc)
	vlib_buffer_free_from_ring (vm, ring->bufs, ring->produce, rxq->size,
				    n_alloc);
      return clib_error_return (0, "buffer alloc failed");
    }

  while (n_alloc)
    {
      rxd = &rxq->rx_desc[1][ring->produce];
      rxd->address =
	vlib_get_buffer_data_physical_address (vm, ring->bufs[ring->produce]);
      rxd->flags = ring->gen | VLIB_BUFFER_DATA_SIZE | VMXNET3_RXF_BTYPE;

      virtio_pci_rx_ring_advance_produce (rxq, ring);
      ring->fill++;
      n_alloc--;
    }

  virtio_pci_reg_write (vd, 0, VMXNET3_REG_RXPROD2, ring->produce);

  return 0;
}
*/
#endif /* __included_virtio_pci_h__ */
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
