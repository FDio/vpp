/* SPDX-License-Identifier: BSD-3-Clause */
/* This header is BSD licensed so anyone can use the definitions to implement
 * compatible drivers/servers.
 *
 * Derived from include/uapi/linux/virtio_net.h.
 */
#pragma once

#include <vppinfra/clib.h>

#define foreach_virtio_net_features                                                                \
  _ (CSUM, 0)                                                                                      \
  _ (GUEST_CSUM, 1)                                                                                \
  _ (CTRL_GUEST_OFFLOADS, 2)                                                                       \
  _ (MTU, 3)                                                                                       \
  _ (MAC, 5)                                                                                       \
  _ (GUEST_TSO4, 7)                                                                                \
  _ (GUEST_TSO6, 8)                                                                                \
  _ (GUEST_ECN, 9)                                                                                 \
  _ (GUEST_UFO, 10)                                                                                \
  _ (HOST_TSO4, 11)                                                                                \
  _ (HOST_TSO6, 12)                                                                                \
  _ (HOST_ECN, 13)                                                                                 \
  _ (HOST_UFO, 14)                                                                                 \
  _ (MRG_RXBUF, 15)                                                                                \
  _ (STATUS, 16)                                                                                   \
  _ (CTRL_VQ, 17)                                                                                  \
  _ (CTRL_RX, 18)                                                                                  \
  _ (CTRL_VLAN, 19)                                                                                \
  _ (CTRL_RX_EXTRA, 20)                                                                            \
  _ (GUEST_ANNOUNCE, 21)                                                                           \
  _ (MQ, 22)                                                                                       \
  _ (CTRL_MAC_ADDR, 23)                                                                            \
  _ (DEVICE_STATS, 50)                                                                             \
  _ (VQ_NOTF_COAL, 52)                                                                             \
  _ (NOTF_COAL, 53)                                                                                \
  _ (GUEST_USO4, 54)                                                                               \
  _ (GUEST_USO6, 55)                                                                               \
  _ (HOST_USO, 56)                                                                                 \
  _ (HASH_REPORT, 57)                                                                              \
  _ (GUEST_HDRLEN, 59)                                                                             \
  _ (RSS, 60)                                                                                      \
  _ (RSC_EXT, 61)                                                                                  \
  _ (STANDBY, 62)                                                                                  \
  _ (SPEED_DUPLEX, 63)

#define foreach_virtio_config_features                                                             \
  _ (NOTIFY_ON_EMPTY, 24)                                                                          \
  _ (ANY_LAYOUT, 27)                                                                               \
  _ (EVENT_IDX, 29)                                                                                \
  _ (VERSION_1, 32)                                                                                \
  _ (ACCESS_PLATFORM, 33)                                                                          \
  _ (RING_PACKED, 34)                                                                              \
  _ (IN_ORDER, 35)                                                                                 \
  _ (ORDER_PLATFORM, 36)                                                                           \
  _ (SR_IOV, 37)                                                                                   \
  _ (NOTIFICATION_DATA, 38)                                                                        \
  _ (RING_RESET, 40)

typedef enum
{
#define _(f, n) VIRTIO_NET_F_##f##_BIT = 1ULL << (n),
  foreach_virtio_net_features
#undef _
#define _(f, n) VIRTIO_F_##f##_BIT = 1ULL << (n),
    foreach_virtio_config_features
#undef _
      VIRTIO_RING_F_INDIRECT_DESC_BIT = 1ULL << 28,
} vnet_virtio_feature_bit_t;

#define foreach_virtq_desc_flag                                                                    \
  _ (0, NEXT)                                                                                      \
  _ (1, WRITE)                                                                                     \
  _ (2, INDIRECT)                                                                                  \
  _ (7, AVAIL)                                                                                     \
  _ (15, USED)

typedef enum
{
#define _(b, n) VRING_DESC_F_##n = 1 << b,
  foreach_virtq_desc_flag
#undef _
} virtq_desc_flag_t;

#define VRING_AVAIL_F_NO_INTERRUPT 1
#define VRING_EVENT_F_ENABLE	   0
#define VRING_EVENT_F_DISABLE	   1

typedef struct
{
  u64 addr;
  u32 len;
  u16 flags;
  u16 next;
} virtq_desc_t;

typedef struct
{
  u16 flags;
  u16 idx;
  u16 ring[];
} virtq_avail_t;

typedef struct
{
  u32 id;
  u32 len;
} virtq_used_elem_t;

typedef struct
{
  u16 flags;
  u16 idx;
  virtq_used_elem_t ring[];
} virtq_used_t;

typedef struct
{
  u64 addr;  /* packet data buffer address */
  u32 len;   /* packet data buffer size */
  u16 id;    /* buffer id */
  u16 flags; /* flags */
} __clib_packed pvirtq_desc_t __clib_aligned (16);

STATIC_ASSERT_SIZEOF (pvirtq_desc_t, 16);

typedef struct
{
  u16 off_wrap;
  u16 flags;
} __clib_packed pvirtq_event_suppress_t __clib_aligned (4);

#define VIRTIO_NET_HDR_F_NEEDS_CSUM 1
#define VIRTIO_NET_HDR_F_DATA_VALID 2
#define VIRTIO_NET_HDR_GSO_NONE	    0
#define VIRTIO_NET_HDR_GSO_TCPV4    1
#define VIRTIO_NET_HDR_GSO_TCPV6    4

typedef struct
{
  u8 flags;
  u8 gso_type;
  u16 hdr_len;	   /* Ethernet + IP + tcp/udp hdrs */
  u16 gso_size;	   /* Bytes to append to hdr_len per frame */
  u16 csum_start;  /* Position to start checksumming from */
  u16 csum_offset; /* Offset after that to place checksum */
  u16 num_buffers; /* Number of merged rx buffers */
} __clib_packed virtio_net_hdr_t;

#define VIRTIO_NET_HDR_V1_SZ 12

#define VIRTIO_CONFIG_STATUS_ACK	 1
#define VIRTIO_CONFIG_STATUS_DRIVER	 2
#define VIRTIO_CONFIG_STATUS_DRIVER_OK	 4
#define VIRTIO_CONFIG_STATUS_FEATURES_OK 8
#define VIRTIO_CONFIG_STATUS_NEEDS_RESET 64
#define VIRTIO_CONFIG_STATUS_FAILED	 128
#define VIRTIO_NET_S_LINK_UP		 1
#define VIRTIO_PCI_ISR_INTR		 1

#define foreach_virtio_net_ctrl_ack                                                                \
  _ (OK, 0)                                                                                        \
  _ (ERR, 1)

#define foreach_virtio_net_ctrl_class                                                              \
  _ (RX, 0)                                                                                        \
  _ (MAC, 1)                                                                                       \
  _ (MQ, 4)

#define foreach_virtio_net_ctrl_rx_cmd                                                             \
  _ (PROMISC, 0)                                                                                   \
  _ (ALLMULTI, 1)

#define foreach_virtio_net_ctrl_mac_cmd                                                            \
  _ (TABLE_SET, 0)                                                                                 \
  _ (ADDR_SET, 1)

#define foreach_virtio_net_ctrl_mq_cmd                                                             \
  _ (VQ_PAIRS_SET, 0)                                                                              \
  _ (RSS_CONFIG, 1)

typedef enum
{
#define _(n, v) VIRTIO_NET_##n = v,
  foreach_virtio_net_ctrl_ack
#undef _
} virtio_net_ctrl_ack_t;

typedef enum
{
#define _(n, v) VIRTIO_NET_CTRL_##n = v,
  foreach_virtio_net_ctrl_class
#undef _
} virtio_net_ctrl_class_t;

typedef enum
{
#define _(n, v) VIRTIO_NET_CTRL_RX_##n = v,
  foreach_virtio_net_ctrl_rx_cmd
#undef _
} virtio_net_ctrl_rx_cmd_t;

typedef enum
{
#define _(n, v) VIRTIO_NET_CTRL_MAC_##n = v,
  foreach_virtio_net_ctrl_mac_cmd
#undef _
} virtio_net_ctrl_mac_cmd_t;

typedef enum
{
#define _(n, v) VIRTIO_NET_CTRL_MQ_##n = v,
  foreach_virtio_net_ctrl_mq_cmd
#undef _
} virtio_net_ctrl_mq_cmd_t;

/* Virtio 1.2 section 5.1.4. Later fields are present only with their features. */
typedef struct
{
  u8 mac[6];
  u16 status;
  u16 max_virtqueue_pairs;
  u16 mtu;
  u32 speed;
  u8 duplex;
  u8 rss_max_key_size;
  u16 rss_max_indirection_table_length;
  u32 supported_hash_types;
} virtio_net_config_t;
STATIC_ASSERT_SIZEOF (virtio_net_config_t, 24);

typedef struct
{
  u8 class, command;
} virtio_net_ctrl_hdr_t;
STATIC_ASSERT_SIZEOF (virtio_net_ctrl_hdr_t, 2);

typedef struct
{
  u32 entries;
  u8 macs[][6];
} __clib_packed virtio_net_ctrl_mac_t;

/* The variable-length indirection table is immediately followed by the tail. */
typedef struct
{
  u32 hash_types;
  u16 indirection_table_mask;
  u16 unclassified_queue;
  u16 indirection_table[];
} __clib_packed virtio_net_rss_config_t;

STATIC_ASSERT_SIZEOF (virtio_net_rss_config_t, 8);

/* Virtio 1.2 sections 4.1.4 and 2.7. Wire fields are little endian, only little endian hosts are
 * supported. */
typedef struct
{
  u8 vendor, next, length, type, bar, id, padding[2];
  u32 offset, region_length;
} virtio_pci_cap_t;
STATIC_ASSERT_SIZEOF (virtio_pci_cap_t, 16);

typedef struct
{
  u32 device_feature_select, device_feature;
  u32 driver_feature_select, driver_feature;
  u16 msix_config, num_queues;
  u8 status, generation;
  u16 queue_select, queue_size, queue_msix_vector, queue_enable, queue_notify_off;
  u32 queue_desc_lo, queue_desc_hi;
  u32 queue_driver_lo, queue_driver_hi;
  u32 queue_device_lo, queue_device_hi;
} virtio_pci_common_cfg_t;
STATIC_ASSERT_SIZEOF (virtio_pci_common_cfg_t, 56);

typedef struct
{
  virtio_pci_cap_t cap;
  u32 notify_off_multiplier;
} virtio_pci_notify_cap_t;
STATIC_ASSERT_SIZEOF (virtio_pci_notify_cap_t, 20);

STATIC_ASSERT_SIZEOF (virtq_desc_t, 16);
STATIC_ASSERT_SIZEOF (virtio_net_hdr_t, 12);
