/* This header is BSD licensed so anyone can use the definitions to implement
 * compatible drivers/servers.
 *
 * Derived from include/uapi/linux/virtio_net.h.
 */
#pragma once

#include <vppinfra/clib.h>

#define foreach_virtio_net_features                                           \
  _ (CSUM, 0)                                                                 \
  _ (GUEST_CSUM, 1)                                                           \
  _ (CTRL_GUEST_OFFLOADS, 2)                                                  \
  _ (MTU, 3)                                                                  \
  _ (MAC, 5)                                                                  \
  _ (GSO, 6)                                                                  \
  _ (GUEST_TSO4, 7)                                                           \
  _ (GUEST_TSO6, 8)                                                           \
  _ (GUEST_ECN, 9)                                                            \
  _ (GUEST_UFO, 10)                                                           \
  _ (HOST_TSO4, 11)                                                           \
  _ (HOST_TSO6, 12)                                                           \
  _ (HOST_ECN, 13)                                                            \
  _ (HOST_UFO, 14)                                                            \
  _ (MRG_RXBUF, 15)                                                           \
  _ (STATUS, 16)                                                              \
  _ (CTRL_VQ, 17)                                                             \
  _ (CTRL_RX, 18)                                                             \
  _ (CTRL_VLAN, 19)                                                           \
  _ (CTRL_RX_EXTRA, 20)                                                       \
  _ (GUEST_ANNOUNCE, 21)                                                      \
  _ (MQ, 22)                                                                  \
  _ (CTRL_MAC_ADDR, 23)                                                       \
  _ (GUEST_UDP_TUNNEL_GSO_MAPPED, 46)                                         \
  _ (GUEST_UDP_TUNNEL_GSO_CSUM_MAPPED, 47)                                    \
  _ (DEVICE_STATS, 50)                                                        \
  _ (VQ_NOTF_COAL, 52)                                                        \
  _ (NOTF_COAL, 53)                                                           \
  _ (GUEST_USO4, 54)                                                          \
  _ (GUEST_USO6, 55)                                                          \
  _ (HOST_USO, 56)                                                            \
  _ (HASH_REPORT, 57)                                                         \
  _ (GUEST_HDRLEN, 59)                                                        \
  _ (RSS, 60)                                                                 \
  _ (RSC_EXT, 61)                                                             \
  _ (STANDBY, 62)                                                             \
  _ (SPEED_DUPLEX, 63)

#define foreach_virtio_config_features                                        \
  _ (NOTIFY_ON_EMPTY, 24)                                                     \
  _ (ANY_LAYOUT, 27)                                                          \
  _ (VERSION_1, 32)                                                           \
  _ (ACCESS_PLATFORM, 33)                                                     \
  _ (RING_PACKED, 34)                                                         \
  _ (IN_ORDER, 35)                                                            \
  _ (ORDER_PLATFORM, 36)                                                      \
  _ (SR_IOV, 37)                                                              \
  _ (NOTIFICATION_DATA, 38)                                                   \
  _ (NOTIF_CONFIG_DATA, 39)                                                   \
  _ (RING_RESET, 40)                                                          \
  _ (ADMIN_VQ, 41)

#define foreach_vhost_features _ (LOG_ALL, 26)

#define foreach_virtio_ring_features                                          \
  _ (INDIRECT_DESC, 28)                                                       \
  _ (EVENT_IDX, 29)

typedef enum
{
#define _(f, n) VIRTIO_NET_F_##f = (n),
  foreach_virtio_net_features
#undef _
#define _(f, n) VIRTIO_F_##f = (n),
    foreach_virtio_config_features
#undef _
#define _(f, n) VHOST_F_##f = (n),
      foreach_vhost_features
#undef _
#define _(f, n) VIRTIO_RING_F_##f = (n),
	foreach_virtio_ring_features
#undef _
} vnet_virtio_feature_t;

typedef enum
{
#define _(f, n) VIRTIO_NET_F_##f##_BIT = 1ULL << (n),
  foreach_virtio_net_features
#undef _
#define _(f, n) VIRTIO_F_##f##_BIT = 1ULL << (n),
    foreach_virtio_config_features
#undef _
#define _(f, n) VHOST_F_##f##_BIT = 1ULL << (n),
      foreach_vhost_features
#undef _
#define _(f, n) VIRTIO_RING_F_##f##_BIT = 1ULL << (n),
	foreach_virtio_ring_features
#undef _
} vnet_virtio_feature_bit_t;

#define VRING_MAX_SIZE 32768

#define VRING_DESC_F_NEXT     1
#define VRING_DESC_F_WRITE    2
#define VRING_DESC_F_INDIRECT 4

#define foreach_virtio_event_idx_flags                                        \
  _ (VRING_EVENT_F_ENABLE, 0)                                                 \
  _ (VRING_EVENT_F_DISABLE, 1)                                                \
  _ (VRING_EVENT_F_DESC, 2)

#define VRING_USED_F_NO_NOTIFY	   1
#define VRING_AVAIL_F_NO_INTERRUPT 1

typedef struct
{
  u64 addr;
  u32 len;
  u16 flags;
  u16 next;
} vnet_virtio_vring_desc_t;

typedef struct
{
  u16 flags;
  u16 idx;
  u16 ring[0];
  /*  u16 used_event; */
} vnet_virtio_vring_avail_t;

typedef struct
{
  u32 id;
  u32 len;
} vnet_virtio_vring_used_elem_t;

typedef struct
{
  u16 flags;
  u16 idx;
  vnet_virtio_vring_used_elem_t ring[0];
  /* u16 avail_event; */
} vnet_virtio_vring_used_t;

typedef CLIB_PACKED (struct {
  u64 addr;  // packet data buffer address
  u32 len;   // packet data buffer size
  u16 id;    // buffer id
  u16 flags; // flags
}) vnet_virtio_vring_packed_desc_t;

STATIC_ASSERT_SIZEOF (vnet_virtio_vring_packed_desc_t, 16);

typedef CLIB_PACKED (struct {
  u16 off_wrap;
  u16 flags;
}) vnet_virtio_vring_desc_event_t;

#define VIRTIO_NET_HDR_F_NEEDS_CSUM 1 /* Use csum_start, csum_offset */
#define VIRTIO_NET_HDR_F_DATA_VALID 2 /* Csum is valid */

#define VIRTIO_NET_HDR_GSO_NONE	 0    /* Not a GSO frame */
#define VIRTIO_NET_HDR_GSO_TCPV4 1    /* GSO frame, IPv4 TCP (TSO) */
#define VIRTIO_NET_HDR_GSO_UDP	 3    /* GSO frame, IPv4 UDP (UFO) */
#define VIRTIO_NET_HDR_GSO_TCPV6 4    /* GSO frame, IPv6 TCP */
#define VIRTIO_NET_HDR_GSO_ECN	 0x80 /* TCP has ECN set */

typedef CLIB_PACKED (struct {
  u8 flags;
  u8 gso_type;
  u16 hdr_len;	   /* Ethernet + IP + tcp/udp hdrs */
  u16 gso_size;	   /* Bytes to append to hdr_len per frame */
  u16 csum_start;  /* Position to start checksumming from */
  u16 csum_offset; /* Offset after that to place checksum */
  u16 num_buffers; /* Number of merged rx buffers */
}) vnet_virtio_net_hdr_v1_t;

typedef CLIB_PACKED (struct {
  u8 flags;
  u8 gso_type;
  u16 hdr_len;
  u16 gso_size;
  u16 csum_start;
  u16 csum_offset;
}) vnet_virtio_net_hdr_t;

typedef CLIB_PACKED (struct {
  vnet_virtio_net_hdr_t hdr;
  u16 num_buffers;
}) vnet_virtio_net_hdr_mrg_rxbuf_t;
