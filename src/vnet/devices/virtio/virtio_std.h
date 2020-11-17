/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
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
#ifndef __VIRTIO_STD_H__
#define __VIRTIO_STD_H__

#define foreach_virtio_net_features      \
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
  _ (VIRTIO_F_ANY_LAYOUT, 27)  /* Can the device handle any descriptor layout */ \
  _ (VIRTIO_RING_F_INDIRECT_DESC, 28)   /* Support indirect buffer descriptors */ \
  _ (VIRTIO_RING_F_EVENT_IDX, 29)       /* The Guest publishes the used index for which it expects an interrupt \
 * at the end of the avail ring. Host should ignore the avail->flags field. */ \
/* The Host publishes the avail index for which it expects a kick \
 * at the end of the used ring. Guest should ignore the used->flags field. */ \
  _ (VHOST_USER_F_PROTOCOL_FEATURES, 30) \
  _ (VIRTIO_F_VERSION_1, 32)  /* v1.0 compliant. */           \
  _ (VIRTIO_F_IOMMU_PLATFORM, 33) \
  _ (VIRTIO_F_RING_PACKED, 34) \
  _ (VIRTIO_F_IN_ORDER, 35)  /* all buffers are used by the device in the */ \
                         /* same order in which they have been made available */ \
  _ (VIRTIO_F_ORDER_PLATFORM, 36) /* memory accesses by the driver and the */ \
                      /* device are ordered in a way described by the platfor */ \
  _ (VIRTIO_F_NOTIFICATION_DATA, 38) /* the driver passes extra data (besides */ \
                      /* identifying the virtqueue) in its device notifications. */ \
  _ (VIRTIO_NET_F_SPEED_DUPLEX, 63)	/* Device set linkspeed and duplex */

typedef enum
{
#define _(f,n) f = n,
  foreach_virtio_net_features
#undef _
} virtio_net_feature_t;

#define VIRTIO_FEATURE(X) (1ULL << X)

#define VRING_MAX_SIZE            32768

#define VRING_DESC_F_NEXT               1
#define VRING_DESC_F_WRITE              2
#define VRING_DESC_F_INDIRECT           4

#define VRING_DESC_F_AVAIL              (1 << 7)
#define VRING_DESC_F_USED               (1 << 15)

#define foreach_virtio_event_idx_flags      \
  _ (VRING_EVENT_F_ENABLE, 0)  \
  _ (VRING_EVENT_F_DISABLE, 1) \
  _ (VRING_EVENT_F_DESC, 2)

typedef enum
{
#define _(f,n) f = n,
  foreach_virtio_event_idx_flags
#undef _
} virtio_event_idx_flags_t;

#define VRING_USED_F_NO_NOTIFY  1
#define VRING_AVAIL_F_NO_INTERRUPT 1

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

/* *INDENT-OFF* */
typedef CLIB_PACKED (struct
{
   u64 addr;	// packet data buffer address
   u32 len;	// packet data buffer size
   u16 id;	// buffer id
   u16 flags;	// flags
}) vring_packed_desc_t;

STATIC_ASSERT_SIZEOF (vring_packed_desc_t, 16);

typedef CLIB_PACKED (struct
{
  u16 off_wrap;
  u16 flags;
}) vring_desc_event_t;

#define VIRTIO_NET_HDR_F_NEEDS_CSUM     1	/* Use csum_start, csum_offset */
#define VIRTIO_NET_HDR_F_DATA_VALID     2	/* Csum is valid */

#define VIRTIO_NET_HDR_GSO_NONE         0	/* Not a GSO frame */
#define VIRTIO_NET_HDR_GSO_TCPV4        1	/* GSO frame, IPv4 TCP (TSO) */
#define VIRTIO_NET_HDR_GSO_UDP          3	/* GSO frame, IPv4 UDP (UFO) */
#define VIRTIO_NET_HDR_GSO_TCPV6        4	/* GSO frame, IPv6 TCP */
#define VIRTIO_NET_HDR_GSO_ECN          0x80	/* TCP has ECN set */

typedef CLIB_PACKED (struct
{
  u8 flags;
  u8 gso_type;
  u16 hdr_len;			/* Ethernet + IP + tcp/udp hdrs */
  u16 gso_size;			/* Bytes to append to hdr_len per frame */
  u16 csum_start;		/* Position to start checksumming from */
  u16 csum_offset;		/* Offset after that to place checksum */
  u16 num_buffers;		/* Number of merged rx buffers */
}) virtio_net_hdr_v1_t;

typedef CLIB_PACKED (struct
{
  u8 flags;
  u8 gso_type;
  u16 hdr_len;
  u16 gso_size;
  u16 csum_start;
  u16 csum_offset;
}) virtio_net_hdr_t;

typedef CLIB_PACKED (struct
{
  virtio_net_hdr_t hdr;
  u16 num_buffers;
}) virtio_net_hdr_mrg_rxbuf_t;

/* *INDENT-ON* */

typedef struct
{
  u16 num;
  vring_desc_t *desc;
  vring_avail_t *avail;
  vring_used_t *used;
} vring_t;

static_always_inline void
vring_init (vring_t * vr, u32 num, void *p, u32 align)
{
  vr->num = num;
  vr->desc = p;
  vr->avail = (vring_avail_t *) ((char *) p + num * sizeof (vring_desc_t));
  vr->used =
    (vring_used_t *) ((char *) p +
		      ((sizeof (vring_desc_t) * num +
			sizeof (u16) * (3 + num) + align - 1) & ~(align -
								  1)));
}

static_always_inline u16
vring_size (u32 num, u32 align)
{
  return ((sizeof (vring_desc_t) * num + sizeof (u16) * (3 + num)
	   + align - 1) & ~(align - 1))
    + sizeof (u16) * 3 + sizeof (vring_used_elem_t) * num;
}
#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
