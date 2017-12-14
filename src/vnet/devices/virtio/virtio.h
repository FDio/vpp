/*
 *------------------------------------------------------------------
 * Copyright (c) 2017 Cisco and/or its affiliates.
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
 *------------------------------------------------------------------
 */

#ifndef _VNET_DEVICES_VIRTIO_VIRTIO_H_
#define _VNET_DEVICES_VIRTIO_VIRTIO_H_

#define foreach_virtio_net_features      \
  _ (VIRTIO_NET_F_CSUM, 0)	/* Host handles pkts w/ partial csum */ \
  _ (VIRTIO_NET_F_GUEST_CSUM, 1) /* Guest handles pkts w/ partial csum */ \
  _ (VIRTIO_NET_F_CTRL_GUEST_OFFLOADS, 2) /* Dynamic offload configuration. */ \
  _ (VIRTIO_NET_F_MTU, 3)       /* Initial MTU advice. */ \
  _ (VIRTIO_NET_F_MAC, 5)	/* Host has given MAC address. */ \
  _ (VIRTIO_NET_F_GSO, 6)	/* Host handles pkts w/ any GSO. */ \
  _ (VIRTIO_NET_F_GUEST_TSO4, 7)	/* Guest can handle TSOv4 in. */ \
  _ (VIRTIO_NET_F_GUEST_TSO6, 8)	/* Guest can handle TSOv6 in. */ \
  _ (VIRTIO_NET_F_GUEST_ECN, 9)	/* Guest can handle TSO[6] w/ ECN in. */ \
  _ (VIRTIO_NET_F_GUEST_UFO, 10)	/* Guest can handle UFO in. */ \
  _ (VIRTIO_NET_F_HOST_TSO4, 11)	/* Host can handle TSOv4 in. */ \
  _ (VIRTIO_NET_F_HOST_TSO6, 12)	/* Host can handle TSOv6 in. */ \
  _ (VIRTIO_NET_F_HOST_ECN, 13)	/* Host can handle TSO[6] w/ ECN in. */ \
  _ (VIRTIO_NET_F_HOST_UFO, 14)	/* Host can handle UFO in. */ \
  _ (VIRTIO_NET_F_MRG_RXBUF, 15)	/* Host can merge receive buffers. */ \
  _ (VIRTIO_NET_F_STATUS, 16)	/* virtio_net_config.status available */ \
  _ (VIRTIO_NET_F_CTRL_VQ, 17)	/* Control channel available */ \
  _ (VIRTIO_NET_F_CTRL_RX, 18)	/* Control channel RX mode support */ \
  _ (VIRTIO_NET_F_CTRL_VLAN, 19)	/* Control channel VLAN filtering */ \
  _ (VIRTIO_NET_F_CTRL_RX_EXTRA, 20)	/* Extra RX mode control support */ \
  _ (VIRTIO_NET_F_GUEST_ANNOUNCE, 21)	/* Guest can announce device on the network */ \
  _ (VIRTIO_NET_F_MQ, 22)	        /* Device supports Receive Flow Steering */ \
  _ (VIRTIO_NET_F_CTRL_MAC_ADDR, 23)	/* Set MAC address */ \
  _ (VIRTIO_F_NOTIFY_ON_EMPTY, 24) \
  _ (VHOST_F_LOG_ALL, 26)      /* Log all write descriptors */ \
  _ (VIRTIO_F_ANY_LAYOUT, 27)  /* Can the device handle any descripor layout */ \
  _ (VIRTIO_RING_F_INDIRECT_DESC, 28)   /* Support indirect buffer descriptors */ \
  _ (VIRTIO_RING_F_EVENT_IDX, 29)       /* The Guest publishes the used index for which it expects an interrupt \
 * at the end of the avail ring. Host should ignore the avail->flags field. */ \
/* The Host publishes the avail index for which it expects a kick \
 * at the end of the used ring. Guest should ignore the used->flags field. */ \
  _ (VHOST_USER_F_PROTOCOL_FEATURES, 30) \
  _ (VIRTIO_F_VERSION_1, 32)

#define foreach_virtio_if_flag		\
  _(0, ADMIN_UP, "admin-up")		\
  _(1, DELETING, "deleting")

typedef enum
{
#define _(a, b, c) VIRTIO_IF_FLAG_##b = (1 << a),
  foreach_virtio_if_flag
#undef _
} virtio_if_flag_t;

typedef enum
{
  VIRTIO_IF_TYPE_TAP,
  VIRTIO_IF_N_TYPES,
} virtio_if_type_t;


typedef struct
{
  struct vring_desc *desc;
  struct vring_used *used;
  struct vring_avail *avail;
  u16 desc_in_use;
  u16 desc_next;
  int kick_fd;
  int call_fd;
  u16 size;
#define VIRTIO_RING_FLAG_MASK_INT 1
  u32 flags;
  u32 call_file_index;
  u32 *buffers;
  u16 last_used_idx;
} virtio_vring_t;

typedef struct
{
  u32 flags;
  u32 id;
  u32 dev_instance;
  u32 hw_if_index;
  u32 sw_if_index;
  u32 per_interface_next_index;
  int fd;
  int tap_fd;
  virtio_vring_t *vrings;

  u64 features, remote_features;

  virtio_if_type_t type;
  u16 tx_ring_sz;
  u16 rx_ring_sz;
  u8 *host_if_name;
  u8 *net_ns;
  u8 *host_bridge;
  u8 host_mac_addr[6];
  ip4_address_t host_ip4_addr;
  u8 host_ip4_prefix_len;
  ip6_address_t host_ip6_addr;
  u8 host_ip6_prefix_len;

  int ifindex;
} virtio_if_t;

typedef struct
{
  virtio_if_t *interfaces;
} virtio_main_t;

extern virtio_main_t virtio_main;
extern vnet_device_class_t virtio_device_class;
extern vlib_node_registration_t virtio_input_node;

clib_error_t *virtio_vring_init (vlib_main_t * vm, virtio_if_t * vif, u16 idx,
				 u16 sz);
clib_error_t *virtio_vring_free (virtio_if_t * vif, u32 idx);

#endif /* _VNET_DEVICES_VIRTIO_VIRTIO_H_ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
