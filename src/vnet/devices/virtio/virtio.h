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
  _ (VIRTIO_NET_F_CSUM, VIRTIO_NET_F_CSUM)	/* Host handles pkts w/ partial csum */ \
  _ (VIRTIO_NET_F_GUEST_CSUM, VIRTIO_NET_F_GUEST_CSUM) /* Guest handles pkts w/ partial csum */ \
  _ (VIRTIO_NET_F_CTRL_GUEST_OFFLOADS, VIRTIO_NET_F_CTRL_GUEST_OFFLOADS) /* Dynamic offload configuration. */ \
  _ (VIRTIO_NET_F_MAC, VIRTIO_NET_F_MAC)	/* Host has given MAC address. */ \
  _ (VIRTIO_NET_F_GUEST_TSO4, VIRTIO_NET_F_GUEST_TSO4)	/* Guest can handle TSOv4 in. */ \
  _ (VIRTIO_NET_F_GUEST_TSO6, VIRTIO_NET_F_GUEST_TSO6)	/* Guest can handle TSOv6 in. */ \
  _ (VIRTIO_NET_F_GUEST_ECN, VIRTIO_NET_F_GUEST_ECN)	/* Guest can handle TSO[6] w/ ECN in. */ \
  _ (VIRTIO_NET_F_GUEST_UFO, VIRTIO_NET_F_GUEST_UFO)	/* Guest can handle UFO in. */ \
  _ (VIRTIO_NET_F_HOST_TSO4, VIRTIO_NET_F_HOST_TSO4)	/* Host can handle TSOv4 in. */ \
  _ (VIRTIO_NET_F_HOST_TSO6, VIRTIO_NET_F_HOST_TSO6)	/* Host can handle TSOv6 in. */ \
  _ (VIRTIO_NET_F_HOST_ECN, VIRTIO_NET_F_HOST_ECN)	/* Host can handle TSO[6] w/ ECN in. */ \
  _ (VIRTIO_NET_F_HOST_UFO, VIRTIO_NET_F_HOST_UFO)	/* Host can handle UFO in. */ \
  _ (VIRTIO_NET_F_MRG_RXBUF, VIRTIO_NET_F_MRG_RXBUF)	/* Host can merge receive buffers. */ \
  _ (VIRTIO_NET_F_STATUS, VIRTIO_NET_F_STATUS)	/* virtio_net_config.status available */ \
  _ (VIRTIO_NET_F_CTRL_VQ, VIRTIO_NET_F_CTRL_VQ)	/* Control channel available */ \
  _ (VIRTIO_NET_F_CTRL_RX, VIRTIO_NET_F_CTRL_RX)	/* Control channel RX mode support */ \
  _ (VIRTIO_NET_F_CTRL_VLAN, VIRTIO_NET_F_CTRL_VLAN)	/* Control channel VLAN filtering */ \
  _ (VIRTIO_NET_F_CTRL_RX_EXTRA, VIRTIO_NET_F_CTRL_RX_EXTRA)	/* Extra RX mode control support */ \
  _ (VIRTIO_NET_F_GUEST_ANNOUNCE, VIRTIO_NET_F_GUEST_ANNOUNCE)	/* Guest can announce device on the network */ \
  _ (VIRTIO_NET_F_MQ, VIRTIO_NET_F_MQ)	        /* Device supports Receive Flow Steering */ \
  _ (VIRTIO_NET_F_CTRL_MAC_ADDR, VIRTIO_NET_F_CTRL_MAC_ADDR)	/* Set MAC address */ \
  _ (VIRTIO_F_NOTIFY_ON_EMPTY, VIRTIO_F_NOTIFY_ON_EMPTY) \
  _ (VIRTIO_F_ANY_LAYOUT, VIRTIO_F_ANY_LAYOUT) \
  _ (VIRTIO_TRANSPORT_F_START, VIRTIO_TRANSPORT_F_START) \
  _ (VIRTIO_F_VERSION_1, VIRTIO_F_VERSION_1) \
  _ (VIRTIO_TRANSPORT_F_END, VIRTIO_TRANSPORT_F_END)

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
  u32 dev_instance;
  u32 hw_if_index;
  u32 sw_if_index;
  u32 per_interface_next_index;
  int fd;
  int tap_fd;
  virtio_vring_t *vrings;

  u64 features, remote_features;

  virtio_if_type_t type;
  u8 *name;
  u8 *net_ns;
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
