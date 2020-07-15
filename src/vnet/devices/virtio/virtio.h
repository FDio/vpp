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

#include <linux/virtio_config.h>
#include <linux/virtio_net.h>
#include <linux/virtio_pci.h>
#include <linux/virtio_ring.h>

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
  _ (VIRTIO_F_ANY_LAYOUT, 27)  /* Can the device handle any descriptor layout */ \
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

#define VIRTIO_NUM_RX_DESC 256
#define VIRTIO_NUM_TX_DESC 256

#define VIRTIO_FEATURE(X) (1ULL << X)

#define TX_QUEUE(X) ((X*2) + 1)
#define RX_QUEUE(X) (X*2)
#define TX_QUEUE_ACCESS(X) (X/2)
#define RX_QUEUE_ACCESS(X) (X/2)

#define foreach_virtio_if_types \
  _ (TAP, 0)                    \
  _ (TUN, 1)                    \
  _ (PCI, 2)

typedef enum
{
#define _(a, b) VIRTIO_IF_TYPE_##a = (1 << b),
  foreach_virtio_if_types
#undef _
    VIRTIO_IF_N_TYPES = (1 << 3),
} virtio_if_type_t;


typedef struct
{
  u8 mac[6];
  u16 status;
  u16 max_virtqueue_pairs;
  u16 mtu;
} virtio_net_config_t;

#define VIRTIO_RING_FLAG_MASK_INT 1

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  clib_spinlock_t lockp;
  struct vring_desc *desc;
  struct vring_used *used;
  struct vring_avail *avail;
  u16 desc_in_use;
  u16 desc_next;
  int kick_fd;
  int call_fd;
  u8 buffer_pool_index;
  u16 size;
  u16 queue_id;
#define VRING_TX_OUT_OF_ORDER 1
  u16 flags;
  u32 *buffers;
  u16 last_used_idx;
  u16 last_kick_avail_idx;
  u32 call_file_index;
} virtio_vring_t;

typedef union
{
  struct
  {
    u16 domain;
    u8 bus;
    u8 slot:5;
    u8 function:3;
  };
  u32 as_u32;
} pci_addr_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  u64 features;
  u32 flags;
  u32 per_interface_next_index;
  u16 num_rxqs;
  u16 num_txqs;
  virtio_vring_t *rxq_vrings;
  virtio_vring_t *txq_vrings;
  int gso_enabled;
  int csum_offload_enabled;
  union
  {
    int *tap_fds;
    struct
    {
      u32 pci_dev_handle;
      u32 msix_enabled;
    };
  };
  u16 virtio_net_hdr_sz;
  virtio_if_type_t type;

  u32 hw_if_index;
  u32 sw_if_index;

    CLIB_CACHE_LINE_ALIGN_MARK (cacheline1);
  union
  {
    u32 id;
    pci_addr_t pci_addr;
  };
  int *vhost_fds;
  u32 dev_instance;
  u32 numa_node;
  u64 remote_features;

  /* error */
  clib_error_t *error;
  u8 support_int_mode;		/* support interrupt mode */
  u16 max_queue_pairs;
  u16 msix_table_size;
  u8 status;
  u8 mac_addr[6];
  u8 *host_if_name;
  u8 *net_ns;
  u8 *host_bridge;
  u8 host_mac_addr[6];
  ip4_address_t host_ip4_addr;
  u8 host_ip4_prefix_len;
  ip6_address_t host_ip6_addr;
  u8 host_ip6_prefix_len;
  u32 host_mtu_size;
  u32 tap_flags;
  int ifindex;
  virtio_vring_t *cxq_vring;
} virtio_if_t;

typedef struct
{
  /* logging */
  vlib_log_class_t log_default;

  virtio_if_t *interfaces;
} virtio_main_t;

extern virtio_main_t virtio_main;
extern vnet_device_class_t virtio_device_class;
extern vlib_node_registration_t virtio_input_node;

clib_error_t *virtio_vring_init (vlib_main_t * vm, virtio_if_t * vif, u16 idx,
				 u16 sz);
clib_error_t *virtio_vring_free_rx (vlib_main_t * vm, virtio_if_t * vif,
				    u32 idx);
clib_error_t *virtio_vring_free_tx (vlib_main_t * vm, virtio_if_t * vif,
				    u32 idx);
void virtio_vring_set_numa_node (vlib_main_t * vm, virtio_if_t * vif,
				 u32 idx);
extern void virtio_free_used_desc (vlib_main_t * vm, virtio_vring_t * vring);
extern void virtio_free_rx_buffers (vlib_main_t * vm, virtio_vring_t * vring);
extern void virtio_set_net_hdr_size (virtio_if_t * vif);
extern void virtio_show (vlib_main_t * vm, u32 * hw_if_indices, u8 show_descr,
			 u32 type);
extern void virtio_pci_legacy_notify_queue (vlib_main_t * vm,
					    virtio_if_t * vif, u16 queue_id);
format_function_t format_virtio_device_name;
format_function_t format_virtio_log_name;

static_always_inline void
virtio_kick (vlib_main_t * vm, virtio_vring_t * vring, virtio_if_t * vif)
{
  if (vif->type == VIRTIO_IF_TYPE_PCI)
    virtio_pci_legacy_notify_queue (vm, vif, vring->queue_id);
  else
    {
      u64 x = 1;
      int __clib_unused r;

      r = write (vring->kick_fd, &x, sizeof (x));
      vring->last_kick_avail_idx = vring->avail->idx;
    }
}


#define virtio_log_debug(vif, f, ...)				\
{								\
  vlib_log(VLIB_LOG_LEVEL_DEBUG, virtio_main.log_default,	\
	   "%U: " f, format_virtio_log_name, vif,		\
           ##__VA_ARGS__);					\
};

#define virtio_log_warning(vif, f, ...)				\
{								\
  vlib_log(VLIB_LOG_LEVEL_WARNING, virtio_main.log_default,	\
	   "%U: " f, format_virtio_log_name, vif,		\
           ##__VA_ARGS__);					\
};

#define virtio_log_error(vif, f, ...)				\
{								\
  vlib_log(VLIB_LOG_LEVEL_ERR, virtio_main.log_default,		\
	   "%U: " f, format_virtio_log_name, vif,		\
           ##__VA_ARGS__);					\
};

#endif /* _VNET_DEVICES_VIRTIO_VIRTIO_H_ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
