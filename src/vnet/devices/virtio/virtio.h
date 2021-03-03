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

#include <vnet/devices/virtio/virtio_std.h>
#include <vnet/devices/virtio/vhost_std.h>
#include <vnet/devices/virtio/virtio_buffering.h>
#include <vnet/gso/gro.h>

#define foreach_virtio_if_flag		\
  _(0, ADMIN_UP, "admin-up")		\
  _(1, DELETING, "deleting")

typedef enum
{
#define _(a, b, c) VIRTIO_IF_FLAG_##b = (1 << a),
  foreach_virtio_if_flag
#undef _
} virtio_if_flag_t;

#define TX_QUEUE(X) ((X*2) + 1)
#define RX_QUEUE(X) (X*2)
#define TX_QUEUE_ACCESS(X) (X/2)
#define RX_QUEUE_ACCESS(X) (X/2)

#define VIRTIO_NUM_RX_DESC 256
#define VIRTIO_NUM_TX_DESC 256

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

#define VIRTIO_RING_FLAG_MASK_INT 1

#define VIRTIO_EVENT_START_TIMER 1
#define VIRTIO_EVENT_STOP_TIMER 2

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  clib_spinlock_t lockp;
  union
  {
    struct
    {
      vring_desc_t *desc;
      vring_used_t *used;
      vring_avail_t *avail;
    };
    struct
    {
      vring_packed_desc_t *packed_desc;
      vring_desc_event_t *driver_event;
      vring_desc_event_t *device_event;
    };
  };
  u32 *buffers;
  u16 size;
  u16 queue_id;
  u32 queue_index;
  u16 desc_in_use;
  u16 desc_next;
  u16 last_used_idx;
  u16 last_kick_avail_idx;
  union
  {
    struct
    {
      int kick_fd;
      int call_fd;
      u32 call_file_index;
    };
    struct
    {
      u16 avail_wrap_counter;
      u16 used_wrap_counter;
      u16 queue_notify_offset;
    };
  };
#define VRING_TX_OUT_OF_ORDER 1
#define VRING_TX_QUEUE_SHARED 2
#define VRING_TX_QUEUE_UNIQUE 4
  u16 flags;
  u8 buffer_pool_index;
  vnet_hw_if_rx_mode mode;
  virtio_vring_buffering_t *buffering;
  gro_flow_table_t *flow_table;
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

/* forward declaration */
typedef struct _virtio_pci_func virtio_pci_func_t;

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
  int packet_coalesce;
  int packet_buffering;
  u32 dev_instance;
  u32 numa_node;
  u64 remote_features;

  /* error */
  clib_error_t *error;
  union
  {
    struct
    {
      u32 mac_addr32;
      u16 mac_addr16;
    };
    u8 mac_addr[6];
  };
  union
  {
    struct			/* tun/tap interface */
    {
      ip6_address_t host_ip6_addr;
      int *vhost_fds;
      u8 *host_if_name;
      u8 *net_ns;
      u8 *host_bridge;
      u8 host_mac_addr[6];
      u32 id;
      u32 host_mtu_size;
      u32 tap_flags;
      int ifindex;
      ip4_address_t host_ip4_addr;
      u8 host_ip4_prefix_len;
      u8 host_ip6_prefix_len;
      u8 host_carrier_up;	/* host tun/tap driver link carrier state */
    };
    struct			/* native virtio */
    {
      void *bar;
      virtio_vring_t *cxq_vring;
      pci_addr_t pci_addr;
      u32 bar_id;
      u32 notify_off_multiplier;
      u32 is_modern;
      u16 common_offset;
      u16 notify_offset;
      u16 device_offset;
      u16 isr_offset;
      u16 max_queue_pairs;
      u16 msix_table_size;
      u8 support_int_mode;	/* support interrupt mode */
      u8 status;
    };
  };
  const virtio_pci_func_t *virtio_pci_func;
  int is_packed;
} virtio_if_t;

typedef struct
{
  u32 interrupt_queues_count;
  /* logging */
  vlib_log_class_t log_default;

  virtio_if_t *interfaces;
} virtio_main_t;

extern virtio_main_t virtio_main;
extern vnet_device_class_t virtio_device_class;
extern vlib_node_registration_t virtio_input_node;
extern vlib_node_registration_t virtio_send_interrupt_node;

clib_error_t *virtio_vring_init (vlib_main_t * vm, virtio_if_t * vif, u16 idx,
				 u16 sz);
clib_error_t *virtio_vring_free_rx (vlib_main_t * vm, virtio_if_t * vif,
				    u32 idx);
clib_error_t *virtio_vring_free_tx (vlib_main_t * vm, virtio_if_t * vif,
				    u32 idx);
void virtio_vring_set_rx_queues (vlib_main_t *vm, virtio_if_t *vif);
void virtio_vring_set_tx_queues (vlib_main_t *vm, virtio_if_t *vif);
extern void virtio_free_buffers (vlib_main_t * vm, virtio_vring_t * vring);
extern void virtio_set_net_hdr_size (virtio_if_t * vif);
extern void virtio_show (vlib_main_t * vm, u32 * hw_if_indices, u8 show_descr,
			 u32 type);
extern void virtio_set_packet_coalesce (virtio_if_t * vif);
clib_error_t *virtio_set_packet_buffering (virtio_if_t * vif, u16 size);
extern void virtio_pci_legacy_notify_queue (vlib_main_t * vm,
					    virtio_if_t * vif, u16 queue_id,
					    u16 queue_notify_offset);
extern void virtio_pci_modern_notify_queue (vlib_main_t * vm,
					    virtio_if_t * vif, u16 queue_id,
					    u16 queue_notify_offset);
format_function_t format_virtio_device_name;
format_function_t format_virtio_log_name;

static_always_inline void
virtio_kick (vlib_main_t * vm, virtio_vring_t * vring, virtio_if_t * vif)
{
  if (vif->type == VIRTIO_IF_TYPE_PCI)
    {
      if (vif->is_modern)
	virtio_pci_modern_notify_queue (vm, vif, vring->queue_id,
					vring->queue_notify_offset);
      else
	virtio_pci_legacy_notify_queue (vm, vif, vring->queue_id,
					vring->queue_notify_offset);
    }
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
