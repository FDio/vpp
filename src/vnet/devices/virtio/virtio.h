/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2017-2025 Cisco and/or its affiliates.
 */

#pragma once

#include <vnet/devices/virtio/virtio_std.h>
#include <vnet/devices/virtio/vhost_std.h>
#include <vnet/devices/virtio/virtio_buffering.h>
#include <vnet/gso/gro.h>
#include <vnet/interface.h>

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

#define VIRTIO_RING_FLAG_MASK_INT 1

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  clib_spinlock_t lockp;
  union
  {
    struct
    {
      vnet_virtio_vring_desc_t *desc;
      vnet_virtio_vring_used_t *used;
      vnet_virtio_vring_avail_t *avail;
    };
    struct
    {
      vnet_virtio_vring_packed_desc_t *packed_desc;
      vnet_virtio_vring_desc_event_t *driver_event;
      vnet_virtio_vring_desc_event_t *device_event;
    };
  };
  u32 *buffers;
  u16 queue_size;
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
#define VRING_TX_SCHEDULED    2
  u16 flags;
  u8 buffer_pool_index;
  vnet_hw_if_rx_mode mode;
  virtio_vring_buffering_t *buffering;
  gro_flow_table_t *flow_table;
  u64 total_packets;
} vnet_virtio_vring_t;

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
  vnet_virtio_vring_t *rxq_vrings;
  vnet_virtio_vring_t *txq_vrings;
  u32 pci_dev_handle;
  u32 msix_enabled;
  u16 virtio_net_hdr_sz;

  u32 hw_if_index;
  u32 sw_if_index;
  u8 *initial_if_name;
  u8 is_packed : 1;
  u8 consistent_qp : 1;
  u8 gso_enabled : 1;
  u8 csum_offload_enabled : 1;
  u8 rss_enabled : 1;

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
  void *bar;
  vnet_virtio_vring_t *cxq_vring;
  pci_addr_t pci_addr;
  u32 bar_id;
  u32 notify_off_multiplier;
  u16 common_offset;
  u16 notify_offset;
  u16 device_offset;
  u16 isr_offset;
  u16 max_queue_pairs;
  u16 msix_table_size;
  u8 support_int_mode; /* support interrupt mode */
  u8 status;
} virtio_if_t;

typedef struct
{
  u32 gro_or_buffering_if_count;
  /* logging */
  vlib_log_class_t log_default;

  virtio_if_t *interfaces;
  u16 msg_id_base;
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
void virtio_vring_set_rx_queues (vlib_main_t *vm, virtio_if_t *vif);
void virtio_vring_set_tx_queues (vlib_main_t *vm, virtio_if_t *vif);
extern void virtio_free_buffers (vlib_main_t *vm, vnet_virtio_vring_t *vring);
extern void virtio_set_net_hdr_size (virtio_if_t * vif);
extern void virtio_show (vlib_main_t *vm, u32 *hw_if_indices, u8 show_descr);
extern void virtio_set_packet_coalesce (virtio_if_t * vif);
clib_error_t *virtio_set_packet_buffering (virtio_if_t * vif, u16 size);
extern void virtio_pci_notify_queue (vlib_main_t *vm, virtio_if_t *vif,
				     u16 queue_id, u16 queue_notify_offset);
extern void virtio_pre_input_node_enable (vlib_main_t *vm, virtio_if_t *vif);
extern void virtio_pre_input_node_disable (vlib_main_t *vm, virtio_if_t *vif);

format_function_t format_virtio_device_name;
format_function_t format_virtio_log_name;

static_always_inline void
virtio_kick (vlib_main_t *vm, vnet_virtio_vring_t *vring, virtio_if_t *vif)
{
  virtio_pci_notify_queue (vm, vif, vring->queue_id,
			   vring->queue_notify_offset);
}

static_always_inline u8
virtio_txq_is_scheduled (vnet_virtio_vring_t *vring)
{
  if (vring)
    return (vring->flags & VRING_TX_SCHEDULED);
  return 1;
}

static_always_inline void
virtio_txq_set_scheduled (vnet_virtio_vring_t *vring)
{
  if (vring)
    vring->flags |= VRING_TX_SCHEDULED;
}

static_always_inline void
virtio_txq_clear_scheduled (vnet_virtio_vring_t *vring)
{
  if (vring)
    vring->flags &= ~VRING_TX_SCHEDULED;
}

static_always_inline void
vnet_virtio_vring_init (vnet_virtio_vring_t *vring, u16 queue_size, void *p,
			u32 align)
{
  vring->queue_size = queue_size;
  vring->desc = p;
  vring->avail =
    (vnet_virtio_vring_avail_t *) ((char *) p +
				   queue_size *
				     sizeof (vnet_virtio_vring_desc_t));
  vring->used =
    (vnet_virtio_vring_used_t
       *) ((char *) p + ((sizeof (vnet_virtio_vring_desc_t) * queue_size +
			  sizeof (u16) * (3 + queue_size) + align - 1) &
			 ~(align - 1)));
  vring->avail->flags = VIRTIO_RING_FLAG_MASK_INT;
}

static_always_inline u16
vnet_virtio_vring_size (u16 queue_size, u32 align)
{
  return ((sizeof (vnet_virtio_vring_desc_t) * queue_size +
	   sizeof (u16) * (3 + queue_size) + align - 1) &
	  ~(align - 1)) +
	 sizeof (u16) * 3 +
	 sizeof (vnet_virtio_vring_used_elem_t) * queue_size;
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

#define virtio_log_error(vif, f, ...)                                         \
  {                                                                           \
    vlib_log (VLIB_LOG_LEVEL_ERR, virtio_main.log_default, "%U: " f,          \
	      format_virtio_log_name, vif, ##__VA_ARGS__);                    \
  };
