/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2017-2025 Cisco and/or its affiliates.
 */
#pragma once

#define TAP_PLUGIN_INTERNAL 1
#include <tap/tap.h>
#include <tap/tap_virtio_std.h>
#include <tap/tap_vhost_std.h>
#include <tap/tap_virtio_buffering.h>
#include <vnet/gso/gro.h>
#include <vnet/gso/hdr_offset_parser.h>
#include <vnet/vnet.h>
#include <vnet/interface.h>

#ifndef MIN
#define MIN(x, y) (((x) < (y)) ? (x) : (y))
#endif

typedef struct
{
  /* logging */
  vlib_log_class_t log_default;

  /* bit-map of in-use IDs */
  uword *tap_ids;

  /* host mtu size, configurable through startup.conf */
  int host_mtu_size;
  u16 msg_id_base;
} tap_main_t;

extern tap_main_t tap_main;

typedef struct
{
  u32 next_index;
  u32 hw_if_index;
  u16 ring;
  u16 len;
  vnet_virtio_net_hdr_v1_t hdr;
} tap_virtio_input_trace_t;

typedef struct
{
  u32 buffer_index;
  u32 sw_if_index;
  generic_header_offset_t gho;
  vlib_buffer_t buffer;
} tap_virtio_tx_trace_t;

typedef struct
{
  u32 id;
  u32 sw_if_index;
  u32 tap_flags;
  u8 dev_name[64];
  u16 tx_ring_sz;
  u16 rx_ring_sz;
  mac_address_t host_mac_addr;
  u8 host_if_name[64];
  u8 host_namespace[64];
  u8 host_bridge[64];
  ip4_address_t host_ip4_addr;
  u8 host_ip4_prefix_len;
  ip6_address_t host_ip6_addr;
  u8 host_ip6_prefix_len;
  u32 host_mtu_size;
} tap_interface_details_t;
int tap_gso_enable_disable (vlib_main_t *vm, u32 sw_if_index,
			    int enable_disable, int packet_coalesce);
int tap_csum_offload_enable_disable (vlib_main_t *vm, u32 sw_if_index,
				     int enable_disable);
int tap_dump_ifs (tap_interface_details_t **out_tapids);

/* Status byte for guest to report progress. */
#define foreach_virtio_config_status_flags                                    \
  _ (VIRTIO_CONFIG_STATUS_RESET, 0x00)                                        \
  _ (VIRTIO_CONFIG_STATUS_ACK, 0x01)                                          \
  _ (VIRTIO_CONFIG_STATUS_DRIVER, 0x02)                                       \
  _ (VIRTIO_CONFIG_STATUS_DRIVER_OK, 0x04)                                    \
  _ (VIRTIO_CONFIG_STATUS_FEATURES_OK, 0x08)                                  \
  _ (VIRTIO_CONFIG_STATUS_DEVICE_NEEDS_RESET, 0x40)                           \
  _ (VIRTIO_CONFIG_STATUS_FAILED, 0x80)

typedef enum
{
#define _(a, b) a = b,
  foreach_virtio_config_status_flags
#undef _
} tap_virtio_config_status_flags_t;

#define foreach_virtio_if_flag                                                \
  _ (0, ADMIN_UP, "admin-up")                                                 \
  _ (1, DELETING, "deleting")

typedef enum
{
#define _(a, b, c) VIRTIO_IF_FLAG_##b = (1 << a),
  foreach_virtio_if_flag
#undef _
} tap_virtio_if_flag_t;

#define TX_QUEUE(X)	   ((X * 2) + 1)
#define RX_QUEUE(X)	   (X * 2)
#define TX_QUEUE_ACCESS(X) (X / 2)
#define RX_QUEUE_ACCESS(X) (X / 2)

#define VIRTIO_NUM_RX_DESC 256
#define VIRTIO_NUM_TX_DESC 256

#define foreach_virtio_if_types                                               \
  _ (TAP, 0)                                                                  \
  _ (TUN, 1)

typedef enum
{
#define _(a, b) VIRTIO_IF_TYPE_##a = (1 << b),
  foreach_virtio_if_types
#undef _
    VIRTIO_IF_N_TYPES = (1 << 3),
} tap_virtio_if_type_t;

#define VIRTIO_RING_FLAG_MASK_INT 1

#define VIRTIO_EVENT_START_TIMER 1
#define VIRTIO_EVENT_STOP_TIMER	 2

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
  tap_virtio_vring_buffering_t *buffering;
  gro_flow_table_t *flow_table;
  u64 total_packets;
} vnet_virtio_vring_t;

typedef union
{
  struct
  {
    u16 domain;
    u8 bus;
    u8 slot : 5;
    u8 function : 3;
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
  int gso_enabled;
  int csum_offload_enabled;
  int rss_enabled;
  union
  {
    int *tap_fds;
    struct
    {
      u32 pci_dev_handle;
      u32 msix_enabled;
    };
  };
  u16 tap_virtio_net_hdr_sz;
  tap_virtio_if_type_t type;

  u32 hw_if_index;
  u32 sw_if_index;
  u8 *initial_if_name;

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
  u8 host_carrier_up; /* host tun/tap driver link carrier state */
  u8 consistent_qp : 1;
} tap_virtio_if_t;

typedef struct
{
  u32 gro_or_buffering_if_count;
  /* logging */
  vlib_log_class_t log_default;

  tap_virtio_if_t *interfaces;
  u16 msg_id_base;
} tap_virtio_main_t;

extern tap_virtio_main_t tap_virtio_main;
extern vnet_device_class_t tap_virtio_device_class;
extern vlib_node_registration_t tap_virtio_input_node;

#define tap_virtio_log_error(vif, f, ...)                                     \
  vlib_log (VLIB_LOG_LEVEL_ERR, tap_virtio_main.log_default, "tap%u: " f,     \
	    (vif)->dev_instance, ##__VA_ARGS__)
#define tap_virtio_log_debug(vif, f, ...)                                     \
  vlib_log (VLIB_LOG_LEVEL_DEBUG, tap_virtio_main.log_default, "tap%u: " f,   \
	    (vif)->dev_instance, ##__VA_ARGS__)

clib_error_t *tap_virtio_vring_init (vlib_main_t *vm, tap_virtio_if_t *vif,
				     u16 idx, u16 sz);
clib_error_t *tap_virtio_vring_free_rx (vlib_main_t *vm, tap_virtio_if_t *vif,
					u32 idx);
clib_error_t *tap_virtio_vring_free_tx (vlib_main_t *vm, tap_virtio_if_t *vif,
					u32 idx);
void tap_virtio_vring_set_rx_queues (vlib_main_t *vm, tap_virtio_if_t *vif);
void tap_virtio_vring_set_tx_queues (vlib_main_t *vm, tap_virtio_if_t *vif);
void tap_virtio_set_net_hdr_size (tap_virtio_if_t *vif);
void tap_virtio_show (vlib_main_t *vm, u32 *hw_if_indices, u8 show_descr,
		      tap_virtio_if_type_t type);
void tap_virtio_set_packet_coalesce (tap_virtio_if_t *vif);
clib_error_t *tap_virtio_set_packet_buffering (tap_virtio_if_t *vif, u16 size);
void tap_virtio_pre_input_node_enable (vlib_main_t *vm, tap_virtio_if_t *vif);
void tap_virtio_pre_input_node_disable (vlib_main_t *vm, tap_virtio_if_t *vif);

format_function_t format_tx_node_name;
format_function_t format_tap_virtio_log_name;
format_function_t format_tap_virtio_device;
format_function_t format_tap_virtio_tx_trace;
format_function_t format_tap_virtio_input_trace;

static_always_inline void
tap_virtio_kick (vlib_main_t *vm, vnet_virtio_vring_t *vring,
		 tap_virtio_if_t *vif)
{
  u64 x = 1;
  int __clib_unused r;

  r = write (vring->kick_fd, &x, sizeof (x));
  vring->last_kick_avail_idx = vring->avail->idx;
}

static_always_inline u8
tap_virtio_txq_is_scheduled (vnet_virtio_vring_t *vring)
{
  if (vring)
    return (vring->flags & VRING_TX_SCHEDULED);
  return 1;
}

static_always_inline void
tap_virtio_txq_set_scheduled (vnet_virtio_vring_t *vring)
{
  if (vring)
    vring->flags |= VRING_TX_SCHEDULED;
}

static_always_inline void
tap_virtio_txq_clear_scheduled (vnet_virtio_vring_t *vring)
{
  if (vring)
    vring->flags &= ~VRING_TX_SCHEDULED;
}
