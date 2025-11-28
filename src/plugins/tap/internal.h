/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2017-2025 Cisco and/or its affiliates.
 */
#pragma once

#define TAP_PLUGIN_INTERNAL 1
#include <tap/tap.h>
#include <tap/virtio_net.h>
#include <tap/vhost.h>
#include <vnet/gso/gro.h>
#include <vnet/gso/hdr_offset_parser.h>
#include <vnet/vnet.h>
#include <vnet/interface.h>

#ifndef MIN
#define MIN(x, y) (((x) < (y)) ? (x) : (y))
#endif

/* we always use VIRTIO_NET_F_MRG_RXBUF */
#define VIRTIO_NET_HDR_SZ sizeof (vnet_virtio_net_hdr_v1_t)

typedef struct
{
  u32 next_index;
  u32 hw_if_index;
  u16 ring;
  u16 len;
  vnet_virtio_net_hdr_v1_t hdr;
} tap_rx_trace_t;

typedef struct
{
  u32 buffer_index;
  u32 sw_if_index;
  generic_header_offset_t gho;
  vlib_buffer_t buffer;
} tap_tx_trace_t;

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

#define TX_QUEUE(X)	   ((X * 2) + 1)
#define RX_QUEUE(X)	   (X * 2)
#define TX_QUEUE_ACCESS(X) (X / 2)
#define RX_QUEUE_ACCESS(X) (X / 2)

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  vnet_virtio_vring_desc_t *desc;
  vnet_virtio_vring_used_t *used;
  vnet_virtio_vring_avail_t *avail;
  u32 *buffers;
  u64 total_packets;
  int kick_fd;
  int call_fd;
  u16 desc_in_use;
  u16 desc_next;
  u16 queue_size;
  u16 last_used_idx;
  u8 lock;
  u8 tx_is_scheduled : 1;
  u8 tx_out_of_order : 1;
  u8 buffer_pool_index;
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline1);
  gro_flow_table_t *flow_table;
  u32 call_file_index;
  u16 queue_id;
  u32 queue_index;
} vnet_virtio_vring_t;

STATIC_ASSERT_SIZEOF (vnet_virtio_vring_t, 2 * CLIB_CACHE_LINE_BYTES);

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  u64 features;
  u8 admin_up : 1;
  u8 is_tun : 1;
  u8 consistent_qp : 1;
  u8 host_carrier_up : 1;
  u8 gso_enabled : 1;
  u8 csum_offload_enabled : 1;
  u8 packet_coalesce : 1;
  u32 per_interface_next_index;
  u16 num_rxqs;
  u16 num_txqs;
  vnet_virtio_vring_t *rxq_vrings;
  vnet_virtio_vring_t *txq_vrings;
  int *tap_fds;
  u32 hw_if_index;
  u32 sw_if_index;
  u8 *initial_if_name;

  CLIB_CACHE_LINE_ALIGN_MARK (cacheline1);
  u32 dev_instance;
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
} tap_if_t;

typedef struct
{
  u32 gro_if_count;
  /* logging */
  vlib_log_class_t log_default;

  /* bit-map of in-use IDs */
  uword *tap_ids;

  tap_if_t *interfaces;
  u16 msg_id_base;
  vhost_memory_t *vhost_mem;
} tap_main_t;

extern tap_main_t tap_main;
extern vnet_device_class_t tap_device_class;
extern vlib_node_registration_t tap_input_node;

#define log_err(tif, f, ...)                                                  \
  vlib_log (VLIB_LOG_LEVEL_ERR, tap_main.log_default, "tap%u: " f,            \
	    (tif)->dev_instance, ##__VA_ARGS__)
#define log_warn(tif, f, ...)                                                 \
  vlib_log (VLIB_LOG_LEVEL_WARNING, tap_main.log_default, "tap%u: " f,        \
	    (tif)->dev_instance, ##__VA_ARGS__)
#define log_dbg(tif, f, ...)                                                  \
  vlib_log (VLIB_LOG_LEVEL_DEBUG, tap_main.log_default, "tap%u: " f,          \
	    (tif)->dev_instance, ##__VA_ARGS__)

void tap_pre_input_node_enable (vlib_main_t *vm, tap_if_t *tif);
void tap_pre_input_node_disable (vlib_main_t *vm, tap_if_t *tif);
int tap_dump_ifs (tap_interface_details_t **out_tapids);

format_function_t format_tx_node_name;
format_function_t format_tap_log_name;
format_function_t format_tap_device;
format_function_t format_tap_tx_trace;
format_function_t format_tap_input_trace;
format_function_t format_virtio_features;
format_function_t format_if_tun_features;
format_function_t format_if_tun_offloads;
