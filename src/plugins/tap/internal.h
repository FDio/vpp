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
#define TUN_DATA_OFFSET	  14

typedef struct
{
  u32 hw_if_index;
  u16 next_index;
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
  u32 call_file_index;
  u16 desc_in_use;
  u16 queue_size;
  u16 last_used_idx;
  u16 desc_next;
  u16 queue_id;
  u8 buffer_pool_index;
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline1);
  u32 queue_index;
} tap_rxq_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  vnet_virtio_vring_desc_t *desc;
  vnet_virtio_vring_used_t *used;
  vnet_virtio_vring_avail_t *avail;
  u32 *buffers;
  gro_flow_table_t *flow_table;
  u64 total_packets;
  int kick_fd;
  u16 desc_in_use;
  u16 queue_size;
  u16 last_used_idx;
  u16 desc_next;
  u16 desc_freelist_head;
  u8 lock;
  u8 tx_is_scheduled : 1;
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline1);
  u16 queue_id;
  u32 queue_index;
} tap_txq_t;

STATIC_ASSERT_SIZEOF (tap_rxq_t, 2 * CLIB_CACHE_LINE_BYTES);
STATIC_ASSERT_SIZEOF (tap_txq_t, 2 * CLIB_CACHE_LINE_BYTES);

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
  u8 feature_arc_enabled : 1;
  u8 feature_arc_index;
  u16 next_index;
  u32 per_interface_next_index;
  tap_rxq_t *rx_queues;
  tap_txq_t *tx_queues;
  int *tap_fds;
  u32 hw_if_index;
  u32 sw_if_index;
  u32 feature_arc_config_index;
  u32 feature_arc_next_index;
  u8 *name;

  CLIB_CACHE_LINE_ALIGN_MARK (cacheline1);
  vlib_buffer_template_t buffer_template;
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline2);
  u64 remote_features;
  u32 dev_instance;
  u32 id;
  u32 host_mtu_size;
  u32 tap_flags;

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
  u8 host_ip4_prefix_len;
  u8 host_ip6_prefix_len;
  int ifindex;
  ip4_address_t host_ip4_addr;
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

static_always_inline tap_rxq_t *
tap_get_rx_queue (tap_if_t *tif, u16 qid)
{
  return vec_elt_at_index (tif->rx_queues, qid);
}

static_always_inline tap_txq_t *
tap_get_tx_queue (tap_if_t *tif, u16 qid)
{
  return vec_elt_at_index (tif->tx_queues, qid);
}

#define log_err(tif, f, ...)                                                  \
  vlib_log (VLIB_LOG_LEVEL_ERR, tap_main.log_default, "%U: " f,               \
	    format_tap_log_name, tif, ##__VA_ARGS__)
#define log_warn(tif, f, ...)                                                 \
  vlib_log (VLIB_LOG_LEVEL_WARNING, tap_main.log_default, "%U: " f,           \
	    format_tap_log_name, tif, ##__VA_ARGS__)
#define log_dbg(tif, f, ...)                                                  \
  vlib_log (VLIB_LOG_LEVEL_DEBUG, tap_main.log_default, "%U: " f,             \
	    format_tap_log_name, tif, ##__VA_ARGS__)

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

#define foreach_tap_tx_func_error                                             \
  _ (NO_FREE_SLOTS, "no free tx slots")                                       \
  _ (TRUNC_PACKET, "packet > buffer size -- truncated in tx ring")            \
  _ (PENDING_MSGS, "pending msgs in tx ring")                                 \
  _ (INDIRECT_DESC_ALLOC_FAILED,                                              \
     "indirect descriptor allocation failed - packet drop")                   \
  _ (OUT_OF_ORDER, "out-of-order buffers in used ring")                       \
  _ (GSO_PACKET_DROP, "gso disabled on itf  -- gso packet drop")              \
  _ (CSUM_OFFLOAD_PACKET_DROP,                                                \
     "checksum offload disabled on itf -- csum offload packet drop")

typedef enum
{
#define _(f, s) TAP_TX_ERROR_##f,
  foreach_tap_tx_func_error
#undef _
    TAP_TX_N_ERROR,
} tap_tx_func_error_t;
