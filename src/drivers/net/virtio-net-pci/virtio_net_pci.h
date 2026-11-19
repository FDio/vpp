/* SPDX-License-Identifier: Apache-2.0 */
#pragma once

#include <vnet/dev/dev.h>
#include <vnet/dev/bus/pci.h>
#include <vnet/ethernet/ethernet.h>

#include <virtio_net.h>

#define log_debug(dev, f, ...)                                                                     \
  vlib_log (VLIB_LOG_LEVEL_DEBUG, vnp_log.class, "%U" f, format_vnet_dev_log, (dev),               \
	    clib_string_skip_prefix (__func__, "vnp_"), ##__VA_ARGS__)
#define log_notice(dev, f, ...)                                                                    \
  vlib_log (VLIB_LOG_LEVEL_NOTICE, vnp_log.class, "%U: " f, format_vnet_dev_addr, (dev),           \
	    ##__VA_ARGS__)
#define log_warn(dev, f, ...)                                                                      \
  vlib_log (VLIB_LOG_LEVEL_WARNING, vnp_log.class, "%U: " f, format_vnet_dev_addr, (dev),          \
	    ##__VA_ARGS__)
#define log_err(dev, f, ...)                                                                       \
  vlib_log (VLIB_LOG_LEVEL_ERR, vnp_log.class, "%U: " f, format_vnet_dev_addr, (dev), ##__VA_ARGS__)

#define VNP_INDIRECT_STRIDE    128
#define VNP_MAX_SEGS	       127
#define VNP_RX_REFILL_BATCH_SZ 64

typedef struct
{
  virtq_desc_t *desc;
  virtq_avail_t *avail;
  virtq_used_t *used;
  pvirtq_desc_t *packed;
  u16 *notify;
  u32 *buffer_indices;
  u16 *free_ids;
  u16 id, last_used, avail_index, n_free;
  u16 packed_avail, packed_used;
  u32 max_len;
  u16 desc_len;
  pvirtq_event_suppress_t *driver_event, *device_event;
} vnp_rxq_t;

typedef struct
{
  virtq_desc_t *desc;
  virtq_avail_t *avail;
  virtq_used_t *used;
  pvirtq_desc_t *packed;
  u16 *packed_count;
  u16 *notify;
  u32 *buffer_indices;
  u16 *free_ids;
  u16 id, last_used, avail_index, n_free;
  u16 packed_avail, packed_used, published, packed_outstanding;
  virtq_desc_t *indirect;
  u64 indirect_dma;
  pvirtq_event_suppress_t *device_event;
} vnp_txq_t;

typedef struct
{
  union
  {
    virtq_desc_t *desc;
    pvirtq_desc_t *pdesc;
  };
  u16 *notify;
  u16 size;
  u16 id;
  u16 index;
  u8 packed : 1;
  u8 failed : 1;
} vnp_ctlq_t;

typedef struct
{
  virtio_pci_common_cfg_t *common;
  virtio_net_config_t *config;
  void *notify;
  u8 *isr;
  u64 offered, features;
  u32 notify_multiplier, notify_length, config_length;
  vnp_ctlq_t control;
} vnp_dev_t;

/* Tail of the RSS configuration, follows the variable-length indirection table. */
typedef struct
{
  u16 max_tx_vq;
  u8 hash_key_length;
  u8 hash_key_data[];
} __clib_packed vnp_rss_tail_t;
STATIC_ASSERT_SIZEOF (vnp_rss_tail_t, 3);

typedef struct
{
  u8 macs[64][6];
  u16 n_macs;
  u8 irq_registered, use_intx;
} vnp_port_t;

#define foreach_vnp_tx_node_counter                                                                \
  _ (FULL, "ring-full", ERROR, "No free TX slots")                                                 \
  _ (INVALID, "invalid-packet", ERROR, "TX packet exceeds frame size or requires offload")

typedef enum
{
#define _(n, s, v, d) VNP_TX_##n,
  foreach_vnp_tx_node_counter
#undef _
} vnp_tx_counter_t;

#define foreach_vnp_rx_node_counter                                                                \
  _ (ALLOC, "alloc-failed", ERROR, "RX buffer allocation failed")                                  \
  _ (INVALID, "invalid-packet", ERROR, "Invalid RX packet")

typedef enum
{
#define _(n, s, v, d) VNP_RX_##n,
  foreach_vnp_rx_node_counter
#undef _
} vnp_rx_counter_t;

typedef struct
{
  u32 length;
  u16 queue_id;
  virtio_net_hdr_t hdr;
} vnp_rx_trace_t;

typedef struct
{
  u32 length;
  u16 queue_id;
  u16 n_descs;
  u8 indirect : 1;
  u8 packed : 1;
  virtio_net_hdr_t hdr;
  virtq_desc_t head;
  virtq_desc_t descs[];
} vnp_tx_trace_t;

/* control.c */
vnet_dev_rv_t vnp_ctlq_alloc (vlib_main_t *, vnet_dev_t *, vnp_ctlq_t *, u16, u16);
void vnp_ctlq_free (vlib_main_t *, vnet_dev_t *, vnp_ctlq_t *);
vnet_dev_rv_t vnp_ctlq_start (vlib_main_t *, vnet_dev_t *, vnp_ctlq_t *);
vnet_dev_rv_t vnp_control (vlib_main_t *, vnet_dev_t *, u8, u8, void *, u32);
vnet_dev_rv_t vnp_filters (vlib_main_t *, vnet_dev_port_t *);
vnet_dev_rv_t vnp_rss (vlib_main_t *, vnet_dev_port_t *, const vnet_dev_rss_config_t *);

/* format.c */
format_function_t format_vnp_ctrl_cmd;
format_function_t format_vnp_ctrl_ack;
format_function_t format_vnp_dev_info;
format_function_t format_vnp_port_status;
format_function_t format_vnp_rx_queue;
format_function_t format_vnp_tx_queue;
format_function_t format_vnp_rx_trace;
format_function_t format_vnp_tx_trace;

/* init.c */
extern vnet_dev_node_t vnp_rx_node;
extern vnet_dev_node_t vnp_tx_node;
vnet_dev_rv_t vnp_reset (vlib_main_t *, vnet_dev_t *);
vnet_dev_rv_t vnp_negotiate (vlib_main_t *, vnet_dev_t *);

/* port.c */
vnet_dev_rv_t vnp_port_init (vlib_main_t *, vnet_dev_port_t *);
void vnp_port_deinit (vlib_main_t *, vnet_dev_port_t *);
vnet_dev_rv_t vnp_port_start (vlib_main_t *, vnet_dev_port_t *);
void vnp_port_stop (vlib_main_t *, vnet_dev_port_t *);
vnet_dev_rv_t vnp_port_cfg_validate (vlib_main_t *, vnet_dev_port_t *,
				     vnet_dev_port_cfg_change_req_t *);
vnet_dev_rv_t vnp_port_cfg_change (vlib_main_t *, vnet_dev_port_t *,
				   vnet_dev_port_cfg_change_req_t *);

/* queue.c */
vnet_dev_rv_t vnp_queue_enable (vlib_main_t *, vnet_dev_t *, u16, u16, void *, void *, void *,
				u16 **);
vnet_dev_rv_t vnp_rxq_alloc (vlib_main_t *, vnet_dev_rx_queue_t *);
vnet_dev_rv_t vnp_txq_alloc (vlib_main_t *, vnet_dev_tx_queue_t *);
void vnp_rxq_free (vlib_main_t *, vnet_dev_rx_queue_t *);
void vnp_txq_free (vlib_main_t *, vnet_dev_tx_queue_t *);
vnet_dev_rv_t vnp_rxq_start (vlib_main_t *, vnet_dev_t *, vnp_rxq_t *, u16, u16);
vnet_dev_rv_t vnp_txq_start (vlib_main_t *, vnet_dev_t *, vnp_txq_t *, u16);
void vnp_rxq_release (vlib_main_t *, vnp_rxq_t *, u16);
void vnp_txq_release (vlib_main_t *, vnp_txq_t *, u16);
