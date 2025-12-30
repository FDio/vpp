/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco Systems, Inc.
 */

#pragma once

#include <vppinfra/clib.h>
#include <vlib/vlib.h>
#include <vnet/dev/dev.h>
#include <common/common.h>
#include <infiniband/verbs.h>

#define log_debug(dev, f, ...)                                                                     \
  vlib_log (VLIB_LOG_LEVEL_DEBUG, ibv_log.class, "%U: " f, format_vnet_dev_addr, (dev),            \
	    ##__VA_ARGS__)
#define log_warn(dev, f, ...)                                                                      \
  vlib_log (VLIB_LOG_LEVEL_WARNING, ibv_log.class, "%U: " f, format_vnet_dev_addr, (dev),          \
	    ##__VA_ARGS__)
#define log_err(dev, f, ...)                                                                       \
  vlib_log (VLIB_LOG_LEVEL_ERR, ibv_log.class, "%U: " f, format_vnet_dev_addr, (dev), ##__VA_ARGS__)

#define foreach_ibv_device_cap_flags                                                               \
  _ (RESIZE_MAX_WR, "resize-max-wr")                                                               \
  _ (BAD_PKEY_CNTR, "bad-pkey-cntr")                                                               \
  _ (BAD_QKEY_CNTR, "bad-qkey-cntr")                                                               \
  _ (RAW_MULTI, "raw-multi")                                                                       \
  _ (AUTO_PATH_MIG, "auto-path-mig")                                                               \
  _ (CHANGE_PHY_PORT, "change-phy-port")                                                           \
  _ (UD_AV_PORT_ENFORCE, "ud-av-port-enforce")                                                     \
  _ (CURR_QP_STATE_MOD, "curr-qp-state-mod")                                                       \
  _ (SHUTDOWN_PORT, "shutdown-port")                                                               \
  _ (INIT_TYPE, "init-type")                                                                       \
  _ (PORT_ACTIVE_EVENT, "port-active-event")                                                       \
  _ (SYS_IMAGE_GUID, "sys-image-guid")                                                             \
  _ (RC_RNR_NAK_GEN, "rc-rnr-nak-gen")                                                             \
  _ (SRQ_RESIZE, "srq-resize")                                                                     \
  _ (N_NOTIFY_CQ, "n-notify-cq")                                                                   \
  _ (MEM_WINDOW, "mem-window")                                                                     \
  _ (UD_IP_CSUM, "ud-ip-csum")                                                                     \
  _ (XRC, "xrc")                                                                                   \
  _ (MEM_MGT_EXTENSIONS, "mem-mgt-extensions")                                                     \
  _ (MEM_WINDOW_TYPE_2A, "mem-window-type-2a")                                                     \
  _ (MEM_WINDOW_TYPE_2B, "mem-window-type-2b")                                                     \
  _ (RC_IP_CSUM, "rc-ip-csum")                                                                     \
  _ (RAW_IP_CSUM, "raw-ip-csum")                                                                   \
  _ (MANAGED_FLOW_STEERING, "managed-flow-steering")                                               \
  _ (RAW_SCATTER_FCS, "raw-scatter-fcs")                                                           \
  _ (PCI_WRITE_END_PADDING, "pci-write-end-padding")

#define foreach_ibv_rss_caps                                                                       \
  _ (SRC_IPV4, "src-ipv4")                                                                         \
  _ (DST_IPV4, "dst-ipv4")                                                                         \
  _ (SRC_IPV6, "src-ipv6")                                                                         \
  _ (DST_IPV6, "dst-ipv6")                                                                         \
  _ (SRC_PORT_TCP, "src-port-tcp")                                                                 \
  _ (DST_PORT_TCP, "dst-port-tcp")                                                                 \
  _ (SRC_PORT_UDP, "src-port-udp")                                                                 \
  _ (DST_PORT_UDP, "dst-port-udp")                                                                 \
  _ (IPSEC_SPI, "ipsec-spi")                                                                       \
  _ (INNER, "inner")

#define foreach_ibv_tso_caps                                                                       \
  _ (RC, "rc")                                                                                     \
  _ (UC, "uc")                                                                                     \
  _ (UD, "ud")                                                                                     \
  _ (RAW_PACKET, "raw-packet")                                                                     \
  _ (XRC_SEND, "xrc-send")                                                                         \
  _ (XRC_RECV, "xrc-recv")

#define foreach_ibv_raw_packet_caps                                                                \
  _ (CVLAN_STRIPPING, "cvlan-stripping")                                                           \
  _ (SCATTER_FCS, "scatter-fcs")                                                                   \
  _ (IP_CSUM, "ip-csum")                                                                           \
  _ (DELAY_DROP, "delay-drop")

#define IBV_RX_REFILL_LOG2_BATCH_SZ 5
#define IBV_RX_REFILL_BATCH_SZ	    (1u << IBV_RX_REFILL_LOG2_BATCH_SZ)
#define IBV_RXQ_MAX_CHAIN_SZ	    5
#define IBV_TXQ_MAX_CHAIN_SZ	    5

#define foreach_ibv_rx_node_counter                                                                \
  _ (IBV_POST_RECV, ibv_post_recv, ERROR, "ibv post recv failed")                                  \
  _ (IBV_POLL_CQ, ibv_poll_cq, ERROR, "ibv poll cq failed")                                        \
  _ (WC_STATUS, wc_status, ERROR, "rx completion with bad status")

typedef enum
{
#define _(f, n, s, d) RDMA_RX_NODE_CTR_##f,
  foreach_ibv_rx_node_counter
#undef _
} ibv_rx_node_counter_t;

#define foreach_ibv_tx_node_counter                                                                \
  _ (IBV_POLL_CQ, ibv_poll_cq, ERROR, "ibv poll cq failed")                                        \
  _ (IBV_POST_SEND, ibv_post_send, ERROR, "ibv post send failed")                                  \
  _ (CHAIN_TOO_LONG, chain_too_long, ERROR, "tx buffer chain too long")                            \
  _ (WC_STATUS, wc_status, ERROR, "tx completion with bad status")

typedef enum
{
#define _(f, n, s, d) RDMA_TX_NODE_CTR_##f,
  foreach_ibv_tx_node_counter
#undef _
} ibv_tx_node_counter_t;

extern vnet_dev_node_t ibv_rx_node;
extern vnet_dev_node_t ibv_tx_node;

typedef struct
{
  struct ibv_context *ctx;
  struct ibv_pd *pd;
  struct ibv_mr *mr;
  u32 async_clib_file_index;
  u8 async_event_file_added : 1;
  u8 rss : 1;
  u32 lkey;
  u32 rss_max_ind_tbl_size;
  u64 rss_hash_fields_mask;
  u32 rss_hash_function;
  u32 max_sge;
} ibv_dev_t;

typedef struct
{
  struct ibv_rwq_ind_table *rwq_ind_tbl;
  struct ibv_qp *rss_qp;
  rdma_rx_flow_t **flows;
  rdma_rx_mac_flow_t *ucast_flows;
  u32 promisc_flow_index;
  u32 mcast_flow_index;
  u8 rss_enabled : 1;
} ibv_port_t;

typedef struct
{
  struct ibv_recv_wr recv_wr;
  struct ibv_sge sge[IBV_RXQ_MAX_CHAIN_SZ];
} ibv_rx_refill_entry_t;

typedef struct
{
  u16 qid;
  u16 next_index;
  u32 hw_if_index;
  struct ibv_wc wc;
} ibv_rx_trace_t;

typedef struct
{
  u16 qid;
  u16 n_sge;
  u16 send_flags;
  u8 dropped;
  u32 hw_if_index;
  u32 buffer_index;
  u32 data_len;
} ibv_tx_trace_t;

typedef struct
{
  struct ibv_cq *ibv_cq;
  struct ibv_qp *ibv_qp;
  struct ibv_wq *ibv_wq;
  rdma_rx_flow_t **flows;
  rdma_rx_mac_flow_t *ucast_flows;
  u32 promisc_flow_index;
  u32 mcast_flow_index;
  u8 use_rss : 1;
  u32 *buffers;
  u32 *second_bufs;
  u8 *n_tail_refills;
  u32 buf_sz;
  u8 n_ds_per_wqe;
  u8 n_ds_per_wqe_max;
  u8 max_tails;
  u8 n_left_to_post;
  ibv_rx_refill_entry_t *refill_entries;
  rdma_rxq_irq_t irq;
  u32 head;
  u32 tail;
} ibv_rxq_t;

typedef struct
{
  struct ibv_cq *ibv_cq;
  struct ibv_qp *ibv_qp;
  struct ibv_send_wr *wr_template;
  struct ibv_sge *sge_template;
  u32 *buffers;
  u32 head;
  u32 tail;
} ibv_txq_t;

/* port.c */
vnet_dev_rv_t ibv_port_start (vlib_main_t *vm, vnet_dev_port_t *port);
void ibv_port_stop (vlib_main_t *vm, vnet_dev_port_t *port);
vnet_dev_rv_t ibv_port_cfg_change_validate (vlib_main_t *vm, vnet_dev_port_t *port,
					    vnet_dev_port_cfg_change_req_t *req);
vnet_dev_rv_t ibv_port_cfg_change (vlib_main_t *vm, vnet_dev_port_t *port,
				   vnet_dev_port_cfg_change_req_t *req);
vnet_dev_rv_t ibv_port_apply_flows (vlib_main_t *vm, vnet_dev_port_t *port);

/* queue.c */
vnet_dev_rv_t ibv_rxq_alloc (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq);
void ibv_rxq_free (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq);
vnet_dev_rv_t ibv_rxq_irq_enable (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq);
void ibv_rxq_irq_disable (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq);
vnet_dev_rv_t ibv_txq_alloc (vlib_main_t *vm, vnet_dev_tx_queue_t *txq);
void ibv_txq_free (vlib_main_t *vm, vnet_dev_tx_queue_t *txq);

/* format.c */
format_function_t format_ibv_port_status;
format_function_t format_ibv_rxq_info;
format_function_t format_ibv_txq_info;
format_function_t format_ibv_rx_trace;
format_function_t format_ibv_tx_trace;
format_function_t format_ibv_dev_info;
