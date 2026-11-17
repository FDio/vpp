/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Damjan Marion
 */

#pragma once

#include <vppinfra/clib.h>
#include <vlib/vlib.h>
#include <vnet/dev/dev.h>
#include <rdma/common.h>
#include <infiniband/verbs.h>

#define log_debug(dev, f, ...)                                                                     \
  vlib_log (VLIB_LOG_LEVEL_DEBUG, ibv_log.class, "%U: " f, format_vnet_dev_addr, (dev),            \
	    ##__VA_ARGS__)
#define log_warn(dev, f, ...)                                                                      \
  vlib_log (VLIB_LOG_LEVEL_WARNING, ibv_log.class, "%U: " f, format_vnet_dev_addr, (dev),          \
	    ##__VA_ARGS__)
#define log_err(dev, f, ...)                                                                       \
  vlib_log (VLIB_LOG_LEVEL_ERR, ibv_log.class, "%U: " f, format_vnet_dev_addr, (dev), ##__VA_ARGS__)

#define IBV_RX_REFILL_LOG2_BATCH_SZ 5
#define IBV_RX_REFILL_BATCH_SZ	    (1u << IBV_RX_REFILL_LOG2_BATCH_SZ)
#define IBV_RXQ_MAX_CHAIN_SZ	    5
#define IBV_TXQ_MAX_SGE		    32
#define IBV_TSO_MAX_HDR_SZ	    192

#define foreach_ibv_rx_node_counter                                                                \
  _ (BUFFER_ALLOC, buffer_alloc, ERROR, "buffer allocation failed")                                \
  _ (IBV_POST_RECV, ibv_post_recv, ERROR, "ibv post recv failed")                                  \
  _ (IBV_POLL_CQ, ibv_poll_cq, ERROR, "ibv poll cq failed")                                        \
  _ (DESC_ERROR, desc_error, ERROR, "receive completion error, queue reset")

typedef enum
{
#define _(f, n, s, d) IBV_RX_NODE_CTR_##f,
  foreach_ibv_rx_node_counter
#undef _
} ibv_rx_node_counter_t;

#define foreach_ibv_tx_node_counter                                                                \
  _ (NO_FREE_SLOTS, no_free_slots, ERROR, "no free tx slots")                                      \
  _ (CHAIN_TOO_LONG, chain_too_long, ERROR, "buffer chain too long")                               \
  _ (IBV_POLL_CQ, ibv_poll_cq, ERROR, "ibv poll cq failed")                                        \
  _ (IBV_POST_SEND, ibv_post_send, ERROR, "ibv post send failed")                                  \
  _ (WC_STATUS, wc_status, ERROR, "tx completion error, queue reset")

typedef enum
{
#define _(f, n, s, d) IBV_TX_NODE_CTR_##f,
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
  u32 max_qp;
  u32 max_cq;
  u32 max_qp_wr;
  u32 max_cqe;
  u32 max_sge;
  u16 tx_max_sge;
  u8 tx_cksum_offload : 1;
  u8 rx_cksum_offload : 1;
  u8 tx_tso : 1;
} ibv_dev_t;

typedef struct
{
  rdma_rss_t rss;
  u32 netdev_ifindex;
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
  u32 buffer_flags;
  u32 slot;
  struct ibv_wc wc;
  u8 n_sge;
  struct ibv_sge sge[];
} ibv_rx_trace_t;

typedef struct
{
  u16 qid;
  u8 dropped;
  u8 n_sge;
  u32 hw_if_index;
  u32 buffer_index;
  u32 data_len;
  u64 wr_id;
  u32 opcode;
  u32 send_flags;
  u16 tso_hdr_sz;
  u16 tso_mss;
  struct ibv_sge sge[];
} ibv_tx_trace_t;

typedef struct
{
  struct ibv_cq *ibv_cq;
  struct ibv_wq *ibv_wq;
  u32 *buffers;
  u8 *n_used;
  ibv_rx_refill_entry_t *refill_entries;
  rdma_rxq_irq_t irq;
  u32 buf_sz;
  u8 n_ds;
  u8 rx_error;
  u8 rx_error_status;
  u8 single_buffer;
  u16 head;
  u16 tail;
} ibv_rxq_t;

typedef struct
{
  struct ibv_cq *ibv_cq;
  struct ibv_qp *ibv_qp;
  struct ibv_send_wr *wr_template;
  struct ibv_sge *sge_template;
  u16 max_sge;
  u32 *buffers;
  u32 head;
  u32 tail;
} ibv_txq_t;

/* port.c */
vnet_dev_rv_t ibv_port_start (vlib_main_t *vm, vnet_dev_port_t *port);
vnet_dev_rv_t ibv_port_get_module_eeprom (vlib_main_t *vm, vnet_dev_port_t *port, void *p);
void ibv_port_stop (vlib_main_t *vm, vnet_dev_port_t *port);
vnet_dev_rv_t ibv_port_cfg_change_validate (vlib_main_t *vm, vnet_dev_port_t *port,
					    vnet_dev_port_cfg_change_req_t *req);
vnet_dev_rv_t ibv_port_cfg_change (vlib_main_t *vm, vnet_dev_port_t *port,
				   vnet_dev_port_cfg_change_req_t *req);
vnet_dev_rv_t ibv_port_apply_flows (vlib_main_t *vm, vnet_dev_port_t *port);

/* queue.c */
vnet_dev_rv_t ibv_rxq_alloc (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq);
vnet_dev_rv_t ibv_rxq_wq_create (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq);
void ibv_rxq_wq_destroy (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq);
void ibv_rxq_free (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq);
vnet_dev_rv_t ibv_rxq_irq_enable (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq);
void ibv_rxq_irq_disable (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq);
vnet_dev_rv_t ibv_txq_alloc (vlib_main_t *vm, vnet_dev_tx_queue_t *txq);
void ibv_txq_free (vlib_main_t *vm, vnet_dev_tx_queue_t *txq);
void ibv_txq_recover (vlib_main_t *vm, vnet_dev_tx_queue_t *txq, int status);

/* format.c */
format_function_t format_ibv_port_status;
format_function_t format_ibv_rxq_info;
format_function_t format_ibv_rx_trace;
format_function_t format_ibv_tx_trace;
format_function_t format_ibv_dev_info;
