/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco Systems, Inc.
 */

#pragma once

#include <vppinfra/clib.h>
#include <vppinfra/error.h>
#include <infiniband/verbs.h>
#include <vnet/dev/dev.h>
#include <common/common.h>
#include <mlx5dv.h>

#ifndef MLX5_ETH_L2_INLINE_HEADER_SIZE
#define MLX5_ETH_L2_INLINE_HEADER_SIZE 18
#endif

typedef struct
{
  CLIB_ALIGN_MARK (align0, MLX5_SEND_WQE_BB);
  union
  {
    struct mlx5_wqe_ctrl_seg ctrl;
    struct
    {
      u8 opc_mod;
      u8 wqe_index_hi;
      u8 wqe_index_lo;
      u8 opcode;
    };
  };
  struct mlx5_wqe_eth_seg eseg;
  struct mlx5_wqe_data_seg dseg;
} mlx5_wqe_t;
#define RDMA_MLX5_WQE_SZ sizeof (mlx5_wqe_t)
#define RDMA_MLX5_WQE_DS (RDMA_MLX5_WQE_SZ / sizeof (struct mlx5_wqe_data_seg))
STATIC_ASSERT (RDMA_MLX5_WQE_SZ == MLX5_SEND_WQE_BB &&
		 RDMA_MLX5_WQE_SZ % sizeof (struct mlx5_wqe_data_seg) == 0,
	       "bad size");

#define RDMA_RXQ_MAX_CHAIN_LOG_SZ	  3 /* This should NOT be lower than 3! */
#define RDMA_RXQ_MAX_CHAIN_SZ		  (1U << RDMA_RXQ_MAX_CHAIN_LOG_SZ)
#define RDMA_RXQ_LEGACY_MODE_MAX_CHAIN_SZ 5

#define foreach_mlx5_rx_node_counter                                                               \
  _ (IP4_CKSUM_BAD, ip4_cksum_bad, ERROR, "rx packets with bad ip4 checksum indication")

typedef enum
{
#define _(f, n, s, d) RDMA_MLX5_RX_NODE_CTR_##f,
  foreach_mlx5_rx_node_counter
#undef _
} mlx5_rx_node_counter_t;

#define foreach_mlx5_tx_node_counter                                                               \
  _ (BUFFER_PREPARE_FAIL, buffer_prepare_fail, ERROR, "tx buffer prepare failed")

typedef enum
{
#define _(f, n, s, d) RDMA_MLX5_TX_NODE_CTR_##f,
  foreach_mlx5_tx_node_counter
#undef _
} mlx5_tx_node_counter_t;

typedef enum
{
  MLX5_RXQ_CTR_PACKETS,
  MLX5_RXQ_CTR_BYTES,
  MLX5_RXQ_CTR_DROPS_HW,
  MLX5_RXQ_CTR_IP4_CKSUM_BAD,
} mlx5_rxq_counter_id_t;

typedef enum
{
  MLX5_TXQ_CTR_PACKETS,
  MLX5_TXQ_CTR_BYTES,
  MLX5_TXQ_CTR_DROPS,
  MLX5_TXQ_CTR_DROPS_HW,
  MLX5_TXQ_CTR_BUFFER_PREPARE_FAIL,
} mlx5_txq_counter_id_t;

extern vnet_dev_node_t mlx5_rx_node_base;
extern vnet_dev_node_t mlx5_rx_node_mini_cqe;
extern vnet_dev_node_t mlx5_rx_node_striding;
extern vnet_dev_node_t mlx5_tx_node_empw;
extern vnet_dev_node_t mlx5_tx_node_mpw;

typedef struct
{
  u8 striding_rq : 1;
  u8 cqe_res_format_hash : 1;
  u8 tx_empw : 1;
  u8 tx_mpw : 1;
  u8 counters_query_failed : 1;
  u8 rss_enabled : 1;
  struct ibv_rwq_ind_table *rwq_ind_tbl;
  struct ibv_qp *rss_qp;
  rdma_rx_flow_t **flows;
  rdma_rx_mac_flow_t *ucast_flows;
  u32 promisc_flow_index;
  u32 mcast_flow_index;
} mlx5_port_t;

typedef struct
{
  u16 qid;
  u16 next_index;
  u32 hw_if_index;
  u32 length;
} mlx5_rx_trace_t;

typedef struct
{
  u16 qid;
  u8 n_sge;
  u8 cs_flags;
  u8 dropped;
  u32 hw_if_index;
  u32 buffer_index;
  u32 data_len;
} mlx5_tx_trace_t;

typedef struct
{
  struct ibv_cq *ibv_cq;
  struct ibv_qp *ibv_qp;
  rdma_rx_flow_t **flows;
  rdma_rx_mac_flow_t *ucast_flows;
  u32 promisc_flow_index;
  u32 mcast_flow_index;
  mlx5dv_wqe_ds_t *dv_sq_wqes;
  u32 *dv_sq_dbrec;
  struct mlx5_cqe64 *dv_cq_cqes;
  u32 *dv_cq_dbrec;
  u32 *buffers;
  u32 *second_bufs;
  u8 *n_used_per_chain;
  u16 head;
  u16 tail;
  u16 dv_cq_idx;
  u16 dv_cq_size;
  u8 dv_cq_log2;
  u16 n_mini_cqes;
  u16 n_mini_cqes_left;
  u32 wqe_cnt;
  u32 buf_sz;
  u16 n_total_additional_segs;
  u16 striding_wqe_tail;
  u8 n_ds_per_wqe;
  u8 log_wqe_sz;
  u8 log_stride_per_wqe;
  struct ibv_wq *ibv_wq;
  struct ibv_rwq_ind_table *rwq_ind_tbl;
  u8 q_counter_set_id;
  u8 q_counter_valid : 1;
  u8 q_counter_query_failed : 1;
  u8 use_rss : 1;
  rdma_rxq_irq_t irq;
} mlx5_rxq_t;

typedef struct
{
  struct ibv_cq *ibv_cq;
  struct ibv_qp *ibv_qp;
  mlx5_wqe_t *dv_sq_wqes;
  u32 *dv_sq_dbrec;
  u64 *dv_sq_db;
  struct mlx5_cqe64 *dv_cq_cqes;
  u32 *dv_cq_dbrec;
  u32 *buffers;
  u16 head;
  u16 tail;
  u16 dv_cq_idx;
  u16 dv_cq_size;
  u8 dv_cq_log2;
  u8 dv_wqe_tmpl[64];
  u8 q_counter_set_id;
  u8 q_counter_valid : 1;
  u8 q_counter_query_failed : 1;
} mlx5_txq_t;

vnet_dev_rv_t mlx5_add_port (vlib_main_t *vm, vnet_dev_t *dev, vnet_dev_port_id_t port_id);
vnet_dev_rv_t mlx5_port_start (vlib_main_t *vm, vnet_dev_port_t *port);
void mlx5_port_stop (vlib_main_t *vm, vnet_dev_port_t *port);
vnet_dev_rv_t mlx5_port_init (vlib_main_t *vm, vnet_dev_port_t *port);
vnet_dev_rv_t mlx5_port_init_counters (vlib_main_t *vm, vnet_dev_port_t *port);
vnet_dev_port_op_no_rv_t mlx5_port_counter_poll;
vnet_dev_rv_t mlx5_rxq_alloc (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq);
void mlx5_rxq_free (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq);
vnet_dev_rv_t mlx5_rxq_irq_enable (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq);
void mlx5_rxq_irq_disable (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq);
vnet_dev_rv_t mlx5_txq_alloc (vlib_main_t *vm, vnet_dev_tx_queue_t *txq);
void mlx5_txq_free (vlib_main_t *vm, vnet_dev_tx_queue_t *txq);
format_function_t format_mlx5_rx_trace;
format_function_t format_mlx5_tx_trace;
format_function_t format_mlx5_cqe64;
format_function_t format_mlx5_port_status;
format_function_t format_mlx5_rxq_info;
