/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco Systems, Inc.
 */

#ifndef _DEV_RDMA_MLX5_H_
#define _DEV_RDMA_MLX5_H_

#include <rdma/rdma.h>
#include <vnet/dev/dev.h>

extern vnet_dev_node_t rdma_mlx5_rx_node;
extern vnet_dev_node_t rdma_mlx5_tx_node;

typedef struct
{
  u8 striding_rq : 1;
} rdma_mlx5_port_t;

typedef struct
{
  rdma_mlx5_wqe_t *dv_sq_wqes;
  volatile u32 *dv_sq_dbrec;
  volatile u64 *dv_sq_db;
  struct mlx5_cqe64 *dv_cq_cqes;
  volatile u32 *dv_cq_dbrec;
  u32 *buffers;
} rdma_mlx5_rxq_t;

typedef struct
{
  u32 *buffers;
} rdma_mlx5_txq_t;

vnet_dev_rv_t rdma_mlx5_add_port (vlib_main_t *vm, vnet_dev_t *dev,
				  vnet_dev_port_id_t port_id);

#endif /* _DEV_RDMA_MLX5_H_ */
