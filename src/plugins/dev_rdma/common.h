/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#ifndef _DEV_RDMA_COMMON_H_
#define _DEV_RDMA_COMMON_H_

#include <vppinfra/clib.h>
#include <vlib/vlib.h>
#include <vnet/dev/dev.h>
#include <infiniband/verbs.h>

typedef enum
{
  RDMA_DEV_T_IBVERBS,
  RDMA_DEV_T_MLX5_DV,
} rdma_dev_type_t;

typedef struct
{
  struct ibv_context *ctx;
  struct ibv_pd *pd;
  rdma_dev_type_t type;
  u8 rss : 1;
  u32 max_qp;
  u32 max_cq;
  u32 max_qp_wr;
  u32 max_cqe;
} rdma_dev_t;

u32 rdma_port_speed (u8 speed);
u16 rdma_port_mtu (u8 mtu);

#endif /* _DEV_RDMA_COMMON_H_ */
