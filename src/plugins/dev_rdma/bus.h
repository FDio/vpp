/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#ifndef _VNET_DEV_RDMA_H_
#define _VNET_DEV_RDMA_H_

#include <vppinfra/clib.h>
#include <vlib/vlib.h>
#include <vnet/dev/dev.h>
#include <infiniband/verbs.h>

typedef struct
{
  struct ibv_device **dev_list;
  struct ibv_device *dev;
} vnet_dev_bus_rdma_device_info_t;

typedef struct
{
  struct ibv_device *dev;
  struct ibv_context *ctx;
  struct ibv_pd *pd;
  struct ibv_mr *mr;
} vnet_dev_bus_rdma_device_data_t;

format_function_t format_vnet_dev_rdma_desc;

#endif /* _VNET_DEV_RDMA_H_ */
