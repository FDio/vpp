/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#pragma once

#include <vppinfra/clib.h>
#include <vlib/vlib.h>
#include <vnet/dev/dev.h>
#include <infiniband/verbs.h>

#define log_debug(dev, f, ...)                                                                     \
  vlib_log (VLIB_LOG_LEVEL_DEBUG, mlx5_log.class, "%U: " f, format_vnet_dev_addr, (dev),           \
	    ##__VA_ARGS__)
#define log_err(dev, f, ...)                                                                       \
  vlib_log (VLIB_LOG_LEVEL_ERR, mlx5_log.class, "%U: " f, format_vnet_dev_addr, (dev),             \
	    ##__VA_ARGS__)

typedef struct
{
  struct ibv_context *ctx;
  struct ibv_pd *pd;
  u8 rss : 1;
  u32 rss_hash_function;
  u64 rss_hash_fields_mask;
  u32 max_qp;
  u32 max_cq;
  u32 max_qp_wr;
  u32 max_cqe;
  u32 max_sge;
} mlx5_dev_t;

u32 mlx5_port_speed (u8 speed);
u16 mlx5_port_mtu (u8 mtu);

/* port.c */
vnet_dev_rv_t mlx5_port_cfg_change_validate (vlib_main_t *vm, vnet_dev_port_t *port,
					     vnet_dev_port_cfg_change_req_t *req);
vnet_dev_rv_t mlx5_port_cfg_change (vlib_main_t *vm, vnet_dev_port_t *port,
				    vnet_dev_port_cfg_change_req_t *req);
vnet_dev_rv_t mlx5_port_apply_flows (vlib_main_t *vm, vnet_dev_port_t *port);
vnet_dev_rv_t mlx5_rxq_add_flow (vnet_dev_t *dev, struct ibv_qp *qp, struct ibv_flow ***flows,
				 u8 ibv_port, const u8 *mac, const u8 *mask, u16 ether_type,
				 u32 flags);
void mlx5_rxq_destroy_flows (vnet_dev_t *dev, struct ibv_flow ***flows);
