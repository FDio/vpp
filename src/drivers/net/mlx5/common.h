/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Damjan Marion
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
#define log_notice(dev, f, ...)                                                                    \
  vlib_log (VLIB_LOG_LEVEL_NOTICE, mlx5_log.class, "%U: " f, format_vnet_dev_addr, (dev),          \
	    ##__VA_ARGS__)

typedef struct
{
  struct ibv_context *ctx;
  struct ibv_pd *pd;
  struct ibv_mr *mr;
  u32 lkey;
  u8 rss : 1;
  u8 tx_cksum_offload : 1;
  u8 tx_tso : 1;
  u32 rss_hash_function;
  u64 rss_hash_fields_mask;
  u32 rss_max_ind_tbl_size;
  u32 max_qp;
  u32 max_cq;
  u32 max_qp_wr;
  u32 max_cqe;
  u32 max_sge;
} mlx5_dev_t;

/* port.c */
vnet_dev_rv_t mlx5_port_cfg_change_validate (vlib_main_t *vm, vnet_dev_port_t *port,
					     vnet_dev_port_cfg_change_req_t *req);
vnet_dev_rv_t mlx5_port_cfg_change (vlib_main_t *vm, vnet_dev_port_t *port,
				    vnet_dev_port_cfg_change_req_t *req);
vnet_dev_rv_t mlx5_port_apply_flows (vlib_main_t *vm, vnet_dev_port_t *port);
