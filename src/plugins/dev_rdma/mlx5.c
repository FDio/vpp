/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#include "vppinfra/error.h"
#include "vppinfra/format.h"
#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vnet/dev/pci.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/plugin/plugin.h>
#include <vppinfra/linux/sysfs.h>
#include <vpp/app/version.h>
#include <dev_rdma/bus.h>

#include <infiniband/verbs.h>
#include <rdma/rdma_mlx5dv.h>

VLIB_REGISTER_LOG_CLASS (rdma_mlx5_log, static) = {
  .class_name = "rdma",
  .subclass_name = "mlx5",
};

#define log_debug(id, f, ...)                                                 \
  vlib_log (VLIB_LOG_LEVEL_DEBUG, rdma_mlx5_log.class, "%U: " f,              \
	    format_vnet_dev_addr, vnet_dev_from_data (id), ##__VA_ARGS__)
#define log_info(id, f, ...)                                                  \
  vlib_log (VLIB_LOG_LEVEL_INFO, rdma_mlx5_log.class, "%U: " f,               \
	    format_vnet_dev_addr, vnet_dev_from_data (id), ##__VA_ARGS__)
#define log_notice(id, f, ...)                                                \
  vlib_log (VLIB_LOG_LEVEL_NOTICE, rdma_mlx5_log.class, "%U: " f,             \
	    format_vnet_dev_addr, vnet_dev_from_data (id), ##__VA_ARGS__)
#define log_warn(id, f, ...)                                                  \
  vlib_log (VLIB_LOG_LEVEL_WARNING, rdma_mlx5_log.class, "%U: " f,            \
	    format_vnet_dev_addr, vnet_dev_from_data (id), ##__VA_ARGS__)
#define log_err(id, f, ...)                                                   \
  vlib_log (VLIB_LOG_LEVEL_ERR, rdma_mlx5_log.class, "%U: " f,                \
	    format_vnet_dev_addr, vnet_dev_from_data (id), ##__VA_ARGS__)

vnet_dev_node_fn_t rdma_mlx5_rx_node_fn = {};
vnet_dev_node_fn_t rdma_mlx5_tx_node_fn = {};

vnet_dev_rv_t
ibv_err_return (vnet_dev_t *dev, char *fmt, ...)
{
  va_list va;
  u8 *str;

  va_start (va, fmt);
  str = va_format (0, fmt, &va);
  va_end (va);

  log_err (dev, "%v [errno %d]", str, errno);
  vec_free (str);
  return VNET_DEV_ERR_BUS;
}

static vnet_dev_rv_t
rdma_mlx5_init (vlib_main_t *vm, vnet_dev_t *dev)
{
  struct ibv_device_attr_ex attr;
  vnet_dev_bus_rdma_device_data_t *rdd = vnet_dev_get_bus_data (dev);
  struct mlx5dv_context mctx;

  if (ibv_query_device_ex (rdd->ctx, 0, &attr) < 0)
    return ibv_err_return (dev, "ibv_query_device_ex failed");

  __builtin_dump_struct (&attr, &printf);

  if (mlx5dv_query_device (rdd->ctx, &mctx) < 0)
    return ibv_err_return (dev, "mlx5dv_query_device failed");

  __builtin_dump_struct (&mctx, &printf);

  for (u32 p = 1; p <= attr.phys_port_cnt_ex; p++)
    {
      struct ibv_port_attr pattr;
      struct mlx5dv_port mpinfo;

      if (ibv_query_port (rdd->ctx, p, &pattr) < 0)
	return ibv_err_return (dev, "ibv_query_port failed");

      if (pattr.link_layer != IBV_LINK_LAYER_ETHERNET)
	{
	  log_debug (dev, "skipping port as link layer is not ethernet");
	  continue;
	}

      __builtin_dump_struct (&pattr, &printf);

      if (mlx5dv_query_port (rdd->ctx, p, &mpinfo) < 0)
	return ibv_err_return (dev, "mlx5dv_query_port failed");

      __builtin_dump_struct (&mpinfo, &printf);
    }

  return 0;
}

static void
rdma_mlx5_free (vlib_main_t *vm, vnet_dev_t *dev)
{
}

static u8 *
rdma_mlx5_probe (vlib_main_t *vm, vnet_dev_bus_index_t bus_index,
		 void *dev_info)
{
  vnet_dev_bus_rdma_device_info_t *di = dev_info;

  if (di->dev->node_type != IBV_NODE_CA)
    return 0;

  if (di->dev->transport_type != IBV_TRANSPORT_IB)
    return 0;

  if (mlx5dv_is_supported (di->dev) == 0)
    return 0;

  return format (0, "%U", format_vnet_dev_rdma_desc, di->dev);
}

VNET_DEV_REGISTER_DRIVER (rdma_mlx5) = {
  .name = "mlx5",
  .bus = "rdma",
  .priority = 100,
  //.device_data_sz = sizeof (rdma_gdev_t),
  .ops = { .device_init = rdma_mlx5_init,
	   .device_free = rdma_mlx5_free,
	   .probe = rdma_mlx5_probe,
  },
};
