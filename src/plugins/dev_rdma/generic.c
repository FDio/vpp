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
#include <vpp/app/version.h>
#include <dev_rdma/bus.h>

VLIB_REGISTER_LOG_CLASS (rdma_generic_log, static) = {
  .class_name = "rdma",
  .subclass_name = "gneneric",
};

#define log_debug(id, f, ...)                                                 \
  vlib_log (VLIB_LOG_LEVEL_DEBUG, rdma_generic_log.class, "%U: " f,           \
	    format_vnet_dev_addr, vnet_dev_from_data (id), ##__VA_ARGS__)
#define log_info(id, f, ...)                                                  \
  vlib_log (VLIB_LOG_LEVEL_INFO, rdma_generic_log.class, "%U: " f,            \
	    format_vnet_dev_addr, vnet_dev_from_data (id), ##__VA_ARGS__)
#define log_notice(id, f, ...)                                                \
  vlib_log (VLIB_LOG_LEVEL_NOTICE, rdma_generic_log.class, "%U: " f,          \
	    format_vnet_dev_addr, vnet_dev_from_data (id), ##__VA_ARGS__)
#define log_warn(id, f, ...)                                                  \
  vlib_log (VLIB_LOG_LEVEL_WARNING, rdma_generic_log.class, "%U: " f,         \
	    format_vnet_dev_addr, vnet_dev_from_data (id), ##__VA_ARGS__)
#define log_err(id, f, ...)                                                   \
  vlib_log (VLIB_LOG_LEVEL_ERR, rdma_generic_log.class, "%U: " f,             \
	    format_vnet_dev_addr, vnet_dev_from_data (id), ##__VA_ARGS__)

vnet_dev_node_fn_t rdma_generic_rx_node_fn = {};
vnet_dev_node_fn_t rdma_generic_tx_node_fn = {};

static vnet_dev_rv_t
rdma_generic_init (vlib_main_t *vm, vnet_dev_t *dev)
{
  return 0;
}

static void
rdma_generic_free (vlib_main_t *vm, vnet_dev_t *dev)
{
}

static u8 *
rdma_generic_probe (vlib_main_t *vm, vnet_dev_bus_index_t bus_index,
		    void *dev_info)
{
  vnet_dev_bus_rdma_device_info_t *di = dev_info;

  if (di->dev->node_type != IBV_NODE_CA)
    return 0;

  if (di->dev->transport_type != IBV_TRANSPORT_IB)
    return 0;

  return format (0, "%s", di->dev->dev_name);
}

VNET_DEV_REGISTER_DRIVER (rdma_generic) = {
  .name = "generic",
  .bus = "rdma",
  //.device_data_sz = sizeof (rdma_gdev_t),
  .ops = { .device_init = rdma_generic_init,
	   .device_free = rdma_generic_free,
	   .probe = rdma_generic_probe,
  },
};
