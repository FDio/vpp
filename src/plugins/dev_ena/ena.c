/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#include "vppinfra/error.h"
#include "vppinfra/format.h"
#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vnet/dev/pci.h>
#include <dev_ena/ena.h>
#include <dev_ena/ena_inlines.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>

static ena_admin_host_info_t host_info = {
  .os_type = 3, /* DPDK */
  .kernel_ver_str = VPP_BUILD_VER,
  .os_dist_str = VPP_BUILD_VER,
  .driver_version = {
    .major = 16,
    .minor = 0,
    .sub_minor = 0,
  },
  .ena_spec_version = {
    .major = 2,
    .minor = 0,
  },
  .driver_supported_features = {
    .rx_offset = 1,
    .rss_configurable_function_key = 1,
  }
};

VLIB_REGISTER_LOG_CLASS (ena_log, static) = {
  .class_name = "dev_ena",
  .subclass_name = "init",
};

vnet_dev_node_fn_t ena_rx_node_fn = {};
vnet_dev_node_fn_t ena_tx_node_fn = {};

static vnet_dev_rv_t
ena_port_init (vlib_main_t *vm, vnet_dev_port_t *port)
{
  ena_log_debug (port->dev, "port init: port %u", port->port_id);

  return 0;
}

static vnet_dev_rv_t
ena_port_start (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  vnet_dev_rv_t rv = VNET_DEV_OK;

  ena_log_debug (dev, "port start: port %u", port->port_id);

  return rv;
}

static void
ena_port_stop (vlib_main_t *vm, vnet_dev_port_t *port)
{
  ena_log_debug (port->dev, "port stop: port %u", port->port_id);
}


static void
ena_free (vlib_main_t *vm, vnet_dev_t *dev)
{
  ena_device_t *ed = vnet_dev_get_data (dev);
  ena_reg_aenq_stop (vm, dev);
  ena_reg_aq_stop (vm, dev);

  ena_reg_aenq_free (vm, dev);
  ena_reg_aq_free (vm, dev);

  vnet_dev_dma_mem_free (vm, dev, ed->host_info);
  vnet_dev_dma_mem_free (vm, dev, ed->mmio_resp);
}

static vnet_dev_rv_t
ena_init (vlib_main_t *vm, vnet_dev_t *dev)
{
  ena_device_t *ed = vnet_dev_get_data (dev);
  ena_admin_feat_host_attr_config_t host_attr = {};
  ena_admin_feat_max_queue_ext_t max_q_ext;
  u8 revision_id;
  vnet_dev_rv_t rv = VNET_DEV_OK;

  vnet_dev_port_add_args_t port = {
    .type = VNET_DEV_PORT_TYPE_ETHERNET,
    .port = {
      .data_size = sizeof (ena_port_t),
    },
    .rx_queue = {
      .data_size = sizeof (ena_rxq_t),
      .default_size = 512,
      .min_size = 32,
      .size_is_power_of_two = 1,
    },
    .tx_queue = {
      .data_size = sizeof (ena_txq_t),
      .default_size = 512,
      .min_size = 32,
      .size_is_power_of_two = 1,
    },
    .ops = {
      .rx_node_fn = &ena_rx_node_fn,
      .tx_node_fn = &ena_tx_node_fn,
      .init = ena_port_init,
      .start = ena_port_start,
      .stop = ena_port_stop,
      .format_status = format_ena_port_status,
      .rx_queue_alloc = ena_rx_queue_alloc,
      .rx_queue_free = ena_rx_queue_free,
      .tx_queue_alloc = ena_tx_queue_alloc,
      .tx_queue_free = ena_tx_queue_free,
    },
  };

  if ((rv = vnet_dev_dma_mem_alloc (vm, dev, 4096, 4096,
				    (void **) &ed->host_info)) != VNET_DEV_OK)
    goto err;

  if ((rv = ena_reg_aq_olloc (vm, dev, ENA_ADMIN_QUEUE_DEPTH)) != VNET_DEV_OK)
    goto err;

  if ((rv = ena_reg_aenq_olloc (vm, dev, ENA_ASYNC_QUEUE_DEPTH)) !=
      VNET_DEV_OK)
    goto err;

  if ((rv = vnet_dev_pci_get_revision (vm, dev, &revision_id)))
    goto err;

  ena_log_debug (dev, "revision_id 0x%x", revision_id);

  if ((revision_id & 1) == 0)
    ed->readless = 1;

  if (ed->readless)
    {
      if (ed->mmio_resp == 0)
	rv = vnet_dev_dma_mem_alloc (vm, dev, sizeof (ena_mmio_resp_t), 0,
				     (void **) &ed->mmio_resp);

      if (rv != VNET_DEV_OK)
	goto err;
    }

  if ((rv = vnet_dev_pci_map_region (vm, dev, 0, &ed->reg_bar)) != VNET_DEV_OK)
    goto err;

  if ((rv = ena_reg_reset (vm, dev, ENA_RESET_REASON_NORMAL)) != VNET_DEV_OK)
    goto err;

  if ((rv = ena_reg_aq_start (vm, dev)) != VNET_DEV_OK)
    goto err;

  *ed->host_info = host_info;
  ed->host_info->num_cpus = vlib_get_n_threads ();
  ena_set_mem_addr (vm, dev, &host_attr.os_info_ba, ed->host_info);

  if ((rv = ena_admin_set_feature (vm, dev, ENA_ADMIN_FEAT_ID_HOST_ATTR_CONFIG,
				   &host_attr)))
    return rv;

  if ((rv = ena_admin_get_feature (
	 vm, dev, ENA_ADMIN_FEAT_ID_DEVICE_ATTRIBUTES, &ed->dev_attr)))
    return rv;

  if (!ena_admin_feature_is_supported (ed, ENA_ADMIN_FEAT_ID_MAX_QUEUES_EXT))
    {
      ena_log_err (dev, "device doesn't support MAX_QUEUES_EXT");
      return VNET_DEV_ERR_UNSUPPORTED_DEV_VER;
    }

  if ((rv = ena_admin_get_feature (vm, dev, ENA_ADMIN_FEAT_ID_MAX_QUEUES_EXT,
				   &max_q_ext)))
    goto err;

  port.port.max_frame_size = ed->dev_attr.max_mtu;
  port.port.max_rx_queues =
    clib_min (max_q_ext.max_rx_cq_num, max_q_ext.max_rx_sq_num);
  port.port.max_tx_queues =
    clib_min (max_q_ext.max_tx_cq_num, max_q_ext.max_tx_sq_num);
  port.rx_queue.max_size =
    clib_min (max_q_ext.max_rx_cq_depth, max_q_ext.max_rx_sq_depth);
  port.tx_queue.max_size =
    clib_min (max_q_ext.max_tx_cq_depth, max_q_ext.max_tx_sq_depth);

  clib_memcpy (port.port.hw_addr, ed->dev_attr.mac_addr,
	       sizeof (ed->dev_attr.mac_addr));

  return vnet_dev_port_add (vm, dev, 0, &port);

err:
  ena_free (vm, dev);
  return rv;
}

static struct
{
  u16 device_id;
  char *description;
} ena_dev_types[] = {
  { .device_id = 0x0ec2, .description = "Elastic Network Adapter (ENA) PF" },
  { .device_id = 0xec20, .description = "Elastic Network Adapter (ENA) VF" },
};

static u8 *
ena_probe (vlib_main_t *vm, vnet_dev_bus_index_t bus_index, void *dev_info)
{
  vnet_dev_bus_pci_device_info_t *di = dev_info;

  if (di->vendor_id != 0x1d0f) /* AMAZON */
    return 0;

  FOREACH_ARRAY_ELT (dt, ena_dev_types)
    {
      if (dt->device_id == di->device_id)
	return format (0, "%s", dt->description);
    }

  return 0;
}

VNET_DEV_REGISTER_DRIVER (ena) = {
  .name = "ena",
  .bus = "pci",
  .device_data_sz = sizeof (ena_device_t),
  .ops = { .device_init = ena_init,
	   .device_free = ena_free,
	   .probe = ena_probe,
  },
};

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "dev_ena",
};
