/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vnet/dev/bus/pci.h>
#include <dev_ena/ena.h>
#include <dev_ena/ena_inlines.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>

static ena_aq_host_info_t host_info = {
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
  .class_name = "ena",
  .subclass_name = "init",
};

#define _(f, n, s, d)                                                         \
  { .name = #n, .desc = d, .severity = VL_COUNTER_SEVERITY_##s },

static vlib_error_desc_t ena_rx_node_counters[] = {
  foreach_ena_rx_node_counter
};
static vlib_error_desc_t ena_tx_node_counters[] = {
  foreach_ena_tx_node_counter
};
#undef _

vnet_dev_node_t ena_rx_node = {
  .error_counters = ena_rx_node_counters,
  .n_error_counters = ARRAY_LEN (ena_rx_node_counters),
  .format_trace = format_ena_rx_trace,
};

vnet_dev_node_t ena_tx_node = {
  .error_counters = ena_tx_node_counters,
  .n_error_counters = ARRAY_LEN (ena_tx_node_counters),
};

static void
ena_deinit (vlib_main_t *vm, vnet_dev_t *dev)
{
  ena_aenq_stop (vm, dev);
  ena_aq_stop (vm, dev);
}

static vnet_dev_rv_t
ena_alloc (vlib_main_t *vm, vnet_dev_t *dev)
{
  ena_device_t *ed = vnet_dev_get_data (dev);
  vnet_dev_rv_t rv;

  if ((rv = vnet_dev_dma_mem_alloc (vm, dev, 4096, 4096,
				    (void **) &ed->host_info)))
    return rv;

  if ((rv = vnet_dev_dma_mem_alloc (vm, dev, sizeof (ena_mmio_resp_t), 0,
				    (void **) &ed->mmio_resp)))
    return rv;

  if ((rv = ena_aq_olloc (vm, dev, ENA_ADMIN_QUEUE_DEPTH)))
    return rv;

  if ((rv = ena_aenq_olloc (vm, dev, ENA_ASYNC_QUEUE_DEPTH)))
    return rv;

  return VNET_DEV_OK;
}

static void
ena_free (vlib_main_t *vm, vnet_dev_t *dev)
{
  ena_device_t *ed = vnet_dev_get_data (dev);

  ena_aenq_free (vm, dev);
  ena_aq_free (vm, dev);

  vnet_dev_dma_mem_free (vm, dev, ed->host_info);
  vnet_dev_dma_mem_free (vm, dev, ed->mmio_resp);
}

static vnet_dev_rv_t
ena_init (vlib_main_t *vm, vnet_dev_t *dev)
{
  ena_device_t *ed = vnet_dev_get_data (dev);
  ena_aq_feat_host_attr_config_t host_attr = {};
  vlib_pci_config_hdr_t pci_cfg_hdr;
  vnet_dev_rv_t rv = VNET_DEV_OK;

  vnet_dev_port_add_args_t port = {
    .port = {
      .attr = {
        .type = VNET_DEV_PORT_TYPE_ETHERNET,
      },
      .ops = {
        .init = ena_port_init,
        .start = ena_port_start,
        .stop = ena_port_stop,
        .config_change = ena_port_cfg_change,
        .config_change_validate = ena_port_cfg_change_validate,
      },
      .data_size = sizeof (ena_port_t),
    },
    .rx_node = &ena_rx_node,
    .tx_node = &ena_tx_node,
    .rx_queue = {
      .config = {
        .data_size = sizeof (ena_rxq_t),
        .default_size = 512,
        .min_size = 32,
        .size_is_power_of_two = 1,
      },
      .ops = {
        .alloc = ena_rx_queue_alloc,
        .start = ena_rx_queue_start,
        .stop = ena_rx_queue_stop,
        .free = ena_rx_queue_free,
      },
    },
    .tx_queue = {
      .config = {
        .data_size = sizeof (ena_txq_t),
        .default_size = 512,
        .min_size = 32,
        .size_is_power_of_two = 1,
      },
      .ops = {
        .alloc = ena_tx_queue_alloc,
        .start = ena_tx_queue_start,
        .stop = ena_tx_queue_stop,
        .free = ena_tx_queue_free,
      },
    },
  };

  if ((rv = vnet_dev_pci_read_config_header (vm, dev, &pci_cfg_hdr)))
    goto err;

  log_debug (dev, "revision_id 0x%x", pci_cfg_hdr.revision_id);

  ed->readless = (pci_cfg_hdr.revision_id & 1) == 0;

  if ((rv = vnet_dev_pci_map_region (vm, dev, 0, &ed->reg_bar)))
    goto err;

  if ((rv = ena_reg_reset (vm, dev, ENA_RESET_REASON_NORMAL)))
    goto err;

  if ((rv = ena_aq_start (vm, dev)))
    goto err;

  *ed->host_info = host_info;
  ed->host_info->num_cpus = vlib_get_n_threads ();
  ena_set_mem_addr (vm, dev, &host_attr.os_info_ba, ed->host_info);

  if ((rv = ena_aq_set_feature (vm, dev, ENA_ADMIN_FEAT_ID_HOST_ATTR_CONFIG,
				&host_attr)))
    return rv;

  if ((rv = ena_aq_get_feature (vm, dev, ENA_ADMIN_FEAT_ID_DEVICE_ATTRIBUTES,
				&ed->dev_attr)))
    return rv;

  if (ena_aq_feature_is_supported (dev, ENA_ADMIN_FEAT_ID_MAX_QUEUES_EXT))
    {
      ena_aq_feat_max_queue_ext_t max_q_ext;
      if ((rv = ena_aq_get_feature (vm, dev, ENA_ADMIN_FEAT_ID_MAX_QUEUES_EXT,
				    &max_q_ext)))
	goto err;
      port.port.attr.max_rx_queues =
	clib_min (max_q_ext.max_rx_cq_num, max_q_ext.max_rx_sq_num);
      port.port.attr.max_tx_queues =
	clib_min (max_q_ext.max_tx_cq_num, max_q_ext.max_tx_sq_num);
      port.rx_queue.config.max_size =
	clib_min (max_q_ext.max_rx_cq_depth, max_q_ext.max_rx_sq_depth);
      port.tx_queue.config.max_size =
	clib_min (max_q_ext.max_tx_cq_depth, max_q_ext.max_tx_sq_depth);
    }
  else
    {
      log_err (dev, "device doesn't support MAX_QUEUES_EXT");
      return VNET_DEV_ERR_UNSUPPORTED_DEVICE_VER;
    }

  if ((rv = ena_aenq_start (vm, dev)))
    goto err;

  port.port.attr.max_supported_rx_frame_size = ed->dev_attr.max_mtu;

  if (ena_aq_feature_is_supported (dev, ENA_ADMIN_FEAT_ID_MTU))
    port.port.attr.caps.change_max_rx_frame_size = 1;

  vnet_dev_set_hw_addr_eth_mac (&port.port.attr.hw_addr,
				ed->dev_attr.mac_addr);

  return vnet_dev_port_add (vm, dev, 0, &port);

err:
  ena_free (vm, dev);
  return rv;
}

static u8 *
ena_probe (vlib_main_t *vm, vnet_dev_bus_index_t bus_index, void *dev_info)
{
  vnet_dev_bus_pci_device_info_t *di = dev_info;
  const struct
  {
    u16 device_id;
    char *description;
  } ena_dev_types[] = {
    { .device_id = 0x0ec2, .description = "Elastic Network Adapter (ENA) PF" },
    { .device_id = 0xec20, .description = "Elastic Network Adapter (ENA) VF" },
  };

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
  .ops = {
    .alloc = ena_alloc,
    .init = ena_init,
    .deinit = ena_deinit,
    .free = ena_free,
    .format_info = format_ena_dev_info,
    .probe = ena_probe,
  },
};

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "dev_ena",
};
