/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vnet/dev/pci.h>
#include <vnet/dev/counters.h>
#include <vppinfra/ring.h>
#include <dev_avf/avf.h>
#include <dev_avf/virtchnl.h>
#include <dev_avf/virtchnl_funcs.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>

VLIB_REGISTER_LOG_CLASS (avf_log, static) = {
  .class_name = "dev_avf",
  .subclass_name = "init",
};

static const u32 driver_cap_flags =
  /**/ VIRTCHNL_VF_CAP_ADV_LINK_SPEED |
  /**/ VIRTCHNL_VF_LARGE_NUM_QPAIRS |
  /**/ VIRTCHNL_VF_OFFLOAD_ADV_RSS_PF |
  /**/ VIRTCHNL_VF_OFFLOAD_FDIR_PF |
  /**/ VIRTCHNL_VF_OFFLOAD_L2 |
  /**/ VIRTCHNL_VF_OFFLOAD_REQ_QUEUES |
  /**/ VIRTCHNL_VF_OFFLOAD_RSS_PF |
  /**/ VIRTCHNL_VF_OFFLOAD_RX_POLLING |
  /**/ VIRTCHNL_VF_OFFLOAD_VLAN |
  /**/ VIRTCHNL_VF_OFFLOAD_VLAN_V2 |
  /**/ VIRTCHNL_VF_OFFLOAD_WB_ON_ITR |
  /**/ 0;

static const virtchnl_version_info_t driver_virtchnl_version = {
  .major = VIRTCHNL_VERSION_MAJOR,
  .minor = VIRTCHNL_VERSION_MINOR,
};

#define _(f, n, s, d)                                                         \
  { .name = #n, .desc = d, .severity = VL_COUNTER_SEVERITY_##s },

vlib_error_desc_t avf_rx_node_counters[] = { foreach_avf_rx_node_counter };
vlib_error_desc_t avf_tx_node_counters[] = { foreach_avf_tx_node_counter };
#undef _

vnet_dev_node_t avf_rx_node = {
  .error_counters = avf_rx_node_counters,
  .n_error_counters = ARRAY_LEN (avf_rx_node_counters),
  .format_trace = format_avf_rx_trace,
};

vnet_dev_node_t avf_tx_node = {
  .error_counters = avf_tx_node_counters,
  .n_error_counters = ARRAY_LEN (avf_tx_node_counters),
};

static struct
{
  u16 device_id;
  char *desc;
} avf_dev_types[] = {
  { 0x1889, "Intel(R) Adaptive Virtual Function" },
  { 0x154c, "Intel(R) X710 Virtual Function" },
  { 0x37cd, "Intel(R) X722 Virtual Function" },
};

static u8 *
avf_probe (vlib_main_t *vm, vnet_dev_bus_index_t bus_index, void *dev_info)
{
  vnet_dev_bus_pci_device_info_t *di = dev_info;

  if (di->vendor_id != 0x8086)
    return 0;

  FOREACH_ARRAY_ELT (dt, avf_dev_types)
    {
      if (dt->device_id == di->device_id)
	return format (0, "%s", dt->desc);
    }

  return 0;
}

static vnet_dev_rv_t
avf_reset (vlib_main_t *vm, vnet_dev_t *dev)
{
  avf_device_t *ad = vnet_dev_get_data (dev);
  u32 n_tries = 50;

  avf_aq_init (vm, dev);
  avf_vc_op_reset_vf (vm, dev);

  do
    {
      if (n_tries-- == 0)
	return VNET_DEV_ERR_TIMEOUT;
      vlib_process_suspend (vm, 0.02);
    }
  while ((avf_reg_read (ad, VFGEN_RSTAT) & 3) != 2);

  avf_aq_init (vm, dev);
  avf_aq_poll_on (vm, dev);
  return (VNET_DEV_OK);
}

static vnet_dev_rv_t
avf_alloc (vlib_main_t *vm, vnet_dev_t *dev)
{
  return avf_aq_alloc (vm, dev);
}

static vnet_dev_rv_t
avf_init (vlib_main_t *vm, vnet_dev_t *dev)
{
  avf_device_t *ad = vnet_dev_get_data (dev);
  virtchnl_version_info_t ver;
  virtchnl_vf_resource_t res;
  vnet_dev_rv_t rv;

  log_debug (dev, "init");

  if ((rv = vnet_dev_pci_map_region (vm, dev, 0, &ad->bar0)))
    return rv;

  if ((rv = vnet_dev_pci_bus_master_enable (vm, dev)))
    return rv;

  if ((rv = avf_reset (vm, dev)))
    return rv;

  if ((rv = avf_vc_op_version (vm, dev, &driver_virtchnl_version, &ver)))
    return rv;

  if (ver.major != driver_virtchnl_version.major ||
      ver.minor != driver_virtchnl_version.minor)
    return VNET_DEV_ERR_UNSUPPORTED_DEVICE_VER;

  if ((rv = avf_vc_op_get_vf_resources (vm, dev, &driver_cap_flags, &res)))
    return rv;

  if (res.num_vsis != 1 || res.vsi_res[0].vsi_type != VIRTCHNL_VSI_SRIOV)
    return VNET_DEV_ERR_UNSUPPORTED_DEVICE;

  avf_port_t avf_port = {
    .vf_cap_flags = res.vf_cap_flags,
    .rss_key_size = res.rss_key_size,
    .rss_lut_size = res.rss_lut_size,
    .max_vectors = res.max_vectors,
    .vsi_id = res.vsi_res[0].vsi_id,
    .num_qp = res.vsi_res[0].num_queue_pairs,
  };

  vnet_dev_port_add_args_t port_add_args = {
    .port = {
      .attr = {
        .type = VNET_DEV_PORT_TYPE_ETHERNET,
        .max_rx_queues = res.num_queue_pairs,
        .max_tx_queues = res.num_queue_pairs,
        .max_supported_frame_size = res.max_mtu,
      },
      .ops = {
        .init = avf_port_init,
        .start = avf_port_start,
        .stop = avf_port_stop,
	.config_change = avf_port_cfg_change,
        .format_status = format_avf_port_status,
      },
      .data_size = sizeof (avf_port_t),
      .initial_data = &avf_port,
    },
    .rx_node = &avf_rx_node,
    .tx_node = &avf_tx_node,
    .rx_queue = {
      .config = {
        .data_size = sizeof (avf_rxq_t),
        .default_size = 512,
        .multiplier = 32,
        .min_size = 32,
        .max_size = 4096,
	.size_is_power_of_two = 1,
      },
      .ops = {
        .alloc = avf_rx_queue_alloc,
        .free = avf_rx_queue_free,
      },
    },
    .tx_queue = {
      .config = {
        .data_size = sizeof (avf_txq_t),
        .default_size = 512,
        .multiplier = 32,
        .min_size = 32,
        .max_size = 4096,
	.size_is_power_of_two = 1,
      },
      .ops = {
        .alloc = avf_tx_queue_alloc,
        .free = avf_tx_queue_free,
      },
    },
  };

  vnet_dev_set_hw_addr_eth_mac (&port_add_args.port.attr.hw_addr,
				res.vsi_res[0].default_mac_addr);

  log_info (dev, "MAC address is %U", format_ethernet_address,
	    res.vsi_res[0].default_mac_addr);

  if (vlib_get_n_threads () <= vnet_dev_get_pci_n_msix_interrupts (dev) - 1)
    port_add_args.port.attr.caps.interrupt_mode = 1;
  else
    log_notice (dev,
		"number of threads (%u) bigger than number of interrupt lines "
		"(%u), interrupt mode disabled",
		vlib_get_n_threads (), res.max_vectors);

  if (res.vf_cap_flags & VIRTCHNL_VF_OFFLOAD_RSS_PF)
    {
      if (res.rss_key_size < AVF_MAX_RSS_KEY_SIZE)
	{
	  log_notice (
	    dev, "unsupported RSS config provided by device, RSS disabled");
	}
      else
	{
	  port_add_args.port.attr.caps.rss = 1;
	  if (res.rss_lut_size > AVF_MAX_RSS_LUT_SIZE)
	    log_notice (dev, "device supports bigger RSS LUT than driver");
	}
    }

  return vnet_dev_port_add (vm, dev, 0, &port_add_args);
}

static void
avf_deinit (vlib_main_t *vm, vnet_dev_t *dev)
{
  log_debug (dev, "deinit");
  avf_aq_poll_off (vm, dev);
  avf_aq_deinit (vm, dev);
  avf_aq_free (vm, dev);
}

static void
avf_free (vlib_main_t *vm, vnet_dev_t *dev)
{
  log_debug (dev, "free");
  avf_aq_free (vm, dev);
}

VNET_DEV_REGISTER_DRIVER (avf) = {
  .name = "avf",
  .bus = "pci",
  .device_data_sz = sizeof (avf_device_t),
  .runtime_temp_space_sz = sizeof (avf_rt_data_t),
  .ops = {
    .alloc = avf_alloc,
    .init = avf_init,
    .deinit = avf_deinit,
    .free = avf_free,
    .probe = avf_probe,
  },
};

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "dev_avf",
};
