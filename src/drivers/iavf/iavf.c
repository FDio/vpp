/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023-2026 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vnet/dev/bus/pci.h>
#include <vnet/dev/counters.h>
#include <vppinfra/ring.h>
#include <iavf.h>
#include <virtchnl.h>
#include <virtchnl_funcs.h>
#include <vnet/ethernet/ethernet.h>

VLIB_REGISTER_LOG_CLASS (iavf_log, static) = {
  .class_name = "iavf",
  .subclass_name = "init",
};

#define IAVF_MAX_QPAIRS 32

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

vlib_error_desc_t iavf_rx_node_counters[] = { foreach_iavf_rx_node_counter };
vlib_error_desc_t iavf_tx_node_counters[] = { foreach_iavf_tx_node_counter };
#undef _

vnet_dev_node_t iavf_rx_node = {
  .error_counters = iavf_rx_node_counters,
  .n_error_counters = ARRAY_LEN (iavf_rx_node_counters),
  .format_trace = format_iavf_rx_trace,
};

vnet_dev_node_t iavf_tx_node = {
  .error_counters = iavf_tx_node_counters,
  .n_error_counters = ARRAY_LEN (iavf_tx_node_counters),
};

static struct
{
  u16 device_id;
  char *desc;
} iavf_dev_types[] = {
  { 0x1889, "Intel(R) Adaptive Virtual Function" },
  { 0x154c, "Intel(R) X710 Virtual Function" },
  { 0x37cd, "Intel(R) X722 Virtual Function" },
};

static u8 *
iavf_probe (vlib_main_t *vm, vnet_dev_probe_args_t *a)
{
  vnet_dev_bus_pci_device_info_t *di = a->device_info;

  if (di->vendor_id != 0x8086)
    return 0;

  FOREACH_ARRAY_ELT (dt, iavf_dev_types)
    {
      if (dt->device_id == di->device_id)
	return format (0, "%s", dt->desc);
    }

  return 0;
}

static vnet_dev_rv_t
iavf_reset (vlib_main_t *vm, vnet_dev_t *dev)
{
  iavf_device_t *ad = vnet_dev_get_data (dev);
  u32 n_tries = 50;

  iavf_aq_init (vm, dev);
  iavf_vc_op_reset_vf (vm, dev);

  do
    {
      if (n_tries-- == 0)
	return VNET_DEV_ERR_TIMEOUT;
      vlib_process_suspend (vm, 0.02);
    }
  while ((iavf_reg_read (ad, IAVF_VFGEN_RSTAT) & 3) != 2);

  iavf_aq_init (vm, dev);
  iavf_aq_poll_on (vm, dev);
  return (VNET_DEV_OK);
}

static vnet_dev_rv_t
iavf_alloc (vlib_main_t *vm, vnet_dev_t *dev)
{
  log_debug (dev, "alloc");
  return iavf_aq_alloc (vm, dev);
}

static vnet_dev_rv_t
iavf_init (vlib_main_t *vm, vnet_dev_t *dev)
{
  iavf_device_t *ad = vnet_dev_get_data (dev);
  virtchnl_version_info_t ver;
  virtchnl_vf_resource_t res;
  u32 n_threads = vlib_get_n_threads ();
  u16 max_frame_sz;
  vnet_dev_rv_t rv;

  log_debug (dev, "init");

  if ((rv = vnet_dev_pci_map_region (vm, dev, 0, &ad->bar0)))
    return rv;

  if ((rv = vnet_dev_pci_bus_master_enable (vm, dev)))
    return rv;

  if ((rv = iavf_reset (vm, dev)))
    return rv;

  if ((rv = iavf_vc_op_version (vm, dev, &driver_virtchnl_version, &ver)))
    return rv;

  if (ver.major != driver_virtchnl_version.major ||
      ver.minor != driver_virtchnl_version.minor)
    return VNET_DEV_ERR_UNSUPPORTED_DEVICE_VER;

  if ((rv = iavf_vc_op_get_vf_resources (vm, dev, &driver_cap_flags, &res)))
    return rv;

  if (res.num_vsis != 1 || res.vsi_res[0].vsi_type != VIRTCHNL_VSI_SRIOV)
    return VNET_DEV_ERR_UNSUPPORTED_DEVICE;

  if (res.max_mtu == 0)
    {
      log_warn (dev, "PF driver is reporting invalid value of 0 for max_mtu, "
		     "consider upgrade");
      max_frame_sz = ETHERNET_MAX_PACKET_BYTES;
    }
  else
    /* reverse of PF driver MTU calculation */
    max_frame_sz = res.max_mtu + 14 /* ethernet header */ + 4 /* FCS */ +
		   2 * 4 /* two VLAN tags */;

  iavf_port_t iavf_port = {
    .vf_cap_flags = res.vf_cap_flags,
    .rss_key_size = res.rss_key_size,
    .rss_lut_size = res.rss_lut_size,
    .max_vectors = res.max_vectors,
    .vsi_id = res.vsi_res[0].vsi_id,
    .num_qp = clib_min (IAVF_MAX_QPAIRS, res.vsi_res[0].num_queue_pairs),
  };

  vnet_dev_port_add_args_t port_add_args = {
    .port = {
      .attr = {
        .type = VNET_DEV_PORT_TYPE_ETHERNET,
        .max_rx_queues = clib_min (IAVF_MAX_QPAIRS, res.num_queue_pairs),
        .max_tx_queues = clib_min (IAVF_MAX_QPAIRS, res.num_queue_pairs),
        .max_supported_rx_frame_size = max_frame_sz,
        .caps = {
          .change_max_rx_frame_size = 1,
          .interrupt_mode = 1,
          .rss = 1,
          .mac_filter = 1,
        },
        .rx_offloads = {
          .ip4_cksum = 1,
        },
        .tx_offloads = {
          .ip4_cksum = 1,
          .tcp_gso = 1,
        },
      },
      .ops = {
        .init = iavf_port_init,
        .start = iavf_port_start,
        .stop = iavf_port_stop,
        .config_change = iavf_port_cfg_change,
        .config_change_validate = iavf_port_cfg_change_validate,
        .format_status = format_iavf_port_status,
      },
      .data_size = sizeof (iavf_port_t),
      .initial_data = &iavf_port,
    },
    .rx_node = &iavf_rx_node,
    .tx_node = &iavf_tx_node,
    .rx_queue = {
      .config = {
        .data_size = sizeof (iavf_rxq_t),
        .default_size = 512,
        .multiplier = 32,
        .min_size = 32,
        .max_size = 4096,
	.size_is_power_of_two = 1,
      },
      .ops = {
        .alloc = iavf_rx_queue_alloc,
        .free = iavf_rx_queue_free,
      },
    },
    .tx_queue = {
      .config = {
        .data_size = sizeof (iavf_txq_t),
        .default_size = 512,
        .multiplier = 32,
        .min_size = 32,
        .max_size = 4096,
	.size_is_power_of_two = 1,
      },
      .ops = {
        .alloc = iavf_tx_queue_alloc,
        .free = iavf_tx_queue_free,
      },
    },
  };

  vnet_dev_set_hw_addr_eth_mac (&port_add_args.port.attr.hw_addr,
				res.vsi_res[0].default_mac_addr);

  log_info (dev, "MAC address is %U", format_ethernet_address,
	    res.vsi_res[0].default_mac_addr);

  if (n_threads <= vnet_dev_get_pci_n_msix_interrupts (dev) - 1)
    {
      port_add_args.port.attr.caps.interrupt_mode = 1;
      iavf_port.n_rx_vectors = n_threads;
    }
  else
    {
      log_notice (
	dev,
	"number of threads (%u) bigger than number of interrupt lines "
	"(%u), interrupt mode disabled",
	vlib_get_n_threads (), res.max_vectors);
      iavf_port.n_rx_vectors = 1;
    }

  if (res.vf_cap_flags & VIRTCHNL_VF_OFFLOAD_RSS_PF)
    {
      if (res.rss_key_size < IAVF_MAX_RSS_KEY_SIZE)
	{
	  log_notice (
	    dev, "unsupported RSS config provided by device, RSS disabled");
	}
      else
	{
	  port_add_args.port.attr.caps.rss = 1;
	  if (res.rss_lut_size > IAVF_MAX_RSS_LUT_SIZE)
	    log_notice (dev, "device supports bigger RSS LUT than driver");
	}
    }

  return vnet_dev_port_add (vm, dev, 0, &port_add_args);
}

static void
iavf_deinit (vlib_main_t *vm, vnet_dev_t *dev)
{
  log_debug (dev, "deinit");
  iavf_aq_poll_off (vm, dev);
  iavf_aq_deinit (vm, dev);
  iavf_aq_free (vm, dev);
}

static void
iavf_free (vlib_main_t *vm, vnet_dev_t *dev)
{
  log_debug (dev, "free");
  iavf_aq_free (vm, dev);
}

VNET_DEV_REGISTER_DRIVER (avf) = {
  .name = "iavf",
  .description = "Intel Adaptive Virtual Function (X710, E810, E830 VFs)",
  .bus = "pci",
  .runtime_temp_space_sz = sizeof (iavf_rt_data_t),
  .device = {
    .data_sz = sizeof (iavf_device_t),
    .ops = {
      .alloc = iavf_alloc,
      .init = iavf_init,
      .deinit = iavf_deinit,
      .free = iavf_free,
      .probe = iavf_probe,
    },
  },
};
