/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vnet/dev/pci.h>
#include <vnet/dev/counters.h>
#include <dev_avf/avf.h>
#include <dev_avf/virtchnl.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>

VLIB_REGISTER_LOG_CLASS (avf_log, static) = {
  .class_name = "dev_avf",
  .subclass_name = "init",
};

#define log_debug(dev, f, ...)                                                \
  vlib_log (VLIB_LOG_LEVEL_DEBUG, avf_log.class, "%U: " f,                    \
	    format_vnet_dev_addr, (dev), ##__VA_ARGS__)
#define log_info(dev, f, ...)                                                 \
  vlib_log (VLIB_LOG_LEVEL_INFO, avf_log.class, "%U: " f,                     \
	    format_vnet_dev_addr, (dev), ##__VA_ARGS__)
#define log_notice(dev, f, ...)                                               \
  vlib_log (VLIB_LOG_LEVEL_NOTICE, avf_log.class, "%U: " f,                   \
	    format_vnet_dev_addr, (dev), ##__VA_ARGS__)
#define log_warn(dev, f, ...)                                                 \
  vlib_log (VLIB_LOG_LEVEL_WARNING, avf_log.class, "%U: " f,                  \
	    format_vnet_dev_addr, (dev), ##__VA_ARGS__)
#define log_err(dev, f, ...)                                                  \
  vlib_log (VLIB_LOG_LEVEL_ERR, avf_log.class, "%U: " f,                      \
	    format_vnet_dev_addr, (dev), ##__VA_ARGS__)

vnet_dev_node_fn_t avf_rx_node_fn = {};
vnet_dev_node_fn_t avf_tx_node_fn = {};

static struct
{
  u16 device_id;
  char *desc;
} avf_dev_types[] = {

#define _(id, d)                                                              \
  {                                                                           \
    .device_id = (id), .desc = (d)                                            \
  }

  _ (0x1889, "Intel(R) Adaptive Virtual Function"),
  _ (0x154c, "Intel(R) X710 Virtual Function"),
  _ (0x37cd, "Intel(R) X722 Virtual Function"),
#undef _
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
  return avf_aq_init (vm, dev);
}

static vnet_dev_rv_t
avf_init (vlib_main_t *vm, vnet_dev_t *dev)
{
  avf_device_t *ad = vnet_dev_get_data (dev);
  virtchnl_version_info_t ver;
  virtchnl_vf_resource_t res;
  vnet_dev_rv_t rv;

  log_debug (dev, "init");

  rv = vnet_dev_pci_map_region (vm, dev, 0, &ad->bar0);
  if (rv != VNET_DEV_OK)
    return rv;

  rv = avf_aq_alloc (vm, dev);
  if (rv != VNET_DEV_OK)
    return rv;

  rv = vnet_dev_pci_bus_master_enable (vm, dev);
  if (rv != VNET_DEV_OK)
    return rv;

  rv = avf_reset (vm, dev);
  if (rv != VNET_DEV_OK)
    return rv;

  rv = avf_vc_op_version (vm, dev, &ver);
  if (rv != VNET_DEV_OK)
    return rv;

  if (ver.major != VIRTCHNL_VERSION_MAJOR ||
      ver.minor != VIRTCHNL_VERSION_MINOR)
    return VNET_DEV_ERR_UNSUPPORTED_DEV_VER;

  avf_vc_op_get_vf_resources (vm, dev, &res);
  if (rv != VNET_DEV_OK)
    return rv;

  if (res.num_vsis != 1 || res.vsi_res[0].vsi_type != VIRTCHNL_VSI_SRIOV)
    return VNET_DEV_ERR_UNSUPPORTED_DEV;

  ad->vsi_id = res.vsi_res[0].vsi_id;
  ad->vf_cap_flags = res.vf_cap_flags;
  ad->rss_key_size = res.rss_key_size;
  ad->rss_lut_size = res.rss_lut_size;

  vnet_dev_port_add_args_t port = {
    .port = {
      .config = {
        .type = VNET_DEV_PORT_TYPE_ETHERNET,
        .data_size = sizeof (avf_port_t),
        .max_rx_queues = res.num_queue_pairs,
        .max_tx_queues = res.num_queue_pairs,
        .max_frame_size = res.max_mtu,
      },
      .ops = {
#if 0
        .init = avf_port_init,
        .start = avf_port_start,
        .stop = avf_port_stop,
        .format_status = format_avf_port_status,
#endif
      },
    },
    .rx_node = {
        .node_fn = &avf_rx_node_fn,
    },
    .tx_node = {
        .node_fn = &avf_tx_node_fn,
    },
    .rx_queue = {
      .config = {
        .data_size = sizeof (avf_rxq_t),
        .default_size = 512,
        .multiplier = 8,
        .min_size = 32,
        .max_size = 32768,
      },
      .ops = {
#if 0
        .alloc = avf_rx_queue_alloc,
        .free = avf_rx_queue_free,
#endif
      },
    },
    .tx_queue = {
      .config = {
        .data_size = sizeof (avf_txq_t),
        .default_size = 512,
        .multiplier = 8,
        .min_size = 32,
        .max_size = 32768,
      },
      .ops = {
#if 0
        .alloc = avf_tx_queue_alloc,
        .free = avf_tx_queue_free,
#endif
      },
    },
  };

#if 0
  id->avail_rxq_bmp = pow2_mask (4);
  id->avail_txq_bmp = pow2_mask (4);
#endif
  clib_memcpy (port.port.config.hw_addr, res.vsi_res[0].default_mac_addr,
	       sizeof (port.port.config.hw_addr));
  log_info (dev, "MAC address is %U", format_ethernet_address,
	    port.port.config.hw_addr);
  vnet_dev_port_add (vm, dev, 0, &port);

  return rv;
}

static void
avf_deinit (vlib_main_t *vm, vnet_dev_t *dev)
{
  log_debug (dev, "deinit");
  avf_aq_deinit (vm, dev);
  avf_aq_free (vm, dev);
}

VNET_DEV_REGISTER_DRIVER (avf) = {
  .name = "avf",
  .bus = "pci",
  .device_data_sz = sizeof (avf_device_t),
  .ops = {
    .device_init = avf_init,
    .device_deinit = avf_deinit,
    .device_reset = avf_reset,
    .probe = avf_probe,
  },
};

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "dev_avf",
};
