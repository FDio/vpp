/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Damjan Marion
 */

#include <vnet/dev/bus/pci.h>
#include <vnet/ethernet/ethernet.h>
#include <ice.h>

VLIB_REGISTER_LOG_CLASS (ice_log, static) = {
  .class_name = "ice",
  .subclass_name = "init",
};

#define _(f, n, s, d) { .name = #n, .desc = d, .severity = VL_COUNTER_SEVERITY_##s },
static vlib_error_desc_t ice_rx_counters[] = { foreach_ice_rx_node_counter };
static vlib_error_desc_t ice_tx_counters[] = { foreach_ice_tx_node_counter };
#undef _

vnet_dev_node_t ice_rx_node = {
  .format_trace = format_ice_rx_trace,
  .error_counters = ice_rx_counters,
  .n_error_counters = ARRAY_LEN (ice_rx_counters),
};

vnet_dev_node_t ice_tx_node = {
  .format_trace = format_ice_tx_trace,
  .error_counters = ice_tx_counters,
  .n_error_counters = ARRAY_LEN (ice_tx_counters),
};

static const struct
{
  u16 id;
  ice_device_family_t family;
  const char *name;
} ice_devices[] = {
  { 0x1591, ICE_DEVICE_FAMILY_E810, "Intel E810-C backplane" },
  { 0x1592, ICE_DEVICE_FAMILY_E810, "Intel E810-C QSFP" },
  { 0x1593, ICE_DEVICE_FAMILY_E810, "Intel E810-C SFP" },
  { 0x1599, ICE_DEVICE_FAMILY_E810, "Intel E810-XXV backplane" },
  { 0x159a, ICE_DEVICE_FAMILY_E810, "Intel E810-XXV QSFP" },
  { 0x159b, ICE_DEVICE_FAMILY_E810, "Intel E810-XXV SFP" },
  { 0x1248, ICE_DEVICE_FAMILY_E835, "Intel E835CC backplane" },
  { 0x1249, ICE_DEVICE_FAMILY_E835, "Intel E835CC QSFP56" },
  { 0x124a, ICE_DEVICE_FAMILY_E835, "Intel E835CC SFP" },
  { 0x1261, ICE_DEVICE_FAMILY_E835, "Intel E835C backplane" },
  { 0x1262, ICE_DEVICE_FAMILY_E835, "Intel E835C QSFP" },
  { 0x1263, ICE_DEVICE_FAMILY_E835, "Intel E835C SFP" },
  { 0x1265, ICE_DEVICE_FAMILY_E835, "Intel E835-L backplane" },
  { 0x1266, ICE_DEVICE_FAMILY_E835, "Intel E835-L QSFP" },
  { 0x1267, ICE_DEVICE_FAMILY_E835, "Intel E835-L SFP" },
  { 0x12d1, ICE_DEVICE_FAMILY_E830, "Intel E830-CC backplane" },
  { 0x12d2, ICE_DEVICE_FAMILY_E830, "Intel E830-CC QSFP56" },
  { 0x12d3, ICE_DEVICE_FAMILY_E830, "Intel E830-CC SFP" },
  { 0x12d5, ICE_DEVICE_FAMILY_E830, "Intel E830-C backplane" },
  { 0x12d8, ICE_DEVICE_FAMILY_E830, "Intel E830-C QSFP" },
  { 0x12da, ICE_DEVICE_FAMILY_E830, "Intel E830-C SFP" },
  { 0x12dc, ICE_DEVICE_FAMILY_E830, "Intel E830-L backplane" },
  { 0x12dd, ICE_DEVICE_FAMILY_E830, "Intel E830-L QSFP" },
  { 0x12de, ICE_DEVICE_FAMILY_E830, "Intel E830-L SFP" },
};

static u8 *
ice_probe (vlib_main_t *vm __clib_unused, vnet_dev_probe_args_t *a)
{
  vnet_dev_bus_pci_device_info_t *di = a->device_info;

  if (di->vendor_id != 0x8086)
    return 0;
  FOREACH_ARRAY_ELT (d, ice_devices)
    if (d->id == di->device_id)
      return format (0, "%s", d->name);
  return 0;
}

static vnet_dev_rv_t
ice_init (vlib_main_t *vm, vnet_dev_t *dev)
{
  ice_dev_t *id = vnet_dev_get_data (dev);
  ice_port_t port_data = {};
  vlib_pci_config_hdr_t hdr;
  vnet_dev_rv_t rv;
  u32 max_frame_size = 0;
  u16 rxq_count;
  u16 txq_count;
  u8 default_mac[6] = {};

  if ((rv = vnet_dev_pci_read_config_header (vm, dev, &hdr)))
    return rv;
  if (hdr.vendor_id != 0x8086)
    return VNET_DEV_ERR_UNSUPPORTED_DEVICE;

  rv = VNET_DEV_ERR_UNSUPPORTED_DEVICE;
  FOREACH_ARRAY_ELT (d, ice_devices)
    if (d->id == hdr.device_id)
      {
	id->info.family = d->family;
	rv = VNET_DEV_OK;
	break;
      }
  if (rv != VNET_DEV_OK)
    return rv;

  log_debug (dev, "PCI device 8086:%04x family %U", hdr.device_id, format_ice_family,
	     id->info.family);

  if ((rv = vnet_dev_pci_map_region (vm, dev, 0, &id->bar0)))
    return rv;
  log_debug (dev, "mapped BAR0 at %p", id->bar0);
  if ((rv = vnet_dev_pci_bus_master_enable (vm, dev)))
    return rv;
  log_debug (dev, "PCI bus mastering enabled");
  if ((rv = ice_hw_init (vm, dev, &port_data, &rxq_count, &txq_count, default_mac)))
    return rv;

  for (u32 i = 0; i < vec_len (id->info.dev_caps); i++)
    if (id->info.dev_caps[i].cap == ICE_AQC_CAPS_MAX_MTU)
      {
	max_frame_size = id->info.dev_caps[i].number;
	break;
      }
  if (max_frame_size == 0)
    {
      log_err (dev, "maximum frame size capability not found");
      ice_hw_deinit (vm, dev, &port_data);
      vec_free (port_data.vsi.sw_rules);
      return VNET_DEV_ERR_DEVICE_NO_REPLY;
    }

  vnet_dev_port_add_args_t args = {
    .port = {
      .attr = {
        .type = VNET_DEV_PORT_TYPE_ETHERNET,
	.max_rx_queues = clib_min (rxq_count, ICE_RSS_MAX_QUEUES),
	.max_tx_queues = txq_count,
	.max_supported_rx_frame_size = max_frame_size,
	.caps = {
	  .rss = 1,
	  .interrupt_mode = 1,
	},
	.rx_offloads = {
	  .ip4_cksum = 1,
	},
	.tx_offloads = {
	  .ip4_cksum = 1,
	},
      },
      .ops = {
        .init = ice_port_init,
        .start = ice_port_start,
        .stop = ice_port_stop,
        .format_status = format_ice_port_status,
        .config_change = ice_port_cfg_change,
        .config_change_validate = ice_port_cfg_change_validate,
      },
      .data_size = sizeof (ice_port_t),
      .initial_data = &port_data,
      .default_rss_config = {
	.key = {
	  0x94, 0xff, 0xfe, 0x8c, 0x39, 0xdf, 0x01, 0xb6, 0x9e, 0x88,
	  0x5f, 0xf2, 0x9c, 0x78, 0x71, 0xe0, 0xfc, 0x1b, 0x94, 0xd1,
	  0xb9, 0x41, 0x06, 0x96, 0x4e, 0x5b, 0x23, 0xdf, 0x26, 0x23,
	  0x0f, 0xcd, 0x32, 0x49, 0x0c, 0xa3, 0xd9, 0xa7, 0x70, 0x97,
	},
	.key_len = ICE_RSS_KEY_SIZE,
	.set_key = 1,
      },
    },
    .rx_node = &ice_rx_node,
    .tx_node = &ice_tx_node,
    .rx_queue = {
      .config = {
        .data_size = sizeof (ice_rxq_t),
        .default_size = 512,
        .size_is_power_of_two = 1,
        .min_size = 64,
        .max_size = 2048,
      },
      .ops = {
	.alloc = ice_rx_queue_alloc,
	.free = ice_rx_queue_free,
	.format_info = format_ice_rx_queue_info,
      },
    },
    .tx_queue = {
      .config = {
        .data_size = sizeof (ice_txq_t),
        .default_size = 512,
        .size_is_power_of_two = 1,
        .min_size = 64,
        .max_size = 2048,
      },
      .ops = {
	.alloc = ice_tx_queue_alloc,
	.free = ice_tx_queue_free,
	.format_info = format_ice_tx_queue_info,
      },
    },
  };

  clib_memcpy (args.port.attr.hw_addr.eth_mac, default_mac, 6);

  if (vlib_get_n_threads () <= vnet_dev_get_pci_n_msix_interrupts (dev) - 1)
    port_data.n_rx_vectors = vlib_get_n_threads ();
  else
    {
      log_notice (dev,
		  "number of threads (%u) exceeds number of available interrupt vectors (%u), "
		  "RX interrupt-mode capability disabled",
		  vlib_get_n_threads (), vnet_dev_get_pci_n_msix_interrupts (dev));
      args.port.attr.caps.interrupt_mode = 0;
      port_data.n_rx_vectors = 1;
    }

  log_debug (dev, "adding Ethernet port 0 with max frame %u and up to %u RX and %u TX queues",
	     max_frame_size, rxq_count, txq_count);
  return vnet_dev_port_add (vm, dev, 0, &args);
}

static void
ice_deinit (vlib_main_t *vm, vnet_dev_t *dev)
{
  ice_dev_t *id = vnet_dev_get_data (dev);
  vnet_dev_port_t *port = vnet_dev_get_port_by_id (dev, 0);
  ice_port_t *ip = port ? vnet_dev_get_port_data (port) : 0;

  log_debug (dev, "deinitializing device");
  if (id->bar0)
    ice_hw_deinit (vm, dev, ip);
  vec_free (id->info.dev_caps);
  vec_free (id->info.pkg_info);
  if (ip)
    vec_free (ip->vsi.sw_rules);
}

VNET_DEV_REGISTER_DRIVER (ice) = {
  .name = "ice",
  .description = "Intel E810, E830 and E835 Ethernet controllers",
  .bus = "pci",
  .device = {
    .data_sz = sizeof (ice_dev_t),
    .ops = {
      .alloc = ice_aq_alloc,
      .init = ice_init,
      .deinit = ice_deinit,
      .free = ice_aq_free,
      .probe = ice_probe,
      .format_info = format_ice_dev_info,
    },
  },
};
