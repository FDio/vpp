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
  vlib_pci_config_hdr_t hdr;
  vnet_dev_rv_t rv;

  if ((rv = vnet_dev_pci_read_config_header (vm, dev, &hdr)))
    return rv;
  if (hdr.vendor_id != 0x8086)
    return VNET_DEV_ERR_UNSUPPORTED_DEVICE;

  rv = VNET_DEV_ERR_UNSUPPORTED_DEVICE;
  FOREACH_ARRAY_ELT (d, ice_devices)
    if (d->id == hdr.device_id)
      {
	id->family = d->family;
	rv = VNET_DEV_OK;
	break;
      }
  if (rv != VNET_DEV_OK)
    return rv;

  log_debug (dev, "PCI device 8086:%04x family %U", hdr.device_id, format_ice_family, id->family);

  if ((rv = vnet_dev_pci_map_region (vm, dev, 0, &id->bar0)))
    return rv;
  log_debug (dev, "mapped BAR0 at %p", id->bar0);
  if ((rv = vnet_dev_pci_bus_master_enable (vm, dev)))
    return rv;
  log_debug (dev, "PCI bus mastering enabled");
  if ((rv = ice_hw_init (vm, dev)))
    return rv;

  vnet_dev_port_add_args_t args = {
    .port = {
      .attr = {
        .type = VNET_DEV_PORT_TYPE_ETHERNET,
	.max_rx_queues = id->rxq_count,
	.max_tx_queues = id->txq_count,
	.max_supported_rx_frame_size = 1514,
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
      .ops = { .alloc = ice_rx_queue_alloc, .free = ice_rx_queue_free },
    },
    .tx_queue = {
      .config = {
        .data_size = sizeof (ice_txq_t),
        .default_size = 512,
        .size_is_power_of_two = 1,
        .min_size = 64,
        .max_size = 2048,
      },
      .ops = { .alloc = ice_tx_queue_alloc, .free = ice_tx_queue_free },
    },
  };

  clib_memcpy (args.port.attr.hw_addr.eth_mac, id->mac, 6);
  log_debug (dev, "adding Ethernet port 0 with up to %u RX and %u TX queues", id->rxq_count,
	     id->txq_count);
  return vnet_dev_port_add (vm, dev, 0, &args);
}

static void
ice_deinit (vlib_main_t *vm, vnet_dev_t *dev)
{
  ice_dev_t *id = vnet_dev_get_data (dev);
  log_debug (dev, "deinitializing device");
  if (id->bar0)
    ice_hw_deinit (vm, dev);
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
