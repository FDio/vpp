/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025-2026 Damjan Marion
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vnet/dev/counters.h>
#include <vnet/dev/bus/pci.h>
#include <ige.h>
#include <vnet/ethernet/ethernet.h>

VLIB_REGISTER_LOG_CLASS (ige_log, static) = {
  .class_name = "ige",
  .subclass_name = "init",
};

#define _(f, n, s, d)                                                         \
  { .name = #n, .desc = d, .severity = VL_COUNTER_SEVERITY_##s },

vlib_error_desc_t ige_tx_node_counters[] = { foreach_ige_tx_node_counter };
#undef _

vnet_dev_node_t ige_rx_node = {
  .format_trace = format_ige_rx_trace,
};

vnet_dev_node_t ige_tx_node = {
  .error_counters = ige_tx_node_counters,
  .n_error_counters = ARRAY_LEN (ige_tx_node_counters),
  .format_trace = format_ige_tx_trace,
};

static ige_dev_config_t config_by_type[] = {
  [IGE_DEV_TYPE_I211] = { .phy_type = IGE_PHY_TYPE_I210_INTERNAL },
  [IGE_DEV_TYPE_I225] = { .phy_type = IGE_PHY_TYPE_GPY211,
			  .supports_2_5g = 1 },
  [IGE_DEV_TYPE_I226] = { .phy_type = IGE_PHY_TYPE_GPY211,
			  .supports_2_5g = 1 },
};

static struct
{
  u16 device_id;
  ige_dev_type_t type;
  char *description;
} ige_dev_types[] = {

#define _(id, t, desc)                                                        \
  {                                                                           \
    .device_id = (id), .type = IGE_DEV_TYPE_##t, .description = (desc)        \
  }

  _ (0x1539, I211, "Intel(R) Ethernet Controller I211"),
  _ (0x15f2, I225, "Intel(R) Ethernet Controller I225-LM"),
  _ (0x15f3, I225, "Intel(R) Ethernet Controller I225-V"),
  _ (0x0d9f, I225, "Intel(R) Ethernet Controller I225-IT"),
  _ (0x125b, I226, "Intel(R) Ethernet Controller I226-LM"),
  _ (0x125c, I226, "Intel(R) Ethernet Controller I226-V"),
  _ (0x125d, I226, "Intel(R) Ethernet Controller I226-IT"),
#undef _
};

static u8 *
ige_probe (vlib_main_t *vm, vnet_dev_probe_args_t *a)
{
  vnet_dev_bus_pci_device_info_t *di = a->device_info;

  if (di->vendor_id != 0x8086)
    return 0;

  FOREACH_ARRAY_ELT (dt, ige_dev_types)
    {
      if (dt->device_id == di->device_id)
	return format (0, "%s", dt->description);
    }

  return 0;
}

static vnet_dev_rv_t
ige_init (vlib_main_t *vm, vnet_dev_t *dev)
{
  ige_device_t *id = vnet_dev_get_data (dev);
  vlib_pci_config_hdr_t pci_hdr;
  vnet_dev_rv_t rv;
  u32 match, mask, tmp;

  rv = vnet_dev_pci_read_config_header (vm, dev, &pci_hdr);
  if (rv != VNET_DEV_OK)
    return rv;

  if (pci_hdr.vendor_id != 0x8086)
    return VNET_DEV_ERR_UNSUPPORTED_DEVICE;

  rv = VNET_DEV_ERR_UNSUPPORTED_DEVICE;

  FOREACH_ARRAY_ELT (dt, ige_dev_types)
    if (dt->device_id == pci_hdr.device_id)
      {
	id->config = config_by_type[dt->type];
	rv = VNET_DEV_OK;
	break;
      }

  if (rv != VNET_DEV_OK)
    return rv;

  /* map BAR0 */
  if (id->bar0 == 0)
    {
      rv = vnet_dev_pci_map_region (vm, dev, 0, &id->bar0);
      if (rv != VNET_DEV_OK)
	return rv;
    }

  /* disable interrupts */
  ige_reg_wr (dev, IGE_REG_IMC, 0xffffffff);
  ige_reg_rd (dev, IGE_REG_ICR, &tmp);

  rv = vnet_dev_pci_function_level_reset (vm, dev);
  if (rv != VNET_DEV_OK)
    return rv;

  rv = vnet_dev_pci_bus_master_enable (vm, dev);
  if (rv != VNET_DEV_OK)
    return rv;

  mask = (ige_reg_status_t){ .rst_done = 1 }.as_u32;
  match = mask;

  if (ige_reg_poll (vm, dev, IGE_REG_STATUS, mask, match, 1e-5, 1e-1) == 0)
    {
      log_err (dev, "reset timeout");
      return VNET_DEV_ERR_TIMEOUT;
    }

  /* disable interrupts again */
  ige_reg_wr (dev, IGE_REG_IMC, 0xffffffff);
  ige_reg_rd (dev, IGE_REG_ICR, &tmp);

  /* notify ME that driver is loaded */
  ige_reg_ctrl_ext_t ctrl_ext;
  ige_reg_rd (dev, IGE_REG_CTRL_EXT, &ctrl_ext.as_u32);
  ctrl_ext.driver_loaded = 1;
  ige_reg_wr (dev, IGE_REG_CTRL_EXT, ctrl_ext.as_u32);

  rv = ige_phy_init (vm, dev);

  if (rv != VNET_DEV_OK)
    {
      log_err (dev, "failed to read PHY ID");
      return rv;
    }

  vnet_dev_port_add_args_t port = {
    .port = {
      .attr = {
        .type = VNET_DEV_PORT_TYPE_ETHERNET,
        .max_rx_queues = 4,
        .max_tx_queues = 4,
        .max_supported_rx_frame_size = 9728,
      },
      .ops = {
        .init = ige_port_init,
        .start = ige_port_start,
        .stop = ige_port_stop,
        .format_status = format_ige_port_status,
        .config_change = ige_port_cfg_change,
        .config_change_validate = ige_port_cfg_change_validate,
      },
      .data_size = sizeof (ige_port_t),
    },
    .rx_node = &ige_rx_node,
    .tx_node = &ige_tx_node,
    .rx_queue = {
      .config = {
        .data_size = sizeof (ige_rxq_t),
        .default_size = 512,
        .size_is_power_of_two = 1,
        .min_size = 512,
        .max_size = 32768,
      },
      .ops = {
        .alloc = ige_rx_queue_alloc,
        .free = ige_rx_queue_free,
      },
    },
    .tx_queue = {
      .config = {
        .data_size = sizeof (ige_txq_t),
        .default_size = 512,
        .size_is_power_of_two = 1,
        .min_size = 512,
        .max_size = 32768,
      },
      .ops = {
        .alloc = ige_tx_queue_alloc,
        .free = ige_tx_queue_free,
      },
    },
  };

  ige_reg_rd (dev, IGE_REG_RAL0, &tmp);
  clib_memcpy (&port.port.attr.hw_addr.eth_mac[0], &tmp, 4);
  ige_reg_rd (dev, IGE_REG_RAH0, &tmp);
  clib_memcpy (&port.port.attr.hw_addr.eth_mac[4], &tmp, 2);
  log_info (dev, "MAC address is %U", format_ethernet_address,
	    port.port.attr.hw_addr.eth_mac);

  id->avail_rxq_bmp = pow2_mask (4);
  id->avail_txq_bmp = pow2_mask (4);
  return vnet_dev_port_add (vm, dev, 0, &port);
}

VNET_DEV_REGISTER_DRIVER (ige) = {
  .name = "ige",
  .description = "Intel Gigabit Ethernet controllers (i210, i225, i226)",
  .bus = "pci",
  .device = {
    .data_sz = sizeof (ige_device_t),
    .ops = {
      .init = ige_init,
      .probe = ige_probe,
    },
  },
};
