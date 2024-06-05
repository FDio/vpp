/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vnet/dev/pci.h>
#include <vnet/dev/counters.h>
#include <dev_ige/ige.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>

VLIB_REGISTER_LOG_CLASS (ige_log, static) = {
  .class_name = "ige",
  .subclass_name = "init",
};

vnet_dev_node_t ige_rx_node = {};
vnet_dev_node_t ige_tx_node = {};

typedef enum
{
  IGE_DEV_TYPE_I211,
  IGE_DEV_TYPE_I225,
  IGE_DEV_TYPE_I226,
} __clib_packed ige_dev_type_t;

static ige_dev_flags_t flags_by_type[] = {
  [IGE_DEV_TYPE_I211] = {},
  [IGE_DEV_TYPE_I225] = { .supports_2_5g = 1 },
  [IGE_DEV_TYPE_I226] = { .supports_2_5g = 1 },
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
ige_probe (vlib_main_t *vm, vnet_dev_bus_index_t bus_index, void *dev_info)
{
  vnet_dev_bus_pci_device_info_t *di = dev_info;

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
ige_err (ige_device_t *id, vnet_dev_rv_t rv, char *fmt, ...)
{
  va_list va;
  u8 *s;

  va_start (va, fmt);
  s = va_format (0, fmt, &va);
  va_end (va);
  log_err (id, "%v", s);
  vec_free (s);
  return rv;
}

static int
ige_reg_poll (vlib_main_t *vm, ige_device_t *id, u32 reg, u32 mask, u32 match,
	      f64 intial_delay, f64 timeout)
{
  f64 t0 = vlib_time_now (vm);
  u32 val;

  for (f64 delay = intial_delay, total_time = delay; total_time < timeout;
       delay *= 2, total_time += delay)
    {
      ige_reg_rd (id, reg, &val);
      if ((val & mask) == match)
	{
	  log_debug (id, "reg_poll: reg %05x (suspend %.6f)", reg,
		     vlib_time_now (vm) - t0);
	  return 1;
	}
      vlib_process_suspend (vm, delay);
    }
  log_debug (id, "reg_poll: reg %05x timeout", reg);
  return 0;
}

static void
ige_reg_sw_fw_sync_release (vlib_main_t *vm, ige_device_t *id)
{
  ige_reg_swsm_t swsm;
  log_debug (id, "reg_sw_fw_sync_release:");
  ige_reg_rd (id, IGE_REG_SWSM, &swsm.as_u32);
  swsm.smbi = 0;
  swsm.swesmbi = 0;
  ige_reg_wr (id, IGE_REG_SWSM, swsm.as_u32);
}

static int
ige_reg_sw_fw_sync_acquire (vlib_main_t *vm, ige_device_t *id)
{
  ige_reg_swsm_t swsm;
  int i, timeout = 10;

  log_debug (id, "reg_sw_fw_sync_acquire:");
  for (i = 0; i < timeout * 2; i++)
    {
      if (i == timeout)
	{
	  log_debug (id,
		     "reg_sw_fw_sync_acquire: timeout, attempt to cleor SWSM");
	  swsm.smbi = 0;
	  swsm.swesmbi = 0;
	  ige_reg_wr (id, IGE_REG_SWSM, swsm.as_u32);
	}
      ige_reg_rd (id, IGE_REG_SWSM, &swsm.as_u32);
      if (swsm.smbi == 0)
	break;
      vlib_process_suspend (vm, 5e-5);
    }

  if (i == timeout)
    {
      log_debug (id, "reg_sw_fw_sync_acquire: timeout acquiring SWSM");
      return 0;
    }

  for (i = 0; i < timeout; i++)
    {
      swsm.swesmbi = 1;
      ige_reg_wr (id, IGE_REG_SWSM, swsm.as_u32);
      ige_reg_rd (id, IGE_REG_SWSM, &swsm.as_u32);
      if (swsm.swesmbi == 1)
	break;
      vlib_process_suspend (vm, 5e-5);
    }

  if (i == timeout)
    {
      swsm.smbi = 0;
      swsm.swesmbi = 0;
      ige_reg_wr (id, IGE_REG_SWSM, swsm.as_u32);
      log_debug (id, "reg_sw_fw_sync_acquire: timeout acquring SWSMBI");
      return 0;
    }

  log_debug (id, "reg_sw_fw_sync_acquire: acquired");
  return 1;
}

static vnet_dev_rv_t
ige_phy_acquire (vlib_main_t *vm, ige_device_t *id)
{
  ige_reg_sw_fw_sync_t sw_fw_sync;
  int n_tries = 5;

  log_debug (id, "phy_acquire:");

  while (n_tries-- > 0)
    {
      if (ige_reg_sw_fw_sync_acquire (vm, id))
	{
	  ige_reg_rd (id, IGE_REG_SW_FW_SYNC, &sw_fw_sync.as_u32);
	  log_debug (id, "phy_acquire: sw_fw_sync 0x%04x");

	  if (sw_fw_sync.fw_phy_sm == 0)
	    {
	      sw_fw_sync.sw_phy_sm = 1;
	      ige_reg_wr (id, IGE_REG_SW_FW_SYNC, sw_fw_sync.as_u32);
	      ige_reg_sw_fw_sync_release (vm, id);
	      return 0;
	    }

	  ige_reg_sw_fw_sync_release (vm, id);
	}
      vlib_process_suspend (vm, 1e-4);
    }
  return ige_err (id, VNET_DEV_ERR_TIMEOUT, "failed to acquire PHY");
}

static vnet_dev_rv_t
ige_phy_release (vlib_main_t *vm, ige_device_t *id)
{
  ige_reg_sw_fw_sync_t sw_fw_sync;

  log_debug (id, "phy_release:");

  /* release phy */
  if (ige_reg_sw_fw_sync_acquire (vm, id) == 0)
    return ige_err (id, VNET_DEV_ERR_TIMEOUT, "sw_fw_sync ownership timeout");

  sw_fw_sync.sw_phy_sm = 0;
  ige_reg_wr (id, IGE_REG_SW_FW_SYNC, sw_fw_sync.as_u32);
  ige_reg_sw_fw_sync_release (vm, id);

  return 0;
}

static vnet_dev_rv_t
ige_phy_read (vlib_main_t *vm, ige_device_t *id, u16 addr, u16 *data)
{
  ige_reg_mdic_t mdic = { .regadd = addr, .opcode = 2 };
  int n_tries = 10;
  f64 t;

  t = vlib_time_now (vm);
  ige_reg_wr (id, IGE_REG_MDIC, mdic.as_u32);
  vlib_process_suspend (vm, 5e-5);
  ige_reg_rd (id, IGE_REG_MDIC, &mdic.as_u32);

  while (mdic.ready == 0 && n_tries-- > 0)
    {
      vlib_process_suspend (vm, 2e-5);
      ige_reg_rd (id, IGE_REG_MDIC, &mdic.as_u32);
    }

  t = vlib_time_now (vm) - t;
  if (t > 1e-4)
    log_warn (id, "phy_read: register read took %.06f sec", t);

  if (mdic.ready == 0)
    return ige_err (id, VNET_DEV_ERR_TIMEOUT, "phy read timeout");

  log_debug (id, "phy_read: addr 0x%02x data 0x%04x", addr, mdic.data);
  *data = mdic.data;
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
	id->dev_flags = flags_by_type[dt->type];
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
  ige_reg_wr (id, IGE_REG_IMC, 0xffffffff);
  ige_reg_rd (id, IGE_REG_ICR, &tmp);

  rv = vnet_dev_pci_function_level_reset (vm, dev);
  if (rv != VNET_DEV_OK)
    return rv;

  rv = vnet_dev_pci_bus_master_enable (vm, dev);
  if (rv != VNET_DEV_OK)
    return rv;

  mask = (ige_reg_status_t){ .rst_done = 1 }.as_u32;
  match = mask;

  if (ige_reg_poll (vm, id, IGE_REG_STATUS, mask, match, 1e-5, 1e-1) == 0)
    return ige_err (id, VNET_DEV_ERR_TIMEOUT, "reset timeout");

  /* disable interrupts again */
  ige_reg_wr (id, IGE_REG_IMC, 0xffffffff);
  ige_reg_rd (id, IGE_REG_ICR, &tmp);

  /* notify ME that driver is loaded */
  ige_reg_ctrl_ext_t ctrl_ext;
  ige_reg_rd (id, IGE_REG_CTRL_EXT, &ctrl_ext.as_u32);
  ctrl_ext.driver_loaded = 1;
  ige_reg_wr (id, IGE_REG_CTRL_EXT, ctrl_ext.as_u32);

  if (1)
    {
      u16 d[32] = {};
      if ((rv = ige_phy_acquire (vm, id)))
	return rv;
      for (int i = 0; i < 32; i++)
	{
	  if ((rv = ige_phy_read (vm, id, i, d + i)))
	    return rv;
	}
      if ((rv = ige_phy_release (vm, id)))
	return rv;

      fformat (stderr, "PHY dump %U\n", format_hexdump_u16, d, 32);
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
      },
      .data_size = sizeof (ige_port_t),
    },
    .rx_node = &ige_rx_node,
    .tx_node = &ige_tx_node,
    .rx_queue = {
      .config = {
        .data_size = sizeof (ige_rxq_t),
        .default_size = 512,
        .multiplier = 8,
        .min_size = 32,
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
        .multiplier = 8,
        .min_size = 32,
        .max_size = 32768,
      },
      .ops = {
        .alloc = ige_tx_queue_alloc,
        .free = ige_tx_queue_free,
      },
    },
  };

  ige_reg_rd (id, IGE_REG_RAL0, &tmp);
  clib_memcpy (&port.port.attr.hw_addr.eth_mac[0], &tmp, 4);
  ige_reg_rd (id, IGE_REG_RAH0, &tmp);
  clib_memcpy (&port.port.attr.hw_addr.eth_mac[4], &tmp, 2);
  log_info (id, "MAC address is %U", format_ethernet_address,
	    port.port.attr.hw_addr.eth_mac);

  id->avail_rxq_bmp = pow2_mask (4);
  id->avail_txq_bmp = pow2_mask (4);
  vnet_dev_port_add (vm, dev, 0, &port);
  return 0;
}

VNET_DEV_REGISTER_DRIVER (ige) = {
  .name = "ige",
  .bus = "pci",
  .device_data_sz = sizeof (ige_device_t),
  .ops = {
    .init = ige_init,
    .probe = ige_probe,
  },
};

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "dev_ige",
};
