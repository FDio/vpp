/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#include "vlib/defs.h"
#include "vlib/pci/pci.h"
#include "dev/igc/igc_regs.h"
#include "vnet/error.h"
#include "vppinfra/error.h"
#include "vppinfra/format.h"
#include <vnet/vnet.h>
#include <vnet/devices/dev.h>
#include <dev/igc/igc.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>

VLIB_REGISTER_LOG_CLASS (igc_log, static) = {
  .class_name = "igc",
  .subclass_name = "init",
};

#define log_debug(id, f, ...)                                                 \
  vlib_log (VLIB_LOG_LEVEL_DEBUG, igc_log.class, "%U: " f,                    \
	    format_vnet_dev_addr, vnet_dev_from_data (id), ##__VA_ARGS__)
#define log_notice(id, f, ...)                                                \
  vlib_log (VLIB_LOG_LEVEL_NOTICE, igc_log.class, "%U: " f,                   \
	    format_vnet_dev_addr, vnet_dev_from_data (id), ##__VA_ARGS__)
#define log_warn(id, f, ...)                                                  \
  vlib_log (VLIB_LOG_LEVEL_WARNING, igc_log.class, "%U: " f,                  \
	    format_vnet_dev_addr, vnet_dev_from_data (id), ##__VA_ARGS__)
#define log_err(id, f, ...)                                                   \
  vlib_log (VLIB_LOG_LEVEL_ERR, igc_log.class, "%U: " f,                      \
	    format_vnet_dev_addr, vnet_dev_from_data (id), ##__VA_ARGS__)

typedef struct
{
  void *bar0;
  u8 avail_rxq_bmp;
  u8 avail_txq_bmp;
} igc_device_t;

typedef struct
{
  igc_reg_status_t last_status;
} igc_port_t;

static vnet_dev_rv_t
igc_err (igc_device_t *id, vnet_dev_rv_t rv, char *fmt, ...)
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

static vnet_dev_rv_t
igc_pci_err (igc_device_t *id, clib_error_t *err)
{
  log_err (id, "PCI error: %U", format_clib_error, err);
  clib_error_free (err);
  return VNET_DEV_ERR_PCI;
}

static void
igc_reg_rd (igc_device_t *id, u32 reg, u32 *val)
{
  u32 rv = __atomic_load_n ((u32 *) ((u8 *) id->bar0 + reg), __ATOMIC_ACQUIRE);
  // log_debug (id, "reg_rd: %U", format_igc_reg_read, reg, rv);
  *val = rv;
}

void
igc_reg_wr (igc_device_t *id, u32 reg, u32 val)
{
  // log_debug (id, "reg_wr: %U", format_igc_reg_write, reg, val);
  __atomic_store_n ((u32 *) ((u8 *) id->bar0 + reg), val, __ATOMIC_RELEASE);
}

static int
igc_reg_poll (vlib_main_t *vm, igc_device_t *id, u32 reg, u32 mask, u32 match,
	      f64 intial_delay, f64 timeout)
{
  f64 t0 = vlib_time_now (vm);
  u32 val;

  for (f64 delay = intial_delay, total_time = delay; total_time < timeout;
       delay *= 2, total_time += delay)
    {
      igc_reg_rd (id, reg, &val);
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
igc_reg_sw_fw_sync_release (vlib_main_t *vm, igc_device_t *id)
{
  igc_reg_swsm_t swsm;
  log_debug (id, "reg_sw_fw_sync_release:");
  igc_reg_rd (id, IGC_REG_SWSM, &swsm.as_u32);
  swsm.smbi = 0;
  swsm.swesmbi = 0;
  igc_reg_wr (id, IGC_REG_SWSM, swsm.as_u32);
}

static int
igc_reg_sw_fw_sync_acquire (vlib_main_t *vm, igc_device_t *id)
{
  igc_reg_swsm_t swsm;
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
	  igc_reg_wr (id, IGC_REG_SWSM, swsm.as_u32);
	}
      igc_reg_rd (id, IGC_REG_SWSM, &swsm.as_u32);
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
      igc_reg_wr (id, IGC_REG_SWSM, swsm.as_u32);
      igc_reg_rd (id, IGC_REG_SWSM, &swsm.as_u32);
      if (swsm.swesmbi == 1)
	break;
      vlib_process_suspend (vm, 5e-5);
    }

  if (i == timeout)
    {
      swsm.smbi = 0;
      swsm.swesmbi = 0;
      igc_reg_wr (id, IGC_REG_SWSM, swsm.as_u32);
      log_debug (id, "reg_sw_fw_sync_acquire: timeout acquring SWSMBI");
      return 0;
    }

  log_debug (id, "reg_sw_fw_sync_acquire: acquired");
  return 1;
}

static vnet_dev_rv_t
igc_phy_acquire (vlib_main_t *vm, igc_device_t *id)
{
  igc_reg_sw_fw_sync_t sw_fw_sync;
  int n_tries = 5;

  log_debug (id, "phy_acquire:");

  while (n_tries-- > 0)
    {
      if (igc_reg_sw_fw_sync_acquire (vm, id))
	{
	  igc_reg_rd (id, IGC_REG_SW_FW_SYNC, &sw_fw_sync.as_u32);
	  log_debug (id, "phy_acquire: sw_fw_sync 0x%04x");

	  if (sw_fw_sync.fw_phy_sm == 0)
	    {
	      sw_fw_sync.sw_phy_sm = 1;
	      igc_reg_wr (id, IGC_REG_SW_FW_SYNC, sw_fw_sync.as_u32);
	      igc_reg_sw_fw_sync_release (vm, id);
	      return 0;
	    }

	  igc_reg_sw_fw_sync_release (vm, id);
	}
      vlib_process_suspend (vm, 1e-4);
    }
  return igc_err (id, VNET_DEV_ERR_TIMEOUT, "failed to acquire PHY");
}

static vnet_dev_rv_t
igc_phy_release (vlib_main_t *vm, igc_device_t *id)
{
  igc_reg_sw_fw_sync_t sw_fw_sync;

  log_debug (id, "phy_release:");

  /* release phy */
  if (igc_reg_sw_fw_sync_acquire (vm, id) == 0)
    return igc_err (id, VNET_DEV_ERR_TIMEOUT, "sw_fw_sync ownership timeout");

  sw_fw_sync.sw_phy_sm = 0;
  igc_reg_wr (id, IGC_REG_SW_FW_SYNC, sw_fw_sync.as_u32);
  igc_reg_sw_fw_sync_release (vm, id);

  return 0;
}

static vnet_dev_rv_t
igc_phy_read (vlib_main_t *vm, igc_device_t *id, u16 addr, u16 *data)
{
  igc_reg_mdic_t mdic = { .regadd = addr, .opcode = 2 };
  int n_tries = 10;
  f64 t;

  t = vlib_time_now (vm);
  igc_reg_wr (id, IGC_REG_MDIC, mdic.as_u32);
  vlib_process_suspend (vm, 5e-5);
  igc_reg_rd (id, IGC_REG_MDIC, &mdic.as_u32);

  while (mdic.ready == 0 && n_tries-- > 0)
    {
      vlib_process_suspend (vm, 2e-5);
      igc_reg_rd (id, IGC_REG_MDIC, &mdic.as_u32);
    }

  t = vlib_time_now (vm) - t;
  if (t > 1e-4)
    log_warn (id, "phy_read: register read took %.06f sec", t);

  if (mdic.ready == 0)
    return igc_err (id, VNET_DEV_ERR_TIMEOUT, "phy read timeout");

  log_debug (id, "phy_read: addr 0x%02x data 0x%04x", addr, mdic.data);
  *data = mdic.data;
  return 0;
}

static uword
igc_rx_node_fn (vlib_main_t *vm, vlib_node_runtime_t *node,
		vlib_frame_t *frame)
{
  fformat (stderr, "%s", __func__);
  return 0;
}

static vnet_dev_rv_t
igc_init (vlib_main_t *vm, vnet_dev_t *dev)
{
  igc_device_t *id = vnet_dev_get_data (dev);
  clib_error_t *err;
  vnet_dev_rv_t rv;
  u32 match, mask, tmp;

  /* map BAR0 */
  if (id->bar0 == 0)
    {
      if ((err = vlib_pci_map_region (vm, dev->pci.handle, 0, &id->bar0)))
	return igc_pci_err (id, err);
    }

  /* disable interrupts */
  igc_reg_wr (id, IGC_REG_IMC, 0xffffffff);
  igc_reg_rd (id, IGC_REG_ICR, &tmp);

  if ((err = vlib_pci_function_level_reset (vm, dev->pci.handle)))
    return igc_pci_err (id, err);
  if ((err = vlib_pci_bus_master_enable (vm, dev->pci.handle)))
    return igc_pci_err (id, err);

  mask = (igc_reg_status_t){ .rst_done = 1 }.as_u32;
  match = mask;

  if (igc_reg_poll (vm, id, IGC_REG_STATUS, mask, match, 1e-5, 1e-1) == 0)
    return igc_err (id, VNET_DEV_ERR_TIMEOUT, "reset timeout");

  /* disable interrupts again */
  igc_reg_wr (id, IGC_REG_IMC, 0xffffffff);
  igc_reg_rd (id, IGC_REG_ICR, &tmp);

  /* notify ME that driver is loaded */
  igc_reg_ctrl_ext_t ctrl_ext;
  igc_reg_rd (id, IGC_REG_CTRL_EXT, &ctrl_ext.as_u32);
  ctrl_ext.driver_loaded = 1;
  igc_reg_wr (id, IGC_REG_CTRL_EXT, ctrl_ext.as_u32);

  u16 d[32] = {};
  if ((rv = igc_phy_acquire (vm, id)))
    return rv;
  for (int i = 0; i < 32; i++)
    {
      if ((rv = igc_phy_read (vm, id, i, d + i)))
	return rv;
    }
  if ((rv = igc_phy_release (vm, id)))
    return rv;

  fformat (stderr, "PHY dump %U\n", format_hexdump_u16, d, 32);

  vnet_dev_port_add_args_t port = {
    .type = VNET_DEV_PORT_TYPE_ETHERNET,
    .max_rx_queues = 4,
    .max_tx_queues = 4,
    .data_sz = sizeof (igc_port_t)
  };

  igc_reg_rd (id, IGC_REG_RAL0, &tmp);
  clib_memcpy (&port.hw_addr[0], &tmp, 4);
  igc_reg_rd (id, IGC_REG_RAH0, &tmp);
  clib_memcpy (&port.hw_addr[4], &tmp, 2);
  log_debug (id, "%U", format_ethernet_address, port.hw_addr);

  id->avail_rxq_bmp = pow2_mask (4);
  id->avail_txq_bmp = pow2_mask (4);
  vnet_dev_port_add (vm, dev, 0, port);
  return 0;
}

static vnet_dev_rv_t
igc_free (vlib_main_t *vm, vnet_dev_t *dev)
{
  return 0;
}

static vnet_dev_rv_t
igc_port_poll (vlib_main_t *vm, vnet_dev_port_t *port)
{
  igc_device_t *id = vnet_dev_get_data (port->dev);
  igc_port_t *ip = vnet_dev_get_port_data (port);
  igc_reg_status_t status;

  igc_reg_rd (id, IGC_REG_STATUS, &status.as_u32);

  if (ip->last_status.as_u32 != status.as_u32)
    {
      vnet_dev_port_state_changes_t changes = {};

      if (ip->last_status.link_up != status.link_up)
	{
	  changes.link_state_change = 1;
	  changes.link_state = status.link_up;
	  log_debug (id, "port_poll: link state chganged to %s",
		     status.link_up ? "up" : "down");
	}

      if (ip->last_status.speed != status.speed ||
	  ip->last_status.speed_2p5 != status.speed_2p5)
	{
	  const u32 link_speeds[8] = {
	    [0b000] = 10000,
	    [0b001] = 100000,
	    [0b010] = 1000000,
	    [0b110] = 2500000,
	  };
	  changes.link_speed_change = 1;
	  changes.link_speed =
	    link_speeds[status.speed_2p5 << 2 | status.speed];
	  if (changes.link_speed)
	    log_debug (id, "port_poll: link speed changed to %u Mbps",
		       changes.link_speed / 1000);
	  else
	    log_warn (id,
		      "port_poll: device reported unknown speed (speed %u "
		      "speed_2p5 %u)",
		      status.speed, status.speed_2p5);
	}
      ip->last_status.as_u32 = status.as_u32;
      if (changes.any)
	vnet_dev_port_state_change (vm, port, changes);
    }

  return 0;
}

static vnet_dev_rv_t
igc_port_init (vlib_main_t *vm, vnet_dev_port_t *port)
{
  igc_device_t *id = vnet_dev_get_data (port->dev);
  log_debug (id, "port init: port %u", port->port_id);

  vnet_dev_poll_port_add (vm, port, 1, igc_port_poll);
  return 0;
}

static vnet_dev_rv_t
igc_rx_queue_alloc (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq)
{
  vnet_dev_t *dev = rxq->port->dev;
  igc_device_t *id = vnet_dev_get_data (dev);
  log_debug (id, "rx_queue_alloc:");
  if (id->avail_rxq_bmp == 0)
    return VNET_DEV_ERR_RESOURCE_NOT_AVAILABLE;
  rxq->queue_id = get_lowest_set_bit_index (id->avail_rxq_bmp);
  id->avail_rxq_bmp ^= 1 << rxq->queue_id;
  return VNET_DEV_OK;
}

static vnet_dev_rv_t
igc_rx_queue_start (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq)
{
  vnet_dev_t *dev = rxq->port->dev;
  igc_device_t *id = vnet_dev_get_data (dev);
  log_debug (id, "rx_queue_start:");
  return VNET_DEV_OK;
}

static vnet_dev_rv_t
igc_rx_queue_stop (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq)
{
  vnet_dev_t *dev = rxq->port->dev;
  igc_device_t *id = vnet_dev_get_data (dev);
  log_debug (id, "rx_queue_stop:");
  return VNET_DEV_OK;
}

static vnet_dev_rv_t
igc_rx_queue_free (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq)
{
  vnet_dev_t *dev = rxq->port->dev;
  igc_device_t *id = vnet_dev_get_data (dev);
  log_debug (id, "rx_queue_free:");
  id->avail_rxq_bmp |= 1 << rxq->queue_id;
  return VNET_DEV_OK;
}

static vnet_dev_rv_t
igc_tx_queue_alloc (vlib_main_t *vm, vnet_dev_tx_queue_t *txq)
{
  vnet_dev_t *dev = txq->port->dev;
  igc_device_t *id = vnet_dev_get_data (dev);
  log_debug (id, "tx_queue_alloc:");
  if (id->avail_txq_bmp == 0)
    return VNET_DEV_ERR_RESOURCE_NOT_AVAILABLE;
  txq->queue_id = get_lowest_set_bit_index (id->avail_txq_bmp);
  id->avail_txq_bmp ^= 1 << txq->queue_id;
  return VNET_DEV_OK;
}

static vnet_dev_rv_t
igc_tx_queue_start (vlib_main_t *vm, vnet_dev_tx_queue_t *txq)
{
  vnet_dev_t *dev = txq->port->dev;
  igc_device_t *id = vnet_dev_get_data (dev);
  log_debug (id, "tx_queue_start:");
  return VNET_DEV_OK;
}

static vnet_dev_rv_t
igc_tx_queue_stop (vlib_main_t *vm, vnet_dev_tx_queue_t *txq)
{
  vnet_dev_t *dev = txq->port->dev;
  igc_device_t *id = vnet_dev_get_data (dev);
  log_debug (id, "tx_queue_stop:");
  return VNET_DEV_OK;
}

static vnet_dev_rv_t
igc_tx_queue_free (vlib_main_t *vm, vnet_dev_tx_queue_t *txq)
{
  vnet_dev_t *dev = txq->port->dev;
  igc_device_t *id = vnet_dev_get_data (dev);
  log_debug (id, "tx_queue_free:");
  id->avail_txq_bmp |= 1 << txq->queue_id;
  return VNET_DEV_OK;
}

VNET_DEV_REGISTER_DRIVER (igc) = {
  .name = "igc",
  .bus_type = VNET_DEV_BUS_TYPE_PCIE,
  .device_data_sz = sizeof (igc_device_t),
  .max_rx_queues = 4,
  .max_tx_queues = 4,
  .ops = { .device_init = igc_init,
	   .device_free = igc_free,
	   .rx_node_fn = igc_rx_node_fn,
	   .port_init = igc_port_init,
	   .rx_queue_alloc = igc_rx_queue_alloc,
	   .rx_queue_start = igc_rx_queue_start,
	   .rx_queue_stop = igc_rx_queue_stop,
	   .rx_queue_free = igc_rx_queue_free,
	   .tx_queue_alloc = igc_tx_queue_alloc,
	   .tx_queue_start = igc_tx_queue_start,
	   .tx_queue_stop = igc_tx_queue_stop,
	   .tx_queue_free = igc_tx_queue_free,
  },
  .match = VNET_DEV_MATCH (
    { .vendor_id = 0x8086,
      .device_id = 0x15F2,
      .description = "Intel(R) Ethernet Controller I225-LM" },
    { .vendor_id = 0x8086,
      .device_id = 0x15F3,
      .description = "Intel(R) Ethernet Controller I225-V" },
    { .vendor_id = 0x8086,
      .device_id = 0x0d9f,
      .description = "Intel(R) Ethernet Controller (2) I225-IT" },
    { .vendor_id = 0x8086,
      .device_id = 0x125b,
      .description = "Intel(R) Ethernet Controller I226-LM" },
    { .vendor_id = 0x8086,
      .device_id = 0x125c,
      .description = "Intel(R) Ethernet Controller I226-V" },
    { .vendor_id = 0x8086,
      .device_id = 0x125d,
      .description = "Intel(R) Ethernet Controller I226-IT" }),
};

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "dev_igc",
};
