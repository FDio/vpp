/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#include "vppinfra/error.h"
#include "vppinfra/format.h"
#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vnet/dev/pci.h>
#include <dev_igc/igc.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>

VLIB_REGISTER_LOG_CLASS (igc_log, static) = {
  .class_name = "dev_igc",
  .subclass_name = "init",
};

#define log_debug(id, f, ...)                                                 \
  vlib_log (VLIB_LOG_LEVEL_DEBUG, igc_log.class, "%U: " f,                    \
	    format_vnet_dev_addr, vnet_dev_from_data (id), ##__VA_ARGS__)
#define log_info(id, f, ...)                                                  \
  vlib_log (VLIB_LOG_LEVEL_INFO, igc_log.class, "%U: " f,                     \
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

vnet_dev_node_fn_t igc_rx_node_fn = {};
vnet_dev_node_fn_t igc_tx_node_fn = {};

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
  return VNET_DEV_ERR_BUS;
}

static void
igc_reg_rd (igc_device_t *id, u32 reg, u32 *val)
{
  u32 rv = __atomic_load_n ((u32 *) ((u8 *) id->bar0 + reg), __ATOMIC_ACQUIRE);
  *val = rv;
}

void
igc_reg_wr (igc_device_t *id, u32 reg, u32 val)
{
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

static vnet_dev_rv_t
igc_port_status_poll (vlib_main_t *vm, vnet_dev_port_t *port)
{
  igc_device_t *id = vnet_dev_get_data (port->dev);
  igc_port_t *ip = vnet_dev_get_port_data (port);
  igc_reg_status_t status;

  igc_reg_rd (id, IGC_REG_STATUS, &status.as_u32);

  if (ip->last_status.as_u32 != status.as_u32)
    {
      vnet_dev_port_state_changes_t changes = {};

      log_debug (id, "port_status_poll: %U", format_igc_reg_diff,
		 IGC_REG_STATUS, ip->last_status.as_u32, status.as_u32);

      if (ip->last_status.link_up != status.link_up)
	{
	  changes.change.link_state = 1;
	  changes.link_state = status.link_up;
	  log_debug (id, "port_poll: link state changed to %s",
		     status.link_up ? "up" : "down");
	}

      if (ip->last_status.full_duplex != status.full_duplex)
	{
	  changes.change.link_duplex = 1;
	  changes.full_duplex = status.full_duplex;
	  log_debug (id, "port_poll: duplex changed to %s",
		     status.full_duplex ? "full" : "half");
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
	  changes.change.link_speed = 1;
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
      if (changes.change.any)
	vnet_dev_port_state_change (vm, port, changes);
    }
  return 0;
}

static void
ppp (igc_device_t *id, u32 r)
{
  u32 v;
  igc_reg_rd (id, r, &v);
  if (v)
    log_debug (id, "%05x: %08x", r, v);
}

static vnet_dev_rv_t
igc_port_counter_poll (vlib_main_t *vm, vnet_dev_port_t *port)
{
  igc_device_t *id = vnet_dev_get_data (port->dev);
  for (u32 r = 0x4000; r < 0x4134; r += 4)
    ppp (id, r);

  ppp (id, 0xc030);
  ppp (id, 0x10010);
  ppp (id, 0x10018);
  return 0;
}

static vnet_dev_rv_t
igc_port_init (vlib_main_t *vm, vnet_dev_port_t *port)
{
  igc_device_t *id = vnet_dev_get_data (port->dev);
  log_debug (id, "port init: port %u", port->port_id);

  vnet_dev_poll_port_add (vm, port, 1, igc_port_status_poll);
  return 0;
}

static vnet_dev_rv_t
igc_port_start (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  igc_device_t *id = vnet_dev_get_data (port->dev);
  igc_rxq_t *iq;
  igc_reg_rctl_t rctl;
  vnet_dev_rv_t rv = VNET_DEV_OK;

  log_debug (id, "port start: port %u", port->port_id);

  pool_foreach_pointer (rxq, port->rx_queues)
    {
      iq = vnet_dev_get_rx_queue_data (rxq);
      iq->tail = vlib_buffer_alloc_from_pool (
	vm, iq->buffer_indices, rxq->size, rxq->buffer_pool_index);

      if (iq->tail == 0)
	rv = VNET_DEV_ERR_BUFFER_ALLOC_FAIL;
    }

  if (rv != VNET_DEV_OK)
    {
      pool_foreach_pointer (rxq, port->rx_queues)
	{
	  iq = vnet_dev_get_rx_queue_data (rxq);
	  if (iq->tail)
	    vlib_buffer_free (vm, iq->buffer_indices, iq->tail);
	  iq->tail = 0;
	}
      return rv;
    }

  igc_reg_rd (id, IGC_REG_RCTL, &rctl.as_u32);
  if (rctl.rx_enable)
    {
      log_warn (id, "port_start: port %u rx is unexpectedlly enabled",
		port->port_id);
      rctl.rx_enable = 0;
      igc_reg_wr (id, IGC_REG_RCTL, rctl.as_u32);
    }

  pool_foreach_pointer (rxq, port->rx_queues)
    {
      const igc_reg_srrctl_t srrctl = {
	.drop_en = 1,
	.desc_type = 1,	  /* advanced, no header */
	.bsizepacket = 2, /* 2k */
			  //.bsizeheader = 2, /* 128 B */
      };

      const igc_reg_rxdctl_t rxdctl = {
	.pthresh = 12,
	.hthresh = 10,
	.wthresh = 1,
	.enable = 1,
      };

      u64 dma_addr;
      u16 q = rxq->queue_id;
      igc_rxq_t *iq = vnet_dev_get_rx_queue_data (rxq);

      for (u16 j = 0; j < iq->tail; j++)
	{
	  vlib_buffer_t *b = vlib_get_buffer (vm, iq->buffer_indices[j]);
	  iq->descs[j].pkt_addr = vnet_dev_get_dma_addr (vm, dev, b->data);
	  iq->descs[j].hdr_addr = 0;
	}

      dma_addr = vnet_dev_get_dma_addr (vm, dev, iq->descs);
      igc_reg_wr (id, IGC_REG_RDLEN (q), rxq->size * sizeof (igc_rx_desc_t));
      igc_reg_wr (id, IGC_REG_RDBAH (q), dma_addr >> 32);
      igc_reg_wr (id, IGC_REG_RDBAL (q), dma_addr);
      igc_reg_wr (id, IGC_REG_SRRCTL (q), srrctl.as_u32);
      igc_reg_wr (id, IGC_REG_RXDCTL (q), rxdctl.as_u32);
      iq->head = 0;
    }

  rctl.rx_enable = 1;
  rctl.store_bad_packets = 0;
  rctl.strip_eth_crc = 1;
  rctl.long_pkt_reception_ena = 0;
  rctl.vlan_filter_ena = 0;
  rctl.bcast_accept_mode = 1;
  rctl.discard_pause_frames = 1;
  igc_reg_wr (id, IGC_REG_RCTL, rctl.as_u32);

  pool_foreach_pointer (rxq, port->rx_queues)
    {
      u16 q = rxq->queue_id;

      igc_rxq_t *iq = vnet_dev_get_rx_queue_data (rxq);
      igc_reg_wr (id, IGC_REG_RDH (q), 0);
      igc_reg_wr (id, IGC_REG_RDT (q), iq->tail);

      u32 reg, val;
      reg = IGC_REG_RXDCTL (q);
      igc_reg_rd (id, reg, &val);
      fformat (stderr, "\n%U\n", format_igc_reg_read, reg, val);
      reg = IGC_REG_SRRCTL (q);
      igc_reg_rd (id, reg, &val);
      fformat (stderr, "\n%U\n", format_igc_reg_read, reg, val);
    }

  vnet_dev_poll_port_add (vm, port, 3, igc_port_counter_poll);
  return 0;
}

static void
igc_port_stop (vlib_main_t *vm, vnet_dev_port_t *port)
{
  igc_device_t *id = vnet_dev_get_data (port->dev);
  log_debug (id, "port stop: port %u", port->port_id);
  igc_reg_rctl_t rctl;
  u32 i;
  vnet_dev_poll_port_remove (vm, port, igc_port_counter_poll);

  igc_reg_rd (id, IGC_REG_RCTL, &rctl.as_u32);
  rctl.rx_enable = 0;
  igc_reg_wr (id, IGC_REG_RCTL, rctl.as_u32);
  pool_foreach_index (i, port->rx_queues)
    {
      vnet_dev_rx_queue_t *rxq = *pool_elt_at_index (port->rx_queues, i);
      igc_rxq_t *iq = vnet_dev_get_rx_queue_data (rxq);
      vlib_buffer_free_from_ring_no_next (vm, iq->buffer_indices, iq->head,
					  rxq->size, iq->tail - iq->head);
    }
}

static vnet_dev_rv_t
igc_rx_queue_alloc (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq)
{
  vnet_dev_t *dev = rxq->port->dev;
  igc_device_t *id = vnet_dev_get_data (dev);
  igc_rxq_t *iq = vnet_dev_get_rx_queue_data (rxq);
  vnet_dev_rv_t rv;

  log_debug (id, "rx_queue_alloc:");

  if (id->avail_rxq_bmp == 0)
    return VNET_DEV_ERR_RESOURCE_NOT_AVAILABLE;
  rxq->queue_id = get_lowest_set_bit_index (id->avail_rxq_bmp);
  id->avail_rxq_bmp ^= 1 << rxq->queue_id;

  iq->buffer_indices = clib_mem_alloc_aligned (
    rxq->size * sizeof (iq->buffer_indices[0]), CLIB_CACHE_LINE_BYTES);
  clib_memset_u32 (iq->buffer_indices, 0, rxq->size);

  rv = vnet_dev_dma_mem_alloc (vm, dev, sizeof (igc_rx_desc_t) * rxq->size, 0,
			       (void **) &iq->descs);
  return rv;
}

static void
igc_rx_queue_free (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq)
{
  vnet_dev_t *dev = rxq->port->dev;
  igc_device_t *id = vnet_dev_get_data (dev);
  igc_rxq_t *iq = vnet_dev_get_rx_queue_data (rxq);

  log_debug (id, "rx_queue_free:");

  id->avail_rxq_bmp |= 1 << rxq->queue_id;
  vnet_dev_dma_mem_free (vm, dev, iq->descs);
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

static void
igc_tx_queue_free (vlib_main_t *vm, vnet_dev_tx_queue_t *txq)
{
  vnet_dev_t *dev = txq->port->dev;
  igc_device_t *id = vnet_dev_get_data (dev);
  log_debug (id, "tx_queue_free:");
  id->avail_txq_bmp |= 1 << txq->queue_id;
}

static vnet_dev_rv_t
igc_init (vlib_main_t *vm, vnet_dev_t *dev)
{
  igc_device_t *id = vnet_dev_get_data (dev);
  vlib_pci_dev_handle_t h = vnet_dev_get_pci_handle (dev);
  clib_error_t *err;
  vnet_dev_rv_t rv;
  u32 match, mask, tmp;

  /* map BAR0 */
  if (id->bar0 == 0)
    {
      if ((err = vlib_pci_map_region (vm, h, 0, &id->bar0)))
	return igc_pci_err (id, err);
    }

  /* disable interrupts */
  igc_reg_wr (id, IGC_REG_IMC, 0xffffffff);
  igc_reg_rd (id, IGC_REG_ICR, &tmp);

  if ((err = vlib_pci_function_level_reset (vm, h)))
    return igc_pci_err (id, err);
  if ((err = vlib_pci_bus_master_enable (vm, h)))
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

  if (0)
    {
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
    }

  vnet_dev_port_add_args_t port = {
    .port = {
      .config = {
        .type = VNET_DEV_PORT_TYPE_ETHERNET,
        .data_size = sizeof (igc_port_t),
        .max_rx_queues = 4,
        .max_tx_queues = 4,
        .max_frame_size = 9728,
      },
      .ops = {
        .init = igc_port_init,
        .start = igc_port_start,
        .stop = igc_port_stop,
        .format_status = format_igc_port_status,
      },
    },
    .rx_node = {
        .node_fn = &igc_rx_node_fn,
    },
    .tx_node = {
        .node_fn = &igc_tx_node_fn,
    },
    .rx_queue = {
      .config = {
        .data_size = sizeof (igc_rxq_t),
        .default_size = 512,
        .multiplier = 8,
        .min_size = 32,
        .max_size = 32768,
      },
      .ops = {
        .alloc = igc_rx_queue_alloc,
        .free = igc_rx_queue_free,
      },
    },
    .tx_queue = {
      .config = {
        .data_size = sizeof (igc_txq_t),
        .default_size = 512,
        .multiplier = 8,
        .min_size = 32,
        .max_size = 32768,
      },
      .ops = {
        .alloc = igc_tx_queue_alloc,
        .free = igc_tx_queue_free,
      },
    },
  };

  igc_reg_rd (id, IGC_REG_RAL0, &tmp);
  clib_memcpy (&port.port.config.hw_addr[0], &tmp, 4);
  igc_reg_rd (id, IGC_REG_RAH0, &tmp);
  clib_memcpy (&port.port.config.hw_addr[4], &tmp, 2);
  log_info (id, "device MAC address is %U", format_ethernet_address,
	    port.port.config.hw_addr);

  id->avail_rxq_bmp = pow2_mask (4);
  id->avail_txq_bmp = pow2_mask (4);
  vnet_dev_port_add (vm, dev, 0, &port);
  return 0;
}

static void
igc_free (vlib_main_t *vm, vnet_dev_t *dev)
{
}

static struct
{
  u16 device_id;
  char *description;
} igc_dev_types[] = {
  { .device_id = 0x15F2,
    .description = "Intel(R) Ethernet Controller I225-LM" },
  { .device_id = 0x15F3,
    .description = "Intel(R) Ethernet Controller I225-V" },
  { .device_id = 0x0d9f,
    .description = "Intel(R) Ethernet Controller (2) I225-IT" },
  { .device_id = 0x125b,
    .description = "Intel(R) Ethernet Controller I226-LM" },
  { .device_id = 0x125c,
    .description = "Intel(R) Ethernet Controller I226-V" },
  { .device_id = 0x125d,
    .description = "Intel(R) Ethernet Controller I226-IT" },
};

static u8 *
igc_probe (vlib_main_t *vm, vnet_dev_bus_index_t bus_index, void *dev_info)
{
  vnet_dev_bus_pci_device_info_t *di = dev_info;

  if (di->vendor_id != 0x8086)
    return 0;

  FOREACH_ARRAY_ELT (dt, igc_dev_types)
    {
      if (dt->device_id == di->device_id)
	return format (0, "%s", dt->description);
    }

  return 0;
}

VNET_DEV_REGISTER_DRIVER (igc) = {
  .name = "igc",
  .bus = "pci",
  .device_data_sz = sizeof (igc_device_t),
  .ops = { .device_init = igc_init,
	   .device_free = igc_free,
	   .probe = igc_probe,
  },
};

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "dev_igc",
};
