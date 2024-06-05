/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Cisco Systems, Inc.
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
  .subclass_name = "port",
};

const u32 link_speeds[8] = {
  [0b000] = 10000,
  [0b001] = 100000,
  [0b010] = 1000000,
  [0b110] = 2500000,
};

static void
ige_port_status_poll (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  ige_port_t *ip = vnet_dev_get_port_data (port);
  ige_reg_status_t status;

  ige_reg_rd (dev, IGE_REG_STATUS, &status.as_u32);

  if (ip->last_status.as_u32 != status.as_u32)
    {
      vnet_dev_port_state_changes_t changes = {};

      log_debug (dev, "\n%U", format_ige_reg_diff, IGE_REG_STATUS,
		 ip->last_status.as_u32, status.as_u32);

      if (ip->last_status.link_up != status.link_up)
	{
	  changes.change.link_state = 1;
	  changes.link_state = status.link_up;
	  log_debug (dev, "link state changed to %s",
		     status.link_up ? "up" : "down");
	}

      if (ip->last_status.full_duplex != status.full_duplex)
	{
	  changes.change.link_duplex = 1;
	  changes.full_duplex = status.full_duplex;
	  log_debug (dev, "duplex changed to %s",
		     status.full_duplex ? "full" : "half");
	}

      if (ip->last_status.speed != status.speed ||
	  ip->last_status.speed_2p5 != status.speed_2p5)
	{
	  changes.change.link_speed = 1;
	  changes.link_speed =
	    link_speeds[status.speed_2p5 << 2 | status.speed];
	  if (changes.link_speed)
	    log_debug (dev, "link speed changed to %u Mbps",
		       changes.link_speed / 1000);
	  else
	    log_warn (dev,
		      "device reported unknown speed (speed %u speed_2p5 %u)",
		      status.speed, status.speed_2p5);
	}
      ip->last_status.as_u32 = status.as_u32;
      if (changes.change.any)
	vnet_dev_port_state_change (vm, port, changes);
    }
}

vnet_dev_rv_t
ige_port_init (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_rv_t rv;

  log_debug (port->dev, "port %u", port->port_id);

  rv = ige_port_counters_init (vm, port);
  vnet_dev_poll_port_add (vm, port, 1, ige_port_status_poll);
  return rv;
}

vnet_dev_rv_t
ige_port_start (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  ige_device_t *id = vnet_dev_get_data (port->dev);
  ige_rxq_t *iq;
  ige_reg_rctl_t rctl;
  vnet_dev_rv_t rv = VNET_DEV_OK;

  log_debug (dev, "port %u", port->port_id);

  foreach_vnet_dev_port_rx_queue (rxq, port)
    {
      iq = vnet_dev_get_rx_queue_data (rxq);
      iq->tail = vlib_buffer_alloc_from_pool (
	vm, iq->buffer_indices, rxq->size,
	vnet_dev_get_rx_queue_buffer_pool_index (rxq));

      if (iq->tail == 0)
	rv = VNET_DEV_ERR_BUFFER_ALLOC_FAIL;
    }

  if (rv != VNET_DEV_OK)
    {
      foreach_vnet_dev_port_rx_queue (rxq, port)
	{
	  iq = vnet_dev_get_rx_queue_data (rxq);
	  if (iq->tail)
	    vlib_buffer_free (vm, iq->buffer_indices, iq->tail);
	  iq->tail = 0;
	}
      return rv;
    }

  ige_reg_rd (dev, IGE_REG_RCTL, &rctl.as_u32);
  if (rctl.rx_enable)
    {
      log_warn (dev, "port %u rx is unexpectedlly enabled", port->port_id);
      rctl.rx_enable = 0;
      ige_reg_wr (dev, IGE_REG_RCTL, rctl.as_u32);
    }

  foreach_vnet_dev_port_rx_queue (rxq, port)
    {
      const ige_reg_srrctl_t srrctl = {
	.drop_en = 1,
	.desc_type = 1,	  /* advanced, no header */
	.bsizepacket = 2, /* 2k */
			  //.bsizeheader = 2, /* 128 B */
      };

      const ige_reg_rxdctl_t rxdctl = {
	.pthresh = 12,
	.hthresh = 10,
	.wthresh = 1,
	.enable = 1,
      };

      u64 dma_addr;
      u16 q = rxq->queue_id;
      ige_rxq_t *iq = vnet_dev_get_rx_queue_data (rxq);

      dma_addr = vnet_dev_get_dma_addr (vm, dev, iq->descs);
      ige_reg_wr (dev, IGE_REG_RDLEN (q), rxq->size * sizeof (ige_rx_desc_t));
      ige_reg_wr (dev, IGE_REG_RDBAH (q), dma_addr >> 32);
      ige_reg_wr (dev, IGE_REG_RDBAL (q), dma_addr);
      ige_reg_wr (dev, IGE_REG_SRRCTL (q), srrctl.as_u32);
      ige_reg_wr (dev, IGE_REG_RXDCTL (q), rxdctl.as_u32);
      iq->head = 0;
      iq->tail = 0;
      iq->reg_rdt = (u32 *) ((u8 *) id->bar0 + IGE_REG_RDT (q));
    }

  rctl.rx_enable = 1;
  rctl.store_bad_packets = 0;
  rctl.strip_eth_crc = 1;
  rctl.long_pkt_reception_ena = 0;
  rctl.vlan_filter_ena = 0;
  rctl.bcast_accept_mode = 1;
  rctl.discard_pause_frames = 1;
  ige_reg_wr (dev, IGE_REG_RCTL, rctl.as_u32);

  foreach_vnet_dev_port_rx_queue (rxq, port)
    {
      u16 q = rxq->queue_id;

      ige_rxq_t *iq = vnet_dev_get_rx_queue_data (rxq);
      ige_reg_wr (dev, IGE_REG_RDH (q), 0);
      ige_reg_wr (dev, IGE_REG_RDT (q), iq->tail);
    }

  vnet_dev_poll_port_add (vm, port, 3, ige_port_counter_poll);
  return 0;
}

void
ige_port_stop (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  log_debug (dev, "port %u", port->port_id);
  ige_reg_rctl_t rctl;
  vnet_dev_poll_port_remove (vm, port, ige_port_counter_poll);

  ige_reg_rd (dev, IGE_REG_RCTL, &rctl.as_u32);
  rctl.rx_enable = 0;
  ige_reg_wr (dev, IGE_REG_RCTL, rctl.as_u32);

  foreach_vnet_dev_port_rx_queue (rxq, port)
    {
      ige_rxq_t *iq = vnet_dev_get_rx_queue_data (rxq);
      vlib_buffer_free_from_ring_no_next (vm, iq->buffer_indices, iq->head,
					  rxq->size, iq->tail - iq->head);
    }
}
