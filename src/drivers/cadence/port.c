/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vnet/dev/counters.h>

#include <cadence.h>

VLIB_REGISTER_LOG_CLASS (cdn_log, static) = {
  .class_name = "cadence",
  .subclass_name = "port",
};

#define CDN_RX_BUFFER_SIZE 2048
#define CDN_DMACFG_INIT	   0x00000f10

static_always_inline u32
cdn_rx_buffer_size_code (u16 buffer_size)
{
  ASSERT (buffer_size % 64 == 0);
  return buffer_size / 64;
}

static_always_inline uword
cdn_sa_bottom_reg (u32 slot)
{
  ASSERT (slot < 4);
  return CDN_SA1B + slot * 8;
}

static_always_inline uword
cdn_sa_top_reg (u32 slot)
{
  ASSERT (slot < 4);
  return CDN_SA1T + slot * 8;
}

static int
cdn_port_hw_addr_equal (const vnet_dev_hw_addr_t *a, const vnet_dev_hw_addr_t *b)
{
  return clib_memcmp (a, b, sizeof (*a)) == 0;
}

static void
cdn_port_write_hw_addr_slot (vnet_dev_port_t *port, u32 slot, const vnet_dev_hw_addr_t *addr)
{
  vnet_dev_t *dev = port->dev;
  cdn_device_t *cd = vnet_dev_get_data (dev);
  u32 bottom = 0;
  u32 top = 0;

  clib_memcpy_fast (&bottom, addr->eth_mac, sizeof (bottom));
  clib_memcpy_fast (&top, addr->eth_mac + sizeof (bottom), sizeof (u16));

  /* Write specific address bottom first, which temporarily deactivates the filter. */
  cdn_reg_wr (dev, cd, cdn_sa_bottom_reg (slot), bottom);
  /* Write specific address top second to reactivate the filter. */
  cdn_reg_wr (dev, cd, cdn_sa_top_reg (slot), top);
}

static void
cdn_port_clear_hw_addr_slot (vnet_dev_port_t *port, u32 slot)
{
  vnet_dev_t *dev = port->dev;
  cdn_device_t *cd = vnet_dev_get_data (dev);

  /* Clear specific address bottom first to deactivate the filter. */
  cdn_reg_wr (dev, cd, cdn_sa_bottom_reg (slot), 0);
  /* Clear specific address top second to keep the slot empty. */
  cdn_reg_wr (dev, cd, cdn_sa_top_reg (slot), 0);
}

static void
cdn_port_write_primary_hw_addr (vnet_dev_port_t *port, const vnet_dev_hw_addr_t *addr)
{
  vnet_dev_t *dev = port->dev;

  cdn_port_write_hw_addr_slot (port, 0, addr);
  log_debug (dev, "primary mac %U", format_vnet_dev_hw_addr, addr);
}

static vnet_dev_rv_t
cdn_port_add_secondary_hw_addr (vnet_dev_port_t *port, const vnet_dev_hw_addr_t *addr)
{
  vnet_dev_t *dev = port->dev;
  cdn_port_t *cp = vnet_dev_get_port_data (port);
  u32 free_slot = ~0;
  u32 i;

  for (i = 0; i < ARRAY_LEN (cp->secondary_hw_addr); i++)
    {
      if (cp->secondary_hw_addr_valid[i])
	{
	  if (cdn_port_hw_addr_equal (&cp->secondary_hw_addr[i], addr))
	    return VNET_DEV_ERR_ALREADY_EXISTS;
	}
      else if (free_slot == ~0)
	free_slot = i;
    }

  if (free_slot == ~0)
    return VNET_DEV_ERR_RESOURCE_NOT_AVAILABLE;

  cp->secondary_hw_addr[free_slot] = *addr;
  cp->secondary_hw_addr_valid[free_slot] = 1;
  cdn_port_write_hw_addr_slot (port, free_slot + 1, addr);
  log_debug (dev, "secondary mac[%u] %U added", free_slot + 1, format_vnet_dev_hw_addr, addr);
  return VNET_DEV_OK;
}

static vnet_dev_rv_t
cdn_port_remove_secondary_hw_addr (vnet_dev_port_t *port, const vnet_dev_hw_addr_t *addr)
{
  vnet_dev_t *dev = port->dev;
  cdn_port_t *cp = vnet_dev_get_port_data (port);
  u32 i;

  for (i = 0; i < ARRAY_LEN (cp->secondary_hw_addr); i++)
    {
      if (cp->secondary_hw_addr_valid[i] == 0)
	continue;
      if (cdn_port_hw_addr_equal (&cp->secondary_hw_addr[i], addr) == 0)
	continue;

      cp->secondary_hw_addr_valid[i] = 0;
      cp->secondary_hw_addr[i] = (vnet_dev_hw_addr_t){};
      cdn_port_clear_hw_addr_slot (port, i + 1);
      log_debug (dev, "secondary mac[%u] %U removed", i + 1, format_vnet_dev_hw_addr, addr);
      return VNET_DEV_OK;
    }

  return VNET_DEV_ERR_NOT_SUPPORTED;
}

static_always_inline void
cdn_rxq_refill_no_wrap (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq, cdn_rxq_t *crq, u16 off, u16 n)
{
  vnet_dev_t *dev = rxq->port->dev;
  u8 bpi = vnet_dev_get_rx_queue_buffer_pool_index (rxq);
  u32 n_alloc;

  n_alloc = vlib_buffer_alloc_from_pool (vm, crq->buffer_indices + off, n, bpi);
  for (u32 i = 0; i < n_alloc; i++)
    {
      vlib_buffer_t *b = vlib_get_buffer (vm, crq->buffer_indices[off + i]);
      u64 dma_addr = vnet_dev_get_dma_addr (vm, dev, b->data);

      u32 addr_lo = cdn_dma_addr_lo (dma_addr);

      if (off + i == rxq->size - 1)
	addr_lo |= 1 << 1;

      crq->descs[off + i].ctrl.as_u32 = 0;
      crq->descs[off + i].addrh = cdn_dma_addr_hi (dma_addr);
      crq->descs[off + i].resvd = 0;
      __atomic_store_n (&crq->descs[off + i].addr.as_u32, addr_lo, __ATOMIC_RELEASE);
    }

  crq->tail += n_alloc;
}

static void
cdn_port_restart_hw (vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  cdn_device_t *cd = vnet_dev_get_data (dev);
  cdn_dcfg1_t dcfg1 = {
    .as_u32 = cdn_reg_rd (dev, cd, CDN_DCFG1),
  };
  cdn_ncr_t ncr = {
    .as_u32 = cdn_reg_rd (dev, cd, CDN_NCR),
  };

  foreach_vnet_dev_port_rx_queue (rxq, port)
    {
      /* Mask RX queue interrupts before restarting the datapath. */
      cdn_reg_wr (dev, cd, cdn_idr_reg (rxq->queue_id), ~0);
      cdn_reg_rd (dev, cd, cdn_isr_reg (rxq->queue_id));
      if (dcfg1.irqcor == 0)
	{
	  /* Clear any pending RX queue interrupt state. */
	  cdn_reg_wr (dev, cd, cdn_isr_reg (rxq->queue_id), ~0);
	}
    }

  foreach_vnet_dev_port_tx_queue (txq, port)
    {
      /* Mask TX queue interrupts before restarting the datapath. */
      cdn_reg_wr (dev, cd, cdn_idr_reg (txq->queue_id), ~0);
      cdn_reg_rd (dev, cd, cdn_isr_reg (txq->queue_id));
      if (dcfg1.irqcor == 0)
	{
	  /* Clear any pending TX queue interrupt state. */
	  cdn_reg_wr (dev, cd, cdn_isr_reg (txq->queue_id), ~0);
	}
    }

  ncr.re = 0;
  ncr.te = 0;
  ncr.clrstat = 1;
  /* Disable RX/TX and request hardware statistics clear. */
  cdn_reg_wr (dev, cd, CDN_NCR, ncr.as_u32);
  /* Clear any sticky TX status before reprogramming queues. */
  cdn_reg_wr (dev, cd, CDN_TSR, ~0);
  /* Clear any sticky RX status before reprogramming queues. */
  cdn_reg_wr (dev, cd, CDN_RSR, ~0);
}

static void
cdn_port_update_mac_config (vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  cdn_device_t *cd = vnet_dev_get_data (dev);
  cdn_dcfg1_t dcfg1 = {
    .as_u32 = cdn_reg_rd (dev, cd, CDN_DCFG1),
  };
  cdn_ncfgr_t ncfgr = {
    .as_u32 = cdn_reg_rd (dev, cd, CDN_NCFGR),
  };
  cdn_ncr_t ncr = {
    .as_u32 = cdn_reg_rd (dev, cd, CDN_NCR),
  };

  ncfgr.pcssel = 0;
  ncfgr.sgmii_en = 0;
  ncfgr.caf = 0;
  ncfgr.mti = 1;
  ncfgr.rxcoen = 1;
  ncr.enable_hs_mac = 0;

  log_debug (dev, "phy-mode %u no-pcs %u promisc %u max-rx-frame-size %u", cd->phy_mode,
	     dcfg1.no_pcs, port->promisc, port->max_rx_frame_size);

  if (!dcfg1.no_pcs)
    {
      if (cd->phy_mode == CDN_PHY_MODE_SGMII)
	{
	  ncfgr.pcssel = 1;
	  ncfgr.sgmii_en = 1;
	  log_debug (dev, "enabling PCSSEL and SGMIIEN");
	}
      else if (cd->phy_mode == CDN_PHY_MODE_10GBASER)
	{
	  ncfgr.pcssel = 1;
	  ncr.enable_hs_mac = 1;
	  log_debug (dev, "enabling PCSSEL and ENABLE_HS_MAC");
	}
      else
	log_debug (dev, "pcs present but phy-mode unknown, leaving PCS bits clear");
    }
  else
    log_debug (dev, "pcs not present");

  if (port->promisc)
    ncfgr.caf = 1;
  if (port->max_rx_frame_size > 1518)
    ncfgr.jframe = 1;

  /* Program the MAC operating mode without disturbing preserved defaults. */
  cdn_reg_wr (dev, cd, CDN_NCFGR, ncfgr.as_u32);
  /* Apply the matching PCS/high-speed MAC control bits. */
  cdn_reg_wr (dev, cd, CDN_NCR, ncr.as_u32);
  if (ncfgr.jframe)
    /* Set the jumbo frame limit when jumbo mode is enabled. */
    cdn_reg_wr (dev, cd, CDN_JML, port->max_rx_frame_size);
}

static void
cdn_port_setup_pcs (vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  cdn_device_t *cd = vnet_dev_get_data (dev);
  cdn_dcfg1_t dcfg1 = {
    .as_u32 = cdn_reg_rd (dev, cd, CDN_DCFG1),
  };

  if (dcfg1.no_pcs)
    {
      log_debug (dev, "skipping PCS setup, no PCS present");
      return;
    }

  if (cd->phy_mode == CDN_PHY_MODE_SGMII)
    {
      cdn_pcscntrl_t pcsctrl = {
	.as_u32 = cdn_reg_rd (dev, cd, CDN_PCSCNTRL),
      };
      cdn_pcssts_t pcssts = {
	.as_u32 = cdn_reg_rd (dev, cd, CDN_PCSSTS),
      };

      log_debug (dev, "initial PCSCNTRL 0x%08x PCSSTS 0x%08x lnksta %u anc %u", pcsctrl.as_u32,
		 pcssts.as_u32, pcssts.lnksta, pcssts.anc);
      pcsctrl.enan = 1;
      /* Enable PCS autonegotiation before checking whether a restart is needed. */
      cdn_reg_wr (dev, cd, CDN_PCSCNTRL, pcsctrl.as_u32);
      if (pcssts.lnksta && pcssts.anc)
	{
	  log_debug (dev, "skipping REAN, PCS already linked and autoneg complete");
	  return;
	}
      pcsctrl.as_u32 = cdn_reg_rd (dev, cd, CDN_PCSCNTRL);
      pcsctrl.rean = 1;
      /* Restart PCS autonegotiation when the link is not already settled. */
      cdn_reg_wr (dev, cd, CDN_PCSCNTRL, pcsctrl.as_u32);
      pcssts.as_u32 = cdn_reg_rd (dev, cd, CDN_PCSSTS);
      log_debug (dev, "after PCS setup PCSSTS 0x%08x lnksta %u anc %u", pcssts.as_u32,
		 pcssts.lnksta, pcssts.anc);
    }
  else if (cd->phy_mode == CDN_PHY_MODE_10GBASER)
    log_debug (dev, "skipping SGMII PCS setup for 10gbase-r");
  else
    log_debug (dev, "skipping PCS setup, unknown phy-mode");
}

static void
cdn_port_setup_sgmii_speed (vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  cdn_device_t *cd = vnet_dev_get_data (dev);
  cdn_ncfgr_t ncfgr = {
    .as_u32 = cdn_reg_rd (dev, cd, CDN_NCFGR),
  };

  if (cd->phy_mode != CDN_PHY_MODE_SGMII)
    return;

  log_debug (dev, "initial NCFGR for SGMII speed setup 0x%08x", ncfgr.as_u32);
  ncfgr.gbe = 1;
  ncfgr.spd = 0;
  ncfgr.fd = 1;
  /* Force the MAC-facing SGMII speed bits to 1G full duplex. */
  cdn_reg_wr (dev, cd, CDN_NCFGR, ncfgr.as_u32);
}

static vnet_dev_rv_t
cdn_port_start_rx_queues (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  cdn_device_t *cd = vnet_dev_get_data (dev);

  foreach_vnet_dev_port_rx_queue (rxq, port)
    {
      cdn_rxq_t *crq = vnet_dev_get_rx_queue_data (rxq);
      u64 dma_addr;
      cdn_dmacfg_t dmacfg = {};

      crq->head = 0;
      crq->tail = 0;

      cdn_rxq_refill_no_wrap (vm, rxq, crq, 0, rxq->size);
      if (crq->tail == 0)
	return VNET_DEV_ERR_BUFFER_ALLOC_FAIL;

      dma_addr = vnet_dev_get_dma_addr (vm, dev, crq->descs);
      /* Program the RX descriptor ring high address. */
      cdn_reg_wr (dev, cd, crq->rbqph_reg, cdn_dma_addr_hi (dma_addr));
      /* Program the RX descriptor ring base address. */
      cdn_reg_wr (dev, cd, crq->rbqp_reg, cdn_dma_addr_lo (dma_addr));

      if (rxq->queue_id)
	{
	  /* Program the non-default RX queue buffer size encoding. */
	  cdn_reg_wr (dev, cd, crq->rbqs_reg, cdn_rx_buffer_size_code (CDN_RX_BUFFER_SIZE));
	}
      else
	{
	  dmacfg.as_u32 = CDN_DMACFG_INIT;
	  dmacfg.fbldo = 0x10;
	  dmacfg.rxbs = cdn_rx_buffer_size_code (CDN_RX_BUFFER_SIZE);
	  dmacfg.addr64 = 1;
	  /* Program RX burst length, buffer size, and 64-bit DMA mode. */
	  cdn_reg_wr (dev, cd, CDN_DMACFG, dmacfg.as_u32);
	}

      /* Keep RX queue interrupts masked in polling mode. */
      cdn_reg_wr (dev, cd, cdn_idr_reg (rxq->queue_id), ~0);
      cdn_reg_rd (dev, cd, cdn_isr_reg (rxq->queue_id));
    }

  return VNET_DEV_OK;
}

static void
cdn_port_stop_rx_queues (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  cdn_device_t *cd = vnet_dev_get_data (dev);

  foreach_vnet_dev_port_rx_queue (rxq, port)
    {
      cdn_rxq_t *crq = vnet_dev_get_rx_queue_data (rxq);

      /* Keep RX queue interrupts masked while stopping the queue. */
      cdn_reg_wr (dev, cd, cdn_idr_reg (rxq->queue_id), ~0);
      cdn_reg_rd (dev, cd, cdn_isr_reg (rxq->queue_id));
      /* Detach the RX descriptor ring base on stop. */
      cdn_reg_wr (dev, cd, crq->rbqp_reg, 1);
      /* Clear the RX descriptor ring high address on stop. */
      cdn_reg_wr (dev, cd, crq->rbqph_reg, 0);

      vlib_buffer_free_from_ring_no_next (vm, crq->buffer_indices, 0, rxq->size, rxq->size);

      crq->head = 0;
      crq->tail = 0;
    }
}

static void
cdn_port_start_tx_queues (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  cdn_device_t *cd = vnet_dev_get_data (dev);

  foreach_vnet_dev_port_tx_queue (txq, port)
    {
      cdn_txq_t *ctq = vnet_dev_get_tx_queue_data (txq);
      u64 dma_addr;
      u16 last;
      u16 i;

      ctq->head = 0;
      ctq->tail = 0;

      last = txq->size - 1;
      for (i = 0; i < txq->size; i++)
	{
	  ctq->descs[i].addr = 0;
	  ctq->descs[i].addrh = 0;
	  ctq->descs[i].resvd = 0;
	  ctq->descs[i].ctrl.as_u32 = (1u << 31) | ((i == last) << 30);
	}

      dma_addr = vnet_dev_get_dma_addr (vm, dev, ctq->descs);
      /* Program the TX descriptor ring high address. */
      cdn_reg_wr (dev, cd, ctq->tbqph_reg, cdn_dma_addr_hi (dma_addr));
      /* Program the TX descriptor ring base address. */
      cdn_reg_wr (dev, cd, ctq->tbqp_reg, cdn_dma_addr_lo (dma_addr));
      /* Keep TX queue interrupts masked in polling mode. */
      cdn_reg_wr (dev, cd, cdn_idr_reg (txq->queue_id), ~0);
      cdn_reg_rd (dev, cd, cdn_isr_reg (txq->queue_id));
    }
}

static void
cdn_port_stop_tx_queues (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  cdn_device_t *cd = vnet_dev_get_data (dev);

  foreach_vnet_dev_port_tx_queue (txq, port)
    {
      cdn_txq_t *ctq = vnet_dev_get_tx_queue_data (txq);
      u16 mask = txq->size - 1;
      u16 start = ctq->head & mask;
      u16 n_free = ctq->tail - ctq->head;

      /* Keep TX queue interrupts masked while stopping the queue. */
      cdn_reg_wr (dev, cd, cdn_idr_reg (txq->queue_id), ~0);
      cdn_reg_rd (dev, cd, cdn_isr_reg (txq->queue_id));
      /* Detach the TX descriptor ring base on stop. */
      cdn_reg_wr (dev, cd, ctq->tbqp_reg, 1);
      /* Clear the TX descriptor ring high address on stop. */
      cdn_reg_wr (dev, cd, ctq->tbqph_reg, 0);

      if (n_free)
	vlib_buffer_free_from_ring_no_next (vm, ctq->buffer_indices, start, txq->size, n_free);

      ctq->head = 0;
      ctq->tail = 0;
    }
}

static void
cdn_port_status_poll (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  cdn_device_t *cd = vnet_dev_get_data (dev);
  cdn_port_t *cp = vnet_dev_get_port_data (port);
  cdn_nsr_t nsr = {
    .as_u32 = cdn_reg_rd_nolog (cd, CDN_NSR),
  };

  if (cp->link_up != nsr.link)
    {
      log_debug (dev, "link state changed to %s (nsr 0x%08x mdio %u idle %u mfd %u)",
		 nsr.link ? "up" : "down", nsr.as_u32, nsr.mdio, nsr.idle, nsr.mfd);
      cp->link_up = nsr.link;
      vnet_dev_port_state_change (vm, port,
				  (vnet_dev_port_state_changes_t){
				    .change.link_state = 1,
				    .link_state = nsr.link,
				  });
    }
}

vnet_dev_rv_t
cdn_port_init (vlib_main_t *vm __clib_unused, vnet_dev_port_t *port)
{
  cdn_port_t *cp = vnet_dev_get_port_data (port);
  vnet_dev_rv_t rv;

  cp->link_up = 0;

  rv = cdn_port_counters_init (vm, port);
  if (rv != VNET_DEV_OK)
    return rv;

  cdn_port_write_primary_hw_addr (port, &port->primary_hw_addr);

  return rv;
}

vnet_dev_rv_t
cdn_port_start (vlib_main_t *vm __clib_unused, vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  cdn_device_t *cd = vnet_dev_get_data (dev);
  cdn_ncr_t ncr = {};
  vnet_dev_rv_t rv;

  log_debug (dev, "start begin");
  cdn_reg_rd (dev, cd, CDN_NCR);
  cdn_reg_rd (dev, cd, CDN_NCFGR);
  cdn_reg_rd (dev, cd, CDN_DMACFG);
  cdn_reg_rd (dev, cd, CDN_PCSCNTRL);
  cdn_reg_rd (dev, cd, CDN_PCSSTS);
  cdn_port_restart_hw (port);
  cdn_port_update_mac_config (port);
  cdn_port_setup_sgmii_speed (port);
  cdn_port_setup_pcs (port);
  /* Clear sticky TX status once more just before enabling traffic. */
  cdn_reg_wr (dev, cd, CDN_TSR, ~0);
  /* Clear sticky RX status once more just before enabling traffic. */
  cdn_reg_wr (dev, cd, CDN_RSR, ~0);
  rv = cdn_port_start_rx_queues (vm, port);
  if (rv != VNET_DEV_OK)
    return rv;
  cdn_port_start_tx_queues (vm, port);
  ncr.as_u32 = cdn_reg_rd (dev, cd, CDN_NCR);
  ncr.re = 1;
  ncr.te = 1;
  /* Enable RX and TX after queues and PCS are ready. */
  cdn_reg_wr (dev, cd, CDN_NCR, ncr.as_u32);
  log_debug (dev, "start end");
  cdn_reg_rd (dev, cd, CDN_NCR);
  cdn_reg_rd (dev, cd, CDN_NCFGR);
  cdn_reg_rd (dev, cd, CDN_DMACFG);
  cdn_reg_rd (dev, cd, CDN_PCSCNTRL);
  cdn_reg_rd (dev, cd, CDN_PCSSTS);
  vnet_dev_poll_port_add (vm, port, 1, cdn_port_status_poll);
  vnet_dev_poll_port_add (vm, port, 1, cdn_port_counter_poll);

  return VNET_DEV_OK;
}

void
cdn_port_stop (vlib_main_t *vm __clib_unused, vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  cdn_device_t *cd = vnet_dev_get_data (dev);
  cdn_port_t *cp = vnet_dev_get_port_data (port);
  cdn_ncr_t ncr = {};

  log_debug (dev, "stop begin");
  cdn_reg_rd (dev, cd, CDN_NCR);
  cdn_reg_rd (dev, cd, CDN_NCFGR);
  cdn_reg_rd (dev, cd, CDN_DMACFG);
  cdn_reg_rd (dev, cd, CDN_PCSCNTRL);
  cdn_reg_rd (dev, cd, CDN_PCSSTS);
  vnet_dev_poll_port_remove (vm, port, cdn_port_status_poll);
  vnet_dev_poll_port_remove (vm, port, cdn_port_counter_poll);
  ncr.as_u32 = cdn_reg_rd (dev, cd, CDN_NCR);
  ncr.re = 0;
  ncr.te = 0;
  /* Disable RX and TX before tearing down queues. */
  cdn_reg_wr (dev, cd, CDN_NCR, ncr.as_u32);
  /* Clear any sticky TX status on shutdown. */
  cdn_reg_wr (dev, cd, CDN_TSR, ~0);
  /* Clear any sticky RX status on shutdown. */
  cdn_reg_wr (dev, cd, CDN_RSR, ~0);
  cdn_port_stop_rx_queues (vm, port);
  cdn_port_stop_tx_queues (vm, port);
  cp->link_up = 0;
  log_debug (dev, "stop end");
  cdn_reg_rd (dev, cd, CDN_NCR);
  cdn_reg_rd (dev, cd, CDN_NCFGR);
  cdn_reg_rd (dev, cd, CDN_DMACFG);
  cdn_reg_rd (dev, cd, CDN_PCSCNTRL);
  cdn_reg_rd (dev, cd, CDN_PCSSTS);
}

void
cdn_port_clear_counters (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  cdn_device_t *cd = vnet_dev_get_data (dev);
  cdn_ncr_t ncr = {};

  ncr.as_u32 = cdn_reg_rd (dev, cd, CDN_NCR);
  ncr.clrstat = 1;
  /* Clear the hardware statistics block on explicit counter reset. */
  cdn_reg_wr (dev, cd, CDN_NCR, ncr.as_u32);

  if (port->counter_main)
    vnet_dev_counters_clear (vm, port->counter_main);
}

vnet_dev_rv_t
cdn_port_cfg_change_validate (vlib_main_t *vm __clib_unused, vnet_dev_port_t *port,
			      vnet_dev_port_cfg_change_req_t *req)
{
  switch (req->type)
    {
    case VNET_DEV_PORT_CFG_MAX_RX_FRAME_SIZE:
      return port->started ? VNET_DEV_ERR_PORT_STARTED : VNET_DEV_OK;

    case VNET_DEV_PORT_CFG_PROMISC_MODE:
    case VNET_DEV_PORT_CFG_CHANGE_PRIMARY_HW_ADDR:
    case VNET_DEV_PORT_CFG_ADD_SECONDARY_HW_ADDR:
    case VNET_DEV_PORT_CFG_REMOVE_SECONDARY_HW_ADDR:
      return VNET_DEV_OK;

    default:
      return VNET_DEV_ERR_NOT_SUPPORTED;
    }
}

vnet_dev_rv_t
cdn_port_cfg_change (vlib_main_t *vm __clib_unused, vnet_dev_port_t *port,
		     vnet_dev_port_cfg_change_req_t *req)
{
  switch (req->type)
    {
    case VNET_DEV_PORT_CFG_MAX_RX_FRAME_SIZE:
      cdn_port_update_mac_config (port);
      return VNET_DEV_OK;

    case VNET_DEV_PORT_CFG_PROMISC_MODE:
      if (port->started)
	cdn_port_update_mac_config (port);
      return VNET_DEV_OK;

    case VNET_DEV_PORT_CFG_CHANGE_PRIMARY_HW_ADDR:
      cdn_port_write_primary_hw_addr (port, &req->addr);
      return VNET_DEV_OK;

    case VNET_DEV_PORT_CFG_ADD_SECONDARY_HW_ADDR:
      return cdn_port_add_secondary_hw_addr (port, &req->addr);

    case VNET_DEV_PORT_CFG_REMOVE_SECONDARY_HW_ADDR:
      return cdn_port_remove_secondary_hw_addr (port, &req->addr);

    default:
      return VNET_DEV_ERR_NOT_SUPPORTED;
    }
}
