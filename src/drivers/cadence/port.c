/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vnet/dev/counters.h>

#include <cadence.h>

VLIB_REGISTER_LOG_CLASS (cdn_port_log, static) = {
  .class_name = "cadence",
  .subclass_name = "port",
};

#define CDN_RX_BUFFER_SIZE 2048

static_always_inline u32
cdn_rx_buffer_size_code (u16 buffer_size)
{
  ASSERT (buffer_size % 64 == 0);
  return buffer_size / 64;
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
cdn_port_update_mac_config (vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  cdn_device_t *cd = vnet_dev_get_data (dev);
  cdn_dcfg1_t dcfg1 = {
    .as_u32 = cdn_readl (cd, CDN_DCFG1),
  };
  cdn_ncfgr_t ncfgr = {
    .as_u32 = cdn_readl (cd, CDN_NCFGR),
  };
  cdn_ncr_t ncr = {
    .as_u32 = cdn_readl (cd, CDN_NCR),
  };

  ncfgr.fd = 1;
  ncfgr.mti = 1;
  ncfgr.drfcs = 1;
  ncfgr.dbw = 1;
  ncfgr.dis_cp_pause = 1;
  ncfgr.rbof = 0;
  ncfgr.rxcoen = 0;
  ncfgr.caf = port->promisc;
  ncfgr.jframe = port->max_rx_frame_size > 1518;
  ncfgr.big = ncfgr.jframe == 0;
  ncfgr.pcssel = 0;
  ncfgr.sgmii_en = 0;
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

  log_debug (dev, "writing NCFGR 0x%08x NCR 0x%08x", ncfgr.as_u32, ncr.as_u32);
  cdn_writel (cd, CDN_NCFGR, ncfgr.as_u32);
  cdn_writel (cd, CDN_NCR, ncr.as_u32);
  if (ncfgr.jframe)
    cdn_writel (cd, CDN_JML, port->max_rx_frame_size);
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
      cdn_writel (cd, crq->rbqph_reg, cdn_dma_addr_hi (dma_addr));
      cdn_writel (cd, crq->rbqp_reg, cdn_dma_addr_lo (dma_addr));

      if (rxq->queue_id)
	cdn_writel (cd, crq->rbqs_reg, cdn_rx_buffer_size_code (CDN_RX_BUFFER_SIZE));
      else
	{
	  dmacfg.as_u32 = cdn_readl (cd, CDN_DMACFG);
	  dmacfg.fbldo = 0x10;
	  dmacfg.rxbs = cdn_rx_buffer_size_code (CDN_RX_BUFFER_SIZE);
	  dmacfg.addr64 = 1;
	  log_debug (dev, "writing DMACFG 0x%08x", dmacfg.as_u32);
	  cdn_writel (cd, CDN_DMACFG, dmacfg.as_u32);
	}

      cdn_writel (cd, cdn_idr_reg (rxq->queue_id), ~0);
      cdn_readl (cd, cdn_isr_reg (rxq->queue_id));
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
      u16 mask = rxq->size - 1;
      u16 start = crq->head & mask;
      u16 n_free = crq->tail - crq->head;

      cdn_writel (cd, cdn_idr_reg (rxq->queue_id), ~0);
      cdn_readl (cd, cdn_isr_reg (rxq->queue_id));
      cdn_writel (cd, crq->rbqp_reg, 1);
      cdn_writel (cd, crq->rbqph_reg, 0);

      if (n_free)
	vlib_buffer_free_from_ring_no_next (vm, crq->buffer_indices, start, rxq->size, n_free);

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
      cdn_writel (cd, ctq->tbqph_reg, cdn_dma_addr_hi (dma_addr));
      cdn_writel (cd, ctq->tbqp_reg, cdn_dma_addr_lo (dma_addr));
      cdn_writel (cd, cdn_idr_reg (txq->queue_id), ~0);
      cdn_readl (cd, cdn_isr_reg (txq->queue_id));
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

      cdn_writel (cd, cdn_idr_reg (txq->queue_id), ~0);
      cdn_readl (cd, cdn_isr_reg (txq->queue_id));
      cdn_writel (cd, ctq->tbqp_reg, 1);
      cdn_writel (cd, ctq->tbqph_reg, 0);

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
    .as_u32 = cdn_readl_nolog (cd, CDN_NSR),
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

  return rv;
}

vnet_dev_rv_t
cdn_port_start (vlib_main_t *vm __clib_unused, vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  cdn_device_t *cd = vnet_dev_get_data (dev);
  cdn_ncr_t ncr = {};
  vnet_dev_rv_t rv;

  cdn_port_update_mac_config (port);
  rv = cdn_port_start_rx_queues (vm, port);
  if (rv != VNET_DEV_OK)
    return rv;
  cdn_port_start_tx_queues (vm, port);
  ncr.as_u32 = cdn_readl (cd, CDN_NCR);
  ncr.re = 1;
  ncr.te = 1;
  cdn_writel (cd, CDN_NCR, ncr.as_u32);
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

  vnet_dev_poll_port_remove (vm, port, cdn_port_status_poll);
  vnet_dev_poll_port_remove (vm, port, cdn_port_counter_poll);
  ncr.as_u32 = cdn_readl (cd, CDN_NCR);
  ncr.re = 0;
  ncr.te = 0;
  cdn_writel (cd, CDN_NCR, ncr.as_u32);
  cdn_port_stop_rx_queues (vm, port);
  cdn_port_stop_tx_queues (vm, port);
  cp->link_up = 0;
}

void
cdn_port_clear_counters (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  cdn_device_t *cd = vnet_dev_get_data (dev);
  cdn_ncr_t ncr = {};

  ncr.as_u32 = cdn_readl (cd, CDN_NCR);
  ncr.clrstat = 1;
  cdn_writel (cd, CDN_NCR, ncr.as_u32);

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

    default:
      return VNET_DEV_ERR_NOT_SUPPORTED;
    }
}
