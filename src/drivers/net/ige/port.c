/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Damjan Marion
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vnet/dev/counters.h>
#include <vnet/dev/bus/pci.h>
#include <ige.h>
#include <vnet/ethernet/ethernet.h>

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

#define IGE_ITR_INTERVAL_US 20
#define IGE_EITR_CNT_IGNR   (1U << 31)
#define IGE_GPIE_MSIX_MODE  (1U << 4)
#define IGE_GPIE_EIAME	    (1U << 30)
#define IGE_GPIE_PBA	    (1U << 31)
#define IGE_IVAR_VALID	    0x80

static void
ige_rx_msix_handler (vlib_main_t *vm __clib_unused, vnet_dev_t *dev, u16 line)
{
  vnet_dev_port_t *port = vnet_dev_get_port_by_id (dev, 0);

  if (!port || !port->interfaces || !port->rx_node_assigned)
    return;

  ige_reg_wr (dev, IGE_REG_EIMS, 1U << line);
  vlib_node_set_interrupt_pending (vlib_get_main_by_index (line - 1),
				   vnet_dev_get_port_rx_node_index (port));
}

static u16
ige_rxq_vector (ige_port_t *ip, vnet_dev_rx_queue_t *rxq)
{
  return clib_min (rxq->rx_thread_index + 1, ip->n_rx_vectors);
}

static void
ige_rx_irq_apply (vnet_dev_port_t *port, vnet_dev_rx_queue_t *target, int override)
{
  ige_port_t *ip = vnet_dev_get_port_data (port);
  u32 all = pow2_mask (ip->n_rx_vectors) << 1;
  u32 mask = 0;

  foreach_vnet_dev_port_rx_queue (q, port)
    {
      int is_intr = q->interrupt_mode;

      if (override >= 0 && (target == 0 || target == q))
	is_intr = override;

      if (is_intr)
	mask |= 1U << ige_rxq_vector (ip, q);
    }

  ige_reg_wr (port->dev, IGE_REG_EIMC, all & ~mask);
  ige_reg_wr (port->dev, IGE_REG_EIMS, mask);
}

static void
ige_rx_irq_map (vnet_dev_port_t *port)
{
  ige_port_t *ip = vnet_dev_get_port_data (port);
  u32 ivar[2] = {};

  foreach_vnet_dev_port_rx_queue (q, port)
    ivar[q->queue_id >> 1] |= (u32) (ige_rxq_vector (ip, q) | IGE_IVAR_VALID)
			      << (16 * (q->queue_id & 1));

  for (u32 i = 0; i < ARRAY_LEN (ivar); i++)
    ige_reg_wr (port->dev, IGE_REG_IVAR (i), ivar[i]);
}

static vnet_dev_rv_t
ige_rss_validate (vnet_dev_port_t *port, const vnet_dev_rss_config_t *config)
{
  if ((config->set_key && config->key_len != IGE_RSS_KEY_SIZE) ||
      (config->set_lut && config->lut_len != IGE_RSS_LUT_SIZE))
    return VNET_DEV_ERR_INVALID_DATA;

  if (config->set_lut)
    for (u32 i = 0; i < IGE_RSS_LUT_SIZE; i++)
      {
	vnet_dev_rx_queue_t *rxq = vnet_dev_get_port_rx_queue_by_id (port, config->lut[i]);

	if (!rxq || !rxq->enabled)
	  return VNET_DEV_ERR_INVALID_VALUE;
      }

  return VNET_DEV_OK;
}

static void
ige_rss_apply (vnet_dev_port_t *port, const vnet_dev_rss_config_t *config)
{
  vnet_dev_t *dev = port->dev;

  if (config->set_key)
    for (u32 i = 0; i < IGE_RSS_KEY_SIZE / 4; i++)
      {
	u32 w;

	clib_memcpy (&w, config->key + i * 4, 4);
	ige_reg_wr (dev, IGE_REG_RSSRK (i), w);
      }

  if (config->set_lut)
    for (u32 i = 0; i < IGE_RSS_LUT_SIZE / 4; i++)
      ige_reg_wr (dev, IGE_REG_RETA (i),
		  config->lut[i * 4] | config->lut[i * 4 + 1] << 8 | config->lut[i * 4 + 2] << 16 |
		    (u32) config->lut[i * 4 + 3] << 24);
}

static void
ige_rss_start (vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  vnet_dev_rss_config_t config = port->rss_config;
  u16 queue_ids[IGE_RSS_LUT_SIZE];
  u32 n_queues = 0;
  ige_reg_mrqc_t mrqc = {
    .mq_enable = 2,
    .ipv4_tcp = 1,
    .ipv4 = 1,
    .ipv6 = 1,
    .ipv6_tcp = 1,
    .ipv4_udp = 1,
    .ipv6_udp = 1,
  };
  ige_reg_rxcsum_t rxcsum;

  foreach_vnet_dev_port_rx_queue (q, port)
    if (q->enabled && n_queues < ARRAY_LEN (queue_ids))
      queue_ids[n_queues++] = q->queue_id;

  if (n_queues == 0)
    return;

  if (config.set_lut && ige_rss_validate (port, &config) != VNET_DEV_OK)
    config.set_lut = 0;

  if (!config.set_lut)
    {
      for (u32 i = 0; i < IGE_RSS_LUT_SIZE; i++)
	config.lut[i] = queue_ids[i % n_queues];

      config.set_lut = 1;
    }

  ige_rss_apply (port, &config);

  ige_reg_rd (dev, IGE_REG_RXCSUM, &rxcsum.as_u32);
  rxcsum.pcsd = 1;
  ige_reg_wr (dev, IGE_REG_RXCSUM, rxcsum.as_u32);
  ige_reg_wr (dev, IGE_REG_MRQC, mrqc.as_u32);
}

vnet_dev_rv_t
ige_port_init (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  ige_port_t *ip = vnet_dev_get_port_data (port);
  vnet_dev_rv_t rv;

  log_debug (dev, "port %u", port->port_id);

  rv = ige_port_counters_init (vm, port);
  if (rv != VNET_DEV_OK)
    return rv;

  if (port->attr.caps.interrupt_mode)
    {
      u32 vectors;

      ip->n_rx_vectors = vlib_get_n_threads ();
      vectors = pow2_mask (ip->n_rx_vectors) << 1;

      rv = vnet_dev_pci_msix_add_handler (vm, dev, &ige_rx_msix_handler, 1, ip->n_rx_vectors);
      if (rv != VNET_DEV_OK)
	return rv;

      ip->irq_registered = 1;

      rv = vnet_dev_pci_msix_enable (vm, dev, 1, ip->n_rx_vectors);
      if (rv != VNET_DEV_OK)
	return rv;

      for (u16 i = 0; i < ip->n_rx_vectors; i++)
	{
	  vnet_dev_pci_msix_set_polling_thread (vm, dev, i + 1, i);
	  ige_reg_wr (dev, IGE_REG_EITR (i + 1), (IGE_ITR_INTERVAL_US * 4) | IGE_EITR_CNT_IGNR);
	}

      ige_reg_wr (dev, IGE_REG_GPIE, IGE_GPIE_MSIX_MODE | IGE_GPIE_EIAME | IGE_GPIE_PBA);
      ige_reg_wr (dev, IGE_REG_EIAC, vectors);
      ige_reg_wr (dev, IGE_REG_EIAM, vectors);
    }

  return VNET_DEV_OK;
}

void
ige_port_deinit (vlib_main_t *vm, vnet_dev_port_t *port)
{
  ige_port_t *ip = vnet_dev_get_port_data (port);
  vnet_dev_rv_t rv;

  if (!ip->irq_registered)
    return;

  /* coverity[tainted_data] - n_rx_vectors is set at port init */
  rv = vnet_dev_pci_msix_disable (vm, port->dev, 1, ip->n_rx_vectors);
  if (rv == VNET_DEV_OK)
    rv = vnet_dev_pci_msix_remove_handler (vm, port->dev, 1, ip->n_rx_vectors);

  if (rv != VNET_DEV_OK)
    log_err (port->dev, "port %u RX interrupt cleanup failed: %U", port->port_id,
	     format_vnet_dev_rv, rv);
  else
    ip->irq_registered = 0;
}

static vnet_dev_rv_t
ige_change_primary_hw_addr (vlib_main_t *vm, vnet_dev_port_t *port,
			    const vnet_dev_hw_addr_t *hw_addr)
{
  vnet_dev_t *dev = port->dev;
  ige_receive_addr_t ra = {
    .av = 1,
  };

  clib_memcpy (ra.hw_addr, hw_addr->eth_mac, sizeof (ra.hw_addr));

  ige_reg_wr (dev, IGE_REG_RAH (0), ra.rah);
  ige_reg_wr (dev, IGE_REG_RAL (0), ra.ral);

  log_debug (dev, "receive addr table:\n%U", format_ige_receive_addr_table, dev);
  return VNET_DEV_OK;
}

vnet_dev_rv_t
ige_port_start (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  ige_device_t *id = vnet_dev_get_data (port->dev);
  ige_port_t *ip = vnet_dev_get_port_data (port);
  ige_rxq_t *iq;
  ige_txq_t *tq;
  ige_reg_rctl_t rctl;
  ige_reg_tctl_t tctl;
  vnet_dev_rv_t rv = VNET_DEV_OK;

  log_debug (dev, "port %u", port->port_id);

  if ((rv = ige_phy_set_power (vm, dev, 1)) != VNET_DEV_OK)
    return rv;

  ip->last_status.as_u32 = 0;
  ige_change_primary_hw_addr (vm, port, &port->primary_hw_addr);

  ige_reg_rd (dev, IGE_REG_RCTL, &rctl.as_u32);
  if (rctl.rx_enable)
    {
      log_warn (dev, "port %u rx is unexpectedly enabled", port->port_id);
      rctl.rx_enable = 0;
      ige_reg_wr (dev, IGE_REG_RCTL, rctl.as_u32);
    }

  ige_reg_rd (dev, IGE_REG_TCTL, &tctl.as_u32);
  if (tctl.tx_enable)
    {
      log_warn (dev, "port %u tx is unexpectedly enabled", port->port_id);
      tctl.tx_enable = 0;
      ige_reg_wr (dev, IGE_REG_TCTL, tctl.as_u32);
    }

  foreach_vnet_dev_port_rx_queue (rxq, port)
    {
      u32 buf_size = vnet_dev_get_rx_queue_buffer_data_size (vm, rxq);
      if (buf_size < 1024)
	{
	  log_err (dev, "rx buffer data size %u is too small (min 1024)", buf_size);
	  rv = VNET_DEV_ERR_BUFFER_ALLOC_FAIL;
	  goto error;
	}

      const ige_reg_srrctl_t srrctl = {
	.drop_en = 1,
	.desc_type = 1, /* advanced, no header */
	.bsizepacket = clib_min (buf_size / 1024, 16),
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

      /* Ensure the queue starts with buffers posted. */
      u16 n_posted = ige_rxq_refill_no_wrap (
	vm, iq->buffer_indices, iq->descs, rxq->size,
	vnet_dev_get_rx_queue_buffer_pool_index (rxq), dev->va_dma);

      iq->tail = n_posted;

      if (iq->tail == 0)
	{
	  rv = VNET_DEV_ERR_BUFFER_ALLOC_FAIL;
	  goto error;
	}

      __atomic_store_n (iq->reg_rdt, (u32) iq->tail, __ATOMIC_RELEASE);
    }

  foreach_vnet_dev_port_tx_queue (txq, port)
    {
      u64 dma_addr;
      u64 wb_dma;
      u16 q = txq->queue_id;
      ige_reg_txctl_t txctl;

      ige_txq_t *tq = vnet_dev_get_tx_queue_data (txq);
      ASSERT (tq->wb != 0);
      dma_addr = vnet_dev_get_dma_addr (vm, dev, tq->descs);
      wb_dma = vnet_dev_get_dma_addr (vm, dev, tq->wb);

      ige_reg_wr (dev, IGE_REG_TDLEN (q), txq->size * sizeof (ige_tx_desc_t));
      ige_reg_wr (dev, IGE_REG_TDBAH (q), dma_addr >> 32);
      ige_reg_wr (dev, IGE_REG_TDBAL (q), dma_addr);
      ige_reg_wr (dev, IGE_REG_TDWBAH (q), wb_dma >> 32);
      ige_reg_wr (dev, IGE_REG_TDWBAL (q),
		  ((u32) wb_dma & ~0x3u) | IGE_TDWBAL_HEAD_WB_ENABLE);

      *tq->wb = 0;

      tq->head = tq->tail = 0;
      tq->reg_tdt = (u32 *) ((u8 *) id->bar0 + IGE_REG_TDT (q));

      ige_reg_wr (dev, IGE_REG_TDH (q), 0);
      ige_reg_wr (dev, IGE_REG_TDT (q), 0);

      ige_reg_txdctl_t txdctl = {
	.pthresh = 8,
	.hthresh = 1,
	.wthresh = 1,
	.enable = 1,
      };

      ige_reg_wr (dev, IGE_REG_TXDCTL (q), txdctl.as_u32);
      ige_reg_rd (dev, IGE_REG_TXCTL (q), &txctl.as_u32);
      txctl.tx_desc_wb_relax_order_en = 0;
      ige_reg_wr (dev, IGE_REG_TXCTL (q), txctl.as_u32);
    }

  ige_rss_start (port);

  rctl.rx_enable = 1;
  rctl.store_bad_packets = 0;
  rctl.strip_eth_crc = 1;
  rctl.long_pkt_reception_ena = 1;
  rctl.vlan_filter_ena = 0;
  rctl.bcast_accept_mode = 1;
  rctl.mc_promisc_ena = 1;
  rctl.discard_pause_frames = 1;
  ige_reg_wr (dev, IGE_REG_RCTL, rctl.as_u32);
  ige_reg_wr (dev, IGE_REG_RLPML, port->max_rx_frame_size);

  tctl.tx_enable = 1;
  tctl.pad_short_pkts = 1;
  ige_reg_wr (dev, IGE_REG_TCTL, tctl.as_u32);

  foreach_vnet_dev_port_rx_queue (rxq, port)
    {
      u16 q = rxq->queue_id;

      ige_rxq_t *iq = vnet_dev_get_rx_queue_data (rxq);
      ige_reg_wr (dev, IGE_REG_RDH (q), 0);
      ige_reg_wr (dev, IGE_REG_RDT (q), iq->tail);
    }

  if (port->attr.caps.interrupt_mode)
    {
      ige_rx_irq_map (port);
      ige_rx_irq_apply (port, 0, -1);
    }

  vnet_dev_poll_port_add (vm, port, 3, ige_port_counter_poll);
  vnet_dev_poll_port_add (vm, port, 1, ige_port_status_poll);
  return 0;

error:
  foreach_vnet_dev_port_rx_queue (rxq, port)
    {
      iq = vnet_dev_get_rx_queue_data (rxq);
      if (iq->tail)
	{
	  u16 n_buffers = iq->tail - iq->head;
	  u16 mask = rxq->size - 1;
	  u16 start = iq->head & mask;
	  if (n_buffers)
	    vlib_buffer_free_from_ring_no_next (vm, iq->buffer_indices, start,
						rxq->size, n_buffers);
	}
      iq->head = iq->tail = 0;
    }
  foreach_vnet_dev_port_tx_queue (txq, port)
    {
      tq = vnet_dev_get_tx_queue_data (txq);
      if (tq->tail != tq->head)
	{
	  u16 mask = txq->size - 1;
	  u16 start = tq->head & mask;
	  u16 n_buffers = tq->tail - tq->head;

	  if (n_buffers)
	    vlib_buffer_free_from_ring_no_next (vm, tq->buffer_indices, start,
						txq->size, n_buffers);
	}

      tq->head = tq->tail = 0;
      if (tq->reg_tdt)
	{
	  ige_reg_txdctl_t txdctl = {};
	  ige_reg_wr (dev, IGE_REG_TDT (txq->queue_id), 0);
	  ige_reg_rd (dev, IGE_REG_TXDCTL (txq->queue_id), &txdctl.as_u32);
	  txdctl.enable = 0;
	  ige_reg_wr (dev, IGE_REG_TXDCTL (txq->queue_id), txdctl.as_u32);
	  ige_reg_wr (dev, IGE_REG_TDWBAL (txq->queue_id), 0);
	  ige_reg_wr (dev, IGE_REG_TDWBAH (txq->queue_id), 0);
	}
    }
  return rv;
}

void
ige_port_stop (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  log_debug (dev, "port %u", port->port_id);
  ige_reg_rctl_t rctl;
  ige_reg_tctl_t tctl;
  vnet_dev_poll_port_remove (vm, port, ige_port_status_poll);
  vnet_dev_poll_port_remove (vm, port, ige_port_counter_poll);

  if (port->attr.caps.interrupt_mode)
    {
      ige_port_t *ip = vnet_dev_get_port_data (port);

      ige_reg_wr (dev, IGE_REG_EIMC, pow2_mask (ip->n_rx_vectors) << 1);
    }

  ige_reg_rd (dev, IGE_REG_RCTL, &rctl.as_u32);
  rctl.rx_enable = 0;
  ige_reg_wr (dev, IGE_REG_RCTL, rctl.as_u32);

  ige_reg_rd (dev, IGE_REG_TCTL, &tctl.as_u32);
  tctl.tx_enable = 0;
  ige_reg_wr (dev, IGE_REG_TCTL, tctl.as_u32);

  foreach_vnet_dev_port_rx_queue (rxq, port)
    {
      ige_rxq_t *iq = vnet_dev_get_rx_queue_data (rxq);
      u16 n_buffers = iq->tail - iq->head;
      u16 mask = rxq->size - 1;
      u16 q = rxq->queue_id;
      ige_reg_rxdctl_t rxdctl;

      ige_reg_rd (dev, IGE_REG_RXDCTL (q), &rxdctl.as_u32);
      rxdctl.enable = 0;
      ige_reg_wr (dev, IGE_REG_RXDCTL (q), rxdctl.as_u32);
      rxdctl.enable = 1;
      if (!ige_reg_poll (vm, dev, IGE_REG_RXDCTL (q), rxdctl.as_u32, 0, 1e-4, 1e-2))
	log_err (dev, "port %u rx queue %u failed to stop", port->port_id, q);

      if (n_buffers)
	vlib_buffer_free_from_ring_no_next (
	  vm, iq->buffer_indices, iq->head & mask, rxq->size, n_buffers);

      iq->head = iq->tail = 0;
    }

  foreach_vnet_dev_port_tx_queue (txq, port)
    {
      ige_txq_t *tq = vnet_dev_get_tx_queue_data (txq);
      u16 n_buffers = tq->tail - tq->head;
      u16 mask = txq->size - 1;

      if (tq->reg_tdt)
	{
	  ige_reg_txdctl_t txdctl = {};

	  ige_reg_rd (dev, IGE_REG_TXDCTL (txq->queue_id), &txdctl.as_u32);
	  txdctl.enable = 0;
	  ige_reg_wr (dev, IGE_REG_TXDCTL (txq->queue_id), txdctl.as_u32);
	  txdctl.enable = 1;
	  if (!ige_reg_poll (vm, dev, IGE_REG_TXDCTL (txq->queue_id), txdctl.as_u32, 0, 1e-4, 1e-2))
	    log_err (dev, "port %u tx queue %u failed to stop", port->port_id, txq->queue_id);
	}

      if (n_buffers)
	vlib_buffer_free_from_ring_no_next (
	  vm, tq->buffer_indices, tq->head & mask, txq->size, n_buffers);

      tq->head = tq->tail = 0;
      if (tq->reg_tdt)
	{
	  ige_reg_wr (dev, IGE_REG_TDT (txq->queue_id), 0);
	  ige_reg_wr (dev, IGE_REG_TDWBAL (txq->queue_id), 0);
	  ige_reg_wr (dev, IGE_REG_TDWBAH (txq->queue_id), 0);
	}
    }

  /* power down the PHY so the link partner sees link down */
  ige_phy_set_power (vm, dev, 0);
}

static vnet_dev_rv_t
ige_set_promisc_mode (vlib_main_t *vm, vnet_dev_port_t *port, int enabled)
{
  vnet_dev_t *dev = port->dev;
  ige_reg_rctl_t rctl;

  ige_reg_rd (dev, IGE_REG_RCTL, &rctl.as_u32);
  rctl.uc_promisc_ena = enabled;
  ige_reg_wr (dev, IGE_REG_RCTL, rctl.as_u32);
  ige_reg_rd (dev, IGE_REG_RCTL, &rctl.as_u32);
  log_debug (dev, "\n %U", format_ige_reg_read, IGE_REG_RCTL, rctl.as_u32);
  return VNET_DEV_OK;
}

static vnet_dev_rv_t
ige_add_secondary_hw_addr (vlib_main_t *vm, vnet_dev_port_t *port,
			   const vnet_dev_hw_addr_t *hw_addr)
{
  vnet_dev_t *dev = port->dev;
  ige_receive_addr_t ra;
  vnet_dev_rv_t rv = VNET_DEV_OK;
  u32 empty_slot = 0;

  for (u32 i = 0; i < 16; i++)
    {
      ige_reg_rd (dev, IGE_REG_RAH (i), &ra.rah);
      ige_reg_rd (dev, IGE_REG_RAL (i), &ra.ral);
      if (memcmp (ra.hw_addr, hw_addr->eth_mac, sizeof (ra.hw_addr)) == 0)
	{
	  log_err (dev, "address %U already exists in table",
		   format_ethernet_address, hw_addr->eth_mac);
	  rv = VNET_DEV_ERR_ALREADY_EXISTS;
	  goto done;
	}
      if (ra.av == 0 && empty_slot == 0 && i > 0)
	empty_slot = i;
    }

  if (empty_slot == 0)
    {
      log_err (dev, "failed to add secondary hw addr %U, table full",
	       format_ethernet_address, hw_addr->eth_mac);
      rv = VNET_DEV_ERR_RESOURCE_NOT_AVAILABLE;
      goto done;
    }

  ra = (ige_receive_addr_t){ .av = 1 };
  clib_memcpy (ra.hw_addr, hw_addr->eth_mac, sizeof (ra.hw_addr));
  ige_reg_wr (dev, IGE_REG_RAH (empty_slot), ra.rah);
  ige_reg_wr (dev, IGE_REG_RAL (empty_slot), ra.ral);

done:
  log_debug (dev, "receive addr table:\n%U", format_ige_receive_addr_table,
	     dev);
  return rv;
}

static vnet_dev_rv_t
ige_remove_secondary_hw_addr (vlib_main_t *vm, vnet_dev_port_t *port,
			      const vnet_dev_hw_addr_t *hw_addr)
{
  vnet_dev_t *dev = port->dev;
  ige_receive_addr_t ra;
  vnet_dev_rv_t rv = VNET_DEV_OK;

  for (u32 i = 1; i < 16; i++)
    {
      ige_reg_rd (dev, IGE_REG_RAH (i), &ra.rah);
      ige_reg_rd (dev, IGE_REG_RAL (i), &ra.ral);
      if (memcmp (ra.hw_addr, hw_addr->eth_mac, sizeof (ra.hw_addr)) == 0)
	{
	  ige_reg_wr (dev, IGE_REG_RAH (i), 0);
	  ige_reg_wr (dev, IGE_REG_RAL (i), 0);
	  goto done;
	}
    }

  log_err (dev, "failed to remove secondary hw addr %U, not found",
	   format_ethernet_address, hw_addr->eth_mac);
  rv = VNET_DEV_ERR_NOT_FOUND;

done:
  log_debug (dev, "receive addr table:\n%U", format_ige_receive_addr_table,
	     dev);
  return rv;
}

vnet_dev_rv_t
ige_port_cfg_change_validate (vlib_main_t *vm, vnet_dev_port_t *port,
			      vnet_dev_port_cfg_change_req_t *req)
{
  vnet_dev_rv_t rv = VNET_DEV_ERR_NOT_SUPPORTED;
  switch (req->type)
    {
    case VNET_DEV_PORT_CFG_MAX_RX_FRAME_SIZE:
      rv = port->started ? VNET_DEV_ERR_PORT_STARTED : VNET_DEV_OK;
      break;

    case VNET_DEV_PORT_CFG_SET_LINK_SPEED:
      if (req->link_speed == 0 ||
	  (port->attr.speed_caps & vnet_hw_if_speed_from_kbps (req->link_speed)))
	rv = VNET_DEV_OK;
      break;

    case VNET_DEV_PORT_CFG_RXQ_INTR_MODE_ENABLE:
    case VNET_DEV_PORT_CFG_RXQ_INTR_MODE_DISABLE:
      if (port->attr.caps.interrupt_mode)
	rv = VNET_DEV_OK;
      break;

    case VNET_DEV_PORT_CFG_SET_RSS_CONFIG:
      rv = ige_rss_validate (port, &req->rss_config);
      break;

    case VNET_DEV_PORT_CFG_PROMISC_MODE:
    case VNET_DEV_PORT_CFG_CHANGE_PRIMARY_HW_ADDR:
    case VNET_DEV_PORT_CFG_ADD_SECONDARY_HW_ADDR:
    case VNET_DEV_PORT_CFG_REMOVE_SECONDARY_HW_ADDR:
      rv = VNET_DEV_OK;
      break;

    default:
      break;
    }

  return rv;
}

vnet_dev_rv_t
ige_port_cfg_change (vlib_main_t *vm, vnet_dev_port_t *port,
		     vnet_dev_port_cfg_change_req_t *req)
{
  vnet_dev_rv_t rv = VNET_DEV_OK;
  switch (req->type)
    {
    case VNET_DEV_PORT_CFG_MAX_RX_FRAME_SIZE:
      break;
    case VNET_DEV_PORT_CFG_SET_LINK_SPEED:
      rv = ige_phy_set_speed (vm, port->dev, req->link_speed);
      break;
    case VNET_DEV_PORT_CFG_SET_RSS_CONFIG:
      if (port->started)
	ige_rss_apply (port, &req->rss_config);
      break;
    case VNET_DEV_PORT_CFG_RXQ_INTR_MODE_ENABLE:
    case VNET_DEV_PORT_CFG_RXQ_INTR_MODE_DISABLE:
      if (port->started)
	{
	  vnet_dev_rx_queue_t *rxq = 0;

	  if (!req->all_queues)
	    rxq = vnet_dev_get_port_rx_queue_by_id (port, req->queue_id);

	  ige_rx_irq_apply (port, rxq, req->type == VNET_DEV_PORT_CFG_RXQ_INTR_MODE_ENABLE);
	}
      break;
    case VNET_DEV_PORT_CFG_PROMISC_MODE:
      rv = ige_set_promisc_mode (vm, port, req->promisc);
      break;
    case VNET_DEV_PORT_CFG_CHANGE_PRIMARY_HW_ADDR:
      rv = ige_change_primary_hw_addr (vm, port, &req->addr);
      break;
    case VNET_DEV_PORT_CFG_ADD_SECONDARY_HW_ADDR:
      rv = ige_add_secondary_hw_addr (vm, port, &req->addr);
      break;
    case VNET_DEV_PORT_CFG_REMOVE_SECONDARY_HW_ADDR:
      rv = ige_remove_secondary_hw_addr (vm, port, &req->addr);
      break;

    default:
      rv = VNET_DEV_ERR_NOT_SUPPORTED;
      break;
    }

  return rv;
}
