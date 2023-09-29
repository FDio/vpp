/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vnet/dev/pci.h>
#include <vnet/dev/counters.h>
#include <dev_avf/avf.h>
#include <dev_avf/virtchnl.h>
#include <dev_avf/virtchnl_funcs.h>
#include <vnet/ethernet/ethernet.h>

VLIB_REGISTER_LOG_CLASS (avf_log, static) = {
  .class_name = "dev_avf",
  .subclass_name = "port",
};

static const u8 default_rss_key[] = {
  0x44, 0x39, 0x79, 0x6b, 0xb5, 0x4c, 0x50, 0x23, 0xb6, 0x75, 0xea, 0x5b, 0x12,
  0x4f, 0x9f, 0x30, 0xb8, 0xa2, 0xc0, 0x3d, 0xdf, 0xdc, 0x4d, 0x02, 0xa0, 0x8c,
  0x9b, 0x33, 0x4a, 0xf6, 0x4a, 0x4c, 0x05, 0xc6, 0xfa, 0x34, 0x39, 0x58, 0xd8,
  0x55, 0x7d, 0x99, 0x58, 0x3a, 0xe1, 0x38, 0xc9, 0x2e, 0x81, 0x15, 0x03, 0x66,
};

typedef enum
{
  AVF_IRQ_STATE_DISABLED,
  AVF_IRQ_STATE_ENABLED,
  AVF_IRQ_STATE_WB_ON_ITR,
} avf_irq_state_t;

static inline void
avf_irq_0_set_state (avf_device_t *ad, avf_irq_state_t state)
{
  u32 dyn_ctl0 = 0, icr0_ena = 0;

  dyn_ctl0 |= (3 << 3); /* 11b = No ITR update */

  avf_reg_write (ad, AVFINT_ICR0_ENA1, icr0_ena);
  avf_reg_write (ad, AVFINT_DYN_CTL0, dyn_ctl0);
  avf_reg_flush (ad);

  if (state == AVF_IRQ_STATE_DISABLED)
    return;

  dyn_ctl0 = 0;
  icr0_ena = 0;

  icr0_ena |= (1 << 30); /* [30] Admin Queue Enable */

  dyn_ctl0 |= (1 << 0); /* [0] Interrupt Enable */
  dyn_ctl0 |= (1 << 1); /* [1] Clear PBA */
  dyn_ctl0 |= (2 << 3); /* [4:3] ITR Index, 11b = No ITR update */
  dyn_ctl0 |= ((AVF_ITR_INT / 2) << 5); /* [16:5] ITR Interval in 2us steps */

  avf_reg_write (ad, AVFINT_ICR0_ENA1, icr0_ena);
  avf_reg_write (ad, AVFINT_DYN_CTL0, dyn_ctl0);
  avf_reg_flush (ad);
}

static inline void
avf_irq_n_set_state (avf_device_t *ad, u8 line, avf_irq_state_t state)
{
  u32 dyn_ctln = 0;

  /* disable */
  avf_reg_write (ad, AVFINT_DYN_CTLN (line), dyn_ctln);
  avf_reg_flush (ad);

  if (state == AVF_IRQ_STATE_DISABLED)
    return;

  dyn_ctln |= (1 << 1); /* [1] Clear PBA */
  if (state == AVF_IRQ_STATE_WB_ON_ITR)
    {
      /* minimal ITR interval, use ITR1 */
      dyn_ctln |= (1 << 3);	   /* [4:3] ITR Index */
      dyn_ctln |= ((32 / 2) << 5); /* [16:5] ITR Interval in 2us steps */
      dyn_ctln |= (1 << 30);	   /* [30] Writeback on ITR */
    }
  else
    {
      /* configured ITR interval, use ITR0 */
      dyn_ctln |= (1 << 0); /* [0] Interrupt Enable */
      dyn_ctln |=
	((AVF_ITR_INT / 2) << 5); /* [16:5] ITR Interval in 2us steps */
    }

  avf_reg_write (ad, AVFINT_DYN_CTLN (line), dyn_ctln);
  avf_reg_flush (ad);
}

vnet_dev_rv_t
avf_port_init_rss (vlib_main_t *vm, vnet_dev_port_t *port, u32 enabled_rxq_bmp)
{
  vnet_dev_t *dev = port->dev;
  avf_device_t *ad = vnet_dev_get_data (dev);
  vnet_dev_rv_t rv = VNET_DEV_OK;
  union
  {
    u8 data[4096];
    virtchnl_rss_lut_t lut;
    virtchnl_rss_key_t key;
  } u = {};

  if ((ad->vf_cap_flags & VIRTCHNL_VF_OFFLOAD_RSS_PF) == 0)
    return rv;

  if (sizeof (default_rss_key) < ad->rss_key_size)
    {
      log_err (dev, "reported rss key size (%u) too small", ad->rss_key_size);
      return VNET_DEV_ERR_UNSUPPORTED_DEV;
    }

  /* config RSS LUT */
  u.lut.vsi_id = ad->vsi_id;
  u.lut.lut_entries = ad->rss_lut_size;
  for (u32 i = 0, j; i < u.lut.lut_entries;)
    foreach_set_bit_index (j, enabled_rxq_bmp)
      {
	u.lut.lut[i++] = j;
	if (i >= u.lut.lut_entries)
	  break;
      }
  rv = avf_vc_op_config_rss_lut (vm, dev, &u.lut);

  if (rv != VNET_DEV_OK)
    return rv;

  /* config RSS key */
  u.key.vsi_id = ad->vsi_id;
  u.key.key_len = clib_min (sizeof (default_rss_key), ad->rss_key_size);
  clib_memcpy (u.key.key, default_rss_key, sizeof (default_rss_key));

  rv = avf_vc_op_config_rss_key (vm, dev, &u.key);
  return rv;
}

vnet_dev_rv_t
avf_port_init_vsi_queues (vlib_main_t *vm, vnet_dev_port_t *port,
			  u32 qpairs_bmp)
{
  u8 arq_buf[256];
  vnet_dev_t *dev = port->dev;
  avf_device_t *ad = vnet_dev_get_data (dev);
  virtchnl_vsi_queue_config_info_t *ci;

  ci = (virtchnl_vsi_queue_config_info_t *) arq_buf;
  *ci = (virtchnl_vsi_queue_config_info_t){
    .num_queue_pairs = count_set_bits (qpairs_bmp),
  };

  virtchnl_queue_pair_info_t *qpi;

  qpi = ci->qpair;

  foreach_vnet_dev_port_rx_queue (q, port)
    {
      avf_rxq_t *arq = vnet_dev_get_rx_queue_data (q);
      qpi->rxq.vsi_id = ad->vsi_id;
      qpi->rxq.queue_id = q->queue_id;
      qpi->rxq.ring_len = q->size;
      qpi->rxq.databuffer_size = vlib_buffer_get_default_data_size (vm);
      qpi->rxq.dma_ring_addr = vnet_dev_get_dma_addr (vm, dev, arq->descs);
      qpi->rxq.max_pkt_size = port->max_frame_size;
      qpi++;
    }

  while (qpi < ci->qpair + ci->num_queue_pairs)
    qpi++->rxq = (virtchnl_rxq_info_t){};

  qpi = ci->qpair;
  foreach_vnet_dev_port_tx_queue (q, port)
    {
      avf_txq_t *atq = vnet_dev_get_tx_queue_data (q);
      qpi->txq.vsi_id = ad->vsi_id;
      qpi->txq.queue_id = q->queue_id;
      qpi->txq.ring_len = q->size;
      qpi->txq.dma_ring_addr = vnet_dev_get_dma_addr (vm, dev, atq->descs);
      qpi++;
    }

  while (qpi < ci->qpair + ci->num_queue_pairs)
    qpi++->txq = (virtchnl_txq_info_t){};

  ci->vsi_id = ad->vsi_id;

  return avf_vc_op_config_vsi_queues (vm, dev, ci);
}

vnet_dev_rv_t
avf_port_init_irq_map (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  avf_device_t *ad = vnet_dev_get_data (dev);
  virtchnl_irq_map_info_t *im;
  vnet_dev_rv_t rv;

  union
  {
    u8 data[4096];
    virtchnl_irq_map_info_t im;
  } u;

  im = &u.im;

  if (port->config.caps.interrupt_mode)
    {
      *im = (virtchnl_irq_map_info_t){
	.num_vectors = 1,
      };
      for (u16 i = 0; i < vlib_get_n_threads (); i++)
	im->vecmap[i] = (virtchnl_vector_map_t){
	  .vsi_id = ad->vsi_id,
	  .vector_id = i + 1,
	};
      foreach_vnet_dev_port_rx_queue (rxq, port)
	if (rxq->enabled)
	  im->vecmap[rxq->rx_thread_index].rxq_map |= 1 << rxq->queue_id;
    }
  else
    {
      *im = (virtchnl_irq_map_info_t){
	.num_vectors = 1,
	.vecmap[0] = {
	  .vsi_id = ad->vsi_id,
	  .vector_id = 1,
	},
      };
      foreach_vnet_dev_port_rx_queue (rxq, port)
	if (rxq->enabled)
	  im->vecmap[0].rxq_map |= 1 << rxq->queue_id;
    }

  rv = avf_vc_op_config_irq_map (vm, dev, im);
  if (rv != VNET_DEV_OK)
    return rv;

  avf_irq_0_set_state (ad, AVF_IRQ_STATE_ENABLED);

  foreach_vnet_dev_port_rx_queue (rxq, port)
    if (rxq->enabled)
      {
	if (ad->vf_cap_flags & VIRTCHNL_VF_OFFLOAD_WB_ON_ITR)
	  avf_irq_n_set_state (ad, rxq->queue_id, AVF_IRQ_STATE_WB_ON_ITR);
	else
	  avf_irq_n_set_state (ad, rxq->queue_id, AVF_IRQ_STATE_ENABLED);
      }

  return rv;
}

vnet_dev_rv_t
avf_port_init (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  avf_device_t *ad = vnet_dev_get_data (dev);
  vnet_dev_rv_t rv;
  u64 enabled_rxq_bmp = 0, enabled_txq_bmp = 0;

  log_debug (port->dev, "port init: port %u", port->port_id);

  foreach_vnet_dev_port_rx_queue (q, port)
    if (q->enabled)
      enabled_rxq_bmp |= 1ULL << q->queue_id;

  foreach_vnet_dev_port_tx_queue (q, port)
    enabled_txq_bmp |= 1ULL << q->queue_id;

  rv = avf_port_init_rss (vm, port, enabled_rxq_bmp);
  if (rv != VNET_DEV_OK)
    return rv;

  /* configure qpairs */
  rv = avf_port_init_vsi_queues (vm, port, enabled_rxq_bmp | enabled_txq_bmp);
  if (rv != VNET_DEV_OK)
    return rv;

  rv = avf_port_init_irq_map (vm, port);
  if (rv != VNET_DEV_OK)
    return rv;

  virtchnl_ether_addr_list_t al = {
    .vsi_id = ad->vsi_id,
    .num_elements = 1,
  };

  clib_memcpy (al.list[0].addr, port->hw_addr.addr, sizeof (al.list[0].addr));

  rv = avf_vc_op_add_eth_addr (vm, dev, &al);
  if (rv != VNET_DEV_OK)
    return rv;

  foreach_vnet_dev_port_rx_queue (rxq, port)
    {
      avf_rxq_t *arq = vnet_dev_get_rx_queue_data (rxq);

      arq->n_enqueued = vlib_buffer_alloc_from_pool (
	vm, arq->buffer_indices, rxq->size - 8,
	vnet_dev_get_rx_queue_buffer_pool_index (rxq));

      avf_rx_desc_t *d = arq->descs;
      for (u32 i = 0; i < arq->n_enqueued; i++, d++)
	{
	  vlib_buffer_t *b = vlib_get_buffer (vm, arq->buffer_indices[i]);
	  d->qword[1] = d->qword[2] = d->qword[3] = 0;

	  if (dev->va_dma)
	    d->qword[0] = vlib_buffer_get_va (b);
	  else
	    d->qword[0] = vlib_buffer_get_pa (vm, b);
	}
      avf_reg_write (ad, AVF_QRX_TAIL (rxq->queue_id), arq->n_enqueued);
    }

  /* enable queues */
  virtchnl_queue_select_t qs = {
    .vsi_id = ad->vsi_id,
    .rx_queues = enabled_rxq_bmp,
    .tx_queues = enabled_txq_bmp,
  };

  rv = avf_vc_op_enable_queues (vm, dev, &qs);
  if (rv != VNET_DEV_OK)
    return rv;

  return VNET_DEV_OK;
}

vnet_dev_rv_t
avf_port_start (vlib_main_t *vm, vnet_dev_port_t *port)
{
  log_debug (port->dev, "port start: port %u", port->port_id);

  vnet_dev_poll_port_add (vm, port, 1, avf_port_poll_stats);
  return VNET_DEV_OK;
}

void
avf_port_stop (vlib_main_t *vm, vnet_dev_port_t *port)
{
  log_debug (port->dev, "port stop: port %u", port->port_id);
  vnet_dev_poll_port_remove (vm, port, avf_port_poll_stats);
}
