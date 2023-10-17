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
avf_port_vlan_strip_disable (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  avf_port_t *ap = vnet_dev_get_port_data (port);
  virtchnl_vlan_caps_t vc;
  vnet_dev_rv_t rv;
  u32 outer, inner;
  const u32 mask = VIRTCHNL_VLAN_ETHERTYPE_8100;

  if ((ap->vf_cap_flags & VIRTCHNL_VF_OFFLOAD_VLAN_V2) == 0)
    return avf_vc_op_disable_vlan_stripping (vm, dev);

  rv = avf_vc_op_get_offload_vlan_v2_caps (vm, dev, &vc);
  if (rv != VNET_DEV_OK)
    return rv;

  outer = vc.offloads.stripping_support.outer;
  inner = vc.offloads.stripping_support.inner;

  outer = outer & VIRTCHNL_VLAN_TOGGLE ? outer & mask : 0;
  inner = inner & VIRTCHNL_VLAN_TOGGLE ? inner & mask : 0;

  virtchnl_vlan_setting_t vs = {
    .vport_id = ap->vsi_id,
    .outer_ethertype_setting = outer,
    .inner_ethertype_setting = inner,
  };

  return avf_vc_op_disable_vlan_stripping_v2 (vm, dev, &vs);
}

vnet_dev_rv_t
avf_port_init_rss (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  avf_port_t *ap = vnet_dev_get_port_data (port);

  struct
  {
    virtchnl_rss_key_t key;
    u8 key_data[AVF_MAX_RSS_KEY_SIZE];
  } req = {};

  if (!port->caps.rss)
    return VNET_DEV_OK;

  /* config RSS key */
  req.key.vsi_id = ap->vsi_id;
  req.key.key_len = clib_min (sizeof (default_rss_key), ap->rss_key_size);
  clib_memcpy (req.key.key, default_rss_key, sizeof (default_rss_key));

  return avf_vc_op_config_rss_key (vm, dev, &req.key);
}

vnet_dev_rv_t
avf_port_update_rss_lut (vlib_main_t *vm, vnet_dev_port_t *port,
			 u32 enabled_rxq_bmp)
{
  vnet_dev_t *dev = port->dev;
  avf_port_t *ap = vnet_dev_get_port_data (port);

  struct
  {
    virtchnl_rss_lut_t lut;
    u8 lut_data[AVF_MAX_RSS_LUT_SIZE];
  } req = {
    .lut = {
      .vsi_id = ap->vsi_id,
      .lut_entries = clib_min (AVF_MAX_RSS_LUT_SIZE, ap->rss_lut_size),
    },
  };

  if (!port->caps.rss)
    return VNET_DEV_OK;

  /* config RSS LUT */
  for (u32 i = 0, j; i < req.lut.lut_entries;)
    foreach_set_bit_index (j, enabled_rxq_bmp)
      {
	req.lut.lut[i++] = j;
	if (i >= req.lut.lut_entries)
	  break;
      }

  return avf_vc_op_config_rss_lut (vm, dev, &req.lut);
}

vnet_dev_rv_t
avf_port_init_vsi_queues (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  avf_port_t *ap = vnet_dev_get_port_data (port);
  virtchnl_queue_pair_info_t *qpi;
  u16 vsi_id = ap->vsi_id;
  u16 data_size = vlib_buffer_get_default_data_size (vm);
  u16 max_frame_size = port->conf.max_frame_size;

  union
  {
    u8 buffer[AVF_AQ_BUF_SIZE];
    virtchnl_vsi_queue_config_info_t ci;
  } req;

  req.ci = (virtchnl_vsi_queue_config_info_t){
    .num_queue_pairs = ap->num_qp,
    .vsi_id = vsi_id,
  };

  for (u16 i = 0; i < ap->num_qp; i++)
    req.ci.qpair[i] = (virtchnl_queue_pair_info_t){
      .rxq = { .vsi_id = vsi_id, .queue_id = i },
      .txq = { .vsi_id = vsi_id, .queue_id = i },
    };

  foreach_vnet_dev_port_rx_queue (q, port)
    {
      avf_rxq_t *arq = vnet_dev_get_rx_queue_data (q);
      qpi = req.ci.qpair + q->queue_id;
      qpi->rxq.ring_len = q->size;
      qpi->rxq.databuffer_size = data_size;
      qpi->rxq.dma_ring_addr = vnet_dev_get_dma_addr (vm, dev, arq->descs);
      qpi->rxq.max_pkt_size = max_frame_size;
    }

  foreach_vnet_dev_port_tx_queue (q, port)
    {
      avf_txq_t *atq = vnet_dev_get_tx_queue_data (q);
      qpi = req.ci.qpair + q->queue_id;
      qpi->txq.ring_len = q->size;
      qpi->txq.dma_ring_addr = vnet_dev_get_dma_addr (vm, dev, atq->descs);
    }

  return avf_vc_op_config_vsi_queues (vm, dev, &req.ci);
}

vnet_dev_rv_t
avf_port_init_irq_map (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  avf_device_t *ad = vnet_dev_get_data (dev);
  avf_port_t *ap = vnet_dev_get_port_data (port);
  virtchnl_irq_map_info_t *im;
  vnet_dev_rv_t rv;

  union
  {
    u8 data[4096];
    virtchnl_irq_map_info_t im;
  } u;

  im = &u.im;

  if (port->attr.caps.interrupt_mode)
    {
      *im = (virtchnl_irq_map_info_t){
	.num_vectors = vlib_get_n_threads (),
      };
      for (u16 i = 0; i < im->num_vectors; i++)
	im->vecmap[i] = (virtchnl_vector_map_t){
	  .vsi_id = ap->vsi_id,
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
	    .vsi_id = ap->vsi_id,
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

  for (int i = 0; i < im->num_vectors; i++)
    {
      u8 line = im->vecmap[i].vector_id;
      if (ap->vf_cap_flags & VIRTCHNL_VF_OFFLOAD_WB_ON_ITR)
	avf_irq_n_set_state (ad, line, AVF_IRQ_STATE_WB_ON_ITR);
      else
	avf_irq_n_set_state (ad, line, AVF_IRQ_STATE_ENABLED);
    }

  return rv;
}

vnet_dev_rv_t
avf_port_add_eth_addr (vlib_main_t *vm, vnet_dev_port_t *port, u8 *addr)
{
  avf_port_t *ap = vnet_dev_get_port_data (port);
  virtchnl_ether_addr_list_t al = {
    .vsi_id = ap->vsi_id,
    .num_elements = 1,
  };

  clib_memcpy (al.list[0].addr, addr, sizeof (al.list[0].addr));
  return avf_vc_op_add_eth_addr (vm, port->dev, &al);
}

vnet_dev_rv_t
avf_port_init (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  avf_device_t *ad = vnet_dev_get_data (dev);
  vnet_dev_rv_t rv;

  log_debug (port->dev, "port init: port %u", port->port_id);

  rv = avf_port_vlan_strip_disable (vm, port);
  if (rv != VNET_DEV_OK)
    return rv;

  rv = avf_port_init_rss (vm, port);
  if (rv != VNET_DEV_OK)
    return rv;

  rv = avf_port_add_eth_addr (vm, port, (u8 *) &port->conf.hw_addr.addr);
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

  avf_port_add_counters (vm, port);

  return VNET_DEV_OK;
}

vnet_dev_rv_t
avf_port_start (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  avf_port_t *ap = vnet_dev_get_port_data (port);
  u64 enabled_rxq_bmp = 0, enabled_txq_bmp = 0;
  vnet_dev_rv_t rv;

  log_debug (port->dev, "port start: port %u", port->port_id);

  foreach_vnet_dev_port_rx_queue (q, port)
    if (q->enabled)
      enabled_rxq_bmp |= 1ULL << q->queue_id;

  foreach_vnet_dev_port_tx_queue (q, port)
    if (q->enabled)
      enabled_txq_bmp |= 1ULL << q->queue_id;

  rv = avf_port_update_rss_lut (vm, port, enabled_rxq_bmp);
  if (rv != VNET_DEV_OK)
    return rv;

  /* configure qpairs */
  rv = avf_port_init_vsi_queues (vm, port);
  if (rv != VNET_DEV_OK)
    return rv;

  rv = avf_port_init_irq_map (vm, port);
  if (rv != VNET_DEV_OK)
    return rv;

  /* enable queues */
  virtchnl_queue_select_t qs = {
    .vsi_id = ap->vsi_id,
    .rx_queues = enabled_rxq_bmp,
    .tx_queues = enabled_txq_bmp,
  };

  rv = avf_vc_op_enable_queues (vm, dev, &qs);
  if (rv != VNET_DEV_OK)
    return rv;

  foreach_vnet_dev_port_rx_queue (rxq, port)
    rxq->started = 1;
  foreach_vnet_dev_port_tx_queue (txq, port)
    txq->started = 1;

  vnet_dev_poll_port_add (vm, port, 1, avf_port_poll_stats);
  return VNET_DEV_OK;
}

void
avf_port_stop (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  avf_port_t *ap = vnet_dev_get_port_data (port);
  vnet_dev_rv_t rv;

  log_debug (port->dev, "port stop: port %u", port->port_id);
  vnet_dev_poll_port_remove (vm, port, avf_port_poll_stats);

  virtchnl_queue_select_t qs = {
    .vsi_id = ap->vsi_id,
  };

  foreach_vnet_dev_port_rx_queue (rxq, port)
    if (rxq->started)
      qs.rx_queues |= 1 << rxq->queue_id;
  foreach_vnet_dev_port_rx_queue (txq, port)
    if (txq->started)
      qs.rx_queues |= 1 << txq->queue_id;

  rv = avf_vc_op_disable_queues (vm, dev, &qs);

  if (rv != VNET_DEV_OK)
    return;

  foreach_vnet_dev_port_rx_queue (rxq, port)
    rxq->started = 0;
  foreach_vnet_dev_port_tx_queue (txq, port)
    txq->started = 0;
}
