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
  u16 keylen = clib_min (sizeof (default_rss_key), ap->rss_key_size);
  u8 buffer[VIRTCHNL_MSG_SZ (virtchnl_rss_key_t, key, keylen)];
  virtchnl_rss_key_t *key = (virtchnl_rss_key_t *) buffer;

  if (!port->attr.caps.rss)
    return VNET_DEV_OK;

  /* config RSS key */
  *key = (virtchnl_rss_key_t){
    .vsi_id = ap->vsi_id,
    .key_len = keylen,
  };

  clib_memcpy (key->key, default_rss_key, sizeof (default_rss_key));

  return avf_vc_op_config_rss_key (vm, dev, key);
}

vnet_dev_rv_t
avf_port_update_rss_lut (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  avf_port_t *ap = vnet_dev_get_port_data (port);
  u16 lut_size = clib_min (AVF_MAX_RSS_LUT_SIZE, ap->rss_lut_size);
  u8 buffer[VIRTCHNL_MSG_SZ (virtchnl_rss_lut_t, lut, lut_size)];
  virtchnl_rss_lut_t *lut = (virtchnl_rss_lut_t *) buffer;
  u32 enabled_rxq_bmp = 0;

  if (!port->attr.caps.rss)
    return VNET_DEV_OK;

  *lut = (virtchnl_rss_lut_t){
    .vsi_id = ap->vsi_id,
    .lut_entries = lut_size,
  };

  foreach_vnet_dev_port_rx_queue (q, port)
    if (q->enabled)
      enabled_rxq_bmp |= 1ULL << q->queue_id;

  /* config RSS LUT */
  for (u32 i = 0, j; i < lut->lut_entries;)
    foreach_set_bit_index (j, enabled_rxq_bmp)
      {
	lut->lut[i++] = j;
	if (i >= lut->lut_entries)
	  break;
      }

  return avf_vc_op_config_rss_lut (vm, dev, lut);
}

vnet_dev_rv_t
avf_port_init_vsi_queues (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  avf_port_t *ap = vnet_dev_get_port_data (port);
  virtchnl_queue_pair_info_t *qpi;
  u16 vsi_id = ap->vsi_id;
  u16 data_size = vlib_buffer_get_default_data_size (vm);
  u16 max_frame_size = port->max_frame_size;
  u8 buffer[VIRTCHNL_MSG_SZ (virtchnl_vsi_queue_config_info_t, qpair,
			     ap->num_qp)];
  virtchnl_vsi_queue_config_info_t *ci =
    (virtchnl_vsi_queue_config_info_t *) buffer;

  *ci = (virtchnl_vsi_queue_config_info_t){
    .num_queue_pairs = ap->num_qp,
    .vsi_id = vsi_id,
  };

  for (u16 i = 0; i < ap->num_qp; i++)
    ci->qpair[i] = (virtchnl_queue_pair_info_t){
      .rxq = { .vsi_id = vsi_id, .queue_id = i },
      .txq = { .vsi_id = vsi_id, .queue_id = i },
    };

  foreach_vnet_dev_port_rx_queue (q, port)
    {
      avf_rxq_t *arq = vnet_dev_get_rx_queue_data (q);
      qpi = ci->qpair + q->queue_id;
      qpi->rxq.ring_len = q->size;
      qpi->rxq.databuffer_size = data_size;
      qpi->rxq.dma_ring_addr = vnet_dev_get_dma_addr (vm, dev, arq->descs);
      qpi->rxq.max_pkt_size = max_frame_size;
    }

  foreach_vnet_dev_port_tx_queue (q, port)
    {
      avf_txq_t *atq = vnet_dev_get_tx_queue_data (q);
      qpi = ci->qpair + q->queue_id;
      qpi->txq.ring_len = q->size;
      qpi->txq.dma_ring_addr = vnet_dev_get_dma_addr (vm, dev, atq->descs);
    }

  return avf_vc_op_config_vsi_queues (vm, dev, ci);
}

vnet_dev_rv_t
avf_port_init_irq_map (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  avf_device_t *ad = vnet_dev_get_data (dev);
  avf_port_t *ap = vnet_dev_get_port_data (port);
  u16 n_threads = vlib_get_n_threads ();
  u8 buffer[VIRTCHNL_MSG_SZ (virtchnl_irq_map_info_t, vecmap, n_threads)];
  virtchnl_irq_map_info_t *im = (virtchnl_irq_map_info_t *) buffer;
  vnet_dev_rv_t rv;

  if (port->attr.caps.interrupt_mode)
    {
      *im = (virtchnl_irq_map_info_t){
	.num_vectors = n_threads,
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

  foreach_vnet_dev_port_rx_queue (rxq, port)
    {
      avf_rxq_t *arq = vnet_dev_get_rx_queue_data (rxq);
      avf_rx_desc_t *d = arq->descs;
      u32 n_enq, *bi = arq->buffer_indices;
      u8 bpi = vnet_dev_get_rx_queue_buffer_pool_index (rxq);

      n_enq = vlib_buffer_alloc_from_pool (vm, bi, rxq->size - 8, bpi);

      if (n_enq < 8)
	{
	  if (n_enq)
	    vlib_buffer_free (vm, bi, n_enq);
	  return VNET_DEV_ERR_BUFFER_ALLOC_FAIL;
	}

      for (u32 i = 0; i < n_enq; i++)
	{
	  vlib_buffer_t *b = vlib_get_buffer (vm, bi[i]);
	  d[i] = (avf_rx_desc_t){ .addr = vnet_dev_get_dma_addr (vm, dev, b) };
	}

      arq->n_enqueued = n_enq;
      arq->next = 0;
      avf_reg_write (ad, AVF_QRX_TAIL (rxq->queue_id), n_enq);
    }

  avf_port_add_counters (vm, port);

  return VNET_DEV_OK;
}

static vnet_dev_rv_t
avf_enable_disable_queues (vlib_main_t *vm, vnet_dev_port_t *port, int enable)
{
  avf_port_t *ap = vnet_dev_get_port_data (port);

  virtchnl_queue_select_t qs = {
    .vsi_id = ap->vsi_id,
  };

  foreach_vnet_dev_port_rx_queue (q, port)
    if ((enable && q->enabled) || (!enable && q->started))
      qs.rx_queues |= 1ULL << q->queue_id;

  foreach_vnet_dev_port_tx_queue (q, port)
    if ((enable && q->enabled) || (!enable && q->started))
      qs.tx_queues |= 1ULL << q->queue_id;

  return enable ? avf_vc_op_enable_queues (vm, port->dev, &qs) :
			avf_vc_op_disable_queues (vm, port->dev, &qs);
}

vnet_dev_rv_t
avf_port_start (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_rv_t rv;

  log_debug (port->dev, "port start: port %u", port->port_id);

  rv = avf_port_update_rss_lut (vm, port);
  if (rv != VNET_DEV_OK)
    return rv;

  /* configure qpairs */
  rv = avf_port_init_vsi_queues (vm, port);
  if (rv != VNET_DEV_OK)
    return rv;

  rv = avf_port_init_irq_map (vm, port);
  if (rv != VNET_DEV_OK)
    return rv;

  rv = avf_enable_disable_queues (vm, port, /* enable */ 1);
  if (rv != VNET_DEV_OK)
    return rv;

  vnet_dev_poll_port_add (vm, port, 1, avf_port_poll_stats);
  return VNET_DEV_OK;
}

void
avf_port_stop (vlib_main_t *vm, vnet_dev_port_t *port)
{
  log_debug (port->dev, "port stop: port %u", port->port_id);

  avf_enable_disable_queues (vm, port, /* enable */ 0);
  vnet_dev_poll_port_remove (vm, port, avf_port_poll_stats);

  foreach_vnet_dev_port_rx_queue (rxq, port)
    {
      avf_rxq_t *arq = vnet_dev_get_rx_queue_data (rxq);
      if (arq->n_enqueued)
	vlib_buffer_free_from_ring_no_next (vm, arq->buffer_indices, arq->next,
					    rxq->size, arq->n_enqueued);
      arq->n_enqueued = arq->next = 0;
    }

  foreach_vnet_dev_port_tx_queue (txq, port)
    {
      avf_txq_t *atq = vnet_dev_get_tx_queue_data (txq);
      if (atq->n_enqueued)
	vlib_buffer_free_from_ring_no_next (vm, atq->buffer_indices, atq->next,
					    txq->size, atq->n_enqueued);
      atq->n_enqueued = atq->next = 0;
    }
}

vnet_dev_rv_t
avf_port_cfg_change_precheck (vlib_main_t *vm, vnet_dev_port_t *port,
			      vnet_dev_port_cfg_change_req_t *req)
{
  vnet_dev_rv_t rv = VNET_DEV_OK;

  switch (req->type)
    {
    case VNET_DEV_PORT_CFG_MAX_FRAME_SIZE:
      if (port->started)
	rv = VNET_DEV_ERR_PORT_STARTED;
      break;

    case VNET_DEV_PORT_CFG_PROMISC_MODE:
    case VNET_DEV_PORT_CFG_CHANGE_PRIMARY_HW_ADDR:
    case VNET_DEV_PORT_CFG_ADD_SECONDARY_HW_ADDR:
    case VNET_DEV_PORT_CFG_REMOVE_SECONDARY_HW_ADDR:
      break;

    default:
      rv = VNET_DEV_ERR_NOT_SUPPORTED;
    };

  return rv;
}

static vnet_dev_rv_t
avf_port_add_del_eth_addr (vlib_main_t *vm, vnet_dev_port_t *port,
			   vnet_dev_hw_addr_t *addr, int is_add,
			   int is_primary)
{
  avf_port_t *ap = vnet_dev_get_port_data (port);
  virtchnl_ether_addr_list_t al = {
    .vsi_id = ap->vsi_id,
    .num_elements = 1,
    .list[0].primary = is_primary ? 1 : 0,
    .list[0].extra = is_primary ? 0 : 1,
  };

  clib_memcpy (al.list[0].addr, addr, sizeof (al.list[0].addr));

  return is_add ? avf_vc_op_add_eth_addr (vm, port->dev, &al) :
			avf_vc_op_del_eth_addr (vm, port->dev, &al);
}

vnet_dev_rv_t
avf_port_cfg_change (vlib_main_t *vm, vnet_dev_port_t *port,
		     vnet_dev_port_cfg_change_req_t *req)
{
  vnet_dev_t *dev = port->dev;
  avf_port_t *ap = vnet_dev_get_port_data (port);
  vnet_dev_rv_t rv = VNET_DEV_OK;

  switch (req->type)
    {
    case VNET_DEV_PORT_CFG_PROMISC_MODE:
      {
	virtchnl_promisc_info_t pi = {
	  .vsi_id = ap->vsi_id,
	  .unicast_promisc = req->promisc,
	  .multicast_promisc = req->promisc,
	};

	rv = avf_vc_op_config_promisc_mode (vm, dev, &pi);
      }
      break;

    case VNET_DEV_PORT_CFG_CHANGE_PRIMARY_HW_ADDR:
      rv = avf_port_add_del_eth_addr (vm, port, &port->primary_hw_addr,
				      /* is_add */ 0,
				      /* is_primary */ 1);
      if (rv == VNET_DEV_OK)
	rv = avf_port_add_del_eth_addr (vm, port, &req->addr,
					/* is_add */ 1,
					/* is_primary */ 1);
      break;

    case VNET_DEV_PORT_CFG_ADD_SECONDARY_HW_ADDR:
      rv = avf_port_add_del_eth_addr (vm, port, &req->addr,
				      /* is_add */ 1,
				      /* is_primary */ 0);
      break;

    case VNET_DEV_PORT_CFG_REMOVE_SECONDARY_HW_ADDR:
      rv = avf_port_add_del_eth_addr (vm, port, &req->addr,
				      /* is_add */ 0,
				      /* is_primary */ 0);
      break;

    case VNET_DEV_PORT_CFG_MAX_FRAME_SIZE:
      break;

    default:
      return VNET_DEV_ERR_NOT_SUPPORTED;
    };

  return rv;
}
