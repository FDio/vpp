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

vnet_dev_rv_t
avf_port_init (vlib_main_t *vm, vnet_dev_port_t *port)
{
  u8 arq_buf[256];
  vnet_dev_t *dev = port->dev;
  avf_device_t *ad = vnet_dev_get_data (dev);
  virtchnl_vsi_queue_config_info_t *ci;
  vnet_dev_rv_t rv;
  u64 enabled_rxq_bmp = 0, enabled_txq_bmp = 0, qpairs_bmp;

  log_debug (port->dev, "port init: port %u", port->port_id);

  pool_foreach_pointer (q, port->rx_queues)
    if (q->enabled)
      enabled_rxq_bmp |= 1ULL << q->queue_id;

  pool_foreach_pointer (q, port->tx_queues)
    enabled_txq_bmp |= 1ULL << q->queue_id;

  log_debug (dev, "bmp %lx", enabled_rxq_bmp);

  if (ad->vf_cap_flags & VIRTCHNL_VF_OFFLOAD_RSS_PF)
    {
      virtchnl_rss_lut_t *lut = (virtchnl_rss_lut_t *) arq_buf;
      virtchnl_rss_key_t *key = (virtchnl_rss_key_t *) arq_buf;

      if (sizeof (default_rss_key) < ad->rss_key_size)
	{
	  log_err (dev, "reported rss key size (%u) too small",
		   ad->rss_key_size);
	  return VNET_DEV_ERR_UNSUPPORTED_DEV;
	}

      /* config RSS LUT */
      lut->vsi_id = ad->vsi_id;
      lut->lut_entries = ad->rss_lut_size;
      for (u32 i = 0, j; i < lut->lut_entries;)
	foreach_set_bit_index (j, enabled_rxq_bmp)
	  {
	    lut->lut[i++] = j;
	    if (i >= lut->lut_entries)
	      break;
	  }
      rv = avf_vc_op_config_rss_lut (vm, dev, lut);
      if (rv != VNET_DEV_OK)
	return rv;

      /* config RSS key */
      key->vsi_id = ad->vsi_id;
      key->key_len = clib_min (sizeof (default_rss_key), ad->rss_key_size);
      clib_memcpy (key->key, default_rss_key, sizeof (default_rss_key));

      rv = avf_vc_op_config_rss_key (vm, dev, key);
      if (rv != VNET_DEV_OK)
	return rv;
    }

  /* configure qpairs */
  qpairs_bmp = enabled_rxq_bmp | enabled_txq_bmp;
  ci = (virtchnl_vsi_queue_config_info_t *) arq_buf;
  *ci = (virtchnl_vsi_queue_config_info_t){
    .vsi_id = ad->vsi_id,
    .num_queue_pairs = count_set_bits (qpairs_bmp),
  };

  for (u32 i = 1; i < ci->num_queue_pairs; i++)
    ci->qpair[i] = (virtchnl_queue_pair_info_t){};

  virtchnl_queue_pair_info_t *qpi;

  qpi = ci->qpair;
  pool_foreach_pointer (q, port->rx_queues)
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
  pool_foreach_pointer (q, port->tx_queues)
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

  rv = avf_vc_op_config_vsi_queues (vm, dev, ci);
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
  return VNET_DEV_OK;
}

void
avf_port_stop (vlib_main_t *vm, vnet_dev_port_t *port)
{
  log_debug (port->dev, "port stop: port %u", port->port_id);
}
