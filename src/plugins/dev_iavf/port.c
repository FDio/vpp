/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vnet/dev/bus/pci.h>
#include <vnet/dev/counters.h>
#include <dev_iavf/iavf.h>
#include <dev_iavf/iavf_regs.h>
#include <dev_iavf/virtchnl.h>
#include <dev_iavf/virtchnl_funcs.h>
#include <vnet/ethernet/ethernet.h>

VLIB_REGISTER_LOG_CLASS (iavf_log, static) = {
  .class_name = "iavf",
  .subclass_name = "port",
};

static const u8 default_rss_key[] = {
  0x44, 0x39, 0x79, 0x6b, 0xb5, 0x4c, 0x50, 0x23, 0xb6, 0x75, 0xea, 0x5b, 0x12,
  0x4f, 0x9f, 0x30, 0xb8, 0xa2, 0xc0, 0x3d, 0xdf, 0xdc, 0x4d, 0x02, 0xa0, 0x8c,
  0x9b, 0x33, 0x4a, 0xf6, 0x4a, 0x4c, 0x05, 0xc6, 0xfa, 0x34, 0x39, 0x58, 0xd8,
  0x55, 0x7d, 0x99, 0x58, 0x3a, 0xe1, 0x38, 0xc9, 0x2e, 0x81, 0x15, 0x03, 0x66,
};

const static iavf_dyn_ctl dyn_ctln_disabled = {};
const static iavf_dyn_ctl dyn_ctln_enabled = {
  .intena = 1,
  .clearpba = 1,
  .interval = IAVF_ITR_INT / 2,
};
const static iavf_dyn_ctl dyn_ctln_wb_on_itr = {
  .itr_indx = 1,
  .interval = 2,
  .wb_on_itr = 1,
};

vnet_dev_rv_t
iavf_port_vlan_strip_disable (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  iavf_port_t *ap = vnet_dev_get_port_data (port);
  virtchnl_vlan_caps_t vc;
  vnet_dev_rv_t rv = VNET_DEV_ERR_NOT_SUPPORTED;
  u32 outer, inner;
  const u32 mask = VIRTCHNL_VLAN_ETHERTYPE_8100;

  if (ap->vf_cap_flags & VIRTCHNL_VF_OFFLOAD_VLAN_V2)
    {
      if ((rv = iavf_vc_op_get_offload_vlan_v2_caps (vm, dev, &vc)))
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

      if ((rv = iavf_vc_op_disable_vlan_stripping_v2 (vm, dev, &vs)))
	return rv;
    }

  if (ap->vf_cap_flags & VIRTCHNL_VF_OFFLOAD_VLAN)
    return iavf_vc_op_disable_vlan_stripping (vm, dev);

  return rv;
}

vnet_dev_rv_t
iavf_port_init_rss (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  iavf_port_t *ap = vnet_dev_get_port_data (port);
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

  clib_memcpy (key->key, default_rss_key, keylen);

  return iavf_vc_op_config_rss_key (vm, dev, key);
}

vnet_dev_rv_t
iavf_port_update_rss_lut (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  iavf_port_t *ap = vnet_dev_get_port_data (port);
  u16 lut_size = clib_min (IAVF_MAX_RSS_LUT_SIZE, ap->rss_lut_size);
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

  return iavf_vc_op_config_rss_lut (vm, dev, lut);
}

vnet_dev_rv_t
iavf_port_init_vsi_queues (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  iavf_port_t *ap = vnet_dev_get_port_data (port);
  virtchnl_queue_pair_info_t *qpi;
  u16 vsi_id = ap->vsi_id;
  u16 data_size = vlib_buffer_get_default_data_size (vm);
  u16 max_frame_size = port->max_rx_frame_size;
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
      .rxq = { .vsi_id = vsi_id,
	       .queue_id = i,
	       .max_pkt_size = ETHERNET_MIN_PACKET_BYTES },
      .txq = { .vsi_id = vsi_id, .queue_id = i },
    };

  foreach_vnet_dev_port_rx_queue (q, port)
    {
      iavf_rxq_t *arq = vnet_dev_get_rx_queue_data (q);
      qpi = ci->qpair + q->queue_id;
      qpi->rxq.ring_len = q->size;
      qpi->rxq.databuffer_size = data_size;
      qpi->rxq.dma_ring_addr = vnet_dev_get_dma_addr (vm, dev, arq->descs);
      qpi->rxq.max_pkt_size = max_frame_size;
    }

  foreach_vnet_dev_port_tx_queue (q, port)
    {
      iavf_txq_t *atq = vnet_dev_get_tx_queue_data (q);
      qpi = ci->qpair + q->queue_id;
      qpi->txq.ring_len = q->size;
      qpi->txq.dma_ring_addr = vnet_dev_get_dma_addr (vm, dev, atq->descs);
    }

  return iavf_vc_op_config_vsi_queues (vm, dev, ci);
}

vnet_dev_rv_t
iavf_port_rx_irq_config (vlib_main_t *vm, vnet_dev_port_t *port, int enable)
{
  vnet_dev_t *dev = port->dev;
  iavf_device_t *ad = vnet_dev_get_data (dev);
  iavf_port_t *ap = vnet_dev_get_port_data (port);
  u16 n_rx_vectors = ap->n_rx_vectors;
  u8 buffer[VIRTCHNL_MSG_SZ (virtchnl_irq_map_info_t, vecmap, n_rx_vectors)];
  u8 n_intr_mode_queues_per_vector[n_rx_vectors];
  u8 n_queues_per_vector[n_rx_vectors];
  virtchnl_irq_map_info_t *im = (virtchnl_irq_map_info_t *) buffer;
  vnet_dev_rv_t rv;

  log_debug (dev, "intr mode per queue bitmap 0x%x",
	     ap->intr_mode_per_rxq_bitmap);

  for (u32 i = 0; i < n_rx_vectors; i++)
    n_intr_mode_queues_per_vector[i] = n_queues_per_vector[i] = 0;

  *im = (virtchnl_irq_map_info_t){
    .num_vectors = n_rx_vectors,
  };

  if (port->attr.caps.interrupt_mode)
    {
      for (u16 i = 0; i < im->num_vectors; i++)
	im->vecmap[i] = (virtchnl_vector_map_t){
	  .vsi_id = ap->vsi_id,
	  .vector_id = i + 1,
	};
      if (enable)
	foreach_vnet_dev_port_rx_queue (rxq, port)
	  if (rxq->enabled)
	    {
	      u32 i = rxq->rx_thread_index;
	      im->vecmap[i].rxq_map |= 1 << rxq->queue_id;
	      n_queues_per_vector[i]++;
	      n_intr_mode_queues_per_vector[i] +=
		u64_is_bit_set (ap->intr_mode_per_rxq_bitmap, rxq->queue_id);
	    }
    }
  else
    {
      im->vecmap[0] = (virtchnl_vector_map_t){
	.vsi_id = ap->vsi_id,
	.vector_id = 1,
      };
      if (enable)
	foreach_vnet_dev_port_rx_queue (rxq, port)
	  if (rxq->enabled)
	    im->vecmap[0].rxq_map |= 1 << rxq->queue_id;
    }

  if ((rv = iavf_vc_op_config_irq_map (vm, dev, im)))
    return rv;

  for (int i = 0; i < n_rx_vectors; i++)
    {
      u32 val;

      if (enable == 0 || n_queues_per_vector[i] == 0)
	val = dyn_ctln_disabled.as_u32;
      else if (ap->vf_cap_flags & VIRTCHNL_VF_OFFLOAD_WB_ON_ITR &&
	       n_intr_mode_queues_per_vector[i] == 0)
	val = dyn_ctln_wb_on_itr.as_u32;
      else
	val = dyn_ctln_enabled.as_u32;

      iavf_reg_write (ad, IAVF_VFINT_DYN_CTLN (i), val);
      log_debug (dev, "VFINT_DYN_CTLN(%u) set to 0x%x", i, val);
    }

  return rv;
}

static void
avf_msix_n_handler (vlib_main_t *vm, vnet_dev_t *dev, u16 line)
{
  iavf_device_t *ad = vnet_dev_get_data (dev);
  vnet_dev_port_t *port = vnet_dev_get_port_by_id (dev, 0);

  line--;

  iavf_reg_write (ad, IAVF_VFINT_DYN_CTLN (line), dyn_ctln_enabled.as_u32);
  vlib_node_set_interrupt_pending (vlib_get_main_by_index (line),
				   vnet_dev_get_port_rx_node_index (port));
}

vnet_dev_rv_t
iavf_port_init (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  iavf_port_t *ap = vnet_dev_get_port_data (port);
  vnet_dev_rv_t rv;

  log_debug (port->dev, "port %u", port->port_id);

  ap->intr_mode_per_rxq_bitmap = 0;
  foreach_vnet_dev_port_rx_queue (q, port)
    if (q->interrupt_mode)
      u64_bit_set (&ap->intr_mode_per_rxq_bitmap, q->queue_id, 1);

  if ((rv = iavf_port_vlan_strip_disable (vm, port)))
    {
      if (rv == VNET_DEV_ERR_NOT_SUPPORTED)
	log_warn (port->dev, "device doesn't support vlan stripping");
      else
	return rv;
    }

  if ((rv = iavf_port_init_rss (vm, port)))
    return rv;

  vnet_dev_pci_msix_add_handler (vm, dev, &avf_msix_n_handler, 1,
				 ap->n_rx_vectors);
  vnet_dev_pci_msix_enable (vm, dev, 1, ap->n_rx_vectors);
  for (u32 i = 1; i < ap->n_rx_vectors; i++)
    vnet_dev_pci_msix_set_polling_thread (vm, dev, i + 1, i);

  if (port->dev->poll_stats)
    iavf_port_add_counters (vm, port);

  return VNET_DEV_OK;
}

static vnet_dev_rv_t
iavf_enable_disable_queues (vlib_main_t *vm, vnet_dev_port_t *port, int enable)
{
  iavf_port_t *ap = vnet_dev_get_port_data (port);

  virtchnl_queue_select_t qs = {
    .vsi_id = ap->vsi_id,
  };

  foreach_vnet_dev_port_rx_queue (q, port)
    if ((enable && q->enabled) || (!enable && q->started))
      qs.rx_queues |= 1ULL << q->queue_id;

  foreach_vnet_dev_port_tx_queue (q, port)
    if ((enable && q->enabled) || (!enable && q->started))
      qs.tx_queues |= 1ULL << q->queue_id;

  return enable ? iavf_vc_op_enable_queues (vm, port->dev, &qs) :
			iavf_vc_op_disable_queues (vm, port->dev, &qs);
}

vnet_dev_rv_t
iavf_port_start (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_rv_t rv;

  log_debug (port->dev, "port %u", port->port_id);

  foreach_vnet_dev_port_rx_queue (q, port)
    if (q->enabled)
      if ((rv = iavf_rx_queue_start (vm, q)))
	goto done;

  foreach_vnet_dev_port_tx_queue (q, port)
    if ((rv = iavf_tx_queue_start (vm, q)))
      goto done;

  if ((rv = iavf_port_update_rss_lut (vm, port)))
    goto done;

  /* configure qpairs */
  if ((rv = iavf_port_init_vsi_queues (vm, port)))
    goto done;

  if ((rv = iavf_port_rx_irq_config (vm, port, /* enable */ 1)))
    goto done;

  if ((rv = iavf_enable_disable_queues (vm, port, 1)))
    goto done;

  if (port->dev->poll_stats)
    vnet_dev_poll_port_add (vm, port, 1, iavf_port_poll_stats);

done:
  if (rv)
    {
      foreach_vnet_dev_port_rx_queue (q, port)
	iavf_rx_queue_stop (vm, q);
      foreach_vnet_dev_port_tx_queue (q, port)
	iavf_tx_queue_stop (vm, q);
    }
  return rv;
}

void
iavf_port_stop (vlib_main_t *vm, vnet_dev_port_t *port)
{
  log_debug (port->dev, "port %u", port->port_id);

  iavf_enable_disable_queues (vm, port, /* enable */ 0);
  iavf_port_rx_irq_config (vm, port, /* disable */ 0);

  if (port->dev->poll_stats)
    vnet_dev_poll_port_remove (vm, port, iavf_port_poll_stats);

  foreach_vnet_dev_port_rx_queue (rxq, port)
    iavf_rx_queue_stop (vm, rxq);

  foreach_vnet_dev_port_tx_queue (txq, port)
    iavf_tx_queue_stop (vm, txq);

  vnet_dev_port_state_change (vm, port,
			      (vnet_dev_port_state_changes_t){
				.change.link_state = 1,
				.change.link_speed = 1,
				.link_speed = 0,
				.link_state = 0,
			      });
}

vnet_dev_rv_t
iavf_port_cfg_change_validate (vlib_main_t *vm, vnet_dev_port_t *port,
			       vnet_dev_port_cfg_change_req_t *req)
{
  vnet_dev_rv_t rv = VNET_DEV_OK;

  switch (req->type)
    {
    case VNET_DEV_PORT_CFG_MAX_RX_FRAME_SIZE:
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
iavf_port_add_del_eth_addr (vlib_main_t *vm, vnet_dev_port_t *port,
			    vnet_dev_hw_addr_t *addr, int is_add,
			    int is_primary)
{
  iavf_port_t *ap = vnet_dev_get_port_data (port);
  u8 buffer[VIRTCHNL_MSG_SZ (virtchnl_ether_addr_list_t, list, 1)];
  virtchnl_ether_addr_list_t *al = (virtchnl_ether_addr_list_t *) buffer;

  *al = (virtchnl_ether_addr_list_t){
    .vsi_id = ap->vsi_id,
    .num_elements = 1,
    .list[0].primary = is_primary ? 1 : 0,
    .list[0].extra = is_primary ? 0 : 1,
  };

  clib_memcpy (al->list[0].addr, addr, sizeof (al->list[0].addr));

  return is_add ? iavf_vc_op_add_eth_addr (vm, port->dev, al) :
		  iavf_vc_op_del_eth_addr (vm, port->dev, al);
}

static vnet_dev_rv_t
iavf_port_cfg_rxq_int_mode_change (vlib_main_t *vm, vnet_dev_port_t *port,
				   u16 qid, u8 state, u8 all)
{
  vnet_dev_rv_t rv = VNET_DEV_OK;
  iavf_port_t *ap = vnet_dev_get_port_data (port);
  vnet_dev_t *dev = port->dev;
  char *ed = state ? "ena" : "disa";
  char qstr[16];
  u64 old, _new = 0;

  state = state != 0;
  old = ap->intr_mode_per_rxq_bitmap;

  if (all)
    {
      snprintf (qstr, sizeof (qstr), "all queues");
      if (state)
	foreach_vnet_dev_port_rx_queue (q, port)
	  u64_bit_set (&_new, q->queue_id, 1);
    }
  else
    {
      snprintf (qstr, sizeof (qstr), "queue %u", qid);
      _new = old;
      u64_bit_set (&_new, qid, state);
    }

  if (_new == old)
    {
      log_warn (dev, "interrupt mode already %sbled on %s", ed, qstr);
      return rv;
    }

  ap->intr_mode_per_rxq_bitmap = _new;

  if (port->started)
    {
      if ((rv = iavf_port_rx_irq_config (vm, port, 1)))
	{
	  ap->intr_mode_per_rxq_bitmap = old;
	  log_err (dev, "failed to %sble interrupt mode on %s", ed, qstr);
	  return rv;
	}
    }

  log_debug (dev, "interrupt mode %sbled on %s, new bitmap is 0x%x", ed, qstr, _new);
  return rv;
}

vnet_dev_rv_t
iavf_port_cfg_change (vlib_main_t *vm, vnet_dev_port_t *port,
		      vnet_dev_port_cfg_change_req_t *req)
{
  vnet_dev_t *dev = port->dev;
  iavf_port_t *ap = vnet_dev_get_port_data (port);
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

	rv = iavf_vc_op_config_promisc_mode (vm, dev, &pi);
      }
      break;

    case VNET_DEV_PORT_CFG_CHANGE_PRIMARY_HW_ADDR:
      rv = iavf_port_add_del_eth_addr (vm, port, &port->primary_hw_addr,
				       /* is_add */ 0,
				       /* is_primary */ 1);
      if (rv == VNET_DEV_OK)
	rv = iavf_port_add_del_eth_addr (vm, port, &req->addr,
					 /* is_add */ 1,
					 /* is_primary */ 1);
      break;

    case VNET_DEV_PORT_CFG_ADD_SECONDARY_HW_ADDR:
      rv = iavf_port_add_del_eth_addr (vm, port, &req->addr,
				       /* is_add */ 1,
				       /* is_primary */ 0);
      break;

    case VNET_DEV_PORT_CFG_REMOVE_SECONDARY_HW_ADDR:
      rv = iavf_port_add_del_eth_addr (vm, port, &req->addr,
				       /* is_add */ 0,
				       /* is_primary */ 0);
      break;

    case VNET_DEV_PORT_CFG_MAX_RX_FRAME_SIZE:
      break;

    case VNET_DEV_PORT_CFG_RXQ_INTR_MODE_ENABLE:
      rv = iavf_port_cfg_rxq_int_mode_change (vm, port, req->queue_id, 1,
					      req->all_queues);
      break;

    case VNET_DEV_PORT_CFG_RXQ_INTR_MODE_DISABLE:
      rv = iavf_port_cfg_rxq_int_mode_change (vm, port, req->queue_id, 0,
					      req->all_queues);
      break;

    default:
      return VNET_DEV_ERR_NOT_SUPPORTED;
    };

  return rv;
}
