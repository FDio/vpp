/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vnet/dev/counters.h>
#include <dev_iavf/iavf.h>
#include <dev_iavf/virtchnl.h>
#include <dev_iavf/virtchnl_funcs.h>
#include <vnet/ethernet/ethernet.h>

VLIB_REGISTER_LOG_CLASS (iavf_log, static) = {
  .class_name = "iavf",
  .subclass_name = "virtchnl",
};

u8 *
format_virtchnl_op_name (u8 *s, va_list *args)
{
  virtchnl_op_t op = va_arg (*args, virtchnl_op_t);
  char *op_names[] = {
#define _(a, b) [a] = #b,
    foreach_virtchnl_op
#undef _
  };

  if (op >= ARRAY_LEN (op_names) || op_names[op] == 0)
    return format (s, "UNKNOWN(%u)", op);

  return format (s, "%s", op_names[op]);
}

u8 *
format_virtchnl_status (u8 *s, va_list *args)
{
  virtchnl_status_t c = va_arg (*args, virtchnl_status_t);

  if (0)
    ;
#define _(a, b) else if (c == a) return format (s, #b);
  foreach_virtchnl_status
#undef _
    return format (s, "UNKNOWN(%d)", c);
}

static u8 *
format_virtchnl_vlan_support_caps (u8 *s, va_list *args)
{
  virtchnl_vlan_support_caps_t v = va_arg (*args, u32);
  int not_first = 0;

  char *strs[32] = {
#define _(a, b, c) [a] = c,
    foreach_virtchnl_vlan_support_bit
#undef _
  };

  if (v == VIRTCHNL_VLAN_UNSUPPORTED)
    return format (s, "unsupported");

  for (int i = 0; i < 32; i++)
    {
      if ((v & (1 << i)) == 0)
	continue;
      if (not_first)
	s = format (s, " ");
      if (strs[i])
	s = format (s, "%s", strs[i]);
      else
	s = format (s, "unknown(%u)", i);
      not_first = 1;
    }
  return s;
}

static u8 *
format_virtchnl_op_req (u8 *s, va_list *args)
{
  virtchnl_op_t op = va_arg (*args, virtchnl_op_t);
  void *p = va_arg (*args, void *);
  u32 indent = format_get_indent (s);

  if (p == 0)
    return format (s, "no data");

  switch (op)
    {
    case VIRTCHNL_OP_VERSION:
      {
	virtchnl_version_info_t *r = p;
	s = format (s, "version: %u.%u", r->major, r->minor);
      }
      break;
    case VIRTCHNL_OP_GET_VF_RESOURCES:
      {
	u32 *r = p;
	s = format (s, "%U", format_iavf_vf_cap_flags, *r);
      }
      break;
    case VIRTCHNL_OP_ENABLE_QUEUES:
    case VIRTCHNL_OP_DISABLE_QUEUES:
    case VIRTCHNL_OP_GET_STATS:
      {
	virtchnl_queue_select_t *r = p;
	s = format (s, "vsi %u rx 0x%x tx 0x%x", r->vsi_id, r->rx_queues,
		    r->tx_queues);
      }
      break;
    case VIRTCHNL_OP_CONFIG_VSI_QUEUES:
      {
	virtchnl_vsi_queue_config_info_t *r = p;
	s = format (s, "vsi %u num_qp %u", r->vsi_id, r->num_queue_pairs);
	for (int i = 0; i < r->num_queue_pairs; i++)
	  {
	    virtchnl_rxq_info_t *ri = &r->qpair[i].rxq;
	    virtchnl_txq_info_t *ti = &r->qpair[i].txq;

	    s = format (s, "\n%U qpair %u", format_white_space, indent + 2, i);
	    s = format (s,
			"\n%U rx vsi %u queue %u dma_ring_addr 0x%lx "
			"ring_len %u data_sz %u max_pkt_sz %u",
			format_white_space, indent + 4, ri->vsi_id,
			ri->queue_id, ri->dma_ring_addr, ri->ring_len,
			ri->databuffer_size, ri->max_pkt_size);
	    s = format (
	      s, "\n%U tx vsi %u queue %u dma_ring_addr 0x%lx ring_len %u",
	      format_white_space, indent + 4, ti->vsi_id, ti->queue_id,
	      ti->dma_ring_addr, ti->ring_len);
	  }
      }
      break;
    case VIRTCHNL_OP_CONFIG_IRQ_MAP:
      {
	virtchnl_irq_map_info_t *r = p;
	s = format (s, "num_vectors %u", r->num_vectors);
	for (int i = 0; i < r->num_vectors; i++)
	  {
	    virtchnl_vector_map_t *vecmap = r->vecmap + i;
	    s = format (s,
			"\n%Uvsi %u vector_id %u rxq_map 0x%04x txq_map "
			"0x%04x rxitr_idx %u txitr_idx %u",
			format_white_space, indent + 2, vecmap->vsi_id,
			vecmap->vector_id, vecmap->rxq_map, vecmap->txq_map,
			vecmap->rxitr_idx, vecmap->txitr_idx);
	  }
      }
      break;
    case VIRTCHNL_OP_CONFIG_RSS_LUT:
      {
	virtchnl_rss_lut_t *r = p;
	s = format (s, "vsi %u entries %u lut", r->vsi_id, r->lut_entries);
	for (int i = 0; i < r->lut_entries; i++)
	  s = format (s, " %u", r->lut[i]);
      }
      break;
    case VIRTCHNL_OP_CONFIG_RSS_KEY:
      {
	virtchnl_rss_key_t *r = p;
	s = format (s, "vsi %u len %u key ", r->vsi_id, r->key_len);
	for (int i = 0; i < r->key_len; i++)
	  s = format (s, "%02x", r->key[i]);
      }
      break;
    case VIRTCHNL_OP_ADD_ETH_ADDR:
    case VIRTCHNL_OP_DEL_ETH_ADDR:
      {
	virtchnl_ether_addr_list_t *r = p;
	s = format (s, "vsi %u num_elements %u elts: ", r->vsi_id,
		    r->num_elements);
	for (int i = 0; i < r->num_elements; i++)
	  s = format (s, "%s%U%s%s", i ? ", " : "", format_ethernet_address,
		      r->list[i].addr, r->list[i].primary ? " primary" : "",
		      r->list[i].extra ? " extra" : "");
      }
      break;
    case VIRTCHNL_OP_CONFIG_PROMISCUOUS_MODE:
      {
	virtchnl_promisc_info_t *r = p;
	s = format (
	  s, "promisc_info: vsi %u flags 0x%x (unicast %s multicast %s)",
	  r->vsi_id, r->flags,
	  r->flags & FLAG_VF_UNICAST_PROMISC ? "on" : "off",
	  r->flags & FLAG_VF_MULTICAST_PROMISC ? "on" : "off");
      }
      break;
    case VIRTCHNL_OP_DISABLE_VLAN_STRIPPING_V2:
      {
	virtchnl_vlan_setting_t *r = p;
	s = format (s,
		    "vport %u outer_ethertype_setting 0x%x [%U] "
		    "inner_ethertype_setting 0x%x [%U]",
		    r->vport_id, r->outer_ethertype_setting,
		    format_virtchnl_vlan_support_caps,
		    r->outer_ethertype_setting, r->inner_ethertype_setting,
		    format_virtchnl_vlan_support_caps,
		    r->inner_ethertype_setting);
      }
      break;
    default:
      s = format (s, "unknown op 0x%04x", op);
      break;
    };
  return s;
}
static u8 *
format_virtchnl_op_resp (u8 *s, va_list *args)
{
  virtchnl_op_t op = va_arg (*args, virtchnl_op_t);
  void *p = va_arg (*args, void *);
  u32 indent = format_get_indent (s);

  if (p == 0)
    return format (s, "no data");

  switch (op)
    {
    case VIRTCHNL_OP_VERSION:
      {
	virtchnl_version_info_t *r = p;
	s = format (s, "version %u.%u", r->major, r->minor);
      }
      break;
    case VIRTCHNL_OP_GET_VF_RESOURCES:
      {
	virtchnl_vf_resource_t *r = p;
	s =
	  format (s,
		  "vf_resource: num_vsis %u num_queue_pairs %u "
		  "max_vectors %u max_mtu %u rss_key_size %u rss_lut_size %u",
		  r->num_vsis, r->num_queue_pairs, r->max_vectors, r->max_mtu,
		  r->rss_key_size, r->rss_lut_size);
	s = format (s, "\n%Uvf_cap_flags 0x%x (%U)", format_white_space,
		    indent + 2, r->vf_cap_flags, format_iavf_vf_cap_flags,
		    r->vf_cap_flags);
	for (int i = 0; i < r->num_vsis; i++)
	  s = format (s,
		      "\n%Uvsi_resource[%u]: vsi %u num_qp %u vsi_type %u "
		      "qset_handle %u default_mac_addr %U",
		      format_white_space, indent + 2, i, r->vsi_res[i].vsi_id,
		      r->vsi_res[i].num_queue_pairs, r->vsi_res[i].vsi_type,
		      r->vsi_res[i].qset_handle, format_ethernet_address,
		      r->vsi_res[i].default_mac_addr);
      }
      break;
    case VIRTCHNL_OP_GET_OFFLOAD_VLAN_V2_CAPS:
      {
	virtchnl_vlan_caps_t *r = p;
	s = format (s, "filtering: ethertype_init 0x%x max_filters %u",
		    r->filtering.ethertype_init, r->filtering.max_filters);
	s = format (s, "\n%U outer [%U] inner [%U]", format_white_space,
		    indent, format_virtchnl_vlan_support_caps,
		    r->filtering.filtering_support.outer,
		    format_virtchnl_vlan_support_caps,
		    r->filtering.filtering_support.inner);
	s = format (s, "\n%Uoffloads: ethertype_init 0x%x ethertype_match %u",
		    format_white_space, indent, r->offloads.ethertype_init,
		    r->offloads.ethertype_match);
	s = format (s, "\n%U stripping outer [%U] stripping inner [%U]",
		    format_white_space, indent,
		    format_virtchnl_vlan_support_caps,
		    r->offloads.stripping_support.outer,
		    format_virtchnl_vlan_support_caps,
		    r->offloads.stripping_support.inner);
	s = format (s, "\n%U insertion outer [%U] inserion inner [%U]",
		    format_white_space, indent,
		    format_virtchnl_vlan_support_caps,
		    r->offloads.insertion_support.outer,
		    format_virtchnl_vlan_support_caps,
		    r->offloads.insertion_support.inner);
      }
      break;
    case VIRTCHNL_OP_GET_STATS:
      {
	virtchnl_eth_stats_t *r = p;
	s = format (s,
		    "rx: bytes %lu, unicast %lu, multicast %lu, broadcast "
		    "%lu, discards %lu unknown_protocol %lu",
		    r->rx_bytes, r->rx_unicast, r->rx_multicast,
		    r->rx_broadcast, r->rx_discards, r->rx_unknown_protocol);
	s = format (s, "\n%U", format_white_space, indent);
	s = format (s,
		    "tx: bytes %lu, unicast %lu, multicast %lu, broadcast "
		    "%lu, discards %lu errors %lu",
		    r->tx_bytes, r->tx_unicast, r->tx_multicast,
		    r->tx_broadcast, r->tx_discards, r->tx_errors);
      }
      break;
    default:
      s = format (s, "unknown op 0x%04x", op);
      break;
    };
  return s;
}

vnet_dev_rv_t
iavf_virtchnl_req (vlib_main_t *vm, vnet_dev_t *dev, iavf_virtchnl_req_t *r)
{
  iavf_device_t *ad = vnet_dev_get_data (dev);
  vnet_dev_rv_t rv;
  iavf_aq_desc_t *d;
  u8 *b;

  log_debug (dev, "%U req:\n  %U", format_virtchnl_op_name, r->op,
	     format_virtchnl_op_req, r->op, r->req);

  iavf_aq_desc_t txd = {
    .opcode = IIAVF_AQ_DESC_OP_SEND_TO_PF,
    .v_opcode = r->op,
    .flags = { .si = 1 },
  };

  rv = iavf_aq_atq_enq (vm, dev, &txd, r->req, r->req_sz, 0.5);

  if (rv != VNET_DEV_OK)
    return rv;

  if (r->no_reply)
    return VNET_DEV_OK;

retry:
  if (!iavf_aq_arq_next_acq (vm, dev, &d, &b, 1.0))
    {
      log_err (ad, "timeout waiting for virtchnl response");
      return VNET_DEV_ERR_TIMEOUT;
    }

  if (d->v_opcode == VIRTCHNL_OP_EVENT)
    {
      if ((d->datalen != sizeof (virtchnl_pf_event_t)) ||
	  ((d->flags.buf) == 0))
	{
	  log_err (dev, "event message error");
	  return VNET_DEV_ERR_BUG;
	}

      vec_add1 (ad->events, *(virtchnl_pf_event_t *) b);
      iavf_aq_arq_next_rel (vm, dev);
      goto retry;
    }

  if (d->v_opcode != r->op)
    {
      log_err (dev,
	       "unexpected response received [v_opcode = %u, expected %u, "
	       "v_retval %d]",
	       d->v_opcode, r->op, d->v_retval);
      rv = VNET_DEV_ERR_BUG;
      goto done;
    }

  r->status = d->v_retval;

  if (d->v_retval)
    {
      log_err (dev, "error [v_opcode = %u, v_retval %d]", d->v_opcode,
	       d->v_retval);
      rv = VNET_DEV_ERR_BUG;
      goto done;
    }

  if (r->resp_sz && d->flags.buf)
    clib_memcpy_fast (r->resp, b, r->resp_sz);

done:
  iavf_aq_arq_next_rel (vm, dev);
  if (rv == VNET_DEV_OK)
    log_debug (dev, "%U resp:\n  %U", format_virtchnl_op_name, r->op,
	       format_virtchnl_op_resp, r->op, r->resp);
  return rv;
}
