/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vnet/dev/pci.h>
#include <vnet/dev/counters.h>
#include <dev_avf/avf.h>
#include <dev_avf/virtchnl.h>
#include <vnet/ethernet/ethernet.h>

VLIB_REGISTER_LOG_CLASS (avf_log, static) = {
  .class_name = "dev_avf",
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
	s = format (s, "%U", format_avf_vf_cap_flags, *r);
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
      {
	virtchnl_ether_addr_list_t *r = p;
	s = format (s, "vsi %u num_elements %u elts: ", r->vsi_id,
		    r->num_elements);
	for (int i = 0; i < r->num_elements; i++)
	  s = format (s, "%s%U", i ? ", " : "", format_ethernet_address,
		      r->list[i].addr);
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
    default:
      s = format (s, "unknown op 0x04x", op);
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
		    indent + 2, r->vf_cap_flags, format_avf_vf_cap_flags,
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
    case VIRTCHNL_OP_GET_OFFLOAD_VLAN_V2_CAPS:
      {
	virtchnl_vlan_caps_t *r = p;
	s = format (s, "filtering: ethertype_init 0x%x max_filters %u",
		    r->filtering.ethertype_init, r->filtering.max_filters);
	s = format (s, "\n%Uoffloads: ethertype_init 0x%x ethertype_match %u",
		    format_white_space, indent, r->offloads.ethertype_init,
		    r->offloads.ethertype_match);
      }
      break;
    default:
      s = format (s, "unknown op 0x04x", op);
      break;
    };
  return s;
}

vnet_dev_rv_t
avf_virtchnl_req (vlib_main_t *vm, vnet_dev_t *dev, virtchnl_op_t op,
		  void *req, u16 req_sz, void *resp, u16 resp_sz)
{
  avf_device_t *ad = vnet_dev_get_data (dev);
  vnet_dev_rv_t rv;
  avf_aq_desc_t *d;
  u8 *b;

  log_debug (dev, "%U req:\n  %U", format_virtchnl_op_name, op,
	     format_virtchnl_op_req, op, req);

  avf_aq_desc_t txd = {
    .opcode = AVF_AQ_DESC_OP_SEND_TO_PF,
    .v_opcode = op,
    .flags = { .si = 1 },
  };

  rv = avf_aq_atq_enq (vm, dev, &txd, req, req_sz, 0.5);

  if (rv != VNET_DEV_OK)
    return rv;

retry:
  if (!avf_aq_arq_next_acq (vm, dev, &d, &b, 1.0))
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
      avf_aq_arq_next_rel (vm, dev);
      goto retry;
    }

  if (d->v_opcode != op)
    {
      log_err (dev,
	       "unexpected response received [v_opcode = %u, expected %u, "
	       "v_retval %d]",
	       d->v_opcode, op, d->v_retval);
      rv = VNET_DEV_ERR_BUG;
      goto done;
    }

  if (d->v_retval)
    {
      log_err (dev, "error [v_opcode = %u, v_retval %d]", d->v_opcode,
	       d->v_retval);
      rv = VNET_DEV_ERR_BUG;
      goto done;
    }

  if (resp_sz && d->flags.buf)
    clib_memcpy_fast (resp, b, resp_sz);

done:
  avf_aq_arq_next_rel (vm, dev);
  if (rv == VNET_DEV_OK)
    log_debug (dev, "%U resp:\n  %U", format_virtchnl_op_name, op,
	       format_virtchnl_op_resp, op, resp);
  return rv;
}
