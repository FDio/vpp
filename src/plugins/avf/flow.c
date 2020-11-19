/*
 *------------------------------------------------------------------
 * Copyright (c) 2020 Intel and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *------------------------------------------------------------------
 */

#include <vlib/vlib.h>
#include <vppinfra/ring.h>
#include <vlib/unix/unix.h>
#include <vlib/pci/pci.h>
#include <vnet/ethernet/ethernet.h>

#include <avf/avf.h>
#include <avf/iavf_osdep.h>
#include <avf/iavf_pkts.h>
#include "virtchnl_proto.h"
#include <avf/iavf_fdir_lib.h>

int
avf_fdir_vc_op_callback (void *vc_hdl, enum virthnl_adv_ops vc_op,
			 void *in, u32 in_len, void *out, u32 out_len)
{
  u32 dev_instance = *(u32 *) vc_hdl;
  avf_device_t *ad = avf_get_device (dev_instance);
  clib_error_t *err = 0;
  virtchnl_ops_t op;

  if (vc_op >= VIRTCHNL_ADV_OP_MAX)
    {
      return -1;
    }

  switch (vc_op)
    {
    case VIRTCHNL_ADV_OP_ADD_FDIR_FILTER:
      op = VIRTCHNL_OP_ADD_FDIR_FILTER;
      break;
    case VIRTCHNL_ADV_OP_DEL_FDIR_FILTER:
      op = VIRTCHNL_OP_DEL_FDIR_FILTER;
      break;
    default:
      avf_log_err (ad, "unsupported avf virtual channel opcode %u\n",
		   (u32) vc_op);
      return -1;
    }

  err =
    avf_general_virtchnl_event_request (dev_instance, op, in, in_len, out,
					out_len);
  if (err != 0)
    {
      avf_log_err (ad, "avf fdir program failed: %U", format_clib_error, err);
      clib_error_free (err);
      return -1;
    }

  avf_log_debug (ad, "avf fdir program success");
  return 0;
}

static int
avf_flow_add (u32 dev_instance, vnet_flow_t * f, avf_flow_entry_t * fe)
{
  avf_device_t *ad = avf_get_device (dev_instance);
  int rv = 0;
  int ret = 0;
  u16 src_port = 0, dst_port = 0;
  u16 src_port_mask = 0, dst_port_mask = 0;
  u8 protocol = IP_PROTOCOL_RESERVED;
  bool fate = false;
  struct iavf_flow_error error;

  int layer = 0;
  int action_count = 0;

  struct iavf_fdir_vc_ctx vc_ctx;
  struct iavf_fdir_conf *filter;
  struct iavf_flow_item iavf_items[VIRTCHNL_MAX_NUM_PROTO_HDRS];
  struct iavf_flow_action iavf_actions[VIRTCHNL_MAX_NUM_ACTIONS];

  struct iavf_ipv4_hdr ip4_spec, ip4_mask;
  struct iavf_tcp_hdr tcp_spec, tcp_mask;
  struct iavf_udp_hdr udp_spec, udp_mask;
  struct iavf_gtp_hdr gtp_spec, gtp_mask;

  struct iavf_flow_action_queue act_q;
  struct iavf_flow_action_mark act_msk;

  ret = iavf_fdir_rcfg_create (&filter, 0, ad->vsi_id, ad->n_rx_queues);
  if (ret)
    {
      rv = VNET_FLOW_ERROR_INTERNAL;
      goto done;
    }

  /* init a virtual channel context */
  vc_ctx.vc_hdl = &dev_instance;
  vc_ctx.vc_op = avf_fdir_vc_op_callback;

  clib_memset (iavf_items, 0, sizeof (iavf_actions));
  clib_memset (iavf_actions, 0, sizeof (iavf_actions));

  /* Ethernet Layer */
  iavf_items[layer].type = VIRTCHNL_PROTO_HDR_ETH;
  iavf_items[layer].spec = NULL;
  layer++;

  /* IPv4 Layer */
  if ((f->type == VNET_FLOW_TYPE_IP4_N_TUPLE) ||
      (f->type == VNET_FLOW_TYPE_IP4_GTPU))
    {
      vnet_flow_ip4_n_tuple_t *t4 = &f->ip4_n_tuple;
      memset (&ip4_spec, 0, sizeof (ip4_spec));
      memset (&ip4_mask, 0, sizeof (ip4_mask));

      /* IPv4 Layer */
      iavf_items[layer].type = VIRTCHNL_PROTO_HDR_IPV4;
      iavf_items[layer].spec = &ip4_spec;
      iavf_items[layer].mask = &ip4_mask;
      layer++;

      src_port = t4->src_port.port;
      dst_port = t4->dst_port.port;
      src_port_mask = t4->src_port.mask;
      dst_port_mask = t4->dst_port.mask;
      protocol = t4->protocol.prot;

      if (t4->src_addr.mask.as_u32)
	{
	  ip4_spec.src_addr = t4->src_addr.addr.as_u32;
	  ip4_mask.src_addr = t4->src_addr.mask.as_u32;
	}
      if (t4->dst_addr.mask.as_u32)
	{
	  ip4_spec.dst_addr = t4->dst_addr.addr.as_u32;
	  ip4_mask.dst_addr = t4->dst_addr.mask.as_u32;
	}
    }

  if (protocol == IP_PROTOCOL_TCP)
    {
      memset (&tcp_spec, 0, sizeof (tcp_spec));
      memset (&tcp_mask, 0, sizeof (tcp_mask));

      iavf_items[layer].type = VIRTCHNL_PROTO_HDR_TCP;
      iavf_items[layer].spec = &tcp_spec;
      iavf_items[layer].mask = &tcp_mask;
      layer++;

      if (src_port_mask)
	{
	  tcp_spec.src_port = clib_host_to_net_u16 (src_port);
	  tcp_mask.src_port = clib_host_to_net_u16 (src_port_mask);
	}
      if (dst_port_mask)
	{
	  tcp_spec.dst_port = clib_host_to_net_u16 (dst_port);
	  tcp_mask.dst_port = clib_host_to_net_u16 (dst_port_mask);
	}
    }
  else if (protocol == IP_PROTOCOL_UDP)
    {
      memset (&udp_spec, 0, sizeof (udp_spec));
      memset (&udp_mask, 0, sizeof (udp_mask));

      iavf_items[layer].type = VIRTCHNL_PROTO_HDR_UDP;
      iavf_items[layer].spec = &udp_spec;
      iavf_items[layer].mask = &udp_mask;
      layer++;

      if (src_port_mask)
	{
	  udp_spec.src_port = clib_host_to_net_u16 (src_port);
	  udp_mask.src_port = clib_host_to_net_u16 (src_port_mask);
	}
      if (dst_port_mask)
	{
	  udp_spec.dst_port = clib_host_to_net_u16 (dst_port);
	  udp_mask.dst_port = clib_host_to_net_u16 (dst_port_mask);
	}
    }
  else
    {
      rv = VNET_FLOW_ERROR_NOT_SUPPORTED;
      goto done;
    }

  if (f->type == VNET_FLOW_TYPE_IP4_GTPU)
    {

      memset (&gtp_spec, 0, sizeof (gtp_spec));
      memset (&gtp_mask, 0, sizeof (gtp_mask));

      vnet_flow_ip4_gtpu_t *gu = &f->ip4_gtpu;
      gtp_spec.teid = clib_host_to_net_u32 (gu->teid);
      gtp_mask.teid = ~0;

      iavf_items[layer].type = VIRTCHNL_PROTO_HDR_GTPU_IP;
      iavf_items[layer].spec = &gtp_spec;
      iavf_items[layer].mask = &gtp_mask;
      layer++;
    }

  /* pattern end flag  */
  iavf_items[layer].type = VIRTCHNL_PROTO_HDR_NONE;
  ret = iavf_fdir_parse_pattern (filter, iavf_items, &error);
  if (ret)
    {
      avf_log_err (ad, "avf fdir parse pattern failed: %s", error.message);
      rv = VNET_FLOW_ERROR_NOT_SUPPORTED;
      goto done;
    }

  /* Action */
  /* Only one 'fate' can be assigned */
  if (f->actions & VNET_FLOW_ACTION_REDIRECT_TO_QUEUE)
    {
      iavf_actions[action_count].type = VIRTCHNL_ACTION_QUEUE;
      iavf_actions[action_count].conf = &act_q;

      act_q.index = f->redirect_queue;
      fate = true;
      action_count++;
    }

  if (f->actions & VNET_FLOW_ACTION_DROP)
    {
      iavf_actions[action_count].type = VIRTCHNL_ACTION_DROP;
      iavf_actions[action_count].conf = NULL;

      if (fate == true)
	{
	  rv = VNET_FLOW_ERROR_INTERNAL;
	  goto done;
	}
      else
	fate = true;

      action_count++;
    }

  if (fate == false)
    {
      iavf_actions[action_count].type = VIRTCHNL_ACTION_PASSTHRU;
      iavf_actions[action_count].conf = NULL;

      fate = true;
      action_count++;
    }

  if (f->actions & VNET_FLOW_ACTION_MARK)
    {
      iavf_actions[action_count].type = VIRTCHNL_ACTION_MARK;
      iavf_actions[action_count].conf = &act_msk;
      action_count++;

      act_msk.id = fe->mark;
    }

  /* action end flag */
  iavf_actions[action_count].type = VIRTCHNL_ACTION_NONE;

  /* parse action */
  ret = iavf_fdir_parse_action (iavf_actions, filter, &error);
  if (ret)
    {
      avf_log_err (ad, "avf fdir parse action failed: %s", error.message);
      rv = VNET_FLOW_ERROR_NOT_SUPPORTED;
      goto done;
    }

  /* create flow rule, save rule */
  ret = iavf_fdir_rule_create (&vc_ctx, filter);

  if (ret)
    {
      avf_log_err (ad, "avf fdir rule create failed: %s",
		   iavf_fdir_prgm_error_decode (ret));
      rv = VNET_FLOW_ERROR_INTERNAL;
      goto done;
    }
  else
    {
      fe->rcfg = filter;
    }
done:

  return rv;
}

int
avf_flow_ops_fn (vnet_main_t * vm, vnet_flow_dev_op_t op, u32 dev_instance,
		 u32 flow_index, uword * private_data)
{
  vnet_flow_t *flow = vnet_get_flow (flow_index);
  avf_device_t *ad = avf_get_device (dev_instance);
  avf_flow_entry_t *fe = NULL;
  avf_flow_lookup_entry_t *fle = NULL;
  int rv = 0;

  if ((ad->feature_bitmap & VIRTCHNL_VF_OFFLOAD_FDIR_PF) == 0)
    {
      rv = VNET_FLOW_ERROR_NOT_SUPPORTED;
      goto done;
    }

  if (op == VNET_FLOW_DEV_OP_ADD_FLOW)
    {
      pool_get (ad->flow_entries, fe);
      fe->flow_index = flow->index;

      /* if we need to mark packets, assign one mark */
      if (flow->actions &
	  (VNET_FLOW_ACTION_MARK | VNET_FLOW_ACTION_REDIRECT_TO_NODE |
	   VNET_FLOW_ACTION_BUFFER_ADVANCE))
	{
	  /* reserve slot 0 */
	  if (ad->flow_lookup_entries == 0)
	    pool_get_aligned (ad->flow_lookup_entries, fle,
			      CLIB_CACHE_LINE_BYTES);
	  pool_get_aligned (ad->flow_lookup_entries, fle,
			    CLIB_CACHE_LINE_BYTES);
	  fe->mark = fle - ad->flow_lookup_entries;

	  /* install entry in the lookup table */
	  clib_memset (fle, -1, sizeof (*fle));
	  if (flow->actions & VNET_FLOW_ACTION_MARK)
	    fle->flow_id = flow->mark_flow_id;
	  if (flow->actions & VNET_FLOW_ACTION_REDIRECT_TO_NODE)
	    fle->next_index = flow->redirect_device_input_next_index;
	  if (flow->actions & VNET_FLOW_ACTION_BUFFER_ADVANCE)
	    fle->buffer_advance = flow->buffer_advance;

	  if ((ad->flags & AVF_DEVICE_F_RX_FLOW_OFFLOAD) == 0)
	    {
	      ad->flags |= AVF_DEVICE_F_RX_FLOW_OFFLOAD;
	    }
	}
      else
	fe->mark = 0;

      switch (flow->type)
	{
	case VNET_FLOW_TYPE_IP4_N_TUPLE:
	case VNET_FLOW_TYPE_IP4_GTPU:
	  if ((rv = avf_flow_add (dev_instance, flow, fe)))
	    goto done;
	  break;
	default:
	  rv = VNET_FLOW_ERROR_NOT_SUPPORTED;
	  goto done;
	}

      *private_data = fe - ad->flow_entries;
    }
  else if (op == VNET_FLOW_DEV_OP_DEL_FLOW)
    {
      fe = vec_elt_at_index (ad->flow_entries, *private_data);

      struct iavf_fdir_vc_ctx ctx;
      ctx.vc_hdl = &dev_instance;
      ctx.vc_op = avf_fdir_vc_op_callback;

      rv = iavf_fdir_rule_destroy (&ctx, fe->rcfg);
      if (rv)
	return VNET_FLOW_ERROR_INTERNAL;

      if (fe->mark)
	{
	  fle = pool_elt_at_index (ad->flow_lookup_entries, fe->mark);
	  clib_memset (fle, -1, sizeof (*fle));
	  pool_put_index (ad->flow_lookup_entries, fe->mark);
	}

      (void) iavf_fdir_rcfg_destroy (fe->rcfg);
      clib_memset (fe, 0, sizeof (*fe));
      pool_put (ad->flow_entries, fe);
      goto disable_rx_offload;
    }
  else
    return VNET_FLOW_ERROR_NOT_SUPPORTED;

done:
  if (rv)
    {
      if (fe)
	{
	  clib_memset (fe, 0, sizeof (*fe));
	  pool_put (ad->flow_entries, fe);
	}

      if (fle)
	{
	  clib_memset (fle, -1, sizeof (*fle));
	  pool_put (ad->flow_lookup_entries, fle);
	}
    }
disable_rx_offload:
  if ((ad->flags & AVF_DEVICE_F_RX_FLOW_OFFLOAD) != 0
      && pool_elts (ad->flow_entries) == 0)
    {
      ad->flags &= ~AVF_DEVICE_F_RX_FLOW_OFFLOAD;
    }

  return rv;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
