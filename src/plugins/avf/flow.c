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

#include <stdbool.h>
#include <vlib/vlib.h>
#include <vppinfra/ring.h>
#include <vlib/unix/unix.h>
#include <vlib/pci/pci.h>
#include <vnet/ethernet/ethernet.h>

#include <avf/avf.h>
#include <avf/avf_advanced_flow.h>

#define FLOW_IS_ETHERNET_CLASS(f) (f->type == VNET_FLOW_TYPE_ETHERNET)

#define FLOW_IS_IPV4_CLASS(f)                                                 \
  ((f->type == VNET_FLOW_TYPE_IP4) ||                                         \
   (f->type == VNET_FLOW_TYPE_IP4_N_TUPLE) ||                                 \
   (f->type == VNET_FLOW_TYPE_IP4_N_TUPLE_TAGGED) ||                          \
   (f->type == VNET_FLOW_TYPE_IP4_VXLAN) ||                                   \
   (f->type == VNET_FLOW_TYPE_IP4_GTPC) ||                                    \
   (f->type == VNET_FLOW_TYPE_IP4_GTPU) ||                                    \
   (f->type == VNET_FLOW_TYPE_IP4_L2TPV3OIP) ||                               \
   (f->type == VNET_FLOW_TYPE_IP4_IPSEC_ESP) ||                               \
   (f->type == VNET_FLOW_TYPE_IP4_IPSEC_AH))

#define FLOW_IS_IPV6_CLASS(f)                                                 \
  ((f->type == VNET_FLOW_TYPE_IP6) ||                                         \
   (f->type == VNET_FLOW_TYPE_IP6_N_TUPLE) ||                                 \
   (f->type == VNET_FLOW_TYPE_IP6_N_TUPLE_TAGGED) ||                          \
   (f->type == VNET_FLOW_TYPE_IP6_VXLAN))

#define FLOW_IS_GENERIC_CLASS(f) (f->type == VNET_FLOW_TYPE_GENERIC)

/* check if flow is L3 type */
#define FLOW_IS_L3_TYPE(f)                                                    \
  ((f->type == VNET_FLOW_TYPE_IP4) || (f->type == VNET_FLOW_TYPE_IP6))

/* check if flow is L4 type */
#define FLOW_IS_L4_TYPE(f)                                                    \
  ((f->type == VNET_FLOW_TYPE_IP4_N_TUPLE) ||                                 \
   (f->type == VNET_FLOW_TYPE_IP6_N_TUPLE) ||                                 \
   (f->type == VNET_FLOW_TYPE_IP4_N_TUPLE_TAGGED) ||                          \
   (f->type == VNET_FLOW_TYPE_IP6_N_TUPLE_TAGGED))

/* check if flow is L4 tunnel type */
#define FLOW_IS_L4_TUNNEL_TYPE(f)                                             \
  ((f->type == VNET_FLOW_TYPE_IP4_VXLAN) ||                                   \
   (f->type == VNET_FLOW_TYPE_IP6_VXLAN) ||                                   \
   (f->type == VNET_FLOW_TYPE_IP4_GTPC) ||                                    \
   (f->type == VNET_FLOW_TYPE_IP4_GTPU))

int
avf_flow_vc_op_callback (void *vc_hdl, enum virthnl_adv_ops vc_op, void *in,
			 u32 in_len, void *out, u32 out_len)
{
  u32 dev_instance = *(u32 *) vc_hdl;
  avf_device_t *ad = avf_get_device (dev_instance);
  clib_error_t *err = 0;
  int is_add;

  if (vc_op >= VIRTCHNL_ADV_OP_MAX)
    {
      return -1;
    }

  switch (vc_op)
    {
    case VIRTCHNL_ADV_OP_ADD_FDIR_FILTER:
    case VIRTCHNL_ADV_OP_ADD_RSS_CFG:
      is_add = 1;
      break;
    case VIRTCHNL_ADV_OP_DEL_FDIR_FILTER:
    case VIRTCHNL_ADV_OP_DEL_RSS_CFG:
      is_add = 0;
      break;
    default:
      avf_log_err (ad, "unsupported avf virtual channel opcode %u\n",
		   (u32) vc_op);
      return -1;
    }

  err =
    avf_program_flow (dev_instance, is_add, vc_op, in, in_len, out, out_len);
  if (err != 0)
    {
      avf_log_err (ad, "avf flow program failed: %U", format_clib_error, err);
      clib_error_free (err);
      return -1;
    }

  avf_log_debug (ad, "avf flow program success");
  return 0;
}

static inline enum avf_eth_hash_function
avf_flow_convert_rss_func (vnet_rss_function_t func)
{
  enum avf_eth_hash_function rss_func;

  switch (func)
    {
    case VNET_RSS_FUNC_DEFAULT:
      rss_func = AVF_ETH_HASH_FUNCTION_DEFAULT;
      break;
    case VNET_RSS_FUNC_TOEPLITZ:
      rss_func = AVF_ETH_HASH_FUNCTION_TOEPLITZ;
      break;
    case VNET_RSS_FUNC_SIMPLE_XOR:
      rss_func = AVF_ETH_HASH_FUNCTION_SIMPLE_XOR;
      break;
    case VNET_RSS_FUNC_SYMMETRIC_TOEPLITZ:
      rss_func = AVF_ETH_HASH_FUNCTION_SYMMETRIC_TOEPLITZ;
      break;
    default:
      rss_func = AVF_ETH_HASH_FUNCTION_MAX;
      break;
    }

  return rss_func;
}

/** Maximum number of queue indices in struct avf_flow_action_rss. */
#define ACTION_RSS_QUEUE_NUM 128

static inline void
avf_flow_convert_rss_queues (u32 queue_index, u32 queue_num,
			     struct avf_flow_action_rss *act_rss)
{
  u16 *queues = clib_mem_alloc (sizeof (*queues) * ACTION_RSS_QUEUE_NUM);
  int i;

  for (i = 0; i < queue_num; i++)
    queues[i] = queue_index++;

  act_rss->queue_num = queue_num;
  act_rss->queue = queues;

  return;
}

void
avf_parse_generic_pattern (struct avf_flow_item *item, u8 *pkt_buf,
			   u8 *msk_buf, u16 spec_len)
{
  u8 *raw_spec, *raw_mask;
  u8 tmp_val = 0;
  u8 tmp_c = 0;
  int i, j;

  raw_spec = (u8 *) item->spec;
  raw_mask = (u8 *) item->mask;

  /* convert string to int array */
  for (i = 0, j = 0; i < spec_len; i += 2, j++)
    {
      tmp_c = raw_spec[i];
      if (tmp_c >= 'a' && tmp_c <= 'f')
	tmp_val = tmp_c - 'a' + 10;
      if (tmp_c >= 'A' && tmp_c <= 'F')
	tmp_val = tmp_c - 'A' + 10;
      if (tmp_c >= '0' && tmp_c <= '9')
	tmp_val = tmp_c - '0';

      tmp_c = raw_spec[i + 1];
      if (tmp_c >= 'a' && tmp_c <= 'f')
	pkt_buf[j] = tmp_val * 16 + tmp_c - 'a' + 10;
      if (tmp_c >= 'A' && tmp_c <= 'F')
	pkt_buf[j] = tmp_val * 16 + tmp_c - 'A' + 10;
      if (tmp_c >= '0' && tmp_c <= '9')
	pkt_buf[j] = tmp_val * 16 + tmp_c - '0';

      tmp_c = raw_mask[i];
      if (tmp_c >= 'a' && tmp_c <= 'f')
	tmp_val = tmp_c - 0x57;
      if (tmp_c >= 'A' && tmp_c <= 'F')
	tmp_val = tmp_c - 0x37;
      if (tmp_c >= '0' && tmp_c <= '9')
	tmp_val = tmp_c - '0';

      tmp_c = raw_mask[i + 1];
      if (tmp_c >= 'a' && tmp_c <= 'f')
	msk_buf[j] = tmp_val * 16 + tmp_c - 'a' + 10;
      if (tmp_c >= 'A' && tmp_c <= 'F')
	msk_buf[j] = tmp_val * 16 + tmp_c - 'A' + 10;
      if (tmp_c >= '0' && tmp_c <= '9')
	msk_buf[j] = tmp_val * 16 + tmp_c - '0';
    }
}

static int
avf_flow_add (u32 dev_instance, vnet_flow_t *f, avf_flow_entry_t *fe)
{
  avf_device_t *ad = avf_get_device (dev_instance);
  int rv = 0;
  int ret = 0;
  u16 src_port = 0, dst_port = 0;
  u16 src_port_mask = 0, dst_port_mask = 0;
  u8 protocol = IP_PROTOCOL_RESERVED;
  bool fate = false;
  bool is_fdir = true;
  struct avf_flow_error error;

  int layer = 0;
  int action_count = 0;

  struct avf_flow_vc_ctx vc_ctx;
  struct avf_fdir_conf *filter;
  struct virtchnl_rss_cfg *rss_cfg;
  struct avf_flow_item avf_items[VIRTCHNL_MAX_NUM_PROTO_HDRS];
  struct avf_flow_action avf_actions[VIRTCHNL_MAX_NUM_ACTIONS];

  struct avf_ipv4_hdr ip4_spec = {}, ip4_mask = {};
  struct avf_ipv6_hdr ip6_spec = {}, ip6_mask = {};
  struct avf_tcp_hdr tcp_spec = {}, tcp_mask = {};
  struct avf_udp_hdr udp_spec = {}, udp_mask = {};
  struct avf_gtp_hdr gtp_spec = {}, gtp_mask = {};
  struct avf_l2tpv3oip_hdr l2tpv3_spec = {}, l2tpv3_mask = {};
  struct avf_esp_hdr esp_spec = {}, esp_mask = {};
  struct avf_ah_hdr ah_spec = {}, ah_mask = {};

  struct avf_flow_action_queue act_q = {};
  struct avf_flow_action_mark act_msk = {};
  struct avf_flow_action_rss act_rss = {};

  enum
  {
    FLOW_UNKNOWN_CLASS,
    FLOW_ETHERNET_CLASS,
    FLOW_IPV4_CLASS,
    FLOW_IPV6_CLASS,
    FLOW_GENERIC_CLASS,
  } flow_class = FLOW_UNKNOWN_CLASS;

  if (FLOW_IS_ETHERNET_CLASS (f))
    flow_class = FLOW_ETHERNET_CLASS;
  else if (FLOW_IS_IPV4_CLASS (f))
    flow_class = FLOW_IPV4_CLASS;
  else if (FLOW_IS_IPV6_CLASS (f))
    flow_class = FLOW_IPV6_CLASS;
  else if (FLOW_IS_GENERIC_CLASS (f))
    flow_class = FLOW_GENERIC_CLASS;
  else
    return VNET_FLOW_ERROR_NOT_SUPPORTED;

  ret = avf_fdir_rcfg_create (&filter, 0, ad->vsi_id, ad->n_rx_queues);
  if (ret)
    {
      rv = VNET_FLOW_ERROR_INTERNAL;
      goto done;
    }

  ret = avf_rss_cfg_create (&rss_cfg, 0);
  if (ret)
    {
      rv = VNET_FLOW_ERROR_INTERNAL;
      goto done;
    }

  /* init a virtual channel context */
  vc_ctx.vc_hdl = &dev_instance;
  vc_ctx.vc_op = avf_flow_vc_op_callback;

  clib_memset (avf_items, 0, sizeof (avf_actions));
  clib_memset (avf_actions, 0, sizeof (avf_actions));

  /* Handle generic flow first */
  if (flow_class == FLOW_GENERIC_CLASS)
    {
      avf_items[layer].is_generic = true;
      avf_items[layer].spec = f->generic.pattern.spec;
      avf_items[layer].mask = f->generic.pattern.mask;

      layer++;

      goto pattern_end;
    }

  /* Ethernet Layer */
  avf_items[layer].type = VIRTCHNL_PROTO_HDR_ETH;
  avf_items[layer].spec = NULL;
  avf_items[layer].mask = NULL;
  layer++;

  if (flow_class == FLOW_IPV4_CLASS)
    {
      vnet_flow_ip4_t *ip4_ptr = &f->ip4;

      /* IPv4 Layer */
      avf_items[layer].type = VIRTCHNL_PROTO_HDR_IPV4;
      avf_items[layer].spec = &ip4_spec;
      avf_items[layer].mask = &ip4_mask;
      layer++;

      if ((!ip4_ptr->src_addr.mask.as_u32) &&
	  (!ip4_ptr->dst_addr.mask.as_u32) && (!ip4_ptr->protocol.mask))
	{
	  ;
	}
      else
	{
	  ip4_spec.src_addr = ip4_ptr->src_addr.addr.as_u32;
	  ip4_mask.src_addr = ip4_ptr->src_addr.mask.as_u32;

	  ip4_spec.dst_addr = ip4_ptr->dst_addr.addr.as_u32;
	  ip4_mask.dst_addr = ip4_ptr->dst_addr.mask.as_u32;

	  ip4_spec.next_proto_id = ip4_ptr->protocol.prot;
	  ip4_mask.next_proto_id = ip4_ptr->protocol.mask;
	}

      if (FLOW_IS_L4_TYPE (f) || FLOW_IS_L4_TUNNEL_TYPE (f))
	{
	  vnet_flow_ip4_n_tuple_t *ip4_n_ptr = &f->ip4_n_tuple;

	  src_port = ip4_n_ptr->src_port.port;
	  dst_port = ip4_n_ptr->dst_port.port;
	  src_port_mask = ip4_n_ptr->src_port.mask;
	  dst_port_mask = ip4_n_ptr->dst_port.mask;
	}

      protocol = ip4_ptr->protocol.prot;
    }
  else if (flow_class == FLOW_IPV6_CLASS)
    {
      vnet_flow_ip6_t *ip6_ptr = &f->ip6;

      /* IPv6 Layer */
      avf_items[layer].type = VIRTCHNL_PROTO_HDR_IPV6;
      avf_items[layer].spec = &ip6_spec;
      avf_items[layer].mask = &ip6_mask;
      layer++;

      if ((ip6_address_is_zero (&ip6_ptr->src_addr.mask)) &&
	  (ip6_address_is_zero (&ip6_ptr->dst_addr.mask)) &&
	  (!ip6_ptr->protocol.mask))
	{
	  ;
	}
      else
	{
	  clib_memcpy (ip6_spec.src_addr, &ip6_ptr->src_addr.addr,
		       ARRAY_LEN (ip6_ptr->src_addr.addr.as_u8));
	  clib_memcpy (ip6_mask.src_addr, &ip6_ptr->src_addr.mask,
		       ARRAY_LEN (ip6_ptr->src_addr.mask.as_u8));
	  clib_memcpy (ip6_spec.dst_addr, &ip6_ptr->dst_addr.addr,
		       ARRAY_LEN (ip6_ptr->dst_addr.addr.as_u8));
	  clib_memcpy (ip6_mask.dst_addr, &ip6_ptr->dst_addr.mask,
		       ARRAY_LEN (ip6_ptr->dst_addr.mask.as_u8));
	  ip6_spec.proto = ip6_ptr->protocol.prot;
	  ip6_mask.proto = ip6_ptr->protocol.mask;
	}

      if (FLOW_IS_L4_TYPE (f) || FLOW_IS_L4_TUNNEL_TYPE (f))
	{
	  vnet_flow_ip6_n_tuple_t *ip6_n_ptr = &f->ip6_n_tuple;

	  src_port = ip6_n_ptr->src_port.port;
	  dst_port = ip6_n_ptr->dst_port.port;
	  src_port_mask = ip6_n_ptr->src_port.mask;
	  dst_port_mask = ip6_n_ptr->dst_port.mask;
	}

      protocol = ip6_ptr->protocol.prot;
    }

  if (FLOW_IS_L3_TYPE (f))
    goto pattern_end;

  /* Layer 4 */
  switch (protocol)
    {
    case IP_PROTOCOL_L2TP:
      avf_items[layer].type = VIRTCHNL_PROTO_HDR_L2TPV3;
      avf_items[layer].spec = &l2tpv3_spec;
      avf_items[layer].mask = &l2tpv3_mask;
      layer++;

      vnet_flow_ip4_l2tpv3oip_t *l2tph = &f->ip4_l2tpv3oip;
      l2tpv3_spec.session_id = clib_host_to_net_u32 (l2tph->session_id);
      l2tpv3_mask.session_id = ~0;
      break;

    case IP_PROTOCOL_IPSEC_ESP:
      avf_items[layer].type = VIRTCHNL_PROTO_HDR_ESP;
      avf_items[layer].spec = &esp_spec;
      avf_items[layer].mask = &esp_mask;
      layer++;

      vnet_flow_ip4_ipsec_esp_t *esph = &f->ip4_ipsec_esp;
      esp_spec.spi = clib_host_to_net_u32 (esph->spi);
      esp_mask.spi = ~0;
      break;

    case IP_PROTOCOL_IPSEC_AH:
      avf_items[layer].type = VIRTCHNL_PROTO_HDR_AH;
      avf_items[layer].spec = &ah_spec;
      avf_items[layer].mask = &ah_mask;
      layer++;

      vnet_flow_ip4_ipsec_ah_t *ah = &f->ip4_ipsec_ah;
      ah_spec.spi = clib_host_to_net_u32 (ah->spi);
      ah_mask.spi = ~0;
      break;

    case IP_PROTOCOL_TCP:
      avf_items[layer].type = VIRTCHNL_PROTO_HDR_TCP;
      avf_items[layer].spec = &tcp_spec;
      avf_items[layer].mask = &tcp_mask;
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
      break;

    case IP_PROTOCOL_UDP:
      avf_items[layer].type = VIRTCHNL_PROTO_HDR_UDP;
      avf_items[layer].spec = &udp_spec;
      avf_items[layer].mask = &udp_mask;
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

      /* handle the UDP tunnels */
      if (f->type == VNET_FLOW_TYPE_IP4_GTPU)
	{
	  avf_items[layer].type = VIRTCHNL_PROTO_HDR_GTPU_IP;
	  avf_items[layer].spec = &gtp_spec;
	  avf_items[layer].mask = &gtp_mask;
	  layer++;

	  vnet_flow_ip4_gtpu_t *gu = &f->ip4_gtpu;
	  gtp_spec.teid = clib_host_to_net_u32 (gu->teid);
	  gtp_mask.teid = ~0;
	}
      break;

    default:
      rv = VNET_FLOW_ERROR_NOT_SUPPORTED;
      goto done;
    }

pattern_end:
  /* pattern end flag  */
  avf_items[layer].type = VIRTCHNL_PROTO_HDR_NONE;

  /* Action */
  /* Only one 'fate' can be assigned */
  if (f->actions & VNET_FLOW_ACTION_REDIRECT_TO_QUEUE)
    {
      avf_actions[action_count].type = VIRTCHNL_ACTION_QUEUE;
      avf_actions[action_count].conf = &act_q;

      act_q.index = f->redirect_queue;
      fate = true;
      action_count++;
    }

  if (f->actions & VNET_FLOW_ACTION_DROP)
    {
      avf_actions[action_count].type = VIRTCHNL_ACTION_DROP;
      avf_actions[action_count].conf = NULL;

      if (fate == true)
	{
	  rv = VNET_FLOW_ERROR_INTERNAL;
	  goto done;
	}
      else
	fate = true;

      action_count++;
    }

  if (f->actions & VNET_FLOW_ACTION_RSS)
    {
      avf_actions[action_count].type = VIRTCHNL_ACTION_RSS;
      avf_actions[action_count].conf = &act_rss;
      is_fdir = false;

      if (f->queue_num)
	{
	  /* convert rss queues to array */
	  avf_flow_convert_rss_queues (f->queue_index, f->queue_num, &act_rss);
	  avf_actions[action_count].type = VIRTCHNL_ACTION_Q_REGION;
	  is_fdir = true;
	}

      if ((act_rss.func = avf_flow_convert_rss_func (f->rss_fun)) ==
	  AVF_ETH_HASH_FUNCTION_MAX)
	{
	  rv = VNET_FLOW_ERROR_NOT_SUPPORTED;
	  goto done;
	}

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
      avf_actions[action_count].type = VIRTCHNL_ACTION_PASSTHRU;
      avf_actions[action_count].conf = NULL;

      fate = true;
      action_count++;
    }

  if (f->actions & VNET_FLOW_ACTION_MARK)
    {
      avf_actions[action_count].type = VIRTCHNL_ACTION_MARK;
      avf_actions[action_count].conf = &act_msk;
      action_count++;

      act_msk.id = fe->mark;
    }

  /* action end flag */
  avf_actions[action_count].type = VIRTCHNL_ACTION_NONE;

  /* parse pattern and actions */
  if (is_fdir)
    {
      if (flow_class == FLOW_GENERIC_CLASS)
	{
	  ret = avf_fdir_parse_generic_pattern (filter, avf_items, &error);
	  if (ret)
	    {
	      avf_log_err (ad, "avf fdir parse generic pattern failed: %s",
			   error.message);
	      rv = VNET_FLOW_ERROR_NOT_SUPPORTED;
	      goto done;
	    }
	}
      else
	{
	  ret = avf_fdir_parse_pattern (filter, avf_items, &error);
	  if (ret)
	    {
	      avf_log_err (ad, "avf fdir parse pattern failed: %s",
			   error.message);
	      rv = VNET_FLOW_ERROR_NOT_SUPPORTED;
	      goto done;
	    }
	}

      ret = avf_fdir_parse_action (avf_actions, filter, &error);
      if (ret)
	{
	  avf_log_err (ad, "avf fdir parse action failed: %s", error.message);
	  rv = VNET_FLOW_ERROR_NOT_SUPPORTED;
	  goto done;
	}

  /* create flow rule, save rule */
  ret = avf_fdir_rule_create (&vc_ctx, filter);

  if (ret)
    {
      avf_log_err (ad, "avf fdir rule create failed: %s",
		   avf_fdir_prgm_error_decode (ret));
      rv = VNET_FLOW_ERROR_INTERNAL;
      goto done;
    }
  else
    {
      fe->rcfg = filter;
      fe->flow_type_flag = 1;
    }
    }
  else
    {
      if (flow_class == FLOW_GENERIC_CLASS)
	{
	  ret = avf_rss_parse_generic_pattern (rss_cfg, avf_items, &error);
	  if (ret)
	    {
	      avf_log_err (ad, "avf rss parse generic pattern failed: %s",
			   error.message);
	      rv = VNET_FLOW_ERROR_NOT_SUPPORTED;
	      goto done;
	    }
	}
      else
	{
	  avf_log_warn (ad, "avf rss is not supported except generic flow");
	  goto done;
	}

      ret = avf_rss_parse_action (avf_actions, rss_cfg, &error);
      if (ret)
	{
	  avf_log_err (ad, "avf rss parse action failed: %s", error.message);
	  rv = VNET_FLOW_ERROR_NOT_SUPPORTED;
	  goto done;
	}

      /* create flow rule, save rule */
      ret = avf_rss_rule_create (&vc_ctx, rss_cfg);

      if (ret)
	{
	  avf_log_err (ad, "avf rss rule create failed");
	  rv = VNET_FLOW_ERROR_INTERNAL;
	  goto done;
	}
      else
	{
	  fe->rss_cfg = rss_cfg;
	  fe->flow_type_flag = 0;
	}
    }

done:

  return rv;
}

int
avf_flow_ops_fn (vnet_main_t *vm, vnet_flow_dev_op_t op, u32 dev_instance,
		 u32 flow_index, uword *private_data)
{
  vnet_flow_t *flow = vnet_get_flow (flow_index);
  avf_device_t *ad = avf_get_device (dev_instance);
  avf_flow_entry_t *fe = NULL;
  avf_flow_lookup_entry_t *fle = NULL;
  int rv = 0;

  if ((ad->cap_flags & VIRTCHNL_VF_OFFLOAD_FDIR_PF) == 0)
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
	case VNET_FLOW_TYPE_IP4:
	case VNET_FLOW_TYPE_IP6:
	case VNET_FLOW_TYPE_IP4_N_TUPLE:
	case VNET_FLOW_TYPE_IP6_N_TUPLE:
	case VNET_FLOW_TYPE_IP4_GTPU:
	case VNET_FLOW_TYPE_IP4_L2TPV3OIP:
	case VNET_FLOW_TYPE_IP4_IPSEC_ESP:
	case VNET_FLOW_TYPE_IP4_IPSEC_AH:
	case VNET_FLOW_TYPE_GENERIC:
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

      struct avf_flow_vc_ctx ctx;
      ctx.vc_hdl = &dev_instance;
      ctx.vc_op = avf_flow_vc_op_callback;

      if (fe->flow_type_flag)
	{
	  rv = avf_fdir_rule_destroy (&ctx, fe->rcfg);
	  if (rv)
	    return VNET_FLOW_ERROR_INTERNAL;
	}
      else
	{
	  rv = avf_rss_rule_destroy (&ctx, fe->rss_cfg);
	  if (rv)
	    return VNET_FLOW_ERROR_INTERNAL;
	}

      if (fe->mark)
	{
	  fle = pool_elt_at_index (ad->flow_lookup_entries, fe->mark);
	  clib_memset (fle, -1, sizeof (*fle));
	  pool_put_index (ad->flow_lookup_entries, fe->mark);
	}

      (void) avf_fdir_rcfg_destroy (fe->rcfg);
      (void) avf_rss_rcfg_destroy (fe->rss_cfg);
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
  if ((ad->flags & AVF_DEVICE_F_RX_FLOW_OFFLOAD) != 0 &&
      pool_elts (ad->flow_entries) == 0)
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
