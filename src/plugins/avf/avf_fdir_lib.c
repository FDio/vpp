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

#include <vppinfra/mem.h>
#include "avf_advanced_flow.h"

#define AVF_FDIR_IPV6_TC_OFFSET	  20
#define AVF_IPV6_TC_MASK	  (0xFF << AVF_FDIR_IPV6_TC_OFFSET)
#define AVF_FDIR_MAX_QREGION_SIZE 128

/*
 * Return the last (most-significant) bit set.
 */
static inline int
fls_u32 (u32 x)
{
  return (x == 0) ? 0 : 32 - count_leading_zeros (x);
}

static inline int
ether_addr_is_zero (const struct avf_ether_addr *ea)
{
  const u16 *w = (const u16 *) ea;

  return (w[0] | w[1] | w[2]) == 0;
}

int
avf_fdir_rcfg_create (struct avf_fdir_conf **rcfg, int tunnel_level, u16 vsi,
		      u16 nrxq)
{
  (*rcfg) = clib_mem_alloc (sizeof (**rcfg));
  if ((*rcfg) == NULL)
    {
      return -1;
    }

  clib_memset (*rcfg, 0, sizeof (**rcfg));

  (*rcfg)->add_fltr.rule_cfg.proto_hdrs.tunnel_level = tunnel_level;
  (*rcfg)->vsi = vsi;
  (*rcfg)->nb_rx_queues = nrxq;

  return 0;
}

int
avf_fdir_rcfg_destroy (struct avf_fdir_conf *rcfg)
{
  clib_mem_free (rcfg);

  return 0;
}

int
avf_fdir_rcfg_set_hdr (struct avf_fdir_conf *rcfg, int layer,
		       enum virtchnl_proto_hdr_type hdr)
{
  struct virtchnl_proto_hdrs *hdrs;

  hdrs = &rcfg->add_fltr.rule_cfg.proto_hdrs;
  if (layer >= VIRTCHNL_MAX_NUM_PROTO_HDRS)
    return -1;

  hdrs->proto_hdr[layer].type = hdr;

  return 0;
}

int
avf_fdir_rcfg_set_field (struct avf_fdir_conf *rcfg, int layer,
			 struct avf_flow_item *item,
			 struct avf_flow_error *error)
{
  const struct avf_ipv4_hdr *ipv4_spec, *ipv4_mask;
  const struct avf_ipv6_hdr *ipv6_spec, *ipv6_mask;
  const struct avf_udp_hdr *udp_spec, *udp_mask;
  const struct avf_tcp_hdr *tcp_spec, *tcp_mask;
  const struct avf_sctp_hdr *sctp_spec, *sctp_mask;
  const struct avf_gtp_hdr *gtp_spec, *gtp_mask;
  const struct avf_gtp_psc_hdr *gtp_psc_spec, *gtp_psc_mask;
  const struct avf_l2tpv3oip_hdr *l2tpv3oip_spec, *l2tpv3oip_mask;
  const struct avf_esp_hdr *esp_spec, *esp_mask;
  const struct avf_ah_hdr *ah_spec, *ah_mask;
  const struct avf_pfcp_hdr *pfcp_spec, *pfcp_mask;
  const struct avf_flow_eth_hdr *eth_spec, *eth_mask;

  struct virtchnl_proto_hdr *hdr;
  enum virtchnl_proto_hdr_type type;
  u16 ether_type;
  int ret = 0;

  u8 ipv6_addr_mask[16] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

  hdr = &rcfg->add_fltr.rule_cfg.proto_hdrs.proto_hdr[layer];
  type = item->type;

  switch (type)
    {
    case VIRTCHNL_PROTO_HDR_ETH:
      eth_spec = item->spec;
      eth_mask = item->mask;

      hdr->type = VIRTCHNL_PROTO_HDR_ETH;

      if (eth_spec && eth_mask)
	{
	  if (!ether_addr_is_zero (&eth_mask->src) ||
	      !ether_addr_is_zero (&eth_mask->dst))
	    {
	      ret = avf_flow_error_set (error, AVF_FAILURE,
					AVF_FLOW_ERROR_TYPE_ITEM, item,
					"Invalid MAC_addr mask.");
	      return ret;
	    }

	  if (eth_mask->type)
	    {
	      if (eth_mask->type != 0xffff)
		{
		  ret = avf_flow_error_set (error, AVF_FAILURE,
					    AVF_FLOW_ERROR_TYPE_ITEM, item,
					    "Invalid type mask.");
		  return ret;
		}
	    }
	}

      if (eth_spec && eth_mask && eth_mask->type)
	{
	  ether_type = clib_net_to_host_u16 (eth_spec->type);
	  if (ether_type == AVF_ETHER_TYPE_IPV4 ||
	      ether_type == AVF_ETHER_TYPE_IPV6)
	    {
	      ret = avf_flow_error_set (error, AVF_FAILURE,
					AVF_FLOW_ERROR_TYPE_ITEM, item,
					"Unsupported ether_type.");
	      return ret;
	    }

	  rcfg->input_set |= AVF_INSET_ETHERTYPE;
	  VIRTCHNL_ADD_PROTO_HDR_FIELD_BIT (hdr, ETH, ETHERTYPE);

	  clib_memcpy (hdr->buffer, eth_spec, sizeof (*eth_spec));
	}
      break;

    case VIRTCHNL_PROTO_HDR_IPV4:
      ipv4_spec = item->spec;
      ipv4_mask = item->mask;
      hdr->type = VIRTCHNL_PROTO_HDR_IPV4;

      if (ipv4_spec && ipv4_mask)
	{
	  if (ipv4_mask->version_ihl || ipv4_mask->total_length ||
	      ipv4_mask->packet_id || ipv4_mask->fragment_offset ||
	      ipv4_mask->hdr_checksum)
	    {
	      ret = avf_flow_error_set (error, AVF_FAILURE,
					AVF_FLOW_ERROR_TYPE_ITEM, item,
					"Invalid IPv4 mask.");
	      return ret;
	    }

	  if (ipv4_mask->type_of_service == 0xff)
	    {
	      rcfg->input_set |= AVF_INSET_IPV4_TOS;
	      VIRTCHNL_ADD_PROTO_HDR_FIELD_BIT (hdr, IPV4, DSCP);
	    }

	  if (ipv4_mask->next_proto_id == 0xff)
	    {
	      rcfg->input_set |= AVF_INSET_IPV4_PROTO;
	      VIRTCHNL_ADD_PROTO_HDR_FIELD_BIT (hdr, IPV4, PROT);
	    }

	  if (ipv4_mask->time_to_live == 0xff)
	    {
	      rcfg->input_set |= AVF_INSET_IPV4_TTL;
	      VIRTCHNL_ADD_PROTO_HDR_FIELD_BIT (hdr, IPV4, TTL);
	    }

	  if (ipv4_mask->src_addr == 0xffffffff)
	    {
	      rcfg->input_set |= AVF_INSET_IPV4_SRC;
	      VIRTCHNL_ADD_PROTO_HDR_FIELD_BIT (hdr, IPV4, SRC);
	    }

	  if (ipv4_mask->dst_addr == 0xffffffff)
	    {
	      rcfg->input_set |= AVF_INSET_IPV4_DST;
	      VIRTCHNL_ADD_PROTO_HDR_FIELD_BIT (hdr, IPV4, DST);
	    }

	  clib_memcpy (hdr->buffer, ipv4_spec, sizeof (*ipv4_spec));
	}
      break;

    case VIRTCHNL_PROTO_HDR_IPV6:
      ipv6_spec = item->spec;
      ipv6_mask = item->mask;
      hdr->type = VIRTCHNL_PROTO_HDR_IPV6;

      if (ipv6_spec && ipv6_mask)
	{
	  if (ipv6_mask->payload_len)
	    {
	      ret = avf_flow_error_set (error, AVF_FAILURE,
					AVF_FLOW_ERROR_TYPE_ITEM, item,
					"Invalid IPv6 mask");
	      return ret;
	    }

	  if ((ipv6_mask->vtc_flow &
	       clib_host_to_net_u32 (AVF_IPV6_TC_MASK)) ==
	      (clib_host_to_net_u32 (AVF_IPV6_TC_MASK)))
	    {
	      rcfg->input_set |= AVF_INSET_IPV6_TC;
	      VIRTCHNL_ADD_PROTO_HDR_FIELD_BIT (hdr, IPV6, TC);
	    }

	  if (ipv6_mask->proto == 0xff)
	    {
	      rcfg->input_set |= AVF_INSET_IPV6_NEXT_HDR;
	      VIRTCHNL_ADD_PROTO_HDR_FIELD_BIT (hdr, IPV6, PROT);
	    }

	  if (ipv6_mask->hop_limits == 0xff)
	    {
	      rcfg->input_set |= AVF_INSET_IPV6_HOP_LIMIT;
	      VIRTCHNL_ADD_PROTO_HDR_FIELD_BIT (hdr, IPV6, HOP_LIMIT);
	    }

	  if (!clib_memcmp (ipv6_mask->src_addr, ipv6_addr_mask,
			    sizeof (ipv6_mask->src_addr)))
	    {
	      rcfg->input_set |= AVF_INSET_IPV6_SRC;
	      VIRTCHNL_ADD_PROTO_HDR_FIELD_BIT (hdr, IPV6, SRC);
	    }
	  if (!clib_memcmp (ipv6_mask->dst_addr, ipv6_addr_mask,
			    sizeof (ipv6_mask->dst_addr)))
	    {
	      rcfg->input_set |= AVF_INSET_IPV6_DST;
	      VIRTCHNL_ADD_PROTO_HDR_FIELD_BIT (hdr, IPV6, DST);

	      clib_memcpy (hdr->buffer, ipv6_spec, sizeof (*ipv6_spec));
	    }
	}

      break;

    case VIRTCHNL_PROTO_HDR_UDP:
      udp_spec = item->spec;
      udp_mask = item->mask;
      hdr->type = VIRTCHNL_PROTO_HDR_UDP;

      if (udp_spec && udp_mask)
	{
	  if (udp_mask->dgram_len || udp_mask->dgram_cksum)
	    {
	      ret = avf_flow_error_set (error, AVF_FAILURE,
					AVF_FLOW_ERROR_TYPE_ITEM, item,
					"Invalid UDP mask");
	      return ret;
	    };

	  if (udp_mask->src_port == 0xffff)
	    {
	      rcfg->input_set |= AVF_INSET_UDP_SRC_PORT;
	      VIRTCHNL_ADD_PROTO_HDR_FIELD_BIT (hdr, UDP, SRC_PORT);
	    }

	  if (udp_mask->dst_port == 0xffff)
	    {
	      rcfg->input_set |= AVF_INSET_UDP_DST_PORT;
	      VIRTCHNL_ADD_PROTO_HDR_FIELD_BIT (hdr, UDP, DST_PORT);
	    }

	  clib_memcpy (hdr->buffer, udp_spec, sizeof (*udp_spec));
	}
      break;

    case VIRTCHNL_PROTO_HDR_TCP:
      tcp_spec = item->spec;
      tcp_mask = item->mask;
      hdr->type = VIRTCHNL_PROTO_HDR_TCP;

      if (tcp_spec && tcp_mask)
	{
	  if (tcp_mask->sent_seq || tcp_mask->recv_ack || tcp_mask->data_off ||
	      tcp_mask->tcp_flags || tcp_mask->rx_win || tcp_mask->cksum ||
	      tcp_mask->tcp_urp)
	    {
	      ret = avf_flow_error_set (error, AVF_FAILURE,
					AVF_FLOW_ERROR_TYPE_ITEM, item,
					"Invalid TCP mask");
	      return ret;
	    }

	  if (tcp_mask->src_port == 0xffff)
	    {
	      rcfg->input_set |= AVF_INSET_TCP_SRC_PORT;
	      VIRTCHNL_ADD_PROTO_HDR_FIELD_BIT (hdr, TCP, SRC_PORT);
	    }

	  if (tcp_mask->dst_port == 0xffff)
	    {
	      rcfg->input_set |= AVF_INSET_TCP_DST_PORT;
	      VIRTCHNL_ADD_PROTO_HDR_FIELD_BIT (hdr, TCP, DST_PORT);
	    }

	  clib_memcpy (hdr->buffer, tcp_spec, sizeof (*tcp_spec));
	}

      break;

    case VIRTCHNL_PROTO_HDR_SCTP:
      sctp_spec = item->spec;
      sctp_mask = item->mask;
      hdr->type = VIRTCHNL_PROTO_HDR_SCTP;

      if (sctp_spec && sctp_mask)
	{
	  if (sctp_mask->cksum)
	    {
	      ret = avf_flow_error_set (error, AVF_FAILURE,
					AVF_FLOW_ERROR_TYPE_ITEM, item,
					"Invalid UDP mask");
	      return ret;
	    }

	  if (sctp_mask->src_port == 0xffff)
	    {
	      rcfg->input_set |= AVF_INSET_SCTP_SRC_PORT;
	      VIRTCHNL_ADD_PROTO_HDR_FIELD_BIT (hdr, SCTP, SRC_PORT);
	    }

	  if (sctp_mask->dst_port == 0xffff)
	    {
	      rcfg->input_set |= AVF_INSET_SCTP_DST_PORT;
	      VIRTCHNL_ADD_PROTO_HDR_FIELD_BIT (hdr, SCTP, DST_PORT);
	    }

	  clib_memcpy (hdr->buffer, sctp_spec, sizeof (*sctp_spec));
	}
      break;

    case VIRTCHNL_PROTO_HDR_GTPU_IP:
      gtp_spec = item->spec;
      gtp_mask = item->mask;
      hdr->type = VIRTCHNL_PROTO_HDR_GTPU_IP;

      if (gtp_spec && gtp_mask)
	{
	  if (gtp_mask->v_pt_rsv_flags || gtp_mask->msg_type ||
	      gtp_mask->msg_len)
	    {
	      ret = avf_flow_error_set (error, AVF_FAILURE,
					AVF_FLOW_ERROR_TYPE_ITEM, item,
					"Invalid GTP mask");
	      return ret;
	    }

	  if (gtp_mask->teid == 0xffffffff)
	    {
	      rcfg->input_set |= AVF_INSET_GTPU_TEID;
	      VIRTCHNL_ADD_PROTO_HDR_FIELD_BIT (hdr, GTPU_IP, TEID);
	    }

	  clib_memcpy (hdr->buffer, gtp_spec, sizeof (*gtp_spec));
	}

      break;

    case VIRTCHNL_PROTO_HDR_GTPU_EH:
      gtp_psc_spec = item->spec;
      gtp_psc_mask = item->mask;
      hdr->type = VIRTCHNL_PROTO_HDR_GTPU_EH;

      if (gtp_psc_spec && gtp_psc_mask)
	{
	  if (gtp_psc_mask->qfi == 0xff)
	    {
	      rcfg->input_set |= AVF_INSET_GTPU_QFI;
	      VIRTCHNL_ADD_PROTO_HDR_FIELD_BIT (hdr, GTPU_EH, QFI);
	    }

	  clib_memcpy (hdr->buffer, gtp_psc_spec, sizeof (*gtp_psc_spec));
	}

      break;

    case VIRTCHNL_PROTO_HDR_L2TPV3:
      l2tpv3oip_spec = item->spec;
      l2tpv3oip_mask = item->mask;
      hdr->type = VIRTCHNL_PROTO_HDR_L2TPV3;

      if (l2tpv3oip_spec && l2tpv3oip_mask)
	{
	  if (l2tpv3oip_mask->session_id == 0xffffffff)
	    {
	      rcfg->input_set |= AVF_L2TPV3OIP_SESSION_ID;
	      VIRTCHNL_ADD_PROTO_HDR_FIELD_BIT (hdr, L2TPV3, SESS_ID);
	    }

	  clib_memcpy (hdr->buffer, l2tpv3oip_spec, sizeof (*l2tpv3oip_spec));
	}
      break;

    case VIRTCHNL_PROTO_HDR_ESP:
      esp_spec = item->spec;
      esp_mask = item->mask;
      hdr->type = VIRTCHNL_PROTO_HDR_ESP;

      if (esp_spec && esp_mask)
	{
	  if (esp_mask->spi == 0xffffffff)
	    {
	      rcfg->input_set |= AVF_INSET_ESP_SPI;
	      VIRTCHNL_ADD_PROTO_HDR_FIELD_BIT (hdr, ESP, SPI);
	    }

	  clib_memcpy (hdr->buffer, esp_spec, sizeof (*esp_spec));
	}
      break;

    case VIRTCHNL_PROTO_HDR_AH:
      ah_spec = item->spec;
      ah_mask = item->mask;
      hdr->type = VIRTCHNL_PROTO_HDR_AH;

      if (ah_spec && ah_mask)
	{
	  if (ah_mask->spi == 0xffffffff)
	    {
	      rcfg->input_set |= AVF_INSET_AH_SPI;
	      VIRTCHNL_ADD_PROTO_HDR_FIELD_BIT (hdr, AH, SPI);
	    }

	  clib_memcpy (hdr->buffer, ah_spec, sizeof (*ah_spec));
	}
      break;

    case VIRTCHNL_PROTO_HDR_PFCP:
      pfcp_spec = item->spec;
      pfcp_mask = item->mask;
      hdr->type = VIRTCHNL_PROTO_HDR_PFCP;

      if (pfcp_spec && pfcp_mask)
	{
	  if (pfcp_mask->s_field == 0xff)
	    {
	      rcfg->input_set |= AVF_INSET_PFCP_S_FIELD;
	      VIRTCHNL_ADD_PROTO_HDR_FIELD_BIT (hdr, PFCP, S_FIELD);
	    }

	  clib_memcpy (hdr->buffer, pfcp_spec, sizeof (*pfcp_spec));
	}
      break;

    default:
      ret = avf_flow_error_set (error, AVF_FAILURE, AVF_FLOW_ERROR_TYPE_ITEM,
				item, "Invalid pattern item.");
      return ret;
    }

  return 0;
}

int
avf_fdir_rcfg_act_queue (struct avf_fdir_conf *rcfg, int queue, int size,
			 int act_idx)
{
  if (act_idx >= VIRTCHNL_MAX_NUM_ACTIONS)
    return -AVF_FAILURE;

  struct virtchnl_filter_action *filter_action;

  filter_action = rcfg->add_fltr.rule_cfg.action_set.actions + act_idx;
  filter_action->type = VIRTCHNL_ACTION_QUEUE;
  filter_action->act_conf.queue.index = queue;

  if (size == 1)
    return 0;
  else if (is_pow2 (size))
    filter_action->act_conf.queue.region = fls_u32 (size) - 1;

  return 0;
}

int
avf_fdir_parse_action_qregion (struct avf_fdir_conf *rcfg,
			       const struct avf_flow_action *act, int act_idx,
			       struct avf_flow_error *error)
{
  const struct avf_flow_action_rss *rss = act->conf;
  struct virtchnl_filter_action *filter_action;
  u32 i;
  int ret;

  filter_action = rcfg->add_fltr.rule_cfg.action_set.actions + act_idx;

  if (rss->queue_num <= 1)
    {
      ret = avf_flow_error_set (error, AVF_FAILURE, AVF_FLOW_ERROR_TYPE_ACTION,
				act, "Queue region size can't be 0 or 1.");
      return ret;
    }

  /* check if queue index for queue region is continuous */
  for (i = 0; i < rss->queue_num - 1; i++)
    {
      if (rss->queue[i + 1] != rss->queue[i] + 1)
	{
	  ret =
	    avf_flow_error_set (error, AVF_FAILURE, AVF_FLOW_ERROR_TYPE_ACTION,
				act, "Discontinuous queue region");
	  return ret;
	}
    }

  if (rss->queue[rss->queue_num - 1] >= rcfg->nb_rx_queues)
    {
      ret = avf_flow_error_set (error, AVF_FAILURE, AVF_FLOW_ERROR_TYPE_ACTION,
				act, "Invalid queue region indexes.");
      return ret;
    }

  if (!(is_pow2 (rss->queue_num) &&
	rss->queue_num <= AVF_FDIR_MAX_QREGION_SIZE))
    {
      ret = avf_flow_error_set (error, AVF_FAILURE, AVF_FLOW_ERROR_TYPE_ACTION,
				act,
				"The region size should be any of the"
				"following values: 1, 2, 4, 8, 16, 32"
				", 64, 128 as long as the total number of"
				"queues do not exceed the VSI allocation");
      return ret;
    }

  filter_action->type = VIRTCHNL_ACTION_Q_REGION;
  filter_action->act_conf.queue.index = rss->queue[0];
  filter_action->act_conf.queue.region = fls_u32 (rss->queue_num) - 1;

  return 0;
}

int
avf_fdir_rcfg_act_drop (struct avf_fdir_conf *rcfg, int act_idx)
{
  struct virtchnl_filter_action *filter_action;

  if (act_idx >= VIRTCHNL_MAX_NUM_ACTIONS)
    return -AVF_FAILURE;

  filter_action = rcfg->add_fltr.rule_cfg.action_set.actions + act_idx;
  filter_action->type = VIRTCHNL_ACTION_DROP;

  return 0;
}

int
avf_fdir_rcfg_act_mark (struct avf_fdir_conf *rcfg, const u32 mark,
			int act_idx)
{
  struct virtchnl_filter_action *filter_action;
  if (act_idx >= VIRTCHNL_MAX_NUM_ACTIONS)
    return -AVF_FAILURE;

  filter_action = rcfg->add_fltr.rule_cfg.action_set.actions + act_idx;

  filter_action->type = VIRTCHNL_ACTION_MARK;
  filter_action->act_conf.mark_id = mark;

  return 0;
}

int
avf_fdir_rcfg_validate (struct avf_flow_vc_ctx *ctx,
			struct avf_fdir_conf *rcfg)
{
  int ret;
  rcfg->add_fltr.vsi_id = rcfg->vsi;
  rcfg->add_fltr.validate_only = 1;
  struct virtchnl_fdir_add fdir_ret;

  ret =
    ctx->vc_op (ctx->vc_hdl, VIRTCHNL_ADV_OP_ADD_FDIR_FILTER, &rcfg->add_fltr,
		sizeof (rcfg->add_fltr), &fdir_ret, sizeof (fdir_ret));

  if (ret != 0)
    {
      return ret;
    }

  if (fdir_ret.status != VIRTCHNL_FDIR_SUCCESS)
    {
      ret = -fdir_ret.status;
    }

  return ret;
}

int
avf_fdir_rule_create (struct avf_flow_vc_ctx *ctx, struct avf_fdir_conf *rcfg)
{
  int ret;
  rcfg->add_fltr.vsi_id = rcfg->vsi;
  rcfg->add_fltr.validate_only = 0;
  struct virtchnl_fdir_add fdir_ret;

  ret =
    ctx->vc_op (ctx->vc_hdl, VIRTCHNL_ADV_OP_ADD_FDIR_FILTER, &rcfg->add_fltr,
		sizeof (rcfg->add_fltr), &fdir_ret, sizeof (fdir_ret));

  if (ret != 0)
    {
      return ret;
    }

  rcfg->flow_id = fdir_ret.flow_id;

  if (fdir_ret.status != VIRTCHNL_FDIR_SUCCESS)
    {
      ret = -fdir_ret.status;
    }

  return ret;
}

int
avf_fdir_rule_destroy (struct avf_flow_vc_ctx *ctx, struct avf_fdir_conf *rcfg)
{
  int ret;
  struct virtchnl_fdir_del fdir_ret;
  rcfg->del_fltr.vsi_id = rcfg->vsi;
  rcfg->del_fltr.flow_id = rcfg->flow_id;

  ret =
    ctx->vc_op (ctx->vc_hdl, VIRTCHNL_ADV_OP_DEL_FDIR_FILTER, &rcfg->del_fltr,
		sizeof (rcfg->del_fltr), &fdir_ret, sizeof (fdir_ret));

  if (ret != 0)
    {
      return ret;
    }

  if (fdir_ret.status != VIRTCHNL_FDIR_SUCCESS)
    {
      ret = -fdir_ret.status;
    }

  return ret;
}

int
avf_fdir_parse_action (const struct avf_flow_action actions[],
		       struct avf_fdir_conf *rcfg,
		       struct avf_flow_error *error)
{
  int act_idx = 0, ret = 0;
  u32 dest_num = 0;
  u32 mark_num = 0;
  u32 act_num;
  struct virtchnl_filter_action *filter_action;
  const struct avf_flow_action_queue *act_q;
  const struct avf_flow_action_mark *act_msk;

  struct virtchnl_fdir_rule *rule_cfg = &rcfg->add_fltr.rule_cfg;

  for (; actions->type != VIRTCHNL_ACTION_NONE; actions++, act_idx++)
    {
      switch (actions->type)
	{
	case VIRTCHNL_ACTION_PASSTHRU:
	  dest_num++;
	  filter_action = &rule_cfg->action_set.actions[act_idx];
	  filter_action->type = VIRTCHNL_ACTION_PASSTHRU;
	  rule_cfg->action_set.count++;
	  break;

	case VIRTCHNL_ACTION_DROP:
	  dest_num++;
	  ret = avf_fdir_rcfg_act_drop (rcfg, act_idx);
	  if (ret)
	    return ret;

	  rule_cfg->action_set.count++;
	  break;

	case VIRTCHNL_ACTION_QUEUE:
	  dest_num++;
	  act_q = actions->conf;

	  if (act_q->index >= rcfg->nb_rx_queues)
	    {
	      ret = avf_flow_error_set (error, AVF_FAILURE,
					AVF_FLOW_ERROR_TYPE_ACTION, actions,
					"Invalid queue for FDIR.");
	      return -AVF_FAILURE;
	    }

	  ret = avf_fdir_rcfg_act_queue (rcfg, act_q->index, 1, act_idx);
	  if (ret)
	    return ret;

	  rule_cfg->action_set.count++;
	  break;

	case VIRTCHNL_ACTION_Q_REGION:
	  dest_num++;
	  filter_action = &rule_cfg->action_set.actions[act_idx];
	  ret = avf_fdir_parse_action_qregion (rcfg, actions, act_idx, error);
	  if (ret)
	    return ret;

	  rule_cfg->action_set.count++;
	  break;

	case VIRTCHNL_ACTION_MARK:
	  mark_num++;
	  act_msk = actions->conf;
	  rcfg->mark_flag = 1;

	  ret = avf_fdir_rcfg_act_mark (rcfg, act_msk->id, act_idx);
	  if (ret)
	    return ret;

	  rule_cfg->action_set.count++;
	  break;

	default:
	  ret =
	    avf_flow_error_set (error, AVF_FAILURE, AVF_FLOW_ERROR_TYPE_ACTION,
				actions, "Invalid action.");
	  return ret;
	}
    }

  if (dest_num >= 2)
    {
      ret = avf_flow_error_set (error, AVF_FAILURE, AVF_FLOW_ERROR_TYPE_ACTION,
				actions, "Unsupported action combination");
      return ret;
    }

  if (mark_num >= 2)
    {
      ret = avf_flow_error_set (error, AVF_FAILURE, AVF_FLOW_ERROR_TYPE_ACTION,
				actions, "Too many mark actions");
      return ret;
    }

  if (dest_num + mark_num == 0)
    {
      ret = avf_flow_error_set (error, AVF_FAILURE, AVF_FLOW_ERROR_TYPE_ACTION,
				actions, "Empty action");
      return ret;
    }

  /* Mark only is equal to mark + passthru. */
  act_num = rule_cfg->action_set.count;
  if (dest_num == 0)
    {
      filter_action = &rule_cfg->action_set.actions[act_num];
      filter_action->type = VIRTCHNL_ACTION_PASSTHRU;
      rule_cfg->action_set.count = ++act_num;
    }

  return ret;
}

int
avf_fdir_parse_generic_pattern (struct avf_fdir_conf *rcfg,
				struct avf_flow_item avf_items[],
				struct avf_flow_error *error)
{
  struct avf_flow_item *item = avf_items;
  u8 *pkt_buf, *msk_buf;
  u16 spec_len, pkt_len;

  spec_len = clib_strnlen (item->spec, VIRTCHNL_MAX_SIZE_GEN_PACKET);
  pkt_len = spec_len / 2;

  pkt_buf = clib_mem_alloc (pkt_len);
  msk_buf = clib_mem_alloc (pkt_len);

  avf_parse_generic_pattern (item, pkt_buf, msk_buf, spec_len);

  clib_memcpy (rcfg->add_fltr.rule_cfg.proto_hdrs.raw.spec, pkt_buf, pkt_len);
  clib_memcpy (rcfg->add_fltr.rule_cfg.proto_hdrs.raw.mask, msk_buf, pkt_len);

  rcfg->add_fltr.rule_cfg.proto_hdrs.count = 0;
  rcfg->add_fltr.rule_cfg.proto_hdrs.tunnel_level = 0;
  rcfg->add_fltr.rule_cfg.proto_hdrs.raw.pkt_len = pkt_len;

  clib_mem_free (pkt_buf);
  clib_mem_free (msk_buf);

  return 0;
}

int
avf_fdir_parse_pattern (struct avf_fdir_conf *rcfg,
			struct avf_flow_item avf_items[],
			struct avf_flow_error *error)
{
  int layer = 0;
  int ret = 0;
  struct avf_flow_item *item;

  for (item = avf_items; item->type != VIRTCHNL_PROTO_HDR_NONE; item++)
    {
      ret = avf_fdir_rcfg_set_field (rcfg, layer, item, error);
      if (ret)
	return ret;

      rcfg->add_fltr.rule_cfg.proto_hdrs.count = ++layer;
    }

  return ret;
}

int
avf_flow_error_set (struct avf_flow_error *error, int code,
		    enum avf_flow_error_type type, const void *cause,
		    const char *message)
{
  if (error)
    {
      *error = (struct avf_flow_error){
	.type = type,
	.cause = cause,
	.message = message,
      };
    }

  return code;
}

char *
avf_fdir_prgm_error_decode (int err_no)
{
  enum virtchnl_fdir_prgm_status status;
  char *s = NULL;

  err_no = -err_no;

  if (err_no >= VIRTCHNL_FDIR_FAILURE_MAX)
    return "Failed to program the rule due to other reasons";

  status = (enum virtchnl_fdir_prgm_status) err_no;
  switch (status)
    {
    case VIRTCHNL_FDIR_SUCCESS:
      s = "Succeed in programming rule request by PF";
      break;
    case VIRTCHNL_FDIR_FAILURE_RULE_NORESOURCE:
      s = "Failed to add rule request due to no hardware resource";
      break;
    case VIRTCHNL_FDIR_FAILURE_RULE_EXIST:
      s = "Failed to add rule request due to the rule is already existed";
      break;
    case VIRTCHNL_FDIR_FAILURE_RULE_CONFLICT:
      s = "Failed to add rule request due to the rule is conflict with "
	  "existing rule";
      break;
    case VIRTCHNL_FDIR_FAILURE_RULE_NONEXIST:
      s = "Failed to delete rule request due to this rule doesn't exist";
      break;
    case VIRTCHNL_FDIR_FAILURE_RULE_INVALID:
      s = "Failed to add rule request due to the hardware doesn't support";
      break;
    case VIRTCHNL_FDIR_FAILURE_RULE_TIMEOUT:
      s = "Failed to add rule request due to time out for programming";
      break;
    case VIRTCHNL_FDIR_FAILURE_QUERY_INVALID:
      s = "Succeed in programming rule request by PF";
      break;
    default:
      s = "Failed to program the rule due to other reasons";
      break;
    }

  return s;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
