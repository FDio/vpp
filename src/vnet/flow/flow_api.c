/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2020 Intel and/or its affiliates.
 */

/*
 * flow_api.c - flow api
 */

#include <stddef.h>

#include <vnet/vnet.h>
#include <vlibmemory/api.h>
#include <vnet/interface.h>
#include <vnet/api_errno.h>
#include <vnet/flow/flow.h>
#include <vnet/fib/fib_table.h>
#include <vnet/udp/udp_local.h>
#include <vnet/tunnel/tunnel_types_api.h>
#include <vnet/ip/ip_types_api.h>

#include <vnet/format_fns.h>
#include <vnet/flow/flow.api_enum.h>
#include <vnet/flow/flow.api_types.h>

#define REPLY_MSG_ID_BASE flow_main.msg_id_base
#include <vlibapi/api_helper_macros.h>

static inline void
ipv4_addr_and_mask_convert (vl_api_ip4_address_and_mask_t * vl_api_addr,
			    ip4_address_and_mask_t * vnet_addr)
{
  clib_memcpy (vnet_addr, vl_api_addr, sizeof (*vnet_addr));
}

static inline void
ipv6_addr_and_mask_convert (vl_api_ip6_address_and_mask_t * vl_api_addr,
			    ip6_address_and_mask_t * vnet_addr)
{
  clib_memcpy (vnet_addr, vl_api_addr, sizeof (*vnet_addr));
}

static inline void
protocol_and_mask_convert (vl_api_ip_prot_and_mask_t * vl_api_protocol,
			   ip_prot_and_mask_t * vnet_protocol)
{
  vnet_protocol->prot = (ip_protocol_t) vl_api_protocol->prot;
  vnet_protocol->mask = vl_api_protocol->mask;
}

static inline void
port_and_mask_convert (vl_api_ip_port_and_mask_t * vl_api_port,
		       ip_port_and_mask_t * vnet_port)
{
  vnet_port->port = ntohs (vl_api_port->port);
  vnet_port->mask = ntohs (vl_api_port->mask);
}

static inline void
ipv4_flow_convert (vl_api_flow_ip4_t *vl_api_flow, vnet_flow_ip4_t *f)
{
  ipv4_addr_and_mask_convert (&vl_api_flow->src_addr, &f->src_addr);
  ipv4_addr_and_mask_convert (&vl_api_flow->dst_addr, &f->dst_addr);

  protocol_and_mask_convert (&vl_api_flow->protocol, &f->protocol);
}

static void
ipv6_flow_convert (vl_api_flow_ip6_t *vl_api_flow, vnet_flow_ip6_t *f)
{
  ipv6_addr_and_mask_convert (&vl_api_flow->src_addr, &f->src_addr);
  ipv6_addr_and_mask_convert (&vl_api_flow->dst_addr, &f->dst_addr);

  protocol_and_mask_convert (&vl_api_flow->protocol, &f->protocol);
}

static inline void
ipv4_n_tuple_flow_convert (vl_api_flow_ip4_n_tuple_t * vl_api_flow,
			   vnet_flow_ip4_n_tuple_t * f)
{
  ipv4_addr_and_mask_convert (&vl_api_flow->src_addr, &f->src_addr);
  ipv4_addr_and_mask_convert (&vl_api_flow->dst_addr, &f->dst_addr);
  protocol_and_mask_convert (&vl_api_flow->protocol, &f->protocol);

  port_and_mask_convert (&vl_api_flow->src_port, &f->src_port);
  port_and_mask_convert (&vl_api_flow->dst_port, &f->dst_port);
}

static void
ipv6_n_tuple_flow_convert (vl_api_flow_ip6_n_tuple_t * vl_api_flow,
			   vnet_flow_ip6_n_tuple_t * f)
{
  ipv6_addr_and_mask_convert (&vl_api_flow->src_addr, &f->src_addr);
  ipv6_addr_and_mask_convert (&vl_api_flow->dst_addr, &f->dst_addr);
  protocol_and_mask_convert (&vl_api_flow->protocol, &f->protocol);

  port_and_mask_convert (&vl_api_flow->src_port, &f->src_port);
  port_and_mask_convert (&vl_api_flow->dst_port, &f->dst_port);
}

static inline void
ipv4_n_tuple_tagged_flow_convert (vl_api_flow_ip4_n_tuple_tagged_t *
				  vl_api_flow,
				  vnet_flow_ip4_n_tuple_tagged_t * f)
{
  return ipv4_n_tuple_flow_convert ((vl_api_flow_ip4_n_tuple_t *) vl_api_flow,
				    (vnet_flow_ip4_n_tuple_t *) f);
}

static inline void
ipv6_n_tuple_tagged_flow_convert (vl_api_flow_ip6_n_tuple_tagged_t *
				  vl_api_flow,
				  vnet_flow_ip6_n_tuple_tagged_t * f)
{
  return ipv6_n_tuple_flow_convert ((vl_api_flow_ip6_n_tuple_t *) vl_api_flow,
				    (vnet_flow_ip6_n_tuple_t *) f);
}

static inline void
ipv4_l2tpv3oip_flow_convert (vl_api_flow_ip4_l2tpv3oip_t * vl_api_flow,
			     vnet_flow_ip4_l2tpv3oip_t * f)
{
  ipv4_addr_and_mask_convert (&vl_api_flow->src_addr, &f->src_addr);
  ipv4_addr_and_mask_convert (&vl_api_flow->dst_addr, &f->dst_addr);

  protocol_and_mask_convert (&vl_api_flow->protocol, &f->protocol);
  f->session_id = ntohl (vl_api_flow->session_id);
}

static inline void
ipv4_ipsec_esp_flow_convert (vl_api_flow_ip4_ipsec_esp_t * vl_api_flow,
			     vnet_flow_ip4_ipsec_esp_t * f)
{
  ipv4_addr_and_mask_convert (&vl_api_flow->src_addr, &f->src_addr);
  ipv4_addr_and_mask_convert (&vl_api_flow->dst_addr, &f->dst_addr);

  protocol_and_mask_convert (&vl_api_flow->protocol, &f->protocol);
  f->spi = ntohl (vl_api_flow->spi);
}

static inline void
ipv4_ipsec_ah_flow_convert (vl_api_flow_ip4_ipsec_ah_t * vl_api_flow,
			    vnet_flow_ip4_ipsec_ah_t * f)
{
  ipv4_addr_and_mask_convert (&vl_api_flow->src_addr, &f->src_addr);
  ipv4_addr_and_mask_convert (&vl_api_flow->dst_addr, &f->dst_addr);

  protocol_and_mask_convert (&vl_api_flow->protocol, &f->protocol);
  f->spi = ntohl (vl_api_flow->spi);
}

static inline void
ipv4_vxlan_flow_convert (vl_api_flow_ip4_vxlan_t *vl_api_flow,
			 vnet_flow_ip4_vxlan_t *f)
{
  ipv4_addr_and_mask_convert (&vl_api_flow->src_addr, &f->src_addr);
  ipv4_addr_and_mask_convert (&vl_api_flow->dst_addr, &f->dst_addr);
  protocol_and_mask_convert (&vl_api_flow->protocol, &f->protocol);

  port_and_mask_convert (&vl_api_flow->src_port, &f->src_port);
  port_and_mask_convert (&vl_api_flow->dst_port, &f->dst_port);

  f->vni = ntohl (vl_api_flow->vni);
}

static inline void
ipv6_vxlan_flow_convert (vl_api_flow_ip6_vxlan_t *vl_api_flow,
			 vnet_flow_ip6_vxlan_t *f)
{
  ipv6_addr_and_mask_convert (&vl_api_flow->src_addr, &f->src_addr);
  ipv6_addr_and_mask_convert (&vl_api_flow->dst_addr, &f->dst_addr);
  protocol_and_mask_convert (&vl_api_flow->protocol, &f->protocol);

  port_and_mask_convert (&vl_api_flow->src_port, &f->src_port);
  port_and_mask_convert (&vl_api_flow->dst_port, &f->dst_port);

  f->vni = ntohl (vl_api_flow->vni);
}

static inline void
ipv4_gtpu_flow_convert (vl_api_flow_ip4_gtpu_t * vl_api_flow,
			vnet_flow_ip4_gtpu_t * f)
{
  ipv4_addr_and_mask_convert (&vl_api_flow->src_addr, &f->src_addr);
  ipv4_addr_and_mask_convert (&vl_api_flow->dst_addr, &f->dst_addr);

  port_and_mask_convert (&vl_api_flow->src_port, &f->src_port);
  port_and_mask_convert (&vl_api_flow->dst_port, &f->dst_port);

  protocol_and_mask_convert (&vl_api_flow->protocol, &f->protocol);
  f->teid = ntohl (vl_api_flow->teid);
}

static inline void
ipv4_gtpc_flow_convert (vl_api_flow_ip4_gtpc_t * vl_api_flow,
			vnet_flow_ip4_gtpc_t * f)
{
  ipv4_addr_and_mask_convert (&vl_api_flow->src_addr, &f->src_addr);
  ipv4_addr_and_mask_convert (&vl_api_flow->dst_addr, &f->dst_addr);

  port_and_mask_convert (&vl_api_flow->src_port, &f->src_port);
  port_and_mask_convert (&vl_api_flow->dst_port, &f->dst_port);

  protocol_and_mask_convert (&vl_api_flow->protocol, &f->protocol);
  f->teid = ntohl (vl_api_flow->teid);
}

static inline void
generic_flow_convert (vl_api_flow_generic_t *vl_api_flow,
		      vnet_flow_generic_t *f)
{
  clib_memcpy (f->pattern.spec, vl_api_flow->pattern.spec,
	       sizeof (vl_api_flow->pattern.spec));
  clib_memcpy (f->pattern.mask, vl_api_flow->pattern.mask,
	       sizeof (vl_api_flow->pattern.mask));
}

static void
vl_api_flow_add_v2_t_handler (vl_api_flow_add_v2_t *mp)
{
  vl_api_flow_add_v2_reply_t *rmp;
  int rv = 0;
  vnet_flow_t flow;
  u32 flow_index = ~0;
  vl_api_flow_rule_v2_t *f = &mp->flow;

  vnet_main_t *vnm = vnet_get_main ();

  flow.type = ntohl (f->type);
  flow.actions = ntohl (f->actions);
  flow.mark_flow_id = ntohl (f->mark_flow_id);
  flow.redirect_node_index = ntohl (f->redirect_node_index);
  flow.redirect_device_input_next_index =
    ntohl (f->redirect_device_input_next_index);
  flow.redirect_queue = ntohl (f->redirect_queue);
  flow.buffer_advance = ntohl (f->buffer_advance);
  flow.queue_index = ntohl (f->queue_index);
  flow.queue_num = ntohl (f->queue_num);
  flow.rss_types = clib_net_to_host_u64 (f->rss_types);
  flow.rss_fun = ntohl (f->rss_fun);

  switch (flow.type)
    {
    case VNET_FLOW_TYPE_IP4:
      ipv4_flow_convert (&f->flow.ip4, &flow.ip4);
      break;
    case VNET_FLOW_TYPE_IP6:
      ipv6_flow_convert (&f->flow.ip6, &flow.ip6);
      break;
    case VNET_FLOW_TYPE_IP4_N_TUPLE:
      ipv4_n_tuple_flow_convert (&f->flow.ip4_n_tuple, &flow.ip4_n_tuple);
      break;
    case VNET_FLOW_TYPE_IP6_N_TUPLE:
      ipv6_n_tuple_flow_convert (&f->flow.ip6_n_tuple, &flow.ip6_n_tuple);
      break;
    case VNET_FLOW_TYPE_IP4_N_TUPLE_TAGGED:
      ipv4_n_tuple_tagged_flow_convert (&f->flow.ip4_n_tuple_tagged,
					&flow.ip4_n_tuple_tagged);
      break;
    case VNET_FLOW_TYPE_IP6_N_TUPLE_TAGGED:
      ipv6_n_tuple_tagged_flow_convert (&f->flow.ip6_n_tuple_tagged,
					&flow.ip6_n_tuple_tagged);
      break;
    case VNET_FLOW_TYPE_IP4_L2TPV3OIP:
      ipv4_l2tpv3oip_flow_convert (&f->flow.ip4_l2tpv3oip,
				   &flow.ip4_l2tpv3oip);
      break;
    case VNET_FLOW_TYPE_IP4_IPSEC_ESP:
      ipv4_ipsec_esp_flow_convert (&f->flow.ip4_ipsec_esp,
				   &flow.ip4_ipsec_esp);
      break;
    case VNET_FLOW_TYPE_IP4_IPSEC_AH:
      ipv4_ipsec_ah_flow_convert (&f->flow.ip4_ipsec_ah, &flow.ip4_ipsec_ah);
      break;
    case VNET_FLOW_TYPE_IP4_VXLAN:
      ipv4_vxlan_flow_convert (&f->flow.ip4_vxlan, &flow.ip4_vxlan);
      break;
    case VNET_FLOW_TYPE_IP6_VXLAN:
      ipv6_vxlan_flow_convert (&f->flow.ip6_vxlan, &flow.ip6_vxlan);
      break;
    case VNET_FLOW_TYPE_IP4_GTPU:
      ipv4_gtpu_flow_convert (&f->flow.ip4_gtpu, &flow.ip4_gtpu);
      break;
    case VNET_FLOW_TYPE_IP4_GTPC:
      ipv4_gtpc_flow_convert (&f->flow.ip4_gtpc, &flow.ip4_gtpc);
      break;
    case VNET_FLOW_TYPE_GENERIC:
      generic_flow_convert (&f->flow.generic, &flow.generic);
      break;
    default:
      rv = VNET_FLOW_ERROR_NOT_SUPPORTED;
      goto out;
      break;
    }

  rv = vnet_flow_add (vnm, &flow, &flow_index);

out:
  REPLY_MACRO2 (VL_API_FLOW_ADD_V2_REPLY, ({ rmp->flow_index = ntohl (flow_index); }));
}

static void
vl_api_flow_add_v3_t_handler (vl_api_flow_add_v3_t *mp)
{
  vl_api_flow_add_v3_reply_t *rmp;
  int rv = 0;
  vnet_flow_t flow;
  u32 flow_index = ~0;
  vl_api_flow_rule_v2_t *f = &mp->flow;

  vnet_main_t *vnm = vnet_get_main ();

  flow.type = ntohl (f->type);
  flow.actions = ntohl (f->actions);
  flow.mark_flow_id = ntohl (f->mark_flow_id);
  flow.redirect_node_index = ntohl (f->redirect_node_index);
  flow.redirect_device_input_next_index = ntohl (f->redirect_device_input_next_index);
  flow.redirect_queue = ntohl (f->redirect_queue);
  flow.buffer_advance = ntohl (f->buffer_advance);
  flow.queue_index = ntohl (f->queue_index);
  flow.queue_num = ntohl (f->queue_num);
  flow.rss_types = clib_net_to_host_u64 (f->rss_types);
  flow.rss_fun = ntohl (f->rss_fun);

  switch (flow.type)
    {
    case VNET_FLOW_TYPE_IP4:
      ipv4_flow_convert (&f->flow.ip4, &flow.ip4);
      break;
    case VNET_FLOW_TYPE_IP6:
      ipv6_flow_convert (&f->flow.ip6, &flow.ip6);
      break;
    case VNET_FLOW_TYPE_IP4_N_TUPLE:
      ipv4_n_tuple_flow_convert (&f->flow.ip4_n_tuple, &flow.ip4_n_tuple);
      break;
    case VNET_FLOW_TYPE_IP6_N_TUPLE:
      ipv6_n_tuple_flow_convert (&f->flow.ip6_n_tuple, &flow.ip6_n_tuple);
      break;
    case VNET_FLOW_TYPE_IP4_N_TUPLE_TAGGED:
      ipv4_n_tuple_tagged_flow_convert (&f->flow.ip4_n_tuple_tagged, &flow.ip4_n_tuple_tagged);
      break;
    case VNET_FLOW_TYPE_IP6_N_TUPLE_TAGGED:
      ipv6_n_tuple_tagged_flow_convert (&f->flow.ip6_n_tuple_tagged, &flow.ip6_n_tuple_tagged);
      break;
    case VNET_FLOW_TYPE_IP4_L2TPV3OIP:
      ipv4_l2tpv3oip_flow_convert (&f->flow.ip4_l2tpv3oip, &flow.ip4_l2tpv3oip);
      break;
    case VNET_FLOW_TYPE_IP4_IPSEC_ESP:
      ipv4_ipsec_esp_flow_convert (&f->flow.ip4_ipsec_esp, &flow.ip4_ipsec_esp);
      break;
    case VNET_FLOW_TYPE_IP4_IPSEC_AH:
      ipv4_ipsec_ah_flow_convert (&f->flow.ip4_ipsec_ah, &flow.ip4_ipsec_ah);
      break;
    case VNET_FLOW_TYPE_IP4_VXLAN:
      ipv4_vxlan_flow_convert (&f->flow.ip4_vxlan, &flow.ip4_vxlan);
      break;
    case VNET_FLOW_TYPE_IP6_VXLAN:
      ipv6_vxlan_flow_convert (&f->flow.ip6_vxlan, &flow.ip6_vxlan);
      break;
    case VNET_FLOW_TYPE_IP4_GTPU:
      ipv4_gtpu_flow_convert (&f->flow.ip4_gtpu, &flow.ip4_gtpu);
      break;
    case VNET_FLOW_TYPE_IP4_GTPC:
      ipv4_gtpc_flow_convert (&f->flow.ip4_gtpc, &flow.ip4_gtpc);
      break;
    case VNET_FLOW_TYPE_GENERIC:
      generic_flow_convert (&f->flow.generic, &flow.generic);
      break;
    default:
      rv = VNET_FLOW_ERROR_NOT_SUPPORTED;
      goto out;
      break;
    }

  if (mp->is_template)
    vnet_flow_add_async_template (vnm, &flow, &flow_index);
  else
    rv = vnet_flow_add (vnm, &flow, &flow_index);

out:
  REPLY_MACRO2 (VL_API_FLOW_ADD_V3_REPLY, ({ rmp->flow_index = ntohl (flow_index); }));
}

static void
vl_api_flow_add_v4_t_handler (vl_api_flow_add_v4_t *mp)
{
  vl_api_flow_add_v4_reply_t *rmp;
  int rv = 0;
  vnet_flow_t flow;
  u32 flow_index = ~0;
  vl_api_flow_rule_v3_t *f = &mp->flow;

  vnet_main_t *vnm = vnet_get_main ();

  flow.type = ntohl (f->type);
  flow.dir = (vnet_flow_direction_t) f->dir;
  flow.group = ntohl (f->group);
  flow.actions = ntohl (f->actions);
  flow.mark_flow_id = ntohl (f->mark_flow_id);
  flow.redirect_node_index = ntohl (f->redirect_node_index);
  flow.redirect_device_input_next_index = ntohl (f->redirect_device_input_next_index);
  flow.redirect_queue = ntohl (f->redirect_queue);
  flow.buffer_advance = ntohl (f->buffer_advance);
  flow.queue_index = ntohl (f->queue_index);
  flow.queue_num = ntohl (f->queue_num);
  flow.rss_types = clib_net_to_host_u64 (f->rss_types);
  flow.rss_fun = ntohl (f->rss_fun);

  switch (flow.type)
    {
    case VNET_FLOW_TYPE_IP4:
      ipv4_flow_convert (&f->flow.ip4, &flow.ip4);
      break;
    case VNET_FLOW_TYPE_IP6:
      ipv6_flow_convert (&f->flow.ip6, &flow.ip6);
      break;
    case VNET_FLOW_TYPE_IP4_N_TUPLE:
      ipv4_n_tuple_flow_convert (&f->flow.ip4_n_tuple, &flow.ip4_n_tuple);
      break;
    case VNET_FLOW_TYPE_IP6_N_TUPLE:
      ipv6_n_tuple_flow_convert (&f->flow.ip6_n_tuple, &flow.ip6_n_tuple);
      break;
    case VNET_FLOW_TYPE_IP4_N_TUPLE_TAGGED:
      ipv4_n_tuple_tagged_flow_convert (&f->flow.ip4_n_tuple_tagged, &flow.ip4_n_tuple_tagged);
      break;
    case VNET_FLOW_TYPE_IP6_N_TUPLE_TAGGED:
      ipv6_n_tuple_tagged_flow_convert (&f->flow.ip6_n_tuple_tagged, &flow.ip6_n_tuple_tagged);
      break;
    case VNET_FLOW_TYPE_IP4_L2TPV3OIP:
      ipv4_l2tpv3oip_flow_convert (&f->flow.ip4_l2tpv3oip, &flow.ip4_l2tpv3oip);
      break;
    case VNET_FLOW_TYPE_IP4_IPSEC_ESP:
      ipv4_ipsec_esp_flow_convert (&f->flow.ip4_ipsec_esp, &flow.ip4_ipsec_esp);
      break;
    case VNET_FLOW_TYPE_IP4_IPSEC_AH:
      ipv4_ipsec_ah_flow_convert (&f->flow.ip4_ipsec_ah, &flow.ip4_ipsec_ah);
      break;
    case VNET_FLOW_TYPE_IP4_VXLAN:
      ipv4_vxlan_flow_convert (&f->flow.ip4_vxlan, &flow.ip4_vxlan);
      break;
    case VNET_FLOW_TYPE_IP6_VXLAN:
      ipv6_vxlan_flow_convert (&f->flow.ip6_vxlan, &flow.ip6_vxlan);
      break;
    case VNET_FLOW_TYPE_IP4_GTPU:
      ipv4_gtpu_flow_convert (&f->flow.ip4_gtpu, &flow.ip4_gtpu);
      break;
    case VNET_FLOW_TYPE_IP4_GTPC:
      ipv4_gtpc_flow_convert (&f->flow.ip4_gtpc, &flow.ip4_gtpc);
      break;
    case VNET_FLOW_TYPE_GENERIC:
      generic_flow_convert (&f->flow.generic, &flow.generic);
      break;
    default:
      rv = VNET_FLOW_ERROR_NOT_SUPPORTED;
      goto out;
      break;
    }

  if (mp->is_template)
    vnet_flow_add_async_template (vnm, &flow, &flow_index);
  else
    rv = vnet_flow_add (vnm, &flow, &flow_index);

out:
  REPLY_MACRO2 (VL_API_FLOW_ADD_V4_REPLY, ({ rmp->flow_index = ntohl (flow_index); }));
}

static void
vl_api_flow_del_t_handler (vl_api_flow_del_t * mp)
{
  vl_api_flow_del_reply_t *rmp;
  int rv = 0;

  vnet_main_t *vnm = vnet_get_main ();
  rv = vnet_flow_del (vnm, ntohl (mp->flow_index));

  REPLY_MACRO (VL_API_FLOW_DEL_REPLY);
}

static void
vl_api_flow_del_v2_t_handler (vl_api_flow_del_v2_t *mp)
{
  vl_api_flow_del_v2_reply_t *rmp;
  int rv = 0;

  vnet_main_t *vnm = vnet_get_main ();

  if (mp->is_template)
    rv = vnet_flow_del_async_template (vnm, ntohl (mp->flow_index));
  else
    rv = vnet_flow_del (vnm, ntohl (mp->flow_index));

  REPLY_MACRO (VL_API_FLOW_DEL_V2_REPLY);
}

static void
vl_api_flow_enable_t_handler (vl_api_flow_enable_t * mp)
{
  vl_api_flow_enable_reply_t *rmp;
  int rv = 0;

  vnet_main_t *vnm = vnet_get_main ();
  rv =
    vnet_flow_enable (vnm, ntohl (mp->flow_index), ntohl (mp->hw_if_index));

  REPLY_MACRO (VL_API_FLOW_ENABLE_REPLY);
}

static void
vl_api_flow_template_enable_t_handler (vl_api_flow_template_enable_t *mp)
{
  vl_api_flow_template_enable_reply_t *rmp;
  int rv = 0;

  vnet_main_t *vnm = vnet_get_main ();
  rv = vnet_flow_async_template_enable (vnm, ntohl (mp->flow_index), ntohl (mp->n_flows),
					ntohl (mp->hw_if_index));

  REPLY_MACRO (VL_API_FLOW_TEMPLATE_ENABLE_REPLY);
}

static void
vl_api_flow_async_enable_t_handler (vl_api_flow_async_enable_t *mp)
{
  vl_api_flow_async_enable_reply_t *rmp;
  int rv = 0;

  vnet_main_t *vnm = vnet_get_main ();
  vnet_flow_range_t range = {
    .start = ntohl (mp->start_flow_index),
    .count = ntohl (mp->count),
  };
  rv = vnet_flow_async_enable (vnm, &range, ntohl (mp->template_index), ntohl (mp->hw_if_index));

  REPLY_MACRO (VL_API_FLOW_ASYNC_ENABLE_REPLY);
}

static void
vl_api_flow_disable_t_handler (vl_api_flow_disable_t * mp)
{
  vl_api_flow_disable_reply_t *rmp;
  int rv = 0;

  vnet_main_t *vnm = vnet_get_main ();
  rv =
    vnet_flow_disable (vnm, ntohl (mp->flow_index), ntohl (mp->hw_if_index));

  REPLY_MACRO (VL_API_FLOW_DISABLE_REPLY);
}

static void
vl_api_flow_template_disable_t_handler (vl_api_flow_template_disable_t *mp)
{
  vl_api_flow_template_disable_reply_t *rmp;
  int rv = 0;

  vnet_main_t *vnm = vnet_get_main ();
  rv = vnet_flow_async_template_disable (vnm, ntohl (mp->flow_index), ntohl (mp->hw_if_index));

  REPLY_MACRO (VL_API_FLOW_TEMPLATE_DISABLE_REPLY);
}

static void
vl_api_flow_async_disable_t_handler (vl_api_flow_async_disable_t *mp)
{
  vl_api_flow_async_disable_reply_t *rmp;
  int rv = 0;

  vnet_main_t *vnm = vnet_get_main ();
  vnet_flow_range_t range = {
    .start = ntohl (mp->start_flow_index),
    .count = ntohl (mp->count),
  };
  rv = vnet_flow_async_disable (vnm, &range, ntohl (mp->hw_if_index));

  REPLY_MACRO (VL_API_FLOW_ASYNC_DISABLE_REPLY);
}

#include <vnet/flow/flow.api.c>
static clib_error_t *
hw_flow_api_hookup (vlib_main_t * vm)
{
  flow_main.msg_id_base = setup_message_id_table ();

  return 0;
}

VLIB_API_INIT_FUNCTION (hw_flow_api_hookup);
