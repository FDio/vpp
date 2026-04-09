/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2016 Cisco and/or its affiliates.
 */

#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include <lb/lb.h>

#include <vppinfra/byte_order.h>
#include <vppinfra/string.h>
#include <vpp/api/types.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vpp/app/version.h>
#include <vnet/format_fns.h>
#include <vnet/ip/ip_types_api.h>

/* define message IDs */
#include <lb/lb.api_enum.h>
#include <lb/lb.api_types.h>


#define REPLY_MSG_ID_BASE lbm->msg_id_base
#include <vlibapi/api_helper_macros.h>

#define FINISH                                                                \
  vec_add1 (s, 0);                                                            \
  vlib_cli_output (handle, (char *) s);                                       \
  vec_free (s);                                                               \
  return handle;

static vl_api_lb_encap_type_t
lb_vip_type_to_api_encap (lb_vip_type_t type)
{
  switch (type)
    {
    case LB_VIP_TYPE_IP4_GRE4:
    case LB_VIP_TYPE_IP6_GRE4:
      return LB_API_ENCAP_TYPE_GRE4;
    case LB_VIP_TYPE_IP4_GRE6:
    case LB_VIP_TYPE_IP6_GRE6:
      return LB_API_ENCAP_TYPE_GRE6;
    case LB_VIP_TYPE_IP4_L3DSR:
      return LB_API_ENCAP_TYPE_L3DSR;
    case LB_VIP_TYPE_IP4_NAT4:
      return LB_API_ENCAP_TYPE_NAT4;
    case LB_VIP_TYPE_IP6_NAT6:
      return LB_API_ENCAP_TYPE_NAT6;
    default:
      return LB_API_ENCAP_TYPE_GRE4;
    }
}

static void
vl_api_lb_conf_t_handler
(vl_api_lb_conf_t * mp)
{
  lb_main_t *lbm = &lb_main;
  vl_api_lb_conf_reply_t * rmp;
  u32 sticky_buckets_per_core, flow_timeout;
  int rv = 0;

  sticky_buckets_per_core = mp->sticky_buckets_per_core == ~0
			    ? lbm->per_cpu_sticky_buckets
			    : ntohl(mp->sticky_buckets_per_core);
  flow_timeout = mp->flow_timeout == ~0
		 ? lbm->flow_timeout
		 : ntohl(mp->flow_timeout);

  rv = lb_conf((ip4_address_t *)&mp->ip4_src_address,
	       (ip6_address_t *)&mp->ip6_src_address,
	       sticky_buckets_per_core, flow_timeout);

 REPLY_MACRO (VL_API_LB_CONF_REPLY);
}

static void
vl_api_lb_conf_get_t_handler (vl_api_lb_conf_get_t *mp)
{
 lb_main_t *lbm = &lb_main;
 vl_api_lb_conf_get_reply_t *rmp;
 int rv = 0;

 REPLY_MACRO2 (
   VL_API_LB_CONF_GET_REPLY, ({
     clib_memcpy (rmp->ip4_src_address, &lbm->ip4_src_address, sizeof (rmp->ip4_src_address));
     clib_memcpy (rmp->ip6_src_address, &lbm->ip6_src_address, sizeof (rmp->ip6_src_address));
     rmp->sticky_buckets_per_core = htonl (lbm->per_cpu_sticky_buckets);
     rmp->flow_timeout = htonl (lbm->flow_timeout);
   }));
}

static void
vl_api_lb_add_del_vip_t_handler
(vl_api_lb_add_del_vip_t * mp)
{
  lb_main_t *lbm = &lb_main;
  vl_api_lb_conf_reply_t * rmp;
  int rv = 0;
  lb_vip_add_args_t args = {};

  /* if port == 0, it means all-port VIP */
  if (mp->port == 0)
    {
      mp->protocol = ~0;
    }

  ip_address_decode (&mp->pfx.address, &(args.prefix));
  u8 plen = mp->pfx.len + (mp->pfx.address.af == ADDRESS_IP4 ? 96 : 0);

  if (mp->is_del) {
    u32 vip_index;
    if (!(rv =
	    lb_vip_find_index (&(args.prefix), plen, mp->protocol, ntohs (mp->port), &vip_index)))
      rv = lb_vip_del(vip_index);
  } else {
    u32 vip_index;
    lb_vip_type_t type = 0;
    u32 encap = clib_net_to_host_u32 (mp->encap);

    if (ip46_prefix_is_ip4 (&(args.prefix), plen))
      {
	if (encap == LB_API_ENCAP_TYPE_GRE4)
	  type = LB_VIP_TYPE_IP4_GRE4;
	else if (encap == LB_API_ENCAP_TYPE_GRE6)
	  type = LB_VIP_TYPE_IP4_GRE6;
	else if (encap == LB_API_ENCAP_TYPE_L3DSR)
	  type = LB_VIP_TYPE_IP4_L3DSR;
	else if (encap == LB_API_ENCAP_TYPE_NAT4)
	  type = LB_VIP_TYPE_IP4_NAT4;
      }
    else
      {
	if (encap == LB_API_ENCAP_TYPE_GRE4)
	  type = LB_VIP_TYPE_IP6_GRE4;
	else if (encap == LB_API_ENCAP_TYPE_GRE6)
	  type = LB_VIP_TYPE_IP6_GRE6;
	else if (encap == LB_API_ENCAP_TYPE_NAT6)
	  type = LB_VIP_TYPE_IP6_NAT6;
      }

    args.plen = plen;
    args.protocol = mp->protocol;
    args.port = ntohs(mp->port);
    args.type = type;
    args.new_length = ntohl(mp->new_flows_table_length);

    if (encap == LB_API_ENCAP_TYPE_L3DSR)
      {
	args.encap_args.dscp = (u8) (mp->dscp & 0x3F);
      }
    else if ((encap == LB_API_ENCAP_TYPE_NAT4) || (encap == LB_API_ENCAP_TYPE_NAT6))
      {
	args.encap_args.srv_type = mp->type;
	args.encap_args.target_port = ntohs (mp->target_port);
      }

    rv = lb_vip_add(args, &vip_index);
  }
 REPLY_MACRO (VL_API_LB_ADD_DEL_VIP_REPLY);
}

static void
vl_api_lb_add_del_vip_v2_t_handler (vl_api_lb_add_del_vip_v2_t *mp)
{
  lb_main_t *lbm = &lb_main;
  vl_api_lb_conf_reply_t *rmp;
  int rv = 0;
  lb_vip_add_args_t args = {};

  /* if port == 0, it means all-port VIP */
  if (mp->port == 0)
    {
      mp->protocol = ~0;
    }

  ip_address_decode (&mp->pfx.address, &(args.prefix));
  u8 plen = mp->pfx.len + (mp->pfx.address.af == ADDRESS_IP4 ? 96 : 0);

  if (mp->is_del)
    {
      u32 vip_index;
      if (!(rv =
	      lb_vip_find_index (&(args.prefix), plen, mp->protocol, ntohs (mp->port), &vip_index)))
      rv = lb_vip_del (vip_index);
    }
  else
    {
      u32 vip_index;
      lb_vip_type_t type = 0;
      u32 encap = clib_net_to_host_u32 (mp->encap);

      if (ip46_prefix_is_ip4 (&(args.prefix), plen))
      {
	if (encap == LB_API_ENCAP_TYPE_GRE4)
	  type = LB_VIP_TYPE_IP4_GRE4;
	else if (encap == LB_API_ENCAP_TYPE_GRE6)
	  type = LB_VIP_TYPE_IP4_GRE6;
	else if (encap == LB_API_ENCAP_TYPE_L3DSR)
	  type = LB_VIP_TYPE_IP4_L3DSR;
	else if (encap == LB_API_ENCAP_TYPE_NAT4)
	  type = LB_VIP_TYPE_IP4_NAT4;
      }
      else
	{
	  if (encap == LB_API_ENCAP_TYPE_GRE4)
	    type = LB_VIP_TYPE_IP6_GRE4;
	  else if (encap == LB_API_ENCAP_TYPE_GRE6)
	    type = LB_VIP_TYPE_IP6_GRE6;
	  else if (encap == LB_API_ENCAP_TYPE_NAT6)
	    type = LB_VIP_TYPE_IP6_NAT6;
	}

      args.plen = plen;
      args.protocol = mp->protocol;
      args.port = ntohs (mp->port);
      args.type = type;
      args.new_length = ntohl (mp->new_flows_table_length);

      if (mp->src_ip_sticky)
	args.src_ip_sticky = 1;

      if (encap == LB_API_ENCAP_TYPE_L3DSR)
	{
	  args.encap_args.dscp = (u8) (mp->dscp & 0x3F);
	}
      else if ((encap == LB_API_ENCAP_TYPE_NAT4) || (encap == LB_API_ENCAP_TYPE_NAT6))
	{
	  args.encap_args.srv_type = mp->type;
	  args.encap_args.target_port = ntohs (mp->target_port);
	}

      rv = lb_vip_add (args, &vip_index);
    }
  REPLY_MACRO (VL_API_LB_ADD_DEL_VIP_V2_REPLY);
}

static void
vl_api_lb_add_del_as_t_handler
(vl_api_lb_add_del_as_t * mp)
{
  lb_main_t *lbm = &lb_main;
  vl_api_lb_conf_reply_t * rmp;
  int rv = 0;
  u32 vip_index;
  ip46_address_t vip_ip_prefix;
  ip46_address_t as_address;

  /* if port == 0, it means all-port VIP */
  if (mp->port == 0)
    {
      mp->protocol = ~0;
    }
  ip_address_decode (&mp->pfx.address, &vip_ip_prefix);
  ip_address_decode (&mp->as_address, &as_address);

  u8 plen = mp->pfx.len + (mp->pfx.address.af == ADDRESS_IP4 ? 96 : 0);

  if ((rv = lb_vip_find_index (&vip_ip_prefix, plen, mp->protocol, ntohs (mp->port), &vip_index)))
    goto done;

  if (mp->is_del)
    rv = lb_vip_del_ass(vip_index, &as_address, 1, mp->is_flush);
  else
    rv = lb_vip_add_ass (vip_index, &as_address, 1, 100, 0);

done:
 REPLY_MACRO (VL_API_LB_ADD_DEL_AS_REPLY);
}

static void
vl_api_lb_add_del_as_v2_t_handler (vl_api_lb_add_del_as_v2_t *mp)
{
 lb_main_t *lbm = &lb_main;
 vl_api_lb_add_del_as_v2_reply_t *rmp;
 int rv = 0;
 u32 vip_index;
 ip46_address_t vip_ip_prefix;
 ip46_address_t as_address;

 if (mp->port == 0)
    mp->protocol = ~0;
 ip_address_decode (&mp->pfx.address, &vip_ip_prefix);
 ip_address_decode (&mp->as_address, &as_address);

 u8 plen = mp->pfx.len + (mp->pfx.address.af == ADDRESS_IP4 ? 96 : 0);

 if ((rv = lb_vip_find_index (&vip_ip_prefix, plen, mp->protocol, ntohs (mp->port), &vip_index)))
    goto done;

 if (mp->is_del)
    rv = lb_vip_del_ass (vip_index, &as_address, 1, mp->is_flush);
 else
    rv = lb_vip_add_ass (vip_index, &as_address, 1, mp->weight, mp->is_flush);

done:
 REPLY_MACRO (VL_API_LB_ADD_DEL_AS_V2_REPLY);
}

static void
vl_api_lb_as_set_weight_t_handler (vl_api_lb_as_set_weight_t *mp)
{
 lb_main_t *lbm = &lb_main;
 vl_api_lb_as_set_weight_reply_t *rmp;
 int rv = 0;
 u32 vip_index;
 ip46_address_t vip_ip_prefix;
 ip46_address_t as_address;

 if (mp->port == 0)
    mp->protocol = ~0;
 ip_address_decode (&mp->pfx.address, &vip_ip_prefix);
 ip_address_decode (&mp->as_address, &as_address);

 u8 plen = mp->pfx.len + (mp->pfx.address.af == ADDRESS_IP4 ? 96 : 0);

 if ((rv = lb_vip_find_index (&vip_ip_prefix, plen, mp->protocol, ntohs (mp->port), &vip_index)))
    goto done;

 rv = lb_vip_set_as_weight (vip_index, &as_address, mp->weight, mp->is_flush);

done:
 REPLY_MACRO (VL_API_LB_AS_SET_WEIGHT_REPLY);
}

static void
vl_api_lb_vip_dump_t_handler
(vl_api_lb_vip_dump_t * mp)
{

  vl_api_registration_t *reg;
  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  lb_main_t *lbm = &lb_main;
  vl_api_lb_vip_details_t * rmp;
  int msg_size = 0;
  lb_vip_t *vip = 0;

  /* construct vip list */
  pool_foreach (vip, lbm->vips) {
      /* Hide placeholder VIP and deleted VIPs */
      if (vip != lbm->vips && (vip->flags & LB_VIP_FLAGS_USED))
	{
	  msg_size = sizeof (*rmp);
	  rmp = vl_msg_api_alloc (msg_size);
	  memset (rmp, 0, msg_size);
	  rmp->_vl_msg_id = htons (VL_API_LB_VIP_DETAILS + lbm->msg_id_base);
	  rmp->context = mp->context;

	  ip_address_encode (&vip->prefix, IP46_TYPE_ANY, &rmp->vip.pfx.address);
	  rmp->vip.pfx.len =
	    ip46_prefix_is_ip4 (&vip->prefix, vip->plen) ? vip->plen - 96 : vip->plen;
	  rmp->vip.protocol = vip->protocol;
	  rmp->vip.port = htons (vip->port);
	  rmp->encap = htonl (lb_vip_type_to_api_encap (vip->type));
	  rmp->dscp = vip->encap_args.dscp;
	  rmp->srv_type = vip->encap_args.srv_type;
	  rmp->target_port = htons (vip->encap_args.target_port);
	  rmp->flow_table_length = htons (vip->new_flow_table_mask + 1);

	  vl_api_send_msg (reg, (u8 *) rmp);
	}
  }


}

static void send_lb_as_details
  (vl_api_registration_t * reg, u32 context, lb_vip_t * vip)
{
  vl_api_lb_as_details_t *rmp;
  lb_main_t *lbm = &lb_main;
  int msg_size = 0;
  u32 *as_index;

  /* construct as list under this vip */
  lb_as_t *as;

  pool_foreach (as_index, vip->as_indexes) {
      /* Hide placeholder As for specific VIP */
      if (*as_index != 0) {
        as = &lbm->ass[*as_index];
        msg_size = sizeof (*rmp);
        rmp = vl_msg_api_alloc (msg_size);
        memset (rmp, 0, msg_size);
        rmp->_vl_msg_id =
          htons (VL_API_LB_AS_DETAILS + lbm->msg_id_base);
        rmp->context = context;
        ip_address_encode(&vip->prefix, IP46_TYPE_ANY, (vl_api_address_t *)&rmp->vip.pfx.address);
	rmp->vip.pfx.len =
	  ip46_prefix_is_ip4 (&vip->prefix, vip->plen) ? vip->plen - 96 : vip->plen;
	rmp->vip.protocol = vip->protocol;
	rmp->vip.port = htons (vip->port);
	ip_address_encode (&as->address, IP46_TYPE_ANY, &rmp->app_srv);
	rmp->flags = as->flags;
	rmp->in_use_since = htonl (as->last_used);

	vl_api_send_msg (reg, (u8 *) rmp);
      }
  }


}

static void
send_lb_as_v2_details (vl_api_registration_t *reg, u32 context, lb_vip_t *vip)
{
  vl_api_lb_as_v2_details_t *rmp;
  lb_main_t *lbm = &lb_main;
  lb_as_t *as;
  u32 *as_index;

  /* Count flow-table buckets per AS pool slot */
  u32 *count = 0;
  vec_validate (count, pool_len (lbm->ass));
  lb_new_flow_entry_t *nfe;
  vec_foreach (nfe, vip->new_flow_table)
  count[nfe->as_index]++;

  pool_foreach (as_index, vip->as_indexes)
  {
      if (*as_index == 0)
      continue;
      as = &lbm->ass[*as_index];
      rmp = vl_msg_api_alloc (sizeof (*rmp));
      clib_memset (rmp, 0, sizeof (*rmp));
      rmp->_vl_msg_id = htons (VL_API_LB_AS_V2_DETAILS + lbm->msg_id_base);
      rmp->context = context;
      ip_address_encode (&vip->prefix, IP46_TYPE_ANY, (vl_api_address_t *) &rmp->vip.pfx.address);
      rmp->vip.pfx.len = ip46_prefix_is_ip4 (&vip->prefix, vip->plen) ? vip->plen - 96 : vip->plen;
      rmp->vip.protocol = vip->protocol;
      rmp->vip.port = htons (vip->port);
      ip_address_encode (&as->address, IP46_TYPE_ANY, &rmp->app_srv);
      rmp->flags = as->flags;
      rmp->in_use_since = htonl (as->last_used);
      rmp->weight = as->weight;
      rmp->num_buckets = htonl (count[*as_index]);
      vl_api_send_msg (reg, (u8 *) rmp);
  }

  vec_free (count);
}

static void
vl_api_lb_as_v2_dump_t_handler (vl_api_lb_as_v2_dump_t *mp)
{
  lb_main_t *lbm = &lb_main;
  lb_vip_t *vip = 0;
  u8 dump_all = 0;
  ip46_address_t prefix;

  vl_api_registration_t *reg;
  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
  return;

  clib_memcpy (&prefix.ip6, mp->pfx.address.un.ip6, sizeof (mp->pfx.address.un.ip6));
  dump_all = (prefix.ip6.as_u64[0] == 0) && (prefix.ip6.as_u64[1] == 0);

  pool_foreach (vip, lbm->vips)
  {
      if (dump_all || ((prefix.as_u64[0] == vip->prefix.as_u64[0]) &&
		       (prefix.as_u64[1] == vip->prefix.as_u64[1]) &&
		       (mp->protocol == vip->protocol) && (ntohs (mp->port) == vip->port)))
      send_lb_as_v2_details (reg, mp->context, vip);
  }
}

static void
vl_api_lb_as_dump_t_handler
(vl_api_lb_as_dump_t * mp)
{
  lb_main_t *lbm = &lb_main;
  lb_vip_t *vip = 0;
  u8 dump_all = 0;
  ip46_address_t prefix;

  vl_api_registration_t *reg;
  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  clib_memcpy(&prefix.ip6, mp->pfx.address.un.ip6, sizeof(mp->pfx.address.un.ip6));

  dump_all = (prefix.ip6.as_u64[0] == 0) && (prefix.ip6.as_u64[1] == 0);

  pool_foreach (vip, lbm->vips)
   {
      if (dump_all || ((prefix.as_u64[0] == vip->prefix.as_u64[0]) &&
		       (prefix.as_u64[1] == vip->prefix.as_u64[1]) &&
		       (mp->protocol == vip->protocol) && (ntohs (mp->port) == vip->port)))
      {
        send_lb_as_details(reg, mp->context, vip);
      }
  }
}

static void
vl_api_lb_flush_vip_t_handler
(vl_api_lb_flush_vip_t * mp)
{
  lb_main_t *lbm = &lb_main;
  int rv = 0;
  ip46_address_t vip_prefix;
  u32 vip_index;
  vl_api_lb_flush_vip_reply_t * rmp;

  if (mp->port == 0)
    {
      mp->protocol = ~0;
    }

  ip_address_decode (&mp->pfx.address, &vip_prefix);
  u8 plen = mp->pfx.len + (mp->pfx.address.af == ADDRESS_IP4 ? 96 : 0);

  rv = lb_vip_find_index (&vip_prefix, plen, mp->protocol, ntohs (mp->port), &vip_index);

  rv = lb_flush_vip_as(vip_index, ~0);

 REPLY_MACRO (VL_API_LB_FLUSH_VIP_REPLY);
}

static void vl_api_lb_add_del_intf_nat4_t_handler
  (vl_api_lb_add_del_intf_nat4_t * mp)
{
  lb_main_t *lbm = &lb_main;
  vl_api_lb_add_del_intf_nat4_reply_t *rmp;
  u32 sw_if_index = ntohl (mp->sw_if_index);
  u8 is_del;
  int rv = 0;

  is_del = !mp->is_add;

  VALIDATE_SW_IF_INDEX (mp);

  rv = lb_nat4_interface_add_del(sw_if_index, is_del);

  BAD_SW_IF_INDEX_LABEL;

  REPLY_MACRO (VL_API_LB_ADD_DEL_INTF_NAT4_REPLY);
}

static void vl_api_lb_add_del_intf_nat6_t_handler
  (vl_api_lb_add_del_intf_nat6_t * mp)
{
  lb_main_t *lbm = &lb_main;
  vl_api_lb_add_del_intf_nat6_reply_t *rmp;
  u32 sw_if_index = ntohl (mp->sw_if_index);
  u8 is_del;
  int rv = 0;

  is_del = !mp->is_add;

  VALIDATE_SW_IF_INDEX (mp);

  rv = lb_nat6_interface_add_del(sw_if_index, is_del);

  BAD_SW_IF_INDEX_LABEL;

  REPLY_MACRO (VL_API_LB_ADD_DEL_INTF_NAT6_REPLY);
}

#include <lb/lb.api.c>
static clib_error_t * lb_api_init (vlib_main_t * vm)
{
  lb_main_t * lbm = &lb_main;

  lbm->vlib_main = vm;
  lbm->vnet_main = vnet_get_main();

  /* Ask for a correctly-sized block of API message decode slots */
  lbm->msg_id_base = setup_message_id_table ();

  return 0;
}

VLIB_INIT_FUNCTION (lb_api_init);
