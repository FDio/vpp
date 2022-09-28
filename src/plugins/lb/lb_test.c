/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
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
 */

#include <vat/vat.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vnet/ip/ip_types_api.h>

#include <vppinfra/error.h>
#include <lb/lb.h>

#define __plugin_msg_base lb_test_main.msg_id_base
#include <vlibapi/vat_helper_macros.h>

#include <vnet/format_fns.h>
#include <lb/lb.api_enum.h>
#include <lb/lb.api_types.h>

//TODO: Move that to vat/plugin_api.c
//////////////////////////
uword unformat_ip46_address (unformat_input_t * input, va_list * args)
{
  ip46_address_t *ip46 = va_arg (*args, ip46_address_t *);
  ip46_type_t type = va_arg (*args, ip46_type_t);
  if ((type != IP46_TYPE_IP6) &&
      unformat(input, "%U", unformat_ip4_address, &ip46->ip4)) {
    ip46_address_mask_ip4(ip46);
    return 1;
  } else if ((type != IP46_TYPE_IP4) &&
      unformat(input, "%U", unformat_ip6_address, &ip46->ip6)) {
    return 1;
  }
  return 0;
}
uword unformat_ip46_prefix (unformat_input_t * input, va_list * args)
{
  ip46_address_t *ip46 = va_arg (*args, ip46_address_t *);
  u8 *len = va_arg (*args, u8 *);
  ip46_type_t type = va_arg (*args, ip46_type_t);

  u32 l;
  if ((type != IP46_TYPE_IP6) && unformat(input, "%U/%u", unformat_ip4_address, &ip46->ip4, &l)) {
    if (l > 32)
      return 0;
    *len = l + 96;
    ip46->pad[0] = ip46->pad[1] = ip46->pad[2] = 0;
  } else if ((type != IP46_TYPE_IP4) && unformat(input, "%U/%u", unformat_ip6_address, &ip46->ip6, &l)) {
    if (l > 128)
      return 0;
    *len = l;
  } else {
    return 0;
  }
  return 1;
}
/////////////////////////

typedef struct {
    /* API message ID base */
    u16 msg_id_base;
    vat_main_t *vat_main;
} lb_test_main_t;

lb_test_main_t lb_test_main;

static int api_lb_conf (vat_main_t * vam)
{
  unformat_input_t *line_input = vam->input;
  vl_api_lb_conf_t *mp;
  u32 ip4_src_address = 0xffffffff;
  ip46_address_t ip6_src_address;
  u32 sticky_buckets_per_core = LB_DEFAULT_PER_CPU_STICKY_BUCKETS;
  u32 flow_timeout = LB_DEFAULT_FLOW_TIMEOUT;
  int ret;

  ip6_src_address.as_u64[0] = 0xffffffffffffffffL;
  ip6_src_address.as_u64[1] = 0xffffffffffffffffL;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
  {
    if (unformat(line_input, "ip4-src-address %U", unformat_ip4_address, &ip4_src_address))
      ;
    else if (unformat(line_input, "ip6-src-address %U", unformat_ip6_address, &ip6_src_address))
      ;
    else if (unformat(line_input, "buckets %d", &sticky_buckets_per_core))
      ;
    else if (unformat(line_input, "timeout %d", &flow_timeout))
      ;
    else {
        errmsg ("invalid arguments\n");
        return -99;
    }
  }

  M(LB_CONF, mp);
  clib_memcpy (&(mp->ip4_src_address), &ip4_src_address, sizeof (ip4_src_address));
  clib_memcpy (&(mp->ip6_src_address), &ip6_src_address, sizeof (ip6_src_address));
  mp->sticky_buckets_per_core = htonl (sticky_buckets_per_core);
  mp->flow_timeout = htonl (flow_timeout);

  S(mp);
  W (ret);
  return ret;
}

static int api_lb_add_del_vip (vat_main_t * vam)
{
  unformat_input_t *line_input = vam->input;
  vl_api_lb_add_del_vip_t *mp;
  int ret;
  ip46_address_t ip_prefix;
  u8 prefix_length = 0;
  u8 protocol = 0;
  u32 port = 0;
  u32 encap = 0;
  u32 dscp = ~0;
  u32 srv_type = LB_SRV_TYPE_CLUSTERIP;
  u32 target_port = 0;
  u32 new_length = 1024;
  int is_del = 0;

  if (!unformat(line_input, "%U", unformat_ip46_prefix, &ip_prefix,
                &prefix_length, IP46_TYPE_ANY, &prefix_length)) {
    errmsg ("lb_add_del_vip: invalid vip prefix\n");
    return -99;
  }

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
  {
    if (unformat(line_input, "new_len %d", &new_length))
      ;
    else if (unformat(line_input, "del"))
      is_del = 1;
    else if (unformat(line_input, "protocol tcp"))
      {
        protocol = IP_PROTOCOL_TCP;
      }
    else if (unformat(line_input, "protocol udp"))
      {
        protocol = IP_PROTOCOL_UDP;
      }
    else if (unformat(line_input, "port %d", &port))
      ;
    else if (unformat(line_input, "encap gre4"))
      encap = LB_ENCAP_TYPE_GRE4;
    else if (unformat(line_input, "encap gre6"))
      encap = LB_ENCAP_TYPE_GRE6;
    else if (unformat(line_input, "encap l3dsr"))
      encap = LB_ENCAP_TYPE_L3DSR;
    else if (unformat(line_input, "encap nat4"))
      encap = LB_ENCAP_TYPE_NAT4;
    else if (unformat(line_input, "encap nat6"))
      encap = LB_ENCAP_TYPE_NAT6;
    else if (unformat(line_input, "dscp %d", &dscp))
      ;
    else if (unformat(line_input, "type clusterip"))
      srv_type = LB_SRV_TYPE_CLUSTERIP;
    else if (unformat(line_input, "type nodeport"))
      srv_type = LB_SRV_TYPE_NODEPORT;
    else if (unformat(line_input, "target_port %d", &target_port))
      ;
    else {
        errmsg ("invalid arguments\n");
        return -99;
    }
  }

  if ((encap != LB_ENCAP_TYPE_L3DSR) && (dscp != ~0))
    {
      errmsg("lb_vip_add error: should not configure dscp for none L3DSR.");
      return -99;
    }

  if ((encap == LB_ENCAP_TYPE_L3DSR) && (dscp >= 64))
    {
      errmsg("lb_vip_add error: dscp for L3DSR should be less than 64.");
      return -99;
    }

  M(LB_ADD_DEL_VIP, mp);
  ip_address_encode(&ip_prefix, IP46_TYPE_ANY, &mp->pfx.address);
  mp->pfx.len = prefix_length;
  mp->protocol = (u8)protocol;
  mp->port = htons((u16)port);
  mp->encap = (u8)encap;
  mp->dscp = (u8)dscp;
  mp->type = (u8)srv_type;
  mp->target_port = htons((u16)target_port);
  mp->node_port = htons((u16)target_port);
  mp->new_flows_table_length = htonl(new_length);
  mp->is_del = is_del;

  S(mp);
  W (ret);
  return ret;
}

static int
api_lb_add_del_vip_v2 (vat_main_t *vam)
{
  unformat_input_t *line_input = vam->input;
  vl_api_lb_add_del_vip_v2_t *mp;
  int ret;
  ip46_address_t ip_prefix;
  u8 prefix_length = 0;
  u8 protocol = 0;
  u32 port = 0;
  u32 encap = 0;
  u32 dscp = ~0;
  u32 srv_type = LB_SRV_TYPE_CLUSTERIP;
  u32 target_port = 0;
  u32 new_length = 1024;
  u8 src_ip_sticky = 0;
  int is_del = 0;

  if (!unformat (line_input, "%U", unformat_ip46_prefix, &ip_prefix,
		 &prefix_length, IP46_TYPE_ANY, &prefix_length))
    {
      errmsg ("lb_add_del_vip: invalid vip prefix\n");
      return -99;
    }

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "new_len %d", &new_length))
	;
      else if (unformat (line_input, "del"))
	is_del = 1;
      else if (unformat (line_input, "src_ip_sticky"))
	src_ip_sticky = 1;
      else if (unformat (line_input, "protocol tcp"))
	{
	  protocol = IP_PROTOCOL_TCP;
	}
      else if (unformat (line_input, "protocol udp"))
	{
	  protocol = IP_PROTOCOL_UDP;
	}
      else if (unformat (line_input, "port %d", &port))
	;
      else if (unformat (line_input, "encap gre4"))
	encap = LB_ENCAP_TYPE_GRE4;
      else if (unformat (line_input, "encap gre6"))
	encap = LB_ENCAP_TYPE_GRE6;
      else if (unformat (line_input, "encap l3dsr"))
	encap = LB_ENCAP_TYPE_L3DSR;
      else if (unformat (line_input, "encap nat4"))
	encap = LB_ENCAP_TYPE_NAT4;
      else if (unformat (line_input, "encap nat6"))
	encap = LB_ENCAP_TYPE_NAT6;
      else if (unformat (line_input, "dscp %d", &dscp))
	;
      else if (unformat (line_input, "type clusterip"))
	srv_type = LB_SRV_TYPE_CLUSTERIP;
      else if (unformat (line_input, "type nodeport"))
	srv_type = LB_SRV_TYPE_NODEPORT;
      else if (unformat (line_input, "target_port %d", &target_port))
	;
      else
	{
	  errmsg ("invalid arguments\n");
	  return -99;
	}
    }

  if ((encap != LB_ENCAP_TYPE_L3DSR) && (dscp != ~0))
    {
      errmsg ("lb_vip_add error: should not configure dscp for none L3DSR.");
      return -99;
    }

  if ((encap == LB_ENCAP_TYPE_L3DSR) && (dscp >= 64))
    {
      errmsg ("lb_vip_add error: dscp for L3DSR should be less than 64.");
      return -99;
    }

  M (LB_ADD_DEL_VIP, mp);
  ip_address_encode (&ip_prefix, IP46_TYPE_ANY, &mp->pfx.address);
  mp->pfx.len = prefix_length;
  mp->protocol = (u8) protocol;
  mp->port = htons ((u16) port);
  mp->encap = (u8) encap;
  mp->dscp = (u8) dscp;
  mp->type = (u8) srv_type;
  mp->target_port = htons ((u16) target_port);
  mp->node_port = htons ((u16) target_port);
  mp->new_flows_table_length = htonl (new_length);
  mp->is_del = is_del;
  mp->src_ip_sticky = src_ip_sticky;

  S (mp);
  W (ret);
  return ret;
}

static int api_lb_add_del_as (vat_main_t * vam)
{

  unformat_input_t *line_input = vam->input;
  vl_api_lb_add_del_as_t *mp;
  int ret;
  ip46_address_t vip_prefix, as_addr;
  u8 vip_plen;
  ip46_address_t *as_array = 0;
  u32 port = 0;
  u8 protocol = 0;
  u8 is_del = 0;
  u8 is_flush = 0;

  if (!unformat(line_input, "%U", unformat_ip46_prefix,
                &vip_prefix, &vip_plen, IP46_TYPE_ANY))
  {
      errmsg ("lb_add_del_as: invalid vip prefix\n");
      return -99;
  }

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
  {
    if (unformat(line_input, "%U", unformat_ip46_address,
                 &as_addr, IP46_TYPE_ANY))
      {
        vec_add1(as_array, as_addr);
      }
    else if (unformat(line_input, "del"))
      {
        is_del = 1;
      }
    else if (unformat(line_input, "flush"))
      {
        is_flush = 1;
      }
    else if (unformat(line_input, "protocol tcp"))
      {
          protocol = IP_PROTOCOL_TCP;
      }
    else if (unformat(line_input, "protocol udp"))
      {
          protocol = IP_PROTOCOL_UDP;
      }
    else if (unformat(line_input, "port %d", &port))
      ;
    else {
        errmsg ("invalid arguments\n");
        return -99;
    }
  }

  if (!vec_len(as_array)) {
    errmsg ("No AS address provided \n");
    return -99;
  }

  M(LB_ADD_DEL_AS, mp);
  ip_address_encode(&vip_prefix, IP46_TYPE_ANY, &mp->pfx.address);
  mp->pfx.len = vip_plen;
  mp->protocol = (u8)protocol;
  mp->port = htons((u16)port);
  ip_address_encode(&as_addr, IP46_TYPE_ANY, &mp->as_address);
  mp->is_del = is_del;
  mp->is_flush = is_flush;

  S(mp);
  W (ret);
  return ret;
}

static int api_lb_flush_vip (vat_main_t * vam)
{

  unformat_input_t *line_input = vam->input;
  vl_api_lb_flush_vip_t *mp;
  int ret;
  ip46_address_t vip_prefix;
  u8 vip_plen;

  if (!unformat(line_input, "%U", unformat_ip46_prefix,
                &vip_prefix, &vip_plen, IP46_TYPE_ANY))
  {
      errmsg ("lb_add_del_as: invalid vip prefix\n");
      return -99;
  }

  M(LB_FLUSH_VIP, mp);
  clib_memcpy (mp->pfx.address.un.ip6, &vip_prefix.ip6, sizeof (vip_prefix.ip6));
  mp->pfx.len = vip_plen;
  S(mp);
  W (ret);
  return ret;
}
static int api_lb_add_del_intf_nat4 (vat_main_t * vam)
{
  // Not yet implemented
  return -99;
}

static int api_lb_add_del_intf_nat6 (vat_main_t * vam)
{
  // Not yet implemented
  return -99;
}

static void vl_api_lb_vip_details_t_handler
  (vl_api_lb_vip_details_t * mp)
{
  vat_main_t *vam = &vat_main;

  print (vam->ofp, "%24U%14d%14d%18d",
       format_ip46_address, &mp->vip.pfx.address, IP46_TYPE_ANY,
       mp->vip.pfx.len,
       mp->vip.protocol,
       ntohs (mp->vip.port));
/*
  lb_main_t *lbm = &lb_main;
  u32 i = 0;

  u32 vip_count = pool_len(lbm->vips);

  print (vam->ofp, "%11d", vip_count);

  for (i=0; i<vip_count; i--)
    {
      print (vam->ofp, "%24U%14d%14d%18d",
           format_ip46_address, &mp->vip.pfx.address, IP46_TYPE_ANY,
           mp->vip.pfx.len,
           mp->vip.protocol,
           ntohs (mp->vip.port));
    }
*/
}

static int api_lb_vip_dump (vat_main_t * vam)
{
  vl_api_lb_vip_dump_t *mp;
  int ret;

  M(LB_VIP_DUMP, mp);

  S(mp);
  W (ret);
  return ret;
}

static void vl_api_lb_as_details_t_handler
  (vl_api_lb_as_details_t * mp)
{
  vat_main_t *vam = &vat_main;

  print (vam->ofp, "%24U%14d%14d%18d%d%d",
       format_ip46_address, &mp->vip.pfx.address, IP46_TYPE_ANY,
       mp->vip.pfx.len,
       mp->vip.protocol,
       ntohs (mp->vip.port),
       mp->flags,
       mp->in_use_since);

  //u32 i = 0;

/*
  lb_main_t *lbm = &lb_main;
  print (vam->ofp, "%11d", pool_len(lbm->ass));
  for (i=0; i<pool_len(lbm->ass); i--)
    {
      print (vam->ofp, "%24U%14d%14d%18d",
           format_ip46_address, &mp->pfx.address, IP46_TYPE_ANY,
           mp->pfx.len,
           mp->pfx.protocol,
           ntohs (mp->pfx.port),
           ntohl(mp->app_srv),
           mp->flags,
           mp->in_use_;
    }
    */
}

static int api_lb_as_dump (vat_main_t * vam)
{

  unformat_input_t *line_input = vam->input;
  vl_api_lb_as_dump_t *mp;
  int ret;
  ip46_address_t vip_prefix, as_addr;
  u8 vip_plen;
  ip46_address_t *as_array = 0;
  u32 port = 0;
  u8 protocol = 0;

  if (!unformat(line_input, "%U", unformat_ip46_prefix,
                &vip_prefix, &vip_plen, IP46_TYPE_ANY))
  {
      errmsg ("lb_add_del_as: invalid vip prefix\n");
      return -99;
  }

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
  {
    if (unformat(line_input, "%U", unformat_ip46_address,
                 &as_addr, IP46_TYPE_ANY))
      {
        vec_add1(as_array, as_addr);
      }
    else if (unformat(line_input, "protocol tcp"))
      {
          protocol = IP_PROTOCOL_TCP;
      }
    else if (unformat(line_input, "protocol udp"))
      {
          protocol = IP_PROTOCOL_UDP;
      }
    else if (unformat(line_input, "port %d", &port))
      ;
    else {
        errmsg ("invalid arguments\n");
        return -99;
    }
  }

  if (!vec_len(as_array)) {
    errmsg ("No AS address provided \n");
    return -99;
  }

  M(LB_AS_DUMP, mp);
  clib_memcpy (mp->pfx.address.un.ip6, &vip_prefix.ip6, sizeof (vip_prefix.ip6));
  mp->pfx.len = vip_plen;
  mp->protocol = (u8)protocol;
  mp->port = htons((u16)port);

  S(mp);
  W (ret);
  return ret;
}

#include <lb/lb.api_test.c>
