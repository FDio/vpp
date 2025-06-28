// SPDX-License-Identifier: Apache-2.0
// Copyright(c) 2022 Cisco Systems, Inc.

#include <vcdp/vcdp.h>

#include <gateway/gateway.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vnet/ip/ip_types_api.h>
#include <vnet/ethernet/ethernet_types_api.h>
#include <vnet/fib/fib_table.h>
#include <vnet/format_fns.h>
#include "tunnel/tunnel.h"
#include <gateway/gateway.api_enum.h>
#include <gateway/gateway.api_types.h>

#define REPLY_MSG_ID_BASE gw->msg_id_base
#include <vlibapi/api_helper_macros.h>

static void
vl_api_vcdp_tunnel_add_t_handler(vl_api_vcdp_tunnel_add_t *mp)
{
  gw_main_t *gw = &gateway_main;
  vl_api_vcdp_tunnel_add_reply_t *rmp;

  ip_address_t src, dst;
  mac_address_t smac, dmac;
  ip_address_decode2(&mp->src, &src);
  ip_address_decode2(&mp->dst, &dst);
  mac_address_decode (mp->src_mac, &smac);
  mac_address_decode (mp->dst_mac, &dmac);

  int rv = vcdp_tunnel_add((char *) mp->tunnel_id, mp->tenant_id, mp->method, &src, &dst, mp->sport,
                           mp->dport, mp->mtu, &smac, &dmac);

  REPLY_MACRO_END(VL_API_VCDP_TUNNEL_ADD_REPLY);
}

static void
vl_api_vcdp_tunnel_remove_t_handler(vl_api_vcdp_tunnel_remove_t *mp)
{
  gw_main_t *gw = &gateway_main;
  vl_api_vcdp_tunnel_remove_reply_t *rmp;
  int rv = vcdp_tunnel_remove((char *)mp->tunnel_id);
  REPLY_MACRO_END(VL_API_VCDP_TUNNEL_REMOVE_REPLY);
}

static void
vl_api_vcdp_gateway_enable_disable_t_handler(vl_api_vcdp_gateway_enable_disable_t *mp)
{
  gw_main_t *gw = &gateway_main;
  vl_api_vcdp_gateway_enable_disable_reply_t *rmp;
  int rv;
  VALIDATE_SW_IF_INDEX_END(mp);

  rv = gw_interface_input_enable_disable(mp->sw_if_index, mp->tenant_id, mp->output_arc, mp->is_enable);
  BAD_SW_IF_INDEX_LABEL;
  REPLY_MACRO_END(VL_API_VCDP_GATEWAY_ENABLE_DISABLE_REPLY);
}

static void
vl_api_vcdp_gateway_prefix_enable_disable_t_handler(vl_api_vcdp_gateway_prefix_enable_disable_t *mp)
{
  gw_main_t *gw = &gateway_main;
  vl_api_vcdp_gateway_prefix_enable_disable_reply_t *rmp;
  int rv;
  ip_prefix_t prefix;
  ip_prefix_decode2(&mp->prefix, &prefix);
  fib_protocol_t proto = prefix.addr.version == AF_IP6 ? FIB_PROTOCOL_IP6 : FIB_PROTOCOL_IP4;
  u32 fib_index = fib_table_find(proto, mp->table_id);

  rv = gw_prefix_input_enable_disable(fib_index, &prefix, mp->tenant_id, mp->is_interpose, mp->is_enable);

  REPLY_MACRO_END(VL_API_VCDP_GATEWAY_PREFIX_ENABLE_DISABLE_REPLY);
}

static void
vl_api_vcdp_gateway_tunnel_enable_disable_t_handler(vl_api_vcdp_gateway_tunnel_enable_disable_t *mp)
{
  gw_main_t *gw = &gateway_main;
  vl_api_vcdp_gateway_tunnel_enable_disable_reply_t *rmp;
  int rv;
  VALIDATE_SW_IF_INDEX_END (mp);
  rv = vcdp_tunnel_enable_disable_input(mp->sw_if_index, mp->is_enable);
  BAD_SW_IF_INDEX_LABEL;
  REPLY_MACRO_END(VL_API_VCDP_GATEWAY_TUNNEL_ENABLE_DISABLE_REPLY);
}

#include <gateway/gateway.api.c>
static clib_error_t *
vcdp_gateway_api_hookup(vlib_main_t *vm)
{
  gw_main_t *gw = &gateway_main;
  gw->msg_id_base = setup_message_id_table();
  return 0;
}
VLIB_API_INIT_FUNCTION(vcdp_gateway_api_hookup);
