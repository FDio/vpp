/*
 *------------------------------------------------------------------
 * Copyright (c) 2018 Cisco and/or its affiliates.
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

#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>

#include <vnet/interface.h>
#include <vnet/api_errno.h>
#include <vnet/ip/ip_types_api.h>
#include <vnet/ethernet/ethernet_types_api.h>
#include <vpp/app/version.h>

#include <gbp/gbp.h>
#include <gbp/gbp_learn.h>
#include <gbp/gbp_itf.h>
#include <gbp/gbp_vxlan.h>
#include <gbp/gbp_bridge_domain.h>
#include <gbp/gbp_route_domain.h>
#include <gbp/gbp_ext_itf.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>

/* define message IDs */
#include <gbp/gbp_msg_enum.h>

#define vl_typedefs		/* define message structures */
#include <gbp/gbp_all_api_h.h>
#undef vl_typedefs

#define vl_endianfun		/* define message structures */
#include <gbp/gbp_all_api_h.h>
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)
#define vl_printfun
#include <gbp/gbp_all_api_h.h>
#undef vl_printfun

/* Get the API version number */
#define vl_api_version(n,v) static u32 api_version=(v);
#include <gbp/gbp_all_api_h.h>
#undef vl_api_version

#include <vlibapi/api_helper_macros.h>

#define foreach_gbp_api_msg                                 \
  _(GBP_ENDPOINT_ADD, gbp_endpoint_add)                     \
  _(GBP_ENDPOINT_DEL, gbp_endpoint_del)                     \
  _(GBP_ENDPOINT_DUMP, gbp_endpoint_dump)                   \
  _(GBP_SUBNET_ADD_DEL, gbp_subnet_add_del)                 \
  _(GBP_SUBNET_DUMP, gbp_subnet_dump)                       \
  _(GBP_ENDPOINT_GROUP_ADD, gbp_endpoint_group_add)         \
  _(GBP_ENDPOINT_GROUP_DEL, gbp_endpoint_group_del)         \
  _(GBP_ENDPOINT_GROUP_DUMP, gbp_endpoint_group_dump)       \
  _(GBP_BRIDGE_DOMAIN_ADD, gbp_bridge_domain_add)           \
  _(GBP_BRIDGE_DOMAIN_DEL, gbp_bridge_domain_del)           \
  _(GBP_BRIDGE_DOMAIN_DUMP, gbp_bridge_domain_dump)         \
  _(GBP_ROUTE_DOMAIN_ADD, gbp_route_domain_add)             \
  _(GBP_ROUTE_DOMAIN_DEL, gbp_route_domain_del)             \
  _(GBP_ROUTE_DOMAIN_DUMP, gbp_route_domain_dump)           \
  _(GBP_RECIRC_ADD_DEL, gbp_recirc_add_del)                 \
  _(GBP_RECIRC_DUMP, gbp_recirc_dump)                       \
  _(GBP_EXT_ITF_ADD_DEL, gbp_ext_itf_add_del)               \
  _(GBP_EXT_ITF_DUMP, gbp_ext_itf_dump)                     \
  _(GBP_CONTRACT_ADD_DEL, gbp_contract_add_del)             \
  _(GBP_CONTRACT_DUMP, gbp_contract_dump)                   \
  _(GBP_ENDPOINT_LEARN_SET_INACTIVE_THRESHOLD, gbp_endpoint_learn_set_inactive_threshold) \
  _(GBP_VXLAN_TUNNEL_ADD, gbp_vxlan_tunnel_add)                         \
  _(GBP_VXLAN_TUNNEL_DEL, gbp_vxlan_tunnel_del)                         \
  _(GBP_VXLAN_TUNNEL_DUMP, gbp_vxlan_tunnel_dump)

gbp_main_t gbp_main;

static u16 msg_id_base;

#define GBP_MSG_BASE msg_id_base

static gbp_endpoint_flags_t
gbp_endpoint_flags_decode (vl_api_gbp_endpoint_flags_t v)
{
  gbp_endpoint_flags_t f = GBP_ENDPOINT_FLAG_NONE;

  v = ntohl (v);

  if (v & GBP_API_ENDPOINT_FLAG_BOUNCE)
    f |= GBP_ENDPOINT_FLAG_BOUNCE;
  if (v & GBP_API_ENDPOINT_FLAG_REMOTE)
    f |= GBP_ENDPOINT_FLAG_REMOTE;
  if (v & GBP_API_ENDPOINT_FLAG_LEARNT)
    f |= GBP_ENDPOINT_FLAG_LEARNT;
  if (v & GBP_API_ENDPOINT_FLAG_EXTERNAL)
    f |= GBP_ENDPOINT_FLAG_EXTERNAL;

  return (f);
}

static vl_api_gbp_endpoint_flags_t
gbp_endpoint_flags_encode (gbp_endpoint_flags_t f)
{
  vl_api_gbp_endpoint_flags_t v = 0;


  if (f & GBP_ENDPOINT_FLAG_BOUNCE)
    v |= GBP_API_ENDPOINT_FLAG_BOUNCE;
  if (f & GBP_ENDPOINT_FLAG_REMOTE)
    v |= GBP_API_ENDPOINT_FLAG_REMOTE;
  if (f & GBP_ENDPOINT_FLAG_LEARNT)
    v |= GBP_API_ENDPOINT_FLAG_LEARNT;
  if (f & GBP_ENDPOINT_FLAG_EXTERNAL)
    v |= GBP_API_ENDPOINT_FLAG_EXTERNAL;

  v = htonl (v);

  return (v);
}

static void
vl_api_gbp_endpoint_add_t_handler (vl_api_gbp_endpoint_add_t * mp)
{
  vl_api_gbp_endpoint_add_reply_t *rmp;
  gbp_endpoint_flags_t gef;
  u32 sw_if_index, handle;
  ip46_address_t *ips;
  mac_address_t mac;
  int rv = 0, ii;

  VALIDATE_SW_IF_INDEX (&(mp->endpoint));

  gef = gbp_endpoint_flags_decode (mp->endpoint.flags), ips = NULL;
  sw_if_index = ntohl (mp->endpoint.sw_if_index);

  if (mp->endpoint.n_ips)
    {
      vec_validate (ips, mp->endpoint.n_ips - 1);

      vec_foreach_index (ii, ips)
      {
	ip_address_decode (&mp->endpoint.ips[ii], &ips[ii]);
      }
    }
  mac_address_decode (mp->endpoint.mac, &mac);

  if (GBP_ENDPOINT_FLAG_REMOTE & gef)
    {
      ip46_address_t tun_src, tun_dst;

      ip_address_decode (&mp->endpoint.tun.src, &tun_src);
      ip_address_decode (&mp->endpoint.tun.dst, &tun_dst);

      rv = gbp_endpoint_update_and_lock (GBP_ENDPOINT_SRC_CP,
					 sw_if_index, ips, &mac,
					 INDEX_INVALID, INDEX_INVALID,
					 ntohs (mp->endpoint.epg_id),
					 gef, &tun_src, &tun_dst, &handle);
    }
  else
    {
      rv = gbp_endpoint_update_and_lock (GBP_ENDPOINT_SRC_CP,
					 sw_if_index, ips, &mac,
					 INDEX_INVALID, INDEX_INVALID,
					 ntohs (mp->endpoint.epg_id),
					 gef, NULL, NULL, &handle);
    }
  vec_free (ips);
  BAD_SW_IF_INDEX_LABEL;

  /* *INDENT-OFF* */
  REPLY_MACRO2 (VL_API_GBP_ENDPOINT_ADD_REPLY + GBP_MSG_BASE,
  ({
    rmp->handle = htonl (handle);
  }));
  /* *INDENT-ON* */
}

static void
vl_api_gbp_endpoint_del_t_handler (vl_api_gbp_endpoint_del_t * mp)
{
  vl_api_gbp_endpoint_del_reply_t *rmp;
  int rv = 0;

  gbp_endpoint_unlock (GBP_ENDPOINT_SRC_CP, ntohl (mp->handle));

  REPLY_MACRO (VL_API_GBP_ENDPOINT_DEL_REPLY + GBP_MSG_BASE);
}

static void
  vl_api_gbp_endpoint_learn_set_inactive_threshold_t_handler
  (vl_api_gbp_endpoint_learn_set_inactive_threshold_t * mp)
{
  vl_api_gbp_endpoint_learn_set_inactive_threshold_reply_t *rmp;
  int rv = 0;

  gbp_learn_set_inactive_threshold (ntohl (mp->threshold));

  REPLY_MACRO (VL_API_GBP_ENDPOINT_LEARN_SET_INACTIVE_THRESHOLD_REPLY +
	       GBP_MSG_BASE);
}

typedef struct gbp_walk_ctx_t_
{
  vl_api_registration_t *reg;
  u32 context;
} gbp_walk_ctx_t;

static walk_rc_t
gbp_endpoint_send_details (index_t gei, void *args)
{
  vl_api_gbp_endpoint_details_t *mp;
  gbp_endpoint_loc_t *gel;
  gbp_endpoint_fwd_t *gef;
  gbp_endpoint_t *ge;
  gbp_walk_ctx_t *ctx;
  u8 n_ips, ii;

  ctx = args;
  ge = gbp_endpoint_get (gei);

  n_ips = vec_len (ge->ge_key.gek_ips);
  mp = vl_msg_api_alloc (sizeof (*mp) + (sizeof (*mp->endpoint.ips) * n_ips));
  if (!mp)
    return 1;

  clib_memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = ntohs (VL_API_GBP_ENDPOINT_DETAILS + GBP_MSG_BASE);
  mp->context = ctx->context;

  gel = &ge->ge_locs[0];
  gef = &ge->ge_fwd;

  if (gbp_endpoint_is_remote (ge))
    {
      mp->endpoint.sw_if_index = ntohl (gel->tun.gel_parent_sw_if_index);
      ip_address_encode (&gel->tun.gel_src, IP46_TYPE_ANY,
			 &mp->endpoint.tun.src);
      ip_address_encode (&gel->tun.gel_dst, IP46_TYPE_ANY,
			 &mp->endpoint.tun.dst);
    }
  else
    {
      mp->endpoint.sw_if_index = ntohl (gef->gef_itf);
    }
  mp->endpoint.epg_id = ntohs (ge->ge_fwd.gef_epg_id);
  mp->endpoint.n_ips = n_ips;
  mp->endpoint.flags = gbp_endpoint_flags_encode (gef->gef_flags);
  mp->handle = htonl (gei);
  mp->age = vlib_time_now (vlib_get_main ()) - ge->ge_last_time;
  mac_address_encode (&ge->ge_key.gek_mac, mp->endpoint.mac);

  vec_foreach_index (ii, ge->ge_key.gek_ips)
  {
    ip_address_encode (&ge->ge_key.gek_ips[ii].fp_addr,
		       IP46_TYPE_ANY, &mp->endpoint.ips[ii]);
  }

  vl_api_send_msg (ctx->reg, (u8 *) mp);

  return (WALK_CONTINUE);
}

static void
vl_api_gbp_endpoint_dump_t_handler (vl_api_gbp_endpoint_dump_t * mp)
{
  vl_api_registration_t *reg;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  gbp_walk_ctx_t ctx = {
    .reg = reg,
    .context = mp->context,
  };

  gbp_endpoint_walk (gbp_endpoint_send_details, &ctx);
}

static void
  vl_api_gbp_endpoint_group_add_t_handler
  (vl_api_gbp_endpoint_group_add_t * mp)
{
  vl_api_gbp_endpoint_group_add_reply_t *rmp;
  int rv = 0;

  rv = gbp_endpoint_group_add_and_lock (ntohs (mp->epg.epg_id),
					ntohl (mp->epg.bd_id),
					ntohl (mp->epg.rd_id),
					ntohl (mp->epg.uplink_sw_if_index));

  REPLY_MACRO (VL_API_GBP_ENDPOINT_GROUP_ADD_REPLY + GBP_MSG_BASE);
}

static void
  vl_api_gbp_endpoint_group_del_t_handler
  (vl_api_gbp_endpoint_group_del_t * mp)
{
  vl_api_gbp_endpoint_group_del_reply_t *rmp;
  int rv = 0;

  rv = gbp_endpoint_group_delete (ntohs (mp->epg_id));

  REPLY_MACRO (VL_API_GBP_ENDPOINT_GROUP_DEL_REPLY + GBP_MSG_BASE);
}

static gbp_bridge_domain_flags_t
gbp_bridge_domain_flags_from_api (vl_api_gbp_bridge_domain_flags_t a)
{
  gbp_bridge_domain_flags_t g;

  g = GBP_BD_FLAG_NONE;
  a = clib_net_to_host_u32 (a);

  if (a & GBP_BD_API_FLAG_DO_NOT_LEARN)
    g |= GBP_BD_FLAG_DO_NOT_LEARN;

  return (g);
}

static void
vl_api_gbp_bridge_domain_add_t_handler (vl_api_gbp_bridge_domain_add_t * mp)
{
  vl_api_gbp_bridge_domain_add_reply_t *rmp;
  int rv = 0;

  rv = gbp_bridge_domain_add_and_lock (ntohl (mp->bd.bd_id),
				       gbp_bridge_domain_flags_from_api
				       (mp->bd.flags),
				       ntohl (mp->bd.bvi_sw_if_index),
				       ntohl (mp->bd.uu_fwd_sw_if_index));

  REPLY_MACRO (VL_API_GBP_BRIDGE_DOMAIN_ADD_REPLY + GBP_MSG_BASE);
}

static void
vl_api_gbp_bridge_domain_del_t_handler (vl_api_gbp_bridge_domain_del_t * mp)
{
  vl_api_gbp_bridge_domain_del_reply_t *rmp;
  int rv = 0;

  rv = gbp_bridge_domain_delete (ntohl (mp->bd_id));

  REPLY_MACRO (VL_API_GBP_BRIDGE_DOMAIN_DEL_REPLY + GBP_MSG_BASE);
}

static void
vl_api_gbp_route_domain_add_t_handler (vl_api_gbp_route_domain_add_t * mp)
{
  vl_api_gbp_route_domain_add_reply_t *rmp;
  int rv = 0;

  rv = gbp_route_domain_add_and_lock (ntohl (mp->rd.rd_id),
				      ntohl (mp->rd.ip4_table_id),
				      ntohl (mp->rd.ip6_table_id),
				      ntohl (mp->rd.ip4_uu_sw_if_index),
				      ntohl (mp->rd.ip6_uu_sw_if_index));

  REPLY_MACRO (VL_API_GBP_ROUTE_DOMAIN_ADD_REPLY + GBP_MSG_BASE);
}

static void
vl_api_gbp_route_domain_del_t_handler (vl_api_gbp_route_domain_del_t * mp)
{
  vl_api_gbp_route_domain_del_reply_t *rmp;
  int rv = 0;

  rv = gbp_route_domain_delete (ntohl (mp->rd_id));

  REPLY_MACRO (VL_API_GBP_ROUTE_DOMAIN_DEL_REPLY + GBP_MSG_BASE);
}

static int
gub_subnet_type_from_api (vl_api_gbp_subnet_type_t a, gbp_subnet_type_t * t)
{
  a = clib_net_to_host_u32 (a);

  switch (a)
    {
    case GBP_API_SUBNET_TRANSPORT:
      *t = GBP_SUBNET_TRANSPORT;
      return (0);
    case GBP_API_SUBNET_L3_OUT:
      *t = GBP_SUBNET_L3_OUT;
      return (0);
    case GBP_API_SUBNET_STITCHED_INTERNAL:
      *t = GBP_SUBNET_STITCHED_INTERNAL;
      return (0);
    case GBP_API_SUBNET_STITCHED_EXTERNAL:
      *t = GBP_SUBNET_STITCHED_EXTERNAL;
      return (0);
    }

  return (-1);
}

static void
vl_api_gbp_subnet_add_del_t_handler (vl_api_gbp_subnet_add_del_t * mp)
{
  vl_api_gbp_subnet_add_del_reply_t *rmp;
  gbp_subnet_type_t type;
  fib_prefix_t pfx;
  int rv = 0;

  ip_prefix_decode (&mp->subnet.prefix, &pfx);

  rv = gub_subnet_type_from_api (mp->subnet.type, &type);

  if (0 != rv)
    goto out;

  if (mp->is_add)
    rv = gbp_subnet_add (ntohl (mp->subnet.rd_id),
			 &pfx, type,
			 ntohl (mp->subnet.sw_if_index),
			 ntohs (mp->subnet.epg_id));
  else
    rv = gbp_subnet_del (ntohl (mp->subnet.rd_id), &pfx);

out:
  REPLY_MACRO (VL_API_GBP_SUBNET_ADD_DEL_REPLY + GBP_MSG_BASE);
}

static vl_api_gbp_subnet_type_t
gub_subnet_type_to_api (gbp_subnet_type_t t)
{
  vl_api_gbp_subnet_type_t a = 0;

  switch (t)
    {
    case GBP_SUBNET_TRANSPORT:
      a = GBP_API_SUBNET_TRANSPORT;
      break;
    case GBP_SUBNET_STITCHED_INTERNAL:
      a = GBP_API_SUBNET_STITCHED_INTERNAL;
      break;
    case GBP_SUBNET_STITCHED_EXTERNAL:
      a = GBP_API_SUBNET_STITCHED_EXTERNAL;
      break;
    case GBP_SUBNET_L3_OUT:
      a = GBP_API_SUBNET_L3_OUT;
      break;
    }

  a = clib_host_to_net_u32 (a);

  return (a);
}

static walk_rc_t
gbp_subnet_send_details (u32 rd_id,
			 const fib_prefix_t * pfx,
			 gbp_subnet_type_t type,
			 u32 sw_if_index, epg_id_t epg, void *args)
{
  vl_api_gbp_subnet_details_t *mp;
  gbp_walk_ctx_t *ctx;

  ctx = args;
  mp = vl_msg_api_alloc (sizeof (*mp));
  if (!mp)
    return 1;

  clib_memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = ntohs (VL_API_GBP_SUBNET_DETAILS + GBP_MSG_BASE);
  mp->context = ctx->context;

  mp->subnet.type = gub_subnet_type_to_api (type);
  mp->subnet.sw_if_index = ntohl (sw_if_index);
  mp->subnet.epg_id = ntohs (epg);
  mp->subnet.rd_id = ntohl (rd_id);
  ip_prefix_encode (pfx, &mp->subnet.prefix);

  vl_api_send_msg (ctx->reg, (u8 *) mp);

  return (WALK_CONTINUE);
}

static void
vl_api_gbp_subnet_dump_t_handler (vl_api_gbp_subnet_dump_t * mp)
{
  vl_api_registration_t *reg;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  gbp_walk_ctx_t ctx = {
    .reg = reg,
    .context = mp->context,
  };

  gbp_subnet_walk (gbp_subnet_send_details, &ctx);
}

static int
gbp_endpoint_group_send_details (gbp_endpoint_group_t * gg, void *args)
{
  vl_api_gbp_endpoint_group_details_t *mp;
  gbp_walk_ctx_t *ctx;

  ctx = args;
  mp = vl_msg_api_alloc (sizeof (*mp));
  if (!mp)
    return 1;

  clib_memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = ntohs (VL_API_GBP_ENDPOINT_GROUP_DETAILS + GBP_MSG_BASE);
  mp->context = ctx->context;

  mp->epg.uplink_sw_if_index = ntohl (gg->gg_uplink_sw_if_index);
  mp->epg.epg_id = ntohs (gg->gg_id);
  mp->epg.bd_id = ntohl (gbp_endpoint_group_get_bd_id (gg));
  mp->epg.rd_id = ntohl (gbp_route_domain_get_rd_id (gg->gg_rd));

  vl_api_send_msg (ctx->reg, (u8 *) mp);

  return (1);
}

static void
vl_api_gbp_endpoint_group_dump_t_handler (vl_api_gbp_endpoint_group_dump_t *
					  mp)
{
  vl_api_registration_t *reg;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  gbp_walk_ctx_t ctx = {
    .reg = reg,
    .context = mp->context,
  };

  gbp_endpoint_group_walk (gbp_endpoint_group_send_details, &ctx);
}

static int
gbp_bridge_domain_send_details (gbp_bridge_domain_t * gb, void *args)
{
  vl_api_gbp_bridge_domain_details_t *mp;
  gbp_walk_ctx_t *ctx;

  ctx = args;
  mp = vl_msg_api_alloc (sizeof (*mp));
  if (!mp)
    return 1;

  memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = ntohs (VL_API_GBP_BRIDGE_DOMAIN_DETAILS + GBP_MSG_BASE);
  mp->context = ctx->context;

  mp->bd.bd_id = ntohl (gb->gb_bd_id);
  mp->bd.bvi_sw_if_index = ntohl (gb->gb_bvi_sw_if_index);
  mp->bd.uu_fwd_sw_if_index = ntohl (gb->gb_uu_fwd_sw_if_index);

  vl_api_send_msg (ctx->reg, (u8 *) mp);

  return (1);
}

static void
vl_api_gbp_bridge_domain_dump_t_handler (vl_api_gbp_bridge_domain_dump_t * mp)
{
  vl_api_registration_t *reg;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  gbp_walk_ctx_t ctx = {
    .reg = reg,
    .context = mp->context,
  };

  gbp_bridge_domain_walk (gbp_bridge_domain_send_details, &ctx);
}

static int
gbp_route_domain_send_details (gbp_route_domain_t * grd, void *args)
{
  vl_api_gbp_route_domain_details_t *mp;
  gbp_walk_ctx_t *ctx;

  ctx = args;
  mp = vl_msg_api_alloc (sizeof (*mp));
  if (!mp)
    return 1;

  memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = ntohs (VL_API_GBP_ROUTE_DOMAIN_DETAILS + GBP_MSG_BASE);
  mp->context = ctx->context;

  mp->rd.rd_id = ntohl (grd->grd_id);
  mp->rd.ip4_uu_sw_if_index =
    ntohl (grd->grd_uu_sw_if_index[FIB_PROTOCOL_IP4]);
  mp->rd.ip6_uu_sw_if_index =
    ntohl (grd->grd_uu_sw_if_index[FIB_PROTOCOL_IP6]);

  vl_api_send_msg (ctx->reg, (u8 *) mp);

  return (1);
}

static void
vl_api_gbp_route_domain_dump_t_handler (vl_api_gbp_route_domain_dump_t * mp)
{
  vl_api_registration_t *reg;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  gbp_walk_ctx_t ctx = {
    .reg = reg,
    .context = mp->context,
  };

  gbp_route_domain_walk (gbp_route_domain_send_details, &ctx);
}

static void
vl_api_gbp_recirc_add_del_t_handler (vl_api_gbp_recirc_add_del_t * mp)
{
  vl_api_gbp_recirc_add_del_reply_t *rmp;
  u32 sw_if_index;
  int rv = 0;

  sw_if_index = ntohl (mp->recirc.sw_if_index);
  if (!vnet_sw_if_index_is_api_valid (sw_if_index))
    goto bad_sw_if_index;

  if (mp->is_add)
    gbp_recirc_add (sw_if_index,
		    ntohs (mp->recirc.epg_id), mp->recirc.is_ext);
  else
    gbp_recirc_delete (sw_if_index);

  BAD_SW_IF_INDEX_LABEL;

  REPLY_MACRO (VL_API_GBP_RECIRC_ADD_DEL_REPLY + GBP_MSG_BASE);
}

static walk_rc_t
gbp_recirc_send_details (gbp_recirc_t * gr, void *args)
{
  vl_api_gbp_recirc_details_t *mp;
  gbp_walk_ctx_t *ctx;

  ctx = args;
  mp = vl_msg_api_alloc (sizeof (*mp));
  if (!mp)
    return (WALK_STOP);

  clib_memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = ntohs (VL_API_GBP_RECIRC_DETAILS + GBP_MSG_BASE);
  mp->context = ctx->context;

  mp->recirc.epg_id = ntohs (gr->gr_epg);
  mp->recirc.sw_if_index = ntohl (gr->gr_sw_if_index);
  mp->recirc.is_ext = gr->gr_is_ext;

  vl_api_send_msg (ctx->reg, (u8 *) mp);

  return (WALK_CONTINUE);
}

static void
vl_api_gbp_recirc_dump_t_handler (vl_api_gbp_recirc_dump_t * mp)
{
  vl_api_registration_t *reg;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  gbp_walk_ctx_t ctx = {
    .reg = reg,
    .context = mp->context,
  };

  gbp_recirc_walk (gbp_recirc_send_details, &ctx);
}

static void
vl_api_gbp_ext_itf_add_del_t_handler (vl_api_gbp_ext_itf_add_del_t * mp)
{
  vl_api_gbp_ext_itf_add_del_reply_t *rmp;
  u32 sw_if_index;
  vl_api_gbp_ext_itf_t ext_itf;
  int rv = 0;

  ext_itf = mp->ext_itf;
  sw_if_index = ntohl (ext_itf.sw_if_index);

  if (!vnet_sw_if_index_is_api_valid (sw_if_index))
    goto bad_sw_if_index;

  if (mp->is_add)
    rv = gbp_ext_itf_add (sw_if_index,
			  ntohl (ext_itf.bd_id), ntohl (ext_itf.rd_id));
  else
    rv = gbp_ext_itf_delete (sw_if_index);

  BAD_SW_IF_INDEX_LABEL;

  REPLY_MACRO (VL_API_GBP_EXT_ITF_ADD_DEL_REPLY + GBP_MSG_BASE);
}

static walk_rc_t
gbp_ext_itf_send_details (gbp_ext_itf_t * gx, void *args)
{
  vl_api_gbp_ext_itf_details_t *mp;
  gbp_walk_ctx_t *ctx;

  ctx = args;
  mp = vl_msg_api_alloc (sizeof (*mp));
  if (!mp)
    return (WALK_STOP);

  clib_memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = ntohs (VL_API_GBP_EXT_ITF_DETAILS + GBP_MSG_BASE);
  mp->context = ctx->context;

  mp->ext_itf.bd_id = ntohl (gbp_bridge_domain_get_bd_id (gx->gx_bd));
  mp->ext_itf.rd_id = ntohl (gbp_route_domain_get_rd_id (gx->gx_rd));
  mp->ext_itf.sw_if_index = ntohl (gx->gx_itf);

  vl_api_send_msg (ctx->reg, (u8 *) mp);

  return (WALK_CONTINUE);
}

static void
vl_api_gbp_ext_itf_dump_t_handler (vl_api_gbp_ext_itf_dump_t * mp)
{
  vl_api_registration_t *reg;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  gbp_walk_ctx_t ctx = {
    .reg = reg,
    .context = mp->context,
  };

  gbp_ext_itf_walk (gbp_ext_itf_send_details, &ctx);
}

static int
gbp_contract_rule_action_deocde (vl_api_gbp_rule_action_t in,
				 gbp_rule_action_t * out)
{
  in = clib_net_to_host_u32 (in);

  switch (in)
    {
    case GBP_API_RULE_PERMIT:
      *out = GBP_RULE_PERMIT;
      return (0);
    case GBP_API_RULE_DENY:
      *out = GBP_RULE_DENY;
      return (0);
    case GBP_API_RULE_REDIRECT:
      *out = GBP_RULE_REDIRECT;
      return (0);
    }

  return (-1);
}

static int
gbp_hash_mode_decode (vl_api_gbp_hash_mode_t in, gbp_hash_mode_t * out)
{
  in = clib_net_to_host_u32 (in);

  switch (in)
    {
    case GBP_API_HASH_MODE_SRC_IP:
      *out = GBP_HASH_MODE_SRC_IP;
      return (0);
    case GBP_API_HASH_MODE_DST_IP:
      *out = GBP_HASH_MODE_DST_IP;
      return (0);
    case GBP_API_HASH_MODE_SYMMETRIC:
      *out = GBP_HASH_MODE_SYMMETRIC;
      return (0);
    }

  return (-2);
}

static int
gbp_next_hop_decode (const vl_api_gbp_next_hop_t * in, index_t * gnhi)
{
  ip46_address_t ip;
  mac_address_t mac;
  index_t grd, gbd;

  gbd = gbp_bridge_domain_find_and_lock (ntohl (in->bd_id));

  if (INDEX_INVALID == gbd)
    return (VNET_API_ERROR_BD_NOT_MODIFIABLE);

  grd = gbp_route_domain_find_and_lock (ntohl (in->rd_id));

  if (INDEX_INVALID == grd)
    return (VNET_API_ERROR_NO_SUCH_FIB);

  ip_address_decode (&in->ip, &ip);
  mac_address_decode (in->mac, &mac);

  *gnhi = gbp_next_hop_alloc (&ip, grd, &mac, gbd);

  return (0);
}

static int
gbp_next_hop_set_decode (const vl_api_gbp_next_hop_set_t * in,
			 gbp_hash_mode_t * hash_mode, index_t ** out)
{

  index_t *gnhis = NULL;
  int rv;
  u8 ii;

  rv = gbp_hash_mode_decode (in->hash_mode, hash_mode);

  if (0 != rv)
    return rv;

  vec_validate (gnhis, in->n_nhs - 1);

  for (ii = 0; ii < in->n_nhs; ii++)
    {
      rv = gbp_next_hop_decode (&in->nhs[ii], &gnhis[ii]);

      if (0 != rv)
	{
	  vec_free (gnhis);
	  break;
	}
    }

  *out = gnhis;
  return (rv);
}

static int
gbp_contract_rule_decode (const vl_api_gbp_rule_t * in, index_t * gui)
{
  gbp_hash_mode_t hash_mode;
  gbp_rule_action_t action;
  index_t *nhs = NULL;
  int rv;

  rv = gbp_contract_rule_action_deocde (in->action, &action);

  if (0 != rv)
    return rv;

  if (GBP_RULE_REDIRECT == action)
    {
      rv = gbp_next_hop_set_decode (&in->nh_set, &hash_mode, &nhs);

      if (0 != rv)
	return (rv);
    }
  else
    {
      hash_mode = GBP_HASH_MODE_SRC_IP;
    }

  *gui = gbp_rule_alloc (action, hash_mode, nhs);

  return (rv);
}

static int
gbp_contract_rules_decode (u8 n_rules,
			   const vl_api_gbp_rule_t * rules, index_t ** out)
{
  index_t *guis = NULL;
  int rv;
  u8 ii;

  if (0 == n_rules)
    {
      *out = NULL;
      return (0);
    }

  vec_validate (guis, n_rules - 1);

  for (ii = 0; ii < n_rules; ii++)
    {
      rv = gbp_contract_rule_decode (&rules[ii], &guis[ii]);

      if (0 != rv)
	{
	  vec_free (guis);
	  return (rv);
	}
    }

  *out = guis;
  return (rv);
}

static void
vl_api_gbp_contract_add_del_t_handler (vl_api_gbp_contract_add_del_t * mp)
{
  vl_api_gbp_contract_add_del_reply_t *rmp;
  u16 *allowed_ethertypes;
  index_t *rules;
  int ii, rv = 0;
  u8 *data, n_et;
  u16 *et;

  if (mp->is_add)
    {
      rv = gbp_contract_rules_decode (mp->contract.n_rules,
				      mp->contract.rules, &rules);
      if (0 != rv)
	goto out;

      allowed_ethertypes = NULL;

      /*
       * move past the variable legnth array of rules to get to the
       * allowed ether types
       */
      data = (((u8 *) & mp->contract.n_ether_types) +
	      (sizeof (mp->contract.rules[0]) * mp->contract.n_rules));
      n_et = *data;
      et = (u16 *) (++data);
      vec_validate (allowed_ethertypes, n_et - 1);

      for (ii = 0; ii < n_et; ii++)
	{
	  /* leave the ether types in network order */
	  allowed_ethertypes[ii] = et[ii];
	}

      rv = gbp_contract_update (ntohs (mp->contract.src_epg),
				ntohs (mp->contract.dst_epg),
				ntohl (mp->contract.acl_index),
				rules, allowed_ethertypes);
    }
  else
    rv = gbp_contract_delete (ntohs (mp->contract.src_epg),
			      ntohs (mp->contract.dst_epg));

out:
  REPLY_MACRO (VL_API_GBP_CONTRACT_ADD_DEL_REPLY + GBP_MSG_BASE);
}

static int
gbp_contract_send_details (gbp_contract_t * gbpc, void *args)
{
  vl_api_gbp_contract_details_t *mp;
  gbp_walk_ctx_t *ctx;

  ctx = args;
  mp = vl_msg_api_alloc (sizeof (*mp));
  if (!mp)
    return 1;

  clib_memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = ntohs (VL_API_GBP_CONTRACT_DETAILS + GBP_MSG_BASE);
  mp->context = ctx->context;

  mp->contract.src_epg = ntohs (gbpc->gc_key.gck_src);
  mp->contract.dst_epg = ntohs (gbpc->gc_key.gck_dst);
  // mp->contract.acl_index = ntohl (gbpc->gc_value.gc_acl_index);

  vl_api_send_msg (ctx->reg, (u8 *) mp);

  return (1);
}

static void
vl_api_gbp_contract_dump_t_handler (vl_api_gbp_contract_dump_t * mp)
{
  vl_api_registration_t *reg;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  gbp_walk_ctx_t ctx = {
    .reg = reg,
    .context = mp->context,
  };

  gbp_contract_walk (gbp_contract_send_details, &ctx);
}

static int
gbp_vxlan_tunnel_mode_2_layer (vl_api_gbp_vxlan_tunnel_mode_t mode,
			       gbp_vxlan_tunnel_layer_t * l)
{
  mode = clib_net_to_host_u32 (mode);

  switch (mode)
    {
    case GBP_VXLAN_TUNNEL_MODE_L2:
      *l = GBP_VXLAN_TUN_L2;
      return (0);
    case GBP_VXLAN_TUNNEL_MODE_L3:
      *l = GBP_VXLAN_TUN_L3;
      return (0);
    }
  return (-1);
}

static void
vl_api_gbp_vxlan_tunnel_add_t_handler (vl_api_gbp_vxlan_tunnel_add_t * mp)
{
  vl_api_gbp_vxlan_tunnel_add_reply_t *rmp;
  gbp_vxlan_tunnel_layer_t layer;
  u32 sw_if_index;
  int rv = 0;

  rv = gbp_vxlan_tunnel_mode_2_layer (mp->tunnel.mode, &layer);

  if (0 != rv)
    goto out;

  rv = gbp_vxlan_tunnel_add (ntohl (mp->tunnel.vni),
			     layer,
			     ntohl (mp->tunnel.bd_rd_id), &sw_if_index);

out:
  /* *INDENT-OFF* */
  REPLY_MACRO2 (VL_API_GBP_VXLAN_TUNNEL_ADD_REPLY + GBP_MSG_BASE,
  ({
    rmp->sw_if_index = htonl (sw_if_index);
  }));
  /* *INDENT-ON* */
}

static void
vl_api_gbp_vxlan_tunnel_del_t_handler (vl_api_gbp_vxlan_tunnel_add_t * mp)
{
  vl_api_gbp_vxlan_tunnel_del_reply_t *rmp;
  int rv = 0;

  rv = gbp_vxlan_tunnel_del (ntohl (mp->tunnel.vni));

  REPLY_MACRO (VL_API_GBP_VXLAN_TUNNEL_DEL_REPLY + GBP_MSG_BASE);
}

static vl_api_gbp_vxlan_tunnel_mode_t
gbp_vxlan_tunnel_layer_2_mode (gbp_vxlan_tunnel_layer_t layer)
{
  vl_api_gbp_vxlan_tunnel_mode_t mode = GBP_VXLAN_TUNNEL_MODE_L2;

  switch (layer)
    {
    case GBP_VXLAN_TUN_L2:
      mode = GBP_VXLAN_TUNNEL_MODE_L2;
      break;
    case GBP_VXLAN_TUN_L3:
      mode = GBP_VXLAN_TUNNEL_MODE_L3;
      break;
    }
  mode = clib_host_to_net_u32 (mode);

  return (mode);
}

static walk_rc_t
gbp_vxlan_tunnel_send_details (gbp_vxlan_tunnel_t * gt, void *args)
{
  vl_api_gbp_vxlan_tunnel_details_t *mp;
  gbp_walk_ctx_t *ctx;

  ctx = args;
  mp = vl_msg_api_alloc (sizeof (*mp));
  if (!mp)
    return 1;

  memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = htons (VL_API_GBP_VXLAN_TUNNEL_DETAILS + GBP_MSG_BASE);
  mp->context = ctx->context;

  mp->tunnel.vni = htonl (gt->gt_vni);
  mp->tunnel.mode = gbp_vxlan_tunnel_layer_2_mode (gt->gt_layer);
  mp->tunnel.bd_rd_id = htonl (gt->gt_bd_rd_id);

  vl_api_send_msg (ctx->reg, (u8 *) mp);

  return (1);
}

static void
vl_api_gbp_vxlan_tunnel_dump_t_handler (vl_api_gbp_vxlan_tunnel_dump_t * mp)
{
  vl_api_registration_t *reg;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  gbp_walk_ctx_t ctx = {
    .reg = reg,
    .context = mp->context,
  };

  gbp_vxlan_walk (gbp_vxlan_tunnel_send_details, &ctx);
}

/*
 * gbp_api_hookup
 * Add vpe's API message handlers to the table.
 * vlib has already mapped shared memory and
 * added the client registration handlers.
 * See .../vlib-api/vlibmemory/memclnt_vlib.c:memclnt_process()
 */
#define vl_msg_name_crc_list
#include <gbp/gbp_all_api_h.h>
#undef vl_msg_name_crc_list

static void
setup_message_id_table (api_main_t * am)
{
#define _(id,n,crc)                                     \
  vl_msg_api_add_msg_name_crc (am, #n "_" #crc, id + GBP_MSG_BASE);
  foreach_vl_msg_name_crc_gbp;
#undef _
}

static void
gbp_api_hookup (vlib_main_t * vm)
{
#define _(N,n)                                                  \
    vl_msg_api_set_handlers(VL_API_##N + GBP_MSG_BASE,          \
                            #n,                                 \
                            vl_api_##n##_t_handler,             \
                            vl_noop_handler,                    \
                            vl_api_##n##_t_endian,              \
                            vl_api_##n##_t_print,               \
                            sizeof(vl_api_##n##_t), 1);
  foreach_gbp_api_msg;
#undef _
}

static clib_error_t *
gbp_init (vlib_main_t * vm)
{
  api_main_t *am = &api_main;
  gbp_main_t *gbpm = &gbp_main;
  u8 *name = format (0, "gbp_%08x%c", api_version, 0);

  gbpm->gbp_acl_user_id = ~0;

  /* Ask for a correctly-sized block of API message decode slots */
  msg_id_base = vl_msg_api_get_msg_ids ((char *) name,
					VL_MSG_FIRST_AVAILABLE);
  gbp_api_hookup (vm);

  /* Add our API messages to the global name_crc hash table */
  setup_message_id_table (am);

  vec_free (name);
  return (NULL);
}

VLIB_API_INIT_FUNCTION (gbp_init);

/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () = {
    .version = VPP_BUILD_VER,
    .description = "Group Based Policy",
};
/* *INDENT-ON* */


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
