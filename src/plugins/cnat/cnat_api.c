/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2016 Cisco and/or its affiliates.
 */

#include <stddef.h>

#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include <cnat/cnat_translation.h>
#include <cnat/cnat_session.h>
#include <cnat/cnat_client.h>
#include <cnat/cnat_snat_policy.h>

#include <vnet/ip/ip_types_api.h>

#include <vnet/fib/fib_table.h>

#include <vpp/app/version.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>

/* define message IDs */
#include <vnet/format_fns.h>
#include <cnat/cnat.api_enum.h>
#include <cnat/cnat.api_types.h>

STATIC_ASSERT ((int) CNAT_TRANSLATION_ALLOC_PORT == (int) CNAT_TR_FLAG_ALLOCATE_PORT,
	       "cnat api enum mismatch");
STATIC_ASSERT ((int) CNAT_TRANSLATION_NO_RETURN_SESSION == (int) CNAT_TR_FLAG_NO_RETURN_SESSION,
	       "cnat api enum mismatch");

STATIC_ASSERT ((int) CNAT_EPT_NO_NAT == (int) CNAT_TRK_FLAG_NO_NAT, "cnat api enum mismatch");

STATIC_ASSERT ((int) CNAT_LB_TYPE_DEFAULT == (int) CNAT_LB_DEFAULT, "cnat api enum mismatch");
STATIC_ASSERT ((int) CNAT_LB_TYPE_MAGLEV == (int) CNAT_LB_MAGLEV, "cnat api enum mismatch");

STATIC_ASSERT ((int) CNAT_POLICY_INCLUDE_V4 == (int) CNAT_SNAT_IF_MAP_INCLUDE_V4,
	       "cnat api enum mismatch");
STATIC_ASSERT ((int) CNAT_POLICY_INCLUDE_V6 == (int) CNAT_SNAT_IF_MAP_INCLUDE_V6,
	       "cnat api enum mismatch");
STATIC_ASSERT ((int) CNAT_POLICY_POD == (int) CNAT_SNAT_IF_MAP_INCLUDE_POD,
	       "cnat api enum mismatch");

STATIC_ASSERT ((int) CNAT_POLICY_NONE == (int) CNAT_SNAT_POLICY_NONE, "cnat api enum mismatch");
STATIC_ASSERT ((int) CNAT_POLICY_IF_PFX == (int) CNAT_SNAT_POLICY_IF_PFX, "cnat api enum mismatch");
STATIC_ASSERT ((int) CNAT_POLICY_K8S == (int) CNAT_SNAT_POLICY_K8S, "cnat api enum mismatch");

/**
 * Base message ID fot the plugin
 */
static u32 cnat_base_msg_id;

#define REPLY_MSG_ID_BASE cnat_base_msg_id

#include <vlibapi/api_helper_macros.h>

static int
cnat_endpoint_decode (const vl_api_cnat_endpoint_t * in,
		      cnat_endpoint_t * out)
{
  int rv = 0;
  out->ce_port = clib_net_to_host_u16 (in->port);
  out->ce_sw_if_index = clib_net_to_host_u32 (in->sw_if_index);
  out->ce_flags = 0;
  if (out->ce_sw_if_index == INDEX_INVALID)
    ip_address_decode2 (&in->addr, &out->ce_ip);
  else
    rv = ip_address_family_decode (in->if_af, &out->ce_ip.version);
  return rv;
}

static int
cnat_endpoint_tuple_decode (const vl_api_cnat_endpoint_tuple_t * in,
			    cnat_endpoint_tuple_t * out)
{
  int rv = 0;
  rv = cnat_endpoint_decode (&in->src_ep, &out->src_ep);
  if (rv)
    return rv;
  rv = cnat_endpoint_decode (&in->dst_ep, &out->dst_ep);
  out->ep_flags = in->flags;
  return rv;
}

static void
cnat_endpoint_encode (const cnat_endpoint_t * in,
		      vl_api_cnat_endpoint_t * out)
{
  out->port = clib_net_to_host_u16 (in->ce_port);
  out->sw_if_index = clib_net_to_host_u32 (in->ce_sw_if_index);
  out->if_af = ip_address_family_encode (in->ce_ip.version);
  if (in->ce_flags & CNAT_EP_FLAG_RESOLVED)
    ip_address_encode2 (&in->ce_ip, &out->addr);
  else
    clib_memset (&out->addr, 0, sizeof (out->addr));
}

static void
cnat_5tuple_encode (const cnat_5tuple_t *in, vl_api_cnat_5tuple_t *out)
{
  out->port[VLIB_RX] = clib_net_to_host_u16 (in->port[VLIB_RX]);
  out->port[VLIB_TX] = clib_net_to_host_u16 (in->port[VLIB_TX]);
  ip_address_encode (&in->ip[VLIB_RX], IP46_TYPE_ANY, &out->addr[VLIB_RX]);
  ip_address_encode (&in->ip[VLIB_TX], IP46_TYPE_ANY, &out->addr[VLIB_TX]);
  out->ip_proto = ip_proto_encode (in->iproto);
}

static void
vl_api_cnat_translation_update_t_handler (vl_api_cnat_translation_update_t
					  * mp)
{
  vl_api_cnat_translation_update_reply_t *rmp;
  cnat_endpoint_t vip;
  cnat_endpoint_tuple_t *paths = NULL, *path;
  ip_protocol_t ip_proto;
  u32 id = ~0;
  u8 flags;
  int rv = 0;
  u32 pi, n_paths;
  cnat_lb_type_t lb_type;
  flow_hash_config_t flow_hash_config = 0;

  rv = ip_proto_decode (mp->translation.ip_proto, &ip_proto);

  if (rv)
    goto done;

  n_paths = clib_net_to_host_u32 (mp->translation.n_paths);
  vec_validate (paths, n_paths - 1);

  for (pi = 0; pi < n_paths; pi++)
    {
      path = &paths[pi];
      rv = cnat_endpoint_tuple_decode (&mp->translation.paths[pi], path);
      if (rv)
	goto done;
    }

  rv = cnat_endpoint_decode (&mp->translation.vip, &vip);
  if (rv)
    goto done;

  flags = mp->translation.flags;
  if (!mp->translation.is_real_ip)
    flags |= CNAT_TR_FLAG_EXCLUSIVE;

  lb_type = (cnat_lb_type_t) mp->translation.lb_type;
  flow_hash_config = (flow_hash_config_t) clib_net_to_host_u32 (
    mp->translation.flow_hash_config);
  id = cnat_translation_update (&vip, ip_proto, paths, flags, lb_type,
				flow_hash_config);

  vec_free (paths);

done:
  REPLY_MACRO2 (VL_API_CNAT_TRANSLATION_UPDATE_REPLY,
  ({
    rmp->id = htonl (id);
  }));
}

static void
vl_api_cnat_translation_del_t_handler (vl_api_cnat_translation_del_t * mp)
{
  vl_api_cnat_translation_del_reply_t *rmp;
  int rv;

  rv = cnat_translation_delete (ntohl (mp->id), CNAT_FIB_TABLE);

  REPLY_MACRO (VL_API_CNAT_TRANSLATION_DEL_REPLY);
}

typedef struct cnat_dump_walk_ctx_t_
{
  vl_api_registration_t *rp;
  u32 context;
} cnat_dump_walk_ctx_t;

static walk_rc_t
cnat_translation_send_details (u32 cti, void *args)
{
  vl_api_cnat_translation_details_t *mp;
  cnat_dump_walk_ctx_t *ctx;
  cnat_ep_trk_t *trk;
  vl_api_cnat_endpoint_tuple_t *path;
  size_t msg_size;
  cnat_translation_t *ct;
  u32 n_paths;

  ctx = args;
  ct = cnat_translation_get (cti);
  n_paths = vec_len (ct->ct_paths);
  msg_size = sizeof (*mp) + sizeof (mp->translation.paths[0]) * n_paths;

  mp = vl_msg_api_alloc_zero (msg_size);
  mp->_vl_msg_id = ntohs (VL_API_CNAT_TRANSLATION_DETAILS + cnat_base_msg_id);

  /* fill in the message */
  mp->context = ctx->context;
  mp->translation.n_paths = clib_host_to_net_u32 (n_paths);
  mp->translation.id = clib_host_to_net_u32 (cti);
  cnat_endpoint_encode (&ct->ct_vip, &mp->translation.vip);
  mp->translation.ip_proto = ip_proto_encode (ct->ct_proto);
  mp->translation.lb_type = (vl_api_cnat_lb_type_t) ct->lb_type;

  path = mp->translation.paths;
  vec_foreach (trk, ct->ct_paths)
  {
    cnat_endpoint_encode (&trk->ct_ep[VLIB_TX], &path->dst_ep);
    cnat_endpoint_encode (&trk->ct_ep[VLIB_RX], &path->src_ep);
    path->flags = trk->ct_flags;
    path++;
  }

  vl_api_send_msg (ctx->rp, (u8 *) mp);

  return (WALK_CONTINUE);
}

static void
vl_api_cnat_translation_dump_t_handler (vl_api_cnat_translation_dump_t * mp)
{
  vl_api_registration_t *rp;

  rp = vl_api_client_index_to_registration (mp->client_index);
  if (rp == 0)
    return;

  cnat_dump_walk_ctx_t ctx = {
    .rp = rp,
    .context = mp->context,
  };

  cnat_translation_walk (cnat_translation_send_details, &ctx);
}

static walk_rc_t
cnat_session_send_details (const cnat_session_t * session, void *args)
{
  vl_api_cnat_session_details_t *mp;
  cnat_dump_walk_ctx_t *ctx;

  ctx = args;

  mp = vl_msg_api_alloc_zero (sizeof (*mp));
  mp->_vl_msg_id = ntohs (VL_API_CNAT_SESSION_DETAILS + cnat_base_msg_id);

  /* fill in the message */
  mp->context = ctx->context;

  cnat_5tuple_encode (&session->key.cs_5tuple, &mp->session.tuple);
  mp->session.ts_index = clib_host_to_net_u32 (session->value.cs_session_index);
  mp->session.flags = clib_host_to_net_u32 (session->value.cs_flags);

  vl_api_send_msg (ctx->rp, (u8 *) mp);

  return (WALK_CONTINUE);
}

static void
vl_api_cnat_session_dump_t_handler (vl_api_cnat_session_dump_t * mp)
{
  vl_api_registration_t *rp;

  rp = vl_api_client_index_to_registration (mp->client_index);
  if (rp == 0)
    return;

  cnat_dump_walk_ctx_t ctx = {
    .rp = rp,
    .context = mp->context,
  };

  cnat_session_walk (cnat_session_send_details, &ctx);
}

static void
vl_api_cnat_session_purge_t_handler (vl_api_cnat_session_purge_t * mp)
{
  vl_api_cnat_session_purge_reply_t *rmp;
  int rv;

  cnat_client_throttle_pool_process ();
  rv = cnat_session_purge ();
  rv |= cnat_translation_purge ();

  REPLY_MACRO (VL_API_CNAT_SESSION_PURGE_REPLY);
}

static void
vl_api_cnat_get_snat_addresses_t_handler (vl_api_cnat_get_snat_addresses_t
					  * mp)
{
  vl_api_cnat_get_snat_addresses_reply_t *rmp;
  cnat_snat_policy_entry_t *cpe = cnat_snat_policy_entry_get_default ();
  int rv = cpe ? 0 : VNET_API_ERROR_FEATURE_DISABLED;

  /* clang-format off */
  REPLY_MACRO2 (
    VL_API_CNAT_GET_SNAT_ADDRESSES_REPLY, ({
      if (cpe)
        {
	  ip6_address_encode (&ip_addr_v6 (&cpe->snat_ip6.ce_ip), rmp->snat_ip6);
	  ip4_address_encode (&ip_addr_v4 (&cpe->snat_ip4.ce_ip), rmp->snat_ip4);
	  rmp->sw_if_index = clib_host_to_net_u32 (cpe->snat_ip6.ce_sw_if_index);
	}
    }));
  /* clang-format on */
}

static void
vl_api_cnat_snat_addresses_dump_t_handler (vl_api_cnat_snat_addresses_dump_t *mp)
{
  cnat_snat_policy_main_t *cpm = &cnat_snat_policy_main;
  cnat_snat_policy_entry_t *cpe = 0;
  vl_api_registration_t *reg;

  u16 msg_id;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  msg_id = ntohs (VL_API_CNAT_SNAT_ADDRESSES_DETAILS + cnat_base_msg_id);

  pool_foreach (cpe, cpm->snat_policies_pool)
    {
    vl_api_cnat_snat_addresses_details_t *rmp;
    rmp = vl_msg_api_alloc (sizeof (*rmp));
    if (!rmp)
	break;

    rmp->_vl_msg_id = msg_id;
    rmp->context = mp->context;
    rmp->fwd_table_id4 =
      clib_host_to_net_u32 (fib_table_get_table_id (cpe->fwd_fib_index4, FIB_PROTOCOL_IP4));
    rmp->fwd_table_id6 =
      clib_host_to_net_u32 (fib_table_get_table_id (cpe->fwd_fib_index6, FIB_PROTOCOL_IP6));
    rmp->ret_table_id4 =
      clib_host_to_net_u32 (fib_table_get_table_id (cpe->ret_fib_index4, FIB_PROTOCOL_IP4));
    rmp->ret_table_id6 =
      clib_host_to_net_u32 (fib_table_get_table_id (cpe->ret_fib_index6, FIB_PROTOCOL_IP6));
    ip6_address_encode (&ip_addr_v6 (&cpe->snat_ip6.ce_ip), rmp->snat_ip6);
    ip4_address_encode (&ip_addr_v4 (&cpe->snat_ip4.ce_ip), rmp->snat_ip4);
    rmp->sw_if_index = clib_host_to_net_u32 (cpe->snat_ip6.ce_sw_if_index);
    vl_api_send_msg (reg, (u8 *) rmp);
    }
}

static void
vl_api_cnat_set_snat_addresses_t_handler (vl_api_cnat_set_snat_addresses_t *mp)
{
  vl_api_cnat_set_snat_addresses_reply_t *rmp;
  u32 sw_if_index = clib_net_to_host_u32 (mp->sw_if_index);
  ip4_address_t ip4;
  ip6_address_t ip6;
  int rv;

  ip4_address_decode (mp->snat_ip4, &ip4);
  ip6_address_decode (mp->snat_ip6, &ip6);

  rv = cnat_set_snat (CNAT_FIB_TABLE, CNAT_FIB_TABLE, &ip4, 32, &ip6, 128, sw_if_index,
		      CNAT_SNAT_POLICY_FLAG_NONE);

  REPLY_MACRO (VL_API_CNAT_SET_SNAT_ADDRESSES_REPLY);
}

static void
vl_api_cnat_set_snat_policy_t_handler (vl_api_cnat_set_snat_policy_t *mp)
{
  vl_api_cnat_set_snat_policy_reply_t *rmp;
  int rv = 0;
  cnat_snat_policy_type_t policy = (cnat_snat_policy_type_t) mp->policy;

  rv = cnat_set_snat_policy (policy);

  REPLY_MACRO (VL_API_CNAT_SET_SNAT_POLICY_REPLY);
}

static void
vl_api_cnat_snat_policy_add_del_exclude_pfx_t_handler (
  vl_api_cnat_snat_policy_add_del_exclude_pfx_t *mp)
{
  vl_api_cnat_snat_policy_add_del_exclude_pfx_reply_t *rmp;
  ip_prefix_t pfx;
  int rv;

  ip_prefix_decode2 (&mp->prefix, &pfx);
  if (mp->is_add)
    rv = cnat_snat_policy_add_pfx (&pfx);
  else
    rv = cnat_snat_policy_del_pfx (&pfx);

  REPLY_MACRO (VL_API_CNAT_SNAT_POLICY_ADD_DEL_EXCLUDE_PFX_REPLY);
}

static void
vl_api_cnat_snat_policy_add_del_if_t_handler (
  vl_api_cnat_snat_policy_add_del_if_t *mp)
{
  vl_api_cnat_snat_policy_add_del_if_reply_t *rmp;
  u32 sw_if_index = ntohl (mp->sw_if_index);
  int rv = 0;

  VALIDATE_SW_IF_INDEX (mp);

  cnat_snat_interface_map_type_t table =
    (cnat_snat_interface_map_type_t) mp->table;

  rv = cnat_snat_policy_add_del_if (sw_if_index, mp->is_add, table);

  BAD_SW_IF_INDEX_LABEL;

  REPLY_MACRO (VL_API_CNAT_SNAT_POLICY_ADD_DEL_IF_REPLY);
}

#include <cnat/cnat.api.c>

static clib_error_t *
cnat_api_init (vlib_main_t * vm)
{
  /* Ask for a correctly-sized block of API message decode slots */
  cnat_base_msg_id = setup_message_id_table ();

  return 0;
}

VLIB_INIT_FUNCTION (cnat_api_init);

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "CNat Translate",
};
