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
#include <vpp/app/version.h>

#include <gbp/gbp.h>

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
  _(GBP_ENDPOINT_ADD_DEL, gbp_endpoint_add_del)             \
  _(GBP_ENDPOINT_DUMP, gbp_endpoint_dump)                   \
  _(GBP_SUBNET_ADD_DEL, gbp_subnet_add_del)                 \
  _(GBP_SUBNET_DUMP, gbp_subnet_dump)                       \
  _(GBP_ENDPOINT_GROUP_ADD_DEL, gbp_endpoint_group_add_del) \
  _(GBP_ENDPOINT_GROUP_DUMP, gbp_endpoint_group_dump)       \
  _(GBP_RECIRC_ADD_DEL, gbp_recirc_add_del)                 \
  _(GBP_RECIRC_DUMP, gbp_recirc_dump)                       \
  _(GBP_CONTRACT_ADD_DEL, gbp_contract_add_del)             \
  _(GBP_CONTRACT_DUMP, gbp_contract_dump)

gbp_main_t gbp_main;

static u16 msg_id_base;

#define GBP_MSG_BASE msg_id_base

static void
vl_api_gbp_endpoint_add_del_t_handler (vl_api_gbp_endpoint_add_del_t * mp)
{
  vl_api_gbp_endpoint_add_del_reply_t *rmp;
  ip46_address_t ip = { };
  u32 sw_if_index;
  int rv = 0;

  sw_if_index = ntohl (mp->endpoint.sw_if_index);
  if (!vnet_sw_if_index_is_api_valid (sw_if_index))
    goto bad_sw_if_index;

  if (mp->endpoint.is_ip6)
    {
      clib_memcpy (&ip.ip6, mp->endpoint.address, sizeof (ip.ip6));
    }
  else
    {
      clib_memcpy (&ip.ip4, mp->endpoint.address, sizeof (ip.ip4));
    }

  if (mp->is_add)
    {
      rv =
	gbp_endpoint_update (sw_if_index, &ip, ntohl (mp->endpoint.epg_id));
    }
  else
    {
      gbp_endpoint_delete (sw_if_index, &ip);
    }

  BAD_SW_IF_INDEX_LABEL;

  REPLY_MACRO (VL_API_GBP_ENDPOINT_ADD_DEL_REPLY + GBP_MSG_BASE);
}

typedef struct gbp_walk_ctx_t_
{
  vl_api_registration_t *reg;
  u32 context;
} gbp_walk_ctx_t;

static int
gbp_endpoint_send_details (gbp_endpoint_t * gbpe, void *args)
{
  vl_api_gbp_endpoint_details_t *mp;
  gbp_walk_ctx_t *ctx;

  ctx = args;
  mp = vl_msg_api_alloc (sizeof (*mp));
  if (!mp)
    return 1;

  memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = ntohs (VL_API_GBP_ENDPOINT_DETAILS + GBP_MSG_BASE);
  mp->context = ctx->context;

  mp->endpoint.sw_if_index = ntohl (gbpe->ge_key->gek_sw_if_index);
  mp->endpoint.is_ip6 = !ip46_address_is_ip4 (&gbpe->ge_key->gek_ip);
  if (mp->endpoint.is_ip6)
    clib_memcpy (&mp->endpoint.address,
		 &gbpe->ge_key->gek_ip.ip6,
		 sizeof (gbpe->ge_key->gek_ip.ip6));
  else
    clib_memcpy (&mp->endpoint.address,
		 &gbpe->ge_key->gek_ip.ip4,
		 sizeof (gbpe->ge_key->gek_ip.ip4));

  mp->endpoint.epg_id = ntohl (gbpe->ge_epg_id);

  vl_api_send_msg (ctx->reg, (u8 *) mp);

  return (1);
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
  vl_api_gbp_endpoint_group_add_del_t_handler
  (vl_api_gbp_endpoint_group_add_del_t * mp)
{
  vl_api_gbp_endpoint_group_add_del_reply_t *rmp;
  u32 uplink_sw_if_index;
  int rv = 0;

  uplink_sw_if_index = ntohl (mp->epg.uplink_sw_if_index);
  if (!vnet_sw_if_index_is_api_valid (uplink_sw_if_index))
    goto bad_sw_if_index;

  if (mp->is_add)
    {
      rv = gbp_endpoint_group_add (ntohl (mp->epg.epg_id),
				   ntohl (mp->epg.bd_id),
				   ntohl (mp->epg.ip4_table_id),
				   ntohl (mp->epg.ip6_table_id),
				   uplink_sw_if_index);
    }
  else
    {
      gbp_endpoint_group_delete (ntohl (mp->epg.epg_id));
    }

  BAD_SW_IF_INDEX_LABEL;

  REPLY_MACRO (VL_API_GBP_ENDPOINT_GROUP_ADD_DEL_REPLY + GBP_MSG_BASE);
}

static void
vl_api_gbp_subnet_add_del_t_handler (vl_api_gbp_subnet_add_del_t * mp)
{
  vl_api_gbp_subnet_add_del_reply_t *rmp;
  int rv = 0;
  fib_prefix_t pfx = {
    .fp_len = mp->subnet.address_length,
    .fp_proto = (mp->subnet.is_ip6 ? FIB_PROTOCOL_IP6 : FIB_PROTOCOL_IP4),
  };

  if (mp->subnet.is_ip6)
    clib_memcpy (&pfx.fp_addr.ip6, mp->subnet.address,
		 sizeof (pfx.fp_addr.ip6));
  else
    clib_memcpy (&pfx.fp_addr.ip4, mp->subnet.address,
		 sizeof (pfx.fp_addr.ip4));

  rv = gbp_subnet_add_del (ntohl (mp->subnet.table_id),
			   &pfx,
			   ntohl (mp->subnet.sw_if_index),
			   ntohl (mp->subnet.epg_id),
			   mp->is_add, mp->subnet.is_internal);

  REPLY_MACRO (VL_API_GBP_SUBNET_ADD_DEL_REPLY + GBP_MSG_BASE);
}

static int
gbp_subnet_send_details (u32 table_id,
			 const fib_prefix_t * pfx,
			 u32 sw_if_index,
			 epg_id_t epg, u8 is_internal, void *args)
{
  vl_api_gbp_subnet_details_t *mp;
  gbp_walk_ctx_t *ctx;

  ctx = args;
  mp = vl_msg_api_alloc (sizeof (*mp));
  if (!mp)
    return 1;

  memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = ntohs (VL_API_GBP_SUBNET_DETAILS + GBP_MSG_BASE);
  mp->context = ctx->context;

  mp->subnet.is_internal = is_internal;
  mp->subnet.sw_if_index = ntohl (sw_if_index);
  mp->subnet.epg_id = ntohl (epg);
  mp->subnet.is_ip6 = (pfx->fp_proto == FIB_PROTOCOL_IP6);
  mp->subnet.address_length = pfx->fp_len;
  mp->subnet.table_id = ntohl (table_id);
  if (mp->subnet.is_ip6)
    clib_memcpy (&mp->subnet.address,
		 &pfx->fp_addr.ip6, sizeof (pfx->fp_addr.ip6));
  else
    clib_memcpy (&mp->subnet.address,
		 &pfx->fp_addr.ip4, sizeof (pfx->fp_addr.ip4));


  vl_api_send_msg (ctx->reg, (u8 *) mp);

  return (1);
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
gbp_endpoint_group_send_details (gbp_endpoint_group_t * gepg, void *args)
{
  vl_api_gbp_endpoint_group_details_t *mp;
  gbp_walk_ctx_t *ctx;

  ctx = args;
  mp = vl_msg_api_alloc (sizeof (*mp));
  if (!mp)
    return 1;

  memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = ntohs (VL_API_GBP_ENDPOINT_GROUP_DETAILS + GBP_MSG_BASE);
  mp->context = ctx->context;

  mp->epg.uplink_sw_if_index = ntohl (gepg->gepg_uplink_sw_if_index);
  mp->epg.epg_id = ntohl (gepg->gepg_id);
  mp->epg.bd_id = ntohl (gepg->gepg_bd);
  mp->epg.ip4_table_id = ntohl (gepg->gepg_rd[FIB_PROTOCOL_IP4]);
  mp->epg.ip6_table_id = ntohl (gepg->gepg_rd[FIB_PROTOCOL_IP6]);

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
		    ntohl (mp->recirc.epg_id), mp->recirc.is_ext);
  else
    gbp_recirc_delete (sw_if_index);

  BAD_SW_IF_INDEX_LABEL;

  REPLY_MACRO (VL_API_GBP_RECIRC_ADD_DEL_REPLY + GBP_MSG_BASE);
}

static int
gbp_recirc_send_details (gbp_recirc_t * gr, void *args)
{
  vl_api_gbp_recirc_details_t *mp;
  gbp_walk_ctx_t *ctx;

  ctx = args;
  mp = vl_msg_api_alloc (sizeof (*mp));
  if (!mp)
    return 1;

  memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = ntohs (VL_API_GBP_RECIRC_DETAILS + GBP_MSG_BASE);
  mp->context = ctx->context;

  mp->recirc.epg_id = ntohl (gr->gr_epg);
  mp->recirc.sw_if_index = ntohl (gr->gr_sw_if_index);
  mp->recirc.is_ext = ntohl (gr->gr_is_ext);

  vl_api_send_msg (ctx->reg, (u8 *) mp);

  return (1);
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
vl_api_gbp_contract_add_del_t_handler (vl_api_gbp_contract_add_del_t * mp)
{
  vl_api_gbp_contract_add_del_reply_t *rmp;
  int rv = 0;

  if (mp->is_add)
    gbp_contract_update (ntohl (mp->contract.src_epg),
			 ntohl (mp->contract.dst_epg),
			 ntohl (mp->contract.acl_index));
  else
    gbp_contract_delete (ntohl (mp->contract.src_epg),
			 ntohl (mp->contract.dst_epg));

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

  memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = ntohs (VL_API_GBP_CONTRACT_DETAILS + GBP_MSG_BASE);
  mp->context = ctx->context;

  mp->contract.src_epg = ntohl (gbpc->gc_key.gck_src);
  mp->contract.dst_epg = ntohl (gbpc->gc_key.gck_dst);
  mp->contract.acl_index = ntohl (gbpc->gc_value.gc_acl_index);

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

/*
 * gbp_api_hookup
 * Add vpe's API message handlers to the table.
 * vlib has alread mapped shared memory and
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
