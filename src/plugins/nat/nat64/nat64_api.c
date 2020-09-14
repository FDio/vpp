/*
 * Copyright (c) 2020 Cisco and/or its affiliates.
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

#include <vnet/ip/ip_types_api.h>
#include <vlibmemory/api.h>
#include <nat/nat64/nat64.h>
#include <nat/nat64/nat64.api_enum.h>
#include <nat/nat64/nat64.api_types.h>
#include <vnet/fib/fib_table.h>
#include <vnet/ip/ip.h>

#define REPLY_MSG_ID_BASE nm->msg_id_base
#include <vlibapi/api_helper_macros.h>

static void
  vl_api_nat64_plugin_enable_disable_t_handler
  (vl_api_nat64_plugin_enable_disable_t * mp)
{
  nat64_main_t *nm = &nat64_main;
  vl_api_nat64_plugin_enable_disable_reply_t *rmp;
  nat64_config_t c = { 0 };
  int rv = 0;
  if (mp->enable)
    {
      c.bib_buckets = ntohl (mp->bib_buckets);
      c.bib_memory_size = ntohl (mp->bib_memory_size);
      c.st_buckets = ntohl (mp->st_buckets);
      c.st_memory_size = ntohl (mp->st_memory_size);
      rv = nat64_plugin_enable (c);
    }
  else
    {
      rv = nat64_plugin_disable ();
    }
  REPLY_MACRO (VL_API_NAT64_PLUGIN_ENABLE_DISABLE_REPLY);
}

static void
vl_api_nat64_set_timeouts_t_handler (vl_api_nat64_set_timeouts_t * mp)
{
  nat64_main_t *nm = &nat64_main;
  vl_api_nat64_set_timeouts_reply_t *rmp;
  int rv = 0;

  nm->udp_timeout = ntohl (mp->udp);
  nm->tcp_est_timeout = ntohl (mp->tcp_established);
  nm->tcp_trans_timeout = ntohl (mp->tcp_transitory);
  nm->icmp_timeout = ntohl (mp->icmp);

  REPLY_MACRO (VL_API_NAT64_SET_TIMEOUTS_REPLY);
}

static void
vl_api_nat64_get_timeouts_t_handler (vl_api_nat64_get_timeouts_t * mp)
{
  nat64_main_t *nm = &nat64_main;
  vl_api_nat64_get_timeouts_reply_t *rmp;
  int rv = 0;

  /* *INDENT-OFF* */
  REPLY_MACRO2 (VL_API_NAT64_GET_TIMEOUTS_REPLY,
  ({
    rmp->udp = htonl (nm->udp_timeout);
    rmp->tcp_established = htonl (nm->tcp_est_timeout);
    rmp->tcp_transitory = htonl (nm->tcp_trans_timeout);
    rmp->icmp = htonl (nm->icmp_timeout);
  }))
  /* *INDENT-ON* */
}

static void
  vl_api_nat64_add_del_pool_addr_range_t_handler
  (vl_api_nat64_add_del_pool_addr_range_t * mp)
{
  nat64_main_t *nm = &nat64_main;
  vl_api_nat64_add_del_pool_addr_range_reply_t *rmp;
  int rv = 0;
  ip4_address_t this_addr;
  u32 start_host_order, end_host_order;
  u32 vrf_id;
  int i, count;
  u32 *tmp;

  tmp = (u32 *) mp->start_addr;
  start_host_order = clib_host_to_net_u32 (tmp[0]);
  tmp = (u32 *) mp->end_addr;
  end_host_order = clib_host_to_net_u32 (tmp[0]);

  count = (end_host_order - start_host_order) + 1;

  vrf_id = clib_host_to_net_u32 (mp->vrf_id);

  memcpy (&this_addr.as_u8, mp->start_addr, 4);

  for (i = 0; i < count; i++)
    {
      if ((rv = nat64_add_del_pool_addr (0, &this_addr, vrf_id, mp->is_add)))
	goto send_reply;

      increment_v4_address (&this_addr);
    }

send_reply:
  REPLY_MACRO (VL_API_NAT64_ADD_DEL_POOL_ADDR_RANGE_REPLY);
}

typedef struct nat64_api_walk_ctx_t_
{
  vl_api_registration_t *reg;
  u32 context;
  nat64_db_t *db;
} nat64_api_walk_ctx_t;

static int
nat64_api_pool_walk (nat64_address_t * a, void *arg)
{
  nat64_main_t *nm = &nat64_main;
  vl_api_nat64_pool_addr_details_t *rmp;
  nat64_api_walk_ctx_t *ctx = arg;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  clib_memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (VL_API_NAT64_POOL_ADDR_DETAILS + nm->msg_id_base);
  clib_memcpy (rmp->address, &(a->addr), 4);
  if (a->fib_index != ~0)
    {
      fib_table_t *fib = fib_table_get (a->fib_index, FIB_PROTOCOL_IP6);
      if (!fib)
	return -1;
      rmp->vrf_id = ntohl (fib->ft_table_id);
    }
  else
    rmp->vrf_id = ~0;
  rmp->context = ctx->context;

  vl_api_send_msg (ctx->reg, (u8 *) rmp);

  return 0;
}

static void
vl_api_nat64_pool_addr_dump_t_handler (vl_api_nat64_pool_addr_dump_t * mp)
{
  vl_api_registration_t *reg;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  nat64_api_walk_ctx_t ctx = {
    .reg = reg,
    .context = mp->context,
  };

  nat64_pool_addr_walk (nat64_api_pool_walk, &ctx);
}

static void
vl_api_nat64_add_del_interface_t_handler (vl_api_nat64_add_del_interface_t *
					  mp)
{
  nat64_main_t *nm = &nat64_main;
  vl_api_nat64_add_del_interface_reply_t *rmp;
  int rv = 0;

  VALIDATE_SW_IF_INDEX (mp);

  rv =
    nat64_interface_add_del (ntohl (mp->sw_if_index),
			     mp->flags & NAT_API_IS_INSIDE, mp->is_add);

  BAD_SW_IF_INDEX_LABEL;

  REPLY_MACRO (VL_API_NAT64_ADD_DEL_INTERFACE_REPLY);
}

static int
nat64_api_interface_walk (nat64_interface_t * i, void *arg)
{
  nat64_main_t *nm = &nat64_main;
  vl_api_nat64_interface_details_t *rmp;
  nat64_api_walk_ctx_t *ctx = arg;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  clib_memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (VL_API_NAT64_INTERFACE_DETAILS + nm->msg_id_base);
  rmp->sw_if_index = ntohl (i->sw_if_index);

  if (nat64_interface_is_inside (i))
    rmp->flags |= NAT_API_IS_INSIDE;
  if (nat64_interface_is_outside (i))
    rmp->flags |= NAT_API_IS_OUTSIDE;

  rmp->context = ctx->context;

  vl_api_send_msg (ctx->reg, (u8 *) rmp);

  return 0;
}

static void
vl_api_nat64_interface_dump_t_handler (vl_api_nat64_interface_dump_t * mp)
{
  vl_api_registration_t *reg;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  nat64_api_walk_ctx_t ctx = {
    .reg = reg,
    .context = mp->context,
  };

  nat64_interfaces_walk (nat64_api_interface_walk, &ctx);
}

static void
  vl_api_nat64_add_del_static_bib_t_handler
  (vl_api_nat64_add_del_static_bib_t * mp)
{
  nat64_main_t *nm = &nat64_main;
  vl_api_nat64_add_del_static_bib_reply_t *rmp;
  ip6_address_t in_addr;
  ip4_address_t out_addr;
  int rv = 0;

  memcpy (&in_addr.as_u8, mp->i_addr, 16);
  memcpy (&out_addr.as_u8, mp->o_addr, 4);

  rv =
    nat64_add_del_static_bib_entry (&in_addr, &out_addr,
				    clib_net_to_host_u16 (mp->i_port),
				    clib_net_to_host_u16 (mp->o_port),
				    mp->proto,
				    clib_net_to_host_u32 (mp->vrf_id),
				    mp->is_add);

  REPLY_MACRO (VL_API_NAT64_ADD_DEL_STATIC_BIB_REPLY);
}

static int
nat64_api_bib_walk (nat64_db_bib_entry_t * bibe, void *arg)
{
  nat64_main_t *nm = &nat64_main;
  vl_api_nat64_bib_details_t *rmp;
  nat64_api_walk_ctx_t *ctx = arg;
  fib_table_t *fib;

  fib = fib_table_get (bibe->fib_index, FIB_PROTOCOL_IP6);
  if (!fib)
    return -1;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  clib_memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (VL_API_NAT64_BIB_DETAILS + nm->msg_id_base);
  rmp->context = ctx->context;
  clib_memcpy (rmp->i_addr, &(bibe->in_addr), 16);
  clib_memcpy (rmp->o_addr, &(bibe->out_addr), 4);
  rmp->i_port = bibe->in_port;
  rmp->o_port = bibe->out_port;
  rmp->vrf_id = ntohl (fib->ft_table_id);
  rmp->proto = bibe->proto;
  if (bibe->is_static)
    rmp->flags |= NAT_API_IS_STATIC;
  rmp->ses_num = ntohl (bibe->ses_num);

  vl_api_send_msg (ctx->reg, (u8 *) rmp);

  return 0;
}

static void
vl_api_nat64_bib_dump_t_handler (vl_api_nat64_bib_dump_t * mp)
{
  nat64_main_t *nm = &nat64_main;
  vl_api_registration_t *reg;
  nat64_db_t *db;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  nat64_api_walk_ctx_t ctx = {
    .reg = reg,
    .context = mp->context,
  };

  /* *INDENT-OFF* */
  vec_foreach (db, nm->db)
    nat64_db_bib_walk (db, mp->proto, nat64_api_bib_walk, &ctx);
  /* *INDENT-ON* */
}

static int
nat64_api_st_walk (nat64_db_st_entry_t * ste, void *arg)
{
  nat64_main_t *nm = &nat64_main;
  vl_api_nat64_st_details_t *rmp;
  nat64_api_walk_ctx_t *ctx = arg;
  nat64_db_bib_entry_t *bibe;
  fib_table_t *fib;

  bibe = nat64_db_bib_entry_by_index (ctx->db, ste->proto, ste->bibe_index);
  if (!bibe)
    return -1;

  fib = fib_table_get (bibe->fib_index, FIB_PROTOCOL_IP6);
  if (!fib)
    return -1;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  clib_memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (VL_API_NAT64_ST_DETAILS + nm->msg_id_base);
  rmp->context = ctx->context;
  clib_memcpy (rmp->il_addr, &(bibe->in_addr), 16);
  clib_memcpy (rmp->ol_addr, &(bibe->out_addr), 4);
  rmp->il_port = bibe->in_port;
  rmp->ol_port = bibe->out_port;
  clib_memcpy (rmp->ir_addr, &(ste->in_r_addr), 16);
  clib_memcpy (rmp->or_addr, &(ste->out_r_addr), 4);
  rmp->il_port = ste->r_port;
  rmp->vrf_id = ntohl (fib->ft_table_id);
  rmp->proto = ste->proto;

  vl_api_send_msg (ctx->reg, (u8 *) rmp);

  return 0;
}

static void
vl_api_nat64_st_dump_t_handler (vl_api_nat64_st_dump_t * mp)
{
  nat64_main_t *nm = &nat64_main;
  vl_api_registration_t *reg;
  nat64_db_t *db;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  nat64_api_walk_ctx_t ctx = {
    .reg = reg,
    .context = mp->context,
  };

  /* *INDENT-OFF* */
  vec_foreach (db, nm->db)
    {
      ctx.db = db;
      nat64_db_st_walk (db, mp->proto, nat64_api_st_walk, &ctx);
    }
  /* *INDENT-ON* */
}

static void
vl_api_nat64_add_del_prefix_t_handler (vl_api_nat64_add_del_prefix_t * mp)
{
  nat64_main_t *nm = &nat64_main;
  vl_api_nat64_add_del_prefix_reply_t *rmp;
  ip6_address_t prefix;
  int rv = 0;

  memcpy (&prefix.as_u8, mp->prefix.address, 16);

  rv =
    nat64_add_del_prefix (&prefix, mp->prefix.len,
			  clib_net_to_host_u32 (mp->vrf_id), mp->is_add);
  REPLY_MACRO (VL_API_NAT64_ADD_DEL_PREFIX_REPLY);
}

static int
nat64_api_prefix_walk (nat64_prefix_t * p, void *arg)
{
  nat64_main_t *nm = &nat64_main;
  vl_api_nat64_prefix_details_t *rmp;
  nat64_api_walk_ctx_t *ctx = arg;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  clib_memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (VL_API_NAT64_PREFIX_DETAILS + nm->msg_id_base);
  clib_memcpy (rmp->prefix.address, &(p->prefix), 16);
  rmp->prefix.len = p->plen;
  rmp->vrf_id = ntohl (p->vrf_id);
  rmp->context = ctx->context;

  vl_api_send_msg (ctx->reg, (u8 *) rmp);

  return 0;
}

static void
vl_api_nat64_prefix_dump_t_handler (vl_api_nat64_prefix_dump_t * mp)
{
  vl_api_registration_t *reg;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  nat64_api_walk_ctx_t ctx = {
    .reg = reg,
    .context = mp->context,
  };

  nat64_prefix_walk (nat64_api_prefix_walk, &ctx);
}

static void
  vl_api_nat64_add_del_interface_addr_t_handler
  (vl_api_nat64_add_del_interface_addr_t * mp)
{
  nat64_main_t *nm = &nat64_main;
  vl_api_nat64_add_del_interface_addr_reply_t *rmp;
  u32 sw_if_index = ntohl (mp->sw_if_index);
  int rv = 0;

  VALIDATE_SW_IF_INDEX (mp);

  rv = nat64_add_interface_address (sw_if_index, mp->is_add);

  BAD_SW_IF_INDEX_LABEL;

  REPLY_MACRO (VL_API_NAT64_ADD_DEL_INTERFACE_ADDR_REPLY);
}

/* API definitions */
#include <vnet/format_fns.h>
#include <nat/nat64/nat64.api.c>

/* Set up the API message handling tables */
clib_error_t *
nat64_api_hookup (vlib_main_t * vm)
{
  nat64_main_t *nm = &nat64_main;
  nm->msg_id_base = setup_message_id_table ();
  return 0;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
