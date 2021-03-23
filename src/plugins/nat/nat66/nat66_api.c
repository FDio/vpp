/*
 * Copyright (c) 2020 Cisco and/or its affiliates.
 *
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

#include <vlibmemory/api.h>
#include <nat/nat66/nat66.h>
#include <nat/nat66/nat66.api_enum.h>
#include <nat/nat66/nat66.api_types.h>
#include <vnet/fib/fib_table.h>

#define REPLY_MSG_ID_BASE nm->msg_id_base
#include <vlibapi/api_helper_macros.h>

static void
vl_api_nat66_plugin_enable_disable_t_handler (
  vl_api_nat66_plugin_enable_disable_t *mp)
{
  nat66_main_t *nm = &nat66_main;
  vl_api_nat66_plugin_enable_disable_reply_t *rmp;
  int rv = 0;

  if (mp->enable)
    {
      rv = nat66_plugin_enable (ntohl (mp->outside_vrf));
    }
  else
    rv = nat66_plugin_disable ();

  REPLY_MACRO (VL_API_NAT66_PLUGIN_ENABLE_DISABLE_REPLY);
}

static void
vl_api_nat66_add_del_interface_t_handler (vl_api_nat66_add_del_interface_t *
					  mp)
{
  nat66_main_t *nm = &nat66_main;
  vl_api_nat66_add_del_interface_reply_t *rmp;
  int rv = 0;

  VALIDATE_SW_IF_INDEX (mp);

  rv =
    nat66_interface_add_del (ntohl (mp->sw_if_index),
			     mp->flags & NAT_IS_INSIDE, mp->is_add);

  BAD_SW_IF_INDEX_LABEL;

  REPLY_MACRO (VL_API_NAT66_ADD_DEL_INTERFACE_REPLY);
}

static void
  vl_api_nat66_add_del_static_mapping_t_handler
  (vl_api_nat66_add_del_static_mapping_t * mp)
{
  nat66_main_t *nm = &nat66_main;
  vl_api_nat66_add_del_static_mapping_reply_t *rmp;
  ip6_address_t l_addr, e_addr;
  int rv = 0;

  memcpy (&l_addr.as_u8, mp->local_ip_address, 16);
  memcpy (&e_addr.as_u8, mp->external_ip_address, 16);

  rv =
    nat66_static_mapping_add_del (&l_addr, &e_addr,
				  clib_net_to_host_u32 (mp->vrf_id),
				  mp->is_add);

  REPLY_MACRO (VL_API_NAT66_ADD_DEL_STATIC_MAPPING_REPLY);
}

typedef struct nat66_api_walk_ctx_t_
{
  vl_api_registration_t *rp;
  u32 context;
} nat66_api_walk_ctx_t;

static int
nat66_api_interface_walk (nat66_interface_t * i, void *arg)
{
  vl_api_nat66_interface_details_t *rmp;
  nat66_main_t *nm = &nat66_main;
  nat66_api_walk_ctx_t *ctx = arg;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  clib_memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (VL_API_NAT66_INTERFACE_DETAILS + nm->msg_id_base);
  rmp->sw_if_index = ntohl (i->sw_if_index);
  if (nat66_interface_is_inside (i))
    rmp->flags |= NAT_IS_INSIDE;
  rmp->context = ctx->context;

  vl_api_send_msg (ctx->rp, (u8 *) rmp);

  return 0;
}

static void
vl_api_nat66_interface_dump_t_handler (vl_api_nat66_interface_dump_t * mp)
{
  vl_api_registration_t *rp;
  nat66_main_t *nm = &nat66_main;

  if (PREDICT_FALSE (!nm->enabled))
    return;

  rp = vl_api_client_index_to_registration (mp->client_index);
  if (rp == 0)
    return;

  nat66_api_walk_ctx_t ctx = {
    .rp = rp,
    .context = mp->context,
  };

  nat66_interfaces_walk (nat66_api_interface_walk, &ctx);
}

static int
nat66_api_static_mapping_walk (nat66_static_mapping_t * m, void *arg)
{
  vl_api_nat66_static_mapping_details_t *rmp;
  nat66_main_t *nm = &nat66_main;
  nat66_api_walk_ctx_t *ctx = arg;
  fib_table_t *fib;
  vlib_counter_t vc;

  fib = fib_table_get (m->fib_index, FIB_PROTOCOL_IP6);
  if (!fib)
    return -1;

  vlib_get_combined_counter (&nm->session_counters, m - nm->sm, &vc);

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  clib_memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id =
    ntohs (VL_API_NAT66_STATIC_MAPPING_DETAILS + nm->msg_id_base);
  clib_memcpy (rmp->local_ip_address, &m->l_addr, 16);
  clib_memcpy (rmp->external_ip_address, &m->e_addr, 16);
  rmp->vrf_id = ntohl (fib->ft_table_id);
  rmp->total_bytes = clib_host_to_net_u64 (vc.bytes);
  rmp->total_pkts = clib_host_to_net_u64 (vc.packets);
  rmp->context = ctx->context;

  vl_api_send_msg (ctx->rp, (u8 *) rmp);

  return 0;
}

static void
vl_api_nat66_static_mapping_dump_t_handler (vl_api_nat66_static_mapping_dump_t
					    * mp)
{
  vl_api_registration_t *rp;
  nat66_main_t *nm = &nat66_main;

  if (PREDICT_FALSE (!nm->enabled))
    return;

  rp = vl_api_client_index_to_registration (mp->client_index);
  if (rp == 0)
    return;

  nat66_api_walk_ctx_t ctx = {
    .rp = rp,
    .context = mp->context,
  };

  nat66_static_mappings_walk (nat66_api_static_mapping_walk, &ctx);
}

/* API definitions */
#include <vnet/format_fns.h>
#include <nat/nat66/nat66.api.c>

/* Set up the API message handling tables */
clib_error_t *
nat66_plugin_api_hookup (vlib_main_t * vm)
{
  nat66_main_t *nm = &nat66_main;
  nm->msg_id_base = setup_message_id_table ();
  return 0;
}
