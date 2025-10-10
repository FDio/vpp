/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco Systems, Inc.
 */

#include <vnet/sfdp/sfdp.h>

#include <sfdp_services/base/nat/nat.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vnet/ip/ip_types_api.h>

#include <vnet/format_fns.h>
#include <sfdp_services/base/nat/nat.api_enum.h>
#include <sfdp_services/base/nat/nat.api_types.h>

#define REPLY_MSG_ID_BASE nat->msg_id_base
#include <vlibapi/api_helper_macros.h>

static void
vl_api_sfdp_nat_set_external_interface_t_handler (
  vl_api_sfdp_nat_set_external_interface_t *mp)
{
  nat_main_t *nat = &nat_main;
  u32 sw_if_index = clib_net_to_host_u32 (mp->sw_if_index);
  u32 tenant_id = clib_net_to_host_u32 (mp->tenant_id);
  u8 unset = mp->is_disable;
  clib_error_t *err =
    nat_external_interface_set_tenant (nat, sw_if_index, tenant_id, unset);
  int rv = err ? -1 : 0;
  vl_api_sfdp_nat_set_external_interface_reply_t *rmp;
  REPLY_MACRO (VL_API_SFDP_NAT_SET_EXTERNAL_INTERFACE_REPLY);
}

static void
vl_api_sfdp_nat_alloc_pool_add_del_t_handler (
  vl_api_sfdp_nat_alloc_pool_add_del_t *mp)
{
  nat_main_t *nat = &nat_main;
  u32 alloc_pool_id = clib_net_to_host_u32 (mp->alloc_pool_id);
  u8 is_del = mp->is_del;
  uword n_addr = clib_net_to_host_u32 (mp->n_addr);
  ip4_address_t *addrs = 0;
  clib_error_t *err;
  int rv;
  vl_api_sfdp_nat_alloc_pool_add_del_reply_t *rmp;
  vec_resize (addrs, n_addr);
  for (int i = 0; i < n_addr; i++)
    ip4_address_decode (mp->addr[i], addrs + i);

  err = nat_alloc_pool_add_del (nat, alloc_pool_id, is_del, addrs);
  vec_free (addrs);
  rv = err ? -1 : 0;
  REPLY_MACRO (VL_API_SFDP_NAT_ALLOC_POOL_ADD_DEL_REPLY);
}

static void
vl_api_sfdp_nat_snat_set_unset_t_handler (vl_api_sfdp_nat_snat_set_unset_t *mp)
{
  nat_main_t *nat = &nat_main;
  u32 tenant_id = clib_net_to_host_u32 (mp->tenant_id);
  u32 outside_tenant_id = clib_net_to_host_u32 (mp->outside_tenant_id);
  u32 table_id = clib_net_to_host_u32 (mp->table_id);
  u32 alloc_pool_id = clib_net_to_host_u32 (mp->alloc_pool_id);
  u8 unset = mp->is_disable;
  clib_error_t *err;
  int rv;
  vl_api_sfdp_nat_alloc_pool_add_del_reply_t *rmp;

  err = nat_tenant_set_snat (nat, tenant_id, outside_tenant_id, table_id,
			     alloc_pool_id, unset);
  rv = err ? -1 : 0;
  REPLY_MACRO (VL_API_SFDP_NAT_SNAT_SET_UNSET_REPLY);
}

#include <sfdp_services/base/nat/nat.api.c>
static clib_error_t *
sfdp_nat_api_hookup (vlib_main_t *vm)
{
  nat_main_t *nat = &nat_main;
  nat->msg_id_base = setup_message_id_table ();
  return 0;
}
VLIB_API_INIT_FUNCTION (sfdp_nat_api_hookup);
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
