/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco Systems, Inc.
 */

#define _GNU_SOURCE
#include <sys/mman.h>

#include <sfdp_services/geneve/gateway.h>

#include <vnet/plugin/plugin.h>
#include <vnet/vnet.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>

gw_main_t gateway_main;

static void
gateway_init_main_if_needed (gw_main_t *gm)
{
  static u32 done = 0;
  sfdp_main_t *sfdp = &sfdp_main;

  if (done)
    return;

  vec_validate (gm->output, sfdp_num_sessions () << 1);
  vec_validate (gm->tenants, 1ULL << sfdp->log2_tenants);

  done = 1;
}

static clib_error_t *
gateway_init (vlib_main_t *vm)
{
  return 0;
}

void
gw_enable_disable_geneve_input (gw_enable_disable_geneve_input_args_t *args)
{
  gw_main_t *gm = &gateway_main;
  int rv = 0;
  gateway_init_main_if_needed (gm);
  rv = vnet_feature_enable_disable ("ip4-unicast", "sfdp-geneve-input",
				    args->sw_if_index, args->enable_disable, 0,
				    0);
  args->rv = rv;
  if (rv)
    args->err = clib_error_return (
      0, "Failed vnet_feature_enable_disable with error %d : %U", rv,
      format_vnet_api_errno, rv);
  else
    args->err = 0;
}

void
gw_set_geneve_output (gw_set_geneve_output_args_t *args)
{
  gw_main_t *gm = &gateway_main;
  sfdp_main_t *sfdp = &sfdp_main;
  sfdp_tenant_t *vt;
  gw_tenant_t *gt;
  clib_bihash_kv_8_8_t kv = {};
  u8 dir = !!args->direction;
  kv.key = args->tenant_id;
  if (clib_bihash_search_inline_8_8 (&sfdp->tenant_idx_by_id, &kv))
    {
      args->rv = -1;
      args->err =
	clib_error_return (0, "tenant-id %d not found", args->tenant_id);
      return;
    }
  vt = sfdp_tenant_at_index (sfdp, kv.value);
  gt = gw_tenant_at_index (gm, kv.value);

  /* Caching tenant id in gt */
  gt->output_tenant_id =
    args->output_tenant_id == ~0 ? vt->tenant_id : args->output_tenant_id;
  gt->flags = GW_TENANT_F_OUTPUT_DATA_SET;
  gt->geneve_src_ip[dir] = args->src_addr;
  gt->geneve_dst_ip[dir] = args->dst_addr;
  gt->geneve_src_port[dir] = args->src_port;
  gt->geneve_dst_port[dir] = args->dst_port;
  if (args->static_mac)
    {
      gt->flags |= GW_TENANT_F_STATIC_MAC;
      gt->src_mac[dir] = args->src_mac;
      gt->dst_mac[dir] = args->dst_mac;
    }
  args->rv = 0;
  args->err = 0;
}

VLIB_INIT_FUNCTION (gateway_init);
VLIB_PLUGIN_REGISTER () = {
  .version = SFDP_GW_PLUGIN_BUILD_VER,
  .description = "sfdp Gateway Plugin",
};