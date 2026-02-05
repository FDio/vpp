/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco Systems, Inc.
 */

#ifndef __included_gateway_h__
#define __included_gateway_h__

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>

#include <vppinfra/hash.h>
#include <vppinfra/error.h>
#include <vppinfra/elog.h>

#include <vppinfra/bihash_24_8.h>
#include <vppinfra/bihash_8_8.h>

#include <vppinfra/bihash_template.h>

#include <vnet/sfdp/sfdp.h>

#define foreach_gw_tenant_flag                                                \
  _ (OUTPUT_DATA_SET, "output-data-set", 0)                                   \
  _ (STATIC_MAC, "static-mac", 1)

typedef enum
{
#define _(a, b, c) GW_TENANT_F_##a = (1 << (c)),
  foreach_gw_tenant_flag
#undef _
} gw_tenant_flags_t;

typedef struct
{
  /* Here goes the geneve rewrite */
  session_version_t session_version;
  u16 encap_size;
  u8 encap_data[124];
} gw_geneve_output_data_t;
STATIC_ASSERT (sizeof (gw_geneve_output_data_t) == 128, "");

typedef struct
{
  u32 output_tenant_id;
  u32 flags;

  /* Geneve output spec for forward/reverse packets */
  ip4_address_t geneve_src_ip[SFDP_FLOW_F_B_N];
  ip4_address_t geneve_dst_ip[SFDP_FLOW_F_B_N];
  u16 geneve_src_port[SFDP_FLOW_F_B_N];
  u16 geneve_dst_port[SFDP_FLOW_F_B_N];
  mac_address_t src_mac[SFDP_FLOW_F_B_N];
  mac_address_t dst_mac[SFDP_FLOW_F_B_N];

} gw_tenant_t;

typedef struct
{
  /* pool of tenants */
  gw_tenant_t *tenants;
  gw_geneve_output_data_t *output; /* by flow_index */
  u16 msg_id_base;
} gw_main_t;

typedef struct
{
  int rv;
  clib_error_t *err;
  u32 sw_if_index;
  u8 enable_disable;
} gw_enable_disable_geneve_input_args_t;

typedef struct
{
  int rv;
  clib_error_t *err;
  sfdp_tenant_id_t tenant_id;
  ip4_address_t src_addr;
  ip4_address_t dst_addr;
  u16 src_port; /*network order*/
  u16 dst_port; /*network order*/
  u8 direction; /* 0 is forward, 1 is reverse */
  u8 static_mac;
  u32 output_tenant_id; /* ~0 means output on the same tenant as input */
  mac_address_t src_mac;
  mac_address_t dst_mac;
} gw_set_geneve_output_args_t;

extern gw_main_t gateway_main;

static_always_inline gw_tenant_t *
gw_tenant_at_index (gw_main_t *gm, u32 idx)
{
  return vec_elt_at_index (gm->tenants, idx);
}

void
gw_enable_disable_geneve_input (gw_enable_disable_geneve_input_args_t *args);
void gw_set_geneve_output (gw_set_geneve_output_args_t *args);

#define SFDP_GW_PLUGIN_BUILD_VER "1.0"

#endif /* __included_gateway_h__ */
