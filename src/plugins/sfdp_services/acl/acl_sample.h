/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco Systems, Inc.
 */

#ifndef __included_acl_sample_h__
#define __included_acl_sample_h__

#include <vlib/vlib.h>
#include <vnet/sfdp/sfdp.h>
#include <acl/exports.h>

typedef struct
{
  u32 acl_user_id;
  u32 *lc_by_tenant_idx; /* vec */
} sfdp_acl_main_t;

clib_error_t *sfdp_acl_sample_tenant_set_acl (sfdp_acl_main_t *vam,
					      u64 tenant_id, u32 acl_index,
					      bool disable);

extern sfdp_acl_main_t sfdp_acl_main;
extern acl_plugin_methods_t acl_plugin;
#endif