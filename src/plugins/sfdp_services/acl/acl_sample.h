/*
 * Copyright (c) 2024 Cisco and/or its affiliates.
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