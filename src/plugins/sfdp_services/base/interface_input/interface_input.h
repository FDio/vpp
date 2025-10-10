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
#ifndef __included_nat_h__
#define __included_nat_h__

#include <vlib/vlib.h>
#include <vnet/sfdp/sfdp.h>

typedef struct
{
  u16 *tenant_idx_by_sw_if_idx; /* vec */
  u16 msg_id_base;
} sfdp_interface_input_main_t;

extern sfdp_interface_input_main_t sfdp_interface_input_main;

clib_error_t *
sfdp_interface_input_set_tenant (sfdp_interface_input_main_t *nat,
				 u32 sw_if_index, u32 tenant_id, u8 unset);
#endif