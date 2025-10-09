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
#ifndef __included_lookup_reass_h__
#define __included_lookup_reass_h__

#include <vlib/vlib.h>
typedef struct
{
  /* Shallow Virtual Reassembly */
  u16 ip4_sv_reass_next_index;
  u16 ip6_sv_reass_next_index;

  /* Full Reassembly */
  u16 ip4_full_reass_next_index;
  u16 ip6_full_reass_next_index;

  /* Full Reassembly error next index */
  u16 ip4_full_reass_err_next_index;
  u16 ip6_full_reass_err_next_index;
} sfdp_reass_main_t;
extern sfdp_reass_main_t sfdp_reass_main;
#endif