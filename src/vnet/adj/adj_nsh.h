/*
 * Copyright (c) 2017 Cisco and/or its affiliates.
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

#ifndef __ADJ_NSH_H__
#define __ADJ_NSH_H__

#include <vnet/adj/adj.h>

extern vlib_node_registration_t adj_nsh_midchain_node;
extern vlib_node_registration_t adj_nsh_rewrite_node;

typedef struct _nsh_main_dummy
{
  u8 output_feature_arc_index;
} nsh_main_dummy_t;

extern nsh_main_dummy_t nsh_main_dummy;

#endif
