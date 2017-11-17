/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
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
#ifndef included_acl_exports_h
#define included_acl_exports_h

/*
 * This file contains the declarations for external consumption,
 * along with the necessary dependent includes.
 */

#include <plugins/acl/acl.h>
#include <plugins/acl/fa_node.h>

void acl_plugin_fill_5tuple (acl_main_t * am, vlib_buffer_t * b0, int is_ip6,
                             int is_input, int is_l2_path, fa_5tuple_t * p5tuple_pkt);

int acl_plugin_single_acl_match_5tuple (acl_main_t * am, u32 acl_index, fa_5tuple_t * pkt_5tuple,
                                        int is_ip6, u8 * r_action, u32 * r_acl_match_p,
                                        u32 * r_rule_match_p, u32 * trace_bitmap);

#endif
