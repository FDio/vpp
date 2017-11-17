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
#include <vlib/unix/plugin.h>


void (*acl_plugin_fill_5tuple) (vlib_buffer_t * b0, int is_ip6, int is_input,
                                int is_l2_path, fa_5tuple_t * p5tuple_pkt);

int (*acl_plugin_single_acl_match_5tuple) (u32 acl_index,
                                           fa_5tuple_t * pkt_5tuple,
                                           int is_ip6, u8 * r_action,
                                           u32 * r_acl_match_p,
                                           u32 * r_rule_match_p,
                                           u32 * trace_bitmap);

u8 (*acl_plugin_acl_exists) (u32 acl_index);


#define LOAD_SYMBOL_FROM_PLUGIN(p, s)                                     \
({                                                                        \
    s = vlib_get_plugin_symbol(p, #s);                                    \
    if (!s)                                                               \
        return clib_error_return(0,                                       \
                "Plugin %s and/or symbol %s not found.", p, #s);          \
})

#define LOAD_SYMBOL(s) LOAD_SYMBOL_FROM_PLUGIN("acl_plugin.so", s)

static inline clib_error_t * acl_plugin_exports_init (void)
{
    LOAD_SYMBOL(acl_plugin_fill_5tuple);
    LOAD_SYMBOL(acl_plugin_single_acl_match_5tuple);
    LOAD_SYMBOL(acl_plugin_acl_exists);
    return 0;
}

#endif
