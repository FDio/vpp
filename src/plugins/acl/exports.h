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

/* check if a given ACL exists */
u8 (*acl_plugin_acl_exists) (u32 acl_index);


/*
 * If you are using ACL plugin, get this unique ID first,
 * so you can identify yourself when creating the lookup contexts.
 */

u32 (*acl_plugin_register_user_module) (char *caller_module_string, char *val1_label, char *val2_label);

/*
 * Allocate a new lookup context index.
 * Supply the id assigned to your module during registration,
 * and two values of your choice identifying instances
 * of use within your module. They are useful for debugging.
 */

u32 (*acl_plugin_get_lookup_context_index) (u32 acl_user_id, u32 val1, u32 val2);

/*
 * Release the lookup context index and destroy
 * any asssociated data structures.
 */
void (*acl_plugin_put_lookup_context_index) (u32 lc_index);

/*
 * Prepare the sequential vector of ACL#s to lookup within a given context.
 * Any existing list will be overwritten. acl_list is a vector.
 */
int (*acl_plugin_set_acl_vec_for_context) (u32 lc_index, u32 *acl_list);

/* Fill the 5-tuple from the packet */

void (*acl_plugin_fill_5tuple) (u32 lc_index, vlib_buffer_t * b0, int is_ip6, int is_input,
                                int is_l2_path, fa_5tuple_t * p5tuple_pkt);

static inline
void acl_plugin_fill_5tuple_inline (u32 lc_index, vlib_buffer_t * b0, int is_ip6, int is_input,
                                int is_l2_path, fa_5tuple_t * p5tuple_pkt) {
  /* FIXME: normally the inlined version of filling in the 5-tuple. But for now just call the non-inlined version */
  acl_plugin_fill_5tuple(lc_index, b0, is_ip6, is_input, is_l2_path, p5tuple_pkt);
}


int (*acl_plugin_match_5tuple) (u32 lc_index,
                                           fa_5tuple_t * pkt_5tuple,
                                           int is_ip6, u8 * r_action,
                                           u32 * r_acl_pos_p,
                                           u32 * r_acl_match_p,
                                           u32 * r_rule_match_p,
                                           u32 * trace_bitmap);
static inline int
acl_plugin_match_5tuple_inline (u32 lc_index,
                                           fa_5tuple_t * pkt_5tuple,
                                           int is_ip6, u8 * r_action,
                                           u32 * r_acl_pos_p,
                                           u32 * r_acl_match_p,
                                           u32 * r_rule_match_p,
                                           u32 * trace_bitmap) {
  /* FIXME: normally the place for the inline version. For now just call the function */

  return acl_plugin_match_5tuple(lc_index, pkt_5tuple, is_ip6, r_action, r_acl_pos_p, r_acl_match_p, r_rule_match_p, trace_bitmap);
}


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
    // LOAD_SYMBOL(acl_plugin_fill_5tuple);
    // LOAD_SYMBOL(acl_plugin_single_acl_match_5tuple);
    LOAD_SYMBOL(acl_plugin_acl_exists);
    LOAD_SYMBOL(acl_plugin_register_user_module);
    LOAD_SYMBOL(acl_plugin_get_lookup_context_index);
    LOAD_SYMBOL(acl_plugin_put_lookup_context_index);
    LOAD_SYMBOL(acl_plugin_set_acl_vec_for_context);
    LOAD_SYMBOL(acl_plugin_fill_5tuple);
    LOAD_SYMBOL(acl_plugin_match_5tuple);
    return 0;
}

#endif
