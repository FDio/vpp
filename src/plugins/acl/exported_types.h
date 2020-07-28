/*
 * Copyright (c) 2018 Cisco and/or its affiliates.
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

#ifndef included_acl_exported_types_h
#define included_acl_exported_types_h

#include <vppinfra/types.h>
#include <vlib/buffer.h>

/* 
 * The overlay struct matching an internal type. Contents/size may change. 
 * During the compile of the ACL plugin it is checked to have the same size
 * as the internal structure.
 */

typedef struct {
  u64 opaque[6];
} fa_5tuple_opaque_t;

/*
 * Use to check if a given acl# exists.
 */

typedef u8 (*acl_plugin_acl_exists_fn_t) (u32 acl_index);

/*
 * If you are using ACL plugin, get this unique ID first,
 * so you can identify yourself when creating the lookup contexts.
 */

typedef u32 (*acl_plugin_register_user_module_fn_t) (char *caller_module_string, char *val1_label, char *val2_label);


/*
 * Allocate a new lookup context index.
 * Supply the id assigned to your module during registration,
 * and two values of your choice identifying instances
 * of use within your module. They are useful for debugging.
 */

typedef int (*acl_plugin_get_lookup_context_index_fn_t) (u32 acl_user_id, u32 val1, u32 val2);

/*
 * Release the lookup context index and destroy
 * any associated data structures.
 */

typedef void (*acl_plugin_put_lookup_context_index_fn_t) (u32 lc_index);

/*
 * Prepare the sequential vector of ACL#s to lookup within a given context.
 * Any existing list will be overwritten. acl_list is a vector.
 */

typedef int (*acl_plugin_set_acl_vec_for_context_fn_t) (u32 lc_index, u32 *acl_list);

typedef void (*acl_plugin_fill_5tuple_fn_t) (u32 lc_index, vlib_buffer_t * b0, int is_ip6, int is_input,
                                int is_l2_path, fa_5tuple_opaque_t * p5tuple_pkt);

typedef int (*acl_plugin_match_5tuple_fn_t) (u32 lc_index,
                                           fa_5tuple_opaque_t * pkt_5tuple,
                                           int is_ip6, u8 * r_action,
                                           u32 * r_acl_pos_p,
                                           u32 * r_acl_match_p,
                                           u32 * r_rule_match_p,
                                           u32 * trace_bitmap);

/*
 * This is an experimental method, subject to change or disappear.
 */

typedef int (*acl_plugin_wip_add_del_custom_access_io_policy_fn_t) (
  int is_add, u32 sw_if_index, int is_input, void *func);

typedef void (*acl_plugin_wip_clear_sessions_fn_t) (u32 sw_if_index);

#define foreach_acl_plugin_exported_method_name                               \
  _ (acl_exists)                                                              \
  _ (register_user_module)                                                    \
  _ (get_lookup_context_index)                                                \
  _ (put_lookup_context_index)                                                \
  _ (set_acl_vec_for_context)                                                 \
  _ (wip_add_del_custom_access_io_policy)                                     \
  _ (wip_clear_sessions)                                                      \
  _ (fill_5tuple)                                                             \
  _ (match_5tuple)

#define _(name) acl_plugin_ ## name ## _fn_t name;
typedef struct {
  void *p_acl_main; /* a local copy of a pointer to acl_main */
  foreach_acl_plugin_exported_method_name
} acl_plugin_methods_t;
#undef _

/*
 * An internally used function to fill in the ACL plugin vtable.
 * The users should call this one:
 * static inline clib_error_t * acl_plugin_exports_init (acl_plugin_methods_t *m);
 */

typedef clib_error_t * (*acl_plugin_methods_vtable_init_fn_t) (acl_plugin_methods_t *m);

#endif

