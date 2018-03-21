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

#ifndef included_acl_lookup_context_h
#define included_acl_lookup_context_h

typedef struct {
  /* A name of the portion of the code using the ACL infra */
  char *user_module_name;
  /* text label for the first u32 user value assigned to context */
  char *val1_label;
  /* text label for the second u32 user value assigned to context */
  char *val2_label;
  /* vector of lookup contexts of this user */
  u32 *lookup_contexts;
} acl_lookup_context_user_t;

typedef struct {
  /* vector of acl #s within this context */
  u32 *acl_indices;
  /* index of corresponding acl_lookup_context_user_t */
  u32 context_user_id;
  /* per-instance user value 1 */
  u32 user_val1;
  /* per-instance user value 2 */
  u32 user_val2;
} acl_lookup_context_t;

void acl_plugin_lookup_context_notify_acl_change(u32 acl_num);

void acl_plugin_show_lookup_context (u32 lc_index);
void acl_plugin_show_lookup_user (u32 user_index);


/* These are in the hash matching for now */
void acl_plugin_show_tables_mask_type (void);
void acl_plugin_show_tables_acl_hash_info (u32 acl_index);
void acl_plugin_show_tables_applied_info (u32 sw_if_index);
void acl_plugin_show_tables_bihash (u32 show_bihash_verbose);

/* Debug functions to turn validate/trace on and off */
void acl_plugin_hash_acl_set_validate_heap(int on);
void acl_plugin_hash_acl_set_trace_heap(int on);



#endif

