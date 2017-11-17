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

#include <plugins/acl/acl.h>
#include <plugins/acl/fa_node.h>
#include <plugins/acl/public_inlines.h>
#include <vlib/unix/plugin.h>

/* check if a given ACL exists */
u8 acl_plugin_acl_exists (u32 acl_index);



static u32 get_acl_user_id(acl_main_t *am, char *user_module_name, char *val1_label, char *val2_label)
{
    acl_lookup_context_user_t *auser;

    pool_foreach (auser, am->acl_users,
    ({
      if (0 == strcmp(auser->user_module_name, user_module_name)) {
        return (auser - am->acl_users);
      }
    }));

    pool_get(am->acl_users, auser);
    auser->user_module_name = user_module_name;
    auser->val1_label = val1_label;
    auser->val2_label = val2_label;
    return (auser - am->acl_users);
}

static int acl_user_id_valid(acl_main_t *am, u32 acl_user_id)
{

  if (pool_is_free_index (am->acl_users, acl_user_id))
    return 0;

  return 1;
}

static int acl_lc_index_valid(acl_main_t *am, u32 lc_index)
{

  if (pool_is_free_index (am->acl_lookup_contexts, lc_index))
    return 0;

  return 1;
}

/*
 * If you are using ACL plugin, get this unique ID first,
 * so you can identify yourself when creating the lookup contexts.
 */

u32 acl_plugin_register_user_module (char *user_module_name, char *val1_label, char *val2_label)
{
  acl_main_t *am = &acl_main;
  u32 user_id = get_acl_user_id(am, user_module_name, val1_label, val2_label);
  return user_id;
}

/*
 * Allocate a new lookup context index.
 * Supply the id assigned to your module during registration,
 * and two values of your choice identifying instances
 * of use within your module. They are useful for debugging.
 */

u32 acl_plugin_get_lookup_context_index (u32 acl_user_id, u32 val1, u32 val2)
{
  acl_main_t *am = &acl_main;
  acl_lookup_context_t *acontext;

  if (!acl_user_id_valid(am, acl_user_id))
    return VNET_API_ERROR_INVALID_REGISTRATION;

  pool_get(am->acl_lookup_contexts, acontext);
  acontext->acl_indices = 0;
  acontext->context_user_id = acl_user_id;
  acontext->user_val1 = val1;
  acontext->user_val2 = val2;

  u32 new_context_id = acontext - am->acl_lookup_contexts; 
  vec_add1(am->acl_users[acl_user_id].lookup_contexts, new_context_id);
  return new_context_id;
}

/*
static void
lock_acl(u32 acl, u32 lc_index)
{

}
*/

static void
lock_acl_vec(u32 lc_index, u32 *acls)
{

}


static void
unlock_acl_vec(u32 lc_index, u32 *acls)
{

}

/*
 * Release the lookup context index and destroy
 * any asssociated data structures.
 */
void acl_plugin_put_lookup_context_index (u32 lc_index)
{
  acl_main_t *am = &acl_main;
  if (!acl_lc_index_valid(am, lc_index)) {
    clib_warning("BUG: lc_index %d is not valid", lc_index);
    return;
  }
  acl_lookup_context_t *acontext = pool_elt_at_index(am->acl_lookup_contexts, lc_index);

  u32 index = vec_search(am->acl_users[acontext->context_user_id].lookup_contexts, lc_index);
  ASSERT(index != ~0);

  vec_del1(am->acl_users[acontext->context_user_id].lookup_contexts, index);
  unlock_acl_vec(lc_index, acontext->acl_indices);
  vec_free(acontext->acl_indices);
  pool_put(am->acl_lookup_contexts, acontext);
}

/*
 * Prepare the sequential vector of ACL#s to lookup within a given context.
 * Any existing list will be overwritten. acl_list is a vector.
 */
int acl_plugin_set_acl_vec_for_context (u32 lc_index, u32 *acl_list)
{
  acl_main_t *am = &acl_main;
  acl_lookup_context_t *acontext;
  if (!acl_lc_index_valid(am, lc_index)) {
    clib_warning("BUG: lc_index %d is not valid", lc_index);
    return -1;
  }
  acontext = pool_elt_at_index(am->acl_lookup_contexts, lc_index);

  u32 *old_acl_vector = acontext->acl_indices;
  acontext->acl_indices = vec_dup(acl_list);
  lock_acl_vec(lc_index, acontext->acl_indices);
  // unapply_old_acls()
  // apply_new_acls()
  unlock_acl_vec(lc_index, old_acl_vector);
  vec_free(old_acl_vector); 
  return 0;
}


void acl_plugin_lookup_context_notify_acl_change(u32 acl_num)
{

}


/* Fill the 5-tuple from the packet */

void acl_plugin_fill_5tuple (u32 lc_index, vlib_buffer_t * b0, int is_ip6, int is_input,
                                int is_l2_path, fa_5tuple_opaque_t * p5tuple_pkt)
{
  acl_plugin_fill_5tuple_inline(lc_index, b0, is_ip6, is_input, is_l2_path, p5tuple_pkt);
}

int acl_plugin_match_5tuple (u32 lc_index,
                                           fa_5tuple_opaque_t * pkt_5tuple,
                                           int is_ip6, u8 * r_action,
                                           u32 * r_acl_pos_p,
                                           u32 * r_acl_match_p,
                                           u32 * r_rule_match_p,
                                           u32 * trace_bitmap)
{
  return acl_plugin_match_5tuple_inline (lc_index, pkt_5tuple, is_ip6, r_action, r_acl_pos_p, r_acl_match_p, r_rule_match_p, trace_bitmap);
}


