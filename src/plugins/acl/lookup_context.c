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

#include <plugins/acl/acl.h>
#include <plugins/acl/acl_caiop.h>
#include <plugins/acl/fa_node.h>
#include <vlib/unix/plugin.h>
#include <plugins/acl/public_inlines.h>
#include "hash_lookup.h"
#include "elog_acl_trace.h"

/* check if a given ACL exists */
static u8
acl_plugin_acl_exists (u32 acl_index)
{
  acl_main_t *am = &acl_main;

  if (pool_is_free_index (am->acls, acl_index))
    return 0;

  return 1;
}


static u32 get_acl_user_id(acl_main_t *am, char *user_module_name, char *val1_label, char *val2_label)
{
    acl_lookup_context_user_t *auser;

    pool_foreach (auser, am->acl_users)
     {
      if (0 == strcmp(auser->user_module_name, user_module_name)) {
        return (auser - am->acl_users);
      }
    }

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

static u32 acl_plugin_register_user_module (char *user_module_name, char *val1_label, char *val2_label)
{
  acl_main_t *am = &acl_main;
  /*
   * Because folks like to call this early on,
   * use the global heap, so as to avoid
   * initializing the main ACL heap before
   * they start using ACLs.
   */
  u32 user_id = get_acl_user_id(am, user_module_name, val1_label, val2_label);
  return user_id;
}

/*
 * Allocate a new lookup context index.
 * Supply the id assigned to your module during registration,
 * and two values of your choice identifying instances
 * of use within your module. They are useful for debugging.
 * If >= 0 - context id. If < 0 - error code.
 */

static int acl_plugin_get_lookup_context_index (u32 acl_user_id, u32 val1, u32 val2)
{
  acl_main_t *am = &acl_main;
  acl_lookup_context_t *acontext;

  if (!acl_user_id_valid(am, acl_user_id))
    return VNET_API_ERROR_INVALID_REGISTRATION;

  /*
   * The lookup context index allocation is
   * an operation done within the global heap,
   * so no heap switching necessary.
   */

  pool_get(am->acl_lookup_contexts, acontext);
  acontext->acl_indices = 0;
  acontext->context_user_id = acl_user_id;
  acontext->user_val1 = val1;
  acontext->user_val2 = val2;

  u32 new_context_id = acontext - am->acl_lookup_contexts;
  vec_add1(am->acl_users[acl_user_id].lookup_contexts, new_context_id);

  return new_context_id;
}

static void
lock_acl(acl_main_t *am, u32 acl, u32 lc_index)
{
  vec_validate(am->lc_index_vec_by_acl, acl);
  elog_acl_cond_trace_X2(am, (am->trace_acl), "lock acl %d in lc_index %d", "i4i4", acl, lc_index);
  vec_add1(am->lc_index_vec_by_acl[acl], lc_index);
}

static void
lock_acl_vec(u32 lc_index, u32 *acls)
{
  int i;
  acl_main_t *am = &acl_main;
  for(i=0; i<vec_len(acls); i++) {
    lock_acl(am, acls[i], lc_index);
  }
}

static void
unlock_acl(acl_main_t *am, u32 acl, u32 lc_index)
{
  vec_validate(am->lc_index_vec_by_acl, acl);
  elog_acl_cond_trace_X2(am, (am->trace_acl), "unlock acl %d in lc_index %d", "i4i4", acl, lc_index);
  u32 index = vec_search(am->lc_index_vec_by_acl[acl], lc_index);
  if (index != ~0)
    vec_del1(am->lc_index_vec_by_acl[acl], index);
  else
    clib_warning("BUG: can not unlock acl %d lc_index %d", acl, lc_index);
}

static void
unlock_acl_vec(u32 lc_index, u32 *acls)
{
  int i;
  acl_main_t *am = &acl_main;
  for(i=0; i<vec_len(acls); i++)
  unlock_acl(am, acls[i], lc_index);
}


static void
apply_acl_vec(u32 lc_index, u32 *acls)
{
  int i;
  acl_main_t *am = &acl_main;

  for(i=0; i<vec_len(acls); i++)
    hash_acl_apply(am, lc_index, acls[i], i);
}


static void
unapply_acl_vec(u32 lc_index, u32 *acls)
{
  int i;
  acl_main_t *am = &acl_main;
  if (vec_len(acls) == 0)
    return;
  for(i=vec_len(acls); i > 0; i--)
    hash_acl_unapply(am, lc_index, acls[i-1]);
}

/*
 * Release the lookup context index and destroy
 * any associated data structures.
 */
static void acl_plugin_put_lookup_context_index (u32 lc_index)
{
  acl_main_t *am = &acl_main;

  elog_acl_cond_trace_X1(am, (am->trace_acl), "LOOKUP-CONTEXT: put-context lc_index %d", "i4", lc_index);
  if (!acl_lc_index_valid(am, lc_index)) {
    clib_warning("BUG: lc_index %d is not valid", lc_index);
    return;
  }

  acl_lookup_context_t *acontext = pool_elt_at_index(am->acl_lookup_contexts, lc_index);

  u32 index = vec_search(am->acl_users[acontext->context_user_id].lookup_contexts, lc_index);
  ASSERT(index != ~0);

  vec_del1(am->acl_users[acontext->context_user_id].lookup_contexts, index);
  unapply_acl_vec(lc_index, acontext->acl_indices);
  unlock_acl_vec(lc_index, acontext->acl_indices);
  vec_free(acontext->acl_indices);
  pool_put(am->acl_lookup_contexts, acontext);
}

/*
 * Prepare the sequential vector of ACL#s to lookup within a given context.
 * Any existing list will be overwritten. acl_list is a vector.
 */
static int acl_plugin_set_acl_vec_for_context (u32 lc_index, u32 *acl_list)
{
  int rv = 0;
  uword *seen_acl_bitmap = 0;
  u32 *pacln = 0;
  acl_main_t *am = &acl_main;
  acl_lookup_context_t *acontext;
  if (am->trace_acl) {
    u32 i;
    elog_acl_cond_trace_X1(am, (1), "LOOKUP-CONTEXT: set-acl-list lc_index %d", "i4", lc_index);
    for(i=0; i<vec_len(acl_list); i++) {
      elog_acl_cond_trace_X2(am, (1), "   acl-list[%d]: %d", "i4i4", i, acl_list[i]);
    }
  }  
  if (!acl_lc_index_valid(am, lc_index)) {
    clib_warning("BUG: lc_index %d is not valid", lc_index);
    return -1;
  }
  vec_foreach (pacln, acl_list)
  {
    if (pool_is_free_index (am->acls, *pacln))
      {
        /* ACL is not defined. Can not apply */
        clib_warning ("ERROR: ACL %d not defined", *pacln);
        rv = VNET_API_ERROR_NO_SUCH_ENTRY;
        goto done;
      }
    if (clib_bitmap_get (seen_acl_bitmap, *pacln))
      {
        /* ACL being applied twice within the list. error. */
        clib_warning ("ERROR: ACL %d being applied twice", *pacln);
        rv = VNET_API_ERROR_ENTRY_ALREADY_EXISTS;
        goto done;
      }
    seen_acl_bitmap = clib_bitmap_set (seen_acl_bitmap, *pacln, 1);
  }

  acontext = pool_elt_at_index(am->acl_lookup_contexts, lc_index);
  u32 *old_acl_vector = acontext->acl_indices;
  acontext->acl_indices = vec_dup(acl_list);

  unapply_acl_vec(lc_index, old_acl_vector);
  unlock_acl_vec(lc_index, old_acl_vector);
  lock_acl_vec(lc_index, acontext->acl_indices);
  apply_acl_vec(lc_index, acontext->acl_indices);

  vec_free(old_acl_vector);

done:
  clib_bitmap_free (seen_acl_bitmap);
  return rv;
}


void acl_plugin_lookup_context_notify_acl_change(u32 acl_num)
{
  acl_main_t *am = &acl_main;
  if (acl_plugin_acl_exists(acl_num)) {
    if (hash_acl_exists(am, acl_num)) {
        /* this is a modification, clean up the older entries */
        hash_acl_delete(am, acl_num);
    }
    hash_acl_add(am, acl_num);
  } else {
    /* this is a deletion notification */
    hash_acl_delete(am, acl_num);
  }
}

/* Fill the 5-tuple from the packet */

static void acl_plugin_fill_5tuple (u32 lc_index, vlib_buffer_t * b0, int is_ip6, int is_input,
                                int is_l2_path, fa_5tuple_opaque_t * p5tuple_pkt)
{
  acl_plugin_fill_5tuple_inline(&acl_main, lc_index, b0, is_ip6, is_input, is_l2_path, p5tuple_pkt);
}

static int acl_plugin_match_5tuple (u32 lc_index,
                                           fa_5tuple_opaque_t * pkt_5tuple,
                                           int is_ip6, u8 * r_action,
                                           u32 * r_acl_pos_p,
                                           u32 * r_acl_match_p,
                                           u32 * r_rule_match_p,
                                           u32 * trace_bitmap)
{
  return acl_plugin_match_5tuple_inline (&acl_main, lc_index, pkt_5tuple, is_ip6, r_action, r_acl_pos_p, r_acl_match_p, r_rule_match_p, trace_bitmap);
}

/* This is an experimental method, subject to change or disappear */
static int
acl_plugin_wip_add_del_custom_access_io_policy (int is_add, u32 sw_if_index,
						int is_input, void *func)
{
  return acl_caiop_add_del (is_add, sw_if_index, is_input, func);
}

void
acl_plugin_show_lookup_user (u32 user_index)
{
    acl_main_t *am = &acl_main;
    vlib_main_t *vm = am->vlib_main;
    acl_lookup_context_user_t *auser;

    pool_foreach (auser, am->acl_users)
     {
      u32 curr_user_index = (auser - am->acl_users);
      if (user_index == ~0 || (curr_user_index == user_index)) {
        vlib_cli_output (vm, "index %d:%s:%s:%s", curr_user_index, auser->user_module_name, auser->val1_label, auser->val2_label);
      }
    }
}


void
acl_plugin_show_lookup_context (u32 lc_index)
{
  acl_main_t *am = &acl_main;
  vlib_main_t *vm = am->vlib_main;
  acl_lookup_context_t *acontext;
  // clib_warning("LOOKUP-CONTEXT: lc_index %d acl_list [ %U ]", lc_index, format_vec32, acl_list, "%d");
  if (!am->acl_lookup_contexts)
  {
    vlib_cli_output(vm, "ACL lookup contexts are not initialized");
    return;
  }

  pool_foreach (acontext, am->acl_lookup_contexts)
   {
    u32 curr_lc_index = (acontext - am->acl_lookup_contexts);
    if ((lc_index == ~0) || (curr_lc_index == lc_index)) {
      if (acl_user_id_valid(am, acontext->context_user_id)) {
        acl_lookup_context_user_t *auser = pool_elt_at_index(am->acl_users, acontext->context_user_id);
        vlib_cli_output (vm, "index %d:%s %s: %d %s: %d, acl_indices: %U",
                       curr_lc_index, auser->user_module_name, auser->val1_label,
                       acontext->user_val1, auser->val2_label, acontext->user_val2,
                       format_vec32, acontext->acl_indices, "%d");
      } else {
        vlib_cli_output (vm, "index %d: user_id: %d user_val1: %d user_val2: %d, acl_indices: %U",
                       curr_lc_index, acontext->context_user_id,
                       acontext->user_val1, acontext->user_val2,
                       format_vec32, acontext->acl_indices, "%d");
      }
    }
  }
}

void *
acl_plugin_get_p_acl_main(void)
{
  return &acl_main;
}

__clib_export clib_error_t *
acl_plugin_methods_vtable_init(acl_plugin_methods_t *m)
{
  m->p_acl_main = &acl_main;
#define _(name) m->name = acl_plugin_ ## name;
  foreach_acl_plugin_exported_method_name
#undef _
  return 0;
}
