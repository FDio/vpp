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

#ifndef __ABF_H__
#define __ABF_H__

#include <vnet/fib/fib_node.h>

#define ABF_PLUGIN_VERSION_MAJOR 1
#define ABF_PLUGIN_VERSION_MINOR 0

/**
 * An ACL based Forwarding 'policy'.
 * This comprises the ACL index to match against and the forwarding
 * path to take if the match is successful.
 *
 * ABF policies are then 'attached' to interfaces. An input feature
 * will run through the list of policies a match will divert the packet,
 * if all miss then we continues down the interface's feature arc
 */
typedef struct abf_policy_t_
{
  /**
   * Linkage into the FIB graph
   */
  fib_node_t ap_node;

  /**
   * ACL index to match
   */
  u32 ap_acl;

  /**
   * The path-list describing how to forward in case of a match
   */
  fib_node_index_t ap_pl;

  /**
   * Sibling index on the path-list
   */
  u32 ap_sibling;

  /**
   * The policy ID - as configured by the client
   */
  u32 ap_id;
} abf_policy_t;

/**
 * Get an ABF object from its VPP index
 */
extern abf_policy_t *abf_policy_get (index_t index);

/**
 * Find a ABF object from the client's policy ID
 *
 * @param policy_id Client's defined policy ID
 * @return VPP's object index
 */
extern index_t abf_policy_find (u32 policy_id);

/**
 * The FIB node type for ABF policies
 */
extern fib_node_type_t abf_policy_fib_node_type;

/**
 * Create or update an ABF Policy
 *
 * @param policy_id User defined Policy ID
 * @param acl_index The ACL the policy with match on
 * @param rpaths The set of paths to add to the forwarding set
 * @return error code
 */
extern int abf_policy_update (u32 policy_id,
			      u32 acl_index, const fib_route_path_t * rpaths);

/**
 * Delete paths from an ABF Policy. If no more paths exist, the policy
 * is deleted.
 *
 * @param policy_id User defined Policy ID
 * @param rpaths The set of paths to forward remove
 */
extern int abf_policy_delete (u32 policy_id, const fib_route_path_t * rpaths);

/**
 * Callback function invoked during a walk of all policies
 */
typedef int (*abf_policy_walk_cb_t) (index_t index, void *ctx);

/**
 * Walk/visit each of the ABF policies
 */
extern void abf_policy_walk (abf_policy_walk_cb_t cb, void *ctx);


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

#endif
