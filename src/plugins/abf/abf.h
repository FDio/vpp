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
 * An ACL based Forwading 'policy'.
 * This comprises the ACL index to match against and the forwarding
 * path to take if the match is successfull.
 *
 * ABF policies are then 'attached' to interfaces. An input feature
 * will run through the list of policies a match will divert the packet,
 * if all miss then we continues down the interface's feature arc
 */
typedef struct abf_t_
{
  /**
   * Linkage into the FIB graph
   */
  fib_node_t abf_node;

  /**
   * ACL index to match
   */
  u32 abf_acl;

  /**
   * The path-list describing how to forward in case of a match
   */
  fib_node_index_t abf_pl;

  /**
   * Sibling index on the path-list
   */
  u32 abf_sibling;

  /**
   * The policy ID - as configured by the client
   */
  u32 abf_id;
} abf_t;

/**
 * Get an ABF object from its VPP index
 */
extern abf_t *abf_get (u32 index);

/**
 * Find a ABF object from the client's policy ID
 */
extern u32 abf_find (u32 policy_id);

extern fib_node_type_t abf_fib_node_type;

extern void abf_policy_update (u32 policy_id,
			       u32 acl_index,
			       const fib_route_path_t * rpaths);

extern int abf_policy_delete (u32 policy_id, const fib_route_path_t * rpaths);

extern int abf_attach (fib_protocol_t fproto,
		       u32 policy_id, u32 priority, u32 sw_if_index);

extern int abf_detach (fib_protocol_t fproto, u32 policy_id, u32 sw_if_index);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

#endif
