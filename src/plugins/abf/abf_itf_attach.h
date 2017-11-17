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

#ifndef __ABF_ITF_ATTACH_H__
#define __ABF_ITF_ATTACH_H__

#include <plugins/abf/abf_policy.h>
#include <vnet/fib/fib_path_list.h>

/**
 * Attachment data for an ABF policy to an interface
 */
typedef struct abf_itf_attach_t_
{
  CLIB_CACHE_LINE_ALIGN_MARK (marker);
  /**
   * The ACL and DPO are cached for fast DP access
   */
  /**
   * ACL index to match
   */
  u32 aia_acl;

  /**
   * The DPO actually used for forwarding
   */
  dpo_id_t aia_dpo;

  /**
   * Linkage into the FIB graph
   */
  fib_node_t aia_node;

  /**
   * The VPP index of the ABF policy
   */
  u32 aia_abf;

  /**
   * Sibling index on the policy's path list
   */
  u32 aia_sibling;

  /**
   * The protocol for the attachment. i.e. the protocol
   * of the packets that are being forwarded
   */
  fib_protocol_t aia_proto;

  /**
   * The interface for the attachment
   */
  u32 aia_sw_if_index;

  /**
   * The priority of this policy for attachment.
   * The lower the value the higher the priority.
   * The higher priority policies are matched first.
   */
  u32 aia_prio;
} abf_itf_attach_t;

/**
 * Pool of ABF interface attachment objects
 */
extern abf_itf_attach_t *abf_itf_attach_pool;

static inline abf_itf_attach_t *
abf_itf_attach_get (u32 index)
{
  return (pool_elt_at_index (abf_itf_attach_pool, index));
}

extern int abf_itf_attach (fib_protocol_t fproto,
			   u32 policy_id, u32 priority, u32 sw_if_index);

extern int abf_itf_detach (fib_protocol_t fproto,
			   u32 policy_id, u32 sw_if_index);

typedef int (*abf_itf_attach_walk_cb_t) (index_t aii, void *ctx0);

extern void abf_itf_attach_walk (abf_itf_attach_walk_cb_t cb, void *ctx);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

#endif
