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
/**
 * Span, i.e. replicate, traffic destined to a given prefix to a [set of] collectors.
 * A collector is simply a FIB path desribing where the traffic should be sent,
 * plus any encapsulation.
 */

#ifndef __L3_SPAN_H__
#define __L3_SPAN_H__

#include <vnet/fib/fib_types.h>

/**
 * A representation of an L3 Span entry
 */
typedef struct l3_span_t_
{
  /**
   * The FIB index the prefix is in
   */
  u32 l3s_fib_index;

  /**
   * The destination prefix to span
   */
  fib_prefix_t l3s_pfx;

  /**
   * The path list descrbing where to spane the traffi to
   */
  fib_node_index_t l3s_pl;

  /**
   * Sibling index on the path-list
   */
  u32 l3s_pl_sibling;

  /**
   * The FIB entry index sourced
   */
  fib_node_index_t l3s_fei;

  /**
   * The L3 Span DPO from which we clone those that
   * are interposed in the FIB graph
   */
  dpo_id_t l3s_dpo;
} l3_span_t;

extern void l3_span_path_add (u32 fib_index,
			      const fib_prefix_t * pfx,
			      const fib_route_path_t * rpath);

extern void l3_span_path_remove (u32 fib_index,
				 const fib_prefix_t * pfx,
				 const fib_route_path_t * rpath);

/**
 * Call back function when walking the L3 Span entries
 *
 * @return 1 to continue walking 0 otherwise
 */
typedef int (*l3_span_walk_t)(const l3_span_t *l3s, void *ctx);

/**
 * Walk the L3 span entries
 */
extern void l3_span_walk(l3_span_walk_t cb,
                         void *ctx);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

#endif
