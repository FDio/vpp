/*
 * Copyright (c) 2019 Cisco and/or its affiliates.
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

#ifndef __FILTER_TYPES_H__
#define __FILTER_TYPES_H__

#include <stdbool.h>
#include <vnet/dpo/dpo.h>

#include <vnet/fib/fib_node.h>

/**
 * Linkage into the filter graph
 */
typedef struct filter_node_t_
{
  fib_node_t fn_node;
  u32 fn_sibling;
} filter_node_t;

/**
 * INPUT =  all received packets
 * FOR_US = packets destined to a local address
 * FORWARD = packets forwarded/routed/switch
 * FROM_US = packet sent by us
 * OUTPUT =  all transmitted packets
 */
#define foreach_filter_hook_type                    \
  _(INPUT, "input")                                 \
  _(OUTPUT, "output")                               \
  _(FORWARD, "forward")                             \
  _(FOR_US, "for-us")                               \
  _(FROM_US, "from-us")                             \
  _(BRANCH, "branch")                               \

typedef enum filter_hook_type_t_
{
#define _(a, b) FILTER_HOOK_##a,
  foreach_filter_hook_type
#undef _
} filter_hook_type_t;

#define FILTER_N_BASE_HOOKS (FILTER_HOOK_FROM_US+1)

#define FOREACH_FILTER_HOOK_BASE_TYPE(__fhn) \
  for (__fhn = FILTER_HOOK_INPUT; __fhn < FILTER_N_BASE_HOOKS; __fhn++)

#define FILTER_HOOK_IS_BASE(_fh) (_fh < FILTER_HOOK_BRANCH)

extern u8 *format_filter_hook_type (u8 * s, va_list * args);
extern uword unformat_filter_hook_type (unformat_input_t * input,
					va_list * args);

/**
 * The action that will occur when the walk of the chain completes
 */
#define foreach_filter_chain_policy \
  _(RETURN, "return")               \
  _(ACCEPT, "accept")               \
  _(DROP, "drop")                   \

typedef enum filter_chain_policy_t_
{
#define _(a,b) FILTER_CHAIN_POLICY_##a,
  foreach_filter_chain_policy
#undef _
} filter_chain_policy_t;

extern u8 *format_filter_chain_policy (u8 * s, va_list * args);
extern uword unformat_filter_chain_policy (unformat_input_t * input,
					   va_list * args);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

#endif
