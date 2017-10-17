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

#ifndef SRC_VNET_SESSION_SESSION_RULES_TABLE_TEMPLATE_H_
#define SRC_VNET_SESSION_SESSION_RULES_TABLE_TEMPLATE_H_

#include <vppinfra/pool.h>

#ifndef SESSION_RT_TYPE
#error SESSION_RT_TYPE not defined
#endif

#define _rt(a,b) a##_##b
#define __rt(a, b) _rt(a,b)
#define RT(a) __rt(a, SESSION_RT_TYPE)

#define _rtt(a,b) a##_##b##_t
#define __rtt(a, b) _rtt(a,b)
#define RTT(a) __rtt(a, SESSION_RT_TYPE)

#define SESSION_RULES_TABLE_INVALID_INDEX ((u32)~0)

typedef struct
{
  u64 as_u64[SESSION_RT_TYPE / 8];
} RTT (session_mask_or_match);

typedef struct
{
  u32 action_index;
  u32 *next_indices;
  RTT (session_mask_or_match) mask;
  RTT (session_mask_or_match) match;
} RTT (session_rule);

typedef struct
{
  /** Root for rules tree */
  u32 root_index;

  /** Rules pool */
  RTT (session_rule) *rules;
} RTT (session_rules_table);

u32
RT (session_rules_table_lookup) (RTT (session_rules_table) * srt,
				 RTT (session_mask_or_match) * key,
				 u32 rule_index);
u32
RT (session_rules_table_lookup_rule) (RTT (session_rules_table) *srt,
				      RTT (session_mask_or_match) *key,
				      u32 rule_index);
int
RT (session_rules_table_add_rule) (RTT (session_rules_table) *srt,
				   RTT (session_rule) *rule);
RTT (session_rule) *
RT (session_rule_alloc) (RTT(session_rules_table) *srt);
RTT (session_rule) *
RT (session_rules_table_get_rule) (RTT (session_rules_table) *srt,
				   u32 srt_index);
u32
RT (session_rules_table_rule_index) (RTT (session_rules_table) *srt,
				     RTT (session_rule) *sr);
#endif /* SRC_VNET_SESSION_SESSION_RULES_TABLE_TEMPLATE_H_ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
