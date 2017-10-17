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

#include <vppinfra/error.h>

u8
RT (rule_is_match_for_key) (RTT (session_mask_or_match) *key, RTT (session_rule) *r)
{
  RTT (session_mask_or_match) _tmp_key, *tkp = &_tmp_key;
  int i;

  *tkp = *key;
  for (i = 0; i < ARRAY_LEN(tkp->as_u64); i++)
    tkp->as_u64[i] &= r->mask.as_u64[i];
  for (i = 0; i < ARRAY_LEN(tkp->as_u64); i++)
    {
      if (tkp->as_u64[i] != r->match.as_u64[i])
	return 0;
    }
  return 1;
}

/**
 * Lookup key in table
 *
 * One day, this should be optimized
 */
u32
RT (session_rules_table_lookup) (RTT (session_rules_table) * srt,
				 RTT (session_mask_or_match) * key,
				 u32 rule_index)
{
  RTT (session_rule) *rp;
  u32 rv;
  int i;

  ASSERT(rule_index != SESSION_RULES_TABLE_INVALID_INDEX);
  rp = RT (session_rules_table_get_rule) (srt, rule_index);
  ASSERT (rp);

  if (!RT (rule_is_match_for_key) (key, rp))
    return ~0;
  for (i = 0; i < vec_len (rp->next_indices); i++)
    {
      rv = RT (session_rules_table_lookup)  (srt, key, rp->next_indices[i]);
      if (rv != ~0)
	return (rv);
    }
  return (rp->action_index);
}

u32
RT (session_rules_table_lookup_rule) (RTT (session_rules_table) *srt,
				      RTT (session_mask_or_match) *key,
				      u32 rule_index)
{
  RTT (session_rule) *rp;
  u32 rv;
  int i;

  ASSERT(rule_index != SESSION_RULES_TABLE_INVALID_INDEX);
  rp = RT (session_rules_table_get_rule) (srt, rule_index);
  ASSERT(rp);

  if (!RT (rule_is_match_for_key) (key, rp))
    return ~0;
  for (i = 0; i < vec_len(rp->next_indices); i++)
    {
      rv = RT (session_rules_table_lookup_rule) (srt, key,
						 rp->next_indices[i]);
      if (rv != ~0)
	return (rv);
    }
  return rule_index;
}

int
RT (session_rules_table_add_rule) (RTT (session_rules_table) *srt,
				   RTT (session_rule) *rule)
{
  u32 parent_index;
  RTT (session_rule) *parent;

  parent_index = RT (session_rules_table_lookup_rule) (srt, &rule->match,
						       srt->root_index);
  parent = RT (session_rules_table_get_rule) (srt, parent_index);
  vec_add1(parent->next_indices, RT (session_rules_table_rule_index) (srt,
								      rule));
  return 0;
}

RTT (session_rule) *
RT (session_rule_alloc) (RTT(session_rules_table) *srt)
{
  RTT (session_rule) *rule;
  pool_get (srt->rules, rule);
  memset (rule, 0, sizeof (*rule));
  return rule;
}

RTT (session_rule) *
RT (session_rules_table_get_rule) (RTT (session_rules_table) *srt,
				   u32 srt_index)
{
  if (!pool_is_free_index (srt->rules, srt_index))
    return (srt->rules + srt_index);
  return 0;
}

u32
RT (session_rules_table_rule_index) (RTT (session_rules_table) *srt,
				     RTT (session_rule) *sr)
{
  ASSERT (sr);
  return (sr - srt->rules);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
