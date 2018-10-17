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

u8 RT (rule_is_exact_match) (RTT (mma_rule) * key, RTT (mma_rule) * r)
{
  int i;

  for (i = 0; i < ARRAY_LEN (key->match.as_u64); i++)
    {
      if (key->match.as_u64[i] != r->match.as_u64[i])
	return 0;
    }
  for (i = 0; i < ARRAY_LEN (key->mask.as_u64); i++)
    {
      if (key->mask.as_u64[i] != r->mask.as_u64[i])
	return 0;
    }
  return 1;
}

u8
RT (rule_is_match_for_key) (RTT (mma_mask_or_match) * key, RTT (mma_rule) * r)
{
  RTT (mma_mask_or_match) _tmp_key, *tkp = &_tmp_key;
  int i;

  *tkp = *key;
  for (i = 0; i < ARRAY_LEN (tkp->as_u64); i++)
    tkp->as_u64[i] &= r->mask.as_u64[i];
  for (i = 0; i < ARRAY_LEN (tkp->as_u64); i++)
    {
      if (tkp->as_u64[i] != r->match.as_u64[i])
	return 0;
    }
  return 1;
}

RTT (mma_rule) * RT (mma_rules_table_rule_alloc) (RTT (mma_rules_table) * srt)
{
  RTT (mma_rule) * rule;
  pool_get (srt->rules, rule);
  clib_memset (rule, 0, sizeof (*rule));
  return rule;
}

RTT (mma_rule) *
RT (mma_rule_free) (RTT (mma_rules_table) * srt, RTT (mma_rule) * rule)
{
  pool_put (srt->rules, rule);
  clib_memset (rule, 0xfa, sizeof (*rule));
  return rule;
}

RTT (mma_rule) *
RT (mma_rules_table_get_rule) (RTT (mma_rules_table) * srt, u32 srt_index)
{
  if (!pool_is_free_index (srt->rules, srt_index))
    return (srt->rules + srt_index);
  return 0;
}

u32
RT (mma_rules_table_rule_index) (RTT (mma_rules_table) * srt,
				 RTT (mma_rule) * sr)
{
  ASSERT (sr);
  return (sr - srt->rules);
}

/**
 * Lookup key in table
 *
 * This should be optimized .. eventually
 */
u32
RT (mma_rules_table_lookup) (RTT (mma_rules_table) * srt,
			     RTT (mma_mask_or_match) * key, u32 rule_index)
{
  RTT (mma_rule) * rp;
  u32 rv;
  int i;

  ASSERT (rule_index != MMA_TABLE_INVALID_INDEX);
  rp = RT (mma_rules_table_get_rule) (srt, rule_index);
  ASSERT (rp);

  if (!RT (rule_is_match_for_key) (key, rp))
    return MMA_TABLE_INVALID_INDEX;
  for (i = 0; i < vec_len (rp->next_indices); i++)
    {
      rv = RT (mma_rules_table_lookup) (srt, key, rp->next_indices[i]);
      if (rv != MMA_TABLE_INVALID_INDEX)
	return (rv);
    }
  return (rp->action_index);
}

u32
RT (mma_rules_table_lookup_rule) (RTT (mma_rules_table) * srt,
				  RTT (mma_mask_or_match) * key,
				  u32 rule_index)
{
  RTT (mma_rule) * rp;
  u32 rv;
  int i;

  ASSERT (rule_index != MMA_TABLE_INVALID_INDEX);
  rp = RT (mma_rules_table_get_rule) (srt, rule_index);
  ASSERT (rp);

  if (!RT (rule_is_match_for_key) (key, rp))
    return MMA_TABLE_INVALID_INDEX;
  for (i = 0; i < vec_len (rp->next_indices); i++)
    {
      rv = RT (mma_rules_table_lookup_rule) (srt, key, rp->next_indices[i]);
      if (rv != MMA_TABLE_INVALID_INDEX)
	return (rv);
    }
  return rule_index;
}

static
RTT (mma_rules_table) *
RTT (sort_srt);

     int RT (mma_sort_indices) (void *e1, void *e2)
{
  u32 *ri1 = e1, *ri2 = e2;
  RTT (mma_rule) * rule1, *rule2;
  rule1 = RT (mma_rules_table_get_rule) (RTT (sort_srt), *ri1);
  rule2 = RT (mma_rules_table_get_rule) (RTT (sort_srt), *ri2);
  return RTT (sort_srt)->rule_cmp_fn (rule1, rule2);
}

void RT (mma_sort) (RTT (mma_rules_table) * srt, u32 * next_indices)
{
  RTT (sort_srt) = srt;
  vec_sort_with_function (next_indices, RT (mma_sort_indices));
}

int
RT (mma_rules_table_add_rule) (RTT (mma_rules_table) * srt,
			       RTT (mma_rule) * rule)
{
  u32 parent_index, i, *next_indices = 0, added = 0, rule_index;
  RTT (mma_rule) * parent, *child;

  rule_index = RT (mma_rules_table_rule_index) (srt, rule);
  parent_index = RT (mma_rules_table_lookup_rule) (srt, &rule->match,
						   srt->root_index);
  parent = RT (mma_rules_table_get_rule) (srt, parent_index);
  if (RT (rule_is_exact_match) (rule, parent))
    {
      parent->action_index = rule->action_index;
      RT (mma_rule_free) (srt, rule);
      return -1;
    }

  if (vec_len (parent->next_indices) == 0)
    {
      vec_add1 (parent->next_indices, rule_index);
      return 0;
    }

  /* Check if new rule is parent of some of the existing children */
  for (i = 0; i < vec_len (parent->next_indices); i++)
    {
      child = RT (mma_rules_table_get_rule) (srt, parent->next_indices[i]);
      if (RT (rule_is_match_for_key) (&child->match, rule))
	{
	  vec_add1 (rule->next_indices, parent->next_indices[i]);
	  if (!added)
	    {
	      vec_add1 (next_indices, rule_index);
	      added = 1;
	    }
	}
      else
	{
	  if (!added && srt->rule_cmp_fn (rule, child) < 0)
	    {
	      vec_add1 (next_indices, rule_index);
	      added = 1;
	    }
	  vec_add1 (next_indices, parent->next_indices[i]);
	}
    }
  if (!added)
    vec_add1 (next_indices, rule_index);
  vec_free (parent->next_indices);
  parent->next_indices = next_indices;
  return 0;
}

int
RT (mma_rules_table_del_rule) (RTT (mma_rules_table) * srt,
			       RTT (mma_rule) * rule, u32 rule_index)
{
  RTT (mma_rule) * rp;
  u32 rv;
  int i;

  ASSERT (rule_index != MMA_TABLE_INVALID_INDEX);
  rp = RT (mma_rules_table_get_rule) (srt, rule_index);

  if (!RT (rule_is_match_for_key) (&rule->match, rp))
    return MMA_TABLE_INVALID_INDEX;
  if (RT (rule_is_exact_match) (rule, rp))
    {
      if (rule_index == srt->root_index)
	rp->action_index = MMA_TABLE_INVALID_INDEX;
      return 1;
    }
  for (i = 0; i < vec_len (rp->next_indices); i++)
    {
      rv = RT (mma_rules_table_del_rule) (srt, rule, rp->next_indices[i]);
      if (rv == 1)
	{
	  RTT (mma_rule) * child;
	  u32 *next_indices = 0, *new_elts, left_to_add;
	  child = RT (mma_rules_table_get_rule) (srt, rp->next_indices[i]);
	  ASSERT (RT (rule_is_exact_match) (rule, child));

	  if (i != 0)
	    {
	      vec_add2 (next_indices, new_elts, i);
	      clib_memcpy (new_elts, rp->next_indices, i * sizeof (u32));
	    }
	  if (vec_len (child->next_indices))
	    vec_append (next_indices, child->next_indices);
	  left_to_add = vec_len (rp->next_indices) - i - 1;
	  if (left_to_add)
	    {
	      vec_add2 (next_indices, new_elts, left_to_add);
	      clib_memcpy (new_elts, &rp->next_indices[i + 1],
			   left_to_add * sizeof (u32));
	    }
	  RT (mma_rule_free) (srt, child);
	  vec_free (rp->next_indices);
	  rp->next_indices = next_indices;
	  return 0;
	}
      else if (rv == 0)
	return rv;
    }
  return MMA_TABLE_INVALID_INDEX;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
