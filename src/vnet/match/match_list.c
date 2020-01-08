/*
 * Copyright (c) 2020 Cisco and/or its affiliates.
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


#include <vnet/match/match.h>

void
match_list_free (match_list_t * ml)
{
  vec_free (ml->ml_rules);
  vec_free (ml->ml_tag);
}

void
match_list_push_back (match_list_t * ml, const match_rule_t * mr)
{
  u32 rule_index;

  vec_add1_aligned (ml->ml_rules, *mr, CLIB_CACHE_LINE_BYTES);

  /* set the rule's index in the list */
  rule_index = vec_len (ml->ml_rules) - 1;

  ml->ml_rules[rule_index].mr_index = rule_index;
}

void
match_list_init (match_list_t * ml, const u8 * tag, u32 n_entries)
{
  memset (ml, 0, sizeof (*ml));

  if (tag)
    ml->ml_tag = vec_dup ((u8 *) tag);

  if (n_entries)
    {
      vec_validate_aligned (ml->ml_rules, n_entries - 1,
			    CLIB_CACHE_LINE_BYTES);
      vec_reset_length (ml->ml_rules);
    }
}

void
match_list_copy (match_list_t * dst, const match_list_t * src)
{
  match_list_free (dst);

  dst->ml_rules = vec_dup (src->ml_rules);
  dst->ml_tag = vec_dup (src->ml_tag);
}

u32
match_list_length (const match_list_t * ml)
{
  return (vec_len (ml->ml_rules));
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
