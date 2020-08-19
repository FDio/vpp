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


#include <capo/capo.h>
#include <capo/capo_policy.h>

capo_policy_t *capo_policies;

static capo_policy_t *
capo_policy_alloc ()
{
  capo_policy_t *policy;
  pool_get_zero (capo_policies, policy);
  return policy;
}

static capo_policy_t *
capo_policy_get_if_exists (u32 index)
{
  if (pool_is_free_index (capo_policies, index))
    return (NULL);
  return pool_elt_at_index (capo_policies, index);
}

static void
capo_policy_cleanup (capo_policy_t * policy)
{
  for (int i = 0; i < VLIB_N_RX_TX; i++)
    vec_free (policy->rule_ids[i]);
}

int
capo_policy_update (u32 * id, capo_policy_rule_t * rules)
{
  capo_policy_t *policy;
  capo_policy_rule_t *rule;

  policy = capo_policy_get_if_exists (*id);
  if (policy)
    capo_policy_cleanup (policy);
  else
    policy = capo_policy_alloc ();

  vec_foreach (rule, rules)
    vec_add1 (policy->rule_ids[rule->direction], rule->rule_id);

  *id = policy - capo_policies;
  return 0;
}

int
capo_policy_delete (u32 id)
{
  capo_policy_t *policy;
  policy = capo_policy_get_if_exists (id);
  if (NULL == policy)
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  capo_policy_cleanup (policy);
  pool_put (capo_policies, policy);

  return 0;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
