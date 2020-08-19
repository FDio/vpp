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
#include <capo/capo_rule.h>

capo_rule_t *capo_rules;

capo_rule_t *
capo_rule_alloc ()
{
  capo_rule_t *rule;
  pool_get_zero (capo_rules, rule);
  return rule;
}

capo_rule_t *
capo_rule_get_if_exists (u32 index)
{
  if (pool_is_free_index (capo_rules, index))
    return (NULL);
  return pool_elt_at_index (capo_rules, index);
}

static void
capo_rule_cleanup (capo_rule_t * rule)
{
  int i;
  vec_free (rule->filters);
  for (i = 0; i < CAPO_RULE_MAX_FLAGS; i++)
    {
      vec_free (rule->prefixes[i]);
      vec_free (rule->port_ranges[i]);
      vec_free (rule->ipsets[i]);
    }
}

int
capo_rule_update (u32 * id, capo_rule_action_t action,
		  ip_address_family_t af, capo_rule_filter_t * filters,
		  capo_rule_entry_t * entries)
{
  capo_rule_t *rule;
  capo_rule_entry_t *entry;
  int rv;

  rule = capo_rule_get_if_exists (*id);
  if (rule)
    capo_rule_cleanup (rule);
  else
    rule = capo_rule_alloc ();

  rule->af = af;
  rule->action = action;
  vec_copy (rule->filters, filters);
  vec_foreach (entry, entries)
  {
    u8 flags = entry->flags;
    switch (entry->type)
      {
      case CAPO_CIDR:
	vec_add1 (rule->prefixes[flags], entry->data.cidr);
	break;
      case CAPO_PORT_RANGE:
	vec_add1 (rule->port_ranges[flags], entry->data.port_range);
	break;
      case CAPO_PORT_IP_SET:
      case CAPO_IP_SET:
	vec_add1 (rule->ipsets[flags], entry->data.set_id);
	break;
      default:
	rv = 1;
	goto error;
      }
  }
  *id = rule - capo_rules;
  return 0;
error:
  capo_rule_cleanup (rule);
  pool_put (capo_rules, rule);
  return rv;
}

int
capo_rule_delete (u32 id)
{
  capo_rule_t *rule;
  rule = capo_rule_get_if_exists (id);
  if (NULL == rule)
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  capo_rule_cleanup (rule);
  pool_put (capo_rules, rule);

  return 0;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
