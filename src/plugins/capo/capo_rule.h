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

#ifndef included_capo_rule_h
#define included_capo_rule_h

#include <capo/capo.h>

typedef vl_api_capo_rule_action_t capo_rule_action_t;
typedef vl_api_capo_entry_type_t capo_entry_type_t;
typedef vl_api_capo_rule_filter_type_t capo_rule_filter_type_t;

typedef struct capo_rule_filter_
{
  capo_rule_filter_type_t type;
  /* Content to filter against */
  u32 value;
  /* If true match packet.property == opaque, else packet.property != opaque */
  u8 should_match;
} capo_rule_filter_t;

typedef union capo_entry_data_t_
{
  ip_prefix_t cidr;
  capo_port_range_t port_range;
  u32 set_id;
} capo_entry_data_t;

typedef enum capo_rule_key_flag_
{
  CAPO_IS_SRC = 1 << 0,
  CAPO_IS_NOT = 1 << 1,
  CAPO_RULE_MAX_FLAGS = 1 << 2,
} capo_rule_key_flag_t;


#define CAPO_SRC        CAPO_IS_SRC
#define CAPO_NOT_SRC    (CAPO_IS_SRC | CAPO_IS_NOT)
#define CAPO_DST        0
#define CAPO_NOT_DST    CAPO_IS_NOT

typedef struct capo_rule_entry_t_
{
  capo_entry_type_t type;
  capo_entry_data_t data;
  capo_rule_key_flag_t flags;
} capo_rule_entry_t;

typedef struct capo_rule_
{
  ip_address_family_t af;
  capo_rule_action_t action;

  capo_rule_filter_t *filters;

  /* Indexed by capo_rule_key_flag_t */
  ip_prefix_t *prefixes[CAPO_RULE_MAX_FLAGS];
  u32 *ip_ipsets[CAPO_RULE_MAX_FLAGS];
  capo_port_range_t *port_ranges[CAPO_RULE_MAX_FLAGS];
  u32 *ipport_ipsets[CAPO_RULE_MAX_FLAGS];
} capo_rule_t;

extern capo_rule_t *capo_rules;

int capo_rule_delete (u32 id);
int capo_rule_update (u32 * id, capo_rule_action_t action,
		      ip_address_family_t af, capo_rule_filter_t * filters,
		      capo_rule_entry_t * entries);

#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
