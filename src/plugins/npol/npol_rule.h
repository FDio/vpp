/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2025 Cisco Systems, Inc.
 */

#ifndef included_npol_rule_h
#define included_npol_rule_h

#include <npol/npol.h>

typedef vl_api_npol_rule_action_t npol_rule_action_t;
typedef vl_api_npol_entry_type_t npol_entry_type_t;
typedef vl_api_npol_rule_filter_type_t npol_rule_filter_type_t;

typedef struct npol_rule_filter_
{
  npol_rule_filter_type_t type;
  /* Content to filter against */
  u32 value;
  /* If true match packet.property == opaque, else packet.property != opaque */
  u8 should_match;
} npol_rule_filter_t;

typedef union npol_entry_data_t_
{
  ip_prefix_t cidr;
  npol_port_range_t port_range;
  u32 set_id;
} npol_entry_data_t;

typedef enum npol_rule_key_flag_
{
  NPOL_IS_SRC = 1 << 0,
  NPOL_IS_NOT = 1 << 1,
  NPOL_RULE_MAX_FLAGS = 1 << 2,
} npol_rule_key_flag_t;

#define NPOL_SRC     NPOL_IS_SRC
#define NPOL_NOT_SRC (NPOL_IS_SRC | NPOL_IS_NOT)
#define NPOL_DST     0
#define NPOL_NOT_DST NPOL_IS_NOT

typedef struct npol_rule_entry_t_
{
  npol_entry_type_t type;
  npol_entry_data_t data;
  npol_rule_key_flag_t flags;
} npol_rule_entry_t;

typedef struct npol_rule_
{
  npol_rule_action_t action;

  npol_rule_filter_t *filters;

  /* Indexed by npol_rule_key_flag_t */
  ip_prefix_t *prefixes[NPOL_RULE_MAX_FLAGS];
  u32 *ip_ipsets[NPOL_RULE_MAX_FLAGS];
  npol_port_range_t *port_ranges[NPOL_RULE_MAX_FLAGS];
  u32 *ipport_ipsets[NPOL_RULE_MAX_FLAGS];
} npol_rule_t;

extern npol_rule_t *npol_rules;

int npol_rule_delete (u32 id);
int npol_rule_update (u32 *id, npol_rule_action_t action,
		      npol_rule_filter_t *filters, npol_rule_entry_t *entries);
npol_rule_t *npol_rule_get_if_exists (u32 index);
npol_rule_entry_t *npol_rule_get_entries (npol_rule_t *rule);

#endif
