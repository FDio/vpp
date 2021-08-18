/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2025 Cisco Systems, Inc.
 */

#ifndef included_npol_policy_h
#define included_npol_policy_h

#include <npol/npol.h>

typedef struct
{
  /* VLIB_RX for inbound
     VLIB_TX for outbound */
  u32 *rule_ids[VLIB_N_RX_TX];
} npol_policy_t;

typedef struct
{
  u32 rule_id;
  /* VLIB_RX or VLIB_TX */
  u8 direction;
} npol_policy_rule_t;

typedef enum
{
  NPOL_POLICY_QUIET,
  NPOL_POLICY_VERBOSE,
  NPOL_POLICY_ONLY_RX,
  NPOL_POLICY_ONLY_TX,
} npol_policy_format_type_t;

extern npol_policy_t *npol_policies;

int npol_policy_update (u32 *id, npol_policy_rule_t *rules);
int npol_policy_delete (u32 id);
npol_policy_t *npol_policy_get_if_exists (u32 index);

#endif
