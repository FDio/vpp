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
u8 *format_npol_policy (u8 *s, va_list *args);
npol_policy_t *npol_policy_get_if_exists (u32 index);

#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
