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

#ifndef included_capo_policy_h
#define included_capo_policy_h

#include <capo/capo.h>

typedef struct
{
  /* VLIB_RX for inbound
     VLIB_TX for outbound */
  u32 *rule_ids[VLIB_N_RX_TX];
} capo_policy_t;

typedef struct
{
  u32 rule_id;
  /* VLIB_RX or VLIB_TX */
  u8 direction;
} capo_policy_rule_t;

extern capo_policy_t *capo_policies;

int capo_policy_update (u32 *id, capo_policy_rule_t *rules);
int capo_policy_delete (u32 id);

#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
