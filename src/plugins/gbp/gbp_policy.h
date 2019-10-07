/*
 * Copyright (c) 2018 Cisco and/or its affiliates.
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

#ifndef __GBP_POLICY_H__
#define __GBP_POLICY_H__

#include <plugins/gbp/gbp_contract.h>

/**
 * per-packet trace data
 */
typedef struct gbp_policy_trace_t_
{
  /* per-pkt trace data */
  gbp_scope_t scope;
  sclass_t sclass;
  sclass_t dclass;
  gbp_rule_action_t action;
  u32 flags;
  u32 acl_match;
  u32 rule_match;
} gbp_policy_trace_t;

/* packet trace format function */
u8 * format_gbp_policy_trace (u8 * s, va_list * args);

static_always_inline void
gbp_policy_trace(vlib_main_t * vm, vlib_node_runtime_t * node, vlib_buffer_t *b, const gbp_contract_key_t *key, gbp_rule_action_t action, u32 acl_match, u32 rule_match)
{
  gbp_policy_trace_t *t;

  if (PREDICT_TRUE (!(b->flags & VLIB_BUFFER_IS_TRACED)))
    return;

  t = vlib_add_trace (vm, node, b, sizeof (*t));
  t->sclass = key->gck_src;
  t->dclass = key->gck_dst;
  t->scope = key->gck_scope;
  t->action = action;
  t->flags = vnet_buffer2 (b)->gbp.flags;
  t->acl_match = acl_match;
  t->rule_match = rule_match;
}

#endif /* __GBP_POLICY_H__ */
