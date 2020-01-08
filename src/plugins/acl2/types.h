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
#ifndef included_acl_types_h
#define included_acl_types_h

#include <vnet/match/match_types.h>

#define foreach_acl_action                      \
  _(DENY, "deny")                               \
  _(PERMIT, "permit")                           \
  _(REFLECT, "reflect")

typedef enum acl_action_t_
{
#define _(a,b) ACL_ACTION_##a,
  foreach_acl_action
#undef _
} __clib_packed acl_action_t;

extern u8 *format_acl_action (u8 * s, va_list * a);
extern uword unformat_acl_action (unformat_input_t * input, va_list * args);

typedef struct acl_rule_t_
{
  acl_action_t action;
  match_rule_t rule;
} acl_rule_t;

extern u8 *format_acl_rule (u8 * s, va_list * a);

#endif // included_acl_types_h

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
