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
#ifndef __ACL_TYPES_H__
#define __ACL_TYPES_H__

#include <vnet/match/match_types.h>

#define foreach_acl2_action                     \
  _(DENY, "deny")                               \
  _(PERMIT, "permit")

typedef enum acl2_action_t_
{
#define _(a,b) ACL2_ACTION_##a,
  foreach_acl2_action
#undef _
} __clib_packed acl2_action_t;

extern u8 *format_acl2_action (u8 * s, va_list * a);
extern uword unformat_acl2_action (unformat_input_t * input, va_list * args);

typedef struct ace2_t_
{
  acl2_action_t ace_action;
  match_rule_t ace_rule;
} ace2_t;

extern u8 *format_ace2 (u8 * s, va_list * a);

/*
 * ACL
 */
typedef struct acl2_t_
{
  match_type_t acl_mtype;
  match_orientation_t acl_mo;
  u8 acl_tag[64];
  index_t *acl_aces;
} acl2_t;

#define FOR_EACH_ACE(_acl, _ace, _body)                         \
{                                                               \
  index_t *_acei;                                               \
  vec_foreach(_acei, _acl->acl_aces)                            \
    {                                                           \
      _ace = pool_elt_at_index(acl2_main.ace_pool, *_acei);     \
      _body;                                                    \
    }                                                           \
}

#define FOR_EACH_ACE_INDEX(_acl, _acei)        \
  vec_foreach(_acei, _acl->acl_aces)

extern u8 *format_acl2 (u8 * s, va_list * a);

#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
