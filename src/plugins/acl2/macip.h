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

#ifndef __MACIP_H__
#define __MACIP_H__

#include <vnet/match/match_set.h>

/**
 * Actions to perform once we match on a macip rule
 */
typedef enum macip_action_t_
{
  MACIP_ACTION_PERMIT,
  MACIP_ACTION_DENY,
} macip_action_t;

extern u8 *format_macip_action (u8 * s, va_list * args);

typedef struct macip_acl_match_t_
{
  match_list_t ml;
  index_t msi;
  match_handle_t mh_list;
  macip_action_t *actions;
  match_set_app_t *apps;
} macip_acl_match_t;

typedef struct macip_acl_t_
{
  u8 *tag;
  macip_acl_match_t matches[VNET_LINK_NUM];
} macip_acl_t;

extern u8 *format_macip_acl (u8 * s, va_list * args);


#define FOR_EACH_MACIP_LINK(_acl, _linkt, _mam, _body)   \
{                                                        \
    FOR_EACH_VNET_LINK(_linkt) {                         \
        _mam = &_acl->matches[_linkt];                   \
        _body;                                           \
    }                                                    \
}

#define FOR_EACH_MACIP_LINK_W_RULES(_acl, _linkt, _mam, _body)  \
{                                                               \
    FOR_EACH_VNET_LINK(_linkt) {                                \
        _mam = &_acl->matches[_linkt];                          \
        if (match_list_length(&mam->ml)) {                      \
            _body;                                              \
        }                                                       \
    }                                                           \
}

#define FOR_EACH_MACIP_IP_LINK_W_RULES(_acl, _linkt, _mam, _body)  \
{                                                                  \
    FOR_EACH_VNET_IP_LINK(_linkt) {                                \
        _mam = &_acl->matches[_linkt];                             \
        if (match_list_length(&mam->ml)) {                         \
            _body;                                                 \
        }                                                          \
    }                                                              \
}

typedef struct macip_acl_main_t
{
  /* Pool of MAC-IP ACLs */
  macip_acl_t *macip_acls;

  /* match-set applications per-link-type and per-sw_if_index */
  match_set_app_t *macip_match_apps_by_sw_if_index[VNET_LINK_NUM];

  /* MACIP (input) ACLs associated with the interfaces */
  u32 *macip_acl_by_sw_if_index;

  /* Vector of interfaces on which given MACIP ACLs are applied */
  u32 **sw_if_index_vec_by_macip_acl;
} macip_acl_main_t;

extern macip_acl_main_t macip_acl_main;

// FIXME
struct _vl_api_macip2_acl_rule;

extern int macip_acl_add_list (u32 count,
			       struct _vl_api_macip2_acl_rule *rules,
			       u32 * acl_list_index, u8 * tag);
extern int macip_acl_del_list (u32 acl_list_index);

extern int macip_acl_interface_add_del_acl (u32 sw_if_index,
					    u8 is_add, u32 macip_acl_index);

#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
