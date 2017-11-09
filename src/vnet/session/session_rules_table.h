/*
 * Copyright (c) 2017 Cisco and/or its affiliates.
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

#ifndef SRC_VNET_SESSION_SESSION_RULES_TABLE_H_
#define SRC_VNET_SESSION_SESSION_RULES_TABLE_H_

#include <vnet/vnet.h>
#include <vnet/fib/fib.h>
#include <vnet/session/transport.h>
#include <vnet/session/mma_16.h>
#include <vnet/session/mma_40.h>

/* *INDENT-OFF* */
typedef CLIB_PACKED (struct
{
  union
    {
      struct
        {
          ip4_address_t rmt_ip;
          ip4_address_t lcl_ip;
          u16 rmt_port;
          u16 lcl_port;
        };
      u64 as_u64[2];
    };
}) session_mask_or_match_4_t;

typedef CLIB_PACKED (struct
{
  union
    {
      struct
        {
          ip6_address_t rmt_ip;
          ip6_address_t lcl_ip;
          u16 rmt_port;
          u16 lcl_port;
        };
      u64 as_u64[5];
    };
}) session_mask_or_match_6_t;
/* *INDENT-ON* */

#define SESSION_RULE_TAG_MAX_LEN 64
#define SESSION_RULES_TABLE_INVALID_INDEX MMA_TABLE_INVALID_INDEX
#define SESSION_RULES_TABLE_ACTION_DROP (((u32)~0) - 1)
#define SESSION_RULES_TABLE_ACTION_NONE SESSION_RULES_TABLE_INVALID_INDEX

typedef struct _session_rules_table_add_del_args
{
  fib_prefix_t lcl;
  fib_prefix_t rmt;
  u16 lcl_port;
  u16 rmt_port;
  u32 action_index;
  u8 *tag;
  u8 is_add;
} session_rule_table_add_del_args_t;

typedef struct _rule_tag
{
  u8 *tag;
} session_rule_tag_t;

typedef struct _session_rules_table_t
{
  /**
   * Per fib proto session rules tables
   */
  mma_rules_table_16_t session_rules_tables_16;
  mma_rules_table_40_t session_rules_tables_40;
  /**
   * Hash table that maps tags to rules
   */
  uword *rules_by_tag;
  /**
   * Pool of rules tags
   */
  session_rule_tag_t *rule_tags;
  /**
   * Hash table that maps rule indices to tags
   */
  uword *tags_by_rules;
} session_rules_table_t;

u32 session_rules_table_lookup4 (session_rules_table_t * srt,
				 ip4_address_t * lcl_ip,
				 ip4_address_t * rmt_ip, u16 lcl_port,
				 u16 rmt_port);
u32 session_rules_table_lookup6 (session_rules_table_t * srt,
				 ip6_address_t * lcl_ip,
				 ip6_address_t * rmt_ip, u16 lcl_port,
				 u16 rmt_port);
void session_rules_table_cli_dump (vlib_main_t * vm,
				   session_rules_table_t * srt, u8 fib_proto);
void session_rules_table_show_rule (vlib_main_t * vm,
				    session_rules_table_t * srt,
				    ip46_address_t * lcl_ip, u16 lcl_port,
				    ip46_address_t * rmt_ip, u16 rmt_port,
				    u8 is_ip4);
clib_error_t *session_rules_table_add_del (session_rules_table_t * srt,
					   session_rule_table_add_del_args_t *
					   args);
u8 *session_rules_table_rule_tag (session_rules_table_t * srt, u32 ri,
				  u8 is_ip4);
void session_rules_table_init (session_rules_table_t * srt);
#endif /* SRC_VNET_SESSION_SESSION_RULES_TABLE_H_ */
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
