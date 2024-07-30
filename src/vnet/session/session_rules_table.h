/*
 * Copyright (c) 2017-2019 Cisco and/or its affiliates.
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
#include <vnet/session/session_types.h>
#include <vnet/session/transport.h>
#include <vnet/session/mma_16.h>
#include <vnet/session/mma_40.h>

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

#define SESSION_RULE_TAG_MAX_LEN 64
#define SESSION_RULES_TABLE_INVALID_INDEX MMA_TABLE_INVALID_INDEX
#define SESSION_RULES_TABLE_ACTION_DROP (MMA_TABLE_INVALID_INDEX - 1)
#define SESSION_RULES_TABLE_ACTION_ALLOW (MMA_TABLE_INVALID_INDEX - 2)

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

typedef struct session_sdl_block
{
  u32 ip_table_id;
  u32 ip6_table_id;
  u32 ip_fib_index;
  u32 ip6_fib_index;
} session_sdl_block_t;

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

  /**
   * sdl table
   */
  session_sdl_block_t sdl_block;
} session_rules_table_t;

session_error_t
session_rules_table_add_del_ (session_rules_table_t *srt,
			      session_rule_table_add_del_args_t *args);
u8 *session_rules_table_rule_tag (session_rules_table_t * srt, u32 ri,
				  u8 is_ip4);
void session_rules_table_init_ (session_rules_table_t *srt, u8 fib_proto,
				const u8 *ns_id, u8 is_local);
void session_rules_table_free_ (session_rules_table_t *srt, u8 fib_proto);

typedef u32 (*rules_table_lookup4) (session_rules_table_t *srt,
				    ip4_address_t *lcl_ip,
				    ip4_address_t *rmt_ip, u16 lcl_port,
				    u16 rmt_port);
typedef u32 (*rules_table_lookup6) (session_rules_table_t *srt,
				    ip6_address_t *lcl_ip,
				    ip6_address_t *rmt_ip, u16 lcl_port,
				    u16 rmt_port);
typedef void (*rules_table_cli_dump) (vlib_main_t *vm,
				      session_rules_table_t *srt,
				      u8 fib_proto);
typedef void (*rules_table_show_rule) (vlib_main_t *vm,
				       session_rules_table_t *srt,
				       ip46_address_t *lcl_ip, u16 lcl_port,
				       ip46_address_t *rmt_ip, u16 rmt_port,
				       u8 is_ip4);
typedef session_error_t (*rules_table_add_del) (
  session_rules_table_t *srt, session_rule_table_add_del_args_t *args);
typedef void (*rules_table_init) (session_rules_table_t *srt, u8 fib_proto,
				  const u8 *ns_id, u8 is_local);
typedef void (*rules_table_free) (session_rules_table_t *srt, u8 fib_proto);

#define foreach_session_engine_vft_method_name                                \
  _ (lookup4)                                                                 \
  _ (lookup6)                                                                 \
  _ (cli_dump)                                                                \
  _ (show_rule)                                                               \
  _ (add_del)                                                                 \
  _ (init)                                                                    \
  _ (free)

#define _(name) rules_table_##name table_##name;
typedef struct session_engine_vft
{
  u32 backend_engine;
  foreach_session_engine_vft_method_name
} session_engine_vft_t;
#undef _

extern u8 *format_session_rule_tag (u8 *s, va_list *args);
extern u8 *session_rules_table_rule_tag (session_rules_table_t *srt, u32 ri,
					 u8 is_ip4);
extern u32 session_rules_table_rule_for_tag (session_rules_table_t *srt,
					     u8 *tag);
extern void session_rules_table_add_tag (session_rules_table_t *srt, u8 *tag,
					 u32 rule_index, u8 is_ip4);
extern void session_rules_table_del_tag (session_rules_table_t *srt, u8 *tag,
					 u8 is_ip4);

extern const session_engine_vft_t *session_engine_vft;
extern clib_error_t *session_rules_table_enable_disable (int enable);

static_always_inline void
session_rules_table_init (session_rules_table_t *srt, u8 fib_proto,
			  const u8 *ns_id, u8 is_local)
{
  if (!session_engine_vft)
    return;
  session_engine_vft->table_init (srt, fib_proto, ns_id, is_local);

  if (srt->rules_by_tag == 0)
    srt->rules_by_tag = hash_create_vec (0, sizeof (u8), sizeof (uword));
  if (srt->tags_by_rules == 0)
    srt->tags_by_rules = hash_create (0, sizeof (uword));
}

static_always_inline void
session_rules_table_free (session_rules_table_t *srt, u8 fib_proto)
{
  if (!session_engine_vft)
    return;
  session_engine_vft->table_free (srt, fib_proto);

  hash_free (srt->tags_by_rules);
  hash_free (srt->rules_by_tag);
}

static_always_inline void
session_rules_table_show_rule (vlib_main_t *vm, session_rules_table_t *srt,
			       ip46_address_t *lcl_ip, u16 lcl_port,
			       ip46_address_t *rmt_ip, u16 rmt_port, u8 is_ip4)
{
  if (!session_engine_vft)
    return;
  session_engine_vft->table_show_rule (vm, srt, lcl_ip, lcl_port, rmt_ip,
				       rmt_port, is_ip4);
}

static_always_inline u32
session_rules_table_lookup6 (session_rules_table_t *srt, ip6_address_t *lcl_ip,
			     ip6_address_t *rmt_ip, u16 lcl_port, u16 rmt_port)
{
  if (!session_engine_vft)
    return SESSION_RULES_TABLE_INVALID_INDEX;
  return session_engine_vft->table_lookup6 (srt, lcl_ip, rmt_ip, lcl_port,
					    rmt_port);
}

static_always_inline void
session_rules_table_cli_dump (vlib_main_t *vm, session_rules_table_t *srt,
			      u8 fib_proto)
{
  if (!session_engine_vft)
    return;
  session_engine_vft->table_cli_dump (vm, srt, fib_proto);
}

static_always_inline u32
session_rules_table_lookup4 (session_rules_table_t *srt, ip4_address_t *lcl_ip,
			     ip4_address_t *rmt_ip, u16 lcl_port, u16 rmt_port)
{
  if (!session_engine_vft)
    return SESSION_RULES_TABLE_INVALID_INDEX;
  return session_engine_vft->table_lookup4 (srt, lcl_ip, rmt_ip, lcl_port,
					    rmt_port);
}

static_always_inline session_error_t
session_rules_table_add_del (session_rules_table_t *srt,
			     session_rule_table_add_del_args_t *args)
{
  if (!session_engine_vft)
    return SESSION_E_NOSUPPORT;
  return session_engine_vft->table_add_del (srt, args);
}

#endif /* SRC_VNET_SESSION_SESSION_RULES_TABLE_H_ */
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
