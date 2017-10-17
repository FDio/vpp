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

#include <vnet/session/session_rules_table.h>
#include <vnet/session/transport.h>

/**
 * Per fib proto and transport proto session rules tables
 */
static session_rules_table_t session_rules_tables[2][TRANSPORT_N_PROTO];

u8 *
format_session_rule (u8 *s, va_list *args)
{
  session_rule_t *sr = va_arg (*args, session_rule_t *);
  s = format (s, "%U %d %U %d", format_ip4_address, &sr->match.lcl_ip,
	      sr->match.lcl_port, format_ip4_address, &sr->match.rmt_ip,
	      sr->match.rmt_port);
  return s;
}

session_rule_t *
session_rules_table_get_rule (session_rules_table_t *srt, u32 srt_index)
{
  if (!pool_is_free_index (srt->rules, srt_index))
    return (srt->rules + srt_index);
  return 0;
}

u8
rule_is_match_for_key (session_mask_or_match_16_t *key, session_rule_t *r)
{
  session_mask_or_match_16_t _tmp_key, *tkp = &_tmp_key;
  int i;

  *tkp = *key;
  for (i = 0; i < ARRAY_LEN(tkp->as_u64); i++)
    tkp->as_u64[i] &= r->mask.as_u64[i];
  for (i = 0; i < ARRAY_LEN(tkp->as_u64); i++)
    {
      if (tkp->as_u64[i] != r->match.as_u64[i])
	  return 0;
    }
  return 1;
}

u32
session_rules_table_lookup (session_rules_table_t * srt,
                            session_mask_or_match_16_t * key, u32 rule_index)
{
  int i;
  session_rule_t *rp;
  u32 rv;

  ASSERT(rule_index != SESSION_RULES_TABLE_INVALID_INDEX);
  rp = session_rules_table_get_rule (srt, rule_index);
  ASSERT (rp);

  if (!rule_is_match_for_key (key, rp))
    return ~0;
  for (i = 0; i < vec_len (rp->next_indices); i++)
    {
      rv = session_rules_table_lookup (srt, key, rp->next_indices[i]);
      if (rv != ~0)
	return (rv);
    }
  return (rp->action_index);
}

session_rules_table_t *
session_rules_table_get (u8 transport_proto, u8 fib_proto)
{
  return &session_rules_tables[fib_proto][transport_proto];
}

u32
session_rules_table_rule_index (session_rules_table_t *srt, session_rule_t *sr)
{
  ASSERT (sr);
  return (sr - srt->rules);
}

u32
session_rules_table_lookup_rule (session_rules_table_t *srt,
                                 session_mask_or_match_16_t *key,
                                 u32 rule_index)
{
  int i;
  session_rule_t *rp;
  u32 rv;

  ASSERT(rule_index != SESSION_RULES_TABLE_INVALID_INDEX);
  rp = session_rules_table_get_rule (srt, rule_index);
  ASSERT(rp);

  if (!rule_is_match_for_key (key, rp))
    return ~0;
  for (i = 0; i < vec_len(rp->next_indices); i++)
    {
      rv = session_rules_table_lookup_rule (srt, key, rp->next_indices[i]);
      if (rv != ~0)
	return (rv);
    }
  return rule_index;
}

int
session_rules_table_add_rule (session_rules_table_t *srt, session_rule_t *rule)
{
  u32 parent_index;
  session_rule_t *parent;

  parent_index = session_rules_table_lookup_rule (srt, &rule->match, srt->root_index);
  parent = session_rules_table_get_rule (srt, parent_index);
  clib_warning ("adding %U as child of %U", format_session_rule, rule, format_session_rule, parent);
  vec_add1 (parent->next_indices, session_rules_table_rule_index (srt, rule));
  return 0;
}

session_rule_t *
session_rule_alloc (session_rules_table_t *srt)
{
  session_rule_t *rule;
  pool_get (srt->rules, rule);
  memset (rule, 0, sizeof (*rule));
  return rule;
}

static u32
ip4_preflen_to_mask (u8 pref_len)
{
  if (pref_len == 0)
    return 0;
  return clib_host_to_net_u32(~((1 << (32 - pref_len)) - 1));
}

static void
fib_pref_normalize (fib_prefix_t *pref)
{
  if (pref->fp_proto == FIB_PROTOCOL_IP4)
    {
      pref->fp_addr.ip4.as_u32 &= ip4_preflen_to_mask (pref->fp_len);
    }
}

session_rule_t *
session_rules_table_alloc_rule (session_rules_table_t *srt,
                                fib_prefix_t *lcl, u16 lcl_port,
                                fib_prefix_t *rmt, u16 rmt_port)
{
  session_rule_t *rule = 0;

  if (rmt->fp_proto == FIB_PROTOCOL_IP4)
    {
      fib_pref_normalize (lcl);
      fib_pref_normalize (rmt);
      rule = session_rule_alloc (srt);
      rule->match.lcl_ip.as_u32 = lcl->fp_addr.ip4.as_u32;
      rule->match.rmt_ip.as_u32 = rmt->fp_addr.ip4.as_u32;
      rule->match.lcl_port = lcl_port;
      rule->match.rmt_port = rmt_port;
      rule->mask.lcl_ip.as_u32 = ip4_preflen_to_mask (lcl->fp_len);
      rule->mask.rmt_ip.as_u32 = ip4_preflen_to_mask (rmt->fp_len);
      rule->mask.rmt_port = rmt_port;
      rule->mask.lcl_port = lcl_port;
    }

  return rule;
}

clib_error_t *
vnet_session_rule_add_del (session_rule_add_del_args_t *args)
{
  session_rules_table_t *srt;
  session_rule_t *rule;
  u8 fib_proto;

  fib_proto = args->lcl.fp_proto;
  srt = session_rules_table_get (args->transport_proto, fib_proto);

  rule = session_rules_table_alloc_rule (srt, &args->lcl, args->lcl_port,
	                                 &args->rmt, args->rmt_port);
  rule->action_index = args->action_index;
  session_rules_table_add_rule (srt, rule);

  return 0;
}

static clib_error_t *
session_rule_command_fn (vlib_main_t * vm, unformat_input_t * input,
                         vlib_cli_command_t * cmd)
{
  u32 proto = ~0, lcl_port, rmt_port, action = 0, lcl_plen, rmt_plen;
  ip46_address_t lcl_ip, rmt_ip;
  u8 is_ip4 = 1, conn_set = 0;
  u8 fib_proto, is_add = 1;

  memset (&lcl_ip, 0, sizeof (lcl_ip));
  memset (&rmt_ip, 0, sizeof (rmt_ip));
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "del"))
	is_add = 0;
      else if (unformat (input, "add"))
	;
      else if (unformat (input, "proto %d", &proto))
	;
      else if (unformat (input, "%U/%d %d %U/%d %d", unformat_ip4_address,
	                 &lcl_ip.ip4, &lcl_plen, &lcl_port,
	                 unformat_ip4_address, &rmt_ip.ip4, &rmt_plen,
	                 &rmt_port))
	{
	  is_ip4 = 1;
	  conn_set = 1;
	}
      else if (unformat (input, "%U/%d %d %U/%d %d", unformat_ip6_address,
	                 &lcl_ip.ip6, &lcl_plen, &lcl_port,
	                 unformat_ip6_address, &rmt_ip.ip6, &rmt_plen,
	                 &rmt_port))
	{
	  is_ip4 = 0;
	  conn_set = 1;
	}
      else if (unformat (input, "action %d", &action))
	;
      else
	return clib_error_return(0, "unknown input `%U'",
	                         format_unformat_error, input);
    }

  if (proto == ~0 || !conn_set || action == ~0)
    return clib_error_return(0, "proto, connection and action must be set");

  fib_proto = is_ip4 ? FIB_PROTOCOL_IP4 : FIB_PROTOCOL_IP6;
  session_rule_add_del_args_t args = {
      .lcl.fp_addr = lcl_ip,
      .lcl.fp_len = lcl_plen,
      .lcl.fp_proto = fib_proto,
      .rmt.fp_addr = rmt_ip,
      .rmt.fp_len = rmt_plen,
      .rmt.fp_proto = fib_proto,
      .lcl_port = lcl_port,
      .rmt_port = rmt_port,
      .action_index = action,
      .is_add = is_add,
  };
  return vnet_session_rule_add_del (&args);
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (session_rule_command, static) =
{
  .path = "session rule",
  .short_help = "session rule [add|del] proto <proto> <lcl-ip/plen> <lcl-port> "
      "<rmt-ip/plen> <rmt-port> action <action>",
  .function = session_rule_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
show_session_rules_command_fn (vlib_main_t * vm, unformat_input_t * input,
                         vlib_cli_command_t * cmd)
{
  session_rules_table_t *srt;
  session_rule_t *sr;

  if (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    return clib_error_return(0, "proto, connection and action must be set");

  srt = session_rules_table_get (TRANSPORT_PROTO_TCP, FIB_PROTOCOL_IP4);

  /* *INDENT-OFF* */
  pool_foreach (sr, srt->rules, ({
    vlib_cli_output (vm, "%U", format_session_rule, sr);
  }));
  /* *INDENT-ON* */
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_session_rules_command, static) =
{
  .path = "show session rules",
  .short_help = "show session rules",
  .function = show_session_rules_command_fn,
};
/* *INDENT-ON* */

clib_error_t *
session_rules_tables_init (vlib_main_t * vm)
{
  session_rules_table_t *srt;
  session_rule_t *rule;
  fib_prefix_t null_prefix;

  memset (&null_prefix, 0, sizeof (null_prefix));

  srt = &session_rules_tables[FIB_PROTOCOL_IP4][TRANSPORT_PROTO_TCP];
  rule = session_rules_table_alloc_rule (srt, &null_prefix, 0, &null_prefix,
                                         0);
  rule->action_index = SESSION_RULES_TABLE_INVALID_INDEX;
  srt->root_index = session_rules_table_rule_index (srt, rule);

  return 0;
}

VLIB_INIT_FUNCTION (session_rules_tables_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

