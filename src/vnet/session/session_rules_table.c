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

#define SESSION_RT_TYPE 16
#include <vnet/session/session_rules_table_template.h>
#include <vnet/session/session_rules_table_template.c>

#undef SRC_VNET_SESSION_SESSION_RULES_TABLE_TEMPLATE_H_
#undef SESSION_RT_TYPE
#define SESSION_RT_TYPE 40
#include <vnet/session/session_rules_table_template.h>
#include <vnet/session/session_rules_table_template.c>

#include <vnet/session/session_rules_table.h>
#include <vnet/session/transport.h>

/**
 * Per fib proto and transport proto session rules tables
 */
static session_rules_table_16_t session_rules_tables_16[TRANSPORT_N_PROTO];
static session_rules_table_40_t session_rules_tables_40[TRANSPORT_N_PROTO];

static u32
ip4_preflen_to_mask (u8 pref_len)
{
  if (pref_len == 0)
    return 0;
  return clib_host_to_net_u32(~((1 << (32 - pref_len)) - 1));
}

u32
ip4_mask_to_preflen (u32 mask)
{
  return (32 - log2_first_set (mask));
}

static void
ip6_preflen_to_mask (u8 pref_len, ip6_address_t *mask)
{
  if (pref_len == 0)
    {
      mask->as_u64[0] = 0;
      mask->as_u64[1] = 0;
    }
  else if (pref_len <= 64)
    {
      mask->as_u64[0] = clib_host_to_net_u64 (
	  0xffffffffffffffffL << (64 - pref_len));
      mask->as_u64[1] = 0;
    }
  else
    {
      mask->as_u64[1] = clib_host_to_net_u64 (
		0xffffffffffffffffL << (128 - pref_len));
    }
}

u32
ip6_mask_to_preflen (ip6_address_t *mask)
{
  u8 first1, first0;
  if (mask->as_u64[0] == 0 && mask->as_u64[1] == 0)
    return 128;
  first1 = log2_first_set (mask->as_u64[1]);
  first0 = log2_first_set (mask->as_u64[0]);

  if (first1 != 0)
    return 128 - first1;
  else
    return 64 - first0;
}

static void
fib_pref_normalize (fib_prefix_t *pref)
{
  if (pref->fp_proto == FIB_PROTOCOL_IP4)
    ip4_address_normalize (&pref->fp_addr.ip4, pref->fp_len);
  else
    ip6_address_normalize (&pref->fp_addr.ip6, pref->fp_len);
}

u8 *
format_session_rule4 (u8 *s, va_list *args)
{
  session_rules_table_16_t *srt = va_arg (*args, session_rules_table_16_t *);
  session_rule_16_t *sr = va_arg (*args, session_rule_16_t *);
  session_mask_or_match_4_t *mask, *match;
  int i;

  match = (session_mask_or_match_4_t *) &sr->match;
  mask = (session_mask_or_match_4_t *) &sr->mask;

  s = format (s, "[%d] rule: %U/%d %d %U/%d %d action: %d",
	      session_rules_table_rule_index_16 (srt, sr), format_ip4_address,
	      &match->lcl_ip,
	      ip4_mask_to_preflen (clib_net_to_host_u32 (mask->lcl_ip.as_u32)),
	      match->lcl_port, format_ip4_address, &match->rmt_ip,
	      ip4_mask_to_preflen (clib_net_to_host_u32 (mask->rmt_ip.as_u32)),
	      match->rmt_port, sr->action_index);
  if (vec_len(sr->next_indices))
    {
      s = format (s, "\n    children: ");
      for (i = 0; i < vec_len(sr->next_indices); i++)
	s = format (s, "%d ", sr->next_indices[i]);
    }
  return s;
}

u8 *
format_session_rule6 (u8 *s, va_list *args)
{
  session_rules_table_40_t *srt = va_arg (*args, session_rules_table_40_t *);
  session_rule_40_t *sr = va_arg (*args, session_rule_40_t *);
  session_mask_or_match_6_t *mask, *match;
  int i;

  match = (session_mask_or_match_6_t *)&sr->match;
  mask = (session_mask_or_match_6_t *)&sr->mask;

  s = format (s, "[%d] rule: %U/%d %d %U/%d %d action: %d",
	      session_rules_table_rule_index_40 (srt, sr), format_ip6_address,
	      &match->lcl_ip, ip6_mask_to_preflen (&mask->lcl_ip),
	      match->lcl_port, format_ip6_address, &match->rmt_ip,
	      ip6_mask_to_preflen (&mask->rmt_ip), match->rmt_port,
	      sr->action_index);
  if (vec_len(sr->next_indices))
    {
      s = format (s, "\n    children: ");
      for (i = 0; i < vec_len(sr->next_indices); i++)
	s = format (s, "%d ", sr->next_indices[i]);
    }
  return s;
}

void *
session_rules_table_get (u8 transport_proto, u8 fib_proto)
{
  if (fib_proto == FIB_PROTOCOL_IP4)
    return &session_rules_tables_16[transport_proto];
  else if (fib_proto == FIB_PROTOCOL_IP6)
    return &session_rules_tables_40[transport_proto];
  return 0;
}

session_rule_16_t *
session_rules_table_alloc_rule_16 (session_rules_table_16_t *srt,
                                   fib_prefix_t *lcl, u16 lcl_port,
                                   fib_prefix_t *rmt, u16 rmt_port)
{
  session_rule_16_t *rule = 0;
  session_mask_or_match_4_t *match, *mask;
  rmt_port = rmt_port == ~0 ? 0 : rmt_port;
  lcl_port = lcl_port == ~0 ? 0 : lcl_port;
  fib_pref_normalize (lcl);
  fib_pref_normalize (rmt);
  rule = session_rule_alloc_16 (srt);
  match = (session_mask_or_match_4_t *)&rule->match;
  match->lcl_ip.as_u32 = lcl->fp_addr.ip4.as_u32;
  match->rmt_ip.as_u32 = rmt->fp_addr.ip4.as_u32;
  match->lcl_port = lcl_port;
  match->rmt_port = rmt_port;
  mask = (session_mask_or_match_4_t *)&rule->mask;
  mask->lcl_ip.as_u32 = ip4_preflen_to_mask (lcl->fp_len);
  mask->rmt_ip.as_u32 = ip4_preflen_to_mask (rmt->fp_len);
  mask->rmt_port = rmt_port;
  mask->lcl_port = lcl_port;
  return rule;
}

session_rule_40_t *
session_rules_table_alloc_rule_40 (session_rules_table_40_t *srt,
                                   fib_prefix_t *lcl, u16 lcl_port,
                                   fib_prefix_t *rmt, u16 rmt_port)
{
  session_rule_40_t *rule;
  session_mask_or_match_6_t *match, *mask;
  rmt_port = rmt_port == ~0 ? 0 : rmt_port;
  lcl_port = lcl_port == ~0 ? 0 : lcl_port;
  fib_pref_normalize (lcl);
  fib_pref_normalize (rmt);
  rule = session_rule_alloc_40 (srt);
  match = (session_mask_or_match_6_t *)&rule->match;
  clib_memcpy (&match->lcl_ip, &lcl->fp_addr.ip6, sizeof (match->lcl_ip));
  clib_memcpy (&match->rmt_ip, &rmt->fp_addr.ip6, sizeof (match->rmt_ip));
  match->lcl_port = lcl_port;
  match->rmt_port = rmt_port;
  mask = (session_mask_or_match_6_t *)&rule->mask;
  ip6_preflen_to_mask (lcl->fp_len, &mask->lcl_ip);
  ip6_preflen_to_mask (rmt->fp_len, &mask->rmt_ip);
  mask->rmt_port = rmt_port;
  mask->lcl_port = lcl_port;
  return rule;
}

clib_error_t *
vnet_session_rule_add_del (session_rule_add_del_args_t *args)
{
  u8 fib_proto;

  fib_proto = args->rmt.fp_proto;
  if (fib_proto == FIB_PROTOCOL_IP4)
    {
      session_rules_table_16_t *srt;
      session_rule_16_t *rule;
      srt = session_rules_table_get (args->transport_proto, fib_proto);
      rule = session_rules_table_alloc_rule_16 (srt, &args->lcl,
                                                args->lcl_port, &args->rmt,
                                                args->rmt_port);
      rule->action_index = args->action_index;
      session_rules_table_add_rule_16 (srt, rule);
    }
  else if (fib_proto == FIB_PROTOCOL_IP6)
    {
      session_rules_table_40_t *srt;
      session_rule_40_t *rule;
      srt = session_rules_table_get (args->transport_proto, fib_proto);
      rule = session_rules_table_alloc_rule_40 (srt, &args->lcl,
                                                args->lcl_port, &args->rmt,
                                                args->rmt_port);
      rule->action_index = args->action_index;
      session_rules_table_add_rule_40 (srt, rule);
    }

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
      else if (unformat (input, "proto %U", unformat_transport_proto, &proto))
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
  u32 transport_proto = ~0, lcl_port, rmt_port, lcl_plen, rmt_plen, ri;
  ip46_address_t lcl_ip, rmt_ip;
  u8 is_ip4 = 1, show_one = 0;
  session_rules_table_16_t *srt4;
  session_rules_table_40_t *srt6;
  session_rule_16_t *sr4;
  session_rule_40_t *sr6;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%U", unformat_transport_proto,
	            &transport_proto))
	;
      else if (unformat (input, "%U/%d %d %U/%d %d", unformat_ip4_address,
	                 &lcl_ip.ip4, &lcl_plen, &lcl_port,
	                 unformat_ip4_address, &rmt_ip.ip4, &rmt_plen,
	                 &rmt_port))
	{
	  is_ip4 = 1;
	  show_one = 1;
	}
      else if (unformat (input, "%U/%d %d %U/%d %d", unformat_ip6_address,
	                 &lcl_ip.ip6, &lcl_plen, &lcl_port,
	                 unformat_ip6_address, &rmt_ip.ip6, &rmt_plen,
	                 &rmt_port))
	{
	  is_ip4 = 0;
	  show_one = 1;
	}
    }

  if (show_one)
    {
      if (is_ip4)
	{
	  srt4 = session_rules_table_get (transport_proto, FIB_PROTOCOL_IP4);
          ip4_address_normalize (&lcl_ip.ip4, lcl_plen);
          ip4_address_normalize (&rmt_ip.ip4, rmt_plen);
          session_mask_or_match_4_t key = {
              .lcl_ip.as_u32 = lcl_ip.ip4.as_u32,
              .rmt_ip.as_u32 = rmt_ip.ip4.as_u32,
              .lcl_port = lcl_port,
              .rmt_port = rmt_port,
          };
	  ri = session_rules_table_lookup_rule_16 (
	      srt4, (session_mask_or_match_16_t *) &key, srt4->root_index);
          sr4 = session_rules_table_get_rule_16 (srt4, ri);
          vlib_cli_output (vm, "%U", format_session_rule4, srt4, sr4);
	}
      else
	{
	  srt6 = session_rules_table_get (transport_proto, FIB_PROTOCOL_IP6);
          ip6_address_normalize (&lcl_ip.ip6, lcl_plen);
          ip6_address_normalize (&rmt_ip.ip6, rmt_plen);
          session_mask_or_match_6_t key = {
              .lcl_port = lcl_port,
              .rmt_port = rmt_port,
          };
          clib_memcpy (&key.lcl_ip, &lcl_ip.ip6, sizeof (&lcl_ip.ip6));
          clib_memcpy (&key.rmt_ip, &rmt_ip.ip6, sizeof (&rmt_ip.ip6));
	  ri = session_rules_table_lookup_rule_40 (
	      srt6, (session_mask_or_match_40_t *) &key, srt6->root_index);
          sr6 = session_rules_table_get_rule_40 (srt6, ri);
          vlib_cli_output (vm, "%U", format_session_rule6, srt6, sr6);
	}
      return 0;
    }

  vlib_cli_output (vm, "%U IP4 rules table", format_transport_proto,
	           transport_proto);
  srt4 = session_rules_table_get (transport_proto, FIB_PROTOCOL_IP4);
  /* *INDENT-OFF* */
  pool_foreach (sr4, srt4->rules, ({
    vlib_cli_output (vm, "%U", format_session_rule4, srt4, sr4);
  }));
  /* *INDENT-ON* */

  vlib_cli_output (vm, "%U IP6 rules table", format_transport_proto,
	           transport_proto);
  srt6 = session_rules_table_get (transport_proto, FIB_PROTOCOL_IP6);
  /* *INDENT-OFF* */
  pool_foreach (sr6, srt6->rules, ({
    vlib_cli_output (vm, "%U", format_session_rule6, srt6, sr6);
  }));
  /* *INDENT-ON* */
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_session_rules_command, static) =
{
  .path = "show session rules",
  .short_help = "show session rules [proto <proto> <lcl-ip/plen> <lcl-port> "
      "<rmt-ip/plen> <rmt-port>]",
  .function = show_session_rules_command_fn,
};
/* *INDENT-ON* */

clib_error_t *
session_rules_tables_init (vlib_main_t * vm)
{
  session_rules_table_16_t *srt4;
  session_rules_table_40_t *srt6;
  session_rule_16_t *rule4;
  session_rule_40_t *rule6;
  fib_prefix_t null_prefix;
  int i;

  memset(&null_prefix, 0, sizeof(null_prefix));

  for (i = 0; i < TRANSPORT_N_PROTO; i++)
    {
      srt4 = &session_rules_tables_16[i];
      rule4 = session_rules_table_alloc_rule_16 (srt4, &null_prefix, 0,
	                                         &null_prefix, 0);
      rule4->action_index = SESSION_RULES_TABLE_INVALID_INDEX;
      srt4->root_index = session_rules_table_rule_index_16 (srt4, rule4);
    }

  for (i = 0; i < TRANSPORT_N_PROTO; i++)
    {
      srt6 = &session_rules_tables_40[i];
      rule6 = session_rules_table_alloc_rule_40 (srt6, &null_prefix, 0,
	                                         &null_prefix, 0);
      rule6->action_index = SESSION_RULES_TABLE_INVALID_INDEX;
      srt6->root_index = session_rules_table_rule_index_40 (srt6, rule6);
    }

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

