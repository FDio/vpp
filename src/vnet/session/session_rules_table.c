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

#include <vnet/session/session_rules_table_16.h>
#include <vnet/session/session_rules_table_template.c>

#include <vnet/session/session_rules_table_40.h>
#include <vnet/session/session_rules_table_template.c>

#include <vnet/session/session_rules_table.h>
#include <vnet/session/transport.h>

/**
 * Per fib proto and transport proto session rules tables
 */
static session_rules_table_16_t session_rules_tables_16[TRANSPORT_N_PROTO];
static session_rules_table_40_t session_rules_tables_40[TRANSPORT_N_PROTO];

static void
fib_pref_normalize (fib_prefix_t * pref)
{
  if (pref->fp_proto == FIB_PROTOCOL_IP4)
    ip4_address_normalize (&pref->fp_addr.ip4, pref->fp_len);
  else
    ip6_address_normalize (&pref->fp_addr.ip6, pref->fp_len);
}

u8 *
format_session_rule4 (u8 * s, va_list * args)
{
  session_rules_table_16_t *srt = va_arg (*args, session_rules_table_16_t *);
  session_rule_16_t *sr = va_arg (*args, session_rule_16_t *);
  session_mask_or_match_4_t *mask, *match;
  int i;

  match = (session_mask_or_match_4_t *) & sr->match;
  mask = (session_mask_or_match_4_t *) & sr->mask;

  s = format (s, "[%d] rule: %U/%d %d %U/%d %d action: %d",
	      session_rules_table_rule_index_16 (srt, sr), format_ip4_address,
	      &match->lcl_ip,
	      ip4_mask_to_preflen (&mask->lcl_ip),
	      match->lcl_port, format_ip4_address, &match->rmt_ip,
	      ip4_mask_to_preflen (&mask->rmt_ip),
	      match->rmt_port, sr->action_index);
  if (vec_len (sr->next_indices))
    {
      s = format (s, "\n    children: ");
      for (i = 0; i < vec_len (sr->next_indices); i++)
	s = format (s, "%d ", sr->next_indices[i]);
    }
  return s;
}

u8 *
format_session_rule6 (u8 * s, va_list * args)
{
  session_rules_table_40_t *srt = va_arg (*args, session_rules_table_40_t *);
  session_rule_40_t *sr = va_arg (*args, session_rule_40_t *);
  session_mask_or_match_6_t *mask, *match;
  int i;

  match = (session_mask_or_match_6_t *) & sr->match;
  mask = (session_mask_or_match_6_t *) & sr->mask;

  s = format (s, "[%d] rule: %U/%d %d %U/%d %d action: %d",
	      session_rules_table_rule_index_40 (srt, sr), format_ip6_address,
	      &match->lcl_ip, ip6_mask_to_preflen (&mask->lcl_ip),
	      match->lcl_port, format_ip6_address, &match->rmt_ip,
	      ip6_mask_to_preflen (&mask->rmt_ip), match->rmt_port,
	      sr->action_index);
  if (vec_len (sr->next_indices))
    {
      s = format (s, "\n    children: ");
      for (i = 0; i < vec_len (sr->next_indices); i++)
	s = format (s, "%d ", sr->next_indices[i]);
    }
  return s;
}

void
session_rules_table_cli_dump (vlib_main_t *vm, u8 fib_proto,
                              u8 transport_proto)
{
  if (fib_proto == FIB_PROTOCOL_IP4)
    {
      session_rules_table_16_t *srt4;
      session_rule_16_t *sr4;
      srt4 = session_rules_table_get (transport_proto, FIB_PROTOCOL_IP4);
      /* *INDENT-OFF* */
      pool_foreach(sr4, srt4->rules, ({
	vlib_cli_output (vm, "%U", format_session_rule4, srt4, sr4);
      }));
      /* *INDENT-ON* */
    }
  else if (fib_proto == FIB_PROTOCOL_IP6)
    {
      session_rules_table_40_t *srt6;
      session_rule_40_t *sr6;
      srt6 = session_rules_table_get (transport_proto, FIB_PROTOCOL_IP6);
      /* *INDENT-OFF* */
      pool_foreach (sr6, srt6->rules, ({
        vlib_cli_output (vm, "%U", format_session_rule6, srt6, sr6);
      }));
    }
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

int
rule_cmp_16 (session_rule_16_t * rule1, session_rule_16_t * rule2)
{
  session_mask_or_match_4_t *m1, *m2;

  m1 = (session_mask_or_match_4_t *) & rule1->max_match;
  m2 = (session_mask_or_match_4_t *) & rule2->max_match;
  if (m1->rmt_ip.as_u32 != m2->rmt_ip.as_u32)
    return (m1->rmt_ip.as_u32 < m2->rmt_ip.as_u32 ? -1 : 1);
  if (m1->lcl_ip.as_u32 != m2->lcl_ip.as_u32)
    return (m1->lcl_ip.as_u32 < m2->lcl_ip.as_u32 ? -1 : 1);
  if (m1->rmt_port != m2->rmt_port)
    return (m1->rmt_port < m2->rmt_port ? -1 : 1);
  if (m1->lcl_port != m2->lcl_port)
    return (m1->lcl_port < m2->lcl_port ? -1 : 1);
  return 0;
}

int
rule_cmp_40 (session_rule_40_t * rule1, session_rule_40_t * rule2)
{
  session_mask_or_match_6_t *r1, *r2;
  r1 = (session_mask_or_match_6_t *) &rule1->max_match;
  r2 = (session_mask_or_match_6_t *) &rule2->max_match;
  if (r1->rmt_ip.as_u64[0] != r2->rmt_ip.as_u64[0])
    return (r1->rmt_ip.as_u64[0] < r2->rmt_ip.as_u64[0] ? -1 : 1);
  if (r1->rmt_ip.as_u64[1] != r2->rmt_ip.as_u64[1])
    return (r1->rmt_ip.as_u64[1] < r2->rmt_ip.as_u64[1] ? -1 : 1);
  if (r1->lcl_ip.as_u64[0] != r2->lcl_ip.as_u64[0])
    return (r1->lcl_ip.as_u64[0] < r2->lcl_ip.as_u64[0] ? -1 : 1);
  if (r1->lcl_ip.as_u64[1] != r2->lcl_ip.as_u64[1])
    return (r1->lcl_ip.as_u64[1] < r2->lcl_ip.as_u64[1]) ? -1 : 1;
  if (r1->rmt_port != r2->rmt_port)
    return (r1->rmt_port < r2->rmt_port ? -1 : 1);
  if (r1->lcl_port != r2->lcl_port)
    return (r1->lcl_port < r2->lcl_port ? -1 : 1);
  return 0;
}

void
session_rules_table_init_rule_16 (session_rule_16_t * rule,
				  fib_prefix_t * lcl, u16 lcl_port,
				  fib_prefix_t * rmt, u16 rmt_port)
{
  session_mask_or_match_4_t *match, *mask, *max_match;
  fib_pref_normalize (lcl);
  fib_pref_normalize (rmt);
  match = (session_mask_or_match_4_t *) & rule->match;
  match->lcl_ip.as_u32 = lcl->fp_addr.ip4.as_u32;
  match->rmt_ip.as_u32 = rmt->fp_addr.ip4.as_u32;
  match->lcl_port = lcl_port;
  match->rmt_port = rmt_port;
  mask = (session_mask_or_match_4_t *) & rule->mask;
  ip4_preflen_to_mask (lcl->fp_len, &mask->lcl_ip);
  ip4_preflen_to_mask (rmt->fp_len, &mask->rmt_ip);
  mask->lcl_port = lcl_port == 0 ? 0 : (u16) ~ 0;
  mask->rmt_port = rmt_port == 0 ? 0 : (u16) ~ 0;
  max_match = (session_mask_or_match_4_t *) & rule->max_match;
  ip4_prefix_max_address_host_order (&rmt->fp_addr.ip4, rmt->fp_len,
                                     &max_match->rmt_ip);
  ip4_prefix_max_address_host_order (&lcl->fp_addr.ip4, lcl->fp_len,
                                     &max_match->lcl_ip);
  max_match->lcl_port = lcl_port == 0 ? (u16)~0 : lcl_port;
  max_match->rmt_port = rmt_port == 0 ? (u16)~0 : rmt_port;
}

void
session_rules_table_init_rule_40 (session_rule_40_t * rule,
				  fib_prefix_t * lcl, u16 lcl_port,
				  fib_prefix_t * rmt, u16 rmt_port)
{
  session_mask_or_match_6_t *match, *mask, *max_match;
  rmt_port = rmt_port == ~0 ? 0 : rmt_port;
  lcl_port = lcl_port == ~0 ? 0 : lcl_port;
  fib_pref_normalize (lcl);
  fib_pref_normalize (rmt);
  match = (session_mask_or_match_6_t *) & rule->match;
  clib_memcpy (&match->lcl_ip, &lcl->fp_addr.ip6, sizeof (match->lcl_ip));
  clib_memcpy (&match->rmt_ip, &rmt->fp_addr.ip6, sizeof (match->rmt_ip));
  match->lcl_port = lcl_port;
  match->rmt_port = rmt_port;
  mask = (session_mask_or_match_6_t *) & rule->mask;
  ip6_preflen_to_mask (lcl->fp_len, &mask->lcl_ip);
  ip6_preflen_to_mask (rmt->fp_len, &mask->rmt_ip);
  mask->lcl_port = lcl_port == 0 ? 0 : (u16) ~ 0;
  mask->rmt_port = rmt_port == 0 ? 0 : (u16) ~ 0;
  max_match = (session_mask_or_match_6_t *) & rule->max_match;
  ip6_prefix_max_address_host_order (&rmt->fp_addr.ip6, rmt->fp_len,
                                     &max_match->rmt_ip);
  ip6_prefix_max_address_host_order (&lcl->fp_addr.ip6, lcl->fp_len,
                                     &max_match->lcl_ip);
  max_match->lcl_port = lcl_port == 0 ? (u16)~0 : lcl_port;
  max_match->rmt_port = rmt_port == 0 ? (u16)~0 : rmt_port;
}

session_rule_16_t *
session_rules_table_alloc_rule_16 (session_rules_table_16_t * srt,
				   fib_prefix_t * lcl, u16 lcl_port,
				   fib_prefix_t * rmt, u16 rmt_port)
{
  session_rule_16_t *rule = 0;
  rule = session_rule_alloc_16 (srt);
  session_rules_table_init_rule_16 (rule, lcl, lcl_port, rmt, rmt_port);
  return rule;
}

session_rule_40_t *
session_rules_table_alloc_rule_40 (session_rules_table_40_t * srt,
				   fib_prefix_t * lcl, u16 lcl_port,
				   fib_prefix_t * rmt, u16 rmt_port)
{
  session_rule_40_t *rule;
  rule = session_rule_alloc_40 (srt);
  session_rules_table_init_rule_40 (rule, lcl, lcl_port, rmt, rmt_port);
  return rule;
}

clib_error_t *
vnet_session_rule_add_del (session_rule_add_del_args_t * args)
{
  u8 fib_proto = args->rmt.fp_proto;

  if (fib_proto == FIB_PROTOCOL_IP4)
    {
      session_rules_table_16_t *srt;
      srt = session_rules_table_get (args->transport_proto, fib_proto);
      if (args->is_add)
	{
	  session_rule_16_t *rule;
	  rule = session_rules_table_alloc_rule_16 (srt, &args->lcl,
						    args->lcl_port,
						    &args->rmt,
						    args->rmt_port);
	  rule->action_index = args->action_index;
	  session_rules_table_add_rule_16 (srt, rule);
	}
      else
	{
	  session_rule_16_t rule;
	  memset (&rule, 0, sizeof (rule));
	  session_rules_table_init_rule_16 (&rule, &args->lcl, args->lcl_port,
					    &args->rmt, args->rmt_port);
	  session_rules_table_del_rule_16 (srt, &rule, srt->root_index);
	}
    }
  else if (fib_proto == FIB_PROTOCOL_IP6)
    {
      session_rules_table_40_t *srt;
      session_rule_40_t *rule;
      srt = session_rules_table_get (args->transport_proto, fib_proto);
      if (args->is_add)
	{
	  rule = session_rules_table_alloc_rule_40 (srt, &args->lcl,
						    args->lcl_port,
						    &args->rmt,
						    args->rmt_port);
	  rule->action_index = args->action_index;
	  session_rules_table_add_rule_40 (srt, rule);
	}
      else
	{
	  session_rule_40_t rule;
	  memset (&rule, 0, sizeof (rule));
	  session_rules_table_init_rule_40 (&rule, &args->lcl, args->lcl_port,
					    &args->rmt, args->rmt_port);
	  session_rules_table_del_rule_40 (srt, &rule, srt->root_index);
	}
    }

  return 0;
}

u32
session_rules_table_lookup4 (u8 transport_proto, ip4_address_t * lcl_ip,
			     ip4_address_t * rmt_ip, u16 lcl_port,
			     u16 rmt_port)
{
  session_rules_table_16_t *srt;
  srt = session_rules_table_get (transport_proto, FIB_PROTOCOL_IP4);
  session_mask_or_match_4_t key = {
    .lcl_ip.as_u32 = lcl_ip->as_u32,
    .rmt_ip.as_u32 = rmt_ip->as_u32,
    .lcl_port = lcl_port,
    .rmt_port = rmt_port,
  };
  return session_rules_table_lookup_16 (srt,
					(session_mask_or_match_16_t *) & key,
					srt->root_index);
}

u32
session_rules_table_lookup6 (u8 transport_proto, ip6_address_t * lcl_ip,
			     ip6_address_t * rmt_ip, u16 lcl_port,
			     u16 rmt_port)
{
  session_rules_table_40_t *srt;
  srt = session_rules_table_get (transport_proto, FIB_PROTOCOL_IP6);
  session_mask_or_match_6_t key = {
    .lcl_port = lcl_port,
    .rmt_port = rmt_port,
  };
  clib_memcpy (&key.lcl_ip, &lcl_ip, sizeof (&lcl_ip));
  clib_memcpy (&key.rmt_ip, &rmt_ip, sizeof (&rmt_ip));
  return session_rules_table_lookup_40 (srt,
					(session_mask_or_match_40_t *) & key,
					srt->root_index);
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
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }

  if (proto == ~0 || !conn_set || action == ~0)
    return clib_error_return (0, "proto, connection and action must be set");

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
      if (unformat (input, "%U", unformat_transport_proto, &transport_proto))
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
	  session_mask_or_match_4_t key = {
	    .lcl_ip.as_u32 = lcl_ip.ip4.as_u32,
	    .rmt_ip.as_u32 = rmt_ip.ip4.as_u32,
	    .lcl_port = lcl_port,
	    .rmt_port = rmt_port,
	  };
	  ri =
	    session_rules_table_lookup_rule_16 (srt4,
						(session_mask_or_match_16_t *)
						& key, srt4->root_index);
	  sr4 = session_rules_table_get_rule_16 (srt4, ri);
	  vlib_cli_output (vm, "%U", format_session_rule4, srt4, sr4);
	}
      else
	{
	  srt6 = session_rules_table_get (transport_proto, FIB_PROTOCOL_IP6);
	  session_mask_or_match_6_t key = {
	    .lcl_port = lcl_port,
	    .rmt_port = rmt_port,
	  };
	  clib_memcpy (&key.lcl_ip, &lcl_ip.ip6, sizeof (&lcl_ip.ip6));
	  clib_memcpy (&key.rmt_ip, &rmt_ip.ip6, sizeof (&rmt_ip.ip6));
	  ri =
	    session_rules_table_lookup_rule_40 (srt6,
						(session_mask_or_match_40_t *)
						& key, srt6->root_index);
	  sr6 = session_rules_table_get_rule_40 (srt6, ri);
	  vlib_cli_output (vm, "%U", format_session_rule6, srt6, sr6);
	}
      return 0;
    }

  vlib_cli_output (vm, "%U IP4 rules table", format_transport_proto,
		   transport_proto);
  session_rules_table_cli_dump (vm, FIB_PROTOCOL_IP4, TRANSPORT_PROTO_TCP);

  vlib_cli_output (vm, "\n%U IP6 rules table", format_transport_proto,
		   transport_proto);
  session_rules_table_cli_dump (vm, FIB_PROTOCOL_IP6, TRANSPORT_PROTO_TCP);

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

  memset (&null_prefix, 0, sizeof (null_prefix));

  for (i = 0; i < TRANSPORT_N_PROTO; i++)
    {
      srt4 = &session_rules_tables_16[i];
      rule4 =
	session_rules_table_alloc_rule_16 (srt4, &null_prefix, 0,
					   &null_prefix, 0);
      rule4->action_index = SESSION_RULES_TABLE_INVALID_INDEX;
      srt4->root_index = session_rules_table_rule_index_16 (srt4, rule4);
      srt4->rule_cmp_fn = rule_cmp_16;
    }

  for (i = 0; i < TRANSPORT_N_PROTO; i++)
    {
      srt6 = &session_rules_tables_40[i];
      rule6 =
	session_rules_table_alloc_rule_40 (srt6, &null_prefix, 0,
					   &null_prefix, 0);
      rule6->action_index = SESSION_RULES_TABLE_INVALID_INDEX;
      srt6->root_index = session_rules_table_rule_index_40 (srt6, rule6);
      srt6->rule_cmp_fn = rule_cmp_40;
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
