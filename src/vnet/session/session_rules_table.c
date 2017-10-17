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
static session_rules_table_t *session_rules_tables[2][TRANSPORT_N_PROTO];

u32
session_rules_table_eval_rule (session_rules_table_t * srt,
                               session_mask_or_match_16_t * key, u32 rule_index)
{
  int i, j;
  session_mask_or_match_16_t _tmp_key, *tkp = &_tmp_key;
  session_rule_t *rp;
  u32 rv;

  ASSERT(rule_index != ~0);

  rp = pool_elt_at_index(srt->rules, rule_index);

  *tkp = *key;
  for (i = 0; i < ARRAY_LEN(tkp->as_u64); i++)
    tkp->as_u64[i] &= rp->mask.as_u64[i];

  for (i = 0; i < ARRAY_LEN(tkp->as_u64); i++)
    {
      if (tkp->as_u64[i] != rp->match.as_u64[i])
	{
	  for (j = 0; j < vec_len(rp->next_indices); j++)
	    {
	      rv = session_rules_table_eval_rule (srt, key, rp->next_indices[j]);
	      if (rv != ~0)
		return (rv);
	    }
	  return ~0;
	}
    }
  return (rp->action_index);
}

session_rules_table_t *
session_rules_table_get (u8 transport_proto, u8 fib_proto)
{
  return session_rules_tables[fib_proto][transport_proto];
}

void
session_rules_table_add (session_rules_table_t *srt, session_rule_t *rule)
{

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
  return ~((1 << (32 - pref_len)) - 1);
}

session_rule_t *
session_rules_table_alloc_rule (session_rules_table_t *srt,
                                fib_prefix_t *lcl, u16 lcl_port,
                                fib_prefix_t *rmt, u16 rmt_port)
{
  session_rule_t *rule = 0;

  if (lcl->fp_proto == FIB_PROTOCOL_IP4)
    {
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
  srt = session_rules_table_get (args->proto, fib_proto);

  rule = session_rules_table_alloc_rule (srt, &args->lcl, args->lcl_port,
	                                 &args->rmt, args->rmt_port);
  session_rules_table_add (srt, rule);

  return 0;
}

static clib_error_t *
session_rule_command_fn (vlib_main_t * vm, unformat_input_t * input,
                         vlib_cli_command_t * cmd)
{
  u32 proto = ~0, lcl_port, rmt_port, action = 0;
  ip46_address_t lcl_ip, rmt_ip;
  u8 is_ip4 = 1, conn_set = 0;
  u8 fib_proto;

  memset (&lcl_ip, 0, sizeof (lcl_ip));
  memset (&rmt_ip, 0, sizeof (rmt_ip));
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "proto %d", &proto))
	;
      if (unformat (input, "%d %U %d %U %d", unformat_ip4_address,
                    &lcl_ip.ip4, &lcl_port, unformat_ip4_address,
                    &rmt_ip.ip4, &rmt_port))
	{
	  is_ip4 = 1;
	  conn_set = 1;
	}
      if (unformat (input, "%d %U %d %U %d", unformat_ip6_address,
                    &lcl_ip.ip6, &lcl_port, unformat_ip6_address,
                    &rmt_ip.ip6, &rmt_port))
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
      .lcl.fp_proto = fib_proto,
      .rmt.fp_addr = rmt_ip,
      .rmt.fp_proto = fib_proto,
      .lcl_port = lcl_port,
      .rmt_port = rmt_port,
  };
  return vnet_session_rule_add_del (&args);
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (session_rule_command, static) =
{
  .path = "session rule",
  .short_help = "session rule [del] proto <proto> <lcl-ip/plen> <lcl-port> "
      "<rmt-ip/plen> <rmt-port> action <action>",
  .function = session_rule_command_fn,
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

