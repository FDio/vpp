/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 FastNetMon
 */

#include <vlib/vlib.h>
#include <plugins/acl/exports.h>

#define ACL_HOOK_TEST(_cond, _comment, _args...)                                                   \
  {                                                                                                \
    if (!(_cond))                                                                                  \
      {                                                                                            \
	vlib_cli_output (vm, "FAIL:%d: " _comment, __LINE__, ##_args);                             \
	return 1;                                                                                  \
      }                                                                                            \
    vlib_cli_output (vm, "PASS:%d: " _comment, __LINE__, ##_args);                                 \
  }

typedef struct
{
  u32 reject_mask;
  u32 n_calls;
} acl_hook_test_ctx_t;

static int
acl_hook_test_check (void *ctx, u32 acl_index, u32 rule_index)
{
  acl_hook_test_ctx_t *c = ctx;

  c->n_calls++;
  return !(c->reject_mask & (1 << rule_index));
}

static void
acl_hook_test_rule (acl_rule_t *r, u8 is_permit, u32 dst, u8 plen, u8 proto, u16 dport_first,
		    u16 dport_last)
{
  clib_memset (r, 0, sizeof (*r));
  r->is_permit = is_permit;
  r->dst.ip4.as_u32 = clib_host_to_net_u32 (dst);
  r->dst_prefixlen = plen;
  r->proto = proto;
  r->src_port_or_type_last = 65535;
  r->dst_port_or_code_first = dport_first;
  r->dst_port_or_code_last = dport_last;
}

static u32
acl_hook_test_match (acl_plugin_methods_t *m, u32 lc_index, u32 dst, u16 dport, int nonfirst,
		     acl_hook_test_ctx_t *c)
{
  acl_plugin_match_check_t chk = { .fn = acl_hook_test_check, .ctx = c };
  fa_5tuple_t t = {};
  u32 pos, acl_index, rule_index, trace = 0;
  u8 action;

  t.ip4_addr[0].as_u32 = clib_host_to_net_u32 (0x01020304);
  t.ip4_addr[1].as_u32 = clib_host_to_net_u32 (dst);
  t.l4.proto = IP_PROTOCOL_UDP;
  if (nonfirst)
    t.pkt.is_nonfirst_fragment = 1;
  else
    {
      t.l4.port[0] = 1234;
      t.l4.port[1] = dport;
      t.pkt.l4_valid = 1;
    }
  if (!acl_plugin_match_5tuple_check_inline (m->p_acl_main, lc_index, (fa_5tuple_opaque_t *) &t, 0,
					     &action, &pos, &acl_index, &rule_index, &trace,
					     c ? &chk : 0))
    return ~0;
  return rule_index;
}

static int
acl_hook_test_lookups (vlib_main_t *vm, acl_plugin_methods_t *m, u32 lc_index, const char *path)
{
  acl_hook_test_ctx_t c = {};
  int nonfirst;

  for (nonfirst = 0; nonfirst < 2; nonfirst++)
    {
      const char *pkt = nonfirst ? "non-initial fragment" : "first fragment";

      ACL_HOOK_TEST (acl_hook_test_match (m, lc_index, 0x0a000001, 80, nonfirst, 0) == 0,
		     "%s %s: no callback matches rule 0", path, pkt);
      c = (acl_hook_test_ctx_t) {};
      ACL_HOOK_TEST (acl_hook_test_match (m, lc_index, 0x0a000001, 80, nonfirst, &c) == 0 &&
		       c.n_calls > 0,
		     "%s %s: accepting callback keeps rule 0", path, pkt);
      c = (acl_hook_test_ctx_t) { .reject_mask = 1 << 0 };
      ACL_HOOK_TEST (acl_hook_test_match (m, lc_index, 0x0a000001, 80, nonfirst, &c) == 1,
		     "%s %s: rejecting rule 0 falls through to rule 1", path, pkt);
      c = (acl_hook_test_ctx_t) { .reject_mask = (1 << 0) | (1 << 1) };
      ACL_HOOK_TEST (acl_hook_test_match (m, lc_index, 0x0a000001, 80, nonfirst, &c) == 2,
		     "%s %s: rejecting rules 0 and 1 falls through to rule 2", path, pkt);
      c = (acl_hook_test_ctx_t) { .reject_mask = ~0 };
      ACL_HOOK_TEST (acl_hook_test_match (m, lc_index, 0x0a000001, 80, nonfirst, &c) == ~0,
		     "%s %s: rejecting every rule gives no match", path, pkt);
    }
  return 0;
}

static int
acl_hook_test_run (vlib_main_t *vm)
{
  acl_plugin_add_replace_rules_fn_t add_replace;
  acl_plugin_methods_t m;
  acl_main_t *am;
  acl_rule_t *rules = 0;
  u32 acl_index = ~0, *acls = 0;
  u32 user_id;
  int lc_index, use_hash, rv;
  clib_error_t *err;

  if ((err = acl_plugin_exports_init (&m)))
    {
      clib_error_report (err);
      return 1;
    }
  add_replace = vlib_get_plugin_symbol ("acl_plugin.so", "acl_plugin_add_replace_rules");
  ACL_HOOK_TEST (add_replace != 0, "acl_plugin_add_replace_rules is exported");
  am = m.p_acl_main;

  vec_validate (rules, 2);
  acl_hook_test_rule (&rules[0], 1, 0x0a000000, 24, IP_PROTOCOL_UDP, 80, 80);
  acl_hook_test_rule (&rules[1], 0, 0x0a000000, 16, IP_PROTOCOL_UDP, 0, 65535);
  acl_hook_test_rule (&rules[2], 1, 0, 0, 0, 0, 65535);
  rv = add_replace (&acl_index, rules, (u8 *) "acl-lookup-hook-test");
  ACL_HOOK_TEST (rv == 0 && acl_index != ~0, "loader creates an ACL (index %u)", acl_index);

  user_id = m.register_user_module ("acl lookup hook test", "test", 0);
  lc_index = m.get_lookup_context_index (user_id, 0, 0);
  ACL_HOOK_TEST (lc_index >= 0, "lookup context allocated");
  vec_add1 (acls, acl_index);
  m.set_acl_vec_for_context (lc_index, acls);

  use_hash = am->use_hash_acl_matching;
  am->use_hash_acl_matching = 1;
  rv = acl_hook_test_lookups (vm, &m, lc_index, "hash");
  am->use_hash_acl_matching = 0;
  if (!rv)
    rv = acl_hook_test_lookups (vm, &m, lc_index, "linear");
  am->use_hash_acl_matching = use_hash;

  if (!rv)
    {
      vec_reset_length (rules);
      vec_validate (rules, 0);
      acl_hook_test_rule (&rules[0], 0, 0x0a000000, 8, 0, 0, 65535);
      rv = add_replace (&acl_index, rules, (u8 *) "acl-lookup-hook-test");
      if (rv == 0 && acl_hook_test_match (&m, lc_index, 0x0a000001, 80, 0, 0) == 0)
	vlib_cli_output (vm, "PASS:%d: loader replaces an applied ACL", __LINE__);
      else
	{
	  vlib_cli_output (vm, "FAIL:%d: loader replaces an applied ACL", __LINE__);
	  rv = 1;
	}
    }

  vec_reset_length (acls);
  m.set_acl_vec_for_context (lc_index, acls);
  m.put_lookup_context_index (lc_index);
  vec_free (acls);
  vec_free (rules);
  return rv;
}

static clib_error_t *
acl_lookup_hook_test (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  if (acl_hook_test_run (vm))
    return clib_error_return (0, "acl lookup hook unit test failed");
  return 0;
}

VLIB_CLI_COMMAND (acl_lookup_hook_test_command, static) = {
  .path = "test acl-lookup-hook",
  .short_help = "unit test of the ACL rule loader and candidate callback",
  .function = acl_lookup_hook_test,
};
