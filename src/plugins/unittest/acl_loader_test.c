/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 FastNetMon
 */

#include <vlib/vlib.h>
#include <plugins/acl/exports.h>

#define ACL_LOADER_TEST(_cond, _comment, _args...)                                                 \
  {                                                                                                \
    if (!(_cond))                                                                                  \
      {                                                                                            \
	vlib_cli_output (vm, "FAIL:%d: " _comment, __LINE__, ##_args);                             \
	return 1;                                                                                  \
      }                                                                                            \
    vlib_cli_output (vm, "PASS:%d: " _comment, __LINE__, ##_args);                                 \
  }

static void
acl_loader_test_rule (acl_rule_t *r, u8 is_permit, u32 dst, u8 plen)
{
  clib_memset (r, 0, sizeof (*r));
  r->is_permit = is_permit;
  r->dst.ip4.as_u32 = clib_host_to_net_u32 (dst);
  r->dst_prefixlen = plen;
  r->src_port_or_type_last = 65535;
  r->dst_port_or_code_last = 65535;
}

static int
acl_loader_test_run (vlib_main_t *vm)
{
  acl_plugin_add_replace_rules_fn_t add_replace;
  acl_plugin_methods_t m;
  acl_main_t *am;
  acl_rule_t *rules = 0;
  u32 acl_index = ~0, bad_index = ~0;
  u8 long_tag[sizeof (am->acls->tag) + 1];
  clib_error_t *err;
  int rv;

  if ((err = acl_plugin_exports_init (&m)))
    {
      clib_error_report (err);
      return 1;
    }
  am = m.p_acl_main;
  add_replace = vlib_get_plugin_symbol ("acl_plugin.so", "acl_plugin_add_replace_rules");
  ACL_LOADER_TEST (add_replace != 0, "acl_plugin_add_replace_rules is exported");

  vec_validate (rules, 1);
  acl_loader_test_rule (&rules[0], 1, 0x0a000000, 24);
  acl_loader_test_rule (&rules[1], 0, 0x0a000000, 16);
  rv = add_replace (&acl_index, rules, (u8 *) "acl-loader-test");
  ACL_LOADER_TEST (rv == 0 && acl_index != ~0 && vec_len (am->acls[acl_index].rules) == 2,
		   "loader creates an ACL with two rules (index %u)", acl_index);

  rules[0].is_permit = 0;
  ACL_LOADER_TEST (am->acls[acl_index].rules[0].is_permit == 1,
		   "the ACL keeps its own copy of the rules");

  vec_set_len (rules, 1);
  acl_loader_test_rule (&rules[0], 0, 0x0a000000, 8);
  rv = add_replace (&acl_index, rules, (u8 *) "acl-loader-test");
  ACL_LOADER_TEST (rv == 0 && vec_len (am->acls[acl_index].rules) == 1 &&
		     am->acls[acl_index].rules[0].dst_prefixlen == 8,
		   "loader replaces the rules of an existing ACL");

  acl_loader_test_rule (&rules[0], 1, 0x0a000000, 33);
  ACL_LOADER_TEST (add_replace (&bad_index, rules, (u8 *) "bad") != 0 && bad_index == ~0,
		   "loader rejects an IPv4 prefix length of 33");
  acl_loader_test_rule (&rules[0], 1, 0x0a000000, 24);
  rules[0].dst_port_or_code_first = 81;
  rules[0].dst_port_or_code_last = 80;
  ACL_LOADER_TEST (add_replace (&bad_index, rules, (u8 *) "bad") != 0,
		   "loader rejects an inverted port range");
  rules[0].dst_port_or_code_first = 0;
  bad_index = 1 << 30;
  ACL_LOADER_TEST (add_replace (&bad_index, rules, (u8 *) "bad") != 0,
		   "loader rejects replacing an ACL that does not exist");
  clib_memset (long_tag, 'x', sizeof (long_tag) - 1);
  long_tag[sizeof (long_tag) - 1] = 0;
  bad_index = ~0;
  ACL_LOADER_TEST (add_replace (&bad_index, rules, long_tag) != 0,
		   "loader rejects a tag that does not fit");

  vec_free (rules);
  return 0;
}

static clib_error_t *
acl_loader_test (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  if (acl_loader_test_run (vm))
    return clib_error_return (0, "acl loader unit test failed");
  return 0;
}

VLIB_CLI_COMMAND (acl_loader_test_command, static) = {
  .path = "test acl-loader",
  .short_help = "unit test of the ACL rule loader",
  .function = acl_loader_test,
};
