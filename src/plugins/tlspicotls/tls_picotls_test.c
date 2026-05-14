/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2026 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>
#include <vnet/plugin/plugin.h>
#include <tlspicotls/tls_picotls.h>
#include <vpp/app/version.h>

#define TLSP_TEST(_cond, _fmt, _args...)                                                           \
  do                                                                                               \
    {                                                                                              \
      if (!(_cond))                                                                                \
	return clib_error_return (0, "%s:%d: " _fmt, __func__, __LINE__, ##_args);                 \
    }                                                                                              \
  while (0)

static void
tlsp_test_alpn_add_proto (u8 **alpn_list, const char *proto)
{
  u8 proto_len = strlen (proto);

  vec_add1 (*alpn_list, proto_len);
  vec_add (*alpn_list, (u8 *) proto, proto_len);
}

static clib_error_t *
tlsp_test_alpn_iovecs_valid (void)
{
  ptls_iovec_t *iovecs = 0;
  u8 *alpn_list = 0;
  int rv;

  tlsp_test_alpn_add_proto (&alpn_list, "h2");
  tlsp_test_alpn_add_proto (&alpn_list, "http/1.1");

  rv = picotls_alpn_list_to_iovecs (alpn_list, &iovecs);
  TLSP_TEST (rv == 2, "expected 2 protocols, got %d", rv);
  TLSP_TEST (iovecs[0].len == 2, "expected first protocol length 2, got %u", iovecs[0].len);
  TLSP_TEST (!clib_memcmp (iovecs[0].base, "h2", 2), "unexpected first protocol");
  TLSP_TEST (iovecs[1].len == 8, "expected second protocol length 8, got %u", iovecs[1].len);
  TLSP_TEST (!clib_memcmp (iovecs[1].base, "http/1.1", 8), "unexpected second protocol");

  vec_free (iovecs);
  vec_free (alpn_list);
  return 0;
}

static clib_error_t *
tlsp_test_alpn_iovecs_truncated_first (void)
{
  ptls_iovec_t *iovecs = 0;
  u8 *alpn_list = 0;
  int rv;

  vec_add1 (alpn_list, 5);
  vec_add (alpn_list, (u8 *) "h2", 2);

  rv = picotls_alpn_list_to_iovecs (alpn_list, &iovecs);
  TLSP_TEST (rv == -1, "expected malformed list failure, got %d", rv);
  TLSP_TEST (vec_len (iovecs) == 0, "malformed list left iovecs allocated");

  vec_free (iovecs);
  vec_free (alpn_list);
  return 0;
}

static clib_error_t *
tlsp_test_alpn_iovecs_truncated_tail (void)
{
  ptls_iovec_t *iovecs = 0;
  u8 *alpn_list = 0;
  int rv;

  tlsp_test_alpn_add_proto (&alpn_list, "h2");
  vec_add1 (alpn_list, 5);
  vec_add (alpn_list, (u8 *) "h3", 2);

  rv = picotls_alpn_list_to_iovecs (alpn_list, &iovecs);
  TLSP_TEST (rv == -1, "expected malformed tail failure, got %d", rv);
  TLSP_TEST (vec_len (iovecs) == 0, "malformed tail left iovecs allocated");

  vec_free (iovecs);
  vec_free (alpn_list);
  return 0;
}

static clib_error_t *
tlsp_test_alpn_select_server_priority (void)
{
  ptls_iovec_t client_protos[] = {
    { .base = (u8 *) "http/1.1", .len = 8 },
    { .base = (u8 *) "h2", .len = 2 },
  };
  u8 *server_alpn_list = 0, *selected = 0, selected_len = 0;
  int rv;

  tlsp_test_alpn_add_proto (&server_alpn_list, "h2");
  tlsp_test_alpn_add_proto (&server_alpn_list, "http/1.1");

  rv = picotls_select_alpn_proto (server_alpn_list, client_protos, ARRAY_LEN (client_protos),
				  &selected, &selected_len);
  TLSP_TEST (rv == 1, "expected alpn match, got %d", rv);
  TLSP_TEST (selected_len == 2, "expected h2 length, got %u", selected_len);
  TLSP_TEST (!clib_memcmp (selected, "h2", 2), "server priority did not select h2");

  vec_free (server_alpn_list);
  return 0;
}

static clib_error_t *
tlsp_test_alpn_select_no_overlap (void)
{
  ptls_iovec_t client_protos[] = {
    { .base = (u8 *) "h3", .len = 2 },
    { .base = (u8 *) "foo", .len = 3 },
  };
  u8 *server_alpn_list = 0, *selected = 0, selected_len = 0;
  int rv;

  tlsp_test_alpn_add_proto (&server_alpn_list, "h2");
  tlsp_test_alpn_add_proto (&server_alpn_list, "http/1.1");

  rv = picotls_select_alpn_proto (server_alpn_list, client_protos, ARRAY_LEN (client_protos),
				  &selected, &selected_len);
  TLSP_TEST (rv == 0, "expected no alpn match, got %d", rv);
  TLSP_TEST (selected == 0, "no-overlap selected a protocol");
  TLSP_TEST (selected_len == 0, "no-overlap selected length %u", selected_len);

  vec_free (server_alpn_list);
  return 0;
}

static clib_error_t *
tlsp_test_alpn_select_malformed_server_list (void)
{
  ptls_iovec_t client_protos[] = {
    { .base = (u8 *) "h2", .len = 2 },
  };
  u8 *server_alpn_list = 0, *selected = 0, selected_len = 0;
  int rv;

  vec_add1 (server_alpn_list, 5);
  vec_add (server_alpn_list, (u8 *) "h2", 2);

  rv = picotls_select_alpn_proto (server_alpn_list, client_protos, ARRAY_LEN (client_protos),
				  &selected, &selected_len);
  TLSP_TEST (rv == -1, "expected malformed server list failure, got %d", rv);
  TLSP_TEST (selected == 0, "malformed server list selected a protocol");
  TLSP_TEST (selected_len == 0, "malformed server list selected length %u", selected_len);

  vec_free (server_alpn_list);
  return 0;
}

static clib_error_t *
test_tlspicotls_alpn_command_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  struct
  {
    const char *name;
    clib_error_t *(*fn) (void);
  } tests[] = {
    { "iovecs valid list", tlsp_test_alpn_iovecs_valid },
    { "iovecs truncated first protocol", tlsp_test_alpn_iovecs_truncated_first },
    { "iovecs truncated tail protocol", tlsp_test_alpn_iovecs_truncated_tail },
    { "select server priority", tlsp_test_alpn_select_server_priority },
    { "select no overlap", tlsp_test_alpn_select_no_overlap },
    { "select malformed server list", tlsp_test_alpn_select_malformed_server_list },
  };
  clib_error_t *error;
  u32 i;

  for (i = 0; i < ARRAY_LEN (tests); i++)
    {
      vlib_cli_output (vm, "RUN  %s", tests[i].name);
      error = tests[i].fn ();
      if (error)
	{
	  vlib_cli_output (vm, "FAIL %s: %U", tests[i].name, format_clib_error, error);
	  return error;
	}
      vlib_cli_output (vm, "PASS %s", tests[i].name);
    }

  vlib_cli_output (vm, "tlspicotls alpn tests passed");
  return 0;
}

VLIB_CLI_COMMAND (test_tlspicotls_alpn_command, static) = {
  .path = "test tlspicotls alpn",
  .short_help = "test tlspicotls alpn",
  .function = test_tlspicotls_alpn_command_fn,
};

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "Picotls TLS unit tests",
  .default_disabled = 1,
};
