/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2024 Cisco Systems, Inc.
 */

#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>
#include <http/http.h>

#define HTTP_TEST_I(_cond, _comment, _args...)                                \
  ({                                                                          \
    int _evald = (_cond);                                                     \
    if (!(_evald))                                                            \
      {                                                                       \
	vlib_cli_output (vm, "FAIL:%d: " _comment "\n", __LINE__, ##_args);   \
      }                                                                       \
    else                                                                      \
      {                                                                       \
	vlib_cli_output (vm, "PASS:%d: " _comment "\n", __LINE__, ##_args);   \
      }                                                                       \
    _evald;                                                                   \
  })

#define HTTP_TEST(_cond, _comment, _args...)                                  \
  {                                                                           \
    if (!HTTP_TEST_I (_cond, _comment, ##_args))                              \
      {                                                                       \
	return 1;                                                             \
      }                                                                       \
  }

static int
http_test_parse_authority (vlib_main_t *vm)
{
  u8 *authority = 0, *formated = 0;
  http_uri_authority_t parsed;
  int rv;

  /* IPv4 address */
  authority = format (0, "10.10.2.45:20");
  rv = http_parse_authority (authority, vec_len (authority), &parsed);
  HTTP_TEST ((rv == 0), "'%v' should be valid", authority);
  HTTP_TEST ((parsed.host_type == HTTP_URI_HOST_TYPE_IP4),
	     "host_type=%d should be %d", parsed.host_type,
	     HTTP_URI_HOST_TYPE_IP4);
  HTTP_TEST ((clib_net_to_host_u16 (parsed.port) == 20),
	     "port=%u should be 20", clib_net_to_host_u16 (parsed.port));
  formated = http_serialize_authority (&parsed);
  rv = vec_cmp (authority, formated);
  HTTP_TEST ((rv == 0), "'%v' should match '%v'", authority, formated);
  vec_free (authority);
  vec_free (formated);

  authority = format (0, "10.255.2.1");
  rv = http_parse_authority (authority, vec_len (authority), &parsed);
  HTTP_TEST ((rv == 0), "'%v' should be valid", authority);
  HTTP_TEST ((parsed.host_type == HTTP_URI_HOST_TYPE_IP4),
	     "host_type=%d should be %d", parsed.host_type,
	     HTTP_URI_HOST_TYPE_IP4);
  HTTP_TEST ((parsed.port == 0), "port=%u should be 0", parsed.port);
  formated = http_serialize_authority (&parsed);
  rv = vec_cmp (authority, formated);
  HTTP_TEST ((rv == 0), "'%v' should match '%v'", authority, formated);
  vec_free (authority);
  vec_free (formated);

  /* IPv6 address */
  authority = format (0, "[dead:beef::1234]:443");
  rv = http_parse_authority (authority, vec_len (authority), &parsed);
  HTTP_TEST ((rv == 0), "'%v' should be valid", authority);
  HTTP_TEST ((parsed.host_type == HTTP_URI_HOST_TYPE_IP6),
	     "host_type=%d should be %d", parsed.host_type,
	     HTTP_URI_HOST_TYPE_IP6);
  HTTP_TEST ((clib_net_to_host_u16 (parsed.port) == 443),
	     "port=%u should be 443", clib_net_to_host_u16 (parsed.port));
  formated = http_serialize_authority (&parsed);
  rv = vec_cmp (authority, formated);
  HTTP_TEST ((rv == 0), "'%v' should match '%v'", authority, formated);
  vec_free (authority);
  vec_free (formated);

  /* registered name */
  authority = format (0, "example.com:80");
  rv = http_parse_authority (authority, vec_len (authority), &parsed);
  HTTP_TEST ((rv == 0), "'%v' should be valid", authority);
  HTTP_TEST ((parsed.host_type == HTTP_URI_HOST_TYPE_REG_NAME),
	     "host_type=%d should be %d", parsed.host_type,
	     HTTP_URI_HOST_TYPE_REG_NAME);
  HTTP_TEST ((clib_net_to_host_u16 (parsed.port) == 80),
	     "port=%u should be 80", clib_net_to_host_u16 (parsed.port));
  formated = http_serialize_authority (&parsed);
  rv = vec_cmp (authority, formated);
  HTTP_TEST ((rv == 0), "'%v' should match '%v'", authority, formated);
  vec_free (authority);
  vec_free (formated);

  authority = format (0, "3xample.com:80");
  rv = http_parse_authority (authority, vec_len (authority), &parsed);
  HTTP_TEST ((rv == 0), "'%v' should be valid", authority);
  HTTP_TEST ((parsed.host_type == HTTP_URI_HOST_TYPE_REG_NAME),
	     "host_type=%d should be %d", parsed.host_type,
	     HTTP_URI_HOST_TYPE_REG_NAME);
  HTTP_TEST ((clib_net_to_host_u16 (parsed.port) == 80),
	     "port=%u should be 80", clib_net_to_host_u16 (parsed.port));
  formated = http_serialize_authority (&parsed);
  rv = vec_cmp (authority, formated);
  HTTP_TEST ((rv == 0), "'%v' should match '%v'", authority, formated);
  vec_free (authority);
  vec_free (formated);

  /* 'invalid IPv4 address' is recognized as registered name */
  authority = format (0, "1000.10.2.45:80");
  rv = http_parse_authority (authority, vec_len (authority), &parsed);
  HTTP_TEST ((rv == 0), "'%v' should be valid", authority);
  HTTP_TEST ((parsed.host_type == HTTP_URI_HOST_TYPE_REG_NAME),
	     "host_type=%d should be %d", parsed.host_type,
	     HTTP_URI_HOST_TYPE_REG_NAME);
  HTTP_TEST ((clib_net_to_host_u16 (parsed.port) == 80),
	     "port=%u should be 80", clib_net_to_host_u16 (parsed.port));
  formated = http_serialize_authority (&parsed);
  rv = vec_cmp (authority, formated);
  HTTP_TEST ((rv == 0), "'%v' should match '%v'", authority, formated);
  vec_free (authority);
  vec_free (formated);

  authority = format (0, "10.10.20:80");
  rv = http_parse_authority (authority, vec_len (authority), &parsed);
  HTTP_TEST ((rv == 0), "'%v' should be valid", authority);
  HTTP_TEST ((parsed.host_type == HTTP_URI_HOST_TYPE_REG_NAME),
	     "host_type=%d should be %d", parsed.host_type,
	     HTTP_URI_HOST_TYPE_REG_NAME);
  HTTP_TEST ((clib_net_to_host_u16 (parsed.port) == 80),
	     "port=%u should be 80", clib_net_to_host_u16 (parsed.port));
  formated = http_serialize_authority (&parsed);
  rv = vec_cmp (authority, formated);
  HTTP_TEST ((rv == 0), "'%v' should match '%v'", authority, formated);
  vec_free (authority);
  vec_free (formated);

  authority = format (0, "10.10.10.10.2");
  rv = http_parse_authority (authority, vec_len (authority), &parsed);
  HTTP_TEST ((rv == 0), "'%v' should be valid", authority);
  HTTP_TEST ((parsed.host_type == HTTP_URI_HOST_TYPE_REG_NAME),
	     "host_type=%d should be %d", parsed.host_type,
	     HTTP_URI_HOST_TYPE_REG_NAME);
  HTTP_TEST ((parsed.port == 0), "port=%u should be 0", parsed.port);
  formated = http_serialize_authority (&parsed);
  rv = vec_cmp (authority, formated);
  HTTP_TEST ((rv == 0), "'%v' should match '%v'", authority, formated);
  vec_free (authority);
  vec_free (formated);

  /* invalid port */
  authority = format (0, "example.com:80000000");
  rv = http_parse_authority (authority, vec_len (authority), &parsed);
  HTTP_TEST ((rv == -1), "'%v' should be invalid", authority);

  /* no port after colon */
  authority = format (0, "example.com:");
  rv = http_parse_authority (authority, vec_len (authority), &parsed);
  HTTP_TEST ((rv == -1), "'%v' should be invalid", authority);

  /* invalid character in registered name */
  authority = format (0, "bad#example.com");
  rv = http_parse_authority (authority, vec_len (authority), &parsed);
  HTTP_TEST ((rv == -1), "'%v' should be invalid", authority);

  /* invalid IPv6 address not terminated with ']' */
  authority = format (0, "[dead:beef::1234");
  rv = http_parse_authority (authority, vec_len (authority), &parsed);
  HTTP_TEST ((rv == -1), "'%v' should be invalid", authority);

  /* empty IPv6 address */
  authority = format (0, "[]");
  rv = http_parse_authority (authority, vec_len (authority), &parsed);
  HTTP_TEST ((rv == -1), "'%v' should be invalid", authority);

  /* invalid IPv6 address too few hex quads */
  authority = format (0, "[dead:beef]:80");
  rv = http_parse_authority (authority, vec_len (authority), &parsed);
  HTTP_TEST ((rv == -1), "'%v' should be invalid", authority);

  /* invalid IPv6 address more than one :: */
  authority = format (0, "[dead::beef::1]:80");
  rv = http_parse_authority (authority, vec_len (authority), &parsed);
  HTTP_TEST ((rv == -1), "'%v' should be invalid", authority);

  /* invalid IPv6 address too much hex quads */
  authority = format (0, "[d:e:a:d:b:e:e:f:1:2]:80");
  rv = http_parse_authority (authority, vec_len (authority), &parsed);
  HTTP_TEST ((rv == -1), "'%v' should be invalid", authority);

  /* invalid character in IPv6 address */
  authority = format (0, "[xyz0::1234]:443");
  rv = http_parse_authority (authority, vec_len (authority), &parsed);
  HTTP_TEST ((rv == -1), "'%v' should be invalid", authority);

  /* invalid IPv6 address */
  authority = format (0, "[deadbeef::1234");
  rv = http_parse_authority (authority, vec_len (authority), &parsed);
  HTTP_TEST ((rv == -1), "'%v' should be invalid", authority);

  return 0;
}

static int
http_test_parse_masque_host_port (vlib_main_t *vm)
{
  u8 *path = 0;
  http_uri_authority_t target;
  int rv;

  path = format (0, "10.10.2.45/443/");
  rv = http_parse_masque_host_port (path, vec_len (path), &target);
  HTTP_TEST ((rv == 0), "'%v' should be valid", path);
  HTTP_TEST ((target.host_type == HTTP_URI_HOST_TYPE_IP4),
	     "host_type=%d should be %d", target.host_type,
	     HTTP_URI_HOST_TYPE_IP4);
  HTTP_TEST ((clib_net_to_host_u16 (target.port) == 443),
	     "port=%u should be 443", clib_net_to_host_u16 (target.port));
  HTTP_TEST ((target.ip.ip4.data[0] == 10 && target.ip.ip4.data[1] == 10 &&
	      target.ip.ip4.data[2] == 2 && target.ip.ip4.data[3] == 45),
	     "target.ip=%U should be 10.10.2.45", format_ip4_address,
	     &target.ip.ip4);
  vec_free (path);

  path = format (0, "dead%%3Abeef%%3A%%3A1234/80/");
  rv = http_parse_masque_host_port (path, vec_len (path), &target);
  HTTP_TEST ((rv == 0), "'%v' should be valid", path);
  HTTP_TEST ((target.host_type == HTTP_URI_HOST_TYPE_IP6),
	     "host_type=%d should be %d", target.host_type,
	     HTTP_URI_HOST_TYPE_IP6);
  HTTP_TEST ((clib_net_to_host_u16 (target.port) == 80),
	     "port=%u should be 80", clib_net_to_host_u16 (target.port));
  HTTP_TEST ((clib_net_to_host_u16 (target.ip.ip6.as_u16[0]) == 0xdead &&
	      clib_net_to_host_u16 (target.ip.ip6.as_u16[1]) == 0xbeef &&
	      target.ip.ip6.as_u16[2] == 0 && target.ip.ip6.as_u16[3] == 0 &&
	      target.ip.ip6.as_u16[4] == 0 && target.ip.ip6.as_u16[5] == 0 &&
	      target.ip.ip6.as_u16[6] == 0 &&
	      clib_net_to_host_u16 (target.ip.ip6.as_u16[7]) == 0x1234),
	     "target.ip=%U should be dead:beef::1234", format_ip6_address,
	     &target.ip.ip6);
  vec_free (path);

  path = format (0, "example.com/443/");
  rv = http_parse_masque_host_port (path, vec_len (path), &target);
  HTTP_TEST ((rv != 0), "'%v' reg-name not supported", path);
  vec_free (path);

  path = format (0, "10.10.2.45/443443/");
  rv = http_parse_masque_host_port (path, vec_len (path), &target);
  HTTP_TEST ((rv != 0), "'%v' should be invalid", path);
  vec_free (path);

  path = format (0, "/443/");
  rv = http_parse_masque_host_port (path, vec_len (path), &target);
  HTTP_TEST ((rv != 0), "'%v' should be invalid", path);
  vec_free (path);

  path = format (0, "10.10.2.45/");
  rv = http_parse_masque_host_port (path, vec_len (path), &target);
  HTTP_TEST ((rv != 0), "'%v' should be invalid", path);
  vec_free (path);

  path = format (0, "10.10.2.45");
  rv = http_parse_masque_host_port (path, vec_len (path), &target);
  HTTP_TEST ((rv != 0), "'%v' should be invalid", path);
  vec_free (path);

  path = format (0, "10.10.2.45/443");
  rv = http_parse_masque_host_port (path, vec_len (path), &target);
  HTTP_TEST ((rv != 0), "'%v' should be invalid", path);
  vec_free (path);

  return 0;
}

static int
http_test_udp_payload_datagram (vlib_main_t *vm)
{
  int rv;
  u8 payload_offset;
  u64 payload_len;

  /* Type = 0x00, Len = 15293,  Context ID = 0x00 */
  u8 valid_input[] = { 0x00, 0x7B, 0xBD, 0x00, 0x12, 0x34, 0x56 };
  rv = http_decap_udp_payload_datagram (valid_input, sizeof (valid_input),
					&payload_offset, &payload_len);
  HTTP_TEST ((rv == 0), "'%U' should be valid", format_hex_bytes, valid_input,
	     sizeof (valid_input));
  HTTP_TEST ((payload_len == 15292), "payload_len=%llu should be 15292",
	     payload_len);
  HTTP_TEST ((payload_offset == 4), "payload_offset=%u should be 4",
	     payload_offset);

  /* Type = 0x00, Len = incomplete */
  u8 invalid_input[] = { 0x00, 0x7B };
  rv = http_decap_udp_payload_datagram (invalid_input, sizeof (invalid_input),
					&payload_offset, &payload_len);
  HTTP_TEST ((rv == -1), "'%U' should be invalid (length incomplete)",
	     format_hex_bytes, invalid_input, sizeof (invalid_input));

  /* Type = 0x00, Len = missing */
  u8 invalid_input2[] = { 0x00 };
  rv = http_decap_udp_payload_datagram (
    invalid_input2, sizeof (invalid_input2), &payload_offset, &payload_len);
  HTTP_TEST ((rv == -1), "'%U' should be invalid (length missing)",
	     format_hex_bytes, invalid_input2, sizeof (invalid_input2));

  /* Type = 0x00, Len = 15293,  Context ID = missing */
  u8 invalid_input3[] = { 0x00, 0x7B, 0xBD };
  rv = http_decap_udp_payload_datagram (
    invalid_input3, sizeof (invalid_input3), &payload_offset, &payload_len);
  HTTP_TEST ((rv == -1), "'%U' should be invalid (context id missing)",
	     format_hex_bytes, invalid_input3, sizeof (invalid_input3));

  /* Type = 0x00, Len = 494878333,  Context ID = 0x00 */
  u8 long_payload_input[] = { 0x00, 0x9D, 0x7F, 0x3E, 0x7D, 0x00, 0x12 };
  rv = http_decap_udp_payload_datagram (long_payload_input,
					sizeof (long_payload_input),
					&payload_offset, &payload_len);
  HTTP_TEST (
    (rv == -1), "'%U' should be invalid (payload exceeded maximum value)",
    format_hex_bytes, long_payload_input, sizeof (long_payload_input));

  /* Type = 0x01, Len = 37,  Context ID = 0x00 */
  u8 unknown_type_input[] = { 0x01, 0x25, 0x00, 0x12, 0x34, 0x56, 0x78 };
  rv = http_decap_udp_payload_datagram (unknown_type_input,
					sizeof (unknown_type_input),
					&payload_offset, &payload_len);
  HTTP_TEST ((rv == 1), "'%U' should be skipped (unknown capsule type)",
	     format_hex_bytes, unknown_type_input,
	     sizeof (unknown_type_input));
  HTTP_TEST ((payload_len == 39), "payload_len=%llu should be 39",
	     payload_len);

  u8 *buffer = 0, *ret;
  vec_validate (buffer, HTTP_UDP_PROXY_DATAGRAM_CAPSULE_OVERHEAD + 2);
  ret = http_encap_udp_payload_datagram (buffer, 15292);
  payload_offset = ret - buffer;
  HTTP_TEST ((payload_offset == 4), "payload_offset=%u should be 4",
	     payload_offset);
  HTTP_TEST ((buffer[0] == HTTP_CAPSULE_TYPE_DATAGRAM),
	     "capsule_type=%u should be %u", buffer[0],
	     HTTP_CAPSULE_TYPE_DATAGRAM);
  HTTP_TEST ((buffer[1] == 0x7B && buffer[2] == 0xBD),
	     "capsule_len=0x%x%x should be 0x7bbd", buffer[1], buffer[2]);
  HTTP_TEST ((buffer[3] == 0), "context_id=%u should be 0", buffer[3]);
  vec_free (buffer);

  return 0;
}

static clib_error_t *
test_http_command_fn (vlib_main_t *vm, unformat_input_t *input,
		      vlib_cli_command_t *cmd)
{
  int res = 0;
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "parse-authority"))
	res = http_test_parse_authority (vm);
      else if (unformat (input, "parse-masque-host-port"))
	res = http_test_parse_masque_host_port (vm);
      else if (unformat (input, "udp-payload-datagram"))
	res = http_test_udp_payload_datagram (vm);
      else if (unformat (input, "all"))
	{
	  if ((res = http_test_parse_authority (vm)))
	    goto done;
	  if ((res = http_test_parse_masque_host_port (vm)))
	    goto done;
	  if ((res = http_test_udp_payload_datagram (vm)))
	    goto done;
	}
      else
	break;
    }

done:
  if (res)
    return clib_error_return (0, "FAILED");

  vlib_cli_output (vm, "SUCCESS");
  return 0;
}

VLIB_CLI_COMMAND (test_http_command) = {
  .path = "test http",
  .short_help = "http unit tests",
  .function = test_http_command_fn,
};

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "HTTP - Unit Test",
  .default_disabled = 1,
};
