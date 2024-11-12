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
http_test_authority_form (vlib_main_t *vm)
{
  u8 *target = 0, *formated_target = 0;
  http_uri_t authority;
  int rv;

  target = format (0, "10.10.2.45:20");
  rv = http_parse_authority_form_target (target, &authority);
  HTTP_TEST ((rv == 0), "'%v' should be valid", target);
  formated_target = http_serialize_authority_form_target (&authority);
  rv = vec_cmp (target, formated_target);
  HTTP_TEST ((rv == 0), "'%v' should match '%v'", target, formated_target);
  vec_free (target);
  vec_free (formated_target);

  target = format (0, "[dead:beef::1234]:443");
  rv = http_parse_authority_form_target (target, &authority);
  HTTP_TEST ((rv == 0), "'%v' should be valid", target);
  formated_target = http_serialize_authority_form_target (&authority);
  rv = vec_cmp (target, formated_target);
  HTTP_TEST ((rv == 0), "'%v' should match '%v'", target, formated_target);
  vec_free (target);
  vec_free (formated_target);

  target = format (0, "example.com:80");
  rv = http_parse_authority_form_target (target, &authority);
  HTTP_TEST ((rv != 0), "'%v' reg-name not supported", target);
  vec_free (target);

  target = format (0, "10.10.2.45");
  rv = http_parse_authority_form_target (target, &authority);
  HTTP_TEST ((rv != 0), "'%v' should be invalid", target);
  vec_free (target);

  target = format (0, "1000.10.2.45:20");
  rv = http_parse_authority_form_target (target, &authority);
  HTTP_TEST ((rv != 0), "'%v' should be invalid", target);
  vec_free (target);

  target = format (0, "[xyz0::1234]:443");
  rv = http_parse_authority_form_target (target, &authority);
  HTTP_TEST ((rv != 0), "'%v' should be invalid", target);
  vec_free (target);

  return 0;
}

static int
http_test_absolute_form (vlib_main_t *vm)
{
  u8 *url = 0;
  http_url_t parsed_url;
  int rv;

  url = format (0, "https://example.org/.well-known/masque/udp/1.2.3.4/123/");
  rv = http_parse_absolute_form (url, &parsed_url);
  HTTP_TEST ((rv == 0), "'%v' should be valid", url);
  HTTP_TEST ((parsed_url.scheme == HTTP_URL_SCHEME_HTTPS),
	     "scheme should be https");
  HTTP_TEST ((parsed_url.host_is_ip6 == 0), "host_is_ip6=%u should be 0",
	     parsed_url.host_is_ip6);
  HTTP_TEST ((parsed_url.host_offset == strlen ("https://")),
	     "host_offset=%u should be %u", parsed_url.host_offset,
	     strlen ("https://"));
  HTTP_TEST ((parsed_url.host_len == strlen ("example.org")),
	     "host_len=%u should be %u", parsed_url.host_len,
	     strlen ("example.org"));
  HTTP_TEST ((clib_net_to_host_u16 (parsed_url.port) == 443),
	     "port=%u should be 443", clib_net_to_host_u16 (parsed_url.port));
  HTTP_TEST ((parsed_url.path_offset == strlen ("https://example.org/")),
	     "path_offset=%u should be %u", parsed_url.path_offset,
	     strlen ("https://example.org/"));
  HTTP_TEST (
    (parsed_url.path_len == strlen (".well-known/masque/udp/1.2.3.4/123/")),
    "path_len=%u should be %u", parsed_url.path_len,
    strlen (".well-known/masque/udp/1.2.3.4/123/"));
  vec_free (url);

  url = format (0, "http://vpp-example.org");
  rv = http_parse_absolute_form (url, &parsed_url);
  HTTP_TEST ((rv == 0), "'%v' should be valid", url);
  HTTP_TEST ((parsed_url.scheme == HTTP_URL_SCHEME_HTTP),
	     "scheme should be http");
  HTTP_TEST ((parsed_url.host_is_ip6 == 0), "host_is_ip6=%u should be 0",
	     parsed_url.host_is_ip6);
  HTTP_TEST ((parsed_url.host_offset == strlen ("http://")),
	     "host_offset=%u should be %u", parsed_url.host_offset,
	     strlen ("http://"));
  HTTP_TEST ((parsed_url.host_len == strlen ("vpp-example.org")),
	     "host_len=%u should be %u", parsed_url.host_len,
	     strlen ("vpp-example.org"));
  HTTP_TEST ((clib_net_to_host_u16 (parsed_url.port) == 80),
	     "port=%u should be 80", clib_net_to_host_u16 (parsed_url.port));
  HTTP_TEST ((parsed_url.path_len == 0), "path_len=%u should be 0",
	     parsed_url.path_len);
  vec_free (url);

  url = format (0, "http://1.2.3.4:8080/abcd");
  rv = http_parse_absolute_form (url, &parsed_url);
  HTTP_TEST ((rv == 0), "'%v' should be valid", url);
  HTTP_TEST ((parsed_url.scheme == HTTP_URL_SCHEME_HTTP),
	     "scheme should be http");
  HTTP_TEST ((parsed_url.host_is_ip6 == 0), "host_is_ip6=%u should be 0",
	     parsed_url.host_is_ip6);
  HTTP_TEST ((parsed_url.host_offset == strlen ("http://")),
	     "host_offset=%u should be %u", parsed_url.host_offset,
	     strlen ("http://"));
  HTTP_TEST ((parsed_url.host_len == strlen ("1.2.3.4")),
	     "host_len=%u should be %u", parsed_url.host_len,
	     strlen ("1.2.3.4"));
  HTTP_TEST ((clib_net_to_host_u16 (parsed_url.port) == 8080),
	     "port=%u should be 8080", clib_net_to_host_u16 (parsed_url.port));
  HTTP_TEST ((parsed_url.path_offset == strlen ("http://1.2.3.4:8080/")),
	     "path_offset=%u should be %u", parsed_url.path_offset,
	     strlen ("http://1.2.3.4:8080/"));
  HTTP_TEST ((parsed_url.path_len == strlen ("abcd")),
	     "path_len=%u should be %u", parsed_url.path_len, strlen ("abcd"));
  vec_free (url);

  url = format (0, "https://[dead:beef::1234]/abcd");
  rv = http_parse_absolute_form (url, &parsed_url);
  HTTP_TEST ((rv == 0), "'%v' should be valid", url);
  HTTP_TEST ((parsed_url.scheme == HTTP_URL_SCHEME_HTTPS),
	     "scheme should be https");
  HTTP_TEST ((parsed_url.host_is_ip6 == 1), "host_is_ip6=%u should be 1",
	     parsed_url.host_is_ip6);
  HTTP_TEST ((parsed_url.host_offset == strlen ("https://[")),
	     "host_offset=%u should be %u", parsed_url.host_offset,
	     strlen ("https://["));
  HTTP_TEST ((parsed_url.host_len == strlen ("dead:beef::1234")),
	     "host_len=%u should be %u", parsed_url.host_len,
	     strlen ("dead:beef::1234"));
  HTTP_TEST ((clib_net_to_host_u16 (parsed_url.port) == 443),
	     "port=%u should be 443", clib_net_to_host_u16 (parsed_url.port));
  HTTP_TEST ((parsed_url.path_offset == strlen ("https://[dead:beef::1234]/")),
	     "path_offset=%u should be %u", parsed_url.path_offset,
	     strlen ("https://[dead:beef::1234]/"));
  HTTP_TEST ((parsed_url.path_len == strlen ("abcd")),
	     "path_len=%u should be %u", parsed_url.path_len, strlen ("abcd"));
  vec_free (url);

  url = format (0, "http://[::ffff:192.0.2.128]:8080/");
  rv = http_parse_absolute_form (url, &parsed_url);
  HTTP_TEST ((rv == 0), "'%v' should be valid", url);
  HTTP_TEST ((parsed_url.scheme == HTTP_URL_SCHEME_HTTP),
	     "scheme should be http");
  HTTP_TEST ((parsed_url.host_is_ip6 == 1), "host_is_ip6=%u should be 1",
	     parsed_url.host_is_ip6);
  HTTP_TEST ((parsed_url.host_offset == strlen ("http://[")),
	     "host_offset=%u should be %u", parsed_url.host_offset,
	     strlen ("http://["));
  HTTP_TEST ((parsed_url.host_len == strlen ("::ffff:192.0.2.128")),
	     "host_len=%u should be %u", parsed_url.host_len,
	     strlen ("::ffff:192.0.2.128"));
  HTTP_TEST ((clib_net_to_host_u16 (parsed_url.port) == 8080),
	     "port=%u should be 8080", clib_net_to_host_u16 (parsed_url.port));
  HTTP_TEST ((parsed_url.path_len == 0), "path_len=%u should be 0",
	     parsed_url.path_len);
  vec_free (url);

  url = format (0, "http://[dead:beef::1234/abc");
  rv = http_parse_absolute_form (url, &parsed_url);
  HTTP_TEST ((rv != 0), "'%v' should be invalid", url);
  vec_free (url);

  url = format (0, "http://[dead|beef::1234]/abc");
  rv = http_parse_absolute_form (url, &parsed_url);
  HTTP_TEST ((rv != 0), "'%v' should be invalid", url);
  vec_free (url);

  url = format (0, "http:example.org:8080/abcd");
  rv = http_parse_absolute_form (url, &parsed_url);
  HTTP_TEST ((rv != 0), "'%v' should be invalid", url);
  vec_free (url);

  url = format (0, "htt://example.org:8080/abcd");
  rv = http_parse_absolute_form (url, &parsed_url);
  HTTP_TEST ((rv != 0), "'%v' should be invalid", url);
  vec_free (url);

  url = format (0, "http://");
  rv = http_parse_absolute_form (url, &parsed_url);
  HTTP_TEST ((rv != 0), "'%v' should be invalid", url);
  vec_free (url);

  url = format (0, "http:///abcd");
  rv = http_parse_absolute_form (url, &parsed_url);
  HTTP_TEST ((rv != 0), "'%v' should be invalid", url);
  vec_free (url);

  url = format (0, "http://example.org:808080/abcd");
  rv = http_parse_absolute_form (url, &parsed_url);
  HTTP_TEST ((rv != 0), "'%v' should be invalid", url);
  vec_free (url);

  url = format (0, "http://example.org/a%%3Xbcd");
  rv = http_parse_absolute_form (url, &parsed_url);
  HTTP_TEST ((rv != 0), "'%v' should be invalid", url);
  vec_free (url);

  url = format (0, "http://example.org/a%%3");
  rv = http_parse_absolute_form (url, &parsed_url);
  HTTP_TEST ((rv != 0), "'%v' should be invalid", url);
  vec_free (url);

  url = format (0, "http://example.org/a[b]cd");
  rv = http_parse_absolute_form (url, &parsed_url);
  HTTP_TEST ((rv != 0), "'%v' should be invalid", url);
  vec_free (url);

  url = format (0, "http://exa[m]ple.org/abcd");
  rv = http_parse_absolute_form (url, &parsed_url);
  HTTP_TEST ((rv != 0), "'%v' should be invalid", url);
  vec_free (url);

  return 0;
}

static int
http_test_parse_masque_host_port (vlib_main_t *vm)
{
  u8 *path = 0;
  http_uri_t target;
  int rv;

  path = format (0, "10.10.2.45/443/");
  rv = http_parse_masque_host_port (path, vec_len (path), &target);
  HTTP_TEST ((rv == 0), "'%v' should be valid", path);
  HTTP_TEST ((target.is_ip4 == 1), "is_ip4=%d should be 1", target.is_ip4);
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
  HTTP_TEST ((target.is_ip4 == 0), "is_ip4=%d should be 0", target.is_ip4);
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

  u8 invalid_input[] = { 0x00, 0x7B };
  rv = http_decap_udp_payload_datagram (invalid_input, sizeof (invalid_input),
					&payload_offset, &payload_len);
  HTTP_TEST ((rv == -1), "'%U' should be invalid", format_hex_bytes,
	     invalid_input, sizeof (invalid_input));

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
      if (unformat (input, "authority-form"))
	res = http_test_authority_form (vm);
      else if (unformat (input, "absolute-form"))
	res = http_test_absolute_form (vm);
      else if (unformat (input, "parse-masque-host-port"))
	res = http_test_parse_masque_host_port (vm);
      else if (unformat (input, "udp-payload-datagram"))
	res = http_test_udp_payload_datagram (vm);
      else if (unformat (input, "all"))
	{
	  if ((res = http_test_authority_form (vm)))
	    goto done;
	  if ((res = http_test_absolute_form (vm)))
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
    return clib_error_return (0, "HTTP unit test failed");
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
