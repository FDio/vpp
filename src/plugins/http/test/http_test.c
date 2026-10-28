/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2024 Cisco Systems, Inc.
 */

#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>
#include <http/http.h>
#include <http/http_header_names.h>
#include <http/http_private.h>
#include <http/http1/chunked.h>
#include <http/http2/http2_inlines.h>
#include <http/http2/hpack_inlines.h>
#include <http/http2/hpack.h>
#include <http/http2/frame.h>
#include <http/http3/qpack.h>
#include <http/http3/frame.h>

#define HTTP_TEST_I(_cond, _comment, _args...)                                                     \
  ({                                                                                               \
    int _evald = (_cond);                                                                          \
    if (!(_evald))                                                                                 \
      {                                                                                            \
	vlib_cli_output (vm, "FAIL:%d: " _comment "\n", __LINE__, ##_args);                        \
      }                                                                                            \
    else                                                                                           \
      {                                                                                            \
	vlib_cli_output (vm, "PASS:%d: " _comment "\n", __LINE__, ##_args);                        \
      }                                                                                            \
    _evald;                                                                                        \
  })

#define HTTP_TEST(_cond, _comment, _args...)                                                       \
  {                                                                                                \
    if (!HTTP_TEST_I (_cond, _comment, ##_args))                                                   \
      {                                                                                            \
	return 1;                                                                                  \
      }                                                                                            \
  }

static int
http_test_parse_ip6 (vlib_main_t *vm)
{
  const struct
  {
    const char *text;
    u8 valid;
    u16 quads[8];
  } cases[] = {
    { "::", 1, {} },
    { "::1", 1, { 0, 0, 0, 0, 0, 0, 0, 1 } },
    { "1::", 1, { 1 } },
    { "2001:DB8::a:B", 1, { 0x2001, 0xdb8, 0, 0, 0, 0, 0xa, 0xb } },
    { "1:2:3:4:5:6:7:8", 1, { 1, 2, 3, 4, 5, 6, 7, 8 } },
    { "1:2:3:4:5:6:7::", 1, { 1, 2, 3, 4, 5, 6, 7 } },
    { "::ffff:192.0.2.1", 1, { 0, 0, 0, 0, 0, 0xffff, 0xc000, 0x201 } },
    { "1:2:3:4:5:6:192.0.2.1", 1, { 1, 2, 3, 4, 5, 6, 0xc000, 0x201 } },
    { "1:2:3:4:5::192.0.2.1", 1, { 1, 2, 3, 4, 5, 0, 0xc000, 0x201 } },
    { "::0.0.0.0", 1, {} },
    { "::255.255.255.255", 1, { 0, 0, 0, 0, 0, 0, 0xffff, 0xffff } },
    { "", 0, {} },
    { ":", 0, {} },
    { ":1:2:3:4:5:6:7:8", 0, {} },
    { "1:2:3:4:5:6:7:8:", 0, {} },
    { "1:2:3:4:5:6:7:8::", 0, {} },
    { "1::2:3:4:5:6:7:8", 0, {} },
    { "1:2:3:4:5:6:7", 0, {} },
    { "1:2:3:4:5:6:7:8:9", 0, {} },
    { ":::1", 0, {} },
    { ":::", 0, {} },
    { "1::2::3", 0, {} },
    { "12345::1", 0, {} },
    { "gg::1", 0, {} },
    { "fe80::1%eth0", 0, {} },
    { "::1junk", 0, {} },
    { "192.0.2.1", 0, {} },
    { "::ffff:192.0.2", 0, {} },
    { "::ffff:192.0.2.1.2", 0, {} },
    { "::ffff:192.0.2.1:", 0, {} },
    { "::ffff:256.0.2.1", 0, {} },
    { "::ffff:192.00.2.1", 0, {} },
    { "::ffff:0192.0.2.1", 0, {} },
    { "::ffff:192..2.1", 0, {} },
    { "::ffff:c0.0.2.1", 0, {} },
    { "1:2:3:4:5:6::192.0.2.1", 0, {} },
    { "1:2:3:4:5:6:7:192.0.2.1", 0, {} },
  };
  for (u32 i = 0; i < ARRAY_LEN (cases); i++)
    {
      u8 *p = (u8 *) cases[i].text;
      u32 len = strlen (cases[i].text);
      ip6_address_t ip6;
      int rv = _http_parse_ip6 (&p, p + len, &ip6);
      HTTP_TEST ((rv == 0 && p == (u8 *) cases[i].text + len) == cases[i].valid, "IPv6 '%s' syntax",
		 cases[i].text);
      if (cases[i].valid)
	{
	  for (u32 j = 0; j < ARRAY_LEN (cases[i].quads); j++)
	    HTTP_TEST (ip6.as_u16[j] == clib_host_to_net_u16 (cases[i].quads[j]),
		       "IPv6 '%s' quad %u", cases[i].text, j);
	}

      u8 *authority = format (0, "[%s]:443", cases[i].text);
      hpack_authority_t parsed;
      u8 valid = hpack_authority_parse (authority, vec_len (authority), 1, 0, &parsed);
      HTTP_TEST (valid == cases[i].valid, "pseudo-header authority '%v' syntax", authority);
      if (valid)
	HTTP_TEST (parsed.is_ip6 && !memcmp (&parsed.ip6, &ip6, sizeof (ip6)),
		   "pseudo-header authority '%v' address", authority);

      http_uri_authority_t uri;
      rv = http_parse_authority (authority, vec_len (authority), &uri);
      HTTP_TEST ((rv == 0) == cases[i].valid, "URI authority '%v' syntax", authority);
      vec_free (authority);
    }
  return 0;
}

static int
http_test_parse_authority (vlib_main_t *vm)
{
  u8 *authority = 0, *formated = 0;
  http_uri_authority_t parsed;
  int rv;

  if (http_test_parse_ip6 (vm))
    return 1;

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

  authority = format (0, "[DEAD:BEEF::1234]:443");
  rv = http_parse_authority (authority, vec_len (authority), &parsed);
  HTTP_TEST ((rv == 0), "'%v' should be valid", authority);
  HTTP_TEST ((parsed.host_type == HTTP_URI_HOST_TYPE_IP6),
	     "host_type=%d should be %d", parsed.host_type,
	     HTTP_URI_HOST_TYPE_IP6);
  HTTP_TEST ((parsed.ip.as_u8[0] == 0xDE && parsed.ip.as_u8[1] == 0xAD &&
	      parsed.ip.as_u8[2] == 0xBE && parsed.ip.as_u8[3] == 0xEF),
	     "not parsed correctly");
  vec_free (authority);

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

  authority = format (0, "1e.com");
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
  vec_free (authority);

  /* no port after colon */
  authority = format (0, "example.com:");
  rv = http_parse_authority (authority, vec_len (authority), &parsed);
  HTTP_TEST ((rv == -1), "'%v' should be invalid", authority);
  vec_free (authority);

  /* invalid character in registered name */
  authority = format (0, "bad#example.com");
  rv = http_parse_authority (authority, vec_len (authority), &parsed);
  HTTP_TEST ((rv == -1), "'%v' should be invalid", authority);
  vec_free (authority);

  /* invalid IPv6 address not terminated with ']' */
  authority = format (0, "[dead:beef::1234");
  rv = http_parse_authority (authority, vec_len (authority), &parsed);
  HTTP_TEST ((rv == -1), "'%v' should be invalid", authority);
  vec_free (authority);

  /* empty IPv6 address */
  authority = format (0, "[]");
  rv = http_parse_authority (authority, vec_len (authority), &parsed);
  HTTP_TEST ((rv == -1), "'%v' should be invalid", authority);
  vec_free (authority);

  /* invalid IPv6 address too few hex quads */
  authority = format (0, "[dead:beef]:80");
  rv = http_parse_authority (authority, vec_len (authority), &parsed);
  HTTP_TEST ((rv == -1), "'%v' should be invalid", authority);
  vec_free (authority);

  /* invalid IPv6 address more than one :: */
  authority = format (0, "[dead::beef::1]:80");
  rv = http_parse_authority (authority, vec_len (authority), &parsed);
  HTTP_TEST ((rv == -1), "'%v' should be invalid", authority);
  vec_free (authority);

  /* invalid IPv6 address too much hex quads */
  authority = format (0, "[d:e:a:d:b:e:e:f:1:2]:80");
  rv = http_parse_authority (authority, vec_len (authority), &parsed);
  HTTP_TEST ((rv == -1), "'%v' should be invalid", authority);
  vec_free (authority);

  /* invalid character in IPv6 address */
  authority = format (0, "[xyz0::1234]:443");
  rv = http_parse_authority (authority, vec_len (authority), &parsed);
  HTTP_TEST ((rv == -1), "'%v' should be invalid", authority);
  vec_free (authority);

  /* invalid IPv6 address */
  authority = format (0, "[deadbeef::1234");
  rv = http_parse_authority (authority, vec_len (authority), &parsed);
  HTTP_TEST ((rv == -1), "'%v' should be invalid", authority);
  vec_free (authority);

  /* registered name too long */
  vec_validate_init_empty (authority, 257, 'a');
  rv = http_parse_authority (authority, vec_len (authority), &parsed);
  HTTP_TEST ((rv == -1), "'%v' should be invalid", authority);
  vec_free (authority);

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
  HTTP_TEST ((rv == 0), "'%v' should be valid", path);
  vec_free (path);

  /* A port in the registered-name segment is invalid. */
  path = format (0, "example.com%%3A443/443/");
  rv = http_parse_masque_host_port (path, vec_len (path), &target);
  HTTP_TEST ((rv != 0), "'%v' should be invalid", path);
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
  rv = http_decap_udp_payload_datagram (valid_input, sizeof (valid_input), &payload_offset,
					&payload_len, 0);
  HTTP_TEST ((rv == HTTP_CAPSULE_NO_ERROR), "'%U' should be valid", format_hex_bytes, valid_input,
	     sizeof (valid_input));
  HTTP_TEST ((payload_len == 15292), "payload_len=%llu should be 15292",
	     payload_len);
  HTTP_TEST ((payload_offset == 4), "payload_offset=%u should be 4",
	     payload_offset);

  /* Type = 0x00, Len = incomplete */
  u8 invalid_input[] = { 0x00, 0x7B };
  rv = http_decap_udp_payload_datagram (invalid_input, sizeof (invalid_input), &payload_offset,
					&payload_len, 0);
  HTTP_TEST ((rv == HTTP_CAPSULE_INCOMPLETE), "'%U' should be invalid (length incomplete)",
	     format_hex_bytes, invalid_input, sizeof (invalid_input));

  /* Type = 0x00, Len = missing */
  u8 invalid_input2[] = { 0x00 };
  rv = http_decap_udp_payload_datagram (invalid_input2, sizeof (invalid_input2), &payload_offset,
					&payload_len, 0);
  HTTP_TEST ((rv == HTTP_CAPSULE_INCOMPLETE), "'%U' should be invalid (length missing)",
	     format_hex_bytes, invalid_input2, sizeof (invalid_input2));

  /* Type = 0x00, Len = 15293,  Context ID = missing */
  u8 invalid_input3[] = { 0x00, 0x7B, 0xBD };
  rv = http_decap_udp_payload_datagram (invalid_input3, sizeof (invalid_input3), &payload_offset,
					&payload_len, 0);
  HTTP_TEST ((rv == HTTP_CAPSULE_INCOMPLETE), "'%U' should be invalid (context id missing)",
	     format_hex_bytes, invalid_input3, sizeof (invalid_input3));

  /* masque-draft-03: Type = 0x00, Len = 15293 */
  u8 draft03_input[] = { 0x00, 0x7B, 0xBD };
  rv = http_decap_udp_payload_datagram (draft03_input, sizeof (draft03_input), &payload_offset,
					&payload_len, 1);
  HTTP_TEST ((rv == HTTP_CAPSULE_NO_ERROR),
	     "'%U' should be valid (no context id in masque-draft03)", format_hex_bytes,
	     draft03_input, sizeof (draft03_input));

  /* Type = 0x00, Len = 494878333,  Context ID = 0x00 */
  u8 long_payload_input[] = { 0x00, 0x9D, 0x7F, 0x3E, 0x7D, 0x00, 0x12 };
  rv = http_decap_udp_payload_datagram (long_payload_input, sizeof (long_payload_input),
					&payload_offset, &payload_len, 0);
  HTTP_TEST ((rv == HTTP_CAPSULE_INVALID),
	     "'%U' should be invalid (payload exceeded maximum value)", format_hex_bytes,
	     long_payload_input, sizeof (long_payload_input));

  /* Type = 0x01, Len = 37,  Context ID = 0x00 */
  u8 unknown_type_input[] = { 0x01, 0x25, 0x00, 0x12, 0x34, 0x56, 0x78 };
  rv = http_decap_udp_payload_datagram (unknown_type_input, sizeof (unknown_type_input),
					&payload_offset, &payload_len, 0);
  HTTP_TEST ((rv == HTTP_CAPSULE_SKIP), "'%U' should be skipped (unknown capsule type)",
	     format_hex_bytes, unknown_type_input, sizeof (unknown_type_input));
  HTTP_TEST ((payload_len == 39), "payload_len=%llu should be 39",
	     payload_len);

  /* Type = 0x00, Len = 37,  Context ID = 0x01 */
  u8 nonzero_context_id[] = { 0x00, 0x25, 0x01, 0x12, 0x34, 0x56, 0x78 };
  rv = http_decap_udp_payload_datagram (nonzero_context_id, sizeof (nonzero_context_id),
					&payload_offset, &payload_len, 0);
  HTTP_TEST ((rv == HTTP_CAPSULE_SKIP), "'%U' should be skipped (context id is not zero)",
	     format_hex_bytes, nonzero_context_id, sizeof (nonzero_context_id));
  HTTP_TEST ((payload_len == 39), "payload_len=%llu should be 39",
	     payload_len);

  u8 *buffer = 0, *ret;
  vec_validate_init_empty (buffer, HTTP_UDP_PROXY_DATAGRAM_CAPSULE_OVERHEAD + 2, 0xFF);
  ret = http_encap_udp_payload_datagram (buffer, 15292, 0);
  payload_offset = ret - buffer;
  HTTP_TEST ((payload_offset == 4), "payload_offset=%u should be 4", payload_offset);
  HTTP_TEST ((buffer[0] == HTTP_CAPSULE_TYPE_DATAGRAM), "capsule_type=%u should be %u", buffer[0],
	     HTTP_CAPSULE_TYPE_DATAGRAM);
  HTTP_TEST ((buffer[1] == 0x7B && buffer[2] == 0xBD), "capsule_len=0x%x%x should be 0x7bbd",
	     buffer[1], buffer[2]);
  HTTP_TEST ((buffer[3] == 0), "context_id=%u should be 0", buffer[3]);
  vec_free (buffer);

  vec_validate_init_empty (buffer, HTTP_UDP_PROXY_DATAGRAM_CAPSULE_OVERHEAD + 2, 0xFF);
  ret = http_encap_udp_payload_datagram (buffer, 15292, 1);
  payload_offset = ret - buffer;
  HTTP_TEST ((payload_offset == 3), "payload_offset=%u should be 3", payload_offset);
  HTTP_TEST ((buffer[0] == HTTP_CAPSULE_TYPE_DATAGRAM),
	     "capsule_type=%u should be %u", buffer[0],
	     HTTP_CAPSULE_TYPE_DATAGRAM);
  HTTP_TEST ((buffer[1] == 0x7B && buffer[2] == 0xBC), "capsule_len=0x%x%x should be 0x7bbc",
	     buffer[1], buffer[2]);
  HTTP_TEST ((buffer[3] == 0xFF), "context_id should not be set");
  vec_free (buffer);

  return 0;
}

static int
http_test_http_token_is_case (vlib_main_t *vm)
{
  static const char eq_1[] = "content-length";
  static const char eq_2[] = "CONtENT-lenGth";
  static const char eq_3[] = "caPsulE-ProtOcol";
  static const char eq_4[] = "ACCESS-CONTROL-REQUEST-METHOD";
  static const char ne_1[] = "content_length";
  static const char ne_2[] = "content-lengXh";
  static const char ne_3[] = "coNtent-lengXh";
  static const char ne_4[] = "content-len";
  static const char ne_5[] = "comtent-length";
  static const char ne_6[] = "content-lengtR";
  u8 rv;

  rv = http_token_is_case (
    eq_1, strlen (eq_1), http_header_name_token (HTTP_HEADER_CONTENT_LENGTH));
  HTTP_TEST ((rv == 1), "'%s' and '%s' are equal", eq_1,
	     http_header_name_str (HTTP_HEADER_CONTENT_LENGTH))

  rv = http_token_is_case (
    eq_2, strlen (eq_2), http_header_name_token (HTTP_HEADER_CONTENT_LENGTH));
  HTTP_TEST ((rv == 1), "'%s' and '%s' are equal", eq_2,
	     http_header_name_str (HTTP_HEADER_CONTENT_LENGTH))

  rv =
    http_token_is_case (eq_3, strlen (eq_3),
			http_header_name_token (HTTP_HEADER_CAPSULE_PROTOCOL));
  HTTP_TEST ((rv == 1), "'%s' and '%s' are equal", eq_3,
	     http_header_name_str (HTTP_HEADER_CAPSULE_PROTOCOL))

  rv = http_token_is_case (
    eq_4, strlen (eq_4),
    http_header_name_token (HTTP_HEADER_ACCESS_CONTROL_REQUEST_METHOD));
  HTTP_TEST ((rv == 1), "'%s' and '%s' are equal", eq_4,
	     http_header_name_str (HTTP_HEADER_ACCESS_CONTROL_REQUEST_METHOD))

  rv = http_token_is_case (
    ne_1, strlen (ne_1), http_header_name_token (HTTP_HEADER_CONTENT_LENGTH));
  HTTP_TEST ((rv == 0), "'%s' and '%s' are not equal", ne_1,
	     http_header_name_str (HTTP_HEADER_CONTENT_LENGTH))

  rv = http_token_is_case (
    ne_2, strlen (ne_2), http_header_name_token (HTTP_HEADER_CONTENT_LENGTH));
  HTTP_TEST ((rv == 0), "'%s' and '%s' are not equal", ne_2,
	     http_header_name_str (HTTP_HEADER_CONTENT_LENGTH))

  rv = http_token_is_case (
    ne_3, strlen (ne_3), http_header_name_token (HTTP_HEADER_CONTENT_LENGTH));
  HTTP_TEST ((rv == 0), "'%s' and '%s' are not equal", ne_3,
	     http_header_name_str (HTTP_HEADER_CONTENT_LENGTH))

  rv = http_token_is_case (
    ne_4, strlen (ne_4), http_header_name_token (HTTP_HEADER_CONTENT_LENGTH));
  HTTP_TEST ((rv == 0), "'%s' and '%s' are not equal", ne_4,
	     http_header_name_str (HTTP_HEADER_CONTENT_LENGTH))

  rv = http_token_is_case (
    ne_5, strlen (ne_5), http_header_name_token (HTTP_HEADER_CONTENT_LENGTH));
  HTTP_TEST ((rv == 0), "'%s' and '%s' are not equal", ne_5,
	     http_header_name_str (HTTP_HEADER_CONTENT_LENGTH))

  rv = http_token_is_case (
    ne_6, strlen (ne_6), http_header_name_token (HTTP_HEADER_CONTENT_LENGTH));
  HTTP_TEST ((rv == 0), "'%s' and '%s' are not equal", ne_6,
	     http_header_name_str (HTTP_HEADER_CONTENT_LENGTH))

  return 0;
}

static int
http_test_http_header_table (vlib_main_t *vm)
{
  http_header_table_t ht = HTTP_HEADER_TABLE_NULL;
  const char buf[] = "daTe: Wed, 15 Jan 2025 16:17:33 GMT"
		     "conTent-tYpE: text/html; charset=utf-8"
		     "STRICT-transport-security: max-age=31536000"
		     "sAnDwich: Eggs"
		     "CONTENT-ENCODING: GZIP"
		     "sandwich: Spam";
  http_msg_t msg = {};
  http_field_line_t *headers = 0, *field_line;
  const http_token_t *value;
  u8 rv;

  /* daTe */
  vec_add2 (headers, field_line, 1);
  field_line->name_offset = 0;
  field_line->name_len = 4;
  field_line->value_offset = 6;
  field_line->value_len = 29;
  /* conTent-tYpE */
  vec_add2 (headers, field_line, 1);
  field_line->name_offset = 35;
  field_line->name_len = 12;
  field_line->value_offset = 49;
  field_line->value_len = 24;
  /* STRICT-transport-security */
  vec_add2 (headers, field_line, 1);
  field_line->name_offset = 73;
  field_line->name_len = 25;
  field_line->value_offset = 100;
  field_line->value_len = 16;
  /* sAnDwich */
  vec_add2 (headers, field_line, 1);
  field_line->name_offset = 116;
  field_line->name_len = 8;
  field_line->value_offset = 126;
  field_line->value_len = 4;
  /* CONTENT-ENCODING */
  vec_add2 (headers, field_line, 1);
  field_line->name_offset = 130;
  field_line->name_len = 16;
  field_line->value_offset = 148;
  field_line->value_len = 4;
  /* sandwich */
  vec_add2 (headers, field_line, 1);
  field_line->name_offset = 152;
  field_line->name_len = 8;
  field_line->value_offset = 162;
  field_line->value_len = 4;

  msg.data.headers_ctx = pointer_to_uword (headers);
  msg.data.headers_len = strlen (buf);

  http_init_header_table_buf (&ht, msg);
  memcpy (ht.buf, buf, strlen (buf));
  http_build_header_table (&ht, msg);

  vlib_cli_output (vm, "%U", format_hash, ht.value_by_name, 1);

  value = http_get_header (
    &ht, http_header_name_token (HTTP_HEADER_CONTENT_ENCODING));
  HTTP_TEST ((value != 0), "'%s' is in headers",
	     http_header_name_str (HTTP_HEADER_CONTENT_ENCODING));
  rv = http_token_is (value->base, value->len, http_token_lit ("GZIP"));
  HTTP_TEST ((rv == 1), "header value '%U' should be 'GZIP'",
	     format_http_bytes, value->base, value->len);
  rv =
    http_token_contains (value->base, value->len, http_token_lit ("deflate"));
  HTTP_TEST ((rv == 0), "header value '%U' doesn't contain 'deflate'",
	     format_http_bytes, value->base, value->len);

  value =
    http_get_header (&ht, http_header_name_token (HTTP_HEADER_CONTENT_TYPE));
  HTTP_TEST ((value != 0), "'%s' is in headers",
	     http_header_name_str (HTTP_HEADER_CONTENT_TYPE));

  value = http_get_header (&ht, http_header_name_token (HTTP_HEADER_DATE));
  HTTP_TEST ((value != 0), "'%s' is in headers",
	     http_header_name_str (HTTP_HEADER_DATE));

  value = http_get_header (
    &ht, http_header_name_token (HTTP_HEADER_STRICT_TRANSPORT_SECURITY));
  HTTP_TEST ((value != 0), "'%s' is in headers",
	     http_header_name_str (HTTP_HEADER_STRICT_TRANSPORT_SECURITY));

  value = http_get_header (&ht, http_token_lit ("DATE"));
  HTTP_TEST ((value != 0), "'DATE' is in headers");

  value = http_get_header (&ht, http_token_lit ("date"));
  HTTP_TEST ((value != 0), "'date' is in headers");

  /* repeated header */
  value = http_get_header (&ht, http_token_lit ("sandwich"));
  HTTP_TEST ((value != 0), "'sandwich' is in headers");
  rv = http_token_is (value->base, value->len, http_token_lit ("Spam"));
  HTTP_TEST ((rv == 0), "header value '%U' should be 'Eggs, Spam'",
	     format_http_bytes, value->base, value->len);
  rv = http_token_is (value->base, value->len, http_token_lit ("Eggs, Spam"));
  HTTP_TEST ((rv == 1), "header value '%U' should be 'Eggs, Spam'",
	     format_http_bytes, value->base, value->len);
  rv = http_token_contains (value->base, value->len, http_token_lit ("Spam"));
  HTTP_TEST ((rv == 1), "header value '%U' contains 'Spam'", format_http_bytes,
	     value->base, value->len);
  rv = http_token_contains (value->base, value->len, http_token_lit ("spam"));
  HTTP_TEST ((rv == 0), "header value '%U' doesn't contain 'spam'",
	     format_http_bytes, value->base, value->len);

  value = http_get_header (&ht, http_token_lit ("Jade"));
  HTTP_TEST ((value == 0), "'Jade' is not in headers");

  value = http_get_header (&ht, http_token_lit ("CONTENT"));
  HTTP_TEST ((value == 0), "'CONTENT' is not in headers");

  value =
    http_get_header (&ht, http_header_name_token (HTTP_HEADER_ACCEPT_CHARSET));
  HTTP_TEST ((value == 0), "'%s' is not in headers",
	     http_header_name_str (HTTP_HEADER_ACCEPT_CHARSET));

  http_free_header_table (&ht);
  vec_free (headers);
  return 0;
}

static int
http_test_parse_request (const char *first_req, uword first_req_len,
			 const char *second_req, uword second_req_len,
			 const char *third_req, uword third_req_len,
			 hpack_dynamic_table_t *dynamic_table)
{
  http2_error_t rv;
  u8 *buf = 0;
  hpack_request_control_data_t control_data;
  http_field_line_t *headers = 0;
  u16 parsed_bitmap = 0;

  static http2_error_t (*_hpack_parse_request) (
    u8 * src, u32 src_len, u8 * dst, u32 dst_len,
    hpack_request_control_data_t * control_data, http_field_line_t * *headers,
    hpack_dynamic_table_t * dynamic_table);

  _hpack_parse_request =
    vlib_get_plugin_symbol ("http_plugin.so", "hpack_parse_request");

  parsed_bitmap =
    HPACK_PSEUDO_HEADER_METHOD_PARSED | HPACK_PSEUDO_HEADER_SCHEME_PARSED |
    HPACK_PSEUDO_HEADER_PATH_PARSED | HPACK_PSEUDO_HEADER_AUTHORITY_PARSED;

  /* first request */
  vec_validate_init_empty (buf, 254, 0);
  memset (&control_data, 0, sizeof (control_data));
  rv = _hpack_parse_request ((u8 *) first_req, (u32) first_req_len, buf, 254,
			     &control_data, &headers, dynamic_table);
  if (rv != HTTP2_ERROR_NO_ERROR ||
      control_data.parsed_bitmap != parsed_bitmap ||
      control_data.method != HTTP_REQ_GET ||
      control_data.scheme != HTTP_URL_SCHEME_HTTP ||
      control_data.path_len != 1 || control_data.authority_len != 15 ||
      dynamic_table->used != 57 || vec_len (headers) != 0)
    return 1;
  if (memcmp (control_data.path, "/", 1))
    return 1;
  if (memcmp (control_data.authority, "www.example.com", 15))
    return 1;
  vec_free (headers);
  vec_free (buf);

  /* second request */
  vec_validate_init_empty (buf, 254, 0);
  memset (&control_data, 0, sizeof (control_data));
  rv = _hpack_parse_request ((u8 *) second_req, (u32) second_req_len, buf, 254,
			     &control_data, &headers, dynamic_table);
  if (rv != HTTP2_ERROR_NO_ERROR ||
      control_data.parsed_bitmap != parsed_bitmap ||
      control_data.method != HTTP_REQ_GET ||
      control_data.scheme != HTTP_URL_SCHEME_HTTP ||
      control_data.path_len != 1 || control_data.authority_len != 15 ||
      dynamic_table->used != 110 || vec_len (headers) != 1 ||
      control_data.headers_len != 21)
    return 2;
  if (memcmp (control_data.path, "/", 1))
    return 2;
  if (memcmp (control_data.authority, "www.example.com", 15))
    return 2;
  if (headers[0].name_len != 13 || headers[0].value_len != 8)
    return 2;
  if (memcmp (control_data.headers + headers[0].name_offset, "cache-control",
	      13))
    return 2;
  if (memcmp (control_data.headers + headers[0].value_offset, "no-cache", 8))
    return 2;
  vec_free (headers);
  vec_free (buf);

  /* third request */
  vec_validate_init_empty (buf, 254, 0);
  memset (&control_data, 0, sizeof (control_data));
  rv = _hpack_parse_request ((u8 *) third_req, (u32) third_req_len, buf, 254,
			     &control_data, &headers, dynamic_table);
  if (rv != HTTP2_ERROR_NO_ERROR ||
      control_data.parsed_bitmap != parsed_bitmap ||
      control_data.method != HTTP_REQ_GET ||
      control_data.scheme != HTTP_URL_SCHEME_HTTPS ||
      control_data.path_len != 11 || control_data.authority_len != 15 ||
      dynamic_table->used != 164 || vec_len (headers) != 1 ||
      control_data.headers_len != 22)
    return 3;
  if (memcmp (control_data.path, "/index.html", 11))
    return 3;
  if (memcmp (control_data.authority, "www.example.com", 15))
    return 3;
  if (headers[0].name_len != 10 || headers[0].value_len != 12)
    return 3;
  if (memcmp (control_data.headers + headers[0].name_offset, "custom-key", 10))
    return 3;
  if (memcmp (control_data.headers + headers[0].value_offset, "custom-value",
	      12))
    return 3;
  vec_free (headers);
  vec_free (buf);

  return 0;
}

static int
http_test_parse_response (const char *first_resp, uword first_resp_len,
			  const char *second_resp, uword second_resp_len,
			  const char *third_resp, uword third_resp_len,
			  hpack_dynamic_table_t *dynamic_table)
{
  http2_error_t rv;
  u8 *buf = 0;
  hpack_response_control_data_t control_data;
  http_field_line_t *headers = 0;
  u16 parsed_bitmap;

  static http2_error_t (*_hpack_parse_response) (
    u8 * src, u32 src_len, u8 * dst, u32 dst_len,
    hpack_response_control_data_t * control_data, http_field_line_t * *headers,
    hpack_dynamic_table_t * dynamic_table);

  _hpack_parse_response =
    vlib_get_plugin_symbol ("http_plugin.so", "hpack_parse_response");

  parsed_bitmap = HPACK_PSEUDO_HEADER_STATUS_PARSED;

  /* first request */
  vec_validate_init_empty (buf, 254, 0);
  memset (&control_data, 0, sizeof (control_data));
  rv = _hpack_parse_response ((u8 *) first_resp, (u32) first_resp_len, buf,
			      254, &control_data, &headers, dynamic_table);
  if (rv != HTTP2_ERROR_NO_ERROR ||
      control_data.parsed_bitmap != parsed_bitmap ||
      control_data.sc != HTTP_STATUS_FOUND || vec_len (headers) != 3 ||
      dynamic_table->used != 222)
    return 1;
  if (headers[0].name_len != 13 || headers[0].value_len != 7)
    return 1;
  if (memcmp (control_data.headers + headers[0].name_offset, "cache-control",
	      13))
    return 1;
  if (memcmp (control_data.headers + headers[0].value_offset, "private", 7))
    return 1;
  if (headers[1].name_len != 4 || headers[1].value_len != 29)
    return 1;
  if (memcmp (control_data.headers + headers[1].name_offset, "date", 4))
    return 1;
  if (memcmp (control_data.headers + headers[1].value_offset,
	      "Mon, 21 Oct 2013 20:13:21 GMT", 29))
    return 1;
  if (headers[2].name_len != 8 || headers[2].value_len != 23)
    return 1;
  if (memcmp (control_data.headers + headers[2].name_offset, "location", 8))
    return 1;
  if (memcmp (control_data.headers + headers[2].value_offset,
	      "https://www.example.com", 23))
    return 1;
  vec_free (headers);
  vec_free (buf);

  /* second request */
  vec_validate_init_empty (buf, 254, 0);
  memset (&control_data, 0, sizeof (control_data));
  rv = _hpack_parse_response ((u8 *) second_resp, (u32) second_resp_len, buf,
			      254, &control_data, &headers, dynamic_table);
  if (rv != HTTP2_ERROR_NO_ERROR ||
      control_data.parsed_bitmap != parsed_bitmap ||
      control_data.sc != HTTP_STATUS_TEMPORARY_REDIRECT ||
      vec_len (headers) != 3 || dynamic_table->used != 222)
    return 2;
  if (headers[0].name_len != 13 || headers[0].value_len != 7)
    return 1;
  if (memcmp (control_data.headers + headers[0].name_offset, "cache-control",
	      13))
    return 1;
  if (memcmp (control_data.headers + headers[0].value_offset, "private", 7))
    return 1;
  if (headers[1].name_len != 4 || headers[1].value_len != 29)
    return 1;
  if (memcmp (control_data.headers + headers[1].name_offset, "date", 4))
    return 1;
  if (memcmp (control_data.headers + headers[1].value_offset,
	      "Mon, 21 Oct 2013 20:13:21 GMT", 29))
    return 1;
  if (headers[2].name_len != 8 || headers[2].value_len != 23)
    return 1;
  if (memcmp (control_data.headers + headers[2].name_offset, "location", 8))
    return 1;
  if (memcmp (control_data.headers + headers[2].value_offset,
	      "https://www.example.com", 23))
    return 1;
  vec_free (headers);
  vec_free (buf);

  /* third request */
  vec_validate_init_empty (buf, 254, 0);
  memset (&control_data, 0, sizeof (control_data));
  rv = _hpack_parse_response ((u8 *) third_resp, (u32) third_resp_len, buf,
			      254, &control_data, &headers, dynamic_table);
  if (rv != HTTP2_ERROR_NO_ERROR ||
      control_data.parsed_bitmap != parsed_bitmap ||
      control_data.sc != HTTP_STATUS_OK || vec_len (headers) != 5 ||
      dynamic_table->used != 215)
    return 3;
  if (headers[0].name_len != 13 || headers[0].value_len != 7)
    return 1;
  if (memcmp (control_data.headers + headers[0].name_offset, "cache-control",
	      13))
    return 1;
  if (memcmp (control_data.headers + headers[0].value_offset, "private", 7))
    return 1;
  if (headers[1].name_len != 4 || headers[1].value_len != 29)
    return 1;
  if (memcmp (control_data.headers + headers[1].name_offset, "date", 4))
    return 1;
  if (memcmp (control_data.headers + headers[1].value_offset,
	      "Mon, 21 Oct 2013 20:13:22 GMT", 29))
    return 1;
  if (headers[2].name_len != 8 || headers[2].value_len != 23)
    return 1;
  if (memcmp (control_data.headers + headers[2].name_offset, "location", 8))
    return 1;
  if (memcmp (control_data.headers + headers[2].value_offset,
	      "https://www.example.com", 23))
    return 1;
  if (headers[3].name_len != 16 || headers[3].value_len != 4)
    return 1;
  if (memcmp (control_data.headers + headers[3].name_offset,
	      "content-encoding", 16))
    return 1;
  if (memcmp (control_data.headers + headers[3].value_offset, "gzip", 4))
    return 1;
  if (headers[4].name_len != 10 || headers[4].value_len != 56)
    return 1;
  if (memcmp (control_data.headers + headers[4].name_offset, "set-cookie", 10))
    return 1;
  if (memcmp (control_data.headers + headers[4].value_offset,
	      "foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1", 56))
    return 1;
  vec_free (headers);
  vec_free (buf);

  return 0;
}

static u8 *
http_test_literal_field (u8 *dst, const char *name, const char *value, u8 qpack)
{
  u32 n = strlen (name), v = strlen (value);
  if (qpack)
    {
      vec_add1 (dst, 0x20 | clib_min (n, 7));
      if (n >= 7)
	vec_add1 (dst, n - 7);
    }
  else
    {
      vec_add1 (dst, 0);
      vec_add1 (dst, n);
    }
  vec_add (dst, name, n);
  vec_add1 (dst, v);
  vec_add (dst, value, v);
  return dst;
}

static int
http_test_validation (vlib_main_t *vm)
{
  const char token_chars[] =
    "!#$%&'*+-.^_`|~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
  const char reg_name_chars[] =
    "-._~!$&'()*+,;=0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
  const char *component_chars[] = { "", ":", ":@/", ":@/?" };
  u8 value[] = { 'x', 0, 'y' };
  u32 token_failure = ~0U, name_failure = ~0U;
  for (u32 byte = 0; byte < 256; byte++)
    {
      value[1] = byte;
      u8 expected = memchr (token_chars, byte, sizeof (token_chars) - 1) != 0;
      if (http_token_char_is_valid (byte) != expected ||
	  http_token_is_valid (value, sizeof (value)) != expected)
	token_failure = byte;
      expected = expected && !(byte >= 'A' && byte <= 'Z');
      if (hpack_header_name_is_valid (value, sizeof (value)) != expected)
	name_failure = byte;
    }
  HTTP_TEST (token_failure == ~0U, "all 256 token bytes (failure 0x%x)", token_failure);
  HTTP_TEST (name_failure == ~0U, "all 256 lowercase field-name bytes (failure 0x%x)",
	     name_failure);
  HTTP_TEST (!http_token_is_valid (value, 0) && !hpack_header_name_is_valid (value, 0),
	     "empty tokens and field names are invalid");

  for (u32 component = 0; component < ARRAY_LEN (component_chars); component++)
    {
      u32 failed_byte = ~0U;
      for (u32 byte = 0; byte < 256; byte++)
	{
	  value[1] = byte;
	  u8 expected =
	    memchr (reg_name_chars, byte, sizeof (reg_name_chars) - 1) ||
	    memchr (component_chars[component], byte, strlen (component_chars[component]));
	  int encoded = -1;
	  int rv = http_validate_uri_component (value, sizeof (value), component, &encoded);
	  if ((rv == 0) != expected || (rv == 0 && encoded != 0))
	    failed_byte = byte;
	}
      HTTP_TEST (failed_byte == ~0U, "all 256 URI component %u bytes (failure 0x%x)", component,
		 failed_byte);
    }

  const struct
  {
    const char *text;
    u8 valid, encoded;
  } escaped[] = {
    { "plain", 1, 0 }, { "%00", 1, 1 }, { "%ff%2F%7e", 1, 1 }, { "x%3Ay", 1, 1 }, { "%", 0, 0 },
    { "%0", 0, 0 },    { "%0g", 0, 0 }, { "%g0", 0, 0 },       { "%%20", 0, 0 },
  };
  for (u32 i = 0; i < ARRAY_LEN (escaped); i++)
    for (u32 component = 0; component < ARRAY_LEN (component_chars); component++)
      {
	int encoded = -1;
	int rv = http_validate_uri_component ((u8 *) escaped[i].text, strlen (escaped[i].text),
					      component, &encoded);
	HTTP_TEST ((rv == 0) == escaped[i].valid &&
		     encoded == (escaped[i].valid ? escaped[i].encoded : -1),
		   "URI component %u percent syntax '%s'", component, escaped[i].text);
      }
  u8 target[] = "/path?query/?%2f";
  int encoded = 0;
  HTTP_TEST (http_validate_target_syntax (target, sizeof (target) - 1, 0, 0) != 0 &&
	       !http_validate_target_syntax (target, sizeof (target) - 1, 1, &encoded) && encoded,
	     "path and combined path/query delimiters remain distinct");

  const struct
  {
    const char *text;
    u32 consumed;
    u16 port;
    u8 valid;
  } ports[] = {
    { "", 0, 0, 0 },	      { "0", 1, 0, 1 },	     { "443", 3, 443, 1 },
    { "65535", 5, 65535, 1 }, { "65536", 0, 0, 0 },  { "00000000000000443", 17, 443, 1 },
    { "443/", 3, 443, 1 },    { "443x", 3, 443, 1 }, { "-1", 0, 0, 0 },
    { " 443", 0, 0, 0 },
  };
  for (u32 i = 0; i < ARRAY_LEN (ports); i++)
    {
      u8 *p = (u8 *) ports[i].text;
      u32 len = strlen (ports[i].text);
      u16 port;
      int rv = _http_parse_port (&p, p + len, &port);
      HTTP_TEST ((rv == 0) == ports[i].valid &&
		   (!ports[i].valid || (p == (u8 *) ports[i].text + ports[i].consumed &&
					clib_net_to_host_u16 (port) == ports[i].port)),
		 "port '%s' bounds, byte order and delimiter", ports[i].text);
      u8 *authority = format (0, "example.com:%s", ports[i].text);
      for (u32 required = 0; required < 2; required++)
	{
	  hpack_authority_t parsed;
	  u8 expected = len ? ports[i].valid && ports[i].consumed == len : !required;
	  u8 valid = hpack_authority_parse (authority, vec_len (authority), required, 0, &parsed);
	  HTTP_TEST (valid == expected &&
		       (!valid || (parsed.has_port == (len != 0) && parsed.port == ports[i].port)),
		     "authority '%v' port policy %u", authority, required);
	}
      vec_free (authority);
    }
  return 0;
}

static int
http_test_schemes (vlib_main_t *vm)
{
  const char first_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
  const char later_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+-.";
  u8 name[] = ":scheme", value[2] = { 'a', 'a' };
  for (u32 position = 0; position < 2; position++)
    {
      u32 failed_byte = ~0;
      for (u32 byte = 0; byte < 256; byte++)
	{
	  hpack_request_control_data_t cd = {};
	  value[0] = position ? 'a' : byte;
	  value[1] = byte;
	  const char *allowed = position ? later_chars : first_chars;
	  u8 expected = memchr (allowed, byte, strlen (allowed)) != 0;
	  hpack_error_t rv =
	    hpack_parse_req_pseudo_header (name, sizeof (name) - 1, value, position + 1, &cd);
	  if ((rv == HPACK_ERROR_NONE) != expected ||
	      (expected && cd.scheme != HTTP_URL_SCHEME_UNKNOWN))
	    {
	      failed_byte = byte;
	      break;
	    }
	}
      HTTP_TEST (
	failed_byte == ~0U,
	"scheme %s character: all 256 byte values classified before enum mapping (failure 0x%x)",
	position ? "continuation" : "initial", failed_byte);
    }

  static http2_error_t (*parse_h2) (u8 *, u32, u8 *, u32, hpack_request_control_data_t *,
				    http_field_line_t **, hpack_dynamic_table_t *);
  static http3_error_t (*parse_h3) (u8 *, u32, u8 *, u32, hpack_request_control_data_t *,
				    http_field_line_t **, qpack_decoder_ctx_t *);
  static void (*table_init) (hpack_dynamic_table_t *, u32);
  static void (*table_free) (hpack_dynamic_table_t *);
  parse_h2 = vlib_get_plugin_symbol ("http_plugin.so", "hpack_parse_request");
  parse_h3 = vlib_get_plugin_symbol ("http_plugin.so", "qpack_parse_request");
  table_init = vlib_get_plugin_symbol ("http_plugin.so", "hpack_dynamic_table_init");
  table_free = vlib_get_plugin_symbol ("http_plugin.so", "hpack_dynamic_table_free");
  const struct
  {
    const char *value;
    http_url_scheme_t scheme;
    u8 malformed;
  } cases[] = {
    { "http", HTTP_URL_SCHEME_HTTP, 0 },	{ "https", HTTP_URL_SCHEME_HTTPS, 0 },
    { "masque", HTTP_URL_SCHEME_MASQUE, 0 },	{ "HtTp", HTTP_URL_SCHEME_HTTP, 0 },
    { "HTTPS", HTTP_URL_SCHEME_HTTPS, 0 },	{ "MaSqUe", HTTP_URL_SCHEME_MASQUE, 0 },
    { "web+demo", HTTP_URL_SCHEME_UNKNOWN, 0 }, { "x", HTTP_URL_SCHEME_UNKNOWN, 0 },
    { "A0+.-", HTTP_URL_SCHEME_UNKNOWN, 0 },	{ "", HTTP_URL_SCHEME_UNKNOWN, 1 },
    { "1https", HTTP_URL_SCHEME_UNKNOWN, 1 },	{ "ht:tps", HTTP_URL_SCHEME_UNKNOWN, 1 },
    { "http_", HTTP_URL_SCHEME_UNKNOWN, 1 },	{ "https ", HTTP_URL_SCHEME_UNKNOWN, 1 },
    { "+http", HTTP_URL_SCHEME_UNKNOWN, 1 },	{ 0, HTTP_URL_SCHEME_UNKNOWN, 1 },
  };
  for (u32 qpack = 0; qpack < 2; qpack++)
    for (u32 i = 0; i < ARRAY_LEN (cases); i++)
      {
	u8 *input = 0, *buf = 0;
	http_field_line_t *headers = 0;
	hpack_request_control_data_t cd;
	hpack_dynamic_table_t table;
	qpack_decoder_ctx_t decoder = {};
	if (qpack)
	  {
	    vec_add1 (input, 0);
	    vec_add1 (input, 0);
	  }
	input = http_test_literal_field (input, ":method", "GET", qpack);
	if (cases[i].value)
	  input = http_test_literal_field (input, ":scheme", cases[i].value, qpack);
	input = http_test_literal_field (input, ":authority", "example.com", qpack);
	input = http_test_literal_field (input, ":path", "/", qpack);
	vec_validate (buf, 1023);
	table_init (&table, 4096);
	u32 rv = qpack ?
		   parse_h3 (input, vec_len (input), buf, vec_len (buf), &cd, &headers, &decoder) :
		   parse_h2 (input, vec_len (input), buf, vec_len (buf), &cd, &headers, &table);
	u32 no_error = qpack ? HTTP3_ERROR_NO_ERROR : HTTP2_ERROR_NO_ERROR;
	u32 message_error = qpack ? HTTP3_ERROR_MESSAGE_ERROR : HTTP2_ERROR_PROTOCOL_ERROR;
	if (rv == no_error && hpack_validate_request_pseudo_headers (&cd, 1))
	  rv = message_error;
	u8 ok = rv == (cases[i].malformed ? message_error : no_error) &&
		(cases[i].malformed || cd.scheme == cases[i].scheme);
	table_free (&table);
	vec_free (input);
	vec_free (buf);
	vec_free (headers);
	HTTP_TEST (ok, "%s scheme '%s': syntax and support classified independently (error %u)",
		   qpack ? "QPACK" : "HPACK", cases[i].value ? cases[i].value : "(missing)", rv);
      }
  return 0;
}

static int
http_test_pseudo_headers (vlib_main_t *vm)
{
  const struct
  {
    char *method, *scheme, *authority, *path, *protocol;
    u8 enable_connect, valid;
  } requests[] = {
    { "GET", "https", "example.com", "/", 0, 0, 1 },
    { "GET", "HTTPS", "example.com", "/?q=%2f", 0, 0, 1 },
    { "OPTIONS", "https", "example.com", "*", 0, 0, 1 },
    { "X-NEW", "new+scheme", 0, "/", 0, 0, 1 },
    { "CONNECT", 0, "example.com:443", 0, 0, 0, 1 },
    { "CONNECT", 0, "[::1]:443", 0, 0, 0, 1 },
    { "CONNECT", "https", "example.com", "/", "websocket", 1, 1 },
    { "CONNECT", "https", "example.com", "/", "unknown", 1, 1 },
    { "CONNECT", "https", "example.com", "/", "websocket", 0, 0 },
    { "CONNECT", 0, "example.com:443", "/", 0, 1, 0 },
    { "CONNECT", "https", "example.com:443", 0, 0, 1, 0 },
    { "CONNECT", "https", "example.com", 0, "websocket", 1, 0 },
    { "CONNECT", 0, "example.com", "/", "websocket", 1, 0 },
    { "CONNECT", 0, "example.com", 0, 0, 0, 0 },
    { "CONNECT", 0, "x", 0, 0, 0, 0 },
    { "CONNECT", 0, "", 0, 0, 0, 0 },
    { "CONNECT", 0, ":443", 0, 0, 0, 0 },
    { "GET", "https", "user@example.com", "/", 0, 0, 0 },
    { "GET", "https", "example.com", "relative", 0, 0, 0 },
    { "GET", "https", "example.com", "*", 0, 0, 0 },
    { "GET", "https", "example.com", "/#fragment", 0, 0, 0 },
    { "GET", "https", "example.com", "/%XX", 0, 0, 0 },
    { "GET", "https", "example.com", "/", "websocket", 1, 0 },
    { "GET", "1https", "example.com", "/", 0, 0, 0 },
    { "GET", "", "example.com", "/", 0, 0, 0 },
    { "GET", "https", "", "/", 0, 0, 0 },
    { "", "https", "example.com", "/", 0, 0, 0 },
    { 0, "https", "example.com", "/", 0, 0, 0 },
    { "CONNECT-UDP", "masque", "example.com:443", "/", 0, 0, 1 },
    { "CONNECT-UDP", 0, "example.com:443", "/", 0, 0, 0 },
  };
  const char *names[] = { ":method", ":scheme", ":authority", ":path", ":protocol" };
  for (u32 i = 0; i < ARRAY_LEN (requests); i++)
    {
      hpack_request_control_data_t cd = {};
      cd.method = HTTP_REQ_UNKNOWN;
      cd.scheme = HTTP_URL_SCHEME_UNKNOWN;
      const char *values[] = { requests[i].method, requests[i].scheme, requests[i].authority,
			       requests[i].path, requests[i].protocol };
      hpack_error_t rv = HPACK_ERROR_NONE;
      for (u32 j = 0; j < ARRAY_LEN (names); j++)
	if (values[j])
	  {
	    rv = hpack_parse_req_pseudo_header ((u8 *) names[j], strlen (names[j]),
						(u8 *) values[j], strlen (values[j]), &cd);
	    if (rv)
	      break;
	  }
      if (!rv)
	rv = hpack_validate_request_pseudo_headers (&cd, requests[i].enable_connect);
      HTTP_TEST ((rv == HPACK_ERROR_NONE) == requests[i].valid,
		 "request pseudo-header presence/value rules, case %u", i);
    }

  static http2_error_t (*parse_h2) (u8 *, u32, u8 *, u32, hpack_response_control_data_t *,
				    http_field_line_t **, hpack_dynamic_table_t *);
  static http3_error_t (*parse_h3) (u8 *, u32, u8 *, u32, hpack_response_control_data_t *,
				    http_field_line_t **, qpack_decoder_ctx_t *);
  static void (*table_init) (hpack_dynamic_table_t *, u32);
  static void (*table_free) (hpack_dynamic_table_t *);
  parse_h2 = vlib_get_plugin_symbol ("http_plugin.so", "hpack_parse_response");
  parse_h3 = vlib_get_plugin_symbol ("http_plugin.so", "qpack_parse_response");
  table_init = vlib_get_plugin_symbol ("http_plugin.so", "hpack_dynamic_table_init");
  table_free = vlib_get_plugin_symbol ("http_plugin.so", "hpack_dynamic_table_free");
  const struct
  {
    char *name, *value, *extra_name, *extra_value;
    u8 valid, bad_index;
  } responses[] = {
    { ":status", "200", 0, 0, 1, 0 },
    { ":status", "100", 0, 0, 1, 0 },
    { ":status", "103", 0, 0, 1, 0 },
    { ":status", "599", "server", "", 1, 0 },
    { 0, 0, 0, 0, 0, 0 },
    { "server", "", 0, 0, 0, 0 },
    { ":status", "", 0, 0, 0, 0 },
    { ":status", "20", 0, 0, 0, 0 },
    { ":status", "2000", 0, 0, 0, 0 },
    { ":status", "2x0", 0, 0, 0, 0 },
    { ":status", "099", 0, 0, 0, 0 },
    { ":status", "600", 0, 0, 0, 0 },
    { ":status", "101", 0, 0, 0, 0 },
    { ":status", "200", ":status", "200", 0, 0 },
    { ":status", "200", ":method", "GET", 0, 0 },
    { ":method", "GET", 0, 0, 0, 0 },
    { ":foobar", "200", 0, 0, 0, 0 },
    { ":abcdefgh", "", 0, 0, 0, 0 },
    { "server", "", ":status", "200", 0, 0 },
    { ":foobar", "200", 0, 0, 0, 1 },
  };
  for (u32 qpack = 0; qpack < 2; qpack++)
    for (u32 i = 0; i < ARRAY_LEN (responses); i++)
      {
	u8 *input = 0, *buf = 0;
	http_field_line_t *headers = 0;
	hpack_response_control_data_t cd;
	hpack_dynamic_table_t table;
	qpack_decoder_ctx_t decoder = {};
	vec_validate (input, 1);
	vec_reset_length (input);
	vec_validate (buf, 1023);
	if (qpack)
	  {
	    vec_add1 (input, 0);
	    vec_add1 (input, 0);
	  }
	if (responses[i].name)
	  input = http_test_literal_field (input, responses[i].name, responses[i].value, qpack);
	if (responses[i].extra_name)
	  input = http_test_literal_field (input, responses[i].extra_name, responses[i].extra_value,
					   qpack);
	if (responses[i].bad_index)
	  {
	    vec_add1 (input, qpack ? 0xff : 0x80);
	    if (qpack)
	      vec_add1 (input, 0x24);
	  }
	table_init (&table, 4096);
	u32 rv = qpack ?
		   parse_h3 (input, vec_len (input), buf, vec_len (buf), &cd, &headers, &decoder) :
		   parse_h2 (input, vec_len (input), buf, vec_len (buf), &cd, &headers, &table);
	u32 expected =
	  responses[i].valid ?
	    (qpack ? HTTP3_ERROR_NO_ERROR : HTTP2_ERROR_NO_ERROR) :
	  responses[i].bad_index ?
	    (qpack ? HTTP3_ERROR_QPACK_DECOMPRESSION_FAILED : HTTP2_ERROR_COMPRESSION_ERROR) :
	    (qpack ? HTTP3_ERROR_MESSAGE_ERROR : HTTP2_ERROR_PROTOCOL_ERROR);
	table_free (&table);
	vec_free (input);
	vec_free (buf);
	vec_free (headers);
	HTTP_TEST (rv == expected, "%s response pseudo-header case %u: %u, expected %u",
		   qpack ? "QPACK" : "HPACK", i, rv, expected);
      }
  return 0;
}

static int
http_test_hpack (vlib_main_t *vm)
{
  if (http_test_validation (vm))
    return 1;
  if (http_test_schemes (vm))
    return 1;
  if (http_test_pseudo_headers (vm))
    return 1;
  vlib_cli_output (vm, "method syntax and mapping");

  hpack_request_control_data_t method_cd;
  hpack_error_t method_rv;
  u8 method_name[] = ":method";
  u8 method_value[] = "X?Y";
  const char token_chars[] =
    "!#$%&'*+-.^_`|~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

  /* Exercise every byte inside a method, including NUL and non-ASCII. */
  for (u32 i = 0; i < 256; i++)
    {
      method_value[1] = i;
      clib_memset (&method_cd, 0, sizeof (method_cd));
      method_rv = hpack_parse_req_pseudo_header (
	method_name, sizeof (method_name) - 1, method_value, sizeof (method_value) - 1, &method_cd);
      u8 valid = memchr (token_chars, i, sizeof (token_chars) - 1) != 0;
      HTTP_TEST (method_rv == (valid ? HPACK_ERROR_NONE : HPACK_ERROR_PROTOCOL),
		 "method containing byte 0x%02x: %s", i, valid ? "valid" : "invalid");
      if (valid)
	HTTP_TEST (method_cd.method == HTTP_REQ_UNKNOWN, "valid extension method");
    }
  clib_memset (&method_cd, 0, sizeof (method_cd));
  method_rv = hpack_parse_req_pseudo_header (method_name, sizeof (method_name) - 1, method_value, 0,
					     &method_cd);
  HTTP_TEST (method_rv == HPACK_ERROR_PROTOCOL, "empty method is invalid");

#define _(sym, str)                                                                                \
  clib_memset (&method_cd, 0, sizeof (method_cd));                                                 \
  method_rv = hpack_parse_req_pseudo_header (method_name, sizeof (method_name) - 1, (u8 *) str,    \
					     sizeof (str) - 1, &method_cd);                        \
  HTTP_TEST (method_rv == HPACK_ERROR_NONE && method_cd.method == HTTP_REQ_##sym,                  \
	     "method mapping: %s", str);
  foreach_http_method
#undef _

    vlib_cli_output (vm, "hpack_decode_int");

  u8 *pos, *end, *input = 0;
  uword value;
#define TEST(i, pl, e)                                                        \
  vec_validate (input, sizeof (i) - 2);                                       \
  memcpy (input, i, sizeof (i) - 1);                                          \
  pos = input;                                                                \
  end = vec_end (input);                                                      \
  value = hpack_decode_int (&pos, end, (u8) pl);                              \
  HTTP_TEST ((value == (uword) e && pos == end),                              \
	     "%U with prefix length %u is %llu", format_hex_bytes, input,     \
	     vec_len (input), (u8) pl, value);                                \
  vec_free (input);

  TEST ("\x00", 8, 0);
  TEST ("\x2A", 8, 42);
  TEST ("\x72", 4, 2);
  TEST ("\x7F\x00", 7, 127);
  TEST ("\x7F\x01", 7, 128);
  TEST ("\x9F\x9A\x0A", 5, 1337);
  TEST ("\xFF\x80\x01", 7, 255);
  /* max value to decode is CLIB_WORD_MAX, CLIB_UWORD_MAX is error */
  TEST ("\x7F\x80\xFF\xFF\xFF\xFF\xFF\xFF\xFF\x7F", 7, CLIB_WORD_MAX);

#undef TEST

#define N_TEST(i, pl)                                                         \
  vec_validate (input, sizeof (i) - 2);                                       \
  memcpy (input, i, sizeof (i) - 1);                                          \
  pos = input;                                                                \
  end = vec_end (input);                                                      \
  value = hpack_decode_int (&pos, end, (u8) pl);                              \
  HTTP_TEST ((value == HPACK_INVALID_INT),                                    \
	     "%U with prefix length %u should be invalid", format_hex_bytes,  \
	     input, vec_len (input), (u8) pl);                                \
  vec_free (input);

  /* incomplete */
  N_TEST ("\x7F", 7);
  N_TEST ("\x0F\xFF\xFF", 4);
  /* overflow */
  N_TEST ("\x0F\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\x00", 4);
  N_TEST ("\x0F\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\x00", 4);

#undef N_TEST

  vlib_cli_output (vm, "hpack_encode_int");

  u8 *buf = 0;
  u8 *p;

#define TEST(v, pl, e)                                                        \
  vec_validate_init_empty (buf, 15, 0);                                       \
  p = hpack_encode_int (buf, v, (u8) pl);                                     \
  HTTP_TEST (((p - buf) == (sizeof (e) - 1) && !memcmp (buf, e, p - buf)),    \
	     "%llu with prefix length %u is encoded as %U", v, (u8) pl,       \
	     format_hex_bytes, buf, p - buf);                                 \
  vec_free (buf);

  TEST (0, 8, "\x00");
  TEST (2, 4, "\x02");
  TEST (42, 8, "\x2A");
  TEST (127, 7, "\x7F\x00");
  TEST (128, 7, "\x7F\x01");
  TEST (255, 7, "\x7F\x80\x01");
  TEST (1337, 5, "\x1F\x9A\x0A");
  TEST (CLIB_WORD_MAX, 7, "\x7F\x80\xFF\xFF\xFF\xFF\xFF\xFF\xFF\x7F");
#undef TEST

  vlib_cli_output (vm, "hpack_decode_string");

  static hpack_error_t (*_hpack_decode_string) (u8 * *src, u8 * end, u8 * *buf,
						uword * buf_len);
  _hpack_decode_string =
    vlib_get_plugin_symbol ("http_plugin.so", "hpack_decode_string");

  u8 *bp;
  uword blen, len;
  hpack_error_t rv;

#define TEST(i, e)                                                            \
  vec_validate (input, sizeof (i) - 2);                                       \
  memcpy (input, i, sizeof (i) - 1);                                          \
  pos = input;                                                                \
  vec_validate_init_empty (buf, 63, 0);                                       \
  bp = buf;                                                                   \
  blen = vec_len (buf);                                                       \
  rv = _hpack_decode_string (&pos, vec_end (input), &bp, &blen);              \
  len = vec_len (buf) - blen;                                                 \
  HTTP_TEST ((len == strlen (e) && !memcmp (buf, e, len) &&                   \
	      pos == vec_end (input) && bp == buf + len &&                    \
	      rv == HPACK_ERROR_NONE),                                        \
	     "%U is decoded as %U", format_hex_bytes, input, vec_len (input), \
	     format_http_bytes, buf, len);                                    \
  vec_free (input);                                                           \
  vec_free (buf);

  /* raw coding */
  TEST ("\x07private", "private");
  /* Huffman coding */
  TEST ("\x85\xAE\xC3\x77\x1A\x4B", "private");
  TEST ("\x86\xA8\xEB\x10\x64\x9C\xBF", "no-cache");
  TEST ("\x8C\xF1\xE3\xC2\xE5\xF2\x3A\x6B\xA0\xAB\x90\xF4\xFF",
	"www.example.com");
  TEST ("\x96\xD0\x7A\xBE\x94\x10\x54\xD4\x44\xA8\x20\x05\x95\x04\x0B\x81\x66"
	"\xE0\x82\xA6\x2D\x1B\xFF",
	"Mon, 21 Oct 2013 20:13:21 GMT")
  TEST ("\xAD\x94\xE7\x82\x1D\xD7\xF2\xE6\xC7\xB3\x35\xDF\xDF\xCD\x5B\x39\x60"
	"\xD5\xAF\x27\x08\x7F\x36\x72\xC1\xAB\x27\x0F\xB5\x29\x1F\x95\x87\x31"
	"\x60\x65\xC0\x03\xED\x4E\xE5\xB1\x06\x3D\x50\x07",
	"foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1");
  TEST ("\x8A\x9C\xB4\x50\x75\x3C\x1E\xCA\x24\xFE\x3F", "hello world!")
  TEST ("\x8A\xFF\xFE\x03\x18\xC6\x31\x8C\x63\x18\xC7", "\\aaaaaaaaaaaa");
  TEST ("\x8C\x1F\xFF\xF0\x18\xC6\x31\x80\x03\x18\xC6\x31\x8F",
	"a\\aaaaa00aaaaaaa");
  TEST ("\x87\x1F\xFF\xF0\xFF\xFE\x11\xFF", "a\\\\b");
  TEST ("\x84\x1F\xF9\xFE\xA3", "a?'b");
  TEST ("\x84\x1F\xFA\xFF\x23", "a'?b");
  TEST ("\x8D\x1F\xFF\xFF\xFF\x0C\x63\x18\xC0\x01\x8C\x63\x18\xC7",
	"\x61\xF9\x61\x61\x61\x61\x61\x30\x30\x61\x61\x61\x61\x61\x61\x61")
#undef TEST

#define N_TEST(i, e)                                                          \
  vec_validate (input, sizeof (i) - 2);                                       \
  memcpy (input, i, sizeof (i) - 1);                                          \
  pos = input;                                                                \
  vec_validate_init_empty (buf, 15, 0);                                       \
  bp = buf;                                                                   \
  blen = vec_len (buf);                                                       \
  rv = _hpack_decode_string (&pos, vec_end (input), &bp, &blen);              \
  HTTP_TEST ((rv == e), "%U should be invalid (%U)", format_hex_bytes, input, \
	     vec_len (input), format_http2_error, rv);                        \
  vec_free (input);                                                           \
  vec_free (buf);

  /* incomplete */
  N_TEST ("\x87", HPACK_ERROR_COMPRESSION);
  N_TEST ("\x07priv", HPACK_ERROR_COMPRESSION);
  /* invalid length */
  N_TEST ("\x7Fprivate", HPACK_ERROR_COMPRESSION);
  /* invalid EOF */
  N_TEST ("\x81\x8C", HPACK_ERROR_COMPRESSION);
  N_TEST ("\x98\xDC\x53\xFF\xFF\xFF\xDF\xFF\xFF\xFF\x14\xFF\xFF\xFF\xF7\xFF"
	  "\xFF\xFF\xC5\x3F\xFF\xFF\xFD\xFF\xFF",
	  HPACK_ERROR_COMPRESSION);
  /* not enough space for decoding */
  N_TEST (
    "\x96\xD0\x7A\xBE\x94\x10\x54\xD4\x44\xA8\x20\x05\x95\x04\x0B\x81\x66"
    "\xE0\x82\xA6\x2D\x1B\xFF",
    HPACK_ERROR_UNKNOWN);
#undef N_TEST

  vlib_cli_output (vm, "hpack_encode_string");

  static u8 *(*_hpack_encode_string) (u8 * dst, const u8 *value,
				      uword value_len);
  _hpack_encode_string =
    vlib_get_plugin_symbol ("http_plugin.so", "hpack_encode_string");

#define TEST(i, e)                                                            \
  vec_validate (input, sizeof (i) - 2);                                       \
  memcpy (input, i, sizeof (i) - 1);                                          \
  pos = input;                                                                \
  vec_validate_init_empty (buf, 63, 0);                                       \
  p = _hpack_encode_string (buf, input, vec_len (input));                     \
  HTTP_TEST (((p - buf) == (sizeof (e) - 1) && !memcmp (buf, e, p - buf)),    \
	     "%v is encoded as %U", input, format_hex_bytes, buf, p - buf);   \
  vec_free (input);                                                           \
  vec_free (buf);

  /* Huffman coding */
  TEST ("private", "\x85\xAE\xC3\x77\x1A\x4B");
  TEST ("no-cache", "\x86\xA8\xEB\x10\x64\x9C\xBF");
  TEST ("www.example.com",
	"\x8C\xF1\xE3\xC2\xE5\xF2\x3A\x6B\xA0\xAB\x90\xF4\xFF");
  TEST ("Mon, 21 Oct 2013 20:13:21 GMT",
	"\x96\xD0\x7A\xBE\x94\x10\x54\xD4\x44\xA8\x20\x05\x95\x04\x0B\x81\x66"
	"\xE0\x82\xA6\x2D\x1B\xFF")
  TEST ("foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1",
	"\xAD\x94\xE7\x82\x1D\xD7\xF2\xE6\xC7\xB3\x35\xDF\xDF\xCD\x5B\x39\x60"
	"\xD5\xAF\x27\x08\x7F\x36\x72\xC1\xAB\x27\x0F\xB5\x29\x1F\x95\x87\x31"
	"\x60\x65\xC0\x03\xED\x4E\xE5\xB1\x06\x3D\x50\x07");
  TEST ("hello world!", "\x8A\x9C\xB4\x50\x75\x3C\x1E\xCA\x24\xFE\x3F")
  TEST ("\\aaaaaaaaaaaa", "\x8A\xFF\xFE\x03\x18\xC6\x31\x8C\x63\x18\xC7");
  /* raw coding */
  TEST ("[XZ]", "\x4[XZ]");
#undef TEST

  vlib_cli_output (vm, "hpack_decode_header");

  static hpack_error_t (*_hpack_decode_header) (u8 * *src, u8 * end, u8 * *buf, uword * buf_len,
						u32 * name_len, u32 * value_len,
						hpack_dynamic_table_t * dt, u8 * never_index);

  _hpack_decode_header =
    vlib_get_plugin_symbol ("http_plugin.so", "hpack_decode_header");

  static void (*_hpack_dynamic_table_init) (hpack_dynamic_table_t * table,
					    u32 max_size);

  _hpack_dynamic_table_init =
    vlib_get_plugin_symbol ("http_plugin.so", "hpack_dynamic_table_init");

  static void (*_hpack_dynamic_table_free) (hpack_dynamic_table_t * table);

  _hpack_dynamic_table_free =
    vlib_get_plugin_symbol ("http_plugin.so", "hpack_dynamic_table_free");

  u32 name_len, value_len;
  hpack_dynamic_table_t table;
  u8 never_index;

  _hpack_dynamic_table_init (&table, 128);

#define TEST(i, e_name, e_value, dt_size, e_never_index)                                           \
  vec_validate (input, sizeof (i) - 2);                                                            \
  memcpy (input, i, sizeof (i) - 1);                                                               \
  pos = input;                                                                                     \
  vec_validate_init_empty (buf, 63, 0);                                                            \
  bp = buf;                                                                                        \
  blen = vec_len (buf);                                                                            \
  never_index = 0;                                                                                 \
  rv = _hpack_decode_header (&pos, vec_end (input), &bp, &blen, &name_len, &value_len, &table,     \
			     &never_index);                                                        \
  len = vec_len (buf) - blen;                                                                      \
  HTTP_TEST ((rv == HPACK_ERROR_NONE && table.used == (dt_size) && name_len == strlen (e_name) &&  \
	      value_len == strlen (e_value) && !memcmp (buf, e_name, name_len) &&                  \
	      !memcmp (buf + name_len, e_value, value_len) &&                                      \
	      vec_len (buf) == (blen + name_len + value_len) && pos == vec_end (input) &&          \
	      bp == buf + name_len + value_len && (e_never_index) == never_index),                 \
	     "%U is decoded as '%U: %U'", format_hex_bytes, input, vec_len (input),                \
	     format_http_bytes, buf, name_len, format_http_bytes, buf + name_len, value_len);      \
  vec_free (input);                                                                                \
  vec_free (buf);

  /* C.2.1. Literal Header Field with Indexing */
  TEST ("\x40\x0A\x63\x75\x73\x74\x6F\x6D\x2D\x6B\x65\x79\x0D\x63\x75\x73\x74"
	"\x6F\x6D\x2D\x68\x65\x61\x64\x65\x72",
	"custom-key", "custom-header", 55, 0);
  /* C.2.2. Literal Header Field without Indexing */
  TEST ("\x04\x0C\x2F\x73\x61\x6D\x70\x6C\x65\x2F\x70\x61\x74\x68", ":path", "/sample/path", 55, 0);
  /* C.2.3. Literal Header Field Never Indexed */
  TEST ("\x10\x08\x70\x61\x73\x73\x77\x6F\x72\x64\x06\x73\x65\x63\x72\x65\x74", "password",
	"secret", 55, 1);
  /* C.2.4. Indexed Header Field */
  TEST ("\x82", ":method", "GET", 55, 0);
  TEST ("\xBE", "custom-key", "custom-header", 55, 0);
  /* Literal Header Field with Indexing - enough space in dynamic table */
  TEST ("\x41\x0F\x77\x77\x77\x2E\x65\x78\x61\x6D\x70\x6C\x65\x2E\x63\x6F\x6D", ":authority",
	"www.example.com", 112, 0);
  /* verification */
  TEST ("\xBE", ":authority", "www.example.com", 112, 0);
  TEST ("\xBF", "custom-key", "custom-header", 112, 0);
  /* Literal Header Field with Indexing - eviction */
  TEST ("\x58\x08\x6E\x6F\x2D\x63\x61\x63\x68\x65", "cache-control", "no-cache", 110, 0);
  /* verification */
  TEST ("\xBE", "cache-control", "no-cache", 110, 0);
  TEST ("\xBF", ":authority", "www.example.com", 110, 0);
  /* Literal Header Field with Indexing - eviction */
  TEST ("\x40\x0A\x63\x75\x73\x74\x6F\x6D\x2D\x6B\x65\x79\x0D\x63\x75\x73\x74"
	"\x6F\x6D\x2D\x68\x65\x61\x64\x65\x72",
	"custom-key", "custom-header", 108, 0);
  /* verification */
  TEST ("\xBE", "custom-key", "custom-header", 108, 0);
  TEST ("\xBF", "cache-control", "no-cache", 108, 0);
  /* Literal Header Field with Indexing - eviction */
  TEST ("\x41\x0F\x77\x77\x77\x2E\x65\x78\x61\x6D\x70\x6C\x65\x2E\x63\x6F\x6D", ":authority",
	"www.example.com", 112, 0);
  /* verification */
  TEST ("\xBE", ":authority", "www.example.com", 112, 0);
  TEST ("\xBF", "custom-key", "custom-header", 112, 0);
  /* Literal Header Field with Indexing - eviction with reference */
  TEST ("\x7F\x00\x0C\x63\x75\x73\x74\x6F\x6D\x2D\x76\x61\x6C\x75\x65", "custom-key",
	"custom-value", 111, 0);
  /* verification */
  TEST ("\xBE", "custom-key", "custom-value", 111, 0);
  TEST ("\xBF", ":authority", "www.example.com", 111, 0);
#undef TEST

  _hpack_dynamic_table_free (&table);

  vlib_cli_output (vm, "hpack_parse_request");

  int result;
  /* C.3. Request Examples without Huffman Coding */
  _hpack_dynamic_table_init (&table, HPACK_DEFAULT_HEADER_TABLE_SIZE);
  result = http_test_parse_request (
    http_token_lit ("\x82\x86\x84\x41\x0F\x77\x77\x77\x2E\x65\x78\x61"
		    "\x6D\x70\x6C\x65\x2E\x63\x6F\x6D"),
    http_token_lit (
      "\x82\x86\x84\xBE\x58\x08\x6E\x6F\x2D\x63\x61\x63\x68\x65"),
    http_token_lit (
      "\x82\x87\x85\xBF\x40\x0A\x63\x75\x73\x74\x6F\x6D\x2D\x6B"
      "\x65\x79\x0C\x63\x75\x73\x74\x6F\x6D\x2D\x76\x61\x6C\x75\x65"),
    &table);
  _hpack_dynamic_table_free (&table);
  HTTP_TEST ((result == 0), "request without Huffman Coding (result=%d)",
	     result);
  /* C.4. Request Examples with Huffman Coding */
  _hpack_dynamic_table_init (&table, HPACK_DEFAULT_HEADER_TABLE_SIZE);
  result = http_test_parse_request (
    http_token_lit (
      "\x82\x86\x84\x41\x8C\xF1\xE3\xC2\xE5\xF2\x3A\x6B\xA0\xAB\x90\xF4\xFF"),
    http_token_lit ("\x82\x86\x84\xBE\x58\x86\xA8\xEB\x10\x64\x9C\xBF"),
    http_token_lit ("\x82\x87\x85\xBF\x40\x88\x25\xA8\x49\xE9\x5B\xA9\x7D\x7F"
		    "\x89\x25\xA8\x49\xE9\x5B\xB8\xE8\xB4\xBF"),
    &table);
  _hpack_dynamic_table_free (&table);
  HTTP_TEST ((result == 0), "request with Huffman Coding (result=%d)", result);

  vlib_cli_output (vm, "hpack_parse_response");

  /* C.5. Response Examples without Huffman Coding */
  _hpack_dynamic_table_init (&table, 256);
  result = http_test_parse_response (
    http_token_lit (
      "\x48\x03\x33\x30\x32\x58\x07\x70\x72\x69\x76\x61\x74\x65"
      "\x61\x1D\x4D\x6F\x6E\x2C\x20\x32\x31\x20\x4F\x63\x74\x20\x32\x30\x31"
      "\x33\x20\x32\x30\x3A\x31\x33\x3A\x32\x31\x20\x47\x4D\x54\x6E\x17\x68"
      "\x74\x74\x70\x73\x3A\x2F\x2F\x77\x77\x77\x2E\x65\x78\x61\x6D\x70\x6C"
      "\x65\x2E\x63\x6F\x6D"),
    http_token_lit ("\x48\x03\x33\x30\x37\xC1\xC0\xBF"),
    http_token_lit (
      "\x88\xC1\x61\x1D\x4D\x6F\x6E\x2C\x20\x32\x31\x20\x4F\x63\x74\x20\x32"
      "\x30\x31\x33\x20\x32\x30\x3A\x31\x33\x3A\x32\x32\x20\x47\x4D\x54\xC0"
      "\x5A\x04\x67\x7A\x69\x70\x77\x38\x66\x6F\x6F\x3D\x41\x53\x44\x4A\x4B"
      "\x48\x51\x4B\x42\x5A\x58\x4F\x51\x57\x45\x4F\x50\x49\x55\x41\x58\x51"
      "\x57\x45\x4F\x49\x55\x3B\x20\x6D\x61\x78\x2D\x61\x67\x65\x3D\x33\x36"
      "\x30\x30\x3B\x20\x76\x65\x72\x73\x69\x6F\x6E\x3D\x31"),
    &table);
  _hpack_dynamic_table_free (&table);
  HTTP_TEST ((result == 0), "response without Huffman Coding (result=%d)",
	     result);

  /* C.6. Response Examples with Huffman Coding */
  _hpack_dynamic_table_init (&table, 256);
  result = http_test_parse_response (
    http_token_lit ("\x48\x82\x64\x02\x58\x85\xAE\xC3\x77\x1A\x4B\x61\x96\xD0"
		    "\x7A\xBE\x94\x10\x54\xD4\x44\xA8\x20\x05\x95\x04\x0B\x81"
		    "\x66\xE0\x82\xA6\x2D\x1B\xFF\x6E\x91\x9D\x29\xAD\x17\x18"
		    "\x63\xC7\x8F\x0B\x97\xC8\xE9\xAE\x82\xAE\x43\xD3"),
    http_token_lit ("\x48\x83\x64\x0E\xFF\xC1\xC0\xBF"),
    http_token_lit (
      "\x88\xC1\x61\x96\xD0\x7A\xBE\x94\x10\x54\xD4\x44\xA8\x20\x05\x95\x04"
      "\x0B\x81\x66\xE0\x84\xA6\x2D\x1B\xFF\xC0\x5A\x83\x9B\xD9\xAB\x77\xAD"
      "\x94\xE7\x82\x1D\xD7\xF2\xE6\xC7\xB3\x35\xDF\xDF\xCD\x5B\x39\x60\xD5"
      "\xAF\x27\x08\x7F\x36\x72\xC1\xAB\x27\x0F\xB5\x29\x1F\x95\x87\x31\x60"
      "\x65\xC0\x03\xED\x4E\xE5\xB1\x06\x3D\x50\x07"),
    &table);
  _hpack_dynamic_table_free (&table);
  HTTP_TEST ((result == 0), "response with Huffman Coding (result=%d)",
	     result);

  vlib_cli_output (vm, "hpack_serialize_response");

  hpack_response_control_data_t resp_cd = {};
  u8 *server_name;
  u8 *date;

  static void (*_hpack_serialize_response) (
    u8 * app_headers, u32 app_headers_len,
    hpack_response_control_data_t * control_data, u8 * *dst);

  _hpack_serialize_response =
    vlib_get_plugin_symbol ("http_plugin.so", "hpack_serialize_response");

  server_name = format (0, "http unit tests");
  date = format (0, "Mon, 21 Oct 2013 20:13:21 GMT");

  vec_validate (buf, 127);
  vec_reset_length (buf);
  resp_cd.sc = HTTP_STATUS_GATEWAY_TIMEOUT;
  resp_cd.content_len = HPACK_ENCODER_SKIP_CONTENT_LEN;
  resp_cd.server_name = server_name;
  resp_cd.server_name_len = vec_len (server_name);
  resp_cd.date = date;
  resp_cd.date_len = vec_len (date);
  u8 expected1[] =
    "\x08\x03\x35\x30\x34\x0F\x27\x8B\x9D\x29\xAD\x4B\x6A\x32\x54\x49\x50\x94"
    "\x7F\x0F\x12\x96\xD0\x7A\xBE\x94\x10\x54\xD4\x44\xA8\x20\x05\x95\x04\x0B"
    "\x81\x66\xE0\x82\xA6\x2D\x1B\xFF";
  _hpack_serialize_response (0, 0, &resp_cd, &buf);
  HTTP_TEST ((vec_len (buf) == (sizeof (expected1) - 1) &&
	      !memcmp (buf, expected1, sizeof (expected1) - 1)),
	     "response encoded as %U", format_hex_bytes, buf, vec_len (buf));
  vec_reset_length (buf);

  resp_cd.sc = HTTP_STATUS_OK;
  resp_cd.content_len = 1024;
  http_headers_ctx_t headers;
  u8 *headers_buf = 0;
  vec_validate (headers_buf, 127);
  http_init_headers_ctx (&headers, headers_buf, vec_len (headers_buf));
  http_add_header (&headers, HTTP_HEADER_CONTENT_TYPE,
		   http_token_lit ("text/plain"));
  http_add_header (&headers, HTTP_HEADER_CACHE_STATUS,
		   http_token_lit ("ExampleCache; hit"));
  http_add_custom_header (&headers, http_token_lit ("sandwich"),
			  http_token_lit ("spam"));
  u8 expected2[] =
    "\x88\x0F\x27\x8B\x9D\x29\xAD\x4B\x6A\x32\x54\x49\x50\x94\x7F\x0F\x12\x96"
    "\xD0\x7A\xBE\x94\x10\x54\xD4\x44\xA8\x20\x05\x95\x04\x0B\x81\x66\xE0\x82"
    "\xA6\x2D\x1B\xFF\x0F\x0D\x83\x08\x04\xD7\x0F\x10\x87\x49\x7C\xA5\x8A\xE8"
    "\x19\xAA\x00\x88\x20\xC9\x39\x56\x42\x46\x9B\x51\x8D\xC1\xE4\x74\xD7\x41"
    "\x6F\x0C\x93\x97\xED\x49\xCC\x9F\x00\x86\x40\xEA\x93\xC1\x89\x3F\x83\x45"
    "\x63\xA7";
  _hpack_serialize_response (headers_buf, headers.tail_offset, &resp_cd, &buf);
  HTTP_TEST ((vec_len (buf) == (sizeof (expected2) - 1) &&
	      !memcmp (buf, expected2, sizeof (expected2) - 1)),
	     "response encoded as %U", format_hex_bytes, buf, vec_len (buf));
  vec_reset_length (buf);
  vec_free (headers_buf);
  vec_free (date);

  vlib_cli_output (vm, "hpack_serialize_request");

  hpack_request_control_data_t req_cd;
  u8 *authority, *path;

  static void (*_hpack_serialize_request) (
    u8 * app_headers, u32 app_headers_len,
    hpack_request_control_data_t * control_data, u8 * *dst);

  _hpack_serialize_request =
    vlib_get_plugin_symbol ("http_plugin.so", "hpack_serialize_request");

  authority = format (0, "www.example.com");
  path = format (0, "/");

  vec_validate (buf, 127);
  vec_reset_length (buf);

  req_cd.method = HTTP_REQ_GET;
  req_cd.parsed_bitmap = HPACK_PSEUDO_HEADER_SCHEME_PARSED;
  req_cd.scheme = HTTP_URL_SCHEME_HTTP;
  req_cd.parsed_bitmap |= HPACK_PSEUDO_HEADER_PATH_PARSED;
  req_cd.path = path;
  req_cd.path_len = vec_len (path);
  req_cd.parsed_bitmap |= HPACK_PSEUDO_HEADER_AUTHORITY_PARSED;
  req_cd.authority = authority;
  req_cd.authority_len = vec_len (authority);
  req_cd.user_agent_len = 0;
  req_cd.content_len = HPACK_ENCODER_SKIP_CONTENT_LEN;
  u8 expected3[] =
    "\x82\x86\x84\x01\x8C\xF1\xE3\xC2\xE5\xF2\x3A\x6B\xA0\xAB\x90\xF4\xFF";
  _hpack_serialize_request (0, 0, &req_cd, &buf);
  HTTP_TEST ((vec_len (buf) == (sizeof (expected3) - 1) &&
	      !memcmp (buf, expected3, sizeof (expected3) - 1)),
	     "request encoded as %U", format_hex_bytes, buf, vec_len (buf));
  vec_reset_length (buf);
  vec_free (authority);
  vec_free (path);
  memset (&req_cd, 0, sizeof (req_cd));

  authority = format (0, "example.org:123");

  req_cd.method = HTTP_REQ_CONNECT;
  req_cd.parsed_bitmap |= HPACK_PSEUDO_HEADER_AUTHORITY_PARSED;
  req_cd.authority = authority;
  req_cd.authority_len = vec_len (authority);
  req_cd.user_agent = server_name;
  req_cd.user_agent_len = vec_len (server_name);
  req_cd.content_len = HPACK_ENCODER_SKIP_CONTENT_LEN;

  vec_validate (headers_buf, 127);
  http_init_headers_ctx (&headers, headers_buf, vec_len (headers_buf));
  http_add_custom_header (&headers, http_token_lit ("sandwich"),
			  http_token_lit ("spam"));

  u8 expected4[] =
    "\x02\x07\x43\x4F\x4E\x4E\x45\x43\x54\x01\x8B\x2F\x91\xD3\x5D\x05\x5C\xF6"
    "\x4D\x70\x22\x67\x0F\x2B\x8B\x9D\x29\xAD\x4B\x6A\x32\x54\x49\x50\x94\x7f"
    "\x00\x86\x40\xEA\x93\xC1\x89\x3F\x83\x45\x63\xA7";
  _hpack_serialize_request (headers_buf, headers.tail_offset, &req_cd, &buf);
  HTTP_TEST ((vec_len (buf) == (sizeof (expected4) - 1) &&
	      !memcmp (buf, expected4, sizeof (expected4) - 1)),
	     "request encoded as %U", format_hex_bytes, buf, vec_len (buf));
  vec_free (buf);
  vec_free (server_name);
  vec_free (authority);

  return 0;
}

static int
http_test_h2_frame (vlib_main_t *vm)
{
  static void (*_http2_frame_header_read) (u8 * src,
					   http2_frame_header_t * fh);

  _http2_frame_header_read =
    vlib_get_plugin_symbol ("http_plugin.so", "http2_frame_header_read");

  vlib_cli_output (vm, "http2_frame_read_settings");

  static http2_error_t (*_http2_frame_read_settings) (http_conn_settings_t * settings, u8 * payload,
						      u32 payload_len);

  _http2_frame_read_settings =
    vlib_get_plugin_symbol ("http_plugin.so", "http2_frame_read_settings");

  http2_error_t rv;
  http2_frame_header_t fh = { 0 };
  http_conn_settings_t conn_settings = http2_default_conn_settings;

  u8 settings[] = { 0x0, 0x0, 0x12, 0x4, 0x0, 0x0,  0x0, 0x0, 0x0,
		    0x0, 0x3, 0x0,  0x0, 0x0, 0x64, 0x0, 0x4, 0x40,
		    0x0, 0x0, 0x0,  0x0, 0x2, 0x0,  0x0, 0x0, 0x0 };
  _http2_frame_header_read (settings, &fh);
  HTTP_TEST ((fh.flags == 0 && fh.type == HTTP2_FRAME_TYPE_SETTINGS &&
	      fh.stream_id == 0 && fh.length == 18),
	     "frame identified as SETTINGS");

  rv = _http2_frame_read_settings (
    &conn_settings, settings + HTTP2_FRAME_HEADER_SIZE, fh.length);
  HTTP_TEST ((rv == HTTP2_ERROR_NO_ERROR &&
	      conn_settings.max_concurrent_streams == 100 &&
	      conn_settings.initial_window_size == 1073741824 &&
	      conn_settings.enable_push == 0),
	     "SETTINGS frame payload parsed")

  u8 settings_ack[] = { 0x0, 0x0, 0x0, 0x4, 0x1, 0x0, 0x0, 0x0, 0x0 };
  _http2_frame_header_read (settings_ack, &fh);
  HTTP_TEST ((fh.flags == HTTP2_FRAME_FLAG_ACK &&
	      fh.type == HTTP2_FRAME_TYPE_SETTINGS && fh.stream_id == 0 &&
	      fh.length == 0),
	     "frame identified as SETTINGS ACK");

  vlib_cli_output (vm, "http2_frame_write_settings_ack");

  static void (*_http2_frame_write_settings_ack) (u8 * *dst);

  _http2_frame_write_settings_ack = vlib_get_plugin_symbol (
    "http_plugin.so", "http2_frame_write_settings_ack");

  u8 *buf = 0;

  _http2_frame_write_settings_ack (&buf);
  HTTP_TEST ((vec_len (buf) == sizeof (settings_ack)) &&
	       !memcmp (buf, settings_ack, sizeof (settings_ack)),
	     "SETTINGS ACK frame written");
  vec_free (buf);

  vlib_cli_output (vm, "http2_frame_write_settings");

  static void (*_http2_frame_write_settings) (
    http2_settings_entry_t * settings, u8 * *dst);

  _http2_frame_write_settings =
    vlib_get_plugin_symbol ("http_plugin.so", "http2_frame_write_settings");

  http2_settings_entry_t *settings_list = 0;
  vec_validate (settings_list, 2);
  settings_list[0].identifier = HTTP2_SETTINGS_MAX_CONCURRENT_STREAMS;
  settings_list[0].value = 100;
  settings_list[1].identifier = HTTP2_SETTINGS_INITIAL_WINDOW_SIZE;
  settings_list[1].value = 1073741824;
  settings_list[2].identifier = HTTP2_SETTINGS_ENABLE_PUSH;
  settings_list[2].value = 0;

  _http2_frame_write_settings (settings_list, &buf);
  HTTP_TEST ((vec_len (buf) == sizeof (settings) &&
	      !memcmp (buf, settings, sizeof (settings))),
	     "SETTINGS frame written");
  vec_free (settings_list);
  vec_free (buf);

  vlib_cli_output (vm, "http2_frame_read_window_update");

  static http2_error_t (*_http2_frame_read_window_update) (
    u32 * increment, u8 * payload, u32 payload_len);

  _http2_frame_read_window_update = vlib_get_plugin_symbol (
    "http_plugin.so", "http2_frame_read_window_update");

  u32 win_increment;
  u8 win_update[] = { 0x0, 0x0, 0x4,  0x8,  0x0, 0x0, 0x0,
		      0x0, 0x0, 0x3f, 0xff, 0x0, 0x1 };
  _http2_frame_header_read (win_update, &fh);
  HTTP_TEST ((fh.flags == 0 && fh.type == HTTP2_FRAME_TYPE_WINDOW_UPDATE &&
	      fh.stream_id == 0 && fh.length == 4),
	     "frame identified as WINDOW_UPDATE");

  rv = _http2_frame_read_window_update (
    &win_increment, win_update + HTTP2_FRAME_HEADER_SIZE, fh.length);
  HTTP_TEST ((rv == HTTP2_ERROR_NO_ERROR && win_increment == 1073676289),
	     "WINDOW_UPDATE frame payload parsed")

  vlib_cli_output (vm, "http2_frame_write_window_update");

  static void (*_http2_frame_write_window_update) (u32 increment,
						   u32 stream_id, u8 * *dst);

  _http2_frame_write_window_update = vlib_get_plugin_symbol (
    "http_plugin.so", "http2_frame_write_window_update");

  _http2_frame_write_window_update (1073676289, 0, &buf);
  HTTP_TEST ((vec_len (buf) == sizeof (win_update) &&
	      !memcmp (buf, win_update, sizeof (win_update))),
	     "WINDOW_UPDATE frame written");
  vec_free (buf);

  vlib_cli_output (vm, "http2_frame_read_rst_stream");

  static http2_error_t (*_http2_frame_read_rst_stream) (
    u32 * error_code, u8 * payload, u32 payload_len);

  _http2_frame_read_rst_stream =
    vlib_get_plugin_symbol ("http_plugin.so", "http2_frame_read_rst_stream");

  u32 error_code;
  u8 rst_stream[] = { 0x0, 0x0, 0x4, 0x3, 0x0, 0x0, 0x0,
		      0x0, 0x5, 0x0, 0x0, 0x0, 0x01 };
  _http2_frame_header_read (rst_stream, &fh);
  HTTP_TEST ((fh.flags == 0 && fh.type == HTTP2_FRAME_TYPE_RST_STREAM &&
	      clib_net_to_host_u32 (fh.stream_id) == 5 && fh.length == 4),
	     "frame identified as RST_STREAM");

  rv = _http2_frame_read_rst_stream (
    &error_code, rst_stream + HTTP2_FRAME_HEADER_SIZE, fh.length);
  HTTP_TEST (
    (rv == HTTP2_ERROR_NO_ERROR && error_code == HTTP2_ERROR_PROTOCOL_ERROR),
    "RST_STREAM frame payload parsed")

  vlib_cli_output (vm, "http2_frame_write_rst_stream");

  static void (*_http2_frame_write_rst_stream) (u32 increment, u32 stream_id,
						u8 * *dst);

  _http2_frame_write_rst_stream =
    vlib_get_plugin_symbol ("http_plugin.so", "http2_frame_write_rst_stream");

  _http2_frame_write_rst_stream (HTTP2_ERROR_PROTOCOL_ERROR, clib_host_to_net_u32 (5), &buf);
  HTTP_TEST ((vec_len (buf) == sizeof (rst_stream) &&
	      !memcmp (buf, rst_stream, sizeof (rst_stream))),
	     "RST_STREAM frame written");
  vec_free (buf);

  vlib_cli_output (vm, "http2_frame_read_goaway");

  static http2_error_t (*_http2_frame_read_goaway) (
    u32 * error_code, u32 * last_stream_id, u8 * payload, u32 payload_len);

  _http2_frame_read_goaway =
    vlib_get_plugin_symbol ("http_plugin.so", "http2_frame_read_goaway");

  u32 last_stream_id;
  u8 goaway[] = { 0x0, 0x0, 0x8, 0x7, 0x0, 0x0, 0x0, 0x0, 0x0,
		  0x0, 0x0, 0x0, 0x5, 0x0, 0x0, 0x0, 0x2 };

  _http2_frame_header_read (goaway, &fh);
  HTTP_TEST ((fh.flags == 0 && fh.type == HTTP2_FRAME_TYPE_GOAWAY &&
	      fh.stream_id == 0 && fh.length == 8),
	     "frame identified as GOAWAY");

  rv = _http2_frame_read_goaway (&error_code, &last_stream_id,
				 goaway + HTTP2_FRAME_HEADER_SIZE, fh.length);
  HTTP_TEST ((rv == HTTP2_ERROR_NO_ERROR &&
	      error_code == HTTP2_ERROR_INTERNAL_ERROR && last_stream_id == 5),
	     "GOAWAY frame payload parsed")

  vlib_cli_output (vm, "http2_frame_write_goaway");

  static void (*_http2_frame_write_goaway) (http2_error_t error_code,
					    u32 last_stream_id, u8 * *dst);

  _http2_frame_write_goaway =
    vlib_get_plugin_symbol ("http_plugin.so", "http2_frame_write_goaway");

  _http2_frame_write_goaway (HTTP2_ERROR_INTERNAL_ERROR, clib_host_to_net_u32 (5), &buf);
  HTTP_TEST ((vec_len (buf) == sizeof (goaway) &&
	      !memcmp (buf, goaway, sizeof (goaway))),
	     "GOAWAY frame written");
  vec_free (buf);

  vlib_cli_output (vm, "http2_frame_read_headers");

  static http2_error_t (*_http2_frame_read_headers) (
    u8 * *headers, u32 * headers_len, u8 * payload, u32 payload_len, u8 flags);

  _http2_frame_read_headers =
    vlib_get_plugin_symbol ("http_plugin.so", "http2_frame_read_headers");

  u8 *h;
  u32 h_len;
  u8 headers[] = { 0x0,	 0x0,  0x28, 0x1,  0x5,	 0x0,  0x0,  0x0,  0x3,	 0x3f,
		   0xe1, 0x1f, 0x82, 0x4,  0x88, 0x62, 0x7b, 0x69, 0x1d, 0x48,
		   0x5d, 0x3e, 0x53, 0x86, 0x41, 0x88, 0xaa, 0x69, 0xd2, 0x9a,
		   0xc4, 0xb9, 0xec, 0x9b, 0x7a, 0x88, 0x25, 0xb6, 0x50, 0xc3,
		   0xab, 0xb8, 0x15, 0xc1, 0x53, 0x3,  0x2a, 0x2f, 0x2a };

  _http2_frame_header_read (headers, &fh);
  HTTP_TEST ((fh.flags == (HTTP2_FRAME_FLAG_END_HEADERS | HTTP2_FRAME_FLAG_END_STREAM) &&
	      fh.type == HTTP2_FRAME_TYPE_HEADERS && clib_net_to_host_u32 (fh.stream_id) == 3 &&
	      fh.length == 40),
	     "frame identified as HEADERS");

  rv = _http2_frame_read_headers (
    &h, &h_len, headers + HTTP2_FRAME_HEADER_SIZE, fh.length, fh.flags);
  HTTP_TEST ((rv == HTTP2_ERROR_NO_ERROR && h_len == 40 &&
	      *h == headers[HTTP2_FRAME_HEADER_SIZE]),
	     "HEADERS frame payload parsed")

  vlib_cli_output (vm, "http2_frame_write_headers_header");

  static void (*_http2_frame_write_headers_header) (
    u32 headers_len, u32 stream_id, u8 flags, u8 * dst);

  _http2_frame_write_headers_header = vlib_get_plugin_symbol (
    "http_plugin.so", "http2_frame_write_headers_header");

  u8 *p = http2_frame_header_alloc (&buf);
  _http2_frame_write_headers_header (40, clib_host_to_net_u32 (3),
				     HTTP2_FRAME_FLAG_END_HEADERS | HTTP2_FRAME_FLAG_END_STREAM, p);
  HTTP_TEST ((vec_len (buf) == HTTP2_FRAME_HEADER_SIZE &&
	      !memcmp (buf, headers, HTTP2_FRAME_HEADER_SIZE)),
	     "HEADERS frame header written");
  vec_free (buf);

  vlib_cli_output (vm, "http2_frame_read_data");

  static http2_error_t (*_http2_frame_read_data) (
    u8 * *data, u32 * data_len, u8 * payload, u32 payload_len, u8 flags);

  _http2_frame_read_data =
    vlib_get_plugin_symbol ("http_plugin.so", "http2_frame_read_data");

  u8 *d;
  u32 d_len;
  u8 data[] = { 0x0,  0x0,  0x9,  0x0,	0x1,  0x0,  0x0,  0x0,	0x3,
		0x6e, 0x6f, 0x74, 0x20, 0x66, 0x6f, 0x75, 0x6e, 0x64 };

  _http2_frame_header_read (data, &fh);
  HTTP_TEST ((fh.flags == HTTP2_FRAME_FLAG_END_STREAM && fh.type == HTTP2_FRAME_TYPE_DATA &&
	      clib_net_to_host_u32 (fh.stream_id) == 3 && fh.length == 9),
	     "frame identified as DATA");

  rv = _http2_frame_read_data (&d, &d_len, data + HTTP2_FRAME_HEADER_SIZE,
			       fh.length, fh.flags);
  HTTP_TEST ((rv == HTTP2_ERROR_NO_ERROR && d_len == 9 &&
	      *d == data[HTTP2_FRAME_HEADER_SIZE]),
	     "DATA frame payload parsed")

  vlib_cli_output (vm, "http2_frame_write_data_header");

  static void (*_http2_frame_write_data_header) (
    u32 headers_len, u32 stream_id, u8 flags, u8 * dst);

  _http2_frame_write_data_header =
    vlib_get_plugin_symbol ("http_plugin.so", "http2_frame_write_data_header");

  p = http2_frame_header_alloc (&buf);
  _http2_frame_write_data_header (9, clib_host_to_net_u32 (3), HTTP2_FRAME_FLAG_END_STREAM, p);
  HTTP_TEST ((vec_len (buf) == HTTP2_FRAME_HEADER_SIZE &&
	      !memcmp (buf, data, HTTP2_FRAME_HEADER_SIZE)),
	     "DATA frame header written");
  vec_free (buf);

  return 0;
}

static int
http_test_qpack (vlib_main_t *vm)
{
  vlib_cli_output (vm, "qpack_decode_header");

  static hpack_error_t (*_qpack_decode_header) (u8 * *src, u8 * end, u8 * *buf, uword * buf_len,
						u32 * name_len, u32 * value_len, void *decoder_ctx,
						u8 *never_index);

  _qpack_decode_header =
    vlib_get_plugin_symbol ("http_plugin.so", "qpack_decode_header");

  u8 *pos, *bp, *buf = 0, *input = 0;
  uword blen;
  u32 name_len, value_len;
  hpack_error_t rv;
  u8 never_index;

#define TEST(i, e_name, e_value, e_never_index)                                                    \
  vec_validate (input, sizeof (i) - 2);                                                            \
  memcpy (input, i, sizeof (i) - 1);                                                               \
  pos = input;                                                                                     \
  vec_validate_init_empty (buf, 63, 0);                                                            \
  bp = buf;                                                                                        \
  blen = vec_len (buf);                                                                            \
  never_index = 0;                                                                                 \
  rv = _qpack_decode_header (&pos, vec_end (input), &bp, &blen, &name_len, &value_len, 0,          \
			     &never_index);                                                        \
  HTTP_TEST ((rv == HPACK_ERROR_NONE && name_len == strlen (e_name) &&                             \
	      value_len == strlen (e_value) && !memcmp (buf, e_name, name_len) &&                  \
	      !memcmp (buf + name_len, e_value, value_len) &&                                      \
	      vec_len (buf) == (blen + name_len + value_len) && pos == vec_end (input) &&          \
	      bp == buf + name_len + value_len && (e_never_index) == never_index),                 \
	     "%U is decoded as '%U: %U'", format_hex_bytes, input, vec_len (input),                \
	     format_http_bytes, buf, name_len, format_http_bytes, buf + name_len, value_len);      \
  vec_free (input);                                                                                \
  vec_free (buf);

  /* literal field line with name reference, static table */
  TEST ("\x51\x0B\x2F\x69\x6E\x64\x65\x78\x2E\x68\x74\x6D\x6C", ":path", "/index.html", 0);
  /* literal field line with name reference, never indexed, static table */
  TEST ("\x71\x0B\x2F\x69\x6E\x64\x65\x78\x2E\x68\x74\x6D\x6C", ":path", "/index.html", 1);
  /* indexed field line, static table */
  TEST ("\xC1", ":path", "/", 0);
  /* Empty static values are valid indexed field lines, including index zero
   * and entries whose indices require an extension byte (RFC 9204, Appendix A). */
  TEST ("\xC0", ":authority", "", 0);
  TEST ("\xC5", "cookie", "", 0);
  TEST ("\xC6", "date", "", 0);
  TEST ("\xC7", "etag", "", 0);
  TEST ("\xFF\x09", "accept-language", "", 0);
  TEST ("\xFF\x1D", "server", "", 0);
  TEST ("\xFF\x20", "user-agent", "", 0);
  /* literal field line with literal name */
  TEST ("\x23\x61\x62\x63\x01\x5A", "abc", "Z", 0);
  /* literal field line with literal name, never indexed */
  TEST ("\x33\x61\x62\x63\x01\x5A", "abc", "Z", 1);

  vlib_cli_output (vm, "qpack_parse_request");

  static http3_error_t (*_qpack_parse_request) (
    u8 * src, u32 src_len, u8 * dst, u32 dst_len,
    hpack_request_control_data_t * control_data, http_field_line_t * *headers,
    qpack_decoder_ctx_t * decoder_ctx);

  _qpack_parse_request =
    vlib_get_plugin_symbol ("http_plugin.so", "qpack_parse_request");

  http3_error_t err;
  http_field_line_t *headers = 0;
  qpack_decoder_ctx_t decoder_ctx = {};
  hpack_request_control_data_t req_control_data = {};
  u8 req[] = { 0x00, 0x00, 0xD1, 0xD7, 0x50, 0x01, 0x61,
	       0xC1, 0x23, 0x61, 0x62, 0x63, 0x01, 0x5A };
  u16 parsed_bitmap =
    HPACK_PSEUDO_HEADER_METHOD_PARSED | HPACK_PSEUDO_HEADER_SCHEME_PARSED |
    HPACK_PSEUDO_HEADER_PATH_PARSED | HPACK_PSEUDO_HEADER_AUTHORITY_PARSED;

  vec_validate_init_empty (buf, 254, 0);
  err = _qpack_parse_request (req, 14, buf, vec_len (buf), &req_control_data,
			      &headers, &decoder_ctx);
  HTTP_TEST (
    (err == HTTP3_ERROR_NO_ERROR &&
     req_control_data.parsed_bitmap == parsed_bitmap &&
     req_control_data.method == HTTP_REQ_GET &&
     req_control_data.scheme == HTTP_URL_SCHEME_HTTPS &&
     req_control_data.path_len == 1 && req_control_data.path[0] == '/' &&
     req_control_data.authority_len == 1 &&
     req_control_data.authority[0] == 'a' && vec_len (headers) == 1 &&
     req_control_data.headers_len == 4 && headers[0].name_len == 3 &&
     headers[0].value_len == 1 &&
     !memcmp (req_control_data.headers + headers[0].name_offset, "abc", 3) &&
     !memcmp (req_control_data.headers + headers[0].value_offset, "Z", 1)),
    "decoder result: %U", format_http3_error, err);

  vec_free (buf);
  vec_free (headers);
  memset (&decoder_ctx, 0, sizeof (decoder_ctx));

  /* Compression must preserve an indexed empty authority for HTTP validation. */
  u8 empty_authority[] = { 0x00, 0x00, 0xd1, 0xd7, 0xc0, 0xc1 };
  vec_validate_init_empty (buf, 254, 0);
  clib_memset (&req_control_data, 0, sizeof (req_control_data));
  err = _qpack_parse_request (empty_authority, sizeof (empty_authority), buf, vec_len (buf),
			      &req_control_data, &headers, &decoder_ctx);
  HTTP_TEST (err == HTTP3_ERROR_NO_ERROR && req_control_data.parsed_bitmap == parsed_bitmap &&
	       req_control_data.authority_len == 0,
	     "indexed empty authority decodes without a compression error");
  vec_free (headers);

  /* The first index beyond the static table still causes a connection error. */
  u8 invalid_static_index[] = { 0x00, 0x00, 0xff, 0x24 };
  err = _qpack_parse_request (invalid_static_index, sizeof (invalid_static_index), buf,
			      vec_len (buf), &req_control_data, &headers, &decoder_ctx);
  HTTP_TEST (err == HTTP3_ERROR_QPACK_DECOMPRESSION_FAILED,
	     "static index 99 remains a compression error");
  vec_free (buf);
  vec_free (headers);

  /* Empty method values are valid QPACK strings, with or without Huffman
   * encoding, but invalid HTTP methods. Keep the error scoped to the stream. */
  u8 empty_method[] = { 0x00, 0x00, 0x5f, 0x00, 0x00, 0xd7, 0x50, 0x01, 0x61, 0xc1 };
  vec_validate_init_empty (buf, 254, 0);
  for (u8 huffman = 0; huffman < 2; huffman++)
    {
      empty_method[4] = huffman ? 0x80 : 0;
      err = _qpack_parse_request (empty_method, sizeof (empty_method), buf, vec_len (buf),
				  &req_control_data, &headers, &decoder_ctx);
      HTTP_TEST (err == HTTP3_ERROR_MESSAGE_ERROR, "empty %s method is a message error",
		 huffman ? "Huffman" : "literal");
    }
  vec_free (buf);
  vec_free (headers);

  vlib_cli_output (vm, "qpack_parse_response");

  static http3_error_t (*_qpack_parse_response) (
    u8 * src, u32 src_len, u8 * dst, u32 dst_len,
    hpack_response_control_data_t * control_data, http_field_line_t * *headers,
    qpack_decoder_ctx_t * decoder_ctx);

  _qpack_parse_response =
    vlib_get_plugin_symbol ("http_plugin.so", "qpack_parse_response");

  hpack_response_control_data_t resp_control_data = {};
  u8 resp[] = { 0x00, 0x00, 0xD9 };

  vec_validate_init_empty (buf, 63, 0);
  err = _qpack_parse_response (resp, 3, buf, vec_len (buf), &resp_control_data,
			       &headers, &decoder_ctx);
  HTTP_TEST (
    (err == HTTP3_ERROR_NO_ERROR &&
     resp_control_data.parsed_bitmap == HPACK_PSEUDO_HEADER_STATUS_PARSED &&
     resp_control_data.sc == HTTP_STATUS_OK && vec_len (headers) == 0),
    "decoder result: %U", format_http3_error, err);
  vec_free (buf);
  vec_free (headers);

  vlib_cli_output (vm, "qpack field section prefix");

  const struct
  {
    char *name;
    u8 *prefix;
    u32 prefix_len;
    u8 append_fields;
    http3_error_t error;
    uword delta_base;
  } prefix_tests[] = {
#define _(name, prefix, fields, error, base)                                                       \
  { name, (u8 *) prefix, sizeof (prefix) - 1, fields, error, base }
    /* Empty initial sections lack mandatory pseudo-headers. */
    _ ("empty initial section, zero Base", "\x00\x00", 0, HTTP3_ERROR_MESSAGE_ERROR, 0),
    _ ("empty initial section, nonzero Base", "\x00\x01", 0, HTTP3_ERROR_MESSAGE_ERROR, 0),
    _ ("empty initial section, extended Base", "\x00\x7f\x00", 0, HTTP3_ERROR_MESSAGE_ERROR, 0),
    _ ("empty initial section, redundant Base encoding", "\x00\x7f\x80\x00", 0,
       HTTP3_ERROR_MESSAGE_ERROR, 0),
    _ ("empty initial section, multi-byte Base", "\x00\x7f\x81\x01", 0, HTTP3_ERROR_MESSAGE_ERROR,
       0),
    /* Invalid prefixes take precedence even without any field lines. */
    _ ("nonzero Required Insert Count without fields", "\x01\x00", 0,
       HTTP3_ERROR_QPACK_DECOMPRESSION_FAILED, 0),
    _ ("negative Base without fields", "\x00\x80", 0, HTTP3_ERROR_QPACK_DECOMPRESSION_FAILED, 0),
    _ ("negative extended Base without fields", "\x00\xff\x00", 0,
       HTTP3_ERROR_QPACK_DECOMPRESSION_FAILED, 0),
    _ ("truncated Delta Base without extension byte", "\x00\x7f", 0,
       HTTP3_ERROR_QPACK_DECOMPRESSION_FAILED, 0),
    _ ("zero Base", "\x00\x00", 1, HTTP3_ERROR_NO_ERROR, 0),
    _ ("nonzero Base", "\x00\x01", 1, HTTP3_ERROR_NO_ERROR, 1),
    _ ("largest single-byte Base", "\x00\x7e", 1, HTTP3_ERROR_NO_ERROR, 126),
    _ ("extended Base", "\x00\x7f\x00", 1, HTTP3_ERROR_NO_ERROR, 127),
    _ ("multi-byte Base", "\x00\x7f\x81\x01", 1, HTTP3_ERROR_NO_ERROR, 256),
    _ ("nonzero Required Insert Count", "\x01\x00", 1, HTTP3_ERROR_QPACK_DECOMPRESSION_FAILED, 0),
    _ ("extended Required Insert Count", "\xff\x00\x00", 1, HTTP3_ERROR_QPACK_DECOMPRESSION_FAILED,
       0),
    _ ("negative Base with zero Delta Base", "\x00\x80", 1, HTTP3_ERROR_QPACK_DECOMPRESSION_FAILED,
       0),
    _ ("negative Base with nonzero Delta Base", "\x00\x81", 1,
       HTTP3_ERROR_QPACK_DECOMPRESSION_FAILED, 0),
    _ ("negative Base with extended Delta Base", "\x00\xff\x00", 1,
       HTTP3_ERROR_QPACK_DECOMPRESSION_FAILED, 0),
    _ ("missing prefix", "", 0, HTTP3_ERROR_QPACK_DECOMPRESSION_FAILED, 0),
    _ ("missing Delta Base", "\x00", 0, HTTP3_ERROR_QPACK_DECOMPRESSION_FAILED, 0),
    _ ("truncated Required Insert Count", "\xff\x80\x80", 0, HTTP3_ERROR_QPACK_DECOMPRESSION_FAILED,
       0),
    _ ("missing Delta Base after extended integer", "\xff\x80\x00", 0,
       HTTP3_ERROR_QPACK_DECOMPRESSION_FAILED, 0),
    _ ("truncated Delta Base", "\x00\x7f\x80", 0, HTTP3_ERROR_QPACK_DECOMPRESSION_FAILED, 0),
    _ ("overflowing Delta Base", "\x00\x7f\xff\xff\xff\xff\xff\xff\xff\xff\xff\x01", 0,
       HTTP3_ERROR_QPACK_DECOMPRESSION_FAILED, 0),
#undef _
  };

  vec_validate_init_empty (buf, 254, 0);
  for (u32 i = 0; i < ARRAY_LEN (prefix_tests); i++)
    {
      vec_add (input, prefix_tests[i].prefix, prefix_tests[i].prefix_len);
      if (prefix_tests[i].append_fields)
	vec_add (input, req + 2, sizeof (req) - 2);
      memset (&decoder_ctx, 0, sizeof (decoder_ctx));
      /* Error classification must not depend on the previous decoder output. */
      memset (&req_control_data, 0xa5, sizeof (req_control_data));
      err = _qpack_parse_request (input, vec_len (input), buf, vec_len (buf), &req_control_data,
				  &headers, &decoder_ctx);
      HTTP_TEST (err == prefix_tests[i].error, "request %s: %U", prefix_tests[i].name,
		 format_http3_error, err);
      if (err == HTTP3_ERROR_NO_ERROR)
	HTTP_TEST (req_control_data.parsed_bitmap == parsed_bitmap &&
		     decoder_ctx.delta_base == prefix_tests[i].delta_base,
		   "request fields decoded with %s", prefix_tests[i].name);
      vec_free (headers);
      vec_reset_length (input);

      vec_add (input, prefix_tests[i].prefix, prefix_tests[i].prefix_len);
      if (prefix_tests[i].append_fields)
	vec_add (input, resp + 2, sizeof (resp) - 2);
      memset (&decoder_ctx, 0, sizeof (decoder_ctx));
      /* Error classification must not depend on the previous decoder output. */
      memset (&resp_control_data, 0xa5, sizeof (resp_control_data));
      err = _qpack_parse_response (input, vec_len (input), buf, vec_len (buf), &resp_control_data,
				   &headers, &decoder_ctx);
      HTTP_TEST (err == prefix_tests[i].error, "response %s: %U", prefix_tests[i].name,
		 format_http3_error, err);
      if (err == HTTP3_ERROR_NO_ERROR)
	HTTP_TEST (resp_control_data.parsed_bitmap == HPACK_PSEUDO_HEADER_STATUS_PARSED &&
		     resp_control_data.sc == HTTP_STATUS_OK &&
		     decoder_ctx.delta_base == prefix_tests[i].delta_base,
		   "response fields decoded with %s", prefix_tests[i].name);
      vec_free (headers);
      vec_reset_length (input);
    }
  vec_free (input);
  vec_free (buf);

  vlib_cli_output (vm, "qpack_encode_header");

  static u8 *(*_qpack_encode_header) (u8 * dst, http_header_name_t name, const u8 *value,
				      u32 value_len, u8 never_index);
  _qpack_encode_header =
    vlib_get_plugin_symbol ("http_plugin.so", "qpack_encode_header");

  /* indexed field line, static table */
  buf = _qpack_encode_header (buf, HTTP_HEADER_CACHE_CONTROL, (const u8 *) "no-cache", 8, 0);
  HTTP_TEST ((vec_len (buf) == 1 && buf[0] == 0xE7),
	     "'cache-control: no-cache' encoded as: %U", format_hex_bytes, buf,
	     vec_len (buf));
  vec_free (buf);

  /* literal field line with name reference, static table */
  u8 expected1[] = "\x56\x96\xD0\x7A\xBE\x94\x10\x54\xD4\x44\xA8\x20\x05\x95"
		   "\x04\x0B\x81\x66\xE0\x82\xA6\x2D\x1B\xFF";
  buf = _qpack_encode_header (buf, HTTP_HEADER_DATE, (const u8 *) "Mon, 21 Oct 2013 20:13:21 GMT",
			      29, 0);
  HTTP_TEST ((vec_len (buf) == (sizeof (expected1) - 1) &&
	      !memcmp (buf, expected1, vec_len (buf))),
	     "'date: Mon, 21 Oct 2013 20:13:21 GMT' encoded as: %U",
	     format_hex_bytes, buf, vec_len (buf));
  vec_free (buf);

  /* literal field line with literal name */
  u8 expected2[] = "\x2F\x01\x20\xC9\x39\x56\x42\x46\x9B\x51\x8D\xC1\xE4\x74"
		   "\xD7\x41\x6F\x0C\x93\x97\xED\x49\xCC\x9F";
  buf =
    _qpack_encode_header (buf, HTTP_HEADER_CACHE_STATUS, (const u8 *) "ExampleCache; hit", 17, 0);
  HTTP_TEST ((vec_len (buf) == (sizeof (expected2) - 1) && !memcmp (buf, expected2, vec_len (buf))),
	     "'cache-status: ExampleCache; hit' encoded as: %U", format_hex_bytes, buf,
	     vec_len (buf));
  vec_free (buf);

  /* literal field line with name reference, never indexed, static table */
  u8 expected3[] = "\x76\x96\xD0\x7A\xBE\x94\x10\x54\xD4\x44\xA8\x20\x05\x95"
		   "\x04\x0B\x81\x66\xE0\x82\xA6\x2D\x1B\xFF";
  buf = _qpack_encode_header (buf, HTTP_HEADER_DATE, (const u8 *) "Mon, 21 Oct 2013 20:13:21 GMT",
			      29, 1);
  HTTP_TEST ((vec_len (buf) == (sizeof (expected3) - 1) && !memcmp (buf, expected3, vec_len (buf))),
	     "'date: Mon, 21 Oct 2013 20:13:21 GMT' encoded as: %U", format_hex_bytes, buf,
	     vec_len (buf));
  vec_free (buf);

  /* literal field line with literal name, never indexed */
  u8 expected4[] = "\x3F\x01\x20\xC9\x39\x56\x42\x46\x9B\x51\x8D\xC1\xE4\x74"
		   "\xD7\x41\x6F\x0C\x93\x97\xED\x49\xCC\x9F";
  buf =
    _qpack_encode_header (buf, HTTP_HEADER_CACHE_STATUS, (const u8 *) "ExampleCache; hit", 17, 1);
  HTTP_TEST ((vec_len (buf) == (sizeof (expected4) - 1) && !memcmp (buf, expected4, vec_len (buf))),
	     "'cache-status: ExampleCache; hit' encoded as: %U", format_hex_bytes, buf,
	     vec_len (buf));
  vec_free (buf);

  vlib_cli_output (vm, "qpack_encode_custom_header");

  static u8 *(*_qpack_encode_custom_header) (u8 * dst, const u8 *name, u32 name_len,
					     const u8 *value, u32 value_len, u8 never_index);
  _qpack_encode_custom_header =
    vlib_get_plugin_symbol ("http_plugin.so", "qpack_encode_custom_header");

  u8 expected5[] = "\x2E\x40\xEA\x93\xC1\x89\x3F\x83\x45\x63\xA7";
  buf = _qpack_encode_custom_header (buf, (const u8 *) "sandwich", 8, (const u8 *) "spam", 4, 0);
  HTTP_TEST ((vec_len (buf) == (sizeof (expected5) - 1) && !memcmp (buf, expected5, vec_len (buf))),
	     "'sandwich: spam' encoded as: %U", format_hex_bytes, buf, vec_len (buf));
  vec_free (buf);

  u8 expected6[] = "\x3E\x40\xEA\x93\xC1\x89\x3F\x83\x45\x63\xA7";
  buf = _qpack_encode_custom_header (buf, (const u8 *) "sandwich", 8, (const u8 *) "spam", 4, 1);
  HTTP_TEST ((vec_len (buf) == (sizeof (expected6) - 1) && !memcmp (buf, expected6, vec_len (buf))),
	     "'sandwich: spam' encoded as: %U", format_hex_bytes, buf, vec_len (buf));
  vec_free (buf);

  vlib_cli_output (vm, "qpack_serialize_response");

  static void (*_qpack_serialize_response) (
    u8 * app_headers, u32 app_headers_len,
    hpack_response_control_data_t * control_data, u8 * *dst);
  _qpack_serialize_response =
    vlib_get_plugin_symbol ("http_plugin.so", "qpack_serialize_response");

  u8 *server_name = format (0, "http unit tests");
  u8 *date = format (0, "Mon, 21 Oct 2013 20:13:21 GMT");

  memset (&resp_control_data, 0, sizeof (resp_control_data));
  vec_validate_init_empty (buf, 127, 0xFF);
  vec_reset_length (buf);
  resp_control_data.sc = HTTP_STATUS_GATEWAY_TIMEOUT;
  resp_control_data.server_name = server_name;
  resp_control_data.server_name_len = vec_len (server_name);
  resp_control_data.date = date;
  resp_control_data.date_len = vec_len (date);
  u8 expected7[] = "\x00\x00\x5F\x09\x03\x35\x30\x34\x5F\x4D\x8B\x9D\x29\xAD\x4B\x6A\x32\x54"
		   "\x49\x50\x94\x7F\x56\x96\xD0\x7A\xBE\x94\x10\x54\xD4\x44\xA8\x20\x05\x95"
		   "\x04\x0B\x81\x66\xE0\x82\xA6\x2D\x1B\xFF\xC4";
  _qpack_serialize_response (0, 0, &resp_control_data, &buf);
  HTTP_TEST ((vec_len (buf) == (sizeof (expected7) - 1) && !memcmp (buf, expected7, vec_len (buf))),
	     "response encoded as: %U", format_hex_bytes, buf, vec_len (buf));
  vec_free (buf);

  /* Static index 67 needs a continuation byte after the 6-bit prefix. */
  resp_control_data.sc = HTTP_STATUS_BAD_REQUEST;
  u8 expected_bad_request[] =
    "\x00\x00\xFF\x04\x5F\x4D\x8B\x9D\x29\xAD\x4B\x6A\x32\x54\x49\x50\x94\x7F\x56"
    "\x96\xD0\x7A\xBE\x94\x10\x54\xD4\x44\xA8\x20\x05\x95\x04\x0B\x81\x66\xE0\x82"
    "\xA6\x2D\x1B\xFF\xC4";
  _qpack_serialize_response (0, 0, &resp_control_data, &buf);
  HTTP_TEST ((vec_len (buf) == sizeof (expected_bad_request) - 1 &&
	      !memcmp (buf, expected_bad_request, vec_len (buf))),
	     "400 response encoded as: %U", format_hex_bytes, buf, vec_len (buf));
  vec_free (buf);

  resp_control_data.sc = HTTP_STATUS_OK;
  resp_control_data.content_len = 1024;
  http_headers_ctx_t headers_ctx;
  u8 *headers_buf = 0;
  vec_validate_init_empty (headers_buf, 127, 0xFF);
  http_init_headers_ctx (&headers_ctx, headers_buf, vec_len (headers_buf));
  http_add_header (&headers_ctx, HTTP_HEADER_CONTENT_TYPE,
		   http_token_lit ("text/plain"));
  http_add_header (&headers_ctx, HTTP_HEADER_CACHE_STATUS,
		   http_token_lit ("ExampleCache; hit"));
  http_add_custom_header (&headers_ctx, http_token_lit ("sandwich"),
			  http_token_lit ("spam"));
  u8 expected8[] = "\x00\x00\xD9\x5F\x4D\x8B\x9D\x29\xAD\x4B\x6A\x32\x54\x49\x50\x94\x7F\x56"
		   "\x96\xD0\x7A\xBE\x94\x10\x54\xD4\x44\xA8\x20\x05\x95\x04\x0B\x81\x66\xE0"
		   "\x82\xA6\x2D\x1B\xFF\x54\x83\x08\x04\xD7\xF5\x2F\x01\x20\xC9\x39\x56\x42"
		   "\x46\x9B\x51\x8D\xC1\xE4\x74\xD7\x41\x6F\x0C\x93\x97\xED\x49\xCC\x9F\x2E"
		   "\x40\xEA\x93\xC1\x89\x3F\x83\x45\x63\xA7";
  _qpack_serialize_response (headers_buf, headers_ctx.tail_offset,
			     &resp_control_data, &buf);
  HTTP_TEST ((vec_len (buf) == (sizeof (expected8) - 1) && !memcmp (buf, expected8, vec_len (buf))),
	     "response encoded as: %U", format_hex_bytes, buf, vec_len (buf));
  vec_free (headers_buf);
  vec_free (buf);
  vec_free (date);

  vlib_cli_output (vm, "qpack_serialize_request");

  static void (*_qpack_serialize_request) (
    u8 * app_headers, u32 app_headers_len,
    hpack_request_control_data_t * control_data, u8 * *dst);
  _qpack_serialize_request =
    vlib_get_plugin_symbol ("http_plugin.so", "qpack_serialize_request");

  u8 *authority = format (0, "www.example.com");
  u8 *path = format (0, "/");
  memset (&req_control_data, 0, sizeof (req_control_data));
  vec_validate_init_empty (headers_buf, 127, 0xFF);
  req_control_data.method = HTTP_REQ_GET;
  req_control_data.parsed_bitmap = HPACK_PSEUDO_HEADER_SCHEME_PARSED;
  req_control_data.scheme = HTTP_URL_SCHEME_HTTPS;
  req_control_data.parsed_bitmap |= HPACK_PSEUDO_HEADER_PATH_PARSED;
  req_control_data.path = path;
  req_control_data.path_len = vec_len (path);
  req_control_data.parsed_bitmap |= HPACK_PSEUDO_HEADER_AUTHORITY_PARSED;
  req_control_data.authority = authority;
  req_control_data.authority_len = vec_len (authority);
  req_control_data.user_agent_len = 0;
  req_control_data.content_len = HPACK_ENCODER_SKIP_CONTENT_LEN;
  u8 expected9[] = "\x00\x00\xD1\xD7\xC1\x50\x8C\xF1\xE3\xC2\xE5\xF2\x3A\x6B"
		   "\xA0\xAB\x90\xF4\xFF";
  _qpack_serialize_request (0, 0, &req_control_data, &buf);
  HTTP_TEST ((vec_len (buf) == (sizeof (expected9) - 1) && !memcmp (buf, expected9, vec_len (buf))),
	     "request encoded as: %U", format_hex_bytes, buf, vec_len (buf));
  vec_free (buf);
  vec_free (authority);
  vec_free (path);

  authority = format (0, "example.org:123");
  memset (&req_control_data, 0, sizeof (req_control_data));
  vec_validate_init_empty (headers_buf, 127, 0xFF);
  req_control_data.method = HTTP_REQ_CONNECT;
  req_control_data.parsed_bitmap |= HPACK_PSEUDO_HEADER_AUTHORITY_PARSED;
  req_control_data.authority = authority;
  req_control_data.authority_len = vec_len (authority);
  req_control_data.user_agent = server_name;
  req_control_data.user_agent_len = vec_len (server_name);
  req_control_data.content_len = HPACK_ENCODER_SKIP_CONTENT_LEN;
  vec_validate (headers_buf, 127);
  http_init_headers_ctx (&headers_ctx, headers_buf, vec_len (headers_buf));
  http_add_custom_header (&headers_ctx, http_token_lit ("sandwich"),
			  http_token_lit ("spam"));
  u8 expected10[] = "\x00\x00\xCF\x50\x8B\x2F\x91\xD3\x5D\x05\x5C\xF6\x4D\x70\x22\x67\x5F\x50"
		    "\x8B\x9D\x29\xAD\x4B\x6A\x32\x54\x49\x50\x94\x7f\x2E\x40\xEA\x93\xC1\x89"
		    "\x3F\x83\x45\x63\xA7";
  _qpack_serialize_request (headers_buf, headers_ctx.tail_offset,
			    &req_control_data, &buf);
  HTTP_TEST (
    (vec_len (buf) == (sizeof (expected10) - 1) && !memcmp (buf, expected10, vec_len (buf))),
    "request encoded as: %U", format_hex_bytes, buf, vec_len (buf));

  vec_free (server_name);
  vec_free (buf);
  vec_free (authority);

  return 0;
}

static int
http_test_h3_frame (vlib_main_t *vm)
{
  vlib_cli_output (vm, "http3_frame_header_read");

  static http3_error_t (*_http3_frame_header_read) (
    u8 * src, u64 src_len, http3_stream_type_t stream_type,
    http3_frame_header_t * fh);
  _http3_frame_header_read =
    vlib_get_plugin_symbol ("http_plugin.so", "http3_frame_header_read");

  http3_error_t rv;
  http3_frame_header_t fh = {};
  u8 data[] = {
    0x00, 0x09, 0x6e, 0x6f, 0x74, 0x20, 0x66, 0x6f, 0x75, 0x6e, 0x64,
  };
  rv = _http3_frame_header_read (data, sizeof (data),
				 HTTP3_STREAM_TYPE_REQUEST, &fh);
  HTTP_TEST ((rv == HTTP3_ERROR_NO_ERROR && fh.type == HTTP3_FRAME_TYPE_DATA &&
	      fh.length == 9 && fh.payload[0] == data[2]),
	     "frame identified as DATA");

  rv = _http3_frame_header_read (data, 1, HTTP3_STREAM_TYPE_REQUEST, &fh);
  HTTP_TEST ((rv == HTTP3_ERROR_INCOMPLETE), "frame is incomplete (rv=%d)",
	     rv);

  rv = _http3_frame_header_read (data, sizeof (data),
				 HTTP3_STREAM_TYPE_CONTROL, &fh);
  HTTP_TEST ((rv == HTTP3_ERROR_FRAME_UNEXPECTED),
	     "frame is on wrong stream (rv=0x%04x)", rv);

  vlib_cli_output (vm, "http3_frame_header_write");

  u8 header_buf[HTTP3_FRAME_HEADER_MAX_LEN] = {};
  u8 header_len =
    http3_frame_header_write (HTTP3_FRAME_TYPE_DATA, 9, header_buf);
  HTTP_TEST ((header_len == 2 && !memcmp (header_buf, data, header_len)),
	     "DATA frame header written: %U", format_http_bytes, header_buf,
	     header_len);

  vlib_cli_output (vm, "http3_frame_goaway_read");

  static http3_error_t (*_http3_frame_goaway_read) (u8 * payload, u64 len,
						    u64 * stream_or_push_id);
  _http3_frame_goaway_read =
    vlib_get_plugin_symbol ("http_plugin.so", "http3_frame_goaway_read");

  u8 goaway[] = {
    0x07, 0x02, 0x7B, 0xBD, 0xFE,
  };
  u64 stream_id;
  rv = _http3_frame_header_read (goaway, 4, HTTP3_STREAM_TYPE_CONTROL, &fh);
  HTTP_TEST ((rv == HTTP3_ERROR_NO_ERROR &&
	      fh.type == HTTP3_FRAME_TYPE_GOAWAY && fh.length == 2 &&
	      fh.payload[0] == goaway[2]),
	     "frame identified as GOAWAY");
  rv = _http3_frame_goaway_read (fh.payload, fh.length, &stream_id);
  HTTP_TEST ((rv == HTTP3_ERROR_NO_ERROR && stream_id == 15293),
	     "GOAWAY stream ID %lu (rv=0x%04x)", stream_id, rv);

  rv = _http3_frame_goaway_read (fh.payload, 1, &stream_id);
  HTTP_TEST ((rv == HTTP3_ERROR_FRAME_ERROR),
	     "GOAWAY frame payload is corrupted (rv=0x%04x)", rv);

  rv = _http3_frame_goaway_read (fh.payload, 3, &stream_id);
  HTTP_TEST ((rv == HTTP3_ERROR_FRAME_ERROR),
	     "GOAWAY frame payload has extra bytes (rv=0x%04x)", rv);

  vlib_cli_output (vm, "http3_frame_goaway_write");
  static void (*_http3_frame_goaway_write) (u64 stream_or_push_id, u8 * *dst);
  _http3_frame_goaway_write =
    vlib_get_plugin_symbol ("http_plugin.so", "http3_frame_goaway_write");

  u8 *buf = 0;
  _http3_frame_goaway_write (15293, &buf);
  HTTP_TEST ((vec_len (buf) == 4 && !memcmp (buf, goaway, 4)),
	     "GOAWAY frame written: %U", format_hex_bytes, buf, vec_len (buf));
  vec_reset_length (buf);

  vlib_cli_output (vm, "http3_frame_settings_read");

  static http3_error_t (*_http3_frame_settings_read) (u8 * payload, u64 len,
						      http_conn_settings_t * settings);

  _http3_frame_settings_read =
    vlib_get_plugin_symbol ("http_plugin.so", "http3_frame_settings_read");

  http_conn_settings_t h3_settings = {};
  u8 settings[] = {
    0x04, 0x04, 0x07, 0x05, 0x08, 0x01, 0x33, 0x02,
  };
  rv = _http3_frame_header_read (settings, 6, HTTP3_STREAM_TYPE_CONTROL, &fh);
  HTTP_TEST ((rv == HTTP3_ERROR_NO_ERROR &&
	      fh.type == HTTP3_FRAME_TYPE_SETTINGS && fh.length == 4 &&
	      fh.payload[0] == settings[2]),
	     "frame identified as SETTINGS");
  rv = _http3_frame_settings_read (fh.payload, fh.length, &h3_settings);
  HTTP_TEST (
    (rv == HTTP3_ERROR_NO_ERROR && h3_settings.qpack_blocked_streams == 5 &&
     h3_settings.enable_connect_protocol == 1 &&
     h3_settings.h3_datagram == 0 && h3_settings.max_field_section_size == 0 &&
     h3_settings.qpack_max_table_capacity == 0),
    "SETTINGS frame payload parsed (rv=0x%04x)", rv);
  rv = _http3_frame_settings_read (fh.payload, 6, &h3_settings);
  HTTP_TEST ((rv == HTTP3_ERROR_SETTINGS_ERROR),
	     "invalid setting value (rv=0x%04x)", rv);

  vlib_cli_output (vm, "http3_frame_settings_write");

  static void (*_http3_frame_settings_write) (http_conn_settings_t * settings, u8 * *dst);
  _http3_frame_settings_write =
    vlib_get_plugin_symbol ("http_plugin.so", "http3_frame_settings_write");
  h3_settings = http3_default_conn_settings;
  h3_settings.enable_connect_protocol = 1;
  h3_settings.qpack_blocked_streams = 5;
  _http3_frame_settings_write (&h3_settings, &buf);
  HTTP_TEST ((vec_len (buf) == 6 && !memcmp (buf, settings, 6)),
	     "SETTINGS frame written: %U", format_hex_bytes, buf,
	     vec_len (buf));

  vec_free (buf);
  return 0;
}

static int
http_test_http_lookup_header_name (vlib_main_t *vm)
{
  http_header_name_t name;

#define _(sym, str_canonical, str_lower, hpack_index, flags)                                       \
  name = http_lookup_header_name (http_token_lit (str_canonical));                                 \
  if (name != HTTP_HEADER_##sym)                                                                   \
    {                                                                                              \
      vlib_cli_output (vm, "FAIL:%d: %s != %u", __LINE__, str_lower, name);                        \
      return 1;                                                                                    \
    }
  foreach_http_header_name
#undef _

    vlib_cli_output (vm, "PASS:%d: http_lookup_header_name", __LINE__);
  return 0;
}

static int
http_test_http_headers_rx_to_tx (vlib_main_t *vm)
{
  const char buf[] = "daTe: Wed, 15 Jan 2025 16:17:33 GMT"
		     "conTent-tYpE: text/html; charset=utf-8"
		     "STRICT-transport-security: max-age=31536000"
		     "Sandwich: Eggs"
		     "CONTENT-ENCODING: GZIP"
		     "Content-Length: 1001"
		     "Proxy-Authorization: spam";
  http_headers_ctx_t headers_ctx, expected_ctx;
  u8 *headers_buf = 0, *expected_buf = 0;
  http_msg_t msg = {};
  http_field_line_t *headers = 0, *field_line;
  int rv;

  /* daTe */
  vec_add2 (headers, field_line, 1);
  field_line->name_offset = 0;
  field_line->name_len = 4;
  field_line->value_offset = 6;
  field_line->value_len = 29;
  /* conTent-tYpE */
  vec_add2 (headers, field_line, 1);
  field_line->name_offset = 35;
  field_line->name_len = 12;
  field_line->value_offset = 49;
  field_line->value_len = 24;
  /* STRICT-transport-security */
  vec_add2 (headers, field_line, 1);
  field_line->name_offset = 73;
  field_line->name_len = 25;
  field_line->value_offset = 100;
  field_line->value_len = 16;
  /* Sandwich */
  vec_add2 (headers, field_line, 1);
  field_line->name_offset = 116;
  field_line->name_len = 8;
  field_line->value_offset = 126;
  field_line->value_len = 4;
  /* CONTENT-ENCODING */
  vec_add2 (headers, field_line, 1);
  field_line->name_offset = 130;
  field_line->name_len = 16;
  field_line->value_offset = 148;
  field_line->value_len = 4;
  /* Content-Length */
  vec_add2 (headers, field_line, 1);
  field_line->name_offset = 152;
  field_line->name_len = 14;
  field_line->value_offset = 168;
  field_line->value_len = 4;
  /* Proxy-Authorization */
  vec_add2 (headers, field_line, 1);
  field_line->name_offset = 172;
  field_line->name_len = 19;
  field_line->value_offset = 193;
  field_line->value_len = 4;

  msg.data.headers_ctx = pointer_to_uword (headers);
  msg.data.headers_len = strlen (buf);

  vec_validate (headers_buf, 255);
  http_init_headers_ctx (&headers_ctx, headers_buf, vec_len (headers_buf));

  vec_validate (expected_buf, 255);
  http_init_headers_ctx (&expected_ctx, expected_buf, vec_len (expected_buf));
  http_add_header (&expected_ctx, HTTP_HEADER_CONTENT_TYPE,
		   http_token_lit ("text/html; charset=utf-8"));
  http_add_header (&expected_ctx, HTTP_HEADER_STRICT_TRANSPORT_SECURITY,
		   http_token_lit ("max-age=31536000"));
  http_add_custom_header (&expected_ctx, http_token_lit ("Sandwich"), http_token_lit ("Eggs"));
  http_add_header (&expected_ctx, HTTP_HEADER_CONTENT_ENCODING, http_token_lit ("GZIP"));

  rv = http_headers_rx_to_tx (msg, (const u8 *) buf, &headers_ctx);
  HTTP_TEST ((rv == 0 && headers_ctx.tail_offset == expected_ctx.tail_offset &&
	      !memcmp (headers_buf, expected_buf, headers_ctx.tail_offset)),
	     "rx headers converted to tx headers as: %U", format_hex_bytes, headers_buf,
	     headers_ctx.tail_offset);

  vec_free (headers_buf);
  vec_free (expected_buf);
  return 0;
}

static int
http_test_rx_publication (vlib_main_t *vm)
{
  session_enable_disable_args_t session_args = {
    .is_en = 1,
    .rt_engine_type = RT_BACKEND_ENGINE_RULE_TABLE,
  };
  clib_error_t *error;
  fifo_segment_main_t fsm = {};
  fifo_segment_create_args_t args = {
    .segment_type = SSVM_SEGMENT_PRIVATE,
    .segment_size = 1 << 20,
    .segment_name = "http-rx-publication",
  };
  fifo_segment_t *fs = 0;
  svm_fifo_t *fifo = 0, *transport_fifo = 0;
  session_t *as = 0, *ts = 0;
  http_ctx_t req = {}, hc = {};
  http_msg_t msg = {}, received;
  svm_fifo_seg_t segs[2];
  u8 expected[9000], actual[sizeof (msg) + sizeof (expected)], marker = 0xa5;
  u32 tail, copied = 0, limit, n_src, moved;
  int n_read, result = 1;

#define RX_TEST(_cond, _comment)                                                                   \
  do                                                                                               \
    {                                                                                              \
      if (!HTTP_TEST_I ((_cond), _comment))                                                        \
	goto done;                                                                                 \
    }                                                                                              \
  while (0)

  /* session_alloc() needs session workers even when no HTTP app is attached. */
  error = vnet_session_enable_disable (vm, &session_args);
  if (error)
    {
      clib_error_report (error);
      return 1;
    }

  fifo_segment_main_init (&fsm, 0, 5);
  RX_TEST (!fifo_segment_create (&fsm, &args), "RX test segment allocated");
  fs = fifo_segment_get_segment (&fsm, args.new_segment_indices[0]);
  fifo = fifo_segment_alloc_fifo_w_slice (fs, 0, 4096, FIFO_SEGMENT_RX_FIFO);
  RX_TEST (fifo != 0, "RX test FIFO allocated");
  svm_fifo_set_size (fifo, 16 << 10);
  /* Exercise producer-index wraparound and metadata crossing a chunk boundary. */
  f_head_cptr (fifo)->start_byte = 0u - f_head_cptr (fifo)->length;
  svm_fifo_init_pointers (fifo, ~0u - 64, ~0u - 64);
  as = session_alloc (vm->thread_index);
  as->rx_fifo = fifo;
  req.c_s_index = as->session_index;
  req.c_thread_index = as->thread_index;
  ts = session_alloc (vm->thread_index);
  /* Allocating the transport session may relocate the session pool. */
  as = session_get (req.c_s_index, req.c_thread_index);
  transport_fifo = fifo_segment_alloc_fifo_w_slice (fs, 0, 4096, FIFO_SEGMENT_RX_FIFO);
  RX_TEST (transport_fifo != 0, "transport RX test FIFO allocated");
  svm_fifo_set_size (transport_fifo, 16 << 10);
  ts->rx_fifo = transport_fifo;
  hc.hc_tc_session_handle = session_handle (ts);
  for (u32 i = 0; i < sizeof (expected); i++)
    expected[i] = (i * 17 + 3) & 0xff;
  /* Grow the source in 4K chunks, so two segment slots cannot map it all. */
  for (u32 offset = 0; offset < sizeof (expected); offset += moved)
    {
      moved = clib_min (4096, sizeof (expected) - offset);
      RX_TEST (svm_fifo_enqueue (transport_fifo, moved, expected + offset) == moved,
	       "transport RX bytes queued");
    }
  n_src = ARRAY_LEN (segs);
  n_read = svm_fifo_segments (transport_fifo, 0, segs, &n_src, sizeof (expected));
  RX_TEST (n_src == ARRAY_LEN (segs) && n_read > 0 && n_read < sizeof (expected),
	   "two source segments map fewer bytes than the requested transfer");

  RX_TEST (svm_fifo_enqueue (fifo, 1, &marker) == 1, "previous message is readable");
  tail = fifo->shr->tail;
  for (u32 fragment = 0; fragment < 2; fragment++)
    {
      limit = fragment ? sizeof (expected) : 1;
      moved = http_io_ts_move_to_as (&hc, &req, sizeof (msg) + copied, limit - copied);
      RX_TEST (moved == limit - copied, "transfer completes across partial source mappings");
      copied += moved;
      RX_TEST (svm_fifo_max_dequeue_cons (transport_fifo) == sizeof (expected) - copied,
	       "transport FIFO drains exactly the successfully staged bytes");
      RX_TEST (fifo->shr->tail == tail, "staging leaves the producer tail unchanged");
      if (!fragment)
	RX_TEST (svm_fifo_dequeue (fifo, 1, actual) == 1 && actual[0] == marker,
		 "consumer can drain the previous message during staging");
      RX_TEST (svm_fifo_max_dequeue_cons (fifo) == 0,
	       "polling consumer cannot read partial headers or metadata");
      RX_TEST (svm_fifo_dequeue (fifo, 1, actual) == SVM_FIFO_EEMPTY,
	       "partial headers remain unreadable without relying on notifications");
      http_io_as_rx_peek (&req, sizeof (msg), copied, actual);
      RX_TEST (!memcmp (actual, expected, copied), "parser can read unpublished fragments");
    }

  msg.type = HTTP_MSG_REPLY;
  msg.code = HTTP_STATUS_OK;
  msg.data.type = HTTP_MSG_DATA_INLINE;
  msg.data.len = sizeof (expected);
  RX_TEST (!http_io_as_rx_publish (&req, &msg, copied), "complete message published");
  RX_TEST (svm_fifo_max_dequeue_cons (fifo) == sizeof (actual),
	   "metadata and all staged bytes become readable together");
  RX_TEST (svm_fifo_dequeue (fifo, sizeof (actual), actual) == sizeof (actual),
	   "consumer reads the complete message");
  clib_memcpy_fast (&received, actual, sizeof (received));
  RX_TEST (!memcmp (&received, &msg, sizeof (msg)), "published metadata is intact");
  RX_TEST (!memcmp (actual + sizeof (msg), expected, sizeof (expected)),
	   "published headers are intact across FIFO chunks and index wraparound");
  result = 0;

done:
  if (ts)
    session_free (ts);
  if (as)
    session_free (as);
  if (transport_fifo)
    fifo_segment_free_fifo (fs, transport_fifo);
  if (fifo)
    fifo_segment_free_fifo (fs, fifo);
  if (fs)
    fifo_segment_delete (&fsm, fs);
  vec_free (args.new_segment_indices);
  pool_free (fsm.segments);
  return result;
#undef RX_TEST
}

static int
http_test_encode_u64_decimal (vlib_main_t *vm)
{
  static const struct
  {
    u64 value;
    http_token_t expected;
  } tests[] = {
    { 0, { http_token_lit ("0") } },
    { 1, { http_token_lit ("1") } },
    { 9, { http_token_lit ("9") } },
    { 10, { http_token_lit ("10") } },
    { 99, { http_token_lit ("99") } },
    { 100, { http_token_lit ("100") } },
    { CLIB_U32_MAX, { http_token_lit ("4294967295") } },
    { (u64) 1 << 63, { http_token_lit ("9223372036854775808") } },
    { CLIB_U64_MAX, { http_token_lit ("18446744073709551615") } },
  };
  u8 buf[HTTP_U64_MAX_DECIMAL_DIGITS + 2];
  u8 *end = buf + sizeof (buf) - 1, *digits;

  for (u32 i = 0; i < ARRAY_LEN (tests); i++)
    {
      clib_memset (buf, 0xA5, sizeof (buf));
      digits = http_encode_u64_decimal (end, tests[i].value);
      HTTP_TEST ((end - digits == tests[i].expected.len &&
		  !memcmp (digits, tests[i].expected.base, tests[i].expected.len)),
		 "decimal encoding of %llu", tests[i].value);
      HTTP_TEST ((buf[0] == 0xA5 && *end == 0xA5), "decimal encoding stays within its buffer");
    }
  return 0;
}

typedef struct
{
  http1_chunked_decoder_t decoder;
  http1_chunked_result_t result;
  u32 consumed;
  u32 body_len;
  u8 body[128];
} http_chunked_test_result_t;

static http1_chunked_result_t (*_http1_chunked_decode) (http1_chunked_decoder_t *, const u8 *, u32,
							u32 *, u32 *);

static int
http_test_chunked_run (http_token_t input, u32 split, u32 fragment_size, u32 write_limit,
		       http_chunked_test_result_t *test)
{
  u32 end = 0, consumed, data_len, n, iterations = 0;
  http1_chunked_result_t result;

  clib_memset (test, 0, sizeof (*test));
  for (;;)
    {
      if (++iterations > input.len * 3 + 4)
	return 1;
      if (test->consumed == end && end < input.len)
	{
	  end = fragment_size ? clib_min (end + fragment_size, input.len) : input.len;
	  if (test->consumed < split)
	    end = clib_min (end, split);
	}
      result = _http1_chunked_decode (&test->decoder, (const u8 *) input.base + test->consumed,
				      end - test->consumed, &consumed, &data_len);
      if (consumed > end - test->consumed)
	return 1;
      test->consumed += consumed;
      if (result == HTTP1_CHUNKED_DATA)
	{
	  if (!data_len || data_len > end - test->consumed ||
	      data_len > test->decoder.chunk_bytes_left)
	    return 1;
	  n = clib_min (data_len, write_limit);
	  if (test->body_len + n > sizeof (test->body))
	    return 1;
	  clib_memcpy_fast (test->body + test->body_len, input.base + test->consumed, n);
	  test->body_len += n;
	  test->consumed += n;
	  http1_chunked_consume_data (&test->decoder, n);
	}
      else
	{
	  if (data_len)
	    return 1;
	  if (result != HTTP1_CHUNKED_MORE || end == input.len)
	    break;
	  if (test->consumed != end)
	    return 1;
	}
    }
  test->result = result;
  /* Empty input must preserve completion, failure, or incomplete status. */
  return _http1_chunked_decode (&test->decoder, 0, 0, &consumed, &data_len) != result || consumed ||
	 data_len;
}

static int
http_test_chunked_valid (vlib_main_t *vm)
{
  static const struct
  {
    const char *name;
    http_token_t input;
    http_token_t body;
    u32 extra;
  } tests[] = {
    { "empty", { http_token_lit ("0\r\n\r\n") }, { http_token_lit ("") }, 0 },
    { "multiple zero digits", { http_token_lit ("0000\r\n\r\n") }, { http_token_lit ("") }, 0 },
    { "one chunk", { http_token_lit ("4\r\nWiki\r\n0\r\n\r\n") }, { http_token_lit ("Wiki") }, 0 },
    { "several chunks",
      { http_token_lit ("4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n") },
      { http_token_lit ("Wikipedia") },
      0 },
    { "mixed case hex",
      { http_token_lit ("a\r\n0123456789\r\nA\r\nabcdefghij\r\n0\r\n\r\n") },
      { http_token_lit ("0123456789abcdefghij") },
      0 },
    { "leading zeros",
      { http_token_lit ("0001\r\nx\r\n000\r\n\r\n") },
      { http_token_lit ("x") },
      0 },
    { "binary payload",
      { http_token_lit ("5\r\n\0\r\n\377x\r\n0\r\n\r\n") },
      { http_token_lit ("\0\r\n\377x") },
      0 },
    { "extensions",
      { http_token_lit ("1;foo;bar=baz\r\nx\r\n0;end=yes\r\n\r\n") },
      { http_token_lit ("x") },
      0 },
    { "extension whitespace",
      { http_token_lit ("1 \t; \tfoo \t= \tbar \t; baz\r\nx\r\n0\r\n\r\n") },
      { http_token_lit ("x") },
      0 },
    { "quoted extensions",
      { http_token_lit ("1;x=\"\";y=\"a;= \\\"\\\\\t\200\";z=\"\\\200\"\r\nx\r\n0\r\n\r\n") },
      { http_token_lit ("x") },
      0 },
    { "token punctuation",
      { http_token_lit ("0;!#$%&'*+-.^_`|~=!#$%&'*+-.^_`|~\r\n\r\n") },
      { http_token_lit ("") },
      0 },
    { "trailers",
      { http_token_lit ("1\r\nx\r\n0\r\nX-Checksum: abc\r\nOther:\r\n\r\n") },
      { http_token_lit ("x") },
      0 },
    { "trailer values",
      { http_token_lit ("0\r\nX: \t!\"\\:;\200\377 \t\r\n\r\n") },
      { http_token_lit ("") },
      0 },
    { "empty with following input",
      { http_token_lit ("0\r\n\r\nNEXT") },
      { http_token_lit ("") },
      4 },
    { "trailers with following input",
      { http_token_lit ("1\r\nx\r\n0\r\nX: v\r\n\r\nNEXT") },
      { http_token_lit ("x") },
      4 },
  };
  http_chunked_test_result_t test;
  int failed;

  for (u32 i = 0; i < ARRAY_LEN (tests); i++)
    {
      failed = 0;
      for (u32 split = 0; split <= tests[i].input.len && !failed; split++)
	for (u32 mode = 0; mode < 3; mode++)
	  {
	    failed = http_test_chunked_run (tests[i].input, split, mode == 2 ? 1 : 0,
					    mode ? 1 : CLIB_U32_MAX, &test);
	    failed |= test.result != HTTP1_CHUNKED_DONE ||
		      test.consumed != tests[i].input.len - tests[i].extra ||
		      test.body_len != tests[i].body.len ||
		      memcmp (test.body, tests[i].body.base, tests[i].body.len);
	    if (failed)
	      {
		vlib_cli_output (vm,
				 "chunked case %s, split %u, mode %u: result %d, consumed %u, "
				 "body length %u",
				 tests[i].name, split, mode, test.result, test.consumed,
				 test.body_len);
		break;
	      }
	  }
      HTTP_TEST (!failed, "chunked: %s across all fragment boundaries", tests[i].name);
    }
  return 0;
}

static int
http_test_chunked_invalid (vlib_main_t *vm)
{
  static const http_token_t tests[] = {
    { http_token_lit ("\r\n") },
    { http_token_lit ("\n") },
    { http_token_lit (" 1\r\n") },
    { http_token_lit ("\t1\r\n") },
    { http_token_lit ("+1\r\n") },
    { http_token_lit ("-1\r\n") },
    { http_token_lit ("0x1\r\n") },
    { http_token_lit ("g\r\n") },
    { http_token_lit ("1G\r\n") },
    { http_token_lit ("1\n") },
    { http_token_lit ("1\rx") },
    { http_token_lit ("1 \r\n") },
    { http_token_lit ("1\tX\r\n") },
    { http_token_lit ("1\r\naX") },
    { http_token_lit ("1\r\na\rX") },
    { http_token_lit ("1\r\na\n") },
    { http_token_lit ("1\r\na\r\n\r\n") },
    { http_token_lit ("0\r\n\n") },
    { http_token_lit ("0\r\n\rX") },
    { http_token_lit ("0\r\nMissing-colon\r\n\r\n") },
    { http_token_lit ("0\r\n: value\r\n\r\n") },
    { http_token_lit ("0\r\nX : value\r\n\r\n") },
    { http_token_lit ("0\r\n X: value\r\n\r\n") },
    { http_token_lit ("0\r\nX: value\n\r\n") },
    { http_token_lit ("0\r\nX: value\rX") },
    { http_token_lit ("0\r\nX: value\r\n folded\r\n\r\n") },
    { http_token_lit ("0\r\nX: \1\r\n\r\n") },
    { http_token_lit ("0\r\nX: \177\r\n\r\n") },
    { http_token_lit ("0\r\nX: \0\r\n\r\n") },
    { http_token_lit ("0;\r\n\r\n") },
    { http_token_lit ("0;;x\r\n\r\n") },
    { http_token_lit ("0;=v\r\n\r\n") },
    { http_token_lit ("0;x=\r\n\r\n") },
    { http_token_lit ("0;x=\"unclosed\r\n\r\n") },
    { http_token_lit ("0;x=\"a\\\r\n") },
    { http_token_lit ("0;x=\"a\"b\r\n\r\n") },
    { http_token_lit ("0;x=v w\r\n\r\n") },
    { http_token_lit ("0;x=v \r\n\r\n") },
    { http_token_lit ("0;x \r\n\r\n") },
    { http_token_lit ("0;x=(v)\r\n\r\n") },
    { http_token_lit ("0;\200=v\r\n\r\n") },
    { http_token_lit ("0;x=\200\r\n\r\n") },
    { http_token_lit ("0;x=\"\177\"\r\n\r\n") },
    { http_token_lit ("0;x=\"\0\"\r\n\r\n") },
    { http_token_lit ("10000000000000000\r\n") },
    { http_token_lit ("ffffffffffffffff0\r\n") },
    { http_token_lit ("80000000000000000\r\n") },
    { http_token_lit ("00010000000000000000\r\n") },
  };
  http_chunked_test_result_t test;
  int failed;

  for (u32 i = 0; i < ARRAY_LEN (tests); i++)
    {
      failed = 0;
      for (u32 split = 0; split <= tests[i].len && !failed; split++)
	for (u32 mode = 0; mode < 2; mode++)
	  {
	    failed = http_test_chunked_run (tests[i], split, mode, 1, &test);
	    failed |= test.result != HTTP1_CHUNKED_INVALID || test.consumed >= tests[i].len;
	    if (failed)
	      {
		vlib_cli_output (vm,
				 "invalid chunked case %u, split %u, mode %u: result %d, "
				 "consumed %u",
				 i, split, mode, test.result, test.consumed);
		break;
	      }
	  }
      HTTP_TEST (!failed, "chunked: malformed input %u rejected across all fragment boundaries", i);
    }
  return 0;
}

static int
http_test_chunked_incremental (vlib_main_t *vm)
{
  static const struct
  {
    http_token_t input;
    u64 size;
  } sizes[] = {
    { { http_token_lit ("0\r\n") }, 0 },
    { { http_token_lit ("1\r\n") }, 1 },
    { { http_token_lit ("a\r\n") }, 10 },
    { { http_token_lit ("F\r\n") }, 15 },
    { { http_token_lit ("10\r\n") }, 16 },
    { { http_token_lit ("FFFFFFFF\r\n") }, CLIB_U32_MAX },
    { { http_token_lit ("100000000\r\n") }, (u64) CLIB_U32_MAX + 1 },
    { { http_token_lit ("7fffffffffffffff\r\n") }, CLIB_U64_MAX >> 1 },
    { { http_token_lit ("8000000000000000\r\n") }, (u64) 1 << 63 },
    { { http_token_lit ("ffffffffffffffff\r\n") }, CLIB_U64_MAX },
    { { http_token_lit ("000FFFFFFFFFFFFFFFF\r\n") }, CLIB_U64_MAX },
  };
  http_token_t input = { http_token_lit ("4;ext=\"a\\\"b\"\r\ndata\r\n0;end\r\nX: value\r\n\r\n") };
  http_token_t huge = { http_token_lit ("ffffffffffffffff\r\nx") };
  http1_chunked_decoder_t decoder = {};
  http_chunked_test_result_t test;
  http1_chunked_result_t result;
  u32 consumed, data_len;

  for (u32 i = 0; i < ARRAY_LEN (sizes); i++)
    {
      for (u32 mode = 0; mode < 2; mode++)
	{
	  HTTP_TEST (!http_test_chunked_run (sizes[i].input, 0, mode, 1, &test) &&
		       test.result == HTTP1_CHUNKED_MORE && test.consumed == sizes[i].input.len &&
		       test.decoder.chunk_bytes_left == sizes[i].size,
		     "chunked: size %llu accepted (fragment size %u)", sizes[i].size, mode);
	}
    }
  HTTP_TEST (!http_test_chunked_run (huge, 0, 1, 1, &test) && test.result == HTTP1_CHUNKED_MORE &&
	       test.decoder.chunk_bytes_left == CLIB_U64_MAX - 1 && test.body_len == 1 &&
	       test.body[0] == 'x',
	     "chunked: large chunk streamed without buffering");

  for (u32 len = 0; len < input.len; len++)
    {
      http_token_t prefix = { input.base, len };
      HTTP_TEST (!http_test_chunked_run (prefix, 0, 1, 1, &test) &&
		   test.result == HTTP1_CHUNKED_MORE && test.consumed == len,
		 "chunked: prefix %u remains incomplete at EOF", len);
    }

  input = (http_token_t) { http_token_lit ("4\r\ndata\r\n0\r\n\r\nNEXT") };
  result =
    _http1_chunked_decode (&decoder, (const u8 *) input.base, input.len, &consumed, &data_len);
  HTTP_TEST (result == HTTP1_CHUNKED_DATA && consumed == 3 && data_len == 4,
	     "chunked: payload returned separately from framing");
  http1_chunked_consume_data (&decoder, 0);
  result = _http1_chunked_decode (&decoder, (const u8 *) input.base + 3, input.len - 3, &consumed,
				  &data_len);
  HTTP_TEST (result == HTTP1_CHUNKED_DATA && !consumed && data_len == 4 &&
	       decoder.chunk_bytes_left == 4,
	     "chunked: full app FIFO leaves payload pending");
  http1_chunked_consume_data (&decoder, 1);
  result = _http1_chunked_decode (&decoder, (const u8 *) input.base + 4, input.len - 4, &consumed,
				  &data_len);
  HTTP_TEST (result == HTTP1_CHUNKED_DATA && !consumed && data_len == 3 &&
	       decoder.chunk_bytes_left == 3,
	     "chunked: partial app write resumes at remaining payload");
  http1_chunked_consume_data (&decoder, 3);
  result = _http1_chunked_decode (&decoder, (const u8 *) input.base + 7, input.len - 7, &consumed,
				  &data_len);
  HTTP_TEST (result == HTTP1_CHUNKED_DONE && consumed == 7 && !data_len,
	     "chunked: completion leaves following input untouched");
  result = _http1_chunked_decode (&decoder, (const u8 *) input.base + 14, 4, &consumed, &data_len);
  HTTP_TEST (result == HTTP1_CHUNKED_DONE && !consumed && !data_len,
	     "chunked: completed decoder does not consume a subsequent message");
  return 0;
}

static int
http_test_chunked_limits (vlib_main_t *vm)
{
  http_chunked_test_result_t test;
  http1_chunked_result_t expected;
  http_token_t input;
  u8 *buf = 0;
  u32 size;
  int failed;

  for (u32 excess = 0; excess < 2; excess++)
    {
      size = HTTP1_CHUNKED_MAX_LINE_SIZE + excess;
      vec_validate (buf, size + 1);
      clib_memcpy_fast (buf, "0;x=", 4);
      clib_memset (buf + 4, 'a', size - 6);
      clib_memcpy_fast (buf + size - 2, "\r\n\r\n", 4);
      input = (http_token_t) { (char *) buf, size + 2 };
      expected = excess ? HTTP1_CHUNKED_TOO_LARGE : HTTP1_CHUNKED_DONE;
      failed = 0;
      for (u32 mode = 0; mode < 2; mode++)
	{
	  failed |= http_test_chunked_run (input, 0, mode, 1, &test);
	  failed |= test.result != expected || test.body_len ||
		    test.consumed != (excess ? HTTP1_CHUNKED_MAX_LINE_SIZE : input.len);
	}
      vec_free (buf);
      HTTP_TEST (!failed, "chunked: size line limit %u (excess %u)", HTTP1_CHUNKED_MAX_LINE_SIZE,
		 excess);

      size = HTTP1_CHUNKED_MAX_TRAILER_SIZE + excess;
      vec_validate (buf, size + 2);
      clib_memcpy_fast (buf, "0\r\nX:", 5);
      clib_memset (buf + 5, 'a', size - 6);
      clib_memcpy_fast (buf + size - 1, "\r\n\r\n", 4);
      input = (http_token_t) { (char *) buf, size + 3 };
      failed = 0;
      for (u32 mode = 0; mode < 2; mode++)
	{
	  failed |= http_test_chunked_run (input, 0, mode, 1, &test);
	  failed |= test.result != expected || test.body_len ||
		    test.consumed != (excess ? 3 + HTTP1_CHUNKED_MAX_TRAILER_SIZE : input.len);
	}
      vec_free (buf);
      HTTP_TEST (!failed, "chunked: trailer section limit %u (excess %u)",
		 HTTP1_CHUNKED_MAX_TRAILER_SIZE, excess);
    }

  /* Leading zeros cannot bypass the size-line bound without overflowing u64. */
  size = HTTP1_CHUNKED_MAX_LINE_SIZE + 1;
  vec_validate (buf, size + 1);
  clib_memset (buf, '0', size - 2);
  clib_memcpy_fast (buf + size - 2, "\r\n\r\n", 4);
  input = (http_token_t) { (char *) buf, size + 2 };
  failed = http_test_chunked_run (input, 0, 1, 1, &test) || test.result != HTTP1_CHUNKED_TOO_LARGE;
  vec_free (buf);
  HTTP_TEST (!failed, "chunked: excessive leading zeros rejected");

  /* The trailer bound applies to the whole section, including short fields. */
  vec_validate (buf, HTTP1_CHUNKED_MAX_TRAILER_SIZE + 4);
  clib_memcpy_fast (buf, "0\r\n", 3);
  for (u32 i = 0; i < HTTP1_CHUNKED_MAX_TRAILER_SIZE; i += 4)
    clib_memcpy_fast (buf + 3 + i, "X:\r\n", 4);
  clib_memcpy_fast (buf + 3 + HTTP1_CHUNKED_MAX_TRAILER_SIZE, "\r\n", 2);
  input = (http_token_t) { (char *) buf, vec_len (buf) };
  failed = http_test_chunked_run (input, 0, 1, 1, &test) ||
	   test.result != HTTP1_CHUNKED_TOO_LARGE ||
	   test.consumed != 3 + HTTP1_CHUNKED_MAX_TRAILER_SIZE;
  vec_free (buf);
  HTTP_TEST (!failed, "chunked: aggregate trailer limit enforced");
  return 0;
}

static int
http_test_decode_chunked (vlib_main_t *vm)
{
  _http1_chunked_decode = vlib_get_plugin_symbol ("http_plugin.so", "http1_chunked_decode");
  HTTP_TEST (_http1_chunked_decode != 0, "chunked decoder symbol resolved");
  return http_test_chunked_valid (vm) || http_test_chunked_invalid (vm) ||
	 http_test_chunked_incremental (vm) || http_test_chunked_limits (vm);
}

static int
http_test_parse_content_length (vlib_main_t *vm)
{
  http_ctx_t req = {};
  http_field_line_t *field_line;
  int rv;

#define SETUP_CL(_str)                                                                             \
  do                                                                                               \
    {                                                                                              \
      vec_reset_length (req.headers);                                                              \
      vec_add2 (req.headers, field_line, 1);                                                       \
      field_line->value_offset = 0;                                                                \
      field_line->value_len = sizeof (_str) - 1;                                                   \
      req.content_len_header_index = 0;                                                            \
      req.headers_offset = 0;                                                                      \
      req.body_len = 0;                                                                            \
    }                                                                                              \
  while (0)

  /* valid value */
  SETUP_CL ("1234");
  rv = http_parse_content_length (&req, (u8 *) "1234");
  HTTP_TEST ((rv == 0 && req.body_len == 1234), "body_len=1234");

  /* zero */
  SETUP_CL ("0");
  rv = http_parse_content_length (&req, (u8 *) "0");
  HTTP_TEST ((rv == 0 && req.body_len == 0), "body_len=0");

  /* non-digit character */
  SETUP_CL ("123abc");
  rv = http_parse_content_length (&req, (u8 *) "123abc");
  HTTP_TEST ((rv == -1), "non-digit rejected");

  /* UINT64_MAX: fits exactly in u64, must be accepted */
  SETUP_CL ("18446744073709551615");
  rv = http_parse_content_length (&req, (u8 *) "18446744073709551615");
  HTTP_TEST ((rv == 0 && req.body_len == CLIB_U64_MAX), "UINT64_MAX accepted");

  /* UINT64_MAX + 1: must be rejected */
  SETUP_CL ("18446744073709551616");
  rv = http_parse_content_length (&req, (u8 *) "18446744073709551616");
  HTTP_TEST ((rv == -1), "UINT64_MAX+1 rejected");

  /* wrap-around overflow not caught by the old body_len*10+digit < body_len
   * check: after parsing "2049638230412172402", body_len*10 wraps to a value
   * greater than body_len, so the old check passes silently */
  SETUP_CL ("20496382304121724020");
  rv = http_parse_content_length (&req, (u8 *) "20496382304121724020");
  HTTP_TEST ((rv == -1), "wrap-around overflow rejected");

  vec_free (req.headers);
#undef SETUP_CL
  return 0;
}

static int
http_test_h2_window_update_scheduling (vlib_main_t *vm)
{
  typedef struct
  {
    const char *name;
    i32 initial_window;
    i64 delta;
    i32 connection_window;
    int expected_rv;
    i32 expected_window;
    u8 initial_flags;
    u8 expected_flags;
    u8 request_linked;
    u8 expected_request_linked;
    u8 expected_connection_linked;
  } http2_window_update_test_t;
  static const http2_window_update_test_t tests[] = {
    {
      .name = "linked request resumes without duplicate",
      .initial_window = 0,
      .delta = 1,
      .initial_flags = HTTP_REQ_F_NEED_WINDOW_UPDATE,
      .request_linked = 1,
      .expected_window = 1,
      .expected_request_linked = 1,
    },
    {
      .name = "unlinked request resumes and schedules",
      .initial_window = 0,
      .delta = 1,
      .initial_flags = HTTP_REQ_F_NEED_WINDOW_UPDATE,
      .expected_window = 1,
      .expected_request_linked = 1,
    },
    {
      .name = "partial recovery remains blocked",
      .initial_window = -2,
      .delta = 1,
      .initial_flags = HTTP_REQ_F_NEED_WINDOW_UPDATE,
      .expected_window = -1,
      .expected_flags = HTTP_REQ_F_NEED_WINDOW_UPDATE,
    },
    {
      .name = "zero window deschedules linked request",
      .initial_window = 1,
      .delta = -1,
      .request_linked = 1,
      .expected_flags = HTTP_REQ_F_NEED_WINDOW_UPDATE,
    },
    {
      .name = "negative window leaves unlinked request blocked",
      .initial_window = 1,
      .delta = -2,
      .expected_window = -1,
      .expected_flags = HTTP_REQ_F_NEED_WINDOW_UPDATE,
    },
    {
      .name = "overflow preserves state",
      .initial_window = HTTP2_WIN_SIZE_MAX,
      .delta = 1,
      .connection_window = 1,
      .expected_rv = -1,
      .expected_window = HTTP2_WIN_SIZE_MAX,
      .initial_flags = HTTP_REQ_F_NEED_WINDOW_UPDATE,
      .expected_flags = HTTP_REQ_F_NEED_WINDOW_UPDATE,
      .request_linked = 1,
      .expected_request_linked = 1,
    },
    {
      .name = "exact maximum is accepted",
      .initial_window = HTTP2_WIN_SIZE_MAX - 1,
      .delta = 1,
      .connection_window = 1,
      .expected_window = HTTP2_WIN_SIZE_MAX,
      .request_linked = 1,
      .expected_request_linked = 1,
    },
    {
      .name = "positive update without blocked flag leaves scheduler unchanged",
      .initial_window = 1,
      .delta = 1,
      .connection_window = 1,
      .expected_window = 2,
    },
    {
      .name = "stream recovery schedules connection",
      .initial_window = 0,
      .delta = 1,
      .connection_window = 1,
      .initial_flags = HTTP_REQ_F_NEED_WINDOW_UPDATE,
      .expected_window = 1,
      .expected_request_linked = 1,
      .expected_connection_linked = 1,
    },
  };
  const http2_window_update_test_t *tc;
  u32 i;

  for (i = 0; i < ARRAY_LEN (tests); i++)
    {
      http_worker_t wrk = {};
      http_ctx_t *ctx_pool = 0;
      http_ctx_t *hc, *stream_head, *sched_head, *req;
      u32 hc_index, stream_head_index, sched_head_index, req_index;
      i32 stream_window;
      int rv;
      u8 flags, request_linked, request_list_valid, connection_linked, connection_list_valid;

      tc = &tests[i];

      pool_get_zero (ctx_pool, hc);
      hc_index = hc - ctx_pool;
      pool_get_zero (ctx_pool, stream_head);
      stream_head_index = stream_head - ctx_pool;
      pool_get_zero (ctx_pool, sched_head);
      sched_head_index = sched_head - ctx_pool;
      pool_get_zero (ctx_pool, req);
      req_index = req - ctx_pool;
      hc = pool_elt_at_index (ctx_pool, hc_index);
      stream_head = pool_elt_at_index (ctx_pool, stream_head_index);
      sched_head = pool_elt_at_index (ctx_pool, sched_head_index);
      req = pool_elt_at_index (ctx_pool, req_index);
      wrk.ctx_pool = ctx_pool;
      wrk.sched_head = sched_head_index;

      hc->old_tx_streams = stream_head_index;
      hc->peer_window = tc->connection_window;
      hc->sched_list.next = CLIB_LLIST_INVALID_INDEX;
      hc->sched_list.prev = CLIB_LLIST_INVALID_INDEX;
      clib_llist_anchor_init (wrk.ctx_pool, stream_sched_list, stream_head);
      clib_llist_anchor_init (wrk.ctx_pool, sched_list, sched_head);
      req->stream_sched_list.next = CLIB_LLIST_INVALID_INDEX;
      req->stream_sched_list.prev = CLIB_LLIST_INVALID_INDEX;
      if (tc->request_linked)
	clib_llist_add_tail (wrk.ctx_pool, stream_sched_list, req, stream_head);
      req->req_flags = tc->initial_flags;
      req->peer_stream_window = tc->initial_window;

      rv = http2_req_update_peer_window (&wrk, hc, req, tc->delta);
      request_linked = clib_llist_elt_is_linked (req, stream_sched_list);
      request_list_valid = request_linked ?
			     (stream_head->stream_sched_list.next == req_index &&
			      stream_head->stream_sched_list.prev == req_index &&
			      req->stream_sched_list.next == stream_head_index &&
			      req->stream_sched_list.prev == stream_head_index) :
			     (stream_head->stream_sched_list.next == stream_head_index &&
			      stream_head->stream_sched_list.prev == stream_head_index &&
			      req->stream_sched_list.next == CLIB_LLIST_INVALID_INDEX &&
			      req->stream_sched_list.prev == CLIB_LLIST_INVALID_INDEX);
      connection_linked = clib_llist_elt_is_linked (hc, sched_list);
      connection_list_valid =
	connection_linked ?
	  (sched_head->sched_list.next == hc_index && sched_head->sched_list.prev == hc_index &&
	   hc->sched_list.next == sched_head_index && hc->sched_list.prev == sched_head_index) :
	  (sched_head->sched_list.next == sched_head_index &&
	   sched_head->sched_list.prev == sched_head_index &&
	   hc->sched_list.next == CLIB_LLIST_INVALID_INDEX &&
	   hc->sched_list.prev == CLIB_LLIST_INVALID_INDEX);
      stream_window = req->peer_stream_window;
      flags = req->req_flags;

      if (request_linked)
	clib_llist_remove (wrk.ctx_pool, stream_sched_list, req);
      if (connection_linked)
	clib_llist_remove (wrk.ctx_pool, sched_list, hc);
      pool_free (ctx_pool);

      HTTP_TEST (rv == tc->expected_rv, "%s: return value %d should be %d", tc->name, rv,
		 tc->expected_rv);
      HTTP_TEST (stream_window == tc->expected_window, "%s: stream window %d should be %d",
		 tc->name, stream_window, tc->expected_window);
      HTTP_TEST (flags == tc->expected_flags, "%s: flags 0x%x should be 0x%x", tc->name, flags,
		 tc->expected_flags);
      HTTP_TEST (request_list_valid && request_linked == tc->expected_request_linked,
		 "%s: request scheduler state should be linked=%u", tc->name,
		 tc->expected_request_linked);
      HTTP_TEST (connection_list_valid && connection_linked == tc->expected_connection_linked,
		 "%s: connection scheduler state should be linked=%u", tc->name,
		 tc->expected_connection_linked);
    }
  return 0;
}

static int
http_test_decode_varint (vlib_main_t *vm)
{
  u8 *p, *end;
  u64 res;

  u8 input1[] = { 0x00, 0xFF };
  p = input1;
  end = p + 1;
  res = http_decode_varint (&p, end);
  HTTP_TEST ((res == 0 && *p == *end), "varint decoded as %lu, expected 0", res);

  u8 input2[] = { 0x25, 0xFF };
  p = input2;
  end = p + 1;
  res = http_decode_varint (&p, end);
  HTTP_TEST ((res == 0x25 && *p == *end), "varint decoded as %lu", res);

  u8 input3[] = { 0x46, 0x65, 0xFF };
  p = input3;
  end = p + 2;
  res = http_decode_varint (&p, end);
  HTTP_TEST ((res == 0x665 && *p == *end), "varint decoded as %lu", res);

  end = p;
  res = http_decode_varint (&p, end);
  HTTP_TEST ((res == HTTP_INVALID_VARINT), "varint decoded is invalid");

  u8 input4[] = { 0x86, 0xAB, 0x65, 0xAD, 0xFF };
  p = input4;
  end = p + 4;
  res = http_decode_varint (&p, end);
  HTTP_TEST ((res == 0x6AB65AD && *p == *end), "varint decoded as %lu", res);

  end = p + 2;
  res = http_decode_varint (&p, end);
  HTTP_TEST ((res == HTTP_INVALID_VARINT), "varint decoded is invalid");

  u8 input5[] = { 0xC0, 0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xFF };
  p = input5;
  end = p + 8;
  res = http_decode_varint (&p, end);
  HTTP_TEST ((res == 0x1234567890ABCD && *p == *end), "varint decoded as %lu", res);

  end = p + 3;
  res = http_decode_varint (&p, end);
  HTTP_TEST ((res == HTTP_INVALID_VARINT), "varint decoded is invalid");

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
      else if (unformat (input, "token-is-case"))
	res = http_test_http_token_is_case (vm);
      else if (unformat (input, "header-table"))
	res = http_test_http_header_table (vm);
      else if (unformat (input, "hpack"))
	res = http_test_hpack (vm);
      else if (unformat (input, "h2-frame"))
	res = http_test_h2_frame (vm);
      else if (unformat (input, "h2-window-update-scheduling"))
	res = http_test_h2_window_update_scheduling (vm);
      else if (unformat (input, "qpack"))
	res = http_test_qpack (vm);
      else if (unformat (input, "h3-frame"))
	res = http_test_h3_frame (vm);
      else if (unformat (input, "lookup-header-name"))
	res = http_test_http_lookup_header_name (vm);
      else if (unformat (input, "headers-rx-to-tx"))
	res = http_test_http_headers_rx_to_tx (vm);
      else if (unformat (input, "parse-content-length"))
	res = http_test_parse_content_length (vm);
      else if (unformat (input, "decode-chunked"))
	res = http_test_decode_chunked (vm);
      else if (unformat (input, "encode-u64-decimal"))
	res = http_test_encode_u64_decimal (vm);
      else if (unformat (input, "rx-publication"))
	res = http_test_rx_publication (vm);
      else if (unformat (input, "decode-varint"))
	res = http_test_decode_varint (vm);
      else if (unformat (input, "all"))
	{
	  if ((res = http_test_rx_publication (vm)))
	    goto done;
	  if ((res = http_test_decode_varint (vm)))
	    goto done;
	  if ((res = http_test_parse_authority (vm)))
	    goto done;
	  if ((res = http_test_parse_masque_host_port (vm)))
	    goto done;
	  if ((res = http_test_udp_payload_datagram (vm)))
	    goto done;
	  if ((res = http_test_http_token_is_case (vm)))
	    goto done;
	  if ((res = http_test_http_header_table (vm)))
	    goto done;
	  if ((res = http_test_hpack (vm)))
	    goto done;
	  if ((res = http_test_h2_frame (vm)))
	    goto done;
	  if ((res = http_test_h2_window_update_scheduling (vm)))
	    goto done;
	  if ((res = http_test_qpack (vm)))
	    goto done;
	  if ((res = http_test_h3_frame (vm)))
	    goto done;
	  if ((res = http_test_http_lookup_header_name (vm)))
	    goto done;
	  if ((res = http_test_http_headers_rx_to_tx (vm)))
	    goto done;
	  if ((res = http_test_parse_content_length (vm)))
	    goto done;
	  if ((res = http_test_decode_chunked (vm)))
	    goto done;
	  if ((res = http_test_encode_u64_decimal (vm)))
	    goto done;
	}
      else
	return clib_error_return (0, "unknown input `%U'", format_unformat_error, input);
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
