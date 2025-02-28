/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2024 Cisco Systems, Inc.
 */

#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>
#include <http/http.h>
#include <http/http_header_names.h>
#include <http/http2/hpack.h>
#include <http/http2/frame.h>

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
  HTTP_TEST ((rv = 1), "header value '%U' should be 'GZIP'", format_http_bytes,
	     value->base, value->len);

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
  rv = http_token_is (value->base, value->len, http_token_lit ("Eggs, Spam"));
  HTTP_TEST ((rv = 1), "header value '%U' should be 'Eggs, Spam'",
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
http_test_hpack (vlib_main_t *vm)
{
  vlib_cli_output (vm, "hpack_decode_int");

  static uword (*_hpack_decode_int) (u8 * *pos, u8 * end, u8 prefix_len);
  _hpack_decode_int =
    vlib_get_plugin_symbol ("http_plugin.so", "hpack_decode_int");

  u8 *pos, *end, *input = 0;
  uword value;
#define TEST(i, pl, e)                                                        \
  vec_validate (input, sizeof (i) - 2);                                       \
  memcpy (input, i, sizeof (i) - 1);                                          \
  pos = input;                                                                \
  end = vec_end (input);                                                      \
  value = _hpack_decode_int (&pos, end, (u8) pl);                             \
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
  value = _hpack_decode_int (&pos, end, (u8) pl);                             \
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

  static u8 *(*_hpack_encode_int) (u8 * dst, uword value, u8 prefix_len);
  _hpack_encode_int =
    vlib_get_plugin_symbol ("http_plugin.so", "hpack_encode_int");

  u8 *buf = 0;
  u8 *p;

#define TEST(v, pl, e)                                                        \
  vec_validate_init_empty (buf, 15, 0);                                       \
  p = _hpack_encode_int (buf, v, (u8) pl);                                    \
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

  static http2_error_t (*_hpack_decode_string) (u8 * *src, u8 * end, u8 * *buf,
						uword * buf_len);
  _hpack_decode_string =
    vlib_get_plugin_symbol ("http_plugin.so", "hpack_decode_string");

  u8 *bp;
  uword blen, len;
  http2_error_t rv;

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
	      rv == HTTP2_ERROR_NO_ERROR),                                    \
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
  N_TEST ("\x87", HTTP2_ERROR_COMPRESSION_ERROR);
  N_TEST ("\x07priv", HTTP2_ERROR_COMPRESSION_ERROR);
  /* invalid length */
  N_TEST ("\x7Fprivate", HTTP2_ERROR_COMPRESSION_ERROR);
  /* invalid EOF */
  N_TEST ("\x81\x8C", HTTP2_ERROR_COMPRESSION_ERROR);
  /* not enough space for decoding */
  N_TEST (
    "\x96\xD0\x7A\xBE\x94\x10\x54\xD4\x44\xA8\x20\x05\x95\x04\x0B\x81\x66"
    "\xE0\x82\xA6\x2D\x1B\xFF",
    HTTP2_ERROR_INTERNAL_ERROR);
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

  static http2_error_t (*_hpack_decode_header) (
    u8 * *src, u8 * end, u8 * *buf, uword * buf_len, u32 * name_len,
    u32 * value_len, hpack_dynamic_table_t * dt);

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

  _hpack_dynamic_table_init (&table, 128);

#define TEST(i, e_name, e_value, dt_size)                                     \
  vec_validate (input, sizeof (i) - 2);                                       \
  memcpy (input, i, sizeof (i) - 1);                                          \
  pos = input;                                                                \
  vec_validate_init_empty (buf, 63, 0);                                       \
  bp = buf;                                                                   \
  blen = vec_len (buf);                                                       \
  rv = _hpack_decode_header (&pos, vec_end (input), &bp, &blen, &name_len,    \
			     &value_len, &table);                             \
  len = vec_len (buf) - blen;                                                 \
  HTTP_TEST ((rv == HTTP2_ERROR_NO_ERROR && table.used == dt_size &&          \
	      name_len == strlen (e_name) && value_len == strlen (e_value) && \
	      !memcmp (buf, e_name, name_len) &&                              \
	      !memcmp (buf + name_len, e_value, value_len) &&                 \
	      vec_len (buf) == (blen + name_len + value_len) &&               \
	      pos == vec_end (input) && bp == buf + name_len + value_len),    \
	     "%U is decoded as '%U: %U'", format_hex_bytes, input,            \
	     vec_len (input), format_http_bytes, buf, name_len,               \
	     format_http_bytes, buf + name_len, value_len);                   \
  vec_free (input);                                                           \
  vec_free (buf);

  /* C.2.1. Literal Header Field with Indexing */
  TEST ("\x40\x0A\x63\x75\x73\x74\x6F\x6D\x2D\x6B\x65\x79\x0D\x63\x75\x73\x74"
	"\x6F\x6D\x2D\x68\x65\x61\x64\x65\x72",
	"custom-key", "custom-header", 55);
  /* C.2.2. Literal Header Field without Indexing */
  TEST ("\x04\x0C\x2F\x73\x61\x6D\x70\x6C\x65\x2F\x70\x61\x74\x68", ":path",
	"/sample/path", 55);
  /* C.2.3. Literal Header Field Never Indexed */
  TEST ("\x10\x08\x70\x61\x73\x73\x77\x6F\x72\x64\x06\x73\x65\x63\x72\x65\x74",
	"password", "secret", 55);
  /* C.2.4. Indexed Header Field */
  TEST ("\x82", ":method", "GET", 55);
  TEST ("\xBE", "custom-key", "custom-header", 55);
  /* Literal Header Field with Indexing - enough space in dynamic table */
  TEST ("\x41\x0F\x77\x77\x77\x2E\x65\x78\x61\x6D\x70\x6C\x65\x2E\x63\x6F\x6D",
	":authority", "www.example.com", 112);
  /* verification */
  TEST ("\xBE", ":authority", "www.example.com", 112);
  TEST ("\xBF", "custom-key", "custom-header", 112);
  /* Literal Header Field with Indexing - eviction */
  TEST ("\x58\x08\x6E\x6F\x2D\x63\x61\x63\x68\x65", "cache-control",
	"no-cache", 110);
  /* verification */
  TEST ("\xBE", "cache-control", "no-cache", 110);
  TEST ("\xBF", ":authority", "www.example.com", 110);
  /* Literal Header Field with Indexing - eviction */
  TEST ("\x40\x0A\x63\x75\x73\x74\x6F\x6D\x2D\x6B\x65\x79\x0D\x63\x75\x73\x74"
	"\x6F\x6D\x2D\x68\x65\x61\x64\x65\x72",
	"custom-key", "custom-header", 108);
  /* verification */
  TEST ("\xBE", "custom-key", "custom-header", 108);
  TEST ("\xBF", "cache-control", "no-cache", 108);
  /* Literal Header Field with Indexing - eviction */
  TEST ("\x41\x0F\x77\x77\x77\x2E\x65\x78\x61\x6D\x70\x6C\x65\x2E\x63\x6F\x6D",
	":authority", "www.example.com", 112);
  /* verification */
  TEST ("\xBE", ":authority", "www.example.com", 112);
  TEST ("\xBF", "custom-key", "custom-header", 112);
  /* Literal Header Field with Indexing - eviction with reference */
  TEST ("\x7F\x00\x0C\x63\x75\x73\x74\x6F\x6D\x2D\x76\x61\x6C\x75\x65",
	"custom-key", "custom-value", 111);
  /* verification */
  TEST ("\xBE", "custom-key", "custom-value", 111);
  TEST ("\xBF", ":authority", "www.example.com", 111);
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

  vlib_cli_output (vm, "hpack_serialize_response");

  hpack_response_control_data_t resp_cd;
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
  vec_free (buf);
  vec_free (headers_buf);
  vec_free (server_name);
  vec_free (date);

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

  static http2_error_t (*_http2_frame_read_settings) (
    http2_conn_settings_t * settings, u8 * payload, u32 payload_len);

  _http2_frame_read_settings =
    vlib_get_plugin_symbol ("http_plugin.so", "http2_frame_read_settings");

  http2_error_t rv;
  http2_frame_header_t fh = { 0 };
  http2_conn_settings_t conn_settings = http2_default_conn_settings;

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
	      fh.stream_id == 5 && fh.length == 4),
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

  _http2_frame_write_rst_stream (HTTP2_ERROR_PROTOCOL_ERROR, 5, &buf);
  HTTP_TEST ((vec_len (buf) == sizeof (rst_stream) &&
	      !memcmp (buf, rst_stream, sizeof (rst_stream))),
	     "RST_STREAM frame written");
  vec_free (buf);

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
      else if (unformat (input, "all"))
	{
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
