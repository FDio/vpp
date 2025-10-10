/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>
#include <vnet/sfdp/sfdp.h>
#include <vnet/sfdp/lookup/parser.h>
#include <sfdp_services/base/tcp-check/tcp_check.h>

u8 *
format_sfdp_tcp_check_session_flags (u8 *s, va_list *args)
{
  u32 flags = va_arg (*args, u32);
#define _(name, x, str)                                                       \
  if (flags & SFDP_TCP_CHECK_SESSION_FLAG_##name)                             \
    s = format (s, "%s", (str));
  foreach_sfdp_tcp_check_session_flag
#undef _

    return s;
}

u32
sfdp_table_format_insert_tcp_check_session (
  table_t *t, u32 n, sfdp_main_t *sfdp, u32 session_index,
  sfdp_session_t *session, sfdp_tcp_check_session_state_t *tcp_session)
{
  sfdp_parser_main_t *pm = &sfdp_parser_main;
  u64 session_net = clib_host_to_net_u64 (session->session_id);
  sfdp_tenant_t *tenant = sfdp_tenant_at_index (sfdp, session->tenant_idx);
  sfdp_session_ip46_key_t skey;
  __clib_aligned (CLIB_CACHE_LINE_BYTES)
  u8 kdata[SFDP_PARSER_MAX_KEY_SIZE];
  sfdp_parser_data_t *parser;
  /* Session id */
  table_format_cell (t, n, 0, "0x%U", format_hex_bytes, &session_net,
		     sizeof (session_net));
  /* Tenant id */
  table_format_cell (t, n, 1, "%d", tenant->tenant_id);
  /* Session index */
  table_format_cell (t, n, 2, "%d", session_index);
  /* Session type */
  table_format_cell (t, n, 3, "%U", format_sfdp_session_type, session->type,
		     session->parser_index[SFDP_SESSION_KEY_PRIMARY]);
  /* Session flags */
  table_format_cell (t, n, 4, "%U", format_sfdp_tcp_check_session_flags,
		     tcp_session->flags);
  if (session->key_flags & SFDP_SESSION_KEY_FLAG_PRIMARY_VALID_IP4)
    {
      sfdp_normalise_ip4_key (session, &skey.key4, SFDP_SESSION_KEY_PRIMARY);
      table_format_cell (t, n, 5, "%U", format_sfdp_ipv4_context_id,
			 &skey.key4);
      table_format_cell (t, n, 6, "%U", format_sfdp_ipv4_ingress, &skey.key4);
      table_format_cell (t, n, 7, "%U", format_sfdp_ipv4_egress, &skey.key4);
    }
  else if (session->key_flags & SFDP_SESSION_KEY_FLAG_PRIMARY_VALID_IP6)
    {
      sfdp_normalise_ip6_key (session, &skey.key6, SFDP_SESSION_KEY_PRIMARY);
      table_format_cell (t, n, 5, "%U", format_sfdp_ipv6_context_id,
			 &skey.key6);
      table_format_cell (t, n, 6, "%U", format_sfdp_ipv6_ingress, &skey.key6);
      table_format_cell (t, n, 7, "%U", format_sfdp_ipv6_egress, &skey.key6);
    }
  else if (session->key_flags & SFDP_SESSION_KEY_FLAG_PRIMARY_VALID_USER)
    {
      parser = vec_elt_at_index (
	pm->parsers, session->parser_index[SFDP_SESSION_KEY_PRIMARY]);
      parser->normalize_key_fn (session, kdata, SFDP_SESSION_KEY_PRIMARY);
      table_format_cell (
	t, n, 5, "%U", parser->format_fn[SFDP_PARSER_FORMAT_FUNCTION_CONTEXT],
	kdata);
      table_format_cell (
	t, n, 6, "%U", parser->format_fn[SFDP_PARSER_FORMAT_FUNCTION_INGRESS],
	kdata);
      table_format_cell (t, n, 7, "%U",
			 parser->format_fn[SFDP_PARSER_FORMAT_FUNCTION_EGRESS],
			 kdata);
    }
  n += 1;
  if (session->key_flags & SFDP_SESSION_KEY_FLAG_SECONDARY_VALID_IP4)
    {
      sfdp_normalise_ip4_key (session, &skey.key4, SFDP_SESSION_KEY_SECONDARY);
      table_format_cell (t, n, 5, "%U", format_sfdp_ipv4_context_id,
			 &skey.key4);
      table_format_cell (t, n, 6, "%U", format_sfdp_ipv4_ingress, &skey.key4);
      table_format_cell (t, n, 7, "%U", format_sfdp_ipv4_egress, &skey.key4);
      n += 1;
    }
  else if (session->key_flags & SFDP_SESSION_KEY_FLAG_SECONDARY_VALID_IP6)
    {
      sfdp_normalise_ip6_key (session, &skey.key6, SFDP_SESSION_KEY_SECONDARY);
      table_format_cell (t, n, 5, "%U", format_sfdp_ipv6_context_id,
			 &skey.key6);
      table_format_cell (t, n, 6, "%U", format_sfdp_ipv6_ingress, &skey.key6);
      table_format_cell (t, n, 7, "%U", format_sfdp_ipv6_egress, &skey.key6);
      n += 1;
    }
  else if (session->key_flags & SFDP_SESSION_KEY_FLAG_SECONDARY_VALID_USER)
    {
      parser = vec_elt_at_index (
	pm->parsers, session->parser_index[SFDP_SESSION_KEY_SECONDARY]);
      parser->normalize_key_fn (session, kdata, SFDP_SESSION_KEY_SECONDARY);
      table_format_cell (
	t, n, 5, "%U", parser->format_fn[SFDP_PARSER_FORMAT_FUNCTION_CONTEXT],
	kdata);
      table_format_cell (
	t, n, 6, "%U", parser->format_fn[SFDP_PARSER_FORMAT_FUNCTION_INGRESS],
	kdata);
      table_format_cell (t, n, 7, "%U",
			 parser->format_fn[SFDP_PARSER_FORMAT_FUNCTION_EGRESS],
			 kdata);
      n += 1;
    }
  return n;
}
