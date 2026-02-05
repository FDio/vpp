/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/sfdp/service.h>
#include <vnet/sfdp/sfdp.h>
#include <vnet/sfdp/lookup/parser.h>
#include <vppinfra/format_table.h>
u8 *
format_sfdp_session_state (u8 *s, va_list *args)
{
  u8 session_state = va_arg (*args, u32);
#define _(n, str)                                                             \
  if (session_state == SFDP_SESSION_STATE_##n)                                \
    s = format (s, "%s", (str));
  foreach_sfdp_session_state
#undef _
    return s;
}

u8 *
format_sfdp_session_type (u8 *s, va_list *args)
{
  sfdp_parser_main_t *pm = &sfdp_parser_main;
  sfdp_parser_data_t *pdata;
  const char *parser_name;
  u32 session_type = va_arg (*args, u32);
  u32 parser_index = va_arg (*args, u32);
  if (session_type == SFDP_SESSION_TYPE_IP4)
    s = format (s, "ipv4");
  else if (session_type == SFDP_SESSION_TYPE_IP6)
    s = format (s, "ipv6");
  else if (session_type == SFDP_SESSION_TYPE_USER)
    {
      pdata = vec_elt_at_index (pm->parsers, parser_index);
      parser_name = pdata->name;
      s = format (s, "custom-parser: %s", parser_name);
    }
  return s;
}

u8 *
format_sfdp_ipv4_context_id (u8 *s, va_list *args)
{
  sfdp_session_ip4_key_t *k = va_arg (*args, sfdp_session_ip4_key_t *);
  s = format (s, "%d", k->context_id);
  return s;
}

u8 *
format_sfdp_ipv4_ingress (u8 *s, va_list *args)
{
  sfdp_session_ip4_key_t *k = va_arg (*args, sfdp_session_ip4_key_t *);
  s = format (s, "%U:%u", format_ip4_address, &k->ip4_key.ip_addr_lo,
	      k->ip4_key.port_lo);
  return s;
}

u8 *
format_sfdp_ipv4_egress (u8 *s, va_list *args)
{
  sfdp_session_ip4_key_t *k = va_arg (*args, sfdp_session_ip4_key_t *);
  s = format (s, "%U:%u", format_ip4_address, &k->ip4_key.ip_addr_hi,
	      k->ip4_key.port_hi);
  return s;
}

u8 *
format_sfdp_ipv6_context_id (u8 *s, va_list *args)
{
  sfdp_session_ip6_key_t *k = va_arg (*args, sfdp_session_ip6_key_t *);
  s = format (s, "%d", k->context_id);
  return s;
}

u8 *
format_sfdp_ipv6_ingress (u8 *s, va_list *args)
{
  sfdp_session_ip6_key_t *k = va_arg (*args, sfdp_session_ip6_key_t *);
  s = format (s, "%U:%u", format_ip6_address, &k->ip6_key.ip6_addr_lo,
	      k->ip6_key.port_lo);
  return s;
}

u8 *
format_sfdp_ipv6_egress (u8 *s, va_list *args)
{
  sfdp_session_ip6_key_t *k = va_arg (*args, sfdp_session_ip6_key_t *);
  s = format (s, "%U:%u", format_ip6_address, &k->ip6_key.ip6_addr_hi,
	      k->ip6_key.port_hi);
  return s;
}

void
sfdp_table_format_add_header_col (table_t *session_table)
{
  table_add_header_col (session_table, 11, "id", "tenant", "thread", "index",
			"type", "proto", "context", "ingress", "egress",
			"state", "TTL(s)");
}

u32
sfdp_table_format_insert_session (table_t *t, u32 n, u32 session_index, sfdp_session_t *session,
				  sfdp_tenant_id_t tenant_id, f64 now)
{
  u64 session_net = clib_host_to_net_u64 (session->session_id);
  sfdp_session_ip46_key_t skey = {};
  __clib_aligned (CLIB_CACHE_LINE_BYTES)
  u8 kdata[SFDP_PARSER_MAX_KEY_SIZE];
  sfdp_parser_main_t *pm = &sfdp_parser_main;
  sfdp_parser_data_t *parser;
  /* Session id */
  table_format_cell (t, n, 0, "0x%U", format_hex_bytes, &session_net,
		     sizeof (session_net));
  /* Tenant id */
  table_format_cell (t, n, 1, "%d", tenant_id);
  /* Owning thread */
  table_format_cell (t, n, 2, "%d", session->owning_thread_index);
  /* Session index */
  table_format_cell (t, n, 3, "%d", session_index);
  /* Session type */
  table_format_cell (t, n, 4, "%U", format_sfdp_session_type, session->type,
		     session->parser_index[SFDP_SESSION_KEY_PRIMARY]);
  /* Protocol */
  table_format_cell (t, n, 5, "%U", format_ip_protocol, session->proto);
  /* Session state */
  table_format_cell (t, n, 9, "%U", format_sfdp_session_state, session->state);
  /* Remaining time */
  table_format_cell (
    t, n, 10, "%f",
    sfdp_main.expiry_callbacks.session_remaining_time (session, now));

  if (session->key_flags & SFDP_SESSION_KEY_FLAG_PRIMARY_VALID_IP4)
    {
      sfdp_normalise_ip4_key (session, &skey.key4, SFDP_SESSION_KEY_PRIMARY);
      table_format_cell (t, n, 6, "%U", format_sfdp_ipv4_context_id,
			 &skey.key4);
      table_format_cell (t, n, 7, "%U", format_sfdp_ipv4_ingress, &skey.key4);
      table_format_cell (t, n, 8, "%U", format_sfdp_ipv4_egress, &skey.key4);
    }
  else if (session->key_flags & SFDP_SESSION_KEY_FLAG_PRIMARY_VALID_IP6)
    {
      sfdp_normalise_ip6_key (session, &skey.key6, SFDP_SESSION_KEY_PRIMARY);
      table_format_cell (t, n, 6, "%U", format_sfdp_ipv6_context_id,
			 &skey.key6);
      table_format_cell (t, n, 7, "%U", format_sfdp_ipv6_ingress, &skey.key6);
      table_format_cell (t, n, 8, "%U", format_sfdp_ipv6_egress, &skey.key6);
    }
  else if (session->key_flags & SFDP_SESSION_KEY_FLAG_PRIMARY_VALID_USER)
    {
      parser = vec_elt_at_index (
	pm->parsers, session->parser_index[SFDP_SESSION_KEY_PRIMARY]);
      parser->normalize_key_fn (session, kdata, SFDP_SESSION_KEY_PRIMARY);
      table_format_cell (
	t, n, 6, "%U", parser->format_fn[SFDP_PARSER_FORMAT_FUNCTION_CONTEXT],
	kdata);
      table_format_cell (
	t, n, 7, "%U", parser->format_fn[SFDP_PARSER_FORMAT_FUNCTION_INGRESS],
	kdata);
      table_format_cell (t, n, 8, "%U",
			 parser->format_fn[SFDP_PARSER_FORMAT_FUNCTION_EGRESS],
			 kdata);
    }
  n += 1;
  if (session->key_flags & SFDP_SESSION_KEY_FLAG_SECONDARY_VALID_IP4)
    {
      sfdp_normalise_ip4_key (session, &skey.key4, SFDP_SESSION_KEY_SECONDARY);
      table_format_cell (t, n, 6, "%U", format_sfdp_ipv4_context_id,
			 &skey.key4);
      table_format_cell (t, n, 7, "%U", format_sfdp_ipv4_ingress, &skey.key4);
      table_format_cell (t, n, 8, "%U", format_sfdp_ipv4_egress, &skey.key4);
      n += 1;
    }
  else if (session->key_flags & SFDP_SESSION_KEY_FLAG_SECONDARY_VALID_IP6)
    {
      sfdp_normalise_ip6_key (session, &skey.key6, SFDP_SESSION_KEY_SECONDARY);
      table_format_cell (t, n, 6, "%U", format_sfdp_ipv6_context_id,
			 &skey.key6);
      table_format_cell (t, n, 7, "%U", format_sfdp_ipv6_ingress, &skey.key6);
      table_format_cell (t, n, 8, "%U", format_sfdp_ipv6_egress, &skey.key6);
      n += 1;
    }
  else if (session->key_flags & SFDP_SESSION_KEY_FLAG_SECONDARY_VALID_USER)
    {
      parser = vec_elt_at_index (
	pm->parsers, session->parser_index[SFDP_SESSION_KEY_SECONDARY]);
      parser->normalize_key_fn (session, kdata, SFDP_SESSION_KEY_SECONDARY);
      table_format_cell (
	t, n, 6, "%U", parser->format_fn[SFDP_PARSER_FORMAT_FUNCTION_CONTEXT],
	kdata);
      table_format_cell (
	t, n, 7, "%U", parser->format_fn[SFDP_PARSER_FORMAT_FUNCTION_INGRESS],
	kdata);
      table_format_cell (t, n, 8, "%U",
			 parser->format_fn[SFDP_PARSER_FORMAT_FUNCTION_EGRESS],
			 kdata);
      n += 1;
    }
  return n;
}

u8 *
format_sfdp_scope (u8 *s, va_list *args)
{
  u32 scope_index = va_arg (*args, u32);
  sfdp_service_main_t *sm = &sfdp_service_main;

  return format (s, "%s", sm->scope_names[scope_index]);
}

u8 *
format_sfdp_bitmap (u8 *s, va_list *args)
{
  u32 scope_index = va_arg (*args, u32);
  sfdp_bitmap_t bmp = va_arg (*args, sfdp_bitmap_t);
  sfdp_service_main_t *sm = &sfdp_service_main;
  sfdp_service_registration_t **services =
    vec_elt_at_index (sm->services_per_scope_index, scope_index)[0];
  int i;
  for (i = 0; i < vec_len (services); i++)
    if (bmp & services[i]->service_mask[0])
      s = format (s, "%s,", services[i]->node_name);
  return s;
}

u8 *
format_sfdp_session_detail (u8 *s, va_list *args)
{
  u32 session_index = va_arg (*args, u32);
  f64 now = va_arg (*args, f64);
  sfdp_session_t *session = sfdp_session_at_index (session_index);
  u32 scope_index = session->scope_index;

  u64 session_net = clib_host_to_net_u64 (session->session_id);
  vlib_counter_t fctr, bctr;
  uword thread_index = session->owning_thread_index;
  sfdp_session_ip46_key_t skey = {};
  __clib_aligned (CLIB_CACHE_LINE_BYTES)
  u8 kdata[SFDP_PARSER_MAX_KEY_SIZE];
  sfdp_parser_main_t *pm = &sfdp_parser_main;
  sfdp_parser_data_t *parser = 0;

  vlib_get_combined_counter (
    &sfdp_main.per_session_ctr[SFDP_FLOW_COUNTER_LOOKUP], session_index << 1,
    &fctr);
  vlib_get_combined_counter (
    &sfdp_main.per_session_ctr[SFDP_FLOW_COUNTER_LOOKUP],
    (session_index << 1) | 0x1, &bctr);
  /* TODO: deal with secondary keys */
  if (session->key_flags & SFDP_SESSION_KEY_FLAG_PRIMARY_VALID_IP4)
    sfdp_normalise_ip4_key (session, &skey.key4, SFDP_SESSION_KEY_PRIMARY);
  else if (session->key_flags & SFDP_SESSION_KEY_FLAG_PRIMARY_VALID_IP6)
    sfdp_normalise_ip6_key (session, &skey.key6, SFDP_SESSION_KEY_PRIMARY);
  else if (session->key_flags & SFDP_SESSION_KEY_FLAG_PRIMARY_VALID_USER)
    {
      parser = vec_elt_at_index (
	pm->parsers, session->parser_index[SFDP_SESSION_KEY_PRIMARY]);
      parser->normalize_key_fn (session, kdata, SFDP_SESSION_KEY_PRIMARY);
    }

  s = format (s, "  session id: 0x%U\n", format_hex_bytes, &session_net,
	      sizeof (u64));
  s = format (s, "  thread index: %d\n",
	      (thread_index == SFDP_UNBOUND_THREAD_INDEX) ? -1 : thread_index);
  s = format (s, "  session index: %d\n", session_index);

  if (session->key_flags & SFDP_SESSION_KEY_FLAG_PRIMARY_VALID_IP4)
    s = format (s, "  specification: %U\t%U\t-> %U\n", format_ip_protocol, session->proto,
		format_sfdp_ipv4_ingress, &skey.key4, format_sfdp_ipv4_egress, &skey.key4);
  else if (session->key_flags & SFDP_SESSION_KEY_FLAG_PRIMARY_VALID_IP6)
    s = format (s, "  specification: %U\t%U\t-> %U\n", format_ip_protocol, session->proto,
		format_sfdp_ipv6_ingress, &skey.key6, format_sfdp_ipv6_egress, &skey.key6);
  else if (session->key_flags & SFDP_SESSION_KEY_FLAG_PRIMARY_VALID_USER)
    s = format (s, "  specification: %U\t%U\t-> %U\n", format_ip_protocol, session->proto,
		parser->format_fn[SFDP_PARSER_FORMAT_FUNCTION_INGRESS], kdata,
		parser->format_fn[SFDP_PARSER_FORMAT_FUNCTION_EGRESS], kdata);

  s = format (s, "  state: %U\n", format_sfdp_session_state, session->state);
  s = format (s, "  %U\n", sfdp_main.expiry_callbacks.format_session_details,
	      session, now);
  s = format (s, "  forward service chain: %U\n", format_sfdp_bitmap,
	      scope_index, session->bitmaps[SFDP_FLOW_FORWARD]);
  s = format (s, "  reverse service chain: %U\n", format_sfdp_bitmap,
	      scope_index, session->bitmaps[SFDP_FLOW_REVERSE]);
  s = format (s, "  counters:\n");
  s = format (s, "    forward flow:\n");
  s = format (s, "      bytes: %llu\n", fctr.bytes);
  s = format (s, "      packets: %llu\n", fctr.packets);
  s = format (s, "    reverse flow:\n");
  s = format (s, "      bytes: %llu\n", bctr.bytes);
  s = format (s, "      packets: %llu\n", bctr.packets);
  return s;
}

u8 *
format_sfdp_tenant (u8 *s, va_list *args)
{

  u32 indent = format_get_indent (s);
  __clib_unused sfdp_main_t *sfdp = va_arg (*args, sfdp_main_t *);
  sfdp_tenant_index_t tenant_idx = va_arg (*args, u32);
  sfdp_tenant_t *tenant = va_arg (*args, sfdp_tenant_t *);
  u32 scope_index;
  s = format (s, "index: %d\n", tenant_idx);
  s = format (s, "%Ucontext: %d\n", format_white_space, indent,
	      tenant->context_id);
  foreach_sfdp_scope_index (scope_index)
  {
    s = format (s, "%Uscope: %U\n", format_white_space, indent,
		format_sfdp_scope, scope_index);
    s =
      format (s, "%Uforward service chain:\n", format_white_space, indent + 2);
    s =
      format (s, "%U%U\n", format_white_space, indent + 4, format_sfdp_bitmap,
	      scope_index, tenant->bitmaps[SFDP_FLOW_FORWARD]);
    s =
      format (s, "%Ureverse service chain:\n", format_white_space, indent + 2);
    s =
      format (s, "%U%U\n", format_white_space, indent + 4, format_sfdp_bitmap,
	      scope_index, tenant->bitmaps[SFDP_FLOW_REVERSE]);
  }
  return s;
}

u8 *
format_sfdp_tenant_extra (u8 *s, va_list *args)
{
  u32 indent = format_get_indent (s);
  sfdp_main_t *sfdp = va_arg (*args, sfdp_main_t *);
  vlib_main_t *vm = vlib_get_main ();
  sfdp_tenant_index_t tenant_idx = va_arg (*args, u32);
  __clib_unused sfdp_tenant_t *tenant = va_arg (*args, sfdp_tenant_t *);
  sfdp_timeout_t *timeout;
  counter_t ctr;
  vlib_counter_t ctr2;
  s = format (s, "%s\n", "Counters:");

#define _(x, y, z)                                                            \
  ctr = vlib_get_simple_counter (                                             \
    &sfdp->tenant_session_ctr[SFDP_TENANT_SESSION_COUNTER_##x], tenant_idx);  \
  s = format (s, "%U%s: %llu\n", format_white_space, indent + 2, z, ctr);
  foreach_sfdp_tenant_session_counter
#undef _
#define _(x, y, z)                                                            \
  vlib_get_combined_counter (                                                 \
    &sfdp->tenant_data_ctr[SFDP_TENANT_DATA_COUNTER_##x], tenant_idx, &ctr2); \
  s = format (s, "%U%s: %llu packets\n", format_white_space, indent + 2, z,   \
	      ctr2.packets);                                                  \
  s = format (s, "%U  %llu bytes\n", format_white_space,                      \
	      indent + strlen (z) + 2, ctr2.bytes);
    foreach_sfdp_tenant_data_counter
#undef _
      s = format (s, "%U%s\n", format_white_space, indent,
		  "Configured Timeout:");

  sfdp_foreach_timeout (sfdp, timeout)
  {
    u32 idx = timeout - sfdp->timeouts;
    if ((timeout->name != NULL) && strlen (timeout->name))
      {
	s = format (s, "%U%s: %d seconds\n", format_white_space, indent + 2,
		    timeout->name, tenant->timeouts[idx]);
      }
  }

  s = format (s, "%U%s\n", format_white_space, indent,
	      "Configured Slowpath nodes:");
#define _(sym, default, name)                                                 \
  s = format (s, "%U%s: %U\n", format_white_space, indent + 2, name,          \
	      format_vlib_node_name, vm,                                      \
	      tenant->sp_node_indices[SFDP_SP_NODE_##sym]);
  foreach_sfdp_sp_node
#undef _
    return s;
}

u8 *
format_sfdp_sp_node (u8 *s, va_list *args)
{
  u32 sp_index = va_arg (*args, u32);
#define _(sym, default, name)                                                 \
  if (sp_index == SFDP_SP_NODE_##sym)                                         \
    s = format (s, name);
  foreach_sfdp_sp_node
#undef _
    return s;
}

uword
unformat_sfdp_service (unformat_input_t *input, va_list *args)
{
  sfdp_service_main_t *sm = &sfdp_service_main;
  u8 *result = va_arg (*args, u8 *);
  int i;
  for (u32 scope_index = 0; scope_index < sm->n_scopes; scope_index++)
    for (i = 0; i < vec_len (sm->services_per_scope_index[scope_index]); i++)
      {
	sfdp_service_registration_t *reg =
	  vec_elt_at_index (sm->services_per_scope_index[scope_index], i)[0];
	if (unformat (input, reg->node_name))
	  {
	    *result = reg->index_in_bitmap[0];
	    return 1;
	  }
      }
  return 0;
}

uword
unformat_sfdp_service_bitmap (unformat_input_t *input, va_list *args)
{
  sfdp_bitmap_t *result = va_arg (*args, sfdp_bitmap_t *);
  u8 i = UINT8_MAX;
  sfdp_bitmap_t bitmap = 0;
  while (unformat_user (input, unformat_sfdp_service, &i))
    bitmap |= 1ULL << i;
  if (i != UINT8_MAX)
    {
      *result = bitmap;
      return 1;
    }
  return 0;
}

uword
unformat_sfdp_scope_name (unformat_input_t *input, va_list *args)
{
  u32 *result = va_arg (*args, u32 *);
  sfdp_service_main_t *sm = &sfdp_service_main;
  u32 scope_index;
  for (scope_index = 0; scope_index < sm->n_scopes; scope_index++)
    if (unformat (input, sm->scope_names[scope_index]))
      {
	*result = scope_index;
	return 1;
      }

  return 0;
}

uword
unformat_sfdp_sp_node (unformat_input_t *input, va_list *args)
{
  u32 *result = va_arg (*args, u32 *);
#define _(sym, default, str)                                                  \
  if (unformat (input, str))                                                  \
    {                                                                         \
      *result = SFDP_SP_NODE_##sym;                                           \
      return 1;                                                               \
    }
  foreach_sfdp_sp_node
#undef _
    return 0;
}

uword
unformat_sfdp_timeout_name (unformat_input_t *input, va_list *args)
{
  u32 *result = va_arg (*args, u32 *);
  sfdp_main_t *sfdp = &sfdp_main;
  sfdp_timeout_t *timeout;
  sfdp_foreach_timeout (sfdp, timeout)
  {
    if ((timeout->name != NULL) && strlen (timeout->name) &&
	unformat (input, timeout->name))
      {
	*result = timeout - sfdp->timeouts;
	return 1;
      }
  }
  return 0;
}
