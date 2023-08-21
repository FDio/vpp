/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2020 Cisco and/or its affiliates.
 */

#include <vnet/ip/ip.h>
#include <cnat/cnat_snat_policy.h>
#include <cnat/cnat_translation.h>

cnat_snat_policy_main_t cnat_snat_policy_main;

uword
unformat_cnat_snat_interface_map_type (unformat_input_t *input, va_list *args)
{
  cnat_snat_interface_map_type_t *a =
    va_arg (*args, cnat_snat_interface_map_type_t *);
  if (unformat (input, "include-v4"))
    *a = CNAT_SNAT_IF_MAP_INCLUDE_V4;
  else if (unformat (input, "include-v6"))
    *a = CNAT_SNAT_IF_MAP_INCLUDE_V6;
  else if (unformat (input, "k8s"))
    *a = CNAT_SNAT_IF_MAP_INCLUDE_POD;
  else if (unformat (input, "host"))
    *a = CNAT_SNAT_IF_MAP_INCLUDE_HOST;
  else
    return 0;
  return 1;
}

u8 *
format_cnat_snat_interface_map_type (u8 *s, va_list *args)
{
  cnat_snat_interface_map_type_t mtype = va_arg (*args, int);
  switch (mtype)
    {
    case CNAT_SNAT_IF_MAP_INCLUDE_V4:
      s = format (s, "Included v4");
      break;
    case CNAT_SNAT_IF_MAP_INCLUDE_V6:
      s = format (s, "Included v6");
      break;
    case CNAT_SNAT_IF_MAP_INCLUDE_POD:
      s = format (s, "k8s pod");
      break;
    case CNAT_SNAT_IF_MAP_INCLUDE_HOST:
      s = format (s, "k8s host");
      break;
    default:
      s = format (s, "(unknown)");
      break;
    }
  return (s);
}

u8 *
format_cnat_snat_prefix (u8 *s, va_list *args)
{
  clib_bihash_kv_24_8_t *kv = va_arg (*args, clib_bihash_kv_24_8_t *);
  CLIB_UNUSED (int verbose) = va_arg (*args, int);
  u32 af = kv->key[2] >> 32;
  u32 len = kv->key[2] & 0xffffffff;
  if (AF_IP4 == af)
    s = format (s, "%U/%d", format_ip4_address, &kv->key[0], len);
  else
    s = format (s, "%U/%d", format_ip6_address, &kv->key[0], len);
  return (s);
}

static void
cnat_compute_prefix_lengths_in_search_order (
  cnat_snat_exclude_pfx_table_t *table, ip_address_family_t af)
{
  int i;
  vec_reset_length (table->meta[af].prefix_lengths_in_search_order);
  /* Note: bitmap reversed so this is in fact a longest prefix match */
  clib_bitmap_foreach (i, table->meta[af].non_empty_dst_address_length_bitmap)
    {
      int dst_address_length = 128 - i;
      vec_add1 (table->meta[af].prefix_lengths_in_search_order,
		dst_address_length);
    }
}

int
cnat_snat_policy_add_del_if (u32 sw_if_index, u8 is_add,
			     cnat_snat_interface_map_type_t table)
{
  cnat_snat_policy_main_t *cpm = &cnat_snat_policy_main;

  if (table >= ARRAY_LEN (cpm->interface_maps))
    return VNET_API_ERROR_INVALID_VALUE;

  clib_bitmap_t **map = &cpm->interface_maps[table];

  *map = clib_bitmap_set (*map, sw_if_index, is_add);
  return 0;
}

static clib_error_t *
cnat_snat_policy_add_del_if_command_fn (vlib_main_t *vm,
					unformat_input_t *input,
					vlib_cli_command_t *cmd)
{
  vnet_main_t *vnm = vnet_get_main ();
  int is_add = 1;
  u32 sw_if_index = ~0;
  cnat_snat_interface_map_type_t table = CNAT_SNAT_IF_MAP_INCLUDE_V4;
  int rv;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "del"))
	is_add = 0;
      else if (unformat (input, "table %U",
			 unformat_cnat_snat_interface_map_type, &table))
	;
      else if (unformat (input, "%U", unformat_vnet_sw_interface, vnm,
			 &sw_if_index))
	;
      else
	return clib_error_return (0, "unknown input '%U'",
				  format_unformat_error, input);
    }

  if (sw_if_index == ~0)
    return clib_error_return (0, "Interface not specified");

  rv = cnat_snat_policy_add_del_if (sw_if_index, is_add, table);

  if (rv)
    return clib_error_return (0, "Error %d", rv);

  return NULL;
}

VLIB_CLI_COMMAND (cnat_snat_policy_add_del_if_command, static) = {
  .path = "set cnat snat-policy if",
  .short_help = "set cnat snat-policy if [del]"
		"[table [include-v4 include-v6 k8s]] [interface]",
  .function = cnat_snat_policy_add_del_if_command_fn,
};

int
cnat_snat_policy_add_pfx (ip_prefix_t *pfx)
{
  /* All packets destined to this prefix won't be source-NAT-ed */
  cnat_snat_exclude_pfx_table_t *table = &cnat_snat_policy_main.excluded_pfx;
  clib_bihash_kv_24_8_t kv;
  ip6_address_t *mask;
  u64 af = ip_prefix_version (pfx);
  ;

  mask = &table->ip_masks[pfx->len];
  if (AF_IP4 == af)
    {
      kv.key[0] = (u64) ip_prefix_v4 (pfx).as_u32 & mask->as_u64[0];
      kv.key[1] = 0;
    }
  else
    {
      kv.key[0] = ip_prefix_v6 (pfx).as_u64[0] & mask->as_u64[0];
      kv.key[1] = ip_prefix_v6 (pfx).as_u64[1] & mask->as_u64[1];
    }
  kv.key[2] = ((u64) af << 32) | pfx->len;
  clib_bihash_add_del_24_8 (&table->ip_hash, &kv, 1 /* is_add */);

  table->meta[af].dst_address_length_refcounts[pfx->len]++;
  table->meta[af].non_empty_dst_address_length_bitmap = clib_bitmap_set (
    table->meta[af].non_empty_dst_address_length_bitmap, 128 - pfx->len, 1);
  cnat_compute_prefix_lengths_in_search_order (table, af);
  return 0;
}

int
cnat_snat_policy_del_pfx (ip_prefix_t *pfx)
{
  cnat_snat_exclude_pfx_table_t *table = &cnat_snat_policy_main.excluded_pfx;
  clib_bihash_kv_24_8_t kv, val;
  ip6_address_t *mask;
  u64 af = ip_prefix_version (pfx);
  ;

  mask = &table->ip_masks[pfx->len];
  if (AF_IP4 == af)
    {
      kv.key[0] = (u64) ip_prefix_v4 (pfx).as_u32 & mask->as_u64[0];
      kv.key[1] = 0;
    }
  else
    {
      kv.key[0] = ip_prefix_v6 (pfx).as_u64[0] & mask->as_u64[0];
      kv.key[1] = ip_prefix_v6 (pfx).as_u64[1] & mask->as_u64[1];
    }
  kv.key[2] = ((u64) af << 32) | pfx->len;

  if (clib_bihash_search_24_8 (&table->ip_hash, &kv, &val))
    {
      return 1;
    }
  clib_bihash_add_del_24_8 (&table->ip_hash, &kv, 0 /* is_add */);
  /* refcount accounting */
  ASSERT (table->meta[af].dst_address_length_refcounts[pfx->len] > 0);
  if (--table->meta[af].dst_address_length_refcounts[pfx->len] == 0)
    {
      table->meta[af].non_empty_dst_address_length_bitmap =
	clib_bitmap_set (table->meta[af].non_empty_dst_address_length_bitmap,
			 128 - pfx->len, 0);
      cnat_compute_prefix_lengths_in_search_order (table, af);
    }
  return 0;
}

int
cnat_search_snat_prefix (ip46_address_t *addr, ip_address_family_t af)
{
  /* Returns 0 if addr matches any of the listed prefixes */
  cnat_snat_exclude_pfx_table_t *table = &cnat_snat_policy_main.excluded_pfx;
  clib_bihash_kv_24_8_t kv, val;
  int i, n_p, rv;
  n_p = vec_len (table->meta[af].prefix_lengths_in_search_order);
  if (AF_IP4 == af)
    {
      kv.key[0] = addr->ip4.as_u32;
      kv.key[1] = 0;
    }
  else
    {
      kv.key[0] = addr->as_u64[0];
      kv.key[1] = addr->as_u64[1];
    }

  /*
   * start search from a mask length same length or shorter.
   * we don't want matches longer than the mask passed
   */
  i = 0;
  for (; i < n_p; i++)
    {
      int dst_address_length =
	table->meta[af].prefix_lengths_in_search_order[i];
      ip6_address_t *mask = &table->ip_masks[dst_address_length];

      ASSERT (dst_address_length >= 0 && dst_address_length <= 128);
      /* As lengths are decreasing, masks are increasingly specific. */
      kv.key[0] &= mask->as_u64[0];
      kv.key[1] &= mask->as_u64[1];
      kv.key[2] = ((u64) af << 32) | dst_address_length;
      rv = clib_bihash_search_inline_2_24_8 (&table->ip_hash, &kv, &val);
      if (rv == 0)
	return 0;
    }
  return -1;
}

static_always_inline int
cnat_snat_policy_interface_enabled (u32 sw_if_index, ip_address_family_t af)
{
  cnat_snat_policy_main_t *cpm = &cnat_snat_policy_main;
  return clib_bitmap_get (cpm->interface_maps[af], sw_if_index);
}

int
cnat_snat_policy_none (vlib_buffer_t *b, ip_address_family_t af, ip4_header_t *ip4,
		       ip6_header_t *ip6, ip_protocol_t iproto, udp_header_t *udp0)
{
  /* srcNAT everything by default */
  return 1;
}

int
cnat_snat_policy_if_pfx (vlib_buffer_t *b, ip_address_family_t af, ip4_header_t *ip4,
			 ip6_header_t *ip6, ip_protocol_t iproto, udp_header_t *udp0)
{
  ip46_address_t dst_addr = { 0 };
  u32 in_if = vnet_buffer (b)->sw_if_index[VLIB_RX];

  if (af == AF_IP4)
    ip46_address_set_ip4 (&dst_addr, &ip4->dst_address);
  else
    ip46_address_set_ip6 (&dst_addr, &ip6->dst_address);

  /* source nat for outgoing connections */
  if (cnat_snat_policy_interface_enabled (in_if, af))
    if (cnat_search_snat_prefix (&dst_addr, af))
      /* Destination is not in the prefixes that don't require snat */
      return 1;
  return 0;
}

int
cnat_snat_policy_k8s (vlib_buffer_t *b, ip_address_family_t af, ip4_header_t *ip4,
		      ip6_header_t *ip6, ip_protocol_t iproto, udp_header_t *udp0)
{
  cnat_snat_policy_main_t *cpm = &cnat_snat_policy_main;
  ip46_address_t dst_addr = { 0 }, src_addr = { 0 };
  u32 in_if = vnet_buffer (b)->sw_if_index[VLIB_RX];
  u32 out_if = vnet_buffer (b)->sw_if_index[VLIB_TX];

  /* we should never snat traffic that we punt to the host, pass traffic as it
   * is for us */
  if (clib_bitmap_get (cpm->interface_maps[CNAT_SNAT_IF_MAP_INCLUDE_HOST],
		       out_if))
    {
      return 0;
    }

  if (af == AF_IP4)
    {
      ip46_address_set_ip4 (&src_addr, &ip4->src_address);
      ip46_address_set_ip4 (&dst_addr, &ip4->dst_address);
    }
  else
    {
      ip46_address_set_ip6 (&src_addr, &ip6->src_address);
      ip46_address_set_ip6 (&dst_addr, &ip6->dst_address);
    }

  /* source nat for outgoing connections */
  if (cnat_snat_policy_interface_enabled (in_if, af))
    if (cnat_search_snat_prefix (&dst_addr, af))
      /* Destination is not in the prefixes that don't require snat */
      return 1;

  /* source nat for translations that come from the outside:
     src not not a pod interface, dst not a pod interface */
  if (!clib_bitmap_get (cpm->interface_maps[CNAT_SNAT_IF_MAP_INCLUDE_POD],
			in_if) &&
      !clib_bitmap_get (cpm->interface_maps[CNAT_SNAT_IF_MAP_INCLUDE_POD],
			out_if))
    {
      if (AF_IP6 == af && ip6_address_is_equal (&src_addr.ip6, &ip_addr_v6 (&cpm->snat_ip6.ce_ip)))
	return 0;
      if (AF_IP4 == af && ip4_address_is_equal (&src_addr.ip4, &ip_addr_v4 (&cpm->snat_ip4.ce_ip)))
	return 0;
      return 1;
    }

  /* handle the case where a container is connecting to itself via a service */
  if (ip46_address_is_equal (&src_addr, &dst_addr))
    return 1;

  return 0;
}

__clib_export void
cnat_set_snat (ip4_address_t *ip4, ip6_address_t *ip6, u32 sw_if_index)
{
  cnat_snat_policy_main_t *cpm = &cnat_snat_policy_main;

  cnat_lazy_init ();

  cnat_translation_unwatch_addr (INDEX_INVALID, CNAT_RESOLV_ADDR_SNAT);

  ip_address_set (&cpm->snat_ip4.ce_ip, ip4, AF_IP4);
  ip_address_set (&cpm->snat_ip6.ce_ip, ip6, AF_IP6);
  cpm->snat_ip4.ce_sw_if_index = sw_if_index;
  cpm->snat_ip6.ce_sw_if_index = sw_if_index;

  cnat_resolve_ep (&cpm->snat_ip4);
  cnat_resolve_ep (&cpm->snat_ip6);
  cnat_translation_watch_addr (INDEX_INVALID, 0, &cpm->snat_ip4,
			       CNAT_RESOLV_ADDR_SNAT);
  cnat_translation_watch_addr (INDEX_INVALID, 0, &cpm->snat_ip6,
			       CNAT_RESOLV_ADDR_SNAT);
}

static clib_error_t *
cnat_set_snat_cli (vlib_main_t *vm, unformat_input_t *input,
		   vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  vnet_main_t *vnm = vnet_get_main ();
  ip4_address_t ip4 = { { 0 } };
  ip6_address_t ip6 = { { 0 } };
  clib_error_t *e = 0;
  u32 sw_if_index = INDEX_INVALID;

  cnat_lazy_init ();

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat_user (line_input, unformat_ip4_address, &ip4))
	;
      else if (unformat_user (line_input, unformat_ip6_address, &ip6))
	;
      else if (unformat_user (line_input, unformat_vnet_sw_interface, vnm,
			      &sw_if_index))
	;
      else
	{
	  e = clib_error_return (0, "unknown input '%U'",
				 format_unformat_error, input);
	  goto done;
	}
    }

  cnat_set_snat (&ip4, &ip6, sw_if_index);

done:
  unformat_free (line_input);

  return (e);
}

VLIB_CLI_COMMAND (cnat_set_snat_command, static) = {
  .path = "set cnat snat-policy addr",
  .short_help =
    "set cnat snat-policy addr [<ip4-address>][<ip6-address>][sw_if_index]",
  .function = cnat_set_snat_cli,
};

static clib_error_t *
cnat_snat_policy_add_del_pfx_command_fn (vlib_main_t *vm,
					 unformat_input_t *input,
					 vlib_cli_command_t *cmd)
{
  ip_prefix_t pfx;
  u8 is_add = 1;
  int rv;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%U", unformat_ip_prefix, &pfx))
	;
      else if (unformat (input, "del"))
	is_add = 0;
      else
	return (clib_error_return (0, "unknown input '%U'",
				   format_unformat_error, input));
    }

  if (is_add)
    rv = cnat_snat_policy_add_pfx (&pfx);
  else
    rv = cnat_snat_policy_del_pfx (&pfx);

  if (rv)
    return (clib_error_return (0, "error %d", rv, input));

  return (NULL);
}

VLIB_CLI_COMMAND (cnat_snat_policy_add_del_pfx_command, static) = {
  .path = "set cnat snat-policy prefix",
  .short_help = "set cnat snat-policy prefix [del] [prefix]",
  .function = cnat_snat_policy_add_del_pfx_command_fn,
};

static clib_error_t *
cnat_show_snat (vlib_main_t *vm, unformat_input_t *input,
		vlib_cli_command_t *cmd)
{
  cnat_snat_exclude_pfx_table_t *excluded_pfx =
    &cnat_snat_policy_main.excluded_pfx;
  cnat_snat_policy_main_t *cpm = &cnat_snat_policy_main;
  vnet_main_t *vnm = vnet_get_main ();
  u32 sw_if_index;

  vlib_cli_output (vm, "Source NAT\n  ip4: %U\n  ip6: %U\n\n",
		   format_cnat_endpoint, &cpm->snat_ip4, format_cnat_endpoint,
		   &cpm->snat_ip6);
  vlib_cli_output (vm, "Excluded prefixes:\n  %U\n", format_bihash_24_8,
		   &excluded_pfx->ip_hash, 1);

  for (int i = 0; i < CNAT_N_SNAT_IF_MAP; i++)
    {
      vlib_cli_output (vm, "\n%U interfaces:\n",
		       format_cnat_snat_interface_map_type, i);
      clib_bitmap_foreach (sw_if_index, cpm->interface_maps[i])
	vlib_cli_output (vm, "  %U\n", format_vnet_sw_if_index_name, vnm,
			 sw_if_index);
    }

  return (NULL);
}

VLIB_CLI_COMMAND (cnat_show_snat_command, static) = {
  .path = "show cnat snat-policy",
  .short_help = "show cnat snat-policy",
  .function = cnat_show_snat,
};

int
cnat_set_snat_policy (cnat_snat_policy_type_t policy)
{
  cnat_snat_policy_main_t *cpm = &cnat_snat_policy_main;
  switch (policy)
    {
    case CNAT_SNAT_POLICY_NONE:
      cpm->snat_policy = cnat_snat_policy_none;
      break;
    case CNAT_SNAT_POLICY_IF_PFX:
      cpm->snat_policy = cnat_snat_policy_if_pfx;
      break;
    case CNAT_SNAT_POLICY_K8S:
      cpm->snat_policy = cnat_snat_policy_k8s;
      break;
    default:
      return 1;
    }
  return 0;
}

static clib_error_t *
cnat_snat_policy_set_cmd_fn (vlib_main_t *vm, unformat_input_t *input,
			     vlib_cli_command_t *cmd)
{
  cnat_snat_policy_type_t policy = CNAT_SNAT_POLICY_NONE;
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "none"))
	;
      else if (unformat (input, "if-pfx"))
	policy = CNAT_SNAT_POLICY_IF_PFX;
      else if (unformat (input, "k8s"))
	policy = CNAT_SNAT_POLICY_K8S;
      else
	return clib_error_return (0, "unknown input '%U'",
				  format_unformat_error, input);
    }

  cnat_set_snat_policy (policy);
  return NULL;
}

VLIB_CLI_COMMAND (cnat_snat_policy_set_cmd, static) = {
  .path = "set cnat snat-policy",
  .short_help = "set cnat snat-policy [none][if-pfx][k8s]",
  .function = cnat_snat_policy_set_cmd_fn,
};

static void
cnat_if_addr_add_del_snat_cb (addr_resolution_t *ar, ip_address_t *address,
			      u8 is_del)
{
  cnat_snat_policy_main_t *cpm = &cnat_snat_policy_main;
  cnat_endpoint_t *ep;

  ep = AF_IP4 == ar->af ? &cpm->snat_ip4 : &cpm->snat_ip6;

  if (!is_del && ep->ce_flags & CNAT_EP_FLAG_RESOLVED)
    return;

  if (is_del)
    {
      ep->ce_flags &= ~CNAT_EP_FLAG_RESOLVED;
      /* Are there remaining addresses ? */
      if (0 == cnat_resolve_addr (ar->sw_if_index, ar->af, address))
	is_del = 0;
    }

  if (!is_del)
    {
      ip_address_copy (&ep->ce_ip, address);
      ep->ce_flags |= CNAT_EP_FLAG_RESOLVED;
    }
}

static clib_error_t *
cnat_snat_init (vlib_main_t *vm)
{
  cnat_snat_policy_main_t *cpm = &cnat_snat_policy_main;
  cnat_main_t *cm = &cnat_main;
  cnat_snat_exclude_pfx_table_t *excluded_pfx = &cpm->excluded_pfx;

  int i;
  for (i = 0; i < ARRAY_LEN (excluded_pfx->ip_masks); i++)
    {
      u32 j, i0, i1;

      i0 = i / 32;
      i1 = i % 32;

      for (j = 0; j < i0; j++)
	excluded_pfx->ip_masks[i].as_u32[j] = ~0;

      if (i1)
	excluded_pfx->ip_masks[i].as_u32[i0] =
	  clib_host_to_net_u32 (pow2_mask (i1) << (32 - i1));
    }
  clib_bihash_init_24_8 (&excluded_pfx->ip_hash, "snat prefixes",
			 cm->snat_hash_buckets, cm->snat_hash_memory);
  clib_bihash_set_kvp_format_fn_24_8 (&excluded_pfx->ip_hash,
				      format_cnat_snat_prefix);

  for (int i = 0; i < CNAT_N_SNAT_IF_MAP; i++)
    clib_bitmap_validate (cpm->interface_maps[i], cm->snat_if_map_length);

  cnat_translation_register_addr_add_cb (CNAT_RESOLV_ADDR_SNAT,
					 cnat_if_addr_add_del_snat_cb);

  cpm->snat_policy = cnat_snat_policy_none;

  return (NULL);
}

VLIB_INIT_FUNCTION (cnat_snat_init);
