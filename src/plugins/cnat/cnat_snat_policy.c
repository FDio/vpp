/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2020 Cisco and/or its affiliates.
 */

#include <vnet/ip/ip.h>
#include <cnat/cnat_snat_policy.h>
#include <cnat/cnat_translation.h>
#include <cnat/cnat_src_policy.h>

cnat_snat_policy_main_t cnat_snat_policy_main;

__clib_export cnat_snat_policy_entry_t *
cnat_snat_policy_entry_get (ip_address_family_t af, u32 fwd_fib_index)
{
  return cnat_snat_policy_entry_get__ (af, fwd_fib_index);
}

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
  u8 is_src = kv->key[2] >> 63;
  u32 af = (kv->key[2] >> 32) & 0x7fffffff;
  u32 len = kv->key[2] & 0xffffffff;
  if (AF_IP4 == af)
    s = format (s, "%U/%d", format_ip4_address, &kv->key[0], len);
  else
    s = format (s, "%U/%d", format_ip6_address, &kv->key[0], len);
  s = format (s, " %s", is_src ? "src" : "dst");
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

cnat_snat_policy_entry_t *
cnat_snat_policy_entry_get_default (void)
{
  cnat_snat_policy_entry_t *cpe = cnat_snat_policy_entry_get (AF_IP4, CNAT_FIB_TABLE);
  if (!cpe)
    cpe = cnat_snat_policy_entry_get (AF_IP6, CNAT_FIB_TABLE);
  return cpe;
}

static int
cnat_snat_policy_entry_is_init (const cnat_snat_policy_entry_t *cpe)
{
  return vec_len (cpe->interface_maps[0]) != 0;
}

static void
cnat_snat_policy_entry_init (cnat_snat_policy_entry_t *cpe)
{
  cnat_main_t *cm = &cnat_main;
  cnat_snat_exclude_pfx_table_t *excluded_pfx = &cpe->excluded_pfx;

  if (cnat_snat_policy_entry_is_init (cpe))
    return; /* already initialized */

  int i;
  for (i = 0; i < ARRAY_LEN (excluded_pfx->ip_masks); i++)
    {
      u32 j, i0, i1;

      i0 = i / 32;
      i1 = i % 32;

      for (j = 0; j < i0; j++)
	excluded_pfx->ip_masks[i].as_u32[j] = ~0;

      if (i1)
	excluded_pfx->ip_masks[i].as_u32[i0] = clib_host_to_net_u32 (pow2_mask (i1) << (32 - i1));
    }
  clib_bihash_init_24_8 (&excluded_pfx->ip_hash, "snat prefixes", cm->snat_hash_buckets,
			 cm->snat_hash_memory);
  clib_bihash_set_kvp_format_fn_24_8 (&excluded_pfx->ip_hash, format_cnat_snat_prefix);

  for (int i = 0; i < CNAT_N_SNAT_IF_MAP; i++)
    clib_bitmap_validate (cpe->interface_maps[i], cm->snat_if_map_length);
}

__clib_export void
cnat_snat_policy_entry_cleanup (cnat_snat_policy_entry_t *cpe)
{
  if (cnat_snat_policy_entry_is_init (cpe))
    {
      cnat_snat_exclude_pfx_table_t *excluded_pfx = &cpe->excluded_pfx;
      clib_bihash_free_24_8 (&excluded_pfx->ip_hash);
      for (int i = 0; i < CNAT_N_SNAT_IF_MAP; i++)
	clib_bitmap_free (cpe->interface_maps[i]);
    }
}

int
cnat_snat_policy_add_del_if (u32 sw_if_index, u8 is_add,
			     cnat_snat_interface_map_type_t table)
{
  cnat_snat_policy_entry_t *cpe;

  if (table >= ARRAY_LEN (cpe->interface_maps))
    return VNET_API_ERROR_INVALID_VALUE;

  cpe = cnat_snat_policy_entry_get_default ();
  if (!cpe)
    return VNET_API_ERROR_FEATURE_DISABLED;

  if (!is_add && !cnat_snat_policy_entry_is_init (cpe))
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  cnat_snat_policy_entry_init (cpe);

  clib_bitmap_t **map = &cpe->interface_maps[table];

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

static_always_inline void
cnat_search_snat_prefix_mkkey__ (clib_bihash_kv_24_8_t *kv, ip_address_family_t af,
				 const void *addr)
{
  if (AF_IP4 == af)
    {
      kv->key[0] = ((const ip4_address_t *) addr)->as_u32;
      kv->key[1] = 0;
    }
  else
    {
      kv->key[0] = ((const ip6_address_t *) addr)->as_u64[0];
      kv->key[1] = ((const ip6_address_t *) addr)->as_u64[1];
    }
  kv->key[2] = 0;
  kv->value = 0xdeadbeef;
}

static void
cnat_search_snat_prefix_mkkey (clib_bihash_kv_24_8_t *kv, const ip_prefix_t *pfx, u8 is_src)
{
  ip_address_family_t af = ip_prefix_version (pfx);
  cnat_search_snat_prefix_mkkey__ (kv, ip_prefix_version (pfx),
				   AF_IP4 == af ? (void *) &ip_prefix_v4 (pfx) :
						  (void *) &ip_prefix_v6 (pfx));
  kv->key[2] = ((u64) is_src << 63) | ((u64) af << 32) | pfx->len;
}

/* Returns 0 if addr matches any of the listed prefixes */
static_always_inline int
cnat_search_snat_prefix__ (cnat_snat_policy_entry_t *cpe, ip_address_family_t af,
			   clib_bihash_kv_24_8_t *kv, u8 is_src)
{
  ASSERT (cpe);
  if (!cnat_snat_policy_entry_is_init (cpe))
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  cnat_snat_exclude_pfx_table_t *table = &cpe->excluded_pfx;
  /* start search from a mask length same length or shorter.
   * we don't want matches longer than the mask passed */
  const u16 *plen;
  vec_foreach (plen, table->meta[af].prefix_lengths_in_search_order)
    {
      ASSERT (*plen >= 0 && *plen <= 128);
      const ip6_address_t *mask = &table->ip_masks[*plen];

      /* As lengths are decreasing, masks are increasingly specific. */
      kv->key[0] &= mask->as_u64[0];
      kv->key[1] &= mask->as_u64[1];
      kv->key[2] = ((u64) is_src << 63) | ((u64) af << 32) | *plen;
      int rv = clib_bihash_search_inline_2_24_8 (&table->ip_hash, kv, kv);
      if (rv == 0)
	return 0;
    }

  return -1; /* not found */
}

static int
cnat_search_snat_prefix (cnat_snat_policy_entry_t *cpe, ip_address_family_t af,
			 const cnat_5tuple_t *tuple)
{
  clib_bihash_kv_24_8_t kv;
  cnat_search_snat_prefix_mkkey__ (
    &kv, af, af == AF_IP4 ? (void *) &tuple->ip[VLIB_TX].ip4 : (void *) &tuple->ip[VLIB_TX].ip6);
  return cnat_search_snat_prefix__ (cpe, af, &kv, 0 /* is_src */);
}

static_always_inline int
cnat_snat_policy_interface_enabled (u32 sw_if_index, ip_address_family_t af)
{
  const cnat_snat_policy_entry_t *cpe = cnat_snat_policy_entry_get_default ();
  if (!cpe || !cnat_snat_policy_entry_is_init (cpe))
    return 0;
  return clib_bitmap_get (cpe->interface_maps[af], sw_if_index);
}

cnat_snat_policy_action_t
cnat_snat_policy_none (cnat_5tuple_t *tuple, cnat_snat_policy_entry_t *cpe, const vlib_buffer_t *b,
		       ip_address_family_t af)
{
  /* srcNAT everything by default */
  return CNAT_SNAT_POLICY_ACTION_SNAT_ALLOC;
}

cnat_snat_policy_action_t
cnat_snat_policy_if_pfx (cnat_5tuple_t *tuple, cnat_snat_policy_entry_t *cpe,
			 const vlib_buffer_t *b, ip_address_family_t af)
{
  u32 in_if = vnet_buffer (b)->sw_if_index[VLIB_RX];
  /* source nat for outgoing connections */
  if (cnat_snat_policy_interface_enabled (in_if, af))
    {
      if (cnat_search_snat_prefix (cpe, af, tuple))
	/* Destination is not in the prefixes that don't require snat */
	return CNAT_SNAT_POLICY_ACTION_SNAT_ALLOC;
    }
  return CNAT_SNAT_POLICY_ACTION_NOOP;
}

cnat_snat_policy_action_t
cnat_snat_policy_k8s (cnat_5tuple_t *tuple, cnat_snat_policy_entry_t *cpe, const vlib_buffer_t *b,
		      ip_address_family_t af)
{
  ASSERT (cpe);

  u32 in_if = vnet_buffer (b)->sw_if_index[VLIB_RX];
  u32 out_if = vnet_buffer (b)->sw_if_index[VLIB_TX];

  /* we should never snat traffic that we punt to the host, pass traffic as it
   * is for us */
  if (clib_bitmap_get (cpe->interface_maps[CNAT_SNAT_IF_MAP_INCLUDE_HOST], out_if))
    {
      return CNAT_SNAT_POLICY_ACTION_NOOP;
    }

  /* source nat for outgoing connections */
  if (cnat_snat_policy_interface_enabled (in_if, af))
    {
      if (cnat_search_snat_prefix (cpe, af, tuple))
	/* Destination is not in the prefixes that don't require snat */
	return CNAT_SNAT_POLICY_ACTION_SNAT_ALLOC;
    }

  /* source nat for translations that come from the outside:
     src not not a pod interface, dst not a pod interface */
  if (!clib_bitmap_get (cpe->interface_maps[CNAT_SNAT_IF_MAP_INCLUDE_POD], in_if) &&
      !clib_bitmap_get (cpe->interface_maps[CNAT_SNAT_IF_MAP_INCLUDE_POD], out_if))
    {
      if (AF_IP6 == af &&
	  ip6_address_is_equal (&tuple->ip[VLIB_RX].ip6, &ip_addr_v6 (&cpe->snat_ip6.ce_ip)))
	return CNAT_SNAT_POLICY_ACTION_NOOP;
      if (AF_IP4 == af &&
	  ip4_address_is_equal (&tuple->ip[VLIB_RX].ip4, &ip_addr_v4 (&cpe->snat_ip4.ce_ip)))
	return CNAT_SNAT_POLICY_ACTION_NOOP;
      return CNAT_SNAT_POLICY_ACTION_SNAT_ALLOC;
    }

  /* handle the case where a container is connecting to itself via a service */
  if ((AF_IP6 == af && ip6_address_is_equal (&tuple->ip[VLIB_RX].ip6, &tuple->ip[VLIB_TX].ip6)) ||
      ip4_address_is_equal (&tuple->ip[VLIB_RX].ip4, &tuple->ip[VLIB_TX].ip4))
    return CNAT_SNAT_POLICY_ACTION_SNAT_ALLOC;

  return CNAT_SNAT_POLICY_ACTION_NOOP;
}

static_always_inline int
cnat_snat_policy_dnat_rewrite (cnat_snat_policy_entry_t *cpe, ip_address_family_t af,
			       const void *addr, u8 is_src)
{
  clib_bihash_kv_24_8_t kv;
  /* check if we have a destination rewrite for the destination address */
  cnat_search_snat_prefix_mkkey__ (&kv, af, addr);
  if (cnat_search_snat_prefix__ (cpe, af, &kv, is_src))
    return 0; /* not found */

  /* found: rewrite address */

  u8 plen = kv.key[2];
  if (AF_IP4 == af)
    {
      ASSERT (plen <= 32);
      u32 mask = plen == 32 ? 0 : clib_host_to_net_u32 (((u32) 1 << (32 - plen)) - 1);
      *(u32 *) addr = kv.value | (*(u32 *) addr & mask);
    }
  else
    {
      plen -= 64;
      ASSERT (plen <= 64);
      u64 mask = plen == 64 ? 0 : clib_host_to_net_u64 (((u64) 1 << (64 - plen)) - 1);
      *(u64 *) addr = kv.value | (*(u64 *) addr & mask);
    }

  return 1;
}

static_always_inline cnat_snat_policy_action_t
cnat_snat_policy_dnat__ (cnat_5tuple_t *tuple, cnat_snat_policy_entry_t *cpe,
			 const vlib_buffer_t *b, ip_address_family_t af,
			 cnat_snat_policy_action_t default_action)
{
  /* rewrite destination address if needed */
  cnat_snat_policy_dnat_rewrite (
    cpe, af, af == AF_IP4 ? (void *) &tuple->ip[VLIB_TX].ip4 : (void *) &tuple->ip[VLIB_TX].ip6,
    0 /* is_src */);

  /* check if we need to rewrite the source address */
  if (cnat_snat_policy_dnat_rewrite (
	cpe, af, af == AF_IP4 ? (void *) &tuple->ip[VLIB_RX].ip4 : (void *) &tuple->ip[VLIB_RX].ip6,
	1 /* is_src */))
    return CNAT_SNAT_POLICY_ACTION_SNAT_KEEP; /* src rewrite done */

  /* no source rewrite, so we need to allocate a new source address */
  return default_action;
}

cnat_snat_policy_action_t
cnat_snat_policy_dnat (cnat_5tuple_t *tuple, cnat_snat_policy_entry_t *cpe, const vlib_buffer_t *b,
		       ip_address_family_t af)
{
  return cnat_snat_policy_dnat__ (tuple, cpe, b, af, CNAT_SNAT_POLICY_ACTION_SNAT_ALLOC);
}

cnat_snat_policy_action_t
cnat_snat_policy_dnat_only (cnat_5tuple_t *tuple, cnat_snat_policy_entry_t *cpe,
			    const vlib_buffer_t *b, ip_address_family_t af)
{
  return cnat_snat_policy_dnat__ (tuple, cpe, b, af, CNAT_SNAT_POLICY_ACTION_SNAT_KEEP);
}

__clib_export int
cnat_snat_policy_add_pfx (cnat_snat_policy_entry_t *cpe, ip_prefix_t *pfx, const ip_address_t *rw,
			  u8 is_src)
{
  /* All packets destined to this prefix won't be source-NAT-ed */
  ASSERT (cpe);

  cnat_snat_policy_entry_init (cpe);

  cnat_snat_exclude_pfx_table_t *table = &cpe->excluded_pfx;
  ip_address_family_t af = ip_prefix_version (pfx);
  clib_bihash_kv_24_8_t kv;

  ip_prefix_normalize (pfx);
  cnat_search_snat_prefix_mkkey (&kv, pfx, is_src);
  if (rw)
    kv.value = AF_IP4 == af ? ip_addr_v4 (rw).as_u32 : ip_addr_v6 (rw).as_u64[0];
  clib_bihash_add_del_24_8 (&table->ip_hash, &kv, 1 /* is_add */);

  table->meta[af].dst_address_length_refcounts[pfx->len]++;
  table->meta[af].non_empty_dst_address_length_bitmap =
    clib_bitmap_set (table->meta[af].non_empty_dst_address_length_bitmap, 128 - pfx->len, 1);
  cnat_compute_prefix_lengths_in_search_order (table, af);

  return 0;
}

__clib_export int
cnat_snat_policy_del_pfx (cnat_snat_policy_entry_t *cpe, ip_prefix_t *pfx, u8 is_src)
{
  ASSERT (cpe);

  if (!cnat_snat_policy_entry_is_init (cpe))
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  cnat_snat_exclude_pfx_table_t *table = &cpe->excluded_pfx;
  ip_address_family_t af = ip_prefix_version (pfx);
  clib_bihash_kv_24_8_t kv;

  ip_prefix_normalize (pfx);
  cnat_search_snat_prefix_mkkey (&kv, pfx, is_src);
  if (clib_bihash_add_del_24_8 (&table->ip_hash, &kv, 0 /* is_add */))
    return 1;

  /* refcount accounting */
  ASSERT (table->meta[af].dst_address_length_refcounts[pfx->len] > 0);
  if (--table->meta[af].dst_address_length_refcounts[pfx->len] == 0)
    {
      table->meta[af].non_empty_dst_address_length_bitmap =
	clib_bitmap_set (table->meta[af].non_empty_dst_address_length_bitmap, 128 - pfx->len, 0);
      cnat_compute_prefix_lengths_in_search_order (table, af);
    }
  return 0;
}

static void
cnat_if_addr_add_del_snat_cb (addr_resolution_t *ar, ip_address_t *address, u8 is_del)
{
  cnat_snat_policy_entry_t *cpe;
  cnat_endpoint_t *ep;
  u32 ret_fib_index;

  cpe = pool_elt_at_index (cnat_snat_policy_main.snat_policies_pool, ar->cti);
  ep = AF_IP4 == ar->af ? &cpe->snat_ip4 : &cpe->snat_ip6;
  ret_fib_index = AF_IP4 == ar->af ? cpe->ret_fib_index4 : cpe->ret_fib_index6;

  if (!is_del && ep->ce_flags & CNAT_EP_FLAG_RESOLVED)
    return;

  if (is_del)
    {
      /* remove installed client */
      if (!(cpe->flags & CNAT_SNAT_POLICY_FLAG_NO_CLIENT))
	cnat_client_free_by_ip (&ip_addr_46 (&ep->ce_ip), ret_fib_index, 0 /* is_session */);
      ep->ce_flags &= ~CNAT_EP_FLAG_RESOLVED;
      /* Are there remaining addresses ? */
      if (0 == cnat_resolve_addr (ar->sw_if_index, ar->af, address))
	is_del = 0;
    }

  if (!is_del)
    {
      ip_address_copy (&ep->ce_ip, address);
      ep->ce_flags |= CNAT_EP_FLAG_RESOLVED;
      if (!(cpe->flags & CNAT_SNAT_POLICY_FLAG_NO_CLIENT))
	cnat_client_add (&ep->ce_ip, ret_fib_index, CNAT_TR_FLAG_EXCLUSIVE);
    }
}

static void
cnat_snat_cleanup (cnat_snat_policy_main_t *cpm, cnat_snat_policy_entry_t *cpe, u32 fwd_fib_index)
{
  u32 index = cpe - cpm->snat_policies_pool;

  if (!(cpe->flags & CNAT_SNAT_POLICY_FLAG_NO_CLIENT))
    {
      if (cpe->snat_ip4.ce_flags & CNAT_EP_FLAG_RESOLVED)
	cnat_client_free_by_ip (&ip_addr_46 (&cpe->snat_ip4.ce_ip), cpe->ret_fib_index4,
				0 /* is_session */);
      if (cpe->snat_ip6.ce_flags & CNAT_EP_FLAG_RESOLVED)
	cnat_client_free_by_ip (&ip_addr_46 (&cpe->snat_ip6.ce_ip), cpe->ret_fib_index6,
				0 /* is_session */);
    }

  if (fwd_fib_index < vec_len (cpm->snat_policy_per_fwd_fib_index4))
    vec_elt (cpm->snat_policy_per_fwd_fib_index4, fwd_fib_index) = ~0;
  if (fwd_fib_index < vec_len (cpm->snat_policy_per_fwd_fib_index6))
    vec_elt (cpm->snat_policy_per_fwd_fib_index6, fwd_fib_index) = ~0;

  cnat_snat_policy_entry_cleanup (cpe);
  cnat_free_port_allocator (fwd_fib_index);

  pool_put_index (cpm->snat_policies_pool, index);
}

__clib_export int
cnat_set_snat (u32 fwd_fib_index, u32 ret_fib_index, const ip4_address_t *ip4, u8 ip4_pfx_len,
	       const ip6_address_t *ip6, u8 ip6_pfx_len, u32 sw_if_index,
	       cnat_snat_policy_flags_t flags)
{
  cnat_snat_policy_main_t *cpm = &cnat_snat_policy_main;
  cnat_timestamp_mpool_t *ctm = &cnat_timestamps;
  cnat_snat_policy_entry_t *cpe4, *cpe6, *cpe;
  u32 index;
  int sw_if_set = sw_if_index != INDEX_INVALID;
  int ip4_set = ip4 && ip4->as_u32 != 0;
  int ip6_set = ip6 && !ip6_address_is_zero (ip6);
  int is_delete = !sw_if_set && !ip4_set && !ip6_set;

  if ((ip4_set && ip4_pfx_len > 32) || (ip6_set && (ip6_pfx_len < 64 || ip6_pfx_len > 128)))
    return VNET_API_ERROR_INVALID_VALUE;

  cnat_lazy_init ();

  /* we can either:
   *  - update only ip4
   *  - update only ip6
   *  - update both ip4 & ip4 or sw_if_index */
  cpe4 = cnat_snat_policy_entry_get (AF_IP4, fwd_fib_index);
  cpe6 = cnat_snat_policy_entry_get (AF_IP6, fwd_fib_index);
  ASSERT (cpe4 == cpe6 || (!sw_if_set && !(ip4_set && ip6_set)));
  cpe = cpe4 ? cpe4 : cpe6;

  if (cpe)
    {
      /* entry found */
      index = cpe - cpm->snat_policies_pool;
      /* if the interface is changed, unwatch it (note: also works for delete)
       */
      if (cpe->snat_ip4.ce_sw_if_index != sw_if_index)
	cnat_translation_unwatch_addr (index, CNAT_RESOLV_ADDR_SNAT);
      if (is_delete)
	{
	  cnat_snat_cleanup (cpm, cpe, fwd_fib_index);
	  return 0;
	}
    }
  else
    {
      /* not found: create new entry */
      if (is_delete)
	return VNET_API_ERROR_FEATURE_DISABLED;
      pool_get_zero (cpm->snat_policies_pool, cpe);
      cnat_translation_register_addr_add_cb (CNAT_RESOLV_ADDR_SNAT, cnat_if_addr_add_del_snat_cb);
      cpe->snat_policy = cnat_snat_policy_none;
      cnat_init_port_allocator (fwd_fib_index);
      cpe->flags = flags;
      index = cpe - cpm->snat_policies_pool;
    }

  if (sw_if_set || ip4_set)
    {
      cpe->snat_ip4.ce_sw_if_index = sw_if_index;
      cpe->fwd_fib_index4 = fwd_fib_index;
      cpe->ret_fib_index4 = ret_fib_index;
      vec_validate_init_empty_aligned (cpm->snat_policy_per_fwd_fib_index4, fwd_fib_index,
				       INDEX_INVALID, CLIB_CACHE_LINE_BYTES);
      vec_elt (cpm->snat_policy_per_fwd_fib_index4, fwd_fib_index) = index;
      vec_validate_init_empty_aligned (ctm->sessions_per_vrf_ip4, fwd_fib_index,
				       ctm->max_sessions_per_vrf, CLIB_CACHE_LINE_BYTES);
      if (ip4_set)
	{
	  ip_address_set (&cpe->snat_ip4.ce_ip, ip4, AF_IP4);
	  ASSERT (32 - ip4_pfx_len >= 0 && 32 - ip4_pfx_len <= 32);
	  cpe->snat_ip4_mask = clib_host_to_net_u32 (((u32) 1 << (32 - ip4_pfx_len)) - 1);
	  ip_addr_v4 (&cpe->snat_ip4.ce_ip).as_u32 &= ~cpe->snat_ip4_mask;
	}
      else
	{
	  ip_addr_version (&cpe->snat_ip4.ce_ip) = AF_IP4;
	  cpe->snat_ip4_mask = (u32) ~0;
	}
      if (cnat_resolve_ep (&cpe->snat_ip4))
	{
	  cnat_translation_watch_addr (index, 0, &cpe->snat_ip4, CNAT_RESOLV_ADDR_SNAT);
	}
      else if (!(cpe->flags & CNAT_SNAT_POLICY_FLAG_NO_CLIENT))
	{
	  cnat_client_add_pfx (&cpe->snat_ip4.ce_ip, ip4_pfx_len, ret_fib_index,
			       ~0 /* fwd_fib_index */,
			       CNAT_TR_FLAG_EXCLUSIVE | CNAT_TR_FLAG_RETURN_ONLY);
	}
    }

  if (sw_if_set || ip6_set)
    {
      cpe->snat_ip6.ce_sw_if_index = sw_if_index;
      cpe->fwd_fib_index6 = fwd_fib_index;
      cpe->ret_fib_index6 = ret_fib_index;
      vec_validate_init_empty_aligned (cpm->snat_policy_per_fwd_fib_index6, fwd_fib_index,
				       INDEX_INVALID, CLIB_CACHE_LINE_BYTES);
      vec_elt (cpm->snat_policy_per_fwd_fib_index6, fwd_fib_index) = index;
      vec_validate_init_empty_aligned (ctm->sessions_per_vrf_ip6, fwd_fib_index,
				       ctm->max_sessions_per_vrf, CLIB_CACHE_LINE_BYTES);
      if (ip6_set)
	{
	  ip_address_set (&cpe->snat_ip6.ce_ip, ip6, AF_IP6);
	  ASSERT (128 - ip6_pfx_len >= 0 && 128 - ip6_pfx_len <= 64);
	  cpe->snat_ip6_mask = clib_host_to_net_u64 (((u64) 1 << (128 - ip6_pfx_len)) - 1);
	  ip_addr_v6 (&cpe->snat_ip6.ce_ip).as_u64[1] &= ~cpe->snat_ip6_mask;
	}
      else
	{
	  ip_addr_version (&cpe->snat_ip6.ce_ip) = AF_IP6;
	  cpe->snat_ip6_mask = (u64) ~0;
	}
      if (cnat_resolve_ep (&cpe->snat_ip6))
	{
	  cnat_translation_watch_addr (index, 0, &cpe->snat_ip6, CNAT_RESOLV_ADDR_SNAT);
	}
      else if (!(cpe->flags & CNAT_SNAT_POLICY_FLAG_NO_CLIENT))
	{
	  cnat_client_add_pfx (&cpe->snat_ip6.ce_ip, ip6_pfx_len, ret_fib_index,
			       ~0 /* fwd_fib_index */,
			       CNAT_TR_FLAG_EXCLUSIVE | CNAT_TR_FLAG_RETURN_ONLY);
	}
    }

  return 0;
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
  u32 fwd_fib_index = CNAT_FIB_TABLE;
  u32 ret_fib_index = CNAT_FIB_TABLE;
  int rv;

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
      else if (unformat (line_input, "fib %d", &fwd_fib_index))
	;
      else if (unformat (line_input, "rfib %d", &ret_fib_index))
	;
      else
	{
	  e = clib_error_return (0, "unknown input '%U'",
				 format_unformat_error, input);
	  goto done;
	}
    }

  rv = cnat_set_snat (fwd_fib_index, ret_fib_index, &ip4, 32, &ip6, 128, sw_if_index,
		      CNAT_SNAT_POLICY_FLAG_NONE);
  if (rv)
    {
      e = clib_error_return (0, "unknown error %d", rv);
      goto done;
    }

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
  u32 fib_index = CNAT_FIB_TABLE;
  ip_prefix_t pfx = { .len = 255 };
  ip_address_t rw = { 0 };
  u8 is_add = 1;
  u8 is_src = 0;
  int rv;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%U", unformat_ip_prefix, &pfx))
	;
      else if (unformat (input, "del"))
	is_add = 0;
      else if (unformat (input, "src"))
	is_src = 1;
      else if (unformat (input, "fib %d", &fib_index))
	;
      else if (unformat (input, "rw %U", unformat_ip_address, &rw))
	;
      else
	return (clib_error_return (0, "unknown input '%U'",
				   format_unformat_error, input));
    }

  if (pfx.len == 255)
    return (clib_error_return (0, "prefix not specified"));

  cnat_snat_policy_entry_t *cpe = cnat_snat_policy_entry_get (ip_prefix_version (&pfx), fib_index);
  if (!cpe)
    return (clib_error_return (0, "no snat policy for fib %d", fib_index));

  if (is_add)
    rv = cnat_snat_policy_add_pfx (cpe, &pfx, &rw, is_src);
  else
    rv = cnat_snat_policy_del_pfx (cpe, &pfx, is_src);

  if (rv)
    return (clib_error_return (0, "error %d", rv, input));

  return (NULL);
}

VLIB_CLI_COMMAND (cnat_snat_policy_add_del_pfx_command, static) = {
  .path = "set cnat snat-policy prefix",
  .short_help = "set cnat snat-policy prefix [del] prefix [fib <id>] [dst-rw <addr>]",
  .function = cnat_snat_policy_add_del_pfx_command_fn,
};

static clib_error_t *
cnat_show_snat (vlib_main_t *vm, unformat_input_t *input,
		vlib_cli_command_t *cmd)
{
  cnat_snat_policy_entry_t *cpe = cnat_snat_policy_entry_get_default ();
  if (!cpe)
    return clib_error_return (0, "no default snat policy");

  cnat_snat_exclude_pfx_table_t *excluded_pfx = &cpe->excluded_pfx;
  vnet_main_t *vnm = vnet_get_main ();
  u32 sw_if_index;

  vlib_cli_output (vm, "Source NAT\n  ip4: %U\n  ip6: %U\n\n", format_cnat_endpoint, &cpe->snat_ip4,
		   format_cnat_endpoint, &cpe->snat_ip6);
  vlib_cli_output (vm, "Excluded prefixes:\n  %U\n", format_bihash_24_8,
		   &excluded_pfx->ip_hash, 1);

  for (int i = 0; i < CNAT_N_SNAT_IF_MAP; i++)
    {
      vlib_cli_output (vm, "\n%U interfaces:\n",
		       format_cnat_snat_interface_map_type, i);
      clib_bitmap_foreach (sw_if_index, cpe->interface_maps[i])
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

__clib_export int
cnat_set_snat_policy (cnat_snat_policy_entry_t *cpe, cnat_snat_policy_type_t policy)
{
  switch (policy)
    {
    case CNAT_SNAT_POLICY_NONE:
      cpe->snat_policy = cnat_snat_policy_none;
      break;
    case CNAT_SNAT_POLICY_IF_PFX:
      cpe->snat_policy = cnat_snat_policy_if_pfx;
      break;
    case CNAT_SNAT_POLICY_K8S:
      cpe->snat_policy = cnat_snat_policy_k8s;
      break;
    case CNAT_SNAT_POLICY_DNAT:
      cpe->snat_policy = cnat_snat_policy_dnat;
      break;
    case CNAT_SNAT_POLICY_DNAT_ONLY:
      cpe->snat_policy = cnat_snat_policy_dnat_only;
      break;
    default:
      return VNET_API_ERROR_INVALID_VALUE;
    }
  return 0;
}

static clib_error_t *
cnat_snat_policy_set_cmd_fn (vlib_main_t *vm, unformat_input_t *input,
			     vlib_cli_command_t *cmd)
{
  cnat_snat_policy_type_t policy = CNAT_SNAT_POLICY_NONE;
  u32 fib_index = CNAT_FIB_TABLE;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "none"))
	;
      else if (unformat (input, "if-pfx"))
	policy = CNAT_SNAT_POLICY_IF_PFX;
      else if (unformat (input, "k8s"))
	policy = CNAT_SNAT_POLICY_K8S;
      else if (unformat (input, "dnat"))
	policy = CNAT_SNAT_POLICY_DNAT;
      else if (unformat (input, "dnat-only"))
	policy = CNAT_SNAT_POLICY_DNAT_ONLY;
      else if (unformat (input, "fib %d", &fib_index))
	;
      else
	return clib_error_return (0, "unknown input '%U'",
				  format_unformat_error, input);
    }

  cnat_snat_policy_entry_t *cpe4 = cnat_snat_policy_entry_get (AF_IP4, fib_index);
  cnat_snat_policy_entry_t *cpe6 = cnat_snat_policy_entry_get (AF_IP6, fib_index);
  if (!cpe4 && !cpe6)
    return clib_error_return (0, "no snat policy for fib %d", fib_index);

  int err;
  if (cpe4)
    {
      err = cnat_set_snat_policy (cpe4, policy);
      if (err)
	return clib_error_return (0, "error %d", err);
    }

  if (cpe6)
    {
      err = cnat_set_snat_policy (cpe6, policy);
      if (err)
	return clib_error_return (0, "error %d", err);
    }

  return 0;
}

VLIB_CLI_COMMAND (cnat_snat_policy_set_cmd, static) = {
  .path = "set cnat snat-policy",
  .short_help = "set cnat snat-policy [none|if-pfx|k8s|dnat] [fib <id>]",
  .function = cnat_snat_policy_set_cmd_fn,
};
