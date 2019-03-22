

#include <vppinfra/vec.h>
#include <vppinfra/random.h>
#include <vppinfra/error.h>
#include <vppinfra/bitops.h>	/* for count_set_bits */
#include <acl/bm_lookup.h>
#include <acl/acl.h>

static bm_main_t bm_main = { 0 };

always_inline void
ip4_address_mask_from_width (ip4_address_t * a, u32 width)
{
  int i, byte, bit, bitnum;
  ASSERT (width <= 32);
  clib_memset (a, 0, sizeof (a[0]));
  for (i = 0; i < width; i++)
    {
      bitnum = (7 - (i & 7));
      byte = i / 8;
      bit = 1 << bitnum;
      a->as_u8[byte] |= bit;
    }
}


void
bm_setclear_for_rule (acl_rule_t * r, u32 rule_idx, acl_sbmatch_t * asbm,
		      int is_set)
{
  int is_ip6 = r->is_ipv6;
  if (is_ip6)
    {
      int j;
      ip6_address_t mask;
      ip6_address_mask_from_width (&mask, r->src_prefixlen);
      u16 *m = (u16 *) & mask;
      u16 *a = (u16 *) & r->src.ip6;
      for (j = 0; j < 8; j++)
	sbmv_setclear_bits_mask (&asbm->l3_sbmv_ip6[j], a[j], m[j], rule_idx,
				 is_set);

      ip6_address_mask_from_width (&mask, r->dst_prefixlen);
      a = (u16 *) & r->dst.ip6;
      for (j = 0; j < 8; j++)
	sbmv_setclear_bits_mask (&asbm->l3_sbmv_ip6[8 + j], a[j], m[j],
				 rule_idx, is_set);
    }
  else
    {
      ip4_address_t mask;
      ip4_address_mask_from_width (&mask, r->src_prefixlen);
      u16 *m = (u16 *) & mask;
      u16 *a = (u16 *) & r->src.ip4;
      sbmv_setclear_bits_mask (&asbm->l3_sbmv_ip4[0], a[0], m[0], rule_idx,
			       is_set);
      sbmv_setclear_bits_mask (&asbm->l3_sbmv_ip4[1], a[1], m[1], rule_idx,
			       is_set);
      ip4_address_mask_from_width (&mask, r->dst_prefixlen);
      a = (u16 *) & r->dst.ip4;
      sbmv_setclear_bits_mask (&asbm->l3_sbmv_ip4[2], a[0], m[0], rule_idx,
			       is_set);
      sbmv_setclear_bits_mask (&asbm->l3_sbmv_ip4[3], a[1], m[1], rule_idx,
			       is_set);
    }
  if (r->proto == 0)
    {
      sbmv_setclear_bits_range (&asbm->proto_sbmv[is_ip6], 0, 0xffff,
				rule_idx, is_set);
      sbmv_setclear_bits_range (&asbm->l4_sbmvs[is_ip6].tcp_sbmv[0], 0,
				0xffff, rule_idx, is_set);
      sbmv_setclear_bits_range (&asbm->l4_sbmvs[is_ip6].tcp_sbmv[1], 0,
				0xffff, rule_idx, is_set);
      sbmv_setclear_bits_range (&asbm->l4_sbmvs[is_ip6].udp_sbmv[0], 0,
				0xffff, rule_idx, is_set);
      sbmv_setclear_bits_range (&asbm->l4_sbmvs[is_ip6].udp_sbmv[1], 0,
				0xffff, rule_idx, is_set);
      sbmv_setclear_bits_range (&asbm->l4_sbmvs[is_ip6].icmp_sbmv[0], 0,
				0xffff, rule_idx, is_set);
      sbmv_setclear_bits_range (&asbm->l4_sbmvs[is_ip6].icmp_sbmv[1], 0,
				0xffff, rule_idx, is_set);
    }
  else if (r->proto == 6)
    {
      sbmv_setclear_bits_range (&asbm->l4_sbmvs[is_ip6].tcp_sbmv[0],
				r->src_port_or_type_first,
				r->src_port_or_type_last, rule_idx, is_set);
      sbmv_setclear_bits_range (&asbm->l4_sbmvs[is_ip6].tcp_sbmv[1],
				r->dst_port_or_code_first,
				r->dst_port_or_code_last, rule_idx, is_set);
    }
  else if (r->proto == 17)
    {
      sbmv_setclear_bits_range (&asbm->l4_sbmvs[is_ip6].udp_sbmv[0],
				r->src_port_or_type_first,
				r->src_port_or_type_last, rule_idx, is_set);
      sbmv_setclear_bits_range (&asbm->l4_sbmvs[is_ip6].udp_sbmv[1],
				r->dst_port_or_code_first,
				r->dst_port_or_code_last, rule_idx, is_set);
    }
  else if ((r->proto == 1) && !is_ip6)
    {
      sbmv_setclear_bits_range (&asbm->l4_sbmvs[0].icmp_sbmv[0],
				r->src_port_or_type_first,
				r->src_port_or_type_last, rule_idx, is_set);
      sbmv_setclear_bits_range (&asbm->l4_sbmvs[0].icmp_sbmv[1],
				r->dst_port_or_code_first,
				r->dst_port_or_code_last, rule_idx, is_set);
    }
  else if ((r->proto == 58) && is_ip6)
    {
      sbmv_setclear_bits_range (&asbm->l4_sbmvs[1].icmp_sbmv[0],
				r->src_port_or_type_first,
				r->src_port_or_type_last, rule_idx, is_set);
      sbmv_setclear_bits_range (&asbm->l4_sbmvs[1].icmp_sbmv[1],
				r->dst_port_or_code_first,
				r->dst_port_or_code_last, rule_idx, is_set);
    }
  else
    {
      sbmv_setclear_bits_range (&asbm->proto_sbmv[is_ip6], r->proto, r->proto,
				rule_idx, is_set);
    }
}

void
bm_set_main (acl_main_t * am)
{
  printf ("Setting bm_main\n");
  am->bm_main = &bm_main;
}

void
bm_acl_add (acl_main_t * am, u32 lc_index, int acl_index)
{
  bm_main_t *bm = &bm_main;
  vec_validate (bm->match_contexts, lc_index);
  acl_sbmatch_t *asbm = &bm->match_contexts[lc_index];
  bm_applied_ace_entry_t applied_entry;
  int i;
  acl_rule_t *acl_rules = am->acls[acl_index].rules;

  vec_add1 (asbm->acl_start_indices, vec_len (asbm->all_rules));
  vec_add1 (asbm->acl_lengths, vec_len (acl_rules));
  applied_entry.acl_position = vec_len (asbm->applied_acls);
  applied_entry.acl_index = acl_index;
  applied_entry.hitcount = 0;
  vec_add1 (asbm->applied_acls, acl_index);
  if (vec_len (acl_rules) > 0)
    {
      int l = vec_len (asbm->all_applied_entries);
      vec_validate (asbm->all_applied_entries, l + vec_len (acl_rules) - 1);
      _vec_len (asbm->all_applied_entries) = l;
    }
  for (i = 0; i < vec_len (acl_rules); i++)
    {
      acl_rule_t *r = &acl_rules[i];
      u32 rule_idx = vec_len (asbm->all_rules) + i;
      bm_setclear_for_rule (r, rule_idx, asbm, 1);
      applied_entry.ace_index = i;
      applied_entry.action = r->is_permit;
      vec_add1 (asbm->all_applied_entries, applied_entry);
    }
  vec_append (asbm->all_rules, acl_rules);
}

void
bm_acl_remove (acl_main_t * am, u32 lc_index, int acl_index)
{
  bm_main_t *bm = &bm_main;
  vec_validate (bm->match_contexts, lc_index);
  acl_sbmatch_t *asbm = &bm->match_contexts[lc_index];
  int i;
  ASSERT (vec_len (asbm->applied_acls) > 0);
  ASSERT (vec_len (asbm->applied_acls) == vec_len (asbm->acl_start_indices));
  int last_acl_index =
    vec_elt (asbm->applied_acls, vec_len (asbm->applied_acls) - 1);
  if (last_acl_index != acl_index)
    {
      bm_acl_remove (am, lc_index, last_acl_index);
      bm_acl_remove (am, lc_index, acl_index);
      bm_acl_add (am, lc_index, last_acl_index);
    }
  else
    {
      u32 start_index = vec_elt (asbm->acl_start_indices,
				 vec_len (asbm->acl_start_indices) - 1);
      acl_rule_t *acl_rules = asbm->all_rules + start_index;
      u32 acl_rules_len =
	vec_elt (asbm->acl_lengths, vec_len (asbm->acl_lengths) - 1);
      for (i = 0; i < acl_rules_len; i++)
	{
	  acl_rule_t *r = &acl_rules[i];
	  u32 rule_idx = start_index + i;
	  bm_setclear_for_rule (r, rule_idx, asbm, 0);
	}
      if (asbm->applied_acls)
	_vec_len (asbm->applied_acls)--;
      if (asbm->acl_start_indices)
	_vec_len (asbm->acl_start_indices)--;
      if (asbm->acl_lengths)
	_vec_len (asbm->acl_lengths)--;
      if (asbm->all_rules)
	_vec_len (asbm->all_rules) = start_index;
      if (asbm->all_applied_entries)
	_vec_len (asbm->all_applied_entries) = start_index;
    }
}


// FIXME: a copy of this is in public_inlines.h
//
always_inline sbitmap_t *
get_indexed_bitmap (sbitmap_t ** bitmaps, u16 index)
{
  if (bitmaps)
    {
      int idx = sparse_vec_index (bitmaps, index);
      if (idx && idx < vec_len (bitmaps))
	{
	  sbitmap_t **res = vec_elt_at_index (bitmaps, idx);
	  return *res;
	}
      else
	{
	  return 0;
	}
    }
  else
    {
      return 0;
    }
}

void
print_indexed_bitmaps (vlib_main_t * vm, sbitmap_t ** indexed_bitmaps)
{
  int j;
  for (j = 0; j <= 0xffff; j++)
    {
      sbitmap_t *bm = get_indexed_bitmap (indexed_bitmaps, j);
      if (vec_len (bm))
	{
	  vlib_cli_output (vm, "             %04x: %U", j, format_sbitmap_hex,
			   bm);
	}
    }
}


void
print_l4_sbmvs (vlib_main_t * vm, acl_sbmatch_t * asbm, int is_ip6)
{
  char *ipv = is_ip6 ? "ip6" : "ip4";

  vlib_cli_output (vm, "  %s tcp src: wildcard: %U", ipv, format_sbitmap_hex,
		   asbm->l4_sbmvs[is_ip6].tcp_sbmv[0].wildcard_bitmap);
  print_indexed_bitmaps (vm,
			 asbm->l4_sbmvs[is_ip6].tcp_sbmv[0].indexed_bitmaps);
  vlib_cli_output (vm, "  %s tcp dst: wildcard: %U", ipv, format_sbitmap_hex,
		   asbm->l4_sbmvs[is_ip6].tcp_sbmv[1].wildcard_bitmap);
  print_indexed_bitmaps (vm,
			 asbm->l4_sbmvs[is_ip6].tcp_sbmv[1].indexed_bitmaps);

  vlib_cli_output (vm, "  %s udp src: wildcard: %U", ipv, format_sbitmap_hex,
		   asbm->l4_sbmvs[is_ip6].udp_sbmv[0].wildcard_bitmap);
  print_indexed_bitmaps (vm,
			 asbm->l4_sbmvs[is_ip6].udp_sbmv[0].indexed_bitmaps);
  vlib_cli_output (vm, "  %s udp dst: wildcard: %U", ipv, format_sbitmap_hex,
		   asbm->l4_sbmvs[is_ip6].udp_sbmv[1].wildcard_bitmap);
  print_indexed_bitmaps (vm,
			 asbm->l4_sbmvs[is_ip6].udp_sbmv[1].indexed_bitmaps);

  vlib_cli_output (vm, "  %s icmp src: wildcard: %U", ipv, format_sbitmap_hex,
		   asbm->l4_sbmvs[is_ip6].icmp_sbmv[0].wildcard_bitmap);
  print_indexed_bitmaps (vm,
			 asbm->l4_sbmvs[is_ip6].icmp_sbmv[0].indexed_bitmaps);
  vlib_cli_output (vm, "  %s icmp dst: wildcard: %U", ipv, format_sbitmap_hex,
		   asbm->l4_sbmvs[is_ip6].icmp_sbmv[1].wildcard_bitmap);
  print_indexed_bitmaps (vm,
			 asbm->l4_sbmvs[is_ip6].icmp_sbmv[1].indexed_bitmaps);

}

void
bm_print_context (vlib_main_t * vm, u32 lc_index)
{
  bm_main_t *bm = &bm_main;
  acl_sbmatch_t *asbm = vec_elt_at_index (bm->match_contexts, lc_index);
  int i;
  vlib_cli_output (vm, "context %d", lc_index);
  for (i = 0; i < 16; i++)
    {
      vlib_cli_output (vm, "  ip6[%02d]: wildcard: %U", i, format_sbitmap_hex,
		       asbm->l3_sbmv_ip6[i].wildcard_bitmap);
      print_indexed_bitmaps (vm, asbm->l3_sbmv_ip6[i].indexed_bitmaps);
    }
  print_l4_sbmvs (vm, asbm, 1);
  for (i = 0; i < 4; i++)
    {
      vlib_cli_output (vm, "  ip4[%02d]: wildcard: %U", i, format_sbitmap_hex,
		       asbm->l3_sbmv_ip4[i].wildcard_bitmap);
      print_indexed_bitmaps (vm, asbm->l3_sbmv_ip4[i].indexed_bitmaps);
    }
  print_l4_sbmvs (vm, asbm, 0);
}


u32 max_sparse_bitmap_len = 0;

static clib_error_t *
acl_show_sparse_bitmap_fn (vlib_main_t * vm,
			   unformat_input_t * input, vlib_cli_command_t * cmd)
{
  clib_error_t *error = 0;
  bm_main_t *bm = &bm_main;

  vlib_cli_output (vm, "max sparse bitmap length: %d", max_sparse_bitmap_len);
  int i;
  for (i = 0; i < vec_len (bm->match_contexts); i++)
    bm_print_context (vm, i);

  return error;
}

VLIB_CLI_COMMAND (aclplugin_show_acl_command, static) =
{
.path = "show acl-plugin sparse-bitmap",.short_help =
    "show acl-plugin sparse-bitmap",.function = acl_show_sparse_bitmap_fn,};



/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
