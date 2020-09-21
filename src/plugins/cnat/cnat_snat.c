/*
 * Copyright (c) 2020 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <vnet/ip/ip.h>
#include <cnat/cnat_snat.h>
#include <cnat/cnat_translation.h>

static void
cnat_compute_prefix_lengths_in_search_order (cnat_snat_pfx_table_t *
					     table, ip_address_family_t af)
{
  int i;
  vec_reset_length (table->meta[af].prefix_lengths_in_search_order);
  /* Note: bitmap reversed so this is in fact a longest prefix match */
  /* *INDENT-OFF* */
  clib_bitmap_foreach (i, table->meta[af].non_empty_dst_address_length_bitmap,
    ({
      int dst_address_length = 128 - i;
      vec_add1 (table->meta[af].prefix_lengths_in_search_order, dst_address_length);
    }));
  /* *INDENT-ON* */
}

int
cnat_add_snat_prefix (ip_prefix_t * pfx)
{
  /* All packets destined to this prefix won't be source-NAT-ed */
  cnat_snat_pfx_table_t *table = &cnat_main.snat_pfx_table;
  clib_bihash_kv_24_8_t kv;
  ip6_address_t *mask;
  u64 af = ip_prefix_version (pfx);;

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
  clib_bihash_add_del_24_8 (&table->ip_hash, &kv, 1 /* is_add */ );

  table->meta[af].dst_address_length_refcounts[pfx->len]++;
  table->meta[af].non_empty_dst_address_length_bitmap =
    clib_bitmap_set (table->meta[af].non_empty_dst_address_length_bitmap,
		     128 - pfx->len, 1);
  cnat_compute_prefix_lengths_in_search_order (table, af);
  return 0;
}

int
cnat_del_snat_prefix (ip_prefix_t * pfx)
{
  cnat_snat_pfx_table_t *table = &cnat_main.snat_pfx_table;
  clib_bihash_kv_24_8_t kv, val;
  ip6_address_t *mask;
  u64 af = ip_prefix_version (pfx);;

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
  clib_bihash_add_del_24_8 (&table->ip_hash, &kv, 0 /* is_add */ );
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

u8 *
format_cnat_snat_prefix (u8 * s, va_list * args)
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

void
cnat_set_snat (ip4_address_t * ip4, ip6_address_t * ip6, u32 sw_if_index)
{
  cnat_main.snat_ip4.as_u32 = ip4->as_u32;
  ip6_address_copy (&cnat_main.snat_ip6, ip6);

  cnat_addr_resolution_cleanup (INDEX_INVALID, CNAT_ADDR_RESOLUTION_SNAT);

  if (cnat_main.snat_ip4.as_u32 == 0 && sw_if_index != INDEX_INVALID)
    {
      ip4_address_t *ip4 = 0;
      ip4 = ip4_interface_first_address (&ip4_main, sw_if_index, 0);
      if (ip4)
	cnat_main.snat_ip4.as_u32 = ip4->as_u32;
      else
	cnat_add_addr_resolution (sw_if_index, AF_IP4,
				  CNAT_ADDR_RESOLUTION_SNAT);
    }
  if (cnat_main.snat_ip6.as_u64[0] == 0 && cnat_main.snat_ip6.as_u64[1] == 0
      && sw_if_index != INDEX_INVALID)
    {
      ip6_address_t *ip6 = 0;
      ip6 = ip6_interface_first_address (&ip6_main, sw_if_index);
      if (ip6)
	ip6_address_copy (&cnat_main.snat_ip6, ip6);
      else
	cnat_add_addr_resolution (sw_if_index, AF_IP6,
				  CNAT_ADDR_RESOLUTION_SNAT);
    }
}

static clib_error_t *
cnat_set_snat_cli (vlib_main_t * vm,
		   unformat_input_t * input, vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  vnet_main_t *vnm = vnet_get_main ();
  ip4_address_t ip4 = { {0} };
  ip6_address_t ip6 = { {0} };
  clib_error_t *e = 0;
  u32 sw_if_index = INDEX_INVALID;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat_user (line_input, unformat_ip4_address, &ip4))
	;
      else if (unformat_user (line_input, unformat_ip6_address, &ip6))
	;
      else if (unformat_user (line_input, unformat_vnet_sw_interface,
			      vnm, &sw_if_index))
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

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (cnat_set_snat_command, static) =
{
  .path = "cnat snat with",
  .short_help = "cnat snat with [<ip4-address>][<ip6-address>]",
  .function = cnat_set_snat_cli,
};
/* *INDENT-ON* */

static clib_error_t *
cnat_snat_exclude (vlib_main_t * vm,
		   unformat_input_t * input, vlib_cli_command_t * cmd)
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
    rv = cnat_add_snat_prefix (&pfx);
  else
    rv = cnat_del_snat_prefix (&pfx);

  if (rv)
    {
      return (clib_error_return (0, "error %d", rv, input));
    }

  return (NULL);
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (cnat_snat_exclude_command, static) =
{
  .path = "cnat snat exclude",
  .short_help = "cnat snat exclude [ip]",
  .function = cnat_snat_exclude,
};
/* *INDENT-ON* */

static clib_error_t *
cnat_show_snat (vlib_main_t * vm,
		unformat_input_t * input, vlib_cli_command_t * cmd)
{
  cnat_snat_pfx_table_t *table = &cnat_main.snat_pfx_table;
  vlib_cli_output (vm, "Source NAT\nip4: %U\nip6: %U\n",
		   format_ip4_address, &cnat_main.snat_ip4,
		   format_ip6_address, &cnat_main.snat_ip6);
  vlib_cli_output (vm, "Prefixes:\n%U\n",
		   format_bihash_24_8, &table->ip_hash, 1);
  return (NULL);
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (cnat_show_snat_command, static) =
{
  .path = "show cnat snat",
  .short_help = "show cnat snat",
  .function = cnat_show_snat,
};
/* *INDENT-ON* */

static clib_error_t *
cnat_snat_init (vlib_main_t * vm)
{
  cnat_snat_pfx_table_t *table = &cnat_main.snat_pfx_table;
  cnat_main_t *cm = &cnat_main;
  int i;
  for (i = 0; i < ARRAY_LEN (table->ip_masks); i++)
    {
      u32 j, i0, i1;

      i0 = i / 32;
      i1 = i % 32;

      for (j = 0; j < i0; j++)
	table->ip_masks[i].as_u32[j] = ~0;

      if (i1)
	table->ip_masks[i].as_u32[i0] =
	  clib_host_to_net_u32 (pow2_mask (i1) << (32 - i1));
    }
  clib_bihash_init_24_8 (&table->ip_hash, "snat prefixes",
			 cm->snat_hash_buckets, cm->snat_hash_memory);
  clib_bihash_set_kvp_format_fn_24_8 (&table->ip_hash,
				      format_cnat_snat_prefix);

  return (NULL);
}

VLIB_INIT_FUNCTION (cnat_snat_init);


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
