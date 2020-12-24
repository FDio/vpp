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

#include <vnet/adj/adj_delegate.h>
#include <linux-cp/lcp_adj.h>

static adj_delegate_type_t adj_type;

/**
 * The table of adjacencies indexed by the rewrite string
 */
BVT (clib_bihash) lcp_adj_tbl;

static_always_inline void
lcp_adj_mk_key_adj (const ip_adjacency_t *adj, lcp_adj_key_t *key)
{
  lcp_adj_mk_key (adj->rewrite_header.data, adj->rewrite_header.data_bytes,
		  adj->rewrite_header.sw_if_index, key);
}

static u8 *
lcp_adj_delegate_format (const adj_delegate_t *aed, u8 *s)
{
  return (format (s, "lcp"));
}

static void
lcp_adj_delegate_adj_deleted (adj_delegate_t *aed)
{
  ip_adjacency_t *adj;
  lcp_adj_kv_t kv;

  adj = adj_get (aed->ad_adj_index);

  lcp_adj_mk_key_adj (adj, &kv.k);

  BV (clib_bihash_add_del) (&lcp_adj_tbl, &kv.kv, 0);
}

static void
lcp_adj_delegate_adj_modified (adj_delegate_t *aed)
{
  ip_adjacency_t *adj;
  lcp_adj_kv_t kv;

  adj = adj_get (aed->ad_adj_index);

  if (IP_LOOKUP_NEXT_REWRITE != adj->lookup_next_index)
    return;

  lcp_adj_mk_key_adj (adj, &kv.k);
  kv.v = aed->ad_adj_index;

  BV (clib_bihash_add_del) (&lcp_adj_tbl, &kv.kv, 1);
}

static void
lcp_adj_delegate_adj_created (adj_index_t ai)
{
  ip_adjacency_t *adj;
  lcp_adj_kv_t kv;

  adj = adj_get (ai);

  if (IP_LOOKUP_NEXT_REWRITE != adj->lookup_next_index)
    return;

  lcp_adj_mk_key_adj (adj, &kv.k);
  kv.v = ai;

  BV (clib_bihash_add_del) (&lcp_adj_tbl, &kv.kv, 1);
}

u8 *
format_lcp_adj_kvp (u8 *s, va_list *args)
{
  BVT (clib_bihash_kv) *kv = va_arg (*args, BVT (clib_bihash_kv) *);
  CLIB_UNUSED (int verbose) = va_arg (*args, int);
  lcp_adj_kv_t *akv = (lcp_adj_kv_t *) kv;

  s = format (s, "  %U:%U\n    %U", format_vnet_sw_if_index_name,
	      vnet_get_main (), akv->k.sw_if_index, format_hex_bytes,
	      akv->k.rewrite, 18, format_adj_nbr, akv->v, 4);

  return (s);
}

static clib_error_t *
lcp_adj_show_cmd (vlib_main_t *vm, unformat_input_t *input,
		  vlib_cli_command_t *cmd)
{
  u8 verbose = 0;

  if (unformat (input, "verbose"))
    verbose = 1;

  vlib_cli_output (vm, "Linux-CP Adjs:\n%U", BV (format_bihash), &lcp_adj_tbl,
		   verbose);

  return 0;
}

VLIB_CLI_COMMAND (lcp_itf_pair_show_cmd_node, static) = {
  .path = "show lcp adj",
  .function = lcp_adj_show_cmd,
  .short_help = "show lcp adj",
  .is_mp_safe = 1,
};

const adj_delegate_vft_t lcp_adj_vft = {
  .adv_format = lcp_adj_delegate_format,
  .adv_adj_deleted = lcp_adj_delegate_adj_deleted,
  .adv_adj_modified = lcp_adj_delegate_adj_modified,
  .adv_adj_created = lcp_adj_delegate_adj_created,
};

static clib_error_t *
lcp_adj_init (vlib_main_t *vm)
{
  adj_type = adj_delegate_register_new_type (&lcp_adj_vft);

  BV (clib_bihash_init) (&lcp_adj_tbl, "linux-cp ADJ table", 1024, 1 << 24);
  BV (clib_bihash_set_kvp_format_fn) (&lcp_adj_tbl, format_lcp_adj_kvp);

  return (NULL);
}

VLIB_INIT_FUNCTION (lcp_adj_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
