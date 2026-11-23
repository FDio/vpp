/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2025 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>
#include <vppinfra/format_ansi.h>
#include <vppinfra/format_table.h>
#include <vnet/crypto/crypto.h>

static const char *
crypto_alg_type_name (vnet_crypto_alg_type_t alg_type)
{
  switch (alg_type)
    {
    case VNET_CRYPTO_ALG_T_NONE:
      return "none";
    case VNET_CRYPTO_ALG_T_CIPHER:
      return "cipher";
    case VNET_CRYPTO_ALG_T_AEAD:
      return "aead";
    case VNET_CRYPTO_ALG_T_AUTH:
      return "auth";
    case VNET_CRYPTO_ALG_T_COMBINED:
      return "combined";
    }

  return "unknown";
}

static const char *
crypto_alg_family_name (vnet_crypto_alg_family_t family)
{
  static char *strings[] = {
#define _(n, s) [VNET_CRYPTO_ALG_FAMILY_##n] = s,
    foreach_crypto_alg_family
#undef _
  };

  if (family == VNET_CRYPTO_ALG_FAMILY_NONE)
    return "-";

  if (family >= VNET_CRYPTO_N_ALG_FAMILIES)
    return "unknown";

  return strings[family];
}

static const char *
crypto_handler_type_name (vnet_crypto_handler_type_t t)
{
  static char *strings[] = {
#define _(n, s) [VNET_CRYPTO_HANDLER_TYPE_##n] = s,
    foreach_crypto_handler_type
#undef _
  };

  if (t >= VNET_CRYPTO_HANDLER_N_TYPES)
    return "unknown";

  return strings[t];
}

static u16
crypto_alg_iv_len (vnet_crypto_alg_data_t *ad)
{
  switch (ad->cipher_family)
    {
    case VNET_CRYPTO_ALG_FAMILY_DES_CBC:
    case VNET_CRYPTO_ALG_FAMILY_TDES_CBC:
      return 8;
    case VNET_CRYPTO_ALG_FAMILY_AES_CBC:
    case VNET_CRYPTO_ALG_FAMILY_AES_CTR:
      return 16;
    case VNET_CRYPTO_ALG_FAMILY_AES_GCM:
    case VNET_CRYPTO_ALG_FAMILY_AES_NULL_GMAC:
    case VNET_CRYPTO_ALG_FAMILY_CHACHA20_POLY1305:
      return 12;
    case VNET_CRYPTO_ALG_FAMILY_NONE:
    case VNET_CRYPTO_ALG_FAMILY_MD5:
    case VNET_CRYPTO_ALG_FAMILY_SHA1:
    case VNET_CRYPTO_ALG_FAMILY_SHA2:
    case VNET_CRYPTO_N_ALG_FAMILIES:
      return 0;
    }

  return 0;
}

typedef struct
{
  u16 index;
  u8 is_hash;
} crypto_cli_alg_entry_t;

static int
crypto_cli_alg_name_cmp (const crypto_cli_alg_entry_t *a0, const crypto_cli_alg_entry_t *a1)
{
  vnet_crypto_main_t *cm = &crypto_main;
  char *n0, *n1;

  n0 = a0->is_hash ? cm->hash_algs[a0->index].name : cm->algs[a0->index].name;
  n1 = a1->is_hash ? cm->hash_algs[a1->index].name : cm->algs[a1->index].name;

  return strcmp (n0, n1);
}

static crypto_cli_alg_entry_t *
crypto_cli_sorted_algs (void)
{
  crypto_cli_alg_entry_t *algs = 0;

  for (vnet_crypto_alg_t alg = 1; alg < VNET_CRYPTO_N_ALGS; alg++)
    vec_add1 (algs, ((crypto_cli_alg_entry_t) {
		      .index = alg,
		    }));
  for (vnet_crypto_hash_alg_t hash_alg = 1; hash_alg < VNET_CRYPTO_N_HASH_ALGS; hash_alg++)
    vec_add1 (algs, ((crypto_cli_alg_entry_t) {
		      .index = hash_alg,
		      .is_hash = 1,
		    }));
  vec_sort_with_function (algs, crypto_cli_alg_name_cmp);

  return algs;
}

static void
show_crypto_algorithms_table (vlib_main_t *vm, int plain_text_only)
{
  vnet_crypto_main_t *cm = &crypto_main;
  table_t table = { .no_ansi = plain_text_only };
  crypto_cli_alg_entry_t *algs = crypto_cli_sorted_algs ();
  crypto_cli_alg_entry_t *alg;
  u8 *s = 0;
  int row = 0;

  table_add_hdr_col (&table, 0);
  table_add_hdr_row (&table, 8, "Name", "Type", "Cipher", "Auth", "Key", "Auth", "AAD", "Block");
  for (int i = 0; i < 8; i++)
    table_set_cell_align (&table, -1, i, TTAA_LEFT);

  vec_foreach (alg, algs)
    {
      int c = -1;

      if (alg->is_hash)
	{
	  vnet_crypto_hash_alg_data_t *ad = cm->hash_algs + alg->index;

	  table_format_cell (&table, row, c++, "%s", ad->name);
	  table_format_cell (&table, row, c++, "%s", "hash");
	  table_format_cell (&table, row, c++, "%s", "-");
	  table_format_cell (&table, row, c++, "%s", crypto_alg_family_name (ad->family));
	  table_format_cell (&table, row, c++, "%s", "-");
	  table_format_cell (&table, row, c++, "%s", "-");
	  table_format_cell (&table, row, c++, "%s", "-");
	  table_format_cell (&table, row, c++, "%u", ad->block_len);
	}
      else
	{
	  vnet_crypto_alg_data_t *ad = cm->algs + alg->index;

	  table_format_cell (&table, row, c++, "%s", ad->name);
	  table_format_cell (&table, row, c++, "%s", crypto_alg_type_name (ad->alg_type));
	  table_format_cell (&table, row, c++, "%s", crypto_alg_family_name (ad->cipher_family));
	  table_format_cell (&table, row, c++, "%s", crypto_alg_family_name (ad->auth_family));
	  table_format_cell (&table, row, c++, "%u", ad->cipher_key_len);
	  if (ad->auth_len)
	    table_format_cell (&table, row, c++, "%u", ad->auth_len);
	  else
	    table_format_cell (&table, row, c++, "%s", "var");
	  if (ad->alg_type == VNET_CRYPTO_ALG_T_AEAD)
	    {
	      if (ad->variable_aad_len == 0)
		table_format_cell (&table, row, c++, "%u", ad->aad_len);
	      else
		table_format_cell (&table, row, c++, "%s", "var");
	    }
	  else
	    table_format_cell (&table, row, c++, "%s", "-");
	  table_format_cell (&table, row, c++, "%u", ad->block_len);
	}
      for (int i = -1; i < c; i++)
	table_set_cell_align (&table, row, i, TTAA_LEFT);
      row++;
    }

  s = format (s, "%U", format_table, &table);
  vlib_cli_output (vm, "%v", s);
  vec_free (algs);
  vec_free (s);
  table_free (&table);
}

static void
show_crypto_algorithm_detail (vlib_main_t *vm, vnet_crypto_alg_t alg)
{
  vnet_crypto_main_t *cm = &crypto_main;
  vnet_crypto_alg_data_t *ad = cm->algs + alg;
  vnet_crypto_ctx_layout_t *kl = cm->ctx_layout + alg;
  vnet_crypto_engine_t *e;
  u32 n_threads = vlib_get_n_threads ();
  vnet_crypto_handler_type_t t;
  vnet_crypto_op_type_t op_type;

  vlib_cli_output (vm, "algorithm: %U", format_vnet_crypto_alg, alg);
  vlib_cli_output (vm, "  type: %s", crypto_alg_type_name (ad->alg_type));
  if (ad->cipher_family != VNET_CRYPTO_ALG_FAMILY_NONE)
    {
      if (ad->alg_type == VNET_CRYPTO_ALG_T_AEAD)
	{
	  if (ad->variable_aad_len)
	    vlib_cli_output (vm,
			     "  cipher: family %s block-size %u key-size %u iv-len %u "
			     "aad-len variable",
			     crypto_alg_family_name (ad->cipher_family), ad->block_len,
			     ad->cipher_key_len, crypto_alg_iv_len (ad));
	  else
	    vlib_cli_output (vm,
			     "  cipher: family %s block-size %u key-size %u iv-len %u "
			     "aad-len %u",
			     crypto_alg_family_name (ad->cipher_family), ad->block_len,
			     ad->cipher_key_len, crypto_alg_iv_len (ad), ad->aad_len);
	}
      else
	vlib_cli_output (vm, "  cipher: family %s block-size %u key-size %u iv-len %u",
			 crypto_alg_family_name (ad->cipher_family), ad->block_len,
			 ad->cipher_key_len, crypto_alg_iv_len (ad));
    }
  if (ad->auth_family != VNET_CRYPTO_ALG_FAMILY_NONE)
    {
      if (ad->variable_auth_key_len)
	vlib_cli_output (vm, "  auth: family %s block-size %u key-size variable icv-len %u",
			 crypto_alg_family_name (ad->auth_family), ad->auth_key_len, ad->auth_len);
      else
	vlib_cli_output (vm, "  auth: family %s block-size %u key-size %u icv-len %u",
			 crypto_alg_family_name (ad->auth_family), ad->auth_key_len,
			 ad->auth_key_len, ad->auth_len);
    }
  vlib_cli_output (vm, "  key-data:");
  for (t = 0; t < VNET_CRYPTO_HANDLER_N_TYPES; t++)
    {
      vlib_cli_output (vm, "    %s: size %u offset %u", crypto_handler_type_name (t),
		       kl->key_data_size[t], kl->key_data_offset[t]);
    }
  vlib_cli_output (vm, "    total: %u", kl->total_key_data_size);

  vlib_cli_output (vm, "  ops:");
  vlib_cli_output (vm, "    %-10s%-18s%-18s%s", "type", "simple", "chained", "async");
  for (op_type = 0; op_type < VNET_CRYPTO_OP_N_TYPES; op_type++)
    {
      if (!vnet_crypto_alg_has_op_type (alg, op_type))
	continue;

      vlib_cli_output (
	vm, "    %-10U%-18U%-18U%U", format_vnet_crypto_op_type, op_type, format_vnet_crypto_engine,
	cm->active_engine_index[alg][VNET_CRYPTO_HANDLER_TYPE_SIMPLE], format_vnet_crypto_engine,
	cm->active_engine_index[alg][VNET_CRYPTO_HANDLER_TYPE_CHAINED], format_vnet_crypto_engine,
	cm->active_engine_index[alg][VNET_CRYPTO_HANDLER_TYPE_ASYNC]);
    }

  vec_foreach (e, cm->engines)
    {
      if (e == cm->engines || e->name == 0)
	continue;

      vlib_cli_output (vm, "  engine '%s':", e->name);
      vlib_cli_output (vm, "    key-data:");
      for (t = 0; t < VNET_CRYPTO_HANDLER_N_TYPES; t++)
	{
	  u8 support = 0;
	  u8 *support_vec = cm->engine_supports_alg[alg][t];
	  u32 key_data_size = e->key_data_sz[t][alg];
	  u8 key_data_per_thread = e->key_data_per_thread[t][alg];

	  if (support_vec && (e - cm->engines) < vec_len (support_vec))
	    support = support_vec[e - cm->engines];

	  if (support == 0)
	    continue;

	  if (key_data_per_thread)
	    vlib_cli_output (vm, "      %s: %u per-thread (%u total)", crypto_handler_type_name (t),
			     key_data_size, key_data_size * n_threads);
	  else
	    vlib_cli_output (vm, "      %s: %u", crypto_handler_type_name (t), key_data_size);
	}
    }
}

static void
show_crypto_hash_algorithm_detail (vlib_main_t *vm, vnet_crypto_hash_alg_t alg)
{
  vnet_crypto_main_t *cm = &crypto_main;
  vnet_crypto_hash_alg_data_t *ad = cm->hash_algs + alg;
  vnet_crypto_engine_t *e;
  vnet_crypto_handler_type_t t;

  vlib_cli_output (vm, "algorithm: %U", format_vnet_crypto_hash_alg, alg);
  vlib_cli_output (vm, "  type: hash");
  vlib_cli_output (vm, "  auth: family %s block-size %u key-size - icv-len %u",
		   crypto_alg_family_name (ad->family), ad->block_len, ad->digest_len);
  vlib_cli_output (vm, "  ops:");
  vlib_cli_output (vm, "    %-10s%-18s%-18s%s", "type", "simple", "chained", "async");
  vlib_cli_output (vm, "    %-10s%-18U%-18U%s", "hash", format_vnet_crypto_engine,
		   cm->active_hash_engine_index[alg][VNET_CRYPTO_HANDLER_TYPE_SIMPLE],
		   format_vnet_crypto_engine,
		   cm->active_hash_engine_index[alg][VNET_CRYPTO_HANDLER_TYPE_CHAINED], "-");

  vec_foreach (e, cm->engines)
    {
      if (e == cm->engines || e->name == 0)
	continue;

      vlib_cli_output (vm, "  engine '%s':", e->name);
      for (t = 0; t < 2; t++)
	if (e->hash_ops[alg].handlers[t])
	  vlib_cli_output (vm, "    %s: yes", t == 0 ? "simple" : "chained");
    }
}

static const cli_column_t crypto_algorithms_columns[] = {
  { "name", "Name" },	{ "type", "Type" },	   { "cipher", "Cipher" },
  { "auth", "Auth" },	{ "key_size", "Key" },	   { "icv_len", "ICV" },
  { "aad_len", "AAD" }, { "block_size", "Block" }, {},
};

static const cli_column_t crypto_algorithm_columns[] = {
  { "name", "Name" },
  { "type", "Type" },
  { "cipher_family", "Cipher" },
  { "cipher_key_size", "Cipher key size" },
  { "auth_family", "Auth" },
  { "icv_len", "ICV length" },
  { "key_data_total", "Key data size" },
  {},
};

static const cli_column_t crypto_engines_columns[] = {
  { "name", "Name" },
  { "priority", "Prio" },
  { "description", "Description" },
  {},
};

static const cli_column_t crypto_handlers_columns[] = {
  { "algorithm", "Algorithm" }, { "op", "Op" },	      { "simple", "Simple" },
  { "chained", "Chained" },	{ "async", "Async" }, {},
};

static const cli_column_t crypto_async_status_columns[] = {
  { "engine", "Engine" },
  { "thread", "Thread" },
  { "state", "State" },
  {},
};

/* name of the engine, 0 if there is none */
static const char *
crypto_cli_engine_name (vnet_crypto_engine_id_t id)
{
  vnet_crypto_main_t *cm = &crypto_main;

  if (id == VNET_CRYPTO_ENGINE_ID_INVALID || id >= vec_len (cm->engines))
    return 0;

  return cm->engines[id].name;
}

static void
crypto_cli_json_add_engine (clib_json_text_t *j, char *key, vnet_crypto_engine_id_t id)
{
  const char *name = crypto_cli_engine_name (id);

  if (name)
    clib_json_add_string (j, key, "%s", name);
}

static clib_error_t *
show_crypto_algorithms_json (cli_ctx_t *ctx)
{
  vnet_crypto_main_t *cm = &crypto_main;
  crypto_cli_alg_entry_t *algs = crypto_cli_sorted_algs ();
  crypto_cli_alg_entry_t *alg;
  clib_json_text_t j;

  clib_json_init (&j);
  clib_json_add_array (&j, 0);
  vec_foreach (alg, algs)
    {
      clib_json_add_object (&j, 0);
      if (alg->is_hash)
	{
	  vnet_crypto_hash_alg_data_t *ad = cm->hash_algs + alg->index;

	  clib_json_add_string (&j, "name", "%s", ad->name);
	  clib_json_add_string (&j, "type", "hash");
	  clib_json_add_string (&j, "auth", "%s", crypto_alg_family_name (ad->family));
	  clib_json_add_number (&j, "icv_len", ad->digest_len);
	  clib_json_add_number (&j, "block_size", ad->block_len);
	}
      else
	{
	  vnet_crypto_alg_data_t *ad = cm->algs + alg->index;

	  clib_json_add_string (&j, "name", "%s", ad->name);
	  clib_json_add_string (&j, "type", "%s", crypto_alg_type_name (ad->alg_type));
	  if (ad->cipher_family != VNET_CRYPTO_ALG_FAMILY_NONE)
	    clib_json_add_string (&j, "cipher", "%s", crypto_alg_family_name (ad->cipher_family));
	  if (ad->auth_family != VNET_CRYPTO_ALG_FAMILY_NONE)
	    clib_json_add_string (&j, "auth", "%s", crypto_alg_family_name (ad->auth_family));
	  clib_json_add_number (&j, "key_size", ad->cipher_key_len);
	  if (ad->auth_len)
	    clib_json_add_number (&j, "icv_len", ad->auth_len);
	  else
	    clib_json_add_true (&j, "variable_icv_len");
	  if (ad->alg_type == VNET_CRYPTO_ALG_T_AEAD)
	    {
	      if (ad->variable_aad_len)
		clib_json_add_true (&j, "variable_aad_len");
	      else
		clib_json_add_number (&j, "aad_len", ad->aad_len);
	    }
	  clib_json_add_number (&j, "block_size", ad->block_len);
	}
      clib_json_parent (&j);
    }
  clib_json_parent (&j);
  vec_free (algs);

  return cli_emit_table (ctx, &j, crypto_algorithms_columns);
}

static clib_error_t *
show_crypto_algorithm_json (cli_ctx_t *ctx, vnet_crypto_alg_t alg)
{
  vnet_crypto_main_t *cm = &crypto_main;
  vnet_crypto_alg_data_t *ad = cm->algs + alg;
  vnet_crypto_ctx_layout_t *kl = cm->ctx_layout + alg;
  u32 n_threads = vlib_get_n_threads ();
  vnet_crypto_engine_t *e;
  clib_json_text_t j;

  clib_json_init (&j);
  clib_json_add_object (&j, 0);
  clib_json_add_string (&j, "name", "%U", format_vnet_crypto_alg, alg);
  clib_json_add_string (&j, "type", "%s", crypto_alg_type_name (ad->alg_type));
  if (ad->cipher_family != VNET_CRYPTO_ALG_FAMILY_NONE)
    {
      clib_json_add_string (&j, "cipher_family", "%s", crypto_alg_family_name (ad->cipher_family));
      clib_json_add_number (&j, "cipher_block_size", ad->block_len);
      clib_json_add_number (&j, "cipher_key_size", ad->cipher_key_len);
      clib_json_add_number (&j, "iv_len", crypto_alg_iv_len (ad));
      if (ad->alg_type == VNET_CRYPTO_ALG_T_AEAD)
	{
	  if (ad->variable_aad_len)
	    clib_json_add_true (&j, "variable_aad_len");
	  else
	    clib_json_add_number (&j, "aad_len", ad->aad_len);
	}
    }
  if (ad->auth_family != VNET_CRYPTO_ALG_FAMILY_NONE)
    {
      clib_json_add_string (&j, "auth_family", "%s", crypto_alg_family_name (ad->auth_family));
      if (ad->variable_auth_key_len)
	clib_json_add_true (&j, "variable_auth_key_size");
      else
	clib_json_add_number (&j, "auth_key_size", ad->auth_key_len);
      clib_json_add_number (&j, "icv_len", ad->auth_len);
    }
  clib_json_add_number (&j, "key_data_total", kl->total_key_data_size);

  clib_json_add_array (&j, "key_data");
  for (vnet_crypto_handler_type_t t = 0; t < VNET_CRYPTO_HANDLER_N_TYPES; t++)
    {
      clib_json_add_object (&j, 0);
      clib_json_add_string (&j, "handler", "%s", crypto_handler_type_name (t));
      clib_json_add_number (&j, "size", kl->key_data_size[t]);
      clib_json_add_number (&j, "offset", kl->key_data_offset[t]);
      clib_json_parent (&j);
    }
  clib_json_parent (&j);

  clib_json_add_array (&j, "ops");
  for (vnet_crypto_op_type_t op_type = 0; op_type < VNET_CRYPTO_OP_N_TYPES; op_type++)
    {
      if (!vnet_crypto_alg_has_op_type (alg, op_type))
	continue;

      clib_json_add_object (&j, 0);
      clib_json_add_string (&j, "type", "%U", format_vnet_crypto_op_type, op_type);
      crypto_cli_json_add_engine (&j, "simple",
				  cm->active_engine_index[alg][VNET_CRYPTO_HANDLER_TYPE_SIMPLE]);
      crypto_cli_json_add_engine (&j, "chained",
				  cm->active_engine_index[alg][VNET_CRYPTO_HANDLER_TYPE_CHAINED]);
      crypto_cli_json_add_engine (&j, "async",
				  cm->active_engine_index[alg][VNET_CRYPTO_HANDLER_TYPE_ASYNC]);
      clib_json_parent (&j);
    }
  clib_json_parent (&j);

  clib_json_add_array (&j, "engines");
  vec_foreach (e, cm->engines)
    {
      if (e == cm->engines || e->name == 0)
	continue;

      clib_json_add_object (&j, 0);
      clib_json_add_string (&j, "name", "%s", e->name);
      clib_json_add_array (&j, "key_data");
      for (vnet_crypto_handler_type_t t = 0; t < VNET_CRYPTO_HANDLER_N_TYPES; t++)
	{
	  u8 *support_vec = cm->engine_supports_alg[alg][t];
	  u32 key_data_size = e->key_data_sz[t][alg];

	  if (!support_vec || (e - cm->engines) >= vec_len (support_vec) ||
	      support_vec[e - cm->engines] == 0)
	    continue;

	  clib_json_add_object (&j, 0);
	  clib_json_add_string (&j, "handler", "%s", crypto_handler_type_name (t));
	  clib_json_add_number (&j, "size", key_data_size);
	  if (e->key_data_per_thread[t][alg])
	    {
	      clib_json_add_true (&j, "per_thread");
	      clib_json_add_number (&j, "total_size", key_data_size * n_threads);
	    }
	  clib_json_parent (&j);
	}
      clib_json_parent (&j);
      clib_json_parent (&j);
    }
  clib_json_parent (&j);
  clib_json_parent (&j);

  return cli_emit_object (ctx, &j, crypto_algorithm_columns);
}

static clib_error_t *
show_crypto_hash_algorithm_json (cli_ctx_t *ctx, vnet_crypto_hash_alg_t alg)
{
  vnet_crypto_main_t *cm = &crypto_main;
  vnet_crypto_hash_alg_data_t *ad = cm->hash_algs + alg;
  vnet_crypto_engine_t *e;
  clib_json_text_t j;

  clib_json_init (&j);
  clib_json_add_object (&j, 0);
  clib_json_add_string (&j, "name", "%U", format_vnet_crypto_hash_alg, alg);
  clib_json_add_string (&j, "type", "hash");
  clib_json_add_string (&j, "auth_family", "%s", crypto_alg_family_name (ad->family));
  clib_json_add_number (&j, "auth_block_size", ad->block_len);
  clib_json_add_number (&j, "icv_len", ad->digest_len);
  clib_json_add_array (&j, "ops");
  clib_json_add_object (&j, 0);
  clib_json_add_string (&j, "type", "hash");
  crypto_cli_json_add_engine (&j, "simple",
			      cm->active_hash_engine_index[alg][VNET_CRYPTO_HANDLER_TYPE_SIMPLE]);
  crypto_cli_json_add_engine (&j, "chained",
			      cm->active_hash_engine_index[alg][VNET_CRYPTO_HANDLER_TYPE_CHAINED]);
  clib_json_parent (&j);
  clib_json_parent (&j);
  clib_json_add_array (&j, "engines");
  vec_foreach (e, cm->engines)
    {
      if (e == cm->engines || e->name == 0)
	continue;

      clib_json_add_object (&j, 0);
      clib_json_add_string (&j, "name", "%s", e->name);
      clib_json_add_array (&j, "handlers");
      for (vnet_crypto_handler_type_t t = 0; t < 2; t++)
	if (e->hash_ops[alg].handlers[t])
	  clib_json_add_string (&j, 0, "%s", crypto_handler_type_name (t));
      clib_json_parent (&j);
      clib_json_parent (&j);
    }
  clib_json_parent (&j);
  clib_json_parent (&j);

  return cli_emit_object (ctx, &j, crypto_algorithm_columns);
}

/* an algorithm or a hash algorithm, the value is the index, hash algorithms
 * have CRYPTO_CLI_HASH_ALG set */
#define CRYPTO_CLI_HASH_ALG (1u << 31)

static const char *
next_algorithm_name (const cli_arg_t *a, u32 *iter, u32 *value, const char **help)
{
  vnet_crypto_main_t *cm = &crypto_main;
  u32 i = *iter;

  if (i + 1 < VNET_CRYPTO_N_ALGS)
    {
      *value = i + 1;
      if (help)
	*help = crypto_alg_type_name (cm->algs[i + 1].alg_type);
      (*iter)++;
      return cm->algs[i + 1].name;
    }

  i -= VNET_CRYPTO_N_ALGS - 1;
  if (i + 1 < VNET_CRYPTO_N_HASH_ALGS)
    {
      *value = (i + 1) | CRYPTO_CLI_HASH_ALG;
      if (help)
	*help = "hash";
      (*iter)++;
      return cm->hash_algs[i + 1].name;
    }

  return 0;
}

CLIB_CLI_TYPE (cli_type_crypto_algorithm, static) = {
  .name = "algorithm",
  .help = "crypto or hash algorithm",
  .next_name = next_algorithm_name,
  .parse = cli_names_parse,
  .complete = cli_names_complete,
};

/* a name of an algorithm or of an engine, not checked, the handler tells
 * if the engine can not be set */
static u8 *
parse_crypto_name (const cli_arg_t *a, u8 *tok, cli_value_t *v)
{
  v->str = vec_dup (tok);
  return 0;
}

static void
complete_crypto_name (const cli_arg_t *a, u8 *prefix, cli_candidate_t **out)
{
  vnet_crypto_main_t *cm = &crypto_main;
  vnet_crypto_engine_t *e;
  char *key;
  u8 *value;

  hash_foreach_mem (key, value, cm->alg_index_by_name, ({
		      (void) value;
		      if (cli_prefix_match (key, prefix))
			cli_candidate_add (out, key, "algorithm");
		    }));
  vec_foreach (e, cm->engines)
    if (e->name && cli_prefix_match (e->name, prefix))
      cli_candidate_add (out, e->name, "engine");
}

CLIB_CLI_TYPE (cli_type_crypto_name, static) = {
  .name = "name",
  .help = "algorithm name, the last name is the engine",
  .owns_str = 1,
  .parse = parse_crypto_name,
  .complete = complete_crypto_name,
};

static clib_error_t *
show_crypto_algorithm_command_fn (vlib_main_t *vm, cli_ctx_t *ctx)
{
  cli_value_t *v = cli_get (ctx, "algorithm");

  if (cli_is_structured (ctx))
    {
      if (!v)
	return show_crypto_algorithms_json (ctx);
      if (v->index & CRYPTO_CLI_HASH_ALG)
	return show_crypto_hash_algorithm_json (ctx, v->index & ~CRYPTO_CLI_HASH_ALG);
      return show_crypto_algorithm_json (ctx, v->index);
    }

  if (!v)
    show_crypto_algorithms_table (vm, ctx->plain_text_only);
  else if (v->index & CRYPTO_CLI_HASH_ALG)
    show_crypto_hash_algorithm_detail (vm, v->index & ~CRYPTO_CLI_HASH_ALG);
  else
    show_crypto_algorithm_detail (vm, v->index);

  return 0;
}

VLIB_CLI_COMMAND (show_crypto_algorithm_command, static) = {
  .path = "show crypto algorithm",
  .short_help = "show crypto algorithm [algorithm]",
  .args = CLI_ARGS (CLI_VALUE ("algorithm", cli_type_crypto_algorithm, .flags = CLI_F_OPTIONAL,
			       .help = "show the details of this algorithm")),
  .handler = show_crypto_algorithm_command_fn,
  .is_structured = 1,
};

static clib_error_t *
show_crypto_engines_command_fn (vlib_main_t *vm, cli_ctx_t *ctx)
{
  vnet_crypto_main_t *cm = &crypto_main;
  vnet_crypto_engine_t *p;

  if (cli_is_structured (ctx))
    {
      clib_json_text_t j;

      clib_json_init (&j);
      clib_json_add_array (&j, 0);
      vec_foreach (p, cm->engines)
	{
	  if (!p->name)
	    continue;

	  clib_json_add_object (&j, 0);
	  clib_json_add_string (&j, "name", "%s", p->name);
	  clib_json_add_number (&j, "priority", p->priority);
	  clib_json_add_string (&j, "description", "%s", p->desc);
	  clib_json_parent (&j);
	}
      clib_json_parent (&j);
      return cli_emit_table (ctx, &j, crypto_engines_columns);
    }

  if (vec_len (cm->engines) == 0)
    {
      vlib_cli_output (vm, "No crypto engines registered");
      return 0;
    }

  vlib_cli_output (vm, "%-20s%-8s%s", "Name", "Prio", "Description");
  vec_foreach (p, cm->engines)
    {
      if (p->name)
	vlib_cli_output (vm, "%-20s%-8u%s", p->name, p->priority, p->desc);
    }
  return 0;
}

VLIB_CLI_COMMAND (show_crypto_engines_command, static) = {
  .path = "show crypto engines",
  .short_help = "show crypto engines",
  .handler = show_crypto_engines_command_fn,
  .is_structured = 1,
};

static clib_error_t *
show_crypto_handlers_json (cli_ctx_t *ctx)
{
  static char *keys[] = { "simple", "chained", "async" };
  static char *active_keys[] = { "simple_active", "chained_active", "async_active" };
  vnet_crypto_main_t *cm = &crypto_main;
  clib_json_text_t j;

  clib_json_init (&j);
  clib_json_add_array (&j, 0);
  FOREACH_ARRAY_ELT (a, cm->algs)
    {
      u32 alg = a - cm->algs;

      if (a == cm->algs)
	continue;

      for (u32 i = 0; i < VNET_CRYPTO_OP_N_TYPES; i++)
	{
	  if (!vnet_crypto_alg_has_op_type (alg, i))
	    continue;

	  clib_json_add_object (&j, 0);
	  clib_json_add_string (&j, "algorithm", "%s", a->name);
	  clib_json_add_string (&j, "op", "%U", format_crypto_op_type_short, i);
	  for (vnet_crypto_handler_type_t ht = 0; ht < VNET_CRYPTO_HANDLER_N_TYPES; ht++)
	    {
	      vnet_crypto_engine_t *e;

	      clib_json_add_array (&j, keys[ht]);
	      vec_foreach (e, cm->engines)
		if (e->ops[alg][i].handlers[ht])
		  clib_json_add_string (&j, 0, "%s", e->name);
	      clib_json_parent (&j);

	      crypto_cli_json_add_engine (&j, active_keys[ht],
					  cm->active_op_engine_index[alg][i][ht]);
	    }
	  crypto_cli_json_add_engine (&j, "async_selected", cm->async_selected_engine_index[alg]);
	  clib_json_parent (&j);
	}
    }
  clib_json_parent (&j);

  return cli_emit_table (ctx, &j, crypto_handlers_columns);
}

static clib_error_t *
show_crypto_handlers_command_fn (vlib_main_t *vm, cli_ctx_t *ctx)
{
  vnet_crypto_main_t *cm = &crypto_main;
  table_t table = { .no_ansi = ctx->plain_text_only }, *t = &table;
  u8 *cell = 0;
  u8 *s = 0;
  int row = 0;

  if (cli_is_structured (ctx))
    return show_crypto_handlers_json (ctx);

  table_add_hdr_col (t, 0);
  table_add_hdr_row (t, 5, "Algorithm", "Op", "Simple", "Chained", "Async");
  for (int i = -1; i <= 3; i++)
    table_set_cell_align (t, -1, i, TTAA_LEFT);

  FOREACH_ARRAY_ELT (a, cm->algs)
    {
      int first = 1;

      if (a == cm->algs)
	continue;

      for (u32 i = 0; i < VNET_CRYPTO_OP_N_TYPES; i++)
	if (vnet_crypto_alg_has_op_type (a - cm->algs, i))
	  {
	    vnet_crypto_handler_type_t ht;

	    table_format_cell (t, row, -1, first ? "%s" : "", a->name);
	    table_format_cell (t, row, 0, "%U", format_crypto_op_type_short, i);
	    first = 0;

	    for (ht = 0; ht < VNET_CRYPTO_HANDLER_N_TYPES; ht++)
	      {
		vnet_crypto_engine_t *e;

		vec_foreach (e, cm->engines)
		  {
		    if (e->ops[a - cm->algs][i].handlers[ht])
		      {
			if (vec_len (cell))
			  cell = format (cell, " ");
			if ((e - cm->engines) == cm->active_op_engine_index[a - cm->algs][i][ht])
			  {
			    if (ctx->plain_text_only)
			      cell = format (cell, "%s*", e->name);
			    else
			      cell = format (cell, ANSI_FG_CYAN "%s*" ANSI_RESET, e->name);
			  }
			else
			  cell = format (cell, "%s", e->name);
			if (ht == VNET_CRYPTO_HANDLER_TYPE_ASYNC &&
			    (e - cm->engines) == cm->async_selected_engine_index[a - cm->algs])
			  cell = format (cell, "+");
		      }
		  }

		if (vec_len (cell))
		  table_format_cell (t, row, 1 + ht,
				     ht == VNET_CRYPTO_HANDLER_TYPE_ASYNC ? "%v" : "%v  ", cell);
		else
		  table_format_cell (t, row, 1 + ht,
				     ht == VNET_CRYPTO_HANDLER_TYPE_ASYNC ? "%s" : "%s  ", "-");
		vec_reset_length (cell);
	      }

	    for (int i = -1; i <= 3; i++)
	      table_set_cell_align (t, row, i, TTAA_LEFT);
	    row++;
	  }
    }
  s = format (s, "%U", format_table, t);
  vlib_cli_output (vm, "%v", s);
  vlib_cli_output (vm, "* active, + selected with 'set crypto handler ... async'");
  table_free (t);
  vec_free (cell);
  vec_free (s);

  return 0;
}

VLIB_CLI_COMMAND (show_crypto_handlers_command, static) = {
  .path = "show crypto handlers",
  .short_help = "show crypto handlers",
  .handler = show_crypto_handlers_command_fn,
  .is_structured = 1,
};

static clib_error_t *
set_crypto_handler_command_fn (vlib_main_t *vm, cli_ctx_t *ctx)
{
  vnet_crypto_main_t *cm = &crypto_main;
  int rc = 0, all = cli_flag (ctx, "all");
  char **args = 0, **arg;
  clib_error_t *error = 0;
  vnet_crypto_set_handlers_args_t ha = {
    .set_simple = cli_flag (ctx, "simple") || cli_flag (ctx, "both"),
    .set_chained = cli_flag (ctx, "chained") || cli_flag (ctx, "both"),
    .set_async = cli_flag (ctx, "async"),
  };
  cli_value_t *v;

  cli_foreach (v, ctx, "name") vec_add1 (args, (char *) format (0, "%v%c", v->str, 0));

  if ((vec_len (args) < 2 && !all) || (vec_len (args) == 0 && all))
    {
      error = clib_error_return (0, "missing cipher or engine!");
      goto done;
    }

  ha.engine = vec_elt_at_index (args, vec_len (args) - 1)[0];
  vec_del1 (args, vec_len (args) - 1);

  if (all)
    {
      char *key;
      u8 *value;

      hash_foreach_mem (key, value, cm->alg_index_by_name, ({
			  (void) value;
			  ha.handler_name = key;
			  rc += vnet_crypto_set_handlers (&ha);
			}));

      if (rc)
	vlib_cli_output (vm, "failed to set crypto engine!");
    }
  else
    {
      vec_foreach (arg, args)
	{
	  ha.handler_name = arg[0];
	  rc = vnet_crypto_set_handlers (&ha);
	  if (rc)
	    vlib_cli_output (vm, "failed to set engine %s for %s!", ha.engine, arg[0]);
	}
    }

done:
  vec_free (ha.engine);
  vec_foreach (arg, args) vec_free (arg[0]);
  vec_free (args);
  return error;
}

VLIB_CLI_COMMAND (set_crypto_handler_command, static) = {
  .path = "set crypto handler",
  .short_help = "set crypto handler cipher [cipher2 cipher3 ...] engine"
		" [simple|chained|async]",
  .args = CLI_ARGS (CLI_FLAG ("all", .help = "all the algorithms, only the engine is given"),
		    CLI_FLAG ("simple", .help = "simple handlers"),
		    CLI_FLAG ("chained", .help = "chained handlers"),
		    CLI_FLAG ("both", .help = "simple and chained handlers"),
		    CLI_FLAG ("async", .help = "async handlers"),
		    CLI_VALUE ("name", cli_type_crypto_name, .flags = CLI_F_OPTIONAL | CLI_F_REPEAT,
			       .help = "algorithms, the last name is the engine")),
  .handler = set_crypto_handler_command_fn,
};

static clib_error_t *
show_crypto_async_status_command_fn (vlib_main_t *vm, cli_ctx_t *ctx)
{
  static const char *state_names[] = {
    [VLIB_NODE_STATE_POLLING] = "POLLING",
    [VLIB_NODE_STATE_INTERRUPT] = "INTERRUPT",
    [VLIB_NODE_STATE_DISABLED] = "DISABLED",
  };
  static const char *json_state_names[] = {
    [VLIB_NODE_STATE_POLLING] = "polling",
    [VLIB_NODE_STATE_INTERRUPT] = "interrupt",
    [VLIB_NODE_STATE_DISABLED] = "disabled",
  };
  vnet_crypto_main_t *cm = &crypto_main;
  vnet_crypto_engine_t *e;
  clib_json_text_t j;
  int structured = cli_is_structured (ctx);

  if (structured)
    {
      clib_json_init (&j);
      clib_json_add_array (&j, 0);
    }

  vec_foreach (e, cm->engines)
    {
      if (e->deq_node_index == ~0)
	continue;

      if (!structured)
	vlib_cli_output (vm, "%s:", e->name);
      for (u32 i = 0; i < vlib_get_n_threads (); i++)
	{
	  vlib_node_state_t state =
	    vlib_node_get_state (vlib_get_main_by_index (i), e->deq_node_index);

	  if (structured)
	    {
	      clib_json_add_object (&j, 0);
	      clib_json_add_string (&j, "engine", "%s", e->name);
	      clib_json_add_number (&j, "thread", i);
	      clib_json_add_string (&j, "state", "%s", json_state_names[state]);
	      clib_json_parent (&j);
	    }
	  else
	    vlib_cli_output (vm, "  threadId: %-6d %s", i, state_names[state]);
	}
    }

  if (structured)
    {
      clib_json_parent (&j);
      return cli_emit_table (ctx, &j, crypto_async_status_columns);
    }

  return 0;
}

VLIB_CLI_COMMAND (show_crypto_async_status_command, static) = {
  .path = "show crypto async status",
  .short_help = "show crypto async status",
  .handler = show_crypto_async_status_command_fn,
  .is_structured = 1,
};
