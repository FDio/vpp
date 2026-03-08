/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019-2026 Cisco and/or its affiliates.
 */

#include <vlib/vlib.h>
#include <vppinfra/time.h>
#include <vppinfra/cache.h>
#include <vppinfra/error.h>
#include <vppinfra/format_table.h>
#include <vlib/unix/unix.h>
#include <vnet/crypto/crypto.h>
#include <unittest/crypto/crypto.h>

crypto_test_main_t crypto_test_main;

VLIB_REGISTER_LOG_CLASS (log, static) = {
  .class_name = "unittest",
  .subclass_name = "crypto",
};

#define log_err(dev, f, ...) vlib_log (VLIB_LOG_LEVEL_ERR, log.class, f, ##__VA_ARGS__)

typedef struct
{
  u32 ok[2];
  u32 fail[2];
  u32 error[2];
  u32 not_supported[2];
} crypto_test_engine_summary_t;

typedef enum
{
  CRYPTO_TEST_RESULT_OK,
  CRYPTO_TEST_RESULT_FAIL,
  CRYPTO_TEST_RESULT_ERROR,
  CRYPTO_TEST_RESULT_NOT_SUPPORTED,
} crypto_test_result_t;

typedef struct
{
  unittest_crypto_test_registration_t *reg;
  vnet_crypto_alg_t alg;
  vnet_crypto_op_type_t type;
  u8 is_chained;
  u8 is_hash;
} crypto_test_result_row_t;

typedef struct
{
  crypto_test_result_row_t *rows;
  crypto_test_result_t **results;
  vnet_crypto_engine_id_t *engines;
  crypto_test_engine_summary_t *summaries;
} crypto_test_result_table_t;

typedef int (crypto_test_engine_has_rows_fn_t) (crypto_test_result_row_t *rows,
						vnet_crypto_engine_id_t engine);
typedef clib_error_t *(crypto_test_run_engine_fn_t) (vlib_main_t *vm, crypto_test_main_t *tm,
						     vnet_crypto_engine_id_t engine,
						     crypto_test_result_table_t *results);

static void
crypto_test_result_format (crypto_test_result_t result, char **text, table_text_attr_color_t *color)
{
  *text = " -- ";
  *color = TTAC_WHITE;

  switch (result)
    {
    case CRYPTO_TEST_RESULT_OK:
      *text = " OK ";
      *color = TTAC_GREEN;
      break;
    case CRYPTO_TEST_RESULT_FAIL:
      *text = "FAIL";
      *color = TTAC_RED;
      break;
    case CRYPTO_TEST_RESULT_ERROR:
      *text = "ERR ";
      *color = TTAC_RED;
      break;
    case CRYPTO_TEST_RESULT_NOT_SUPPORTED:
      break;
    }
}

static_always_inline int
crypto_test_reg_has_op_type (unittest_crypto_test_registration_t *r, vnet_crypto_op_type_t type)
{
  switch (type)
    {
    case VNET_CRYPTO_OP_TYPE_HMAC:
      return r->digest.length != 0;
    case VNET_CRYPTO_OP_TYPE_ENCRYPT:
    case VNET_CRYPTO_OP_TYPE_DECRYPT:
      return 1;
    case VNET_CRYPTO_OP_N_TYPES:
      return 0;
    }

  return 0;
}

static_always_inline unittest_crypto_test_data_t *
crypto_test_digest_data (unittest_crypto_test_registration_t *r, vnet_crypto_op_type_t type)
{
  return &r->digest;
}

static vnet_crypto_hash_alg_t
crypto_test_get_hash_alg (vnet_crypto_alg_t alg)
{
  vnet_crypto_main_t *cm = &crypto_main;
  vnet_crypto_hash_alg_t hash_alg;

  for (hash_alg = 1; hash_alg < VNET_CRYPTO_N_HASH_ALGS; hash_alg++)
    if (cm->hash_algs[hash_alg].alg == alg)
      return hash_alg;

  return VNET_CRYPTO_HASH_ALG_NONE;
}

static_always_inline int
crypto_test_reg_matches_alg (crypto_test_main_t *tm, unittest_crypto_test_registration_t *r)
{
  return tm->has_alg_filter == 0 || r->alg == tm->alg;
}

static_always_inline vnet_crypto_op_type_t
crypto_test_first_op_type (vnet_crypto_alg_t alg)
{
  int i;

  for (i = 0; i < VNET_CRYPTO_OP_N_TYPES; i++)
    if (vnet_crypto_alg_has_op_type (alg, i))
      return i;

  return VNET_CRYPTO_OP_N_TYPES;
}

static_always_inline int
crypto_test_op_has_digest (vnet_crypto_alg_data_t *ad, vnet_crypto_op_type_t type)
{
  return ad->alg_type == VNET_CRYPTO_ALG_T_COMBINED || type == VNET_CRYPTO_OP_TYPE_HMAC;
}

static void
crypto_test_result_table_format_cell (table_t *t, int row, int col, crypto_test_result_t result)
{
  table_cell_t *cell;
  table_text_attr_color_t color;
  char *text;

  crypto_test_result_format (result, &text, &color);
  table_format_cell (t, row, col, "%s", text);
  table_set_cell_align (t, row, col, TTAA_CENTER);

  if (result == CRYPTO_TEST_RESULT_NOT_SUPPORTED)
    {
      cell = &t->cells[row + t->n_header_cols][col + t->n_header_rows];
      cell->attr.flags |= TTAF_DIM;
    }
  else
    table_set_cell_fg_color (t, row, col, color);
}

static int
sort_registrations (void *a0, void *a1)
{
  unittest_crypto_test_registration_t **r0 = a0;
  unittest_crypto_test_registration_t **r1 = a1;

  return strncmp (r0[0]->name, r1[0]->name, 256);
}

static int
sort_result_rows (void *a0, void *a1)
{
  crypto_test_result_row_t *r0 = a0;
  crypto_test_result_row_t *r1 = a1;

  if (r0->reg == r1->reg && r0->alg == r1->alg && r0->type == r1->type &&
      r0->is_hash == r1->is_hash)
    return r0->is_chained - r1->is_chained;

  if (r0->reg == r1->reg)
    {
      if (r0->alg != r1->alg)
	return r0->alg - r1->alg;
      if (r0->is_hash != r1->is_hash)
	return r0->is_hash - r1->is_hash;
      return r0->type - r1->type;
    }

  return strncmp (r0->reg->name, r1->reg->name, 256);
}

static int
crypto_test_result_table_find_row (crypto_test_result_table_t *rt,
				   unittest_crypto_test_registration_t *r, vnet_crypto_alg_t alg,
				   vnet_crypto_op_type_t type, u8 is_chained, u8 is_hash)
{
  crypto_test_result_row_t *row;
  int i;

  vec_foreach_index (i, rt->rows)
    {
      row = vec_elt_at_index (rt->rows, i);
      if (row->reg == r && row->alg == alg && row->type == type && row->is_chained == is_chained &&
	  row->is_hash == is_hash)
	return i;
    }

  return -1;
}

static int
crypto_test_result_table_find_engine_col (crypto_test_result_table_t *rt,
					  vnet_crypto_engine_id_t engine)
{
  int i;

  vec_foreach_index (i, rt->engines)
    if (rt->engines[i] == engine)
      return i;

  return -1;
}

static void
crypto_test_result_table_set (crypto_test_result_table_t *rt, vnet_crypto_engine_id_t engine,
			      unittest_crypto_test_registration_t *r, vnet_crypto_alg_t alg,
			      vnet_crypto_op_type_t type, u8 is_chained, u8 is_hash,
			      crypto_test_result_t result)
{
  int row, col;

  if (rt == 0)
    return;

  row = crypto_test_result_table_find_row (rt, r, alg, type, is_chained, is_hash);
  col = crypto_test_result_table_find_engine_col (rt, engine);

  if (row < 0 || col < 0)
    return;

  rt->results[row][col] = result;
}

static void
crypto_test_result_table_free (crypto_test_result_table_t *rt)
{
  vec_free (rt->rows);
  vec_free (rt->engines);
  vec_free (rt->results);
  vec_free (rt->summaries);
}

static void
crypto_test_result_table_init_engines (crypto_test_result_table_t *rt, crypto_test_main_t *tm)
{
  vnet_crypto_main_t *cm = &crypto_main;
  int i;

  if (tm->engine)
    vec_add1 (rt->engines, vnet_crypto_get_engine_index_by_name ("%s", tm->engine));
  else
    for (i = 1; i < vec_len (cm->engines); i++)
      vec_add1 (rt->engines, i);
}

static void
crypto_test_result_table_filter_engines (crypto_test_result_table_t *rt,
					 crypto_test_engine_has_rows_fn_t *fn)
{
  vnet_crypto_engine_id_t *engines = 0;
  int i;

  vec_foreach_index (i, rt->engines)
    if (fn (rt->rows, rt->engines[i]))
      vec_add1 (engines, rt->engines[i]);

  vec_free (rt->engines);
  rt->engines = engines;
}

static void
crypto_test_result_table_init_storage (crypto_test_result_table_t *rt)
{
  int i, j;

  if (vec_len (rt->rows))
    vec_validate (rt->results, vec_len (rt->rows) - 1);
  if (vec_len (rt->engines))
    vec_validate (rt->summaries, vec_len (rt->engines) - 1);

  vec_foreach_index (i, rt->rows)
    {
      if (vec_len (rt->engines))
	vec_validate (rt->results[i], vec_len (rt->engines) - 1);
      vec_foreach_index (j, rt->engines)
	rt->results[i][j] = CRYPTO_TEST_RESULT_NOT_SUPPORTED;
    }
}

static clib_error_t *
crypto_test_run_engines (vlib_main_t *vm, crypto_test_main_t *tm, vnet_crypto_engine_id_t engine,
			 crypto_test_result_table_t *results, crypto_test_run_engine_fn_t *fn)
{
  clib_error_t *err = 0;
  u32 i;

  if (tm->engine)
    return fn (vm, tm, engine, results);

  vec_foreach_index (i, results->engines)
    {
      err = fn (vm, tm, results->engines[i], results);
      if (err)
	break;
    }

  return err;
}

static unittest_crypto_test_registration_t **
crypto_test_collect_regs (crypto_test_main_t *tm, u8 include_incremental)
{
  unittest_crypto_test_registration_t *r = tm->test_registrations;
  unittest_crypto_test_registration_t **regs = 0;

  while (r)
    {
      if (include_incremental || r->plaintext_incremental == 0)
	vec_add1 (regs, r);
      r = r->next;
    }

  vec_sort_with_function (regs, sort_registrations);
  return regs;
}

static void
crypto_test_result_table_add_reg_rows (crypto_test_result_table_t *rt,
				       vnet_crypto_main_t *cm __clib_unused,
				       unittest_crypto_test_registration_t *r, u8 add_chained,
				       u8 add_hash)
{
  int i;
  vnet_crypto_hash_alg_t hash_alg;

  hash_alg = crypto_test_get_hash_alg (r->alg);
  if (add_hash && r->hash.length != 0 && hash_alg != VNET_CRYPTO_HASH_ALG_NONE)
    {
      vec_add1 (rt->rows, ((crypto_test_result_row_t){
			    .reg = r,
			    .alg = r->alg,
			    .type = 0,
			    .is_chained = 0,
			    .is_hash = 1,
			  }));

      if (add_chained)
	vec_add1 (rt->rows, ((crypto_test_result_row_t){
			      .reg = r,
			      .alg = r->alg,
			      .type = 0,
			      .is_chained = 1,
			      .is_hash = 1,
			    }));
    }

  for (i = 0; i < VNET_CRYPTO_OP_N_TYPES; i++)
    {
      if (!crypto_test_reg_has_op_type (r, i) || !vnet_crypto_alg_has_op_type (r->alg, i))
	continue;

      vec_add1 (rt->rows, ((crypto_test_result_row_t){
			    .reg = r,
			    .alg = r->alg,
			    .type = i,
			    .is_chained = 0,
			    .is_hash = 0,
			  }));

      if (add_chained)
	vec_add1 (rt->rows, ((crypto_test_result_row_t){
			      .reg = r,
			      .alg = r->alg,
			      .type = i,
			      .is_chained = 1,
			      .is_hash = 0,
			    }));
    }
}

static_always_inline void crypto_test_append_data_chunks (vnet_crypto_op_chunk_t **chunks, u8 *data,
							  u32 data_len);

static int
crypto_test_engine_has_sync_rows (crypto_test_result_row_t *rows, vnet_crypto_engine_id_t engine)
{
  vnet_crypto_main_t *cm = &crypto_main;
  vnet_crypto_engine_t *e = vec_elt_at_index (cm->engines, engine);
  crypto_test_result_row_t *row;
  vnet_crypto_handler_type_t ht;
  vnet_crypto_hash_alg_t hash_alg;

  vec_foreach (row, rows)
    {
      ht = row->is_chained ? VNET_CRYPTO_HANDLER_TYPE_CHAINED : VNET_CRYPTO_HANDLER_TYPE_SIMPLE;
      if (row->is_hash)
	{
	  hash_alg = crypto_test_get_hash_alg (row->alg);
	  if (hash_alg != VNET_CRYPTO_HASH_ALG_NONE && e->hash_ops[hash_alg].handlers[ht] != 0)
	    return 1;
	}
      else if (e->ops[row->alg][row->type].handlers[ht] != 0)
	return 1;
    }

  return 0;
}

static void
crypto_test_sync_result_table_init (crypto_test_result_table_t *rt, crypto_test_main_t *tm)
{
  vnet_crypto_main_t *cm = &crypto_main;
  unittest_crypto_test_registration_t **regs = 0;
  int i;

  *rt = (crypto_test_result_table_t){};
  crypto_test_result_table_init_engines (rt, tm);
  regs = crypto_test_collect_regs (tm, 1);

  vec_foreach_index (i, regs)
    {
      if (!crypto_test_reg_matches_alg (tm, regs[i]))
	continue;

      crypto_test_result_table_add_reg_rows (rt, cm, regs[i], regs[i]->plaintext_incremental == 0,
					     1);
    }

  vec_sort_with_function (rt->rows, sort_result_rows);

  if (!tm->engine)
    crypto_test_result_table_filter_engines (rt, crypto_test_engine_has_sync_rows);

  crypto_test_result_table_init_storage (rt);

  vec_free (regs);
}

static void
crypto_test_result_table_print (vlib_main_t *vm, crypto_test_result_table_t *rt, int failures_only)
{
  unix_main_t *um = vlib_unix_get_main ();
  vnet_crypto_main_t *cm = &crypto_main;
  table_t t = {
    .no_ansi = (um->flags & UNIX_FLAG_NOCOLOR) != 0,
  };
  crypto_test_result_row_t *prev_row = 0, *row;
  u8 *s = 0;
  int i, j;

  table_add_hdr_row (&t, 3, "", "", "");
  table_add_hdr_row (&t, 3, "Name", "Algorithm", "Type");
  table_add_hdr_col (&t, 0);
  for (i = -2; i <= -1; i++)
    {
      table_set_cell_align (&t, i, -1, TTAA_LEFT);
      table_set_cell_align (&t, i, 0, TTAA_LEFT);
      table_set_cell_align (&t, i, 1, TTAA_LEFT);
    }

  vec_foreach_index (i, rt->engines)
    {
      int col;
      u8 is_chained;

      for (is_chained = 0; is_chained <= 1; is_chained++)
	{
	  col = 2 + 2 * i + is_chained;
	  table_format_cell (&t, -2, col, is_chained ? "" : "%u", rt->engines[i]);
	  table_format_cell (&t, -1, col, "%s", is_chained ? "Chained" : "Simple");
	  table_set_cell_align (&t, -2, col, TTAA_CENTER);
	  table_set_cell_align (&t, -1, col, TTAA_CENTER);
	}
    }

  j = 0;
  vec_foreach_index (i, rt->rows)
    {
      crypto_test_result_t simple;
      int has_fail = 0;
      int k;

      row = vec_elt_at_index (rt->rows, i);
      if (row->is_chained)
	continue;

      vec_foreach_index (k, rt->engines)
	{
	  int chained_row;

	  if (rt->results[i][k] == CRYPTO_TEST_RESULT_FAIL ||
	      rt->results[i][k] == CRYPTO_TEST_RESULT_ERROR)
	    {
	      has_fail = 1;
	      break;
	    }

	  chained_row =
	    crypto_test_result_table_find_row (rt, row->reg, row->alg, row->type, 1, row->is_hash);
	  if (chained_row >= 0 && (rt->results[chained_row][k] == CRYPTO_TEST_RESULT_FAIL ||
				   rt->results[chained_row][k] == CRYPTO_TEST_RESULT_ERROR))
	    {
	      has_fail = 1;
	      break;
	    }
	}

      if (failures_only && has_fail == 0)
	continue;

      if (prev_row && prev_row->reg == row->reg)
	table_format_cell (&t, j, -1, "");
      else
	table_format_cell (&t, j, -1, "%s", row->reg->name);

      if (prev_row && prev_row->reg == row->reg && prev_row->alg == row->alg &&
	  prev_row->is_hash == row->is_hash)
	table_format_cell (&t, j, 0, "");
      else
	table_format_cell (&t, j, 0, "%s",
			   row->is_hash ? cm->hash_algs[crypto_test_get_hash_alg (row->alg)].name :
					  cm->algs[row->alg].name);

      if (row->is_hash)
	table_format_cell (&t, j, 1, "%s", "hash");
      else
	table_format_cell (&t, j, 1, "%U", format_crypto_op_type_short, row->type);
      table_set_cell_align (&t, j, -1, TTAA_LEFT);
      table_set_cell_align (&t, j, 0, TTAA_LEFT);
      table_set_cell_align (&t, j, 1, TTAA_LEFT);

      vec_foreach_index (k, rt->engines)
	{
	  int chained_row;
	  int col;

	  simple = rt->results[i][k];
	  col = 2 + 2 * k;
	  crypto_test_result_table_format_cell (&t, j, col, simple);

	  chained_row =
	    crypto_test_result_table_find_row (rt, row->reg, row->alg, row->type, 1, row->is_hash);
	  col = 3 + 2 * k;
	  if (chained_row >= 0)
	    crypto_test_result_table_format_cell (&t, j, col, rt->results[chained_row][k]);
	  else
	    {
	      table_format_cell (&t, j, col, "");
	      table_set_cell_align (&t, j, col, TTAA_CENTER);
	    }
	}

      prev_row = row;
      j++;
    }

  if (j == 0)
    {
      table_free (&t);
      return;
    }

  s = format (s, "\n%U", format_table, &t);
  vlib_cli_output (vm, "%v", s);
  vec_free (s);
  table_free (&t);
}

static void
crypto_test_summary_table_print (vlib_main_t *vm, crypto_test_result_table_t *rt, char *title)
{
  unix_main_t *um = vlib_unix_get_main ();
  table_t t = {
    .no_ansi = (um->flags & UNIX_FLAG_NOCOLOR) != 0,
  };
  crypto_test_engine_summary_t *summary;
  static const char *mode_labels[] = {
    "Simple",
    "Chained",
  };
  static const char *metric_labels[] = {
    "OK",
    "Fail",
    "Error",
    "Not Supported",
  };
  u8 *s = 0;
  int i;

  table_format_title (&t, "%s", title);
  table_add_hdr_row (&t, 10, "", "", "", mode_labels[0], "", "", "", mode_labels[1], "", "", "");
  table_add_hdr_row (&t, 10, "ID", "Engine", metric_labels[0], metric_labels[1], metric_labels[2],
		     metric_labels[3], metric_labels[0], metric_labels[1], metric_labels[2],
		     metric_labels[3]);

  for (i = -2; i <= -1; i++)
    {
      int j;

      table_set_cell_align (&t, i, 0, TTAA_RIGHT);
      table_set_cell_align (&t, i, 1, TTAA_LEFT);
      for (j = 2; j < 10; j++)
	table_set_cell_align (&t, i, j, i == -2 ? TTAA_CENTER : TTAA_RIGHT);
    }

  vec_foreach_index (i, rt->engines)
    {
      int j;

      summary = vec_elt_at_index (rt->summaries, i);
      table_format_cell (&t, i, 0, "%u", rt->engines[i]);
      table_format_cell (&t, i, 1, "%U", format_vnet_crypto_engine, rt->engines[i]);
      table_format_cell (&t, i, 2, "%u", summary->ok[0]);
      table_format_cell (&t, i, 3, "%u", summary->fail[0]);
      table_format_cell (&t, i, 4, "%u", summary->error[0]);
      table_format_cell (&t, i, 5, "%u", summary->not_supported[0]);
      table_format_cell (&t, i, 6, "%u", summary->ok[1]);
      table_format_cell (&t, i, 7, "%u", summary->fail[1]);
      table_format_cell (&t, i, 8, "%u", summary->error[1]);
      table_format_cell (&t, i, 9, "%u", summary->not_supported[1]);

      table_set_cell_align (&t, i, 0, TTAA_RIGHT);
      table_set_cell_align (&t, i, 1, TTAA_LEFT);
      for (j = 2; j < 10; j++)
	table_set_cell_align (&t, i, j, TTAA_RIGHT);
    }

  s = format (s, "\n%U", format_table, &t);
  vlib_cli_output (vm, "%v", s);
  vec_free (s);
  table_free (&t);
}

static int
crypto_test_has_failures (crypto_test_result_table_t *rt)
{
  crypto_test_engine_summary_t *summary;

  vec_foreach (summary, rt->summaries)
    if (summary->fail[0] || summary->fail[1] || summary->error[0] || summary->error[1])
      return 1;

  return 0;
}

static void
crypto_test_print_not_supported (unittest_crypto_test_registration_t *r, vnet_crypto_alg_t alg,
				 vnet_crypto_op_type_t type, u8 is_chained,
				 crypto_test_engine_summary_t *summary,
				 vnet_crypto_engine_id_t engine,
				 crypto_test_result_table_t *results)
{
  summary->not_supported[is_chained]++;
  crypto_test_result_table_set (results, engine, r, alg, type, is_chained, 0,
				CRYPTO_TEST_RESULT_NOT_SUPPORTED);
}

static void
print_results (unittest_crypto_test_registration_t **rv, vnet_crypto_op_t *ops,
	       vnet_crypto_op_chunk_t *chunks, u32 n_ops, crypto_test_main_t *tm,
	       crypto_test_engine_summary_t *summary, vnet_crypto_engine_id_t engine,
	       crypto_test_result_table_t *results)
{
  vnet_crypto_main_t *cm = &crypto_main;
  char *engine_name = vec_elt_at_index (cm->engines, engine)->name;
  int i;
  unittest_crypto_test_registration_t *r;
  vnet_crypto_op_chunk_t *chp;
  u8 *err = 0;
  vnet_crypto_op_t *op;
  u32 op_index;

  for (op_index = 0; op_index < n_ops; op_index++)
    {
      op = ops + op_index;
      int fail = 0;
      r = rv[op->user_data];
      u32 is_chained = (op->flags & VNET_CRYPTO_OP_FLAG_CHAINED_BUFFERS) != 0;
      unittest_crypto_test_data_t *exp_pt = 0, *exp_ct = 0, exp_pt_data;
      unittest_crypto_test_data_t *exp_digest = 0, *exp_tag = 0;
      vnet_crypto_alg_data_t *ad;

      ASSERT (op->ctx != 0);
      ad = cm->algs + op->ctx->alg;

      switch (op->type)
	{
	case VNET_CRYPTO_OP_TYPE_ENCRYPT:
	  exp_ct = &r->ciphertext;
	  if (ad->alg_type == VNET_CRYPTO_ALG_T_AEAD)
	    exp_tag = &r->tag;
	  else if (ad->alg_type == VNET_CRYPTO_ALG_T_COMBINED)
	    exp_digest = &r->digest;
	  break;
	case VNET_CRYPTO_OP_TYPE_DECRYPT:
	  if (r->plaintext_incremental)
	    {
	      exp_pt_data.length = r->plaintext_incremental;
	      exp_pt_data.data = tm->inc_data;
	      exp_pt = &exp_pt_data;
	    }
	  else
	    exp_pt = &r->plaintext;
	  break;
	case VNET_CRYPTO_OP_TYPE_HMAC:
	  exp_digest = &r->digest;
	  break;
	default:
	  ASSERT (0);
	}

      vec_reset_length (err);

      if (op->status != VNET_CRYPTO_OP_STATUS_COMPLETED)
	err = format (err, "%sengine error: %U", vec_len (err) ? ", " : "",
		      format_vnet_crypto_op_status, op->status);

      if (op->flags & VNET_CRYPTO_OP_FLAG_CHAINED_BUFFERS)
	{
	  if (exp_ct)
	    {
	      u32 offset = 0;
	      chp = vec_elt_at_index (chunks, op->chunk_index);
	      for (i = 0; i < op->n_chunks; i++)
		{
		  if (memcmp (chp->dst, exp_ct->data + offset, chp->len))
		    err = format (err, "%sciphertext mismatch [chunk %d]",
				  vec_len (err) ? ", " : "", i);
		  offset += chp->len;
		  chp += 1;
		}
	    }

	  if (exp_pt)
	    {
	      u32 offset = 0;
	      chp = vec_elt_at_index (chunks, op->chunk_index);
	      for (i = 0; i < op->n_chunks; i++)
		{
		  if (memcmp (chp->dst, exp_pt->data + offset, chp->len))
		    err =
		      format (err, "%splaintext mismatch [chunk %d]", vec_len (err) ? ", " : "", i);
		  offset += chp->len;
		  chp += 1;
		}
	    }
	}
      else
	{
	  if (exp_ct && memcmp (op->dst, exp_ct->data, exp_ct->length) != 0)
	    err = format (err, "%sciphertext mismatch", vec_len (err) ? ", " : "");

	  if (exp_pt && memcmp (op->dst, exp_pt->data, exp_pt->length) != 0)
	    err = format (err, "%splaintext mismatch", vec_len (err) ? ", " : "");
	}

      if (exp_tag && memcmp (op->auth, exp_tag->data, exp_tag->length) != 0)
	err = format (err, "%stag mismatch", vec_len (err) ? ", " : "");

      if (exp_digest && memcmp (op->auth, exp_digest->data, exp_digest->length) != 0)
	err = format (err, "%sdigest mismatch", vec_len (err) ? ", " : "");

      if (vec_len (err))
	fail = 1;

      if (fail)
	log_err (0, "%s %s %U-%U %s: %v", engine_name, r->name, format_crypto_op_type_short,
		 op->type, format_vnet_crypto_alg, op->ctx->alg, is_chained ? "chained" : "simple",
		 err);

      if (fail)
	summary->fail[is_chained]++;
      else
	summary->ok[is_chained]++;

      crypto_test_result_table_set (results, engine, r, op->ctx->alg, op->type, is_chained, 0,
				    fail ? CRYPTO_TEST_RESULT_FAIL : CRYPTO_TEST_RESULT_OK);
    }
  vec_free (err);
}

static int
crypto_test_hash_op_supported (vnet_crypto_engine_id_t engine,
			       unittest_crypto_test_registration_t *r, u8 is_chained)
{
  vnet_crypto_main_t *cm = &crypto_main;
  vnet_crypto_engine_t *e = vec_elt_at_index (cm->engines, engine);
  vnet_crypto_handler_type_t ht;
  vnet_crypto_hash_alg_t hash_alg;

  hash_alg = crypto_test_get_hash_alg (r->alg);
  if (hash_alg == VNET_CRYPTO_HASH_ALG_NONE || r->hash.length == 0)
    return 0;

  ht = is_chained ? VNET_CRYPTO_HANDLER_TYPE_CHAINED : VNET_CRYPTO_HANDLER_TYPE_SIMPLE;
  return e->hash_ops[hash_alg].handlers[ht] != 0;
}

static void
print_hash_results (unittest_crypto_test_registration_t **rv, vnet_crypto_hash_op_t *ops, u32 n_ops,
		    crypto_test_engine_summary_t *summary, vnet_crypto_engine_id_t engine,
		    crypto_test_result_table_t *results)
{
  vnet_crypto_main_t *cm = &crypto_main;
  char *engine_name = vec_elt_at_index (cm->engines, engine)->name;
  unittest_crypto_test_registration_t *r;
  vnet_crypto_hash_op_t *op;
  u32 op_index;

  for (op_index = 0; op_index < n_ops; op_index++)
    {
      int fail = 0;
      u32 is_chained;

      op = ops + op_index;
      r = rv[op->user_data];
      is_chained = (op->flags & VNET_CRYPTO_OP_FLAG_CHAINED_BUFFERS) != 0;

      if (op->status != VNET_CRYPTO_OP_STATUS_COMPLETED ||
	  memcmp (op->digest, r->hash.data, r->hash.length) != 0)
	fail = 1;

      if (fail)
	log_err (0, "%s %s hash-%U %s: %s", engine_name, r->name, format_vnet_crypto_hash_alg,
		 op->ctx->alg, is_chained ? "chained" : "simple",
		 op->status != VNET_CRYPTO_OP_STATUS_COMPLETED ? "engine error" :
								 "digest mismatch");

      if (fail)
	summary->fail[is_chained]++;
      else
	summary->ok[is_chained]++;

      crypto_test_result_table_set (results, engine, r, r->alg, 0, is_chained, 1,
				    fail ? CRYPTO_TEST_RESULT_FAIL : CRYPTO_TEST_RESULT_OK);
    }
}

static clib_error_t *
test_crypto_hash_static (vlib_main_t *vm, unittest_crypto_test_registration_t **rv, u32 n_ops,
			 u32 n_chained_ops, u32 computed_data_total_len,
			 vnet_crypto_engine_id_t engine, crypto_test_engine_summary_t *summary,
			 crypto_test_result_table_t *results)
{
  vnet_crypto_hash_ctx_t **ctxs = 0;
  vnet_crypto_op_chunk_t *chunks = 0;
  unittest_crypto_test_registration_t *r;
  vnet_crypto_hash_op_t *ops = 0, *op;
  vnet_crypto_hash_op_t *current_chained_op, *current_op;
  u8 *computed_data = 0;
  u32 i;

  if (n_ops == 0 && n_chained_ops == 0)
    return 0;

  vec_sort_with_function (rv, sort_registrations);

  if (computed_data_total_len)
    vec_validate_aligned (computed_data, computed_data_total_len - 1, CLIB_CACHE_LINE_BYTES);
  if (n_ops + n_chained_ops)
    vec_validate_aligned (ops, n_ops + n_chained_ops - 1, CLIB_CACHE_LINE_BYTES);

  current_op = ops;
  current_chained_op = ops + n_ops;
  computed_data_total_len = 0;

  vec_foreach_index (i, rv)
    {
      u32 is_chained;
      vnet_crypto_hash_alg_t hash_alg;

      r = rv[i];
      hash_alg = crypto_test_get_hash_alg (r->alg);
      if (r->hash.length == 0 || hash_alg == VNET_CRYPTO_HASH_ALG_NONE)
	continue;

      for (is_chained = 0; is_chained <= 1; is_chained++)
	{
	  if (!crypto_test_hash_op_supported (engine, r, is_chained))
	    continue;

	  op = is_chained ? current_chained_op++ : current_op++;
	  vnet_crypto_hash_op_init (op);
	  op->ctx = vnet_crypto_hash_ctx_create (hash_alg);
	  if (op->ctx == 0)
	    return clib_error_return (0, "hash ctx create failed");
	  vec_add1 (ctxs, op->ctx);
	  vnet_crypto_hash_ctx_set_engine (op->ctx,
					   is_chained ? VNET_CRYPTO_HANDLER_TYPE_CHAINED :
							VNET_CRYPTO_HANDLER_TYPE_SIMPLE,
					   engine);
	  op->digest = computed_data + computed_data_total_len;
	  computed_data_total_len += r->hash.length;
	  op->user_data = i;
	  if (is_chained)
	    {
	      op->flags |= VNET_CRYPTO_OP_FLAG_CHAINED_BUFFERS;
	      op->chunk_index = vec_len (chunks);
	      crypto_test_append_data_chunks (&chunks, r->plaintext.data, r->plaintext.length);
	      op->n_chunks = vec_len (chunks) - op->chunk_index;
	    }
	  else
	    {
	      op->src = r->plaintext.data;
	      op->len = r->plaintext.length;
	    }
	}
    }

  if (vec_len (ops))
    vnet_crypto_process_hash_ops (vm, ops, chunks, vec_len (ops));

  print_hash_results (rv, ops, vec_len (ops), summary, engine, results);

  vec_foreach_index (i, ctxs)
    vnet_crypto_hash_ctx_destroy (ctxs[i]);
  vec_free (ctxs);
  vec_free (computed_data);
  vec_free (ops);
  vec_free (chunks);
  return 0;
}

static void
validate_data (u8 **data, u32 len)
{
  u32 i, diff, old_len;
  if (vec_len (data[0]) >= len)
    return;

  old_len = vec_len (data[0]);
  diff = len - vec_len (data[0]);
  vec_validate (data[0], old_len + diff - 1);
  for (i = old_len; i < len; i++)
    data[0][i] = (u8) i;
}

static int
crypto_test_op_supported (vnet_crypto_engine_id_t engine, unittest_crypto_test_registration_t *r,
			  vnet_crypto_op_type_t type, u8 is_chained)
{
  vnet_crypto_main_t *cm = &crypto_main;
  vnet_crypto_alg_data_t *ad = cm->algs + r->alg;
  vnet_crypto_handler_type_t ht;
  vnet_crypto_engine_t *e = vec_elt_at_index (cm->engines, engine);

  if (!vnet_crypto_alg_has_op_type (r->alg, type))
    return 0;
  if (!crypto_test_reg_has_op_type (r, type))
    return 0;

  ht = is_chained ? VNET_CRYPTO_HANDLER_TYPE_CHAINED : VNET_CRYPTO_HANDLER_TYPE_SIMPLE;
  return e->ops[ad - cm->algs][type].handlers[ht] != 0;
}

static_always_inline u32
crypto_test_chunk_count (u32 len)
{
  if (len <= 1)
    return 1;
  if (len <= 32)
    return 2;

  return 3;
}

static_always_inline u32
crypto_test_chunk_len (u32 total_len, u32 chunk_index, u32 n_chunks)
{
  u32 base = total_len / n_chunks;
  u32 rem = total_len % n_chunks;

  return base + (chunk_index < rem);
}

static_always_inline void
crypto_test_append_data_chunks (vnet_crypto_op_chunk_t **chunks, u8 *data, u32 data_len)
{
  vnet_crypto_op_chunk_t ch = {};
  u32 i, n_chunks, offset = 0;

  n_chunks = crypto_test_chunk_count (data_len);
  for (i = 0; i < n_chunks; i++)
    {
      ch.src = data + offset;
      ch.len = crypto_test_chunk_len (data_len, i, n_chunks);
      vec_add1 (*chunks, ch);
      offset += ch.len;
    }
}

static_always_inline void
crypto_test_append_buffer_chunks (vnet_crypto_op_chunk_t **chunks, u8 *data, u32 data_len,
				  u8 *computed_data, u32 *computed_data_total_len, u16 *n_chunks)
{
  vnet_crypto_op_chunk_t ch = {};
  u32 i, split_chunks, offset = 0;

  split_chunks = crypto_test_chunk_count (data_len);
  for (i = 0; i < split_chunks; i++)
    {
      ch.src = data + offset;
      ch.len = crypto_test_chunk_len (data_len, i, split_chunks);
      ch.dst = computed_data + *computed_data_total_len;
      *computed_data_total_len += ch.len;
      vec_add1 (*chunks, ch);
      *n_chunks += 1;
      offset += ch.len;
    }
}

static vnet_crypto_ctx_t *
crypto_test_ctx_add_data (vlib_main_t *vm, vnet_crypto_engine_id_t engine, vnet_crypto_alg_t alg,
			  const u8 *key_data, u16 key_len, u8 is_async)
{
  vnet_crypto_main_t *cm = &crypto_main;
  vnet_crypto_alg_data_t *ad = cm->algs + alg;
  vnet_crypto_ctx_t *ctx;

  ctx = vnet_crypto_ctx_create (alg);

  if (ctx == 0)
    return 0;

  if (ad->alg_type == VNET_CRYPTO_ALG_T_COMBINED)
    {
      if (!vnet_crypto_ctx_set_cipher_key (ctx, key_data, ad->cipher_key_len) ||
	  !vnet_crypto_ctx_set_auth_key (ctx, key_data + ad->cipher_key_len,
					 key_len - ad->cipher_key_len))
	{
	  vnet_crypto_ctx_destroy (vm, ctx);
	  return 0;
	}
    }
  else if (ad->alg_type != VNET_CRYPTO_ALG_T_AUTH || key_len != 0)
    {
      if ((ad->alg_type == VNET_CRYPTO_ALG_T_AUTH ?
	     !vnet_crypto_ctx_set_auth_key (ctx, key_data, key_len) :
	     !vnet_crypto_ctx_set_cipher_key (ctx, key_data, key_len)))
	{
	  vnet_crypto_ctx_destroy (vm, ctx);
	  return 0;
	}
    }

  if (is_async)
    vnet_crypto_ctx_set_engine (ctx, VNET_CRYPTO_HANDLER_TYPE_ASYNC, engine);
  else
    {
      vnet_crypto_ctx_set_engine (ctx, VNET_CRYPTO_HANDLER_TYPE_SIMPLE, engine);
      vnet_crypto_ctx_set_engine (ctx, VNET_CRYPTO_HANDLER_TYPE_CHAINED, engine);
    }

  return ctx;
}

static vnet_crypto_ctx_t *
crypto_test_key_add (vlib_main_t *vm, vnet_crypto_engine_id_t engine,
		     unittest_crypto_test_registration_t *r)
{
  return crypto_test_ctx_add_data (vm, engine, r->alg, r->key.data, r->key.length, 0);
}

static clib_error_t *
generate_digest (vlib_main_t *vm, unittest_crypto_test_registration_t *r,
		 vnet_crypto_op_type_t type, vnet_crypto_engine_id_t engine)
{
  crypto_test_main_t *cm = &crypto_test_main;
  vnet_crypto_op_t op[1];
  clib_error_t *err = 0;

  op->ctx = crypto_test_ctx_add_data (vm, engine, r->alg, cm->inc_data, r->key.length, 0);
  if (op->ctx == 0)
    return clib_error_return (0, "failed to add key for digest generation");
  vnet_crypto_op_init (op->ctx, op);
  op->type = type;
  vec_validate (r->digest.data, r->digest.length - 1);
  op->auth_src = cm->inc_data;
  op->auth_src_len = r->plaintext_incremental;
  op->auth = r->digest.data;
  op->auth_len = r->digest.length;

  vnet_crypto_process_ops (vm, op, 0, 1);
  if (op->status != VNET_CRYPTO_OP_STATUS_COMPLETED)
    err = clib_error_return (0, "digest generation failed: %U", format_vnet_crypto_op_status,
			     op->status);

  vnet_crypto_ctx_destroy (vm, op->ctx);
  return err;
}

static clib_error_t *
test_crypto_incremental (vlib_main_t *vm, crypto_test_main_t *tm,
			 unittest_crypto_test_registration_t **rv, u32 n_ops,
			 u32 computed_data_total_len, vnet_crypto_engine_id_t engine,
			 crypto_test_engine_summary_t *summary, crypto_test_result_table_t *results)
{
  vnet_crypto_main_t *cm = &crypto_main;
  vnet_crypto_alg_data_t *ad;
  vnet_crypto_ctx_t **ctxs = 0;
  u32 i;
  u32 n_encrypt_ops = 0;
  u32 n_check_ops = 0;
  unittest_crypto_test_registration_t *r;
  vnet_crypto_op_t *encrypt_ops = 0, *ops = 0, *op;
  u8 *encrypted_data = 0, *decrypted_data = 0;

  if (n_ops == 0)
    return 0;

  vec_validate_aligned (encrypted_data, computed_data_total_len - 1, CLIB_CACHE_LINE_BYTES);
  vec_validate_aligned (decrypted_data, computed_data_total_len - 1, CLIB_CACHE_LINE_BYTES);
  vec_validate_aligned (encrypt_ops, n_ops - 1, CLIB_CACHE_LINE_BYTES);
  vec_validate_aligned (ops, n_ops - 1, CLIB_CACHE_LINE_BYTES);
  computed_data_total_len = 0;

  vec_foreach_index (i, rv)
    {
      r = rv[i];
      int t;

      ad = cm->algs + r->alg;
      for (t = 0; t < VNET_CRYPTO_OP_N_TYPES; t++)
	{
	  if (!crypto_test_reg_has_op_type (r, t))
	    continue;
	  if (!vnet_crypto_alg_has_op_type (r->alg, t))
	    continue;
	  if (!crypto_test_op_supported (engine, r, t, 0))
	    continue;

	  switch (t)
	    {
	    case VNET_CRYPTO_OP_TYPE_ENCRYPT:
	      op = encrypt_ops + n_encrypt_ops++;
	      op->ctx =
		crypto_test_ctx_add_data (vm, engine, r->alg, tm->inc_data, r->key.length, 0);
	      vec_add1 (ctxs, op->ctx);
	      vnet_crypto_op_init (op->ctx, op);
	      op->type = VNET_CRYPTO_OP_TYPE_ENCRYPT;
	      op->iv = tm->inc_data;
	      op->len = r->plaintext_incremental;
	      op->src = tm->inc_data;
	      op->dst = encrypted_data + computed_data_total_len;
	      computed_data_total_len += r->plaintext_incremental;

	      if (ad->alg_type == VNET_CRYPTO_ALG_T_AEAD)
		{
		  op->aad = tm->inc_data;
		  op->aad_len = r->aad.length;
		  op->auth = encrypted_data + computed_data_total_len;
		  computed_data_total_len += r->tag.length;
		  op->auth_len = r->tag.length;
		}
	      op->user_data = i;
	      break;
	    case VNET_CRYPTO_OP_TYPE_HMAC:
	      computed_data_total_len += r->digest.length;
	      break;
	    default:
	      break;
	    };
	}
    }

  if (n_encrypt_ops)
    {
      vnet_crypto_process_ops (vm, encrypt_ops, 0, n_encrypt_ops);
      for (i = 0; i < n_encrypt_ops; i++)
	{
	  crypto_test_result_t result;
	  op = encrypt_ops + i;
	  r = rv[op->user_data];

	  if (op->status == VNET_CRYPTO_OP_STATUS_COMPLETED)
	    {
	      summary->ok[0]++;
	      result = CRYPTO_TEST_RESULT_OK;
	    }
	  else
	    {
	      summary->fail[0]++;
	      result = CRYPTO_TEST_RESULT_FAIL;
	    }

	  crypto_test_result_table_set (results, engine, r, op->ctx->alg, op->type, 0, 0, result);
	}
    }

  computed_data_total_len = 0;

  vec_foreach_index (i, rv)
    {
      r = rv[i];
      int t;

      ad = cm->algs + r->alg;
      for (t = 0; t < VNET_CRYPTO_OP_N_TYPES; t++)
	{
	  if (!crypto_test_reg_has_op_type (r, t))
	    continue;
	  if (!vnet_crypto_alg_has_op_type (r->alg, t))
	    continue;
	  if (!crypto_test_op_supported (engine, r, t, 0))
	    continue;

	  switch (t)
	    {
	    case VNET_CRYPTO_OP_TYPE_DECRYPT:
	      op = ops + n_check_ops++;
	      op->ctx =
		crypto_test_ctx_add_data (vm, engine, r->alg, tm->inc_data, r->key.length, 0);
	      vec_add1 (ctxs, op->ctx);
	      vnet_crypto_op_init (op->ctx, op);
	      op->type = VNET_CRYPTO_OP_TYPE_DECRYPT;
	      op->iv = tm->inc_data;
	      op->len = r->plaintext_incremental;
	      op->src = encrypted_data + computed_data_total_len;
	      op->dst = decrypted_data + computed_data_total_len;
	      computed_data_total_len += r->plaintext_incremental;

	      if (ad->alg_type == VNET_CRYPTO_ALG_T_AEAD)
		{
		  op->aad = tm->inc_data;
		  op->aad_len = r->aad.length;
		  op->auth = encrypted_data + computed_data_total_len;
		  computed_data_total_len += r->tag.length;
		  op->auth_len = r->tag.length;
		}
	      op->user_data = i;
	      break;
	    case VNET_CRYPTO_OP_TYPE_HMAC:
	      op = ops + n_check_ops++;
	      op->ctx =
		crypto_test_ctx_add_data (vm, engine, r->alg, tm->inc_data, r->key.length, 0);
	      vec_add1 (ctxs, op->ctx);
	      vnet_crypto_op_init (op->ctx, op);
	      op->type = VNET_CRYPTO_OP_TYPE_HMAC;
	      op->auth_src = tm->inc_data;
	      op->auth_src_len = r->plaintext_incremental;
	      op->auth_len = r->digest.length;
	      op->auth = encrypted_data + computed_data_total_len;
	      computed_data_total_len += r->digest.length;
	      op->user_data = i;
	      break;
	    default:
	      break;
	    };
	}
    }

  if (n_check_ops)
    {
      vnet_crypto_process_ops (vm, ops, 0, n_check_ops);
      print_results (rv, ops, 0, n_check_ops, tm, summary, engine, results);
    }

  vec_foreach_index (i, ctxs)
    vnet_crypto_ctx_destroy (vm, ctxs[i]);
  vec_free (ops);
  vec_free (encrypt_ops);
  vec_free (encrypted_data);
  vec_free (decrypted_data);
  return 0;
}

static clib_error_t *
test_crypto_static (vlib_main_t *vm, crypto_test_main_t *tm,
		    unittest_crypto_test_registration_t **rv, u32 n_ops, u32 n_chained_ops,
		    u32 computed_data_total_len, vnet_crypto_engine_id_t engine,
		    crypto_test_engine_summary_t *summary, crypto_test_result_table_t *results)
{
  vnet_crypto_op_chunk_t *chunks = 0, ch;
  unittest_crypto_test_registration_t *r;
  vnet_crypto_op_t *ops = 0, *op;
  vnet_crypto_op_t *current_chained_op, *current_op;
  vnet_crypto_main_t *cm = &crypto_main;
  vnet_crypto_alg_data_t *ad;
  vnet_crypto_ctx_t **ctxs = 0;
  u8 *computed_data = 0;
  u32 i, j;

  if (n_ops == 0 && n_chained_ops == 0)
    return 0;

  vec_sort_with_function (rv, sort_registrations);

  if (computed_data_total_len)
    vec_validate_aligned (computed_data, computed_data_total_len - 1, CLIB_CACHE_LINE_BYTES);
  if (n_ops + n_chained_ops)
    vec_validate_aligned (ops, n_ops + n_chained_ops - 1, CLIB_CACHE_LINE_BYTES);
  computed_data_total_len = 0;

  current_op = ops;
  current_chained_op = ops + n_ops;
  vec_foreach_index (i, rv)
    {
      r = rv[i];
      int t;

      ad = cm->algs + r->alg;
      for (t = 0; t < VNET_CRYPTO_OP_N_TYPES; t++)
	{
	  u32 is_chained;

	  if (!crypto_test_reg_has_op_type (r, t))
	    continue;
	  if (!vnet_crypto_alg_has_op_type (r->alg, t))
	    continue;

	  for (is_chained = 0; is_chained <= 1; is_chained++)
	    {
	      if (!crypto_test_op_supported (engine, r, t, is_chained))
		continue;

	      if (is_chained)
		{
		  op = current_chained_op;
		  current_chained_op += 1;
		}
	      else
		{
		  op = current_op;
		  current_op += 1;
		}

	      switch (t)
		{
		case VNET_CRYPTO_OP_TYPE_ENCRYPT:
		case VNET_CRYPTO_OP_TYPE_DECRYPT:
		  if (ad->alg_type != VNET_CRYPTO_ALG_T_AEAD)
		    {
		      op->ctx = crypto_test_key_add (vm, engine, r);
		      vec_add1 (ctxs, op->ctx);
		      vnet_crypto_op_init (op->ctx, op);
		      op->type = t;
		      op->iv = r->iv.data;

		      if (is_chained)
			{
			  op->flags |= VNET_CRYPTO_OP_FLAG_CHAINED_BUFFERS;
			  op->chunk_index = vec_len (chunks);
			  crypto_test_append_buffer_chunks (
			    &chunks,
			    t == VNET_CRYPTO_OP_TYPE_ENCRYPT ? r->plaintext.data :
							       r->ciphertext.data,
			    t == VNET_CRYPTO_OP_TYPE_ENCRYPT ? r->plaintext.length :
							       r->ciphertext.length,
			    computed_data, &computed_data_total_len, &op->n_chunks);

			  if (ad->alg_type == VNET_CRYPTO_ALG_T_COMBINED)
			    {
			      op->auth_len = r->digest.length;
			      if (t == VNET_CRYPTO_OP_TYPE_ENCRYPT)
				{
				  op->auth = computed_data + computed_data_total_len;
				  computed_data_total_len += r->digest.length;
				  op->auth_chunk_index = vec_len (chunks);
				  op->auth_n_chunks = 0;
				  for (j = 0; j < op->n_chunks; j++)
				    {
				      clib_memset (&ch, 0, sizeof (ch));
				      ch.src = vec_elt_at_index (chunks, op->chunk_index + j)->dst;
				      ch.len = vec_elt_at_index (chunks, op->chunk_index + j)->len;
				      vec_add1 (chunks, ch);
				      op->auth_n_chunks++;
				    }
				}
			      else
				{
				  op->flags |= VNET_CRYPTO_OP_FLAG_HMAC_CHECK;
				  op->auth = r->digest.data;
				  op->auth_chunk_index = op->chunk_index;
				  op->auth_n_chunks = op->n_chunks;
				}
			    }
			}
		      else
			{
			  op->len = r->plaintext.length;
			  op->src = t == VNET_CRYPTO_OP_TYPE_ENCRYPT ? r->plaintext.data :
								       r->ciphertext.data;
			  op->dst = computed_data + computed_data_total_len;
			  computed_data_total_len += r->ciphertext.length;

			  if (ad->alg_type == VNET_CRYPTO_ALG_T_COMBINED)
			    {
			      op->auth_src = t == VNET_CRYPTO_OP_TYPE_ENCRYPT ? op->dst : op->src;
			      op->auth_src_len = r->ciphertext.length;
			      op->auth_len = r->digest.length;
			      if (t == VNET_CRYPTO_OP_TYPE_ENCRYPT)
				{
				  op->auth = computed_data + computed_data_total_len;
				  computed_data_total_len += r->digest.length;
				}
			      else
				{
				  op->flags |= VNET_CRYPTO_OP_FLAG_HMAC_CHECK;
				  op->auth = r->digest.data;
				}
			    }
			}
		    }
		  else
		    {
		      op->ctx = crypto_test_key_add (vm, engine, r);
		      vec_add1 (ctxs, op->ctx);
		      vnet_crypto_op_init (op->ctx, op);
		      op->type = t;
		      op->iv = r->iv.data;
		      op->aad = r->aad.data;
		      op->aad_len = r->aad.length;
		      if (is_chained)
			{
			  op->flags |= VNET_CRYPTO_OP_FLAG_CHAINED_BUFFERS;
			  op->chunk_index = vec_len (chunks);
			  crypto_test_append_buffer_chunks (
			    &chunks,
			    t == VNET_CRYPTO_OP_TYPE_ENCRYPT ? r->plaintext.data :
							       r->ciphertext.data,
			    t == VNET_CRYPTO_OP_TYPE_ENCRYPT ? r->plaintext.length :
							       r->ciphertext.length,
			    computed_data, &computed_data_total_len, &op->n_chunks);
			  if (t == VNET_CRYPTO_OP_TYPE_ENCRYPT)
			    {
			      op->auth = computed_data + computed_data_total_len;
			      computed_data_total_len += r->tag.length;
			    }
			  else
			    op->auth = r->tag.data;
			}
		      else
			{
			  op->len = r->plaintext.length;
			  op->dst = computed_data + computed_data_total_len;
			  computed_data_total_len += r->ciphertext.length;

			  if (t == VNET_CRYPTO_OP_TYPE_ENCRYPT)
			    {
			      op->src = r->plaintext.data;
			      op->auth = computed_data + computed_data_total_len;
			      computed_data_total_len += r->tag.length;
			    }
			  else
			    {
			      op->auth = r->tag.data;
			      op->src = r->ciphertext.data;
			    }
			}
		      op->auth_len = r->tag.length;
		    }
		  break;
		case VNET_CRYPTO_OP_TYPE_HMAC:
		  op->ctx = crypto_test_key_add (vm, engine, r);
		  vec_add1 (ctxs, op->ctx);
		  vnet_crypto_op_init (op->ctx, op);
		  op->type = VNET_CRYPTO_OP_TYPE_HMAC;
		  op->auth_len = r->digest.length;
		  op->auth = computed_data + computed_data_total_len;
		  computed_data_total_len += r->digest.length;
		  if (is_chained)
		    {
		      op->flags |= VNET_CRYPTO_OP_FLAG_CHAINED_BUFFERS;
		      op->auth_chunk_index = vec_len (chunks);
		      crypto_test_append_data_chunks (&chunks, r->plaintext.data,
						      r->plaintext.length);
		      op->auth_n_chunks = vec_len (chunks) - op->auth_chunk_index;
		    }
		  else
		    {
		      op->auth_src = r->plaintext.data;
		      op->auth_src_len = r->plaintext.length;
		    }
		  break;
		default:
		  break;
		};

	      op->user_data = i;
	    }
	}
    }

  if (vec_len (ops))
    vnet_crypto_process_ops (vm, ops, chunks, vec_len (ops));

  print_results (rv, ops, chunks, vec_len (ops), tm, summary, engine, results);

  vec_foreach_index (i, ctxs)
    vnet_crypto_ctx_destroy (vm, ctxs[i]);
  vec_free (computed_data);
  vec_free (ops);
  vec_free (chunks);
  return 0;
}

static clib_error_t *
test_crypto_engine (vlib_main_t *vm, crypto_test_main_t *tm, vnet_crypto_engine_id_t engine,
		    crypto_test_result_table_t *results)
{
  clib_error_t *err = 0;
  vnet_crypto_main_t *cm = &crypto_main;
  unittest_crypto_test_registration_t *r = tm->test_registrations;
  unittest_crypto_test_registration_t **hash_tests = 0, **static_tests = 0, **inc_tests = 0;
  crypto_test_result_table_t *rt = results;
  u32 i, n_hash_ops = 0, n_hash_chained_ops = 0, n_ops_static = 0, n_ops_incr = 0,
	 n_chained_ops = 0;
  u32 computed_data_total_len = 0;
  u32 computed_hash_data_total_len = 0;
  u32 computed_data_total_incr_len = 0;
  crypto_test_engine_summary_t summary = {};

  while (r)
    {
      int used = 0;

      if (!crypto_test_reg_matches_alg (tm, r))
	{
	  r = r->next;
	  continue;
	}

      if (r->hash.length != 0)
	{
	  u32 is_chained;

	  for (is_chained = 0; is_chained <= (r->plaintext_incremental ? 0 : 1); is_chained++)
	    {
	      if (!crypto_test_hash_op_supported (engine, r, is_chained))
		{
		  crypto_test_result_table_set (results, engine, r, r->alg, 0, is_chained, 1,
						CRYPTO_TEST_RESULT_NOT_SUPPORTED);
		  summary.not_supported[is_chained]++;
		  continue;
		}

	      used = 1;
	      computed_hash_data_total_len += r->hash.length;
	      if (is_chained)
		n_hash_chained_ops += 1;
	      else
		n_hash_ops += 1;
	    }
	}

      for (i = 0; i < VNET_CRYPTO_OP_N_TYPES; i++)
	{
	  u32 max_mode = r->plaintext_incremental ? 0 : 1;
	  u32 is_chained;

	  if (!crypto_test_reg_has_op_type (r, i) || !vnet_crypto_alg_has_op_type (r->alg, i))
	    continue;

	  for (is_chained = 0; is_chained <= max_mode; is_chained++)
	    {
	      if (!crypto_test_op_supported (engine, r, i, is_chained))
		{
		  crypto_test_print_not_supported (r, r->alg, i, is_chained, &summary, engine,
						   results);
		  continue;
		}

	      used = 1;

	      switch (i)
		{
		case VNET_CRYPTO_OP_TYPE_ENCRYPT:
		  if (cm->algs[r->alg].alg_type == VNET_CRYPTO_ALG_T_AEAD)
		    {
		      if (r->plaintext_incremental)
			{
			  computed_data_total_incr_len += r->plaintext_incremental;
			  computed_data_total_incr_len += r->tag.length;
			  n_ops_incr += 1;
			}
		      else
			{
			  computed_data_total_len += r->ciphertext.length;
			  computed_data_total_len += r->tag.length;
			  if (is_chained)
			    n_chained_ops += 1;
			  else
			    n_ops_static += 1;
			}
		      break;
		    }

		  if (r->plaintext_incremental)
		    {
		      computed_data_total_incr_len += r->plaintext_incremental;
		      n_ops_incr += 1;
		    }
		  /* fall through */
		case VNET_CRYPTO_OP_TYPE_DECRYPT:
		  if (!r->plaintext_incremental)
		    {
		      computed_data_total_len += r->ciphertext.length;
		      if (i == VNET_CRYPTO_OP_TYPE_ENCRYPT &&
			  cm->algs[r->alg].alg_type == VNET_CRYPTO_ALG_T_COMBINED)
			computed_data_total_len += r->digest.length;
		      if (is_chained)
			n_chained_ops += 1;
		      else
			n_ops_static += 1;
		    }
		  break;
		case VNET_CRYPTO_OP_TYPE_HMAC:
		  if (r->plaintext_incremental)
		    {
		      computed_data_total_incr_len += r->digest.length;
		      n_ops_incr += 1;
		    }
		  else
		    {
		      computed_data_total_len += r->digest.length;
		      if (is_chained)
			n_chained_ops += 1;
		      else
			n_ops_static += 1;
		    }
		  break;
		default:
		  break;
		};
	    }
	}

      if (used)
	{
	  if (r->hash.length != 0)
	    vec_add1 (hash_tests, r);
	  else if (r->plaintext_incremental)
	    vec_add1 (inc_tests, r);
	  else
	    vec_add1 (static_tests, r);
	}

      r = r->next;
    }

  err = test_crypto_static (vm, tm, static_tests, n_ops_static, n_chained_ops,
			    computed_data_total_len, engine, &summary, results);
  if (err)
    goto done;

  err = test_crypto_hash_static (vm, hash_tests, n_hash_ops, n_hash_chained_ops,
				 computed_hash_data_total_len, engine, &summary, results);
  if (err)
    goto done;

  err = test_crypto_incremental (vm, tm, inc_tests, n_ops_incr, computed_data_total_incr_len,
				 engine, &summary, results);

done:
  if (rt)
    {
      i = crypto_test_result_table_find_engine_col (rt, engine);
      if (i >= 0)
	rt->summaries[i] = summary;
    }

  vec_free (inc_tests);
  vec_free (hash_tests);
  vec_free (static_tests);
  return err;
}

static clib_error_t *
test_crypto (vlib_main_t *vm, crypto_test_main_t *tm)
{
  clib_error_t *err = 0;
  unittest_crypto_test_registration_t *r = tm->test_registrations;
  vnet_crypto_engine_id_t engine = VNET_CRYPTO_ENGINE_ID_NONE;
  vnet_crypto_engine_id_t ref_engine;
  crypto_test_result_table_t results;
  u32 i;

  /* pre-allocate plaintext data with reasonable length */
  validate_data (&tm->inc_data, 2048);

  ref_engine = vnet_crypto_get_engine_index_by_name ("openssl");
  if (ref_engine == VNET_CRYPTO_ENGINE_ID_INVALID)
    return clib_error_return (0, "failed to find openssl crypto engine");

  if (tm->engine)
    {
      engine = vnet_crypto_get_engine_index_by_name ("%s", tm->engine);
      if (engine == VNET_CRYPTO_ENGINE_ID_INVALID)
	return clib_error_return (0, "unknown engine '%s'", tm->engine);
    }

  crypto_test_sync_result_table_init (&results, tm);

  while (r)
    {
      if (!crypto_test_reg_matches_alg (tm, r))
	{
	  r = r->next;
	  continue;
	}

      for (i = 0; i < VNET_CRYPTO_OP_N_TYPES; i++)
	{
	  if (!crypto_test_reg_has_op_type (r, i) || !vnet_crypto_alg_has_op_type (r->alg, i))
	    continue;
	  if (i == VNET_CRYPTO_OP_TYPE_HMAC && r->plaintext_incremental)
	    {
	      err = generate_digest (vm, r, i, ref_engine);
	      if (err)
		goto done;
	    }
	}

      /* next: */
      r = r->next;
    }

  err = crypto_test_run_engines (vm, tm, engine, &results, test_crypto_engine);

done:
  if (tm->quiet)
    vlib_cli_output (vm, "%s", crypto_test_has_failures (&results) ? "FAIL" : "OK");
  else
    {
      if (tm->verbose || crypto_test_has_failures (&results))
	crypto_test_result_table_print (vm, &results, !tm->verbose);
      crypto_test_summary_table_print (vm, &results, "Sync Test Execution Summary");
    }
  crypto_test_result_table_free (&results);
  vec_free (tm->inc_data);
  r = tm->test_registrations;
  while (r)
    {
      if (r->plaintext_incremental)
	vec_free (r->digest.data);
      r = r->next;
    }

  return err;
}

typedef struct
{
  vnet_crypto_async_frame_t *frame;
} crypto_test_async_result_t;

static int
crypto_test_engine_has_async_rows (crypto_test_result_row_t *rows, vnet_crypto_engine_id_t engine)
{
  vnet_crypto_main_t *cm = &crypto_main;
  vnet_crypto_engine_t *e = vec_elt_at_index (cm->engines, engine);
  crypto_test_result_row_t *row;

  if (e->dequeue_handler == 0)
    return 0;

  vec_foreach (row, rows)
    if (e->ops[row->alg][row->type].handlers[VNET_CRYPTO_HANDLER_TYPE_ASYNC] != 0)
      return 1;

  return 0;
}

static void
crypto_test_async_result_table_init (crypto_test_result_table_t *rt, crypto_test_main_t *tm)
{
  vnet_crypto_main_t *cm = &crypto_main;
  unittest_crypto_test_registration_t **regs = 0;
  int i;

  *rt = (crypto_test_result_table_t){};
  crypto_test_result_table_init_engines (rt, tm);
  regs = crypto_test_collect_regs (tm, 0);

  vec_foreach_index (i, regs)
    {
      if (!crypto_test_reg_matches_alg (tm, regs[i]))
	continue;

      crypto_test_result_table_add_reg_rows (rt, cm, regs[i], 1, 0);
    }

  vec_sort_with_function (rt->rows, sort_result_rows);

  if (!tm->engine)
    crypto_test_result_table_filter_engines (rt, crypto_test_engine_has_async_rows);

  crypto_test_result_table_init_storage (rt);

  vec_free (regs);
}

static clib_error_t *
crypto_test_wait_for_async_frame (vlib_main_t *vm, vnet_crypto_engine_id_t engine,
				  vnet_crypto_async_frame_t *submitted_frame,
				  crypto_test_async_result_t *result)
{
  vnet_crypto_main_t *cm = &crypto_main;
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  vnet_crypto_engine_t *e = vec_elt_at_index (cm->engines, engine);
  f64 deadline = clib_time_now (&vm->clib_time) + 1.0;
  u32 i;

  if (e->dequeue_handler == 0)
    return clib_error_return (0, "engine '%s' has no async dequeue handler", e->name);

  while (clib_time_now (&vm->clib_time) < deadline)
    {
      for (i = 0; i < tm->n_vlib_mains; i++)
	{
	  vlib_main_t *ovm = vlib_get_main_by_index (i);
	  clib_thread_index_t enqueue_thread_idx = CLIB_INVALID_THREAD_INDEX;
	  u32 n_elts = 0;
	  vnet_crypto_async_frame_t *frame;

	  frame = e->dequeue_handler (ovm, &n_elts, &enqueue_thread_idx);
	  if (frame == 0)
	    continue;

	  if (frame == submitted_frame)
	    {
	      *result = (crypto_test_async_result_t){
		.frame = frame,
	      };
	      return 0;
	    }

	  vnet_crypto_async_free_frame (vlib_get_main_by_index (enqueue_thread_idx), frame);
	}

      vlib_process_wait_for_event_or_clock (vm, 10e-3);
    }

  return clib_error_return (0, "async frame timeout");
}

static_always_inline u32
crypto_test_async_chunk_count (u32 len)
{
  if (len <= 1)
    return 1;
  if (len <= 32)
    return 2;

  return 3;
}

static void
crypto_test_async_buffer_chain_init (vlib_main_t *vm, u32 *buffer_indices, u32 n_buffers,
				     unittest_crypto_test_data_t *data)
{
  u32 i, offset = 0;

  for (i = 0; i < n_buffers; i++)
    {
      vlib_buffer_t *b = vlib_get_buffer (vm, buffer_indices[i]);
      u32 base = data->length / n_buffers;
      u32 rem = data->length % n_buffers;
      u32 len = n_buffers == 1 ? data->length : base + (i < rem);

      vlib_buffer_reset (b);
      b->current_data = len ? 0 : 1;
      b->current_length = len;
      b->flags = 0;
      b->next_buffer = 0;
      b->total_length_not_including_first_buffer = 0;

      if (len)
	clib_memcpy (vlib_buffer_get_current (b), data->data + offset, len);

      if (i + 1 < n_buffers)
	{
	  b->flags |= VLIB_BUFFER_NEXT_PRESENT;
	  b->next_buffer = buffer_indices[i + 1];
	}

      offset += len;
    }

  if (n_buffers > 1)
    {
      vlib_buffer_t *head = vlib_get_buffer (vm, buffer_indices[0]);
      head->total_length_not_including_first_buffer = data->length - head->current_length;
    }
}

static int
crypto_test_async_buffer_chain_compare (vlib_main_t *vm, u32 buffer_index,
					unittest_crypto_test_data_t *expected)
{
  u32 offset = 0;

  while (1)
    {
      vlib_buffer_t *b = vlib_get_buffer (vm, buffer_index);

      if (offset + b->current_length > expected->length)
	return 1;

      if (b->current_length &&
	  memcmp (vlib_buffer_get_current (b), expected->data + offset, b->current_length))
	return 1;

      offset += b->current_length;
      if ((b->flags & VLIB_BUFFER_NEXT_PRESENT) == 0)
	break;

      buffer_index = b->next_buffer;
    }

  return offset != expected->length;
}

static clib_error_t *
test_crypto_async_case (vlib_main_t *vm, crypto_test_main_t *tm,
			unittest_crypto_test_registration_t *r, vnet_crypto_engine_id_t engine,
			vnet_crypto_op_type_t op_type, u8 is_chained,
			crypto_test_result_t *test_result)
{
  vlib_main_t *async_vm;
  vnet_crypto_main_t *cm = &crypto_main;
  vnet_crypto_alg_data_t *ad = cm->algs + r->alg;
  char *engine_name = vec_elt_at_index (cm->engines, engine)->name;
  vnet_crypto_async_frame_t *frame = 0;
  unittest_crypto_test_data_t *input = 0;
  unittest_crypto_test_data_t *output = 0;
  vlib_buffer_t *head = 0;
  u32 *buffer_indices = 0;
  u32 *head_indices = 0;
  u32 n_alloc = 0;
  u32 n_buffers;
  u32 n_elts;
  u32 total_buffers;
  u32 scratch_len;
  u32 digest_len = 0;
  u32 auth_data_len = 0;
  u8 *aad = 0;
  u8 *iv = 0;
  u8 *tag = 0;
  u8 flags = 0;
  u8 submitted = 0;
  vnet_crypto_ctx_t **ctxs = 0;
  crypto_test_async_result_t result = {};
  clib_error_t *rv = 0;
  vnet_crypto_async_frame_elt_t *fe;
  char *mismatch = 0;
  u32 fail_idx = ~0;
  u32 i;

  *test_result = CRYPTO_TEST_RESULT_FAIL;
  async_vm = vlib_num_workers () > 0 ? vlib_get_main_by_index (1) : vm;

  switch (op_type)
    {
    case VNET_CRYPTO_OP_TYPE_ENCRYPT:
      input = &r->plaintext;
      output = &r->ciphertext;
      break;
    case VNET_CRYPTO_OP_TYPE_DECRYPT:
      input = &r->ciphertext;
      output = &r->plaintext;
      break;
    case VNET_CRYPTO_OP_TYPE_HMAC:
      input = &r->plaintext;
      break;
    case VNET_CRYPTO_OP_N_TYPES:
      return clib_error_return (0, "invalid async op type");
    }

  if (ad->alg_type == VNET_CRYPTO_ALG_T_AEAD)
    digest_len = r->tag.length;
  else if (crypto_test_op_has_digest (ad, op_type))
    digest_len = crypto_test_digest_data (r, op_type)->length;

  if (crypto_test_op_has_digest (ad, op_type))
    auth_data_len = input->length;

  scratch_len = r->iv.length + r->aad.length + digest_len;
  if (scratch_len > VLIB_BUFFER_PRE_DATA_SIZE)
    return clib_error_return (0, "buffer headroom too small for async test");

  n_buffers = is_chained ? crypto_test_async_chunk_count (input->length) : 1;
  n_elts = tm->elts_per_frame;
  total_buffers = n_buffers * n_elts;

  if (n_elts == 0 || n_elts > VNET_CRYPTO_FRAME_SIZE)
    return clib_error_return (0, "elts-per-frame must be in range 1..%u", VNET_CRYPTO_FRAME_SIZE);

  vec_validate_aligned (buffer_indices, total_buffers - 1, CLIB_CACHE_LINE_BYTES);
  vec_validate_aligned (head_indices, n_elts - 1, CLIB_CACHE_LINE_BYTES);

  n_alloc = vlib_buffer_alloc (vm, buffer_indices, total_buffers);
  if (n_alloc != total_buffers)
    {
      if (n_alloc)
	vlib_buffer_free (vm, buffer_indices, n_alloc);
      return clib_error_return (0, "buffer alloc failure");
    }

  frame = vnet_crypto_async_get_frame (async_vm, r->alg, op_type);
  if (frame == 0)
    {
      rv = clib_error_return (0, "async frame alloc failed");
      goto done;
    }

  vec_validate (ctxs, n_elts - 1);

  for (i = 0; i < n_elts; i++)
    {
      flags = is_chained ? VNET_CRYPTO_OP_FLAG_CHAINED_BUFFERS : 0;

      ctxs[i] = crypto_test_ctx_add_data (async_vm, engine, r->alg, r->key.data, r->key.length, 1);
      if (ctxs[i] == 0)
	{
	  rv = clib_error_return (0, "key add failed");
	  goto done;
	}

      crypto_test_async_buffer_chain_init (vm, buffer_indices + i * n_buffers, n_buffers, input);
      head_indices[i] = buffer_indices[i * n_buffers];

      head = vlib_get_buffer (vm, head_indices[i]);
      iv = head->pre_data;
      aad = iv + r->iv.length;
      tag = aad + r->aad.length;

      if (r->iv.length)
	clib_memcpy (iv, r->iv.data, r->iv.length);
      if (r->aad.length)
	clib_memcpy (aad, r->aad.data, r->aad.length);
      if (digest_len)
	clib_memset (tag, 0, digest_len);

      if (op_type == VNET_CRYPTO_OP_TYPE_DECRYPT)
	{
	  if (ad->alg_type == VNET_CRYPTO_ALG_T_AEAD && r->tag.length)
	    clib_memcpy (tag, r->tag.data, r->tag.length);
	  else if (ad->alg_type == VNET_CRYPTO_ALG_T_COMBINED && r->digest.length)
	    {
	      flags |= VNET_CRYPTO_OP_FLAG_HMAC_CHECK;
	      clib_memcpy (tag, r->digest.data, r->digest.length);
	    }
	}

      vnet_crypto_async_add_to_frame (async_vm, frame, ctxs[i], input->length, auth_data_len, 0, 0,
				      head_indices[i], 0, iv, tag, aad, flags);

      fe = &frame->elts[i];
      fe->aad_len = r->aad.length;
      fe->icv_len = digest_len;
    }

  if (vnet_crypto_async_submit_open_frame (async_vm, frame) < 0)
    {
      rv = clib_error_return (0, "async enqueue failed");
      goto done;
    }
  submitted = 1;

  rv = crypto_test_wait_for_async_frame (vm, engine, frame, &result);
  if (rv)
    goto done;

  if (result.frame->n_elts != n_elts)
    {
      log_err (0, "%s %s %U-%U %s: frame elt count mismatch got %u expected %u", engine_name,
	       r->name, format_crypto_op_type_short, op_type, format_vnet_crypto_alg, r->alg,
	       is_chained ? "chained" : "simple", result.frame->n_elts, n_elts);
      *test_result = CRYPTO_TEST_RESULT_ERROR;
      goto done;
    }

  if (vnet_crypto_async_frame_bitmap_count_set_bits (result.frame->engine_error_bitmap))
    {
      log_err (0, "%s %s %U-%U %s: fail-engine-err %U", engine_name, r->name,
	       format_crypto_op_type_short, op_type, format_vnet_crypto_alg, r->alg,
	       is_chained ? "chained" : "simple", format_uword_bitmap,
	       result.frame->engine_error_bitmap);
      *test_result = CRYPTO_TEST_RESULT_ERROR;
      goto done;
    }

  if (vnet_crypto_async_frame_bitmap_count_set_bits (result.frame->bad_hmac_bitmap))
    {
      log_err (0, "%s %s %U-%U %s: fail-bad-hmac %U", engine_name, r->name,
	       format_crypto_op_type_short, op_type, format_vnet_crypto_alg, r->alg,
	       is_chained ? "chained" : "simple", format_uword_bitmap,
	       result.frame->bad_hmac_bitmap);
      *test_result = CRYPTO_TEST_RESULT_FAIL;
      goto done;
    }

  if (output)
    for (i = 0; i < n_elts; i++)
      if (crypto_test_async_buffer_chain_compare (vm, head_indices[i], output))
	{
	  mismatch =
	    op_type == VNET_CRYPTO_OP_TYPE_ENCRYPT ? "ciphertext mismatch" : "plaintext mismatch";
	  fail_idx = i;
	  break;
	}

  if (mismatch == 0 && ad->alg_type == VNET_CRYPTO_ALG_T_AEAD &&
      op_type == VNET_CRYPTO_OP_TYPE_ENCRYPT && r->tag.length)
    for (i = 0; i < n_elts; i++)
      {
	head = vlib_get_buffer (vm, head_indices[i]);
	tag = head->pre_data + r->iv.length + r->aad.length;
	if (memcmp (tag, r->tag.data, r->tag.length))
	  {
	    mismatch = "tag mismatch";
	    fail_idx = i;
	    break;
	  }
      }

  if (mismatch == 0 && crypto_test_op_has_digest (ad, op_type) &&
      op_type != VNET_CRYPTO_OP_TYPE_DECRYPT && digest_len)
    for (i = 0; i < n_elts; i++)
      {
	head = vlib_get_buffer (vm, head_indices[i]);
	tag = head->pre_data + r->iv.length + r->aad.length;
	if (memcmp (tag, crypto_test_digest_data (r, op_type)->data,
		    crypto_test_digest_data (r, op_type)->length))
	  {
	    mismatch = "digest mismatch";
	    fail_idx = i;
	    break;
	  }
      }

  if (mismatch)
    {
      log_err (0, "%s %s %U-%U %s: elt %u %s", engine_name, r->name, format_crypto_op_type_short,
	       op_type, format_vnet_crypto_alg, r->alg, is_chained ? "chained" : "simple", fail_idx,
	       mismatch);
      *test_result = CRYPTO_TEST_RESULT_FAIL;
      goto done;
    }

  *test_result = CRYPTO_TEST_RESULT_OK;

done:
  if (result.frame)
    vnet_crypto_async_free_frame (vlib_get_main_by_index (result.frame->enqueue_thread_index),
				  result.frame);
  if (frame && !submitted)
    vnet_crypto_async_free_frame (async_vm, frame);
  if (n_alloc && (!submitted || result.frame))
    {
      if (is_chained)
	vlib_buffer_free (vm, head_indices, n_elts);
      else
	vlib_buffer_free (vm, buffer_indices, n_alloc);
    }
  vec_foreach_index (i, ctxs)
    if (ctxs[i] && (result.frame || !submitted))
      vnet_crypto_ctx_destroy (async_vm, ctxs[i]);
  vec_free (head_indices);
  vec_free (ctxs);
  vec_free (buffer_indices);
  return rv;
}

static clib_error_t *
test_crypto_async_engine (vlib_main_t *vm, crypto_test_main_t *tm, vnet_crypto_engine_id_t engine,
			  crypto_test_result_table_t *results)
{
  clib_error_t *err = 0;
  char *engine_name = vec_elt_at_index (crypto_main.engines, engine)->name;
  unittest_crypto_test_registration_t *r = tm->test_registrations;
  crypto_test_engine_summary_t summary = {};
  crypto_test_result_t result;
  u32 i;

  while (r)
    {
      if (!crypto_test_reg_matches_alg (tm, r))
	{
	  r = r->next;
	  continue;
	}

      if (r->plaintext_incremental)
	{
	  r = r->next;
	  continue;
	}

      for (i = 0; i < VNET_CRYPTO_OP_N_TYPES; i++)
	{
	  u32 is_chained;

	  if (!crypto_test_reg_has_op_type (r, i) || !vnet_crypto_alg_has_op_type (r->alg, i))
	    continue;

	  if (vec_elt_at_index (crypto_main.engines, engine)->dequeue_handler == 0 ||
	      vec_elt_at_index (crypto_main.engines, engine)
		  ->ops[r->alg][i]
		  .handlers[VNET_CRYPTO_HANDLER_TYPE_ASYNC] == 0)
	    {
	      crypto_test_print_not_supported (r, r->alg, i, 0, &summary, engine, results);
	      crypto_test_print_not_supported (r, r->alg, i, 1, &summary, engine, results);
	      continue;
	    }

	  for (is_chained = 0; is_chained <= 1; is_chained++)
	    {
	      err = test_crypto_async_case (vm, tm, r, engine, i, is_chained, &result);
	      if (err)
		{
		  summary.error[is_chained]++;
		  crypto_test_result_table_set (results, engine, r, r->alg, i, is_chained, 0,
						CRYPTO_TEST_RESULT_ERROR);
		  log_err (0, "%s %s %U-%U %s: %U", engine_name, r->name,
			   format_crypto_op_type_short, i, format_vnet_crypto_alg, r->alg,
			   is_chained ? "chained" : "simple", format_clib_error, err);
		  clib_error_free (err);
		  err = 0;
		  continue;
		}

	      if (result == CRYPTO_TEST_RESULT_OK)
		summary.ok[is_chained]++;
	      else
		summary.fail[is_chained]++;

	      crypto_test_result_table_set (results, engine, r, r->alg, i, is_chained, 0, result);
	    }
	}

      r = r->next;
    }

  if (results)
    {
      i = crypto_test_result_table_find_engine_col (results, engine);
      if (i >= 0)
	results->summaries[i] = summary;
    }

  return err;
}

clib_error_t *
test_crypto_async (vlib_main_t *vm, crypto_test_main_t *tm)
{
  clib_error_t *err = 0;
  vlib_thread_main_t *vtm = vlib_get_thread_main ();
  crypto_test_result_table_t results;
  vnet_crypto_engine_id_t engine = VNET_CRYPTO_ENGINE_ID_NONE;
  vlib_node_state_t *node_states = 0;
  u32 i;

  if (tm->engine)
    {
      engine = vnet_crypto_get_engine_index_by_name ("%s", tm->engine);
      if (engine == VNET_CRYPTO_ENGINE_ID_INVALID)
	return clib_error_return (0, "unknown engine '%s'", tm->engine);
    }

  crypto_test_async_result_table_init (&results, tm);
  vec_validate (node_states, vtm->n_vlib_mains - 1);
  vec_foreach_index (i, node_states)
    {
      vlib_main_t *ovm = vlib_get_main_by_index (i);
      vlib_node_t *n = vlib_get_node (ovm, crypto_main.crypto_node_index);

      node_states[i] = n->state;
      vlib_node_set_state (ovm, crypto_main.crypto_node_index, VLIB_NODE_STATE_DISABLED);
    }

  err = crypto_test_run_engines (vm, tm, engine, &results, test_crypto_async_engine);

  vec_foreach_index (i, node_states)
    vlib_node_set_state (vlib_get_main_by_index (i), crypto_main.crypto_node_index, node_states[i]);

  if (tm->quiet)
    vlib_cli_output (vm, "%s", crypto_test_has_failures (&results) ? "FAIL" : "OK");
  else
    {
      if (tm->verbose || crypto_test_has_failures (&results))
	crypto_test_result_table_print (vm, &results, !tm->verbose);
      crypto_test_summary_table_print (vm, &results, "Async Test Execution Summary");
    }

  vec_free (node_states);
  crypto_test_result_table_free (&results);
  return err;
}

static clib_error_t *
test_crypto_perf (vlib_main_t * vm, crypto_test_main_t * tm)
{
  vnet_crypto_main_t *cm = &crypto_main;
  clib_error_t *err = 0;
  vnet_crypto_engine_id_t engine = VNET_CRYPTO_ENGINE_ID_INVALID;
  u32 n_buffers, n_alloc = 0, warmup_rounds, rounds;
  u32 *buffer_indices = 0;
  vnet_crypto_op_t *ops1 = 0, *ops2 = 0, *op1, *op2;
  vnet_crypto_alg_data_t *ad = cm->algs + tm->alg;
  vnet_crypto_ctx_t *ctx = 0;
  u16 combined_crypto_key_len = 0;
  u32 key_sz = 0;
  u8 combined_digest_len = 0;
  int is_combined_alg = 0;
  u8 key_data[128];
  int buffer_size = vlib_buffer_get_default_data_size (vm);
  u64 seed = clib_cpu_time_now ();
  u64 t0[5], t1[5], t2[5];
  u64 payload_bytes =
    0; /* total payload bytes per round (not doubled for multi-pass) */
  int i, j;

  if (tm->buffer_size > buffer_size)
    return clib_error_return (0, "buffer size must be <= %u", buffer_size);

  if (tm->engine)
    {
      engine = vnet_crypto_get_engine_index_by_name ("%s", tm->engine);
      if (engine == VNET_CRYPTO_ENGINE_ID_INVALID)
	return clib_error_return (0, "unknown engine '%s'", tm->engine);
    }

  rounds = tm->rounds ? tm->rounds : 100;
  n_buffers = tm->n_buffers ? tm->n_buffers : 256;
  buffer_size = tm->buffer_size ? tm->buffer_size : 2048;
  warmup_rounds = tm->warmup_rounds ? tm->warmup_rounds : 100;

  if (buffer_size > vlib_buffer_get_default_data_size (vm))
    return clib_error_return (0, "buffer size too big");

  vec_validate_aligned (buffer_indices, n_buffers - 1, CLIB_CACHE_LINE_BYTES);
  vec_validate_aligned (ops1, n_buffers - 1, CLIB_CACHE_LINE_BYTES);
  vec_validate_aligned (ops2, n_buffers - 1, CLIB_CACHE_LINE_BYTES);

  n_alloc = vlib_buffer_alloc (vm, buffer_indices, n_buffers);
  if (n_alloc != n_buffers)
    {
      if (n_alloc)
	vlib_buffer_free (vm, buffer_indices, n_alloc);
      err = clib_error_return (0, "buffer alloc failure");
      goto done;
    }

  vlib_cli_output (vm, "%U: n_buffers %u buffer-size %u rounds %u "
		   "warmup-rounds %u",
		   format_vnet_crypto_alg, tm->alg, n_buffers, buffer_size,
		   rounds, warmup_rounds);
  vlib_cli_output (vm, "   cpu-freq %.2f GHz",
		   (f64) vm->clib_time.clocks_per_second * 1e-9);

  vnet_crypto_op_type_t ot;

  if (ad->alg_type == VNET_CRYPTO_ALG_T_COMBINED)
    {
      if (vnet_crypto_alg_has_op_type (tm->alg, VNET_CRYPTO_OP_TYPE_ENCRYPT) &&
	  vnet_crypto_alg_has_op_type (tm->alg, VNET_CRYPTO_OP_TYPE_DECRYPT) && ad->cipher_key_len)
	{
	  combined_digest_len = ad->auth_len;
	  if (combined_digest_len)
	    {
	      is_combined_alg = 1;
	      combined_crypto_key_len = ad->cipher_key_len;
	    }
	}
    }

  /* Handle combined algorithms (crypto+integrity) */
  if (is_combined_alg)
    {
      key_sz = combined_crypto_key_len + 32;
    }
  else
    {
      key_sz = cm->algs[tm->alg].cipher_key_len;
      if (key_sz == 0)
	key_sz = 32; /* Use 32 bytes for HMAC algorithms (0 key_len) */
    }

  for (i = 0; i < key_sz; i++)
    key_data[i] = i;

  if (tm->engine)
    ctx = crypto_test_ctx_add_data (vm, engine, tm->alg, key_data, key_sz, 0);
  else if (is_combined_alg)
    {
      ctx = vnet_crypto_ctx_create (tm->alg);
      if (ctx && (!vnet_crypto_ctx_set_cipher_key (ctx, key_data, combined_crypto_key_len) ||
		  !vnet_crypto_ctx_set_auth_key (ctx, key_data + combined_crypto_key_len,
						 key_sz - combined_crypto_key_len)))
	{
	  vnet_crypto_ctx_destroy (vm, ctx);
	  ctx = 0;
	}
    }
  else
    {
      ctx = vnet_crypto_ctx_create (tm->alg);
      if (ctx && ((ad->alg_type == VNET_CRYPTO_ALG_T_AUTH &&
		   !vnet_crypto_ctx_set_auth_key (ctx, key_data, key_sz)) ||
		  (ad->alg_type != VNET_CRYPTO_ALG_T_AUTH &&
		   !vnet_crypto_ctx_set_cipher_key (ctx, key_data, key_sz))))
	{
	  vnet_crypto_ctx_destroy (vm, ctx);
	  ctx = 0;
	}
    }

  if (ctx == 0)
    {
      err = clib_error_return (0, "ctx create failed");
      goto done;
    }

  ot = crypto_test_first_op_type (tm->alg);
  if (ot == VNET_CRYPTO_OP_N_TYPES)
    goto done;

  for (i = 0; i < n_buffers; i++)
    {
      vlib_buffer_t *b = vlib_get_buffer (vm, buffer_indices[i]);
      op1 = ops1 + i;
      op2 = ops2 + i;

      switch (ot)
	{
	case VNET_CRYPTO_OP_TYPE_ENCRYPT:
	case VNET_CRYPTO_OP_TYPE_DECRYPT:
	  vnet_crypto_op_init (ctx, op1);
	  vnet_crypto_op_init (ctx, op2);
	  op1->type = VNET_CRYPTO_OP_TYPE_ENCRYPT;
	  op2->type = VNET_CRYPTO_OP_TYPE_DECRYPT;
	  op1->src = op2->src = op1->dst = op2->dst = b->data;
	  op1->iv = op2->iv = b->data - 64;

	  if (is_combined_alg)
	    {
	      /* For combined algorithms, both encrypt and decrypt operations
	       * include integrity (HMAC) processing */
	      op1->auth_src = op2->auth_src = b->data;
	      op1->auth_src_len = op2->auth_src_len = buffer_size;
	      op1->auth = op2->auth = b->data - VLIB_BUFFER_PRE_DATA_SIZE;
	      op1->auth_len = op2->auth_len = combined_digest_len;
	      op2->flags |= VNET_CRYPTO_OP_FLAG_HMAC_CHECK;
	    }
	  else if (ad->alg_type == VNET_CRYPTO_ALG_T_AEAD)
	    {
	      op1->auth = op2->auth = b->data - 32;
	      op1->aad = op2->aad = b->data - VLIB_BUFFER_PRE_DATA_SIZE;
	      op1->aad_len = op2->aad_len = 64;
	      op1->auth_len = op2->auth_len = 16;
	    }

	  op1->len = op2->len = buffer_size;
	  break;
	case VNET_CRYPTO_OP_TYPE_HMAC:
	  vnet_crypto_op_init (ctx, op1);
	  op1->type = VNET_CRYPTO_OP_TYPE_HMAC;
	  op1->auth_src = b->data;
	  op1->auth = b->data - VLIB_BUFFER_PRE_DATA_SIZE;
	  op1->auth_len = 12;
	  op1->auth_src_len = buffer_size;
	  break;
	default:
	  return 0;
	}

      for (j = -VLIB_BUFFER_PRE_DATA_SIZE; j < buffer_size; j += 8)
	*(u64 *) (b->data + j) = 1 + random_u64 (&seed);
    }

  for (i = 0; i < 5; i++)
    {
      for (j = 0; j < warmup_rounds; j++)
	{
	  if (tm->engine)
	    vnet_crypto_process_ops (vm, ops1, 0, n_buffers);
	  else
	    vnet_crypto_process_ops (vm, ops1, 0, n_buffers);
	  if (ot != VNET_CRYPTO_OP_TYPE_HMAC)
	    {
	      if (tm->engine)
		vnet_crypto_process_ops (vm, ops2, 0, n_buffers);
	      else
		vnet_crypto_process_ops (vm, ops2, 0, n_buffers);
	    }
	}

      t0[i] = clib_cpu_time_now ();
      for (j = 0; j < rounds; j++)
	{
	  if (tm->engine)
	    vnet_crypto_process_ops (vm, ops1, 0, n_buffers);
	  else
	    vnet_crypto_process_ops (vm, ops1, 0, n_buffers);
	}
      t1[i] = clib_cpu_time_now ();

      if (ot != VNET_CRYPTO_OP_TYPE_HMAC)
	{
	  for (j = 0; j < rounds; j++)
	    {
	      if (tm->engine)
		vnet_crypto_process_ops (vm, ops2, 0, n_buffers);
	      else
		vnet_crypto_process_ops (vm, ops2, 0, n_buffers);
	    }
	  t2[i] = clib_cpu_time_now ();
	}
    }

  /* establish payload bytes once (cipher len or integ_len per buffer) */
  payload_bytes = (u64) n_buffers * buffer_size;

  for (i = 0; i < 5; i++)
    {
      f64 tpb1 = (f64) (t1[i] - t0[i]) / (payload_bytes * rounds);
      f64 gbps1 = vm->clib_time.clocks_per_second * 1e-9 * 8 / tpb1;
      f64 tpb2, gbps2;

      if (ot != VNET_CRYPTO_OP_TYPE_HMAC)
	{
	  tpb2 = (f64) (t2[i] - t1[i]) / (payload_bytes * rounds);
	  gbps2 = vm->clib_time.clocks_per_second * 1e-9 * 8 / tpb2;
	  if (is_combined_alg)
	    {
	      /* For combined alg we measured encrypt(+hmac) and
	       * decrypt(+hmac-check) separately */
	      vlib_cli_output (
		vm,
		"%-2u: encrypt+hmac %.03f ticks/byte, %.02f Gbps; "
		"decrypt+hmac %.03f ticks/byte, %.02f Gbps",
		i + 1, tpb1, gbps1, tpb2, gbps2);
	    }
	  else
	    {
	      vlib_cli_output (vm,
			       "%-2u: encrypt %.03f ticks/byte, %.02f Gbps; "
			       "decrypt %.03f ticks/byte, %.02f Gbps",
			       i + 1, tpb1, gbps1, tpb2, gbps2);
	    }
	}
      else
	{
	  vlib_cli_output (vm, "%-2u: hash %.03f ticks/byte, %.02f Gbps\n",
			   i + 1, tpb1, gbps1);
	}
    }

done:
  if (n_alloc)
    vlib_buffer_free (vm, buffer_indices, n_alloc);

  if (ctx)
    vnet_crypto_ctx_destroy (vm, ctx);

  vec_free (buffer_indices);
  vec_free (ops1);
  vec_free (ops2);
  return err;
}

static clib_error_t *
test_crypto_command_dispatch (vlib_main_t *vm, unformat_input_t *input, u8 force_async)
{
  crypto_test_main_t *tm = &crypto_test_main;
  unittest_crypto_test_registration_t *tr;
  vnet_crypto_engine_id_t engine;
  int is_perf = 0;

  tr = tm->test_registrations;
  vec_free (tm->engine);
  memset (tm, 0, sizeof (crypto_test_main_t));
  tm->test_registrations = tr;
  tm->async = force_async;
  tm->elts_per_frame = 31;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "verbose"))
	tm->verbose = 1;
      else if (unformat (input, "quiet"))
	tm->quiet = 1;
      else if (unformat (input, "async"))
	tm->async = 1;
      else if (unformat (input, "engine %U", unformat_vnet_crypto_engine, &engine))
	tm->engine = format (0, "%U%c", format_vnet_crypto_engine, engine, 0);
      else if (unformat (input, "algo %U", unformat_vnet_crypto_alg, &tm->alg))
	tm->has_alg_filter = 1;
      else
	if (unformat (input, "perf %U", unformat_vnet_crypto_alg, &tm->alg))
	is_perf = 1;
      else if (unformat (input, "buffers %u", &tm->n_buffers))
	;
      else if (unformat (input, "rounds %u", &tm->rounds))
	;
      else if (unformat (input, "warmup-rounds %u", &tm->warmup_rounds))
	;
      else if (unformat (input, "buffer-size %u", &tm->buffer_size))
	;
      else if (unformat (input, "elts-per-frame %u", &tm->elts_per_frame))
	;
      else
	return clib_error_return (0, "unknown input '%U'",
				  format_unformat_error, input);
    }

  if (is_perf)
    {
      if (tm->async)
	return clib_error_return (0, "'async' and 'perf' are mutually exclusive");
      return test_crypto_perf (vm, tm);
    }
  else if (tm->async)
    return test_crypto_async (vm, tm);
  else
    return test_crypto (vm, tm);
}

static clib_error_t *
test_crypto_command_fn (vlib_main_t *vm, unformat_input_t *input,
			vlib_cli_command_t *cmd __clib_unused)
{
  return test_crypto_command_dispatch (vm, input, 0);
}

VLIB_CLI_COMMAND (test_crypto_command, static) = {
  .path = "test crypto",
  .short_help = "test crypto [quiet|verbose] [async [engine <name>]] [perf <alg>]",
  .function = test_crypto_command_fn,
};

static clib_error_t *
crypto_test_init (vlib_main_t * vm)
{
  return (0);
}

VLIB_INIT_FUNCTION (crypto_test_init);
