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
  vnet_crypto_op_id_t op_id;
  u8 is_chained;
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
    case VNET_CRYPTO_OP_TYPE_HASH:
      return r->hash.length != 0;
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
  return type == VNET_CRYPTO_OP_TYPE_HASH ? &r->hash : &r->digest;
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

  if (r0->reg == r1->reg && r0->op_id == r1->op_id)
    return r0->is_chained - r1->is_chained;

  if (r0->reg == r1->reg)
    return r0->op_id - r1->op_id;

  return strncmp (r0->reg->name, r1->reg->name, 256);
}

static int
crypto_test_result_table_find_row (crypto_test_result_table_t *rt,
				   unittest_crypto_test_registration_t *r,
				   vnet_crypto_op_id_t op_id, u8 is_chained)
{
  crypto_test_result_row_t *row;
  int i;

  vec_foreach_index (i, rt->rows)
    {
      row = vec_elt_at_index (rt->rows, i);
      if (row->reg == r && row->op_id == op_id && row->is_chained == is_chained)
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
			      unittest_crypto_test_registration_t *r, vnet_crypto_op_id_t op_id,
			      u8 is_chained, crypto_test_result_t result)
{
  int row, col;

  if (rt == 0)
    return;

  row = crypto_test_result_table_find_row (rt, r, op_id, is_chained);
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
static int
crypto_test_engine_has_sync_rows (crypto_test_result_row_t *rows, vnet_crypto_engine_id_t engine)
{
  vnet_crypto_main_t *cm = &crypto_main;
  vnet_crypto_engine_t *e = vec_elt_at_index (cm->engines, engine);
  crypto_test_result_row_t *row;
  vnet_crypto_handler_type_t ht;

  vec_foreach (row, rows)
    {
      ht = row->is_chained ? VNET_CRYPTO_HANDLER_TYPE_CHAINED : VNET_CRYPTO_HANDLER_TYPE_SIMPLE;
      if (e->ops[row->op_id].handlers[ht] != 0)
	return 1;
    }

  return 0;
}

static void
crypto_test_sync_result_table_init (crypto_test_result_table_t *rt, crypto_test_main_t *tm)
{
  vnet_crypto_main_t *cm = &crypto_main;
  unittest_crypto_test_registration_t *r = tm->test_registrations;
  unittest_crypto_test_registration_t **regs = 0;
  int i, j;

  *rt = (crypto_test_result_table_t){};
  crypto_test_result_table_init_engines (rt, tm);

  while (r)
    {
      vec_add1 (regs, r);
      r = r->next;
    }

  vec_sort_with_function (regs, sort_registrations);

  vec_foreach_index (i, regs)
    {
      vnet_crypto_alg_data_t *ad = cm->algs + regs[i]->alg;

      for (j = 0; j < VNET_CRYPTO_OP_N_TYPES; j++)
	{
	  vnet_crypto_op_id_t id = ad->op_by_type[j];

	  if (!crypto_test_reg_has_op_type (regs[i], j))
	    continue;
	  if (id == 0)
	    continue;

	  vec_add1 (rt->rows, ((crypto_test_result_row_t){
				.reg = regs[i],
				.op_id = id,
				.is_chained = 0,
			      }));

	  if (regs[i]->plaintext_incremental == 0)
	    vec_add1 (rt->rows, ((crypto_test_result_row_t){
				  .reg = regs[i],
				  .op_id = id,
				  .is_chained = 1,
				}));
	}
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

	  chained_row = crypto_test_result_table_find_row (rt, row->reg, row->op_id, 1);
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

      if (prev_row && prev_row->reg == row->reg &&
	  cm->opt_data[prev_row->op_id].alg == cm->opt_data[row->op_id].alg)
	table_format_cell (&t, j, 0, "");
      else
	table_format_cell (&t, j, 0, "%s", cm->algs[cm->opt_data[row->op_id].alg].name);

      table_format_cell (&t, j, 1, "%U", format_crypto_op_type_short,
			 cm->opt_data[row->op_id].type);
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

	  chained_row = crypto_test_result_table_find_row (rt, row->reg, row->op_id, 1);
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
crypto_test_print_not_supported (unittest_crypto_test_registration_t *r, vnet_crypto_op_id_t op_id,
				 u8 is_chained, crypto_test_engine_summary_t *summary,
				 vnet_crypto_engine_id_t engine,
				 crypto_test_result_table_t *results)
{
  summary->not_supported[is_chained]++;
  crypto_test_result_table_set (results, engine, r, op_id, is_chained,
				CRYPTO_TEST_RESULT_NOT_SUPPORTED);
}

static void
print_results (unittest_crypto_test_registration_t **rv, vnet_crypto_op_t *ops,
	       vnet_crypto_op_chunk_t *chunks, u32 n_ops, crypto_test_main_t *tm,
	       crypto_test_engine_summary_t *summary, vnet_crypto_engine_id_t engine,
	       crypto_test_result_table_t *results)
{
  vnet_crypto_main_t *cm = &crypto_main;
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
      vnet_crypto_op_data_t *od = cm->opt_data + op->op;
      vnet_crypto_alg_data_t *ad = cm->algs + od->alg;

      switch (vnet_crypto_get_op_type (op->op))
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
	case VNET_CRYPTO_OP_TYPE_HASH:
	  exp_digest = &r->hash;
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

      if (exp_tag && memcmp (op->tag, exp_tag->data, exp_tag->length) != 0)
	err = format (err, "%stag mismatch", vec_len (err) ? ", " : "");

      if (exp_digest && memcmp (op->digest, exp_digest->data, exp_digest->length) != 0)
	err = format (err, "%sdigest mismatch", vec_len (err) ? ", " : "");

      if (vec_len (err))
	fail = 1;

      if (fail)
	summary->fail[is_chained]++;
      else
	summary->ok[is_chained]++;

      crypto_test_result_table_set (results, engine, r, op->op, is_chained,
				    fail ? CRYPTO_TEST_RESULT_FAIL : CRYPTO_TEST_RESULT_OK);
    }
  vec_free (err);
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
  vnet_crypto_op_id_t id = ad->op_by_type[type];
  vnet_crypto_engine_t *e = vec_elt_at_index (cm->engines, engine);

  if (id == 0)
    return 0;
  if (!crypto_test_reg_has_op_type (r, type))
    return 0;

  ht = is_chained ? VNET_CRYPTO_HANDLER_TYPE_CHAINED : VNET_CRYPTO_HANDLER_TYPE_SIMPLE;
  return e->ops[id].handlers[ht] != 0;
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

static vnet_crypto_key_t *
crypto_test_key_add_data (vlib_main_t *vm, vnet_crypto_engine_id_t engine, vnet_crypto_alg_t alg,
			  const u8 *key_data, u16 key_len)
{
  vnet_crypto_main_t *cm = &crypto_main;
  vnet_crypto_alg_data_t *ad = cm->algs + alg;

  if (ad->alg_type == VNET_CRYPTO_ALG_T_COMBINED)
    return vnet_crypto_key_add_for_engine (vm, engine, alg, key_data, ad->key_len,
					   key_data + ad->key_len, key_len - ad->key_len);

  return vnet_crypto_key_add_for_engine (vm, engine, alg, key_data, key_len, 0, 0);
}

static vnet_crypto_key_t *
crypto_test_key_add (vlib_main_t *vm, vnet_crypto_engine_id_t engine,
		     unittest_crypto_test_registration_t *r)
{
  vnet_crypto_main_t *cm = &crypto_main;

  if (cm->algs[r->alg].alg_type == VNET_CRYPTO_ALG_T_INTEG && r->digest.length == 0)
    return 0;

  return crypto_test_key_add_data (vm, engine, r->alg, r->key.data, r->key.length);
}

static clib_error_t *
generate_digest (vlib_main_t *vm, unittest_crypto_test_registration_t *r, vnet_crypto_op_id_t id,
		 vnet_crypto_engine_id_t engine)
{
  crypto_test_main_t *cm = &crypto_test_main;
  vnet_crypto_op_t op[1];
  clib_error_t *err = 0;

  vnet_crypto_op_init (op, id);
  vec_validate (r->digest.data, r->digest.length - 1);
  op->integ_src = cm->inc_data;
  op->integ_len = r->plaintext_incremental;
  op->digest = r->digest.data;
  op->digest_len = r->digest.length;
  op->key = crypto_test_key_add_data (vm, engine, r->alg, cm->inc_data, r->key.length);
  if (op->key == 0)
    return clib_error_return (0, "failed to add key for digest generation");

  vnet_crypto_process_ops_with_engine (vm, engine, op, 1);
  if (op->status != VNET_CRYPTO_OP_STATUS_COMPLETED)
    err = clib_error_return (0, "digest generation failed: %U", format_vnet_crypto_op_status,
			     op->status);

  vnet_crypto_key_del (vm, op->key);
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
  vnet_crypto_key_t **keys = 0;
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
	  vnet_crypto_op_id_t id = ad->op_by_type[t];

	  if (!crypto_test_reg_has_op_type (r, t))
	    continue;
	  if (id == 0)
	    continue;
	  if (!crypto_test_op_supported (engine, r, t, 0))
	    continue;

	  switch (t)
	    {
	    case VNET_CRYPTO_OP_TYPE_ENCRYPT:
	      op = encrypt_ops + n_encrypt_ops++;
	      vnet_crypto_op_init (op, id);
	      op->iv = tm->inc_data;
	      op->key = crypto_test_key_add_data (vm, engine, r->alg, tm->inc_data, r->key.length);
	      vec_add1 (keys, op->key);
	      op->len = r->plaintext_incremental;
	      op->src = tm->inc_data;
	      op->dst = encrypted_data + computed_data_total_len;
	      computed_data_total_len += r->plaintext_incremental;

	      if (ad->alg_type == VNET_CRYPTO_ALG_T_AEAD)
		{
		  op->aad = tm->inc_data;
		  op->aad_len = r->aad.length;
		  op->tag = encrypted_data + computed_data_total_len;
		  computed_data_total_len += r->tag.length;
		  op->tag_len = r->tag.length;
		}
	      op->user_data = i;
	      break;
	    case VNET_CRYPTO_OP_TYPE_HMAC:
	      computed_data_total_len += r->digest.length;
	      break;
	    case VNET_CRYPTO_OP_TYPE_HASH:
	      computed_data_total_len += r->hash.length;
	      break;
	    default:
	      break;
	    };
	}
    }

  if (n_encrypt_ops)
    {
      vnet_crypto_process_ops_with_engine (vm, engine, encrypt_ops, n_encrypt_ops);
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

	  crypto_test_result_table_set (results, engine, r, op->op, 0, result);
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
	  vnet_crypto_op_id_t id = ad->op_by_type[t];

	  if (!crypto_test_reg_has_op_type (r, t))
	    continue;
	  if (id == 0)
	    continue;
	  if (!crypto_test_op_supported (engine, r, t, 0))
	    continue;

	  switch (t)
	    {
	    case VNET_CRYPTO_OP_TYPE_DECRYPT:
	      op = ops + n_check_ops++;
	      vnet_crypto_op_init (op, id);
	      op->iv = tm->inc_data;
	      op->key = crypto_test_key_add_data (vm, engine, r->alg, tm->inc_data, r->key.length);
	      vec_add1 (keys, op->key);
	      op->len = r->plaintext_incremental;
	      op->src = encrypted_data + computed_data_total_len;
	      op->dst = decrypted_data + computed_data_total_len;
	      computed_data_total_len += r->plaintext_incremental;

	      if (ad->alg_type == VNET_CRYPTO_ALG_T_AEAD)
		{
		  op->aad = tm->inc_data;
		  op->aad_len = r->aad.length;
		  op->tag = encrypted_data + computed_data_total_len;
		  computed_data_total_len += r->tag.length;
		  op->tag_len = r->tag.length;
		}
	      op->user_data = i;
	      break;
	    case VNET_CRYPTO_OP_TYPE_HMAC:
	      op = ops + n_check_ops++;
	      vnet_crypto_op_init (op, id);
	      op->key = crypto_test_key_add_data (vm, engine, r->alg, tm->inc_data, r->key.length);
	      vec_add1 (keys, op->key);
	      op->integ_src = tm->inc_data;
	      op->integ_len = r->plaintext_incremental;
	      op->digest_len = r->digest.length;
	      op->digest = encrypted_data + computed_data_total_len;
	      computed_data_total_len += r->digest.length;
	      op->user_data = i;
	      break;
	    case VNET_CRYPTO_OP_TYPE_HASH:
	      op = ops + n_check_ops++;
	      vnet_crypto_op_init (op, id);
	      op->src = tm->inc_data;
	      op->len = r->plaintext_incremental;
	      op->digest_len = r->hash.length;
	      op->digest = encrypted_data + computed_data_total_len;
	      computed_data_total_len += r->hash.length;
	      op->user_data = i;
	      break;
	    default:
	      break;
	    };
	}
    }

  if (n_check_ops)
    {
      vnet_crypto_process_ops_with_engine (vm, engine, ops, n_check_ops);
      print_results (rv, ops, 0, n_check_ops, tm, summary, engine, results);
    }

  vec_foreach_index (i, keys)
    vnet_crypto_key_del (vm, keys[i]);
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
  vnet_crypto_op_t *ops = 0, *op, *chained_ops = 0;
  vnet_crypto_op_t *current_chained_op = 0, *current_op = 0;
  vnet_crypto_main_t *cm = &crypto_main;
  vnet_crypto_alg_data_t *ad;
  vnet_crypto_key_t **keys = 0;
  u8 *computed_data = 0;
  u32 i, j;

  if (n_ops == 0 && n_chained_ops == 0)
    return 0;

  vec_sort_with_function (rv, sort_registrations);

  if (computed_data_total_len)
    vec_validate_aligned (computed_data, computed_data_total_len - 1, CLIB_CACHE_LINE_BYTES);
  if (n_ops)
    vec_validate_aligned (ops, n_ops - 1, CLIB_CACHE_LINE_BYTES);
  if (n_chained_ops)
    vec_validate_aligned (chained_ops, n_chained_ops - 1, CLIB_CACHE_LINE_BYTES);
  computed_data_total_len = 0;

  current_op = ops;
  current_chained_op = chained_ops;
  vec_foreach_index (i, rv)
    {
      r = rv[i];
      int t;

      ad = cm->algs + r->alg;
      for (t = 0; t < VNET_CRYPTO_OP_N_TYPES; t++)
	{
	  vnet_crypto_op_id_t id = ad->op_by_type[t];
	  u32 is_chained;

	  if (!crypto_test_reg_has_op_type (r, t))
	    continue;
	  if (id == 0)
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

	      vnet_crypto_op_init (op, id);

	      switch (t)
		{
		case VNET_CRYPTO_OP_TYPE_ENCRYPT:
		case VNET_CRYPTO_OP_TYPE_DECRYPT:
		  if (ad->alg_type != VNET_CRYPTO_ALG_T_AEAD)
		    {
		      op->iv = r->iv.data;
		      op->key = crypto_test_key_add (vm, engine, r);
		      vec_add1 (keys, op->key);

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
			      op->digest_len = r->digest.length;
			      if (t == VNET_CRYPTO_OP_TYPE_ENCRYPT)
				{
				  op->digest = computed_data + computed_data_total_len;
				  computed_data_total_len += r->digest.length;
				  op->integ_chunk_index = vec_len (chunks);
				  op->integ_n_chunks = 0;
				  for (j = 0; j < op->n_chunks; j++)
				    {
				      clib_memset (&ch, 0, sizeof (ch));
				      ch.src = vec_elt_at_index (chunks, op->chunk_index + j)->dst;
				      ch.len = vec_elt_at_index (chunks, op->chunk_index + j)->len;
				      vec_add1 (chunks, ch);
				      op->integ_n_chunks++;
				    }
				}
			      else
				{
				  op->flags |= VNET_CRYPTO_OP_FLAG_HMAC_CHECK;
				  op->digest = r->digest.data;
				  op->integ_chunk_index = op->chunk_index;
				  op->integ_n_chunks = op->n_chunks;
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
			      op->integ_src = t == VNET_CRYPTO_OP_TYPE_ENCRYPT ? op->dst : op->src;
			      op->integ_len = r->ciphertext.length;
			      op->digest_len = r->digest.length;
			      if (t == VNET_CRYPTO_OP_TYPE_ENCRYPT)
				{
				  op->digest = computed_data + computed_data_total_len;
				  computed_data_total_len += r->digest.length;
				}
			      else
				{
				  op->flags |= VNET_CRYPTO_OP_FLAG_HMAC_CHECK;
				  op->digest = r->digest.data;
				}
			    }
			}
		    }
		  else
		    {
		      op->iv = r->iv.data;
		      op->key = crypto_test_key_add (vm, engine, r);
		      vec_add1 (keys, op->key);
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
			      op->tag = computed_data + computed_data_total_len;
			      computed_data_total_len += r->tag.length;
			    }
			  else
			    op->tag = r->tag.data;
			}
		      else
			{
			  op->len = r->plaintext.length;
			  op->dst = computed_data + computed_data_total_len;
			  computed_data_total_len += r->ciphertext.length;

			  if (t == VNET_CRYPTO_OP_TYPE_ENCRYPT)
			    {
			      op->src = r->plaintext.data;
			      op->tag = computed_data + computed_data_total_len;
			      computed_data_total_len += r->tag.length;
			    }
			  else
			    {
			      op->tag = r->tag.data;
			      op->src = r->ciphertext.data;
			    }
			}
		      op->tag_len = r->tag.length;
		    }
		  break;
		case VNET_CRYPTO_OP_TYPE_HMAC:
		  op->key = crypto_test_key_add (vm, engine, r);
		  vec_add1 (keys, op->key);
		  op->digest_len = r->digest.length;
		  op->digest = computed_data + computed_data_total_len;
		  computed_data_total_len += r->digest.length;
		  if (is_chained)
		    {
		      op->flags |= VNET_CRYPTO_OP_FLAG_CHAINED_BUFFERS;
		      op->integ_chunk_index = vec_len (chunks);
		      crypto_test_append_data_chunks (&chunks, r->plaintext.data,
						      r->plaintext.length);
		      op->integ_n_chunks = vec_len (chunks) - op->integ_chunk_index;
		    }
		  else
		    {
		      op->integ_src = r->plaintext.data;
		      op->integ_len = r->plaintext.length;
		    }
		  break;
		case VNET_CRYPTO_OP_TYPE_HASH:
		  op->digest_len = r->hash.length;
		  op->digest = computed_data + computed_data_total_len;
		  computed_data_total_len += r->hash.length;
		  if (is_chained)
		    {
		      op->flags |= VNET_CRYPTO_OP_FLAG_CHAINED_BUFFERS;
		      op->chunk_index = vec_len (chunks);
		      crypto_test_append_data_chunks (&chunks, r->plaintext.data,
						      r->plaintext.length);
		      op->n_chunks = vec_len (chunks) - op->chunk_index;
		    }
		  else
		    {
		      op->src = r->plaintext.data;
		      op->len = r->plaintext.length;
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
    vnet_crypto_process_ops_with_engine (vm, engine, ops, vec_len (ops));
  if (vec_len (chained_ops))
    vnet_crypto_process_chained_ops_with_engine (vm, engine, chained_ops, chunks,
						 vec_len (chained_ops));

  print_results (rv, ops, chunks, vec_len (ops), tm, summary, engine, results);
  print_results (rv, chained_ops, chunks, vec_len (chained_ops), tm, summary, engine, results);

  vec_foreach_index (i, keys)
    vnet_crypto_key_del (vm, keys[i]);
  vec_free (computed_data);
  vec_free (ops);
  vec_free (chained_ops);
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
  unittest_crypto_test_registration_t **static_tests = 0, **inc_tests = 0;
  crypto_test_result_table_t *rt = results;
  u32 i, n_ops_static = 0, n_ops_incr = 0, n_chained_ops = 0;
  vnet_crypto_alg_data_t *ad;
  u32 computed_data_total_len = 0;
  u32 computed_data_total_incr_len = 0;
  crypto_test_engine_summary_t summary = {};

  while (r)
    {
      int used = 0;

      ad = cm->algs + r->alg;
      for (i = 0; i < VNET_CRYPTO_OP_N_TYPES; i++)
	{
	  vnet_crypto_op_id_t id = ad->op_by_type[i];
	  u32 max_mode = r->plaintext_incremental ? 0 : 1;
	  u32 is_chained;

	  if (!crypto_test_reg_has_op_type (r, i))
	    continue;
	  if (id == 0)
	    continue;

	  for (is_chained = 0; is_chained <= max_mode; is_chained++)
	    {
	      if (!crypto_test_op_supported (engine, r, i, is_chained))
		{
		  crypto_test_print_not_supported (r, id, is_chained, &summary, engine, results);
		  continue;
		}

	      used = 1;

	      switch (i)
		{
		case VNET_CRYPTO_OP_TYPE_ENCRYPT:
		  if (ad->alg_type == VNET_CRYPTO_ALG_T_AEAD)
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
			  ad->alg_type == VNET_CRYPTO_ALG_T_COMBINED)
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
		case VNET_CRYPTO_OP_TYPE_HASH:
		  computed_data_total_len += r->hash.length;
		  if (is_chained)
		    n_chained_ops += 1;
		  else
		    n_ops_static += 1;
		  break;
		default:
		  break;
		};
	    }
	}

      if (used)
	{
	  if (r->plaintext_incremental)
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
  vec_free (static_tests);
  return err;
}

static clib_error_t *
test_crypto (vlib_main_t *vm, crypto_test_main_t *tm)
{
  clib_error_t *err = 0;
  vnet_crypto_main_t *cm = &crypto_main;
  unittest_crypto_test_registration_t *r = tm->test_registrations;
  vnet_crypto_alg_data_t *ad;
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
      ad = cm->algs + r->alg;

      for (i = 0; i < VNET_CRYPTO_OP_N_TYPES; i++)
	{
	  vnet_crypto_op_id_t id = ad->op_by_type[i];

	  if (id == 0)
	    continue;
	  if (i == VNET_CRYPTO_OP_TYPE_HMAC && r->plaintext_incremental &&
	      crypto_test_reg_has_op_type (r, i))
	    {
	      err = generate_digest (vm, r, id, ref_engine);
	      if (err)
		goto done;
	    }
	}

      /* next: */
      r = r->next;
    }

  if (tm->engine)
    {
      err = test_crypto_engine (vm, tm, engine, &results);
    }
  else
    {
      vec_foreach_index (i, results.engines)
	{
	  err = test_crypto_engine (vm, tm, results.engines[i], &results);
	  if (err)
	    break;
	}
    }

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

typedef struct
{
  vnet_crypto_alg_t base_alg;
  vnet_crypto_alg_t fixed_alg;
  u8 digest_len;
  u8 aad_len;
} crypto_test_aead_fixed_alg_t;

static const crypto_test_aead_fixed_alg_t crypto_test_aead_fixed_algs[] = {
#define _(n, s, cf, inf, k, t, a, b)                                                               \
  {                                                                                                \
    .base_alg = VNET_CRYPTO_ALG_##n,                                                               \
    .fixed_alg = VNET_CRYPTO_ALG_##n##_TAG##t##_AAD##a,                                            \
    .digest_len = t,                                                                               \
    .aad_len = a,                                                                                  \
  },
  foreach_crypto_aead_async_alg
#undef _
};

static vnet_crypto_op_id_t
crypto_test_get_async_op_id (unittest_crypto_test_registration_t *r, vnet_crypto_op_type_t op_type)
{
  vnet_crypto_main_t *cm = &crypto_main;
  vnet_crypto_alg_data_t *ad = cm->algs + r->alg;
  vnet_crypto_op_id_t op_id = ad->op_by_type[op_type];
  u32 i;

  if (!crypto_test_reg_has_op_type (r, op_type))
    return 0;

  if (ad->alg_type != VNET_CRYPTO_ALG_T_AEAD)
    return op_id;

  if (op_id)
    {
      vnet_crypto_op_data_t *od = cm->opt_data + op_id;

      if (od->aad_len == r->aad.length && od->digest_len == r->tag.length)
	return op_id;
    }

  for (i = 0; i < ARRAY_LEN (crypto_test_aead_fixed_algs); i++)
    {
      const crypto_test_aead_fixed_alg_t *fa = crypto_test_aead_fixed_algs + i;

      if (fa->base_alg != r->alg)
	continue;
      if (fa->aad_len != r->aad.length)
	continue;
      if (fa->digest_len != r->tag.length)
	continue;

      return cm->algs[fa->fixed_alg].op_by_type[op_type];
    }

  return op_id;
}

static int
crypto_test_engine_has_async_rows (crypto_test_result_row_t *rows, vnet_crypto_engine_id_t engine)
{
  vnet_crypto_main_t *cm = &crypto_main;
  vnet_crypto_engine_t *e = vec_elt_at_index (cm->engines, engine);
  crypto_test_result_row_t *row;

  if (e->dequeue_handler == 0)
    return 0;

  vec_foreach (row, rows)
    if (e->ops[row->op_id].handlers[VNET_CRYPTO_HANDLER_TYPE_ASYNC] != 0)
      return 1;

  return 0;
}

static void
crypto_test_async_result_table_init (crypto_test_result_table_t *rt, crypto_test_main_t *tm)
{
  unittest_crypto_test_registration_t *r = tm->test_registrations;
  unittest_crypto_test_registration_t **regs = 0;
  int i, j;

  *rt = (crypto_test_result_table_t){};
  crypto_test_result_table_init_engines (rt, tm);

  while (r)
    {
      if (r->plaintext_incremental == 0)
	vec_add1 (regs, r);
      r = r->next;
    }

  vec_sort_with_function (regs, sort_registrations);

  vec_foreach_index (i, regs)
    {
      for (j = 0; j < VNET_CRYPTO_OP_N_TYPES; j++)
	{
	  if (!crypto_test_reg_has_op_type (regs[i], j))
	    continue;
	  vnet_crypto_op_id_t id = crypto_test_get_async_op_id (regs[i], j);

	  if (id == 0)
	    continue;

	  vec_add1 (rt->rows, ((crypto_test_result_row_t){
				.reg = regs[i],
				.op_id = id,
				.is_chained = 0,
			      }));
	  vec_add1 (rt->rows, ((crypto_test_result_row_t){
				.reg = regs[i],
				.op_id = id,
				.is_chained = 1,
			      }));
	}
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

static vnet_crypto_key_t *
crypto_test_async_key_add (vlib_main_t *vm, vnet_crypto_engine_id_t engine,
			   unittest_crypto_test_registration_t *r, vnet_crypto_op_type_t op_type)
{
  vnet_crypto_main_t *cm = &crypto_main;
  vnet_crypto_alg_data_t *ad = cm->algs + r->alg;

  if (op_type == VNET_CRYPTO_OP_TYPE_HASH)
    return 0;

  if (ad->alg_type == VNET_CRYPTO_ALG_T_COMBINED)
    return vnet_crypto_key_add_for_async_engine (vm, engine, r->alg, r->key.data, ad->key_len,
						 r->key.data + ad->key_len,
						 r->key.length - ad->key_len);

  return vnet_crypto_key_add_for_async_engine (vm, engine, r->alg, r->key.data, r->key.length, 0,
					       0);
}

static clib_error_t *
test_crypto_async_case (vlib_main_t *vm, unittest_crypto_test_registration_t *r,
			vnet_crypto_engine_id_t engine, vnet_crypto_op_id_t op_id, u8 is_chained,
			crypto_test_result_t *test_result)
{
  vlib_main_t *async_vm;
  vnet_crypto_main_t *cm = &crypto_main;
  vnet_crypto_alg_data_t *ad = cm->algs + r->alg;
  vnet_crypto_op_type_t op_type = vnet_crypto_get_op_type (op_id);
  vnet_crypto_async_frame_t *frame = 0;
  unittest_crypto_test_data_t *input = 0;
  unittest_crypto_test_data_t *output = 0;
  vlib_buffer_t *head = 0;
  u32 buffer_indices[3];
  u32 n_alloc = 0;
  u32 n_buffers;
  u32 scratch_len;
  u32 digest_len = 0;
  u8 *aad = 0;
  u8 *err = 0;
  u8 *iv = 0;
  u8 *tag = 0;
  u8 flags = 0;
  u8 submitted = 0;
  vnet_crypto_key_t *key = 0;
  crypto_test_async_result_t result = {};
  clib_error_t *rv = 0;
  vnet_crypto_async_frame_elt_t *fe;
  int has_key = 0;

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
    case VNET_CRYPTO_OP_TYPE_HASH:
      input = &r->plaintext;
      break;
    case VNET_CRYPTO_OP_N_TYPES:
      return clib_error_return (0, "invalid async op type");
    }

  if (ad->alg_type == VNET_CRYPTO_ALG_T_AEAD)
    digest_len = r->tag.length;
  else if (ad->alg_type == VNET_CRYPTO_ALG_T_COMBINED || op_type == VNET_CRYPTO_OP_TYPE_HMAC ||
	   op_type == VNET_CRYPTO_OP_TYPE_HASH)
    digest_len = crypto_test_digest_data (r, op_type)->length;

  scratch_len = r->iv.length + r->aad.length + digest_len;
  if (scratch_len > VLIB_BUFFER_PRE_DATA_SIZE)
    return clib_error_return (0, "buffer headroom too small for async test");

  n_buffers = is_chained ? crypto_test_async_chunk_count (input->length) : 1;

  n_alloc = vlib_buffer_alloc (vm, buffer_indices, n_buffers);
  if (n_alloc != n_buffers)
    {
      if (n_alloc)
	vlib_buffer_free (vm, buffer_indices, n_alloc);
      return clib_error_return (0, "buffer alloc failure");
    }

  key = crypto_test_async_key_add (async_vm, engine, r, op_type);
  has_key = key != 0;
  if (op_type != VNET_CRYPTO_OP_TYPE_HASH && has_key == 0)
    {
      rv = clib_error_return (0, "key add failed");
      goto done;
    }

  frame = vnet_crypto_async_get_frame (async_vm, op_id);
  if (frame == 0)
    {
      rv = clib_error_return (0, "async frame alloc failed");
      goto done;
    }

  crypto_test_async_buffer_chain_init (vm, buffer_indices, n_buffers, input);

  head = vlib_get_buffer (vm, buffer_indices[0]);
  iv = head->pre_data;
  aad = iv + r->iv.length;
  tag = aad + r->aad.length;
  flags = is_chained ? VNET_CRYPTO_OP_FLAG_CHAINED_BUFFERS : 0;

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

  vnet_crypto_async_add_to_frame (async_vm, frame, has_key ? key : 0, input->length, 0, 0, 0,
				  buffer_indices[0], 0, iv - head->data, tag - head->data,
				  aad - head->data, flags);

  fe = &frame->elts[0];
  fe->aad_len = r->aad.length;
  fe->digest_len = digest_len;

  if (vnet_crypto_async_submit_open_frame_with_engine (async_vm, engine, frame) < 0)
    {
      rv = clib_error_return (0, "async enqueue failed");
      goto done;
    }
  submitted = 1;

  rv = crypto_test_wait_for_async_frame (vm, engine, frame, &result);
  if (rv)
    goto done;

  if (result.frame->state != VNET_CRYPTO_FRAME_STATE_SUCCESS)
    {
      if (result.frame->elts[0].status != VNET_CRYPTO_OP_STATUS_COMPLETED)
	err = format (err, "%U", format_vnet_crypto_op_status, result.frame->elts[0].status);
    }

  if (output && crypto_test_async_buffer_chain_compare (vm, buffer_indices[0], output))
    err = format (err, "%s%s mismatch", vec_len (err) ? ", " : "",
		  op_type == VNET_CRYPTO_OP_TYPE_ENCRYPT ? "ciphertext" : "plaintext");

  if (ad->alg_type == VNET_CRYPTO_ALG_T_AEAD && op_type == VNET_CRYPTO_OP_TYPE_ENCRYPT &&
      r->tag.length && memcmp (tag, r->tag.data, r->tag.length))
    err = format (err, "%stag mismatch", vec_len (err) ? ", " : "");

  if ((ad->alg_type == VNET_CRYPTO_ALG_T_COMBINED || op_type == VNET_CRYPTO_OP_TYPE_HMAC ||
       op_type == VNET_CRYPTO_OP_TYPE_HASH) &&
      op_type != VNET_CRYPTO_OP_TYPE_DECRYPT && digest_len &&
      memcmp (tag, crypto_test_digest_data (r, op_type)->data,
	      crypto_test_digest_data (r, op_type)->length))
    err = format (err, "%sdigest mismatch", vec_len (err) ? ", " : "");

  *test_result = vec_len (err) ? CRYPTO_TEST_RESULT_FAIL : CRYPTO_TEST_RESULT_OK;

done:
  vec_free (err);
  if (result.frame)
    vnet_crypto_async_free_frame (vlib_get_main_by_index (result.frame->enqueue_thread_index),
				  result.frame);
  if (frame && !submitted)
    vnet_crypto_async_free_frame (async_vm, frame);
  if (n_alloc && (!submitted || result.frame))
    {
      if (is_chained)
	vlib_buffer_free (vm, buffer_indices, 1);
      else
	vlib_buffer_free (vm, buffer_indices, n_alloc);
    }
  if (has_key && (result.frame || !submitted))
    vnet_crypto_key_del (async_vm, key);
  return rv;
}

static clib_error_t *
test_crypto_async_engine (vlib_main_t *vm, crypto_test_main_t *tm, vnet_crypto_engine_id_t engine,
			  crypto_test_result_table_t *results)
{
  clib_error_t *err = 0;
  unittest_crypto_test_registration_t *r = tm->test_registrations;
  crypto_test_engine_summary_t summary = {};
  crypto_test_result_t result;
  u32 i;

  while (r)
    {
      if (r->plaintext_incremental)
	{
	  r = r->next;
	  continue;
	}

      for (i = 0; i < VNET_CRYPTO_OP_N_TYPES; i++)
	{
	  vnet_crypto_op_id_t id = crypto_test_get_async_op_id (r, i);
	  u32 is_chained;

	  if (id == 0)
	    continue;

	  if (vec_elt_at_index (crypto_main.engines, engine)->dequeue_handler == 0 ||
	      vec_elt_at_index (crypto_main.engines, engine)
		  ->ops[id]
		  .handlers[VNET_CRYPTO_HANDLER_TYPE_ASYNC] == 0)
	    {
	      crypto_test_print_not_supported (r, id, 0, &summary, engine, results);
	      crypto_test_print_not_supported (r, id, 1, &summary, engine, results);
	      continue;
	    }

	  for (is_chained = 0; is_chained <= 1; is_chained++)
	    {
	      err = test_crypto_async_case (vm, r, engine, id, is_chained, &result);
	      if (err)
		{
		  summary.error[is_chained]++;
		  crypto_test_result_table_set (results, engine, r, id, is_chained,
						CRYPTO_TEST_RESULT_ERROR);
		  if (tm->verbose)
		    vlib_cli_output (vm, "%s op %u %s: %U", r->name, id,
				     is_chained ? "chained" : "simple", format_clib_error, err);
		  clib_error_free (err);
		  err = 0;
		  continue;
		}

	      if (result == CRYPTO_TEST_RESULT_OK)
		summary.ok[is_chained]++;
	      else
		summary.fail[is_chained]++;

	      crypto_test_result_table_set (results, engine, r, id, is_chained, result);
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

  if (tm->engine)
    err = test_crypto_async_engine (vm, tm, engine, &results);
  else
    {
      vec_foreach_index (i, results.engines)
	{
	  err = test_crypto_async_engine (vm, tm, results.engines[i], &results);
	  if (err)
	    break;
	}
    }

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
  vnet_crypto_key_t *key = 0;
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

  vnet_crypto_op_type_t ot = 0;

  for (i = 0; i < sizeof (key_data); i++)
    key_data[i] = i;

  if (ad->alg_type == VNET_CRYPTO_ALG_T_COMBINED)
    {
      vnet_crypto_op_id_t enc_op_id = ad->op_by_type[VNET_CRYPTO_OP_TYPE_ENCRYPT];
      if (enc_op_id && ad->op_by_type[VNET_CRYPTO_OP_TYPE_DECRYPT] && ad->key_len)
	{
	  combined_digest_len = ad->digest_len;
	  if (combined_digest_len)
	    {
	      is_combined_alg = 1;
	      combined_crypto_key_len = ad->key_len;
	    }
	}
    }

  /* Handle combined algorithms (crypto+integrity) */
  if (is_combined_alg)
    {
      key_sz = combined_crypto_key_len + 32;
      for (i = 0; i < key_sz; i++)
	key_data[i] = i;
    }
  else
    {
      key_sz = cm->algs[tm->alg].key_len;
      if (key_sz == 0)
	key_sz = 32; /* Use 32 bytes for HMAC algorithms (0 key_len) */
      for (i = 0; i < key_sz; i++)
	key_data[i] = i;
    }
  if (tm->engine)
    key = crypto_test_key_add_data (vm, engine, tm->alg, key_data, key_sz);
  else if (is_combined_alg)
    key =
      vnet_crypto_key_add (vm, tm->alg, key_data, combined_crypto_key_len,
			   key_data + combined_crypto_key_len, key_sz - combined_crypto_key_len);
  else
    key = vnet_crypto_key_add (vm, tm->alg, key_data, key_sz, 0, 0);

  for (i = 0; i < VNET_CRYPTO_OP_N_TYPES; i++)
    {
      vnet_crypto_op_id_t id = ad->op_by_type[i];
      if (id == 0)
	continue;
      ot = i;
      break;
    }

  for (i = 0; i < n_buffers; i++)
    {
      vlib_buffer_t *b = vlib_get_buffer (vm, buffer_indices[i]);
      op1 = ops1 + i;
      op2 = ops2 + i;

      switch (ot)
	{
	case VNET_CRYPTO_OP_TYPE_ENCRYPT:
	case VNET_CRYPTO_OP_TYPE_DECRYPT:
	  vnet_crypto_op_init (op1,
			       ad->op_by_type[VNET_CRYPTO_OP_TYPE_ENCRYPT]);
	  vnet_crypto_op_init (op2,
			       ad->op_by_type[VNET_CRYPTO_OP_TYPE_DECRYPT]);
	  op1->src = op2->src = op1->dst = op2->dst = b->data;
	  op1->key = op2->key = key;
	  op1->iv = op2->iv = b->data - 64;

	  if (is_combined_alg)
	    {
	      /* For combined algorithms, both encrypt and decrypt operations
	       * include integrity (HMAC) processing */
	      op1->integ_src = op2->integ_src = b->data;
	      op1->integ_len = op2->integ_len = buffer_size;
	      op1->digest = op2->digest = b->data - VLIB_BUFFER_PRE_DATA_SIZE;
	      op1->digest_len = op2->digest_len = combined_digest_len;
	      op2->flags |= VNET_CRYPTO_OP_FLAG_HMAC_CHECK;
	    }
	  else if (ad->alg_type == VNET_CRYPTO_ALG_T_AEAD)
	    {
	      op1->tag = op2->tag = b->data - 32;
	      op1->aad = op2->aad = b->data - VLIB_BUFFER_PRE_DATA_SIZE;
	      op1->aad_len = op2->aad_len = 64;
	      op1->tag_len = op2->tag_len = 16;
	    }

	  op1->len = op2->len = buffer_size;
	  break;
	case VNET_CRYPTO_OP_TYPE_HMAC:
	  vnet_crypto_op_init (op1, ad->op_by_type[VNET_CRYPTO_OP_TYPE_HMAC]);
	  op1->integ_src = b->data;
	  op1->key = key;
	  op1->digest = b->data - VLIB_BUFFER_PRE_DATA_SIZE;
	  op1->digest_len = 12;
	  op1->integ_len = buffer_size;
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
	    vnet_crypto_process_ops_with_engine (vm, engine, ops1, n_buffers);
	  else
	    vnet_crypto_process_ops (vm, ops1, n_buffers);
	  if (ot != VNET_CRYPTO_OP_TYPE_HMAC)
	    {
	      if (tm->engine)
		vnet_crypto_process_ops_with_engine (vm, engine, ops2, n_buffers);
	      else
		vnet_crypto_process_ops (vm, ops2, n_buffers);
	    }
	}

      t0[i] = clib_cpu_time_now ();
      for (j = 0; j < rounds; j++)
	{
	  if (tm->engine)
	    vnet_crypto_process_ops_with_engine (vm, engine, ops1, n_buffers);
	  else
	    vnet_crypto_process_ops (vm, ops1, n_buffers);
	}
      t1[i] = clib_cpu_time_now ();

      if (ot != VNET_CRYPTO_OP_TYPE_HMAC)
	{
	  for (j = 0; j < rounds; j++)
	    {
	      if (tm->engine)
		vnet_crypto_process_ops_with_engine (vm, engine, ops2, n_buffers);
	      else
		vnet_crypto_process_ops (vm, ops2, n_buffers);
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

  if (key)
    vnet_crypto_key_del (vm, key);

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
  tm->alg = ~0;
  tm->async = force_async;

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
