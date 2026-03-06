/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco and/or its affiliates.
 */

#include <vlib/vlib.h>
#include <vppinfra/error.h>
#include <vppinfra/format_table.h>
#include <vlib/unix/unix.h>
#include <vnet/crypto/crypto.h>
#include <unittest/crypto/crypto.h>

typedef struct
{
  vlib_main_t *dequeue_vm;
  vnet_crypto_async_frame_t *frame;
} crypto_test_async_result_t;

typedef struct
{
  u32 ok[2];
  u32 fail[2];
  u32 not_supported[2];
} crypto_test_engine_summary_t;

typedef enum
{
  CRYPTO_TEST_RESULT_OK,
  CRYPTO_TEST_RESULT_FAIL,
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

typedef struct
{
  vnet_crypto_alg_t base_alg;
  vnet_crypto_alg_t fixed_alg;
  u8 digest_len;
  u8 aad_len;
} crypto_test_aead_fixed_alg_t;

static const crypto_test_aead_fixed_alg_t crypto_test_aead_fixed_algs[] = {
#define _(n, s, k, t, a)                                                                           \
  {                                                                                                \
    .base_alg = VNET_CRYPTO_ALG_##n,                                                               \
    .fixed_alg = VNET_CRYPTO_ALG_##n##_TAG##t##_AAD##a,                                            \
    .digest_len = t,                                                                               \
    .aad_len = a,                                                                                  \
  },
  foreach_crypto_aead_async_alg
#undef _
};

static int
crypto_test_result_is_visible (crypto_test_result_row_t *row)
{
  return row->is_chained == 0;
}

static u8 *
format_crypto_test_op_type_short (u8 *s, va_list *args)
{
  vnet_crypto_op_id_t op_id = va_arg (*args, int);
  vnet_crypto_main_t *cm = &crypto_main;
  vnet_crypto_op_data_t *od = cm->opt_data + op_id;

  switch (od->type)
    {
    case VNET_CRYPTO_OP_TYPE_ENCRYPT:
      return format (s, "enc");
    case VNET_CRYPTO_OP_TYPE_DECRYPT:
      return format (s, "dec");
    case VNET_CRYPTO_OP_TYPE_HASH:
      return format (s, "hash");
    case VNET_CRYPTO_OP_TYPE_HMAC:
      return format (s, "hmac");
    case VNET_CRYPTO_OP_N_TYPES:
      break;
    }

  return format (s, "%U", format_vnet_crypto_op_type, od->type);
}

static u8 *
format_crypto_test_alg (u8 *s, va_list *args)
{
  vnet_crypto_op_id_t op_id = va_arg (*args, int);
  vnet_crypto_main_t *cm = &crypto_main;
  vnet_crypto_op_data_t *od = cm->opt_data + op_id;
  vnet_crypto_alg_data_t *ad = cm->algs + od->alg;
  char *name = ad->name;

  if (od->type == VNET_CRYPTO_OP_TYPE_HMAC && strncmp (name, "hmac-", 5) == 0)
    name += 5;

  return format (s, "%s", name);
}

static void
crypto_test_result_format (crypto_test_result_t result, char **text, table_text_attr_color_t *color)
{
  *text = "x";
  *color = TTAC_WHITE;

  switch (result)
    {
    case CRYPTO_TEST_RESULT_OK:
      *text = "+";
      *color = TTAC_GREEN;
      break;
    case CRYPTO_TEST_RESULT_FAIL:
      *text = "-";
      *color = TTAC_RED;
      break;
    case CRYPTO_TEST_RESULT_NOT_SUPPORTED:
      break;
    }
}

static void
crypto_test_table_set_cell_dim (table_t *t, int c, int r)
{
  table_cell_t *cell;

  cell = &t->cells[c + t->n_header_cols][r + t->n_header_rows];
  cell->attr.flags |= TTAF_DIM;
}

static_always_inline int
crypto_test_result_name_col (void)
{
  return -1;
}

static_always_inline int
crypto_test_result_alg_col (void)
{
  return 0;
}

static_always_inline int
crypto_test_result_type_col (void)
{
  return 1;
}

static_always_inline int
crypto_test_result_simple_col (int i)
{
  return 2 + 2 * i;
}

static_always_inline int
crypto_test_result_chained_col (int i)
{
  return 3 + 2 * i;
}

static int
sort_registrations (void *a0, void *a1)
{
  unittest_crypto_test_registration_t **r0 = a0;
  unittest_crypto_test_registration_t **r1 = a1;

  return (strncmp (r0[0]->name, r1[0]->name, 256));
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

static vnet_crypto_op_id_t
crypto_test_get_async_op_id (unittest_crypto_test_registration_t *r, vnet_crypto_op_type_t op_type)
{
  vnet_crypto_main_t *cm = &crypto_main;
  vnet_crypto_alg_data_t *ad = cm->algs + r->alg;
  vnet_crypto_op_id_t op_id = ad->op_by_type[op_type];
  u32 i;

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
crypto_test_result_table_init (crypto_test_result_table_t *rt, crypto_test_main_t *tm)
{
  vnet_crypto_main_t *cm = &crypto_main;
  unittest_crypto_test_registration_t *r = tm->test_registrations;
  unittest_crypto_test_registration_t **regs = 0;
  int i, j;

  clib_memset (rt, 0, sizeof (*rt));

  if (tm->engine)
    vec_add1 (rt->engines, vnet_crypto_get_engine_index_by_name ("%s", tm->engine));
  else
    for (i = 1; i < vec_len (cm->engines); i++)
      vec_add1 (rt->engines, i);

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
    {
      vnet_crypto_engine_id_t *engines = 0;

      vec_foreach_index (i, rt->engines)
	if (crypto_test_engine_has_async_rows (rt->rows, rt->engines[i]))
	  vec_add1 (engines, rt->engines[i]);

      vec_free (rt->engines);
      rt->engines = engines;
    }

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

  vec_free (regs);
}

static void
crypto_test_result_table_print (vlib_main_t *vm, crypto_test_main_t *tm,
				crypto_test_result_table_t *rt)
{
  unix_main_t *um = vlib_unix_get_main ();
  vnet_crypto_main_t *cm = &crypto_main;
  table_t t = {
    .no_ansi = (um->flags & UNIX_FLAG_NOCOLOR) != 0,
    .n_header_cols = 2,
    .n_header_rows = 1,
  };
  crypto_test_result_row_t *prev_row = 0, *row;
  u8 *s = 0;
  int i, j;

  table_format_cell (&t, -2, crypto_test_result_alg_col (), "");
  table_format_cell (&t, -2, crypto_test_result_type_col (), "");
  table_format_cell (&t, -1, crypto_test_result_alg_col (), "alg");
  table_format_cell (&t, -1, crypto_test_result_type_col (), "type");
  table_set_cell_align (&t, -2, crypto_test_result_alg_col (), TTAA_LEFT);
  table_set_cell_align (&t, -2, crypto_test_result_type_col (), TTAA_LEFT);
  table_set_cell_align (&t, -1, crypto_test_result_alg_col (), TTAA_LEFT);
  table_set_cell_align (&t, -1, crypto_test_result_type_col (), TTAA_LEFT);

  vec_foreach_index (i, rt->engines)
    {
      table_format_cell (&t, -2, crypto_test_result_simple_col (i), "%u", rt->engines[i]);
      table_format_cell (&t, -2, crypto_test_result_chained_col (i), "");
      table_format_cell (&t, -1, crypto_test_result_simple_col (i), "s");
      table_format_cell (&t, -1, crypto_test_result_chained_col (i), "c");
      table_set_cell_align (&t, -2, crypto_test_result_simple_col (i), TTAA_CENTER);
      table_set_cell_align (&t, -2, crypto_test_result_chained_col (i), TTAA_CENTER);
      table_set_cell_align (&t, -1, crypto_test_result_simple_col (i), TTAA_CENTER);
      table_set_cell_align (&t, -1, crypto_test_result_chained_col (i), TTAA_CENTER);
    }

  j = 0;
  vec_foreach_index (i, rt->rows)
    {
      crypto_test_result_t simple, chained;
      table_text_attr_color_t simple_color, chained_color;
      char *simple_text, *chained_text;
      int k;

      row = vec_elt_at_index (rt->rows, i);
      if (!crypto_test_result_is_visible (row))
	continue;

      if (prev_row && prev_row->reg == row->reg &&
	  cm->opt_data[prev_row->op_id].alg == cm->opt_data[row->op_id].alg)
	table_format_cell (&t, j, crypto_test_result_alg_col (), "");
      else
	table_format_cell (&t, j, crypto_test_result_alg_col (), "%U", format_crypto_test_alg,
			   row->op_id);

      table_format_cell (&t, j, crypto_test_result_type_col (), "%U",
			 format_crypto_test_op_type_short, row->op_id);
      table_set_cell_align (&t, j, crypto_test_result_name_col (), TTAA_LEFT);
      table_set_cell_align (&t, j, crypto_test_result_alg_col (), TTAA_LEFT);
      table_set_cell_align (&t, j, crypto_test_result_type_col (), TTAA_LEFT);

      if (prev_row == 0 || prev_row->reg != row->reg)
	table_format_cell (&t, j, crypto_test_result_name_col (), "%s", row->reg->name);
      else
	table_format_cell (&t, j, crypto_test_result_name_col (), "");

      vec_foreach_index (k, rt->engines)
	{
	  int chained_row;

	  simple = rt->results[i][k];
	  crypto_test_result_format (simple, &simple_text, &simple_color);
	  chained_row = crypto_test_result_table_find_row (rt, row->reg, row->op_id, 1);

	  table_format_cell (&t, j, crypto_test_result_simple_col (k), "%s", simple_text);
	  table_set_cell_align (&t, j, crypto_test_result_simple_col (k), TTAA_CENTER);
	  if (simple == CRYPTO_TEST_RESULT_NOT_SUPPORTED)
	    crypto_test_table_set_cell_dim (&t, j, crypto_test_result_simple_col (k));
	  else
	    table_set_cell_fg_color (&t, j, crypto_test_result_simple_col (k), simple_color);

	  if (chained_row >= 0)
	    {
	      chained = rt->results[chained_row][k];
	      crypto_test_result_format (chained, &chained_text, &chained_color);
	      table_format_cell (&t, j, crypto_test_result_chained_col (k), "%s", chained_text);
	      if (chained == CRYPTO_TEST_RESULT_NOT_SUPPORTED)
		crypto_test_table_set_cell_dim (&t, j, crypto_test_result_chained_col (k));
	      else
		table_set_cell_fg_color (&t, j, crypto_test_result_chained_col (k), chained_color);
	    }
	  else
	    table_format_cell (&t, j, crypto_test_result_chained_col (k), "");

	  table_set_cell_align (&t, j, crypto_test_result_chained_col (k), TTAA_CENTER);
	}

      prev_row = row;
      j++;
    }

  s = format (s, "\n%U", format_table, &t);
  vlib_cli_output (vm, "%v", s);
  vec_free (s);
  table_free (&t);
}

static void
crypto_test_summary_table_print (vlib_main_t *vm, crypto_test_main_t *tm,
				 crypto_test_result_table_t *rt)
{
  unix_main_t *um = vlib_unix_get_main ();
  table_t t = {
    .no_ansi = (um->flags & UNIX_FLAG_NOCOLOR) != 0,
  };
  crypto_test_engine_summary_t *summary;
  u8 *s = 0;
  int i;

  table_format_title (&t, "Async Test Execution Summary");
  table_add_header_col (&t, 8, "", "", "", "Simple", "", "", "Chained", "");
  table_add_header_col (&t, 8, "ID", "Engine", "OK", "Fail", "Not Supported", "OK", "Fail",
			"Not Supported");

  table_set_cell_align (&t, -2, 0, TTAA_RIGHT);
  table_set_cell_align (&t, -2, 1, TTAA_LEFT);
  table_set_cell_align (&t, -2, 2, TTAA_CENTER);
  table_set_cell_align (&t, -2, 3, TTAA_CENTER);
  table_set_cell_align (&t, -2, 4, TTAA_CENTER);
  table_set_cell_align (&t, -2, 5, TTAA_CENTER);
  table_set_cell_align (&t, -2, 6, TTAA_CENTER);
  table_set_cell_align (&t, -2, 7, TTAA_CENTER);

  table_set_cell_align (&t, -1, 0, TTAA_RIGHT);
  table_set_cell_align (&t, -1, 1, TTAA_LEFT);
  table_set_cell_align (&t, -1, 2, TTAA_RIGHT);
  table_set_cell_align (&t, -1, 3, TTAA_RIGHT);
  table_set_cell_align (&t, -1, 4, TTAA_RIGHT);
  table_set_cell_align (&t, -1, 5, TTAA_RIGHT);
  table_set_cell_align (&t, -1, 6, TTAA_RIGHT);
  table_set_cell_align (&t, -1, 7, TTAA_RIGHT);

  vec_foreach_index (i, rt->engines)
    {
      summary = vec_elt_at_index (rt->summaries, i);
      table_format_cell (&t, i, 0, "%u", rt->engines[i]);
      table_format_cell (&t, i, 1, "%U", format_vnet_crypto_engine, rt->engines[i]);
      table_format_cell (&t, i, 2, "%u", summary->ok[0]);
      table_format_cell (&t, i, 3, "%u", summary->fail[0]);
      table_format_cell (&t, i, 4, "%u", summary->not_supported[0]);
      table_format_cell (&t, i, 5, "%u", summary->ok[1]);
      table_format_cell (&t, i, 6, "%u", summary->fail[1]);
      table_format_cell (&t, i, 7, "%u", summary->not_supported[1]);

      table_set_cell_align (&t, i, 0, TTAA_RIGHT);
      table_set_cell_align (&t, i, 1, TTAA_LEFT);
      table_set_cell_align (&t, i, 2, TTAA_RIGHT);
      table_set_cell_align (&t, i, 3, TTAA_RIGHT);
      table_set_cell_align (&t, i, 4, TTAA_RIGHT);
      table_set_cell_align (&t, i, 5, TTAA_RIGHT);
      table_set_cell_align (&t, i, 6, TTAA_RIGHT);
      table_set_cell_align (&t, i, 7, TTAA_RIGHT);
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
    if (summary->fail[0] || summary->fail[1])
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

static int
crypto_test_async_op_supported (vnet_crypto_engine_id_t engine, vnet_crypto_op_id_t op_id)
{
  vnet_crypto_main_t *cm = &crypto_main;
  vnet_crypto_engine_t *e = vec_elt_at_index (cm->engines, engine);

  return e->dequeue_handler != 0 && e->ops[op_id].handlers[VNET_CRYPTO_HANDLER_TYPE_ASYNC] != 0;
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
		.dequeue_vm = ovm,
		.frame = frame,
	      };
	      return 0;
	    }

	  vnet_crypto_async_free_frame (ovm, frame);
	}

      vlib_process_wait_for_event_or_clock (vm, 10e-3);
    }

  return clib_error_return (0, "async frame timeout");
}

static_always_inline vlib_main_t *
crypto_test_get_async_vm (vlib_main_t *vm)
{
  if (vlib_num_workers () > 0)
    return vlib_get_main_by_index (1);

  return vm;
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

static_always_inline u32
crypto_test_async_chunk_len (u32 total_len, u32 chunk_index, u32 n_chunks)
{
  u32 base = total_len / n_chunks;
  u32 rem = total_len % n_chunks;

  return base + (chunk_index < rem);
}

static void
crypto_test_async_buffer_chain_init (vlib_main_t *vm, u32 *buffer_indices, u32 n_buffers,
				     unittest_crypto_test_data_t *data)
{
  u32 i, offset = 0;

  for (i = 0; i < n_buffers; i++)
    {
      vlib_buffer_t *b = vlib_get_buffer (vm, buffer_indices[i]);
      u32 len =
	n_buffers == 1 ? data->length : crypto_test_async_chunk_len (data->length, i, n_buffers);

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

static_always_inline void
crypto_test_async_buffer_chain_free (vlib_main_t *vm, u32 *buffer_indices, u32 n_buffers,
				     u8 is_chained)
{
  if (n_buffers == 0)
    return;

  if (is_chained)
    vlib_buffer_free (vm, buffer_indices, 1);
  else
    vlib_buffer_free (vm, buffer_indices, n_buffers);
}

static vnet_crypto_key_index_t
crypto_test_async_key_add (vlib_main_t *vm, vnet_crypto_engine_id_t engine,
			   unittest_crypto_test_registration_t *r)
{
  vnet_crypto_main_t *cm = &crypto_main;
  vnet_crypto_alg_data_t *ad = cm->algs + r->alg;

  if (ad->alg_type == VNET_CRYPTO_ALG_T_HASH)
    return ~0;

  if (ad->alg_type == VNET_CRYPTO_ALG_T_COMBINED)
    return vnet_crypto_key_add_for_async_engine (vm, engine, r->alg, r->key.data, ad->key_length,
						 r->key.data + ad->key_length,
						 r->key.length - ad->key_length);

  return vnet_crypto_key_add_for_async_engine (vm, engine, r->alg, r->key.data, r->key.length, 0,
					       0);
}

static clib_error_t *
test_crypto_async_case (vlib_main_t *vm, crypto_test_main_t *tm,
			unittest_crypto_test_registration_t *r, vnet_crypto_engine_id_t engine,
			vnet_crypto_op_id_t op_id, u8 is_chained, crypto_test_result_t *test_result)
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
  vnet_crypto_key_index_t key_index = ~0;
  crypto_test_async_result_t result = {};
  clib_error_t *rv = 0;
  vnet_crypto_async_frame_elt_t *fe;
  int has_key = 0;

  *test_result = CRYPTO_TEST_RESULT_FAIL;
  async_vm = crypto_test_get_async_vm (vm);

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
    digest_len = r->digest.length;

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

  key_index = crypto_test_async_key_add (async_vm, engine, r);
  has_key = key_index != ~0;
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

  vnet_crypto_async_add_to_frame (async_vm, frame, has_key ? key_index : 0, input->length, 0, 0, 0,
				  buffer_indices[0], 0, iv, tag, aad, flags);

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
      memcmp (tag, r->digest.data, r->digest.length))
    err = format (err, "%sdigest mismatch", vec_len (err) ? ", " : "");

  *test_result = vec_len (err) ? CRYPTO_TEST_RESULT_FAIL : CRYPTO_TEST_RESULT_OK;

done:
  vec_free (err);
  if (result.frame)
    vnet_crypto_async_free_frame (result.dequeue_vm, result.frame);
  if (frame && !submitted)
    vnet_crypto_async_free_frame (async_vm, frame);
  if (n_alloc && (!submitted || result.frame))
    crypto_test_async_buffer_chain_free (vm, buffer_indices, n_alloc, is_chained);
  if (has_key && (result.frame || !submitted))
    vnet_crypto_key_del (async_vm, key_index);
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

	  if (!crypto_test_async_op_supported (engine, id))
	    {
	      crypto_test_print_not_supported (r, id, 0, &summary, engine, results);
	      crypto_test_print_not_supported (r, id, 1, &summary, engine, results);
	      continue;
	    }

	  for (is_chained = 0; is_chained <= 1; is_chained++)
	    {
	      err = test_crypto_async_case (vm, tm, r, engine, id, is_chained, &result);
	      if (err)
		goto done;

	      if (result == CRYPTO_TEST_RESULT_OK)
		summary.ok[is_chained]++;
	      else
		summary.fail[is_chained]++;

	      crypto_test_result_table_set (results, engine, r, id, is_chained, result);
	    }
	}

      r = r->next;
    }

done:
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
  crypto_test_result_table_t results;
  vnet_crypto_engine_id_t engine = VNET_CRYPTO_ENGINE_ID_NONE;
  u32 i;

  if (tm->engine)
    {
      engine = vnet_crypto_get_engine_index_by_name ("%s", tm->engine);
      if (engine == VNET_CRYPTO_ENGINE_ID_INVALID)
	return clib_error_return (0, "unknown engine '%s'", tm->engine);
    }

  crypto_test_result_table_init (&results, tm);

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

  if (tm->quiet)
    vlib_cli_output (vm, "%s", crypto_test_has_failures (&results) ? "FAIL" : "OK");
  else
    {
      crypto_test_result_table_print (vm, tm, &results);
      crypto_test_summary_table_print (vm, tm, &results);
    }

  crypto_test_result_table_free (&results);
  return err;
}
