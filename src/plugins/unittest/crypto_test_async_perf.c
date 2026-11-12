/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Damjan Marion
 */

#include <unittest/crypto_test.h>

static void
crypto_test_async_perf_set_hmac_check (vlib_main_t *vm, u32 *buffer_indices, u32 n_buffers,
				       u8 is_hmac_check)
{
  for (u32 i = 0; i < n_buffers; i++)
    vnet_crypto_buffer_get_metadata (vlib_get_buffer (vm, buffer_indices[i]))->is_hmac_check =
      is_hmac_check;
}

typedef struct
{
  vnet_crypto_engine_t *engine;
  vnet_crypto_async_frame_t *frames;
  u32 n_frames;
  u32 n_in_flight;
} crypto_test_async_perf_t;

static clib_error_t *
crypto_test_async_perf_run (vlib_main_t *vm, crypto_test_async_perf_t *p,
			    vnet_crypto_frame_enq_fn_t *fn, vnet_crypto_op_type_t type)
{
  vnet_crypto_async_frame_t *f;
  u32 n_submitted = 0, n_left_complete = p->n_frames;
  u64 timeout = vm->clib_time.clocks_per_second * 5;
  u64 last_progress = clib_cpu_time_now ();
  u32 n_engine_errors = 0, n_auth_failures = 0;
  clib_error_t *err = 0;

  while (n_left_complete)
    {
      vnet_crypto_frame_dequeue_args_t a = { .user_data = p->engine->user_data };

      while (n_submitted < p->n_frames)
	{
	  f = p->frames + n_submitted;
	  f->state = VNET_CRYPTO_FRAME_STATE_PENDING;
	  f->type = type;
	  f->user_data = p->engine->user_data;
	  f->enqueue_thread_index = vm->thread_index;
	  clib_memset (f->bad_hmac_bitmap, 0, sizeof (f->bad_hmac_bitmap));
	  clib_memset (f->engine_error_bitmap, 0, sizeof (f->engine_error_bitmap));
	  if (fn (vm, f))
	    break;
	  n_submitted++;
	  p->n_in_flight++;
	}

      while ((f = p->engine->dequeue_handler (vm, &a)))
	{
	  n_engine_errors += vnet_crypto_async_frame_bitmap_count_set_bits (f->engine_error_bitmap);
	  n_auth_failures += vnet_crypto_async_frame_bitmap_count_set_bits (f->bad_hmac_bitmap);
	  n_left_complete--;
	  p->n_in_flight--;
	  last_progress = clib_cpu_time_now ();
	}

      if (clib_cpu_time_now () - last_progress > timeout)
	{
	  err = clib_error_return (0, "timeout, %u frames in flight", p->n_in_flight);
	  break;
	}
    }

  if (err == 0 && n_engine_errors)
    err = clib_error_return (0, "%u engine errors", n_engine_errors);
  else if (err == 0 && n_auth_failures)
    err = clib_error_return (0, "%u auth failures", n_auth_failures);

  return err;
}

clib_error_t *
test_crypto_async_perf (vlib_main_t *vm, crypto_test_main_t *tm)
{
  vnet_crypto_main_t *cm = &crypto_main;
  vnet_crypto_alg_data_t *ad = cm->algs + tm->alg;
  vnet_crypto_op_type_t types[2], ot;
  vnet_crypto_frame_enq_fn_t *fns[2];
  vnet_crypto_engine_id_t engine;
  vnet_crypto_engine_t *e;
  vlib_node_state_t *node_states = 0;
  vnet_crypto_ctx_t *ctx = 0;
  clib_error_t *err = 0;
  u32 *buffer_indices = 0;
  u32 n_buffers, elts_per_frame, buffer_size;
  crypto_test_async_perf_t p = {};
  u32 n_alloc = 0, n_types = 0, key_sz, post_next_index;
  u32 icv_len = 0, aad_len = 0;
  u8 is_combined = ad->alg_type == VNET_CRYPTO_ALG_T_COMBINED;
  u8 has_auth = is_combined || ad->alg_type == VNET_CRYPTO_ALG_T_AUTH;
  u64 seed = clib_cpu_time_now ();
  u64 t0[5][2], t1[5][2];
  u8 key_data[128];
  int i, j;

  n_buffers = tm->n_buffers ? tm->n_buffers : 4096;
  buffer_size = tm->buffer_size ? tm->buffer_size : 2048;
  elts_per_frame = tm->elts_per_frame ? tm->elts_per_frame : VNET_CRYPTO_FRAME_SIZE;

  if (buffer_size > vlib_buffer_get_default_data_size (vm))
    return clib_error_return (0, "buffer size must be <= %u",
			      vlib_buffer_get_default_data_size (vm));

  if (elts_per_frame == 0 || elts_per_frame > VNET_CRYPTO_FRAME_SIZE)
    return clib_error_return (0, "elts-per-frame must be in range 1..%u", VNET_CRYPTO_FRAME_SIZE);

  ot = crypto_test_first_op_type (tm->alg);
  if (ot == VNET_CRYPTO_OP_N_TYPES)
    return clib_error_return (0, "algorithm has no op types");

  if (ot == VNET_CRYPTO_OP_TYPE_HMAC)
    types[n_types++] = VNET_CRYPTO_OP_TYPE_HMAC;
  else
    {
      types[n_types++] = VNET_CRYPTO_OP_TYPE_ENCRYPT;
      types[n_types++] = VNET_CRYPTO_OP_TYPE_DECRYPT;
    }

  if (tm->engine)
    {
      engine = vnet_crypto_get_engine_index_by_name ("%s", tm->engine);
      if (engine == VNET_CRYPTO_ENGINE_ID_INVALID)
	return clib_error_return (0, "unknown engine '%s'", tm->engine);
    }
  else
    engine = cm->active_op_engine_index[tm->alg][types[0]][VNET_CRYPTO_HANDLER_TYPE_ASYNC];

  if (engine == VNET_CRYPTO_ENGINE_ID_NONE)
    return clib_error_return (0, "no async engine for %U", format_vnet_crypto_alg, tm->alg);

  e = vec_elt_at_index (cm->engines, engine);
  if (e->dequeue_handler == 0)
    return clib_error_return (0, "engine '%s' has no async dequeue handler", e->name);

  for (i = 0; i < n_types; i++)
    {
      fns[i] = e->ops[tm->alg][types[i]].handlers[VNET_CRYPTO_HANDLER_TYPE_ASYNC];
      if (fns[i] == 0)
	return clib_error_return (0, "engine '%s' has no async %U handler for %U", e->name,
				  format_crypto_op_type_short, types[i], format_vnet_crypto_alg,
				  tm->alg);
    }

  if (ad->alg_type == VNET_CRYPTO_ALG_T_AEAD)
    {
      icv_len = ad->auth_len ? ad->auth_len : 16;
      aad_len = ad->aad_len ? ad->aad_len : 8;
    }
  else if (has_auth)
    icv_len = ad->auth_len ? ad->auth_len : 12;

  if (16 + aad_len + icv_len > VLIB_BUFFER_PRE_DATA_SIZE)
    return clib_error_return (0, "buffer headroom too small");

  key_sz = is_combined ? ad->cipher_key_len + 32 : ad->cipher_key_len;
  if (key_sz == 0)
    key_sz = 32;

  for (i = 0; i < key_sz; i++)
    key_data[i] = i;

  post_next_index = vnet_crypto_register_post_node (vm, "error-drop");
  if (post_next_index == ~0)
    return clib_error_return (0, "crypto post node registration failed");

  ctx = crypto_test_ctx_add_data (vm, engine, tm->alg, key_data, key_sz, 1);
  if (ctx == 0)
    return clib_error_return (0, "ctx create failed");

  vec_validate_aligned (buffer_indices, n_buffers - 1, CLIB_CACHE_LINE_BYTES);
  n_alloc = vlib_buffer_alloc (vm, buffer_indices, n_buffers);
  if (n_alloc != n_buffers)
    {
      err = clib_error_return (0, "buffer alloc failure");
      goto done;
    }

  for (i = 0; i < n_buffers; i++)
    {
      vlib_buffer_t *b = vlib_get_buffer (vm, buffer_indices[i]);
      i16 pre_data_off = vnet_crypto_buffer_metadata_pre_data_off (b);

      b->current_length = buffer_size;
      for (j = -VLIB_BUFFER_PRE_DATA_SIZE; j < buffer_size; j += 8)
	*(u64 *) (b->data + j) = 1 + random_u64 (&seed);

      *vnet_crypto_buffer_get_metadata (b) = (vnet_crypto_buffer_metadata_t) {
	.cipher_data_len = ot == VNET_CRYPTO_OP_TYPE_HMAC ? 0 : buffer_size,
	.auth_data_len = has_auth ? buffer_size : 0,
	.iv_off = pre_data_off,
	.aad_off = aad_len ? pre_data_off + 16 : 0,
	.icv_off = pre_data_off + 16 + aad_len,
	.aad_len = crypto_test_alg_has_fixed_aad_len (tm->alg) ? 0xfe : aad_len,
	.icv_len = crypto_test_alg_has_fixed_auth_len (tm->alg) ? 0xfe : icv_len,
      };
    }

  p.engine = e;
  p.n_frames = (n_buffers + elts_per_frame - 1) / elts_per_frame;
  vec_validate_aligned (p.frames, p.n_frames - 1, CLIB_CACHE_LINE_BYTES);
  for (i = 0; i < n_buffers; i++)
    {
      vnet_crypto_async_frame_t *f = p.frames + i / elts_per_frame;

      f->alg = tm->alg;
      vnet_crypto_async_add_to_frame (vm, f, ctx, buffer_indices[i], post_next_index);
    }

  vlib_cli_output (vm, "%U: n_buffers %u buffer-size %u elts-per-frame %u engine %s",
		   format_vnet_crypto_alg, tm->alg, n_buffers, buffer_size, elts_per_frame,
		   e->name);

  crypto_test_async_deq_node_disable (&node_states);

  for (i = 0; i < 5 && err == 0; i++)
    for (j = 0; j < n_types && err == 0; j++)
      {
	u8 is_hmac_check = is_combined && types[j] == VNET_CRYPTO_OP_TYPE_DECRYPT;

	crypto_test_async_perf_set_hmac_check (vm, buffer_indices, n_buffers, is_hmac_check);
	t0[i][j] = clib_cpu_time_now ();
	err = crypto_test_async_perf_run (vm, &p, fns[j], types[j]);
	t1[i][j] = clib_cpu_time_now ();
      }

  crypto_test_async_deq_node_restore (node_states);

  for (i = 0; i < 5 && err == 0; i++)
    {
      f64 n_ops = n_buffers;
      f64 gbps[2], mops[2];

      for (j = 0; j < n_types; j++)
	{
	  f64 t = (t1[i][j] - t0[i][j]) / vm->clib_time.clocks_per_second;
	  gbps[j] = n_ops * buffer_size * 8 / t * 1e-9;
	  mops[j] = n_ops / t * 1e-6;
	}

      if (n_types == 1)
	vlib_cli_output (vm, "%-2u: hash %.02f Gbps, %.02f Mops", i + 1, gbps[0], mops[0]);
      else
	vlib_cli_output (vm,
			 "%-2u: encrypt%s %.02f Gbps, %.02f Mops; decrypt%s %.02f Gbps, %.02f Mops",
			 i + 1, is_combined ? "+hmac" : "", gbps[0], mops[0],
			 is_combined ? "+hmac" : "", gbps[1], mops[1]);
    }

done:
  if (p.n_in_flight)
    return err;

  if (n_alloc)
    vlib_buffer_free (vm, buffer_indices, n_alloc);
  vnet_crypto_ctx_destroy (vm, ctx);
  vec_free (node_states);
  vec_free (p.frames);
  vec_free (buffer_indices);
  return err;
}
