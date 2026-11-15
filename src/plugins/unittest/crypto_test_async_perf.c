/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Damjan Marion
 */

#include <unittest/crypto_test.h>

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  u32 *buffers;
  vnet_crypto_ctx_t *ctx;
  vnet_crypto_ctx_t **ctxs; /* frame aux data, the thread ctx for all buffers */
  u32 n_submitted;
  u32 n_completed;
  u32 n_errors;
  u64 errors_base;
  u64 t_start, t_end;
  u8 active;
  u8 done;
} crypto_test_async_perf_thread_t;

typedef struct
{
  crypto_test_async_perf_thread_t *threads;
  u32 enq_node_index;
  u32 *error_node_indices;
  u32 sink_next_index;
  u32 elts_per_frame;
  u32 max_in_flight;
  vnet_crypto_op_type_t type;
  vnet_crypto_alg_t alg;
} crypto_test_async_perf_main_t;

static crypto_test_async_perf_main_t crypto_test_async_perf_main;

static u64
crypto_test_async_perf_errors (vlib_main_t *vm, crypto_test_async_perf_main_t *pm)
{
  vlib_error_main_t *em = &vm->error_main;
  u64 n = 0;

  for (u32 i = 0; i < vec_len (pm->error_node_indices); i++)
    {
      vlib_node_t *node = vlib_get_node (vm, pm->error_node_indices[i]);

      for (u32 j = 0; j < node->n_errors; j++)
	n += em->counters[node->error_heap_index + j];
    }

  return n;
}

VLIB_NODE_FN (crypto_test_async_sink_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  crypto_test_async_perf_main_t *pm = &crypto_test_async_perf_main;

  pm->threads[vm->thread_index].n_completed += frame->n_vectors;
  return frame->n_vectors;
}

VLIB_REGISTER_NODE (crypto_test_async_sink_node) = {
  .name = "crypto-test-async-sink",
  .vector_size = sizeof (u32),
};

VLIB_NODE_FN (crypto_test_async_perf_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  crypto_test_async_perf_main_t *pm = &crypto_test_async_perf_main;
  crypto_test_async_perf_thread_t *pt = pm->threads + vm->thread_index;
  u32 n = vec_len (pt->buffers), n_submitted = pt->n_submitted;

  if (__atomic_load_n (&pt->active, __ATOMIC_ACQUIRE) == 0)
    return 0;

  if (pt->t_start == 0)
    {
      pt->errors_base = crypto_test_async_perf_errors (vm, pm);
      pt->t_start = clib_cpu_time_now ();
    }

  /* buffers failed by the engine are dropped, they show up only in error counters */
  pt->n_errors = crypto_test_async_perf_errors (vm, pm) - pt->errors_base;
  if (pt->n_completed + pt->n_errors >= n)
    {
      pt->t_end = clib_cpu_time_now ();
      pt->active = 0;
      __atomic_store_n (&pt->done, 1, __ATOMIC_RELEASE);
      return 0;
    }

  while (n_submitted < n)
    {
      u32 n_vectors = clib_min (pm->elts_per_frame, n - n_submitted);
      u32 in_flight = n_submitted - pt->n_completed - pt->n_errors;
      vlib_frame_t *f;

      if (pm->max_in_flight && in_flight + n_vectors > pm->max_in_flight)
	break;

      f = vlib_get_frame_to_node (vm, pm->enq_node_index);
      f->n_vectors = n_vectors;
      clib_memcpy_fast (vlib_frame_vector_args (f), pt->buffers + n_submitted,
			n_vectors * sizeof (u32));
      clib_memcpy_fast (vlib_frame_aux_args (f), pt->ctxs, n_vectors * sizeof (pt->ctxs[0]));
      *(vnet_crypto_deq_scalar_data_t *) vlib_frame_scalar_args (f) =
	(vnet_crypto_deq_scalar_data_t) {
	  .next_node_index = pm->sink_next_index,
	  .op_type = pm->type,
	  .alg = pm->alg,
	};
      vlib_put_frame_to_node (vm, pm->enq_node_index, f);
      n_submitted += n_vectors;
    }

  pt->n_submitted = n_submitted;
  vlib_node_set_interrupt_pending (vm, node->node_index);
  return 0;
}

VLIB_REGISTER_NODE (crypto_test_async_perf_node) = {
  .name = "crypto-test-async-perf",
  .type = VLIB_NODE_TYPE_INPUT,
  .state = VLIB_NODE_STATE_INTERRUPT,
};

static void
crypto_test_async_perf_set_hmac_check (vlib_main_t *vm, u32 *buffer_indices, u8 is_hmac_check)
{
  for (u32 i = 0; i < vec_len (buffer_indices); i++)
    vnet_crypto_buffer_get_metadata (vlib_get_buffer (vm, buffer_indices[i]))->is_hmac_check =
      is_hmac_check;
}

/* runs one direction on all test threads and stores the Mops of each */
static clib_error_t *
crypto_test_async_perf_run (vlib_main_t *vm, crypto_test_async_perf_main_t *pm,
			    clib_bitmap_t *threads, f64 *mops)
{
  f64 deadline = vlib_time_now (vm) + 5.0;
  uword ti;

  clib_bitmap_foreach (ti, threads)
    {
      crypto_test_async_perf_thread_t *pt = pm->threads + ti;

      pt->n_submitted = pt->n_completed = pt->n_errors = 0;
      pt->t_start = pt->t_end = 0;
      pt->done = 0;
      __atomic_store_n (&pt->active, 1, __ATOMIC_RELEASE);
    }

  clib_bitmap_foreach (ti, threads)
    vlib_node_set_interrupt_pending (vlib_get_main_by_index (ti),
				     crypto_test_async_perf_node.index);

  clib_bitmap_foreach (ti, threads)
    {
      crypto_test_async_perf_thread_t *pt = pm->threads + ti;

      while (__atomic_load_n (&pt->done, __ATOMIC_ACQUIRE) == 0)
	{
	  if (vlib_time_now (vm) > deadline)
	    return clib_error_return (0, "thread %u timeout, %u of %u buffers completed", ti,
				      pt->n_completed + pt->n_errors, vec_len (pt->buffers));
	  vlib_process_suspend (vm, 1e-3);
	}

      if (pt->n_errors)
	return clib_error_return (0, "thread %u: %u buffers failed%s", ti, pt->n_errors,
				  pm->max_in_flight ? "" : ", try max-in-flight");

      mops[ti] =
	vec_len (pt->buffers) * vm->clib_time.clocks_per_second / (pt->t_end - pt->t_start) * 1e-6;
    }

  return 0;
}

clib_error_t *
test_crypto_async_perf (vlib_main_t *vm, crypto_test_main_t *tm)
{
  crypto_test_async_perf_main_t *pm = &crypto_test_async_perf_main;
  vnet_crypto_main_t *cm = &crypto_main;
  vnet_crypto_alg_data_t *ad = cm->algs + tm->alg;
  vnet_crypto_op_type_t types[2], ot;
  vnet_crypto_engine_id_t engine;
  vnet_crypto_engine_t *e;
  clib_bitmap_t *threads = 0;
  clib_error_t *err = 0;
  u32 n_buffers, buffer_size, n_types = 0, key_sz, rounds;
  u32 icv_len = 0, aad_len = 0;
  u8 is_combined = ad->alg_type == VNET_CRYPTO_ALG_T_COMBINED;
  u8 has_auth = is_combined || ad->alg_type == VNET_CRYPTO_ALG_T_AUTH;
  u8 in_flight = 0;
  u64 seed = clib_cpu_time_now ();
  f64 *mops[2] = {}, warmup_end;
  u8 key_data[128];
  uword ti;

  n_buffers = tm->n_buffers ? tm->n_buffers : 4096;
  buffer_size = tm->buffer_size ? tm->buffer_size : 2048;
  rounds = tm->rounds ? tm->rounds : 5;

  if (buffer_size > vlib_buffer_get_default_data_size (vm))
    return clib_error_return (0, "buffer size must be <= %u",
			      vlib_buffer_get_default_data_size (vm));

  if (tm->elts_per_frame > VLIB_FRAME_SIZE)
    return clib_error_return (0, "elts-per-frame must be in range 1..%u", VLIB_FRAME_SIZE);

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
  for (u32 i = 0; i < n_types; i++)
    if (e->ops[tm->alg][types[i]].handlers[VNET_CRYPTO_HANDLER_TYPE_ASYNC] == 0)
      return clib_error_return (0, "engine '%s' has no async %U handler for %U", e->name,
				format_crypto_op_type_short, types[i], format_vnet_crypto_alg,
				tm->alg);

  if (tm->threads)
    threads = clib_bitmap_dup (tm->threads);
  else
    threads = clib_bitmap_set_region (0, 0, 1, vlib_get_n_threads ());

  if (clib_bitmap_last_set (threads) >= vlib_get_n_threads ())
    {
      clib_bitmap_free (threads);
      return clib_error_return (0, "thread index out of range");
    }

  if (ad->alg_type == VNET_CRYPTO_ALG_T_AEAD)
    {
      icv_len = ad->auth_len ? ad->auth_len : 16;
      aad_len = ad->aad_len ? ad->aad_len : 8;
    }
  else if (has_auth)
    icv_len = ad->auth_len ? ad->auth_len : 12;

  if (16 + aad_len + icv_len > VLIB_BUFFER_PRE_DATA_SIZE)
    {
      clib_bitmap_free (threads);
      return clib_error_return (0, "buffer headroom too small");
    }

  key_sz = is_combined ? ad->cipher_key_len + 32 : ad->cipher_key_len;
  if (key_sz == 0)
    key_sz = 32;

  for (u32 i = 0; i < key_sz; i++)
    key_data[i] = i;

  if (pm->sink_next_index == 0)
    pm->sink_next_index = vnet_crypto_register_post_node (vm, "crypto-test-async-sink");

  /* encrypt and decrypt may share the enqueue node */
  vec_reset_length (pm->error_node_indices);
  vec_add1 (pm->error_node_indices, e->deq_node_index);
  for (u32 i = 0; i < n_types; i++)
    if (vec_search (pm->error_node_indices, e->ops[tm->alg][types[i]].enq_node_index) == ~0)
      vec_add1 (pm->error_node_indices, e->ops[tm->alg][types[i]].enq_node_index);
  pm->elts_per_frame = tm->elts_per_frame ? tm->elts_per_frame : VLIB_FRAME_SIZE;
  pm->max_in_flight = tm->max_in_flight;
  pm->alg = tm->alg;
  vec_validate_aligned (pm->threads, vlib_get_n_threads () - 1, CLIB_CACHE_LINE_BYTES);

  clib_bitmap_foreach (ti, threads)
    {
      crypto_test_async_perf_thread_t *pt = pm->threads + ti;
      u32 n_alloc;

      /* each thread has its own key, as each worker usually serves different SAs */
      key_data[0] = ti;
      pt->ctx = crypto_test_ctx_add_data (vm, engine, tm->alg, key_data, key_sz, 1);
      if (pt->ctx == 0)
	{
	  err = clib_error_return (0, "ctx create failed");
	  goto done;
	}

      vec_validate (pt->ctxs, VLIB_FRAME_SIZE - 1);
      for (u32 i = 0; i < VLIB_FRAME_SIZE; i++)
	pt->ctxs[i] = pt->ctx;

      vec_validate_aligned (pt->buffers, n_buffers - 1, CLIB_CACHE_LINE_BYTES);
      n_alloc = vlib_buffer_alloc (vm, pt->buffers, n_buffers);
      if (n_alloc != n_buffers)
	{
	  vlib_buffer_free (vm, pt->buffers, n_alloc);
	  vec_free (pt->buffers);
	  err = clib_error_return (0, "buffer alloc failure");
	  goto done;
	}

      for (u32 i = 0; i < n_buffers; i++)
	{
	  vlib_buffer_t *b = vlib_get_buffer (vm, pt->buffers[i]);
	  i16 pre_data_off = vnet_crypto_buffer_metadata_pre_data_off (b);

	  b->current_length = buffer_size;
	  for (i32 j = -VLIB_BUFFER_PRE_DATA_SIZE; j < (i32) buffer_size; j += 8)
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
    }

  vlib_cli_output (vm, "%U: threads %U, n_buffers %u per thread, buffer-size %u engine %s",
		   format_vnet_crypto_alg, tm->alg, format_bitmap_list, threads, n_buffers,
		   buffer_size, e->name);

  for (u32 i = 0; i < n_types; i++)
    vec_validate (mops[i], vlib_get_n_threads () - 1);

  /* idle cores need time to reach full speed, a round lasts only a few milliseconds */
  warmup_end = vlib_time_now (vm) + (tm->warmup_time_set ? tm->warmup_time : 3.0);

  for (u32 r = 0, n_warmup = 0; r < rounds && err == 0;)
    {
      u8 is_warmup = n_warmup < tm->warmup_rounds || vlib_time_now (vm) < warmup_end;
      f64 total[2] = {};

      for (u32 i = 0; i < n_types && err == 0; i++)
	{
	  pm->type = types[i];
	  pm->enq_node_index = e->ops[pm->alg][pm->type].enq_node_index;
	  clib_bitmap_foreach (ti, threads)
	    crypto_test_async_perf_set_hmac_check (
	      vm, pm->threads[ti].buffers, is_combined && types[i] == VNET_CRYPTO_OP_TYPE_DECRYPT);

	  err = crypto_test_async_perf_run (vm, pm, threads, mops[i]);
	  in_flight = err != 0;

	  clib_bitmap_foreach (ti, threads)
	    total[i] += mops[i][ti];
	}

      if (err)
	break;

      if (is_warmup)
	{
	  n_warmup++;
	  continue;
	}

      r++;
      if (n_types == 1)
	vlib_cli_output (vm, "%-2u: hash %.02f Mops", r, total[0]);
      else
	vlib_cli_output (vm, "%-2u: encrypt%s %.02f Mops; decrypt%s %.02f Mops", r,
			 is_combined ? "+hmac" : "", total[0], is_combined ? "+hmac" : "",
			 total[1]);

      if (tm->verbose)
	clib_bitmap_foreach (ti, threads)
	  {
	    if (n_types == 1)
	      vlib_cli_output (vm, "    thread %u: %.02f Mops", ti, mops[0][ti]);
	    else
	      vlib_cli_output (vm, "    thread %u: %.02f / %.02f Mops", ti, mops[0][ti],
			       mops[1][ti]);
	  }
    }

done:
  /* after a timeout buffers may still be in flight, failed ones were freed by error-drop */
  clib_bitmap_foreach (ti, threads)
    {
      crypto_test_async_perf_thread_t *pt = pm->threads + ti;

      __atomic_store_n (&pt->active, 0, __ATOMIC_RELEASE);
      if (in_flight == 0)
	{
	  vlib_buffer_free (vm, pt->buffers, vec_len (pt->buffers));
	  if (pt->ctx)
	    vnet_crypto_ctx_destroy (vm, pt->ctx);
	}
      pt->ctx = 0;
      vec_free (pt->ctxs);
      vec_free (pt->buffers);
    }

  for (u32 i = 0; i < n_types; i++)
    vec_free (mops[i]);
  clib_bitmap_free (threads);
  return err;
}
