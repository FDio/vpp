/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Damjan Marion
 */

#include <unittest/crypto_test.h>

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  u32 *buffers;
  u32 *completed; /* buffers back at the sink */
  vnet_crypto_ctx_t *ctx;
  vnet_crypto_ctx_t **ctxs; /* frame aux data, the thread ctx for all buffers */
  u32 n_submitted;
  u32 trace_end; /* buffers below this index are traced */
  u32 n_completed;
  u32 n_errors; /* completed buffers with a failed status */
  u64 t_start, t_end;
  u8 active;
  u8 done;
} crypto_test_async_perf_thread_t;

typedef struct
{
  crypto_test_async_perf_thread_t *threads;
  u32 enq_node_index;
  u32 sink_next_index;
  u32 elts_per_frame;
  u32 max_in_flight;
  vnet_crypto_op_type_t type;
  vnet_crypto_alg_t alg;
} crypto_test_async_perf_main_t;

static crypto_test_async_perf_main_t crypto_test_async_perf_main;

typedef struct
{
  u32 thread_index;
  u32 buffer_index;
  vnet_crypto_op_type_t type;
} crypto_test_async_perf_trace_t;

static u8 *
format_crypto_test_async_perf_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  crypto_test_async_perf_trace_t *t = va_arg (*args, crypto_test_async_perf_trace_t *);

  return format (s, "thread %u buffer %u %U", t->thread_index, t->buffer_index,
		 format_vnet_crypto_op_type, t->type);
}

static u8 *
format_crypto_test_async_sink_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  crypto_test_async_perf_trace_t *t = va_arg (*args, crypto_test_async_perf_trace_t *);

  return format (s, "thread %u completion %u %U", t->thread_index, t->buffer_index,
		 format_vnet_crypto_op_type, t->type);
}

VLIB_NODE_FN (crypto_test_async_sink_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  crypto_test_async_perf_main_t *pm = &crypto_test_async_perf_main;
  crypto_test_async_perf_thread_t *pt = pm->threads + vm->thread_index;
  vnet_crypto_frame_scalar_data_t *sd = vlib_frame_scalar_args (frame);
  u32 *from = vlib_frame_vector_args (frame), n = frame->n_vectors;

  if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE))
    for (u32 i = 0; i < n; i++)
      {
	vlib_buffer_t *b = vlib_get_buffer (vm, from[i]);
	crypto_test_async_perf_trace_t *t;

	if ((b->flags & VLIB_BUFFER_IS_TRACED) == 0)
	  continue;

	t = vlib_add_trace (vm, node, b, sizeof (*t));
	t->thread_index = vm->thread_index;
	t->buffer_index = pt->n_completed + i;
	t->type = pm->type;
      }

  /* completions arriving after the test ended */
  if (__atomic_load_n (&pt->active, __ATOMIC_ACQUIRE) == 0)
    {
      vlib_buffer_free (vm, from, n);
      return n;
    }

  pt->n_errors += vnet_crypto_frame_n_failures (sd);

  clib_memcpy_fast (pt->completed + pt->n_completed, from, n * sizeof (from[0]));
  pt->n_completed += n;
  return n;
}

VLIB_REGISTER_NODE (crypto_test_async_sink_node) = {
  .name = "crypto-test-async-sink",
  .vector_size = sizeof (u32),
  .scalar_size = sizeof (vnet_crypto_frame_scalar_data_t),
  .aux_size = sizeof (vnet_crypto_ctx_t *),
  .flags = VLIB_NODE_FLAG_TRACE_SUPPORTED,
  .format_trace = format_crypto_test_async_sink_trace,
};

VLIB_NODE_FN (crypto_test_async_perf_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  crypto_test_async_perf_main_t *pm = &crypto_test_async_perf_main;
  crypto_test_async_perf_thread_t *pt = pm->threads + vm->thread_index;
  u32 n = vec_len (pt->buffers), n_submitted = pt->n_submitted;
  u32 n_trace;

  if (__atomic_load_n (&pt->active, __ATOMIC_ACQUIRE) == 0)
    return 0;

  if (pt->t_start == 0)
    pt->t_start = clib_cpu_time_now ();

  if (pt->n_completed >= n)
    {
      pt->t_end = clib_cpu_time_now ();
      pt->active = 0;
      __atomic_store_n (&pt->done, 1, __ATOMIC_RELEASE);
      return 0;
    }

  /* buffers are marked before submission, so the frames carrying them are traced */
  if (PREDICT_FALSE ((n_trace = vlib_get_trace_count (vm, node))))
    {
      for (u32 i = pt->trace_end > n_submitted ? pt->trace_end : n_submitted; i < n && n_trace; i++)
	{
	  vlib_buffer_t *b = vlib_get_buffer (vm, pt->buffers[i]);
	  crypto_test_async_perf_trace_t *t;

	  if (vlib_trace_buffer (vm, node, 0, b, 1) == 0)
	    continue;

	  t = vlib_add_trace (vm, node, b, sizeof (*t));
	  t->thread_index = vm->thread_index;
	  t->buffer_index = i;
	  t->type = pm->type;
	  pt->trace_end = i + 1;
	  n_trace--;
	}
      vlib_set_trace_count (vm, node, n_trace);
    }

  while (n_submitted < n)
    {
      u32 n_vectors = clib_min (pm->elts_per_frame, n - n_submitted);
      u32 in_flight = n_submitted - pt->n_completed;
      vlib_frame_t *f;

      if (pm->max_in_flight && in_flight + n_vectors > pm->max_in_flight)
	break;

      f = vlib_get_frame_to_node (vm, pm->enq_node_index);
      f->n_vectors = n_vectors;
      if (PREDICT_FALSE (n_submitted < pt->trace_end))
	f->frame_flags |= VLIB_FRAME_TRACE;
      clib_memcpy_fast (vlib_frame_vector_args (f), pt->buffers + n_submitted,
			n_vectors * sizeof (u32));
      clib_memcpy_fast (vlib_frame_aux_args (f), pt->ctxs, n_vectors * sizeof (pt->ctxs[0]));
      *(vnet_crypto_frame_scalar_data_t *) vlib_frame_scalar_args (f) =
	(vnet_crypto_frame_scalar_data_t) {
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
  .flags = VLIB_NODE_FLAG_TRACE_SUPPORTED,
  .format_trace = format_crypto_test_async_perf_trace,
  /* vlib_trace_buffer marks next 0, frames go to the engine with vlib_put_frame_to_node */
  .n_next_nodes = 1,
  .next_nodes = { [0] = "error-drop" },
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
				      pt->n_completed, vec_len (pt->buffers));
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
  u64 seed = clib_cpu_time_now ();
  f64 *mops[2] = {}, warmup_end, gbps_per_mops;
  u8 key_data[128];
  uword ti;

  n_buffers = tm->n_buffers ? tm->n_buffers : 4096;
  buffer_size = tm->buffer_size ? tm->buffer_size : 2048;
  rounds = tm->rounds ? tm->rounds : 5;
  gbps_per_mops = buffer_size * 8 * 1e-3;

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

  pm->elts_per_frame = tm->elts_per_frame ? tm->elts_per_frame : VLIB_FRAME_SIZE;
  pm->max_in_flight = tm->max_in_flight;
  pm->alg = tm->alg;
  vec_validate_aligned (pm->threads, vlib_get_n_threads () - 1, CLIB_CACHE_LINE_BYTES);
  clib_bitmap_foreach (ti, threads)
    {
      crypto_test_async_perf_thread_t *pt = pm->threads + ti;

      pt->n_submitted = pt->n_completed = pt->n_errors = pt->trace_end = 0;
    }

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
      vec_validate_aligned (pt->completed, n_buffers - 1, CLIB_CACHE_LINE_BYTES);
      n_alloc = vlib_buffer_alloc (vm, pt->buffers, n_buffers);
      if (n_alloc != n_buffers)
	{
	  vlib_buffer_free (vm, pt->buffers, n_alloc);
	  vec_free (pt->buffers);
	  err =
	    clib_error_return (0, "buffer alloc failure, %u buffers per thread needed", n_buffers);
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

  if (tm->trace_count)
    trace_update_capture_options (tm->trace_count, crypto_test_async_perf_node.index, 0, 0);

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

	  clib_bitmap_foreach (ti, threads)
	    total[i] += mops[i][ti];
	}

      if (err)
	break;

      /* buffers are reused, only the first round is traced */
      if (tm->trace_count && r == 0 && n_warmup == 0)
	clib_bitmap_foreach (ti, threads)
	  {
	    crypto_test_async_perf_thread_t *pt = pm->threads + ti;

	    for (u32 i = 0; i < pt->trace_end; i++)
	      vlib_get_buffer (vm, pt->buffers[i])->flags &= ~VLIB_BUFFER_IS_TRACED;
	    pt->trace_end = 0;
	  }

      if (is_warmup)
	{
	  n_warmup++;
	  continue;
	}

      r++;
      if (n_types == 1)
	vlib_cli_output (vm, "%-2u: hash %.02f Mops %.02f Gbps", r, total[0],
			 total[0] * gbps_per_mops);
      else
	vlib_cli_output (vm,
			 "%-2u: encrypt%s %.02f Mops %.02f Gbps; decrypt%s %.02f Mops %.02f Gbps",
			 r, is_combined ? "+hmac" : "", total[0], total[0] * gbps_per_mops,
			 is_combined ? "+hmac" : "", total[1], total[1] * gbps_per_mops);

      if (clib_bitmap_count_set_bits (threads) > 1)
	clib_bitmap_foreach (ti, threads)
	  {
	    if (n_types == 1)
	      vlib_cli_output (vm, "    thread %u: %.02f Mops %.02f Gbps", ti, mops[0][ti],
			       mops[0][ti] * gbps_per_mops);
	    else
	      vlib_cli_output (vm, "    thread %u: %.02f Mops %.02f Gbps / %.02f Mops %.02f Gbps",
			       ti, mops[0][ti], mops[0][ti] * gbps_per_mops, mops[1][ti],
			       mops[1][ti] * gbps_per_mops);
	  }
    }

done:
  /* buffers still in flight are freed by the sink when they complete */
  vlib_worker_thread_barrier_sync (vm);
  clib_bitmap_foreach (ti, threads)
    {
      crypto_test_async_perf_thread_t *pt = pm->threads + ti;
      u32 n_submitted = pt->n_submitted;

      __atomic_store_n (&pt->active, 0, __ATOMIC_RELEASE);
      vlib_buffer_free (vm, pt->completed, pt->n_completed);
      vlib_buffer_free (vm, pt->buffers + n_submitted, vec_len (pt->buffers) - n_submitted);
      if (pt->ctx && n_submitted == pt->n_completed)
	vnet_crypto_ctx_destroy (vm, pt->ctx);
      pt->ctx = 0;
      vec_free (pt->ctxs);
      vec_free (pt->buffers);
      vec_free (pt->completed);
    }
  vlib_worker_thread_barrier_release (vm);

  for (u32 i = 0; i < n_types; i++)
    vec_free (mops[i]);
  clib_bitmap_free (threads);
  return err;
}
