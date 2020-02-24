/*
 *------------------------------------------------------------------
 * Copyright (c) 2019 Cisco and/or its affiliates.
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
 *------------------------------------------------------------------
 */

#include <vlib/vlib.h>
#include <vnet/plugin/plugin.h>
#include <vnet/crypto/crypto.h>
#include <crypto_native/crypto_native.h>

crypto_native_main_t crypto_native_main;

static void
crypto_native_key_handler (vlib_main_t * vm, vnet_crypto_key_op_t kop,
			   vnet_crypto_key_index_t idx)
{
  vnet_crypto_key_t *key = vnet_crypto_get_key (idx);
  crypto_native_main_t *cm = &crypto_native_main;

  if (cm->key_fn[key->alg] == 0)
    return;

  if (kop == VNET_CRYPTO_KEY_OP_DEL)
    {
      if (idx >= vec_len (cm->key_data))
	return;

      if (cm->key_data[idx] == 0)
	return;

      clib_mem_free_s (cm->key_data[idx]);
      cm->key_data[idx] = 0;
      return;
    }

  vec_validate_aligned (cm->key_data, idx, CLIB_CACHE_LINE_BYTES);

  if (kop == VNET_CRYPTO_KEY_OP_MODIFY && cm->key_data[idx])
    {
      clib_mem_free_s (cm->key_data[idx]);
    }

  cm->key_data[idx] = cm->key_fn[key->alg] (key);
}

u32
crypto_native_get_pending_jobs (crypto_native_queue_t * q,
				vnet_crypto_op_t * jobs[], u32 n_jobs)
{
  u32 i;
  vnet_crypto_op_t *j;
  u32 tail = q->tail;
  u32 head = q->head;
  u32 mask = q->size - 1;
  u32 n_got = 0;

  if (head == tail)
    return 0;

  for (i = tail; i < head; i++)
    {
      j = &q->jobs[i & mask];

      if (clib_atomic_bool_cmp_and_swap (&j->status,
					 VNET_CRYPTO_OP_STATUS_PENDING,
					 VNET_CRYPTO_OP_STATUS_WORK_IN_PROGRESS))
	{
	  jobs[n_got++] = j;
	  if (PREDICT_FALSE (n_got == n_jobs))
	    break;
	}
    }
  return n_got;
}

u32
crypto_native_dequeue_ops (crypto_native_per_thread_data_t * ptd,
			   crypto_native_queue_t * q,
			   vnet_crypto_op_async_data_t post_jobs[],
			   u32 n_jobs)
{
  vnet_crypto_op_id_t opt = q->op;
  u32 head = q->head;
  u32 mask = q->size - 1;
  u32 n_total = 0;

  while (1)
    {
      u32 tail = clib_atomic_load_acq_n (&q->tail);
      vnet_crypto_op_t *job = &q->jobs[tail & mask];

      if (head == tail)
	{
	  clib_bitmap_set_no_check (ptd->act_queues, opt, 0);
	  break;
	}

      if (job->status >= VNET_CRYPTO_OP_STATUS_COMPLETED)
	{
	  post_jobs[n_total].bi = job->async_dst.bi;
	  post_jobs[n_total].next = job->async_dst.next;
	  post_jobs[n_total++].status = (u16) job->status;
	  q->jobs[tail & mask].status = VNET_CRYPTO_OP_STATUS_IDLE;
	  clib_atomic_fetch_add (&q->tail, 1);
	}

      if (n_total == n_jobs)
	break;
    }

  return n_total;
}

u32
crypto_native_enqueue_ops (vlib_main_t * vm, vnet_crypto_op_id_t opt,
			   vnet_crypto_op_t * jobs[], u32 n_jobs)
{
  crypto_native_main_t *cm = &crypto_native_main;
  crypto_native_per_thread_data_t *ptd =
    vec_elt_at_index (cm->per_thread_data,
		      vm->thread_index);
  crypto_native_queue_t *q = ptd->queues[opt];

  u32 n_enq = 0;
  u32 head = q->head;
  u32 mask = q->size - 1;

  while (n_enq < n_jobs)
    {
      if (q->jobs[head & mask].status != VNET_CRYPTO_OP_STATUS_IDLE)
	break;
      jobs[n_enq]->status = VNET_CRYPTO_OP_STATUS_PENDING;
      q->jobs[head & mask] = *jobs[n_enq];
      head += 1;
      n_enq += 1;
    }

  if (n_enq)
    {
      CLIB_MEMORY_STORE_BARRIER ();
      q->head = head;
    }
  return n_enq;
}

clib_error_t *
crypto_native_init (vlib_main_t * vm)
{
  crypto_native_main_t *cm = &crypto_native_main;
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  clib_error_t *error = 0;

  if (clib_cpu_supports_x86_aes () == 0 &&
      clib_cpu_supports_aarch64_aes () == 0)
    return 0;

  vec_validate_aligned (cm->per_thread_data, tm->n_vlib_mains - 1,
			CLIB_CACHE_LINE_BYTES);

  cm->crypto_engine_index =
    vnet_crypto_register_engine (vm, "native", 100,
				 "Native ISA Optimized Crypto");

#if __x86_64__
  if (clib_cpu_supports_vaes ())
    error = crypto_native_aes_cbc_init_vaes (vm);
  else if (clib_cpu_supports_avx512f ())
    error = crypto_native_aes_cbc_init_avx512 (vm);
  else if (clib_cpu_supports_avx2 ())
    error = crypto_native_aes_cbc_init_avx2 (vm);
  else
    error = crypto_native_aes_cbc_init_sse42 (vm);

  if (error)
    goto error;

  if (clib_cpu_supports_pclmulqdq ())
    {
      if (clib_cpu_supports_vaes ())
	error = crypto_native_aes_gcm_init_vaes (vm);
      else if (clib_cpu_supports_avx512f ())
	error = crypto_native_aes_gcm_init_avx512 (vm);
      else if (clib_cpu_supports_avx2 ())
	error = crypto_native_aes_gcm_init_avx2 (vm);
      else
	error = crypto_native_aes_gcm_init_sse42 (vm);

      if (error)
	goto error;
    }
#endif
#if __aarch64__
  if ((error = crypto_native_aes_cbc_init_neon (vm)))
    goto error;

  if ((error = crypto_native_aes_gcm_init_neon (vm)))
    goto error;
#endif

  vnet_crypto_register_key_handler (vm, cm->crypto_engine_index,
				    crypto_native_key_handler);

  u32 sz =
    CRYPTO_NATIVE_RING_SIZE * sizeof (vnet_crypto_op_t) +
    sizeof (crypto_native_queue_t);
  crypto_native_queue_t *q;
  crypto_native_per_thread_data_t *ptd;

  vec_foreach (ptd, cm->per_thread_data)
  {
    for (int opt = 0; opt < VNET_CRYPTO_N_OP_IDS; opt++)
      {
	q = clib_mem_alloc_aligned (sz, CLIB_CACHE_LINE_BYTES);
	ptd->queues[opt] = q;
	clib_memset_u8 (q, 0, sz);
	q->size = CRYPTO_NATIVE_RING_SIZE;
	q->op = opt;
      }
    clib_bitmap_vec_validate (ptd->act_queues, VNET_CRYPTO_N_OP_IDS);
    vec_validate_aligned (ptd->jobs, VLIB_FRAME_SIZE, CLIB_CACHE_LINE_BYTES);
  }

error:
  if (error)
    vec_free (cm->per_thread_data);

  return error;
}

/* *INDENT-OFF* */
VLIB_INIT_FUNCTION (crypto_native_init) =
{
  .runs_after = VLIB_INITS ("vnet_crypto_init"),
};
/* *INDENT-ON* */

#include <vpp/app/version.h>

/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "Intel IA32 Software Crypto Engine",
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
