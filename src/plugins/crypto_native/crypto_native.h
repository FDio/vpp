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


#ifndef __crypto_native_h__
#define __crypto_native_h__

#define NATIVE_QUEUE_SIZE 32
#define NATIVE_QUEUE_SIZE 32
#define NATIVE_QUEUE_MASK (NATIVE_QUEUE_SIZE - 1)

typedef void *(crypto_native_key_fn_t) (vnet_crypto_key_t * key);

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  u32 head;
  u32 tail;
  vnet_crypto_async_frame_t *frames[NATIVE_QUEUE_SIZE];
} native_queue_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  u8x16 cbc_iv[4];
  native_queue_t *frames[VNET_CRYPTO_ASYNC_OP_N_IDS];
} crypto_native_per_thread_data_t;

typedef struct
{
  u32 crypto_engine_index;
  crypto_native_per_thread_data_t *per_thread_data;
  crypto_native_key_fn_t *key_fn[VNET_CRYPTO_N_ALGS];
  void **key_data;
} crypto_native_main_t;



extern crypto_native_main_t crypto_native_main;

clib_error_t *crypto_native_aes_cbc_init_sse42 (vlib_main_t * vm);
clib_error_t *crypto_native_aes_cbc_init_avx2 (vlib_main_t * vm);
clib_error_t *crypto_native_aes_cbc_init_avx512 (vlib_main_t * vm);
clib_error_t *crypto_native_aes_cbc_init_vaes (vlib_main_t * vm);
clib_error_t *crypto_native_aes_cbc_init_neon (vlib_main_t * vm);

clib_error_t *crypto_native_aes_gcm_init_sse42 (vlib_main_t * vm);
clib_error_t *crypto_native_aes_gcm_init_avx2 (vlib_main_t * vm);
clib_error_t *crypto_native_aes_gcm_init_avx512 (vlib_main_t * vm);
clib_error_t *crypto_native_aes_gcm_init_vaes (vlib_main_t * vm);
clib_error_t *crypto_native_aes_gcm_init_neon (vlib_main_t * vm);
#endif /* __crypto_native_h__ */




static_always_inline int
native_async_enqueue (vlib_main_t * vm, vnet_crypto_async_frame_t * frame,
		      vnet_crypto_async_op_id_t opt)
{
  crypto_native_main_t *nvem = &crypto_native_main;
  crypto_native_per_thread_data_t *ptd =
    vec_elt_at_index (nvem->per_thread_data,
		      vm->thread_index);
  native_queue_t *q = ptd->frames[opt];
  u32 head;

  if (PREDICT_FALSE (q == 0))
    {
      q = clib_mem_alloc_aligned (sizeof (*q), CLIB_CACHE_LINE_BYTES);
      ptd->frames[opt] = q;
    }

  head = q->head;

  if (q->frames[head & NATIVE_QUEUE_MASK])
    return -1;
  q->frames[head & NATIVE_QUEUE_MASK] = frame;
  CLIB_MEMORY_STORE_BARRIER ();
  q->head++;

  return 0;
}


static_always_inline vnet_crypto_async_frame_t *
native_get_pending_frame (native_queue_t * q)
{
  u32 i;
  vnet_crypto_async_frame_t *f;
  u32 tail;
  u32 head;

  if (!q)
    return 0;

  tail = q->tail;
  head = q->head;
  if (head == tail)
    return 0;

  for (i = tail; i < head; i++)
    {
      f = q->frames[i & NATIVE_QUEUE_MASK];
      if (clib_atomic_bool_cmp_and_swap (&f->state,
					 VNET_CRYPTO_FRAME_STATE_NOT_PROCESSED,
					 VNET_CRYPTO_FRAME_STATE_WORK_IN_PROGRESS))
	return f;
    }
  return 0;
}


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
