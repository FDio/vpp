/*
 * Copyright (c) 2020 Intel and/or its affiliates.
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

#include <vnet/crypto/crypto.h>

#ifndef __crypto_sw_scheduler_h__
#define __crypto_sw_scheduler_h__

#define CRYPTO_SW_SCHEDULER_QUEUE_SIZE 64
#define CRYPTO_SW_SCHEDULER_QUEUE_MASK (CRYPTO_SW_SCHEDULER_QUEUE_SIZE - 1)
STATIC_ASSERT ((0 == (CRYPTO_SW_SCHEDULER_QUEUE_SIZE &
		      (CRYPTO_SW_SCHEDULER_QUEUE_SIZE - 1))),
	       "CRYPTO_SW_SCHEDULER_QUEUE_SIZE is not pow2");

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);

  struct
  {
    u32 head;
    u32 tail;
    vnet_crypto_async_frame_t **jobs;
  } queue;
  u32 last_serve_lcore_id;
  vnet_crypto_op_t *crypto_ops;
  vnet_crypto_op_t *integ_ops;
  u32 self_crypto_enabled;
  u64 n_enqd;
  u64 n_deqd;
  u64 *n_proc;
  vnet_crypto_op_t *chained_crypto_ops;
  vnet_crypto_op_t *chained_integ_ops;
  vnet_crypto_op_chunk_t *chunks;

} crypto_sw_scheduler_per_thread_data_t;

typedef struct
{
  u32 crypto_engine_index;
  crypto_sw_scheduler_per_thread_data_t *per_thread_data;
  vnet_crypto_key_t *keys;
} crypto_sw_scheduler_main_t;

extern crypto_sw_scheduler_main_t crypto_sw_scheduler_main;

extern int crypto_sw_scheduler_set_worker_crypto (u32 worker_idx, u8 enabled);

extern clib_error_t *crypto_sw_scheduler_api_init (vlib_main_t * vm);

#endif // __crypto_native_h__

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
