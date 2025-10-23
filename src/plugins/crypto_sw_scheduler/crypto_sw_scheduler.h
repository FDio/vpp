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

typedef enum crypto_sw_scheduler_queue_type_t_
{
  CRYPTO_SW_SCHED_QUEUE_TYPE_ENCRYPT = 0,
  CRYPTO_SW_SCHED_QUEUE_TYPE_DECRYPT,
  CRYPTO_SW_SCHED_QUEUE_N_TYPES
} crypto_sw_scheduler_queue_type_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  u32 head;
  u32 tail;
  vnet_crypto_async_frame_t **jobs;
} crypto_sw_scheduler_queue_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  crypto_sw_scheduler_queue_t queue[CRYPTO_SW_SCHED_QUEUE_N_TYPES];
  u32 last_serve_lcore_id;
  u8 last_serve_encrypt;
  u8 last_return_queue;
  vnet_crypto_op_t *crypto_ops;
  vnet_crypto_op_t *chained_crypto_ops;
  vnet_crypto_op_chunk_t *chunks;
  u8 self_crypto_enabled;
} crypto_sw_scheduler_per_thread_data_t;

typedef struct
{
  u32 crypto_engine_index;
  crypto_sw_scheduler_per_thread_data_t *per_thread_data;
  vnet_crypto_key_t *keys;
  u32 crypto_sw_scheduler_queue_mask;
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
