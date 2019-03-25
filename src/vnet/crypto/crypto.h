/*
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
 */

#ifndef included_vnet_crypto_crypto_h
#define included_vnet_crypto_crypto_h

#define VNET_CRYPTO_RING_SIZE 512

#include <vlib/vlib.h>

#define foreach_crypto_alg \
  _(DES_CBC, "des-cbc") \
  _(3DES_CBC, "3des-cbc") \
  _(AES_128_CBC, "aes-128-cbc") \
  _(AES_192_CBC, "aes-192-cbc") \
  _(AES_256_CBC, "aes-256-cbc")

#define foreach_hmac_alg \
  _(MD5, "md5") \
  _(SHA1, "sha-1") \
  _(SHA224, "sha-224")  \
  _(SHA256, "sha-256")  \
  _(SHA384, "sha-384")  \
  _(SHA512, "sha-512")

/* *INDENT-OFF* */
typedef enum
{
#define _(n, s) VNET_CRYPTO_ALG_##n,
  foreach_crypto_alg
#undef _
#define _(n, s) VNET_CRYPTO_ALG_##n,
  foreach_hmac_alg
#undef _
  VNET_CRYPTO_N_ALGS,
} vnet_crypto_alg_t;

typedef enum
{
  VNET_CRYPTO_OP_NONE = 0,
#define _(n, s) VNET_CRYPTO_OP_##n##_ENC, VNET_CRYPTO_OP_##n##_DEC,
  foreach_crypto_alg
#undef _
#define _(n, s) VNET_CRYPTO_OP_##n##_HMAC,
  foreach_hmac_alg
#undef _
    VNET_CRYPTO_N_OP_TYPES,
} __attribute__ ((packed)) vnet_crypto_op_type_t;
/* *INDENT-ON* */

STATIC_ASSERT (sizeof (vnet_crypto_op_type_t) <= 2,
	       "crypto op type > 2 bytes");

typedef struct
{
  char *name;
} vnet_crypto_alg_data_t;

typedef enum
{
  VNET_CRYPTO_OP_STATUS_PENDING,
  VNET_CRYPTO_OP_STATUS_COMPLETED,
  VNET_CRYPTO_OP_STATUS_FAIL_NO_HANDLER,
  VNET_CRYPTO_OP_STATUS_FAIL_BAD_HMAC,
} __attribute__ ((packed)) vnet_crypto_op_status_t;

STATIC_ASSERT (sizeof (vnet_crypto_op_status_t) == 1,
	       "crypto op status > 1 byte");

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  vnet_crypto_op_type_t op;
  vnet_crypto_op_status_t status;
  u8 key_len, hmac_trunc_len;
  u16 flags;
#define VNET_CRYPTO_OP_FLAG_INIT_IV (1 << 0)
#define VNET_CRYPTO_OP_FLAG_HMAC_CHECK (1 << 1)
  u32 len;
  u8 *key;
  u8 *iv;
  u8 *src;
  u8 *dst;
  uword user_data;
} vnet_crypto_op_t;

typedef struct
{
  vnet_crypto_alg_t alg;
  const char *desc;
  u32 active_engine_index;
} vnet_crypto_op_type_data_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  u32 head;
  u32 tail;
  u32 size;
  vnet_crypto_alg_t alg:8;
  vnet_crypto_op_type_t op:8;
  vnet_crypto_op_t *jobs[0];
} vnet_crypto_queue_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  clib_bitmap_t *act_queues;
  vnet_crypto_queue_t *queues[VNET_CRYPTO_N_OP_TYPES];
} vnet_crypto_thread_t;

typedef u32 (vnet_crypto_ops_handler_t) (vlib_main_t * vm,
					 vnet_crypto_op_t * ops[], u32 n_ops);

u32 vnet_crypto_register_engine (vlib_main_t * vm, char *name, int prio,
				 char *desc);

vlib_error_t *vnet_crypto_register_ops_handler (vlib_main_t * vm,
						u32 provider_index,
						vnet_crypto_op_type_t opt,
						vnet_crypto_ops_handler_t *
						f);

typedef struct
{
  char *name;
  char *desc;
  int priority;
  vnet_crypto_ops_handler_t *ops_handlers[VNET_CRYPTO_N_OP_TYPES];
} vnet_crypto_engine_t;

typedef struct
{
  vnet_crypto_alg_data_t *algs;
  vnet_crypto_thread_t *threads;
  vnet_crypto_ops_handler_t **ops_handlers;
  vnet_crypto_op_type_data_t opt_data[VNET_CRYPTO_N_OP_TYPES];
  vnet_crypto_engine_t *engines;
  uword *engine_index_by_name;
  uword *ops_handler_index_by_name;
} vnet_crypto_main_t;

extern vnet_crypto_main_t crypto_main;

u32 vnet_crypto_submit_ops (vlib_main_t * vm, vnet_crypto_op_t ** jobs,
			    u32 n_jobs);

u32 vnet_crypto_process_ops (vlib_main_t * vm, vnet_crypto_op_t ops[],
			     u32 n_ops);


int vnet_crypto_set_handler (char *ops_handler_name, char *engine);

format_function_t format_vnet_crypto_alg;
format_function_t format_vnet_crypto_engine;
format_function_t format_vnet_crypto_op;

#endif /* included_vnet_crypto_crypto_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
