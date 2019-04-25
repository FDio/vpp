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

#define foreach_crypto_cipher_alg \
  _(DES_CBC,     "des-cbc") \
  _(3DES_CBC,    "3des-cbc") \
  _(AES_128_CBC, "aes-128-cbc") \
  _(AES_192_CBC, "aes-192-cbc") \
  _(AES_256_CBC, "aes-256-cbc") \
  _(AES_128_CTR, "aes-128-ctr") \
  _(AES_192_CTR, "aes-192-ctr") \
  _(AES_256_CTR, "aes-256-ctr")

#define foreach_crypto_aead_alg \
  _(AES_128_GCM, "aes-128-gcm") \
  _(AES_192_GCM, "aes-192-gcm") \
  _(AES_256_GCM, "aes-256-gcm")

#define foreach_crypto_hmac_alg \
  _(MD5, "md5") \
  _(SHA1, "sha-1") \
  _(SHA224, "sha-224")  \
  _(SHA256, "sha-256")  \
  _(SHA384, "sha-384")  \
  _(SHA512, "sha-512")


#define foreach_crypto_op_type \
  _(ENCRYPT, "encrypt") \
  _(DECRYPT, "decrypt") \
  _(AEAD_ENCRYPT, "aead-encrypt") \
  _(AEAD_DECRYPT, "aead-decrypt") \
  _(HMAC, "hmac")

typedef enum
{
#define _(n, s) VNET_CRYPTO_OP_TYPE_##n,
  foreach_crypto_op_type
#undef _
    VNET_CRYPTO_OP_N_TYPES,
} vnet_crypto_op_type_t;

#define foreach_crypto_op_status \
  _(PENDING, "pending") \
  _(COMPLETED, "completed") \
  _(FAIL_NO_HANDLER, "no-handler") \
  _(FAIL_BAD_HMAC, "bad-hmac") \
  _(FAIL_DECRYPT, "decrypt-fail")

typedef enum
{
  VNET_CRYPTO_KEY_OP_ADD,
  VNET_CRYPTO_KEY_OP_DEL,
  VNET_CRYPTO_KEY_OP_MODIFY,
} vnet_crypto_key_op_t;

typedef enum
{
#define _(n, s) VNET_CRYPTO_OP_STATUS_##n,
  foreach_crypto_op_status
#undef _
    VNET_CRYPTO_OP_N_STATUS,
} vnet_crypto_op_status_t;

/* *INDENT-OFF* */
typedef enum
{
  VNET_CRYPTO_ALG_NONE = 0,
#define _(n, s) VNET_CRYPTO_ALG_##n,
  foreach_crypto_cipher_alg
  foreach_crypto_aead_alg
#undef _
#define _(n, s) VNET_CRYPTO_ALG_HMAC_##n,
  foreach_crypto_hmac_alg
#undef _
  VNET_CRYPTO_N_ALGS,
} vnet_crypto_alg_t;

typedef struct
{
  u8 *data;
  vnet_crypto_alg_t alg:8;
} vnet_crypto_key_t;

typedef enum
{
  VNET_CRYPTO_OP_NONE = 0,
#define _(n, s) VNET_CRYPTO_OP_##n##_ENC, VNET_CRYPTO_OP_##n##_DEC,
  foreach_crypto_cipher_alg
  foreach_crypto_aead_alg
#undef _
#define _(n, s) VNET_CRYPTO_OP_##n##_HMAC,
 foreach_crypto_hmac_alg
#undef _
    VNET_CRYPTO_N_OP_IDS,
} vnet_crypto_op_id_t;
/* *INDENT-ON* */

typedef struct
{
  char *name;
  vnet_crypto_op_id_t op_by_type[VNET_CRYPTO_OP_N_TYPES];
} vnet_crypto_alg_data_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  vnet_crypto_op_id_t op:16;
  vnet_crypto_op_status_t status:8;
  u8 flags;
#define VNET_CRYPTO_OP_FLAG_INIT_IV (1 << 0)
#define VNET_CRYPTO_OP_FLAG_HMAC_CHECK (1 << 1)
  u32 key_index;
  u32 len;
  u16 aad_len;
  u8 digest_len, tag_len;
  u8 *iv;
  u8 *src;
  u8 *dst;
  u8 *aad;
  u8 *tag;
  u8 *digest;
  uword user_data;
} vnet_crypto_op_t;

typedef struct
{
  vnet_crypto_op_type_t type;
  vnet_crypto_alg_t alg;
  u32 active_engine_index;
} vnet_crypto_op_data_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  clib_bitmap_t *act_queues;
} vnet_crypto_thread_t;

typedef u32 vnet_crypto_key_index_t;

typedef u32 (vnet_crypto_ops_handler_t) (vlib_main_t * vm,
					 vnet_crypto_op_t * ops[], u32 n_ops);

typedef void (vnet_crypto_key_handler_t) (vlib_main_t * vm,
					  vnet_crypto_key_op_t kop,
					  vnet_crypto_key_index_t idx);

u32 vnet_crypto_register_engine (vlib_main_t * vm, char *name, int prio,
				 char *desc);

void vnet_crypto_register_ops_handler (vlib_main_t * vm, u32 engine_index,
				       vnet_crypto_op_id_t opt,
				       vnet_crypto_ops_handler_t * oph);
void vnet_crypto_register_key_handler (vlib_main_t * vm, u32 engine_index,
				       vnet_crypto_key_handler_t * keyh);

typedef struct
{
  char *name;
  char *desc;
  int priority;
  vnet_crypto_key_handler_t *key_op_handler;
  vnet_crypto_ops_handler_t *ops_handlers[VNET_CRYPTO_N_OP_IDS];
} vnet_crypto_engine_t;

typedef struct
{
  vnet_crypto_alg_data_t *algs;
  vnet_crypto_thread_t *threads;
  vnet_crypto_ops_handler_t **ops_handlers;
  vnet_crypto_op_data_t opt_data[VNET_CRYPTO_N_OP_IDS];
  vnet_crypto_engine_t *engines;
  vnet_crypto_key_t *keys;
  uword *engine_index_by_name;
  uword *alg_index_by_name;
} vnet_crypto_main_t;

extern vnet_crypto_main_t crypto_main;

u32 vnet_crypto_submit_ops (vlib_main_t * vm, vnet_crypto_op_t ** jobs,
			    u32 n_jobs);

u32 vnet_crypto_process_ops (vlib_main_t * vm, vnet_crypto_op_t ops[],
			     u32 n_ops);

int vnet_crypto_set_handler (char *ops_handler_name, char *engine);

u32 vnet_crypto_key_add (vlib_main_t * vm, vnet_crypto_alg_t alg,
			 u8 * data, u16 length);
void vnet_crypto_key_del (vlib_main_t * vm, vnet_crypto_key_index_t index);
void vnet_crypto_key_modify (vlib_main_t * vm, vnet_crypto_key_index_t index,
			     vnet_crypto_alg_t alg, u8 * data, u16 len);

format_function_t format_vnet_crypto_alg;
format_function_t format_vnet_crypto_engine;
format_function_t format_vnet_crypto_op;
format_function_t format_vnet_crypto_op_type;
format_function_t format_vnet_crypto_op_status;
unformat_function_t unformat_vnet_crypto_alg;

static_always_inline void
vnet_crypto_op_init (vnet_crypto_op_t * op, vnet_crypto_op_id_t type)
{
  if (CLIB_DEBUG > 0)
    clib_memset (op, 0xfe, sizeof (*op));
  op->op = type;
  op->flags = 0;
  op->key_index = ~0;
}

static_always_inline vnet_crypto_op_type_t
vnet_crypto_get_op_type (vnet_crypto_op_id_t id)
{
  vnet_crypto_main_t *cm = &crypto_main;
  vnet_crypto_op_data_t *od = vec_elt_at_index (cm->opt_data, id);
  return od->type;
}

static_always_inline vnet_crypto_key_t *
vnet_crypto_get_key (vnet_crypto_key_index_t index)
{
  vnet_crypto_main_t *cm = &crypto_main;
  return vec_elt_at_index (cm->keys, index);
}

#endif /* included_vnet_crypto_crypto_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
