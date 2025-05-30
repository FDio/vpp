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

#include <vlib/vlib.h>

#define VNET_CRYPTO_FRAME_SIZE 64
#define VNET_CRYPTO_FRAME_POOL_SIZE 1024

/* CRYPTO_ID, PRETTY_NAME, ARGS*/
#define foreach_crypto_cipher_alg                                             \
  _ (DES_CBC, "des-cbc", .key_length = 7)                                     \
  _ (3DES_CBC, "3des-cbc", .key_length = 24)                                  \
  _ (AES_128_CBC, "aes-128-cbc", .key_length = 16)                            \
  _ (AES_192_CBC, "aes-192-cbc", .key_length = 24)                            \
  _ (AES_256_CBC, "aes-256-cbc", .key_length = 32)                            \
  _ (AES_128_CTR, "aes-128-ctr", .key_length = 16)                            \
  _ (AES_192_CTR, "aes-192-ctr", .key_length = 24)                            \
  _ (AES_256_CTR, "aes-256-ctr", .key_length = 32)

/* CRYPTO_ID, PRETTY_NAME,  ARGS */
#define foreach_crypto_aead_alg                                               \
  _ (AES_128_GCM, "aes-128-gcm", .is_aead = 1, .key_length = 16)              \
  _ (AES_192_GCM, "aes-192-gcm", .is_aead = 1, .key_length = 24)              \
  _ (AES_256_GCM, "aes-256-gcm", .is_aead = 1, .key_length = 32)              \
  _ (AES_128_NULL_GMAC, "aes-128-null-gmac", .is_aead = 1, .key_length = 16)  \
  _ (AES_192_NULL_GMAC, "aes-192-null-gmac", .is_aead = 1, .key_length = 24)  \
  _ (AES_256_NULL_GMAC, "aes-256-null-gmac", .is_aead = 1, .key_length = 32)  \
  _ (CHACHA20_POLY1305, "chacha20-poly1305", .is_aead = 1, .key_length = 32)

#define foreach_crypto_hash_alg                                               \
  _ (MD5, "md5")                                                              \
  _ (SHA1, "sha-1")                                                           \
  _ (SHA224, "sha-224")                                                       \
  _ (SHA256, "sha-256")                                                       \
  _ (SHA384, "sha-384")                                                       \
  _ (SHA512, "sha-512")

#define foreach_crypto_op_type                                                \
  _ (ENCRYPT, "encrypt")                                                      \
  _ (DECRYPT, "decrypt")                                                      \
  _ (HMAC, "hmac")                                                            \
  _ (HASH, "hash")

typedef enum
{
#define _(n, s) VNET_CRYPTO_OP_TYPE_##n,
  foreach_crypto_op_type
#undef _
    VNET_CRYPTO_OP_N_TYPES,
} vnet_crypto_op_type_t;

#define foreach_crypto_op_status \
  _(IDLE, "idle") \
  _(PENDING, "pending") \
  _(WORK_IN_PROGRESS, "work-in-progress") \
  _(COMPLETED, "completed") \
  _(FAIL_NO_HANDLER, "no-handler") \
  _(FAIL_BAD_HMAC, "bad-hmac") \
  _(FAIL_ENGINE_ERR, "engine-error")

/** async crypto **/

/* CRYPTO_ID, PRETTY_NAME, KEY_LENGTH_IN_BYTES, TAG_LEN, AAD_LEN */
#define foreach_crypto_aead_async_alg                                         \
  _ (AES_128_GCM, "aes-128-gcm-aad8", 16, 16, 8)                              \
  _ (AES_128_GCM, "aes-128-gcm-aad12", 16, 16, 12)                            \
  _ (AES_192_GCM, "aes-192-gcm-aad8", 24, 16, 8)                              \
  _ (AES_192_GCM, "aes-192-gcm-aad12", 24, 16, 12)                            \
  _ (AES_256_GCM, "aes-256-gcm-aad8", 32, 16, 8)                              \
  _ (AES_256_GCM, "aes-256-gcm-aad12", 32, 16, 12)                            \
  _ (AES_128_NULL_GMAC, "aes-128-null-gmac-aad8", 16, 16, 8)                  \
  _ (AES_128_NULL_GMAC, "aes-128-null-gmac-aad12", 16, 16, 12)                \
  _ (AES_192_NULL_GMAC, "aes-192-null-gmac-aad8", 24, 16, 8)                  \
  _ (AES_192_NULL_GMAC, "aes-192-null-gmac-aad12", 24, 16, 12)                \
  _ (AES_256_NULL_GMAC, "aes-256-null-gmac-aad8", 32, 16, 8)                  \
  _ (AES_256_NULL_GMAC, "aes-256-null-gmac-aad12", 32, 16, 12)                \
  _ (CHACHA20_POLY1305, "chacha20-poly1305-aad8", 32, 16, 8)                  \
  _ (CHACHA20_POLY1305, "chacha20-poly1305-aad12", 32, 16, 12)                \
  _ (CHACHA20_POLY1305, "chacha20-poly1305-aad0", 32, 16, 0)

/* CRYPTO_ID, INTEG_ID, PRETTY_NAME, KEY_LENGTH_IN_BYTES, DIGEST_LEN */
#define foreach_crypto_link_async_alg                                         \
  _ (3DES_CBC, MD5, "3des-cbc-hmac-md5", 24, 12)                              \
  _ (AES_128_CBC, MD5, "aes-128-cbc-hmac-md5", 16, 12)                        \
  _ (AES_192_CBC, MD5, "aes-192-cbc-hmac-md5", 24, 12)                        \
  _ (AES_256_CBC, MD5, "aes-256-cbc-hmac-md5", 32, 12)                        \
  _ (3DES_CBC, SHA1, "3des-cbc-hmac-sha-1", 24, 12)                           \
  _ (AES_128_CBC, SHA1, "aes-128-cbc-hmac-sha-1", 16, 12)                     \
  _ (AES_192_CBC, SHA1, "aes-192-cbc-hmac-sha-1", 24, 12)                     \
  _ (AES_256_CBC, SHA1, "aes-256-cbc-hmac-sha-1", 32, 12)                     \
  _ (3DES_CBC, SHA224, "3des-cbc-hmac-sha-224", 24, 14)                       \
  _ (AES_128_CBC, SHA224, "aes-128-cbc-hmac-sha-224", 16, 14)                 \
  _ (AES_192_CBC, SHA224, "aes-192-cbc-hmac-sha-224", 24, 14)                 \
  _ (AES_256_CBC, SHA224, "aes-256-cbc-hmac-sha-224", 32, 14)                 \
  _ (3DES_CBC, SHA256, "3des-cbc-hmac-sha-256", 24, 16)                       \
  _ (AES_128_CBC, SHA256, "aes-128-cbc-hmac-sha-256", 16, 16)                 \
  _ (AES_192_CBC, SHA256, "aes-192-cbc-hmac-sha-256", 24, 16)                 \
  _ (AES_256_CBC, SHA256, "aes-256-cbc-hmac-sha-256", 32, 16)                 \
  _ (3DES_CBC, SHA384, "3des-cbc-hmac-sha-384", 24, 24)                       \
  _ (AES_128_CBC, SHA384, "aes-128-cbc-hmac-sha-384", 16, 24)                 \
  _ (AES_192_CBC, SHA384, "aes-192-cbc-hmac-sha-384", 24, 24)                 \
  _ (AES_256_CBC, SHA384, "aes-256-cbc-hmac-sha-384", 32, 24)                 \
  _ (3DES_CBC, SHA512, "3des-cbc-hmac-sha-512", 24, 32)                       \
  _ (AES_128_CBC, SHA512, "aes-128-cbc-hmac-sha-512", 16, 32)                 \
  _ (AES_192_CBC, SHA512, "aes-192-cbc-hmac-sha-512", 24, 32)                 \
  _ (AES_256_CBC, SHA512, "aes-256-cbc-hmac-sha-512", 32, 32)                 \
  _ (AES_128_CTR, SHA1, "aes-128-ctr-hmac-sha-1", 16, 12)                     \
  _ (AES_192_CTR, SHA1, "aes-192-ctr-hmac-sha-1", 24, 12)                     \
  _ (AES_256_CTR, SHA1, "aes-256-ctr-hmac-sha-1", 32, 12)                     \
  _ (AES_128_CTR, SHA256, "aes-128-ctr-hmac-sha-256", 16, 16)                 \
  _ (AES_192_CTR, SHA256, "aes-192-ctr-hmac-sha-256", 24, 16)                 \
  _ (AES_256_CTR, SHA256, "aes-256-ctr-hmac-sha-256", 32, 16)                 \
  _ (AES_128_CTR, SHA384, "aes-128-ctr-hmac-sha-384", 16, 24)                 \
  _ (AES_192_CTR, SHA384, "aes-192-ctr-hmac-sha-384", 24, 24)                 \
  _ (AES_256_CTR, SHA384, "aes-256-ctr-hmac-sha-384", 32, 24)                 \
  _ (AES_128_CTR, SHA512, "aes-128-ctr-hmac-sha-512", 16, 32)                 \
  _ (AES_192_CTR, SHA512, "aes-192-ctr-hmac-sha-512", 24, 32)                 \
  _ (AES_256_CTR, SHA512, "aes-256-ctr-hmac-sha-512", 32, 32)

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

typedef enum
{
  VNET_CRYPTO_ALG_NONE = 0,
#define _(n, s, ...) VNET_CRYPTO_ALG_##n,
  foreach_crypto_cipher_alg foreach_crypto_aead_alg
#undef _
#define _(n, s) VNET_CRYPTO_ALG_HASH_##n, VNET_CRYPTO_ALG_HMAC_##n,
    foreach_crypto_hash_alg
#undef _
#define _(n, s, k, t, a) \
  VNET_CRYPTO_ALG_##n##_TAG##t##_AAD##a,
      foreach_crypto_aead_async_alg
#undef _
#define _(c, h, s, k ,d) \
  VNET_CRYPTO_ALG_##c##_##h##_TAG##d,
	foreach_crypto_link_async_alg
#undef _
	  VNET_CRYPTO_N_ALGS,
} vnet_crypto_alg_t;

typedef struct
{
  u32 index;
  u16 length;
  u8 is_link : 1;
  vnet_crypto_alg_t alg : 8;
  union
  {
    struct
    {
      u32 index_crypto;
      u32 index_integ;
    };
  };
  u8 data[];
} vnet_crypto_key_t;

typedef enum
{
  VNET_CRYPTO_OP_NONE = 0,
#define _(n, s, ...) VNET_CRYPTO_OP_##n##_ENC, VNET_CRYPTO_OP_##n##_DEC,
  foreach_crypto_cipher_alg foreach_crypto_aead_alg
#undef _
#define _(n, s) VNET_CRYPTO_OP_##n##_HASH, VNET_CRYPTO_OP_##n##_HMAC,
    foreach_crypto_hash_alg
#undef _
#define _(n, s, k, t, a)                                                      \
  VNET_CRYPTO_OP_##n##_TAG##t##_AAD##a##_ENC,                                 \
    VNET_CRYPTO_OP_##n##_TAG##t##_AAD##a##_DEC,
      foreach_crypto_aead_async_alg
#undef _
#define _(c, h, s, k, d)                                                      \
  VNET_CRYPTO_OP_##c##_##h##_TAG##d##_ENC,                                    \
    VNET_CRYPTO_OP_##c##_##h##_TAG##d##_DEC,
	foreach_crypto_link_async_alg
#undef _
	  VNET_CRYPTO_N_OP_IDS,
} __clib_packed vnet_crypto_op_id_t;

typedef struct
{
  char *name;
  u16 key_length;
  u8 is_aead : 1;
  u8 variable_key_length : 1;
  vnet_crypto_op_id_t op_by_type[VNET_CRYPTO_OP_N_TYPES];
} vnet_crypto_alg_data_t;

typedef struct
{
  u8 *src;
  u8 *dst;
  u32 len;
} vnet_crypto_op_chunk_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  uword user_data;
  vnet_crypto_op_id_t op;
  vnet_crypto_op_status_t status:8;
  u8 flags;
#define VNET_CRYPTO_OP_FLAG_HMAC_CHECK	    (1 << 0)
#define VNET_CRYPTO_OP_FLAG_CHAINED_BUFFERS (1 << 1)

  union
  {
    u8 digest_len;
    u8 tag_len;
  };
  u16 aad_len;

  union
  {
    struct
    {
      u8 *src;
      u8 *dst;
    };

    /* valid if VNET_CRYPTO_OP_FLAG_CHAINED_BUFFERS is set */
    u16 n_chunks;
  };

  union
  {
    u32 len;
    /* valid if VNET_CRYPTO_OP_FLAG_CHAINED_BUFFERS is set */
    u32 chunk_index;
  };

  u32 key_index;
  u8 *iv;
  u8 *aad;

  union
  {
    u8 *tag;
    u8 *digest;
  };
} vnet_crypto_op_t;

STATIC_ASSERT_SIZEOF (vnet_crypto_op_t, CLIB_CACHE_LINE_BYTES);

#define foreach_crypto_handler_type                                           \
  _ (SIMPLE, "simple")                                                        \
  _ (CHAINED, "chained")                                                      \
  _ (ASYNC, "async")

typedef enum
{
#define _(n, s) VNET_CRYPTO_HANDLER_TYPE_##n,
  foreach_crypto_handler_type
#undef _
    VNET_CRYPTO_HANDLER_N_TYPES

} vnet_crypto_handler_type_t;

typedef struct
{
  u8 *iv;
  union
  {
    u8 *digest;
    u8 *tag;
  };
  u8 *aad;
  u32 key_index;
  u32 crypto_total_length;
  i16 crypto_start_offset; /* first buffer offset */
  i16 integ_start_offset;
  /* adj total_length for integ, e.g.4 bytes for IPSec ESN */
  i16 integ_length_adj;
  vnet_crypto_op_status_t status : 8;
  u8 flags; /**< share same VNET_CRYPTO_OP_FLAG_* values */
} vnet_crypto_async_frame_elt_t;

/* Assert the size so the compiler will warn us when it changes */
STATIC_ASSERT_SIZEOF (vnet_crypto_async_frame_elt_t, 5 * sizeof (u64));

typedef enum vnet_crypto_async_frame_state_t_
{
  VNET_CRYPTO_FRAME_STATE_NOT_PROCESSED,
  /* frame waiting to be processed */
  VNET_CRYPTO_FRAME_STATE_PENDING,
  VNET_CRYPTO_FRAME_STATE_WORK_IN_PROGRESS,
  VNET_CRYPTO_FRAME_STATE_SUCCESS,
  VNET_CRYPTO_FRAME_STATE_ELT_ERROR
} __clib_packed vnet_crypto_async_frame_state_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  vnet_crypto_async_frame_state_t state;
  vnet_crypto_op_id_t op : 8;
  u16 n_elts;
  vnet_crypto_async_frame_elt_t elts[VNET_CRYPTO_FRAME_SIZE];
  u32 buffer_indices[VNET_CRYPTO_FRAME_SIZE];
  u16 next_node_index[VNET_CRYPTO_FRAME_SIZE];
  clib_thread_index_t enqueue_thread_index;
} vnet_crypto_async_frame_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  vnet_crypto_async_frame_t *frame_pool;
  u32 *buffer_indices;
  u16 *nexts;
} vnet_crypto_thread_t;

typedef u32 vnet_crypto_key_index_t;

typedef u32 (vnet_crypto_chained_op_fn_t) (vlib_main_t *vm,
					   vnet_crypto_op_t *ops[],
					   vnet_crypto_op_chunk_t *chunks,
					   u32 n_ops);

typedef u32 (vnet_crypto_simple_op_fn_t) (vlib_main_t *vm,
					  vnet_crypto_op_t *ops[], u32 n_ops);

typedef void (vnet_crypto_key_fn_t) (vnet_crypto_key_op_t kop,
				     vnet_crypto_key_index_t idx);

/** async crypto function handlers **/
typedef int (vnet_crypto_frame_enq_fn_t) (vlib_main_t *vm,
					  vnet_crypto_async_frame_t *frame);
typedef vnet_crypto_async_frame_t *(
  vnet_crypto_frame_dequeue_t) (vlib_main_t *vm, u32 *nb_elts_processed,
				clib_thread_index_t *enqueue_thread_idx);

u32
vnet_crypto_register_engine (vlib_main_t * vm, char *name, int prio,
			     char *desc);

void vnet_crypto_register_ops_handler (vlib_main_t *vm, u32 engine_index,
				       vnet_crypto_op_id_t opt,
				       vnet_crypto_simple_op_fn_t *oph);

void
vnet_crypto_register_chained_ops_handler (vlib_main_t *vm, u32 engine_index,
					  vnet_crypto_op_id_t opt,
					  vnet_crypto_chained_op_fn_t *oph);

void vnet_crypto_register_ops_handlers (vlib_main_t *vm, u32 engine_index,
					vnet_crypto_op_id_t opt,
					vnet_crypto_simple_op_fn_t *fn,
					vnet_crypto_chained_op_fn_t *cfn);

void vnet_crypto_register_key_handler (vlib_main_t *vm, u32 engine_index,
				       vnet_crypto_key_fn_t *keyh);

/** async crypto register functions */
u32 vnet_crypto_register_post_node (vlib_main_t * vm, char *post_node_name);

void vnet_crypto_register_enqueue_handler (vlib_main_t *vm, u32 engine_index,
					   vnet_crypto_op_id_t opt,
					   vnet_crypto_frame_enq_fn_t *enq_fn);

void
vnet_crypto_register_dequeue_handler (vlib_main_t *vm, u32 engine_index,
				      vnet_crypto_frame_dequeue_t *deq_fn);

typedef struct
{
  void *handlers[VNET_CRYPTO_HANDLER_N_TYPES];
} vnet_crypto_engine_op_t;

typedef struct
{
  char *name;
  char *desc;
  int priority;
  vnet_crypto_engine_op_t ops[VNET_CRYPTO_N_OP_IDS];
  vnet_crypto_key_fn_t *key_op_handler;
  vnet_crypto_frame_dequeue_t *dequeue_handler;
} vnet_crypto_engine_t;

typedef struct
{
  u32 node_idx;
  u32 next_idx;
} vnet_crypto_async_next_node_t;

typedef struct
{
  vnet_crypto_op_type_t type;
  vnet_crypto_alg_t alg;
  u8 active_engine_index[VNET_CRYPTO_HANDLER_N_TYPES];
  void *handlers[VNET_CRYPTO_HANDLER_N_TYPES];
} vnet_crypto_op_data_t;

typedef struct
{
  char *name;
  u8 is_disabled;
  u8 is_enabled;
} vnet_crypto_config_t;

typedef struct
{
  vnet_crypto_key_t **keys;
  u8 keys_lock;
  u32 crypto_node_index;
  vnet_crypto_thread_t *threads;
  vnet_crypto_frame_dequeue_t **dequeue_handlers;
  vnet_crypto_engine_t *engines;
  /* configs and hash by name */
  vnet_crypto_config_t *configs;
  uword *config_index_by_name;
  uword *engine_index_by_name;
  uword *alg_index_by_name;
  vnet_crypto_async_next_node_t *next_nodes;
  vnet_crypto_alg_data_t algs[VNET_CRYPTO_N_ALGS];
  vnet_crypto_op_data_t opt_data[VNET_CRYPTO_N_OP_IDS];
  u8 default_disabled;
} vnet_crypto_main_t;

extern vnet_crypto_main_t crypto_main;

u32 vnet_crypto_process_chained_ops (vlib_main_t * vm, vnet_crypto_op_t ops[],
				     vnet_crypto_op_chunk_t * chunks,
				     u32 n_ops);
u32 vnet_crypto_process_ops (vlib_main_t * vm, vnet_crypto_op_t ops[],
			     u32 n_ops);

void vnet_crypto_set_async_dispatch (u8 mode, u8 adaptive);

typedef struct
{
  char *handler_name;
  char *engine;
  u8 set_simple : 1;
  u8 set_chained : 1;
  u8 set_async : 1;
} vnet_crypto_set_handlers_args_t;

int vnet_crypto_set_handlers (vnet_crypto_set_handlers_args_t *);
int vnet_crypto_is_set_handler (vnet_crypto_alg_t alg);

u32 vnet_crypto_key_add (vlib_main_t * vm, vnet_crypto_alg_t alg,
			 u8 * data, u16 length);
void vnet_crypto_key_del (vlib_main_t * vm, vnet_crypto_key_index_t index);
void vnet_crypto_key_update (vlib_main_t *vm, vnet_crypto_key_index_t index);

/**
 * Use 2 created keys to generate new key for linked algs (cipher + integ)
 * The returned key index is to be used for linked alg only.
 **/
u32 vnet_crypto_key_add_linked (vlib_main_t * vm,
				vnet_crypto_key_index_t index_crypto,
				vnet_crypto_key_index_t index_integ);

vnet_crypto_alg_t vnet_crypto_link_algs (vnet_crypto_alg_t crypto_alg,
					 vnet_crypto_alg_t integ_alg);

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
  op->n_chunks = 0;
}

static_always_inline vnet_crypto_op_type_t
vnet_crypto_get_op_type (vnet_crypto_op_id_t id)
{
  vnet_crypto_main_t *cm = &crypto_main;
  ASSERT (id < VNET_CRYPTO_N_OP_IDS);
  vnet_crypto_op_data_t *od = cm->opt_data + id;
  return od->type;
}

static_always_inline vnet_crypto_key_t *
vnet_crypto_get_key (vnet_crypto_key_index_t index)
{
  vnet_crypto_main_t *cm = &crypto_main;
  return cm->keys[index];
}

/** async crypto inline functions **/

static_always_inline vnet_crypto_async_frame_t *
vnet_crypto_async_get_frame (vlib_main_t *vm, vnet_crypto_op_id_t opt)
{
  vnet_crypto_main_t *cm = &crypto_main;
  vnet_crypto_thread_t *ct = cm->threads + vm->thread_index;
  vnet_crypto_async_frame_t *f = NULL;

  if (PREDICT_TRUE (pool_free_elts (ct->frame_pool)))
    {
      pool_get_aligned (ct->frame_pool, f, CLIB_CACHE_LINE_BYTES);
#if CLIB_DEBUG > 0
      clib_memset (f, 0xfe, sizeof (*f));
#endif
      f->state = VNET_CRYPTO_FRAME_STATE_NOT_PROCESSED;
      f->op = opt;
      f->n_elts = 0;
    }

  return f;
}

static_always_inline void
vnet_crypto_async_free_frame (vlib_main_t * vm,
			      vnet_crypto_async_frame_t * frame)
{
  vnet_crypto_main_t *cm = &crypto_main;
  vnet_crypto_thread_t *ct = cm->threads + vm->thread_index;
  pool_put (ct->frame_pool, frame);
}

static_always_inline int
vnet_crypto_async_submit_open_frame (vlib_main_t * vm,
				     vnet_crypto_async_frame_t * frame)
{
  vnet_crypto_main_t *cm = &crypto_main;
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  vnet_crypto_op_id_t op = frame->op;
  vnet_crypto_frame_enq_fn_t *fn =
    cm->opt_data[op].handlers[VNET_CRYPTO_HANDLER_TYPE_ASYNC];
  u32 i;
  vlib_node_t *n;

  frame->state = VNET_CRYPTO_FRAME_STATE_PENDING;
  frame->enqueue_thread_index = vm->thread_index;

  if (PREDICT_FALSE (fn == 0))
    {
      frame->state = VNET_CRYPTO_FRAME_STATE_ELT_ERROR;
      return -1;
    }

  int ret = fn (vm, frame);

  if (PREDICT_TRUE (ret == 0))
    {
      n = vlib_get_node (vm, cm->crypto_node_index);
      if (n->state == VLIB_NODE_STATE_INTERRUPT)
	{
	  for (i = 0; i < tm->n_vlib_mains; i++)
	    vlib_node_set_interrupt_pending (vlib_get_main_by_index (i),
					     cm->crypto_node_index);
	}
    }
  else
    {
      frame->state = VNET_CRYPTO_FRAME_STATE_ELT_ERROR;
    }

  return ret;
}

static_always_inline void
vnet_crypto_async_add_to_frame (vlib_main_t *vm, vnet_crypto_async_frame_t *f,
				u32 key_index, u32 crypto_len,
				i16 integ_len_adj, i16 crypto_start_offset,
				i16 integ_start_offset, u32 buffer_index,
				u16 next_node, u8 *iv, u8 *tag, u8 *aad,
				u8 flags)
{
  vnet_crypto_async_frame_elt_t *fe;
  u16 index;

  ASSERT (f->n_elts < VNET_CRYPTO_FRAME_SIZE);

  index = f->n_elts;
  fe = &f->elts[index];
  f->n_elts++;
  fe->key_index = key_index;
  fe->crypto_total_length = crypto_len;
  fe->crypto_start_offset = crypto_start_offset;
  fe->integ_start_offset = integ_start_offset;
  fe->integ_length_adj = integ_len_adj;
  fe->iv = iv;
  fe->tag = tag;
  fe->aad = aad;
  fe->flags = flags;
  f->buffer_indices[index] = buffer_index;
  f->next_node_index[index] = next_node;
}

static_always_inline void
vnet_crypto_async_reset_frame (vnet_crypto_async_frame_t * f)
{
  vnet_crypto_op_id_t opt;
  ASSERT (f != 0);
  ASSERT ((f->state == VNET_CRYPTO_FRAME_STATE_NOT_PROCESSED
	   || f->state == VNET_CRYPTO_FRAME_STATE_ELT_ERROR));
  opt = f->op;
  if (CLIB_DEBUG > 0)
    clib_memset (f, 0xfe, sizeof (*f));
  f->state = VNET_CRYPTO_FRAME_STATE_NOT_PROCESSED;
  f->op = opt;
  f->n_elts = 0;
}

static_always_inline u8
vnet_crypto_async_frame_is_full (const vnet_crypto_async_frame_t *f)
{
  return (f->n_elts == VNET_CRYPTO_FRAME_SIZE);
}

#endif /* included_vnet_crypto_crypto_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
