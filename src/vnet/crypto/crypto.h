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

/* CRYPTO_ID, PRETTY_NAME, KEY_LENGTH_IN_BYTES */
#define foreach_crypto_cipher_alg \
  _(DES_CBC,     "des-cbc", 7) \
  _(3DES_CBC,    "3des-cbc", 24) \
  _(AES_128_CBC, "aes-128-cbc", 16) \
  _(AES_192_CBC, "aes-192-cbc", 24) \
  _(AES_256_CBC, "aes-256-cbc", 32) \
  _(AES_128_CTR, "aes-128-ctr", 16) \
  _(AES_192_CTR, "aes-192-ctr", 24) \
  _(AES_256_CTR, "aes-256-ctr", 32)

/* CRYPTO_ID, PRETTY_NAME, KEY_LENGTH_IN_BYTES */
#define foreach_crypto_aead_alg \
  _(AES_128_GCM, "aes-128-gcm", 16) \
  _(AES_192_GCM, "aes-192-gcm", 24) \
  _(AES_256_GCM, "aes-256-gcm", 32) \
  _(CHACHA20_POLY1305, "chacha20-poly1305", 32)

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
  _(IDLE, "idle") \
  _(PENDING, "pending") \
  _(WORK_IN_PROGRESS, "work-in-progress") \
  _(COMPLETED, "completed") \
  _(FAIL_NO_HANDLER, "no-handler") \
  _(FAIL_BAD_HMAC, "bad-hmac") \
  _(FAIL_ENGINE_ERR, "engine-error")

/** async crypto **/

/* CRYPTO_ID, PRETTY_NAME, KEY_LENGTH_IN_BYTES, TAG_LEN, AAD_LEN */
#define foreach_crypto_aead_async_alg \
  _(AES_128_GCM, "aes-128-gcm-aad8", 16, 16, 8) \
  _(AES_128_GCM, "aes-128-gcm-aad12", 16, 16, 12) \
  _(AES_192_GCM, "aes-192-gcm-aad8", 24, 16, 8) \
  _(AES_192_GCM, "aes-192-gcm-aad12", 24, 16, 12) \
  _(AES_256_GCM, "aes-256-gcm-aad8", 32, 16, 8) \
  _(AES_256_GCM, "aes-256-gcm-aad12", 32, 16, 12) \
  _(CHACHA20_POLY1305, "chacha20-poly1305-aad8", 32, 16, 8) \
  _(CHACHA20_POLY1305, "chacha20-poly1305-aad12", 32, 16, 12)

/* CRYPTO_ID, INTEG_ID, PRETTY_NAME, KEY_LENGTH_IN_BYTES, DIGEST_LEN */
#define foreach_crypto_link_async_alg \
  _ (AES_128_CBC, SHA1, "aes-128-cbc-hmac-sha-1", 16, 12) \
  _ (AES_192_CBC, SHA1, "aes-192-cbc-hmac-sha-1", 24, 12) \
  _ (AES_256_CBC, SHA1, "aes-256-cbc-hmac-sha-1", 32, 12) \
  _ (AES_128_CBC, SHA224, "aes-128-cbc-hmac-sha-224", 16, 14) \
  _ (AES_192_CBC, SHA224, "aes-192-cbc-hmac-sha-224", 24, 14) \
  _ (AES_256_CBC, SHA224, "aes-256-cbc-hmac-sha-224", 32, 14) \
  _ (AES_128_CBC, SHA256, "aes-128-cbc-hmac-sha-256", 16, 16) \
  _ (AES_192_CBC, SHA256, "aes-192-cbc-hmac-sha-256", 24, 16) \
  _ (AES_256_CBC, SHA256, "aes-256-cbc-hmac-sha-256", 32, 16) \
  _ (AES_128_CBC, SHA384, "aes-128-cbc-hmac-sha-384", 16, 24) \
  _ (AES_192_CBC, SHA384, "aes-192-cbc-hmac-sha-384", 24, 24) \
  _ (AES_256_CBC, SHA384, "aes-256-cbc-hmac-sha-384", 32, 24) \
  _ (AES_128_CBC, SHA512, "aes-128-cbc-hmac-sha-512", 16, 32) \
  _ (AES_192_CBC, SHA512, "aes-192-cbc-hmac-sha-512", 24, 32) \
  _ (AES_256_CBC, SHA512, "aes-256-cbc-hmac-sha-512", 32, 32)

#define foreach_crypto_async_op_type \
  _(ENCRYPT, "async-encrypt") \
  _(DECRYPT, "async-decrypt")

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
#define _(n, s, l) VNET_CRYPTO_ALG_##n,
  foreach_crypto_cipher_alg
  foreach_crypto_aead_alg
#undef _
#define _(n, s) VNET_CRYPTO_ALG_HMAC_##n,
  foreach_crypto_hmac_alg
#undef _
  VNET_CRYPTO_N_ALGS,
} vnet_crypto_alg_t;

typedef enum
{
#define _(n, s) VNET_CRYPTO_ASYNC_OP_TYPE_##n,
  foreach_crypto_async_op_type
#undef _
    VNET_CRYPTO_ASYNC_OP_N_TYPES,
} vnet_crypto_async_op_type_t;

typedef enum
{
  VNET_CRYPTO_ASYNC_ALG_NONE = 0,
#define _(n, s, k, t, a) \
  VNET_CRYPTO_ALG_##n##_TAG##t##_AAD##a,
  foreach_crypto_aead_async_alg
#undef _
#define _(c, h, s, k ,d) \
  VNET_CRYPTO_ALG_##c##_##h##_TAG##d,
  foreach_crypto_link_async_alg
#undef _
  VNET_CRYPTO_N_ASYNC_ALGS,
} vnet_crypto_async_alg_t;

typedef enum
{
  VNET_CRYPTO_ASYNC_OP_NONE = 0,
#define _(n, s, k, t, a) \
  VNET_CRYPTO_OP_##n##_TAG##t##_AAD##a##_ENC, \
  VNET_CRYPTO_OP_##n##_TAG##t##_AAD##a##_DEC,
  foreach_crypto_aead_async_alg
#undef _
#define _(c, h, s, k ,d) \
  VNET_CRYPTO_OP_##c##_##h##_TAG##d##_ENC, \
  VNET_CRYPTO_OP_##c##_##h##_TAG##d##_DEC,
  foreach_crypto_link_async_alg
#undef _
  VNET_CRYPTO_ASYNC_OP_N_IDS,
} vnet_crypto_async_op_id_t;

typedef struct
{
  union
  {
    struct
    {
      u8 *data;
      vnet_crypto_alg_t alg:8;
    };
    struct
    {
      u32 index_crypto;
      u32 index_integ;
      vnet_crypto_async_alg_t async_alg:8;
    };
  };
#define VNET_CRYPTO_KEY_TYPE_DATA 0
#define VNET_CRYPTO_KEY_TYPE_LINK 1
  u8 type;
} vnet_crypto_key_t;

typedef enum
{
  VNET_CRYPTO_OP_NONE = 0,
#define _(n, s, l) VNET_CRYPTO_OP_##n##_ENC, VNET_CRYPTO_OP_##n##_DEC,
  foreach_crypto_cipher_alg
  foreach_crypto_aead_alg
#undef _
#define _(n, s) VNET_CRYPTO_OP_##n##_HMAC,
 foreach_crypto_hmac_alg
#undef _
    VNET_CRYPTO_N_OP_IDS,
} vnet_crypto_op_id_t;
/* *INDENT-ON* */

typedef enum
{
  CRYPTO_OP_SIMPLE,
  CRYPTO_OP_CHAINED,
  CRYPTO_OP_BOTH,
} crypto_op_class_type_t;

typedef struct
{
  char *name;
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
  vnet_crypto_op_id_t op:16;
  vnet_crypto_op_status_t status:8;
  u8 flags;
#define VNET_CRYPTO_OP_FLAG_INIT_IV (1 << 0)
#define VNET_CRYPTO_OP_FLAG_HMAC_CHECK (1 << 1)
#define VNET_CRYPTO_OP_FLAG_CHAINED_BUFFERS (1 << 2)

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

typedef struct
{
  vnet_crypto_op_type_t type;
  vnet_crypto_alg_t alg;
  u32 active_engine_index_simple;
  u32 active_engine_index_chained;
} vnet_crypto_op_data_t;

typedef struct
{
  vnet_crypto_async_op_type_t type;
  vnet_crypto_async_alg_t alg;
  u32 active_engine_index_async;
} vnet_crypto_async_op_data_t;

typedef struct
{
  char *name;
  vnet_crypto_async_op_id_t op_by_type[VNET_CRYPTO_ASYNC_OP_N_TYPES];
} vnet_crypto_async_alg_data_t;

typedef struct
{
  vnet_crypto_op_status_t status:8;
  u32 key_index;
  i16 crypto_start_offset;	/* first buffer offset */
  i16 integ_start_offset;
  u32 crypto_total_length;
  /* adj total_length for integ, e.g.4 bytes for IPSec ESN */
  u16 integ_length_adj;
  u8 *iv;
  union
  {
    u8 *digest;
    u8 *tag;
  };
  u8 *aad;
  u8 flags; /**< share same VNET_CRYPTO_OP_FLAG_* values */
} vnet_crypto_async_frame_elt_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
#define VNET_CRYPTO_FRAME_STATE_NOT_PROCESSED 0
#define VNET_CRYPTO_FRAME_STATE_PENDING 1	/* frame waiting to be processed */
#define VNET_CRYPTO_FRAME_STATE_WORK_IN_PROGRESS 2
#define VNET_CRYPTO_FRAME_STATE_SUCCESS 3
#define VNET_CRYPTO_FRAME_STATE_ELT_ERROR 4
  u8 state;
  vnet_crypto_async_op_id_t op:8;
  u16 n_elts;
  vnet_crypto_async_frame_elt_t elts[VNET_CRYPTO_FRAME_SIZE];
  u32 buffer_indices[VNET_CRYPTO_FRAME_SIZE];
  u16 next_node_index[VNET_CRYPTO_FRAME_SIZE];
  u32 enqueue_thread_index;
} vnet_crypto_async_frame_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  vnet_crypto_async_frame_t *frames[VNET_CRYPTO_ASYNC_OP_N_IDS];
  vnet_crypto_async_frame_t *frame_pool;
  u32 *buffer_indice;
  u16 *nexts;
} vnet_crypto_thread_t;

typedef u32 vnet_crypto_key_index_t;

typedef u32 (vnet_crypto_chained_ops_handler_t) (vlib_main_t * vm,
						 vnet_crypto_op_t * ops[],
						 vnet_crypto_op_chunk_t *
						 chunks, u32 n_ops);

typedef u32 (vnet_crypto_ops_handler_t) (vlib_main_t * vm,
					 vnet_crypto_op_t * ops[], u32 n_ops);

typedef void (vnet_crypto_key_handler_t) (vlib_main_t * vm,
					  vnet_crypto_key_op_t kop,
					  vnet_crypto_key_index_t idx);

/** async crypto function handlers **/
typedef int
  (vnet_crypto_frame_enqueue_t) (vlib_main_t * vm,
				 vnet_crypto_async_frame_t * frame);
typedef vnet_crypto_async_frame_t *
  (vnet_crypto_frame_dequeue_t) (vlib_main_t * vm, u32 * nb_elts_processed,
				 u32 * enqueue_thread_idx);

u32
vnet_crypto_register_engine (vlib_main_t * vm, char *name, int prio,
			     char *desc);

void vnet_crypto_register_ops_handler (vlib_main_t * vm, u32 engine_index,
				       vnet_crypto_op_id_t opt,
				       vnet_crypto_ops_handler_t * oph);

void vnet_crypto_register_chained_ops_handler (vlib_main_t * vm,
					       u32 engine_index,
					       vnet_crypto_op_id_t opt,
					       vnet_crypto_chained_ops_handler_t
					       * oph);

void vnet_crypto_register_ops_handlers (vlib_main_t * vm, u32 engine_index,
					vnet_crypto_op_id_t opt,
					vnet_crypto_ops_handler_t * fn,
					vnet_crypto_chained_ops_handler_t *
					cfn);

void vnet_crypto_register_key_handler (vlib_main_t * vm, u32 engine_index,
				       vnet_crypto_key_handler_t * keyh);

/** async crypto register functions */
u32 vnet_crypto_register_post_node (vlib_main_t * vm, char *post_node_name);
void vnet_crypto_register_async_handler (vlib_main_t * vm,
					 u32 engine_index,
					 vnet_crypto_async_op_id_t opt,
					 vnet_crypto_frame_enqueue_t * enq_fn,
					 vnet_crypto_frame_dequeue_t *
					 deq_fn);

typedef struct
{
  char *name;
  char *desc;
  int priority;
  vnet_crypto_key_handler_t *key_op_handler;
  vnet_crypto_ops_handler_t *ops_handlers[VNET_CRYPTO_N_OP_IDS];
    vnet_crypto_chained_ops_handler_t
    * chained_ops_handlers[VNET_CRYPTO_N_OP_IDS];
  vnet_crypto_frame_enqueue_t *enqueue_handlers[VNET_CRYPTO_ASYNC_OP_N_IDS];
  vnet_crypto_frame_dequeue_t *dequeue_handlers[VNET_CRYPTO_ASYNC_OP_N_IDS];
} vnet_crypto_engine_t;

typedef struct
{
  u32 node_idx;
  u32 next_idx;
} vnet_crypto_async_next_node_t;

typedef struct
{
  vnet_crypto_alg_data_t *algs;
  vnet_crypto_thread_t *threads;
  vnet_crypto_ops_handler_t **ops_handlers;
  vnet_crypto_chained_ops_handler_t **chained_ops_handlers;
  vnet_crypto_frame_enqueue_t **enqueue_handlers;
  vnet_crypto_frame_dequeue_t **dequeue_handlers;
  clib_bitmap_t *async_active_ids;
  vnet_crypto_op_data_t opt_data[VNET_CRYPTO_N_OP_IDS];
  vnet_crypto_async_op_data_t async_opt_data[VNET_CRYPTO_ASYNC_OP_N_IDS];
  vnet_crypto_engine_t *engines;
  vnet_crypto_key_t *keys;
  uword *engine_index_by_name;
  uword *alg_index_by_name;
  uword *async_alg_index_by_name;
  vnet_crypto_async_alg_data_t *async_algs;
  u32 async_refcnt;
  vnet_crypto_async_next_node_t *next_nodes;
  u32 crypto_node_index;
#define VNET_CRYPTO_ASYNC_DISPATCH_POLLING 0
#define VNET_CRYPTO_ASYNC_DISPATCH_INTERRUPT 1
  u8 dispatch_mode;
} vnet_crypto_main_t;

extern vnet_crypto_main_t crypto_main;

u32 vnet_crypto_process_chained_ops (vlib_main_t * vm, vnet_crypto_op_t ops[],
				     vnet_crypto_op_chunk_t * chunks,
				     u32 n_ops);
u32 vnet_crypto_process_ops (vlib_main_t * vm, vnet_crypto_op_t ops[],
			     u32 n_ops);


int vnet_crypto_set_handler2 (char *ops_handler_name, char *engine,
			      crypto_op_class_type_t oct);
int vnet_crypto_is_set_handler (vnet_crypto_alg_t alg);

u32 vnet_crypto_key_add (vlib_main_t * vm, vnet_crypto_alg_t alg,
			 u8 * data, u16 length);
void vnet_crypto_key_del (vlib_main_t * vm, vnet_crypto_key_index_t index);

/**
 * Use 2 created keys to generate new key for linked algs (cipher + integ)
 * The returned key index is to be used for linked alg only.
 **/
u32 vnet_crypto_key_add_linked (vlib_main_t * vm,
				vnet_crypto_key_index_t index_crypto,
				vnet_crypto_key_index_t index_integ);

clib_error_t *crypto_dispatch_enable_disable (int is_enable);

int vnet_crypto_set_async_handler2 (char *alg_name, char *engine);

int vnet_crypto_is_set_async_handler (vnet_crypto_async_op_id_t opt);

void vnet_crypto_request_async_mode (int is_enable);

void vnet_crypto_set_async_dispatch_mode (u8 mode);

vnet_crypto_async_alg_t vnet_crypto_link_algs (vnet_crypto_alg_t crypto_alg,
					       vnet_crypto_alg_t integ_alg);

clib_error_t *crypto_dispatch_enable_disable (int is_enable);

format_function_t format_vnet_crypto_alg;
format_function_t format_vnet_crypto_engine;
format_function_t format_vnet_crypto_op;
format_function_t format_vnet_crypto_op_type;
format_function_t format_vnet_crypto_op_status;
unformat_function_t unformat_vnet_crypto_alg;

format_function_t format_vnet_crypto_async_op;
format_function_t format_vnet_crypto_async_alg;
format_function_t format_vnet_crypto_async_op_type;

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
  return vec_elt_at_index (cm->keys, index);
}

static_always_inline int
vnet_crypto_set_handler (char *alg_name, char *engine)
{
  return vnet_crypto_set_handler2 (alg_name, engine, CRYPTO_OP_BOTH);
}

/** async crypto inline functions **/

static_always_inline vnet_crypto_async_frame_t *
vnet_crypto_async_get_frame (vlib_main_t * vm, vnet_crypto_async_op_id_t opt)
{
  vnet_crypto_main_t *cm = &crypto_main;
  vnet_crypto_thread_t *ct = cm->threads + vm->thread_index;
  vnet_crypto_async_frame_t *f = ct->frames[opt];

  if (!f)
    {
      pool_get_aligned (ct->frame_pool, f, CLIB_CACHE_LINE_BYTES);
      if (CLIB_DEBUG > 0)
	clib_memset (f, 0xfe, sizeof (*f));
      f->state = VNET_CRYPTO_FRAME_STATE_NOT_PROCESSED;
      f->op = opt;
      f->n_elts = 0;
      ct->frames[opt] = f;
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
  vnet_crypto_thread_t *ct = cm->threads + vm->thread_index;
  vnet_crypto_async_op_id_t opt = frame->op;
  u32 i = vlib_num_workers () > 0;

  frame->state = VNET_CRYPTO_FRAME_STATE_PENDING;
  frame->enqueue_thread_index = vm->thread_index;

  int ret = (cm->enqueue_handlers[frame->op]) (vm, frame);

  clib_bitmap_set_no_check (cm->async_active_ids, opt, 1);
  if (PREDICT_TRUE (ret == 0))
    {
      vnet_crypto_async_frame_t *nf = 0;
      pool_get_aligned (ct->frame_pool, nf, CLIB_CACHE_LINE_BYTES);
      if (CLIB_DEBUG > 0)
	clib_memset (nf, 0xfe, sizeof (*nf));
      nf->state = VNET_CRYPTO_FRAME_STATE_NOT_PROCESSED;
      nf->op = opt;
      nf->n_elts = 0;
      ct->frames[opt] = nf;
    }
  else
    {
      frame->state = VNET_CRYPTO_FRAME_STATE_ELT_ERROR;
    }

  if (cm->dispatch_mode == VNET_CRYPTO_ASYNC_DISPATCH_INTERRUPT)
    {
      for (; i < tm->n_vlib_mains; i++)
	{
	  vlib_node_set_interrupt_pending (vlib_mains[i],
					   cm->crypto_node_index);
	}
    }
  return ret;
}

static_always_inline int
vnet_crypto_async_add_to_frame (vlib_main_t * vm,
				vnet_crypto_async_frame_t ** frame,
				u32 key_index,
				u32 crypto_len, i16 integ_len_adj,
				i16 crypto_start_offset,
				u16 integ_start_offset,
				u32 buffer_index,
				u16 next_node,
				u8 * iv, u8 * tag, u8 * aad, u8 flags)
{
  vnet_crypto_async_frame_t *f = *frame;
  vnet_crypto_async_frame_elt_t *fe;
  u16 index;

  if (PREDICT_FALSE (f->n_elts == VNET_CRYPTO_FRAME_SIZE))
    {
      vnet_crypto_async_op_id_t opt = f->op;
      int ret;
      ret = vnet_crypto_async_submit_open_frame (vm, f);
      if (PREDICT_FALSE (ret < 0))
	return -1;
      f = vnet_crypto_async_get_frame (vm, opt);
      *frame = f;
    }

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

  return 0;
}

static_always_inline void
vnet_crypto_async_reset_frame (vnet_crypto_async_frame_t * f)
{
  vnet_crypto_async_op_id_t opt;
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

#endif /* included_vnet_crypto_crypto_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
