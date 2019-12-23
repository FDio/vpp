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
#define VNET_CRYPTO_QUEUE_MASK (VNET_CRYPTO_RING_SIZE - 1)

#include <vlib/vlib.h>
#include <vnet/buffer.h>

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
  _(AES_256_GCM, "aes-256-gcm", 32)

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
  _(AVAILABLE, "available") \
  _(READY, "ready") \
  _(PENDING, "pending") \
  _(WORK_IN_PROGRESS, "work-in-progress") \
  _(COMPLETED, "completed") \
  _(FAIL_NO_HANDLER, "no-handler") \
  _(FAIL_BAD_HMAC, "bad-hmac") \
  _(ENGINE_ERR, "engine-error")

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

typedef struct
{
  u8 *data;
  vnet_crypto_alg_t alg:8;
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

typedef struct
{
  char *name;
  vnet_crypto_op_id_t op_by_type[VNET_CRYPTO_OP_N_TYPES];
} vnet_crypto_alg_data_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  vnet_crypto_op_id_t op:16;
  vnet_crypto_op_status_t status;
  u8 flags;
#define VNET_CRYPTO_OP_FLAG_INIT_IV (1 << 0)
#define VNET_CRYPTO_OP_FLAG_HMAC_CHECK (1 << 1)
  u32 key_index;
  u32 len;
  u16 aad_len;
  union
  {
    u8 digest_len;
    u8 tag_len;
  };
  u8 *iv;
  u8 *src;
  u8 *dst;
  u8 *aad;
  union
  {
    u8 *tag;
    u8 *digest;
  };
  uword user_data;
  /* for async mode */
  u32 bi;
  u16 next;
} vnet_crypto_op_t;

typedef struct
{
  vnet_crypto_op_type_t type;
  vnet_crypto_alg_t alg;
  u32 active_engine_index;
  u32 active_async_engine_index;
} vnet_crypto_op_data_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  u32 head;
  u32 tail;
  u32 last;
  u8 *ops_buf;
} vnet_crypto_queue_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  clib_bitmap_t *act_queues;
  vnet_crypto_queue_t *queues;
} vnet_crypto_thread_t;

typedef u32 vnet_crypto_key_index_t;

typedef u32 (vnet_crypto_queue_handler_t) (vlib_main_t * vm, u32 thread_idx,
					   vnet_crypto_queue_t * q);

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

void vnet_crypto_register_queue_handler (vlib_main_t * vm, u32 engine_index,
					 vnet_crypto_op_id_t opt,
					 vnet_crypto_queue_handler_t * qh);

/* register private data size for async crypto ops */
void vnet_crypto_async_register_op_priv_size (u32 priv_size);

typedef struct
{
  char *name;
  char *desc;
  int priority;
  vnet_crypto_key_handler_t *key_op_handler;
  vnet_crypto_ops_handler_t *ops_handlers[VNET_CRYPTO_N_OP_IDS];
  vnet_crypto_queue_handler_t *queue_handlers[VNET_CRYPTO_N_OP_IDS];
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
  vnet_crypto_op_data_t opt_data[VNET_CRYPTO_N_OP_IDS];
  vnet_crypto_engine_t *engines;
  vnet_crypto_key_t *keys;
  uword *engine_index_by_name;
  uword *alg_index_by_name;
  vnet_crypto_queue_handler_t **queue_handlers;
  int async_mode;
  vnet_crypto_async_next_node_t *next_nodes;
  u32 async_op_size;
} vnet_crypto_main_t;

u32 crypto_register_post_node (vlib_main_t * vm, char *post_node_name);

extern vnet_crypto_main_t crypto_main;

static_always_inline int
vnet_crypto_is_async_mode ()
{
  vnet_crypto_main_t *cm = &crypto_main;
  return cm->async_mode;
}

void vnet_crypto_async_mode_enable_disable (u8 is_enabled);

u32 vnet_crypto_process_ops (vlib_main_t * vm, vnet_crypto_op_t ops[],
			     u32 n_ops);

int vnet_crypto_set_handler (char *ops_handler_name, char *engine);
int vnet_crypto_is_set_handler (vnet_crypto_alg_t alg);

u32 vnet_crypto_key_add (vlib_main_t * vm, vnet_crypto_alg_t alg,
			 u8 * data, u16 length);
void vnet_crypto_key_del (vlib_main_t * vm, vnet_crypto_key_index_t index);

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
  op->status = VNET_CRYPTO_OP_STATUS_PENDING;
  op->op = type;
  op->flags = 0;
  op->key_index = ~0;
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


/* get an async op ptr from queue, used by crypto infra only */
static_always_inline vnet_crypto_op_t *
vnet_crypto_async_get_op (vnet_crypto_queue_t * q, u32 idx)
{
  vnet_crypto_main_t *cm = &crypto_main;

  return (vnet_crypto_op_t *) (q->ops_buf + idx * cm->async_op_size);
}

/* get async op private data, used by async op engine only */
static_always_inline void *
vnet_crypto_async_get_op_priv (vnet_crypto_op_t * op)
{
  return (void *) ((u8 *) op + sizeof (vnet_crypto_op_t));
}

/**
 * Get one not processed op from queue, mark its status as in_progress, and
 * return to the caller. Used by crypto engine only. If is possible to use
 * fast "thread unsafe" mode to avoid atomic operation. However this mode
 * should only be used when the crypto engine runs on the same lcore as
 * the worker who owns the queue.
 *
 * @param q:      the queue pointer.
 * @param atomic: 1 as using thread safe atomic operation, 0 as thread unsafe
 *                mode. Only set to 0 when crypto engine runs on the same lcore
 *                as the worker.
 * @return:       the pointer to a vnet_crypto_op_t data to be processed by the
 *                engine.
 **/
static_always_inline vnet_crypto_op_t *
vnet_crypto_async_get_pending_op (vnet_crypto_queue_t * q, u32 atomic)
{
  vnet_crypto_op_t *op;
  u32 head = q->head;
  u32 last;
  u32 i;

  if (atomic)
    {
      u32 tail;
      tail = clib_atomic_load_acq_n (&q->tail);
      for (i = tail; i < head; i++)
	{
	  op = vnet_crypto_async_get_op (q, i & VNET_CRYPTO_QUEUE_MASK);

	  if (clib_atomic_bool_cmp_and_swap (&op->status,
					     VNET_CRYPTO_OP_STATUS_PENDING,
					     VNET_CRYPTO_OP_STATUS_WORK_IN_PROGRESS))
	    {
	      return op;
	    }
	}

      return 0;
    }

  last = q->last;
  for (i = last; i < head; i++)
    {
      op = vnet_crypto_async_get_op (q, i & VNET_CRYPTO_QUEUE_MASK);

      if (op->status == VNET_CRYPTO_OP_STATUS_PENDING)
	{
	  op->status = VNET_CRYPTO_OP_STATUS_WORK_IN_PROGRESS;
	  q->last = i + 1;
	  return op;
	}
    }

  return 0;
}

/**
 * get an available op to be submit, only used by application who want to
 * use async crypto service.
 **/
static_always_inline vnet_crypto_op_t *
vnet_crypto_async_get_available_op (vlib_main_t * vm,
				    vnet_crypto_op_id_t op_id)
{
  vnet_crypto_main_t *cm = &crypto_main;
  vnet_crypto_thread_t *ct = vec_elt_at_index (cm->threads, vm->thread_index);
  vnet_crypto_queue_t *q = &ct->queues[op_id];
  vnet_crypto_op_t *op;

  CLIB_MEMORY_STORE_BARRIER ();
  clib_bitmap_set_no_check (ct->act_queues, op_id, 1);

  if (PREDICT_FALSE (q->ops_buf == 0))
    {
      clib_pmalloc_main_t *pm = vm->physmem_main.pmalloc_main;
      q->ops_buf = clib_pmalloc_alloc_aligned_on_numa (pm, cm->async_op_size *
						       VNET_CRYPTO_RING_SIZE,
						       CLIB_CACHE_LINE_BYTES,
						       vm->numa_node);
      if (q->ops_buf == 0)
	return 0;
      q->head = 0;
      q->tail = 0;
      q->last = 0;
    }

  op = vnet_crypto_async_get_op (q, q->head & VNET_CRYPTO_QUEUE_MASK);

  if (PREDICT_FALSE (op->status != VNET_CRYPTO_OP_STATUS_AVAILABLE))
    return 0;

  op->status = VNET_CRYPTO_OP_STATUS_READY;
  op->op = op_id;
  op->flags = 0;
  op->key_index = ~0;
  q->head++;
  return op;
}

/**
 * change op status to "pending" so the crypto engine will pick it up and
 * process.
 **/
static_always_inline void
vnet_crypto_async_submit_op (vnet_crypto_op_t * op)
{
  op->status = VNET_CRYPTO_OP_STATUS_PENDING;
}

#endif /* included_vnet_crypto_crypto_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
