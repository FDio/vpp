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

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#include <vlib/vlib.h>
#include <vnet/plugin/plugin.h>
#include <vnet/crypto/crypto.h>
#include <vpp/app/version.h>

#define CRYPTO_OPENSSL_RING_SIZE 512
#define CRYPTO_OPENSSL_RING_MASK (CRYPTO_OPENSSL_RING_SIZE - 1)

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  u64 head;
  u64 tail;
  u32 size;
  vnet_crypto_op_id_t op:8;
  vnet_crypto_op_t *jobs[0];
} openssl_queue_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  EVP_CIPHER_CTX *evp_cipher_ctx;
  HMAC_CTX *hmac_ctx;
#if OPENSSL_VERSION_NUMBER < 0x10100000L
  HMAC_CTX _hmac_ctx;
#endif
  clib_bitmap_t *act_queues;
  openssl_queue_t *queues[VNET_CRYPTO_N_OP_IDS];
} openssl_per_thread_data_t;

static openssl_per_thread_data_t *per_thread_data = 0;

#define foreach_openssl_evp_op \
  _(cbc, DES_CBC, EVP_des_cbc) \
  _(cbc, 3DES_CBC, EVP_des_ede3_cbc) \
  _(cbc, AES_128_CBC, EVP_aes_128_cbc) \
  _(cbc, AES_192_CBC, EVP_aes_192_cbc) \
  _(cbc, AES_256_CBC, EVP_aes_256_cbc) \
  _(gcm, AES_128_GCM, EVP_aes_128_gcm) \
  _(gcm, AES_192_GCM, EVP_aes_192_gcm) \
  _(gcm, AES_256_GCM, EVP_aes_256_gcm) \
  _(cbc, AES_128_CTR, EVP_aes_128_ctr) \
  _(cbc, AES_192_CTR, EVP_aes_192_ctr) \
  _(cbc, AES_256_CTR, EVP_aes_256_ctr) \

#define foreach_openssl_hmac_op \
  _(MD5, EVP_md5) \
  _(SHA1, EVP_sha1) \
  _(SHA224, EVP_sha224) \
  _(SHA256, EVP_sha256) \
  _(SHA384, EVP_sha384) \
  _(SHA512, EVP_sha512)

static_always_inline vnet_crypto_op_t *
openssl_alloc_job (vlib_main_t * vm, vnet_crypto_op_id_t op_id)
{
  vnet_crypto_op_t *j = clib_mem_alloc_aligned (sizeof (j[0]),
						CLIB_CACHE_LINE_BYTES);
  if (PREDICT_FALSE (j == 0))
    return 0;

  vnet_crypto_op_init (j, op_id);
  j->flags = VNET_CRYPTO_OP_FLAG_ASYNC;
  return j;
}

static_always_inline void
openssl_free_job (vlib_main_t * vm, vnet_crypto_op_t *j)
{
  clib_mem_free (j);
}

static_always_inline u32
openssl_enqueue_ops (vlib_main_t * vm, vnet_crypto_op_id_t opt,
			   vnet_crypto_op_t * jobs[], u32 n_jobs)
{
  openssl_per_thread_data_t *ptd = vec_elt_at_index (per_thread_data,
						     vm->thread_index);
  openssl_queue_t *q = ptd->queues[opt];
  u32 n_enq = 0;
  u64 head = q->head;

  while (n_enq < n_jobs)
    {
      vnet_crypto_op_t *j = jobs[n_enq];

      /* job is not taken from the queue if pointer is still set */
      if (q->jobs[head & CRYPTO_OPENSSL_RING_MASK])
	break;

      q->jobs[head & CRYPTO_OPENSSL_RING_MASK] = j;
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

static_always_inline u32
openssl_get_pending_jobs (openssl_queue_t * q, vnet_crypto_op_t * jobs[],
			        u32 n_jobs)
{
  u32 i;
  vnet_crypto_op_t *j;
  u32 tail = q->tail;
  u32 head = q->head;
  u32 n_got = 0;

  for (i = tail; i < head; i++)
    {
      j = q->jobs[i & CRYPTO_OPENSSL_RING_MASK];
      if (!j)
	continue;

      if (clib_atomic_bool_cmp_and_swap (&j->sta,
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

static_always_inline u32
openssl_dequeue_ops (vlib_main_t * vm, vnet_crypto_op_id_t opt,
		     vnet_crypto_op_t * jobs[], u32 n_jobs,
		     vnet_crypto_ops_handler_t *f)
{
  openssl_per_thread_data_t *ptd;
  openssl_queue_t * q;
  u64 head;
  u32 n_total = 0;
  u32 i;

  /* *INDENT-OFF* */
  vec_foreach_index (i, per_thread_data)
  {
    ptd = per_thread_data + i;
    q = ptd->queues[opt];
    if (q->head != q->tail)
      n_total += openssl_get_pending_jobs (q, jobs + n_total,
						 n_jobs - n_total);
    if (n_total == n_jobs)
      break;
  }
  /* *INDENT-ON* */

  if (n_total)
    (f) (vm, jobs, n_total);

  ptd = per_thread_data + vm->thread_index;
  q = ptd->queues[opt];
  head = q->head;
  n_total = 0;

  while (1)
    {
      u32 tail = clib_atomic_load_acq_n (&q->tail);
      vnet_crypto_op_t *job = q->jobs[tail & CRYPTO_OPENSSL_RING_MASK];

      if (head == tail)
	{
	  clib_bitmap_set_no_check (ptd->act_queues, opt, 0);
	  break;
	}

      if (job->status == VNET_CRYPTO_OP_STATUS_COMPLETED)
	{
	  q->jobs[tail & CRYPTO_OPENSSL_RING_MASK] = 0;
	  clib_atomic_fetch_add (&q->tail, 1);
	  jobs[n_total++] = job;
	}

      if (n_total == n_jobs)
	break;
    }

  return n_total;
}

static_always_inline u32
openssl_ops_enc_cbc (vlib_main_t * vm, vnet_crypto_op_t * ops[], u32 n_ops,
		     const EVP_CIPHER * cipher)
{
  openssl_per_thread_data_t *ptd = vec_elt_at_index (per_thread_data,
						     vm->thread_index);
  EVP_CIPHER_CTX *ctx = ptd->evp_cipher_ctx;
  u32 i;
  for (i = 0; i < n_ops; i++)
    {
      vnet_crypto_op_t *op = ops[i];
      vnet_crypto_key_t *key = vnet_crypto_get_key (op->key_index);
      int out_len;
      int iv_len;

      if (op->op == VNET_CRYPTO_OP_3DES_CBC_ENC)
	iv_len = 8;
      else
	iv_len = 16;

      if (op->flags & VNET_CRYPTO_OP_FLAG_INIT_IV)
	RAND_bytes (op->iv, iv_len);

      EVP_EncryptInit_ex (ctx, cipher, NULL, key->data, op->iv);
      EVP_EncryptUpdate (ctx, op->dst, &out_len, op->src, op->len);
      if (out_len < op->len)
	EVP_EncryptFinal_ex (ctx, op->dst + out_len, &out_len);
      op->status = VNET_CRYPTO_OP_STATUS_COMPLETED;
    }
  return n_ops;
}

static_always_inline u32
openssl_ops_dec_cbc (vlib_main_t * vm, vnet_crypto_op_t * ops[], u32 n_ops,
		     const EVP_CIPHER * cipher)
{
  openssl_per_thread_data_t *ptd = vec_elt_at_index (per_thread_data,
						     vm->thread_index);
  EVP_CIPHER_CTX *ctx = ptd->evp_cipher_ctx;
  u32 i;
  for (i = 0; i < n_ops; i++)
    {
      vnet_crypto_op_t *op = ops[i];
      vnet_crypto_key_t *key = vnet_crypto_get_key (op->key_index);
      int out_len;

      EVP_DecryptInit_ex (ctx, cipher, NULL, key->data, op->iv);
      EVP_DecryptUpdate (ctx, op->dst, &out_len, op->src, op->len);
      if (out_len < op->len)
	EVP_DecryptFinal_ex (ctx, op->dst + out_len, &out_len);
      op->status = VNET_CRYPTO_OP_STATUS_COMPLETED;
    }
  return n_ops;
}

static_always_inline u32
openssl_ops_enc_gcm (vlib_main_t * vm, vnet_crypto_op_t * ops[], u32 n_ops,
		     const EVP_CIPHER * cipher)
{
  openssl_per_thread_data_t *ptd = vec_elt_at_index (per_thread_data,
						     vm->thread_index);
  EVP_CIPHER_CTX *ctx = ptd->evp_cipher_ctx;
  u32 i;
  for (i = 0; i < n_ops; i++)
    {
      vnet_crypto_op_t *op = ops[i];
      vnet_crypto_key_t *key = vnet_crypto_get_key (op->key_index);
      int len;

      if (op->flags & VNET_CRYPTO_OP_FLAG_INIT_IV)
	RAND_bytes (op->iv, 8);

      EVP_EncryptInit_ex (ctx, cipher, 0, 0, 0);
      EVP_CIPHER_CTX_ctrl (ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL);
      EVP_EncryptInit_ex (ctx, 0, 0, key->data, op->iv);
      if (op->aad_len)
	EVP_EncryptUpdate (ctx, NULL, &len, op->aad, op->aad_len);
      EVP_EncryptUpdate (ctx, op->dst, &len, op->src, op->len);
      EVP_EncryptFinal_ex (ctx, op->dst + len, &len);
      EVP_CIPHER_CTX_ctrl (ctx, EVP_CTRL_GCM_GET_TAG, op->tag_len, op->tag);
      op->status = VNET_CRYPTO_OP_STATUS_COMPLETED;
    }
  return n_ops;
}

static_always_inline u32
openssl_ops_dec_gcm (vlib_main_t * vm, vnet_crypto_op_t * ops[], u32 n_ops,
		     const EVP_CIPHER * cipher)
{
  openssl_per_thread_data_t *ptd = vec_elt_at_index (per_thread_data,
						     vm->thread_index);
  EVP_CIPHER_CTX *ctx = ptd->evp_cipher_ctx;
  u32 i, n_fail = 0;
  for (i = 0; i < n_ops; i++)
    {
      vnet_crypto_op_t *op = ops[i];
      vnet_crypto_key_t *key = vnet_crypto_get_key (op->key_index);
      int len;

      EVP_DecryptInit_ex (ctx, cipher, 0, 0, 0);
      EVP_CIPHER_CTX_ctrl (ctx, EVP_CTRL_GCM_SET_IVLEN, 12, 0);
      EVP_DecryptInit_ex (ctx, 0, 0, key->data, op->iv);
      if (op->aad_len)
	EVP_DecryptUpdate (ctx, 0, &len, op->aad, op->aad_len);
      EVP_DecryptUpdate (ctx, op->dst, &len, op->src, op->len);
      EVP_CIPHER_CTX_ctrl (ctx, EVP_CTRL_GCM_SET_TAG, op->tag_len, op->tag);

      if (EVP_DecryptFinal_ex (ctx, op->dst + len, &len) > 0)
	op->status = VNET_CRYPTO_OP_STATUS_COMPLETED;
      else
	{
	  n_fail++;
	  op->status = VNET_CRYPTO_OP_STATUS_FAIL_BAD_HMAC;
	}
    }
  return n_ops - n_fail;
}

static_always_inline u32
openssl_ops_hmac (vlib_main_t * vm, vnet_crypto_op_t * ops[], u32 n_ops,
		  const EVP_MD * md)
{
  u8 buffer[64];
  openssl_per_thread_data_t *ptd = vec_elt_at_index (per_thread_data,
						     vm->thread_index);
  HMAC_CTX *ctx = ptd->hmac_ctx;
  u32 i, n_fail = 0;
  for (i = 0; i < n_ops; i++)
    {
      vnet_crypto_op_t *op = ops[i];
      vnet_crypto_key_t *key = vnet_crypto_get_key (op->key_index);
      unsigned int out_len;
      size_t sz = op->digest_len ? op->digest_len : EVP_MD_size (md);

      HMAC_Init_ex (ctx, key->data, vec_len (key->data), md, NULL);
      HMAC_Update (ctx, op->src, op->len);
      HMAC_Final (ctx, buffer, &out_len);

      if (op->flags & VNET_CRYPTO_OP_FLAG_HMAC_CHECK)
	{
	  if ((memcmp (op->digest, buffer, sz)))
	    {
	      n_fail++;
	      op->status = VNET_CRYPTO_OP_STATUS_FAIL_BAD_HMAC;
	      continue;
	    }
	}
      else
	clib_memcpy_fast (op->digest, buffer, sz);
      op->status = VNET_CRYPTO_OP_STATUS_COMPLETED;
    }
  return n_ops - n_fail;
}

#define _(m, a, b) \
static u32 \
openssl_ops_enc_##a (vlib_main_t * vm, vnet_crypto_op_t * ops[], u32 n_ops) \
{ return openssl_ops_enc_##m (vm, ops, n_ops, b ()); } \
\
u32 \
openssl_ops_dec_##a (vlib_main_t * vm, vnet_crypto_op_t * ops[], u32 n_ops) \
{ return openssl_ops_dec_##m (vm, ops, n_ops, b ()); } \
\
u32 \
openssl_enq_enc_##a (vlib_main_t *vm, vnet_crypto_op_t * jobs[], u32 n_jobs) \
{ return openssl_enqueue_ops (vm, VNET_CRYPTO_OP_##a##_ENC, jobs, n_jobs); } \
\
u32 \
openssl_enq_dec_##a (vlib_main_t *vm, vnet_crypto_op_t * jobs[], u32 n_jobs) \
{ return openssl_enqueue_ops (vm, VNET_CRYPTO_OP_##a##_DEC, jobs, n_jobs); } \
\
u32 \
openssl_deq_enc_##a (vlib_main_t *vm, vnet_crypto_op_t * jobs[], u32 n_jobs) \
{ return openssl_dequeue_ops (vm, VNET_CRYPTO_OP_##a##_ENC, jobs, n_jobs, \
			      openssl_ops_enc_##a); } \
\
u32 \
openssl_deq_dec_##a (vlib_main_t *vm, vnet_crypto_op_t * jobs[], u32 n_jobs) \
{ return openssl_dequeue_ops (vm, VNET_CRYPTO_OP_##a##_ENC, jobs, n_jobs, \
			      openssl_ops_dec_##a); }

foreach_openssl_evp_op;
#undef _

#define _(a, b) \
static u32 \
openssl_ops_hmac_##a (vlib_main_t * vm, vnet_crypto_op_t * ops[], u32 n_ops) \
{ return openssl_ops_hmac (vm, ops, n_ops, b ()); } \
\
u32 \
openssl_enq_hmac_##a (vlib_main_t *vm, vnet_crypto_op_t * jobs[], u32 n_jobs) \
{ return openssl_enqueue_ops (vm, VNET_CRYPTO_OP_##a##_HMAC, jobs, n_jobs); } \
\
u32 \
openssl_deq_hmac_##a (vlib_main_t *vm, vnet_crypto_op_t * jobs[], u32 n_jobs) \
{ return openssl_dequeue_ops (vm, VNET_CRYPTO_OP_##a##_HMAC, jobs, n_jobs, \
			      openssl_ops_hmac_##a); }

foreach_openssl_hmac_op;
#undef _


clib_error_t *
crypto_openssl_init (vlib_main_t * vm)
{
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  openssl_per_thread_data_t *ptd;
  u8 *seed_data = 0;
  time_t t;
  pid_t pid;

  u32 eidx = vnet_crypto_register_engine (vm, "openssl", 50, "OpenSSL");

  void vnet_crypto_register_async_handlers (vlib_main_t *vm, u32 engine_index,
					  vnet_crypto_op_id_t opt,
					  vnet_crypto_ops_handler_t * enqueue_oph,
					  vnet_crypto_ops_handler_t * dequeue_oph,
					  vnet_crypto_op_alloc_t * alloc_oph,
					  vnet_crypto_op_free_t * free_oph);
#define _(m, a, b) \
  vnet_crypto_register_ops_handler (vm, eidx, VNET_CRYPTO_OP_##a##_ENC, \
				    openssl_ops_enc_##a); \
  vnet_crypto_register_ops_handler (vm, eidx, VNET_CRYPTO_OP_##a##_DEC, \
				    openssl_ops_dec_##a); \
  vnet_crypto_register_async_handlers (vm, eidx, VNET_CRYPTO_OP_##a##_ENC, \
				       openssl_enq_enc_##a, \
				       openssl_deq_enc_##a, \
				       openssl_alloc_job, \
				       openssl_free_job); \
  vnet_crypto_register_async_handlers (vm, eidx, VNET_CRYPTO_OP_##a##_DEC, \
				       openssl_enq_dec_##a, \
				       openssl_deq_dec_##a, \
				       openssl_alloc_job, \
				       openssl_free_job);
  foreach_openssl_evp_op;
#undef _

#define _(a, b) \
  vnet_crypto_register_ops_handler (vm, eidx, VNET_CRYPTO_OP_##a##_HMAC, \
				    openssl_ops_hmac_##a); \
  vnet_crypto_register_async_handlers (vm, eidx, VNET_CRYPTO_OP_##a##_HMAC, \
				       openssl_enq_hmac_##a, \
				       openssl_deq_hmac_##a, \
				       openssl_alloc_job, \
				       openssl_free_job);

  foreach_openssl_hmac_op;
#undef _

  vec_validate_aligned (per_thread_data, tm->n_vlib_mains - 1,
			CLIB_CACHE_LINE_BYTES);

  u32 queue_size = CRYPTO_OPENSSL_RING_SIZE * sizeof (void *) +
      sizeof (openssl_queue_t);
  vec_foreach (ptd, per_thread_data)
  {
    u32 i;
    ptd->evp_cipher_ctx = EVP_CIPHER_CTX_new ();
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    ptd->hmac_ctx = HMAC_CTX_new ();
#else
    HMAC_CTX_init (&(ptd->_hmac_ctx));
    ptd->hmac_ctx = &ptd->_hmac_ctx;
#endif

    for (i = 0; i < VNET_CRYPTO_N_OP_IDS; i++)
      {
	openssl_queue_t *q = clib_mem_alloc_aligned (queue_size,
						     CLIB_CACHE_LINE_BYTES);
	ASSERT (q != 0);
	ptd->queues[i] = q;
	clib_memset_u8 (q, 0, queue_size);
	q->size = CRYPTO_OPENSSL_RING_SIZE;
	q->op = i;
      }
    clib_bitmap_vec_validate (ptd->act_queues, VNET_CRYPTO_N_OP_IDS);
  }

  t = time (NULL);
  pid = getpid ();
  vec_add (seed_data, &t, sizeof (t));
  vec_add (seed_data, &pid, sizeof (pid));
  vec_add (seed_data, seed_data, sizeof (seed_data));

  RAND_seed ((const void *) seed_data, vec_len (seed_data));

  vec_free (seed_data);

  return 0;
}

/* *INDENT-OFF* */
VLIB_INIT_FUNCTION (crypto_openssl_init) =
{
  .runs_after = VLIB_INITS ("vnet_crypto_init"),
};
/* *INDENT-ON* */


/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "OpenSSL Crypto Engine",
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
