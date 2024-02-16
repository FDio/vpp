/*
 * Copyright (c) 2024 Marvell.
 * SPDX-License-Identifier: Apache-2.0
 * https://spdx.org/licenses/Apache-2.0.html
 */

#ifndef _CRYPTO_H_
#define _CRYPTO_H_
#include <vnet/crypto/crypto.h>
#include <vnet/ip/ip.h>

/* CRYPTO_ID, KEY_LENGTH_IN_BYTES, TAG_LEN, AAD_LEN */
#define foreach_oct_crypto_aead_async_alg                                     \
  _ (AES_128_GCM, 16, 16, 8)                                                  \
  _ (AES_128_GCM, 16, 16, 12)                                                 \
  _ (AES_192_GCM, 24, 16, 8)                                                  \
  _ (AES_192_GCM, 24, 16, 12)                                                 \
  _ (AES_256_GCM, 32, 16, 8)                                                  \
  _ (AES_256_GCM, 32, 16, 12)

/* CRYPTO_ID, INTEG_ID, KEY_LENGTH_IN_BYTES, DIGEST_LEN */
#define foreach_oct_crypto_link_async_alg                                     \
  _ (AES_128_CBC, SHA1, 16, 12)                                               \
  _ (AES_192_CBC, SHA1, 24, 12)                                               \
  _ (AES_256_CBC, SHA1, 32, 12)                                               \
  _ (AES_128_CBC, SHA256, 16, 16)                                             \
  _ (AES_192_CBC, SHA256, 24, 16)                                             \
  _ (AES_256_CBC, SHA256, 32, 16)                                             \
  _ (AES_128_CBC, SHA384, 16, 24)                                             \
  _ (AES_192_CBC, SHA384, 24, 24)                                             \
  _ (AES_256_CBC, SHA384, 32, 24)                                             \
  _ (AES_128_CBC, SHA512, 16, 32)                                             \
  _ (AES_192_CBC, SHA512, 24, 32)                                             \
  _ (AES_256_CBC, SHA512, 32, 32)

#define OCT_MOD_INC(i, l) ((i) == (l - 1) ? (i) = 0 : (i)++)

#define OCT_SCATTER_GATHER_BUFFER_SIZE		1024
#define OCT_CRYPTO_DEFAULT_SW_ASYNC_FRAME_COUNT 256

#define CPT_LMT_SIZE_COPY (sizeof (struct cpt_inst_s) / 16)
#define OCT_MAX_LMT_SZ	  16

#define SRC_IOV_SIZE                                                          \
  (sizeof (struct roc_se_iov_ptr) +                                           \
   (sizeof (struct roc_se_buf_ptr) * ROC_MAX_SG_CNT))

#define OCT_CPT_LMT_GET_LINE_ADDR(lmt_addr, lmt_num)                          \
  (void *) ((u64) (lmt_addr) + ((u64) (lmt_num) << ROC_LMT_LINE_SIZE_LOG2))

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  struct roc_cpt *roc_cpt;
  struct roc_cpt_lmtline lmtline;
  struct roc_cpt_lf lf;
  vnet_dev_t *dev;
} oct_crypto_dev_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  u16 cpt_op : 4;
  u16 aes_gcm : 1;
  u8 iv_length;
  u8 auth_iv_length;
  u16 iv_offset;
  u16 auth_iv_offset;
  u64 cpt_inst_w7;

  oct_crypto_dev_t *crypto_dev;
  struct roc_se_ctx cpt_ctx;
} oct_crypto_sess_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  oct_crypto_sess_t *sess;
  oct_crypto_dev_t *crypto_dev;
} oct_crypto_key_t;

typedef struct oct_crypto_scatter_gather
{
  u8 buf[OCT_SCATTER_GATHER_BUFFER_SIZE];
} oct_crypto_scatter_gather_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  volatile union cpt_res_s res[VNET_CRYPTO_FRAME_SIZE];
  void *sg_data;
  vnet_crypto_async_frame_t *frame;
  u16 elts;
  u16 deq_elts;
} oct_crypto_inflight_req_t;

typedef struct
{
  oct_crypto_inflight_req_t *req_queue;
  u32 n_crypto_inflight;
  u16 enq_tail;
  u16 deq_head;
  u16 n_desc;
} oct_crypto_pending_queue_t;

typedef struct
{
  oct_crypto_key_t *keys[VNET_CRYPTO_ASYNC_OP_N_TYPES];
  oct_crypto_pending_queue_t *pend_q;
} oct_crypto_t;

void oct_crypto_key_del_handler (vlib_main_t *vm,
				 vnet_crypto_key_index_t key_index);

void oct_crypto_key_add_handler (vlib_main_t *vm,
				 vnet_crypto_key_index_t key_index);

void oct_crypto_key_handler (vlib_main_t *vm, vnet_crypto_key_op_t kop,
			     vnet_crypto_key_index_t idx);

int oct_crypto_enqueue_linked_alg_enc (vlib_main_t *vm,
				       vnet_crypto_async_frame_t *frame);
int oct_crypto_enqueue_linked_alg_dec (vlib_main_t *vm,
				       vnet_crypto_async_frame_t *frame);
int oct_crypto_enqueue_aead_aad_enc (vlib_main_t *vm,
				     vnet_crypto_async_frame_t *frame,
				     u8 aad_len);
int oct_crypto_enqueue_aead_aad_dec (vlib_main_t *vm,
				     vnet_crypto_async_frame_t *frame,
				     u8 aad_len);
int oct_crypto_enqueue_aead_aad_8_enc (vlib_main_t *vm,
				       vnet_crypto_async_frame_t *frame);
int oct_crypto_enqueue_aead_aad_12_enc (vlib_main_t *vm,
					vnet_crypto_async_frame_t *frame);
int oct_crypto_enqueue_aead_aad_8_dec (vlib_main_t *vm,
				       vnet_crypto_async_frame_t *frame);
int oct_crypto_enqueue_aead_aad_12_dec (vlib_main_t *vm,
					vnet_crypto_async_frame_t *frame);
vnet_crypto_async_frame_t *oct_crypto_frame_dequeue (vlib_main_t *vm,
						     u32 *nb_elts_processed,
						     u32 *enqueue_thread_idx);
int oct_init_crypto_engine_handlers (vlib_main_t *vm, vnet_dev_t *dev);
int oct_conf_sw_queue (vlib_main_t *vm, vnet_dev_t *dev);
#endif /* _CRYPTO_H_ */
