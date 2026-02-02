/*
 * Copyright (c) 2024 Marvell.
 * SPDX-License-Identifier: Apache-2.0
 * https://spdx.org/licenses/Apache-2.0.html
 */

#ifndef _CRYPTO_H_
#define _CRYPTO_H_
#include <vnet/crypto/crypto.h>
#include <vnet/ip/ip.h>

#define OCT_MAX_N_CPT_DEV 2

#define OCT_CPT_LF_DEF_NB_DESC 16384

#define OCT_CPT_LF_MIN_NB_DESC 1024
#define OCT_CPT_LF_MAX_NB_DESC 128000

/* CRYPTO_ID, KEY_LENGTH_IN_BYTES, TAG_LEN, AAD_LEN */
#define foreach_oct_crypto_aead_async_alg                                     \
  _ (AES_128_GCM, 16, 16, 8)                                                  \
  _ (AES_128_GCM, 16, 16, 12)                                                 \
  _ (AES_192_GCM, 24, 16, 8)                                                  \
  _ (AES_192_GCM, 24, 16, 12)                                                 \
  _ (AES_256_GCM, 32, 16, 8)                                                  \
  _ (AES_256_GCM, 32, 16, 12)                                                 \
  _ (CHACHA20_POLY1305, 32, 16, 8)                                            \
  _ (CHACHA20_POLY1305, 32, 16, 12)                                           \
  _ (CHACHA20_POLY1305, 32, 16, 0)

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
  _ (AES_256_CBC, SHA512, 32, 32)                                             \
  _ (AES_128_CBC, MD5, 16, 12)                                                \
  _ (AES_192_CBC, MD5, 24, 12)                                                \
  _ (AES_256_CBC, MD5, 32, 12)                                                \
  _ (3DES_CBC, MD5, 24, 12)                                                   \
  _ (3DES_CBC, SHA1, 24, 12)                                                  \
  _ (3DES_CBC, SHA256, 24, 16)                                                \
  _ (3DES_CBC, SHA384, 24, 24)                                                \
  _ (3DES_CBC, SHA512, 24, 32)                                                \
  _ (AES_128_CTR, SHA1, 16, 12)                                               \
  _ (AES_192_CTR, SHA1, 24, 12)                                               \
  _ (AES_256_CTR, SHA1, 32, 12)                                               \
  _ (AES_128_CTR, SHA256, 16, 16)                                             \
  _ (AES_192_CTR, SHA256, 24, 16)                                             \
  _ (AES_256_CTR, SHA256, 32, 16)                                             \
  _ (AES_128_CTR, SHA384, 16, 24)                                             \
  _ (AES_192_CTR, SHA384, 24, 24)                                             \
  _ (AES_256_CTR, SHA384, 32, 24)                                             \
  _ (AES_128_CTR, SHA512, 16, 32)                                             \
  _ (AES_192_CTR, SHA512, 24, 32)                                             \
  _ (AES_256_CTR, SHA512, 32, 32)

#define OCT_MOD_INC(i, l) ((i) == (l - 1) ? (i) = 0 : (i)++)

#define OCT_SCATTER_GATHER_BUFFER_SIZE 1024

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
  u32 n_desc;
} oct_crypto_dev_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  /** CPT opcode */
  u16 cpt_op : 4;
  /** Flag for AES GCM */
  u16 aes_gcm : 1;
  /** IV length in bytes */
  u8 iv_length;
  /** Auth IV length in bytes */
  u8 auth_iv_length;
  /** IV offset in bytes */
  u16 iv_offset;
  /** Auth IV offset in bytes */
  u16 auth_iv_offset;
  /** CPT inst word 7 */
  u64 cpt_inst_w7;
  /* initialise as part of first packet */
  u8 initialised;
  /* store link key index in case of linked algo */
  vnet_crypto_key_index_t key_index;
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
  /** Result data */
  volatile union cpt_res_s res;
  /** Frame pointer */
  vnet_crypto_async_frame_t *frame;
  /** Async frame element */
  vnet_crypto_async_frame_elt_t *fe;
  /** AAD meta data */
  u8 aad[8];
  /** IV meta data */
  u8 iv[16];
  /** Digest len */
  u8 mac_len;
  /** aead */
  bool aead_algo;
  /** Set when encrypting linked algo with esn.
   * To move digest data */
  bool esn_enabled;
  /** Set if this is last element in frame */
  bool last_elts;
  /** Index of element in frame */
  int index;
} __plt_cache_aligned oct_crypto_inflight_req_t;

typedef struct
{
  /** Array of pending request */
  oct_crypto_inflight_req_t *req_queue;
  /** Number of inflight operations in queue */
  u32 n_crypto_inflight;
  /** Number of frames in queue */
  u32 n_crypto_frame;
  /** Tail of queue to be used for enqueue */
  u16 enq_tail;
  /** Head of queue to be used for dequeue */
  u16 deq_head;
  /** Number of descriptors */
  u16 n_desc;
  /** Scatter gather data */
  void *sg_data;
} oct_crypto_pending_queue_t;

typedef struct
{
  oct_crypto_dev_t *crypto_dev[OCT_MAX_N_CPT_DEV];
  oct_crypto_key_t *keys[VNET_CRYPTO_OP_N_TYPES];
  oct_crypto_pending_queue_t *pend_q;
  int n_cpt;
  u8 started;
} oct_crypto_main_t;

static_always_inline bool
oct_hw_ctx_cache_enable (void)
{
  return roc_errata_cpt_hang_on_mixed_ctx_val () ||
	 roc_model_is_cn10ka_b0 () || roc_model_is_cn10kb_a0 ();
}

extern oct_crypto_main_t oct_crypto_main;

void oct_crypto_key_del_handler (vlib_main_t *vm,
				 vnet_crypto_key_index_t key_index);

void oct_crypto_key_add_handler (vlib_main_t *vm,
				 vnet_crypto_key_index_t key_index);

void oct_crypto_key_handler (vnet_crypto_key_op_t kop, void *key_data, vnet_crypto_alg_t alg,
			     const u8 *data, u16 length);

int oct_crypto_enqueue_linked_alg_enc (vlib_main_t *vm,
				       vnet_crypto_async_frame_t *frame);
int oct_crypto_enqueue_linked_alg_dec (vlib_main_t *vm,
				       vnet_crypto_async_frame_t *frame);
int oct_crypto_enqueue_aead_aad_8_enc (vlib_main_t *vm,
				       vnet_crypto_async_frame_t *frame);
int oct_crypto_enqueue_aead_aad_12_enc (vlib_main_t *vm,
					vnet_crypto_async_frame_t *frame);
int oct_crypto_enqueue_aead_aad_0_enc (vlib_main_t *vm,
				       vnet_crypto_async_frame_t *frame);
int oct_crypto_enqueue_aead_aad_8_dec (vlib_main_t *vm,
				       vnet_crypto_async_frame_t *frame);
int oct_crypto_enqueue_aead_aad_12_dec (vlib_main_t *vm,
					vnet_crypto_async_frame_t *frame);
int oct_crypto_enqueue_aead_aad_0_dec (vlib_main_t *vm,
				       vnet_crypto_async_frame_t *frame);
vnet_crypto_async_frame_t *
oct_crypto_frame_dequeue (vlib_main_t *vm, u32 *nb_elts_processed,
			  clib_thread_index_t *enqueue_thread_idx);
int oct_init_crypto_engine_handlers (vlib_main_t *vm, vnet_dev_t *dev);
int oct_conf_sw_queue (vlib_main_t *vm, vnet_dev_t *dev,
		       oct_crypto_dev_t *ocd);
#endif /* _CRYPTO_H_ */
