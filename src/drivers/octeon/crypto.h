/*
 * Copyright (c) 2024 Marvell.
 * SPDX-License-Identifier: Apache-2.0
 * https://spdx.org/licenses/Apache-2.0.html
 * Copyright (c) 2026 Cisco and/or its affiliates.
 */

#ifndef _CRYPTO_H_
#define _CRYPTO_H_
#include <vnet/crypto/crypto.h>
#include <vnet/ip/ip.h>

#define OCT_MAX_N_CPT_DEV 2

#define OCT_CPT_LF_DEF_NB_DESC 16384

#define OCT_CPT_LF_MIN_NB_DESC 1024
#define OCT_CPT_LF_MAX_NB_DESC 128000

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
  vnet_crypto_op_id_t op_id;
  /* store key */
  vnet_crypto_key_t *key;
  oct_crypto_dev_t *crypto_dev;
  struct roc_se_ctx cpt_ctx;
} oct_crypto_sess_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  oct_crypto_sess_t *sess[VNET_CRYPTO_OP_N_TYPES];
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
  /** Set when encrypting combined algo with esn.
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

void oct_crypto_key_change_handler (vnet_crypto_key_t *key, vnet_crypto_key_change_args_t *args);
vnet_crypto_async_frame_t *
oct_crypto_frame_dequeue (vlib_main_t *vm, u32 *nb_elts_processed,
			  clib_thread_index_t *enqueue_thread_idx);
int oct_init_crypto_engine_handlers (vlib_main_t *vm, vnet_dev_t *dev);
int oct_conf_sw_queue (vlib_main_t *vm, vnet_dev_t *dev,
		       oct_crypto_dev_t *ocd);
#endif /* _CRYPTO_H_ */
