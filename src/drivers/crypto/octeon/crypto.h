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

/* index of the engine in the driver registration */

#define OCT_CPT_LF_DEF_NB_DESC 4096

#define OCT_CPT_LF_MIN_NB_DESC 1024
#define OCT_CPT_LF_MAX_NB_DESC 32768

typedef struct
{
  oct_dev_common_t common;
  struct roc_cpt *roc_cpt;
  u8 hw_ctx_cache;
} oct_crypto_device_t;

typedef union cpt_res_s cpt_res_t;

#ifdef PLATFORM_OCTEON9
typedef struct roc_sglist_comp oct_sg_comp_t;
#define OCT_SG_PER_COMP 4
#define OCT_SG_MAX_COMP 2
#else
typedef struct roc_sg2list_comp oct_sg_comp_t;
#define OCT_SG_PER_COMP 3
#define OCT_SG_MAX_COMP 3
#endif

/* per request data read and written by CPT, gather entry 0 covers ctrl, IV and AAD.
   Result writes are slow when other requests share the 128 byte line. */
typedef struct
{
  u64 offset_ctrl;
  u8 iv[16];
  u8 aad[16];
#ifdef PLATFORM_OCTEON9
  u16 sg_hdr[4];
  /* scatter components follow the used gather components */
  oct_sg_comp_t sg[2 * OCT_SG_MAX_COMP];
  cpt_res_t res;
#else
  cpt_res_t res __clib_aligned (16);
  oct_sg_comp_t gather[OCT_SG_MAX_COMP] __clib_aligned (64);
  oct_sg_comp_t scatter[OCT_SG_MAX_COMP];
#endif
} __clib_aligned (ROC_ALIGN)
oct_crypto_meta_t;

STATIC_ASSERT_SIZEOF (oct_crypto_meta_t, 256);

typedef struct
{
  struct roc_se_ctx *enc_ctx;
  struct roc_se_ctx *dec_ctx;
  u64 enc_inst_w4;
  u64 dec_inst_w4;
  u64 enc_inst_w7;
  u64 dec_inst_w7;
  u8 iv_length;
  u8 mac_len;
  u8 cbc_pad : 1;
  u8 flush_on_free : 1;
} oct_crypto_key_t;

typedef struct
{
  vlib_frame_t **frames;
  u16 elt_head;
  u16 elt_tail;
  u16 frame_head;
  u16 frame_tail;
  u16 deq_left;
  u16 deq_next;
  u16 n_desc;
  oct_crypto_meta_t *meta;
  struct roc_cpt_lf *lf;
  struct roc_cpt_lmtline lmtline;
} oct_crypto_queue_t;

typedef struct
{
  u16 lf_id;
  u16 slot;
  struct cpt_inst_s inst;
} oct_crypto_enq_trace_t;

typedef struct
{
  u16 lf_id;
  u16 slot;
  cpt_res_t res;
} oct_crypto_deq_trace_t;

typedef struct
{
  roc_se_cipher_type cipher_type;
  roc_se_auth_type auth_type;
  u8 aad_len;
  u8 digest_len;
  u8 iv_length;
  u16 opcode_minor_flags;
  u8 valid;
} oct_crypto_alg_data_t;

/* algs.c */
extern const oct_crypto_alg_data_t oct_crypto_algs[VNET_CRYPTO_N_ALGS];
vnet_dev_crypto_alg_handlers_t *oct_crypto_get_alg_handlers (union cpt_eng_caps *caps);

/* key.c */
void oct_crypto_key_change_handler (vnet_crypto_ctx_t *ctx, vnet_crypto_key_change_args_t *args);

/* deq.c */
extern vnet_dev_node_t oct_crypto_deq_node;

/* enq.c, one enqueue node per handler variant */
#define foreach_oct_crypto_enqueue_node                                                            \
  _ (enc, "enc", 0, 0, 1)                                                                          \
  _ (dec, "dec", 0, 0, 0)                                                                          \
  _ (aead_aad0_enc, "aead-aad0-enc", 1, 0, 1)                                                      \
  _ (aead_aad0_dec, "aead-aad0-dec", 1, 0, 0)                                                      \
  _ (aead_aad8_enc, "aead-aad8-enc", 1, 8, 1)                                                      \
  _ (aead_aad8_dec, "aead-aad8-dec", 1, 8, 0)                                                      \
  _ (aead_aad12_enc, "aead-aad12-enc", 1, 12, 1)                                                   \
  _ (aead_aad12_dec, "aead-aad12-dec", 1, 12, 0)

#define _(n, s, is_aead, aad_len, is_enc) extern vnet_dev_node_t oct_crypto_enq_##n##_node;
foreach_oct_crypto_enqueue_node
#undef _

  /* format.c */
  format_function_t format_oct_cpt_dev_info;
format_function_t format_oct_cpt_queue_info;
format_function_t format_oct_cpt_enq_trace;
format_function_t format_oct_cpt_deq_trace;

/* queue.c */
vnet_dev_rv_t oct_crypto_queue_init (vlib_main_t *vm, vnet_dev_crypto_queue_t *cq);
void oct_crypto_queue_deinit (vlib_main_t *vm, vnet_dev_crypto_queue_t *cq);
void oct_crypto_queue_stop (vlib_main_t *vm, vnet_dev_crypto_queue_t *cq);

/* session.c */
i32 oct_crypto_session_init (vlib_main_t *vm, oct_crypto_key_t *ckey, vnet_crypto_ctx_t *ctx,
			     oct_crypto_device_t *cd);

#endif /* _CRYPTO_H_ */
