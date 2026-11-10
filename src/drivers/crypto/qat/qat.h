/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Damjan Marion
 */

#pragma once

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vnet/crypto/crypto.h>
#include <vppinfra/crypto/sha2.h>
#include <qat_hw.h>

#define QAT_DEFAULT_QUEUE_SIZE 1024
#define QAT_MIN_QUEUE_SIZE     128
#define QAT_MAX_QUEUE_SIZE     4096

/* request opaque is the fifo entry index and the frame element index */
#define QAT_OPAQUE_ELT_BITS 8
STATIC_ASSERT (VLIB_FRAME_SIZE <= 1 << QAT_OPAQUE_ELT_BITS, "frame index must fit opaque");

#define foreach_qat_cipher_alg                                                                     \
  _ (AES_128_CBC)                                                                                  \
  _ (AES_192_CBC)                                                                                  \
  _ (AES_256_CBC)                                                                                  \
  _ (AES_128_CTR)                                                                                  \
  _ (AES_192_CTR)                                                                                  \
  _ (AES_256_CTR)

#define foreach_qat_aead_alg                                                                       \
  _ (AES_128_GCM_ICV16_AAD8)                                                                       \
  _ (AES_128_GCM_ICV16_AAD12)                                                                      \
  _ (AES_128_GCM_ICV16_AAD20)                                                                      \
  _ (AES_128_GCM_ICV16_AAD28)                                                                      \
  _ (AES_192_GCM_ICV16_AAD8)                                                                       \
  _ (AES_192_GCM_ICV16_AAD12)                                                                      \
  _ (AES_192_GCM_ICV16_AAD20)                                                                      \
  _ (AES_192_GCM_ICV16_AAD28)                                                                      \
  _ (AES_256_GCM_ICV16_AAD8)                                                                       \
  _ (AES_256_GCM_ICV16_AAD12)                                                                      \
  _ (AES_256_GCM_ICV16_AAD20)                                                                      \
  _ (AES_256_GCM_ICV16_AAD28)                                                                      \
  _ (CHACHA20_POLY1305_ICV16_AAD0)                                                                 \
  _ (CHACHA20_POLY1305_ICV16_AAD8)                                                                 \
  _ (CHACHA20_POLY1305_ICV16_AAD12)

#define foreach_qat_combined_alg                                                                   \
  _ (AES_128_CBC_SHA2_224)                                                                         \
  _ (AES_192_CBC_SHA2_224)                                                                         \
  _ (AES_256_CBC_SHA2_224)                                                                         \
  _ (AES_128_CBC_SHA2_256)                                                                         \
  _ (AES_192_CBC_SHA2_256)                                                                         \
  _ (AES_256_CBC_SHA2_256)                                                                         \
  _ (AES_128_CBC_SHA2_384)                                                                         \
  _ (AES_192_CBC_SHA2_384)                                                                         \
  _ (AES_256_CBC_SHA2_384)                                                                         \
  _ (AES_128_CBC_SHA2_512)                                                                         \
  _ (AES_192_CBC_SHA2_512)                                                                         \
  _ (AES_256_CBC_SHA2_512)                                                                         \
  _ (AES_128_CTR_SHA2_256)                                                                         \
  _ (AES_192_CTR_SHA2_256)                                                                         \
  _ (AES_256_CTR_SHA2_256)                                                                         \
  _ (AES_128_CTR_SHA2_384)                                                                         \
  _ (AES_192_CTR_SHA2_384)                                                                         \
  _ (AES_256_CTR_SHA2_384)                                                                         \
  _ (AES_128_CTR_SHA2_512)                                                                         \
  _ (AES_192_CTR_SHA2_512)                                                                         \
  _ (AES_256_CTR_SHA2_512)                                                                         \
  _ (AES_128_CBC_SHA2_224_ICV14)                                                                   \
  _ (AES_192_CBC_SHA2_224_ICV14)                                                                   \
  _ (AES_256_CBC_SHA2_224_ICV14)                                                                   \
  _ (AES_128_CBC_SHA2_256_ICV12)                                                                   \
  _ (AES_192_CBC_SHA2_256_ICV12)                                                                   \
  _ (AES_256_CBC_SHA2_256_ICV12)                                                                   \
  _ (AES_128_CBC_SHA2_256_ICV16)                                                                   \
  _ (AES_192_CBC_SHA2_256_ICV16)                                                                   \
  _ (AES_256_CBC_SHA2_256_ICV16)                                                                   \
  _ (AES_128_CBC_SHA2_384_ICV24)                                                                   \
  _ (AES_192_CBC_SHA2_384_ICV24)                                                                   \
  _ (AES_256_CBC_SHA2_384_ICV24)                                                                   \
  _ (AES_128_CBC_SHA2_512_ICV32)                                                                   \
  _ (AES_192_CBC_SHA2_512_ICV32)                                                                   \
  _ (AES_256_CBC_SHA2_512_ICV32)                                                                   \
  _ (AES_128_CTR_SHA2_256_ICV12)                                                                   \
  _ (AES_192_CTR_SHA2_256_ICV12)                                                                   \
  _ (AES_256_CTR_SHA2_256_ICV12)                                                                   \
  _ (AES_128_CTR_SHA2_256_ICV16)                                                                   \
  _ (AES_192_CTR_SHA2_256_ICV16)                                                                   \
  _ (AES_256_CTR_SHA2_256_ICV16)                                                                   \
  _ (AES_128_CTR_SHA2_384_ICV24)                                                                   \
  _ (AES_192_CTR_SHA2_384_ICV24)                                                                   \
  _ (AES_256_CTR_SHA2_384_ICV24)                                                                   \
  _ (AES_128_CTR_SHA2_512_ICV32)                                                                   \
  _ (AES_192_CTR_SHA2_512_ICV32)                                                                   \
  _ (AES_256_CTR_SHA2_512_ICV32)

#define foreach_qat_gen2_alg foreach_qat_cipher_alg foreach_qat_combined_alg
#define foreach_qat_gen4_alg foreach_qat_cipher_alg foreach_qat_combined_alg foreach_qat_aead_alg

typedef enum
{
  QAT_ALG_TYPE_NONE = 0,
  QAT_ALG_TYPE_CIPHER,
  QAT_ALG_TYPE_AEAD,
  QAT_ALG_TYPE_COMBINED,
} __clib_packed qat_alg_type_t;

typedef struct
{
  qat_alg_type_t type;
  qat_hw_cipher_mode_t cipher_mode;
  qat_hw_cipher_algo_t cipher_algo;
  qat_hw_auth_algo_t auth_algo;
  u8 sha2_type; /* clib_sha2_type_t */
  u8 is_ucs : 1;
  u8 key_len;
  u8 iv_len;
  u8 digest_len;
  u8 aad_len;
} qat_alg_t;

STATIC_ASSERT_SIZEOF (qat_alg_t, 10);

#define QAT_CD_SIZE 256

/* content descriptors read by the device, one per direction */
typedef struct
{
  u8 cd[2][QAT_CD_SIZE];
} qat_session_cd_t;

/* templates and content descriptors are indexed by the op type */
STATIC_ASSERT (VNET_CRYPTO_OP_TYPE_ENCRYPT == 0 && VNET_CRYPTO_OP_TYPE_DECRYPT == 1,
	       "unexpected crypto op type values");

typedef struct
{
  qat_fw_la_req_t req[2];
} qat_alg_tmpl_t;

/* per key data kept by vnet crypto */
typedef struct
{
  const qat_alg_tmpl_t *tmpl;
  qat_session_cd_t *cd;
  u64 cd_dma;
} qat_key_t;

typedef struct
{
  vlib_frame_t *frame;
  vnet_crypto_op_status_t *status; /* vector, allocated only when some element fails */
  u16 n_pending;
} qat_frame_entry_t;

typedef enum
{
  QAT_GEN2,
  QAT_GEN4,
  QAT_N_GENS,
} qat_gen_t;

typedef struct
{
  char *group;
  char *engine_desc;
  const vnet_crypto_alg_t *algs;
  u16 n_algs;
  u32 required_caps;
  u16 bank_size;
  u16 ring_cfg_offset;
  u8 ring_base_shift;
  u8 has_ucs : 1;
} qat_gen_config_t;

typedef struct
{
  qat_alg_tmpl_t *templates[QAT_N_GENS]; /* vectors indexed by alg, zero if unsupported */
} qat_driver_t;

typedef struct
{
  u8 bank;
  u8 tx_ring;
  u8 rx_ring;
} qat_ring_pair_t;

#define QAT_MAX_SYM_RING_PAIRS QAT_GEN4_VF_N_BANKS

typedef struct
{
  void *bar0;
  void *bar2;
  qat_gen_t gen;
  const qat_gen_config_t *cfg;
  u8 pf_version;
  qat_ring_to_svc_map_t ring_to_svc_map;
  qat_blkmsg_caps_t caps;
  u8 n_sym_ring_pairs;
  qat_ring_pair_t sym_ring_pairs[QAT_MAX_SYM_RING_PAIRS];
  u8 pfvf_initialized : 1;
} qat_device_t;

typedef struct
{
  qat_fw_la_req_t *tx_ring;
  qat_fw_resp_t *rx_ring;
  qat_sgl_t *sgl;
  u32 *tx_tail_csr;
  u32 *rx_head_csr;
  u32 tx_tail;
  u32 rx_head;
  u32 n_enq;
  u32 n_deq;
  u32 mask;
  u32 max_inflight;
  u32 fifo_head;
  u32 fifo_tail;
  qat_frame_entry_t *fifo;
  qat_ring_pair_t rp;
  u8 va_dma : 1;
  u64 tx_ring_dma;
  u64 rx_ring_dma;
  u64 sgl_dma;
} qat_queue_t;

extern const qat_alg_t qat_algs[VNET_CRYPTO_N_ALGS];

/* pfvf.c */
vnet_dev_rv_t qat_pfvf_init (vlib_main_t *, vnet_dev_t *);
void qat_pfvf_shutdown (vlib_main_t *, vnet_dev_t *);
vnet_dev_rv_t qat_pfvf_ring_pair_reset (vlib_main_t *, vnet_dev_t *, u8);
vnet_dev_rv_t qat_pfvf_get_caps (vlib_main_t *, vnet_dev_t *, qat_blkmsg_caps_t *);

/* queue.c */
vnet_dev_rv_t qat_ring_pair_reset (vlib_main_t *, vnet_dev_t *, qat_ring_pair_t *);
vnet_dev_rv_t qat_queue_init (vlib_main_t *, vnet_dev_crypto_queue_t *);
void qat_queue_deinit (vlib_main_t *, vnet_dev_crypto_queue_t *);
vnet_dev_rv_t qat_queue_start (vlib_main_t *, vnet_dev_crypto_queue_t *);
void qat_queue_stop (vlib_main_t *, vnet_dev_crypto_queue_t *);

/* session.c */
vnet_crypto_key_change_fn_t qat_key_change;
void qat_tmpl_build (qat_fw_la_req_t *, const qat_alg_t *, u8, const qat_gen_config_t *);

static_always_inline void
qat_frame_set_status (qat_frame_entry_t *fe, u32 index, vnet_crypto_op_status_t status)
{
  if (fe->status == 0)
    {
      vec_validate (fe->status, fe->frame->n_vectors - 1);
      for (u32 i = 0; i < fe->frame->n_vectors; i++)
	fe->status[i] = VNET_CRYPTO_OP_STATUS_COMPLETED;
    }

  fe->status[index] = status;
}

static_always_inline void
qat_frame_done (vlib_main_t *vm, vlib_node_runtime_t *node, qat_frame_entry_t *fe)
{
  vnet_dev_crypto_frame_done (vm, node, fe->frame, fe->status);
  vec_free (fe->status);
}

/* enq.c, one enqueue node per handler variant */
#define foreach_qat_enqueue_node                                                                   \
  _ (cipher_enc, "cipher-enc", 1, QAT_ALG_TYPE_CIPHER)                                             \
  _ (cipher_dec, "cipher-dec", 0, QAT_ALG_TYPE_CIPHER)                                             \
  _ (aead_enc, "aead-enc", 1, QAT_ALG_TYPE_AEAD)                                                   \
  _ (aead_dec, "aead-dec", 0, QAT_ALG_TYPE_AEAD)                                                   \
  _ (combined_enc, "combined-enc", 1, QAT_ALG_TYPE_COMBINED)                                       \
  _ (combined_dec, "combined-dec", 0, QAT_ALG_TYPE_COMBINED)

extern vnet_dev_node_t qat_enq_cipher_enc_node, qat_enq_cipher_dec_node;
extern vnet_dev_node_t qat_enq_aead_enc_node, qat_enq_aead_dec_node;
extern vnet_dev_node_t qat_enq_combined_enc_node, qat_enq_combined_dec_node;

/* deq.c */
extern vnet_dev_node_t qat_deq_node;

/* format.c */
format_function_t format_qat_dev_info;
format_function_t format_qat_queue_info;
format_function_t format_qat_svc;
format_function_t format_qat_capabilities;
format_function_t format_qat_pf2vf_msgtype;
format_function_t format_qat_vf2pf_msgtype;
format_function_t format_qat_pf2vf_compat;
format_function_t format_qat_blkmsg_type;
format_function_t format_qat_ring_to_svc_map;
format_function_t format_qat_ring_csrs;
format_function_t format_qat_ring_dump;
format_function_t format_qat_fw_req;
format_function_t format_qat_fw_resp;
format_function_t format_qat_session;

static_always_inline u32
qat_reg_read (void *bar, u32 reg)
{
  return __atomic_load_n ((u32 *) ((u8 *) bar + reg), __ATOMIC_RELAXED);
}

static_always_inline void
qat_reg_write (void *bar, u32 reg, u32 value)
{
  __atomic_store_n ((u32 *) ((u8 *) bar + reg), value, __ATOMIC_RELEASE);
}

static_always_inline u32
qat_bank_reg (qat_device_t *qd, u8 bank, u32 reg)
{
  return bank * qd->cfg->bank_size + reg;
}

/* ring config and base registers */
static_always_inline u32
qat_ring_cfg_reg (qat_device_t *qd, u8 bank, u32 reg)
{
  return qat_bank_reg (qd, bank, qd->cfg->ring_cfg_offset + reg);
}

#define log_debug(dev, f, ...)                                                                     \
  vlib_log (VLIB_LOG_LEVEL_DEBUG, qat_log.class, "%U" f, format_vnet_dev_log, (dev),               \
	    clib_string_skip_prefix (__func__, "qat_"), ##__VA_ARGS__)
#define log_notice(dev, f, ...)                                                                    \
  vlib_log (VLIB_LOG_LEVEL_NOTICE, qat_log.class, "%U: " f, format_vnet_dev_addr, (dev),           \
	    ##__VA_ARGS__)
#define log_warn(dev, f, ...)                                                                      \
  vlib_log (VLIB_LOG_LEVEL_WARNING, qat_log.class, "%U: " f, format_vnet_dev_addr, (dev),          \
	    ##__VA_ARGS__)
#define log_err(dev, f, ...)                                                                       \
  vlib_log (VLIB_LOG_LEVEL_ERR, qat_log.class, "%U: " f, format_vnet_dev_addr, (dev), ##__VA_ARGS__)
