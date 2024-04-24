/*
 * Copyright (c) 2024 Marvell.
 * SPDX-License-Identifier: Apache-2.0
 * https://spdx.org/licenses/Apache-2.0.html
 */

#ifndef _CRYPTO_H_
#define _CRYPTO_H_
#include <vnet/dev/dev.h>
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

#define CPT_LMT_SIZE_COPY (sizeof (struct cpt_inst_s) / 16)
#define OCT_MAX_LMT_SZ	  16

#define SRC_IOV_SIZE                                                          \
  (sizeof (struct roc_se_iov_ptr) +                                           \
   (sizeof (struct roc_se_buf_ptr) * ROC_MAX_SG_CNT))

#define OCT_CPT_LMT_GET_LINE_ADDR(lmt_addr, lmt_num)                          \
  (void *) ((u64) (lmt_addr) + ((u64) (lmt_num) << ROC_LMT_LINE_SIZE_LOG2))

typedef struct
{
  oct_crypto_key_t *keys[VNET_CRYPTO_ASYNC_OP_N_TYPES];
  oct_crypto_pending_queue_t *pend_q;
} oct_crypto_t;

int oct_init_crypto_engine_handlers (vlib_main_t *vm, vnet_dev_t *dev);
#endif /* _CRYPTO_H_ */
