/*
 *------------------------------------------------------------------
 * Copyright (c) 2019 Intel and/or its affiliates.
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

#include <vlib/vlib.h>
#include <vnet/plugin/plugin.h>
#include <vnet/crypto/crypto.h>
#include <vnet/vnet.h>
#include <vpp/app/version.h>

#include <dpdk/buffer.h>
#include <dpdk/device/dpdk.h>
#include <dpdk/device/dpdk_priv.h>
#include <rte_cryptodev.h>
#include <rte_crypto_sym.h>
#include <rte_crypto.h>
#include <rte_cryptodev_pmd.h>
#include <rte_bus_vdev.h>
#include <rte_config.h>

#include "cryptodev.h"

#define IV_OFF (sizeof(struct rte_crypto_op) + sizeof(struct rte_crypto_sym_op))
#define MAX_IV_SIZE 16

/* VNET_CRYPTO_ALGO, TYPE, DPDK_CRYPTO_ALGO, KEY_LEN, IV_LEN */
#define foreach_vnet_cipher_crypto_conversion \
  _(AES_128_CBC, CIPHER, AES_CBC, 16, 16) \
  _(AES_192_CBC, CIPHER, AES_CBC, 24, 16) \
  _(AES_256_CBC, CIPHER, AES_CBC, 32, 16) \
  _(AES_128_CTR, CIPHER, AES_CTR, 16, 16) \
  _(AES_192_CTR, CIPHER, AES_CTR, 24, 16) \
  _(AES_256_CTR, CIPHER, AES_CTR, 32, 16) \
  _(3DES_CBC, CIPHER, 3DES_CBC, 24, 8)

/* VNET_CRYPTO_ALGO, TYPE, DPDK_CRYPTO_ALGO, KEY_LEN, IV_LEN */
#define foreach_vnet_aead_crypto_conversion \
  _(AES_128_GCM, AEAD, AES_GCM, 16, 12) \
  _(AES_192_GCM, AEAD, AES_GCM, 24, 12) \
  _(AES_256_GCM, AEAD, AES_GCM, 32, 12)

/* VNET_CRYPTO_ALGO, TYPE, DPDK_CRYPTO_ALGO, KEY_LEN */
#define foreach_vnet_hmac_crypto_conversion \
  _(SHA1, AUTH, SHA1_HMAC, 10) \
  _(SHA224, AUTH, SHA224_HMAC, 28) \
  _(SHA256, AUTH, SHA256_HMAC, 32) \
  _(SHA384, AUTH, SHA384_HMAC, 48) \
  _(SHA512, AUTH, SHA512_HMAC, 64)

#define foreach_vnet_crypto_status_conversion \
  _(WORK_IN_PROGRESS, NOT_PROCESSED) \
  _(COMPLETED, SUCCESS) \
  _(FAIL_BAD_HMAC, AUTH_FAILED)

typedef struct
{
  struct rte_crypto_op op;
  struct rte_crypto_sym_op sop;
  u8 iv[16];
  u8 aad[16];
  struct rte_mbuf msrc;
  struct rte_mbuf mdst;
  vnet_crypto_op_t *vop;
} cryptodev_op_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  cryptodev_op_t *crypto_op_pool;
  u8 cryptodev_id;
  u8 cryptodev_q;
  u32 inflight;
  u16 cur_op_idx;
  u32 enc_counter;
  u32 dec_counter;
  struct rte_crypto_op **ops;
} cryptodev_engine_thread_t;

typedef enum
{
  DIR_OUT = 0,		/**< Need to be encrypted */
  DIR_IN	      /**< Need to be decrypted */
} cryptodev_encryption_dir_t;

typedef struct
{
  struct rte_cryptodev_sym_session *keys[2];
  u32 iv_len;
  u32 aad_len;
} key_info_t;

typedef struct
{
  u32 dev_id;
  u32 q_id;
  char *desc;
} cryptodev_inst_t;

typedef struct
{
  struct rte_mempool *sess_pool;
  struct rte_mempool *sess_priv_pool;
} cryptodev_numa_data_t;

typedef struct
{
  cryptodev_numa_data_t *per_numa_data;
  key_info_t *keys;
  cryptodev_engine_thread_t *per_thread_data;
  cryptodev_inst_t *cryptodev_inst;
} cryptodev_main_t;

cryptodev_main_t cryptodev_main;
u32 cryptodev_enabled;

static int
prepare_cipher_xform (struct rte_crypto_sym_xform *xform,
		      u32 direction, vnet_crypto_key_t * key, u32 algo,
		      u32 key_len, u32 iv_len)
{
  struct rte_crypto_cipher_xform *cipher_xform = &xform->cipher;

  memset (xform, 0, sizeof (*xform));
  xform->type = RTE_CRYPTO_SYM_XFORM_CIPHER;

  cipher_xform->algo = algo;
  cipher_xform->op = (direction == DIR_OUT) ?
    RTE_CRYPTO_CIPHER_OP_ENCRYPT : RTE_CRYPTO_CIPHER_OP_DECRYPT;
  cipher_xform->key.data = key->data;
  cipher_xform->key.length = key_len;
  cipher_xform->iv.length = iv_len;
  cipher_xform->iv.offset = IV_OFF;
  return 0;
}

/**
 * lookup the vnet_crypto_alg_t type and transform to dpdk xform type
 *
 *  @param vnet_alg: vnet_crypto_alg_t algo
 *  @param xform_type: the transformed xform type
 *
 *  @return: rte_crypto_cipher_algorithm / rte_crypto_auth_algorithm /
 *      rte_crypto_aead_algorithm enum type
 */
static u32
transform_vnet_crypto_type (vnet_crypto_alg_t vnet_alg,
			    enum rte_crypto_sym_xform_type *xform_type,
			    u32 * key_len, u32 * iv_len)
{
  switch (vnet_alg)
    {
#define _(v, d, a, l, s) \
    case VNET_CRYPTO_ALG_##v: \
      *xform_type = RTE_CRYPTO_SYM_XFORM_##d; \
      *key_len = l; \
      *iv_len = s; \
    return RTE_CRYPTO_##d##_##a;
      foreach_vnet_cipher_crypto_conversion
	//foreach_vnet_aead_crypto_conversion
#undef _
    default:
      *xform_type = RTE_CRYPTO_SYM_XFORM_NOT_SPECIFIED;
      *key_len = 0;
      return ~0;
    }
}

  /**
 * Return a created session by parsing vnet_crypto_key_t, REMEMBER:
 * - check key->next for chained op
 * - every device type should have a sess priv data set-up, unless the device does not support the alg
 */
static int
cryptodev_session_create (vnet_crypto_key_t * const key,
			  struct rte_mempool *sess_pool,
			  struct rte_mempool *sess_priv_pool,
			  key_info_t * session_pair)
{
  struct rte_crypto_sym_xform cipher_xform;
  struct rte_cryptodev_sym_session *session_in;
  struct rte_cryptodev_sym_session *session_out;
  cryptodev_main_t *cmt = &cryptodev_main;
  cryptodev_inst_t *dev_inst;
  int ret;
  u32 use_cipher = 0;
  vnet_crypto_key_t *key_next = key;
  u32 cryptodev_algo;
  u32 cipher_cryptodev_algo;
  vnet_crypto_key_t *cipher_key = 0;
  enum rte_crypto_sym_xform_type xform_type;
  u32 key_len, iv_len;

  cryptodev_algo = transform_vnet_crypto_type (key_next->alg, &xform_type,
					       &key_len, &iv_len);
  switch (xform_type)
    {
    case RTE_CRYPTO_SYM_XFORM_CIPHER:
      use_cipher = 1;
      cipher_cryptodev_algo = cryptodev_algo;
      cipher_key = key_next;
      break;

    default:
      return -1;
    }

  session_out = rte_cryptodev_sym_session_create (sess_pool);
  session_in = rte_cryptodev_sym_session_create (sess_pool);
  if (use_cipher)
    {
      uint8_t dev_id = 0;

      prepare_cipher_xform (&cipher_xform, DIR_OUT, cipher_key,
			    cipher_cryptodev_algo, key_len, iv_len);

      vec_foreach (dev_inst, cmt->cryptodev_inst)
      {
	dev_id = dev_inst->dev_id;
	ret =
	  rte_cryptodev_sym_session_init (dev_id, session_out, &cipher_xform,
					  sess_priv_pool);
	if (ret < 0)
	  {
	    return ret;
	  }
	cipher_xform.cipher.op = RTE_CRYPTO_CIPHER_OP_DECRYPT;
	ret =
	  rte_cryptodev_sym_session_init (dev_id, session_in, &cipher_xform,
					  sess_priv_pool);
	if (ret < 0)
	  {
	    return ret;
	  }
      }
    }
  session_pair->keys[0] = session_out;
  session_pair->keys[1] = session_in;
  session_pair->aad_len = 0;
  session_pair->iv_len = iv_len;
  return 0;
}

static void
cryptodev_session_del (struct rte_cryptodev_sym_session *sess)
{
  u32 n_devs = rte_cryptodev_count (), i;

  for (i = 0; i < n_devs; i++)
    rte_cryptodev_sym_session_clear (i, sess);

  rte_cryptodev_sym_session_free (sess);
}

/*static*/ void
cryptodev_key_handler (vlib_main_t * vm, vnet_crypto_key_op_t kop,
		       vnet_crypto_key_index_t idx)
{
  cryptodev_main_t *cm = &cryptodev_main;
  cryptodev_numa_data_t *numa_data;
  vnet_crypto_key_t *key = vnet_crypto_get_key (idx);
  struct rte_mempool *sess_pool, *sess_priv_pool;
  int res;
  key_info_t sess;
  u32 numa;

  switch (kop)
    {
    case VNET_CRYPTO_KEY_OP_MODIFY:
      if (idx >= vec_len (cm->keys))
	return;
      if (cm->keys[idx].keys[0])
	{
	  cryptodev_session_del ((cm->keys[idx]).keys[0]);
	  cm->keys[idx].keys[0] = 0;
	}
      if (cm->keys[idx].keys[1])
	{
	  cryptodev_session_del ((cm->keys[idx]).keys[1]);
	  cm->keys[idx].keys[1] = 0;
	}
    case VNET_CRYPTO_KEY_OP_ADD:
      numa = clib_get_current_numa_node ();
      numa_data = vec_elt_at_index (cm->per_numa_data, numa);
      sess_pool = numa_data->sess_pool;
      sess_priv_pool = numa_data->sess_priv_pool;

      res = cryptodev_session_create (key, sess_pool, sess_priv_pool, &sess);
      if (res != 0)
	{
	  /* TODO: find a way to invalidate this engine */
	  return;
	}

      vec_validate (cm->keys, idx + 1);

      cm->keys[idx] = sess;
      break;

    case VNET_CRYPTO_KEY_OP_DEL:
      if (idx >= vec_len (cm->keys))
	return;
      if (cm->keys[idx].keys[0])
	{
	  cryptodev_session_del ((cm->keys[idx]).keys[0]);
	  cm->keys[idx].keys[0] = 0;
	}
      if (cm->keys[idx].keys[1])
	{
	  cryptodev_session_del ((cm->keys[idx]).keys[1]);
	  cm->keys[idx].keys[1] = 0;
	}
      break;
    }
}

static_always_inline rte_iova_t
cryptodev_get_data_iova (clib_pmalloc_main_t * pm, void *data)
{
  uword index;

  if (rte_eal_iova_mode () == RTE_IOVA_VA)
    return pointer_to_uword (data);

  index = (pointer_to_uword (data) - pointer_to_uword (pm->base)) >>
    pm->def_log2_page_sz;

  if (PREDICT_FALSE (index >= vec_len (pm->pages)))
    return 0;

  return pointer_to_uword (data) - pm->lookup_table[index];
}

/**
 * Duplicate of vlib_physmem_get_pa (), with validity checking and in/out
 * of place decision.
 *
 * @return 0: valid physical address, in-place operation
 * @return 1: valid physical address, out-of-place operation
 * @return -1: invalid physical address.
 */
static_always_inline int
cryptodev_get_buf_iova (clib_pmalloc_main_t * pm, vnet_crypto_op_t * vop,
			rte_iova_t * phyaddr_src, rte_iova_t * phyaddr_dst)
{
  int oop = ((vop->dst) && (vop->dst != vop->src));
  uword index;

  if (rte_eal_iova_mode () == RTE_IOVA_VA)
    {
      *phyaddr_src = pointer_to_uword (vop->src);
      *phyaddr_dst = pointer_to_uword (vop->src);

      return oop;
    }

  index = (pointer_to_uword (vop->src) - pointer_to_uword (pm->base)) >>
    pm->def_log2_page_sz;

  if (PREDICT_FALSE (index >= vec_len (pm->pages)))
    return -1;

  *phyaddr_src = pointer_to_uword (vop->src) - pm->lookup_table[index];

  if (oop)
    {
      uword index2 = (pointer_to_uword (vop->dst) -
		      pointer_to_uword (pm->base)) >> pm->def_log2_page_sz;

      if (PREDICT_FALSE (index2 >= vec_len (pm->pages)))
	return -1;

      *phyaddr_dst = pointer_to_uword (vop->dst) - pm->lookup_table[index];
    }

  return oop;
}

static_always_inline void
prepare_op_post (vlib_main_t * vm, cryptodev_op_t * cop,
		 vnet_crypto_op_t * vop, rte_iova_t phyaddr_src,
		 rte_iova_t phyaddr_dst, int oop)
{
  struct rte_crypto_sym_op *sop = &cop->sop;

  cop->msrc.buf_addr = (void *) vop->src;
  cop->msrc.buf_iova = phyaddr_src;
  cop->msrc.buf_len = cop->msrc.data_len = vop->len;

  if (oop)
    {
      sop->m_dst = &cop->mdst;
      cop->mdst.buf_addr = (void *) vop->dst;
      cop->mdst.buf_iova = phyaddr_dst;
      cop->mdst.buf_len = cop->mdst.data_len = vop->len;;
    }
  else
    sop->m_dst = NULL;

  cop->vop = vop;
}

static_always_inline void
translate_cipher_op (cryptodev_op_t * op, vnet_crypto_op_t * vop,
		     struct rte_cryptodev_sym_session *sess, u16 iv_len)
{
  struct rte_crypto_sym_op *sop = &op->sop;

  sop->session = sess;
  sop->cipher.data.length = vop->len;
  sop->cipher.data.offset = 0;
  memcpy (op->iv, vop->iv, iv_len);
}

static_always_inline void
enqueue_to_cryptodev (cryptodev_engine_thread_t * cet)
{
  u16 n_enqd = rte_cryptodev_enqueue_burst (cet->cryptodev_id,
					    cet->cryptodev_q,
					    cet->ops, cet->cur_op_idx);

  ASSERT (n_enqd == cet->cur_op_idx);

  cet->inflight += n_enqd;
  cet->cur_op_idx = 0;
}

static_always_inline vnet_crypto_op_status_t
decode_crypto_op_status (enum rte_crypto_op_status status)
{
  switch (status)
    {
#define _(a, b) \
    case RTE_CRYPTO_OP_STATUS_##b: \
      return VNET_CRYPTO_OP_STATUS_##a;
      foreach_vnet_crypto_status_conversion
#undef _
    default:
      return VNET_CRYPTO_OP_STATUS_ENGINE_ERR;
    }
}

static_always_inline u32
dequeue_from_cryptodev (cryptodev_engine_thread_t * cet)
{
  struct rte_crypto_op *ops[CRYPTODEV_MAX_INFLIGHT];
  u16 nb_deq = ~0, total_deq = 0, i;

  while (nb_deq >= CRYPTODEV_BURST_SIZE && cet->inflight)
    {
      nb_deq = rte_cryptodev_dequeue_burst (cet->cryptodev_id,
					    cet->cryptodev_q,
					    ops, CRYPTODEV_BURST_SIZE);
      cet->inflight -= nb_deq;
      total_deq += nb_deq;

      for (i = 0; i < nb_deq; i++)
	{
	  cryptodev_op_t *cop = (cryptodev_op_t *) ops[i];
	  vnet_crypto_op_t *vop = cop->vop;

	  vop->status = decode_crypto_op_status (ops[i]->status);
	  pool_put (cet->crypto_op_pool, cop);
	}
    }

  return total_deq;
}

static_always_inline void
cryptodev_alloc_cop_pool (vlib_main_t * vm, cryptodev_engine_thread_t * cet)
{
  cryptodev_op_t *cop;
  u32 i;

  pool_alloc_aligned (cet->crypto_op_pool, CRYPTODEV_NB_CRYPTO_OPS,
		      CLIB_CACHE_LINE_BYTES);

  for (i = 0; i < CRYPTODEV_NB_CRYPTO_OPS; i++)
    {
      cop = cet->crypto_op_pool + i;

      cop->op.phys_addr = vlib_physmem_get_pa (vm, cop);
      cop->op.type = RTE_CRYPTO_OP_TYPE_SYMMETRIC;
      cop->op.sess_type = RTE_CRYPTO_OP_WITH_SESSION;
      cop->msrc.data_off = 0;
      cop->mdst.data_off = 0;
      cop->sop.aead.data.offset = 0;
      cop->sop.m_src = &cop->msrc;
    };
}

static_always_inline u32
cryptodev_cipher_queue_handler (vlib_main_t * vm, u32 thread_idx,
				vnet_crypto_queue_t * q, u32 dir)
{
  cryptodev_main_t *cmt = &cryptodev_main;
  vnet_crypto_op_t *vop;
  clib_pmalloc_main_t *pm = vm->physmem_main.pmalloc_main;
  cryptodev_engine_thread_t *cet = vec_elt_at_index (cmt->per_thread_data,
						     vm->thread_index);
  key_info_t *keys = 0;
  u32 last_key_idx = ~0;
  u16 fetch_sz;
  u16 op_idx;
  u32 atomic = (vm->thread_index != thread_idx);

  if (cet->crypto_op_pool == 0)
    cryptodev_alloc_cop_pool (vm, cet);

  fetch_sz = CRYPTODEV_NB_CRYPTO_OPS - cet->inflight - cet->cur_op_idx;

  op_idx = cet->cur_op_idx;

  while ((vop = vnet_crypto_async_get_one_op (q, atomic)) && fetch_sz)
    {
      rte_iova_t iova_src, iova_dst;
      cryptodev_op_t *cop;
      int oop;

      oop = cryptodev_get_buf_iova (pm, vop, &iova_src, &iova_dst);
      if (PREDICT_FALSE (oop < 0))
	{
	  vop->status = VNET_CRYPTO_OP_STATUS_ENGINE_ERR;
	  continue;
	}

      pool_get_aligned (cet->crypto_op_pool, cop, CLIB_CACHE_LINE_BYTES);
      CLIB_PREFETCH (&cop->sop, sizeof (struct rte_crypto_sym_op), STORE);
      CLIB_PREFETCH (&cop->msrc, sizeof (struct rte_mbuf), STORE);
      CLIB_PREFETCH (&cop->mdst, sizeof (struct rte_mbuf) + 8, STORE);

      vec_validate_aligned (cet->ops, op_idx, CLIB_CACHE_LINE_BYTES);

      if (last_key_idx != vop->key_index)
	{
	  keys = vec_elt_at_index (cmt->keys, vop->key_index);
	  last_key_idx = vop->key_index;
	}

      translate_cipher_op (cop, vop, keys->keys[dir], keys->iv_len);
      prepare_op_post (vm, cop, vop, iova_src, iova_dst, oop);

      cet->ops[cet->cur_op_idx++] = (struct rte_crypto_op *) cop;

      if (PREDICT_FALSE (cet->cur_op_idx >= CRYPTODEV_BURST_SIZE))
	{
	  enqueue_to_cryptodev (cet);
	  cet->enc_counter = 0;
	}

      fetch_sz--;
    }

  if (PREDICT_FALSE (cet->enc_counter++ >= CRYPTODEV_MAX_TIMER))
    {
      enqueue_to_cryptodev (cet);
      cet->enc_counter = 0;
    }

  if (cet->inflight >= CRYPTODEV_MAX_INFLIGHT ||
      cet->dec_counter++ >= CRYPTODEV_MAX_TIMER)
    {
      cet->dec_counter = 0;
      return dequeue_from_cryptodev (cet);
    }

  return 0;
}

u32
cryptodev_queue_cipher_encrypt (vlib_main_t * vm, u32 thread_idx,
				vnet_crypto_queue_t * q)
{
  return cryptodev_cipher_queue_handler (vm, thread_idx, q, DIR_OUT);
}

u32
cryptodev_queue_cipher_decrypt (vlib_main_t * vm, u32 thread_idx,
				vnet_crypto_queue_t * q)
{
  return cryptodev_cipher_queue_handler (vm, thread_idx, q, DIR_IN);
}

static int
check_cryptodev_alg_support (u32 dev_id)
{
  const struct rte_cryptodev_symmetric_capability *cap;
  struct rte_cryptodev_sym_capability_idx cap_idx;

#define _(v, d, a, l, s) \
  cap_idx.type = RTE_CRYPTO_SYM_XFORM_##d; \
  cap_idx.algo.cipher = RTE_CRYPTO_##d##_##a; \
  cap = rte_cryptodev_sym_capability_get (dev_id, &cap_idx); \
  if (!cap) \
    return -RTE_CRYPTO_##d##_##a; \
  if (rte_cryptodev_sym_capability_check_cipher (cap, l, s)) \
    return -RTE_CRYPTO_##d##_##a;

  foreach_vnet_cipher_crypto_conversion
#undef _
#define _(v, d, a, l) \
  cap_idx.type = RTE_CRYPTO_SYM_XFORM_##d; \
  cap_idx.algo.auth = RTE_CRYPTO_##d##_##a; \
  cap = rte_cryptodev_sym_capability_get (dev_id, &cap_idx); \
  if (!cap) \
    return -RTE_CRYPTO_##d##_##a; \
  if (rte_cryptodev_sym_capability_check_auth (cap, l, \
                                               cap->auth.digest_size.min, \
                                               cap->auth.iv_size.min)) \
    return -RTE_CRYPTO_##d##_##a;
    foreach_vnet_hmac_crypto_conversion
#undef _
#define _(v, d, a, l, s) \
  cap_idx.type = RTE_CRYPTO_SYM_XFORM_##d; \
  cap_idx.algo.aead = RTE_CRYPTO_##d##_##a; \
  cap = rte_cryptodev_sym_capability_get (dev_id, &cap_idx); \
  if (!cap) \
    return -RTE_CRYPTO_##d##_##a; \
  if (rte_cryptodev_sym_capability_check_aead (cap, l, \
                                               cap->aead.digest_size.min, \
                                               cap->aead.aad_size.min, \
                                               s)) \
    return -RTE_CRYPTO_##d##_##a;
    foreach_vnet_aead_crypto_conversion
#undef _
    return 0;
}

static void
cryptodev_probe (vlib_main_t * vm)
{
  cryptodev_main_t *cmt = &cryptodev_main;
  cryptodev_numa_data_t *numa_data;
  u32 n_cryptodevs = rte_cryptodev_count ();
  u32 numa = vm->numa_node;
  u32 i;

  numa_data = vec_elt_at_index (cmt->per_numa_data, numa);

  for (i = 0; i < n_cryptodevs; i++)
    {
      struct rte_cryptodev_info info;
      struct rte_cryptodev *cdev;
      i32 qp_setup_err = 0;
      u32 n_cdev_inst;
      u32 j;

      cdev = rte_cryptodev_pmd_get_dev (i);
      rte_cryptodev_info_get (i, &info);

      /**
       * Cryptodev is NUMA sensitive, for performance reason the device
       * lies in different numa node is not used.
       **/
      if (rte_cryptodev_socket_id (i) != numa)
	continue;

      if (check_cryptodev_alg_support (i) != 0)
	continue;

      n_cdev_inst = vec_len (cmt->cryptodev_inst);

      /** If the device is already started, we reuse it, otherwise configure
       *  both the device and queue pair.
       **/
      if (!cdev->data->dev_started)
	{
	  struct rte_cryptodev_config cfg;

	  cfg.socket_id = vm->numa_node;
	  cfg.nb_queue_pairs = info.max_nb_queue_pairs;

	  rte_cryptodev_configure (i, &cfg);

	  for (j = 0; j < info.max_nb_queue_pairs; j++)
	    {
	      struct rte_cryptodev_qp_conf qp_cfg;

	      int ret;

	      if (qp_setup_err)
		continue;

	      qp_cfg.mp_session = numa_data->sess_pool;
	      qp_cfg.mp_session_private = numa_data->sess_priv_pool;
	      qp_cfg.nb_descriptors = CRYPTODEV_NB_CRYPTO_OPS;

	      ret = rte_cryptodev_queue_pair_setup (i, j, &qp_cfg, numa);
	      if (ret)
		qp_setup_err = 1;
	    }

	  /* start the device */
	  rte_cryptodev_start (i);
	}

      if (qp_setup_err)
	continue;

      for (j = 0; j < info.max_nb_queue_pairs; j++)
	{
	  cryptodev_inst_t *cdev_inst;

	  vec_validate (cmt->cryptodev_inst, n_cdev_inst + j);
	  cdev_inst = vec_elt_at_index (cmt->cryptodev_inst, n_cdev_inst + j);
	  cdev_inst->desc = vec_new (char, strlen (info.device->name) + 10);
	  cdev_inst->dev_id = i;
	  cdev_inst->q_id = j;

	  snprintf (cdev_inst->desc, 128, "%s_q%u", info.device->name, j);
	}
    }
}

static i32
cryptodev_get_session_sz (void)
{
  u32 sess_data_sz = 0, i;

  if (rte_cryptodev_count () == 0)
    return -1;

  for (i = 0; i < rte_cryptodev_count (); i++)
    {
      u32 dev_sess_sz = rte_cryptodev_sym_get_private_session_size (i);

      sess_data_sz = dev_sess_sz > sess_data_sz ? dev_sess_sz : sess_data_sz;
    }

  return sess_data_sz;
}

/*static*/ clib_error_t *
cryptodev_early_init (vlib_main_t * vm)
{
  cryptodev_main_t *cmt = &cryptodev_main;
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  u32 n_workers = vlib_thread_main.n_vlib_mains - 1;
  u32 n_numa;

  vec_reset_length (cmt->per_numa_data);
  vec_reset_length (cmt->cryptodev_inst);

  n_numa = clib_bitmap_count_set_bits (tm->cpu_socket_bitmap);
  vec_validate (cmt->per_numa_data, n_numa);
  vec_validate_aligned (cmt->per_thread_data, n_workers,
			CLIB_CACHE_LINE_BYTES);

  return NULL;
}

static void
dpdk_disable_cryptodev_engine (vlib_main_t * vm)
{
  cryptodev_main_t *cmt = &cryptodev_main;
  cryptodev_engine_thread_t *cet = 0;
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  u32 numa;

  clib_bitmap_foreach (numa, tm->cpu_socket_bitmap, (
						      {
						      cryptodev_numa_data_t *
						      numa_data;
						      numa_data =
						      vec_elt_at_index
						      (cmt->per_numa_data,
						       numa);
						      if
						      (numa_data->sess_pool)
						      rte_mempool_free
						      (numa_data->sess_pool);
						      if
						      (numa_data->sess_priv_pool)
						      rte_mempool_free
						      (numa_data->sess_priv_pool);}
		       ));

  vec_foreach (cet, cmt->per_thread_data)
  {
    if (cet->crypto_op_pool)
      pool_free (cet->crypto_op_pool);
  }

  cryptodev_enabled = 0;
}

clib_error_t *
dpdk_enable_cryptodev_engine (vlib_main_t * vm)
{
  cryptodev_main_t *cmt = &cryptodev_main;
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  u32 n_workers = vlib_thread_main.n_vlib_mains - 1;
  i32 sess_sz;
  u32 numa;
  u32 eidx;
  u8 *name;
  clib_error_t *error;

  if (cryptodev_enabled)
    {
      error = clib_error_return (0, "Cryptodev engine already enabled");
      return error;
    }

  sess_sz = cryptodev_get_session_sz ();
  if (sess_sz < 0)
    {
      error = clib_error_return (0, "No Cryptodev available");
      return error;
    }

  clib_bitmap_foreach (numa, tm->cpu_socket_bitmap, (
						      {
						      cryptodev_numa_data_t *
						      numa_data;
						      struct rte_mempool * mp;
						      char mp_name[128];
						      numa_data =
						      vec_elt_at_index
						      (cmt->per_numa_data,
						       numa);
						      snprintf (mp_name, 128,
								"vcryptodev_sess_pool_%u",
								numa);
						      mp =
						      rte_cryptodev_sym_session_pool_create
						      (mp_name,
						       CRYPTODEV_NB_SESSION,
						       0, 0, 0, numa);
						      if (!mp)
						      {
						      error =
						      clib_error_return (0,
									 "Not enough memory for mp %s",
									 mp_name);
						      goto err_handling;}

						      numa_data->sess_pool =
						      mp;
						      snprintf (mp_name, 128,
								"vcryptodev_sess_ppool_%u",
								numa);
						      mp =
						      rte_mempool_create
						      (mp_name,
						       CRYPTODEV_NB_SESSION,
						       sess_sz, 0, 0, NULL,
						       NULL, NULL, NULL, numa,
						       0); if (!mp)
						      {
						      error =
						      clib_error_return (0,
									 "Not enough memory for mp %s",
									 mp_name);
						      goto err_handling;}

						      numa_data->sess_priv_pool
						      = mp;}
		       ));

  cryptodev_probe (vm);

  if (n_workers > vec_len (cmt->cryptodev_inst))
    {
      error = clib_error_return (0, "Not enough crypto devs");
      goto err_handling;
    }

  vec_foreach_index (numa, cmt->per_thread_data)
  {
    cryptodev_engine_thread_t *cet = vec_elt_at_index (cmt->per_thread_data,
						       numa);
    cryptodev_inst_t *cit = vec_elt_at_index (cmt->cryptodev_inst, numa);

    cet->cryptodev_id = cit->dev_id;
    cet->cryptodev_q = cit->q_id;
    vec_validate_aligned (cet->ops, CRYPTODEV_BURST_SIZE * 2,
			  CLIB_CACHE_LINE_BYTES);
    cet->cur_op_idx = 0;
  }

  name = format (0, "DPDK Cryptodev Engine");
  eidx =
    vnet_crypto_register_engine (vm, "DPDK Cryptodev", 80, (char *) name);

  vnet_crypto_register_async_queue_handler (vm, eidx,
					    VNET_CRYPTO_OP_AES_128_CBC_ENC,
					    cryptodev_queue_cipher_encrypt);
  vnet_crypto_register_async_queue_handler (vm, eidx,
					    VNET_CRYPTO_OP_AES_128_CBC_DEC,
					    cryptodev_queue_cipher_decrypt);
  vnet_crypto_register_async_queue_handler (vm, eidx,
					    VNET_CRYPTO_OP_AES_192_CBC_ENC,
					    cryptodev_queue_cipher_encrypt);
  vnet_crypto_register_async_queue_handler (vm, eidx,
					    VNET_CRYPTO_OP_AES_192_CBC_DEC,
					    cryptodev_queue_cipher_decrypt);
  vnet_crypto_register_async_queue_handler (vm, eidx,
					    VNET_CRYPTO_OP_AES_256_CBC_ENC,
					    cryptodev_queue_cipher_encrypt);
  vnet_crypto_register_async_queue_handler (vm, eidx,
					    VNET_CRYPTO_OP_AES_256_CBC_DEC,
					    cryptodev_queue_cipher_decrypt);
  vnet_crypto_register_async_queue_handler (vm, eidx,
					    VNET_CRYPTO_OP_AES_128_CTR_ENC,
					    cryptodev_queue_cipher_encrypt);
  vnet_crypto_register_async_queue_handler (vm, eidx,
					    VNET_CRYPTO_OP_AES_128_CTR_DEC,
					    cryptodev_queue_cipher_decrypt);
  vnet_crypto_register_async_queue_handler (vm, eidx,
					    VNET_CRYPTO_OP_AES_192_CTR_ENC,
					    cryptodev_queue_cipher_encrypt);
  vnet_crypto_register_async_queue_handler (vm, eidx,
					    VNET_CRYPTO_OP_AES_192_CTR_DEC,
					    cryptodev_queue_cipher_decrypt);
  vnet_crypto_register_async_queue_handler (vm, eidx,
					    VNET_CRYPTO_OP_AES_256_CTR_ENC,
					    cryptodev_queue_cipher_encrypt);
  vnet_crypto_register_async_queue_handler (vm, eidx,
					    VNET_CRYPTO_OP_AES_256_CTR_DEC,
					    cryptodev_queue_cipher_decrypt);

  vnet_crypto_register_key_handler (vm, eidx, cryptodev_key_handler);
  cryptodev_enabled = 1;

  return 0;

err_handling:
  dpdk_disable_cryptodev_engine (vm);

  return error;
}

VLIB_INIT_FUNCTION (cryptodev_early_init) =
{
.runs_after = VLIB_INITS ("dpdk_init"),};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
