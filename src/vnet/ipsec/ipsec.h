/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
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
#ifndef __IPSEC_H__
#define __IPSEC_H__

#include <vnet/ip/ip.h>
#include <vnet/crypto/crypto.h>
#include <vnet/feature/feature.h>

#include <vppinfra/types.h>
#include <vppinfra/cache.h>

#include <vnet/ipsec/ipsec_spd.h>
#include <vnet/ipsec/ipsec_spd_policy.h>
#include <vnet/ipsec/ipsec_sa.h>

#include <vppinfra/bihash_8_16.h>

#include <vppinfra/bihash_24_16.h>

#include <vppinfra/pcg.h>

typedef clib_error_t *(*add_del_sa_sess_cb_t) (u32 sa_index, u8 is_add);
typedef clib_error_t *(*check_support_cb_t) (ipsec_sa_t * sa);
typedef clib_error_t *(*enable_disable_cb_t) (int is_enable);

typedef struct
{
  u64 key[2];
  u64 value;
  i32 bucket_lock;
  u32 un_used;
} ipsec4_hash_kv_16_8_t;

typedef union
{
  struct
  {
    ip4_address_t ip4_addr[2];
    u16 port[2];
    u8 proto;
    u8 pad[3];
  };
  ipsec4_hash_kv_16_8_t kv_16_8;
} ipsec4_spd_5tuple_t;

typedef struct
{
  u8 *name;
  /* add/del callback */
  add_del_sa_sess_cb_t add_del_sa_sess_cb;
  /* check support function */
  check_support_cb_t check_support_cb;
  u32 ah4_encrypt_node_index;
  u32 ah4_decrypt_node_index;
  u32 ah4_encrypt_next_index;
  u32 ah4_decrypt_next_index;
  u32 ah6_encrypt_node_index;
  u32 ah6_decrypt_node_index;
  u32 ah6_encrypt_next_index;
  u32 ah6_decrypt_next_index;
} ipsec_ah_backend_t;

typedef struct
{
  u8 *name;
  /* add/del callback */
  add_del_sa_sess_cb_t add_del_sa_sess_cb;
  /* check support function */
  check_support_cb_t check_support_cb;
  /* enable or disable function */
  enable_disable_cb_t enable_disable_cb;
  u32 esp4_encrypt_node_index;
  u32 esp4_decrypt_node_index;
  u32 esp4_encrypt_next_index;
  u32 esp4_decrypt_next_index;
  u32 esp6_encrypt_node_index;
  u32 esp6_decrypt_node_index;
  u32 esp6_encrypt_next_index;
  u32 esp6_decrypt_next_index;
  u32 esp4_decrypt_tun_node_index;
  u32 esp4_decrypt_tun_next_index;
  u32 esp4_encrypt_tun_node_index;
  u32 esp6_decrypt_tun_node_index;
  u32 esp6_decrypt_tun_next_index;
  u32 esp6_encrypt_tun_node_index;
  u32 esp_mpls_encrypt_tun_node_index;
} ipsec_esp_backend_t;

typedef struct
{
  vnet_crypto_op_id_t enc_op_id;
  vnet_crypto_op_id_t dec_op_id;
  vnet_crypto_alg_t alg;
  u8 iv_size;
  u8 block_align;
  u8 icv_size;
} ipsec_main_crypto_alg_t;

typedef struct
{
  vnet_crypto_op_id_t op_id;
  vnet_crypto_alg_t alg;
  u8 icv_size;
} ipsec_main_integ_alg_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  clib_pcg64i_random_t iv_prng;
  vnet_crypto_op_t *crypto_ops;
  vnet_crypto_op_t *integ_ops;
  vnet_crypto_op_t *chained_crypto_ops;
  vnet_crypto_op_t *chained_integ_ops;
  vnet_crypto_op_chunk_t *chunks;
  vnet_crypto_async_frame_t **async_frames;
} ipsec_per_thread_data_t;

typedef struct
{
  /* pool of tunnel instances */
  ipsec_spd_t *spds;
  /* pool of policies */
  ipsec_policy_t *policies;

  /* hash tables of UDP port registrations */
  uword *udp_port_registrations;

  uword *tunnel_index_by_key;

  /* convenience */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;

  /* hashes */
  uword *spd_index_by_spd_id;
  uword *spd_index_by_sw_if_index;
  uword *sa_index_by_sa_id;
  uword *ipsec4_if_pool_index_by_key;
  uword *ipsec6_if_pool_index_by_key;
  uword *ipsec_if_real_dev_by_show_dev;
  uword *ipsec_if_by_sw_if_index;

  ipsec4_hash_kv_16_8_t *ipsec4_out_spd_hash_tbl;
  clib_bihash_8_16_t tun4_protect_by_key;
  clib_bihash_24_16_t tun6_protect_by_key;

  /* node indices */
  u32 error_drop_node_index;
  u32 esp4_encrypt_node_index;
  u32 esp4_decrypt_node_index;
  u32 esp4_decrypt_tun_node_index;
  u32 esp4_encrypt_tun_node_index;
  u32 ah4_encrypt_node_index;
  u32 ah4_decrypt_node_index;
  u32 esp6_encrypt_node_index;
  u32 esp6_decrypt_node_index;
  u32 esp6_decrypt_tun_node_index;
  u32 esp6_encrypt_tun_node_index;
  u32 esp_mpls_encrypt_tun_node_index;
  u32 ah6_encrypt_node_index;
  u32 ah6_decrypt_node_index;
  /* next node indices */
  u32 esp4_encrypt_next_index;
  u32 esp4_decrypt_next_index;
  u32 esp4_decrypt_tun_next_index;
  u32 ah4_encrypt_next_index;
  u32 ah4_decrypt_next_index;
  u32 esp6_encrypt_next_index;
  u32 esp6_decrypt_next_index;
  u32 esp6_decrypt_tun_next_index;
  u32 ah6_encrypt_next_index;
  u32 ah6_decrypt_next_index;

  /* pool of ah backends */
  ipsec_ah_backend_t *ah_backends;
  /* pool of esp backends */
  ipsec_esp_backend_t *esp_backends;
  /* index of current ah backend */
  u32 ah_current_backend;
  /* index of current esp backend */
  u32 esp_current_backend;
  /* index of default ah backend */
  u32 ah_default_backend;
  /* index of default esp backend */
  u32 esp_default_backend;

  /* crypto alg data */
  ipsec_main_crypto_alg_t *crypto_algs;

  /* crypto integ data */
  ipsec_main_integ_alg_t *integ_algs;

  /* per-thread data */
  ipsec_per_thread_data_t *ptd;

  /** Worker handoff */
  u32 ah4_enc_fq_index;
  u32 ah4_dec_fq_index;
  u32 ah6_enc_fq_index;
  u32 ah6_dec_fq_index;

  u32 esp4_enc_fq_index;
  u32 esp4_dec_fq_index;
  u32 esp6_enc_fq_index;
  u32 esp6_dec_fq_index;
  u32 esp4_enc_tun_fq_index;
  u32 esp6_enc_tun_fq_index;
  u32 esp_mpls_enc_tun_fq_index;
  u32 esp4_dec_tun_fq_index;
  u32 esp6_dec_tun_fq_index;

  /* Number of buckets for flow cache */
  u32 ipsec4_out_spd_hash_num_buckets;
  u32 ipsec4_out_spd_flow_cache_entries;
  u32 epoch_count;
  u8 async_mode;
  u16 msg_id_base;
  u8 flow_cache_flag;
} ipsec_main_t;

typedef enum ipsec_format_flags_t_
{
  IPSEC_FORMAT_BRIEF = 0,
  IPSEC_FORMAT_DETAIL = (1 << 0),
  IPSEC_FORMAT_INSECURE = (1 << 1),
} ipsec_format_flags_t;

extern ipsec_main_t ipsec_main;

clib_error_t *ipsec_add_del_sa_sess_cb (ipsec_main_t * im, u32 sa_index,
					u8 is_add);

clib_error_t *ipsec_check_support_cb (ipsec_main_t * im, ipsec_sa_t * sa);

extern vlib_node_registration_t ipsec4_tun_input_node;
extern vlib_node_registration_t ipsec6_tun_input_node;

/*
 * functions
 */

/*
 *  inline functions
 */

static_always_inline u32
get_next_output_feature_node_index (vlib_buffer_t * b,
				    vlib_node_runtime_t * nr)
{
  u32 next;
  vlib_main_t *vm = vlib_get_main ();
  vlib_node_t *node = vlib_get_node (vm, nr->node_index);

  vnet_feature_next (&next, b);
  return node->next_nodes[next];
}

static_always_inline u64
ipsec4_hash_16_8 (ipsec4_hash_kv_16_8_t *v)
{
#ifdef clib_crc32c_uses_intrinsics
  return clib_crc32c ((u8 *) v->key, 16);
#else
  u64 tmp = v->key[0] ^ v->key[1];
  return clib_xxhash (tmp);
#endif
}

static_always_inline int
ipsec4_hash_key_compare_16_8 (u64 *a, u64 *b)
{
#if defined(CLIB_HAVE_VEC128) && defined(CLIB_HAVE_VEC128_UNALIGNED_LOAD_STORE)
  u64x2 v;
  v = u64x2_load_unaligned (a) ^ u64x2_load_unaligned (b);
  return u64x2_is_all_zero (v);
#else
  return ((a[0] ^ b[0]) | (a[1] ^ b[1])) == 0;
#endif
}

/* clib_spinlock_lock is not used to save another memory indirection */
static_always_inline void
ipsec_spinlock_lock (i32 *lock)
{
  i32 free = 0;
  while (!clib_atomic_cmp_and_swap_acq_relax_n (lock, &free, 1, 0))
    {
      /* atomic load limits number of compare_exchange executions */
      while (clib_atomic_load_relax_n (lock))
	CLIB_PAUSE ();
      /* on failure, compare_exchange writes lock into free */
      free = 0;
    }
}

static_always_inline void
ipsec_spinlock_unlock (i32 *lock)
{
  /* Make sure all reads/writes are complete before releasing the lock */
  clib_atomic_release (lock);
}

u32 ipsec_register_ah_backend (vlib_main_t * vm, ipsec_main_t * im,
			       const char *name,
			       const char *ah4_encrypt_node_name,
			       const char *ah4_decrypt_node_name,
			       const char *ah6_encrypt_node_name,
			       const char *ah6_decrypt_node_name,
			       check_support_cb_t ah_check_support_cb,
			       add_del_sa_sess_cb_t ah_add_del_sa_sess_cb);

u32 ipsec_register_esp_backend (
  vlib_main_t *vm, ipsec_main_t *im, const char *name,
  const char *esp4_encrypt_node_name, const char *esp4_encrypt_tun_node_name,
  const char *esp4_decrypt_node_name, const char *esp4_decrypt_tun_node_name,
  const char *esp6_encrypt_node_name, const char *esp6_encrypt_tun_node_name,
  const char *esp6_decrypt_node_name, const char *esp6_decrypt_tun_node_name,
  const char *esp_mpls_encrypt_tun_node_name,
  check_support_cb_t esp_check_support_cb,
  add_del_sa_sess_cb_t esp_add_del_sa_sess_cb,
  enable_disable_cb_t enable_disable_cb);

int ipsec_select_ah_backend (ipsec_main_t * im, u32 ah_backend_idx);
int ipsec_select_esp_backend (ipsec_main_t * im, u32 esp_backend_idx);

clib_error_t *ipsec_rsc_in_use (ipsec_main_t * im);
void ipsec_set_async_mode (u32 is_enabled);

extern void ipsec_register_udp_port (u16 udp_port);
extern void ipsec_unregister_udp_port (u16 udp_port);

#endif /* __IPSEC_H__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
