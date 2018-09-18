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
#include <vnet/feature/feature.h>

#define IPSEC_FLAG_IPSEC_GRE_TUNNEL (1 << 0)


#define foreach_ipsec_output_next                \
_(DROP, "error-drop")                            \
_(ESP_ENCRYPT, "esp-encrypt")                    \
_(AH_ENCRYPT, "ah-encrypt")

#define _(v, s) IPSEC_OUTPUT_NEXT_##v,
typedef enum
{
  foreach_ipsec_output_next
#undef _
    IPSEC_OUTPUT_N_NEXT,
} ipsec_output_next_t;


#define foreach_ipsec_input_next                \
_(DROP, "error-drop")                           \
_(ESP_DECRYPT, "esp-decrypt")                   \
_(AH_DECRYPT, "ah-decrypt")

#define _(v, s) IPSEC_INPUT_NEXT_##v,
typedef enum
{
  foreach_ipsec_input_next
#undef _
    IPSEC_INPUT_N_NEXT,
} ipsec_input_next_t;


#define foreach_ipsec_policy_action \
  _(0, BYPASS,  "bypass")          \
  _(1, DISCARD, "discard")         \
  _(2, RESOLVE, "resolve")         \
  _(3, PROTECT, "protect")

typedef enum
{
#define _(v,f,s) IPSEC_POLICY_ACTION_##f = v,
  foreach_ipsec_policy_action
#undef _
    IPSEC_POLICY_N_ACTION,
} ipsec_policy_action_t;

#define foreach_ipsec_crypto_alg \
  _(0, NONE,  "none")               \
  _(1, AES_CBC_128, "aes-cbc-128")  \
  _(2, AES_CBC_192, "aes-cbc-192")  \
  _(3, AES_CBC_256, "aes-cbc-256")  \
  _(4, AES_CTR_128, "aes-ctr-128")  \
  _(5, AES_CTR_192, "aes-ctr-192")  \
  _(6, AES_CTR_256, "aes-ctr-256")  \
  _(7, AES_GCM_128, "aes-gcm-128")  \
  _(8, AES_GCM_192, "aes-gcm-192")  \
  _(9, AES_GCM_256, "aes-gcm-256")  \
  _(10, DES_CBC, "des-cbc")         \
  _(11, 3DES_CBC, "3des-cbc")

typedef enum
{
#define _(v,f,s) IPSEC_CRYPTO_ALG_##f = v,
  foreach_ipsec_crypto_alg
#undef _
    IPSEC_CRYPTO_N_ALG,
} ipsec_crypto_alg_t;

#define foreach_ipsec_integ_alg \
  _(0, NONE,  "none")                                                     \
  _(1, MD5_96, "md5-96")           /* RFC2403 */                          \
  _(2, SHA1_96, "sha1-96")         /* RFC2404 */                          \
  _(3, SHA_256_96, "sha-256-96")   /* draft-ietf-ipsec-ciph-sha-256-00 */ \
  _(4, SHA_256_128, "sha-256-128") /* RFC4868 */                          \
  _(5, SHA_384_192, "sha-384-192") /* RFC4868 */                          \
  _(6, SHA_512_256, "sha-512-256")	/* RFC4868 */

typedef enum
{
#define _(v,f,s) IPSEC_INTEG_ALG_##f = v,
  foreach_ipsec_integ_alg
#undef _
    IPSEC_INTEG_N_ALG,
} ipsec_integ_alg_t;

typedef enum
{
  IPSEC_PROTOCOL_AH = 0,
  IPSEC_PROTOCOL_ESP = 1
} ipsec_protocol_t;

typedef struct
{
  u32 id;
  u32 spi;
  ipsec_protocol_t protocol;

  ipsec_crypto_alg_t crypto_alg;
  u8 crypto_key_len;
  u8 crypto_key[128];
#ifdef WITH_IPSEC_MB
  u8 aes_enc_key_expanded[16*15] __attribute__((aligned(16)));
  u8 aes_dec_key_expanded[16*15] __attribute__((aligned(16)));
  u8 ipad_hash[256] __attribute__((aligned(16)));
  u8 opad_hash[256] __attribute__((aligned(16)));
#endif

  ipsec_integ_alg_t integ_alg;
  u8 integ_key_len;
  u8 integ_key[128];

  u8 use_esn;
  u8 use_anti_replay;

  u8 is_tunnel;
  u8 is_tunnel_ip6;
  u8 udp_encap;
  ip46_address_t tunnel_src_addr;
  ip46_address_t tunnel_dst_addr;

  u32 salt;

  /* runtime */
  u32 seq;
  u32 seq_hi;
  u32 last_seq;
  u32 last_seq_hi;
  u64 replay_window;

  /*lifetime data */
  u64 total_data_size;
} ipsec_sa_t;

typedef struct
{
  ip46_address_t start, stop;
} ip46_address_range_t;

typedef struct
{
  u16 start, stop;
} port_range_t;

typedef struct
{
  u8 is_add;
  u8 esn;
  u8 anti_replay;
  ip4_address_t local_ip, remote_ip;
  u32 local_spi;
  u32 remote_spi;
  ipsec_crypto_alg_t crypto_alg;
  u8 local_crypto_key_len;
  u8 local_crypto_key[128];
  u8 remote_crypto_key_len;
  u8 remote_crypto_key[128];
  ipsec_integ_alg_t integ_alg;
  u8 local_integ_key_len;
  u8 local_integ_key[128];
  u8 remote_integ_key_len;
  u8 remote_integ_key[128];
  u8 renumber;
  u32 show_instance;
  u8 udp_encap;
} ipsec_add_del_tunnel_args_t;

typedef struct
{
  u8 is_add;
  u32 local_sa_id;
  u32 remote_sa_id;
  ip4_address_t local_ip;
  ip4_address_t remote_ip;
} ipsec_add_del_ipsec_gre_tunnel_args_t;

typedef enum
{
  IPSEC_IF_SET_KEY_TYPE_NONE,
  IPSEC_IF_SET_KEY_TYPE_LOCAL_CRYPTO,
  IPSEC_IF_SET_KEY_TYPE_REMOTE_CRYPTO,
  IPSEC_IF_SET_KEY_TYPE_LOCAL_INTEG,
  IPSEC_IF_SET_KEY_TYPE_REMOTE_INTEG,
} ipsec_if_set_key_type_t;

typedef struct
{
  u32 id;
  i32 priority;
  u8 is_outbound;

  // Selector
  u8 is_ipv6;
  ip46_address_range_t laddr;
  ip46_address_range_t raddr;
  u8 protocol;
  port_range_t lport;
  port_range_t rport;

  // Policy
  u8 policy;
  u32 sa_id;
  u32 sa_index;

  // Counter
  vlib_counter_t counter;
} ipsec_policy_t;

typedef struct
{
  u32 id;
  /* pool of policies */
  ipsec_policy_t *policies;
  /* vectors of policy indices */
  u32 *ipv4_outbound_policies;
  u32 *ipv6_outbound_policies;
  u32 *ipv4_inbound_protect_policy_indices;
  u32 *ipv4_inbound_policy_discard_and_bypass_indices;
  u32 *ipv6_inbound_protect_policy_indices;
  u32 *ipv6_inbound_policy_discard_and_bypass_indices;
} ipsec_spd_t;

typedef struct
{
  u32 spd_index;
} ip4_ipsec_config_t;

typedef struct
{
  u32 spd_index;
} ip6_ipsec_config_t;

typedef struct
{
  /* Required for pool_get_aligned */
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  u32 input_sa_index;
  u32 output_sa_index;
  u32 hw_if_index;
  u32 show_instance;
} ipsec_tunnel_if_t;

typedef struct
{
  clib_error_t *(*add_del_sa_sess_cb) (u32 sa_index, u8 is_add);
  clib_error_t *(*check_support_cb) (ipsec_sa_t * sa);
} ipsec_main_callbacks_t;


#ifdef WITH_IPSEC_MB
#include <vppinfra/warnings.h>
WARN_OFF (attributes);

#ifdef always_inline
#undef always_inline
#define __need_redefine__
#endif

#include <intel-ipsec-mb.h>

#ifdef __need_redefine__
#if CLIB_DEBUG > 0
#define always_inline static inline
#else
#define always_inline static inline __attribute__ ((__always_inline__))
#endif
#endif // __need_redefine__

WARN_ON (attributes);
#else
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#endif

#include <vppinfra/types.h>
#include <vppinfra/cache.h>

typedef struct
{
#ifdef WITH_IPSEC_MB
  keyexp_t keyexp_fn;
  JOB_CIPHER_MODE cipher_mode;
  u8 key_len;
#else
  const EVP_CIPHER *type;
#endif
  u8 iv_size;
  u8 block_size;
} ipsec_proto_main_crypto_alg_t;

typedef struct
{
#ifdef WITH_IPSEC_MB
  hash_fn_t hash_fn;
  hash_one_block_t hash_one_block_fn;
  u8 block_size;
  JOB_HASH_ALG hash_alg;
#else
  const EVP_MD *md;
#endif
  u8 trunc_size;
} ipsec_proto_main_integ_alg_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
#ifdef WITH_IPSEC_MB
#elif OPENSSL_VERSION_NUMBER >= 0x10100000L
  EVP_CIPHER_CTX *encrypt_ctx;
#else
  EVP_CIPHER_CTX encrypt_ctx;
#endif
    CLIB_CACHE_LINE_ALIGN_MARK (cacheline1);
#ifdef WITH_IPSEC_MB
#elif OPENSSL_VERSION_NUMBER >= 0x10100000L
  EVP_CIPHER_CTX *decrypt_ctx;
#else
  EVP_CIPHER_CTX decrypt_ctx;
#endif
    CLIB_CACHE_LINE_ALIGN_MARK (cacheline2);
#ifdef WITH_IPSEC_MB
#elif OPENSSL_VERSION_NUMBER >= 0x10100000L
  HMAC_CTX *hmac_ctx;
#else
  HMAC_CTX hmac_ctx;
#endif
  ipsec_crypto_alg_t last_encrypt_alg;
  ipsec_crypto_alg_t last_decrypt_alg;
  ipsec_integ_alg_t last_integ_alg;
} ipsec_proto_main_per_thread_data_t;

typedef struct
{
  ipsec_proto_main_crypto_alg_t *ipsec_proto_main_crypto_algs;
  ipsec_proto_main_integ_alg_t *ipsec_proto_main_integ_algs;
  ipsec_proto_main_per_thread_data_t *per_thread_data;
} ipsec_proto_main_t;

extern ipsec_proto_main_t ipsec_proto_main;

always_inline void
ipsec_proto_init ()
{
  ipsec_proto_main_t *em = &ipsec_proto_main;
  vlib_thread_main_t *tm = vlib_get_thread_main ();

  memset (em, 0, sizeof (em[0]));

  vec_validate (em->ipsec_proto_main_crypto_algs, IPSEC_CRYPTO_N_ALG - 1);
  vec_validate (em->ipsec_proto_main_integ_algs, IPSEC_INTEG_N_ALG - 1);
  ipsec_proto_main_integ_alg_t *i;
  em->ipsec_proto_main_crypto_algs[IPSEC_CRYPTO_ALG_AES_CBC_128].block_size =
    16;
  em->ipsec_proto_main_crypto_algs[IPSEC_CRYPTO_ALG_AES_CBC_192].block_size =
    16;
  em->ipsec_proto_main_crypto_algs[IPSEC_CRYPTO_ALG_AES_CBC_256].block_size =
    16;
  em->ipsec_proto_main_crypto_algs[IPSEC_CRYPTO_ALG_DES_CBC].block_size = 8;
  em->ipsec_proto_main_crypto_algs[IPSEC_CRYPTO_ALG_3DES_CBC].block_size = 8;
  em->ipsec_proto_main_crypto_algs[IPSEC_CRYPTO_ALG_AES_CBC_128].iv_size = 16;
  em->ipsec_proto_main_crypto_algs[IPSEC_CRYPTO_ALG_AES_CBC_192].iv_size = 16;
  em->ipsec_proto_main_crypto_algs[IPSEC_CRYPTO_ALG_AES_CBC_256].iv_size = 16;
  em->ipsec_proto_main_crypto_algs[IPSEC_CRYPTO_ALG_DES_CBC].iv_size = 8;
  em->ipsec_proto_main_crypto_algs[IPSEC_CRYPTO_ALG_3DES_CBC].iv_size = 8;
#ifdef WITH_IPSEC_MB
  em->ipsec_proto_main_crypto_algs[IPSEC_CRYPTO_ALG_AES_CBC_128].cipher_mode =
    CBC;
  em->ipsec_proto_main_crypto_algs[IPSEC_CRYPTO_ALG_AES_CBC_192].cipher_mode =
    CBC;
  em->ipsec_proto_main_crypto_algs[IPSEC_CRYPTO_ALG_AES_CBC_256].cipher_mode =
    CBC;
  i = &em->ipsec_proto_main_integ_algs[IPSEC_INTEG_ALG_SHA1_96];
  i->hash_alg = SHA1;
  i->block_size = SHA1_BLOCK_SIZE;

  i = &em->ipsec_proto_main_integ_algs[IPSEC_INTEG_ALG_SHA_256_96];
  i->hash_alg = SHA_256;
  i->block_size = SHA_256_BLOCK_SIZE;

  i = &em->ipsec_proto_main_integ_algs[IPSEC_INTEG_ALG_SHA_256_128];
  i->hash_alg = SHA_256;
  i->block_size = SHA_256_BLOCK_SIZE;

  i = &em->ipsec_proto_main_integ_algs[IPSEC_INTEG_ALG_SHA_384_192];
  i->hash_alg = SHA_384;
  i->block_size = SHA_384_BLOCK_SIZE;

  i = &em->ipsec_proto_main_integ_algs[IPSEC_INTEG_ALG_SHA_512_256];
  i->hash_alg = SHA_512;
  i->block_size = SHA_512_BLOCK_SIZE;
#define __set_funcs(arch)                                                    \
  do{\
  em->ipsec_proto_main_crypto_algs[IPSEC_CRYPTO_ALG_AES_CBC_128].keyexp_fn = \
      aes_keyexp_128_##arch;\
  em->ipsec_proto_main_crypto_algs[IPSEC_CRYPTO_ALG_AES_CBC_192].keyexp_fn = \
      aes_keyexp_192_##arch;\
  em->ipsec_proto_main_crypto_algs[IPSEC_CRYPTO_ALG_AES_CBC_256].keyexp_fn = \
      aes_keyexp_256_##arch;\
  em->ipsec_proto_main_integ_algs[IPSEC_INTEG_ALG_SHA1_96].hash_fn = \
      sha1_##arch;\
  em->ipsec_proto_main_integ_algs[IPSEC_INTEG_ALG_SHA_256_96].hash_fn = \
      sha256_##arch;\
  em->ipsec_proto_main_integ_algs[IPSEC_INTEG_ALG_SHA_256_128].hash_fn = \
      sha256_##arch;\
  em->ipsec_proto_main_integ_algs[IPSEC_INTEG_ALG_SHA_384_192].hash_fn = \
      sha384_##arch;\
  em->ipsec_proto_main_integ_algs[IPSEC_INTEG_ALG_SHA_512_256].hash_fn = \
      sha512_##arch;\
  em->ipsec_proto_main_integ_algs[IPSEC_INTEG_ALG_SHA1_96].hash_one_block_fn = \
      sha1_one_block_##arch;\
  em->ipsec_proto_main_integ_algs[IPSEC_INTEG_ALG_SHA_256_96].hash_one_block_fn = \
      sha256_one_block_##arch;\
  em->ipsec_proto_main_integ_algs[IPSEC_INTEG_ALG_SHA_256_128].hash_one_block_fn = \
      sha256_one_block_##arch;\
  em->ipsec_proto_main_integ_algs[IPSEC_INTEG_ALG_SHA_384_192].hash_one_block_fn = \
      sha384_one_block_##arch;\
  em->ipsec_proto_main_integ_algs[IPSEC_INTEG_ALG_SHA_512_256].hash_one_block_fn = \
      sha512_one_block_##arch;\
  }while(0);

  if (clib_cpu_supports_avx512f ())
    {
      __set_funcs (avx512);
    }
  else if (clib_cpu_supports_avx2 ())
    {
      __set_funcs (avx2);
    }
  else
    {
      __set_funcs (sse);
    }
#undef __set_funcs
#else
  em->ipsec_proto_main_crypto_algs[IPSEC_CRYPTO_ALG_AES_CBC_128].type =
    EVP_aes_128_cbc ();
  em->ipsec_proto_main_crypto_algs[IPSEC_CRYPTO_ALG_AES_CBC_192].type =
    EVP_aes_192_cbc ();
  em->ipsec_proto_main_crypto_algs[IPSEC_CRYPTO_ALG_AES_CBC_256].type =
    EVP_aes_256_cbc ();
  em->ipsec_proto_main_crypto_algs[IPSEC_CRYPTO_ALG_DES_CBC].type =
    EVP_des_cbc ();
  em->ipsec_proto_main_crypto_algs[IPSEC_CRYPTO_ALG_3DES_CBC].type =
    EVP_des_ede3_cbc ();

  i = &em->ipsec_proto_main_integ_algs[IPSEC_INTEG_ALG_SHA1_96];
  i->md = EVP_sha1 ();

  i = &em->ipsec_proto_main_integ_algs[IPSEC_INTEG_ALG_SHA_256_96];
  i->md = EVP_sha256 ();

  i = &em->ipsec_proto_main_integ_algs[IPSEC_INTEG_ALG_SHA_256_128];
  i->md = EVP_sha256 ();

  i = &em->ipsec_proto_main_integ_algs[IPSEC_INTEG_ALG_SHA_384_192];
  i->md = EVP_sha384 ();

  i = &em->ipsec_proto_main_integ_algs[IPSEC_INTEG_ALG_SHA_512_256];
  i->md = EVP_sha512 ();
#endif

  i = &em->ipsec_proto_main_integ_algs[IPSEC_INTEG_ALG_SHA1_96];
  i->trunc_size = 12;

  i = &em->ipsec_proto_main_integ_algs[IPSEC_INTEG_ALG_SHA_256_96];
  i->trunc_size = 12;

  i = &em->ipsec_proto_main_integ_algs[IPSEC_INTEG_ALG_SHA_256_128];
  i->trunc_size = 16;

  i = &em->ipsec_proto_main_integ_algs[IPSEC_INTEG_ALG_SHA_384_192];
  i->trunc_size = 24;

  i = &em->ipsec_proto_main_integ_algs[IPSEC_INTEG_ALG_SHA_512_256];
  i->trunc_size = 32;

  vec_validate_aligned (em->per_thread_data, tm->n_vlib_mains - 1,
			CLIB_CACHE_LINE_BYTES);
  int thread_id;

  for (thread_id = 0; thread_id < tm->n_vlib_mains; thread_id++)
    {
#ifdef WITH_IPSEC_MB
      /* nothing to do here */
#elif OPENSSL_VERSION_NUMBER >= 0x10100000L
      em->per_thread_data[thread_id].encrypt_ctx = EVP_CIPHER_CTX_new ();
      em->per_thread_data[thread_id].decrypt_ctx = EVP_CIPHER_CTX_new ();
      em->per_thread_data[thread_id].hmac_ctx = HMAC_CTX_new ();
#else
      EVP_CIPHER_CTX_init (&(em->per_thread_data[thread_id].encrypt_ctx));
      EVP_CIPHER_CTX_init (&(em->per_thread_data[thread_id].decrypt_ctx));
      HMAC_CTX_init (&(em->per_thread_data[thread_id].hmac_ctx));
#endif
    }
}

#ifdef WITH_IPSEC_MB
typedef struct
{
  init_mb_mgr_t init_mb_mgr;
  get_next_job_t get_next_job;
  submit_job_t submit_job;
  submit_job_t submit_job_nocheck;
  get_completed_job_t get_completed_job;
  queue_size_t queue_size;
  flush_job_t flush_job;
} funcs_t;
#endif

typedef struct
{
  /* pool of tunnel instances */
  ipsec_spd_t *spds;
  ipsec_sa_t *sad;

  /* pool of tunnel interfaces */
  ipsec_tunnel_if_t *tunnel_interfaces;
  u32 *free_tunnel_if_indices;

#ifdef WITH_IPSEC_MB
  MB_MGR **mb_mgr;
  funcs_t funcs;
#else
  u32 **empty_buffers;
#endif

  uword *tunnel_index_by_key;

  /* convenience */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;

  /* next node indices */
  u32 feature_next_node_index[32];

  /* hashes */
  uword *spd_index_by_spd_id;
  uword *spd_index_by_sw_if_index;
  uword *sa_index_by_sa_id;
  uword *ipsec_if_pool_index_by_key;
  uword *ipsec_if_real_dev_by_show_dev;

  /* node indeces */
  u32 error_drop_node_index;
  u32 esp_encrypt_node_index;
  u32 esp_decrypt_node_index;
  u32 ah_encrypt_node_index;
  u32 ah_decrypt_node_index;
  /* next node indeces */
  u32 esp_encrypt_next_index;
  u32 esp_decrypt_next_index;
  u32 ah_encrypt_next_index;
  u32 ah_decrypt_next_index;

  /* callbacks */
  ipsec_main_callbacks_t cb;

  /* helper for sort function */
  ipsec_spd_t *spd_to_sort;
} ipsec_main_t;

extern ipsec_main_t ipsec_main;

extern vlib_node_registration_t esp_encrypt_node;
extern vlib_node_registration_t esp_decrypt_node;
extern vlib_node_registration_t ah_encrypt_node;
extern vlib_node_registration_t ah_decrypt_node;
extern vlib_node_registration_t ipsec_if_input_node;


/*
 * functions
 */
int ipsec_set_interface_spd (vlib_main_t * vm, u32 sw_if_index, u32 spd_id,
			     int is_add);
int ipsec_add_del_spd (vlib_main_t * vm, u32 spd_id, int is_add);
int ipsec_add_del_policy (vlib_main_t * vm, ipsec_policy_t * policy,
			  int is_add);
int ipsec_add_del_sa (vlib_main_t * vm, ipsec_sa_t * new_sa, int is_add);
int ipsec_set_sa_key (vlib_main_t * vm, ipsec_sa_t * sa_update);

u32 ipsec_get_sa_index_by_sa_id (u32 sa_id);
u8 ipsec_is_sa_used (u32 sa_index);
u8 *format_ipsec_policy_action (u8 * s, va_list * args);
u8 *format_ipsec_crypto_alg (u8 * s, va_list * args);
u8 *format_ipsec_integ_alg (u8 * s, va_list * args);
u8 *format_ipsec_replay_window (u8 * s, va_list * args);
uword unformat_ipsec_policy_action (unformat_input_t * input, va_list * args);
uword unformat_ipsec_crypto_alg (unformat_input_t * input, va_list * args);
uword unformat_ipsec_integ_alg (unformat_input_t * input, va_list * args);

int ipsec_add_del_tunnel_if_internal (vnet_main_t * vnm,
				      ipsec_add_del_tunnel_args_t * args,
				      u32 * sw_if_index);
int ipsec_add_del_tunnel_if (ipsec_add_del_tunnel_args_t * args);
int ipsec_add_del_ipsec_gre_tunnel (vnet_main_t * vnm,
				    ipsec_add_del_ipsec_gre_tunnel_args_t *
				    args);
int ipsec_set_interface_key (vnet_main_t * vnm, u32 hw_if_index,
			     ipsec_if_set_key_type_t type, u8 alg, u8 * key);
int ipsec_set_interface_sa (vnet_main_t * vnm, u32 hw_if_index, u32 sa_id,
			    u8 is_outbound);


#ifdef WITH_IPSEC_MB
int sa_expand_keys_ipsec_mb (ipsec_sa_t * sa);
#else
/*
 *  inline functions
 */
always_inline void
ipsec_alloc_empty_buffers (vlib_main_t * vm, ipsec_main_t * im)
{
  u32 thread_index = vm->thread_index;
  uword l = vec_len (im->empty_buffers[thread_index]);
  uword n_alloc = 0;

  if (PREDICT_FALSE (l < VLIB_FRAME_SIZE))
    {
      if (!im->empty_buffers[thread_index])
	{
	  vec_alloc (im->empty_buffers[thread_index], 2 * VLIB_FRAME_SIZE);
	}

      n_alloc = vlib_buffer_alloc (vm, im->empty_buffers[thread_index] + l,
				   2 * VLIB_FRAME_SIZE - l);

      _vec_len (im->empty_buffers[thread_index]) = l + n_alloc;
    }
}
#endif

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

#endif /* __IPSEC_H__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
