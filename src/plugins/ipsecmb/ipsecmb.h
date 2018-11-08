#ifndef __included_ipsecmb_h__
#define __included_ipsecmb_h__

#include <vppinfra/types.h>
#include <vppinfra/vec.h>
#include <vppinfra/clib.h>
#include <vppinfra/warnings.h>
#include <vnet/ipsec/ipsec.h>

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

typedef struct
{
  keyexp_t keyexp_fn;
  JOB_CIPHER_MODE cipher_mode;
  u8 key_len;
  u8 iv_size;
  u8 block_size;
} ipsecmb_crypto_alg_t;

typedef struct
{
  hash_one_block_t hash_one_block_fn;
  u8 block_size;
  JOB_HASH_ALG hash_alg;
  u8 hash_output_length;
} ipsecmb_integ_alg_t;

typedef struct
{
  u8 aes_enc_key_expanded[16 * 15] __attribute__ ((aligned (16)));
  u8 aes_dec_key_expanded[16 * 15] __attribute__ ((aligned (16)));
  u8 ipad_hash[256] __attribute__ ((aligned (16)));
  u8 opad_hash[256] __attribute__ ((aligned (16)));
} ipsecmb_sa_t;

typedef struct
{
  u8 data[16];
} random_bytes_t;

typedef u8 urandom_buffer_t[4096];

typedef struct
{
  /** read buffer for random data from /dev/urandom */
  urandom_buffer_t urandom_buffer;
  /** pool of all the random_bytes_t objects ever allocated */
  random_bytes_t *rb_pool;
  /** vector of random_bytes_t objects containing random bytes */
  u32 *rb_from_dev_urandom;
  /** vector of used random_bytes_t objects */
  u32 *rb_recycle_list;
  /** vector of random bytes collected from encrypted data */
  u32 *rb_from_traffic;
} ipsecmb_per_thread_data_t;

typedef struct
{
  ipsecmb_crypto_alg_t *crypto_algs;
  ipsecmb_integ_alg_t *integ_algs;
  MB_MGR **mb_mgr;
  ipsecmb_sa_t *sad;
  ipsecmb_per_thread_data_t *per_thread_data;
  int dev_urandom_fd;
} ipsecmb_main_t;

extern ipsecmb_main_t ipsecmb_main;

#define P(x,y) x ## _ ## y
#define E(x,y) P(x,y)
#define IPSECMB_FUNC(f) E(f,CLIB_MARCH_VARIANT)
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

#endif /* __included_ipsecmb_h__ */
