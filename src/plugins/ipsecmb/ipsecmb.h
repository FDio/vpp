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
  u8 trunc_size;
} ipsecmb_integ_alg_t;

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

typedef struct
{
  u8 aes_enc_key_expanded[16 * 15] __attribute__ ((aligned (16)));
  u8 aes_dec_key_expanded[16 * 15] __attribute__ ((aligned (16)));
  u8 ipad_hash[256] __attribute__ ((aligned (16)));
  u8 opad_hash[256] __attribute__ ((aligned (16)));
} ipsecmb_sa_t;

typedef struct
{
  ipsecmb_crypto_alg_t *crypto_algs;
  ipsecmb_integ_alg_t *integ_algs;
  MB_MGR **mb_mgr;
  funcs_t funcs;
  ipsecmb_sa_t *sad;
} ipsecmb_main_t;

extern ipsecmb_main_t ipsecmb_main;

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

#endif /* __included_ipsecmb_h__ */
