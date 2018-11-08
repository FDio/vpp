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

typedef enum
{
  IMB_ERR_OK = 0,
  IMB_ERR_DECRYPTION_FAILED,
  IMB_ERR_ENCRYPTION_FAILED,
  IMB_ERR_INTEG_ERROR,
  IMB_ERR_SEQ_CYCLED,
  IMB_ERR_REPLAY,
  IMB_ERR_NOT_IP,
  IMB_ERR_NO_BUF,
} ipsecmb_error_e;

u8 *format_ipsecmb_error (u8 * s, va_list * args);
u8 *format_ipsecmb_sts (u8 * s, va_list * args);

typedef struct
{
  u32 spi;
  u32 seq;
  u8 udp_encap;
  ipsec_crypto_alg_t crypto_alg;
  ipsec_integ_alg_t integ_alg;
  ipsecmb_error_e error;
  JOB_STS sts;
  u32 data_len;
  u32 crypto_len;
  u32 hash_len;
} ipsecmb_esp_trace_t;

typedef struct
{
  /** buffer (chain), which this job works with */
  vlib_buffer_t *b;
  /** vector used for storing temp copy of packet data for buffer chains */
  u8 *data;
  /** source - might point to packet_data or (inside) vlib_buffer->data */
  u8 *src;
  /** data length of this job */
  u32 data_len;
  u32 msg_len_to_hash_in_bytes;
  u32 hash_start_src_offset_in_bytes;
  u32 icv_output_len_in_bytes;
  /** where to put calculated integrity check value */
  void *icv_dst;
  /** vector used for storing incoming integrity check value for comparison */
  u8 *icv;
  u32 msg_len_to_cipher_in_bytes;
  u32 cipher_start_src_offset_in_bytes;
  u8 *cipher_dst;
  void *iv;
  u8 iv_len_in_bytes;
  u32 next;
  u8 tos;
  u8 ttl;
  u32 ip_version_traffic_class_and_flow_label;
  u8 hop_limit;
  ipsecmb_error_e error;
  JOB_STS sts;
  JOB_HASH_ALG hash_alg;
  JOB_CIPHER_MODE cipher_mode;
  ipsec_sa_t *sa;
  ipsecmb_sa_t *samb;
} ipsecmb_job_desc_t;

typedef struct
{
  MB_MGR *mb_mgr;
  /** read buffer for random data from /dev/urandom */
  urandom_buffer_t urandom_buffer;
  /** pool of all the random_bytes_t objects ever allocated */
  random_bytes_t *rb_pool;
  /** vector of random_bytes_t objects containing random bytes */
  u32 *rb_from_dev_urandom;
  /** vector of used random_bytes_t objects */
  u32 *rb_recycle_list;
  /** job descriptors */
  ipsecmb_job_desc_t jobs[VLIB_FRAME_SIZE];
} ipsecmb_per_thread_data_t;

typedef struct
{
  ipsecmb_crypto_alg_t *crypto_algs;
  ipsecmb_integ_alg_t *integ_algs;
  ipsecmb_sa_t *sad;
  ipsecmb_per_thread_data_t *per_thread_data;
  int dev_urandom_fd;
} ipsecmb_main_t;

extern ipsecmb_main_t ipsecmb_main;

#define P(x,y) x ## _ ## y
#define E(x,y) P(x,y)
#define IPSECMB_FUNC(f) E(f,CLIB_MARCH_VARIANT)

always_inline void
ipsecmb_postprocess_job (JOB_AES_HMAC * imb_job, u32 next_index_drop,
			 int is_encrypt)
{
  ipsec_job_desc_t *job = imb_job->user_data;
  if (STS_COMPLETED != imb_job->status)
    {
      job->error = IPSEC_ERR_CIPHERING_FAILED;
      job->next = next_index_drop;
    }
  else if (!is_encrypt && job->msg_len_to_hash_in_bytes &&
	   memcmp (job->icv_dst, job->icv, job->icv_output_len_in_bytes))
    {
      job->next = next_index_drop;
      job->error = IPSEC_ERR_INTEG_ERROR;
    }
}

always_inline void
ipsecmb_process_job (vlib_main_t * vm, ipsec_main_t * im,
		     ipsecmb_main_t * imbm, MB_MGR * mgr,
		     ipsec_job_desc_t * job, int is_encrypt,
		     get_next_job_t get_next_job, submit_job_t submit_job,
		     int is_ip6, u32 next_index_drop)
{
  JOB_AES_HMAC *imb_job = get_next_job (mgr);
  ipsecmb_sa_t *samb = pool_elt_at_index (imbm->sad, job->sa - im->sad);
  imb_job->src = job->src;
  imb_job->dst = job->cipher_dst;
  imb_job->hash_start_src_offset_in_bytes = 0;
  imb_job->msg_len_to_hash_in_bytes = job->msg_len_to_hash_in_bytes;
  imb_job->hash_alg = imbm->integ_algs[job->sa->integ_alg].hash_alg;
  imb_job->auth_tag_output_len_in_bytes = job->icv_output_len_in_bytes;
  imb_job->auth_tag_output = job->icv_dst;
  if (job->msg_len_to_cipher_in_bytes)
    {
      imb_job->cipher_mode = CBC;	// FIXME
      if (is_encrypt)
	{
	  imb_job->cipher_direction = ENCRYPT;
	  imb_job->chain_order = CIPHER_HASH;
	}
      else
	{
	  imb_job->cipher_direction = DECRYPT;
	  imb_job->chain_order = HASH_CIPHER;
	}
    }
  else
    {
      imb_job->cipher_mode = NULL_CIPHER;
      imb_job->chain_order = HASH_CIPHER;
    }
  imb_job->msg_len_to_cipher_in_bytes = job->msg_len_to_cipher_in_bytes;
  imb_job->cipher_start_src_offset_in_bytes =
    job->cipher_start_src_offset_in_bytes;
  imb_job->aes_enc_key_expanded = samb->aes_enc_key_expanded;
  imb_job->aes_dec_key_expanded = samb->aes_dec_key_expanded;
  imb_job->aes_key_len_in_bytes = job->sa->crypto_key.len;
  imb_job->iv = job->iv;
  imb_job->iv_len_in_bytes = job->iv_len_in_bytes;
  imb_job->u.HMAC._hashed_auth_key_xor_ipad = samb->ipad_hash;
  imb_job->u.HMAC._hashed_auth_key_xor_opad = samb->opad_hash;
  imb_job->user_data = job;

  imb_job = submit_job (mgr);
  if (imb_job)
    {
      ipsecmb_postprocess_job (imb_job, next_index_drop, is_encrypt);
    }
}

always_inline void
ipsecmb_process_jobs (vlib_main_t * vm, ipsec_main_t * im,
		      ipsecmb_main_t * imbm, MB_MGR * mb_mgr,
		      ipsec_job_desc_t * job, int n_jobs, int is_encrypt,
		      get_next_job_t get_next_job, submit_job_t submit_job,
		      flush_job_t flush_job, int is_ip6, u32 next_index_drop)
{
  while (n_jobs)
    {
      if (IPSEC_ERR_OK == job->error)
	{
	  ipsecmb_process_job (vm, im, imbm, mb_mgr, job, is_encrypt,
			       get_next_job, submit_job, is_ip6,
			       next_index_drop);
	}
      --n_jobs;
      ++job;
    }

  // flush all remaining jobs
  JOB_AES_HMAC *imb_job;
  while ((imb_job = flush_job (mb_mgr)))
    {
      job = imb_job->user_data;
      ipsecmb_postprocess_job (imb_job, next_index_drop, is_encrypt);
    }
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

#endif /* __included_ipsecmb_h__ */
