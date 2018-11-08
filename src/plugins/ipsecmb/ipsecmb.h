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

u8 *format_esp_trace (u8 * s, va_list * args);

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
  /** vector of random bytes collected from encrypted data */
  u32 *rb_from_traffic;
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
ipsecmb_process_job (vlib_main_t * vm, MB_MGR * mgr,
		     ipsecmb_job_desc_t * imb_job,
		     JOB_CIPHER_DIRECTION cipher_direction,
		     JOB_CHAIN_ORDER chain_order,
		     get_next_job_t get_next_job,
		     submit_job_t submit_job, int is_ip6)
{
  JOB_AES_HMAC *job = get_next_job (mgr);
  job->src = imb_job->src;
  job->dst = imb_job->cipher_dst;
  job->hash_start_src_offset_in_bytes = 0;
  job->msg_len_to_hash_in_bytes = imb_job->msg_len_to_hash_in_bytes;
  job->hash_alg = imb_job->hash_alg;
  job->auth_tag_output_len_in_bytes = imb_job->icv_output_len_in_bytes;
  job->auth_tag_output = imb_job->icv_dst;
  job->cipher_mode = imb_job->cipher_mode;
  job->cipher_direction = cipher_direction;
  job->msg_len_to_cipher_in_bytes = imb_job->msg_len_to_cipher_in_bytes;
  job->cipher_start_src_offset_in_bytes =
    imb_job->cipher_start_src_offset_in_bytes;
  job->aes_enc_key_expanded = imb_job->samb->aes_enc_key_expanded;
  job->aes_dec_key_expanded = imb_job->samb->aes_dec_key_expanded;
  job->aes_key_len_in_bytes = imb_job->sa->crypto_key_len;
  job->iv = imb_job->iv;
  job->iv_len_in_bytes = imb_job->iv_len_in_bytes;
  job->chain_order = chain_order;
  job->u.HMAC._hashed_auth_key_xor_ipad = imb_job->samb->ipad_hash;
  job->u.HMAC._hashed_auth_key_xor_opad = imb_job->samb->opad_hash;
  job->user_data = imb_job;

  job = submit_job (mgr);
  if (job)
    {
      imb_job = job->user_data;
      imb_job->sts = job->status;
    }
}

always_inline void
ipsecmb_process_jobs (vlib_main_t * vm, MB_MGR * mb_mgr,
		      ipsecmb_job_desc_t * jobs, int count,
		      JOB_CIPHER_DIRECTION cipher_direction,
		      JOB_CHAIN_ORDER chain_order,
		      get_next_job_t get_next_job, submit_job_t submit_job,
		      flush_job_t flush_job, int is_ip6)
{
  int i;
  ipsecmb_job_desc_t *imb_job;
  for (i = 0; i < count; ++i)
    {
      imb_job = &jobs[i];
      if (IMB_ERR_OK == imb_job->error)
	{
	  ipsecmb_process_job (vm, mb_mgr, imb_job, cipher_direction,
			       chain_order, get_next_job, submit_job, is_ip6);
	}
    }

  // flush all remaining jobs
  JOB_AES_HMAC *job;
  while ((job = flush_job (mb_mgr)))
    {
      imb_job = job->user_data;
      imb_job->sts = job->status;
    }
}

always_inline void
ipsecmb_merge_chain_to_job_data (vlib_main_t * vm, ipsecmb_job_desc_t * job,
				 ssize_t data_offset,
				 size_t extra_space_required,
				 void **extra_space)
{
  const size_t space_left = space_left_in_buffer (job->b);
  if (job->b->flags & VLIB_BUFFER_NEXT_PRESENT
      || (space_left < extra_space_required))
    {
      vec_validate (job->data,
		    vlib_buffer_length_in_chain (vm, job->b) +
		    extra_space_required);
      size_t offset = 0;
      vlib_buffer_t *b = job->b;
      while (1)
	{
	  clib_memcpy_fast (job->data + offset,
			    vlib_buffer_get_current (b) + data_offset,
			    b->current_length - data_offset);
	  offset += b->current_length - data_offset;
	  if (b->flags & VLIB_BUFFER_NEXT_PRESENT)
	    {
	      b = vlib_get_buffer (vm, b->next_buffer);
	      data_offset = 0;
	    }
	  else
	    {
	      break;
	    }
	}
      job->src = job->data;
      job->data_len = offset + extra_space_required;
      if (extra_space)
	{
	  *extra_space = (u8 *) job->data + offset;
	}
    }
  else
    {
      job->src = (u8 *) vlib_buffer_get_current (job->b) + data_offset;
      job->data_len =
	job->b->current_length - data_offset + extra_space_required;
      if (extra_space)
	{
	  *extra_space =
	    (u8 *) job->src + job->b->current_length - data_offset;
	}
    }
}

always_inline int
ipsecmb_split_job_data_to_chain (vlib_main_t * vm, vlib_node_runtime_t * node,
				 u32 err_counter_idx, u32 drop_error_idx,
				 ipsecmb_job_desc_t * job, u32 length_to_copy)
{
  u32 offset = 0;
  vlib_buffer_t *b = job->b;
  u32 first_buffer_len_before = job->b->current_length;
  const size_t space_left = space_left_in_buffer (b);
  const size_t amount_to_copy = clib_min (space_left, length_to_copy);
  void *data = vlib_buffer_put_uninit (b, amount_to_copy);
  clib_memcpy_fast (data, job->data, amount_to_copy);
  offset = amount_to_copy;

  if (b->flags & VLIB_BUFFER_NEXT_PRESENT)
    {
      vlib_buffer_free_one (vm, b->next_buffer);
    }

  b->total_length_not_including_first_buffer = 0;
  b->flags &= ~VLIB_BUFFER_NEXT_PRESENT;
  b->flags |= VLIB_BUFFER_TOTAL_LENGTH_VALID;

  if (length_to_copy == offset)
    {
      return 0;
    }

  u32 n_buffers = ((length_to_copy - offset) / VLIB_BUFFER_DATA_SIZE) +
    (((length_to_copy - offset) % VLIB_BUFFER_DATA_SIZE) > 1);
  u32 buffer_indices[n_buffers];

  u32 n_alloc = vlib_buffer_alloc (vm, buffer_indices, n_buffers);
  if (n_alloc != n_buffers)
    {
      vlib_buffer_free_no_next (vm, buffer_indices, n_alloc);
      vlib_node_increment_counter (vm, node->node_index, err_counter_idx, 1);
      job->next = drop_error_idx;
      job->error = IMB_ERR_NO_BUF;
    }

  int i;
  vlib_buffer_t *prev_b = job->b;
  vlib_buffer_t *buffers[n_buffers];
  vlib_get_buffers (vm, buffer_indices, buffers, n_buffers);
  for (i = 0; i < n_buffers; ++i)
    {
      ASSERT (offset > 0);
      b = buffers[i];
      b->current_data = 0;
      b->current_length = 0;
      b->flags = 0;
      const size_t amount_to_copy =
	clib_min (VLIB_BUFFER_DATA_SIZE, length_to_copy - offset);
      void *data = vlib_buffer_put_uninit (b, amount_to_copy);
      clib_memcpy_fast (data, job->src + offset, amount_to_copy);
      offset += amount_to_copy;
      prev_b->next_buffer = buffer_indices[i];
      prev_b->flags |= VLIB_BUFFER_NEXT_PRESENT;
      prev_b = b;
    }
  ASSERT (length_to_copy == offset);

  job->b->flags |= VLIB_BUFFER_TOTAL_LENGTH_VALID;
  job->b->total_length_not_including_first_buffer =
    length_to_copy - (job->b->current_length - first_buffer_len_before);
  return 0;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

#endif /* __included_ipsecmb_h__ */
