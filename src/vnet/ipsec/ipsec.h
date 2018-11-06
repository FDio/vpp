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

#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/evp.h>

#include <vppinfra/types.h>
#include <vppinfra/cache.h>

#include <vnet/ipsec/ipsec_spd.h>
#include <vnet/ipsec/ipsec_spd_policy.h>
#include <vnet/ipsec/ipsec_sa.h>
#include <vnet/ipsec/ipsec_if.h>
#include <vnet/ipsec/ipsec_io.h>

typedef clib_error_t *(*add_del_sa_sess_cb_t) (u32 sa_index, u8 is_add);
typedef clib_error_t *(*check_support_cb_t) (ipsec_sa_t * sa);

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
  u32 esp4_encrypt_node_index;
  u32 esp4_decrypt_node_index;
  u32 esp4_encrypt_next_index;
  u32 esp4_decrypt_next_index;
  u32 esp6_encrypt_node_index;
  u32 esp6_decrypt_node_index;
  u32 esp6_encrypt_next_index;
  u32 esp6_decrypt_next_index;
} ipsec_esp_backend_t;

typedef struct
{
  const EVP_CIPHER *type;
  u8 iv_size;
  u8 block_size;
} ipsec_proto_main_crypto_alg_t;

typedef struct
{
  const EVP_MD *md;
  u8 trunc_size;
} ipsec_proto_main_integ_alg_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
  EVP_CIPHER_CTX *encrypt_ctx;
#else
  EVP_CIPHER_CTX encrypt_ctx;
#endif
    CLIB_CACHE_LINE_ALIGN_MARK (cacheline1);
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
  EVP_CIPHER_CTX *decrypt_ctx;
#else
  EVP_CIPHER_CTX decrypt_ctx;
#endif
    CLIB_CACHE_LINE_ALIGN_MARK (cacheline2);
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

typedef enum
{
  IPSEC_ERR_OK = 0,
  IPSEC_ERR_CIPHERING_FAILED,
  IPSEC_ERR_INTEG_ERROR,
  IPSEC_ERR_SEQ_CYCLED,
  IPSEC_ERR_REPLAY,
  IPSEC_ERR_NOT_IP,
  IPSEC_ERR_NO_BUF,
  IPSEC_ERR_RND_GEN_FAILED,
} ipsec_error_e;

typedef struct
{
  u32 spi;
  u32 seq;
  u8 udp_encap;
  ipsec_crypto_alg_t crypto_alg;
  ipsec_integ_alg_t integ_alg;
  ipsec_error_e error;
  u32 data_len;
  u32 crypto_len;
  u32 hash_len;
} ipsec_trace_t;

u8 *format_ipsec_error (u8 * s, va_list * args);
u8 *format_ipsec_trace (u8 * s, va_list * args);

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
  ipsec_sa_t *sa;
  ipsec_error_e error;
} ipsec_job_desc_t;

typedef struct
{
  ipsec_job_desc_t jobs[VLIB_FRAME_SIZE];
} ipsec_main_per_thread_data_t;

typedef struct
{
  /* pool of tunnel instances */
  ipsec_spd_t *spds;
  /* Pool of security associations */
  ipsec_sa_t *sad;
  /* pool of policies */
  ipsec_policy_t *policies;

  /* pool of tunnel interfaces */
  ipsec_tunnel_if_t *tunnel_interfaces;

  u32 **empty_buffers;

  uword *tunnel_index_by_key;

  /* convenience */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;

  /* hashes */
  uword *spd_index_by_spd_id;
  uword *spd_index_by_sw_if_index;
  uword *sa_index_by_sa_id;
  uword *ipsec_if_pool_index_by_key;
  uword *ipsec_if_real_dev_by_show_dev;

  /* node indices */
  u32 error_drop_node_index;
  u32 esp4_encrypt_node_index;
  u32 esp4_decrypt_node_index;
  u32 ah4_encrypt_node_index;
  u32 ah4_decrypt_node_index;
  u32 esp6_encrypt_node_index;
  u32 esp6_decrypt_node_index;
  u32 ah6_encrypt_node_index;
  u32 ah6_decrypt_node_index;
  /* next node indices */
  u32 esp4_encrypt_next_index;
  u32 esp4_decrypt_next_index;
  u32 ah4_encrypt_next_index;
  u32 ah4_decrypt_next_index;
  u32 esp6_encrypt_next_index;
  u32 esp6_decrypt_next_index;
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
  /* per-thread data */
  ipsec_main_per_thread_data_t *per_thread_data;
} ipsec_main_t;

extern ipsec_main_t ipsec_main;

clib_error_t *ipsec_add_del_sa_sess_cb (ipsec_main_t * im, u32 sa_index,
					u8 is_add);

clib_error_t *ipsec_check_support_cb (ipsec_main_t * im, ipsec_sa_t * sa);

extern vlib_node_registration_t esp4_encrypt_node;
extern vlib_node_registration_t esp4_decrypt_node;
extern vlib_node_registration_t ah4_encrypt_node;
extern vlib_node_registration_t ah4_decrypt_node;
extern vlib_node_registration_t esp6_encrypt_node;
extern vlib_node_registration_t esp6_decrypt_node;
extern vlib_node_registration_t ah6_encrypt_node;
extern vlib_node_registration_t ah6_decrypt_node;
extern vlib_node_registration_t ipsec_if_input_node;

/*
 * functions
 */
u8 *format_ipsec_replay_window (u8 * s, va_list * args);

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

u32 ipsec_register_ah_backend (vlib_main_t * vm, ipsec_main_t * im,
			       const char *name,
			       const char *ah4_encrypt_node_name,
			       const char *ah4_decrypt_node_name,
			       const char *ah6_encrypt_node_name,
			       const char *ah6_decrypt_node_name,
			       check_support_cb_t ah_check_support_cb,
			       add_del_sa_sess_cb_t ah_add_del_sa_sess_cb);

u32 ipsec_register_esp_backend (vlib_main_t * vm, ipsec_main_t * im,
				const char *name,
				const char *esp4_encrypt_node_name,
				const char *esp4_decrypt_node_name,
				const char *esp6_encrypt_node_name,
				const char *esp6_decrypt_node_name,
				check_support_cb_t esp_check_support_cb,
				add_del_sa_sess_cb_t esp_add_del_sa_sess_cb);

int ipsec_select_ah_backend (ipsec_main_t * im, u32 ah_backend_idx);
int ipsec_select_esp_backend (ipsec_main_t * im, u32 esp_backend_idx);

always_inline int
hmac_calc (ipsec_integ_alg_t alg, u8 * key, int key_len,
	   u8 * data, int data_len, u8 * signature, int signature_len)
{
  ipsec_proto_main_t *em = &ipsec_proto_main;

  ASSERT (alg < IPSEC_INTEG_N_ALG);

  if (PREDICT_FALSE (em->ipsec_proto_main_integ_algs[alg].md == 0))
    return 1;

  const EVP_MD *md = em->ipsec_proto_main_integ_algs[alg].md;

  u8 tmp[EVP_MAX_MD_SIZE];
  if (!HMAC (md, key, key_len, data, data_len, tmp, NULL))
    {
      return 0;
    }
  clib_memcpy_fast (signature, tmp, clib_min (sizeof (tmp), signature_len));
  return 1;
}


always_inline u32
space_left_in_buffer (vlib_main_t * vm, vlib_buffer_t * b)
{
  return VLIB_BUFFER_PRE_DATA_SIZE + vlib_buffer_get_default_data_size (vm) -
    ((u8 *) vlib_buffer_get_current (b) + b->current_length - b->pre_data);
}

void openssl_random_bytes (u32 thread_index, void *dest, size_t size);

always_inline int
esp_cipher_cbc (vlib_main_t * vm, ipsec_crypto_alg_t alg, vlib_buffer_t * ib,
		u32 ib_offset, vlib_buffer_t * ob, u8 * key,
		u8 * iv, vlib_buffer_t ** last_ob, u32 * empty_buffers,
		int is_encrypt)
{
  ipsec_proto_main_t *em = &ipsec_proto_main;
  u32 thread_index = vlib_get_thread_index ();
  EVP_CIPHER_CTX *ctx;
  if (is_encrypt)
    {
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
      ctx = em->per_thread_data[thread_index].encrypt_ctx;
#else
      ctx = &(em->per_thread_data[thread_index].encrypt_ctx);
#endif
    }
  else
    {
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
      ctx = em->per_thread_data[thread_index].decrypt_ctx;
#else
      ctx = &(em->per_thread_data[thread_index].decrypt_ctx);
#endif
    }
  const EVP_CIPHER *cipher = NULL;
  int out_len;

  if (PREDICT_FALSE (em->ipsec_proto_main_crypto_algs[alg].type == 0))
    {
      return 0;
    }

  if (is_encrypt)
    {
      if (PREDICT_FALSE
	  (alg != em->per_thread_data[thread_index].last_encrypt_alg))
	{
	  cipher = em->ipsec_proto_main_crypto_algs[alg].type;
	  em->per_thread_data[thread_index].last_encrypt_alg = alg;
	}
    }
  else
    {
      if (PREDICT_FALSE
	  (alg != em->per_thread_data[thread_index].last_decrypt_alg))
	{
	  cipher = em->ipsec_proto_main_crypto_algs[alg].type;
	  em->per_thread_data[thread_index].last_decrypt_alg = alg;
	}
    }
  const int block_size = em->ipsec_proto_main_crypto_algs[alg].block_size;

  if (!EVP_CipherInit_ex (ctx, cipher, NULL, key, iv, is_encrypt))
    {
      return 0;
    }

  EVP_CIPHER_CTX_set_padding (ctx, 0);

  vlib_buffer_t *first_ob = ob;
  u32 total_length = ob->current_length;
  do
    {
      u32 in_length = ib->current_length - ib_offset;
      const u32 cipher_could_write = in_length + block_size - 1;
      u32 space_left = space_left_in_buffer (vm, ob);
      if (space_left < block_size)
	{
	  u32 last_empty_buffer = vec_len (empty_buffers) - 1;
	  u32 ebi = empty_buffers[last_empty_buffer];
	  vlib_buffer_t *eb = vlib_get_buffer (vm, ebi);
	  eb->current_data = 0;
	  eb->current_length = 0;
	  vlib_buffer_chain_buffer (vm, ob, ebi);
	  vlib_prefetch_buffer_with_index (vm,
					   empty_buffers[last_empty_buffer -
							 1], STORE);
	  _vec_len (empty_buffers) = last_empty_buffer;
	  ob = eb;
	  space_left = space_left_in_buffer (vm, ob);
	}
      if (space_left < cipher_could_write)
	{
	  in_length -= cipher_could_write - space_left;
	}

      if (!EVP_CipherUpdate
	  (ctx, vlib_buffer_get_current (ob) + ob->current_length,
	   &out_len, vlib_buffer_get_current (ib) + ib_offset, in_length))
	{
	  return 0;
	}
      total_length += out_len;
      ob->current_length += out_len;
      ib_offset += in_length;

      if (ib_offset == ib->current_length
	  && ib->flags & VLIB_BUFFER_NEXT_PRESENT)
	{
	  ib = vlib_get_buffer (vm, ib->next_buffer);
	  ib_offset = 0;
	}
    }
  while (ib_offset < ib->current_length
	 || ib->flags & VLIB_BUFFER_NEXT_PRESENT);


  u8 dummy[block_size + 1];
  if (!EVP_CipherFinal_ex (ctx, dummy, &out_len))
    {
      return 0;
    }
  if (out_len != 0)
    {
      /* this really shouldn't happen, because padding is disabled */
      return 0;
    }

  if (ob != first_ob)
    {
      first_ob->total_length_not_including_first_buffer =
	total_length - first_ob->current_length;
      first_ob->flags |= VLIB_BUFFER_TOTAL_LENGTH_VALID;
#if 0
      u32 x = vlib_buffer_length_in_chain (vm, first_ob);
      first_ob->flags &= ~VLIB_BUFFER_TOTAL_LENGTH_VALID;
      u32 y = vlib_buffer_length_in_chain (vm, first_ob);
      ASSERT (x == y);
#endif
    }
  if (last_ob)
    {
      *last_ob = ob;
    }
  return 1;
}


#define SEQ_MAX 		(4294967295UL)

always_inline int
sa_seq_advance (ipsec_sa_t * sa)
{
  if (PREDICT_TRUE (sa->use_esn))
    {
      if (PREDICT_FALSE (sa->seq == SEQ_MAX))
	{
	  if (PREDICT_FALSE (sa->use_anti_replay && sa->seq_hi == SEQ_MAX))
	    return 1;
	  sa->seq_hi++;
	}
      sa->seq++;
    }
  else
    {
      if (PREDICT_FALSE (sa->use_anti_replay && sa->seq == SEQ_MAX))
	return 1;
      sa->seq++;
    }

  return 0;
}

always_inline void
ipsec_merge_chain_to_job_data (vlib_main_t * vm, ipsec_job_desc_t * job,
			       ssize_t data_offset,
			       size_t extra_space_required,
			       void **extra_space)
{
  const size_t space_left = space_left_in_buffer (vm, job->b);
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
ipsec_split_job_data_to_chain (vlib_main_t * vm, u32 next_index_drop,
			       ipsec_job_desc_t * job, u32 length_to_copy)
{
  u32 offset = 0;
  vlib_buffer_t *b = job->b;
  u32 first_buffer_len_before = job->b->current_length;
  const size_t space_left = space_left_in_buffer (vm, b);
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

  u32 n_buffers =
    ((length_to_copy - offset) / vlib_buffer_get_default_data_size (vm)) +
    (((length_to_copy - offset) % vlib_buffer_get_default_data_size (vm)) >
     1);
  u32 buffer_indices[n_buffers];

  u32 n_alloc = vlib_buffer_alloc (vm, buffer_indices, n_buffers);
  if (n_alloc != n_buffers)
    {
      vlib_buffer_free_no_next (vm, buffer_indices, n_alloc);
      job->next = next_index_drop;
      job->error = IPSEC_ERR_NO_BUF;
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
	clib_min (vlib_buffer_get_default_data_size (vm),
		  length_to_copy - offset);
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

void
ipsec_process_jobs (ipsec_proto_main_t * em, ipsec_job_desc_t * job,
		    u32 n_jobs, u32 next_index_drop, int is_encrypt);

always_inline void
ipsec_add_traces (vlib_main_t * vm, vlib_node_runtime_t * node,
		  ipsec_job_desc_t * job, int n_jobs)
{
  while (n_jobs)
    {
      if (PREDICT_FALSE (job->b->flags & VLIB_BUFFER_IS_TRACED))
	{
	  ipsec_trace_t *tr = vlib_add_trace (vm, node, job->b, sizeof (*tr));
	  tr->spi = job->sa->spi;
	  tr->seq = job->sa->seq;
	  tr->integ_alg = job->sa->integ_alg;
	  tr->crypto_alg = job->sa->crypto_alg;
	  tr->error = job->error;
	  if (job->src)
	    {
	      tr->data_len = job->data_len;
	    }
	  else
	    {
	      tr->data_len = 0;
	    }
	  tr->crypto_len = job->msg_len_to_cipher_in_bytes;
	  tr->hash_len = job->msg_len_to_hash_in_bytes;
	}
      --n_jobs;
      ++job;
    }
}

always_inline void
ipsec_update_packet_counters (vlib_main_t * vm, vlib_node_runtime_t * node,
			      ipsec_job_desc_t * job, int n_jobs,
			      u32 node_counter_ipsec_err_ciphering_failed,
			      u32 node_counter_ipsec_err_integ_error,
			      u32 node_counter_ipsec_err_seq_cycled,
			      u32 node_counter_ipsec_err_replay,
			      u32 node_counter_ipsec_err_not_ip,
			      u32 node_counter_ipsec_err_no_buf,
			      u32 node_counter_ipsec_err_rnd_gen_failed)
{
  u32 count_ipsec_err_ciphering_failed = 0;
  u32 count_ipsec_err_integ_error = 0;
  u32 count_ipsec_err_seq_cycled = 0;
  u32 count_ipsec_err_replay = 0;
  u32 count_ipsec_err_not_ip = 0;
  u32 count_ipsec_err_no_buf = 0;
  u32 count_ipsec_err_rnd_gen_failed = 0;
  while (n_jobs)
    {
      switch (job->error)
	{
	case IPSEC_ERR_OK:
	  /* nothing to do here */
	  break;
	case IPSEC_ERR_CIPHERING_FAILED:
	  ++count_ipsec_err_ciphering_failed;
	  break;
	case IPSEC_ERR_INTEG_ERROR:
	  ++count_ipsec_err_integ_error;
	  break;
	case IPSEC_ERR_SEQ_CYCLED:
	  ++count_ipsec_err_seq_cycled;
	  break;
	case IPSEC_ERR_REPLAY:
	  ++count_ipsec_err_replay;
	  break;
	case IPSEC_ERR_NOT_IP:
	  ++count_ipsec_err_not_ip;
	  break;
	case IPSEC_ERR_NO_BUF:
	  ++count_ipsec_err_no_buf;
	  break;
	case IPSEC_ERR_RND_GEN_FAILED:
	  ++count_ipsec_err_rnd_gen_failed;
	  break;
	}
      --n_jobs;
      ++job;
    }
  if (count_ipsec_err_ciphering_failed)
    vlib_node_increment_counter (vm, node->node_index,
				 node_counter_ipsec_err_ciphering_failed,
				 count_ipsec_err_ciphering_failed);
  if (count_ipsec_err_integ_error)
    vlib_node_increment_counter (vm, node->node_index,
				 node_counter_ipsec_err_integ_error,
				 count_ipsec_err_integ_error);
  if (count_ipsec_err_seq_cycled)
    vlib_node_increment_counter (vm, node->node_index,
				 node_counter_ipsec_err_seq_cycled,
				 count_ipsec_err_seq_cycled);
  if (count_ipsec_err_replay)
    vlib_node_increment_counter (vm, node->node_index,
				 node_counter_ipsec_err_replay,
				 count_ipsec_err_replay);
  if (count_ipsec_err_not_ip)
    vlib_node_increment_counter (vm, node->node_index,
				 node_counter_ipsec_err_not_ip,
				 count_ipsec_err_not_ip);
  if (count_ipsec_err_no_buf)
    vlib_node_increment_counter (vm, node->node_index,
				 node_counter_ipsec_err_no_buf,
				 count_ipsec_err_no_buf);
  if (count_ipsec_err_rnd_gen_failed)
    vlib_node_increment_counter (vm, node->node_index,
				 node_counter_ipsec_err_rnd_gen_failed,
				 count_ipsec_err_rnd_gen_failed);
}

#define SA_WINDOW_SIZE		(64)

always_inline int
sa_replay_check_esn (ipsec_sa_t * sa, u32 seq)
{
  u32 tl = sa->last_seq;
  u32 th = sa->last_seq_hi;
  u32 diff = tl - seq;

  if (PREDICT_TRUE (tl >= (SA_WINDOW_SIZE - 1)))
    {
      if (seq >= (tl - SA_WINDOW_SIZE + 1))
	{
	  sa->seq_hi = th;
	  if (seq <= tl)
	    return (sa->replay_window & (1ULL << diff)) ? 1 : 0;
	  else
	    return 0;
	}
      else
	{
	  sa->seq_hi = th + 1;
	  return 0;
	}
    }
  else
    {
      if (seq >= (tl - SA_WINDOW_SIZE + 1))
	{
	  sa->seq_hi = th - 1;
	  return (sa->replay_window & (1ULL << diff)) ? 1 : 0;
	}
      else
	{
	  sa->seq_hi = th;
	  if (seq <= tl)
	    return (sa->replay_window & (1ULL << diff)) ? 1 : 0;
	  else
	    return 0;
	}
    }

  return 0;
}

always_inline int
sa_replay_check (ipsec_sa_t * sa, u32 seq)
{
  u32 diff;

  if (PREDICT_TRUE (seq > sa->last_seq))
    return 0;

  diff = sa->last_seq - seq;

  if (SA_WINDOW_SIZE > diff)
    return (sa->replay_window & (1ULL << diff)) ? 1 : 0;
  else
    return 1;

  return 0;
}

/* TODO seq increment should be atomic to be accessed by multiple workers */
always_inline void
sa_replay_advance (ipsec_sa_t * sa, u32 seq)
{
  u32 pos;

  if (seq > sa->last_seq)
    {
      pos = seq - sa->last_seq;
      if (pos < SA_WINDOW_SIZE)
	sa->replay_window = ((sa->replay_window) << pos) | 1;
      else
	sa->replay_window = 1;
      sa->last_seq = seq;
    }
  else
    {
      pos = sa->last_seq - seq;
      sa->replay_window |= (1ULL << pos);
    }
}

always_inline void
sa_replay_advance_esn (ipsec_sa_t * sa, u32 seq)
{
  int wrap = sa->seq_hi - sa->last_seq_hi;
  u32 pos;

  if (wrap == 0 && seq > sa->last_seq)
    {
      pos = seq - sa->last_seq;
      if (pos < SA_WINDOW_SIZE)
	sa->replay_window = ((sa->replay_window) << pos) | 1;
      else
	sa->replay_window = 1;
      sa->last_seq = seq;
    }
  else if (wrap > 0)
    {
      pos = ~seq + sa->last_seq + 1;
      if (pos < SA_WINDOW_SIZE)
	sa->replay_window = ((sa->replay_window) << pos) | 1;
      else
	sa->replay_window = 1;
      sa->last_seq = seq;
      sa->last_seq_hi = sa->seq_hi;
    }
  else if (wrap < 0)
    {
      pos = ~seq + sa->last_seq + 1;
      sa->replay_window |= (1ULL << pos);
    }
  else
    {
      pos = sa->last_seq - seq;
      sa->replay_window |= (1ULL << pos);
    }
}

#endif /* __IPSEC_H__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
