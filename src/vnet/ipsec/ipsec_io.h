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
#ifndef __IPSEC_IO_H__
#define __IPSEC_IO_H__

#include <vnet/ipsec/ipsec.h>

#define IPSEC_FLAG_IPSEC_GRE_TUNNEL (1 << 0)

#define foreach_ipsec_output_next  \
  _ (DROP, "error-drop")

#define _(v, s) IPSEC_OUTPUT_NEXT_##v,
typedef enum
{
  foreach_ipsec_output_next
#undef _
    IPSEC_OUTPUT_N_NEXT,
} ipsec_output_next_t;

#define foreach_ipsec_input_next   \
  _ (DROP, "error-drop")

#define _(v, s) IPSEC_INPUT_NEXT_##v,
typedef enum
{
  foreach_ipsec_input_next
#undef _
    IPSEC_INPUT_N_NEXT,
} ipsec_input_next_t;


typedef struct
{
  u32 spd_index;
} ip4_ipsec_config_t;

typedef struct
{
  u32 spd_index;
} ip6_ipsec_config_t;

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
  const size_t space_left = vlib_buffer_space_left_at_end (vm, job->b);
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
  const size_t space_left = vlib_buffer_space_left_at_end (vm, b);
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
#endif /* __IPSEC_IO_H__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
