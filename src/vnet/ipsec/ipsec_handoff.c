/*
 * esp_encrypt.c : IPSec ESP encrypt node
 *
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

#include <vnet/ipsec/ipsec.h>
#include <vnet/ipsec/ipsec_sa.h>

#define foreach_ipsec_handoff_error  \
_(CONGESTION_DROP, "congestion drop")

typedef enum
{
#define _(sym,str) IPSEC_HANDOFF_ERROR_##sym,
  foreach_ipsec_handoff_error
#undef _
    NAT44_HANDOFF_N_ERROR,
} ipsec_handoff_error_t;

static char *ipsec_handoff_error_strings[] = {
#define _(sym,string) string,
  foreach_ipsec_handoff_error
#undef _
};

typedef struct ipsec_handoff_trace_t_
{
  u32 next_worker_index;
} ipsec_handoff_trace_t;

static u8 *
format_ipsec_handoff_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  ipsec_handoff_trace_t *t = va_arg (*args, ipsec_handoff_trace_t *);

  s = format (s, "next-worker %d", t->next_worker_index);

  return s;
}

/* do worker handoff based on thread_index in NAT HA protcol header */
static_always_inline uword
ipsec_handoff (vlib_main_t * vm,
	       vlib_node_runtime_t * node,
	       vlib_frame_t * frame, u32 fq_index, bool is_enc)
{
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;
  u16 thread_indices[VLIB_FRAME_SIZE], *ti;
  u32 n_enq, n_left_from, *from;
  ipsec_main_t *im;

  im = &ipsec_main;
  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  vlib_get_buffers (vm, from, bufs, n_left_from);

  b = bufs;
  ti = thread_indices;

  while (n_left_from >= 4)
    {
      ipsec_sa_t *sa0, *sa1, *sa2, *sa3;
      u32 sai0, sai1, sai2, sai3;

      /* Prefetch next iteration. */
      if (n_left_from >= 12)
	{
	  vlib_prefetch_buffer_header (b[8], LOAD);
	  vlib_prefetch_buffer_header (b[9], LOAD);
	  vlib_prefetch_buffer_header (b[10], LOAD);
	  vlib_prefetch_buffer_header (b[11], LOAD);

	  vlib_prefetch_buffer_data (b[4], LOAD);
	  vlib_prefetch_buffer_data (b[5], LOAD);
	  vlib_prefetch_buffer_data (b[6], LOAD);
	  vlib_prefetch_buffer_data (b[7], LOAD);
	}

      sai0 = vnet_buffer (b[0])->ipsec.sad_index;
      sai1 = vnet_buffer (b[1])->ipsec.sad_index;
      sai2 = vnet_buffer (b[2])->ipsec.sad_index;
      sai3 = vnet_buffer (b[3])->ipsec.sad_index;
      sa0 = pool_elt_at_index (im->sad, sai0);
      sa1 = pool_elt_at_index (im->sad, sai1);
      sa2 = pool_elt_at_index (im->sad, sai2);
      sa3 = pool_elt_at_index (im->sad, sai3);

      if (is_enc)
	{
	  ti[0] = sa0->encrypt_thread_index;
	  ti[1] = sa1->encrypt_thread_index;
	  ti[2] = sa2->encrypt_thread_index;
	  ti[3] = sa3->encrypt_thread_index;
	}
      else
	{
	  ti[0] = sa0->decrypt_thread_index;
	  ti[1] = sa1->decrypt_thread_index;
	  ti[2] = sa2->decrypt_thread_index;
	  ti[3] = sa3->decrypt_thread_index;
	}

      if (node->flags & VLIB_NODE_FLAG_TRACE)
	{
	  if (PREDICT_FALSE (b[0]->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      ipsec_handoff_trace_t *t =
		vlib_add_trace (vm, node, b[0], sizeof (*t));
	      t->next_worker_index = ti[0];
	    }
	  if (PREDICT_FALSE (b[1]->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      ipsec_handoff_trace_t *t =
		vlib_add_trace (vm, node, b[1], sizeof (*t));
	      t->next_worker_index = ti[1];
	    }
	  if (PREDICT_FALSE (b[2]->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      ipsec_handoff_trace_t *t =
		vlib_add_trace (vm, node, b[2], sizeof (*t));
	      t->next_worker_index = ti[2];
	    }
	  if (PREDICT_FALSE (b[3]->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      ipsec_handoff_trace_t *t =
		vlib_add_trace (vm, node, b[3], sizeof (*t));
	      t->next_worker_index = ti[3];
	    }
	}

      n_left_from -= 4;
      ti += 4;
      b += 4;
    }
  while (n_left_from > 0)
    {
      ipsec_sa_t *sa0;
      u32 sai0;

      sai0 = vnet_buffer (b[0])->ipsec.sad_index;
      sa0 = pool_elt_at_index (im->sad, sai0);

      if (is_enc)
	ti[0] = sa0->encrypt_thread_index;
      else
	ti[0] = sa0->decrypt_thread_index;

      if (PREDICT_FALSE (b[0]->flags & VLIB_BUFFER_IS_TRACED))
	{
	  ipsec_handoff_trace_t *t =
	    vlib_add_trace (vm, node, b[0], sizeof (*t));
	  t->next_worker_index = ti[0];
	}

      n_left_from -= 1;
      ti += 1;
      b += 1;
    }

  n_enq = vlib_buffer_enqueue_to_thread (vm, fq_index, from,
					 thread_indices, frame->n_vectors, 1);

  if (n_enq < frame->n_vectors)
    vlib_node_increment_counter (vm, node->node_index,
				 IPSEC_HANDOFF_ERROR_CONGESTION_DROP,
				 frame->n_vectors - n_enq);

  return n_enq;
}

VLIB_NODE_FN (esp4_encrypt_handoff) (vlib_main_t * vm,
				     vlib_node_runtime_t * node,
				     vlib_frame_t * from_frame)
{
  ipsec_main_t *im = &ipsec_main;

  return ipsec_handoff (vm, node, from_frame, im->esp4_enc_fq_index, true);
}

VLIB_NODE_FN (esp6_encrypt_handoff) (vlib_main_t * vm,
				     vlib_node_runtime_t * node,
				     vlib_frame_t * from_frame)
{
  ipsec_main_t *im = &ipsec_main;

  return ipsec_handoff (vm, node, from_frame, im->esp6_enc_fq_index, true);
}

VLIB_NODE_FN (esp4_encrypt_tun_handoff) (vlib_main_t * vm,
					 vlib_node_runtime_t * node,
					 vlib_frame_t * from_frame)
{
  ipsec_main_t *im = &ipsec_main;

  return ipsec_handoff (vm, node, from_frame, im->esp4_enc_tun_fq_index,
			true);
}

VLIB_NODE_FN (esp6_encrypt_tun_handoff) (vlib_main_t * vm,
					 vlib_node_runtime_t * node,
					 vlib_frame_t * from_frame)
{
  ipsec_main_t *im = &ipsec_main;

  return ipsec_handoff (vm, node, from_frame, im->esp6_enc_tun_fq_index,
			true);
}

VLIB_NODE_FN (esp_mpls_encrypt_tun_handoff)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *from_frame)
{
  ipsec_main_t *im = &ipsec_main;

  return ipsec_handoff (vm, node, from_frame, im->esp_mpls_enc_tun_fq_index,
			true);
}

VLIB_NODE_FN (esp4_decrypt_handoff) (vlib_main_t * vm,
				     vlib_node_runtime_t * node,
				     vlib_frame_t * from_frame)
{
  ipsec_main_t *im = &ipsec_main;

  return ipsec_handoff (vm, node, from_frame, im->esp4_dec_fq_index, false);
}

VLIB_NODE_FN (esp6_decrypt_handoff) (vlib_main_t * vm,
				     vlib_node_runtime_t * node,
				     vlib_frame_t * from_frame)
{
  ipsec_main_t *im = &ipsec_main;

  return ipsec_handoff (vm, node, from_frame, im->esp6_dec_fq_index, false);
}

VLIB_NODE_FN (esp4_decrypt_tun_handoff) (vlib_main_t * vm,
					 vlib_node_runtime_t * node,
					 vlib_frame_t * from_frame)
{
  ipsec_main_t *im = &ipsec_main;

  return ipsec_handoff (vm, node, from_frame, im->esp4_dec_tun_fq_index,
			false);
}

VLIB_NODE_FN (esp6_decrypt_tun_handoff) (vlib_main_t * vm,
					 vlib_node_runtime_t * node,
					 vlib_frame_t * from_frame)
{
  ipsec_main_t *im = &ipsec_main;

  return ipsec_handoff (vm, node, from_frame, im->esp6_dec_tun_fq_index,
			false);
}

VLIB_NODE_FN (ah4_encrypt_handoff) (vlib_main_t * vm,
				    vlib_node_runtime_t * node,
				    vlib_frame_t * from_frame)
{
  ipsec_main_t *im = &ipsec_main;

  return ipsec_handoff (vm, node, from_frame, im->ah4_enc_fq_index, true);
}

VLIB_NODE_FN (ah6_encrypt_handoff) (vlib_main_t * vm,
				    vlib_node_runtime_t * node,
				    vlib_frame_t * from_frame)
{
  ipsec_main_t *im = &ipsec_main;

  return ipsec_handoff (vm, node, from_frame, im->ah6_enc_fq_index, true);
}

VLIB_NODE_FN (ah4_decrypt_handoff) (vlib_main_t * vm,
				    vlib_node_runtime_t * node,
				    vlib_frame_t * from_frame)
{
  ipsec_main_t *im = &ipsec_main;

  return ipsec_handoff (vm, node, from_frame, im->ah4_dec_fq_index, false);
}

VLIB_NODE_FN (ah6_decrypt_handoff) (vlib_main_t * vm,
				    vlib_node_runtime_t * node,
				    vlib_frame_t * from_frame)
{
  ipsec_main_t *im = &ipsec_main;

  return ipsec_handoff (vm, node, from_frame, im->ah6_dec_fq_index, false);
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (esp4_encrypt_handoff) = {
  .name = "esp4-encrypt-handoff",
  .vector_size = sizeof (u32),
  .format_trace = format_ipsec_handoff_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(ipsec_handoff_error_strings),
  .error_strings = ipsec_handoff_error_strings,
  .n_next_nodes = 1,
  .next_nodes = {
    [0] = "error-drop",
  },
};
VLIB_REGISTER_NODE (esp6_encrypt_handoff) = {
  .name = "esp6-encrypt-handoff",
  .vector_size = sizeof (u32),
  .format_trace = format_ipsec_handoff_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(ipsec_handoff_error_strings),
  .error_strings = ipsec_handoff_error_strings,
  .n_next_nodes = 1,
  .next_nodes = {
    [0] = "error-drop",
  },
};
VLIB_REGISTER_NODE (esp4_encrypt_tun_handoff) = {
  .name = "esp4-encrypt-tun-handoff",
  .vector_size = sizeof (u32),
  .format_trace = format_ipsec_handoff_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(ipsec_handoff_error_strings),
  .error_strings = ipsec_handoff_error_strings,
  .n_next_nodes = 1,
  .next_nodes = {
    [0] = "error-drop",
  },
};
VLIB_REGISTER_NODE (esp6_encrypt_tun_handoff) = {
  .name = "esp6-encrypt-tun-handoff",
  .vector_size = sizeof (u32),
  .format_trace = format_ipsec_handoff_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(ipsec_handoff_error_strings),
  .error_strings = ipsec_handoff_error_strings,
  .n_next_nodes = 1,
  .next_nodes = {
    [0] = "error-drop",
  },
};
VLIB_REGISTER_NODE (esp_mpls_encrypt_tun_handoff) = {
  .name = "esp-mpls-encrypt-tun-handoff",
  .vector_size = sizeof (u32),
  .format_trace = format_ipsec_handoff_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(ipsec_handoff_error_strings),
  .error_strings = ipsec_handoff_error_strings,
  .n_next_nodes = 1,
  .next_nodes = {
    [0] = "error-drop",
  },
};
VLIB_REGISTER_NODE (esp4_decrypt_handoff) = {
  .name = "esp4-decrypt-handoff",
  .vector_size = sizeof (u32),
  .format_trace = format_ipsec_handoff_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(ipsec_handoff_error_strings),
  .error_strings = ipsec_handoff_error_strings,
  .n_next_nodes = 1,
  .next_nodes = {
    [0] = "error-drop",
  },
};
VLIB_REGISTER_NODE (esp6_decrypt_handoff) = {
  .name = "esp6-decrypt-handoff",
  .vector_size = sizeof (u32),
  .format_trace = format_ipsec_handoff_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(ipsec_handoff_error_strings),
  .error_strings = ipsec_handoff_error_strings,
  .n_next_nodes = 1,
  .next_nodes = {
    [0] = "error-drop",
  },
};
VLIB_REGISTER_NODE (esp4_decrypt_tun_handoff) = {
  .name = "esp4-decrypt-tun-handoff",
  .vector_size = sizeof (u32),
  .format_trace = format_ipsec_handoff_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(ipsec_handoff_error_strings),
  .error_strings = ipsec_handoff_error_strings,
  .n_next_nodes = 1,
  .next_nodes = {
    [0] = "error-drop",
  },
};
VLIB_REGISTER_NODE (esp6_decrypt_tun_handoff) = {
  .name = "esp6-decrypt-tun-handoff",
  .vector_size = sizeof (u32),
  .format_trace = format_ipsec_handoff_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(ipsec_handoff_error_strings),
  .error_strings = ipsec_handoff_error_strings,
  .n_next_nodes = 1,
  .next_nodes = {
    [0] = "error-drop",
  },
};
VLIB_REGISTER_NODE (ah4_encrypt_handoff) = {
  .name = "ah4-encrypt-handoff",
  .vector_size = sizeof (u32),
  .format_trace = format_ipsec_handoff_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(ipsec_handoff_error_strings),
  .error_strings = ipsec_handoff_error_strings,
  .n_next_nodes = 1,
  .next_nodes = {
    [0] = "error-drop",
  },
};
VLIB_REGISTER_NODE (ah6_encrypt_handoff) = {
  .name = "ah6-encrypt-handoff",
  .vector_size = sizeof (u32),
  .format_trace = format_ipsec_handoff_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(ipsec_handoff_error_strings),
  .error_strings = ipsec_handoff_error_strings,
  .n_next_nodes = 1,
  .next_nodes = {
    [0] = "error-drop",
  },
};
VLIB_REGISTER_NODE (ah4_decrypt_handoff) = {
  .name = "ah4-decrypt-handoff",
  .vector_size = sizeof (u32),
  .format_trace = format_ipsec_handoff_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(ipsec_handoff_error_strings),
  .error_strings = ipsec_handoff_error_strings,
  .n_next_nodes = 1,
  .next_nodes = {
    [0] = "error-drop",
  },
};
VLIB_REGISTER_NODE (ah6_decrypt_handoff) = {
  .name = "ah6-decrypt-handoff",
  .vector_size = sizeof (u32),
  .format_trace = format_ipsec_handoff_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(ipsec_handoff_error_strings),
  .error_strings = ipsec_handoff_error_strings,
  .n_next_nodes = 1,
  .next_nodes = {
    [0] = "error-drop",
  },
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
