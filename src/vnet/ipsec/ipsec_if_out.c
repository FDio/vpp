/*
 * ipsec_if_out.c : IPSec interface output node
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

#include <vnet/vnet.h>
#include <vnet/api_errno.h>
#include <vnet/ip/ip.h>

#include <vnet/ipsec/ipsec.h>

/* Statistics (not really errors) */
#define foreach_ipsec_if_output_error    \
_(TX, "good packets transmitted")

static char *ipsec_if_output_error_strings[] = {
#define _(sym,string) string,
  foreach_ipsec_if_output_error
#undef _
};

typedef enum
{
#define _(sym,str) IPSEC_IF_OUTPUT_ERROR_##sym,
  foreach_ipsec_if_output_error
#undef _
    IPSEC_IF_OUTPUT_N_ERROR,
} ipsec_if_output_error_t;


typedef struct
{
  u32 spi;
} ipsec_if_output_trace_t;

static u8 *
format_ipsec_if_output_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  ipsec_if_output_trace_t *t = va_arg (*args, ipsec_if_output_trace_t *);

  s = format (s, "IPSec: spi %u", t->spi);
  return s;
}

always_inline uword
ipsec_if_output_inline (vlib_main_t * vm, vlib_node_runtime_t * node,
			vlib_frame_t * from_frame, int is_ip6, int is_trace)
{
  ipsec_main_t *im = &ipsec_main;
  vnet_main_t *vnm = im->vnet_main;
  vnet_interface_main_t *vim = &vnm->interface_main;

  u32 n_left_from, *from;
  u16 nexts[VLIB_FRAME_SIZE], *next;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;

  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;

  vlib_get_buffers (vm, from, bufs, n_left_from);
  b = bufs;
  next = nexts;

  CLIB_PREFETCH (b[0], CLIB_CACHE_LINE_BYTES, LOAD);
  CLIB_PREFETCH (b[1], CLIB_CACHE_LINE_BYTES, LOAD);

  if (is_ip6)
    clib_memset_u16 (next, im->esp6_encrypt_next_index, n_left_from);
  else
    clib_memset_u16 (next, im->esp4_encrypt_next_index, n_left_from);

  u32 last_sw_if_index = ~0, last_sa_index = ~0;
  u32 thread_index = vm->thread_index;
  u32 n_bytes = 0, n_packets = 0;

  while (n_left_from >= 2)
    {
      u32 len0, len1;
      u32 sw_if_index0, sw_if_index1;

      if (n_left_from >= 4)
	{
	  CLIB_PREFETCH (b[2], CLIB_CACHE_LINE_BYTES, LOAD);
	  CLIB_PREFETCH (b[3], CLIB_CACHE_LINE_BYTES, LOAD);
	}

      sw_if_index0 = vnet_buffer (b[0])->sw_if_index[VLIB_TX];
      sw_if_index1 = vnet_buffer (b[1])->sw_if_index[VLIB_TX];

      len0 = vlib_buffer_length_in_chain (vm, b[0]);
      len1 = vlib_buffer_length_in_chain (vm, b[1]);

      if (PREDICT_TRUE (sw_if_index0 == last_sw_if_index))
	{
	  n_packets++;
	  n_bytes += len0;
	}
      else
	{
	  vnet_hw_interface_t *hi =
	    vnet_get_sup_hw_interface (vnm, sw_if_index0);
	  ipsec_tunnel_if_t *t =
	    pool_elt_at_index (im->tunnel_interfaces, hi->dev_instance);
	  last_sa_index = t->output_sa_index;

	  if (n_packets)
	    vlib_increment_combined_counter (vim->combined_sw_if_counters +
					     VNET_INTERFACE_COUNTER_TX,
					     thread_index, last_sw_if_index,
					     n_packets, n_bytes);

	  last_sw_if_index = sw_if_index0;
	  n_packets = 1;
	  n_bytes = len0;
	}
      vnet_buffer (b[0])->ipsec.sad_index = last_sa_index;

      if (PREDICT_TRUE (sw_if_index1 == last_sw_if_index))
	{
	  n_packets++;
	  n_bytes += len1;
	}
      else
	{
	  vnet_hw_interface_t *hi =
	    vnet_get_sup_hw_interface (vnm, sw_if_index1);
	  ipsec_tunnel_if_t *t =
	    pool_elt_at_index (im->tunnel_interfaces, hi->dev_instance);
	  last_sa_index = t->output_sa_index;

	  if (n_packets)
	    vlib_increment_combined_counter (vim->combined_sw_if_counters +
					     VNET_INTERFACE_COUNTER_TX,
					     thread_index, last_sw_if_index,
					     n_packets, n_bytes);

	  last_sw_if_index = sw_if_index1;
	  n_packets = 1;
	  n_bytes = len1;
	}
      vnet_buffer (b[1])->ipsec.sad_index = last_sa_index;

      if (PREDICT_FALSE (is_trace))
	{
	  if (b[0]->flags & VLIB_BUFFER_IS_TRACED)
	    {
	      ipsec_if_output_trace_t *tr =
		vlib_add_trace (vm, node, b[0], sizeof (*tr));
	      ipsec_sa_t *sa0 = pool_elt_at_index (im->sad,
						   vnet_buffer (b[0])->ipsec.
						   sad_index);
	      tr->spi = sa0->spi;
	    }
	  if (b[1]->flags & VLIB_BUFFER_IS_TRACED)
	    {
	      ipsec_if_output_trace_t *tr =
		vlib_add_trace (vm, node, b[1], sizeof (*tr));
	      ipsec_sa_t *sa1 = pool_elt_at_index (im->sad,
						   vnet_buffer (b[1])->ipsec.
						   sad_index);
	      tr->spi = sa1->spi;
	    }
	}

      /* next */
      b += 2;
      next += 2;
      n_left_from -= 2;
    }

  while (n_left_from > 0)
    {
      u32 len0;
      u32 sw_if_index0;

      sw_if_index0 = vnet_buffer (b[0])->sw_if_index[VLIB_TX];
      len0 = vlib_buffer_length_in_chain (vm, b[0]);

      if (PREDICT_TRUE (sw_if_index0 == last_sw_if_index))
	{
	  n_packets++;
	  n_bytes += len0;
	}
      else
	{
	  vnet_hw_interface_t *hi =
	    vnet_get_sup_hw_interface (vnm, sw_if_index0);
	  ipsec_tunnel_if_t *t =
	    pool_elt_at_index (im->tunnel_interfaces, hi->dev_instance);
	  last_sa_index = t->output_sa_index;

	  if (n_packets)
	    vlib_increment_combined_counter (vim->combined_sw_if_counters +
					     VNET_INTERFACE_COUNTER_TX,
					     thread_index, last_sw_if_index,
					     n_packets, n_bytes);

	  last_sw_if_index = sw_if_index0;
	  n_packets = 1;
	  n_bytes = len0;
	}
      vnet_buffer (b[0])->ipsec.sad_index = last_sa_index;

      if (PREDICT_FALSE (is_trace))
	{
	  if (b[0]->flags & VLIB_BUFFER_IS_TRACED)
	    {
	      ipsec_if_output_trace_t *tr =
		vlib_add_trace (vm, node, b[0], sizeof (*tr));
	      ipsec_sa_t *sa0 = pool_elt_at_index (im->sad,
						   vnet_buffer (b[0])->ipsec.
						   sad_index);
	      tr->spi = sa0->spi;
	    }
	}

      /* next */
      b += 1;
      next += 1;
      n_left_from -= 1;
    }

  if (n_packets)
    {
      vlib_increment_combined_counter (vim->combined_sw_if_counters +
				       VNET_INTERFACE_COUNTER_TX,
				       thread_index,
				       last_sw_if_index, n_packets, n_bytes);
    }

  vlib_node_increment_counter (vm, node->node_index,
			       IPSEC_IF_OUTPUT_ERROR_TX,
			       from_frame->n_vectors);

  vlib_buffer_enqueue_to_next (vm, node, from, nexts, from_frame->n_vectors);

  return from_frame->n_vectors;
}

VLIB_NODE_FN (ipsec4_if_output_node) (vlib_main_t * vm,
				      vlib_node_runtime_t * node,
				      vlib_frame_t * from_frame)
{
  if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE))
    return ipsec_if_output_inline (vm, node, from_frame, 0,
				   1 /* is_trace */ );
  else
    return ipsec_if_output_inline (vm, node, from_frame, 0,
				   0 /* is_trace */ );
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (ipsec4_if_output_node) = {
  .name = "ipsec4-if-output",
  .vector_size = sizeof (u32),
  .format_trace = format_ipsec_if_output_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(ipsec_if_output_error_strings),
  .error_strings = ipsec_if_output_error_strings,
  .sibling_of = "ipsec4-output-feature",
};
/* *INDENT-ON* */

VLIB_NODE_FN (ipsec6_if_output_node) (vlib_main_t * vm,
				      vlib_node_runtime_t * node,
				      vlib_frame_t * from_frame)
{
  if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE))
    return ipsec_if_output_inline (vm, node, from_frame, 1,
				   1 /* is_trace */ );
  else
    return ipsec_if_output_inline (vm, node, from_frame, 1,
				   0 /* is_trace */ );
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (ipsec6_if_output_node) = {
  .name = "ipsec6-if-output",
  .vector_size = sizeof (u32),
  .format_trace = format_ipsec_if_output_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(ipsec_if_output_error_strings),
  .error_strings = ipsec_if_output_error_strings,
  .sibling_of = "ipsec6-output-feature",
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
