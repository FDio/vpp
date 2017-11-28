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
  u32 seq;
} ipsec_if_output_trace_t;

u8 *
format_ipsec_if_output_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  ipsec_if_output_trace_t *t = va_arg (*args, ipsec_if_output_trace_t *);

  s = format (s, "IPSec: spi %u seq %u", t->spi, t->seq);
  return s;
}

static uword
ipsec_if_output_node_fn_inline (vlib_main_t * vm, vlib_node_runtime_t * node,
				vlib_frame_t * from_frame,
				int collect_detailed_stats)
{
  ipsec_main_t *im = &ipsec_main;
  vnet_main_t *vnm = im->vnet_main;
  vnet_interface_main_t *vim = &vnm->interface_main;
  u32 *from, *to_next = 0, next_index;
  u32 n_left_from, sw_if_index0, last_sw_if_index = ~0;
  u32 thread_index = vlib_get_thread_index ();
  u32 stats_n_packets[VNET_N_COMBINED_INTERFACE_COUNTER];
  u64 stats_n_bytes[VNET_N_COMBINED_INTERFACE_COUNTER];
  if (collect_detailed_stats)
    {
      memset (stats_n_packets, 0, sizeof (stats_n_packets));
      memset (stats_n_bytes, 0, sizeof (stats_n_bytes));
    }
  else
    {
      stats_n_packets[VNET_INTERFACE_COUNTER_TX] = 0;
      stats_n_bytes[VNET_INTERFACE_COUNTER_TX] = 0;
    }

  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0, next0, len0;
	  vlib_buffer_t *b0;
	  int b0_ctype;
	  ipsec_tunnel_if_t *t0;
	  vnet_hw_interface_t *hi0;

	  bi0 = to_next[0] = from[0];
	  from += 1;
	  n_left_from -= 1;
	  to_next += 1;
	  n_left_to_next -= 1;
	  b0 = vlib_get_buffer (vm, bi0);
	  sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_TX];
	  hi0 = vnet_get_sup_hw_interface (vnm, sw_if_index0);
	  t0 = pool_elt_at_index (im->tunnel_interfaces, hi0->dev_instance);
	  vnet_buffer (b0)->ipsec.sad_index = t0->output_sa_index;
	  next0 = im->esp_encrypt_next_index;

	  len0 = vlib_buffer_length_in_chain (vm, b0);

	  if (collect_detailed_stats)
	    {
	      b0_ctype =
		eh_dst_addr_to_tx_ctype (vlib_buffer_get_current (b0));
	    }

	  if (PREDICT_TRUE (sw_if_index0 == last_sw_if_index))
	    {
	      stats_n_packets[VNET_INTERFACE_COUNTER_TX] += 1;
	      stats_n_bytes[VNET_INTERFACE_COUNTER_TX] += len0;
	      if (collect_detailed_stats)
		{
		  stats_n_packets[b0_ctype] += 1;
		  stats_n_bytes[b0_ctype] += len0;
		}
	    }
	  else
	    {
	      last_sw_if_index = sw_if_index0;
#define inc_counter(ctype, rx_tx)                                          \
  if (stats_n_packets[ctype])                                              \
    {                                                                      \
      vlib_increment_combined_counter (                                    \
          vim->combined_sw_if_counters + ctype, thread_index,              \
          last_sw_if_index, stats_n_packets[ctype], stats_n_bytes[ctype]); \
    }
	      if (collect_detailed_stats)
		{
		  foreach_combined_interface_counter (inc_counter);
		  memset (stats_n_packets, 0, sizeof (stats_n_packets));
		  memset (stats_n_bytes, 0, sizeof (stats_n_bytes));
		}
	      else
		{
		  inc_counter (VNET_INTERFACE_COUNTER_TX, tx);
		}
	      stats_n_packets[VNET_INTERFACE_COUNTER_TX] = 1;
	      stats_n_bytes[VNET_INTERFACE_COUNTER_TX] = len0;
	      if (collect_detailed_stats)
		{
		  stats_n_packets[b0_ctype] = 1;
		  stats_n_bytes[b0_ctype] = len0;
		}
	    }

	  if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      ipsec_if_output_trace_t *tr =
		vlib_add_trace (vm, node, b0, sizeof (*tr));
	      ipsec_sa_t *sa0 =
		pool_elt_at_index (im->sad, t0->output_sa_index);
	      tr->spi = sa0->spi;
	      tr->seq = sa0->seq;
	    }

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);
	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  if (last_sw_if_index != ~0)
    {
      if (collect_detailed_stats)
	{
	  foreach_combined_interface_counter (inc_counter);
	}
      else
	{
	  inc_counter (VNET_INTERFACE_COUNTER_TX, tx);
	}
    }

  vlib_node_increment_counter (vm, ipsec_if_output_node.index,
			       IPSEC_IF_OUTPUT_ERROR_TX,
			       from_frame->n_vectors);

  return from_frame->n_vectors;
}

static uword
ipsec_if_output_node_fn (vlib_main_t * vm, vlib_node_runtime_t * node,
			 vlib_frame_t * from_frame)
{
  if (collect_detailed_interface_stats ())
    {
      return ipsec_if_output_node_fn_inline (vm, node, from_frame,
					     COLLECT_DETAILED_STATS);
    }
  else
    {
      return ipsec_if_output_node_fn_inline (vm, node, from_frame,
					     COLLECT_SIMPLE_STATS);
    }
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (ipsec_if_output_node) = {
  .function = ipsec_if_output_node_fn,
  .name = "ipsec-if-output",
  .vector_size = sizeof (u32),
  .format_trace = format_ipsec_if_output_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(ipsec_if_output_error_strings),
  .error_strings = ipsec_if_output_error_strings,

  .sibling_of = "ipsec-output-ip4",
};
/* *INDENT-ON* */

VLIB_NODE_FUNCTION_MULTIARCH (ipsec_if_output_node, ipsec_if_output_node_fn)
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
