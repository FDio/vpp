/*
 * ipsec_if_in.c : IPSec interface input node
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
#include <vnet/ipsec/esp.h>
#include <vnet/ipsec/ipsec_io.h>

/* Statistics (not really errors) */
#define foreach_ipsec_if_input_error				  \
_(RX, "good packets received")					  \
_(DISABLED, "ipsec packets received on disabled interface")       \
_(NO_TUNNEL, "no matching tunnel")

static char *ipsec_if_input_error_strings[] = {
#define _(sym,string) string,
  foreach_ipsec_if_input_error
#undef _
};

typedef enum
{
#define _(sym,str) IPSEC_IF_INPUT_ERROR_##sym,
  foreach_ipsec_if_input_error
#undef _
    IPSEC_IF_INPUT_N_ERROR,
} ipsec_if_input_error_t;


typedef struct
{
  u32 spi;
  u32 seq;
} ipsec_if_input_trace_t;

static u8 *
format_ipsec_if_input_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  ipsec_if_input_trace_t *t = va_arg (*args, ipsec_if_input_trace_t *);

  s = format (s, "IPSec: spi %u seq %u", t->spi, t->seq);
  return s;
}

VLIB_NODE_FN (ipsec_if_input_node) (vlib_main_t * vm,
				    vlib_node_runtime_t * node,
				    vlib_frame_t * from_frame)
{
  ipsec_main_t *im = &ipsec_main;
  vnet_main_t *vnm = im->vnet_main;
  vnet_interface_main_t *vim = &vnm->interface_main;
  u32 *from, *to_next = 0, next_index;
  u32 n_left_from, last_sw_if_index = ~0;
  u32 thread_index = vm->thread_index;
  u64 n_bytes = 0, n_packets = 0;
  const ipsec_tunnel_if_t *last_t = NULL;
  vlib_combined_counter_main_t *rx_counter;
  vlib_combined_counter_main_t *drop_counter;
  u32 n_disabled = 0, n_no_tunnel = 0;

  rx_counter = vim->combined_sw_if_counters + VNET_INTERFACE_COUNTER_RX;
  drop_counter = vim->combined_sw_if_counters + VNET_INTERFACE_COUNTER_DROP;

  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0, next0, sw_if_index0;
	  const esp_header_t *esp0;
	  const ip4_header_t *ip0;
	  vlib_buffer_t *b0;
	  uword *p;
	  u32 len0;

	  bi0 = to_next[0] = from[0];
	  from += 1;
	  n_left_from -= 1;
	  to_next += 1;
	  n_left_to_next -= 1;
	  b0 = vlib_get_buffer (vm, bi0);
	  ip0 = vlib_buffer_get_current (b0);
	  esp0 = (const esp_header_t *) ((u8 *) ip0 + ip4_header_bytes (ip0));

	  next0 = IPSEC_INPUT_NEXT_DROP;

	  u64 key = (u64) ip0->src_address.as_u32 << 32 | (u64) esp0->spi;

	  p = hash_get (im->ipsec_if_pool_index_by_key, key);

	  /* stats for the tunnel include all the data after the IP header
	     just like a norml IP-IP tunnel */
	  vlib_buffer_advance (b0, ip4_header_bytes (ip0));
	  len0 = vlib_buffer_length_in_chain (vm, b0);

	  if (PREDICT_TRUE (NULL != p))
	    {
	      const ipsec_tunnel_if_t *t0;

	      t0 = pool_elt_at_index (im->tunnel_interfaces, p[0]);
	      vnet_buffer (b0)->ipsec.sad_index = t0->input_sa_index;

	      if (PREDICT_TRUE (t0->hw_if_index != ~0))
		{
		  vnet_buffer (b0)->ipsec.flags = 0;
		  sw_if_index0 = t0->sw_if_index;
		  vnet_buffer (b0)->sw_if_index[VLIB_RX] = sw_if_index0;

		  if (PREDICT_FALSE
		      (!(t0->flags & VNET_HW_INTERFACE_FLAG_LINK_UP)))
		    {
		      vlib_increment_combined_counter
			(drop_counter, thread_index, sw_if_index0, 1, len0);
		      b0->error = node->errors[IPSEC_IF_INPUT_ERROR_DISABLED];
		      n_disabled++;
		      goto trace;
		    }

		  if (PREDICT_TRUE (sw_if_index0 == last_sw_if_index))
		    {
		      n_packets++;
		      n_bytes += len0;
		    }
		  else
		    {
		      if (last_t)
			{
			  vlib_increment_combined_counter
			    (rx_counter, thread_index, sw_if_index0,
			     n_packets, n_bytes);
			}

		      last_sw_if_index = sw_if_index0;
		      last_t = t0;
		      n_packets = 1;
		      n_bytes = len0;
		    }
		}
	      else
		{
		  vnet_buffer (b0)->ipsec.flags = IPSEC_FLAG_IPSEC_GRE_TUNNEL;
		}

	      next0 = im->esp4_decrypt_next_index;
	    }
	  else
	    {
	      b0->error = node->errors[IPSEC_IF_INPUT_ERROR_NO_TUNNEL];
	      n_no_tunnel++;
	    }

	trace:
	  if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      ipsec_if_input_trace_t *tr =
		vlib_add_trace (vm, node, b0, sizeof (*tr));
	      tr->spi = clib_host_to_net_u32 (esp0->spi);
	      tr->seq = clib_host_to_net_u32 (esp0->seq);
	    }

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);
	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  if (last_t)
    {
      vlib_increment_combined_counter (rx_counter,
				       thread_index,
				       last_sw_if_index, n_packets, n_bytes);
    }

  vlib_node_increment_counter (vm, ipsec_if_input_node.index,
			       IPSEC_IF_INPUT_ERROR_RX,
			       from_frame->n_vectors - n_disabled);

  vlib_node_increment_counter (vm, ipsec_if_input_node.index,
			       IPSEC_IF_INPUT_ERROR_DISABLED, n_disabled);
  vlib_node_increment_counter (vm, ipsec_if_input_node.index,
			       IPSEC_IF_INPUT_ERROR_DISABLED, n_no_tunnel);

  return from_frame->n_vectors;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (ipsec_if_input_node) = {
  .name = "ipsec-if-input",
  .vector_size = sizeof (u32),
  .format_trace = format_ipsec_if_input_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(ipsec_if_input_error_strings),
  .error_strings = ipsec_if_input_error_strings,

  .sibling_of = "ipsec4-input-feature",
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
