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

/* Statistics (not really errors) */
#define foreach_ipsec_if_input_error    \
_(RX, "good packets received")

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

u8 *
format_ipsec_if_input_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  ipsec_if_input_trace_t *t = va_arg (*args, ipsec_if_input_trace_t *);

  s = format (s, "IPSec: spi %u seq %u", t->spi, t->seq);
  return s;
}

static uword
ipsec_if_input_node_fn (vlib_main_t * vm, vlib_node_runtime_t * node,
			vlib_frame_t * from_frame)
{
  ipsec_main_t *im = &ipsec_main;
  u32 *from, *to_next = 0, next_index;
  u32 n_left_from;

  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0, next0;
	  vlib_buffer_t *b0;
	  ip4_header_t *ip0;
	  esp_header_t *esp0;
	  uword *p;

	  bi0 = to_next[0] = from[0];
	  from += 1;
	  n_left_from -= 1;
	  to_next += 1;
	  n_left_to_next -= 1;
	  b0 = vlib_get_buffer (vm, bi0);
	  ip0 = vlib_buffer_get_current (b0);
	  esp0 = (esp_header_t *) ((u8 *) ip0 + ip4_header_bytes (ip0));

	  next0 = IPSEC_INPUT_NEXT_DROP;

	  u64 key = (u64) ip0->src_address.as_u32 << 32 |
	    (u64) clib_net_to_host_u32 (esp0->spi);

	  p = hash_get (im->ipsec_if_pool_index_by_key, key);

	  if (p)
	    {
	      ipsec_tunnel_if_t *t;
	      t = pool_elt_at_index (im->tunnel_interfaces, p[0]);
	      vnet_buffer (b0)->ipsec.sad_index = t->input_sa_index;
	      vnet_buffer (b0)->ipsec.flags =
		t->hw_if_index == ~0 ? IPSEC_FLAG_IPSEC_GRE_TUNNEL : 0;
	      vlib_buffer_advance (b0, ip4_header_bytes (ip0));
	      next0 = im->esp_decrypt_next_index;
	    }

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

  vlib_node_increment_counter (vm, ipsec_if_input_node.index,
			       IPSEC_IF_INPUT_ERROR_RX,
			       from_frame->n_vectors);

  return from_frame->n_vectors;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (ipsec_if_input_node) = {
  .function = ipsec_if_input_node_fn,
  .name = "ipsec-if-input",
  .vector_size = sizeof (u32),
  .format_trace = format_ipsec_if_input_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(ipsec_if_input_error_strings),
  .error_strings = ipsec_if_input_error_strings,

  .sibling_of = "ipsec-input-ip4",
};
/* *INDENT-ON* */

VLIB_NODE_FUNCTION_MULTIARCH (ipsec_if_input_node, ipsec_if_input_node_fn)
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
