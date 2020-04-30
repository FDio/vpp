/*
 * node.c - packet data fuzzer
 *
 * Copyright (c) 2019 by Cisco and/or its affiliates.
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
#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/pg/pg.h>
#include <vppinfra/error.h>
#include <pfuzz/pfuzz.h>

typedef struct
{
  u32 sw_if_index;
  u32 next_index;
  u16 offset;
  u8 bits;
} pfuzz_trace_t;

#ifndef CLIB_MARCH_VARIANT

/* packet trace format function */
static u8 *
format_pfuzz_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  pfuzz_trace_t *t = va_arg (*args, pfuzz_trace_t *);

  s =
    format (s,
	    "PFUZZ: sw_if_index %d, next index %d, mangle offset %u bits 0x%x\n",
	    t->sw_if_index, t->next_index, (u32) t->offset, (u32) t->bits);
  return s;
}

vlib_node_registration_t pfuzz_node;

#endif /* CLIB_MARCH_VARIANT */

#define foreach_pfuzz_error \
_(FUZZED, "Packets fuzzed")

typedef enum
{
#define _(sym,str) PFUZZ_ERROR_##sym,
  foreach_pfuzz_error
#undef _
    PFUZZ_N_ERROR,
} pfuzz_error_t;

#ifndef CLIB_MARCH_VARIANT
static char *pfuzz_error_strings[] = {
#define _(sym,string) string,
  foreach_pfuzz_error
#undef _
};
#endif /* CLIB_MARCH_VARIANT */

typedef enum
{
  PFUZZ_NEXT_DROP,
  PFUZZ_N_NEXT,
} pfuzz_next_t;


always_inline uword
pfuzz_inline (vlib_main_t * vm,
	      vlib_node_runtime_t * node, vlib_frame_t * frame,
	      int is_ip4, int is_trace)
{
  pfuzz_main_t *pm = &pfuzz_main;
  u32 n_left_from, *from;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;
  vlib_buffer_t *b0;
  u16 nexts[VLIB_FRAME_SIZE], *next;
  u16 limit;
  u16 offset;
  u32 next0;
  u8 *target;
  u8 bits;
  ethernet_header_t *eh;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;

  vlib_get_buffers (vm, from, bufs, n_left_from);
  b = bufs;
  next = nexts;

  while (n_left_from > 0)
    {
      b0 = b[0];
      vnet_feature_next (&next0, b0);
      next[0] = next0;

      eh = vlib_buffer_get_current (b0);
      switch (pm->mode)
	{
	  /*
	   * Header mode: flip one bit
	   * somewhere in the ethernet or IP header
	   */
	case PFUZZ_MODE_HEADER:
	  limit = sizeof (*eh);
	  if (eh->type == ETHERNET_TYPE_IP6)
	    limit += sizeof (ip6_header_t);
	  else
	    limit += sizeof (ip4_header_t);
	  break;

	  /*
	   * Body / default mode: flip one octet's worth of bits
	   * somewhere in the packet
	   */
	default:
	  limit = b0->current_length;
	  break;
	}

      /* Just in case... */
      limit = clib_min (limit, b0->current_length);

      offset = random_u32 (&pm->seed) % limit;
      target = vlib_buffer_get_current (b0) + offset;
      bits = random_u32 (&pm->seed) & 0x7;
      *target ^= bits;

      if (is_trace)
	{
	  if (b[0]->flags & VLIB_BUFFER_IS_TRACED)
	    {
	      pfuzz_trace_t *t = vlib_add_trace (vm, node, b[0], sizeof (*t));
	      t->next_index = next[0];
	      t->sw_if_index = vnet_buffer (b[0])->sw_if_index[VLIB_RX];
	      t->offset = offset;
	      t->bits = bits;
	    }
	}

      b += 1;
      next += 1;
      n_left_from -= 1;
    }

  vlib_node_increment_counter (vm, node->node_index,
			       PFUZZ_ERROR_FUZZED, frame->n_vectors);
  vlib_buffer_enqueue_to_next (vm, node, from, nexts, frame->n_vectors);

  return frame->n_vectors;
}

VLIB_NODE_FN (pfuzz_node) (vlib_main_t * vm, vlib_node_runtime_t * node,
			   vlib_frame_t * frame)
{
  if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE))
    return pfuzz_inline (vm, node, frame, 1 /* is_ip4 */ ,
			 1 /* is_trace */ );
  else
    return pfuzz_inline (vm, node, frame, 1 /* is_ip4 */ ,
			 0 /* is_trace */ );
}

/* *INDENT-OFF* */
#ifndef CLIB_MARCH_VARIANT
VLIB_REGISTER_NODE (pfuzz_node) =
{
  .name = "pfuzz",
  .vector_size = sizeof (u32),
  .format_trace = format_pfuzz_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(pfuzz_error_strings),
  .error_strings = pfuzz_error_strings,

  .n_next_nodes = PFUZZ_N_NEXT,

  /* edit / add dispositions here */
  .next_nodes = {
        [PFUZZ_NEXT_DROP] = "error-drop",
  },
};
#endif /* CLIB_MARCH_VARIANT */
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
