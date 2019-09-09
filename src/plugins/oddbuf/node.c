/*
 * node.c - - awkward chained buffer geometry test tool
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
#include <oddbuf/oddbuf.h>

typedef struct
{
  u32 sw_if_index;
  u32 next_index;
  u16 udp_checksum;
} oddbuf_trace_t;

#ifndef CLIB_MARCH_VARIANT

/* packet trace format function */
static u8 *
format_oddbuf_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  oddbuf_trace_t *t = va_arg (*args, oddbuf_trace_t *);

  s = format (s, "ODDBUF: sw_if_index %d, next index %d, udp checksum %04x\n",
	      t->sw_if_index, t->next_index, (u32) t->udp_checksum);
  return s;
}

vlib_node_registration_t oddbuf_node;

#endif /* CLIB_MARCH_VARIANT */

#define foreach_oddbuf_error \
_(SWAPPED, "Mac swap packets processed")

typedef enum
{
#define _(sym,str) ODDBUF_ERROR_##sym,
  foreach_oddbuf_error
#undef _
    ODDBUF_N_ERROR,
} oddbuf_error_t;

#ifndef CLIB_MARCH_VARIANT
static char *oddbuf_error_strings[] = {
#define _(sym,string) string,
  foreach_oddbuf_error
#undef _
};
#endif /* CLIB_MARCH_VARIANT */

typedef enum
{
  ODDBUF_NEXT_DROP,
  ODDBUF_N_NEXT,
} oddbuf_next_t;


always_inline uword
oddbuf_inline (vlib_main_t * vm,
	       vlib_node_runtime_t * node, vlib_frame_t * frame,
	       int is_ip4, int is_trace)
{
  oddbuf_main_t *om = &oddbuf_main;
  u32 n_left_from, *from;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;
  vlib_buffer_t *b0, *b0next;
  u32 bi;
  u16 nexts[VLIB_FRAME_SIZE], *next;
  u16 save_current_length;
  u32 next0;
  u8 *src, *dst;
  int i;
  ethernet_header_t *eh;
  ip4_header_t *ip;
  udp_header_t *udp;


  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;

  vlib_get_buffers (vm, from, bufs, n_left_from);
  b = bufs;
  next = nexts;

  while (n_left_from > 0)
    {
      b0 = b[0];
      vnet_feature_next (&next0, b0);
      nexts[0] = next0;

      if (vlib_buffer_alloc (vm, &bi, 1) != 1)
	{
	  clib_warning ("Buffer alloc fail, skipping");
	  goto skip;
	}

      if (om->first_chunk_offset)
	{
	  memmove (b0->data + b0->current_data + om->first_chunk_offset,
		   b0->data + b0->current_data, b0->current_length);
	  b0->current_data += om->first_chunk_offset;
	}

      eh = vlib_buffer_get_current (b0);
      ip = (ip4_header_t *) (eh + 1);
      udp = (udp_header_t *) (ip4_next_header (ip));

      if (1)
	{
	  save_current_length = vlib_buffer_length_in_chain (vm, b0);

	  b0next = vlib_get_buffer (vm, bi);
	  b0->flags |= VLIB_BUFFER_NEXT_PRESENT;
	  b0->flags &= ~VLIB_BUFFER_TOTAL_LENGTH_VALID;
	  b0->next_buffer = bi;

	  src = b0->data + b0->current_data + b0->current_length -
	    om->n_to_copy;
	  b0next->current_data = om->second_chunk_offset;
	  b0next->current_length = om->n_to_copy;
	  dst = b0next->data + b0next->current_data;

	  for (i = 0; i < om->n_to_copy; i++)
	    dst[i] = src[i];

	  b0->current_length -= om->n_to_copy;
	  b0next->current_length = om->n_to_copy;

	  if (vlib_buffer_length_in_chain (vm, b0) != save_current_length)
	    clib_warning ("OOPS, length incorrect after chunk split...");
	}

      udp->checksum = 0;
      udp->checksum = ip4_tcp_udp_compute_checksum (vm, b0, ip);

      if (is_trace)
	{
	  if (b[0]->flags & VLIB_BUFFER_IS_TRACED)
	    {
	      oddbuf_trace_t *t =
		vlib_add_trace (vm, node, b[0], sizeof (*t));
	      t->next_index = next[0];
	      t->sw_if_index = vnet_buffer (b[0])->sw_if_index[VLIB_RX];
	      t->udp_checksum = clib_net_to_host_u16 (udp->checksum);
	    }
	}

    skip:
      b += 1;
      next += 1;
      n_left_from -= 1;
    }

  vlib_buffer_enqueue_to_next (vm, node, from, nexts, frame->n_vectors);

  return frame->n_vectors;
}

VLIB_NODE_FN (oddbuf_node) (vlib_main_t * vm, vlib_node_runtime_t * node,
			    vlib_frame_t * frame)
{
  if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE))
    return oddbuf_inline (vm, node, frame, 1 /* is_ip4 */ ,
			  1 /* is_trace */ );
  else
    return oddbuf_inline (vm, node, frame, 1 /* is_ip4 */ ,
			  0 /* is_trace */ );
}

/* *INDENT-OFF* */
#ifndef CLIB_MARCH_VARIANT
VLIB_REGISTER_NODE (oddbuf_node) =
{
  .name = "oddbuf",
  .vector_size = sizeof (u32),
  .format_trace = format_oddbuf_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(oddbuf_error_strings),
  .error_strings = oddbuf_error_strings,

  .n_next_nodes = ODDBUF_N_NEXT,

  /* edit / add dispositions here */
  .next_nodes = {
        [ODDBUF_NEXT_DROP] = "error-drop",
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
