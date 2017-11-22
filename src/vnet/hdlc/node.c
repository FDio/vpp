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
/*
 * hdlc_node.c: hdlc packet processing
 *
 * Copyright (c) 2010 Eliot Dresselhaus
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 *  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 *  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 *  NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 *  LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 *  OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 *  WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#include <vlib/vlib.h>
#include <vnet/pg/pg.h>
#include <vnet/hdlc/hdlc.h>
#include <vppinfra/sparse_vec.h>

#define foreach_hdlc_input_next			\
  _ (PUNT, "error-punt")			\
  _ (DROP, "error-drop")

typedef enum
{
#define _(s,n) HDLC_INPUT_NEXT_##s,
  foreach_hdlc_input_next
#undef _
    HDLC_INPUT_N_NEXT,
} hdlc_input_next_t;

typedef struct
{
  u8 packet_data[32];
} hdlc_input_trace_t;

static u8 *
format_hdlc_input_trace (u8 * s, va_list * va)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*va, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*va, vlib_node_t *);
  hdlc_input_trace_t *t = va_arg (*va, hdlc_input_trace_t *);

  s = format (s, "%U", format_hdlc_header, t->packet_data);

  return s;
}

typedef struct
{
  /* Sparse vector mapping hdlc protocol in network byte order
     to next index. */
  u16 *next_by_protocol;

  u32 *sparse_index_by_next_index;
} hdlc_input_runtime_t;

static uword
hdlc_input (vlib_main_t * vm,
	    vlib_node_runtime_t * node, vlib_frame_t * from_frame)
{
  hdlc_input_runtime_t *rt = (void *) node->runtime_data;
  u32 n_left_from, next_index, i_next, *from, *to_next;

  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;

  if (node->flags & VLIB_NODE_FLAG_TRACE)
    vlib_trace_frame_buffers_only (vm, node,
				   from,
				   n_left_from,
				   sizeof (from[0]),
				   sizeof (hdlc_input_trace_t));

  next_index = node->cached_next_index;
  i_next = vec_elt (rt->sparse_index_by_next_index, next_index);

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from >= 4 && n_left_to_next >= 2)
	{
	  u32 bi0, bi1;
	  vlib_buffer_t *b0, *b1;
	  hdlc_header_t *h0, *h1;
	  u32 i0, i1, len0, len1, protocol0, protocol1, enqueue_code;

	  /* Prefetch next iteration. */
	  {
	    vlib_buffer_t *b2, *b3;

	    b2 = vlib_get_buffer (vm, from[2]);
	    b3 = vlib_get_buffer (vm, from[3]);

	    vlib_prefetch_buffer_header (b2, LOAD);
	    vlib_prefetch_buffer_header (b3, LOAD);

	    CLIB_PREFETCH (b2->data, sizeof (h0[0]), LOAD);
	    CLIB_PREFETCH (b3->data, sizeof (h1[0]), LOAD);
	  }

	  bi0 = from[0];
	  bi1 = from[1];
	  to_next[0] = bi0;
	  to_next[1] = bi1;
	  from += 2;
	  to_next += 2;
	  n_left_to_next -= 2;
	  n_left_from -= 2;

	  b0 = vlib_get_buffer (vm, bi0);
	  b1 = vlib_get_buffer (vm, bi1);

	  h0 = (void *) (b0->data + b0->current_data);
	  h1 = (void *) (b1->data + b1->current_data);

	  protocol0 = h0->protocol;
	  protocol1 = h1->protocol;

	  /* Add padding bytes for OSI protocols. */
	  len0 = sizeof (h0[0]);
	  len1 = sizeof (h1[0]);

	  len0 += protocol0 == clib_host_to_net_u16 (HDLC_PROTOCOL_osi);
	  len1 += protocol1 == clib_host_to_net_u16 (HDLC_PROTOCOL_osi);

	  b0->current_data += len0;
	  b1->current_data += len1;

	  b0->current_length -= len0;
	  b1->current_length -= len1;

	  /* Index sparse array with network byte order. */
	  sparse_vec_index2 (rt->next_by_protocol, protocol0, protocol1, &i0,
			     &i1);

	  b0->error =
	    node->errors[i0 ==
			 SPARSE_VEC_INVALID_INDEX ?
			 HDLC_ERROR_UNKNOWN_PROTOCOL : HDLC_ERROR_NONE];
	  b1->error =
	    node->errors[i1 ==
			 SPARSE_VEC_INVALID_INDEX ?
			 HDLC_ERROR_UNKNOWN_PROTOCOL : HDLC_ERROR_NONE];

	  enqueue_code = (i0 != i_next) + 2 * (i1 != i_next);

	  if (PREDICT_FALSE (enqueue_code != 0))
	    {
	      switch (enqueue_code)
		{
		case 1:
		  /* A B A */
		  to_next[-2] = bi1;
		  to_next -= 1;
		  n_left_to_next += 1;
		  vlib_set_next_frame_buffer (vm, node,
					      vec_elt (rt->next_by_protocol,
						       i0), bi0);
		  break;

		case 2:
		  /* A A B */
		  to_next -= 1;
		  n_left_to_next += 1;
		  vlib_set_next_frame_buffer (vm, node,
					      vec_elt (rt->next_by_protocol,
						       i1), bi1);
		  break;

		case 3:
		  /* A B B or A B C */
		  to_next -= 2;
		  n_left_to_next += 2;
		  vlib_set_next_frame_buffer (vm, node,
					      vec_elt (rt->next_by_protocol,
						       i0), bi0);
		  vlib_set_next_frame_buffer (vm, node,
					      vec_elt (rt->next_by_protocol,
						       i1), bi1);
		  if (i0 == i1)
		    {
		      vlib_put_next_frame (vm, node, next_index,
					   n_left_to_next);
		      i_next = i1;
		      next_index = vec_elt (rt->next_by_protocol, i_next);
		      vlib_get_next_frame (vm, node, next_index, to_next,
					   n_left_to_next);
		    }
		}
	    }
	}

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0;
	  vlib_buffer_t *b0;
	  hdlc_header_t *h0;
	  u32 i0, len0, protocol0;

	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);

	  h0 = (void *) (b0->data + b0->current_data);

	  protocol0 = h0->protocol;

	  /* Add padding bytes for OSI protocols. */
	  len0 = sizeof (h0[0]);
	  len0 += protocol0 == clib_host_to_net_u16 (HDLC_PROTOCOL_osi);

	  b0->current_data += len0;
	  b0->current_length -= len0;

	  i0 = sparse_vec_index (rt->next_by_protocol, protocol0);

	  b0->error =
	    node->errors[i0 ==
			 SPARSE_VEC_INVALID_INDEX ?
			 HDLC_ERROR_UNKNOWN_PROTOCOL : HDLC_ERROR_NONE];

	  /* Sent packet to wrong next? */
	  if (PREDICT_FALSE (i0 != i_next))
	    {
	      /* Return old frame; remove incorrectly enqueued packet. */
	      vlib_put_next_frame (vm, node, next_index, n_left_to_next + 1);

	      /* Send to correct next. */
	      i_next = i0;
	      next_index = vec_elt (rt->next_by_protocol, i_next);
	      vlib_get_next_frame (vm, node, next_index,
				   to_next, n_left_to_next);

	      to_next[0] = bi0;
	      to_next += 1;
	      n_left_to_next -= 1;
	    }
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return from_frame->n_vectors;
}

static char *hdlc_error_strings[] = {
#define hdlc_error(n,s) s,
#include "error.def"
#undef hdlc_error
};

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (hdlc_input_node) = {
  .function = hdlc_input,
  .name = "hdlc-input",
  /* Takes a vector of packets. */
  .vector_size = sizeof (u32),

  .runtime_data_bytes = sizeof (hdlc_input_runtime_t),

  .n_errors = HDLC_N_ERROR,
  .error_strings = hdlc_error_strings,

  .n_next_nodes = HDLC_INPUT_N_NEXT,
  .next_nodes = {
#define _(s,n) [HDLC_INPUT_NEXT_##s] = n,
    foreach_hdlc_input_next
#undef _
  },

  .format_buffer = format_hdlc_header_with_length,
  .format_trace = format_hdlc_input_trace,
  .unformat_buffer = unformat_hdlc_header,
};
/* *INDENT-ON* */

static clib_error_t *
hdlc_input_runtime_init (vlib_main_t * vm)
{
  hdlc_input_runtime_t *rt;
  rt = vlib_node_get_runtime_data (vm, hdlc_input_node.index);

  rt->next_by_protocol = sparse_vec_new
    ( /* elt bytes */ sizeof (rt->next_by_protocol[0]),
     /* bits in index */ BITS (((hdlc_header_t *) 0)->protocol));

  vec_validate (rt->sparse_index_by_next_index, HDLC_INPUT_NEXT_DROP);
  vec_validate (rt->sparse_index_by_next_index, HDLC_INPUT_NEXT_PUNT);
  rt->sparse_index_by_next_index[HDLC_INPUT_NEXT_DROP]
    = SPARSE_VEC_INVALID_INDEX;
  rt->sparse_index_by_next_index[HDLC_INPUT_NEXT_PUNT]
    = SPARSE_VEC_INVALID_INDEX;

  return 0;
}

static clib_error_t *
hdlc_input_init (vlib_main_t * vm)
{

  {
    clib_error_t *error = vlib_call_init_function (vm, hdlc_init);
    if (error)
      clib_error_report (error);
  }

  hdlc_setup_node (vm, hdlc_input_node.index);
  hdlc_input_runtime_init (vm);

  return 0;
}

VLIB_INIT_FUNCTION (hdlc_input_init);
VLIB_WORKER_INIT_FUNCTION (hdlc_input_runtime_init);

void
hdlc_register_input_protocol (vlib_main_t * vm,
			      hdlc_protocol_t protocol, u32 node_index)
{
  hdlc_main_t *em = &hdlc_main;
  hdlc_protocol_info_t *pi;
  hdlc_input_runtime_t *rt;
  u16 *n;
  u32 i;

  {
    clib_error_t *error = vlib_call_init_function (vm, hdlc_input_init);
    if (error)
      clib_error_report (error);
  }

  pi = hdlc_get_protocol_info (em, protocol);
  pi->node_index = node_index;
  pi->next_index = vlib_node_add_next (vm, hdlc_input_node.index, node_index);

  /* Setup hdlc protocol -> next index sparse vector mapping. */
  rt = vlib_node_get_runtime_data (vm, hdlc_input_node.index);
  n =
    sparse_vec_validate (rt->next_by_protocol,
			 clib_host_to_net_u16 (protocol));
  n[0] = pi->next_index;

  /* Rebuild next index -> sparse index inverse mapping when sparse vector
     is updated. */
  vec_validate (rt->sparse_index_by_next_index, pi->next_index);
  for (i = 1; i < vec_len (rt->next_by_protocol); i++)
    rt->sparse_index_by_next_index[rt->next_by_protocol[i]] = i;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
