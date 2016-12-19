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
 * snap_node.c: snap packet processing
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
#include <vnet/llc/llc.h>
#include <vnet/snap/snap.h>

typedef enum
{
  SNAP_INPUT_NEXT_DROP,
  SNAP_INPUT_NEXT_PUNT,
  SNAP_INPUT_NEXT_ETHERNET_TYPE,
  SNAP_INPUT_N_NEXT,
} snap_input_next_t;

typedef struct
{
  u8 packet_data[32];
} snap_input_trace_t;

static u8 *
format_snap_input_trace (u8 * s, va_list * va)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*va, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*va, vlib_node_t *);
  snap_input_trace_t *t = va_arg (*va, snap_input_trace_t *);

  s = format (s, "%U", format_snap_header, t->packet_data);

  return s;
}

static uword
snap_input (vlib_main_t * vm,
	    vlib_node_runtime_t * node, vlib_frame_t * from_frame)
{
  snap_main_t *sm = &snap_main;
  u32 n_left_from, next_index, *from, *to_next;

  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;

  if (node->flags & VLIB_NODE_FLAG_TRACE)
    vlib_trace_frame_buffers_only (vm, node,
				   from,
				   n_left_from,
				   sizeof (from[0]),
				   sizeof (snap_input_trace_t));

  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from >= 4 && n_left_to_next >= 2)
	{
	  u32 bi0, bi1;
	  vlib_buffer_t *b0, *b1;
	  snap_header_t *h0, *h1;
	  snap_protocol_info_t *pi0, *pi1;
	  u8 next0, next1, is_ethernet0, is_ethernet1, len0, len1,
	    enqueue_code;
	  u32 oui0, oui1;

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

	  oui0 = snap_header_get_oui (h0);
	  oui1 = snap_header_get_oui (h1);

	  is_ethernet0 = oui0 == IEEE_OUI_ethernet;
	  is_ethernet1 = oui1 == IEEE_OUI_ethernet;

	  len0 = sizeof (h0[0]) - (is_ethernet0 ? sizeof (h0->protocol) : 0);
	  len1 = sizeof (h1[0]) - (is_ethernet1 ? sizeof (h1->protocol) : 0);

	  b0->current_data += len0;
	  b1->current_data += len1;

	  b0->current_length -= len0;
	  b1->current_length -= len1;

	  pi0 = snap_get_protocol_info (sm, h0);
	  pi1 = snap_get_protocol_info (sm, h1);

	  next0 = pi0 ? pi0->next_index : SNAP_INPUT_NEXT_DROP;
	  next1 = pi1 ? pi1->next_index : SNAP_INPUT_NEXT_DROP;

	  next0 = is_ethernet0 ? SNAP_INPUT_NEXT_ETHERNET_TYPE : next0;
	  next1 = is_ethernet1 ? SNAP_INPUT_NEXT_ETHERNET_TYPE : next1;

	  /* In case of error. */
	  b0->error = node->errors[SNAP_ERROR_UNKNOWN_PROTOCOL];
	  b1->error = node->errors[SNAP_ERROR_UNKNOWN_PROTOCOL];

	  enqueue_code = (next0 != next_index) + 2 * (next1 != next_index);

	  if (PREDICT_FALSE (enqueue_code != 0))
	    {
	      switch (enqueue_code)
		{
		case 1:
		  /* A B A */
		  to_next[-2] = bi1;
		  to_next -= 1;
		  n_left_to_next += 1;
		  vlib_set_next_frame_buffer (vm, node, next0, bi0);
		  break;

		case 2:
		  /* A A B */
		  to_next -= 1;
		  n_left_to_next += 1;
		  vlib_set_next_frame_buffer (vm, node, next1, bi1);
		  break;

		case 3:
		  /* A B B or A B C */
		  to_next -= 2;
		  n_left_to_next += 2;
		  vlib_set_next_frame_buffer (vm, node, next0, bi0);
		  vlib_set_next_frame_buffer (vm, node, next1, bi1);
		  if (next0 == next1)
		    {
		      vlib_put_next_frame (vm, node, next_index,
					   n_left_to_next);
		      next_index = next1;
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
	  snap_header_t *h0;
	  snap_protocol_info_t *pi0;
	  u8 next0, is_ethernet0, len0;
	  u32 oui0;

	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);

	  h0 = (void *) (b0->data + b0->current_data);

	  oui0 = snap_header_get_oui (h0);

	  is_ethernet0 = oui0 == IEEE_OUI_ethernet;

	  len0 = sizeof (h0[0]) - (is_ethernet0 ? sizeof (h0->protocol) : 0);

	  b0->current_data += len0;

	  b0->current_length -= len0;

	  pi0 = snap_get_protocol_info (sm, h0);

	  next0 = pi0 ? pi0->next_index : SNAP_INPUT_NEXT_DROP;

	  next0 = is_ethernet0 ? SNAP_INPUT_NEXT_ETHERNET_TYPE : next0;

	  /* In case of error. */
	  b0->error = node->errors[SNAP_ERROR_UNKNOWN_PROTOCOL];

	  /* Sent packet to wrong next? */
	  if (PREDICT_FALSE (next0 != next_index))
	    {
	      /* Return old frame; remove incorrectly enqueued packet. */
	      vlib_put_next_frame (vm, node, next_index, n_left_to_next + 1);

	      /* Send to correct next. */
	      next_index = next0;
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

static char *snap_error_strings[] = {
#define _(f,s) s,
  foreach_snap_error
#undef _
};

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (snap_input_node) = {
  .function = snap_input,
  .name = "snap-input",
  /* Takes a vector of packets. */
  .vector_size = sizeof (u32),

  .n_errors = SNAP_N_ERROR,
  .error_strings = snap_error_strings,

  .n_next_nodes = SNAP_INPUT_N_NEXT,
  .next_nodes = {
    [SNAP_INPUT_NEXT_DROP] = "error-drop",
    [SNAP_INPUT_NEXT_PUNT] = "error-punt",
    [SNAP_INPUT_NEXT_ETHERNET_TYPE] = "ethernet-input-type",
  },

  .format_buffer = format_snap_header_with_length,
  .format_trace = format_snap_input_trace,
  .unformat_buffer = unformat_snap_header,
};
/* *INDENT-ON* */

static clib_error_t *
snap_input_init (vlib_main_t * vm)
{
  {
    clib_error_t *error = vlib_call_init_function (vm, snap_init);
    if (error)
      clib_error_report (error);
  }

  snap_setup_node (vm, snap_input_node.index);

  llc_register_input_protocol (vm, LLC_PROTOCOL_snap, snap_input_node.index);

  return 0;
}

VLIB_INIT_FUNCTION (snap_input_init);

void
snap_register_input_protocol (vlib_main_t * vm,
			      char *name,
			      u32 ieee_oui, u16 protocol, u32 node_index)
{
  snap_main_t *sm = &snap_main;
  snap_protocol_info_t *pi;
  snap_header_t h;
  snap_oui_and_protocol_t key;

  {
    clib_error_t *error = vlib_call_init_function (vm, snap_input_init);
    if (error)
      clib_error_report (error);
  }

  h.protocol = clib_host_to_net_u16 (protocol);
  h.oui[0] = (ieee_oui >> 16) & 0xff;
  h.oui[1] = (ieee_oui >> 8) & 0xff;
  h.oui[2] = (ieee_oui >> 0) & 0xff;
  pi = snap_get_protocol_info (sm, &h);
  if (pi)
    return;

  vec_add2 (sm->protocols, pi, 1);

  pi->name = format (0, "%s", name);
  pi->node_index = node_index;
  pi->next_index = vlib_node_add_next (vm, snap_input_node.index, node_index);

  key.oui = ieee_oui;
  key.protocol = clib_host_to_net_u16 (protocol);

  mhash_set (&sm->protocol_hash, &key, pi - sm->protocols, /* old_value */ 0);
  hash_set_mem (sm->protocol_info_by_name, name, pi - sm->protocols);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
