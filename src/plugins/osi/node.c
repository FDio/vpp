/* SPDX-License-Identifier: Apache-2.0 OR MIT
 * Copyright (c) 2015 Cisco and/or its affiliates.
 * Copyright (c) 2010 Eliot Dresselhaus
 */

/* osi_node.c: osi packet processing */

#include <vlib/vlib.h>
#include <vnet/pg/pg.h>
#include <osi/osi.h>
#include <plugins/ppp/ppp.h>
#include <vnet/hdlc/hdlc.h>
#include <vnet/llc/llc.h>
#include <vnet/plugin/plugin.h>

#define foreach_osi_input_next			\
  _ (PUNT, "error-punt")			\
  _ (DROP, "error-drop")

typedef enum
{
#define _(s,n) OSI_INPUT_NEXT_##s,
  foreach_osi_input_next
#undef _
    OSI_INPUT_N_NEXT,
} osi_input_next_t;

typedef struct
{
  u8 packet_data[32];
} osi_input_trace_t;

static u8 *
format_osi_input_trace (u8 * s, va_list * va)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*va, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*va, vlib_node_t *);
  osi_input_trace_t *t = va_arg (*va, osi_input_trace_t *);

  s = format (s, "%U", format_osi_header, t->packet_data);

  return s;
}

static uword
osi_input (vlib_main_t * vm,
	   vlib_node_runtime_t * node, vlib_frame_t * from_frame)
{
  osi_main_t *lm = &osi_main;
  u32 n_left_from, next_index, *from, *to_next;

  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;

  if (node->flags & VLIB_NODE_FLAG_TRACE)
    vlib_trace_frame_buffers_only (vm, node,
				   from,
				   n_left_from,
				   sizeof (from[0]),
				   sizeof (osi_input_trace_t));

  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from >= 4 && n_left_to_next >= 2)
	{
	  u32 bi0, bi1;
	  vlib_buffer_t *b0, *b1;
	  osi_header_t *h0, *h1;
	  u8 next0, next1, enqueue_code;

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

	  h0 = vlib_buffer_get_current (b0);
	  h1 = vlib_buffer_get_current (b1);

	  next0 = lm->input_next_by_protocol[h0->protocol];
	  next1 = lm->input_next_by_protocol[h1->protocol];

	  b0->error =
	    node->errors[next0 ==
			 OSI_INPUT_NEXT_DROP ? OSI_ERROR_UNKNOWN_PROTOCOL :
			 OSI_ERROR_NONE];
	  b1->error =
	    node->errors[next1 ==
			 OSI_INPUT_NEXT_DROP ? OSI_ERROR_UNKNOWN_PROTOCOL :
			 OSI_ERROR_NONE];

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
	  osi_header_t *h0;
	  u8 next0;

	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);

	  h0 = vlib_buffer_get_current (b0);

	  next0 = lm->input_next_by_protocol[h0->protocol];

	  b0->error =
	    node->errors[next0 ==
			 OSI_INPUT_NEXT_DROP ? OSI_ERROR_UNKNOWN_PROTOCOL :
			 OSI_ERROR_NONE];

	  /* Sent packet to wrong next? */
	  if (PREDICT_FALSE (next0 != next_index))
	    {
	      /* Return old frame; remove incorrectly enqueued packet. */
	      vlib_put_next_frame (vm, node, next_index, n_left_to_next + 1);

	      /* Send to correct next. */
	      next_index = next0;
	      vlib_get_next_frame (vm, node, next_index, to_next,
				   n_left_to_next);

	      to_next[0] = bi0;
	      to_next += 1;
	      n_left_to_next -= 1;
	    }
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return from_frame->n_vectors;
}

static char *osi_error_strings[] = {
#define _(f,s) s,
  foreach_osi_error
#undef _
};

VLIB_REGISTER_NODE (osi_input_node) = {
  .function = osi_input,
  .name = "osi-input",
  /* Takes a vector of packets. */
  .vector_size = sizeof (u32),

  .n_errors = OSI_N_ERROR,
  .error_strings = osi_error_strings,

  .n_next_nodes = OSI_INPUT_N_NEXT,
  .next_nodes = {
#define _(s,n) [OSI_INPUT_NEXT_##s] = n,
    foreach_osi_input_next
#undef _
  },

  .format_buffer = format_osi_header_with_length,
  .format_trace = format_osi_input_trace,
  .unformat_buffer = unformat_osi_header,
};

static void
osi_setup_node (vlib_main_t *vm, u32 node_index)
{
  vlib_node_t *n = vlib_get_node (vm, node_index);
  pg_node_t *pn = pg_get_node (node_index);

  n->format_buffer = format_osi_header_with_length;
  n->unformat_buffer = unformat_osi_header;
  pn->unformat_edit = unformat_pg_osi_header;
}

typedef void (*ppp_register_input_protocol_fn) (vlib_main_t *vm,
						ppp_protocol_t protocol,
						u32 node_index);

static clib_error_t *
osi_input_init (vlib_main_t * vm)
{
  clib_error_t *error = 0;
  osi_main_t *lm = &osi_main;
  ppp_register_input_protocol_fn ppp_register_input_protocol_fn_ptr;

  ppp_register_input_protocol_fn_ptr =
    vlib_get_plugin_symbol ("ppp_plugin.so", "ppp_register_input_protocol");
  if (ppp_register_input_protocol_fn_ptr == 0)
    {
      error = clib_error_return (0, "ppp_plugin.so is not loaded");
      return error;
    }

  if ((error = vlib_call_init_function (vm, osi_init)))
    return error;

  osi_setup_node (vm, osi_input_node.index);

  {
    int i;
    for (i = 0; i < ARRAY_LEN (lm->input_next_by_protocol); i++)
      lm->input_next_by_protocol[i] = OSI_INPUT_NEXT_DROP;
  }

  ppp_register_input_protocol_fn_ptr (vm, PPP_PROTOCOL_osi,
				      osi_input_node.index);
  hdlc_register_input_protocol (vm, HDLC_PROTOCOL_osi, osi_input_node.index);
  llc_register_input_protocol (vm, LLC_PROTOCOL_osi_layer1,
			       osi_input_node.index);
  llc_register_input_protocol (vm, LLC_PROTOCOL_osi_layer2,
			       osi_input_node.index);
  llc_register_input_protocol (vm, LLC_PROTOCOL_osi_layer3,
			       osi_input_node.index);
  llc_register_input_protocol (vm, LLC_PROTOCOL_osi_layer4,
			       osi_input_node.index);
  llc_register_input_protocol (vm, LLC_PROTOCOL_osi_layer5,
			       osi_input_node.index);

  return 0;
}

VLIB_INIT_FUNCTION (osi_input_init);

__clib_export int
osi_register_input_protocol (osi_protocol_t protocol, u32 node_index)
{
  osi_main_t *lm = &osi_main;
  vlib_main_t *vm = lm->vlib_main;
  osi_protocol_info_t *pi;

  {
    clib_error_t *error = vlib_call_init_function (vm, osi_input_init);
    if (error)
      clib_error_report (error);
  }

  pi = osi_get_protocol_info (lm, protocol);
  if (!pi)
    return VNET_API_ERROR_INVALID_REGISTRATION;
  pi->node_index = node_index;
  pi->next_index = vlib_node_add_next (vm, osi_input_node.index, node_index);

  lm->input_next_by_protocol[protocol] = pi->next_index;

  return 0;
}
