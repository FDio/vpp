/*
 * l2_output_acl.c : layer 2 output acl processing
 *
 * Copyright (c) 2013 Cisco and/or its affiliates.
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
#include <vnet/ethernet/ethernet.h>
#include <vnet/ethernet/packet.h>
#include <vnet/ip/ip_packet.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>
#include <vlib/cli.h>
#include <vnet/l2/feat_bitmap.h>
#include <vnet/l2/l2_output.h>

#include <vppinfra/error.h>
#include <vppinfra/hash.h>
#include <vppinfra/cache.h>


typedef struct
{
  /* Next nodes for L2 output features */
  u32 l2_out_feat_next[32];

  /* convenience variables */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;
} l2_outacl_main_t;



typedef struct
{
  /* per-pkt trace data */
  u8 src[6];
  u8 dst[6];
  u32 next_index;
  u32 sw_if_index;
} l2_outacl_trace_t;

/* packet trace format function */
static u8 *
format_l2_outacl_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  l2_outacl_trace_t *t = va_arg (*args, l2_outacl_trace_t *);

  s = format (s, "l2-output-acl: sw_if_index %d dst %U src %U",
	      t->sw_if_index,
	      format_ethernet_address, t->dst,
	      format_ethernet_address, t->src);
  return s;
}

l2_outacl_main_t l2_outacl_main;

static vlib_node_registration_t l2_outacl_node;

#define foreach_l2_outacl_error			\
_(L2_OUTACL,    "L2 output ACL packets")	\
_(DROP,         "L2 output drops")

typedef enum
{
#define _(sym,str) L2_OUTACL_ERROR_##sym,
  foreach_l2_outacl_error
#undef _
    L2_OUTACL_N_ERROR,
} l2_outacl_error_t;

static char *l2_outacl_error_strings[] = {
#define _(sym,string) string,
  foreach_l2_outacl_error
#undef _
};

typedef enum
{
  L2_OUTACL_NEXT_DROP,
  L2_OUTACL_N_NEXT,
} l2_outacl_next_t;



static uword
l2_outacl_node_fn (vlib_main_t * vm,
		   vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  u32 n_left_from, *from, *to_next;
  l2_outacl_next_t next_index;
  l2_outacl_main_t *msm = &l2_outacl_main;
  vlib_node_t *n = vlib_get_node (vm, l2_outacl_node.index);
  u32 node_counter_base_index = n->error_heap_index;
  vlib_error_main_t *em = &vm->error_main;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;	/* number of packets to process */
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      /* get space to enqueue frame to graph node "next_index" */
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (0 && n_left_from >= 4 && n_left_to_next >= 2)
	{
	  u32 bi0, bi1;
	  vlib_buffer_t *b0, *b1;
	  u32 next0, next1;
	  u32 sw_if_index0, sw_if_index1;
	  ethernet_header_t *h0, *h1;

	  /* Prefetch next iteration. */
	  {
	    vlib_buffer_t *p2, *p3;

	    p2 = vlib_get_buffer (vm, from[2]);
	    p3 = vlib_get_buffer (vm, from[3]);

	    vlib_prefetch_buffer_header (p2, LOAD);
	    vlib_prefetch_buffer_header (p3, LOAD);

	    CLIB_PREFETCH (p2->data, CLIB_CACHE_LINE_BYTES, STORE);
	    CLIB_PREFETCH (p3->data, CLIB_CACHE_LINE_BYTES, STORE);
	  }

	  /* speculatively enqueue b0 and b1 to the current next frame */
	  /* bi is "buffer index", b is pointer to the buffer */
	  to_next[0] = bi0 = from[0];
	  to_next[1] = bi1 = from[1];
	  from += 2;
	  to_next += 2;
	  n_left_from -= 2;
	  n_left_to_next -= 2;

	  b0 = vlib_get_buffer (vm, bi0);
	  b1 = vlib_get_buffer (vm, bi1);

	  /* TX interface handles */
	  sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_TX];
	  sw_if_index1 = vnet_buffer (b1)->sw_if_index[VLIB_TX];

	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)))
	    {
	      if (b0->flags & VLIB_BUFFER_IS_TRACED)
		{
		  l2_outacl_trace_t *t =
		    vlib_add_trace (vm, node, b0, sizeof (*t));
		  t->sw_if_index = sw_if_index0;
		  t->next_index = next0;
		  clib_memcpy (t->src, h0->src_address, 6);
		  clib_memcpy (t->dst, h0->dst_address, 6);
		}
	      if (b1->flags & VLIB_BUFFER_IS_TRACED)
		{
		  l2_outacl_trace_t *t =
		    vlib_add_trace (vm, node, b1, sizeof (*t));
		  t->sw_if_index = sw_if_index1;
		  t->next_index = next1;
		  clib_memcpy (t->src, h1->src_address, 6);
		  clib_memcpy (t->dst, h1->dst_address, 6);
		}
	    }

	  em->counters[node_counter_base_index + L2_OUTACL_ERROR_L2_OUTACL] +=
	    2;

	  /* add core loop code here */

	  /* verify speculative enqueues, maybe switch current next frame */
	  /* if next0==next1==next_index then nothing special needs to be done */
	  vlib_validate_buffer_enqueue_x2 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, bi1, next0, next1);
	}

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0;
	  vlib_buffer_t *b0;
	  u32 next0;
	  u32 sw_if_index0;
	  ethernet_header_t *h0;

	  /* speculatively enqueue b0 to the current next frame */
	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
	  h0 = vlib_buffer_get_current (b0);

	  sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_TX];

	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)
			     && (b0->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      l2_outacl_trace_t *t =
		vlib_add_trace (vm, node, b0, sizeof (*t));
	      t->sw_if_index = sw_if_index0;
	      clib_memcpy (t->src, h0->src_address, 6);
	      clib_memcpy (t->dst, h0->dst_address, 6);
	    }

	  em->counters[node_counter_base_index + L2_OUTACL_ERROR_L2_OUTACL] +=
	    1;

	  /*
	   * L2_OUTACL code
	   * Dummy for now, just go to next feature node
	   */

	  /* Determine next node */
	  next0 = vnet_l2_feature_next (b0, msm->l2_out_feat_next,
					L2OUTPUT_FEAT_ACL);

	  /* verify speculative enqueue, maybe switch current next frame */
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return frame->n_vectors;
}


/* *INDENT-OFF* */
VLIB_REGISTER_NODE (l2_outacl_node,static) = {
  .function = l2_outacl_node_fn,
  .name = "l2-output-acl",
  .vector_size = sizeof (u32),
  .format_trace = format_l2_outacl_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(l2_outacl_error_strings),
  .error_strings = l2_outacl_error_strings,

  .n_next_nodes = L2_OUTACL_N_NEXT,

  /* edit / add dispositions here */
  .next_nodes = {
       [L2_OUTACL_NEXT_DROP]  = "error-drop",
  },
};
/* *INDENT-ON* */

VLIB_NODE_FUNCTION_MULTIARCH (l2_outacl_node, l2_outacl_node_fn)
     clib_error_t *l2_outacl_init (vlib_main_t * vm)
{
  l2_outacl_main_t *mp = &l2_outacl_main;

  mp->vlib_main = vm;
  mp->vnet_main = vnet_get_main ();

  /* Initialize the feature next-node indexes */
  feat_bitmap_init_next_nodes (vm,
			       l2_outacl_node.index,
			       L2OUTPUT_N_FEAT,
			       l2output_get_feat_names (),
			       mp->l2_out_feat_next);

  return 0;
}

VLIB_INIT_FUNCTION (l2_outacl_init);

#if 0
/** @todo maybe someone will add output ACL's in the future.
 * Set subinterface outacl enable/disable.
 * The CLI format is:
 *    set interface acl output <interface> [disable]
 */
static clib_error_t *
int_l2_outacl (vlib_main_t * vm,
	       unformat_input_t * input, vlib_cli_command_t * cmd)
{
  vnet_main_t *vnm = vnet_get_main ();
  clib_error_t *error = 0;
  u32 sw_if_index;
  u32 enable;

  if (!unformat_user (input, unformat_vnet_sw_interface, vnm, &sw_if_index))
    {
      error = clib_error_return (0, "unknown interface `%U'",
				 format_unformat_error, input);
      goto done;
    }

  enable = 1;
  if (unformat (input, "disable"))
    {
      enable = 0;
    }

  /* set the interface flag */
  l2output_intf_bitmap_enable (sw_if_index, L2OUTPUT_FEAT_ACL, enable);

done:
  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (int_l2_outacl_cli, static) = {
  .path = "set interface acl output",
  .short_help = "set interface acl output <interface> [disable]",
  .function = int_l2_outacl,
};
/* *INDENT-ON* */
#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
