/*
 * l2_input_vtr.c : layer 2 input vlan tag rewrite processing
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
#include <vnet/ethernet/ethernet.h>
#include <vnet/ethernet/packet.h>
#include <vnet/l2/l2_input.h>
#include <vnet/l2/feat_bitmap.h>
#include <vnet/l2/l2_vtr.h>
#include <vnet/l2/l2_input_vtr.h>
#include <vnet/l2/l2_output.h>

#include <vppinfra/error.h>
#include <vppinfra/cache.h>


typedef struct
{
  /* per-pkt trace data */
  u8 src[6];
  u8 dst[6];
  u8 raw[12];			/* raw data (vlans) */
  u32 sw_if_index;
} l2_invtr_trace_t;

/* packet trace format function */
static u8 *
format_l2_invtr_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  l2_invtr_trace_t *t = va_arg (*args, l2_invtr_trace_t *);

  s = format (s, "l2-input-vtr: sw_if_index %d dst %U src %U data "
	      "%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x",
	      t->sw_if_index,
	      format_ethernet_address, t->dst,
	      format_ethernet_address, t->src,
	      t->raw[0], t->raw[1], t->raw[2], t->raw[3], t->raw[4],
	      t->raw[5], t->raw[6], t->raw[7], t->raw[8], t->raw[9],
	      t->raw[10], t->raw[11]);
  return s;
}

l2_invtr_main_t l2_invtr_main;

static vlib_node_registration_t l2_invtr_node;

#define foreach_l2_invtr_error			\
_(L2_INVTR,    "L2 inverter packets")		\
_(DROP,        "L2 input tag rewrite drops")

typedef enum
{
#define _(sym,str) L2_INVTR_ERROR_##sym,
  foreach_l2_invtr_error
#undef _
    L2_INVTR_N_ERROR,
} l2_invtr_error_t;

static char *l2_invtr_error_strings[] = {
#define _(sym,string) string,
  foreach_l2_invtr_error
#undef _
};

typedef enum
{
  L2_INVTR_NEXT_DROP,
  L2_INVTR_N_NEXT,
} l2_invtr_next_t;


static uword
l2_invtr_node_fn (vlib_main_t * vm,
		  vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  u32 n_left_from, *from, *to_next;
  l2_invtr_next_t next_index;
  l2_invtr_main_t *msm = &l2_invtr_main;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;	/* number of packets to process */
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      /* get space to enqueue frame to graph node "next_index" */
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from >= 6 && n_left_to_next >= 2)
	{
	  u32 bi0, bi1;
	  vlib_buffer_t *b0, *b1;
	  u32 next0, next1;
	  u32 sw_if_index0, sw_if_index1;

	  /* Prefetch next iteration. */
	  {
	    vlib_buffer_t *p2, *p3, *p4, *p5;
	    u32 sw_if_index2, sw_if_index3;

	    p2 = vlib_get_buffer (vm, from[2]);
	    p3 = vlib_get_buffer (vm, from[3]);
	    p4 = vlib_get_buffer (vm, from[4]);
	    p5 = vlib_get_buffer (vm, from[5]);

	    /* Prefetch the buffer header and packet for the N+2 loop iteration */
	    vlib_prefetch_buffer_header (p4, LOAD);
	    vlib_prefetch_buffer_header (p5, LOAD);

	    CLIB_PREFETCH (p4->data, CLIB_CACHE_LINE_BYTES, STORE);
	    CLIB_PREFETCH (p5->data, CLIB_CACHE_LINE_BYTES, STORE);

	    /*
	     * Prefetch the input config for the N+1 loop iteration
	     * This depends on the buffer header above
	     */
	    sw_if_index2 = vnet_buffer (p2)->sw_if_index[VLIB_RX];
	    sw_if_index3 = vnet_buffer (p3)->sw_if_index[VLIB_RX];
	    CLIB_PREFETCH (vec_elt_at_index
			   (l2output_main.configs, sw_if_index2),
			   CLIB_CACHE_LINE_BYTES, LOAD);
	    CLIB_PREFETCH (vec_elt_at_index
			   (l2output_main.configs, sw_if_index3),
			   CLIB_CACHE_LINE_BYTES, LOAD);
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

	  /* RX interface handles */
	  sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];
	  sw_if_index1 = vnet_buffer (b1)->sw_if_index[VLIB_RX];

	  /* Determine the next node */
	  next0 = vnet_l2_feature_next (b0, msm->feat_next_node_index,
					L2INPUT_FEAT_VTR);
	  next1 = vnet_l2_feature_next (b1, msm->feat_next_node_index,
					L2INPUT_FEAT_VTR);

	  l2_output_config_t *config0;
	  l2_output_config_t *config1;
	  config0 = vec_elt_at_index (l2output_main.configs, sw_if_index0);
	  config1 = vec_elt_at_index (l2output_main.configs, sw_if_index1);

	  if (PREDICT_FALSE (config0->out_vtr_flag))
	    {
	      if (config0->output_vtr.push_and_pop_bytes)
		{
		  /* perform the tag rewrite on two packets */
		  if (l2_vtr_process (b0, &config0->input_vtr))
		    {
		      /* Drop packet */
		      next0 = L2_INVTR_NEXT_DROP;
		      b0->error = node->errors[L2_INVTR_ERROR_DROP];
		    }
		}
	      else if (config0->output_pbb_vtr.push_and_pop_bytes)
		{
		  if (l2_pbb_process (b0, &(config0->input_pbb_vtr)))
		    {
		      /* Drop packet */
		      next0 = L2_INVTR_NEXT_DROP;
		      b0->error = node->errors[L2_INVTR_ERROR_DROP];
		    }
		}
	    }
	  if (PREDICT_FALSE (config1->out_vtr_flag))
	    {
	      if (config1->output_vtr.push_and_pop_bytes)
		{
		  if (l2_vtr_process (b1, &config1->input_vtr))
		    {
		      /* Drop packet */
		      next1 = L2_INVTR_NEXT_DROP;
		      b1->error = node->errors[L2_INVTR_ERROR_DROP];
		    }
		}
	      else if (config1->output_pbb_vtr.push_and_pop_bytes)
		{
		  if (l2_pbb_process (b1, &(config1->input_pbb_vtr)))
		    {
		      /* Drop packet */
		      next1 = L2_INVTR_NEXT_DROP;
		      b1->error = node->errors[L2_INVTR_ERROR_DROP];
		    }
		}
	    }

	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)))
	    {
	      if (b0->flags & VLIB_BUFFER_IS_TRACED)
		{
		  l2_invtr_trace_t *t =
		    vlib_add_trace (vm, node, b0, sizeof (*t));
		  ethernet_header_t *h0 = vlib_buffer_get_current (b0);
		  t->sw_if_index = sw_if_index0;
		  clib_memcpy (t->src, h0->src_address, 6);
		  clib_memcpy (t->dst, h0->dst_address, 6);
		  clib_memcpy (t->raw, &h0->type, sizeof (t->raw));
		}
	      if (b1->flags & VLIB_BUFFER_IS_TRACED)
		{
		  l2_invtr_trace_t *t =
		    vlib_add_trace (vm, node, b1, sizeof (*t));
		  ethernet_header_t *h1 = vlib_buffer_get_current (b1);
		  t->sw_if_index = sw_if_index0;
		  clib_memcpy (t->src, h1->src_address, 6);
		  clib_memcpy (t->dst, h1->dst_address, 6);
		  clib_memcpy (t->raw, &h1->type, sizeof (t->raw));
		}
	    }

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

	  /* speculatively enqueue b0 to the current next frame */
	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);

	  sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];

	  /* Determine the next node */
	  next0 = vnet_l2_feature_next (b0, msm->feat_next_node_index,
					L2INPUT_FEAT_VTR);

	  l2_output_config_t *config0;
	  config0 = vec_elt_at_index (l2output_main.configs, sw_if_index0);

	  if (PREDICT_FALSE (config0->out_vtr_flag))
	    {
	      if (config0->output_vtr.push_and_pop_bytes)
		{
		  /* perform the tag rewrite on one packet */
		  if (l2_vtr_process (b0, &config0->input_vtr))
		    {
		      /* Drop packet */
		      next0 = L2_INVTR_NEXT_DROP;
		      b0->error = node->errors[L2_INVTR_ERROR_DROP];
		    }
		}
	      else if (config0->output_pbb_vtr.push_and_pop_bytes)
		{
		  if (l2_pbb_process (b0, &(config0->input_pbb_vtr)))
		    {
		      /* Drop packet */
		      next0 = L2_INVTR_NEXT_DROP;
		      b0->error = node->errors[L2_INVTR_ERROR_DROP];
		    }
		}
	    }

	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)
			     && (b0->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      l2_invtr_trace_t *t =
		vlib_add_trace (vm, node, b0, sizeof (*t));
	      ethernet_header_t *h0 = vlib_buffer_get_current (b0);
	      t->sw_if_index = sw_if_index0;
	      clib_memcpy (t->src, h0->src_address, 6);
	      clib_memcpy (t->dst, h0->dst_address, 6);
	      clib_memcpy (t->raw, &h0->type, sizeof (t->raw));
	    }

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
VLIB_REGISTER_NODE (l2_invtr_node,static) = {
  .function = l2_invtr_node_fn,
  .name = "l2-input-vtr",
  .vector_size = sizeof (u32),
  .format_trace = format_l2_invtr_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(l2_invtr_error_strings),
  .error_strings = l2_invtr_error_strings,

  .n_next_nodes = L2_INVTR_N_NEXT,

  /* edit / add dispositions here */
  .next_nodes = {
       [L2_INVTR_NEXT_DROP]  = "error-drop",
  },
};
/* *INDENT-ON* */

VLIB_NODE_FUNCTION_MULTIARCH (l2_invtr_node, l2_invtr_node_fn)
     clib_error_t *l2_invtr_init (vlib_main_t * vm)
{
  l2_invtr_main_t *mp = &l2_invtr_main;

  mp->vlib_main = vm;
  mp->vnet_main = vnet_get_main ();

  /* Initialize the feature next-node indexes */
  feat_bitmap_init_next_nodes (vm,
			       l2_invtr_node.index,
			       L2INPUT_N_FEAT,
			       l2input_get_feat_names (),
			       mp->feat_next_node_index);

  return 0;
}

VLIB_INIT_FUNCTION (l2_invtr_init);


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
