/*
 * l2_output.c : layer 2 output packet processing
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
#include <vlib/cli.h>

#include <vppinfra/error.h>
#include <vppinfra/hash.h>
#include <vnet/l2/feat_bitmap.h>
#include <vnet/l2/l2_output.h>


/* Feature graph node names */
static char *l2output_feat_names[] = {
#define _(sym,name) name,
  foreach_l2output_feat
#undef _
};

char **
l2output_get_feat_names (void)
{
  return l2output_feat_names;
}

l2output_main_t l2output_main;

typedef struct
{
  /* per-pkt trace data */
  u8 src[6];
  u8 dst[6];
  u32 sw_if_index;
} l2output_trace_t;

/* packet trace format function */
static u8 *
format_l2output_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  l2output_trace_t *t = va_arg (*args, l2output_trace_t *);

  s = format (s, "l2-output: sw_if_index %d dst %U src %U",
	      t->sw_if_index,
	      format_ethernet_address, t->dst,
	      format_ethernet_address, t->src);
  return s;
}


static char *l2output_error_strings[] = {
#define _(sym,string) string,
  foreach_l2output_error
#undef _
};

/**
 * Check for split horizon violations.
 * Return 0 if split horizon check passes, otherwise return non-zero.
 * Packets should not be transmitted out an interface with the same
 * split-horizon group as the input interface, except if the @c shg is 0
 * in which case the check always passes.
 */
static_always_inline u32
split_horizon_violation (u8 shg1, u8 shg2)
{
  if (PREDICT_TRUE (shg1 == 0))
    {
      return 0;
    }
  else
    {
      return shg1 == shg2;
    }
}


static vlib_node_registration_t l2output_node;

static uword
l2output_node_fn (vlib_main_t * vm,
		  vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  u32 n_left_from, *from, *to_next;
  l2output_next_t next_index;
  l2output_main_t *msm = &l2output_main;
  vlib_node_t *n = vlib_get_node (vm, l2output_node.index);
  u32 node_counter_base_index = n->error_heap_index;
  vlib_error_main_t *em = &vm->error_main;
  u32 cached_sw_if_index;
  u32 cached_next_index;

  /* Invalidate cache */
  cached_sw_if_index = ~0;
  cached_next_index = ~0;	/* warning be gone */

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
	  ethernet_header_t *h0, *h1;
	  l2_output_config_t *config0, *config1;
	  u32 feature_bitmap0, feature_bitmap1;

	  /* Prefetch next iteration. */
	  {
	    vlib_buffer_t *p2, *p3, *p4, *p5;
	    u32 sw_if_index2, sw_if_index3;

	    p2 = vlib_get_buffer (vm, from[2]);
	    p3 = vlib_get_buffer (vm, from[3]);
	    p4 = vlib_get_buffer (vm, from[4]);
	    p5 = vlib_get_buffer (vm, from[5]);

	    /* Prefetch the buffer header for the N+2 loop iteration */
	    vlib_prefetch_buffer_header (p4, LOAD);
	    vlib_prefetch_buffer_header (p5, LOAD);
	    /*
	     * Note: no need to prefetch packet data.
	     * This node doesn't reference it.
	     *
	     * Prefetch the input config for the N+1 loop iteration
	     * This depends on the buffer header above
	     */
	    sw_if_index2 = vnet_buffer (p2)->sw_if_index[VLIB_TX];
	    sw_if_index3 = vnet_buffer (p3)->sw_if_index[VLIB_TX];
	    CLIB_PREFETCH (&msm->configs[sw_if_index2], CLIB_CACHE_LINE_BYTES,
			   LOAD);
	    CLIB_PREFETCH (&msm->configs[sw_if_index3], CLIB_CACHE_LINE_BYTES,
			   LOAD);
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
	      h0 = vlib_buffer_get_current (b0);
	      h1 = vlib_buffer_get_current (b1);
	      if (b0->flags & VLIB_BUFFER_IS_TRACED)
		{
		  l2output_trace_t *t =
		    vlib_add_trace (vm, node, b0, sizeof (*t));
		  t->sw_if_index = sw_if_index0;
		  clib_memcpy (t->src, h0->src_address, 6);
		  clib_memcpy (t->dst, h0->dst_address, 6);
		}
	      if (b1->flags & VLIB_BUFFER_IS_TRACED)
		{
		  l2output_trace_t *t =
		    vlib_add_trace (vm, node, b1, sizeof (*t));
		  t->sw_if_index = sw_if_index1;
		  clib_memcpy (t->src, h1->src_address, 6);
		  clib_memcpy (t->dst, h1->dst_address, 6);
		}
	    }

	  em->counters[node_counter_base_index + L2OUTPUT_ERROR_L2OUTPUT] +=
	    2;

	  /* Get config for the output interface */
	  config0 = vec_elt_at_index (msm->configs, sw_if_index0);
	  config1 = vec_elt_at_index (msm->configs, sw_if_index1);

	  /*
	   * Get features from the config
	   * TODO: mask out any non-applicable features
	   */
	  feature_bitmap0 = config0->feature_bitmap;
	  feature_bitmap1 = config1->feature_bitmap;

	  /* Determine next node */
	  l2_output_dispatch (msm->vlib_main,
			      msm->vnet_main,
			      node,
			      l2output_node.index,
			      &cached_sw_if_index,
			      &cached_next_index,
			      &msm->next_nodes,
			      b0, sw_if_index0, feature_bitmap0, &next0);

	  l2_output_dispatch (msm->vlib_main,
			      msm->vnet_main,
			      node,
			      l2output_node.index,
			      &cached_sw_if_index,
			      &cached_next_index,
			      &msm->next_nodes,
			      b1, sw_if_index1, feature_bitmap1, &next1);

	  if (PREDICT_FALSE (config0->out_vtr_flag))
	    {
	      /* Perform pre-vtr EFP filter check if configured */
	      if (config0->output_vtr.push_and_pop_bytes)
		{
		  /*
		   * Perform output vlan tag rewrite and the pre-vtr EFP filter check.
		   * The EFP Filter only needs to be run if there is an output VTR
		   * configured. The flag for the post-vtr EFP Filter node is used
		   * to trigger the pre-vtr check as well.
		   */
		  u32 failed1 = (feature_bitmap0 & L2OUTPUT_FEAT_EFP_FILTER)
		    && (l2_efp_filter_process (b0, &(config0->input_vtr)));
		  u32 failed2 = l2_vtr_process (b0, &(config0->output_vtr));

		  if (PREDICT_FALSE (failed1 | failed2))
		    {
		      next0 = L2OUTPUT_NEXT_DROP;
		      if (failed2)
			{
			  b0->error = node->errors[L2OUTPUT_ERROR_VTR_DROP];
			}
		      if (failed1)
			{
			  b0->error = node->errors[L2OUTPUT_ERROR_EFP_DROP];
			}
		    }
		}
	      // perform the PBB rewrite
	      else if (config0->output_pbb_vtr.push_and_pop_bytes)
		{
		  u32 failed =
		    l2_pbb_process (b0, &(config0->output_pbb_vtr));
		  if (PREDICT_FALSE (failed))
		    {
		      next0 = L2OUTPUT_NEXT_DROP;
		      b0->error = node->errors[L2OUTPUT_ERROR_VTR_DROP];
		    }
		}
	    }
	  if (PREDICT_FALSE (config1->out_vtr_flag))
	    {
	      /* Perform pre-vtr EFP filter check if configured */
	      if (config1->output_vtr.push_and_pop_bytes)
		{
		  u32 failed1 = (feature_bitmap1 & L2OUTPUT_FEAT_EFP_FILTER)
		    && (l2_efp_filter_process (b1, &(config1->input_vtr)));
		  u32 failed2 = l2_vtr_process (b1, &(config1->output_vtr));

		  if (PREDICT_FALSE (failed1 | failed2))
		    {
		      next1 = L2OUTPUT_NEXT_DROP;
		      if (failed2)
			{
			  b1->error = node->errors[L2OUTPUT_ERROR_VTR_DROP];
			}
		      if (failed1)
			{
			  b1->error = node->errors[L2OUTPUT_ERROR_EFP_DROP];
			}
		    }
		}
	      // perform the PBB rewrite
	      else if (config1->output_pbb_vtr.push_and_pop_bytes)
		{
		  u32 failed =
		    l2_pbb_process (b0, &(config1->output_pbb_vtr));
		  if (PREDICT_FALSE (failed))
		    {
		      next1 = L2OUTPUT_NEXT_DROP;
		      b1->error = node->errors[L2OUTPUT_ERROR_VTR_DROP];
		    }
		}
	    }

	  /*
	   * Perform the split horizon check
	   * The check can only fail for non-zero shg's
	   */
	  if (PREDICT_FALSE (config0->shg + config1->shg))
	    {
	      /* one of the checks might fail, check both */
	      if (split_horizon_violation
		  (config0->shg, vnet_buffer (b0)->l2.shg))
		{
		  next0 = L2OUTPUT_NEXT_DROP;
		  b0->error = node->errors[L2OUTPUT_ERROR_SHG_DROP];
		}
	      if (split_horizon_violation
		  (config1->shg, vnet_buffer (b1)->l2.shg))
		{
		  next1 = L2OUTPUT_NEXT_DROP;
		  b1->error = node->errors[L2OUTPUT_ERROR_SHG_DROP];
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
	  ethernet_header_t *h0;
	  l2_output_config_t *config0;
	  u32 feature_bitmap0;

	  /* speculatively enqueue b0 to the current next frame */
	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);

	  sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_TX];

	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)
			     && (b0->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      l2output_trace_t *t =
		vlib_add_trace (vm, node, b0, sizeof (*t));
	      t->sw_if_index = sw_if_index0;
	      h0 = vlib_buffer_get_current (b0);
	      clib_memcpy (t->src, h0->src_address, 6);
	      clib_memcpy (t->dst, h0->dst_address, 6);
	    }

	  em->counters[node_counter_base_index +
		       L2OUTPUT_ERROR_L2OUTPUT] += 1;

	  /* Get config for the output interface */
	  config0 = vec_elt_at_index (msm->configs, sw_if_index0);

	  /*
	   * Get features from the config
	   * TODO: mask out any non-applicable features
	   */
	  feature_bitmap0 = config0->feature_bitmap;

	  /* Determine next node */
	  l2_output_dispatch (msm->vlib_main,
			      msm->vnet_main,
			      node,
			      l2output_node.index,
			      &cached_sw_if_index,
			      &cached_next_index,
			      &msm->next_nodes,
			      b0, sw_if_index0, feature_bitmap0, &next0);

	  if (PREDICT_FALSE (config0->out_vtr_flag))
	    {
	      /*
	       * Perform output vlan tag rewrite and the pre-vtr EFP filter check.
	       * The EFP Filter only needs to be run if there is an output VTR
	       * configured. The flag for the post-vtr EFP Filter node is used
	       * to trigger the pre-vtr check as well.
	       */

	      if (config0->output_vtr.push_and_pop_bytes)
		{
		  /* Perform pre-vtr EFP filter check if configured */
		  u32 failed1 = (feature_bitmap0 & L2OUTPUT_FEAT_EFP_FILTER)
		    && (l2_efp_filter_process (b0, &(config0->input_vtr)));
		  u32 failed2 = l2_vtr_process (b0, &(config0->output_vtr));

		  if (PREDICT_FALSE (failed1 | failed2))
		    {
		      next0 = L2OUTPUT_NEXT_DROP;
		      if (failed2)
			{
			  b0->error = node->errors[L2OUTPUT_ERROR_VTR_DROP];
			}
		      if (failed1)
			{
			  b0->error = node->errors[L2OUTPUT_ERROR_EFP_DROP];
			}
		    }
		}
	      // perform the PBB rewrite
	      else if (config0->output_pbb_vtr.push_and_pop_bytes)
		{
		  u32 failed =
		    l2_pbb_process (b0, &(config0->output_pbb_vtr));
		  if (PREDICT_FALSE (failed))
		    {
		      next0 = L2OUTPUT_NEXT_DROP;
		      b0->error = node->errors[L2OUTPUT_ERROR_VTR_DROP];
		    }
		}
	    }
	  /* Perform the split horizon check */
	  if (PREDICT_FALSE
	      (split_horizon_violation
	       (config0->shg, vnet_buffer (b0)->l2.shg)))
	    {
	      next0 = L2OUTPUT_NEXT_DROP;
	      b0->error = node->errors[L2OUTPUT_ERROR_SHG_DROP];
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
VLIB_REGISTER_NODE (l2output_node,static) = {
  .function = l2output_node_fn,
  .name = "l2-output",
  .vector_size = sizeof (u32),
  .format_trace = format_l2output_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(l2output_error_strings),
  .error_strings = l2output_error_strings,

  .n_next_nodes = L2OUTPUT_N_NEXT,

  /* edit / add dispositions here */
  .next_nodes = {
        [L2OUTPUT_NEXT_DROP] = "error-drop",
        [L2OUTPUT_NEXT_BAD_INTF] = "l2-output-bad-intf",
  },
};
/* *INDENT-ON* */


#define foreach_l2output_bad_intf_error	\
_(DROP,     "L2 output to interface not in L2 mode or deleted")

static char *l2output_bad_intf_error_strings[] = {
#define _(sym,string) string,
  foreach_l2output_bad_intf_error
#undef _
};

typedef enum
{
#define _(sym,str) L2OUTPUT_BAD_INTF_ERROR_##sym,
  foreach_l2output_bad_intf_error
#undef _
    L2OUTPUT_BAD_INTF_N_ERROR,
} l2output_bad_intf_error_t;


/**
 * Output node for interfaces/tunnels which was in L2 mode but were changed
 * to L3 mode or possibly deleted thereafter. On changing forwarding mode
 * of any tunnel/interface from L2 to L3, its entry in l2_output_main table
 * next_nodes.output_node_index_vec[sw_if_index] MUST be set to the value of
 * L2OUTPUT_NEXT_BAD_INTF. Thus, if there are stale entries in the L2FIB for
 * this sw_if_index, l2-output will send packets for this sw_if_index to the
 * l2-output-bad-intf node which just setup the proper drop reason before
 * sending packets to the error-drop node to drop the packet. Then, stale L2FIB
 * entries for delted tunnels won't cause possible packet or memory corrpution.
 */
static vlib_node_registration_t l2output_bad_intf_node;

static uword
l2output_bad_intf_node_fn (vlib_main_t * vm,
			   vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  u32 n_left_from, *from, *to_next;
  l2output_next_t next_index = 0;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;	/* number of packets to process */

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      /* get space to enqueue frame to graph node "next_index" */
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from >= 4 && n_left_to_next >= 2)
	{
	  u32 bi0, bi1;
	  vlib_buffer_t *b0, *b1;

	  to_next[0] = bi0 = from[0];
	  to_next[1] = bi1 = from[1];
	  from += 2;
	  to_next += 2;
	  n_left_from -= 2;
	  n_left_to_next -= 2;
	  b0 = vlib_get_buffer (vm, bi0);
	  b1 = vlib_get_buffer (vm, bi1);
	  b0->error = node->errors[L2OUTPUT_BAD_INTF_ERROR_DROP];
	  b1->error = node->errors[L2OUTPUT_BAD_INTF_ERROR_DROP];
	}

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0;
	  vlib_buffer_t *b0;

	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;
	  b0 = vlib_get_buffer (vm, bi0);
	  b0->error = node->errors[L2OUTPUT_BAD_INTF_ERROR_DROP];
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return frame->n_vectors;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (l2output_bad_intf_node,static) = {
  .function = l2output_bad_intf_node_fn,
  .name = "l2-output-bad-intf",
  .vector_size = sizeof (u32),
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors =  ARRAY_LEN(l2output_bad_intf_error_strings),
  .error_strings = l2output_bad_intf_error_strings,

  .n_next_nodes = 1,

  /* edit / add dispositions here */
  .next_nodes = {
	[0] = "error-drop",
  },
};
/* *INDENT-ON* */


VLIB_NODE_FUNCTION_MULTIARCH (l2output_node, l2output_node_fn)
     clib_error_t *l2output_init (vlib_main_t * vm)
{
  l2output_main_t *mp = &l2output_main;

  mp->vlib_main = vm;
  mp->vnet_main = vnet_get_main ();

  /* Create the config vector */
  vec_validate (mp->configs, 100);
  /* Until we hook up the CLI config, just create 100 sw interface entries  and zero them */

  /* Initialize the feature next-node indexes */
  feat_bitmap_init_next_nodes (vm,
			       l2output_node.index,
			       L2OUTPUT_N_FEAT,
			       l2output_get_feat_names (),
			       mp->next_nodes.feat_next_node_index);

  /* Initialize the output node mapping table */
  l2output_init_output_node_vec (&mp->next_nodes.output_node_index_vec);

  return 0;
}

VLIB_INIT_FUNCTION (l2output_init);

typedef struct
{
  u32 node_index;
  u32 sw_if_index;
} output_node_mapping_rpc_args_t;

#if DPDK > 0
static void output_node_rpc_callback (output_node_mapping_rpc_args_t * a);

static void
output_node_mapping_send_rpc (u32 node_index, u32 sw_if_index)
{
  output_node_mapping_rpc_args_t args;
  void vl_api_rpc_call_main_thread (void *fp, u8 * data, u32 data_length);

  args.node_index = node_index;
  args.sw_if_index = sw_if_index;

  vl_api_rpc_call_main_thread (output_node_rpc_callback,
			       (u8 *) & args, sizeof (args));
}
#endif


/** Create a mapping in the next node mapping table for the given sw_if_index. */
u32
l2output_create_output_node_mapping (vlib_main_t * vlib_main, vnet_main_t * vnet_main, u32 node_index,	/* index of current node */
				     u32 * output_node_index_vec,
				     u32 sw_if_index)
{

  u32 next;			/* index of next graph node */
  vnet_hw_interface_t *hw0;
  u32 *node;

  hw0 = vnet_get_sup_hw_interface (vnet_main, sw_if_index);

#if DPDK > 0
  uword cpu_number;

  cpu_number = os_get_cpu_number ();

  if (cpu_number)
    {
      u32 oldflags;

      oldflags = __sync_fetch_and_or (&hw0->flags,
				      VNET_HW_INTERFACE_FLAG_L2OUTPUT_MAPPED);

      if ((oldflags & VNET_HW_INTERFACE_FLAG_L2OUTPUT_MAPPED))
	return L2OUTPUT_NEXT_DROP;

      output_node_mapping_send_rpc (node_index, sw_if_index);
      return L2OUTPUT_NEXT_DROP;
    }
#endif

  /* dynamically create graph node arc  */
  next = vlib_node_add_next (vlib_main, node_index, hw0->output_node_index);

  /* Initialize vector with the mapping */

  node = vec_elt_at_index (output_node_index_vec, sw_if_index);
  *node = next;

  /* reset mapping bit, includes memory barrier */
  __sync_fetch_and_and (&hw0->flags, ~VNET_HW_INTERFACE_FLAG_L2OUTPUT_MAPPED);

  return next;
}

#if DPDK > 0
void
output_node_rpc_callback (output_node_mapping_rpc_args_t * a)
{
  vlib_main_t *vm = vlib_get_main ();
  vnet_main_t *vnm = vnet_get_main ();
  l2output_main_t *mp = &l2output_main;

  (void) l2output_create_output_node_mapping
    (vm, vnm, a->node_index, mp->next_nodes.output_node_index_vec,
     a->sw_if_index);
}
#endif

/* Get a pointer to the config for the given interface */
l2_output_config_t *
l2output_intf_config (u32 sw_if_index)
{
  l2output_main_t *mp = &l2output_main;

  vec_validate (mp->configs, sw_if_index);
  return vec_elt_at_index (mp->configs, sw_if_index);
}

/** Enable (or disable) the feature in the bitmap for the given interface. */
void
l2output_intf_bitmap_enable (u32 sw_if_index, u32 feature_bitmap, u32 enable)
{
  l2output_main_t *mp = &l2output_main;
  l2_output_config_t *config;

  vec_validate (mp->configs, sw_if_index);
  config = vec_elt_at_index (mp->configs, sw_if_index);

  if (enable)
    {
      config->feature_bitmap |= feature_bitmap;
    }
  else
    {
      config->feature_bitmap &= ~feature_bitmap;
    }
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
