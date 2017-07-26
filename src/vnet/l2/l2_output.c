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

u8 *
format_l2_output_features (u8 * s, va_list * args)
{
  static char *display_names[] = {
#define _(sym,name) #sym,
    foreach_l2output_feat
#undef _
  };
  u32 feature_bitmap = va_arg (*args, u32);

  if (feature_bitmap == 0)
    {
      s = format (s, "  none configured");
      return s;
    }

  int i;
  for (i = L2OUTPUT_N_FEAT - 1; i >= 0; i--)
    if (feature_bitmap & (1 << i))
      s = format (s, "%10s (%s)\n", display_names[i], l2output_feat_names[i]);
  return s;
}

l2output_main_t l2output_main;

typedef struct
{
  /* per-pkt trace data */
  u8 src[6];
  u8 dst[6];
  u32 sw_if_index;
  u8 raw[12];			/* raw data */
} l2output_trace_t;

/* packet trace format function */
static u8 *
format_l2output_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  l2output_trace_t *t = va_arg (*args, l2output_trace_t *);

  s = format (s, "l2-output: sw_if_index %d dst %U src %U data "
	      "%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x",
	      t->sw_if_index,
	      format_ethernet_address, t->dst,
	      format_ethernet_address, t->src,
	      t->raw[0], t->raw[1], t->raw[2], t->raw[3], t->raw[4],
	      t->raw[5], t->raw[6], t->raw[7], t->raw[8], t->raw[9],
	      t->raw[10], t->raw[11]);

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

/** Determine the next L2 node based on the output feature bitmap */
static_always_inline void
l2_output_dispatch (vlib_buffer_t * b0, vlib_node_runtime_t * node,
		    u32 * cached_sw_if_index, u32 * cached_next_index,
		    u32 sw_if_index, u32 feature_bitmap, u32 * next0)
{
  /*
   * The output feature bitmap always have at least the L2 output bit set
   * for a normal L2 interface (or 0 if the interface is changed from L2
   * to L3 mode). So if the feature bitmap is 0 or just have L2 output bits set,
   * we know there is no more feature and will just output packets on interface.
   * Otherwise, get the index of the next feature node.
   */
  if (PREDICT_FALSE ((feature_bitmap & ~L2OUTPUT_FEAT_OUTPUT) != 0))
    {
      /* Save bitmap for the next feature graph nodes */
      vnet_buffer (b0)->l2.feature_bitmap = feature_bitmap;

      /* Determine the next node */
      *next0 =
	feat_bitmap_get_next_node_index (l2output_main.l2_out_feat_next,
					 feature_bitmap);
    }
  else
    {
      /*
       * There are no features. Send packet to TX node for sw_if_index0
       * This is a little tricky in that the output interface next node indexes
       * are not precomputed at init time.
       */

      if (sw_if_index == *cached_sw_if_index)
	{
	  /* We hit in the one-entry cache. Use it. */
	  *next0 = *cached_next_index;
	}
      else
	{
	  /* Look up the output TX node for the sw_if_index */
	  *next0 = vec_elt (l2output_main.output_node_index_vec, sw_if_index);

	  if (PREDICT_FALSE (*next0 == L2OUTPUT_NEXT_DROP))
	    b0->error = node->errors[L2OUTPUT_ERROR_MAPPING_DROP];

	  /* Update the one-entry cache */
	  *cached_sw_if_index = sw_if_index;
	  *cached_next_index = *next0;
	}
    }
}

static_always_inline void
l2output_vtr (vlib_node_runtime_t * node, l2_output_config_t * config,
	      u32 feature_bitmap, vlib_buffer_t * b, u32 * next)
{
  if (PREDICT_FALSE (config->out_vtr_flag))
    {
      /* Perform pre-vtr EFP filter check if configured */
      if (config->output_vtr.push_and_pop_bytes)
	{
	  /*
	   * Perform output vlan tag rewrite and the pre-vtr EFP filter check.
	   * The EFP Filter only needs to be run if there is an output VTR
	   * configured. The flag for the post-vtr EFP Filter node is used
	   * to trigger the pre-vtr check as well.
	   */
	  u32 failed1 = (feature_bitmap & L2OUTPUT_FEAT_EFP_FILTER)
	    && (l2_efp_filter_process (b, &(config->input_vtr)));
	  u32 failed2 = l2_vtr_process (b, &(config->output_vtr));

	  if (PREDICT_FALSE (failed1 | failed2))
	    {
	      *next = L2OUTPUT_NEXT_DROP;
	      if (failed2)
		{
		  b->error = node->errors[L2OUTPUT_ERROR_VTR_DROP];
		}
	      if (failed1)
		{
		  b->error = node->errors[L2OUTPUT_ERROR_EFP_DROP];
		}
	    }
	}
      // perform the PBB rewrite
      else if (config->output_pbb_vtr.push_and_pop_bytes)
	{
	  u32 failed = l2_pbb_process (b, &(config->output_pbb_vtr));
	  if (PREDICT_FALSE (failed))
	    {
	      *next = L2OUTPUT_NEXT_DROP;
	      b->error = node->errors[L2OUTPUT_ERROR_VTR_DROP];
	    }
	}
    }
}


static_always_inline uword
l2output_node_inline (vlib_main_t * vm, vlib_node_runtime_t * node,
		      vlib_frame_t * frame, int do_trace)
{
  u32 n_left_from, *from, *to_next;
  l2output_next_t next_index;
  l2output_main_t *msm = &l2output_main;
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

      while (n_left_from >= 8 && n_left_to_next >= 4)
	{
	  u32 bi0, bi1, bi2, bi3;
	  vlib_buffer_t *b0, *b1, *b2, *b3;
	  u32 next0, next1, next2, next3;
	  u32 sw_if_index0, sw_if_index1, sw_if_index2, sw_if_index3;
	  ethernet_header_t *h0, *h1, *h2, *h3;
	  l2_output_config_t *config0, *config1, *config2, *config3;
	  u32 feature_bitmap0, feature_bitmap1;
	  u32 feature_bitmap2, feature_bitmap3;

	  /* Prefetch next iteration. */
	  {
	    vlib_buffer_t *p4, *p5, *p6, *p7;

	    p4 = vlib_get_buffer (vm, from[4]);
	    p5 = vlib_get_buffer (vm, from[5]);
	    p6 = vlib_get_buffer (vm, from[6]);
	    p7 = vlib_get_buffer (vm, from[7]);

	    /* Prefetch the buffer header for the N+2 loop iteration */
	    vlib_prefetch_buffer_header (p4, LOAD);
	    vlib_prefetch_buffer_header (p5, LOAD);
	    vlib_prefetch_buffer_header (p6, LOAD);
	    vlib_prefetch_buffer_header (p7, LOAD);
	  }

	  /* speculatively enqueue b0 and b1 to the current next frame */
	  /* bi is "buffer index", b is pointer to the buffer */
	  to_next[0] = bi0 = from[0];
	  to_next[1] = bi1 = from[1];
	  to_next[2] = bi2 = from[2];
	  to_next[3] = bi3 = from[3];
	  from += 4;
	  to_next += 4;
	  n_left_from -= 4;
	  n_left_to_next -= 4;

	  b0 = vlib_get_buffer (vm, bi0);
	  b1 = vlib_get_buffer (vm, bi1);
	  b2 = vlib_get_buffer (vm, bi2);
	  b3 = vlib_get_buffer (vm, bi3);

	  /* TX interface handles */
	  sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_TX];
	  sw_if_index1 = vnet_buffer (b1)->sw_if_index[VLIB_TX];
	  sw_if_index2 = vnet_buffer (b2)->sw_if_index[VLIB_TX];
	  sw_if_index3 = vnet_buffer (b3)->sw_if_index[VLIB_TX];

	  vlib_node_increment_counter (vm, l2output_node.index,
				       L2OUTPUT_ERROR_L2OUTPUT, 4);

	  /* Get config for the output interface */
	  config0 = vec_elt_at_index (msm->configs, sw_if_index0);
	  config1 = vec_elt_at_index (msm->configs, sw_if_index1);
	  config2 = vec_elt_at_index (msm->configs, sw_if_index2);
	  config3 = vec_elt_at_index (msm->configs, sw_if_index3);

	  /*
	   * Get features from the config
	   * TODO: mask out any non-applicable features
	   */
	  feature_bitmap0 = config0->feature_bitmap;
	  feature_bitmap1 = config1->feature_bitmap;
	  feature_bitmap2 = config2->feature_bitmap;
	  feature_bitmap3 = config3->feature_bitmap;

	  /* Determine next node */
	  l2_output_dispatch (b0, node, &cached_sw_if_index,
			      &cached_next_index, sw_if_index0,
			      feature_bitmap0, &next0);
	  l2_output_dispatch (b1, node, &cached_sw_if_index,
			      &cached_next_index, sw_if_index1,
			      feature_bitmap1, &next1);
	  l2_output_dispatch (b2, node, &cached_sw_if_index,
			      &cached_next_index, sw_if_index2,
			      feature_bitmap2, &next2);
	  l2_output_dispatch (b3, node, &cached_sw_if_index,
			      &cached_next_index, sw_if_index3,
			      feature_bitmap3, &next3);

	  l2output_vtr (node, config0, feature_bitmap0, b0, &next0);
	  l2output_vtr (node, config1, feature_bitmap1, b1, &next1);
	  l2output_vtr (node, config2, feature_bitmap2, b2, &next2);
	  l2output_vtr (node, config3, feature_bitmap3, b3, &next3);

	  if (do_trace)
	    {
	      h0 = vlib_buffer_get_current (b0);
	      h1 = vlib_buffer_get_current (b1);
	      h2 = vlib_buffer_get_current (b2);
	      h3 = vlib_buffer_get_current (b3);
	      if (b0->flags & VLIB_BUFFER_IS_TRACED)
		{
		  l2output_trace_t *t =
		    vlib_add_trace (vm, node, b0, sizeof (*t));
		  t->sw_if_index = sw_if_index0;
		  clib_memcpy (t->src, h0->src_address, 6);
		  clib_memcpy (t->dst, h0->dst_address, 6);
		  clib_memcpy (t->raw, &h0->type, sizeof (t->raw));
		}
	      if (b1->flags & VLIB_BUFFER_IS_TRACED)
		{
		  l2output_trace_t *t =
		    vlib_add_trace (vm, node, b1, sizeof (*t));
		  t->sw_if_index = sw_if_index1;
		  clib_memcpy (t->src, h1->src_address, 6);
		  clib_memcpy (t->dst, h1->dst_address, 6);
		  clib_memcpy (t->raw, &h1->type, sizeof (t->raw));
		}
	      if (b2->flags & VLIB_BUFFER_IS_TRACED)
		{
		  l2output_trace_t *t =
		    vlib_add_trace (vm, node, b2, sizeof (*t));
		  t->sw_if_index = sw_if_index2;
		  clib_memcpy (t->src, h2->src_address, 6);
		  clib_memcpy (t->dst, h2->dst_address, 6);
		  clib_memcpy (t->raw, &h2->type, sizeof (t->raw));
		}
	      if (b3->flags & VLIB_BUFFER_IS_TRACED)
		{
		  l2output_trace_t *t =
		    vlib_add_trace (vm, node, b3, sizeof (*t));
		  t->sw_if_index = sw_if_index3;
		  clib_memcpy (t->src, h3->src_address, 6);
		  clib_memcpy (t->dst, h3->dst_address, 6);
		  clib_memcpy (t->raw, &h3->type, sizeof (t->raw));
		}
	    }

	  /*
	   * Perform the split horizon check
	   * The check can only fail for non-zero shg's
	   */
	  if (PREDICT_FALSE (config0->shg + config1->shg +
			     config2->shg + config3->shg))
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
	      if (split_horizon_violation
		  (config2->shg, vnet_buffer (b2)->l2.shg))
		{
		  next2 = L2OUTPUT_NEXT_DROP;
		  b2->error = node->errors[L2OUTPUT_ERROR_SHG_DROP];
		}
	      if (split_horizon_violation
		  (config3->shg, vnet_buffer (b3)->l2.shg))
		{
		  next3 = L2OUTPUT_NEXT_DROP;
		  b3->error = node->errors[L2OUTPUT_ERROR_SHG_DROP];
		}
	    }

	  /* verify speculative enqueues, maybe switch current next frame */
	  /* if next0==next1==next_index then nothing special needs to be done */
	  vlib_validate_buffer_enqueue_x4 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, bi1, bi2, bi3,
					   next0, next1, next2, next3);
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

	  vlib_node_increment_counter (vm, l2output_node.index,
				       L2OUTPUT_ERROR_L2OUTPUT, 1);

	  /* Get config for the output interface */
	  config0 = vec_elt_at_index (msm->configs, sw_if_index0);

	  /*
	   * Get features from the config
	   * TODO: mask out any non-applicable features
	   */
	  feature_bitmap0 = config0->feature_bitmap;

	  /* Determine next node */
	  l2_output_dispatch (b0, node, &cached_sw_if_index,
			      &cached_next_index, sw_if_index0,
			      feature_bitmap0, &next0);

	  l2output_vtr (node, config0, feature_bitmap0, b0, &next0);

	  if (do_trace && PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      l2output_trace_t *t =
		vlib_add_trace (vm, node, b0, sizeof (*t));
	      t->sw_if_index = sw_if_index0;
	      h0 = vlib_buffer_get_current (b0);
	      clib_memcpy (t->src, h0->src_address, 6);
	      clib_memcpy (t->dst, h0->dst_address, 6);
	      clib_memcpy (t->raw, &h0->type, sizeof (t->raw));
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

static uword
l2output_node_fn (vlib_main_t * vm,
		  vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)))
    return l2output_node_inline (vm, node, frame, 1 /* do_trace */ );
  return l2output_node_inline (vm, node, frame, 0 /* do_trace */ );
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (l2output_node) = {
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

VLIB_NODE_FUNCTION_MULTIARCH (l2output_node, l2output_node_fn);
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

VLIB_NODE_FUNCTION_MULTIARCH (l2output_bad_intf_node, l2output_bad_intf_node_fn);
/* *INDENT-ON* */

static clib_error_t *
l2output_init (vlib_main_t * vm)
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
			       mp->l2_out_feat_next);

  /* Initialize the output node mapping table */
  vec_validate_init_empty (mp->output_node_index_vec, 100,
			   L2OUTPUT_NEXT_DROP);

  return 0;
}

VLIB_INIT_FUNCTION (l2output_init);


/** Create a mapping in the next node mapping table for the given sw_if_index. */
void
l2output_create_output_node_mapping (vlib_main_t * vlib_main,
				     vnet_main_t * vnet_main, u32 sw_if_index)
{
  vnet_hw_interface_t *hw0 =
    vnet_get_sup_hw_interface (vnet_main, sw_if_index);

  /* dynamically create graph node arc  */
  u32 next = vlib_node_add_next (vlib_main, l2output_node.index,
				 hw0->output_node_index);
  l2output_main.output_node_index_vec[sw_if_index] = next;
}

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
