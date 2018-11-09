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


#ifndef CLIB_MARCH_VARIANT
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
  u32 verbose = va_arg (*args, u32);

  if (feature_bitmap == 0)
    {
      s = format (s, "  none configured");
      return s;
    }

  int i;
  for (i = L2OUTPUT_N_FEAT - 1; i >= 0; i--)
    {
      if (feature_bitmap & (1 << i))
	{
	  if (verbose)
	    s =
	      format (s, "%17s (%s)\n", display_names[i],
		      l2output_feat_names[i]);
	  else
	    s = format (s, "%s ", l2output_feat_names[i]);
	}
    }

  return s;
}

l2output_main_t l2output_main;
#endif

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
static_always_inline void
split_horizon_violation (vlib_node_runtime_t * node, u8 shg,
			 vlib_buffer_t * b, u16 * next)
{
  if (shg != vnet_buffer (b)->l2.shg)
    return;
  next[0] = L2OUTPUT_NEXT_DROP;
  b->error = node->errors[L2OUTPUT_ERROR_SHG_DROP];
}

static_always_inline void
l2output_process_batch_inline (vlib_main_t * vm, vlib_node_runtime_t * node,
			       l2_output_config_t * config,
			       vlib_buffer_t ** b, i16 * cdo, u16 * next,
			       u32 n_left, int l2_efp, int l2_vtr, int l2_pbb,
			       int shg_set, int update_feature_bitmap)
{
  while (n_left >= 8)
    {
      vlib_prefetch_buffer_header (b[4], LOAD);
      vlib_prefetch_buffer_header (b[5], LOAD);
      vlib_prefetch_buffer_header (b[6], LOAD);
      vlib_prefetch_buffer_header (b[7], LOAD);

      /* prefetch eth headers only if we need to touch them */
      if (l2_vtr || l2_pbb || shg_set)
	{
	  CLIB_PREFETCH (b[4]->data + cdo[4], CLIB_CACHE_LINE_BYTES, LOAD);
	  CLIB_PREFETCH (b[5]->data + cdo[5], CLIB_CACHE_LINE_BYTES, LOAD);
	  CLIB_PREFETCH (b[6]->data + cdo[6], CLIB_CACHE_LINE_BYTES, LOAD);
	  CLIB_PREFETCH (b[7]->data + cdo[7], CLIB_CACHE_LINE_BYTES, LOAD);
	}

      if (update_feature_bitmap)
	{
	  vnet_buffer (b[0])->l2.feature_bitmap = config->feature_bitmap;
	  vnet_buffer (b[1])->l2.feature_bitmap = config->feature_bitmap;
	  vnet_buffer (b[2])->l2.feature_bitmap = config->feature_bitmap;
	  vnet_buffer (b[3])->l2.feature_bitmap = config->feature_bitmap;
	}

      if (l2_vtr)
	{
	  int i;
	  for (i = 0; i < 4; i++)
	    {
	      u32 failed1 = l2_efp &&
		l2_efp_filter_process (b[i], &(config->input_vtr));
	      u32 failed2 = l2_vtr_process (b[i], &(config->output_vtr));
	      if (PREDICT_FALSE (failed1 | failed2))
		{
		  next[i] = L2OUTPUT_NEXT_DROP;
		  if (failed2)
		    b[i]->error = node->errors[L2OUTPUT_ERROR_VTR_DROP];
		  if (failed1)
		    b[i]->error = node->errors[L2OUTPUT_ERROR_EFP_DROP];
		}
	    }
	}

      if (l2_pbb)
	{
	  int i;
	  for (i = 0; i < 4; i++)
	    if (l2_pbb_process (b[i], &(config->output_pbb_vtr)))
	      {
		next[i] = L2OUTPUT_NEXT_DROP;
		b[i]->error = node->errors[L2OUTPUT_ERROR_VTR_DROP];
	      }
	}

      if (shg_set)
	{
	  split_horizon_violation (node, config->shg, b[0], next);
	  split_horizon_violation (node, config->shg, b[1], next + 1);
	  split_horizon_violation (node, config->shg, b[2], next + 2);
	  split_horizon_violation (node, config->shg, b[3], next + 3);
	}
      /* next */
      n_left -= 4;
      b += 4;
      next += 4;
      cdo += 4;
    }

  while (n_left)
    {
      if (update_feature_bitmap)
	vnet_buffer (b[0])->l2.feature_bitmap = config->feature_bitmap;

      if (l2_vtr)
	{
	  u32 failed1 = l2_efp &&
	    l2_efp_filter_process (b[0], &(config->input_vtr));
	  u32 failed2 = l2_vtr_process (b[0], &(config->output_vtr));
	  if (PREDICT_FALSE (failed1 | failed2))
	    {
	      *next = L2OUTPUT_NEXT_DROP;
	      if (failed2)
		b[0]->error = node->errors[L2OUTPUT_ERROR_VTR_DROP];
	      if (failed1)
		b[0]->error = node->errors[L2OUTPUT_ERROR_EFP_DROP];
	    }
	}

      if (l2_pbb && l2_pbb_process (b[0], &(config->output_pbb_vtr)))
	{
	  next[0] = L2OUTPUT_NEXT_DROP;
	  b[0]->error = node->errors[L2OUTPUT_ERROR_VTR_DROP];
	}

      if (shg_set)
	split_horizon_violation (node, config->shg, b[0], next);

      /* next */
      n_left -= 1;
      b += 1;
      next += 1;
    }
}

static_always_inline void
l2output_set_buffer_error (vlib_buffer_t ** b, u32 n_left, vlib_error_t error)
{
  while (n_left >= 8)
    {
      vlib_prefetch_buffer_header (b[4], LOAD);
      vlib_prefetch_buffer_header (b[5], LOAD);
      vlib_prefetch_buffer_header (b[6], LOAD);
      vlib_prefetch_buffer_header (b[7], LOAD);
      b[0]->error = b[1]->error = b[2]->error = b[3]->error = error;
      b += 4;
      n_left -= 4;
    }
  while (n_left)
    {
      b[0]->error = error;
      b += 1;
      n_left -= 1;
    }
}

static_always_inline void
l2output_process_batch (vlib_main_t * vm, vlib_node_runtime_t * node,
			l2_output_config_t * config, vlib_buffer_t ** b,
			i16 * cdo, u16 * next, u32 n_left, int l2_efp,
			int l2_vtr, int l2_pbb)
{
  u32 feature_bitmap = config->feature_bitmap & ~L2OUTPUT_FEAT_OUTPUT;
  if (config->shg == 0 && feature_bitmap == 0)
    {
      if ((l2_efp | l2_vtr | l2_pbb) == 0)
	return;
      l2output_process_batch_inline (vm, node, config, b, cdo, next, n_left,
				     l2_efp, l2_vtr, l2_pbb, 0, 0);
    }
  else if (config->shg == 0)
    l2output_process_batch_inline (vm, node, config, b, cdo, next, n_left,
				   l2_efp, l2_vtr, l2_pbb, 0, 1);
  else if (feature_bitmap == 0)
    l2output_process_batch_inline (vm, node, config, b, cdo, next, n_left,
				   l2_efp, l2_vtr, l2_pbb, 1, 0);
  else
    l2output_process_batch_inline (vm, node, config, b, cdo, next, n_left,
				   l2_efp, l2_vtr, l2_pbb, 1, 1);
}

VLIB_NODE_FN (l2output_node) (vlib_main_t * vm,
			      vlib_node_runtime_t * node,
			      vlib_frame_t * frame)
{
  u32 n_left, *from;
  l2output_main_t *msm = &l2output_main;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;
  u16 nexts[VLIB_FRAME_SIZE];
  u32 sw_if_indices[VLIB_FRAME_SIZE], *sw_if_index;
  i16 cur_data_offsets[VLIB_FRAME_SIZE], *cdo;
  l2_output_config_t *config;
  u32 feature_bitmap;

  from = vlib_frame_vector_args (frame);
  n_left = frame->n_vectors;	/* number of packets to process */

  vlib_get_buffers (vm, from, bufs, n_left);
  b = bufs;
  sw_if_index = sw_if_indices;
  cdo = cur_data_offsets;

  /* extract data from buffer metadata */
  while (n_left >= 8)
    {
      /* Prefetch the buffer header for the N+2 loop iteration */
      vlib_prefetch_buffer_header (b[4], LOAD);
      vlib_prefetch_buffer_header (b[5], LOAD);
      vlib_prefetch_buffer_header (b[6], LOAD);
      vlib_prefetch_buffer_header (b[7], LOAD);

      sw_if_index[0] = vnet_buffer (b[0])->sw_if_index[VLIB_TX];
      cdo[0] = b[0]->current_data;
      sw_if_index[1] = vnet_buffer (b[1])->sw_if_index[VLIB_TX];
      cdo[1] = b[1]->current_data;
      sw_if_index[2] = vnet_buffer (b[2])->sw_if_index[VLIB_TX];
      cdo[2] = b[2]->current_data;
      sw_if_index[3] = vnet_buffer (b[3])->sw_if_index[VLIB_TX];
      cdo[3] = b[3]->current_data;

      /* next */
      sw_if_index += 4;
      n_left -= 4;
      b += 4;
      cdo += 4;
    }
  while (n_left)
    {
      sw_if_index[0] = vnet_buffer (b[0])->sw_if_index[VLIB_TX];
      cdo[0] = b[0]->current_data;

      /* next */
      sw_if_index += 1;
      n_left -= 1;
      b += 1;
      cdo += 1;
    }

  n_left = frame->n_vectors;
  while (n_left)
    {
      u16 count, new_next, *next;
      u16 off = frame->n_vectors - n_left;
      b = bufs + off;

      if (n_left >= 4)
	{
	  vlib_prefetch_buffer_header (b[0], LOAD);
	  vlib_prefetch_buffer_header (b[1], LOAD);
	  vlib_prefetch_buffer_header (b[2], LOAD);
	  vlib_prefetch_buffer_header (b[3], LOAD);
	}

      sw_if_index = sw_if_indices + off;
      cdo = cur_data_offsets + off;
      next = nexts + off;

      count = clib_count_equal_u32 (sw_if_index, n_left);
      n_left -= count;

      config = vec_elt_at_index (msm->configs, sw_if_index[0]);
      feature_bitmap = config->feature_bitmap;
      if (PREDICT_FALSE ((feature_bitmap & ~L2OUTPUT_FEAT_OUTPUT) != 0))
	new_next = feat_bitmap_get_next_node_index
	  (l2output_main.l2_out_feat_next, feature_bitmap);
      else
	new_next = vec_elt (l2output_main.output_node_index_vec,
			    sw_if_index[0]);
      clib_memset_u16 (nexts + off, new_next, count);

      if (new_next == L2OUTPUT_NEXT_DROP)
	{
	  l2output_set_buffer_error
	    (b, count, node->errors[L2OUTPUT_ERROR_MAPPING_DROP]);
	  continue;
	}

      /* VTR */
      if (config->out_vtr_flag && config->output_vtr.push_and_pop_bytes)
	{
	  if (feature_bitmap & L2OUTPUT_FEAT_EFP_FILTER)
	    l2output_process_batch (vm, node, config, b, cdo, next, count,
				    /* l2_efp */ 1,
				    /* l2_vtr */ 1,
				    /* l2_pbb */ 0);
	  else
	    l2output_process_batch (vm, node, config, b, cdo, next, count,
				    /* l2_efp */ 0,
				    /* l2_vtr */ 1,
				    /* l2_pbb */ 0);
	}
      else if (config->out_vtr_flag &&
	       config->output_pbb_vtr.push_and_pop_bytes)
	l2output_process_batch (vm, node, config, b, cdo, next, count,
				/* l2_efp */ 0,
				/* l2_vtr */ 0,
				/* l2_pbb */ 1);
      else
	l2output_process_batch (vm, node, config, b, cdo, next, count,
				/* l2_efp */ 0,
				/* l2_vtr */ 0,
				/* l2_pbb */ 0);
    }


  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)))
    {
      n_left = frame->n_vectors;	/* number of packets to process */
      b = bufs;

      while (n_left)
	{
	  if (PREDICT_FALSE (b[0]->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      ethernet_header_t *h;
	      l2output_trace_t *t =
		vlib_add_trace (vm, node, b[0], sizeof (*t));
	      t->sw_if_index = vnet_buffer (b[0])->sw_if_index[VLIB_TX];
	      h = vlib_buffer_get_current (b[0]);
	      clib_memcpy (t->src, h->src_address, 6);
	      clib_memcpy (t->dst, h->dst_address, 6);
	      clib_memcpy (t->raw, &h->type, sizeof (t->raw));
	    }
	  /* next */
	  n_left--;
	  b++;
	}
    }

  vlib_buffer_enqueue_to_next (vm, node, from, nexts, frame->n_vectors);
  vlib_node_increment_counter (vm, l2output_node.index,
			       L2OUTPUT_ERROR_L2OUTPUT, frame->n_vectors);

  return frame->n_vectors;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (l2output_node) = {
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
 * entries for deleted tunnels won't cause possible packet or memory corruption.
 */

VLIB_NODE_FN (l2output_bad_intf_node) (vlib_main_t * vm,
				       vlib_node_runtime_t * node,
				       vlib_frame_t * frame)
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
VLIB_REGISTER_NODE (l2output_bad_intf_node) = {
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


#ifndef CLIB_MARCH_VARIANT
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
l2output_intf_bitmap_enable (u32 sw_if_index,
			     l2output_feat_masks_t feature_bitmap, u32 enable)
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
#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
