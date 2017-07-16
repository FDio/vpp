/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
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
#include <vppinfra/error.h>

#include <vnet/span/span.h>
#include <vnet/l2/l2_input.h>
#include <vnet/l2/l2_output.h>
#include <vnet/l2/feat_bitmap.h>

#include <vppinfra/error.h>
#include <vppinfra/elog.h>

vlib_node_registration_t span_node;

/* packet trace format function */
u8 *
format_span_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  span_trace_t *t = va_arg (*args, span_trace_t *);

  vnet_main_t *vnm = &vnet_main;
  s = format (s, "SPAN: mirrored %U -> %U",
	      format_vnet_sw_if_index_name, vnm, t->src_sw_if_index,
	      format_vnet_sw_if_index_name, vnm, t->mirror_sw_if_index);

  return s;
}

#define foreach_span_error                      \
_(HITS, "SPAN incomming packets processed")

typedef enum
{
#define _(sym,str) SPAN_ERROR_##sym,
  foreach_span_error
#undef _
    SPAN_N_ERROR,
} span_error_t;

static char *span_error_strings[] = {
#define _(sym,string) string,
  foreach_span_error
#undef _
};

static_always_inline void
span_mirror (vlib_main_t * vm, vlib_node_runtime_t * node, u32 sw_if_index0,
	     vlib_buffer_t * b0, vlib_frame_t ** mirror_frames,
	     vlib_rx_or_tx_t rxtx, span_feat_t sf)
{
  vlib_buffer_t *c0;
  span_main_t *sm = &span_main;
  vnet_main_t *vnm = &vnet_main;
  u32 *to_mirror_next = 0;
  u32 i;

  span_interface_t *si0 = vec_elt_at_index (sm->interfaces, sw_if_index0);
  span_mirror_t *sm0 = &si0->mirror_rxtx[sf][rxtx];

  if (sm0->num_mirror_ports == 0)
    return;

  /* Don't do it again */
  if (PREDICT_FALSE (b0->flags & VNET_BUFFER_F_SPAN_CLONE))
    return;

  /* *INDENT-OFF* */
  clib_bitmap_foreach (i, sm0->mirror_ports, (
    {
      if (mirror_frames[i] == 0)
        {
          if (sf == SPAN_FEAT_L2)
            mirror_frames[i] = vlib_get_frame_to_node (vnm->vlib_main, l2output_node.index);
          else
            mirror_frames[i] = vnet_get_frame_to_sw_interface (vnm, i);
	}
      to_mirror_next = vlib_frame_vector_args (mirror_frames[i]);
      to_mirror_next += mirror_frames[i]->n_vectors;
      /* This can fail */
      c0 = vlib_buffer_copy (vm, b0);
      if (PREDICT_TRUE(c0 != 0))
        {
          vnet_buffer (c0)->sw_if_index[VLIB_TX] = i;
          c0->flags |= VNET_BUFFER_F_SPAN_CLONE;
          if (sf == SPAN_FEAT_L2)
	    vnet_buffer (c0)->l2.feature_bitmap = L2OUTPUT_FEAT_OUTPUT;
          to_mirror_next[0] = vlib_get_buffer_index (vm, c0);
          mirror_frames[i]->n_vectors++;
          if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
            {
              span_trace_t *t = vlib_add_trace (vm, node, b0, sizeof (*t));
              t->src_sw_if_index = sw_if_index0;
              t->mirror_sw_if_index = i;
            }
        }
    }));
  /* *INDENT-ON* */
}

static_always_inline uword
span_node_inline_fn (vlib_main_t * vm, vlib_node_runtime_t * node,
		     vlib_frame_t * frame, vlib_rx_or_tx_t rxtx,
		     span_feat_t sf)
{
  span_main_t *sm = &span_main;
  vnet_main_t *vnm = &vnet_main;
  u32 n_left_from, *from, *to_next;
  u32 n_span_packets = 0;
  u32 next_index;
  u32 sw_if_index;
  static __thread vlib_frame_t **mirror_frames = 0;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  vec_validate_aligned (mirror_frames, sm->max_sw_if_index,
			CLIB_CACHE_LINE_BYTES);

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from >= 4 && n_left_to_next >= 2)
	{
	  u32 bi0;
	  u32 bi1;
	  vlib_buffer_t *b0;
	  vlib_buffer_t *b1;
	  u32 sw_if_index0;
	  u32 next0 = 0;
	  u32 sw_if_index1;
	  u32 next1 = 0;

	  /* speculatively enqueue b0, b1 to the current next frame */
	  to_next[0] = bi0 = from[0];
	  to_next[1] = bi1 = from[1];
	  to_next += 2;
	  n_left_to_next -= 2;
	  from += 2;
	  n_left_from -= 2;

	  b0 = vlib_get_buffer (vm, bi0);
	  b1 = vlib_get_buffer (vm, bi1);
	  sw_if_index0 = vnet_buffer (b0)->sw_if_index[rxtx];
	  sw_if_index1 = vnet_buffer (b1)->sw_if_index[rxtx];

	  span_mirror (vm, node, sw_if_index0, b0, mirror_frames, rxtx, sf);
	  span_mirror (vm, node, sw_if_index1, b1, mirror_frames, rxtx, sf);

	  switch (sf)
	    {
	    case SPAN_FEAT_L2:
	      if (rxtx == VLIB_RX)
		{
		  next0 = vnet_l2_feature_next (b0, sm->l2_input_next,
						L2INPUT_FEAT_SPAN);
		  next1 = vnet_l2_feature_next (b1, sm->l2_input_next,
						L2INPUT_FEAT_SPAN);
		}
	      else
		{
		  next0 = vnet_l2_feature_next (b0, sm->l2_output_next,
						L2OUTPUT_FEAT_SPAN);
		  next1 = vnet_l2_feature_next (b1, sm->l2_output_next,
						L2OUTPUT_FEAT_SPAN);
		}
	      break;
	    case SPAN_FEAT_DEVICE:
	    default:
	      vnet_feature_next (sw_if_index0, &next0, b0);
	      vnet_feature_next (sw_if_index1, &next1, b1);
	      break;
	    }

	  /* verify speculative enqueue, maybe switch current next frame */
	  vlib_validate_buffer_enqueue_x2 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, bi1, next0, next1);
	}
      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0;
	  vlib_buffer_t *b0;
	  u32 sw_if_index0;
	  u32 next0 = 0;

	  /* speculatively enqueue b0 to the current next frame */
	  to_next[0] = bi0 = from[0];
	  to_next += 1;
	  n_left_to_next -= 1;
	  from += 1;
	  n_left_from -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
	  sw_if_index0 = vnet_buffer (b0)->sw_if_index[rxtx];

	  span_mirror (vm, node, sw_if_index0, b0, mirror_frames, rxtx, sf);

	  switch (sf)
	    {
	    case SPAN_FEAT_L2:
	      if (rxtx == VLIB_RX)
		next0 = vnet_l2_feature_next (b0, sm->l2_input_next,
					      L2INPUT_FEAT_SPAN);
	      else
		next0 = vnet_l2_feature_next (b0, sm->l2_output_next,
					      L2OUTPUT_FEAT_SPAN);
	      break;
	    case SPAN_FEAT_DEVICE:
	    default:
	      vnet_feature_next (sw_if_index0, &next0, b0);
	      break;
	    }

	  /* verify speculative enqueue, maybe switch current next frame */
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }


  for (sw_if_index = 0; sw_if_index < vec_len (mirror_frames); sw_if_index++)
    {
      vlib_frame_t *f = mirror_frames[sw_if_index];
      if (f == 0)
	continue;

      if (sf == SPAN_FEAT_L2)
	vlib_put_frame_to_node (vnm->vlib_main, l2output_node.index, f);
      else
	vnet_put_frame_to_sw_interface (vnm, sw_if_index, f);
      mirror_frames[sw_if_index] = 0;
    }
  vlib_node_increment_counter (vm, span_node.index, SPAN_ERROR_HITS,
			       n_span_packets);

  return frame->n_vectors;
}

static uword
span_device_input_node_fn (vlib_main_t * vm, vlib_node_runtime_t * node,
			   vlib_frame_t * frame)
{
  return span_node_inline_fn (vm, node, frame, VLIB_RX, SPAN_FEAT_DEVICE);
}

static uword
span_device_output_node_fn (vlib_main_t * vm, vlib_node_runtime_t * node,
			    vlib_frame_t * frame)
{
  return span_node_inline_fn (vm, node, frame, VLIB_TX, SPAN_FEAT_DEVICE);
}

static uword
span_l2_input_node_fn (vlib_main_t * vm, vlib_node_runtime_t * node,
		       vlib_frame_t * frame)
{
  return span_node_inline_fn (vm, node, frame, VLIB_RX, SPAN_FEAT_L2);
}

static uword
span_l2_output_node_fn (vlib_main_t * vm, vlib_node_runtime_t * node,
			vlib_frame_t * frame)
{
  return span_node_inline_fn (vm, node, frame, VLIB_TX, SPAN_FEAT_L2);
}

#define span_node_defs                           \
  .vector_size = sizeof (u32),                   \
  .format_trace = format_span_trace,             \
  .type = VLIB_NODE_TYPE_INTERNAL,               \
  .n_errors = ARRAY_LEN(span_error_strings),     \
  .error_strings = span_error_strings,           \
  .n_next_nodes = 0,                             \
  .next_nodes = {                                \
    [0] = "error-drop"                           \
  }

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (span_input_node) = {
  span_node_defs,
  .function = span_device_input_node_fn,
  .name = "span-input",
};

VLIB_NODE_FUNCTION_MULTIARCH (span_input_node, span_device_input_node_fn)

VLIB_REGISTER_NODE (span_output_node) = {
  span_node_defs,
  .function = span_device_output_node_fn,
  .name = "span-output",
};

VLIB_NODE_FUNCTION_MULTIARCH (span_output_node, span_device_output_node_fn)

VLIB_REGISTER_NODE (span_l2_input_node) = {
  span_node_defs,
  .function = span_l2_input_node_fn,
  .name = "span-l2-input",
};

VLIB_NODE_FUNCTION_MULTIARCH (span_l2_input_node, span_l2_input_node_fn)

VLIB_REGISTER_NODE (span_l2_output_node) = {
  span_node_defs,
  .function = span_l2_output_node_fn,
  .name = "span-l2-output",
};

VLIB_NODE_FUNCTION_MULTIARCH (span_l2_output_node, span_l2_output_node_fn)

clib_error_t *span_init (vlib_main_t * vm)
{
  span_main_t *sm = &span_main;

  sm->vlib_main = vm;
  sm->vnet_main = vnet_get_main ();

  /* Initialize the feature next-node indexes */
  feat_bitmap_init_next_nodes (vm,
			       span_l2_input_node.index,
			       L2INPUT_N_FEAT,
			       l2input_get_feat_names (),
			       sm->l2_input_next);

  feat_bitmap_init_next_nodes (vm,
			       span_l2_output_node.index,
			       L2OUTPUT_N_FEAT,
			       l2output_get_feat_names (),
			       sm->l2_output_next);
  return 0;
}

VLIB_INIT_FUNCTION (span_init);
/* *INDENT-ON* */

#undef span_node_defs
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
