/*
 * feat_bitmap.c: bitmap for managing feature invocation
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
#include <vlib/cli.h>
#include <vnet/l2/l2_input.h>
#include <vnet/l2/feat_bitmap.h>

#include <vppinfra/error.h>
#include <vppinfra/hash.h>
#include <vppinfra/cache.h>


/*
 * Drop node for feature bitmaps
 * For features that just do a drop, or are not yet implemented.
 * Initial feature dispatch nodes don't need to set b0->error
 * in case of a possible drop because that will be done here.
 *The next node is always error-drop.
 */

static vlib_node_registration_t feat_bitmap_drop_node;

#define foreach_feat_bitmap_drop_error		\
_(NO_FWD,     "L2 feature forwarding disabled")	\
_(NYI,        "L2 feature not implemented")

typedef enum
{
#define _(sym,str) FEAT_BITMAP_DROP_ERROR_##sym,
  foreach_feat_bitmap_drop_error
#undef _
    FEAT_BITMAP_DROP_N_ERROR,
} feat_bitmap_drop_error_t;

static char *feat_bitmap_drop_error_strings[] = {
#define _(sym,string) string,
  foreach_feat_bitmap_drop_error
#undef _
};

typedef enum
{
  FEAT_BITMAP_DROP_NEXT_DROP,
  FEAT_BITMAP_DROP_N_NEXT,
} feat_bitmap_drop_next_t;

typedef struct
{
  u32 feature_bitmap;
} feat_bitmap_drop_trace_t;

/* packet trace format function */
static u8 *
format_feat_bitmap_drop_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  feat_bitmap_drop_trace_t *t = va_arg (*args, feat_bitmap_drop_trace_t *);

  s =
    format (s, "feat_bitmap_drop: feature bitmap 0x%08x", t->feature_bitmap);
  return s;
}

static uword
feat_bitmap_drop_node_fn (vlib_main_t * vm,
			  vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  u32 n_left_from, *from, *to_next;
  feat_bitmap_drop_next_t next_index;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;	/* number of packets to process */
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      /* get space to enqueue frame to graph node "next_index" */
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0;
	  vlib_buffer_t *b0;
	  u32 next0;

	  /* speculatively enqueue b0 to the current next frame */
	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);

	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)
			     && (b0->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      feat_bitmap_drop_trace_t *t =
		vlib_add_trace (vm, node, b0, sizeof (*t));
	      t->feature_bitmap = vnet_buffer (b0)->l2.feature_bitmap;
	    }

	  if (vnet_buffer (b0)->l2.feature_bitmap == 1)
	    {
	      /*
	       * If we are executing the last feature, this is the
	       * No forwarding catch-all
	       */
	      b0->error = node->errors[FEAT_BITMAP_DROP_ERROR_NO_FWD];
	    }
	  else
	    {
	      b0->error = node->errors[FEAT_BITMAP_DROP_ERROR_NYI];
	    }
	  next0 = FEAT_BITMAP_DROP_NEXT_DROP;

	  /* verify speculative enqueue, maybe switch current next frame */
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }
  return frame->n_vectors;
}

clib_error_t *
feat_bitmap_drop_init (vlib_main_t * vm)
{
  return 0;
}

VLIB_INIT_FUNCTION (feat_bitmap_drop_init);

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (feat_bitmap_drop_node,static) = {
  .function = feat_bitmap_drop_node_fn,
  .name = "feature-bitmap-drop",
  .vector_size = sizeof (u32),
  .format_trace = format_feat_bitmap_drop_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(feat_bitmap_drop_error_strings),
  .error_strings = feat_bitmap_drop_error_strings,

  .n_next_nodes = FEAT_BITMAP_DROP_N_NEXT,

  /* edit / add dispositions here */
  .next_nodes = {
    [FEAT_BITMAP_DROP_NEXT_DROP]  = "error-drop",
  },
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
