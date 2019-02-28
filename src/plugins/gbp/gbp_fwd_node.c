/*
 * Copyright (c) 2018 Cisco and/or its affiliates.
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

#include <plugins/gbp/gbp.h>
#include <vnet/l2/l2_input.h>

#define foreach_gbp_fwd                      \
  _(DROP,    "drop")                         \
  _(OUTPUT,  "output")

typedef enum
{
#define _(sym,str) GBP_FWD_ERROR_##sym,
  foreach_gbp_fwd
#undef _
    GBP_FWD_N_ERROR,
} gbp_fwd_error_t;

static char *gbp_fwd_error_strings[] = {
#define _(sym,string) string,
  foreach_gbp_fwd
#undef _
};

typedef enum
{
#define _(sym,str) GBP_FWD_NEXT_##sym,
  foreach_gbp_fwd
#undef _
    GBP_FWD_N_NEXT,
} gbp_fwd_next_t;

/**
 * per-packet trace data
 */
typedef struct gbp_fwd_trace_t_
{
  /* per-pkt trace data */
  sclass_t sclass;
  u32 sw_if_index;
} gbp_fwd_trace_t;

VLIB_NODE_FN (gbp_fwd_node) (vlib_main_t * vm, vlib_node_runtime_t * node,
			     vlib_frame_t * frame)
{
  u32 n_left_from, *from, *to_next;
  u32 next_index;

  next_index = 0;
  n_left_from = frame->n_vectors;
  from = vlib_frame_vector_args (frame);

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0, sw_if_index0;
	  gbp_fwd_next_t next0;
	  vlib_buffer_t *b0;
	  sclass_t sclass0;

	  next0 = GBP_FWD_NEXT_DROP;
	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);

	  /*
	   * lookup the uplink based on src EPG
	   */
	  sclass0 = vnet_buffer2 (b0)->gbp.sclass;

	  sw_if_index0 = gbp_epg_itf_lookup_sclass (sclass0);

	  if (~0 != sw_if_index0)
	    {
	      vnet_buffer (b0)->sw_if_index[VLIB_TX] = sw_if_index0;

	      next0 = GBP_FWD_NEXT_OUTPUT;
	    }
	  /*
	   * else
	   *  don't know the uplink interface for this EPG => drop
	   */

	  if (PREDICT_FALSE ((b0->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      gbp_fwd_trace_t *t = vlib_add_trace (vm, node, b0, sizeof (*t));
	      t->sclass = sclass0;
	      t->sw_if_index = sw_if_index0;
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

/* packet trace format function */
static u8 *
format_gbp_fwd_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  gbp_fwd_trace_t *t = va_arg (*args, gbp_fwd_trace_t *);

  s = format (s, "sclass:%d", t->sclass);

  return s;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (gbp_fwd_node) = {
  .name = "gbp-fwd",
  .vector_size = sizeof (u32),
  .format_trace = format_gbp_fwd_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(gbp_fwd_error_strings),
  .error_strings = gbp_fwd_error_strings,

  .n_next_nodes = GBP_FWD_N_NEXT,

  .next_nodes = {
    [GBP_FWD_NEXT_DROP] = "error-drop",
    [GBP_FWD_NEXT_OUTPUT] = "l2-output",
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
