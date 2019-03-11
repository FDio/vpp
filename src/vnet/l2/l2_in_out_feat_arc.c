/*
 * l2_in_out_feat_arc.c : layer 2 input/output acl processing
 *
 * Copyright (c) 2013,2018 Cisco and/or its affiliates.
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
#include <vnet/l2/l2_input.h>
#include <vnet/l2/l2_output.h>
#include <vnet/l2/feat_bitmap.h>
#include <vnet/l2/l2_in_out_feat_arc.h>

#include <vppinfra/error.h>
#include <vppinfra/hash.h>
#include <vppinfra/cache.h>


typedef struct
{

  /* Next nodes for each feature */
  u32 feat_next_node_index[IN_OUT_FEAT_ARC_N_TABLE_GROUPS][32];
  u8 ip4_feat_arc_index[IN_OUT_FEAT_ARC_N_TABLE_GROUPS];
  u8 ip6_feat_arc_index[IN_OUT_FEAT_ARC_N_TABLE_GROUPS];
  u8 nonip_feat_arc_index[IN_OUT_FEAT_ARC_N_TABLE_GROUPS];
  u32 next_slot[IN_OUT_FEAT_ARC_N_TABLE_GROUPS];

  /* convenience variables */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;
} l2_in_out_feat_arc_main_t __attribute__ ((aligned (CLIB_CACHE_LINE_BYTES)));

typedef struct
{
  u32 sw_if_index;
  u32 next_index;
  u32 feature_bitmap;
  u16 ethertype;
  u8 arc_head;
} l2_in_out_feat_arc_trace_t;

/* packet trace format function */
static u8 *
format_l2_in_out_feat_arc_trace (u8 * s, u32 is_output, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  l2_in_out_feat_arc_trace_t *t =
    va_arg (*args, l2_in_out_feat_arc_trace_t *);

  s =
    format (s,
	    "%s: head %d feature_bitmap %x ethertype %x sw_if_index %d, next_index %d",
	    is_output ? "OUT-FEAT-ARC" : "IN-FEAT-ARC", t->arc_head,
	    t->feature_bitmap, t->ethertype, t->sw_if_index, t->next_index);
  return s;
}

static u8 *
format_l2_in_feat_arc_trace (u8 * s, va_list * args)
{
  return format_l2_in_out_feat_arc_trace (s,
					  IN_OUT_FEAT_ARC_INPUT_TABLE_GROUP,
					  args);
}

static u8 *
format_l2_out_feat_arc_trace (u8 * s, va_list * args)
{
  return format_l2_in_out_feat_arc_trace (s,
					  IN_OUT_FEAT_ARC_OUTPUT_TABLE_GROUP,
					  args);
}


#define foreach_l2_in_feat_arc_error                   \
_(DEFAULT, "in default")                         \


#define foreach_l2_out_feat_arc_error                   \
_(DEFAULT, "out default")                         \


typedef enum
{
#define _(sym,str) L2_IN_FEAT_ARC_ERROR_##sym,
  foreach_l2_in_feat_arc_error
#undef _
    L2_IN_FEAT_ARC_N_ERROR,
} l2_in_feat_arc_error_t;

static char *l2_in_feat_arc_error_strings[] = {
#define _(sym,string) string,
  foreach_l2_in_feat_arc_error
#undef _
};

typedef enum
{
#define _(sym,str) L2_OUT_FEAT_ARC_ERROR_##sym,
  foreach_l2_out_feat_arc_error
#undef _
    L2_OUT_FEAT_ARC_N_ERROR,
} l2_out_feat_arc_error_t;

static char *l2_out_feat_arc_error_strings[] = {
#define _(sym,string) string,
  foreach_l2_out_feat_arc_error
#undef _
};

extern l2_in_out_feat_arc_main_t l2_in_out_feat_arc_main;

#ifndef CLIB_MARCH_VARIANT
l2_in_out_feat_arc_main_t l2_in_out_feat_arc_main;
#endif /* CLIB_MARCH_VARIANT */

#define get_u16(addr) ( *((u16 *)(addr)) )
#define L2_FEAT_ARC_VEC_SIZE 2

static_always_inline void
buffer_prefetch_xN (int vector_sz, vlib_buffer_t ** b)
{
  int ii;
  for (ii = 0; ii < vector_sz; ii++)
    CLIB_PREFETCH (b[ii], CLIB_CACHE_LINE_BYTES, STORE);
}

static_always_inline void
get_sw_if_index_xN (int vector_sz, int is_output, vlib_buffer_t ** b,
		    u32 * out_sw_if_index)
{
  int ii;
  for (ii = 0; ii < vector_sz; ii++)
    if (is_output)
      out_sw_if_index[ii] = vnet_buffer (b[ii])->sw_if_index[VLIB_TX];
    else
      out_sw_if_index[ii] = vnet_buffer (b[ii])->sw_if_index[VLIB_RX];
}

static_always_inline void
get_ethertype_xN (int vector_sz, int is_output, vlib_buffer_t ** b,
		  u16 * out_ethertype)
{
  int ii;
  for (ii = 0; ii < vector_sz; ii++)
    {
      ethernet_header_t *h0 = vlib_buffer_get_current (b[ii]);
      u8 *l3h0 = (u8 *) h0 + vnet_buffer (b[ii])->l2.l2_len;
      out_ethertype[ii] = clib_net_to_host_u16 (get_u16 (l3h0 - 2));
    }
}


static_always_inline void
set_next_in_arc_head_xN (int vector_sz, int is_output, u32 * next_nodes,
			 vlib_buffer_t ** b, u32 * sw_if_index,
			 u16 * ethertype, u8 ip4_arc, u8 ip6_arc,
			 u8 nonip_arc, u16 * out_next)
{
  int ii;
  for (ii = 0; ii < vector_sz; ii++)
    {
      u32 next_index = 0;
      u8 feature_arc;
      switch (ethertype[ii])
	{
	case ETHERNET_TYPE_IP4:
	  feature_arc = ip4_arc;
	  break;
	case ETHERNET_TYPE_IP6:
	  feature_arc = ip6_arc;
	  break;
	default:
	  feature_arc = nonip_arc;
	}
      if (PREDICT_TRUE (vnet_have_features (feature_arc, sw_if_index[ii])))
	vnet_feature_arc_start (feature_arc,
				sw_if_index[ii], &next_index, b[ii]);
      else
	next_index =
	  vnet_l2_feature_next (b[ii], next_nodes,
				is_output ? L2OUTPUT_FEAT_OUTPUT_FEAT_ARC :
				L2INPUT_FEAT_INPUT_FEAT_ARC);

      out_next[ii] = next_index;
    }
}

static_always_inline void
set_next_in_arc_tail_xN (int vector_sz, int is_output, u32 * next_nodes,
			 vlib_buffer_t ** b, u16 * out_next)
{
  int ii;
  for (ii = 0; ii < vector_sz; ii++)
    {
      out_next[ii] =
	vnet_l2_feature_next (b[ii], next_nodes,
			      is_output ? L2OUTPUT_FEAT_OUTPUT_FEAT_ARC :
			      L2INPUT_FEAT_INPUT_FEAT_ARC);
    }

}


static_always_inline void
maybe_trace_xN (int vector_sz, int arc_head, vlib_main_t * vm,
		vlib_node_runtime_t * node, vlib_buffer_t ** b,
		u32 * sw_if_index, u16 * ethertype, u16 * next)
{
  int ii;
  for (ii = 0; ii < vector_sz; ii++)
    if (PREDICT_FALSE (b[ii]->flags & VLIB_BUFFER_IS_TRACED))
      {
	l2_in_out_feat_arc_trace_t *t =
	  vlib_add_trace (vm, node, b[ii], sizeof (*t));
	t->arc_head = arc_head;
	t->sw_if_index = arc_head ? sw_if_index[ii] : ~0;
	t->feature_bitmap = vnet_buffer (b[ii])->l2.feature_bitmap;
	t->ethertype = arc_head ? ethertype[ii] : 0;
	t->next_index = next[ii];
      }
}

always_inline uword
l2_in_out_feat_arc_node_fn (vlib_main_t * vm,
			    vlib_node_runtime_t * node, vlib_frame_t * frame,
			    int is_output, vlib_node_registration_t * fa_node,
			    int arc_head, int do_trace)
{
  u32 n_left, *from;
  u16 nexts[VLIB_FRAME_SIZE], *next;
  u16 ethertypes[VLIB_FRAME_SIZE], *ethertype;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;
  u32 sw_if_indices[VLIB_FRAME_SIZE], *sw_if_index;
  l2_in_out_feat_arc_main_t *fam = &l2_in_out_feat_arc_main;

  u8 ip4_arc_index = fam->ip4_feat_arc_index[is_output];
  u8 ip6_arc_index = fam->ip6_feat_arc_index[is_output];
  u8 nonip_arc_index = fam->nonip_feat_arc_index[is_output];
  u32 *next_node_indices = fam->feat_next_node_index[is_output];

  from = vlib_frame_vector_args (frame);
  vlib_get_buffers (vm, from, bufs, frame->n_vectors);
  /* set the initial values for the current buffer the next pointers */
  b = bufs;
  next = nexts;
  ethertype = ethertypes;
  sw_if_index = sw_if_indices;
  n_left = frame->n_vectors;

  CLIB_PREFETCH (next_node_indices, 2 * CLIB_CACHE_LINE_BYTES, LOAD);

  while (n_left > 3 * L2_FEAT_ARC_VEC_SIZE)
    {
      const int vec_sz = L2_FEAT_ARC_VEC_SIZE;
      /* prefetch next N buffers */
      buffer_prefetch_xN (vec_sz, b + 2 * vec_sz);

      if (arc_head)
	{
	  get_sw_if_index_xN (vec_sz, is_output, b, sw_if_index);
	  get_ethertype_xN (vec_sz, is_output, b, ethertype);
	  set_next_in_arc_head_xN (vec_sz, is_output, next_node_indices, b,
				   sw_if_index, ethertype, ip4_arc_index,
				   ip6_arc_index, nonip_arc_index, next);
	}
      else
	{
	  set_next_in_arc_tail_xN (vec_sz, is_output, next_node_indices, b,
				   next);
	}
      if (do_trace)
	maybe_trace_xN (vec_sz, arc_head, vm, node, b, sw_if_index, ethertype,
			next);

      next += vec_sz;
      b += vec_sz;
      sw_if_index += vec_sz;
      ethertype += vec_sz;

      n_left -= vec_sz;
    }

  while (n_left > 0)
    {
      const int vec_sz = 1;

      if (arc_head)
	{
	  get_sw_if_index_xN (vec_sz, is_output, b, sw_if_index);
	  get_ethertype_xN (vec_sz, is_output, b, ethertype);
	  set_next_in_arc_head_xN (vec_sz, is_output, next_node_indices, b,
				   sw_if_index, ethertype, ip4_arc_index,
				   ip6_arc_index, nonip_arc_index, next);
	}
      else
	{
	  set_next_in_arc_tail_xN (vec_sz, is_output, next_node_indices, b,
				   next);
	}
      if (do_trace)
	maybe_trace_xN (vec_sz, arc_head, vm, node, b, sw_if_index, ethertype,
			next);

      next += vec_sz;
      b += vec_sz;
      sw_if_index += vec_sz;
      ethertype += vec_sz;

      n_left -= vec_sz;
    }

  vlib_buffer_enqueue_to_next (vm, node, from, nexts, frame->n_vectors);

  return frame->n_vectors;
}

VLIB_NODE_FN (l2_in_feat_arc_node) (vlib_main_t * vm,
				    vlib_node_runtime_t * node,
				    vlib_frame_t * frame)
{
  if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE))
    return l2_in_out_feat_arc_node_fn (vm, node, frame,
				       IN_OUT_FEAT_ARC_INPUT_TABLE_GROUP,
				       &l2_in_feat_arc_node, 1, 1);
  else
    return l2_in_out_feat_arc_node_fn (vm, node, frame,
				       IN_OUT_FEAT_ARC_INPUT_TABLE_GROUP,
				       &l2_in_feat_arc_node, 1, 0);
}

VLIB_NODE_FN (l2_out_feat_arc_node) (vlib_main_t * vm,
				     vlib_node_runtime_t * node,
				     vlib_frame_t * frame)
{
  if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE))
    return l2_in_out_feat_arc_node_fn (vm, node, frame,
				       IN_OUT_FEAT_ARC_OUTPUT_TABLE_GROUP,
				       &l2_out_feat_arc_node, 1, 1);
  else
    return l2_in_out_feat_arc_node_fn (vm, node, frame,
				       IN_OUT_FEAT_ARC_OUTPUT_TABLE_GROUP,
				       &l2_out_feat_arc_node, 1, 0);
}

VLIB_NODE_FN (l2_in_feat_arc_end_node) (vlib_main_t * vm,
					vlib_node_runtime_t * node,
					vlib_frame_t * frame)
{
  if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE))
    return l2_in_out_feat_arc_node_fn (vm, node, frame,
				       IN_OUT_FEAT_ARC_INPUT_TABLE_GROUP,
				       &l2_in_feat_arc_end_node, 0, 1);
  else
    return l2_in_out_feat_arc_node_fn (vm, node, frame,
				       IN_OUT_FEAT_ARC_INPUT_TABLE_GROUP,
				       &l2_in_feat_arc_end_node, 0, 0);
}

VLIB_NODE_FN (l2_out_feat_arc_end_node) (vlib_main_t * vm,
					 vlib_node_runtime_t * node,
					 vlib_frame_t * frame)
{
  if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE))
    return l2_in_out_feat_arc_node_fn (vm, node, frame,
				       IN_OUT_FEAT_ARC_OUTPUT_TABLE_GROUP,
				       &l2_out_feat_arc_end_node, 0, 1);
  else
    return l2_in_out_feat_arc_node_fn (vm, node, frame,
				       IN_OUT_FEAT_ARC_OUTPUT_TABLE_GROUP,
				       &l2_out_feat_arc_end_node, 0, 0);
}


#ifndef CLIB_MARCH_VARIANT
void
vnet_l2_in_out_feat_arc_enable_disable (u32 sw_if_index, int is_output,
					int enable_disable)
{
  if (is_output)
    l2output_intf_bitmap_enable (sw_if_index, L2OUTPUT_FEAT_OUTPUT_FEAT_ARC,
				 (u32) enable_disable);
  else
    l2input_intf_bitmap_enable (sw_if_index, L2INPUT_FEAT_INPUT_FEAT_ARC,
				(u32) enable_disable);
}
#endif /* CLIB_MARCH_VARIANT */

/* *INDENT-OFF* */
VNET_FEATURE_ARC_INIT (l2_in_ip4_arc, static) =
{
  .arc_name  = "l2-input-ip4",
  .start_nodes = VNET_FEATURES ("l2-input-feat-arc"),
  .arc_index_ptr = &l2_in_out_feat_arc_main.ip4_feat_arc_index[IN_OUT_FEAT_ARC_INPUT_TABLE_GROUP],
};

VNET_FEATURE_ARC_INIT (l2_out_ip4_arc, static) =
{
  .arc_name  = "l2-output-ip4",
  .start_nodes = VNET_FEATURES ("l2-output-feat-arc"),
  .arc_index_ptr = &l2_in_out_feat_arc_main.ip4_feat_arc_index[IN_OUT_FEAT_ARC_OUTPUT_TABLE_GROUP],
};

VNET_FEATURE_ARC_INIT (l2_out_ip6_arc, static) =
{
  .arc_name  = "l2-input-ip6",
  .start_nodes = VNET_FEATURES ("l2-input-feat-arc"),
  .arc_index_ptr = &l2_in_out_feat_arc_main.ip6_feat_arc_index[IN_OUT_FEAT_ARC_INPUT_TABLE_GROUP],
};
VNET_FEATURE_ARC_INIT (l2_in_ip6_arc, static) =
{
  .arc_name  = "l2-output-ip6",
  .start_nodes = VNET_FEATURES ("l2-output-feat-arc"),
  .arc_index_ptr = &l2_in_out_feat_arc_main.ip6_feat_arc_index[IN_OUT_FEAT_ARC_OUTPUT_TABLE_GROUP],
};

VNET_FEATURE_ARC_INIT (l2_out_nonip_arc, static) =
{
  .arc_name  = "l2-input-nonip",
  .start_nodes = VNET_FEATURES ("l2-input-feat-arc"),
  .arc_index_ptr = &l2_in_out_feat_arc_main.nonip_feat_arc_index[IN_OUT_FEAT_ARC_INPUT_TABLE_GROUP],
};
VNET_FEATURE_ARC_INIT (l2_in_nonip_arc, static) =
{
  .arc_name  = "l2-output-nonip",
  .start_nodes = VNET_FEATURES ("l2-output-feat-arc"),
  .arc_index_ptr = &l2_in_out_feat_arc_main.nonip_feat_arc_index[IN_OUT_FEAT_ARC_OUTPUT_TABLE_GROUP],
};


/* *INDENT-ON* */


/* *INDENT-OFF* */
VLIB_REGISTER_NODE (l2_in_feat_arc_node) = {
  .name = "l2-input-feat-arc",
  .vector_size = sizeof (u32),
  .format_trace = format_l2_in_feat_arc_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(l2_in_feat_arc_error_strings),
  .error_strings = l2_in_feat_arc_error_strings,

};

VLIB_REGISTER_NODE (l2_out_feat_arc_node) = {
  .name = "l2-output-feat-arc",
  .vector_size = sizeof (u32),
  .format_trace = format_l2_out_feat_arc_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(l2_out_feat_arc_error_strings),
  .error_strings = l2_out_feat_arc_error_strings,

};

VLIB_REGISTER_NODE (l2_in_feat_arc_end_node) = {
  .name = "l2-input-feat-arc-end",
  .vector_size = sizeof (u32),
  .format_trace = format_l2_in_feat_arc_trace,
  .sibling_of = "l2-input-feat-arc",
};

VLIB_REGISTER_NODE (l2_out_feat_arc_end_node) = {
  .name = "l2-output-feat-arc-end",
  .vector_size = sizeof (u32),
  .format_trace = format_l2_out_feat_arc_trace,
  .sibling_of = "l2-output-feat-arc",
};

VNET_FEATURE_INIT (l2_in_ip4_arc_end, static) =
{
  .arc_name = "l2-input-ip4",
  .node_name = "l2-input-feat-arc-end",
  .runs_before = 0,     /* not before any other features */
};

VNET_FEATURE_INIT (l2_out_ip4_arc_end, static) =
{
  .arc_name = "l2-output-ip4",
  .node_name = "l2-output-feat-arc-end",
  .runs_before = 0,     /* not before any other features */
};

VNET_FEATURE_INIT (l2_in_ip6_arc_end, static) =
{
  .arc_name = "l2-input-ip6",
  .node_name = "l2-input-feat-arc-end",
  .runs_before = 0,     /* not before any other features */
};


VNET_FEATURE_INIT (l2_out_ip6_arc_end, static) =
{
  .arc_name = "l2-output-ip6",
  .node_name = "l2-output-feat-arc-end",
  .runs_before = 0,     /* not before any other features */
};

VNET_FEATURE_INIT (l2_in_nonip_arc_end, static) =
{
  .arc_name = "l2-input-nonip",
  .node_name = "l2-input-feat-arc-end",
  .runs_before = 0,     /* not before any other features */
};


VNET_FEATURE_INIT (l2_out_nonip_arc_end, static) =
{
  .arc_name = "l2-output-nonip",
  .node_name = "l2-output-feat-arc-end",
  .runs_before = 0,     /* not before any other features */
};
/* *INDENT-ON* */


#ifndef CLIB_MARCH_VARIANT
clib_error_t *
l2_in_out_feat_arc_init (vlib_main_t * vm)
{
  l2_in_out_feat_arc_main_t *mp = &l2_in_out_feat_arc_main;

  mp->vlib_main = vm;
  mp->vnet_main = vnet_get_main ();

  /* Initialize the feature next-node indexes */
  feat_bitmap_init_next_nodes (vm,
			       l2_in_feat_arc_end_node.index,
			       L2INPUT_N_FEAT,
			       l2input_get_feat_names (),
			       mp->feat_next_node_index
			       [IN_OUT_FEAT_ARC_INPUT_TABLE_GROUP]);
  feat_bitmap_init_next_nodes (vm, l2_out_feat_arc_end_node.index,
			       L2OUTPUT_N_FEAT, l2output_get_feat_names (),
			       mp->feat_next_node_index
			       [IN_OUT_FEAT_ARC_OUTPUT_TABLE_GROUP]);
  return 0;
}


static int
l2_has_features (u32 sw_if_index, int is_output)
{
  int has_features = 0;
  l2_in_out_feat_arc_main_t *mp = &l2_in_out_feat_arc_main;
  has_features +=
    vnet_have_features (mp->ip4_feat_arc_index[is_output], sw_if_index);
  has_features +=
    vnet_have_features (mp->ip6_feat_arc_index[is_output], sw_if_index);
  has_features +=
    vnet_have_features (mp->nonip_feat_arc_index[is_output], sw_if_index);
  return has_features > 0;
}

static int
l2_is_output_arc (u8 arc_index)
{
  l2_in_out_feat_arc_main_t *mp = &l2_in_out_feat_arc_main;
  int idx = IN_OUT_FEAT_ARC_OUTPUT_TABLE_GROUP;
  return (mp->ip4_feat_arc_index[idx] == arc_index
	  || mp->ip6_feat_arc_index[idx] == arc_index
	  || mp->nonip_feat_arc_index[idx] == arc_index);
}

static int
l2_is_input_arc (u8 arc_index)
{
  l2_in_out_feat_arc_main_t *mp = &l2_in_out_feat_arc_main;
  int idx = IN_OUT_FEAT_ARC_INPUT_TABLE_GROUP;
  return (mp->ip4_feat_arc_index[idx] == arc_index
	  || mp->ip6_feat_arc_index[idx] == arc_index
	  || mp->nonip_feat_arc_index[idx] == arc_index);
}

int
vnet_l2_feature_enable_disable (const char *arc_name, const char *node_name,
				u32 sw_if_index, int enable_disable,
				void *feature_config,
				u32 n_feature_config_bytes)
{
  u8 arc_index = vnet_get_feature_arc_index (arc_name);
  if (arc_index == (u8) ~ 0)
    return VNET_API_ERROR_INVALID_VALUE;

  /* check the state before we tried to enable/disable */
  int had_features = vnet_have_features (arc_index, sw_if_index);

  int ret = vnet_feature_enable_disable (arc_name, node_name, sw_if_index,
					 enable_disable, feature_config,
					 n_feature_config_bytes);
  if (ret)
    return ret;

  int has_features = vnet_have_features (arc_index, sw_if_index);

  if (had_features != has_features)
    {
      if (l2_is_output_arc (arc_index))
	{
	  vnet_l2_in_out_feat_arc_enable_disable (sw_if_index, 1,
						  l2_has_features
						  (sw_if_index, 1));
	}
      if (l2_is_input_arc (arc_index))
	{
	  vnet_l2_in_out_feat_arc_enable_disable (sw_if_index, 0,
						  l2_has_features
						  (sw_if_index, 0));
	}
    }
  return 0;
}


VLIB_INIT_FUNCTION (l2_in_out_feat_arc_init);
#endif /* CLIB_MARCH_VARIANT */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
