/*
 * Copyright (c) 2019 Cisco and/or its affiliates.
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
#include <plugins/gbp/gbp_vxlan.h>
#include <plugins/gbp/gbp_itf.h>
#include <plugins/gbp/gbp_learn.h>
#include <plugins/gbp/gbp_bridge_domain.h>
#include <plugins/gbp/gbp_route_domain.h>

#include <vnet/vxlan-gbp/vxlan_gbp.h>
#include <vlibmemory/api.h>
#include <vnet/fib/fib_table.h>

extern uword *gv_db;

typedef struct gbp_vxlan_trace_t_
{
  u8 dropped;
  u32 vni;
  u32 sw_if_index;
  u16 sclass;
  u8 flags;
} gbp_vxlan_trace_t;

#define foreach_gbp_vxlan_input_next         \
  _(DROP, "error-drop")                      \
  _(L2_INPUT, "l2-input")                    \
  _(IP4_INPUT, "ip4-input")                  \
  _(IP6_INPUT, "ip6-input")

typedef enum
{
#define _(s,n) GBP_VXLAN_INPUT_NEXT_##s,
  foreach_gbp_vxlan_input_next
#undef _
    GBP_VXLAN_INPUT_N_NEXT,
} gbp_vxlan_input_next_t;


#define foreach_gbp_vxlan_error              \
  _(DECAPPED, "decapped")                    \
  _(LEARNED, "learned")

typedef enum
{
#define _(s,n) GBP_VXLAN_ERROR_##s,
  foreach_gbp_vxlan_error
#undef _
    GBP_VXLAN_N_ERROR,
} gbp_vxlan_input_error_t;

static char *gbp_vxlan_error_strings[] = {
#define _(n,s) s,
  foreach_gbp_vxlan_error
#undef _
};

static uword
gbp_vxlan_decap (vlib_main_t * vm,
		 vlib_node_runtime_t * node,
		 vlib_frame_t * from_frame, u8 is_ip4)
{
  u32 n_left_to_next, n_left_from, next_index, *to_next, *from;

  next_index = 0;
  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;

  while (n_left_from > 0)
    {

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  vxlan_gbp_header_t *vxlan_gbp0;
	  gbp_vxlan_input_next_t next0;
	  gbp_vxlan_tunnel_t *gt0;
	  vlib_buffer_t *b0;
	  u32 bi0, vni0;
	  uword *p;

	  bi0 = to_next[0] = from[0];
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;
	  next0 = GBP_VXLAN_INPUT_NEXT_DROP;

	  b0 = vlib_get_buffer (vm, bi0);
	  vxlan_gbp0 =
	    vlib_buffer_get_current (b0) - sizeof (vxlan_gbp_header_t);

	  vni0 = vxlan_gbp_get_vni (vxlan_gbp0);
	  p = hash_get (gv_db, vni0);

	  if (PREDICT_FALSE (NULL == p))
	    {
	      gt0 = NULL;
	      next0 = GBP_VXLAN_INPUT_NEXT_DROP;
	    }
	  else
	    {
	      gt0 = gbp_vxlan_tunnel_get (p[0]);

	      vnet_buffer (b0)->sw_if_index[VLIB_RX] = gt0->gt_sw_if_index;

	      if (GBP_VXLAN_TUN_L2 == gt0->gt_layer)
		/*
		 * An L2 layer tunnel goes into the BD
		 */
		next0 = GBP_VXLAN_INPUT_NEXT_L2_INPUT;
	      else
		{
		  /*
		   * An L3 layer tunnel needs to strip the L2 header
		   * an inject into the RD
		   */
		  ethernet_header_t *e0;
		  u16 type0;

		  e0 = vlib_buffer_get_current (b0);
		  type0 = clib_net_to_host_u16 (e0->type);
		  switch (type0)
		    {
		    case ETHERNET_TYPE_IP4:
		      next0 = GBP_VXLAN_INPUT_NEXT_IP4_INPUT;
		      break;
		    case ETHERNET_TYPE_IP6:
		      next0 = GBP_VXLAN_INPUT_NEXT_IP6_INPUT;
		      break;
		    default:
		      goto trace;
		    }
		  vlib_buffer_advance (b0, sizeof (*e0));
		}
	    }

	trace:
	  if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      gbp_vxlan_trace_t *tr;

	      tr = vlib_add_trace (vm, node, b0, sizeof (*tr));
	      tr->dropped = (next0 == GBP_VXLAN_INPUT_NEXT_DROP);
	      tr->vni = vni0;
	      tr->sw_if_index = (gt0 ? gt0->gt_sw_if_index : ~0);
	      tr->flags = vxlan_gbp_get_gpflags (vxlan_gbp0);
	      tr->sclass = vxlan_gbp_get_sclass (vxlan_gbp0);
	    }

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return from_frame->n_vectors;
}

VLIB_NODE_FN (gbp_vxlan4_input_node) (vlib_main_t * vm,
				      vlib_node_runtime_t * node,
				      vlib_frame_t * from_frame)
{
  return gbp_vxlan_decap (vm, node, from_frame, 1);
}

static u8 *
format_gbp_vxlan_rx_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  gbp_vxlan_trace_t *t = va_arg (*args, gbp_vxlan_trace_t *);

  s = format (s, "vni:%d dropped:%d rx:%d sclass:%d flags:%U",
	      t->vni, t->dropped, t->sw_if_index,
	      t->sclass, format_vxlan_gbp_header_gpflags, t->flags);

  return (s);
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (gbp_vxlan4_input_node) =
{
  .name = "gbp-vxlan4",
  .vector_size = sizeof (u32),
  .n_errors = GBP_VXLAN_N_ERROR,
  .error_strings = gbp_vxlan_error_strings,
  .n_next_nodes = GBP_VXLAN_INPUT_N_NEXT,
  .format_trace = format_gbp_vxlan_rx_trace,
  .next_nodes = {
#define _(s,n) [GBP_VXLAN_INPUT_NEXT_##s] = n,
    foreach_gbp_vxlan_input_next
#undef _
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
