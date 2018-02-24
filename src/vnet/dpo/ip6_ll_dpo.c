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
/**
 * @brief
 * The data-path object representing performing a lookup in the IPv6
 * link local table
 */

#include <vnet/dpo/ip6_ll_dpo.h>
#include <vnet/ip/ip6_ll_table.h>

/**
 * @brief the IP6 link-local DPO is global
 */
static dpo_id_t ip6_ll_dpo = {
  .dpoi_type = DPO_IP6_LL,
  .dpoi_proto = DPO_PROTO_IP6,
  .dpoi_index = 0,
};

const dpo_id_t *
ip6_ll_dpo_get (void)
{
  return (&ip6_ll_dpo);
}

static void
ip6_ll_dpo_lock (dpo_id_t * dpo)
{
  /*
   * not maintaining a lock count on the ip6_ll, they are const global and
   * never die.
   */
}

static void
ip6_ll_dpo_unlock (dpo_id_t * dpo)
{
}

static u8 *
format_ip6_ll_dpo (u8 * s, va_list * ap)
{
  CLIB_UNUSED (index_t index) = va_arg (*ap, index_t);
  CLIB_UNUSED (u32 indent) = va_arg (*ap, u32);

  return (format (s, "ip6-link-local"));
}

const static dpo_vft_t ip6_ll_vft = {
  .dv_lock = ip6_ll_dpo_lock,
  .dv_unlock = ip6_ll_dpo_unlock,
  .dv_format = format_ip6_ll_dpo,
};

/**
 * @brief The per-protocol VLIB graph nodes that are assigned to a ip6_ll
 *        object.
 *
 * this means that these graph nodes are ones from which a ip6_ll is the
 * parent object in the DPO-graph.
 */
const static char *const ip6_null_nodes[] = {
  "ip6-link-local",
  NULL,
};

const static char *const *const ip6_ll_nodes[DPO_PROTO_NUM] = {
  [DPO_PROTO_IP6] = ip6_null_nodes,
};

typedef struct ip6_ll_dpo_trace_t_
{
  u32 fib_index;
  u32 sw_if_index;
} ip6_ll_dpo_trace_t;

/**
 * @brief Exit nodes from a IP6_LL
 */
typedef enum ip6_ll_next_t_
{
  IP6_LL_NEXT_DROP,
  IP6_LL_NEXT_LOOKUP,
  IP6_LL_NEXT_NUM,
} ip6_ll_next_t;

always_inline uword
ip6_ll_dpo_inline (vlib_main_t * vm,
		   vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  u32 n_left_from, next_index, *from, *to_next;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0, fib_index0, next0;
	  vlib_buffer_t *p0;

	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;
	  next0 = IP6_LL_NEXT_LOOKUP;

	  p0 = vlib_get_buffer (vm, bi0);

	  /* use the packet's RX interface to pick the link-local FIB */
	  fib_index0 =
	    ip6_ll_fib_get (vnet_buffer (p0)->sw_if_index[VLIB_RX]);
	  /* write that fib index into the packet so it's used in the
	   * lookup node next */
	  vnet_buffer (p0)->sw_if_index[VLIB_TX] = fib_index0;

	  if (PREDICT_FALSE (p0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      ip6_ll_dpo_trace_t *tr = vlib_add_trace (vm, node, p0,
						       sizeof (*tr));
	      tr->sw_if_index = vnet_buffer (p0)->sw_if_index[VLIB_RX];
	      tr->fib_index = fib_index0;
	    }
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return frame->n_vectors;
}

static u8 *
format_ip6_ll_dpo_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  ip6_ll_dpo_trace_t *t = va_arg (*args, ip6_ll_dpo_trace_t *);

  s = format (s, "sw_if_index:%d fib_index:%d", t->sw_if_index, t->fib_index);
  return s;
}

static uword
ip6_ll_dpo_switch (vlib_main_t * vm,
		   vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  return (ip6_ll_dpo_inline (vm, node, frame));
}

/**
 * @brief
 */
/* *INDENT-OFF* */
VLIB_REGISTER_NODE (ip6_ll_dpo_node) =
{
  .function = ip6_ll_dpo_switch,
  .name = "ip6-link-local",
  .vector_size = sizeof (u32),
  .format_trace = format_ip6_ll_dpo_trace,
  .n_next_nodes = IP6_LL_NEXT_NUM,
  .next_nodes = {
    [IP6_LL_NEXT_DROP] = "ip6-drop",
    [IP6_LL_NEXT_LOOKUP] = "ip6-lookup",
  },
};
/* *INDENT-ON* */

void
ip6_ll_dpo_module_init (void)
{
  dpo_register (DPO_IP6_LL, &ip6_ll_vft, ip6_ll_nodes);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
