/*
 * Copyright (c) 2020 Cisco and/or its affiliates.
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

#include <vlibmemory/api.h>
#include <vnet/dpo/load_balance.h>
#include <vnet/dpo/load_balance_map.h>

#include <cnat/cnat_session.h>
#include <cnat/cnat_client.h>
#include <cnat/cnat_inline.h>
#include <cnat/cnat_translation.h>

#include <vnet/ip/ip4_inlines.h>
#include <vnet/ip/ip6_inlines.h>

#include <pbl/pbl_client.h>

typedef enum pbl_translation_next_t_
{
  PBL_NEXT_DROP,
  PBL_NEXT_LOOKUP,
  PBL_TRANSLATION_N_NEXT,
} pbl_translation_next_t;

vlib_node_registration_t pbl_vip_ip4_node;
vlib_node_registration_t pbl_vip_ip6_node;

typedef struct
{
  u8 matched;
} pbl_trace_t;

static u8 *
format_pbl_trace (u8 *s, va_list *args)
{
  vlib_main_t *__clib_unused vm = va_arg (*args, vlib_main_t *);
  vlib_node_t *__clib_unused node = va_arg (*args, vlib_node_t *);
  pbl_trace_t *t = va_arg (*args, pbl_trace_t *);
  if (t->matched)
    s = format (s, "matched PBL client");
  else
    s = format (s, "no match");
  return s;
}

/* CNat sub for NAT behind a fib entry (VIP or interposed real IP) */
static uword
pbl_node_inline (vlib_main_t *vm, vlib_node_runtime_t *node,
		 vlib_frame_t *frame, ip_address_family_t af, u8 do_trace)
{

  u32 n_left, *from;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE];
  vlib_buffer_t **b = bufs;
  u16 nexts[VLIB_FRAME_SIZE], *next;
  pbl_trace_t *t;
  int matched = 0;

  from = vlib_frame_vector_args (frame);
  n_left = frame->n_vectors;
  next = nexts;
  vlib_get_buffers (vm, from, bufs, n_left);

  while (n_left > 0)
    {
      ip4_header_t *ip4 = NULL;
      ip6_header_t *ip6 = NULL;
      pbl_client_port_map_proto_t proto;
      udp_header_t *udp0;
      pbl_client_t *pc;

      if (AF_IP4 == af)
	{
	  ip4 = vlib_buffer_get_current (b[0]);
	  proto = pbl_iproto_to_port_map_proto (ip4->protocol);
	  udp0 = (udp_header_t *) (ip4 + 1);
	}
      else
	{
	  ip6 = vlib_buffer_get_current (b[0]);
	  proto = pbl_iproto_to_port_map_proto (ip6->protocol);
	  udp0 = (udp_header_t *) (ip6 + 1);
	}

      pc = pbl_client_get (vnet_buffer (b[0])->ip.adj_index[VLIB_TX]);
      if (proto < PBL_CLIENT_PORT_MAP_N_PROTOS &&
	  clib_bitmap_get (pc->pc_port_maps[proto],
			   clib_net_to_host_u16 (udp0->dst_port)))
	{
	  /* matched */
	  next[0] = pc->pc_dpo.dpoi_next_node;
	  vnet_buffer (b[0])->ip.adj_index[VLIB_TX] = pc->pc_dpo.dpoi_index;
	  matched = 1;
	  goto trace;
	}

      /* Dont translate & Follow the fib programming */
      matched = 0;
      vnet_buffer (b[0])->ip.adj_index[VLIB_TX] = pc->pc_parent.dpoi_index;
      next[0] = pc->pc_parent.dpoi_next_node;

    trace:

      if (do_trace)
	{
	  t = vlib_add_trace (vm, node, b[0], sizeof (*t));
	  t->matched = matched;
	}

      b++;
      next++;
      n_left--;
    }

  vlib_buffer_enqueue_to_next (vm, node, from, nexts, frame->n_vectors);

  return frame->n_vectors;
}

VLIB_NODE_FN (pbl_vip_ip4_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)))
    return pbl_node_inline (vm, node, frame, AF_IP4, 1 /* do_trace */);
  return pbl_node_inline (vm, node, frame, AF_IP4, 0 /* do_trace */);
}

VLIB_NODE_FN (pbl_vip_ip6_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)))
    return pbl_node_inline (vm, node, frame, AF_IP6, 1 /* do_trace */);
  return pbl_node_inline (vm, node, frame, AF_IP6, 0 /* do_trace */);
}

VLIB_REGISTER_NODE (pbl_vip_ip4_node) =
{
  .name = "ip4-pbl-tx",
  .vector_size = sizeof (u32),
  .format_trace = format_pbl_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = 0,
  .n_next_nodes = PBL_TRANSLATION_N_NEXT,
  .next_nodes =
  {
    [PBL_NEXT_DROP] = "ip4-drop",
    [PBL_NEXT_LOOKUP] = "ip4-lookup",
  },
};
VLIB_REGISTER_NODE (pbl_vip_ip6_node) =
{
  .name = "ip6-pbl-tx",
  .vector_size = sizeof (u32),
  .format_trace = format_pbl_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = 0,
  .n_next_nodes = PBL_TRANSLATION_N_NEXT,
  .next_nodes =
  {
    [PBL_NEXT_DROP] = "ip6-drop",
    [PBL_NEXT_LOOKUP] = "ip6-lookup",
  },
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
