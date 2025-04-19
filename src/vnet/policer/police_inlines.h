/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
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
#ifndef __POLICE_INLINES_H__
#define __POLICE_INLINES_H__

#include <vnet/policer/police.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip.h>

#define IP4_NON_DSCP_BITS 0x03
#define IP4_DSCP_SHIFT    2
#define IP6_NON_DSCP_BITS 0xf03fffff
#define IP6_DSCP_SHIFT    22

static_always_inline void
vnet_policer_mark (vlib_buffer_t *b, ip_dscp_t dscp)
{
  ethernet_header_t *eh;
  ip4_header_t *ip4h;
  ip6_header_t *ip6h;
  u16 type;

  eh = (ethernet_header_t *) b->data;
  type = clib_net_to_host_u16 (eh->type);

  if (PREDICT_TRUE (type == ETHERNET_TYPE_IP4))
    {
      ip4h = (ip4_header_t *) & (b->data[sizeof (ethernet_header_t)]);;
      ip4h->tos &= IP4_NON_DSCP_BITS;
      ip4h->tos |= dscp << IP4_DSCP_SHIFT;
      ip4h->checksum = ip4_header_checksum (ip4h);
    }
  else
    {
      if (PREDICT_TRUE (type == ETHERNET_TYPE_IP6))
	{
	  ip6h = (ip6_header_t *) & (b->data[sizeof (ethernet_header_t)]);
	  ip6h->ip_version_traffic_class_and_flow_label &=
	    clib_host_to_net_u32 (IP6_NON_DSCP_BITS);
	  ip6h->ip_version_traffic_class_and_flow_label |=
	    clib_host_to_net_u32 (dscp << IP6_DSCP_SHIFT);
	}
    }
}

static_always_inline u8
vnet_policer_police (vlib_main_t *vm, vlib_buffer_t *b, u32 policer_index,
		     u64 time_in_policer_periods,
		     policer_result_e packet_color, bool handoff)
{
  qos_action_type_en act;
  u32 len;
  u32 col;
  policer_t *pol;
  vnet_policer_main_t *pm = &vnet_policer_main;

  /* Speculative prefetch assuming a conform result */
  vlib_prefetch_combined_counter (&policer_counters[POLICE_CONFORM],
				  vm->thread_index, policer_index);

  pol = &pm->policers[policer_index];

  if (handoff)
    {
      if (PREDICT_FALSE (pol->thread_index == CLIB_INVALID_THREAD_INDEX))
	/*
	 * This is the first packet to use this policer. Set the
	 * thread index in the policer to this thread and any
	 * packets seen by this node on other threads will
	 * be handed off to this one.
	 *
	 * This could happen simultaneously on another thread.
	 */
	clib_atomic_cmp_and_swap (&pol->thread_index, ~0, vm->thread_index);
      else if (PREDICT_FALSE (pol->thread_index != vm->thread_index))
	return QOS_ACTION_HANDOFF;
    }

  len = vlib_buffer_length_in_chain (vm, b);
  col = vnet_police_packet (pol, len, packet_color, time_in_policer_periods);
  act = pol->action[col];
  vlib_increment_combined_counter (&policer_counters[col], vm->thread_index,
				   policer_index, 1, len);
  if (PREDICT_TRUE (act == QOS_ACTION_MARK_AND_TRANSMIT))
    vnet_policer_mark (b, pol->mark_dscp[col]);

  return act;
}

typedef enum
{
  POLICER_HANDOFF_ERROR_CONGESTION_DROP,
} policer_handoff_error_t;

typedef struct policer_handoff_trace_t_
{
  u32 policer_index;
  u32 current_worker_index;
  u32 next_worker_index;
} policer_handoff_trace_t;

extern u8 *format_policer_handoff_trace (u8 *s, va_list *args);

/* Do worker handoff based on the policer's thread_index */
static_always_inline uword
policer_handoff (vlib_main_t *vm, vlib_node_runtime_t *node,
		 vlib_frame_t *frame, u32 fq_index, u32 policer_index)
{
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;
  u16 thread_indices[VLIB_FRAME_SIZE], *ti;
  u32 n_enq, n_left_from, *from;
  vnet_policer_main_t *pm;
  policer_t *policer;
  u32 this_thread, policer_thread = 0;
  bool single_policer_node = (policer_index != ~0);

  pm = &vnet_policer_main;
  if (single_policer_node)
    {
      policer = &pm->policers[policer_index];
      policer_thread = policer->thread_index;
    }

  this_thread = vm->thread_index;
  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  vlib_get_buffers (vm, from, bufs, n_left_from);

  b = bufs;
  ti = thread_indices;

  while (n_left_from > 0)
    {
      if (!single_policer_node)
	{
	  policer_index = vnet_buffer (b[0])->policer.index;
	  policer = &pm->policers[policer_index];
	  ti[0] = policer->thread_index;
	}
      else
	{
	  ti[0] = policer_thread;
	}

      if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE) &&
			 b[0]->flags & VLIB_BUFFER_IS_TRACED))
	{
	  policer_handoff_trace_t *t =
	    vlib_add_trace (vm, node, b[0], sizeof (*t));
	  t->current_worker_index = this_thread;
	  t->next_worker_index = ti[0];
	  t->policer_index = policer_index;
	}

      n_left_from--;
      ti++;
      b++;
    }

  n_enq = vlib_buffer_enqueue_to_thread (vm, node, fq_index, from,
					 thread_indices, frame->n_vectors, 1);

  if (n_enq < frame->n_vectors)
    vlib_node_increment_counter (vm, node->node_index,
				 POLICER_HANDOFF_ERROR_CONGESTION_DROP,
				 frame->n_vectors - n_enq);

  return n_enq;
}
#endif // __POLICE_INLINES_H__

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
