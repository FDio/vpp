/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2015 Cisco and/or its affiliates.
 */

#ifndef __POLICE_INLINES_H__
#define __POLICE_INLINES_H__

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <policer/policer.h>

#define IP4_NON_DSCP_BITS 0x03
#define IP4_DSCP_SHIFT	  2
#define IP6_NON_DSCP_BITS 0xf03fffff
#define IP6_DSCP_SHIFT	  22

static_always_inline void
policer_mark (vlib_buffer_t *b, ip_dscp_t dscp)
{
  ethernet_header_t *eh;
  ip4_header_t *ip4h;
  ip6_header_t *ip6h;
  u16 type;

  eh = (ethernet_header_t *) b->data;
  type = clib_net_to_host_u16 (eh->type);

  if (PREDICT_TRUE (type == ETHERNET_TYPE_IP4))
    {
      ip4h = (ip4_header_t *) &(b->data[sizeof (ethernet_header_t)]);
      ;
      ip4h->tos &= IP4_NON_DSCP_BITS;
      ip4h->tos |= dscp << IP4_DSCP_SHIFT;
      ip4h->checksum = ip4_header_checksum (ip4h);
    }
  else
    {
      if (PREDICT_TRUE (type == ETHERNET_TYPE_IP6))
	{
	  ip6h = (ip6_header_t *) &(b->data[sizeof (ethernet_header_t)]);
	  ip6h->ip_version_traffic_class_and_flow_label &= clib_host_to_net_u32 (IP6_NON_DSCP_BITS);
	  ip6h->ip_version_traffic_class_and_flow_label |=
	    clib_host_to_net_u32 (dscp << IP6_DSCP_SHIFT);
	}
    }
}

static_always_inline u8
policer_police (vlib_main_t *vm, vlib_buffer_t *b, u32 policer_index, u64 time_in_policer_periods,
		policer_result_e packet_color, bool handoff, u16 l2_overhead)
{
  qos_action_type_en act;
  u32 len;
  u32 col;
  policer_t *pol;
  policer_main_t *pm = &policer_main;

  /* Speculative prefetch assuming a conform result */
  vlib_prefetch_combined_counter (&policer_counters[POLICE_CONFORM], vm->thread_index,
				  policer_index);

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
  len += l2_overhead;
  col = vnet_police_packet (pol, len, packet_color, time_in_policer_periods);
  act = pol->action[col];
  vlib_increment_combined_counter (&policer_counters[col], vm->thread_index, policer_index, 1, len);
  if (PREDICT_TRUE (act == QOS_ACTION_MARK_AND_TRANSMIT))
    policer_mark (b, pol->mark_dscp[col]);

  return act;
}

#endif // __POLICE_INLINES_H__
