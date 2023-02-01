/*
 * Copyright (c) 2023 Cisco and/or its affiliates.
 * Copyright (c) 2023 Graphiant.
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
/*
 * ip/ip_input.h: Common IP input node
 *
 * Copyright (c) 2008 Eliot Dresselhaus
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 *  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 *  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 *  NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 *  LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 *  OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 *  WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#ifndef __IP_INPUT_H__
#define __IP_INPUT_H__

#include <vnet/ip/ip_input_types.h>
#include <vnet/ip/ip4_input.h>
#include <vnet/ip/ip6_input.h>

static_always_inline void
ip_input_check_sw_if_index (vlib_main_t *vm, vlib_simple_counter_main_t *cm,
			    ip_address_family_t af, u32 sw_if_index,
			    u32 *last_sw_if_index, u32 *cnt, int *arc_enabled)
{
  ip_lookup_main_t *lm =
    (AF_IP4 == af ? &ip4_main.lookup_main : &ip6_main.lookup_main);
  u32 thread_index;
  if (*last_sw_if_index == sw_if_index)
    {
      (*cnt)++;
      return;
    }

  thread_index = vm->thread_index;
  if (*cnt)
    vlib_increment_simple_counter (cm, thread_index, *last_sw_if_index, *cnt);
  *cnt = 1;
  *last_sw_if_index = sw_if_index;

  if (vnet_have_features (lm->ucast_feature_arc_index, sw_if_index) ||
      vnet_have_features (lm->mcast_feature_arc_index, sw_if_index))
    *arc_enabled = 1;
  else
    *arc_enabled = 0;
}

static_always_inline u32
ip_input_set_next (u32 sw_if_index, ip_address_family_t af, vlib_buffer_t *b,
		   int arc_enabled)
{
  ip_lookup_main_t *lm =
    (AF_IP4 == af ? &ip4_main.lookup_main : &ip6_main.lookup_main);
  u32 next;
  u8 arc;

  if (AF_IP4 == af)
    {
      const ip4_header_t *ip = vlib_buffer_get_current (b);

      if (PREDICT_FALSE (ip4_address_is_multicast (&ip->dst_address)))
	{
	  next = IP_INPUT_NEXT_LOOKUP_MULTICAST;
	  arc = lm->mcast_feature_arc_index;
	}
      else
	{
	  next = IP_INPUT_NEXT_LOOKUP;
	  arc = lm->ucast_feature_arc_index;
	}
    }
  else
    {
      const ip6_header_t *ip = vlib_buffer_get_current (b);

      if (PREDICT_FALSE (ip6_address_is_multicast (&ip->dst_address)))
	{
	  next = IP_INPUT_NEXT_LOOKUP_MULTICAST;
	  arc = lm->mcast_feature_arc_index;
	}
      else
	{
	  next = IP_INPUT_NEXT_LOOKUP;
	  arc = lm->ucast_feature_arc_index;
	}
    }

  if (arc_enabled)
    vnet_feature_arc_start (arc, sw_if_index, &next, b);

  return next;
}

/* Validate IP v4 packets and pass them either to forwarding code
   or drop/punt exception packets. */
always_inline uword
ip_input_inline (vlib_main_t *vm, vlib_node_runtime_t *node,
		 vlib_frame_t *frame, vlib_node_runtime_t *error_node,
		 vnet_interface_counter_type_t counter_type,
		 ip_address_family_t af, u32 trace_size,
		 ip_input_flags_t flags)
{
  vnet_main_t *vnm = vnet_get_main ();
  u32 n_left_from, *from;
  u32 thread_index = vm->thread_index;
  vlib_simple_counter_main_t *cm;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;
  u16 nexts[VLIB_FRAME_SIZE], *next;
  u32 sw_if_index[4];
  u32 last_sw_if_index = ~0;
  u32 cnt = 0;
  int arc_enabled = 0;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;

  cm = vec_elt_at_index (vnm->interface_main.sw_if_counters, counter_type);

  if (node->flags & VLIB_NODE_FLAG_TRACE)
    vlib_trace_frame_buffers_only (vm, node, from, frame->n_vectors,
				   /* stride */ 1, trace_size);

  vlib_get_buffers (vm, from, bufs, n_left_from);
  b = bufs;
  next = nexts;

#if (CLIB_N_PREFETCHES >= 8)
  while (n_left_from >= 4)
    {
      u32 x = 0;

      /* Prefetch next iteration. */
      if (n_left_from >= 12)
	{
	  vlib_prefetch_buffer_header (b[8], LOAD);
	  vlib_prefetch_buffer_header (b[9], LOAD);
	  vlib_prefetch_buffer_header (b[10], LOAD);
	  vlib_prefetch_buffer_header (b[11], LOAD);

	  vlib_prefetch_buffer_data (b[4], LOAD);
	  vlib_prefetch_buffer_data (b[5], LOAD);
	  vlib_prefetch_buffer_data (b[6], LOAD);
	  vlib_prefetch_buffer_data (b[7], LOAD);
	}

      vnet_buffer (b[0])->ip.adj_index[VLIB_RX] = ~0;
      vnet_buffer (b[1])->ip.adj_index[VLIB_RX] = ~0;
      vnet_buffer (b[2])->ip.adj_index[VLIB_RX] = ~0;
      vnet_buffer (b[3])->ip.adj_index[VLIB_RX] = ~0;

      sw_if_index[0] = vnet_buffer (b[0])->sw_if_index[VLIB_RX];
      sw_if_index[1] = vnet_buffer (b[1])->sw_if_index[VLIB_RX];
      sw_if_index[2] = vnet_buffer (b[2])->sw_if_index[VLIB_RX];
      sw_if_index[3] = vnet_buffer (b[3])->sw_if_index[VLIB_RX];

      x |= sw_if_index[0] ^ last_sw_if_index;
      x |= sw_if_index[1] ^ last_sw_if_index;
      x |= sw_if_index[2] ^ last_sw_if_index;
      x |= sw_if_index[3] ^ last_sw_if_index;

      if (PREDICT_TRUE (x == 0))
	{
	  /* we deal with 4 more packets sharing the same sw_if_index
	     with the previous one, so we can optimize */
	  cnt += 4;
	  if (arc_enabled)
	    {
	      next[0] = ip_input_set_next (sw_if_index[0], af, b[0], 1);
	      next[1] = ip_input_set_next (sw_if_index[1], af, b[1], 1);
	      next[2] = ip_input_set_next (sw_if_index[2], af, b[2], 1);
	      next[3] = ip_input_set_next (sw_if_index[3], af, b[3], 1);
	    }
	  else
	    {
	      next[0] = ip_input_set_next (sw_if_index[0], af, b[0], 0);
	      next[1] = ip_input_set_next (sw_if_index[1], af, b[1], 0);
	      next[2] = ip_input_set_next (sw_if_index[2], af, b[2], 0);
	      next[3] = ip_input_set_next (sw_if_index[3], af, b[3], 0);
	    }
	}
      else
	{
	  ip_input_check_sw_if_index (vm, cm, af, sw_if_index[0],
				      &last_sw_if_index, &cnt, &arc_enabled);
	  ip_input_check_sw_if_index (vm, cm, af, sw_if_index[1],
				      &last_sw_if_index, &cnt, &arc_enabled);
	  ip_input_check_sw_if_index (vm, cm, af, sw_if_index[2],
				      &last_sw_if_index, &cnt, &arc_enabled);
	  ip_input_check_sw_if_index (vm, cm, af, sw_if_index[3],
				      &last_sw_if_index, &cnt, &arc_enabled);

	  next[0] = ip_input_set_next (sw_if_index[0], af, b[0], 1);
	  next[1] = ip_input_set_next (sw_if_index[1], af, b[1], 1);
	  next[2] = ip_input_set_next (sw_if_index[2], af, b[2], 1);
	  next[3] = ip_input_set_next (sw_if_index[3], af, b[3], 1);
	}

      if (AF_IP4 == af)
	ip4_input_check_x4 (vm, error_node, b, next, flags);
      else
	ip6_input_check_x4 (vm, error_node, b, next);

      /* next */
      b += 4;
      next += 4;
      n_left_from -= 4;
    }
#elif (CLIB_N_PREFETCHES >= 4)
  while (n_left_from >= 2)
    {
      u32 x = 0;

      /* Prefetch next iteration. */
      if (n_left_from >= 6)
	{
	  vlib_prefetch_buffer_header (b[4], LOAD);
	  vlib_prefetch_buffer_header (b[5], LOAD);

	  vlib_prefetch_buffer_data (b[2], LOAD);
	  vlib_prefetch_buffer_data (b[3], LOAD);
	}

      vnet_buffer (b[0])->ip.adj_index[VLIB_RX] = ~0;
      vnet_buffer (b[1])->ip.adj_index[VLIB_RX] = ~0;

      sw_if_index[0] = vnet_buffer (b[0])->sw_if_index[VLIB_RX];
      sw_if_index[1] = vnet_buffer (b[1])->sw_if_index[VLIB_RX];

      x |= sw_if_index[0] ^ last_sw_if_index;
      x |= sw_if_index[1] ^ last_sw_if_index;

      if (PREDICT_TRUE (x == 0))
	{
	  /* we deal with 2 more packets sharing the same sw_if_index
	     with the previous one, so we can optimize */
	  cnt += 2;
	  if (arc_enabled)
	    {
	      next[0] = ip_input_set_next (sw_if_index[0], af, b[0], 1);
	      next[1] = ip_input_set_next (sw_if_index[1], af, b[1], 1);
	    }
	  else
	    {
	      next[0] = ip_input_set_next (sw_if_index[0], af, b[0], 0);
	      next[1] = ip_input_set_next (sw_if_index[1], af, b[1], 0);
	    }
	}
      else
	{
	  ip_input_check_sw_if_index (vm, cm, af, sw_if_index[0],
				      &last_sw_if_index, &cnt, &arc_enabled);
	  ip_input_check_sw_if_index (vm, cm, af, sw_if_index[1],
				      &last_sw_if_index, &cnt, &arc_enabled);

	  next[0] = ip_input_set_next (sw_if_index[0], af, b[0], 1);
	  next[1] = ip_input_set_next (sw_if_index[1], af, b[1], 1);
	}

      if (AF_IP4 == af)
	ip4_input_check_x2 (vm, error_node, b, next, flags);
      else
	ip6_input_check_x2 (vm, error_node, b, next);

      /* next */
      b += 2;
      next += 2;
      n_left_from -= 2;
    }
#endif

  while (n_left_from)
    {
      vnet_buffer (b[0])->ip.adj_index[VLIB_RX] = ~0;
      sw_if_index[0] = vnet_buffer (b[0])->sw_if_index[VLIB_RX];
      ip_input_check_sw_if_index (vm, cm, af, sw_if_index[0],
				  &last_sw_if_index, &cnt, &arc_enabled);
      next[0] = ip_input_set_next (sw_if_index[0], af, b[0], arc_enabled);

      if (AF_IP4 == af)
	ip4_input_check_x1 (vm, error_node, b, next, flags);
      else
	ip6_input_check_x1 (vm, error_node, b, next);

      /* next */
      b += 1;
      next += 1;
      n_left_from -= 1;
    }

  vlib_increment_simple_counter (cm, thread_index, last_sw_if_index, cnt);
  vlib_buffer_enqueue_to_next (vm, node, from, nexts, frame->n_vectors);
  return frame->n_vectors;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

#endif
