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
/*
 * ip/ip4_source_check.c: IP v4 check source address (unicast RPF check)
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

#ifndef __URPF_DP_H__
#define __URPF_DP_H__

#include <vnet/fib/ip4_fib.h>
#include <vnet/fib/ip6_fib.h>
#include <vnet/fib/fib_urpf_list.h>
#include <vnet/dpo/load_balance.h>

#include <urpf/urpf.h>

/**
 * @file
 * @brief Unicast Reverse Path forwarding.
 *
 * This file contains the interface unicast source check.
 */
typedef struct
{
  index_t urpf;
} urpf_trace_t;

static u8 *
format_urpf_trace (u8 * s, va_list * va)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*va, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*va, vlib_node_t *);
  urpf_trace_t *t = va_arg (*va, urpf_trace_t *);

  s = format (s, "uRPF:%d", t->urpf);

  return s;
}

#define foreach_urpf_error                 \
  _(DROP, "uRPF Drop")                     \

typedef enum urpf_error_t_
{
#define _(a,b) URPF_ERROR_##a,
  foreach_urpf_error
#undef _
    URPF_N_ERROR,
} urpf_error_t;

typedef enum
{
  URPF_NEXT_DROP,
  URPF_N_NEXT,
} urpf_next_t;

static_always_inline uword
urpf_inline (vlib_main_t * vm,
	     vlib_node_runtime_t * node,
	     vlib_frame_t * frame,
	     ip_address_family_t af, vlib_dir_t dir, urpf_mode_t mode)
{
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;
  u16 nexts[VLIB_FRAME_SIZE], *next;
  u32 n_left, *from;

  from = vlib_frame_vector_args (frame);
  n_left = frame->n_vectors;
  b = bufs;
  next = nexts;

  vlib_get_buffers (vm, from, bufs, n_left);

  while (n_left >= 4)
    {
      u32 pass0, lb_index0, pass1, lb_index1;
      const load_balance_t *lb0, *lb1;
      u32 fib_index0, fib_index1;
      const u8 *h0, *h1;

      /* Prefetch next iteration. */
      {
	vlib_prefetch_buffer_header (b[2], LOAD);
	vlib_prefetch_buffer_header (b[3], LOAD);
	vlib_prefetch_buffer_data (b[2], LOAD);
	vlib_prefetch_buffer_data (b[3], LOAD);
      }

      h0 = (u8 *) vlib_buffer_get_current (b[0]);
      h1 = (u8 *) vlib_buffer_get_current (b[1]);

      if (VLIB_TX == dir)
	{
	  h0 += vnet_buffer (b[0])->ip.save_rewrite_length;
	  h1 += vnet_buffer (b[1])->ip.save_rewrite_length;
	}

      if (AF_IP4 == af)
	{
	  const ip4_header_t *ip0, *ip1;

	  ip0 = (ip4_header_t *) h0;
	  ip1 = (ip4_header_t *) h1;

	  fib_index0 = ip4_main.fib_index_by_sw_if_index
	    [vnet_buffer (b[0])->sw_if_index[dir]];
	  fib_index1 = ip4_main.fib_index_by_sw_if_index
	    [vnet_buffer (b[1])->sw_if_index[dir]];

	  ip4_fib_forwarding_lookup_x2 (fib_index0,
					fib_index1,
					&ip0->src_address,
					&ip1->src_address,
					&lb_index0, &lb_index1);
	  /* Pass multicast. */
	  pass0 = (ip4_address_is_multicast (&ip0->src_address) ||
		   ip4_address_is_global_broadcast (&ip0->src_address));
	  pass1 = (ip4_address_is_multicast (&ip1->src_address) ||
		   ip4_address_is_global_broadcast (&ip1->src_address));
	}
      else
	{
	  const ip6_header_t *ip0, *ip1;

	  fib_index0 = ip6_main.fib_index_by_sw_if_index
	    [vnet_buffer (b[0])->sw_if_index[dir]];
	  fib_index1 = ip6_main.fib_index_by_sw_if_index
	    [vnet_buffer (b[1])->sw_if_index[dir]];

	  ip0 = (ip6_header_t *) h0;
	  ip1 = (ip6_header_t *) h1;

	  lb_index0 = ip6_fib_table_fwding_lookup (fib_index0,
						   &ip0->src_address);
	  lb_index1 = ip6_fib_table_fwding_lookup (fib_index1,
						   &ip1->src_address);
	  pass0 = (ip6_address_is_multicast (&ip0->src_address) |
		   ip6_address_is_link_local_unicast (&ip0->src_address));
	  pass1 = (ip6_address_is_multicast (&ip1->src_address) |
		   ip6_address_is_link_local_unicast (&ip0->src_address));
	}

      lb0 = load_balance_get (lb_index0);
      lb1 = load_balance_get (lb_index1);

      if (URPF_MODE_STRICT == mode)
	{
	  /* for RX the check is: would this source adddress be forwarded
	   * out of the interface on which it was recieved, if yes allow.
	   * For TX it's; would this source address be forwarded out of the
	   * interface through which it is being sent, if yes drop.
	   */
	  int res0, res1;

	  res0 = fib_urpf_check (lb0->lb_urpf,
				 vnet_buffer (b[0])->sw_if_index[dir]);
	  res1 = fib_urpf_check (lb1->lb_urpf,
				 vnet_buffer (b[1])->sw_if_index[dir]);

	  if (VLIB_RX == dir)
	    {
	      pass0 |= res0;
	      pass1 |= res1;
	    }
	  else
	    {
	      pass0 |= !res0 && fib_urpf_check_size (lb0->lb_urpf);
	      pass1 |= !res1 && fib_urpf_check_size (lb1->lb_urpf);

	      /* allow locally generated */
	      pass0 |= b[0]->flags & VNET_BUFFER_F_LOCALLY_ORIGINATED;
	      pass1 |= b[1]->flags & VNET_BUFFER_F_LOCALLY_ORIGINATED;
	    }
	}
      else
	{
	  pass0 |= fib_urpf_check_size (lb0->lb_urpf);
	  pass1 |= fib_urpf_check_size (lb1->lb_urpf);
	}

      if (PREDICT_TRUE (pass0))
	vnet_feature_next_u16 (&next[0], b[0]);
      else
	{
	  next[0] = URPF_NEXT_DROP;
	  b[0]->error = node->errors[URPF_ERROR_DROP];
	}
      if (PREDICT_TRUE (pass1))
	vnet_feature_next_u16 (&next[1], b[1]);
      else
	{
	  next[1] = URPF_NEXT_DROP;
	  b[1]->error = node->errors[URPF_ERROR_DROP];
	}

      if (b[0]->flags & VLIB_BUFFER_IS_TRACED)
	{
	  urpf_trace_t *t;

	  t = vlib_add_trace (vm, node, b[0], sizeof (*t));
	  t->urpf = lb0->lb_urpf;
	}
      if (b[1]->flags & VLIB_BUFFER_IS_TRACED)
	{
	  urpf_trace_t *t;

	  t = vlib_add_trace (vm, node, b[1], sizeof (*t));
	  t->urpf = lb1->lb_urpf;
	}

      b += 2;
      next += 2;
      n_left -= 2;
    }

  while (n_left)
    {
      u32 pass0, lb_index0, fib_index0;
      const load_balance_t *lb0;
      const u8 *h0;

      h0 = (u8 *) vlib_buffer_get_current (b[0]);

      if (VLIB_TX == dir)
	h0 += vnet_buffer (b[0])->ip.save_rewrite_length;

      if (AF_IP4 == af)
	{
	  const ip4_header_t *ip0;

	  fib_index0 = ip4_main.fib_index_by_sw_if_index
	    [vnet_buffer (b[0])->sw_if_index[dir]];
	  ip0 = (ip4_header_t *) h0;

	  lb_index0 = ip4_fib_forwarding_lookup (fib_index0,
						 &ip0->src_address);

	  /* Pass multicast. */
	  pass0 = (ip4_address_is_multicast (&ip0->src_address) ||
		   ip4_address_is_global_broadcast (&ip0->src_address));
	}
      else
	{
	  const ip6_header_t *ip0;

	  ip0 = (ip6_header_t *) h0;
	  fib_index0 = ip6_main.fib_index_by_sw_if_index
	    [vnet_buffer (b[0])->sw_if_index[dir]];

	  lb_index0 = ip6_fib_table_fwding_lookup (fib_index0,
						   &ip0->src_address);
	  pass0 = (ip6_address_is_multicast (&ip0->src_address) |
		   ip6_address_is_link_local_unicast (&ip0->src_address));
	}

      lb0 = load_balance_get (lb_index0);

      if (URPF_MODE_STRICT == mode)
	{
	  int res0;

	  res0 = fib_urpf_check (lb0->lb_urpf,
				 vnet_buffer (b[0])->sw_if_index[dir]);
	  if (VLIB_RX == dir)
	    pass0 |= res0;
	  else
	    {
	      pass0 |= !res0 && fib_urpf_check_size (lb0->lb_urpf);
	      pass0 |= b[0]->flags & VNET_BUFFER_F_LOCALLY_ORIGINATED;
	    }
	}
      else
	pass0 |= fib_urpf_check_size (lb0->lb_urpf);

      if (PREDICT_TRUE (pass0))
	vnet_feature_next_u16 (&next[0], b[0]);
      else
	{
	  next[0] = URPF_NEXT_DROP;
	  b[0]->error = node->errors[URPF_ERROR_DROP];
	}

      if (b[0]->flags & VLIB_BUFFER_IS_TRACED)
	{
	  urpf_trace_t *t;

	  t = vlib_add_trace (vm, node, b[0], sizeof (*t));
	  t->urpf = lb0->lb_urpf;
	}
      b++;
      next++;
      n_left--;
    }

  vlib_buffer_enqueue_to_next (vm, node, from, nexts, frame->n_vectors);

  return frame->n_vectors;
}

#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
