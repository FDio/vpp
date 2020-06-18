/*
 * Copyright (c) 2015-2019 Cisco and/or its affiliates.
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
 * ip/ip4_forward.h: IP v4 forwarding
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

#ifndef __included_ip4_forward_h__
#define __included_ip4_forward_h__

#include <vppinfra/cache.h>
#include <vnet/fib/ip4_fib.h>
#include <vnet/dpo/load_balance_map.h>

/**
 * @file
 * @brief IPv4 Forwarding.
 *
 * This file contains the source code for IPv4 forwarding.
 */

static_always_inline void
mtrie_lookup_step (ip4_fib_mtrie_t ** mtrie, ip4_fib_mtrie_leaf_t * leaf,
		   ip4_address_t * da, u32 n_left, int st)
{
  while (n_left >= 4)
    {
      if (st > 1)
	{
	  leaf[0] = ip4_fib_mtrie_lookup_step (mtrie[0], leaf[0], da + 0, st);
	  leaf[1] = ip4_fib_mtrie_lookup_step (mtrie[1], leaf[1], da + 1, st);
	  leaf[2] = ip4_fib_mtrie_lookup_step (mtrie[2], leaf[2], da + 2, st);
	  leaf[3] = ip4_fib_mtrie_lookup_step (mtrie[3], leaf[3], da + 3, st);
	}
      else
	{
	  leaf[0] = ip4_fib_mtrie_lookup_step_one (mtrie[0], da + 0);
	  leaf[1] = ip4_fib_mtrie_lookup_step_one (mtrie[1], da + 1);
	  leaf[2] = ip4_fib_mtrie_lookup_step_one (mtrie[2], da + 2);
	  leaf[3] = ip4_fib_mtrie_lookup_step_one (mtrie[3], da + 3);
	}
      da += 4;
      leaf += 4;
      mtrie += 4;
      n_left -= 4;
    }
  while (n_left)
    {
      if (st > 1)
	leaf[0] = ip4_fib_mtrie_lookup_step (mtrie[0], leaf[0], da + 0, st);
      else
	leaf[0] = ip4_fib_mtrie_lookup_step_one (mtrie[0], da + 0);
      da += 1;
      leaf += 1;
      mtrie += 1;
      n_left -= 1;
    }
}

static_always_inline const dpo_id_t *
get_dpo (u32 lb_index, vlib_buffer_t * b)
{
  load_balance_t *lb = load_balance_get (lb_index);
  ip4_header_t *ip;
  u32 hash;

  if (PREDICT_TRUE (lb->lb_n_buckets == 1))
    return load_balance_get_bucket_i (lb, 0);;

  ip = vlib_buffer_get_current (b);
  hash = ip4_compute_flow_hash (ip, lb->lb_hash_config);
  vnet_buffer (b)->ip.flow_hash = hash;
  hash &= lb->lb_n_buckets_minus_1;
  return load_balance_get_fwd_bucket (lb, hash);
}

always_inline uword
ip4_lookup_inline (vlib_main_t * vm,
		   vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  ip4_main_t *im = &ip4_main;
  vlib_combined_counter_main_t *cm = &load_balance_main.lbm_to_counters;
  u32 n_left, *from;
  u32 thread_index = vm->thread_index;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE];
  vlib_buffer_t **b = bufs;
  u16 nexts[VLIB_FRAME_SIZE], *next = nexts;
  ip4_address_t dst_addrs[VLIB_FRAME_SIZE], *da = dst_addrs;
  ip4_fib_mtrie_t *mtries[VLIB_FRAME_SIZE], **mtrie = mtries;
  ip4_fib_mtrie_leaf_t leafs[VLIB_FRAME_SIZE];
  u32 lb_indices[VLIB_FRAME_SIZE];
  u32 *lb_index = lb_indices;

  from = vlib_frame_vector_args (frame);
  n_left = frame->n_vectors;
  vlib_get_buffers (vm, from, bufs, n_left);

  while (n_left >= 4)
    {
      ip4_header_t *ip;
      if (n_left >= 8)
	{
	  vlib_prefetch_buffer_header (b[4], LOAD);
	  vlib_prefetch_buffer_header (b[5], LOAD);
	  vlib_prefetch_buffer_header (b[6], LOAD);
	  vlib_prefetch_buffer_header (b[7], LOAD);

	  CLIB_PREFETCH (b[4]->data, sizeof (ip[0]), LOAD);
	  CLIB_PREFETCH (b[5]->data, sizeof (ip[0]), LOAD);
	  CLIB_PREFETCH (b[6]->data, sizeof (ip[0]), LOAD);
	  CLIB_PREFETCH (b[7]->data, sizeof (ip[0]), LOAD);
	}

      ip = vlib_buffer_get_current (b[0]);
      da[0] = ip->dst_address;
      ip = vlib_buffer_get_current (b[1]);
      da[1] = ip->dst_address;
      ip = vlib_buffer_get_current (b[2]);
      da[2] = ip->dst_address;
      ip = vlib_buffer_get_current (b[3]);
      da[3] = ip->dst_address;

      ip_lookup_set_buffer_fib_index (im->fib_index_by_sw_if_index, b[0]);
      ip_lookup_set_buffer_fib_index (im->fib_index_by_sw_if_index, b[1]);
      ip_lookup_set_buffer_fib_index (im->fib_index_by_sw_if_index, b[2]);
      ip_lookup_set_buffer_fib_index (im->fib_index_by_sw_if_index, b[3]);

      mtrie[0] = &ip4_fib_get (vnet_buffer (b[0])->ip.fib_index)->mtrie;
      mtrie[1] = &ip4_fib_get (vnet_buffer (b[1])->ip.fib_index)->mtrie;
      mtrie[2] = &ip4_fib_get (vnet_buffer (b[2])->ip.fib_index)->mtrie;
      mtrie[3] = &ip4_fib_get (vnet_buffer (b[3])->ip.fib_index)->mtrie;

      vnet_buffer (b[0])->ip.flow_hash = 0;
      vnet_buffer (b[1])->ip.flow_hash = 0;
      vnet_buffer (b[2])->ip.flow_hash = 0;
      vnet_buffer (b[3])->ip.flow_hash = 0;

      b += 4;
      da += 4;
      mtrie += 4;
      n_left -= 4;
    }
  while (n_left)
    {
      ip4_header_t *ip;
      ip = vlib_buffer_get_current (b[0]);
      da[0].as_u32 = ip->dst_address.as_u32;
      ip_lookup_set_buffer_fib_index (im->fib_index_by_sw_if_index, b[0]);
      mtrie[0] = &ip4_fib_get (vnet_buffer (b[0])->ip.fib_index)->mtrie;
      vnet_buffer (b[0])->ip.flow_hash = 0;

      b += 1;
      da += 1;
      mtrie += 1;
      n_left -= 1;
    }

  n_left = frame->n_vectors;
  mtrie_lookup_step (mtries, leafs, dst_addrs, n_left, 1);
  mtrie_lookup_step (mtries, leafs, dst_addrs, n_left, 2);
  mtrie_lookup_step (mtries, leafs, dst_addrs, n_left, 3);

  for (int i = 0; i < frame->n_vectors; i++)
    {
      load_balance_t *lb;
      lb_indices[i] = ip4_fib_mtrie_leaf_get_adj_index (leafs[i]);
      lb = load_balance_get (lb_indices[i]);
      ASSERT (lb_indices[i]);
      ASSERT (lb->lb_n_buckets > 0);
      ASSERT (is_pow2 (lb->lb_n_buckets));
    }

  b = bufs;
  n_left = frame->n_vectors;
  lb_index = lb_indices;

  while (n_left >= 4)
    {
      const dpo_id_t *dpo0, *dpo1, *dpo2, *dpo3;

      /* Prefetch next iteration. */
      if (n_left >= 8)
	{
	  vlib_prefetch_buffer_header (b[4], LOAD);
	  vlib_prefetch_buffer_header (b[5], LOAD);
	  vlib_prefetch_buffer_header (b[6], LOAD);
	  vlib_prefetch_buffer_header (b[7], LOAD);
	}

      dpo0 = get_dpo (lb_index[0], b[0]);
      dpo1 = get_dpo (lb_index[1], b[1]);
      dpo2 = get_dpo (lb_index[2], b[2]);
      dpo3 = get_dpo (lb_index[3], b[3]);

      next[0] = dpo0->dpoi_next_node;
      vnet_buffer (b[0])->ip.adj_index[VLIB_TX] = dpo0->dpoi_index;
      next[1] = dpo1->dpoi_next_node;
      vnet_buffer (b[1])->ip.adj_index[VLIB_TX] = dpo1->dpoi_index;
      next[2] = dpo2->dpoi_next_node;
      vnet_buffer (b[2])->ip.adj_index[VLIB_TX] = dpo2->dpoi_index;
      next[3] = dpo3->dpoi_next_node;
      vnet_buffer (b[3])->ip.adj_index[VLIB_TX] = dpo3->dpoi_index;

      vlib_increment_combined_counter
	(cm, thread_index, lb_index[0], 1,
	 vlib_buffer_length_in_chain (vm, b[0]));
      vlib_increment_combined_counter
	(cm, thread_index, lb_index[1], 1,
	 vlib_buffer_length_in_chain (vm, b[1]));
      vlib_increment_combined_counter
	(cm, thread_index, lb_index[2], 1,
	 vlib_buffer_length_in_chain (vm, b[2]));
      vlib_increment_combined_counter
	(cm, thread_index, lb_index[3], 1,
	 vlib_buffer_length_in_chain (vm, b[3]));

      b += 4;
      next += 4;
      lb_index += 4;
      n_left -= 4;
    }
  while (n_left > 0)
    {
      const dpo_id_t *dpo0;
      dpo0 = get_dpo (lb_index[0], b[0]);
      next[0] = dpo0->dpoi_next_node;
      vnet_buffer (b[0])->ip.adj_index[VLIB_TX] = dpo0->dpoi_index;
      vlib_increment_combined_counter
	(cm, thread_index, lb_index[0], 1,
	 vlib_buffer_length_in_chain (vm, b[0]));

      b += 1;
      next += 1;
      lb_index += 1;
      n_left -= 1;
    }

  vlib_buffer_enqueue_to_next (vm, node, from, nexts, frame->n_vectors);

  if (node->flags & VLIB_NODE_FLAG_TRACE)
    ip4_forward_next_trace (vm, node, frame, VLIB_TX);

  return frame->n_vectors;
}

#endif /* __included_ip4_forward_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
