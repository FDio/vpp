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

static_always_inline int
eight_leaf_ptrs_are_not_equal (u32 ** leafp)
{
#ifdef CLIB_HAVE_VEC256
  u64x4 v0, v1, b;

  v0 = u64x4_load_unaligned (leafp);
  v1 = u64x4_load_unaligned (leafp + 4);
  b = u64x4_broadcast (v1);

#ifdef __AVX512F__
#define u64x4_ternary_logic(a, b, c, d) \
  (u64x4) _mm256_ternarylogic_epi32 ((__m256i) a, (__m256i) b, (__m256i) c, d)
  b = u64x4_ternary_logic (b, v0, v1, 0x7e);
#else
  b = (v0 ^ b) | (v1 ^ b);
#endif

  if (u64x4_is_all_zero (b))
    return 0;
  return 1;
#endif
  return 1;
}

static_always_inline void
leaf_pointers_to_lb_indices (ip4_fib_mtrie_leaf_t ** leafp,
			     ip4_fib_mtrie_leaf_t * leaf, int n_left)
{
#ifdef CLIB_HAVE_VEC256
  while (n_left >= 0)
    {
      clib_prefetch_load (leafp[8]);

      if (eight_leaf_ptrs_are_not_equal (leafp + 8))
	{
	  clib_prefetch_load (leafp[9]);
	  clib_prefetch_load (leafp[10]);
	  clib_prefetch_load (leafp[11]);
	  clib_prefetch_load (leafp[12]);
	  clib_prefetch_load (leafp[13]);
	  clib_prefetch_load (leafp[14]);
	  clib_prefetch_load (leafp[15]);
	}

      if (eight_leaf_ptrs_are_not_equal (leafp))
	{
	  u32x8 r;
	  r = u32x8_gather (leafp[0], leafp[1], leafp[2], leafp[3],
			    leafp[4], leafp[5], leafp[6], leafp[7]);
	  u32x8_store_unaligned (r >> 1, leaf);
	}
      else
	u32x8_store_unaligned (u32x8_splat ((*leafp[0]) >> 1), leaf);

      leaf += 8;
      leafp += 8;
      n_left -= 8;
    }
#else
  while (n_left >= 8)
    {
      clib_prefetch_load (leafp[8]);

      clib_prefetch_load (leafp[9]);
      clib_prefetch_load (leafp[10]);
      clib_prefetch_load (leafp[11]);
      clib_prefetch_load (leafp[12]);
      clib_prefetch_load (leafp[13]);
      clib_prefetch_load (leafp[14]);
      clib_prefetch_load (leafp[15]);

      leaf[0] = (*leafp[0]) >> 1;
      leaf[1] = (*leafp[1]) >> 1;
      leaf[2] = (*leafp[2]) >> 1;
      leaf[3] = (*leafp[3]) >> 1;
      leaf[4] = (*leafp[4]) >> 1;
      leaf[5] = (*leafp[5]) >> 1;
      leaf[6] = (*leafp[6]) >> 1;
      leaf[7] = (*leafp[7]) >> 1;

      leaf += 8;
      leafp += 8;
      n_left -= 8;
    }

  while (n_left)
    {
      leaf[0] = (*leafp[0]) >> 1;
      leaf += 1;
      leafp += 1;
      n_left -= 1;
    }
#endif
}

static_always_inline void __clib_unused
get_next_leaf_ptr (ip4_fib_mtrie_8_ply_t * ply, ip4_fib_mtrie_leaf_t ** leafp,
		   u8 addr_byte)
{
  int lsz = sizeof (ip4_fib_mtrie_leaf_t);
  int off = STRUCT_OFFSET_OF (ip4_fib_mtrie_8_ply_t, leaves);
  ip4_fib_mtrie_leaf_t leaf = *leafp[0];

  if (ip4_fib_mtrie_leaf_is_terminal (leaf))
    return;

  leafp[0] = (void *) (ply + (leaf >> 1)) + off + addr_byte * lsz;
}

static_always_inline void
ip4_lookup_step (u32 ** leafp, u8 * bp, int n_left)
{
  ip4_fib_mtrie_8_ply_t *ply = ip4_ply_pool;

#ifdef CLIB_HAVE_VEC256
  u64x4 ply_pool4 = u64x4_splat (pointer_to_uword (ply));
  u64x4 sizeof_leaf4 = u64x4_splat (sizeof (ip4_fib_mtrie_leaf_t));
  u64x4 terminal_bit_mask = u64x4_splat (1);
  u64x4 sizeof_ply8 = u64x4_splat (sizeof (ip4_fib_mtrie_8_ply_t));
  u16x8 octet_mask = u16x8_splat (0xff);

  STATIC_ASSERT_OFFSET_OF (ip4_fib_mtrie_8_ply_t, leaves, 0);
  while (n_left >= 8)
    {
      ip4_fib_mtrie_leaf_t leaf;
      u64x4 p0, p1, m0, m1;
      u8x32 d;

      clib_prefetch_load (leafp[8]);
      if (eight_leaf_ptrs_are_not_equal (leafp + 8))
	{
	  clib_prefetch_load (leafp[9]);
	  clib_prefetch_load (leafp[10]);
	  clib_prefetch_load (leafp[11]);
	  clib_prefetch_load (leafp[12]);
	  clib_prefetch_load (leafp[13]);
	  clib_prefetch_load (leafp[14]);
	  clib_prefetch_load (leafp[15]);
	}

    last:
      if (eight_leaf_ptrs_are_not_equal (leafp))
	{
	  p0 = u32x4_extend_to_u64x4 (u32x4_gather (leafp[0], leafp[1],
						    leafp[2], leafp[3]));

	  p1 = u32x4_extend_to_u64x4 (u32x4_gather (leafp[4], leafp[5],
						    leafp[6], leafp[7]));

	  m0 = (p0 & terminal_bit_mask) != terminal_bit_mask;
	  p0 >>= 1;
	  p0 *= sizeof_ply8;	/* ply offset */
	  p0 += ply_pool4;	/* ply addr */

	  m1 = (p1 & terminal_bit_mask) != terminal_bit_mask;
	  p1 >>= 1;
	  p1 *= sizeof_ply8;	/* ply offset */
	  p1 += ply_pool4;	/* ply addr */

	  /* leaf offset inside the ply */
	  u16x8 x = *(u16x8u *) bp & octet_mask;
	  p0 += u16x8_extend_to_u64x4 (x) * sizeof_leaf4;
	  x = (u16x8) u8x16_align_right (x, x, 8);
	  p1 += u16x8_extend_to_u64x4 (x) * sizeof_leaf4;

	  /* store next leaf pointer */
	  d = u8x32_load_unaligned (leafp);
	  d = u8x32_blend (d, (u8x32) p0, (u8x32) m0);
	  u8x32_store_unaligned (d, leafp);

	  d = u8x32_load_unaligned (leafp + 4);
	  d = u8x32_blend (d, (u8x32) p1, (u8x32) m1);
	  u8x32_store_unaligned (d, leafp + 4);
	}
      else if (!ip4_fib_mtrie_leaf_is_terminal (leaf = *leafp[0]))
	{
	  /* all 8 leaf pointers are equal so we are dealing with 4
	   * identical leafs which makes our life simpler */

	  p0 = u64x4_splat (leaf);
	  p0 >>= 1;		/* remove terminal bit */
	  p0 *= sizeof_ply8;	/* ply offset */
	  p0 += ply_pool4;	/* ply addr */

	  p1 = p0;

	  /* leaf offset inside the ply */
	  u16x8 x = u16x8_load_unaligned (bp) & octet_mask;
	  p0 += u16x8_extend_to_u64x4 (x) * sizeof_leaf4;
	  x = (u16x8) u8x16_align_right (x, x, 8);
	  p1 += u16x8_extend_to_u64x4 (x) * sizeof_leaf4;

	  /* store next leaf pointer */
	  u64x4_store_unaligned (p0, leafp);
	  u64x4_store_unaligned (p1, leafp + 4);
	}

      bp += 16;
      leafp += 8;
      n_left -= 8;
    }
  if (n_left > 0)
    goto last;
#else
  while (n_left >= 8)
    {
      clib_prefetch_load (leafp[8]);
      clib_prefetch_load (leafp[9]);
      clib_prefetch_load (leafp[10]);
      clib_prefetch_load (leafp[11]);

      get_next_leaf_ptr (ply, leafp + 0, bp[0]);
      get_next_leaf_ptr (ply, leafp + 1, bp[2]);
      get_next_leaf_ptr (ply, leafp + 2, bp[4]);
      get_next_leaf_ptr (ply, leafp + 3, bp[6]);

      clib_prefetch_load (leafp[12]);
      clib_prefetch_load (leafp[13]);
      clib_prefetch_load (leafp[14]);
      clib_prefetch_load (leafp[15]);

      get_next_leaf_ptr (ply, leafp + 4, bp[8]);
      get_next_leaf_ptr (ply, leafp + 5, bp[10]);
      get_next_leaf_ptr (ply, leafp + 6, bp[12]);
      get_next_leaf_ptr (ply, leafp + 7, bp[14]);

      bp += 16;
      leafp += 8;
      n_left -= 8;
    }
  while (n_left)
    {
      get_next_leaf_ptr (ply, leafp, bp[0]);
      bp += 2;
      leafp += 1;
      n_left -= 1;
    }
#endif
}

static_always_inline const dpo_id_t *
get_dpo (u32 lb_index, vlib_buffer_t * b)
{
  load_balance_t *lb = load_balance_get (lb_index);
  ip4_header_t *ip;
  u32 hash;

  if (PREDICT_TRUE (lb->lb_n_buckets == 1))
    return load_balance_get_bucket_i (lb, 0);

  ip = vlib_buffer_get_current (b);
  hash = ip4_compute_flow_hash (ip, lb->lb_hash_config);
  vnet_buffer (b)->ip.flow_hash = hash;
  hash &= lb->lb_n_buckets_minus_1;
  return load_balance_get_fwd_bucket (lb, hash);
}

always_inline uword __clib_unused
ip4_lookup_inline (vlib_main_t * vm,
		   vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  u32 *lt = ip4_main.fib_index_by_sw_if_index;
  vlib_combined_counter_main_t *cm = &load_balance_main.lbm_to_counters;
  u32 n_left, *from;
  vlib_buffer_t __clib_cl_aligned *bufs[VLIB_FRAME_SIZE + 8], **b = bufs;
  u16 __clib_cl_aligned dst_addr_low[VLIB_FRAME_SIZE + 8], *dal =
    dst_addr_low;
  u32 __clib_cl_aligned pkt_bytes[VLIB_FRAME_SIZE], *pb = pkt_bytes;
  const dpo_id_t *dpo[4];
  ip4_header_t *ip;
  ip4_fib_t *fib;

  /* following union is used for different purpose at different stages
   * to reduce stack usage and reduce number of l1 evictions */
  union
  {
    ip4_fib_mtrie_leaf_t *leaf_ptrs[VLIB_FRAME_SIZE + 8];
    u32 lb_indices[VLIB_FRAME_SIZE];
    u16 next_indices[VLIB_FRAME_SIZE];
  } __clib_cl_aligned data;

  u16 *next = data.next_indices;
  u32 *lb_index = data.lb_indices;
  ip4_fib_mtrie_leaf_t **leafp = data.leaf_ptrs;

  from = vlib_frame_vector_args (frame);
  n_left = frame->n_vectors;
  vlib_get_buffers (vm, from, bufs, n_left);

  /* Process packet data, results in 3 VLIB_FRAME_SIZE sized arrays:
   *  - array of pointers to stage-1 leaf data
   *  - u32 array of packet lengths
   *  - u16 array of byte 2 and 3 of dst IP address
   */
  if (PREDICT_TRUE (n_left >= 4))
    {
      /* for a meaningful branchless prefetching, we duplicate last 4 buffer
       * pointers two times at the end of buffer array */
      int sz = 4 * sizeof (vlib_buffer_t *);
      clib_memcpy_fast (bufs + n_left, bufs + n_left - 4, sz);
      clib_memcpy_fast (bufs + n_left + 4, bufs + n_left - 4, sz);

      while (n_left >= 4)
	{
	  ip4_address_t da;

	  vlib_prefetch_buffer_header (b[8], LOAD);
	  clib_prefetch_load (b[8]->data);
	  vlib_prefetch_buffer_header (b[9], LOAD);
	  clib_prefetch_load (b[9]->data);
	  vlib_prefetch_buffer_header (b[10], LOAD);
	  clib_prefetch_load (b[10]->data);
	  vlib_prefetch_buffer_header (b[11], LOAD);
	  clib_prefetch_load (b[11]->data);

	  ip = vlib_buffer_get_current (b[0]);
	  da = ip->dst_address;
	  fib = ip4_fib_get (ip_lookup_set_buffer_fib_index (lt, b[0]));
	  leafp[0] = fib->mtrie.root_ply.leaves + da.as_u16[0];
	  dal[0] = da.as_u16[1];

	  ip = vlib_buffer_get_current (b[1]);
	  da = ip->dst_address;
	  fib = ip4_fib_get (ip_lookup_set_buffer_fib_index (lt, b[1]));
	  leafp[1] = fib->mtrie.root_ply.leaves + da.as_u16[0];
	  dal[1] = da.as_u16[1];

	  ip = vlib_buffer_get_current (b[2]);
	  da = ip->dst_address;
	  fib = ip4_fib_get (ip_lookup_set_buffer_fib_index (lt, b[2]));
	  leafp[2] = fib->mtrie.root_ply.leaves + da.as_u16[0];
	  dal[2] = da.as_u16[1];

	  ip = vlib_buffer_get_current (b[3]);
	  da = ip->dst_address;
	  fib = ip4_fib_get (ip_lookup_set_buffer_fib_index (lt, b[3]));
	  leafp[3] = fib->mtrie.root_ply.leaves + da.as_u16[0];
	  dal[3] = da.as_u16[1];

	  pb[0] = vlib_buffer_length_in_chain (vm, b[0]);
	  pb[1] = vlib_buffer_length_in_chain (vm, b[1]);
	  pb[2] = vlib_buffer_length_in_chain (vm, b[2]);
	  pb[3] = vlib_buffer_length_in_chain (vm, b[3]);

	  b += 4;
	  pb += 4;
	  dal += 4;
	  leafp += 4;
	  n_left -= 4;
	}
    }
  while (n_left)
    {
      ip4_address_t da;
      ip = vlib_buffer_get_current (b[0]);
      da.as_u32 = ip->dst_address.as_u32;
      dal[0] = da.as_u16[1];
      pb[0] = vlib_buffer_length_in_chain (vm, b[0]);
      fib = ip4_fib_get (ip_lookup_set_buffer_fib_index (lt, b[0]));
      leafp[0] = fib->mtrie.root_ply.leaves + da.as_u16[0];

      b += 1;
      pb += 1;
      dal += 1;
      leafp += 1;
      n_left -= 1;
    }

#ifdef CLIB_HAVE_VEC256
  /* for next lookup steps, we need to fill tail of arrays so we can prefetch
   * safely and process 8 packets in parallel even if number of packets is
   * not multiple of 8 */
  n_left = frame->n_vectors;
  u16x8_store_unaligned (u16x8_splat (dal[-1]), dal);
  u64x4 p = u64x4_splat (pointer_to_uword (leafp[-1]));
  u64x4_store_unaligned (p, leafp);
  u64x4_store_unaligned (p, leafp + 4);
  leafp += round_pow2 (n_left, 8) - n_left;
  u64x4_store_unaligned (p, leafp);
  u64x4_store_unaligned (p, leafp + 4);
#else
  /* just prefetch pointers */
  for (int i = 0; i < 8; i++)
    leafp[i] = leafp[-1];
#endif

  /* lookup step 2 and 3 - we deal with leaf pointers so we can effectively
   * pefetch. Result of each step is updated list of leaf pointers.
   * Only pointers which are not pointing to terminal nodes are updated. */
  n_left = frame->n_vectors;
  ip4_lookup_step (data.leaf_ptrs, (u8 *) dst_addr_low, n_left);

  /* to reduce number of stores in previos step, we store dst ip address
   * octets 2 qnd 3 in the singe u16 array, so here we need to shift by 1 */
  ip4_lookup_step (data.leaf_ptrs, (u8 *) dst_addr_low + 1, n_left);

  /* after the step 3 we have array of pointers to terminal leafs, so we can
   * prefetch, read and convert them to lb indices.
   * As we don't need leaf pointers anymore we reuse same stack area so
   * as those cachelines are already in L1 cache */
  leaf_pointers_to_lb_indices (data.leaf_ptrs, data.lb_indices, n_left);

  /* we increment counter based of array of lb indices and pkt byte counts */
  vlib_increment_combined_counters (cm, vm->thread_index, data.lb_indices,
				    pkt_bytes, n_left);

  /* final step - we have array of lb indices, so for simple cases we just
   * need to update array of nexts and adj_index in the buffer metadata
   * again, for cache efficiency, we are reusing stack space for storing
   * array of next indices */

  b = bufs;
  next = data.next_indices;
  lb_index = data.lb_indices;

  if (n_left >= 4)
    {
      int sz = 4 * sizeof (lb_index[0]);
      clib_memcpy_fast (lb_index + n_left, lb_index + n_left - 4, sz);
      clib_memcpy_fast (lb_index + n_left + 4, lb_index + n_left - 4, sz);
    }

  while (n_left >= 4)
    {
      clib_prefetch_load (load_balance_get (lb_index[8]));
      vlib_prefetch_buffer_header (b[8], STORE);
      clib_prefetch_load (load_balance_get (lb_index[9]));
      vlib_prefetch_buffer_header (b[9], STORE);

      vnet_buffer (b[0])->ip.flow_hash = 0;
      vnet_buffer (b[1])->ip.flow_hash = 0;
      vnet_buffer (b[2])->ip.flow_hash = 0;
      vnet_buffer (b[3])->ip.flow_hash = 0;

      clib_prefetch_load (load_balance_get (lb_index[10]));
      vlib_prefetch_buffer_header (b[10], STORE);
      clib_prefetch_load (load_balance_get (lb_index[11]));
      vlib_prefetch_buffer_header (b[11], STORE);

      dpo[0] = get_dpo (lb_index[0], b[0]);
      dpo[1] = get_dpo (lb_index[1], b[1]);
      dpo[2] = get_dpo (lb_index[2], b[2]);
      dpo[3] = get_dpo (lb_index[3], b[3]);

      next[0] = dpo[0]->dpoi_next_node;
      next[1] = dpo[1]->dpoi_next_node;
      next[2] = dpo[2]->dpoi_next_node;
      next[3] = dpo[3]->dpoi_next_node;

      vnet_buffer (b[0])->ip.adj_index[VLIB_TX] = dpo[0]->dpoi_index;
      vnet_buffer (b[1])->ip.adj_index[VLIB_TX] = dpo[1]->dpoi_index;
      vnet_buffer (b[2])->ip.adj_index[VLIB_TX] = dpo[2]->dpoi_index;
      vnet_buffer (b[3])->ip.adj_index[VLIB_TX] = dpo[3]->dpoi_index;

      b += 4;
      next += 4;
      lb_index += 4;
      n_left -= 4;
    }
  while (n_left > 0)
    {
      vnet_buffer (b[0])->ip.flow_hash = 0;
      dpo[0] = get_dpo (lb_index[0], b[0]);
      next[0] = dpo[0]->dpoi_next_node;
      vnet_buffer (b[0])->ip.adj_index[VLIB_TX] = dpo[0]->dpoi_index;

      b += 1;
      next += 1;
      lb_index += 1;
      n_left -= 1;
    }

  /* enqueue to next node */
  vlib_buffer_enqueue_to_next (vm, node, from, data.next_indices,
			       frame->n_vectors);

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
