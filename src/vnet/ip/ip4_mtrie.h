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
 * ip/ip4_fib.h: ip4 mtrie fib
 *
 * Copyright (c) 2012 Eliot Dresselhaus
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

#ifndef included_ip_ip4_fib_h
#define included_ip_ip4_fib_h

#include <vppinfra/cache.h>
#include <vppinfra/vector.h>
#include <vnet/ip/lookup.h>
#include <vnet/ip/ip4_packet.h>	/* for ip4_address_t */

/* ip4 fib leafs: 4 ply 8-8-8-8 mtrie.
   1 + 2*adj_index for terminal leaves.
   0 + 2*next_ply_index for non-terminals, i.e. PLYs
   1 => empty (adjacency index of zero is special miss adjacency). */
typedef u32 ip4_fib_mtrie_leaf_t;

#define IP4_FIB_MTRIE_LEAF_EMPTY (1 + 2*0)

/**
 * @brief the 16 way stride that is the top PLY of the mtrie
 * We do not maintain the count of 'real' leaves in this PLY, since
 * it is never removed. The FIB will destroy the mtrie and the ply once
 * the FIB is destroyed.
 */
#define PLY_16_SIZE (1<<16)
typedef struct ip4_fib_mtrie_16_ply_t_
{
  /**
   * The leaves/slots/buckets to be filed with leafs
   */
  union
  {
    ip4_fib_mtrie_leaf_t leaves[PLY_16_SIZE];

#ifdef CLIB_HAVE_VEC128
    u32x4 leaves_as_u32x4[PLY_16_SIZE / 4];
#endif
  };

  /**
   * Prefix length for terminal leaves.
   */
  u8 dst_address_bits_of_leaves[PLY_16_SIZE];
} ip4_fib_mtrie_16_ply_t;

/**
 * @brief One ply of the 4 ply mtrie fib.
 */
typedef struct ip4_fib_mtrie_8_ply_t_
{
  /**
   * The leaves/slots/buckets to be filed with leafs
   */
  union
  {
    ip4_fib_mtrie_leaf_t leaves[256];

#ifdef CLIB_HAVE_VEC128
    u32x4 leaves_as_u32x4[256 / 4];
#endif
  };

  /**
   * Prefix length for leaves/ply.
   */
  u8 dst_address_bits_of_leaves[256];

  /**
   * Number of non-empty leafs (whether terminal or not).
   */
  i32 n_non_empty_leafs;

  /**
   * The length of the ply's covering prefix. Also a measure of its depth
   * If a leaf in a slot has a mask length longer than this then it is
   * 'non-empty'. Otherwise it is the value of the cover.
   */
  i32 dst_address_bits_base;

  /* Pad to cache line boundary. */
  u8 pad[CLIB_CACHE_LINE_BYTES - 2 * sizeof (i32)];
}
ip4_fib_mtrie_8_ply_t;

STATIC_ASSERT (0 == sizeof (ip4_fib_mtrie_8_ply_t) % CLIB_CACHE_LINE_BYTES,
	       "IP4 Mtrie ply cache line");

/**
 * @brief The mutiway-TRIE.
 * There is no data associated with the mtrie apart from the top PLY
 */
typedef struct
{
  /**
   * Embed the PLY with the mtrie struct. This means that the Data-plane
   * 'get me the mtrie' returns the first ply, and not an indirect 'pointer'
   * to it. therefore no cacheline misses in the data-path.
   */
  ip4_fib_mtrie_16_ply_t root_ply;
} ip4_fib_mtrie_t;

/**
 * @brief Initialise an mtrie
 */
void ip4_mtrie_init (ip4_fib_mtrie_t * m);

/**
 * @brief Free an mtrie, It must be emty when free'd
 */
void ip4_mtrie_free (ip4_fib_mtrie_t * m);

/**
 * @brief Add a route/entry to the mtrie
 */
void ip4_fib_mtrie_route_add (ip4_fib_mtrie_t * m,
			      const ip4_address_t * dst_address,
			      u32 dst_address_length, u32 adj_index);
/**
 * @brief remove a route/entry to the mtrie
 */
void ip4_fib_mtrie_route_del (ip4_fib_mtrie_t * m,
			      const ip4_address_t * dst_address,
			      u32 dst_address_length,
			      u32 adj_index,
			      u32 cover_address_length, u32 cover_adj_index);

/**
 * @brief return the memory used by the table
 */
uword ip4_fib_mtrie_memory_usage (ip4_fib_mtrie_t * m);

/**
 * @brief Format/display the contents of the mtrie
 */
format_function_t format_ip4_fib_mtrie;

/**
 * @brief A global pool of 8bit stride plys
 */
extern ip4_fib_mtrie_8_ply_t *ip4_ply_pool;

/**
 * Is the leaf terminal (i.e. an LB index) or non-terminal (i.e. a PLY index)
 */
always_inline u32
ip4_fib_mtrie_leaf_is_terminal (ip4_fib_mtrie_leaf_t n)
{
  return n & 1;
}

/**
 * From the stored slot value extract the LB index value
 */
always_inline u32
ip4_fib_mtrie_leaf_get_adj_index (ip4_fib_mtrie_leaf_t n)
{
  ASSERT (ip4_fib_mtrie_leaf_is_terminal (n));
  return n >> 1;
}

/**
 * @brief Lookup step.  Processes 1 byte of 4 byte ip4 address.
 */
always_inline ip4_fib_mtrie_leaf_t
ip4_fib_mtrie_lookup_step (const ip4_fib_mtrie_t * m,
			   ip4_fib_mtrie_leaf_t current_leaf,
			   const ip4_address_t * dst_address,
			   u32 dst_address_byte_index)
{
  ip4_fib_mtrie_8_ply_t *ply;

  uword current_is_terminal = ip4_fib_mtrie_leaf_is_terminal (current_leaf);

  if (!current_is_terminal)
    {
      ply = ip4_ply_pool + (current_leaf >> 1);
      return (ply->leaves[dst_address->as_u8[dst_address_byte_index]]);
    }

  return current_leaf;
}

/**
 * @brief Lookup step number 1.  Processes 2 bytes of 4 byte ip4 address.
 */
always_inline ip4_fib_mtrie_leaf_t
ip4_fib_mtrie_lookup_step_one (const ip4_fib_mtrie_t * m,
			       const ip4_address_t * dst_address)
{
  ip4_fib_mtrie_leaf_t next_leaf;

  next_leaf = m->root_ply.leaves[dst_address->as_u16[0]];

  return next_leaf;
}

always_inline u64x2
u64x2_deref (u64x2 a, u64x2 o)
{
  u64x2 r = a + o;
  u64x2 s = { *(u32 *) r[0], *(u32 *) r[1] };
  return s;
}

always_inline u64x2
u64x2_deref2 (u64x2 p, u64x2 o, u64x2 l)
{
  u64x2 t = l & 1;
  u64x2 r = { t[0] ? l[0] : *(ip4_fib_mtrie_leaf_t *) (p[0] + o[0]),
    t[1] ? l[1] : *(ip4_fib_mtrie_leaf_t *) (p[1] + o[1])
  };
  return r;
}

always_inline void
ip4_fib_mtrie_lookup_step_one_vx2 (const ip4_fib_mtrie_t * m1,
				   const ip4_fib_mtrie_t * m2,
				   const ip4_address_t * a1,
				   const ip4_address_t * a2,
				   ip4_fib_mtrie_leaf_t * n1,
				   ip4_fib_mtrie_leaf_t * n2)
{
  u32x4 ad = { 0, a1->as_u32, 0, a2->as_u32 };
  u64x2 a = (u64x2) ad;
  u64x2 base = { (u64) m1->root_ply.leaves, (u64) m2->root_ply.leaves };

  // permute the address vector so we get the ply lookup indicess
#if CLIB_ARCH_IS_BIG_ENDIAN
  u8x16 o1, s_ply1 = {
    0, 0, 0, 0, 0, 0, 4, 5, 0, 0, 0, 0, 0, 0, 12, 13,
  };
  u8x16 o2, s_ply2 = {
    0, 0, 0, 0, 0, 0, 0, 6, 0, 0, 0, 0, 0, 0, 0, 14,
  };
  u8x16 o3, s_ply3 = {
    0, 0, 0, 0, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0, 15,
  };
#else
  u8x16 o1, s_ply1 = {
    4, 5, 0, 0, 0, 0, 0, 0, 12, 13, 0, 0, 0, 0, 0, 0,
  };
  u8x16 o2, s_ply2 = {
    6, 0, 0, 0, 0, 0, 0, 0, 14, 0, 0, 0, 0, 0, 0, 0,
  };
  u8x16 o3, s_ply3 = {
    7, 0, 0, 0, 0, 0, 0, 0, 15, 0, 0, 0, 0, 0, 0, 0,
  };
#endif
  u64x2 ply1, ply2, l, pool = { (u64) ip4_ply_pool, (u64) ip4_ply_pool };

  // << 2 is *4, which is for u32 pointer arthmetic on ply bucket
  o1 = u8x16_shuffle ((u8x16) a, s_ply1) << 2;
  o2 = u8x16_shuffle ((u8x16) a, s_ply2) << 2;
  o3 = u8x16_shuffle ((u8x16) a, s_ply3) << 2;

  l = u64x2_deref (base, (u64x2) o1);
  ply1 = pool + ((l >> 1) * sizeof (ip4_fib_mtrie_8_ply_t));
  l = u64x2_deref2 (ply1, (u64x2) o2, l);
  ply2 = pool + ((l >> 1) * sizeof (ip4_fib_mtrie_8_ply_t));
  l = u64x2_deref2 (ply2, (u64x2) o3, l);
  l = (l >> 1);
  *n1 = l[0];
  *n2 = l[1];
}

#ifdef CLIB_HAVE_VEC256

always_inline u64x4
u64x4_deref (u64x4 a, u64x4 o)
{
  u64x4 r = a + o;
  u64x4 s = { *(u32 *) r[0], *(u32 *) r[1], *(u32 *) r[2], *(u32 *) r[3] };
  return s;
}

always_inline u64x4
u64x4_deref2 (u64x4 p, u64x4 o, u64x4 l)
{
  u64x4 t = l & 1;
  u64x4 r = { t[0] ? l[0] : *(ip4_fib_mtrie_leaf_t *) (p[0] + o[0]),
    t[1] ? l[1] : *(ip4_fib_mtrie_leaf_t *) (p[1] + o[1]),
    t[2] ? l[2] : *(ip4_fib_mtrie_leaf_t *) (p[2] + o[2]),
    t[3] ? l[1] : *(ip4_fib_mtrie_leaf_t *) (p[1] + o[3])
  };
  return r;
}

always_inline void
ip4_fib_mtrie_lookup_step_one_vx4 (const ip4_fib_mtrie_t * m1,
				   const ip4_fib_mtrie_t * m2,
				   const ip4_fib_mtrie_t * m3,
				   const ip4_fib_mtrie_t * m4,
				   const ip4_address_t * a1,
				   const ip4_address_t * a2,
				   const ip4_address_t * a3,
				   const ip4_address_t * a4,
				   ip4_fib_mtrie_leaf_t * n1,
				   ip4_fib_mtrie_leaf_t * n2,
				   ip4_fib_mtrie_leaf_t * n3,
				   ip4_fib_mtrie_leaf_t * n4)
{
  u32x8 ad = { 0, a1->as_u32, 0, a2->as_u32, 0, a2->as_u32, 0, a3->as_u32 };
  u64x4 a = (u64x4) ad;
  u64x4 base = { (u64) m1->root_ply.leaves, (u64) m2->root_ply.leaves,
    (u64) m3->root_ply.leaves, (u64) m4->root_ply.leaves
  };

  // permute the address vector so we get the ply lookup indicess
#if CLIB_ARCH_IS_BIG_ENDIAN
  u8x16 o1, s_ply1 = {
    0, 0, 0, 0, 0, 0, 4, 5, 0, 0, 0, 0, 0, 0, 12, 13,
    0, 0, 0, 0, 0, 0, 20, 21, 0, 0, 0, 0, 0, 0, 28, 29,
  };
  u8x16 o2, s_ply2 = {
    0, 0, 0, 0, 0, 0, 0, 6, 0, 0, 0, 0, 0, 0, 0, 14,
    0, 0, 0, 0, 0, 0, 0, 22, 0, 0, 0, 0, 0, 0, 0, 30,
  };
  u8x16 o3, s_ply3 = {
    0, 0, 0, 0, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0, 15,
    0, 0, 0, 0, 0, 0, 0, 23, 0, 0, 0, 0, 0, 0, 0, 31,
  };
#else
  u8x32 o1, s_ply1 = {
    4, 5, 0, 0, 0, 0, 0, 0, 12, 13, 0, 0, 0, 0, 0, 0,
    20, 21, 0, 0, 0, 0, 0, 0, 28, 29, 0, 0, 0, 0, 0, 0,
  };
  u8x32 o2, s_ply2 = {
    6, 0, 0, 0, 0, 0, 0, 0, 14, 0, 0, 0, 0, 0, 0, 0,
    22, 0, 0, 0, 0, 0, 0, 0, 30, 0, 0, 0, 0, 0, 0, 0,
  };
  u8x32 o3, s_ply3 = {
    7, 0, 0, 0, 0, 0, 0, 0, 15, 0, 0, 0, 0, 0, 0, 0,
    23, 0, 0, 0, 0, 0, 0, 0, 31, 0, 0, 0, 0, 0, 0, 0,
  };
#endif
  u64x4 ply1, ply2, l;
  u64x4 pool = u64x4_splat ((u64) ip4_ply_pool);

  // << 2 is *4, which is for u32 pointer arthmetic on ply bucket
  o1 = u8x32_shuffle ((u8x32) a, s_ply1) << 2;
  o2 = u8x32_shuffle ((u8x32) a, s_ply2) << 2;
  o3 = u8x32_shuffle ((u8x32) a, s_ply3) << 2;

  // 3 successvie layer in the mrtie
  l = u64x4_deref (base, (u64x4) o1);
  // (l >> 1) results in the index. the LSB signals terminal (or not)
  // pointer arithmetic on the pool address
  ply1 = pool + ((l >> 1) * sizeof (ip4_fib_mtrie_8_ply_t));
  l = u64x4_deref2 (ply1, (u64x4) o2, l);
  ply2 = pool + ((l >> 1) * sizeof (ip4_fib_mtrie_8_ply_t));
  l = u64x4_deref2 (ply2, (u64x4) o3, l);

  // return the last leafs
  l = (l >> 1);
  *n1 = l[0];
  *n2 = l[1];
  *n3 = l[2];
  *n4 = l[3];
}

#endif

#endif /* included_ip_ip4_fib_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
