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

#include <vnet/ip/ip.h>
#include <vnet/ip/ip4_mtrie.h>
#include <vnet/fib/ip4_fib.h>


/**
 * Global pool of IPv4 8bit PLYs
 */
ip4_fib_mtrie_8_ply_t *ip4_ply_pool;

always_inline u32
ip4_fib_mtrie_leaf_is_non_empty (ip4_fib_mtrie_8_ply_t * p, u8 dst_byte)
{
  /*
   * It's 'non-empty' if the length of the leaf stored is greater than the
   * length of a leaf in the covering ply. i.e. the leaf is more specific
   * than it's would be cover in the covering ply
   */
  if (p->dst_address_bits_of_leaves[dst_byte] > p->dst_address_bits_base)
    return (1);
  return (0);
}

always_inline ip4_fib_mtrie_leaf_t
ip4_fib_mtrie_leaf_set_adj_index (u32 adj_index)
{
  ip4_fib_mtrie_leaf_t l;
  l = 1 + 2 * adj_index;
  ASSERT (ip4_fib_mtrie_leaf_get_adj_index (l) == adj_index);
  return l;
}

always_inline u32
ip4_fib_mtrie_leaf_is_next_ply (ip4_fib_mtrie_leaf_t n)
{
  return (n & 1) == 0;
}

always_inline u32
ip4_fib_mtrie_leaf_get_next_ply_index (ip4_fib_mtrie_leaf_t n)
{
  ASSERT (ip4_fib_mtrie_leaf_is_next_ply (n));
  return n >> 1;
}

always_inline ip4_fib_mtrie_leaf_t
ip4_fib_mtrie_leaf_set_next_ply_index (u32 i)
{
  ip4_fib_mtrie_leaf_t l;
  l = 0 + 2 * i;
  ASSERT (ip4_fib_mtrie_leaf_get_next_ply_index (l) == i);
  return l;
}

#ifndef __ALTIVEC__
#define PLY_X4_SPLAT_INIT(init_x4, init) \
  init_x4 = u32x4_splat (init);
#else
#define PLY_X4_SPLAT_INIT(init_x4, init)                                \
{                                                                       \
  u32x4_union_t y;                                                      \
  y.as_u32[0] = init;                                                   \
  y.as_u32[1] = init;                                                   \
  y.as_u32[2] = init;                                                   \
  y.as_u32[3] = init;                                                   \
  init_x4 = y.as_u32x4;                                                 \
}
#endif

#ifdef CLIB_HAVE_VEC128
#define PLY_INIT_LEAVES(p)                                              \
{                                                                       \
    u32x4 *l, init_x4;                                                  \
                                                                        \
    PLY_X4_SPLAT_INIT(init_x4, init);                                   \
    for (l = p->leaves_as_u32x4;                                        \
	 l < p->leaves_as_u32x4 + ARRAY_LEN (p->leaves_as_u32x4);       \
         l += 4)                                                        \
      {                                                                 \
	l[0] = init_x4;                                                 \
	l[1] = init_x4;                                                 \
	l[2] = init_x4;                                                 \
	l[3] = init_x4;                                                 \
      }                                                                 \
}
#else
#define PLY_INIT_LEAVES(p)                                              \
{                                                                       \
  u32 *l;                                                               \
                                                                        \
  for (l = p->leaves; l < p->leaves + ARRAY_LEN (p->leaves); l += 4)    \
    {                                                                   \
      l[0] = init;                                                      \
      l[1] = init;                                                      \
      l[2] = init;                                                      \
      l[3] = init;                                                      \
      }                                                                 \
}
#endif

#define PLY_INIT(p, init, prefix_len, ply_base_len)                     \
{                                                                       \
  /*                                                                    \
   * A leaf is 'empty' if it represents a leaf from the covering PLY    \
   * i.e. if the prefix length of the leaf is less than or equal to     \
   * the prefix length of the PLY                                       \
   */                                                                   \
  p->n_non_empty_leafs = (prefix_len > ply_base_len ?                   \
			  ARRAY_LEN (p->leaves) : 0);                   \
  memset (p->dst_address_bits_of_leaves, prefix_len,                    \
	  sizeof (p->dst_address_bits_of_leaves));                      \
  p->dst_address_bits_base = ply_base_len;                              \
                                                                        \
  /* Initialize leaves. */                                              \
  PLY_INIT_LEAVES(p);                                                   \
}

static void
ply_8_init (ip4_fib_mtrie_8_ply_t * p,
	    ip4_fib_mtrie_leaf_t init, uword prefix_len, u32 ply_base_len)
{
  PLY_INIT (p, init, prefix_len, ply_base_len);
}

static void
ply_16_init (ip4_fib_mtrie_16_ply_t * p,
	     ip4_fib_mtrie_leaf_t init, uword prefix_len)
{
  memset (p->dst_address_bits_of_leaves, prefix_len,
	  sizeof (p->dst_address_bits_of_leaves));
  PLY_INIT_LEAVES (p);
}

static ip4_fib_mtrie_leaf_t
ply_create (ip4_fib_mtrie_t * m,
	    ip4_fib_mtrie_leaf_t init_leaf,
	    u32 leaf_prefix_len, u32 ply_base_len)
{
  ip4_fib_mtrie_8_ply_t *p;

  /* Get cache aligned ply. */
  pool_get_aligned (ip4_ply_pool, p, CLIB_CACHE_LINE_BYTES);

  ply_8_init (p, init_leaf, leaf_prefix_len, ply_base_len);
  return ip4_fib_mtrie_leaf_set_next_ply_index (p - ip4_ply_pool);
}

always_inline ip4_fib_mtrie_8_ply_t *
get_next_ply_for_leaf (ip4_fib_mtrie_t * m, ip4_fib_mtrie_leaf_t l)
{
  uword n = ip4_fib_mtrie_leaf_get_next_ply_index (l);

  return pool_elt_at_index (ip4_ply_pool, n);
}

void
ip4_mtrie_free (ip4_fib_mtrie_t * m)
{
  /* the root ply is embedded so the is nothing to do,
   * the assumption being that the IP4 FIB table has emptied the trie
   * before deletion.
   */
#if CLIB_DEBUG > 0
  int i;
  for (i = 0; i < ARRAY_LEN (m->root_ply.leaves); i++)
    {
      ASSERT (!ip4_fib_mtrie_leaf_is_next_ply (m->root_ply.leaves[i]));
    }
#endif
}

void
ip4_mtrie_init (ip4_fib_mtrie_t * m)
{
  ply_16_init (&m->root_ply, IP4_FIB_MTRIE_LEAF_EMPTY, 0);
}

typedef struct
{
  ip4_address_t dst_address;
  u32 dst_address_length;
  u32 adj_index;
  u32 cover_address_length;
  u32 cover_adj_index;
} ip4_fib_mtrie_set_unset_leaf_args_t;

static void
set_ply_with_more_specific_leaf (ip4_fib_mtrie_t * m,
				 ip4_fib_mtrie_8_ply_t * ply,
				 ip4_fib_mtrie_leaf_t new_leaf,
				 uword new_leaf_dst_address_bits)
{
  ip4_fib_mtrie_leaf_t old_leaf;
  uword i;

  ASSERT (ip4_fib_mtrie_leaf_is_terminal (new_leaf));

  for (i = 0; i < ARRAY_LEN (ply->leaves); i++)
    {
      old_leaf = ply->leaves[i];

      /* Recurse into sub plies. */
      if (!ip4_fib_mtrie_leaf_is_terminal (old_leaf))
	{
	  ip4_fib_mtrie_8_ply_t *sub_ply =
	    get_next_ply_for_leaf (m, old_leaf);
	  set_ply_with_more_specific_leaf (m, sub_ply, new_leaf,
					   new_leaf_dst_address_bits);
	}

      /* Replace less specific terminal leaves with new leaf. */
      else if (new_leaf_dst_address_bits >=
	       ply->dst_address_bits_of_leaves[i])
	{
	  __sync_val_compare_and_swap (&ply->leaves[i], old_leaf, new_leaf);
	  ASSERT (ply->leaves[i] == new_leaf);
	  ply->dst_address_bits_of_leaves[i] = new_leaf_dst_address_bits;
	  ply->n_non_empty_leafs += ip4_fib_mtrie_leaf_is_non_empty (ply, i);
	}
    }
}

static void
set_leaf (ip4_fib_mtrie_t * m,
	  const ip4_fib_mtrie_set_unset_leaf_args_t * a,
	  u32 old_ply_index, u32 dst_address_byte_index)
{
  ip4_fib_mtrie_leaf_t old_leaf, new_leaf;
  i32 n_dst_bits_next_plies;
  u8 dst_byte;
  ip4_fib_mtrie_8_ply_t *old_ply;

  old_ply = pool_elt_at_index (ip4_ply_pool, old_ply_index);

  ASSERT (a->dst_address_length <= 32);
  ASSERT (dst_address_byte_index < ARRAY_LEN (a->dst_address.as_u8));

  /* how many bits of the destination address are in the next PLY */
  n_dst_bits_next_plies =
    a->dst_address_length - BITS (u8) * (dst_address_byte_index + 1);

  dst_byte = a->dst_address.as_u8[dst_address_byte_index];

  /* Number of bits next plies <= 0 => insert leaves this ply. */
  if (n_dst_bits_next_plies <= 0)
    {
      /* The mask length of the address to insert maps to this ply */
      uword old_leaf_is_terminal;
      u32 i, n_dst_bits_this_ply;

      /* The number of bits, and hence slots/buckets, we will fill */
      n_dst_bits_this_ply = clib_min (8, -n_dst_bits_next_plies);
      ASSERT ((a->dst_address.as_u8[dst_address_byte_index] &
	       pow2_mask (n_dst_bits_this_ply)) == 0);

      /* Starting at the value of the byte at this section of the v4 address
       * fill the buckets/slots of the ply */
      for (i = dst_byte; i < dst_byte + (1 << n_dst_bits_this_ply); i++)
	{
	  ip4_fib_mtrie_8_ply_t *new_ply;

	  old_leaf = old_ply->leaves[i];
	  old_leaf_is_terminal = ip4_fib_mtrie_leaf_is_terminal (old_leaf);

	  if (a->dst_address_length >= old_ply->dst_address_bits_of_leaves[i])
	    {
	      /* The new leaf is more or equally specific than the one currently
	       * occupying the slot */
	      new_leaf = ip4_fib_mtrie_leaf_set_adj_index (a->adj_index);

	      if (old_leaf_is_terminal)
		{
		  /* The current leaf is terminal, we can replace it with
		   * the new one */
		  old_ply->n_non_empty_leafs -=
		    ip4_fib_mtrie_leaf_is_non_empty (old_ply, i);

		  old_ply->dst_address_bits_of_leaves[i] =
		    a->dst_address_length;
		  __sync_val_compare_and_swap (&old_ply->leaves[i], old_leaf,
					       new_leaf);
		  ASSERT (old_ply->leaves[i] == new_leaf);

		  old_ply->n_non_empty_leafs +=
		    ip4_fib_mtrie_leaf_is_non_empty (old_ply, i);
		  ASSERT (old_ply->n_non_empty_leafs <=
			  ARRAY_LEN (old_ply->leaves));
		}
	      else
		{
		  /* Existing leaf points to another ply.  We need to place
		   * new_leaf into all more specific slots. */
		  new_ply = get_next_ply_for_leaf (m, old_leaf);
		  set_ply_with_more_specific_leaf (m, new_ply, new_leaf,
						   a->dst_address_length);
		}
	    }
	  else if (!old_leaf_is_terminal)
	    {
	      /* The current leaf is less specific and not termial (i.e. a ply),
	       * recurse on down the trie */
	      new_ply = get_next_ply_for_leaf (m, old_leaf);
	      set_leaf (m, a, new_ply - ip4_ply_pool,
			dst_address_byte_index + 1);
	    }
	  /*
	   * else
	   *  the route we are adding is less specific than the leaf currently
	   *  occupying this slot. leave it there
	   */
	}
    }
  else
    {
      /* The address to insert requires us to move down at a lower level of
       * the trie - recurse on down */
      ip4_fib_mtrie_8_ply_t *new_ply;
      u8 ply_base_len;

      ply_base_len = 8 * (dst_address_byte_index + 1);

      old_leaf = old_ply->leaves[dst_byte];

      if (ip4_fib_mtrie_leaf_is_terminal (old_leaf))
	{
	  /* There is a leaf occupying the slot. Replace it with a new ply */
	  old_ply->n_non_empty_leafs -=
	    ip4_fib_mtrie_leaf_is_non_empty (old_ply, dst_byte);

	  new_leaf = ply_create (m, old_leaf,
				 clib_max (old_ply->dst_address_bits_of_leaves
					   [dst_byte], ply_base_len),
				 ply_base_len);
	  new_ply = get_next_ply_for_leaf (m, new_leaf);

	  /* Refetch since ply_create may move pool. */
	  old_ply = pool_elt_at_index (ip4_ply_pool, old_ply_index);

	  __sync_val_compare_and_swap (&old_ply->leaves[dst_byte], old_leaf,
				       new_leaf);
	  ASSERT (old_ply->leaves[dst_byte] == new_leaf);
	  old_ply->dst_address_bits_of_leaves[dst_byte] = ply_base_len;

	  old_ply->n_non_empty_leafs +=
	    ip4_fib_mtrie_leaf_is_non_empty (old_ply, dst_byte);
	  ASSERT (old_ply->n_non_empty_leafs >= 0);
	}
      else
	new_ply = get_next_ply_for_leaf (m, old_leaf);

      set_leaf (m, a, new_ply - ip4_ply_pool, dst_address_byte_index + 1);
    }
}

static void
set_root_leaf (ip4_fib_mtrie_t * m,
	       const ip4_fib_mtrie_set_unset_leaf_args_t * a)
{
  ip4_fib_mtrie_leaf_t old_leaf, new_leaf;
  ip4_fib_mtrie_16_ply_t *old_ply;
  i32 n_dst_bits_next_plies;
  u16 dst_byte;

  old_ply = &m->root_ply;

  ASSERT (a->dst_address_length <= 32);

  /* how many bits of the destination address are in the next PLY */
  n_dst_bits_next_plies = a->dst_address_length - BITS (u16);

  dst_byte = a->dst_address.as_u16[0];

  /* Number of bits next plies <= 0 => insert leaves this ply. */
  if (n_dst_bits_next_plies <= 0)
    {
      /* The mask length of the address to insert maps to this ply */
      uword old_leaf_is_terminal;
      u32 i, n_dst_bits_this_ply;

      /* The number of bits, and hence slots/buckets, we will fill */
      n_dst_bits_this_ply = 16 - a->dst_address_length;
      ASSERT ((clib_host_to_net_u16 (a->dst_address.as_u16[0]) &
	       pow2_mask (n_dst_bits_this_ply)) == 0);

      /* Starting at the value of the byte at this section of the v4 address
       * fill the buckets/slots of the ply */
      for (i = 0; i < (1 << n_dst_bits_this_ply); i++)
	{
	  ip4_fib_mtrie_8_ply_t *new_ply;
	  u16 slot;

	  slot = clib_net_to_host_u16 (dst_byte);
	  slot += i;
	  slot = clib_host_to_net_u16 (slot);

	  old_leaf = old_ply->leaves[slot];
	  old_leaf_is_terminal = ip4_fib_mtrie_leaf_is_terminal (old_leaf);

	  if (a->dst_address_length >=
	      old_ply->dst_address_bits_of_leaves[slot])
	    {
	      /* The new leaf is more or equally specific than the one currently
	       * occupying the slot */
	      new_leaf = ip4_fib_mtrie_leaf_set_adj_index (a->adj_index);

	      if (old_leaf_is_terminal)
		{
		  /* The current leaf is terminal, we can replace it with
		   * the new one */
		  old_ply->dst_address_bits_of_leaves[slot] =
		    a->dst_address_length;
		  __sync_val_compare_and_swap (&old_ply->leaves[slot],
					       old_leaf, new_leaf);
		  ASSERT (old_ply->leaves[slot] == new_leaf);
		}
	      else
		{
		  /* Existing leaf points to another ply.  We need to place
		   * new_leaf into all more specific slots. */
		  new_ply = get_next_ply_for_leaf (m, old_leaf);
		  set_ply_with_more_specific_leaf (m, new_ply, new_leaf,
						   a->dst_address_length);
		}
	    }
	  else if (!old_leaf_is_terminal)
	    {
	      /* The current leaf is less specific and not termial (i.e. a ply),
	       * recurse on down the trie */
	      new_ply = get_next_ply_for_leaf (m, old_leaf);
	      set_leaf (m, a, new_ply - ip4_ply_pool, 2);
	    }
	  /*
	   * else
	   *  the route we are adding is less specific than the leaf currently
	   *  occupying this slot. leave it there
	   */
	}
    }
  else
    {
      /* The address to insert requires us to move down at a lower level of
       * the trie - recurse on down */
      ip4_fib_mtrie_8_ply_t *new_ply;
      u8 ply_base_len;

      ply_base_len = 16;

      old_leaf = old_ply->leaves[dst_byte];

      if (ip4_fib_mtrie_leaf_is_terminal (old_leaf))
	{
	  /* There is a leaf occupying the slot. Replace it with a new ply */
	  new_leaf = ply_create (m, old_leaf,
				 clib_max (old_ply->dst_address_bits_of_leaves
					   [dst_byte], ply_base_len),
				 ply_base_len);
	  new_ply = get_next_ply_for_leaf (m, new_leaf);

	  __sync_val_compare_and_swap (&old_ply->leaves[dst_byte], old_leaf,
				       new_leaf);
	  ASSERT (old_ply->leaves[dst_byte] == new_leaf);
	  old_ply->dst_address_bits_of_leaves[dst_byte] = ply_base_len;
	}
      else
	new_ply = get_next_ply_for_leaf (m, old_leaf);

      set_leaf (m, a, new_ply - ip4_ply_pool, 2);
    }
}

static uword
unset_leaf (ip4_fib_mtrie_t * m,
	    const ip4_fib_mtrie_set_unset_leaf_args_t * a,
	    ip4_fib_mtrie_8_ply_t * old_ply, u32 dst_address_byte_index)
{
  ip4_fib_mtrie_leaf_t old_leaf, del_leaf;
  i32 n_dst_bits_next_plies;
  i32 i, n_dst_bits_this_ply, old_leaf_is_terminal;
  u8 dst_byte;

  ASSERT (a->dst_address_length <= 32);
  ASSERT (dst_address_byte_index < ARRAY_LEN (a->dst_address.as_u8));

  n_dst_bits_next_plies =
    a->dst_address_length - BITS (u8) * (dst_address_byte_index + 1);

  dst_byte = a->dst_address.as_u8[dst_address_byte_index];
  if (n_dst_bits_next_plies < 0)
    dst_byte &= ~pow2_mask (-n_dst_bits_next_plies);

  n_dst_bits_this_ply =
    n_dst_bits_next_plies <= 0 ? -n_dst_bits_next_plies : 0;
  n_dst_bits_this_ply = clib_min (8, n_dst_bits_this_ply);

  del_leaf = ip4_fib_mtrie_leaf_set_adj_index (a->adj_index);

  for (i = dst_byte; i < dst_byte + (1 << n_dst_bits_this_ply); i++)
    {
      old_leaf = old_ply->leaves[i];
      old_leaf_is_terminal = ip4_fib_mtrie_leaf_is_terminal (old_leaf);

      if (old_leaf == del_leaf
	  || (!old_leaf_is_terminal
	      && unset_leaf (m, a, get_next_ply_for_leaf (m, old_leaf),
			     dst_address_byte_index + 1)))
	{
	  old_ply->n_non_empty_leafs -=
	    ip4_fib_mtrie_leaf_is_non_empty (old_ply, i);

	  old_ply->leaves[i] =
	    ip4_fib_mtrie_leaf_set_adj_index (a->cover_adj_index);
	  old_ply->dst_address_bits_of_leaves[i] =
	    clib_max (old_ply->dst_address_bits_base,
		      a->cover_address_length);

	  old_ply->n_non_empty_leafs +=
	    ip4_fib_mtrie_leaf_is_non_empty (old_ply, i);

	  ASSERT (old_ply->n_non_empty_leafs >= 0);
	  if (old_ply->n_non_empty_leafs == 0 && dst_address_byte_index > 0)
	    {
	      pool_put (ip4_ply_pool, old_ply);
	      /* Old ply was deleted. */
	      return 1;
	    }
#if CLIB_DEBUG > 0
	  else if (dst_address_byte_index)
	    {
	      int ii, count = 0;
	      for (ii = 0; ii < ARRAY_LEN (old_ply->leaves); ii++)
		{
		  count += ip4_fib_mtrie_leaf_is_non_empty (old_ply, ii);
		}
	      ASSERT (count);
	    }
#endif
	}
    }

  /* Old ply was not deleted. */
  return 0;
}

static void
unset_root_leaf (ip4_fib_mtrie_t * m,
		 const ip4_fib_mtrie_set_unset_leaf_args_t * a)
{
  ip4_fib_mtrie_leaf_t old_leaf, del_leaf;
  i32 n_dst_bits_next_plies;
  i32 i, n_dst_bits_this_ply, old_leaf_is_terminal;
  u16 dst_byte;
  ip4_fib_mtrie_16_ply_t *old_ply;

  ASSERT (a->dst_address_length <= 32);

  old_ply = &m->root_ply;
  n_dst_bits_next_plies = a->dst_address_length - BITS (u16);

  dst_byte = a->dst_address.as_u16[0];

  n_dst_bits_this_ply = (n_dst_bits_next_plies <= 0 ?
			 (16 - a->dst_address_length) : 0);

  del_leaf = ip4_fib_mtrie_leaf_set_adj_index (a->adj_index);

  /* Starting at the value of the byte at this section of the v4 address
   * fill the buckets/slots of the ply */
  for (i = 0; i < (1 << n_dst_bits_this_ply); i++)
    {
      u16 slot;

      slot = clib_net_to_host_u16 (dst_byte);
      slot += i;
      slot = clib_host_to_net_u16 (slot);

      old_leaf = old_ply->leaves[slot];
      old_leaf_is_terminal = ip4_fib_mtrie_leaf_is_terminal (old_leaf);

      if (old_leaf == del_leaf
	  || (!old_leaf_is_terminal
	      && unset_leaf (m, a, get_next_ply_for_leaf (m, old_leaf), 2)))
	{
	  old_ply->leaves[slot] =
	    ip4_fib_mtrie_leaf_set_adj_index (a->cover_adj_index);
	  old_ply->dst_address_bits_of_leaves[slot] = a->cover_address_length;
	}
    }
}

void
ip4_fib_mtrie_route_add (ip4_fib_mtrie_t * m,
			 const ip4_address_t * dst_address,
			 u32 dst_address_length, u32 adj_index)
{
  ip4_fib_mtrie_set_unset_leaf_args_t a;
  ip4_main_t *im = &ip4_main;

  /* Honor dst_address_length. Fib masks are in network byte order */
  a.dst_address.as_u32 = (dst_address->as_u32 &
			  im->fib_masks[dst_address_length]);
  a.dst_address_length = dst_address_length;
  a.adj_index = adj_index;

  set_root_leaf (m, &a);
}

void
ip4_fib_mtrie_route_del (ip4_fib_mtrie_t * m,
			 const ip4_address_t * dst_address,
			 u32 dst_address_length,
			 u32 adj_index,
			 u32 cover_address_length, u32 cover_adj_index)
{
  ip4_fib_mtrie_set_unset_leaf_args_t a;
  ip4_main_t *im = &ip4_main;

  /* Honor dst_address_length. Fib masks are in network byte order */
  a.dst_address.as_u32 = (dst_address->as_u32 &
			  im->fib_masks[dst_address_length]);
  a.dst_address_length = dst_address_length;
  a.adj_index = adj_index;
  a.cover_adj_index = cover_adj_index;
  a.cover_address_length = cover_address_length;

  /* the top level ply is never removed */
  unset_root_leaf (m, &a);
}

/* Returns number of bytes of memory used by mtrie. */
static uword
mtrie_ply_memory_usage (ip4_fib_mtrie_t * m, ip4_fib_mtrie_8_ply_t * p)
{
  uword bytes, i;

  bytes = sizeof (p[0]);
  for (i = 0; i < ARRAY_LEN (p->leaves); i++)
    {
      ip4_fib_mtrie_leaf_t l = p->leaves[i];
      if (ip4_fib_mtrie_leaf_is_next_ply (l))
	bytes += mtrie_ply_memory_usage (m, get_next_ply_for_leaf (m, l));
    }

  return bytes;
}

/* Returns number of bytes of memory used by mtrie. */
uword
ip4_fib_mtrie_memory_usage (ip4_fib_mtrie_t * m)
{
  uword bytes, i;

  bytes = sizeof (*m);
  for (i = 0; i < ARRAY_LEN (m->root_ply.leaves); i++)
    {
      ip4_fib_mtrie_leaf_t l = m->root_ply.leaves[i];
      if (ip4_fib_mtrie_leaf_is_next_ply (l))
	bytes += mtrie_ply_memory_usage (m, get_next_ply_for_leaf (m, l));
    }

  return bytes;
}

static u8 *
format_ip4_fib_mtrie_leaf (u8 * s, va_list * va)
{
  ip4_fib_mtrie_leaf_t l = va_arg (*va, ip4_fib_mtrie_leaf_t);

  if (ip4_fib_mtrie_leaf_is_terminal (l))
    s = format (s, "lb-index %d", ip4_fib_mtrie_leaf_get_adj_index (l));
  else
    s = format (s, "next ply %d", ip4_fib_mtrie_leaf_get_next_ply_index (l));
  return s;
}

#define FORMAT_PLY(s, _p, _i, _base_address, _ply_max_len, _indent)     \
({                                                                      \
  u32 a, ia_length;                                                     \
  ip4_address_t ia;                                                     \
  ip4_fib_mtrie_leaf_t _l = p->leaves[(_i)];                            \
                                                                        \
  a = (_base_address) + ((_i) << (32 - (_ply_max_len)));                \
  ia.as_u32 = clib_host_to_net_u32 (a);                                 \
  ia_length = (_p)->dst_address_bits_of_leaves[(_i)];                   \
  s = format (s, "\n%U%20U %U",                                         \
              format_white_space, (_indent) + 2,                        \
              format_ip4_address_and_length, &ia, ia_length,            \
              format_ip4_fib_mtrie_leaf, _l);                           \
                                                                        \
  if (ip4_fib_mtrie_leaf_is_next_ply (_l))                              \
    s = format (s, "\n%U%U",                                            \
                format_white_space, (_indent) + 2,                      \
                format_ip4_fib_mtrie_ply, m, a,                         \
                ip4_fib_mtrie_leaf_get_next_ply_index (_l));            \
  s;                                                                    \
})

static u8 *
format_ip4_fib_mtrie_ply (u8 * s, va_list * va)
{
  ip4_fib_mtrie_t *m = va_arg (*va, ip4_fib_mtrie_t *);
  u32 base_address = va_arg (*va, u32);
  u32 ply_index = va_arg (*va, u32);
  ip4_fib_mtrie_8_ply_t *p;
  u32 indent;
  int i;

  p = pool_elt_at_index (ip4_ply_pool, ply_index);
  indent = format_get_indent (s);
  s = format (s, "ply index %d, %d non-empty leaves", ply_index,
	      p->n_non_empty_leafs);

  for (i = 0; i < ARRAY_LEN (p->leaves); i++)
    {
      if (ip4_fib_mtrie_leaf_is_non_empty (p, i))
	{
	  FORMAT_PLY (s, p, i, base_address,
		      p->dst_address_bits_base + 8, indent);
	}
    }

  return s;
}

u8 *
format_ip4_fib_mtrie (u8 * s, va_list * va)
{
  ip4_fib_mtrie_t *m = va_arg (*va, ip4_fib_mtrie_t *);
  int verbose = va_arg (*va, int);
  ip4_fib_mtrie_16_ply_t *p;
  u32 base_address = 0;
  int i;

  s = format (s, "%d plies, memory usage %U\n",
	      pool_elts (ip4_ply_pool),
	      format_memory_size, ip4_fib_mtrie_memory_usage (m));
  s = format (s, "root-ply");
  p = &m->root_ply;

  if (verbose)
    {
      s = format (s, "root-ply");
      p = &m->root_ply;

      for (i = 0; i < ARRAY_LEN (p->leaves); i++)
	{
	  u16 slot;

	  slot = clib_host_to_net_u16 (i);

	  if (p->dst_address_bits_of_leaves[slot] > 0)
	    {
	      FORMAT_PLY (s, p, slot, base_address, 16, 2);
	    }
	}
    }

  return s;
}

static clib_error_t *
ip4_mtrie_module_init (vlib_main_t * vm)
{
  /* Burn one ply so index 0 is taken */
  CLIB_UNUSED (ip4_fib_mtrie_8_ply_t * p);

  pool_get (ip4_ply_pool, p);

  return (NULL);
}

VLIB_INIT_FUNCTION (ip4_mtrie_module_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
