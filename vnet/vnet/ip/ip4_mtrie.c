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

static void
ply_init (ip4_fib_mtrie_ply_t * p, ip4_fib_mtrie_leaf_t init, uword prefix_len)
{
  p->n_non_empty_leafs = ip4_fib_mtrie_leaf_is_empty (init) ? 0 : ARRAY_LEN (p->leaves);
  memset (p->dst_address_bits_of_leaves, prefix_len, sizeof (p->dst_address_bits_of_leaves));

  /* Initialize leaves. */
#ifdef CLIB_HAVE_VEC128
  {
    u32x4 * l, init_x4;

#ifndef __ALTIVEC__
    init_x4 = u32x4_splat (init);
#else
    {
      u32x4_union_t y;
      y.as_u32[0] = init;
      y.as_u32[1] = init;
      y.as_u32[2] = init;
      y.as_u32[3] = init;
      init_x4 = y.as_u32x4;
    }
#endif    

    for (l = p->leaves_as_u32x4; l < p->leaves_as_u32x4 + ARRAY_LEN (p->leaves_as_u32x4); l += 4)
      {
	l[0] = init_x4;
	l[1] = init_x4;
	l[2] = init_x4;
	l[3] = init_x4;
      }
  }
#else
  {
    u32 * l;

    for (l = p->leaves; l < p->leaves + ARRAY_LEN (p->leaves); l += 4)
      {
	l[0] = init;
	l[1] = init;
	l[2] = init;
	l[3] = init;
      }
  }
#endif
}

static ip4_fib_mtrie_leaf_t
ply_create (ip4_fib_mtrie_t * m, ip4_fib_mtrie_leaf_t init_leaf, uword prefix_len)
{
  ip4_fib_mtrie_ply_t * p;

  /* Get cache aligned ply. */
  pool_get_aligned (m->ply_pool, p, sizeof (p[0]));

  ply_init (p, init_leaf, prefix_len);
  return ip4_fib_mtrie_leaf_set_next_ply_index (p - m->ply_pool);
}

always_inline ip4_fib_mtrie_ply_t *
get_next_ply_for_leaf (ip4_fib_mtrie_t * m, ip4_fib_mtrie_leaf_t l)
{
  uword n = ip4_fib_mtrie_leaf_get_next_ply_index (l);
  /* It better not be the root ply. */
  ASSERT (n != 0);
  return pool_elt_at_index (m->ply_pool, n);
}

static void
ply_free (ip4_fib_mtrie_t * m, ip4_fib_mtrie_ply_t * p)
{
  uword i, is_root;

  is_root = p - m->ply_pool == 0;

  for (i = 0 ; i < ARRAY_LEN (p->leaves); i++)
    {
      ip4_fib_mtrie_leaf_t l = p->leaves[i];
      if (ip4_fib_mtrie_leaf_is_next_ply (l))
	ply_free (m, get_next_ply_for_leaf (m, l));
    }      

  if (is_root)
    ply_init (p, IP4_FIB_MTRIE_LEAF_EMPTY, /* prefix_len */ 0);
  else
    pool_put (m->ply_pool, p);
}

void ip4_fib_free (ip4_fib_mtrie_t * m)
{
  ip4_fib_mtrie_ply_t * root_ply = pool_elt_at_index (m->ply_pool, 0);
  ply_free (m, root_ply);
}

u32 ip4_mtrie_lookup_address (ip4_fib_mtrie_t * m, ip4_address_t dst)
{
  ip4_fib_mtrie_ply_t * p = pool_elt_at_index (m->ply_pool, 0);
  ip4_fib_mtrie_leaf_t l;

  l = p->leaves[dst.as_u8[0]];
  if (ip4_fib_mtrie_leaf_is_terminal (l))
    return ip4_fib_mtrie_leaf_get_adj_index (l);

  p = get_next_ply_for_leaf (m, l);
  l = p->leaves[dst.as_u8[1]];
  if (ip4_fib_mtrie_leaf_is_terminal (l))
    return ip4_fib_mtrie_leaf_get_adj_index (l);

  p = get_next_ply_for_leaf (m, l);
  l = p->leaves[dst.as_u8[2]];
  if (ip4_fib_mtrie_leaf_is_terminal (l))
    return ip4_fib_mtrie_leaf_get_adj_index (l);

  p = get_next_ply_for_leaf (m, l);
  l = p->leaves[dst.as_u8[3]];

  ASSERT (ip4_fib_mtrie_leaf_is_terminal (l));
  return ip4_fib_mtrie_leaf_get_adj_index (l);
}

typedef struct {
  ip4_address_t dst_address;
  u32 dst_address_length;
  u32 adj_index;
} ip4_fib_mtrie_set_unset_leaf_args_t;

static void
set_ply_with_more_specific_leaf (ip4_fib_mtrie_t * m,
				 ip4_fib_mtrie_ply_t * ply,
				 ip4_fib_mtrie_leaf_t new_leaf,
				 uword new_leaf_dst_address_bits)
{
  ip4_fib_mtrie_leaf_t old_leaf;
  uword i;

  ASSERT (ip4_fib_mtrie_leaf_is_terminal (new_leaf));
  ASSERT (! ip4_fib_mtrie_leaf_is_empty (new_leaf));

  for (i = 0; i < ARRAY_LEN (ply->leaves); i++)
    {
      old_leaf = ply->leaves[i];

      /* Recurse into sub plies. */
      if (! ip4_fib_mtrie_leaf_is_terminal (old_leaf))
	{
	  ip4_fib_mtrie_ply_t * sub_ply = get_next_ply_for_leaf (m, old_leaf);
	  set_ply_with_more_specific_leaf (m, sub_ply, new_leaf, new_leaf_dst_address_bits);
	}

      /* Replace less specific terminal leaves with new leaf. */
      else if (new_leaf_dst_address_bits >= ply->dst_address_bits_of_leaves[i])
	{
          __sync_val_compare_and_swap (&ply->leaves[i], old_leaf, new_leaf);
          ASSERT(ply->leaves[i] == new_leaf);
	  ply->dst_address_bits_of_leaves[i] = new_leaf_dst_address_bits;
	  ply->n_non_empty_leafs += ip4_fib_mtrie_leaf_is_empty (old_leaf);
	}
    }
}

static void
set_leaf (ip4_fib_mtrie_t * m,
	  ip4_fib_mtrie_set_unset_leaf_args_t * a,
	  u32 old_ply_index,
	  u32 dst_address_byte_index)
{
  ip4_fib_mtrie_leaf_t old_leaf, new_leaf;
  i32 n_dst_bits_next_plies;
  u8 dst_byte;

  ASSERT (a->dst_address_length > 0 && a->dst_address_length <= 32);
  ASSERT (dst_address_byte_index < ARRAY_LEN (a->dst_address.as_u8));

  n_dst_bits_next_plies = a->dst_address_length - BITS (u8) * (dst_address_byte_index + 1);

  dst_byte = a->dst_address.as_u8[dst_address_byte_index];

  /* Number of bits next plies <= 0 => insert leaves this ply. */
  if (n_dst_bits_next_plies <= 0)
    {
      uword i, n_dst_bits_this_ply, old_leaf_is_terminal;

      n_dst_bits_this_ply = -n_dst_bits_next_plies;
      ASSERT ((a->dst_address.as_u8[dst_address_byte_index] & pow2_mask (n_dst_bits_this_ply)) == 0);

      for (i = dst_byte; i < dst_byte + (1 << n_dst_bits_this_ply); i++)
	{
	  ip4_fib_mtrie_ply_t * old_ply, * new_ply;

	  old_ply = pool_elt_at_index (m->ply_pool, old_ply_index);

	  old_leaf = old_ply->leaves[i];
	  old_leaf_is_terminal = ip4_fib_mtrie_leaf_is_terminal (old_leaf);

	  /* Is leaf to be inserted more specific? */
	  if (a->dst_address_length >= old_ply->dst_address_bits_of_leaves[i])
	    {
	      new_leaf = ip4_fib_mtrie_leaf_set_adj_index (a->adj_index);

	      if (old_leaf_is_terminal)
		{
		  old_ply->dst_address_bits_of_leaves[i] = a->dst_address_length;
                  __sync_val_compare_and_swap (&old_ply->leaves[i], old_leaf,
                                               new_leaf);
                  ASSERT(old_ply->leaves[i] == new_leaf);
		  old_ply->n_non_empty_leafs += ip4_fib_mtrie_leaf_is_empty (old_leaf);
		  ASSERT (old_ply->n_non_empty_leafs <= ARRAY_LEN (old_ply->leaves));
		}
	      else
		{
		  /* Existing leaf points to another ply.  We need to place new_leaf into all
		     more specific slots. */
		  new_ply = get_next_ply_for_leaf (m, old_leaf);
		  set_ply_with_more_specific_leaf (m, new_ply, new_leaf, a->dst_address_length);
		}
	    }

	  else if (! old_leaf_is_terminal)
	    {
	      new_ply = get_next_ply_for_leaf (m, old_leaf);
	      set_leaf (m, a, new_ply - m->ply_pool, dst_address_byte_index + 1);
	    }
	}
    }
  else
    {
      ip4_fib_mtrie_ply_t * old_ply, * new_ply;

      old_ply = pool_elt_at_index (m->ply_pool, old_ply_index);
      old_leaf = old_ply->leaves[dst_byte];
      if (ip4_fib_mtrie_leaf_is_terminal (old_leaf))
	{
	  new_leaf = ply_create (m, old_leaf, old_ply->dst_address_bits_of_leaves[dst_byte]);
	  new_ply = get_next_ply_for_leaf (m, new_leaf);

	  /* Refetch since ply_create may move pool. */
	  old_ply = pool_elt_at_index (m->ply_pool, old_ply_index);

          __sync_val_compare_and_swap (&old_ply->leaves[dst_byte], old_leaf,
                                       new_leaf);
          ASSERT(old_ply->leaves[dst_byte] == new_leaf);
	  old_ply->dst_address_bits_of_leaves[dst_byte] = 0;

	  old_ply->n_non_empty_leafs -= ip4_fib_mtrie_leaf_is_non_empty (old_leaf);
	  ASSERT (old_ply->n_non_empty_leafs >= 0);

	  /* Account for the ply we just created. */
	  old_ply->n_non_empty_leafs += 1;
	}
      else
	new_ply = get_next_ply_for_leaf (m, old_leaf);

      set_leaf (m, a, new_ply - m->ply_pool, dst_address_byte_index + 1);
    }
}

static uword
unset_leaf (ip4_fib_mtrie_t * m,
	    ip4_fib_mtrie_set_unset_leaf_args_t * a,
	    ip4_fib_mtrie_ply_t * old_ply,
	    u32 dst_address_byte_index)
{
  ip4_fib_mtrie_leaf_t old_leaf, del_leaf;
  i32 n_dst_bits_next_plies;
  uword i, n_dst_bits_this_ply, old_leaf_is_terminal;
  u8 dst_byte;

  ASSERT (a->dst_address_length > 0 && a->dst_address_length <= 32);
  ASSERT (dst_address_byte_index < ARRAY_LEN (a->dst_address.as_u8));

  n_dst_bits_next_plies = a->dst_address_length - BITS (u8) * (dst_address_byte_index + 1);

  dst_byte = a->dst_address.as_u8[dst_address_byte_index];
  if (n_dst_bits_next_plies < 0)
    dst_byte &= ~pow2_mask (-n_dst_bits_next_plies);

  n_dst_bits_this_ply = n_dst_bits_next_plies <= 0 ? -n_dst_bits_next_plies : 0;
  n_dst_bits_this_ply = clib_min (8, n_dst_bits_this_ply);

  del_leaf = ip4_fib_mtrie_leaf_set_adj_index (a->adj_index);

  for (i = dst_byte; i < dst_byte + (1 << n_dst_bits_this_ply); i++)
    {
      old_leaf = old_ply->leaves[i];
      old_leaf_is_terminal = ip4_fib_mtrie_leaf_is_terminal (old_leaf);

      if (old_leaf == del_leaf
	  || (! old_leaf_is_terminal
	      && unset_leaf (m, a, get_next_ply_for_leaf (m, old_leaf), dst_address_byte_index + 1)))
	{
	  old_ply->leaves[i] = IP4_FIB_MTRIE_LEAF_EMPTY;
	  old_ply->dst_address_bits_of_leaves[i] = 0;

	  /* No matter what we just deleted a non-empty leaf. */
	  ASSERT (! ip4_fib_mtrie_leaf_is_empty (old_leaf));
	  old_ply->n_non_empty_leafs -= 1;

	  ASSERT (old_ply->n_non_empty_leafs >= 0);
	  if (old_ply->n_non_empty_leafs == 0 && dst_address_byte_index > 0)
	    {
	      pool_put (m->ply_pool, old_ply);
	      /* Old ply was deleted. */
	      return 1;
	    }
	}
    }

  /* Old ply was not deleted. */
  return 0;
}

void ip4_mtrie_init (ip4_fib_mtrie_t * m)
{
  ip4_fib_mtrie_leaf_t root;
  memset (m, 0, sizeof (m[0]));
  m->default_leaf = IP4_FIB_MTRIE_LEAF_EMPTY;
  root = ply_create (m, IP4_FIB_MTRIE_LEAF_EMPTY, /* dst_address_bits_of_leaves */ 0);
  ASSERT (ip4_fib_mtrie_leaf_get_next_ply_index (root) == 0);
}

void
ip4_fib_mtrie_add_del_route (ip4_fib_t * fib,
			     ip4_address_t dst_address,
			     u32 dst_address_length,
			     u32 adj_index,
			     u32 is_del)
{
  ip4_fib_mtrie_t * m = &fib->mtrie;
  ip4_fib_mtrie_ply_t * root_ply;
  ip4_fib_mtrie_set_unset_leaf_args_t a;
  ip4_main_t * im = &ip4_main;

  ASSERT(m->ply_pool != 0);

  root_ply = pool_elt_at_index (m->ply_pool, 0);

  /* Honor dst_address_length. Fib masks are in network byte order */
  dst_address.as_u32 &= im->fib_masks[dst_address_length];
  a.dst_address = dst_address;
  a.dst_address_length = dst_address_length;
  a.adj_index = adj_index;

  if (! is_del)
    {
      if (dst_address_length == 0)
	m->default_leaf = ip4_fib_mtrie_leaf_set_adj_index (adj_index);
      else
	set_leaf (m, &a, /* ply_index */ 0, /* dst_address_byte_index */ 0);
    }
  else
    {
      if (dst_address_length == 0)
	m->default_leaf = IP4_FIB_MTRIE_LEAF_EMPTY;

      else
	{
	  ip4_main_t * im = &ip4_main;
	  uword i;

	  unset_leaf (m, &a, root_ply, 0);

	  /* Find next less specific route and insert into mtrie. */
	  for (i = ARRAY_LEN (fib->adj_index_by_dst_address) - 1; i >= 1; i--)
	    {
	      uword * p;
	      ip4_address_t key;

	      if (! fib->adj_index_by_dst_address[i])
		continue;
	      
	      key.as_u32 = dst_address.as_u32 & im->fib_masks[i];
	      p = hash_get (fib->adj_index_by_dst_address[i], key.as_u32);
	      if (p)
		{
		  a.dst_address = key;
		  a.dst_address_length = i;
		  a.adj_index = p[0];
		  set_leaf (m, &a, /* ply_index */ 0, /* dst_address_byte_index */ 0);
		  break;
		}
	    }
	}
    }
}

always_inline uword
maybe_remap_leaf (ip_lookup_main_t * lm, ip4_fib_mtrie_leaf_t * p)
{
  ip4_fib_mtrie_leaf_t l = p[0];
  uword was_remapped_to_empty_leaf = 0;
  if (ip4_fib_mtrie_leaf_is_terminal (l))
    {
      u32 adj_index = ip4_fib_mtrie_leaf_get_adj_index (l);
      u32 m = vec_elt (lm->adjacency_remap_table, adj_index);
      if (m)
	{
	  was_remapped_to_empty_leaf = m == ~0;
	  if (was_remapped_to_empty_leaf)
	    p[0] = (was_remapped_to_empty_leaf
		    ? IP4_FIB_MTRIE_LEAF_EMPTY
		    : ip4_fib_mtrie_leaf_set_adj_index (m - 1));
	}
    }
  return was_remapped_to_empty_leaf;
}

static void maybe_remap_ply (ip_lookup_main_t * lm, ip4_fib_mtrie_ply_t * ply)
{
  u32 n_remapped_to_empty = 0;
  u32 i;
  for (i = 0; i < ARRAY_LEN (ply->leaves); i++)
    n_remapped_to_empty += maybe_remap_leaf (lm, &ply->leaves[i]);
  if (n_remapped_to_empty > 0)
    {
      ASSERT (n_remapped_to_empty <= ply->n_non_empty_leafs);
      ply->n_non_empty_leafs -= n_remapped_to_empty;
      if (ply->n_non_empty_leafs == 0)
	os_panic ();
    }
}

void ip4_mtrie_maybe_remap_adjacencies (ip_lookup_main_t * lm, ip4_fib_mtrie_t * m)
{
  ip4_fib_mtrie_ply_t * ply;
  pool_foreach (ply, m->ply_pool, maybe_remap_ply (lm, ply));
  maybe_remap_leaf (lm, &m->default_leaf);
}

/* Returns number of bytes of memory used by mtrie. */
static uword mtrie_memory_usage (ip4_fib_mtrie_t * m, ip4_fib_mtrie_ply_t * p)
{
  uword bytes, i;

  if (! p)
    {
      if (pool_is_free_index (m->ply_pool, 0))
	return 0;
      p = pool_elt_at_index (m->ply_pool, 0);
    }

  bytes = sizeof (p[0]);
  for (i = 0 ; i < ARRAY_LEN (p->leaves); i++)
    {
      ip4_fib_mtrie_leaf_t l = p->leaves[i];
      if (ip4_fib_mtrie_leaf_is_next_ply (l))
	bytes += mtrie_memory_usage (m, get_next_ply_for_leaf (m, l));
    }

  return bytes;
}

static u8 * format_ip4_fib_mtrie_leaf (u8 * s, va_list * va)
{
  ip4_fib_mtrie_leaf_t l = va_arg (*va, ip4_fib_mtrie_leaf_t);

  if (ip4_fib_mtrie_leaf_is_empty (l))
    s = format (s, "miss");
  else if (ip4_fib_mtrie_leaf_is_terminal (l))
    s = format (s, "adj %d", ip4_fib_mtrie_leaf_get_adj_index (l));
  else
    s = format (s, "next ply %d", ip4_fib_mtrie_leaf_get_next_ply_index (l));
  return s;
}

static u8 * format_ip4_fib_mtrie_ply (u8 * s, va_list * va)
{
  ip4_fib_mtrie_t * m = va_arg (*va, ip4_fib_mtrie_t *);
  u32 base_address = va_arg (*va, u32);
  u32 ply_index = va_arg (*va, u32);
  u32 dst_address_byte_index = va_arg (*va, u32);
  ip4_fib_mtrie_ply_t * p;
  uword i, indent;

  p = pool_elt_at_index (m->ply_pool, ply_index);
  indent = format_get_indent (s);
  s = format (s, "ply index %d, %d non-empty leaves", ply_index, p->n_non_empty_leafs);
  for (i = 0; i < ARRAY_LEN (p->leaves); i++)
    {
      ip4_fib_mtrie_leaf_t l = p->leaves[i];

      if (! ip4_fib_mtrie_leaf_is_empty (l))
	{
	  u32 a, ia_length;
	  ip4_address_t ia;

	  a = base_address + (i << (24 - 8*dst_address_byte_index));
	  ia.as_u32 = clib_host_to_net_u32 (a);
	  if (ip4_fib_mtrie_leaf_is_terminal (l))
	    ia_length = p->dst_address_bits_of_leaves[i];
	  else
	    ia_length = 8*(1 + dst_address_byte_index);
	  s = format (s, "\n%U%20U %U",
		      format_white_space, indent + 2,
		      format_ip4_address_and_length, &ia, ia_length,
		      format_ip4_fib_mtrie_leaf, l);

	  if (ip4_fib_mtrie_leaf_is_next_ply (l))
	    s = format (s, "\n%U%U",
			format_white_space, indent + 2,
			format_ip4_fib_mtrie_ply, m, a,
			ip4_fib_mtrie_leaf_get_next_ply_index (l),
			dst_address_byte_index + 1);
	}
    }

  return s;
}

u8 * format_ip4_fib_mtrie (u8 * s, va_list * va)
{
  ip4_fib_mtrie_t * m = va_arg (*va, ip4_fib_mtrie_t *);

  s = format (s, "%d plies, memory usage %U",
	      pool_elts (m->ply_pool),
	      format_memory_size, mtrie_memory_usage (m, 0));

  if (pool_elts (m->ply_pool) > 0)
    {
      ip4_address_t base_address;
      base_address.as_u32 = 0;
      s = format (s, "\n  %U", format_ip4_fib_mtrie_ply, m, base_address, 0, 0);
    }

  return s;
}
