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
  Copyright (c) 2005 Eliot Dresselhaus

  Permission is hereby granted, free of charge, to any person obtaining
  a copy of this software and associated documentation files (the
  "Software"), to deal in the Software without restriction, including
  without limitation the rights to use, copy, modify, merge, publish,
  distribute, sublicense, and/or sell copies of the Software, and to
  permit persons to whom the Software is furnished to do so, subject to
  the following conditions:

  The above copyright notice and this permission notice shall be
  included in all copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
  NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
  LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
  OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
  WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

/* This is all stolen from Bob Jenkins and reworked for clib.  Thanks
   once again Bob for the great work. */

/*
------------------------------------------------------------------------------
perfect.c: code to generate code for a hash for perfect hashing.
(c) Bob Jenkins, September 1996, December 1999
You may use this code in any way you wish, and it is free.  No warranty.
I hereby place this in the public domain.
Source is http://burtleburtle.net/bob/c/perfect.c

This generates a minimal perfect hash function.  That means, given a
set of n keys, this determines a hash function that maps each of
those keys into a value in 0..n-1 with no collisions.

The perfect hash function first uses a normal hash function on the key
to determine (a,b) such that the pair (a,b) is distinct for all
keys, then it computes a^scramble[tab[b]] to get the final perfect hash.
tab[] is an array of 1-byte values and scramble[] is a 256-term array of
2-byte or 4-byte values.  If there are n keys, the length of tab[] is a
power of two between n/3 and n.

I found the idea of computing distinct (a,b) values in "Practical minimal
perfect hash functions for large databases", Fox, Heath, Chen, and Daoud,
Communications of the ACM, January 1992.  They found the idea in Chichelli
(CACM Jan 1980).  Beyond that, our methods differ.

The key is hashed to a pair (a,b) where a in 0..*alen*-1 and b in
0..*blen*-1.  A fast hash function determines both a and b
simultaneously.  Any decent hash function is likely to produce
hashes so that (a,b) is distinct for all pairs.  I try the hash
using different values of *salt* until all pairs are distinct.

The final hash is (a XOR scramble[tab[b]]).  *scramble* is a
predetermined mapping of 0..255 into 0..smax-1.  *tab* is an
array that we fill in in such a way as to make the hash perfect.

First we fill in all values of *tab* that are used by more than one
key.  We try all possible values for each position until one works.

This leaves m unmapped keys and m values that something could hash to.
If you treat unmapped keys as lefthand nodes and unused hash values
as righthand nodes, and draw a line connecting each key to each hash
value it could map to, you get a bipartite graph.  We attempt to
find a perfect matching in this graph.  If we succeed, we have
determined a perfect hash for the whole set of keys.

*scramble* is used because (a^tab[i]) clusters keys around *a*.
------------------------------------------------------------------------------
*/

#include <vppinfra/bitmap.h>
#include <vppinfra/format.h>
#include <vppinfra/phash.h>
#include <vppinfra/random.h>

static void
init_keys_direct_u32 (phash_main_t * pm)
{
  int n_keys_left, b_mask, a_shift;
  u32 seed;
  phash_key_t *k;

  seed = pm->hash_seed;
  b_mask = (1 << pm->b_bits) - 1;
  a_shift = BITS (seed) - pm->a_bits;

  k = pm->keys;
  n_keys_left = vec_len (pm->keys);

  while (n_keys_left >= 2)
    {
      u32 x0, y0, z0;
      u32 x1, y1, z1;

      x0 = y0 = z0 = seed;
      x1 = y1 = z1 = seed;
      x0 += (u32) k[0].key;
      x1 += (u32) k[1].key;

      hash_mix32 (x0, y0, z0);
      hash_mix32 (x1, y1, z1);

      k[0].b = z0 & b_mask;
      k[1].b = z1 & b_mask;
      k[0].a = z0 >> a_shift;
      k[1].a = z1 >> a_shift;
      if (PREDICT_FALSE (a_shift >= BITS (z0)))
	k[0].a = k[1].a = 0;

      k += 2;
      n_keys_left -= 2;
    }

  if (n_keys_left >= 1)
    {
      u32 x0, y0, z0;

      x0 = y0 = z0 = seed;
      x0 += k[0].key;

      hash_mix32 (x0, y0, z0);

      k[0].b = z0 & b_mask;
      k[0].a = z0 >> a_shift;
      if (PREDICT_FALSE (a_shift >= BITS (z0)))
	k[0].a = 0;

      k += 1;
      n_keys_left -= 1;
    }
}

static void
init_keys_direct_u64 (phash_main_t * pm)
{
  int n_keys_left, b_mask, a_shift;
  u64 seed;
  phash_key_t *k;

  seed = pm->hash_seed;
  b_mask = (1 << pm->b_bits) - 1;
  a_shift = BITS (seed) - pm->a_bits;

  k = pm->keys;
  n_keys_left = vec_len (pm->keys);

  while (n_keys_left >= 2)
    {
      u64 x0, y0, z0;
      u64 x1, y1, z1;

      x0 = y0 = z0 = seed;
      x1 = y1 = z1 = seed;
      x0 += (u64) k[0].key;
      x1 += (u64) k[1].key;

      hash_mix64 (x0, y0, z0);
      hash_mix64 (x1, y1, z1);

      k[0].b = z0 & b_mask;
      k[1].b = z1 & b_mask;
      k[0].a = z0 >> a_shift;
      k[1].a = z1 >> a_shift;
      if (PREDICT_FALSE (a_shift >= BITS (z0)))
	k[0].a = k[1].a = 0;

      k += 2;
      n_keys_left -= 2;
    }

  if (n_keys_left >= 1)
    {
      u64 x0, y0, z0;

      x0 = y0 = z0 = seed;
      x0 += k[0].key;

      hash_mix64 (x0, y0, z0);

      k[0].b = z0 & b_mask;
      k[0].a = z0 >> a_shift;
      if (PREDICT_FALSE (a_shift >= BITS (z0)))
	k[0].a = 0;

      k += 1;
      n_keys_left -= 1;
    }
}

static void
init_keys_indirect_u32 (phash_main_t * pm)
{
  int n_keys_left, b_mask, a_shift;
  u32 seed;
  phash_key_t *k;

  seed = pm->hash_seed;
  b_mask = (1 << pm->b_bits) - 1;
  a_shift = BITS (seed) - pm->a_bits;

  k = pm->keys;
  n_keys_left = vec_len (pm->keys);

  while (n_keys_left >= 2)
    {
      u32 xyz[6];
      u32 x0, y0, z0;
      u32 x1, y1, z1;

      pm->key_seed2 (pm->private, k[0].key, k[1].key, &xyz);

      x0 = y0 = z0 = seed;
      x1 = y1 = z1 = seed;
      x0 += xyz[0];
      y0 += xyz[1];
      z0 += xyz[2];
      x1 += xyz[3];
      y1 += xyz[4];
      z1 += xyz[5];

      hash_mix32 (x0, y0, z0);
      hash_mix32 (x1, y1, z1);

      k[0].b = z0 & b_mask;
      k[1].b = z1 & b_mask;
      k[0].a = z0 >> a_shift;
      k[1].a = z1 >> a_shift;
      if (PREDICT_FALSE (a_shift >= BITS (z0)))
	k[0].a = k[1].a = 0;

      k += 2;
      n_keys_left -= 2;
    }

  if (n_keys_left >= 1)
    {
      u32 xyz[3];
      u32 x0, y0, z0;

      pm->key_seed1 (pm->private, k[0].key, &xyz);

      x0 = y0 = z0 = seed;
      x0 += xyz[0];
      y0 += xyz[1];
      z0 += xyz[2];

      hash_mix32 (x0, y0, z0);

      k[0].b = z0 & b_mask;
      k[0].a = z0 >> a_shift;
      if (PREDICT_FALSE (a_shift >= BITS (z0)))
	k[0].a = 0;

      k += 1;
      n_keys_left -= 1;
    }
}

static void
init_keys_indirect_u64 (phash_main_t * pm)
{
  int n_keys_left, b_mask, a_shift;
  u64 seed;
  phash_key_t *k;

  seed = pm->hash_seed;
  b_mask = (1 << pm->b_bits) - 1;
  a_shift = BITS (seed) - pm->a_bits;

  k = pm->keys;
  n_keys_left = vec_len (pm->keys);

  while (n_keys_left >= 2)
    {
      u64 xyz[6];
      u64 x0, y0, z0;
      u64 x1, y1, z1;

      pm->key_seed2 (pm->private, k[0].key, k[1].key, &xyz);

      x0 = y0 = z0 = seed;
      x1 = y1 = z1 = seed;
      x0 += xyz[0];
      y0 += xyz[1];
      z0 += xyz[2];
      x1 += xyz[3];
      y1 += xyz[4];
      z1 += xyz[5];

      hash_mix64 (x0, y0, z0);
      hash_mix64 (x1, y1, z1);

      k[0].b = z0 & b_mask;
      k[1].b = z1 & b_mask;
      k[0].a = z0 >> a_shift;
      k[1].a = z1 >> a_shift;
      if (PREDICT_FALSE (a_shift >= BITS (z0)))
	k[0].a = k[1].a = 0;

      k += 2;
      n_keys_left -= 2;
    }

  if (n_keys_left >= 1)
    {
      u64 xyz[3];
      u64 x0, y0, z0;

      pm->key_seed1 (pm->private, k[0].key, &xyz);

      x0 = y0 = z0 = seed;
      x0 += xyz[0];
      y0 += xyz[1];
      z0 += xyz[2];

      hash_mix64 (x0, y0, z0);

      k[0].b = z0 & b_mask;
      k[0].a = z0 >> a_shift;
      if (PREDICT_FALSE (a_shift >= BITS (z0)))
	k[0].a = 0;

      k += 1;
      n_keys_left -= 1;
    }
}

/*
 * insert keys into table according to key->b
 * check if the initial hash might work
 */
static int
init_tabb (phash_main_t * pm)
{
  int no_collisions;
  phash_tabb_t *tb;
  phash_key_t *k, *l;

  if (pm->key_seed1)
    {
      if (pm->flags & PHASH_FLAG_MIX64)
	init_keys_indirect_u64 (pm);
      else
	init_keys_indirect_u32 (pm);
    }
  else
    {
      if (pm->flags & PHASH_FLAG_MIX64)
	init_keys_direct_u64 (pm);
      else
	init_keys_direct_u32 (pm);
    }

  if (!pm->tabb)
    vec_resize (pm->tabb, 1 << pm->b_bits);
  else
    vec_foreach (tb, pm->tabb) phash_tabb_free (tb);

  /* Two keys with the same (a,b) guarantees a collision */
  no_collisions = 1;
  vec_foreach (k, pm->keys)
  {
    u32 i, *ki;

    tb = pm->tabb + k->b;
    ki = tb->keys;
    for (i = 0; i < vec_len (ki); i++)
      {
	l = pm->keys + ki[i];
	if (k->a == l->a)
	  {
	    /* Given keys are supposed to be unique. */
	    if (pm->key_is_equal
		&& pm->key_is_equal (pm->private, l->key, k->key))
	      clib_error ("duplicate keys");
	    no_collisions = 0;
	    goto done;
	  }
      }

    vec_add1 (tb->keys, k - pm->keys);
  }

done:
  return no_collisions;
}

/* Try to apply an augmenting list */
static int
apply (phash_main_t * pm, u32 tail, u32 rollback)
{
  phash_key_t *k;
  phash_tabb_t *pb;
  phash_tabq_t *q_child, *q_parent;
  u32 ki, i, hash, child, parent;
  u32 stabb;			/* scramble[tab[b]] */
  int no_collision;

  no_collision = 1;

  /* Walk from child to parent until root is reached. */
  for (child = tail - 1; child; child = parent)
    {
      q_child = &pm->tabq[child];
      parent = q_child->parent_q;
      q_parent = &pm->tabq[parent];

      /* find parent's list of siblings */
      ASSERT (q_parent->b_q < vec_len (pm->tabb));
      pb = pm->tabb + q_parent->b_q;

      /* erase old hash values */
      stabb = pm->scramble[pb->val_b];
      for (i = 0; i < vec_len (pb->keys); i++)
	{
	  ki = pb->keys[i];
	  k = pm->keys + ki;
	  hash = k->a ^ stabb;

	  /* Erase hash for all of child's siblings. */
	  if (ki == pm->tabh[hash])
	    pm->tabh[hash] = ~0;
	}

      /* change pb->val_b, which will change the hashes of all parent siblings */
      pb->val_b = rollback ? q_child->oldval_q : q_child->newval_q;

      /* set new hash values */
      stabb = pm->scramble[pb->val_b];
      for (i = 0; i < vec_len (pb->keys); i++)
	{
	  ki = pb->keys[i];
	  k = pm->keys + ki;

	  hash = k->a ^ stabb;
	  if (rollback)
	    {
	      if (parent == 0)
		continue;	/* root never had a hash */
	    }
	  else if (pm->tabh[hash] != ~0)
	    {
	      /* Very rare case: roll back any changes. */
	      apply (pm, tail, /* rollback changes */ 1);
	      no_collision = 0;
	      goto done;
	    }
	  pm->tabh[hash] = ki;
	}
    }

done:
  return no_collision;
}


/*
-------------------------------------------------------------------------------
augment(): Add item to the mapping.

Construct a spanning tree of *b*s with *item* as root, where each
parent can have all its hashes changed (by some new val_b) with
at most one collision, and each child is the b of that collision.

I got this from Tarjan's "Data Structures and Network Algorithms".  The
path from *item* to a *b* that can be remapped with no collision is
an "augmenting path".  Change values of tab[b] along the path so that
the unmapped key gets mapped and the unused hash value gets used.

Assuming 1 key per b, if m out of n hash values are still unused,
you should expect the transitive closure to cover n/m nodes before
an unused node is found.  Sum(i=1..n)(n/i) is about nlogn, so expect
this approach to take about nlogn time to map all single-key b's.
-------------------------------------------------------------------------------

high_water: a value higher than any now in tabb[].water_b.
*/
static int
augment (phash_main_t * pm, u32 b_root, u32 high_water)
{
  u32 q;			/* current position walking through the queue */
  u32 tail;			/* tail of the queue.  0 is the head of the queue. */
  phash_tabb_t *tb_parent, *tb_child, *tb_hit;
  phash_key_t *k_parent, *k_child;
  u32 v, v_limit;		/* possible value for myb->val_b */
  u32 i, ki, hash;

  v_limit =
    1 << ((pm->flags & PHASH_FLAG_USE_SCRAMBLE) ? pm->s_bits : BITS (u8));

  /* Initialize the root of the spanning tree. */
  pm->tabq[0].b_q = b_root;
  tail = 1;

  /* construct the spanning tree by walking the queue, add children to tail */
  for (q = 0; q < tail; q++)
    {
      if ((pm->flags & PHASH_FLAG_FAST_MODE)
	  && !(pm->flags & PHASH_FLAG_MINIMAL) && q == 1)
	break;			/* don't do transitive closure */

      tb_parent = pm->tabb + pm->tabq[q].b_q;	/* the b for this node */

      for (v = 0; v < v_limit; v++)
	{
	  tb_child = 0;

	  for (i = 0; i < vec_len (tb_parent->keys); i++)
	    {
	      ki = tb_parent->keys[i];
	      k_parent = pm->keys + ki;

	      hash = k_parent->a ^ pm->scramble[v];
	      if (hash >= pm->hash_max)
		goto try_next_v;	/* hash code out of bounds => we can't use this v */

	      ki = pm->tabh[hash];
	      if (ki == ~0)
		continue;

	      k_child = pm->keys + ki;
	      tb_hit = pm->tabb + k_child->b;

	      if (tb_child)
		{
		  /* Hit at most one child b. */
		  if (tb_child == tb_hit)
		    goto try_next_v;
		}
	      else
		{
		  /* Remember this as child b. */
		  tb_child = tb_hit;
		  if (tb_hit->water_b == high_water)
		    goto try_next_v;	/* already explored */
		}
	    }

	  /* tb_parent with v has either one or zero collisions. */

	  /* add childb to the queue of reachable things */
	  if (tb_child)
	    tb_child->water_b = high_water;
	  pm->tabq[tail].b_q = tb_child ? tb_child - pm->tabb : ~0;
	  pm->tabq[tail].newval_q = v;	/* how to make parent (myb) use this hash */
	  pm->tabq[tail].oldval_q = tb_parent->val_b;	/* need this for rollback */
	  pm->tabq[tail].parent_q = q;
	  ++tail;

	  /* Found a v with no collisions? */
	  if (!tb_child)
	    {
	      /* Try to apply the augmenting path. */
	      if (apply (pm, tail, /* rollback */ 0))
		return 1;	/* success, item was added to the perfect hash */
	      --tail;		/* don't know how to handle such a child! */
	    }

	try_next_v:
	  ;
	}
    }
  return 0;
}


static phash_tabb_t *sort_tabb;

static int
phash_tabb_compare (void *a1, void *a2)
{
  u32 *b1 = a1;
  u32 *b2 = a2;
  phash_tabb_t *tb1, *tb2;

  tb1 = sort_tabb + b1[0];
  tb2 = sort_tabb + b2[0];

  return ((int) vec_len (tb2->keys) - (int) vec_len (tb1->keys));
}

/* find a mapping that makes this a perfect hash */
static int
perfect (phash_main_t * pm)
{
  u32 i;

  /* clear any state from previous attempts */
  if (vec_bytes (pm->tabh))
    memset (pm->tabh, ~0, vec_bytes (pm->tabh));

  vec_validate (pm->tabb_sort, vec_len (pm->tabb) - 1);
  for (i = 0; i < vec_len (pm->tabb_sort); i++)
    pm->tabb_sort[i] = i;

  sort_tabb = pm->tabb;

  vec_sort_with_function (pm->tabb_sort, phash_tabb_compare);

  /* In descending order by number of keys, map all *b*s */
  for (i = 0; i < vec_len (pm->tabb_sort); i++)
    {
      if (!augment (pm, pm->tabb_sort[i], i + 1))
	return 0;
    }

  /* Success!  We found a perfect hash of all keys into 0..nkeys-1. */
  return 1;
}


/*
 * Find initial a_bits = log2 (a_max), b_bits = log2 (b_max).
 * Initial a_max and b_max values were found empirically.  Some factors:
 *
 * If s_max<256 there is no scramble, so tab[b] needs to cover 0..s_max-1.
 *
 * a_max and b_max must be powers of 2 because the values in 0..a_max-1 and
 * 0..b_max-1 are produced by applying a bitmask to the initial hash function.
 *
 * a_max must be less than s_max, in fact less than n_keys, because otherwise
 * there would often be no i such that a^scramble[i] is in 0..n_keys-1 for
 * all the *a*s associated with a given *b*, so there would be no legal
 * value to assign to tab[b].  This only matters when we're doing a minimal
 * perfect hash.
 *
 * It takes around 800 trials to find distinct (a,b) with nkey=s_max*(5/8)
 * and a_max*b_max = s_max*s_max/32.
 *
 * Values of b_max less than s_max/4 never work, and s_max/2 always works.
 *
 * We want b_max as small as possible because it is the number of bytes in
 * the huge array we must create for the perfect hash.
 *
 * When nkey <= s_max*(5/8), b_max=s_max/4 works much more often with
 * a_max=s_max/8 than with a_max=s_max/4.  Above s_max*(5/8), b_max=s_max/4
 * doesn't seem to care whether a_max=s_max/8 or a_max=s_max/4.  I think it
 * has something to do with 5/8 = 1/8 * 5.  For example examine 80000,
 * 85000, and 90000 keys with different values of a_max.  This only matters
 * if we're doing a minimal perfect hash.
 *
 * When a_max*b_max <= 1<<U32BITS, the initial hash must produce one integer.
 * Bigger than that it must produce two integers, which increases the
 * cost of the hash per character hashed.
 */
static void
guess_initial_parameters (phash_main_t * pm)
{
  u32 s_bits, s_max, a_max, b_max, n_keys;
  int is_minimal, is_fast_mode;
  const u32 b_max_use_scramble_threshold = 4096;

  is_minimal = (pm->flags & PHASH_FLAG_MINIMAL) != 0;
  is_fast_mode = (pm->flags & PHASH_FLAG_FAST_MODE) != 0;

  n_keys = vec_len (pm->keys);
  s_bits = max_log2 (n_keys);
  s_max = 1 << s_bits;
  a_max = 0;

  if (is_minimal)
    {
      switch (s_bits)
	{
	case 0:
	  a_max = 1;
	  b_max = 1;
	case 1:
	case 2:
	case 3:
	case 4:
	case 5:
	case 6:
	case 7:
	case 8:
	  /*
	   * Was: a_max = is_minimal ? s_max / 2 : s_max;
	   * However, we know that is_minimal must be true, so the
	   * if-arm of the ternary expression is always executed.
	   */
	  a_max = s_max / 2;
	  b_max = s_max / 2;
	  break;
	case 9:
	case 10:
	case 11:
	case 12:
	case 13:
	case 14:
	case 15:
	case 16:
	case 17:
	  if (is_fast_mode)
	    {
	      a_max = s_max / 2;
	      b_max = s_max / 4;
	    }
	  else if (s_max / 4 < b_max_use_scramble_threshold)
	    {
	      if (n_keys <= s_max * 0.52)
		a_max = b_max = s_max / 8;
	      else
		a_max = b_max = s_max / 4;
	    }
	  else
	    {
	      a_max = ((n_keys <= s_max * (5.0 / 8.0)) ? s_max / 8 :
		       (n_keys <=
			s_max * (3.0 / 4.0)) ? s_max / 4 : s_max / 2);
	      b_max = s_max / 4;	/* always give the small size a shot */
	    }
	  break;
	case 18:
	  if (is_fast_mode)
	    a_max = b_max = s_max / 2;
	  else
	    {
	      a_max = s_max / 8;	/* never require the multiword hash */
	      b_max = (n_keys <= s_max * (5.0 / 8.0)) ? s_max / 4 : s_max / 2;
	    }
	  break;
	case 19:
	case 20:
	  a_max = (n_keys <= s_max * (5.0 / 8.0)) ? s_max / 8 : s_max / 2;
	  b_max = (n_keys <= s_max * (5.0 / 8.0)) ? s_max / 4 : s_max / 2;
	  break;
	default:
	  /* Just find a hash as quick as possible.
	     We'll be thrashing virtual memory at this size. */
	  a_max = b_max = s_max / 2;
	  break;
	}
    }
  else
    {
      /* Non-minimal perfect hash. */
      if (is_fast_mode && n_keys > s_max * 0.8)
	{
	  s_max *= 2;
	  s_bits += 1;
	}

      if (s_max / 4 <= (1 << 14))
	b_max = ((n_keys <= s_max * 0.56) ? s_max / 32 :
		 (n_keys <= s_max * 0.74) ? s_max / 16 : s_max / 8);
      else
	b_max = ((n_keys <= s_max * 0.6) ? s_max / 16 :
		 (n_keys <= s_max * 0.8) ? s_max / 8 : s_max / 4);

      if (is_fast_mode && b_max < s_max / 8)
	b_max = s_max / 8;

      if (a_max < 1)
	a_max = 1;
      if (b_max < 1)
	b_max = 1;
    }

  ASSERT (s_max == (1 << s_bits));
  ASSERT (is_pow2 (a_max));
  ASSERT (is_pow2 (b_max));
  pm->s_bits = s_bits;
  pm->a_bits = min_log2 (a_max);
  pm->b_bits = min_log2 (b_max);
  if (b_max >= b_max_use_scramble_threshold)
    pm->flags |= PHASH_FLAG_USE_SCRAMBLE;
}

/* compute p(x), where p is a permutation of 0..(1<<nbits)-1 */
/* permute(0)=0.  This is intended and useful. */
always_inline u32
scramble_permute (u32 x, u32 nbits)
{
  int i;
  int mask = (1 << nbits) - 1;
  int const2 = 1 + nbits / 2;
  int const3 = 1 + nbits / 3;
  int const4 = 1 + nbits / 4;
  int const5 = 1 + nbits / 5;
  for (i = 0; i < 20; i++)
    {
      x = (x + (x << const2)) & mask;
      x = (x ^ (x >> const3));
      x = (x + (x << const4)) & mask;
      x = (x ^ (x >> const5));
    }
  return x;
}

/* initialize scramble[] with distinct random values in 0..smax-1 */
static void
scramble_init (phash_main_t * pm)
{
  u32 i;

  /* fill scramble[] with distinct random integers in 0..smax-1 */
  vec_validate (pm->scramble, (1 << (pm->s_bits < 8 ? 8 : pm->s_bits)) - 1);
  for (i = 0; i < vec_len (pm->scramble); i++)
    pm->scramble[i] = scramble_permute (i, pm->s_bits);
}

/* Try to find a perfect hash function. */
clib_error_t *
phash_find_perfect_hash (phash_main_t * pm)
{
  clib_error_t *error = 0;
  u32 max_a_bits, n_tries_this_a_b, want_minimal;

  /* guess initial values for s_max, a_max and b_max */
  guess_initial_parameters (pm);

  want_minimal = pm->flags & PHASH_FLAG_MINIMAL;

new_s:
  if (pm->b_bits == 0)
    pm->a_bits = pm->s_bits;

  max_a_bits = pm->s_bits - want_minimal;
  if (max_a_bits < 1)
    max_a_bits = 1;

  pm->hash_max = want_minimal ? vec_len (pm->keys) : (1 << pm->s_bits);

  scramble_init (pm);

  /* Allocate working memory. */
  vec_free (pm->tabh);
  vec_validate_init_empty (pm->tabh, pm->hash_max - 1, ~0);
  vec_free (pm->tabq);
  vec_validate (pm->tabq, 1 << pm->b_bits);

  /* Actually find the perfect hash */
  n_tries_this_a_b = 0;
  while (1)
    {
      /* Choose random hash seeds until keys become unique. */
      pm->hash_seed = random_u64 (&pm->random_seed);
      pm->n_seed_trials++;
      if (init_tabb (pm))
	{
	  /* Found unique (A, B). */

	  /* Hash may already be perfect. */
	  if (pm->b_bits == 0)
	    goto done;

	  pm->n_perfect_calls++;
	  if (perfect (pm))
	    goto done;

	  goto increase_b;
	}

      /* Keep trying with different seed value. */
      n_tries_this_a_b++;
      if (n_tries_this_a_b < 2048)
	continue;

      /* Try to put more bits in (A,B) to make distinct (A,B) more likely */
      if (pm->a_bits < max_a_bits)
	pm->a_bits++;
      else if (pm->b_bits < pm->s_bits)
	{
	increase_b:
	  vec_resize (pm->tabb, vec_len (pm->tabb));
	  vec_resize (pm->tabq, vec_len (pm->tabq));
	  pm->b_bits++;
	}
      else
	{
	  /* Can't increase (A, B) any more, so try increasing S. */
	  goto new_s;
	}
    }

done:
  /* Construct mapping table for hash lookups. */
  if (!error)
    {
      u32 b, v;

      pm->a_shift = ((pm->flags & PHASH_FLAG_MIX64) ? 64 : 32) - pm->a_bits;
      pm->b_mask = (1 << pm->b_bits) - 1;

      vec_resize (pm->tab, vec_len (pm->tabb));
      for (b = 0; b < vec_len (pm->tabb); b++)
	{
	  v = pm->tabb[b].val_b;

	  /* Apply scramble now for small enough value of b_bits. */
	  if (!(pm->flags & PHASH_FLAG_USE_SCRAMBLE))
	    v = pm->scramble[v];

	  pm->tab[b] = v;
	}
    }

  /* Free working memory. */
  phash_main_free_working_memory (pm);

  return error;
}

/* Slow hash computation for general keys. */
uword
phash_hash_slow (phash_main_t * pm, uword key)
{
  u32 a, b, v;

  if (pm->flags & PHASH_FLAG_MIX64)
    {
      u64 x0, y0, z0;

      x0 = y0 = z0 = pm->hash_seed;

      if (pm->key_seed1)
	{
	  u64 xyz[3];
	  pm->key_seed1 (pm->private, key, &xyz);
	  x0 += xyz[0];
	  y0 += xyz[1];
	  z0 += xyz[2];
	}
      else
	x0 += key;

      hash_mix64 (x0, y0, z0);

      a = z0 >> pm->a_shift;
      b = z0 & pm->b_mask;
    }
  else
    {
      u32 x0, y0, z0;

      x0 = y0 = z0 = pm->hash_seed;

      if (pm->key_seed1)
	{
	  u32 xyz[3];
	  pm->key_seed1 (pm->private, key, &xyz);
	  x0 += xyz[0];
	  y0 += xyz[1];
	  z0 += xyz[2];
	}
      else
	x0 += key;

      hash_mix32 (x0, y0, z0);

      a = z0 >> pm->a_shift;
      b = z0 & pm->b_mask;
    }

  v = pm->tab[b];
  if (pm->flags & PHASH_FLAG_USE_SCRAMBLE)
    v = pm->scramble[v];
  return a ^ v;
}

/* Verify that perfect hash is perfect. */
clib_error_t *
phash_validate (phash_main_t * pm)
{
  phash_key_t *k;
  uword *unique_bitmap = 0;
  clib_error_t *error = 0;

  vec_foreach (k, pm->keys)
  {
    uword h = phash_hash_slow (pm, k->key);

    if (h >= pm->hash_max)
      {
	error = clib_error_return (0, "hash out of range %wd", h);
	goto done;
      }

    if (clib_bitmap_get (unique_bitmap, h))
      {
	error = clib_error_return (0, "hash non-unique");
	goto done;
      }

    unique_bitmap = clib_bitmap_ori (unique_bitmap, h);
  }

done:
  clib_bitmap_free (unique_bitmap);
  return error;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
