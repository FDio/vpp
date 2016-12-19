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

#ifndef included_phash_h
#define included_phash_h

#include <vppinfra/hash.h>	/* for Bob's mixing functions */

typedef struct
{
  /* Maybe either pointer to vector or inline word. */
  uword key;

  /* Hash code (A, B). */
  u32 a, b;
} phash_key_t;

/* Table indexed by B. */
typedef struct
{
  /* Vector of key indices with this same value of B. */
  u32 *keys;

  /* hash=a^tabb[b].val_b */
  u32 val_b;

  /* High watermark of who has visited this map node. */
  u32 water_b;
} phash_tabb_t;

always_inline void
phash_tabb_free (phash_tabb_t * b)
{
  vec_free (b->keys);
  b->val_b = b->water_b = 0;
}

typedef struct
{
  /* b that currently occupies this hash */
  u32 b_q;

  /* Queue position of parent that could use this hash. */
  u32 parent_q;

  /* What to change parent tab[b] to use this hash. */
  u32 newval_q;

  /* Original value of tab[b]. */
  u32 oldval_q;
} phash_tabq_t;

typedef struct
{
  u8 a_bits, b_bits, s_bits, a_shift;
  u32 b_mask;
  u32 *tab;
  u32 *scramble;

  /* Seed value for hash mixer. */
  u64 hash_seed;

  u32 flags;

  /* Key functions want 64 bit keys.
     Use hash_mix64 rather than hash_mix32. */
#define PHASH_FLAG_MIX64		(1 << 0)
#define PHASH_FLAG_MIX32		(0 << 0)

  /* When b_bits is large enough (>= 12) we scramble. */
#define PHASH_FLAG_USE_SCRAMBLE		(1 << 1)

  /* Slow mode gives smaller tables but at the expense of more run time. */
#define PHASH_FLAG_SLOW_MODE		(0 << 2)
#define PHASH_FLAG_FAST_MODE		(1 << 2)

  /* Generate minimal perfect hash instead of perfect hash. */
#define PHASH_FLAG_NON_MINIMAL		(0 << 3)
#define PHASH_FLAG_MINIMAL		(1 << 3)

  /* vec_len (keys) for minimal hash;
     1 << s_bits for non-minimal hash. */
  u32 hash_max;

  /* Vector of keys. */
  phash_key_t *keys;

  /* Used by callbacks to identify keys. */
  void *private;

  /* Key comparison callback. */
  int (*key_is_equal) (void *private, uword key1, uword key2);

  /* Callback to reduce single key -> hash seeds. */
  void (*key_seed1) (void *private, uword key, void *seed);

  /* Callback to reduce two key2 -> hash seeds. */
  void (*key_seed2) (void *private, uword key1, uword key2, void *seed);

  /* Stuff used to compute perfect hash. */
  u32 random_seed;

  /* Stuff indexed by B. */
  phash_tabb_t *tabb;

  /* Table of B ordered by number of keys in tabb[b]. */
  u32 *tabb_sort;

  /* Unique key (or ~0 if none) for a given hash
     H = A ^ scramble[tab[B].val_b]. */
  u32 *tabh;

  /* Stuff indexed by q. */
  phash_tabq_t *tabq;

  /* Stats. */
  u32 n_seed_trials, n_perfect_calls;
} phash_main_t;

always_inline void
phash_main_free_working_memory (phash_main_t * pm)
{
  vec_free (pm->tabb);
  vec_free (pm->tabq);
  vec_free (pm->tabh);
  vec_free (pm->tabb_sort);
  if (!(pm->flags & PHASH_FLAG_USE_SCRAMBLE))
    vec_free (pm->scramble);
}

always_inline void
phash_main_free (phash_main_t * pm)
{
  phash_main_free_working_memory (pm);
  vec_free (pm->tab);
  vec_free (pm->keys);
  memset (pm, 0, sizeof (pm[0]));
}

/* Slow hash computation for general keys. */
uword phash_hash_slow (phash_main_t * pm, uword key);

/* Main routine to compute perfect hash. */
clib_error_t *phash_find_perfect_hash (phash_main_t * pm);

/* Validates that hash is indeed perfect. */
clib_error_t *phash_validate (phash_main_t * pm);

/* Unit test. */
int phash_test_main (unformat_input_t * input);

#endif /* included_phash_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
