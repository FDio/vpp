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
  Copyright (c) 2001-2005 Eliot Dresselhaus

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

#include <vppinfra/hash.h>
#include <vppinfra/error.h>
#include <vppinfra/mem.h>
#include <vppinfra/byte_order.h>	/* for clib_arch_is_big_endian */

always_inline void
zero_pair (hash_t * h, hash_pair_t * p)
{
  clib_memset (p, 0, hash_pair_bytes (h));
}

always_inline void
init_pair (hash_t * h, hash_pair_t * p)
{
  clib_memset (p->value, ~0, hash_value_bytes (h));
}

always_inline hash_pair_union_t *
get_pair (void *v, uword i)
{
  hash_t *h = hash_header (v);
  hash_pair_t *p;
  ASSERT (i < vec_len (v));
  p = v;
  p += i << h->log2_pair_size;
  return (hash_pair_union_t *) p;
}

always_inline void
set_is_user (void *v, uword i, uword is_user)
{
  hash_t *h = hash_header (v);
  uword i0 = i / BITS (h->is_user[0]);
  uword i1 = (uword) 1 << (i % BITS (h->is_user[0]));
  if (is_user)
    h->is_user[i0] |= i1;
  else
    h->is_user[i0] &= ~i1;
}

static u8 *hash_format_pair_default (u8 * s, va_list * args);

#if uword_bits == 64

static inline u64
zap64 (u64 x, word n)
{
#define _(n) (((u64) 1 << (u64) (8*(n))) - (u64) 1)
  static u64 masks_little_endian[] = {
    0, _(1), _(2), _(3), _(4), _(5), _(6), _(7),
  };
  static u64 masks_big_endian[] = {
    0, ~_(7), ~_(6), ~_(5), ~_(4), ~_(3), ~_(2), ~_(1),
  };
#undef _
  if (clib_arch_is_big_endian)
    return x & masks_big_endian[n];
  else
    return x & masks_little_endian[n];
}

/**
 * make address-sanitizer skip this:
 * clib_mem_unaligned + zap64 casts its input as u64, computes a mask
 * according to the input length, and returns the casted maked value.
 * Therefore all the 8 Bytes of the u64 are systematically read, which
 * rightfully causes address-sanitizer to raise an error on smaller inputs.
 *
 * However the invalid Bytes are discarded within zap64(), which is why
 * this can be silenced safely.
 *
 * The above is true *unless* the extra bytes cross a page boundary
 * into unmapped or no-access space, hence the boundary crossing check.
 */
static inline u64
hash_memory64 (void *p, word n_bytes, u64 state)
{
  u64 *q = p;
  u64 a, b, c, n;
  int page_boundary_crossing;
  u64 start_addr, end_addr;
  union
  {
    u8 as_u8[8];
    u64 as_u64;
  } tmp;

  /*
   * If the request crosses a 4k boundary, it's not OK to assume
   * that the zap64 game is safe. 4k is the minimum known page size.
   */
  start_addr = (u64) p;
  end_addr = start_addr + n_bytes + 7;
  page_boundary_crossing = (start_addr >> 12) != (end_addr >> 12);

  a = b = 0x9e3779b97f4a7c13LL;
  c = state;
  n = n_bytes;

  while (n >= 3 * sizeof (u64))
    {
      a += clib_mem_unaligned (q + 0, u64);
      b += clib_mem_unaligned (q + 1, u64);
      c += clib_mem_unaligned (q + 2, u64);
      hash_mix64 (a, b, c);
      n -= 3 * sizeof (u64);
      q += 3;
    }

  c += n_bytes;
  switch (n / sizeof (u64))
    {
    case 2:
      a += clib_mem_unaligned (q + 0, u64);
      b += clib_mem_unaligned (q + 1, u64);
      if (n % sizeof (u64))
	{
	  if (PREDICT_TRUE (page_boundary_crossing == 0))
	    {
	      CLIB_MEM_OVERFLOW_PUSH (q + 2, sizeof (u64));
	      c += zap64 (clib_mem_unaligned (q + 2, u64), n % sizeof (u64))
		   << 8;
	      CLIB_MEM_OVERFLOW_POP ();
	    }
	  else
	    {
	      clib_memcpy_fast (tmp.as_u8, q + 2, n % sizeof (u64));
	      c += zap64 (tmp.as_u64, n % sizeof (u64)) << 8;
	    }
	}
      break;

    case 1:
      a += clib_mem_unaligned (q + 0, u64);
      if (n % sizeof (u64))
	{
	  if (PREDICT_TRUE (page_boundary_crossing == 0))
	    {
	      CLIB_MEM_OVERFLOW_PUSH (q + 1, sizeof (u64));
	      b += zap64 (clib_mem_unaligned (q + 1, u64), n % sizeof (u64));
	      CLIB_MEM_OVERFLOW_POP ();
	    }
	  else
	    {
	      clib_memcpy_fast (tmp.as_u8, q + 1, n % sizeof (u64));
	      b += zap64 (tmp.as_u64, n % sizeof (u64));
	    }
	}
      break;

    case 0:
      if (n % sizeof (u64))
	{
	  if (PREDICT_TRUE (page_boundary_crossing == 0))
	    {
	      CLIB_MEM_OVERFLOW_PUSH (q + 0, sizeof (u64));
	      a += zap64 (clib_mem_unaligned (q + 0, u64), n % sizeof (u64));
	      CLIB_MEM_OVERFLOW_POP ();
	    }
	  else
	    {
	      clib_memcpy_fast (tmp.as_u8, q, n % sizeof (u64));
	      a += zap64 (tmp.as_u64, n % sizeof (u64));
	    }
	}
      break;
    }

  hash_mix64 (a, b, c);

  return c;
}

#else /* if uword_bits == 64 */

static inline u32
zap32 (u32 x, word n)
{
#define _(n) (((u32) 1 << (u32) (8*(n))) - (u32) 1)
  static u32 masks_little_endian[] = {
    0, _(1), _(2), _(3),
  };
  static u32 masks_big_endian[] = {
    0, ~_(3), ~_(2), ~_(1),
  };
#undef _
  if (clib_arch_is_big_endian)
    return x & masks_big_endian[n];
  else
    return x & masks_little_endian[n];
}

static inline u32
hash_memory32 (void *p, word n_bytes, u32 state)
{
  u32 *q = p;
  u32 a, b, c, n;

  a = b = 0x9e3779b9;
  c = state;
  n = n_bytes;

  while (n >= 3 * sizeof (u32))
    {
      a += clib_mem_unaligned (q + 0, u32);
      b += clib_mem_unaligned (q + 1, u32);
      c += clib_mem_unaligned (q + 2, u32);
      hash_mix32 (a, b, c);
      n -= 3 * sizeof (u32);
      q += 3;
    }

  c += n_bytes;
  switch (n / sizeof (u32))
    {
    case 2:
      a += clib_mem_unaligned (q + 0, u32);
      b += clib_mem_unaligned (q + 1, u32);
      if (n % sizeof (u32))
	c += zap32 (clib_mem_unaligned (q + 2, u32), n % sizeof (u32)) << 8;
      break;

    case 1:
      a += clib_mem_unaligned (q + 0, u32);
      if (n % sizeof (u32))
	b += zap32 (clib_mem_unaligned (q + 1, u32), n % sizeof (u32));
      break;

    case 0:
      if (n % sizeof (u32))
	a += zap32 (clib_mem_unaligned (q + 0, u32), n % sizeof (u32));
      break;
    }

  hash_mix32 (a, b, c);

  return c;
}
#endif

__clib_export uword
hash_memory (void *p, word n_bytes, uword state)
{
  uword *q = p;

#if uword_bits == 64
  return hash_memory64 (q, n_bytes, state);
#else
  return hash_memory32 (q, n_bytes, state);
#endif
}

#if uword_bits == 64
always_inline uword
hash_uword (uword x)
{
  u64 a, b, c;

  a = b = 0x9e3779b97f4a7c13LL;
  c = 0;
  a += x;
  hash_mix64 (a, b, c);
  return c;
}
#else
always_inline uword
hash_uword (uword x)
{
  u32 a, b, c;

  a = b = 0x9e3779b9;
  c = 0;
  a += x;
  hash_mix32 (a, b, c);
  return c;
}
#endif

/* Call sum function.  Hash code will be sum function value
   modulo the prime length of the hash table. */
always_inline uword
key_sum (hash_t * h, uword key)
{
  uword sum;
  switch (pointer_to_uword ((void *) h->key_sum))
    {
    case KEY_FUNC_NONE:
      sum = hash_uword (key);
      break;

    case KEY_FUNC_POINTER_UWORD:
      sum = hash_uword (*uword_to_pointer (key, uword *));
      break;

    case KEY_FUNC_POINTER_U32:
      sum = hash_uword (*uword_to_pointer (key, u32 *));
      break;

    case KEY_FUNC_STRING:
      sum = string_key_sum (h, key);
      break;

    case KEY_FUNC_MEM:
      sum = mem_key_sum (h, key);
      break;

    default:
      sum = h->key_sum (h, key);
      break;
    }

  return sum;
}

always_inline uword
key_equal1 (hash_t * h, uword key1, uword key2, uword e)
{
  switch (pointer_to_uword ((void *) h->key_equal))
    {
    case KEY_FUNC_NONE:
      break;

    case KEY_FUNC_POINTER_UWORD:
      e =
	*uword_to_pointer (key1, uword *) == *uword_to_pointer (key2,
								uword *);
      break;

    case KEY_FUNC_POINTER_U32:
      e = *uword_to_pointer (key1, u32 *) == *uword_to_pointer (key2, u32 *);
      break;

    case KEY_FUNC_STRING:
      e = string_key_equal (h, key1, key2);
      break;

    case KEY_FUNC_MEM:
      e = mem_key_equal (h, key1, key2);
      break;

    default:
      e = h->key_equal (h, key1, key2);
      break;
    }
  return e;
}

/* Compares two keys: returns 1 if equal, 0 if not. */
always_inline uword
key_equal (hash_t * h, uword key1, uword key2)
{
  uword e = key1 == key2;
  if (CLIB_DEBUG > 0 && key1 == key2)
    ASSERT (key_equal1 (h, key1, key2, e));
  if (!e)
    e = key_equal1 (h, key1, key2, e);
  return e;
}

static hash_pair_union_t *
get_indirect (void *v, hash_pair_indirect_t * pi, uword key)
{
  hash_t *h = hash_header (v);
  hash_pair_t *p0, *p1;

  p0 = p1 = pi->pairs;
  if (h->log2_pair_size > 0)
    p1 = hash_forward (h, p0, indirect_pair_get_len (pi));
  else
    p1 += vec_len (p0);

  while (p0 < p1)
    {
      if (key_equal (h, p0->key, key))
	return (hash_pair_union_t *) p0;
      p0 = hash_forward1 (h, p0);
    }

  return (hash_pair_union_t *) 0;
}

static hash_pair_union_t *
set_indirect_is_user (void *v, uword i, hash_pair_union_t * p, uword key)
{
  hash_t *h = hash_header (v);
  hash_pair_t *q;
  hash_pair_indirect_t *pi = &p->indirect;
  uword log2_bytes = 0;

  if (h->log2_pair_size == 0)
    q = vec_new (hash_pair_t, 2);
  else
    {
      log2_bytes = 1 + hash_pair_log2_bytes (h);
      q = clib_mem_alloc (1ULL << log2_bytes);
    }
  clib_memcpy_fast (q, &p->direct, hash_pair_bytes (h));

  pi->pairs = q;
  if (h->log2_pair_size > 0)
    indirect_pair_set (pi, log2_bytes, 2);

  set_is_user (v, i, 0);

  /* First element is used by existing pair, second will be used by caller. */
  q = hash_forward1 (h, q);
  q->key = key;
  init_pair (h, q);
  return (hash_pair_union_t *) q;
}

static hash_pair_union_t *
set_indirect (void *v, hash_pair_indirect_t * pi, uword key,
	      uword * found_key)
{
  hash_t *h = hash_header (v);
  hash_pair_t *new_pair;
  hash_pair_union_t *q;

  q = get_indirect (v, pi, key);
  if (q)
    {
      *found_key = 1;
      return q;
    }

  if (h->log2_pair_size == 0)
    vec_add2 (pi->pairs, new_pair, 1);
  else
    {
      uword len, new_len, log2_bytes;

      len = indirect_pair_get_len (pi);
      log2_bytes = indirect_pair_get_log2_bytes (pi);

      new_len = len + 1;
      if (new_len * hash_pair_bytes (h) > (1ULL << log2_bytes))
	{
	  pi->pairs = clib_mem_realloc (pi->pairs,
					1ULL << (log2_bytes + 1),
					1ULL << log2_bytes);
	  log2_bytes++;
	}

      indirect_pair_set (pi, log2_bytes, new_len);
      new_pair = pi->pairs + (len << h->log2_pair_size);
    }
  new_pair->key = key;
  init_pair (h, new_pair);
  *found_key = 0;
  return (hash_pair_union_t *) new_pair;
}

static void
unset_indirect (void *v, uword i, hash_pair_t * q)
{
  hash_t *h = hash_header (v);
  hash_pair_union_t *p = get_pair (v, i);
  hash_pair_t *e;
  hash_pair_indirect_t *pi = &p->indirect;
  uword len, is_vec;

  is_vec = h->log2_pair_size == 0;

  ASSERT (!hash_is_user (v, i));
  len = is_vec ? vec_len (pi->pairs) : indirect_pair_get_len (pi);
  e = hash_forward (h, pi->pairs, len - 1);
  ASSERT (q >= pi->pairs && q <= e);

  /* We have two or fewer pairs and we are delete one pair.
     Make indirect pointer direct and free indirect memory. */
  if (len <= 2)
    {
      hash_pair_t *r = pi->pairs;

      if (len == 2)
	{
	  clib_memcpy_fast (p, q == r ? hash_forward1 (h, r) : r,
			    hash_pair_bytes (h));
	  set_is_user (v, i, 1);
	}
      else
	zero_pair (h, &p->direct);

      if (is_vec)
	vec_free (r);
      else if (r)
	clib_mem_free (r);
    }
  else
    {
      /* If deleting a pair we need to keep non-null pairs together. */
      if (q < e)
	clib_memcpy_fast (q, e, hash_pair_bytes (h));
      else
	zero_pair (h, q);
      if (is_vec)
	_vec_len (pi->pairs) -= 1;
      else
	indirect_pair_set (pi, indirect_pair_get_log2_bytes (pi), len - 1);
    }
}

enum lookup_opcode
{
  GET = 1,
  SET = 2,
  UNSET = 3,
};

static hash_pair_t *
lookup (void *v, uword key, enum lookup_opcode op,
	void *new_value, void *old_value)
{
  hash_t *h = hash_header (v);
  hash_pair_union_t *p = 0;
  uword found_key = 0;
  uword value_bytes;
  uword i;

  if (!v)
    return 0;

  i = key_sum (h, key) & (_vec_len (v) - 1);
  p = get_pair (v, i);
  value_bytes = hash_value_bytes (h);

  if (hash_is_user (v, i))
    {
      found_key = key_equal (h, p->direct.key, key);
      if (found_key)
	{
	  if (op == UNSET)
	    {
	      set_is_user (v, i, 0);
	      if (old_value && value_bytes)
		clib_memcpy_fast (old_value, p->direct.value, value_bytes);
	      zero_pair (h, &p->direct);
	    }
	}
      else
	{
	  if (op == SET)
	    p = set_indirect_is_user (v, i, p, key);
	  else
	    p = 0;
	}
    }
  else
    {
      hash_pair_indirect_t *pi = &p->indirect;

      if (op == SET)
	{
	  if (!pi->pairs)
	    {
	      p->direct.key = key;
	      set_is_user (v, i, 1);
	    }
	  else
	    p = set_indirect (v, pi, key, &found_key);
	}
      else
	{
	  p = get_indirect (v, pi, key);
	  found_key = p != 0;
	  if (found_key && op == UNSET)
	    {
	      if (old_value && value_bytes)
		clib_memcpy_fast (old_value, &p->direct.value, value_bytes);

	      unset_indirect (v, i, &p->direct);

	      /* Nullify p (since it's just been deleted).
	         Otherwise we might be tempted to play with it. */
	      p = 0;
	    }
	}
    }

  if (op == SET && p != 0 && value_bytes)
    {
      /* Save away old value for caller. */
      if (old_value && found_key)
	clib_memcpy_fast (old_value, &p->direct.value, value_bytes);
      clib_memcpy_fast (&p->direct.value, new_value, value_bytes);
    }

  if (op == SET)
    h->elts += !found_key;
  if (op == UNSET)
    h->elts -= found_key;

  return &p->direct;
}

/* Fetch value of key. */
__clib_export uword *
_hash_get (void *v, uword key)
{
  hash_t *h;
  hash_pair_t *p;

  /* Don't even search table if its empty. */
  if (hash_elts (v) == 0)
    return 0;

  p = lookup (v, key, GET, 0, 0);
  if (!p)
    return 0;

  h = hash_header (v);
  if (h->log2_pair_size == 0)
    return &p->key;
  else
    return &p->value[0];
}

__clib_export hash_pair_t *
_hash_get_pair (void *v, uword key)
{
  return lookup (v, key, GET, 0, 0);
}

__clib_export hash_pair_t *
hash_next (void *v, hash_next_t *hn)
{
  hash_t *h = hash_header (v);
  hash_pair_t *p;

  while (1)
    {
      if (hn->i == 0 && hn->j == 0)
	{
	  /* Save flags. */
	  hn->f = h->flags;

	  /* Prevent others from re-sizing hash table. */
	  h->flags |=
	    (HASH_FLAG_NO_AUTO_GROW
	     | HASH_FLAG_NO_AUTO_SHRINK | HASH_FLAG_HASH_NEXT_IN_PROGRESS);
	}
      else if (hn->i >= hash_capacity (v))
	{
	  /* Restore flags. */
	  h->flags = hn->f;
	  clib_memset (hn, 0, sizeof (hn[0]));
	  return 0;
	}

      p = hash_forward (h, v, hn->i);
      if (hash_is_user (v, hn->i))
	{
	  hn->i++;
	  return p;
	}
      else
	{
	  hash_pair_indirect_t *pi = (void *) p;
	  uword n;

	  if (h->log2_pair_size > 0)
	    n = indirect_pair_get_len (pi);
	  else
	    n = vec_len (pi->pairs);

	  if (hn->j >= n)
	    {
	      hn->i++;
	      hn->j = 0;
	    }
	  else
	    return hash_forward (h, pi->pairs, hn->j++);
	}
    }
}

/* Remove key from table. */
__clib_export void *
_hash_unset (void *v, uword key, void *old_value)
{
  hash_t *h;

  if (!v)
    return v;

  (void) lookup (v, key, UNSET, 0, old_value);

  h = hash_header (v);
  if (!(h->flags & HASH_FLAG_NO_AUTO_SHRINK))
    {
      /* Resize when 1/4 full. */
      if (h->elts > 32 && 4 * (h->elts + 1) < vec_len (v))
	v = hash_resize (v, vec_len (v) / 2);
    }

  return v;
}

__clib_export void *
_hash_create (uword elts, hash_t * h_user)
{
  hash_t *h;
  uword log2_pair_size;
  void *v;

  /* Size of hash is power of 2 >= ELTS and larger than
     number of bits in is_user bitmap elements. */
  elts = clib_max (elts, BITS (h->is_user[0]));
  elts = 1ULL << max_log2 (elts);

  log2_pair_size = 1;
  if (h_user)
    log2_pair_size = h_user->log2_pair_size;

  v = _vec_resize ((void *) 0,
		   /* vec len: */ elts,
		   /* data bytes: */
		   (elts << log2_pair_size) * sizeof (hash_pair_t),
		   /* header bytes: */
		   sizeof (h[0]) +
		   (elts / BITS (h->is_user[0])) * sizeof (h->is_user[0]),
		   /* alignment */ sizeof (hash_pair_t));
  h = hash_header (v);

  if (h_user)
    h[0] = h_user[0];

  h->log2_pair_size = log2_pair_size;
  h->elts = 0;

  /* Default flags to never shrinking hash tables.
     Shrinking tables can cause "jackpot" cases. */
  if (!h_user)
    h->flags = HASH_FLAG_NO_AUTO_SHRINK;

  if (!h->format_pair)
    {
      h->format_pair = hash_format_pair_default;
      h->format_pair_arg = 0;
    }

  return v;
}

__clib_export void *
_hash_free (void *v)
{
  hash_t *h;
  hash_pair_union_t *p;
  uword i;

  if (!v)
    return v;

  h = hash_header (v);
  /* We zero all freed memory in case user would be tempted to use it. */
  for (i = 0; i < hash_capacity (v); i++)
    {
      if (hash_is_user (v, i))
	continue;
      p = get_pair (v, i);
      if (h->log2_pair_size == 0)
	vec_free (p->indirect.pairs);
      else if (p->indirect.pairs)
	clib_mem_free (p->indirect.pairs);
    }

  vec_free_header (h);

  return 0;
}

static void *
hash_resize_internal (void *old, uword new_size, uword free_old)
{
  void *new;
  hash_pair_t *p;

  new = 0;
  if (new_size > 0)
    {
      hash_t *h = old ? hash_header (old) : 0;
      new = _hash_create (new_size, h);
      /* *INDENT-OFF* */
      hash_foreach_pair (p, old, {
	new = _hash_set3 (new, p->key, &p->value[0], 0);
      });
      /* *INDENT-ON* */
    }

  if (free_old)
    hash_free (old);
  return new;
}

__clib_export void *
hash_resize (void *old, uword new_size)
{
  return hash_resize_internal (old, new_size, 1);
}

__clib_export void *
hash_dup (void *old)
{
  return hash_resize_internal (old, vec_len (old), 0);
}

__clib_export void *
_hash_set3 (void *v, uword key, void *value, void *old_value)
{
  hash_t *h;

  if (!v)
    v = hash_create (0, sizeof (uword));

  h = hash_header (v);
  (void) lookup (v, key, SET, value, old_value);

  if (!(h->flags & HASH_FLAG_NO_AUTO_GROW))
    {
      /* Resize when 3/4 full. */
      if (4 * (h->elts + 1) > 3 * vec_len (v))
	v = hash_resize (v, 2 * vec_len (v));
    }

  return v;
}

__clib_export uword
vec_key_sum (hash_t * h, uword key)
{
  void *v = uword_to_pointer (key, void *);
  return hash_memory (v, vec_len (v) * h->user, 0);
}

__clib_export uword
vec_key_equal (hash_t * h, uword key1, uword key2)
{
  void *v1 = uword_to_pointer (key1, void *);
  void *v2 = uword_to_pointer (key2, void *);
  uword l1 = vec_len (v1);
  uword l2 = vec_len (v2);
  return l1 == l2 && 0 == memcmp (v1, v2, l1 * h->user);
}

__clib_export u8 *
vec_key_format_pair (u8 * s, va_list * args)
{
  void *CLIB_UNUSED (user_arg) = va_arg (*args, void *);
  void *v = va_arg (*args, void *);
  hash_pair_t *p = va_arg (*args, hash_pair_t *);
  hash_t *h = hash_header (v);
  void *u = uword_to_pointer (p->key, void *);
  int i;

  switch (h->user)
    {
    case 1:
      s = format (s, "%v", u);
      break;

    case 2:
      {
	u16 *w = u;
	for (i = 0; i < vec_len (w); i++)
	  s = format (s, "0x%x, ", w[i]);
	break;
      }

    case 4:
      {
	u32 *w = u;
	for (i = 0; i < vec_len (w); i++)
	  s = format (s, "0x%x, ", w[i]);
	break;
      }

    case 8:
      {
	u64 *w = u;
	for (i = 0; i < vec_len (w); i++)
	  s = format (s, "0x%Lx, ", w[i]);
	break;
      }

    default:
      s = format (s, "0x%U", format_hex_bytes, u, vec_len (u) * h->user);
      break;
    }

  if (hash_value_bytes (h) > 0)
    s = format (s, " -> 0x%wx", p->value[0]);

  return s;
}

__clib_export uword
mem_key_sum (hash_t * h, uword key)
{
  uword *v = uword_to_pointer (key, void *);
  return hash_memory (v, h->user, 0);
}

__clib_export uword
mem_key_equal (hash_t * h, uword key1, uword key2)
{
  void *v1 = uword_to_pointer (key1, void *);
  void *v2 = uword_to_pointer (key2, void *);
  return v1 && v2 && 0 == memcmp (v1, v2, h->user);
}

uword
string_key_sum (hash_t * h, uword key)
{
  char *v = uword_to_pointer (key, char *);
  return hash_memory (v, strlen (v), 0);
}

uword
string_key_equal (hash_t * h, uword key1, uword key2)
{
  void *v1 = uword_to_pointer (key1, void *);
  void *v2 = uword_to_pointer (key2, void *);
  return v1 && v2 && 0 == strcmp (v1, v2);
}

u8 *
string_key_format_pair (u8 * s, va_list * args)
{
  void *CLIB_UNUSED (user_arg) = va_arg (*args, void *);
  void *v = va_arg (*args, void *);
  hash_pair_t *p = va_arg (*args, hash_pair_t *);
  hash_t *h = hash_header (v);
  void *u = uword_to_pointer (p->key, void *);

  s = format (s, "%s", u);

  if (hash_value_bytes (h) > 0)
    s =
      format (s, " -> 0x%8U", format_hex_bytes, &p->value[0],
	      hash_value_bytes (h));

  return s;
}

static u8 *
hash_format_pair_default (u8 * s, va_list * args)
{
  void *CLIB_UNUSED (user_arg) = va_arg (*args, void *);
  void *v = va_arg (*args, void *);
  hash_pair_t *p = va_arg (*args, hash_pair_t *);
  hash_t *h = hash_header (v);

  s = format (s, "0x%08x", p->key);
  if (hash_value_bytes (h) > 0)
    s =
      format (s, " -> 0x%8U", format_hex_bytes, &p->value[0],
	      hash_value_bytes (h));
  return s;
}

__clib_export uword
hash_bytes (void *v)
{
  uword i, bytes;
  hash_t *h = hash_header (v);

  if (!v)
    return 0;

  bytes = vec_capacity (v, hash_header_bytes (v));

  for (i = 0; i < hash_capacity (v); i++)
    {
      if (!hash_is_user (v, i))
	{
	  hash_pair_union_t *p = get_pair (v, i);
	  if (h->log2_pair_size > 0)
	    bytes += 1 << indirect_pair_get_log2_bytes (&p->indirect);
	  else
	    bytes += vec_capacity (p->indirect.pairs, 0);
	}
    }
  return bytes;
}

__clib_export u8 *
format_hash (u8 *s, va_list *va)
{
  void *v = va_arg (*va, void *);
  int verbose = va_arg (*va, int);
  hash_pair_t *p;
  hash_t *h = hash_header (v);
  uword i;

  s = format (s, "hash %p, %wd elts, capacity %wd, %wd bytes used,\n",
	      v, hash_elts (v), hash_capacity (v), hash_bytes (v));

  {
    uword *occupancy = 0;

    /* Count number of buckets with each occupancy. */
    for (i = 0; i < hash_capacity (v); i++)
      {
	uword j;

	if (hash_is_user (v, i))
	  {
	    j = 1;
	  }
	else
	  {
	    hash_pair_union_t *p = get_pair (v, i);
	    if (h->log2_pair_size > 0)
	      j = indirect_pair_get_len (&p->indirect);
	    else
	      j = vec_len (p->indirect.pairs);
	  }

	vec_validate (occupancy, j);
	occupancy[j]++;
      }

    s = format (s, "  profile ");
    for (i = 0; i < vec_len (occupancy); i++)
      s = format (s, "%wd%c", occupancy[i],
		  i + 1 == vec_len (occupancy) ? '\n' : ' ');

    s = format (s, "  lookup # of compares: ");
    for (i = 1; i < vec_len (occupancy); i++)
      s = format (s, "%wd: .%03d%c", i,
		  (1000 * i * occupancy[i]) / hash_elts (v),
		  i + 1 == vec_len (occupancy) ? '\n' : ' ');

    vec_free (occupancy);
  }

  if (verbose)
    {
      /* *INDENT-OFF* */
      hash_foreach_pair (p, v, {
	s = format (s, "  %U\n", h->format_pair, h->format_pair_arg, v, p);
      });
      /* *INDENT-ON* */
    }

  return s;
}

static uword
unformat_hash_string_internal (unformat_input_t * input,
			       va_list * va, int is_vec)
{
  uword *hash = va_arg (*va, uword *);
  int *result = va_arg (*va, int *);
  u8 *string = 0;
  uword *p;

  if (!unformat (input, is_vec ? "%v%_" : "%s%_", &string))
    return 0;

  p = hash_get_mem (hash, string);
  if (p)
    *result = *p;

  vec_free (string);
  return p ? 1 : 0;
}

__clib_export uword
unformat_hash_vec_string (unformat_input_t * input, va_list * va)
{
  return unformat_hash_string_internal (input, va, /* is_vec */ 1);
}

__clib_export uword
unformat_hash_string (unformat_input_t * input, va_list * va)
{
  return unformat_hash_string_internal (input, va, /* is_vec */ 0);
}

__clib_export clib_error_t *
hash_validate (void *v)
{
  hash_t *h = hash_header (v);
  uword i, j;
  uword *keys = 0;
  clib_error_t *error = 0;

#define CHECK(x) if ((error = ERROR_ASSERT (x))) goto done;

  for (i = 0; i < hash_capacity (v); i++)
    {
      hash_pair_union_t *pu = get_pair (v, i);

      if (hash_is_user (v, i))
	{
	  CHECK (pu->direct.key != 0);
	  vec_add1 (keys, pu->direct.key);
	}
      else
	{
	  hash_pair_t *p;
	  hash_pair_indirect_t *pi = &pu->indirect;
	  uword n;

	  n = h->log2_pair_size > 0
	    ? indirect_pair_get_len (pi) : vec_len (pi->pairs);

	  for (p = pi->pairs; n-- > 0; p = hash_forward1 (h, p))
	    {
	      /* Assert key uniqueness. */
	      for (j = 0; j < vec_len (keys); j++)
		CHECK (keys[j] != p->key);
	      vec_add1 (keys, p->key);
	    }
	}
    }

  CHECK (vec_len (keys) == h->elts);

  vec_free (keys);
done:
  return error;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
