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
  Copyright (c) 2001, 2002, 2003 Eliot Dresselhaus

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

#ifndef included_mem_mheap_h
#define included_mem_mheap_h

/* Bootstrap include so that #include <vppinfra/mem.h> can include e.g.
   <vppinfra/mheap.h> which depends on <vppinfra/vec.h>. */

#include <vppinfra/vec_bootstrap.h>
#include <vppinfra/error_bootstrap.h>
#include <vppinfra/os.h>
#include <vppinfra/vector.h>

/* Each element in heap is immediately followed by this struct. */
typedef struct
{
  /* Number of mheap_size_t words of user data in previous object.
     Used to find mheap_elt_t for previous object. */
#if CLIB_VEC64 > 0
  u64 prev_n_user_data:63;

  /* Used to mark end/start of of doubly-linked list of mheap_elt_t's. */
#define MHEAP_N_USER_DATA_INVALID (0x7fffffffffffffffULL)
#define MHEAP_GROUNDED (~0ULL)

  /* Set if previous object is free. */
  u64 prev_is_free:1;

  /* Number of mheap_size_t words of user data that follow this object. */
  u64 n_user_data:63;

  /* Set if this object is on free list (and therefore following free_elt
     is valid). */
  u64 is_free:1;

#else
  u32 prev_n_user_data:31;

  /* Used to mark end/start of of doubly-linked list of mheap_elt_t's. */
#define MHEAP_N_USER_DATA_INVALID (0x7fffffff)
#define MHEAP_GROUNDED (~0)

  /* Set if previous object is free. */
  u32 prev_is_free:1;

  /* Number of mheap_size_t words of user data that follow this object. */
  u32 n_user_data:31;

  /* Set if this object is on free list (and therefore following free_elt
     is valid). */
  u32 is_free:1;
#endif

  union
  {
#if CLIB_VEC64 > 0
    /* For allocated objects: user data follows.
       User data is allocated in units of typeof (user_data[0]). */
    u64 user_data[0];

    /* For free objects, offsets of next and previous free objects of this size;
       ~0 means end of doubly-linked list.
       This is stored in user data (guaranteed to be at least 8 bytes)
       but only for *free* objects. */
    struct
    {
      u64 next_uoffset, prev_uoffset;
    } free_elt;
#else
    /* For allocated objects: user data follows.
       User data is allocated in units of typeof (user_data[0]). */
    u32 user_data[0];

    /* For free objects, offsets of next and previous free objects of this size;
       ~0 means end of doubly-linked list.
       This is stored in user data (guaranteed to be at least 8 bytes)
       but only for *free* objects. */
    struct
    {
      u32 next_uoffset, prev_uoffset;
    } free_elt;
#endif
  };
} mheap_elt_t;

/* Number of bytes of "overhead": e.g. not user data. */
#define MHEAP_ELT_OVERHEAD_BYTES (sizeof (mheap_elt_t) - STRUCT_OFFSET_OF (mheap_elt_t, user_data))

/* User objects must be large enough to hold 2 x u32 free offsets in free elt. */
#define MHEAP_MIN_USER_DATA_BYTES MHEAP_ELT_OVERHEAD_BYTES

/* Number of byte in user data "words". */
#define MHEAP_USER_DATA_WORD_BYTES STRUCT_SIZE_OF (mheap_elt_t, user_data[0])

typedef struct
{
  /* Address of callers: outer first, inner last. */
  uword callers[12];

  /* Count of allocations with this traceback. */
#if CLIB_VEC64 > 0
  u64 n_allocations;
#else
  u32 n_allocations;
#endif

  /* Count of bytes allocated with this traceback. */
  u32 n_bytes;

  /* Offset of this item */
  uword offset;
} mheap_trace_t;

typedef struct
{
  mheap_trace_t *traces;

  /* Indices of free traces. */
  u32 *trace_free_list;

  /* Hash table mapping callers to trace index. */
  uword *trace_by_callers;

  /* Hash table mapping mheap offset to trace index. */
  uword *trace_index_by_offset;
} mheap_trace_main_t;

/* Without vector instructions don't bother with small object cache. */
#ifdef CLIB_HAVE_VEC128
#define MHEAP_HAVE_SMALL_OBJECT_CACHE 1
#else
#define MHEAP_HAVE_SMALL_OBJECT_CACHE 0
#endif

  /* Small object bin i is for objects with
     user_size >  sizeof (mheap_elt_t) + sizeof (mheap_elt_t) * (i - 1)
     user_size <= sizeof (mheap_elt_t) + sizeof (mheap_size_t) * i. */
#if MHEAP_HAVE_SMALL_OBJECT_CACHE > 0
#define MHEAP_LOG2_N_SMALL_OBJECT_BINS 8
#define MHEAP_N_SMALL_OBJECT_BINS (1 << MHEAP_LOG2_N_SMALL_OBJECT_BINS)
#else
#define MHEAP_LOG2_N_SMALL_OBJECT_BINS 0
#define MHEAP_N_SMALL_OBJECT_BINS 0
#endif

#define MHEAP_N_BINS							\
  (MHEAP_N_SMALL_OBJECT_BINS						\
   + (STRUCT_BITS_OF (mheap_elt_t, user_data[0]) - MHEAP_LOG2_N_SMALL_OBJECT_BINS))

typedef struct
{
  struct
  {
    u64 n_search_attempts;
    u64 n_objects_searched;
    u64 n_objects_found;
  } free_list;

  u64 n_vector_expands;

  u64 n_small_object_cache_hits;
  u64 n_small_object_cache_attempts;

  u64 n_gets, n_puts;
  u64 n_clocks_get, n_clocks_put;
} mheap_stats_t;

/* For objects with align == 4 and align_offset == 0 (e.g. vector strings). */
typedef struct
{
  union
  {
#ifdef CLIB_HAVE_VEC128
    u8x16 as_u8x16[BITS (uword) / 16];
#endif

    /* Store bin + 1; zero means unused. */
    u8 as_u8[BITS (uword)];
  } bins;

  uword offsets[BITS (uword)];

  u32 replacement_index;
} mheap_small_object_cache_t;

/* Vec header for heaps. */
typedef struct
{
  /* User offsets for head of doubly-linked list of free objects of this size. */
#if CLIB_VEC64 > 0
  u64 first_free_elt_uoffset_by_bin[MHEAP_N_BINS];
#else
  u32 first_free_elt_uoffset_by_bin[MHEAP_N_BINS];
#endif

  /* Bitmap of non-empty free list bins. */
  uword non_empty_free_elt_heads[(MHEAP_N_BINS + BITS (uword) - 1) /
				 BITS (uword)];

  mheap_small_object_cache_t small_object_cache;

  u32 flags;
#define MHEAP_FLAG_TRACE			(1 << 0)
#define MHEAP_FLAG_DISABLE_VM			(1 << 1)
#define MHEAP_FLAG_THREAD_SAFE			(1 << 2)
#define MHEAP_FLAG_SMALL_OBJECT_CACHE		(1 << 3)
#define MHEAP_FLAG_VALIDATE			(1 << 4)

  /* Lock use when MHEAP_FLAG_THREAD_SAFE is set. */
  volatile u32 lock;
  volatile u32 owner_cpu;
  int recursion_count;

  /* Number of allocated objects. */
  u64 n_elts;

  /* Maximum size (in bytes) this heap is allowed to grow to.
     Set to ~0 to grow heap (via vec_resize) arbitrarily. */
  u64 max_size;

  uword vm_alloc_offset_from_header;
  uword vm_alloc_size;

  /* Each successful mheap_validate call increments this serial number.
     Used to debug heap corruption problems.  GDB breakpoints can be
     made conditional on validate_serial. */
  u64 validate_serial;

  mheap_trace_main_t trace_main;

  mheap_stats_t stats;
} mheap_t;

always_inline mheap_t *
mheap_header (u8 * v)
{
  return vec_aligned_header (v, sizeof (mheap_t), 16);
}

always_inline u8 *
mheap_vector (mheap_t * h)
{
  return vec_aligned_header_end (h, sizeof (mheap_t), 16);
}

always_inline uword
mheap_elt_uoffset (void *v, mheap_elt_t * e)
{
  return (uword) e->user_data - (uword) v;
}

always_inline mheap_elt_t *
mheap_user_pointer_to_elt (void *v)
{
  return v - STRUCT_OFFSET_OF (mheap_elt_t, user_data);
}

/* For debugging we keep track of offsets for valid objects.
   We make sure user is not trying to free object with invalid offset. */
always_inline uword
mheap_offset_is_valid (void *v, uword uo)
{
  return uo >= MHEAP_ELT_OVERHEAD_BYTES && uo <= vec_len (v);
}

always_inline mheap_elt_t *
mheap_elt_at_uoffset (void *v, uword uo)
{
  ASSERT (mheap_offset_is_valid (v, uo));
  return (mheap_elt_t *) (v + uo - STRUCT_OFFSET_OF (mheap_elt_t, user_data));
}

always_inline void *
mheap_elt_data (void *v, mheap_elt_t * e)
{
  return v + mheap_elt_uoffset (v, e);
}

always_inline uword
mheap_elt_data_bytes (mheap_elt_t * e)
{
  return e->n_user_data * sizeof (e->user_data[0]);
}

always_inline uword
mheap_data_bytes (void *v, uword uo)
{
  mheap_elt_t *e = mheap_elt_at_uoffset (v, uo);
  return mheap_elt_data_bytes (e);
}

#define mheap_len(v,d) (mheap_data_bytes((v),(void *) (d) - (void *) (v)) / sizeof ((d)[0]))

always_inline mheap_elt_t *
mheap_next_elt (mheap_elt_t * e)
{
  ASSERT (e->n_user_data < MHEAP_N_USER_DATA_INVALID);
  return (mheap_elt_t *) (e->user_data + e->n_user_data);
}

always_inline mheap_elt_t *
mheap_prev_elt (mheap_elt_t * e)
{
  ASSERT (e->prev_n_user_data < MHEAP_N_USER_DATA_INVALID);
  return ((void *) e
	  - e->prev_n_user_data * sizeof (e->user_data[0])
	  - MHEAP_ELT_OVERHEAD_BYTES);
}

/* Exported operations. */

always_inline uword
mheap_elts (void *v)
{
  return v ? mheap_header (v)->n_elts : 0;
}

always_inline uword
mheap_max_size (void *v)
{
  return v ? mheap_header (v)->max_size : ~0;
}

/* Free previously allocated offset. */
void mheap_put (void *v, uword offset);

/* Allocate object from mheap. */
void *mheap_get_aligned (void *v, uword size, uword align, uword align_offset,
			 uword * offset_return);

#endif /* included_mem_mheap_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
