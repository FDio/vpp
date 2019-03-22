/*
 *------------------------------------------------------------------
 * Copyright (c) 2019 Cisco and/or its affiliates.
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
 *------------------------------------------------------------------
 */

#ifndef _SPARSE_BITMAP_H_
#define _SPARSE_BITMAP_H_

#include <vppinfra/vec.h>
#include <vppinfra/random.h>
#include <vppinfra/error.h>
#include <vppinfra/bitops.h>    /* for count_set_bits */
#include <vppinfra/sparse_vec.h>
#include <vlib/vlib.h>



#if defined (__GNUC__)
#define IACA_SSC_MARK( MARK_ID )                                                \
__asm__ __volatile__ (                                                                  \
                                          "\n\t  movl $"#MARK_ID", %%ebx"       \
                                          "\n\t  .byte 0x64, 0x67, 0x90"        \
                                          : : : "memory" );

#else
#define IACA_SSC_MARK(x) {__asm  mov ebx, x\
        __asm  _emit 0x64 \
        __asm  _emit 0x67 \
        __asm  _emit 0x90 }
#endif

#define IACA_START {IACA_SSC_MARK(111)}
#define IACA_END {IACA_SSC_MARK(222)}

#ifdef _WIN64
#include <intrin.h>
#define IACA_VC64_START __writegsbyte(111, 111);
#define IACA_VC64_END   __writegsbyte(222, 222);
#endif




/*
 * This implements sparse bitmaps, optimized for only a few set bits in the long bitstring
 */

typedef struct sbm_el_t {
  u32 elt_zero;
  u32 elt_bits;
} sbm_elt_t;

typedef sbm_elt_t sbitmap_t;

void sparse_bitmap_test(vlib_main_t * vm);

typedef struct sbmv_u16_t {
  sbitmap_t *wildcard_bitmap;
  sbitmap_t **indexed_bitmaps;
} sbmv_u16_t;

static inline u8 *
format_sbitmap_el_hex (u8 * s, va_list * args)
{
  sbm_elt_t *pel = va_arg (*args, sbm_elt_t *);
  sbm_elt_t el = *pel;
  if (el.elt_zero)
    {
      s = format (s, "[%d*0s]", el.elt_zero * sizeof (el.elt_bits) * 8 / 4);
    }
  int i;
  for (i = 0; i < (8 * sizeof (el.elt_bits)) / 4; i++)
    {
      u8 x = el.elt_bits & 0xf;
      el.elt_bits = el.elt_bits >> 4;

      s = format (s, "%x", x);
    }
  return s;
}

/** Format a bitmap as a string of hex bytes

    uword * bitmap;
    s = format ("%U", format_sbitmap_hex, bitmap);

    Standard format_function_t arguments

    @param s - string under construction
    @param args - varargs list comprising a single sbitmap_t *
    @returns string under construction
*/
static inline u8 *
format_sbitmap_hex (u8 * s, va_list * args)
{
  sbitmap_t *bitmap = va_arg (*args, sbitmap_t *);
  sbm_elt_t *el;
  int i;

  if (!bitmap)
    return format (s, "0");


  for (i = 0; i < vec_len (bitmap); i++)
    {
      el = &bitmap[i];
      s = format (s, "%U", format_sbitmap_el_hex, el);
    }
  return s;
}



always_inline 
u32 sbm_len_elts (sbitmap_t ** sbm)
{
  sbm_elt_t *el;
  u32 elen = 0;
  vec_foreach (el, *sbm)
  {
    /* "1" account for elt_bits in each element */
    elen += el->elt_zero + 1;
  }
  return elen;
}

always_inline void
sbm_and (sbitmap_t ** bitmap0, sbitmap_t * bitmap1, sbitmap_t * bitmap2)
{
  sbitmap_t *sbm1 = bitmap1;
  sbitmap_t *sbm2 = bitmap2;
  sbm_elt_t nel = { 0 };
  sbitmap_t *sbm1e = sbm1 + vec_len (sbm1);
  sbitmap_t *sbm2e = sbm2 + vec_len (sbm2);
  u32 sbm1i = 0, sbm2i = 0;
  u32 sbm0i = 0;
  vec_reset_length (*bitmap0);
  while ((sbm1 < sbm1e) && (sbm2 < sbm2e))
    {
      u32 sbm1iw = sbm1i + sbm1->elt_zero;
      u32 sbm2iw = sbm2i + sbm2->elt_zero;

      if (sbm1iw == sbm2iw)
	{
	  /* words aligned at the same offset */
	  nel.elt_bits = sbm1->elt_bits & sbm2->elt_bits;
	  if (nel.elt_bits)
	    {
	      /* result is non-zero, push to output accumulator */
	      nel.elt_zero = sbm1iw - sbm0i;
	      vec_add1 (*bitmap0, nel);
	      /* move to new offset */
	      sbm0i = sbm1iw + 1;
	    }
	  /* advance both sources */
	  sbm1i += sbm1->elt_zero + 1;
	  sbm2i += sbm2->elt_zero + 1;
	  sbm1++;
	  sbm2++;
	}
      else if (sbm1iw < sbm2iw)
	{
	  /* try to catch up the 1st string with second */
	  sbm1i += sbm1->elt_zero + 1;
	  sbm1++;
	}
      else
	{
	  /* try to catch up the 2nd string with first */
	  sbm2i += sbm2->elt_zero + 1;
	  sbm2++;
	}
    }
}

always_inline void
sbm_or (sbitmap_t ** bitmap0, sbitmap_t * bitmap1, sbitmap_t * bitmap2)
{
  sbitmap_t *sbm1 = bitmap1;
  sbitmap_t *sbm2 = bitmap2;
  sbm_elt_t nel = { 0 };
  sbitmap_t *sbm1e = sbm1 + vec_len (sbm1);
  sbitmap_t *sbm2e = sbm2 + vec_len (sbm2);
  u32 sbm1i = 0, sbm2i = 0;
  u32 sbm0i = 0;
  vec_validate (*bitmap0, vec_len (sbm1) + vec_len (sbm2));
  vec_reset_length (*bitmap0);
  while ((sbm1 < sbm1e) && (sbm2 < sbm2e))
    {
      u32 sbm1iw = sbm1i + sbm1->elt_zero;
      u32 sbm2iw = sbm2i + sbm2->elt_zero;

      if (sbm1iw == sbm2iw)
	{
	  /* words aligned at the same offset */
	  nel.elt_bits = sbm1->elt_bits | sbm2->elt_bits;
	  if (nel.elt_bits)
	    {
	      /* result is non-zero, push to output accumulator */
	      nel.elt_zero = sbm1iw - sbm0i;
	      vec_add1 (*bitmap0, nel);
	      /* move to new offset */
	      sbm0i = sbm1iw + 1;
	    }
	  /* advance both sources */
	  sbm1i += sbm1->elt_zero + 1;
	  sbm2i += sbm2->elt_zero + 1;
	  sbm1++;
	  sbm2++;
	}
      else if (sbm1iw < sbm2iw)
	{
	  nel.elt_bits = sbm1->elt_bits;
	  if (nel.elt_bits)
	    {
	      /* result is non-zero, push to output accumulator */
	      nel.elt_zero = sbm1iw - sbm0i;
	      vec_add1 (*bitmap0, nel);
	      /* move to new offset */
	      sbm0i = sbm1iw + 1;
	    }
	  /* try to catch up the 1st string with second */
	  sbm1i += sbm1->elt_zero + 1;
	  sbm1++;
	}
      else
	{
	  nel.elt_bits = sbm2->elt_bits;
	  if (nel.elt_bits)
	    {
	      /* result is non-zero, push to output accumulator */
	      nel.elt_zero = sbm2iw - sbm0i;
	      vec_add1 (*bitmap0, nel);
	      /* move to new offset */
	      sbm0i = sbm2iw + 1;
	    }
	  /* try to catch up the 2nd string with first */
	  sbm2i += sbm2->elt_zero + 1;
	  sbm2++;
	}
    }
  while (sbm1 < sbm1e)
    {
      u32 sbm1iw = sbm1i + sbm1->elt_zero;
      nel.elt_bits = sbm1->elt_bits;
      if (nel.elt_bits)
	{
	  /* result is non-zero, push to output accumulator */
	  nel.elt_zero = sbm1iw - sbm0i;
	  vec_add1 (*bitmap0, nel);
	  /* move to new offset */
	  sbm0i = sbm1iw + 1;
	}
      /* try to catch up the 1st string with second */
      sbm1i += sbm1->elt_zero + 1;
      sbm1++;
    }
  while (sbm2 < sbm2e)
    {
      u32 sbm2iw = sbm2i + sbm2->elt_zero;
      nel.elt_bits = sbm2->elt_bits;
      if (nel.elt_bits)
	{
	  /* result is non-zero, push to output accumulator */
	  nel.elt_zero = sbm2iw - sbm0i;
	  vec_add1 (*bitmap0, nel);
	  /* move to new offset */
	  sbm0i = sbm2iw + 1;
	}
      /* try to catch up the 1st string with second */
      sbm2i += sbm2->elt_zero + 1;
      sbm2++;
    }
}


always_inline void
sbm_and_or (sbitmap_t ** bitmap0, sbitmap_t * bitmap1, sbitmap_t * bitmap2a,
	    sbitmap_t * bitmap2b)
{
  sbitmap_t *sbm1 = bitmap1;
  sbitmap_t *sbm2a = bitmap2a;
  sbitmap_t *sbm2b = bitmap2b;
  sbm_elt_t nel = { 0 };
  sbitmap_t *sbm1e = sbm1 + vec_len (sbm1);
  sbitmap_t *sbm2ae = sbm2a + vec_len (sbm2a);
  sbitmap_t *sbm2be = sbm2b + vec_len (sbm2b);
  u32 sbm1i = 0, sbm2ai = 0, sbm2bi = 0;
  u32 sbm0i = 0;
  u32 vlen0 = vec_len (*bitmap0);
  vec_validate (*bitmap0,
		clib_min (vec_len (bitmap1),
			  vec_len (bitmap2a) + vec_len (bitmap2b)));
  if (*bitmap0)
    {
      _vec_len (*bitmap0) = vlen0;
    }

  vec_reset_length (*bitmap0);
  while ((sbm1 < sbm1e) && ((sbm2a < sbm2ae) || (sbm2b < sbm2be)))
    {
      u32 sbm1iw = sbm1i + sbm1->elt_zero;
      u32 sbm2aiw = sbm2a < sbm2ae ? sbm2ai + sbm2a->elt_zero : ~0;
      u32 sbm2biw = sbm2b < sbm2be ? sbm2bi + sbm2b->elt_zero : ~0;

      if (sbm2aiw == sbm2biw)
	{
	  if (sbm1iw == sbm2aiw)
	    {
	      /* words aligned at the same offset */
	      nel.elt_bits =
		sbm1->elt_bits & (sbm2a->elt_bits | sbm2b->elt_bits);
	      if (nel.elt_bits)
		{
		  /* result is non-zero, push to output accumulator */
		  nel.elt_zero = sbm1iw - sbm0i;
		  vec_add1 (*bitmap0, nel);
		  /* move to new offset */
		  sbm0i = sbm1iw + 1;
		}
	      /* advance both sources */
	      sbm1i += sbm1->elt_zero + 1;
	      sbm2ai += sbm2a->elt_zero + 1;
	      sbm2bi += sbm2b->elt_zero + 1;
	      sbm1++;
	      sbm2a++;
	      sbm2b++;
	    }
	  else if (sbm1iw < sbm2aiw)
	    {
	      /* try to catch up the 1st string with second */
	      sbm1i += sbm1->elt_zero + 1;
	      sbm1++;
	    }
	  else
	    {
	      /* try to catch up the 2nd string with first */
	      sbm2ai += sbm2a->elt_zero + 1;
	      sbm2a++;
	      sbm2bi += sbm2b->elt_zero + 1;
	      sbm2b++;
	    }
	}
      else
	{
	  if (sbm2aiw < sbm2biw)
	    {
	      if (sbm1iw == sbm2aiw)
		{
		  /* words aligned at the same offset */
		  nel.elt_bits = sbm1->elt_bits & sbm2a->elt_bits;
		  if (nel.elt_bits)
		    {
		      /* result is non-zero, push to output accumulator */
		      nel.elt_zero = sbm1iw - sbm0i;
		      vec_add1 (*bitmap0, nel);
		      /* move to new offset */
		      sbm0i = sbm1iw + 1;
		    }
		  /* advance both sources */
		  sbm1i += sbm1->elt_zero + 1;
		  sbm2ai += sbm2a->elt_zero + 1;
		  sbm1++;
		  sbm2a++;
		}
	      else if (sbm1iw < sbm2aiw)
		{
		  /* try to catch up the 1st string with second */
		  sbm1i += sbm1->elt_zero + 1;
		  sbm1++;
		}
	      else
		{
		  /* try to catch up the 2nd string with first */
		  sbm2ai += sbm2a->elt_zero + 1;
		  sbm2a++;
		}
	    }
	  else
	    {
	      /* sbm2aiw > sbm2biw */
	      if (sbm1iw == sbm2biw)
		{
		  /* words aligned at the same offset */
		  nel.elt_bits = sbm1->elt_bits & sbm2b->elt_bits;
		  if (nel.elt_bits)
		    {
		      /* result is non-zero, push to output accumulator */
		      nel.elt_zero = sbm1iw - sbm0i;
		      vec_add1 (*bitmap0, nel);
		      /* move to new offset */
		      sbm0i = sbm1iw + 1;
		    }
		  /* advance both sources */
		  sbm1i += sbm1->elt_zero + 1;
		  sbm2bi += sbm2b->elt_zero + 1;
		  sbm1++;
		  sbm2b++;
		}
	      else if (sbm1iw < sbm2biw)
		{
		  /* try to catch up the 1st string with second */
		  sbm1i += sbm1->elt_zero + 1;
		  sbm1++;
		}
	      else
		{
		  /* try to catch up the 2nd string with first */
		  sbm2bi += sbm2b->elt_zero + 1;
		  sbm2b++;
		}
	    }
	}
    }
}


extern u32 max_sparse_bitmap_len;

always_inline void
sbm_set_bit (sbitmap_t ** sbm, u32 bitpos)
{
  sbm_elt_t nel = { 0 };
  u32 elt_pos = bitpos / (sizeof (nel.elt_bits) * 8);
  u32 elt_off = bitpos % (sizeof (nel.elt_bits) * 8);
  u32 sbm_len_e = sbm_len_elts (sbm);
  sbm_elt_t *el = *sbm;
  u32 elen = 0;
  vec_foreach (el, *sbm)
  {
    if (elen + el->elt_zero == elt_pos)
      {
	/* we stumbled upon the position where we can just set the bit */
	el->elt_bits |= 1 << elt_off;
	return;
      }
    else if (elen + el->elt_zero > elt_pos)
      {
	int index = el - *sbm;
	sbm_elt_t nel;
	nel.elt_bits = 1 << elt_off;
	nel.elt_zero = elt_pos - elen;
	el->elt_zero -= nel.elt_zero + 1;
	vec_insert ((*sbm), 1, index);
	(*sbm)[index] = nel;
	if (vec_len(*sbm) > max_sparse_bitmap_len) {
	  max_sparse_bitmap_len = vec_len(*sbm);
	}
	return;
      }
    /* "1" account for elt_bits in each element */
    elen += el->elt_zero + 1;
  }

  if (elt_pos >= sbm_len_e)
    {
      /* beyond the current length, append a new element */
      nel.elt_bits = 1 << elt_off;
      nel.elt_zero = elt_pos - sbm_len_e;
      vec_add1 (*sbm, nel);
      if (vec_len(*sbm) > max_sparse_bitmap_len) {
        max_sparse_bitmap_len = vec_len(*sbm);
      }
    }
  else if (elt_pos == sbm_len_e - 1)
    {
      /* fits within the last element, just set the bit */
      (*sbm)[vec_len (*sbm) - 1].elt_bits |= 1 << elt_off;
    }
  else
    {
      clib_error ("should not happen");
    }
}

always_inline u32
sbm_clear_bit (sbitmap_t ** sbm, u32 bitpos)
{
  sbm_elt_t nel = { 0 };
  u32 elt_pos = bitpos / (sizeof (nel.elt_bits) * 8);
  u32 elt_off = bitpos % (sizeof (nel.elt_bits) * 8);
  u32 sbm_len_e = sbm_len_elts (sbm);
  sbm_elt_t *el = *sbm;
  u32 elen = 0;
  vec_foreach (el, *sbm)
  {
    if (elen + el->elt_zero == elt_pos)
      {
	/* we stumbled upon the position where we can just clear the bit */
	el->elt_bits &= ~(1 << elt_off);
	return ~0;
      }
    else if (elen + el->elt_zero > elt_pos) {
	/* we are past position where bits need to be cleared - so no-op */
	return ~0;
    }
    /* "1" account for elt_bits in each element */
    elen += el->elt_zero + 1;
  }

  if (elt_pos >= sbm_len_e)
    {
      /* no op */
    }
  else if (elt_pos == sbm_len_e - 1)
    {
      /* fits within the last element, just clear the bit */
      (*sbm)[vec_len (*sbm) - 1].elt_bits &= ~(1 << elt_off);
    }
  else
    {
      clib_error ("should not happen");
    }
  return sbm_len_e + nel.elt_zero + 1;
}

always_inline
void sbmv_set_bits_mask(sbmv_u16_t *sbmv, u16 index, u16 mask, u32 bitpos)
{
  if (mask == 0) {
    sbm_set_bit(&sbmv->wildcard_bitmap, bitpos);
  } else if (mask == 0xffff) {
    sbitmap_t **n = sparse_vec_validate(sbmv->indexed_bitmaps, index);
    sbm_set_bit(n, bitpos);
  } else {
    /* simple and boring for now */
    u32 i;
    for(i=0; i<=0xffff; i++) {
      if ((i & mask) == (index & mask)) {
        sbitmap_t **n = sparse_vec_validate(sbmv->indexed_bitmaps, i);
        sbm_set_bit(n, bitpos);
      }
    }
  }
}

always_inline
void sbmv_clear_bits_mask(sbmv_u16_t *sbmv, u16 index, u16 mask, u32 bitpos)
{
  if (mask == 0) {
    sbm_clear_bit(&sbmv->wildcard_bitmap, bitpos);
  } else if (mask == 0xffff) {
    sbitmap_t **n = sparse_vec_validate(sbmv->indexed_bitmaps, index);
    sbm_clear_bit(n, bitpos);
  } else {
    /* simple and boring for now */
    u32 i;
    for(i=0; i<=0xffff; i++) {
      if ((i & mask) == (index & mask)) {
        sbitmap_t **n = sparse_vec_validate(sbmv->indexed_bitmaps, i);
        sbm_clear_bit(n, bitpos);
      }
    }
  }
}

always_inline void
sbmv_set_bits_range(sbmv_u16_t *sbmv, u16 start_index, u16 end_index, u32 bitpos)
{
  if (start_index == 0 && end_index == 65535) {
    sbm_set_bit(&sbmv->wildcard_bitmap, bitpos);
  } else if (start_index == end_index) {
    sbitmap_t **n = sparse_vec_validate(sbmv->indexed_bitmaps, start_index);
    sbm_set_bit(n, bitpos);
  } else {
    u32 i;
    for(i=start_index; i<=end_index; i++) {
        sbitmap_t **n = sparse_vec_validate(sbmv->indexed_bitmaps, i);
        sbm_set_bit(n, bitpos);
    }
  }
}

always_inline void
sbmv_clear_bits_range(sbmv_u16_t *sbmv, u16 start_index, u16 end_index, u32 bitpos)
{
  if (start_index == 0 && end_index == 65535) {
    sbm_clear_bit(&sbmv->wildcard_bitmap, bitpos);
  } else if (start_index == end_index) {
    sbitmap_t **n = sparse_vec_validate(sbmv->indexed_bitmaps, start_index);
    sbm_clear_bit(n, bitpos);
  } else {
    u32 i;
    for(i=start_index; i<=end_index; i++) {
        sbitmap_t **n = sparse_vec_validate(sbmv->indexed_bitmaps, i);
        sbm_clear_bit(n, bitpos);
    }
  }
}

always_inline
void sbmv_setclear_bits_mask(sbmv_u16_t *sbmv, u16 index, u16 mask, u32 bitpos, int is_set)
{
  if (is_set) {
    sbmv_set_bits_mask(sbmv, index, mask, bitpos);
  } else {
    sbmv_clear_bits_mask(sbmv, index, mask, bitpos);
  }
}

always_inline void
sbmv_setclear_bits_range(sbmv_u16_t *sbmv, u16 start_index, u16 end_index, u32 bitpos, int is_set)
{
  if (is_set) {
    sbmv_set_bits_range(sbmv, start_index, end_index, bitpos);
  } else {
    sbmv_clear_bits_range(sbmv, start_index, end_index, bitpos);
  }
}



#endif

