/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2025 Cisco Systems, Inc.
 */

#include <vppinfra/error.h>
#include <http/http2/hpack.h>
#include <http/http2/huffman_table.h>

__clib_export uword
hpack_decode_int (u8 **src, u8 *end, u8 prefix_len)
{
  uword value, new_value;
  u8 *p, shift = 0, byte;
  u16 prefix_max;

  ASSERT (*src < end);
  ASSERT (prefix_len >= 1 && prefix_len <= 8);

  p = *src;
  prefix_max = (1 << prefix_len) - 1;
  value = *p & (u8) prefix_max;
  p++;
  /* if integer value is less than 2^prefix_len-1 it's encoded within prefix */
  if (value != prefix_max)
    {
      *src = p;
      return value;
    }

  while (p != end)
    {
      byte = *p;
      p++;
      new_value = value + ((uword) (byte & 0x7F) << shift);
      shift += 7;
      /* check for overflow */
      if (new_value < value)
	return HPACK_INVALID_INT;
      value = new_value;
      /* MSB of the last byte is zero */
      if ((byte & 0x80) == 0)
	{
	  *src = p;
	  return value;
	}
    }

  return HPACK_INVALID_INT;
}

int
hpack_decode_huffman (u8 **src, u8 *end, u8 **buf, uword *buf_len)
{
  u64 accumulator = 0;
  u8 accumulator_len = 0;
  u8 *p;
  hpack_huffman_code_t *code;

  p = *src;
  while (1)
    {
      /* out of space?  */
      if (*buf_len == 0)
	return -1;
      /* refill */
      while (p < end && accumulator_len <= 56)
	{
	  accumulator <<= 8;
	  accumulator_len += 8;
	  accumulator |= (u64) *p++;
	}
      /* first try short codes (5 - 8 bits) */
      code =
	&huff_code_table_fast[(u8) (accumulator >> (accumulator_len - 8))];
      /* zero code length mean no luck */
      if (PREDICT_TRUE (code->code_len))
	{
	  **buf = code->symbol;
	  (*buf)++;
	  (*buf_len)--;
	  accumulator_len -= code->code_len;
	}
      else
	{
	  /* slow path / long codes (10 - 30 bits) */
	  u32 tmp;
	  /* group boundaries are aligned to 32 bits */
	  if (accumulator_len < 32)
	    tmp = accumulator << (32 - accumulator_len);
	  else
	    tmp = accumulator >> (accumulator_len - 32);
	  /* figure out which interval code falls into, this is possible
	   * because HPACK use canonical Huffman codes
	   * see Schwartz, E. and B. Kallick, “Generating a canonical prefix
	   * encoding”
	   */
	  hpack_huffman_group_t *hg = hpack_huffman_get_group (tmp);
	  /* trim code to correct length */
	  u32 code = (accumulator >> (accumulator_len - hg->code_len)) &
		     ((1 << hg->code_len) - 1);
	  /* find symbol in the list */
	  **buf = hg->symbols[code - hg->first_code];
	  (*buf)++;
	  (*buf_len)--;
	  accumulator_len -= hg->code_len;
	}
      /* all done */
      if (p == end && accumulator_len < 8)
	{
	  /* there might be one more symbol encoded with short code */
	  if (accumulator_len >= 5)
	    {
	      /* first check EOF case */
	      if (((1 << accumulator_len) - 1) ==
		  (accumulator & ((1 << accumulator_len) - 1)))
		break;

	      /* out of space?  */
	      if (*buf_len == 0)
		return -1;

	      /* if bogus EOF check bellow will fail */
	      code = &huff_code_table_fast[(u8) (accumulator
						 << (8 - accumulator_len))];
	      **buf = code->symbol;
	      (*buf)++;
	      (*buf_len)--;
	      accumulator_len -= code->code_len;
	      /* end at byte boundary? */
	      if (accumulator_len == 0)
		break;
	    }
	  /* we must end with EOF here */
	  if (((1 << accumulator_len) - 1) !=
	      (accumulator & ((1 << accumulator_len) - 1)))
	    return -1;
	  break;
	}
    }
  return 0;
}

__clib_export int
hpack_decode_string (u8 **src, u8 *end, u8 **buf, uword *buf_len)
{
  u8 *p, is_huffman;
  uword len;

  ASSERT (*src < end);

  p = *src;
  /* H flag in first bit */
  is_huffman = *p & 0x80;

  /* length is integer with 7 bit prefix */
  len = hpack_decode_int (&p, end, 7);
  if (PREDICT_FALSE (len == HPACK_INVALID_INT))
    return -1;

  /* do we have everything? */
  if (len > (end - p))
    return -1;

  if (is_huffman)
    {
      *src = (p + len);
      return hpack_decode_huffman (&p, p + len, buf, buf_len);
    }
  else
    {
      /* enough space? */
      if (len > *buf_len)
	return -1;

      clib_memcpy (*buf, p, len);
      *buf_len -= len;
      *buf += len;
      *src = (p + len);
      return 0;
    }
}

__clib_export u8 *
hpack_encode_int (u8 *dst, uword value, u8 prefix_len)
{
  u16 prefix_max;

  ASSERT (prefix_len >= 1 && prefix_len <= 8);

  prefix_max = (1 << prefix_len) - 1;

  /* if integer value is less than 2^prefix_len-1 it's encoded within prefix */
  if (value < prefix_max)
    {
      *dst++ |= (u8) value;
      return dst;
    }

  /* otherwise all bits of the prefix are set to 1 */
  *dst++ |= (u8) prefix_max;
  /* and the value is decreased by 2^prefix_len-1 */
  value -= prefix_max;
  /* MSB of each byte is used as continuation flag */
  for (; value >= 0x80; value >>= 7)
    *dst++ = 0x80 | (value & 0x7F);
  /* except for the last byte */
  *dst++ = (u8) value;

  return dst;
}

uword
hpack_huffman_encoded_len (const u8 *value, uword value_len)
{
  uword len = 0;
  u8 *end;
  hpack_huffman_symbol_t *sym;

  end = (u8 *) value + value_len;
  while (value != end)
    {
      sym = &huff_sym_table[*value++];
      len += sym->code_len;
    }
  /* round up to byte boundary */
  return (len + 7) / 8;
}

u8 *
hpack_encode_huffman (u8 *dst, const u8 *value, uword value_len)
{
  u8 *end;
  hpack_huffman_symbol_t *sym;
  u8 accumulator_len = 40; /* leftover (1 byte) + max code_len (4 bytes) */
  u64 accumulator = 0;	   /* to fit leftover and current code */

  end = (u8 *) value + value_len;

  while (value != end)
    {
      sym = &huff_sym_table[*value++];
      /* add current code to leftover of previous one */
      accumulator |= (u64) sym->code << (accumulator_len - sym->code_len);
      accumulator_len -= sym->code_len;
      /* write only fully occupied bytes (max 4) */
      switch (accumulator_len)
	{
	case 1 ... 8:
#define WRITE_BYTE()                                                          \
  *dst = (u8) (accumulator >> 32);                                            \
  accumulator_len += 8;                                                       \
  accumulator <<= 8;                                                          \
  dst++;
	  WRITE_BYTE ();
	case 9 ... 16:
	  WRITE_BYTE ();
	case 17 ... 24:
	  WRITE_BYTE ();
	case 25 ... 32:
	  WRITE_BYTE ();
	default:
	  break;
	}
    }

  /* padding (0-7 bits)*/
  ASSERT (accumulator_len > 32 && accumulator_len <= 40);
  if (accumulator_len != 40)
    {
      accumulator |= (u64) 0x7F << (accumulator_len - 7);
      *dst = (u8) (accumulator >> 32);
      dst++;
    }
  return dst;
}

__clib_export u8 *
hpack_encode_string (u8 *dst, const u8 *value, uword value_len)
{
  uword huff_len;

  huff_len = hpack_huffman_encoded_len (value, value_len);
  /* raw bytes might take fewer bytes */
  if (huff_len >= value_len)
    {
      *dst = 0; /* clear H flag */
      dst = hpack_encode_int (dst, value_len, 7);
      clib_memcpy (dst, value, value_len);
      return dst + value_len;
    }

  *dst = 0x80; /* set H flag */
  dst = hpack_encode_int (dst, huff_len, 7);
  dst = hpack_encode_huffman (dst, value, value_len);

  return dst;
}
