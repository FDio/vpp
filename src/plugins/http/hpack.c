/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2025 Cisco Systems, Inc.
 */

#include <vppinfra/error.h>
#include <http/hpack.h>
#include <http/huffman_table.h>

__clib_export uword
hpack_decode_int (u8 **src, u8 *end, u8 prefix_len)
{
  uword value, new_value;
  u8 *p, byte;
  u16 shift = 0, prefix_max;

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
      new_value = value + (uword) ((byte & 0x7F) << shift);
      shift += 7;
      /* check for overflow */
      if (new_value < value)
	return HPACK_INVALID_INTEGER;
      value = new_value;
      /* MSB of the last byte is zero */
      if ((byte & 0x80) == 0)
	{
	  *src = p;
	  return value;
	}
    }

  return HPACK_INVALID_INTEGER;
}

__clib_export uword
hpack_decode_string (u8 **src, u8 *end, u8 **buf, uword *buf_len)
{
  u8 *p, is_huffman;
  uword len;

  ASSERT (*src < end);

  p = *src;
  is_huffman = *p & 0x80;

  len = hpack_decode_int (&p, end, 7);
  if (PREDICT_FALSE (len == HPACK_INVALID_INTEGER))
    return 0;

  if (len > (end - p))
    return 0;

  if (is_huffman)
    {
      /* FIXME */
      return 0;
    }

  if (len > *buf_len)
    return 0;

  clib_memcpy (*buf, p, len);
  *buf_len -= len;
  *buf += len;
  *src = (p + len);
  return len;
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

static inline uword
http_encode_huffman_len (const u8 *value, uword value_len)
{
  uword len = 0;
  u8 *end;
  http_huffman_symbol_t *sym;

  end = (u8 *) value + value_len;
  while (value != end)
    {
      sym = &huff_sym_table[*value++];
      len += sym->code_len;
    }
  /* add padding */
  return (len + 7) / 8;
}

static inline u8 *
hpack_encode_huffman (u8 *dst, const u8 *value, uword value_len)
{
  u8 *end;
  http_huffman_symbol_t *sym;
  u8 left = 40; /* leftover (1 byte) + max code_len (4 bytes) */
  u64 tmp = 0;	/* to fit leftover and current code */

  end = (u8 *) value + value_len;

  while (value != end)
    {
      sym = &huff_sym_table[*value++];
      /* add current code to leftover of previous one */
      tmp |= (u64) sym->code << (left - sym->code_len);
      left -= sym->code_len;
      /* write only fully occupied bytes (max 4) */
      while (left <= 32)
	{
	  *dst = (u8) (tmp >> 32);
	  left += 8;
	  tmp <<= 8;
	  dst++;
	}
    }

  /* padding (0-7 bits)*/
  ASSERT (left > 32 && left <= 40);
  if (left != 40)
    {
      tmp |= (u64) 0x7F << (left - 7);
      *dst = (u8) (tmp >> 32);
      dst++;
    }
  return dst;
}

__clib_export u8 *
hpack_encode_string (u8 *dst, const u8 *value, uword value_len)
{
  uword huff_len;

  huff_len = http_encode_huffman_len (value, value_len);
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
