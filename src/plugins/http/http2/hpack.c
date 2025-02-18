/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2025 Cisco Systems, Inc.
 */

#include <vppinfra/error.h>
#include <http/http.h>
#include <http/http_header_names.h>
#include <http/http2/hpack.h>
#include <http/http2/huffman_table.h>

#define HPACK_STATIC_TABLE_SIZE 61

typedef struct
{
  char *name;
  uword name_len;
  char *value;
  uword value_len;
} hpack_static_table_entry;

#define name_val_token_lit(name, value)                                       \
  (name), sizeof (name) - 1, (value), sizeof (value) - 1

static hpack_static_table_entry hpack_static_table[HPACK_STATIC_TABLE_SIZE] = {
  { name_val_token_lit (":authority", "") },
  { name_val_token_lit (":method", "GET") },
  { name_val_token_lit (":method", "POST") },
  { name_val_token_lit (":path", "/") },
  { name_val_token_lit (":path", "/index.html") },
  { name_val_token_lit (":scheme", "http") },
  { name_val_token_lit (":scheme", "https") },
  { name_val_token_lit (":status", "200") },
  { name_val_token_lit (":status", "204") },
  { name_val_token_lit (":status", "206") },
  { name_val_token_lit (":status", "304") },
  { name_val_token_lit (":status", "400") },
  { name_val_token_lit (":status", "404") },
  { name_val_token_lit (":status", "500") },
  { name_val_token_lit ("accept-charset", "") },
  { name_val_token_lit ("accept-encoding", "gzip, deflate") },
  { name_val_token_lit ("accept-language", "") },
  { name_val_token_lit ("accept-ranges", "") },
  { name_val_token_lit ("accept", "") },
  { name_val_token_lit ("access-control-allow-origin", "") },
  { name_val_token_lit ("age", "") },
  { name_val_token_lit ("allow", "") },
  { name_val_token_lit ("authorization", "") },
  { name_val_token_lit ("cache-control", "") },
  { name_val_token_lit ("content-disposition", "") },
  { name_val_token_lit ("content-encoding", "") },
  { name_val_token_lit ("content-language", "") },
  { name_val_token_lit ("content-length", "") },
  { name_val_token_lit ("content-location", "") },
  { name_val_token_lit ("content-range", "") },
  { name_val_token_lit ("content-type", "") },
  { name_val_token_lit ("cookie", "") },
  { name_val_token_lit ("date", "") },
  { name_val_token_lit ("etag", "") },
  { name_val_token_lit ("etag", "") },
  { name_val_token_lit ("expires", "") },
  { name_val_token_lit ("from", "") },
  { name_val_token_lit ("host", "") },
  { name_val_token_lit ("if-match", "") },
  { name_val_token_lit ("if-modified-since", "") },
  { name_val_token_lit ("if-none-match", "") },
  { name_val_token_lit ("if-range", "") },
  { name_val_token_lit ("if-unmodified-since", "") },
  { name_val_token_lit ("last-modified", "") },
  { name_val_token_lit ("link", "") },
  { name_val_token_lit ("location", "") },
  { name_val_token_lit ("max-forwards", "") },
  { name_val_token_lit ("proxy-authenticate", "") },
  { name_val_token_lit ("proxy-authorization", "") },
  { name_val_token_lit ("range", "") },
  { name_val_token_lit ("referer", "") },
  { name_val_token_lit ("refresh", "") },
  { name_val_token_lit ("retry-after", "") },
  { name_val_token_lit ("server", "") },
  { name_val_token_lit ("set-cookie", "") },
  { name_val_token_lit ("strict-transport-security", "") },
  { name_val_token_lit ("transfer-encoding", "") },
  { name_val_token_lit ("user-agent", "") },
  { name_val_token_lit ("vary", "") },
  { name_val_token_lit ("via", "") },
  { name_val_token_lit ("www-authenticate", "") },
};

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

static int
hpack_get_table_entry (uword index, http_token_t *name, http_token_t *value,
		       u8 value_is_indexed)
{
  if (index <= HPACK_STATIC_TABLE_SIZE)
    {
      hpack_static_table_entry *e = &hpack_static_table[index - 1];
      name->base = e->name;
      name->len = e->name_len;
      if (value_is_indexed)
	{
	  if (PREDICT_FALSE (e->value_len == 0))
	    return -1;
	  value->base = e->value;
	  value->len = e->value_len;
	}
      return 0;
    }
  else
    {
      /* FIXME */
      return -1;
    }
}

__clib_export int
hpack_decode_header (u8 **src, u8 *end, u8 **buf, uword *buf_len,
		     u32 *name_len, u32 *value_len)
{
  u8 *p;
  u8 value_is_indexed = 0, add_new_entry = 0;
  uword old_len, new_max, index = 0;
  http_token_t name, value;
  int rv;

  ASSERT (*src < end);
  p = *src;

  /* dynamic table size update */
  while ((*p & 0xE0) == 0x20)
    {
      new_max = hpack_decode_int (&p, end, 5);
      if (new_max == HPACK_INVALID_INT)
	return -1;
      /* TODO check new_max and resize */
      if (p == end)
	return -1;
    }

  if (*p & 0x80) /* indexed header field */
    {
      index = hpack_decode_int (&p, end, 7);
      /* index value of 0 is not used */
      if (index == 0 || index == HPACK_INVALID_INT)
	return -1;
      value_is_indexed = 1;
    }
  else if (*p > 0x40) /* incremental indexing - indexed name */
    {
      index = hpack_decode_int (&p, end, 7);
      /* index value of 0 is not used */
      if (index == 0 || index == HPACK_INVALID_INT)
	return -1;
      add_new_entry = 1;
    }
  else if (*p == 0x40) /* incremental indexing - new name */
    {
      add_new_entry = 1;
      p++;
    }
  else /* without indexing / never indexed */
    {
      if ((*p & 0x0F) == 0) /* new name */
	p++;
      else /* indexed name */
	{
	  index = hpack_decode_int (&p, end, 7);
	  /* index value of 0 is not used */
	  if (index == 0 || index == HPACK_INVALID_INT)
	    return -1;
	}
    }

  if (index)
    {
      rv = hpack_get_table_entry (index, &name, &value, value_is_indexed);
      if (rv != 0 || name.len > *buf_len)
	return -1;
      clib_memcpy (*buf, name.base, name.len);
      *buf_len -= name.len;
      *buf += name.len;
      *name_len = name.len;
      if (value_is_indexed)
	{
	  if (value.len > *buf_len)
	    return -1;
	  clib_memcpy (*buf, value.base, value.len);
	  *buf_len -= value.len;
	  *buf += value.len;
	  *value_len = value.len;
	}
    }
  else
    {
      old_len = *buf_len;
      rv = hpack_decode_string (&p, end, buf, buf_len);
      if (rv != 0)
	return -1;
      *name_len = old_len - *buf_len;
    }

  if (!value_is_indexed)
    {
      old_len = *buf_len;
      rv = hpack_decode_string (&p, end, buf, buf_len);
      if (rv != 0)
	return -1;
      *value_len = old_len - *buf_len;
    }

  if (add_new_entry)
    {
      /* FIXME */
      return -1;
    }

  return 0;
}
