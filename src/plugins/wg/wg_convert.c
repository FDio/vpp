/*
 * Copyright (c) 2020 Doc.ai and/or its affiliates.
 * Copyright (c) 2005-2011 Jouni Malinen <j@w1.fi>.
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

#include <wg/wg_convert.h>

static const u8 base64_table[65] =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/**
 * base64_encode - Base64 encode
 * @src: Data to be encoded
 * @src_len: Length of the data to be encoded
 * @out: Pointer to output data
 * Returns: true if encoded ok
 */
bool
base64_encode (const u8 * src, size_t src_len, u8 * out)
{
  u8 *pos;
  const u8 *end, *in;
  size_t olen;

  olen = src_len * 4 / 3 + 4;	/* 3-byte blocks to 4-byte */
  olen += olen / 72;		/* line feeds */
  olen++;			/* nul termination */
  if (olen < src_len)
    return false;		/* integer overflow */

  end = src + src_len;
  in = src;
  pos = out;
  while (end - in >= 3)
    {
      *pos++ = base64_table[in[0] >> 2];
      *pos++ = base64_table[((in[0] & 0x03) << 4) | (in[1] >> 4)];
      *pos++ = base64_table[((in[1] & 0x0f) << 2) | (in[2] >> 6)];
      *pos++ = base64_table[in[2] & 0x3f];
      in += 3;
    }

  if (end - in)
    {
      *pos++ = base64_table[in[0] >> 2];
      if (end - in == 1)
	{
	  *pos++ = base64_table[(in[0] & 0x03) << 4];
	  *pos++ = '=';
	}
      else
	{
	  *pos++ = base64_table[((in[0] & 0x03) << 4) | (in[1] >> 4)];
	  *pos++ = base64_table[(in[1] & 0x0f) << 2];
	}
      *pos++ = '=';
    }
  *pos = '\0';

  return true;
}


/**
 * base64_decode - Base64 decode
 * @src: Data to be decoded
 * @src_len: Length of the data to be decoded
 * @out: Pointer to output data
 * Returns: true if decoded ok
 */
bool
base64_decode (const u8 * src, size_t src_len, u8 * out)
{
  u8 dtable[256], *pos, block[4], tmp;
  size_t i, count;
  int pad = 0;

  clib_memset (dtable, 0x80, 256);
  for (i = 0; i < sizeof (base64_table) - 1; i++)
    dtable[base64_table[i]] = (u8) i;
  dtable['='] = 0;

  count = 0;
  for (i = 0; i < src_len; i++)
    {
      if (dtable[src[i]] != 0x80)
	count++;
    }

  if (count == 0 || count % 4)
    return false;

  pos = out;

  count = 0;
  for (i = 0; i < src_len; i++)
    {
      tmp = dtable[src[i]];
      if (tmp == 0x80)
	continue;

      if (src[i] == '=')
	pad++;
      block[count] = tmp;
      count++;
      if (count == 4)
	{
	  *pos++ = (block[0] << 2) | (block[1] >> 4);
	  *pos++ = (block[1] << 4) | (block[2] >> 2);
	  *pos++ = (block[2] << 6) | block[3];
	  count = 0;
	  if (pad)
	    {
	      if (pad == 1)
		pos--;
	      else if (pad == 2)
		pos -= 2;
	      else
		{
		  return false;
		}
	      break;
	    }
	}
    }
  return true;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
