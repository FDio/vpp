/*
 * Copyright (c) 2025 AmneziaWG 1.5 i-header support for VPP
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

#include <vppinfra/format.h>
#include <vppinfra/time.h>
#include <vppinfra/random.h>
#include <wireguard/wireguard_awg_tags.h>
#include <wireguard/wireguard_awg.h>

/* External random state from wireguard_awg.c */
extern __thread u64 wg_awg_random_state;

/* Parse hex string (with or without 0x prefix) */
static int
parse_hex_string (const char *hex_str, u8 **out_data, u32 *out_len)
{
  const char *p = hex_str;
  u32 len, i;
  u8 *data;

  /* Skip 0x or 0X prefix */
  if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X'))
    p += 2;

  len = strlen (p);
  if (len == 0 || len % 2 != 0)
    return -1; /* Must be even number of hex digits */

  *out_len = len / 2;
  *out_data = data = clib_mem_alloc (*out_len);

  for (i = 0; i < *out_len; i++)
    {
      char byte_str[3] = { p[i * 2], p[i * 2 + 1], 0 };
      data[i] = (u8) strtol (byte_str, NULL, 16);
    }

  return 0;
}

/* Parse tag string format: <tagname param> */
int
wg_awg_parse_tag_string (const char *tag_string, wg_awg_i_header_t *hdr)
{
  const char *p = tag_string;
  wg_awg_tag_t tag;
  u8 has_counter = 0, has_timestamp = 0;

  if (!tag_string || !hdr)
    return -1;

  clib_memset (hdr, 0, sizeof (*hdr));
  hdr->tags = NULL;

  while (*p)
    {
      /* Skip whitespace */
      while (*p == ' ' || *p == '\t' || *p == '\n')
	p++;

      if (*p == '\0')
	break;

      if (*p != '<')
	{
	  clib_warning ("Expected '<' at position %ld", p - tag_string);
	  goto error;
	}
      p++; /* Skip '<' */

      clib_memset (&tag, 0, sizeof (tag));

      /* Parse tag type */
      if (p[0] == 'b' && p[1] == ' ')
	{
	  /* Bytes tag: <b 0xHEXDATA> */
	  tag.type = WG_AWG_TAG_BYTES;
	  p += 2;

	  /* Find closing > */
	  const char *end = strchr (p, '>');
	  if (!end)
	    {
	      clib_warning ("Missing '>' for bytes tag");
	      goto error;
	    }

	  /* Extract hex string */
	  char *hex_str = clib_mem_alloc (end - p + 1);
	  clib_memcpy (hex_str, p, end - p);
	  hex_str[end - p] = '\0';

	  if (parse_hex_string (hex_str, &tag.bytes.data, &tag.bytes.len) < 0)
	    {
	      clib_mem_free (hex_str);
	      clib_warning ("Invalid hex data in bytes tag");
	      goto error;
	    }

	  clib_mem_free (hex_str);
	  p = end + 1;
	}
      else if (p[0] == 'c' && p[1] == '>')
	{
	  /* Counter tag: <c> */
	  if (has_counter)
	    {
	      clib_warning ("Only one <c> tag allowed per i-header");
	      goto error;
	    }
	  tag.type = WG_AWG_TAG_COUNTER;
	  has_counter = 1;
	  p += 2;
	}
      else if (p[0] == 't' && p[1] == '>')
	{
	  /* Timestamp tag: <t> */
	  if (has_timestamp)
	    {
	      clib_warning ("Only one <t> tag allowed per i-header");
	      goto error;
	    }
	  tag.type = WG_AWG_TAG_TIMESTAMP;
	  has_timestamp = 1;
	  p += 2;
	}
      else if (p[0] == 'r' && p[1] == ' ')
	{
	  /* Random bytes tag: <r N> */
	  tag.type = WG_AWG_TAG_RANDOM;
	  p += 2;
	  tag.random_len = strtoul (p, (char **) &p, 10);
	  if (*p != '>')
	    {
	      clib_warning ("Expected '>' after random length");
	      goto error;
	    }
	  p++;
	}
      else if (p[0] == 'r' && p[1] == 'c' && p[2] == ' ')
	{
	  /* Random ASCII tag: <rc N> */
	  tag.type = WG_AWG_TAG_RANDOM_ASCII;
	  p += 3;
	  tag.random_len = strtoul (p, (char **) &p, 10);
	  if (*p != '>')
	    {
	      clib_warning ("Expected '>' after random ASCII length");
	      goto error;
	    }
	  p++;
	}
      else if (p[0] == 'r' && p[1] == 'd' && p[2] == ' ')
	{
	  /* Random digits tag: <rd N> */
	  tag.type = WG_AWG_TAG_RANDOM_DIGIT;
	  p += 3;
	  tag.random_len = strtoul (p, (char **) &p, 10);
	  if (*p != '>')
	    {
	      clib_warning ("Expected '>' after random digit length");
	      goto error;
	    }
	  p++;
	}
      else
	{
	  clib_warning ("Unknown tag type at position %ld", p - tag_string);
	  goto error;
	}

      /* Add tag to vector */
      vec_add1 (hdr->tags, tag);
    }

  hdr->enabled = 1;
  hdr->counter = 0;

  /* Calculate total size */
  hdr->total_size = wg_awg_i_header_size (hdr);

  return 0;

error:
  wg_awg_free_i_header (hdr);
  return -1;
}

/* Calculate total packet size */
u32
wg_awg_i_header_size (const wg_awg_i_header_t *hdr)
{
  u32 total = 0;
  wg_awg_tag_t *tag;

  if (!hdr || !hdr->enabled)
    return 0;

  vec_foreach (tag, hdr->tags)
    {
      switch (tag->type)
	{
	case WG_AWG_TAG_BYTES:
	  total += tag->bytes.len;
	  break;
	case WG_AWG_TAG_COUNTER:
	case WG_AWG_TAG_TIMESTAMP:
	  total += 8; /* 64-bit values */
	  break;
	case WG_AWG_TAG_RANDOM:
	case WG_AWG_TAG_RANDOM_ASCII:
	case WG_AWG_TAG_RANDOM_DIGIT:
	  total += tag->random_len;
	  break;
	}
    }

  return total;
}

/* Generate packet from i-header tags */
u8 *
wg_awg_generate_i_header_packet (wg_awg_i_header_t *hdr)
{
  u8 *packet, *p;
  wg_awg_tag_t *tag;
  u32 total_size;
  u64 value;
  u32 i;

  if (!hdr || !hdr->enabled)
    return NULL;

  total_size = hdr->total_size;
  if (total_size == 0)
    return NULL;

  packet = clib_mem_alloc (total_size);
  p = packet;

  vec_foreach (tag, hdr->tags)
    {
      switch (tag->type)
	{
	case WG_AWG_TAG_BYTES:
	  /* Copy literal hex bytes */
	  clib_memcpy (p, tag->bytes.data, tag->bytes.len);
	  p += tag->bytes.len;
	  break;

	case WG_AWG_TAG_COUNTER:
	  /* 64-bit big-endian counter */
	  value = clib_host_to_net_u64 ((u64) hdr->counter);
	  clib_memcpy (p, &value, 8);
	  p += 8;
	  hdr->counter++; /* Increment for next packet */
	  break;

	case WG_AWG_TAG_TIMESTAMP:
	  /* 64-bit big-endian unix timestamp */
	  value = clib_host_to_net_u64 ((u64) unix_time_now ());
	  clib_memcpy (p, &value, 8);
	  p += 8;
	  break;

	case WG_AWG_TAG_RANDOM:
	  /* Random bytes */
	  wg_awg_generate_junk (p, tag->random_len);
	  p += tag->random_len;
	  break;

	case WG_AWG_TAG_RANDOM_ASCII:
	  /* Random alphanumeric ASCII */
	  for (i = 0; i < tag->random_len; i++)
	    {
	      u32 rand = random_u32 (&wg_awg_random_state);
	      u32 char_set_size = 62; /* A-Z, a-z, 0-9 */
	      u32 idx = rand % char_set_size;

	      if (idx < 26)
		p[i] = 'A' + idx;
	      else if (idx < 52)
		p[i] = 'a' + (idx - 26);
	      else
		p[i] = '0' + (idx - 52);
	    }
	  p += tag->random_len;
	  break;

	case WG_AWG_TAG_RANDOM_DIGIT:
	  /* Random digits 0-9 */
	  for (i = 0; i < tag->random_len; i++)
	    {
	      u32 rand = random_u32 (&wg_awg_random_state);
	      p[i] = '0' + (rand % 10);
	    }
	  p += tag->random_len;
	  break;
	}
    }

  return packet;
}

/* Free i-header resources */
void
wg_awg_free_i_header (wg_awg_i_header_t *hdr)
{
  wg_awg_tag_t *tag;

  if (!hdr)
    return;

  vec_foreach (tag, hdr->tags)
    {
      if (tag->type == WG_AWG_TAG_BYTES && tag->bytes.data)
	{
	  clib_mem_free (tag->bytes.data);
	  tag->bytes.data = NULL;
	}
    }

  vec_free (hdr->tags);
  hdr->tags = NULL;
  hdr->enabled = 0;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
