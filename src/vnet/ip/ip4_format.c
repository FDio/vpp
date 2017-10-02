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
 * ip/ip4_format.c: ip4 formatting
 *
 * Copyright (c) 2008 Eliot Dresselhaus
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 *  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 *  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 *  NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 *  LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 *  OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 *  WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#include <vnet/ip/ip.h>

/* Format an IP4 address. */
u8 *
format_ip4_address (u8 * s, va_list * args)
{
  u8 *a = va_arg (*args, u8 *);
  return format (s, "%d.%d.%d.%d", a[0], a[1], a[2], a[3]);
}

/* Format an IP4 route destination and length. */
u8 *
format_ip4_address_and_length (u8 * s, va_list * args)
{
  u8 *a = va_arg (*args, u8 *);
  u8 l = va_arg (*args, u32);
  return format (s, "%U/%d", format_ip4_address, a, l);
}

/* Parse an IP4 address %d.%d.%d.%d. */
uword
unformat_ip4_address (unformat_input_t * input, va_list * args)
{
  u8 *result = va_arg (*args, u8 *);
  unsigned a[4];

  if (!unformat (input, "%d.%d.%d.%d", &a[0], &a[1], &a[2], &a[3]))
    return 0;

  if (a[0] >= 256 || a[1] >= 256 || a[2] >= 256 || a[3] >= 256)
    return 0;

  result[0] = a[0];
  result[1] = a[1];
  result[2] = a[2];
  result[3] = a[3];

  return 1;
}

/* Format an IP4 header. */
u8 *
format_ip4_header (u8 * s, va_list * args)
{
  ip4_header_t *ip = va_arg (*args, ip4_header_t *);
  u32 max_header_bytes = va_arg (*args, u32);
  u32 ip_version, header_bytes;
  u32 indent;

  /* Nothing to do. */
  if (max_header_bytes < sizeof (ip[0]))
    return format (s, "IP header truncated");

  indent = format_get_indent (s);
  indent += 2;

  ip_version = (ip->ip_version_and_header_length >> 4);
  header_bytes = (ip->ip_version_and_header_length & 0xf) * sizeof (u32);

  s = format (s, "%U: %U -> %U",
	      format_ip_protocol, ip->protocol,
	      format_ip4_address, ip->src_address.data,
	      format_ip4_address, ip->dst_address.data);

  /* Show IP version and header length only with unexpected values. */
  if (ip_version != 4 || header_bytes != sizeof (ip4_header_t))
    s = format (s, "\n%Uversion %d, header length %d",
		format_white_space, indent, ip_version, header_bytes);

  s = format (s, "\n%Utos 0x%02x, ttl %d, length %d, checksum 0x%04x",
	      format_white_space, indent,
	      ip->tos, ip->ttl,
	      clib_net_to_host_u16 (ip->length),
	      clib_net_to_host_u16 (ip->checksum));

  /* Check and report invalid checksums. */
  {
    u16 c = ip4_header_checksum (ip);
    if (c != ip->checksum)
      s = format (s, " (should be 0x%04x)", clib_net_to_host_u16 (c));
  }

  {
    u32 f = clib_net_to_host_u16 (ip->flags_and_fragment_offset);
    u32 o;

    s = format (s, "\n%Ufragment id 0x%04x",
		format_white_space, indent,
		clib_net_to_host_u16 (ip->fragment_id));

    /* Fragment offset. */
    o = 8 * (f & 0x1fff);
    f ^= o;
    if (o != 0)
      s = format (s, " offset %d", o);

    if (f != 0)
      {
	s = format (s, ", flags ");
#define _(l) if (f & IP4_HEADER_FLAG_##l) s = format (s, #l);
	_(MORE_FRAGMENTS);
	_(DONT_FRAGMENT);
	_(CONGESTION);
#undef _
      }
  }

  /* Recurse into next protocol layer. */
  if (max_header_bytes != 0 && header_bytes < max_header_bytes)
    {
      ip_main_t *im = &ip_main;
      ip_protocol_info_t *pi = ip_get_protocol_info (im, ip->protocol);

      if (pi && pi->format_header)
	s = format (s, "\n%U%U",
		    format_white_space, indent - 2, pi->format_header,
		    /* next protocol header */ (void *) ip + header_bytes,
		    max_header_bytes - header_bytes);
    }

  return s;
}

/* Parse an IP4 header. */
uword
unformat_ip4_header (unformat_input_t * input, va_list * args)
{
  u8 **result = va_arg (*args, u8 **);
  ip4_header_t *ip;
  int old_length;

  /* Allocate space for IP header. */
  {
    void *p;

    old_length = vec_len (*result);
    vec_add2 (*result, p, sizeof (ip4_header_t));
    ip = p;
  }

  memset (ip, 0, sizeof (ip[0]));
  ip->ip_version_and_header_length = IP4_VERSION_AND_HEADER_LENGTH_NO_OPTIONS;

  if (!unformat (input, "%U: %U -> %U",
		 unformat_ip_protocol, &ip->protocol,
		 unformat_ip4_address, &ip->src_address,
		 unformat_ip4_address, &ip->dst_address))
    return 0;

  /* Parse options. */
  while (1)
    {
      int i, j;

      if (unformat (input, "tos %U", unformat_vlib_number, &i))
	ip->tos = i;

      else if (unformat (input, "ttl %U", unformat_vlib_number, &i))
	ip->ttl = i;

      else if (unformat (input, "fragment id %U offset %U",
			 unformat_vlib_number, &i, unformat_vlib_number, &j))
	{
	  ip->fragment_id = clib_host_to_net_u16 (i);
	  ip->flags_and_fragment_offset |=
	    clib_host_to_net_u16 ((i / 8) & 0x1fff);
	}

      /* Flags. */
      else if (unformat (input, "mf") || unformat (input, "MF"))
	ip->flags_and_fragment_offset |=
	  clib_host_to_net_u16 (IP4_HEADER_FLAG_MORE_FRAGMENTS);

      else if (unformat (input, "df") || unformat (input, "DF"))
	ip->flags_and_fragment_offset |=
	  clib_host_to_net_u16 (IP4_HEADER_FLAG_DONT_FRAGMENT);

      else if (unformat (input, "ce") || unformat (input, "CE"))
	ip->flags_and_fragment_offset |=
	  clib_host_to_net_u16 (IP4_HEADER_FLAG_CONGESTION);

      /* Can't parse input: try next protocol level. */
      else
	break;
    }

  /* Fill in checksum. */
  ip->checksum = ip4_header_checksum (ip);

  /* Recurse into next protocol layer. */
  {
    ip_main_t *im = &ip_main;
    ip_protocol_info_t *pi = ip_get_protocol_info (im, ip->protocol);

    if (pi && pi->unformat_header)
      {
	if (!unformat_user (input, pi->unformat_header, result))
	  return 0;

	/* Result may have moved. */
	ip = (void *) *result + old_length;
      }
  }

  /* Fill in IP length. */
  ip->length = clib_host_to_net_u16 (vec_len (*result) - old_length);

  return 1;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
