/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
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

#include <vnet/ip/ip_types.h>
#include <vnet/ip/format.h>

u8 *
format_ip_address (u8 * s, va_list * args)
{
  ip_address_t *a = va_arg (*args, ip_address_t *);
  u8 ver = ip_addr_version (a);
  if (ver == AF_IP4)
    {
      return format (s, "%U", format_ip4_address, &ip_addr_v4 (a));
    }
  else if (ver == AF_IP6)
    {
      return format (s, "%U", format_ip6_address, &ip_addr_v6 (a));
    }
  else
    {
      clib_warning ("Can't format IP version %d!", ver);
      return 0;
    }
}

uword
unformat_ip_address (unformat_input_t * input, va_list * args)
{
  ip_address_t *a = va_arg (*args, ip_address_t *);

  clib_memset (a, 0, sizeof (*a));
  if (unformat (input, "%U", unformat_ip4_address, &ip_addr_v4 (a)))
    ip_addr_version (a) = AF_IP4;
  else if (unformat_user (input, unformat_ip6_address, &ip_addr_v6 (a)))
    ip_addr_version (a) = AF_IP6;
  else
    return 0;
  return 1;
}

u8 *
format_ip_prefix (u8 * s, va_list * args)
{
  ip_prefix_t *a = va_arg (*args, ip_prefix_t *);
  return format (s, "%U/%d", format_ip_address, &ip_prefix_addr (a),
		 ip_prefix_len (a));
}

uword
unformat_ip_prefix (unformat_input_t * input, va_list * args)
{
  ip_prefix_t *a = va_arg (*args, ip_prefix_t *);
  if (unformat (input, "%U/%d", unformat_ip_address, &ip_prefix_addr (a),
		&ip_prefix_len (a)))
    {
      if ((ip_prefix_version (a) == AF_IP4 && 32 < ip_prefix_len (a)) ||
	  (ip_prefix_version (a) == AF_IP6 && 128 < ip_prefix_len (a)))
	{
	  clib_warning ("Prefix length to big: %d!", ip_prefix_len (a));
	  return 0;
	}
      ip_prefix_normalize (a);
    }
  else
    return 0;
  return 1;
}

u16
ip_address_size (const ip_address_t * a)
{
  switch (ip_addr_version (a))
    {
    case AF_IP4:
      return sizeof (ip4_address_t);
      break;
    case AF_IP6:
      return sizeof (ip6_address_t);
      break;
    }
  return 0;
}

int
ip_address_cmp (const ip_address_t * ip1, const ip_address_t * ip2)
{
  int res = 0;
  if (ip_addr_version (ip1) != ip_addr_version (ip2))
    return -1;
  res =
    memcmp (&ip_addr_addr (ip1), &ip_addr_addr (ip2), ip_address_size (ip1));

  if (res < 0)
    res = 2;
  else if (res > 0)
    res = 1;

  return res;
}

void
ip_address_copy (ip_address_t * dst, const ip_address_t * src)
{
  if (AF_IP4 == ip_addr_version (src))
    {
      /* don't copy any garbage from the union */
      clib_memset (dst, 0, sizeof (*dst));
      dst->ip.v4 = src->ip.v4;
      dst->version = AF_IP4;
    }
  else
    {
      clib_memcpy (dst, src, sizeof (ip_address_t));
    }
}

void
ip_address_copy_addr (void *dst, const ip_address_t * src)
{
  clib_memcpy (dst, src, ip_address_size (src));
}

u16
ip_version_to_size (u8 ver)
{
  switch (ver)
    {
    case AF_IP4:
      return sizeof (ip4_address_t);
      break;
    case AF_IP6:
      return sizeof (ip6_address_t);
      break;
    }
  return 0;
}

void
ip_address_set (ip_address_t * dst, const void *src, u8 version)
{
  clib_memcpy (dst, src, ip_version_to_size (version));
  ip_addr_version (dst) = version;
}

void
ip_address_to_46 (const ip_address_t * addr,
		  ip46_address_t * a, fib_protocol_t * proto)
{
  *proto = (AF_IP4 == ip_addr_version (addr) ?
	    FIB_PROTOCOL_IP4 : FIB_PROTOCOL_IP6);
  switch (*proto)
    {
    case FIB_PROTOCOL_IP4:
      ip46_address_set_ip4 (a, &addr->ip.v4);
      break;
    case FIB_PROTOCOL_IP6:
      a->ip6 = addr->ip.v6;
      break;
    default:
      ASSERT (0);
      break;
    }
}

static void
ip_prefix_normalize_ip4 (ip4_address_t * ip4, u8 preflen)
{
  u32 mask = ~0;

  ASSERT (ip4);

  if (32 <= preflen)
    {
      return;
    }

  mask = pow2_mask (preflen) << (32 - preflen);
  mask = clib_host_to_net_u32 (mask);
  ip4->data_u32 &= mask;
}

static void
ip_prefix_normalize_ip6 (ip6_address_t * ip6, u8 preflen)
{
  u8 mask_6[16];
  u32 *m;
  u8 j, i0, i1;

  ASSERT (ip6);

  clib_memset (mask_6, 0, sizeof (mask_6));

  if (128 <= preflen)
    {
      return;
    }

  i1 = preflen % 32;
  i0 = preflen / 32;
  m = (u32 *) & mask_6[0];

  for (j = 0; j < i0; j++)
    {
      m[j] = ~0;
    }

  if (i1)
    {
      m[i0] = clib_host_to_net_u32 (pow2_mask (i1) << (32 - i1));
    }

  for (j = 0; j < sizeof (mask_6); j++)
    {
      ip6->as_u8[j] &= mask_6[j];
    }
}

void
ip_prefix_normalize (ip_prefix_t * a)
{
  u8 preflen = ip_prefix_len (a);

  switch (ip_prefix_version (a))
    {
    case AF_IP4:
      ip_prefix_normalize_ip4 (&ip_prefix_v4 (a), preflen);
      break;

    case AF_IP6:
      ip_prefix_normalize_ip6 (&ip_prefix_v6 (a), preflen);
      break;

    default:
      ASSERT (0);
    }
}

void
ip_prefix_copy (void *dst, void *src)
{
  clib_memcpy (dst, src, sizeof (ip_prefix_t));
}

int
ip_prefix_cmp (ip_prefix_t * p1, ip_prefix_t * p2)
{
  int cmp = 0;

  ip_prefix_normalize (p1);
  ip_prefix_normalize (p2);

  cmp = ip_address_cmp (&ip_prefix_addr (p1), &ip_prefix_addr (p2));
  if (cmp == 0)
    {
      if (ip_prefix_len (p1) < ip_prefix_len (p2))
	{
	  cmp = 1;
	}
      else
	{
	  if (ip_prefix_len (p1) > ip_prefix_len (p2))
	    cmp = 2;
	}
    }
  return cmp;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
