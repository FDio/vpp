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
#include <vnet/ip/ip.h>

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
  /* %d writes more than a u8 */
  int plen;
  if (unformat (input, "%U/%d", unformat_ip_address, &ip_prefix_addr (a),
		&plen))
    {
      ip_prefix_len (a) = plen;
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

bool
ip_address_is_zero (const ip_address_t * ip)
{
  switch (ip_addr_version (ip))
    {
    case AF_IP4:
      return (ip_addr_v4 (ip).as_u32 == 0);
    case AF_IP6:
      return (ip_addr_v6 (ip).as_u64[0] == 0 &&
	      ip_addr_v6 (ip).as_u64[1] == 0);
      break;
    }
  return false;
}

int
ip_address_cmp (const ip_address_t * ip1, const ip_address_t * ip2)
{
  int res = 0;
  if (ip_addr_version (ip1) != ip_addr_version (ip2))
    return -1;
  res = ip46_address_cmp (&ip_addr_46 (ip1), &ip_addr_46 (ip2));

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
      ip_addr_v4 (dst) = ip_addr_v4 (src);
      dst->version = AF_IP4;
    }
  else
    {
      clib_memcpy (dst, src, sizeof (ip_address_t));
    }
}

u8 *
ip_addr_bytes (ip_address_t * ip)
{
  switch (ip->version)
    {
    case AF_IP4:
      return (u8 *) & ip_addr_v4 (ip);
    case AF_IP6:
      return (u8 *) & ip_addr_v6 (ip);
      break;
    }
  ASSERT (0);
  return (NULL);
}

void
ip_address_copy_addr (void *dst, const ip_address_t * src)
{
  switch (src->version)
    {
    case AF_IP4:
      clib_memcpy (dst, &ip_addr_v4 (src), ip_address_size (src));
      break;
    case AF_IP6:
      clib_memcpy (dst, &ip_addr_v6 (src), ip_address_size (src));
      break;
    }
}

u16
ip_version_to_size (ip_address_family_t af)
{
  switch (af)
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

vnet_link_t
ip_address_family_to_link_type (ip_address_family_t af)
{
  switch (af)
    {
    case AF_IP4:
      return (VNET_LINK_IP4);
    case AF_IP6:
      return (VNET_LINK_IP6);
    }
  ASSERT (0);
  return (VNET_LINK_IP4);
}


void
ip_address_set (ip_address_t * dst, const void *src, ip_address_family_t af)
{
  ip_addr_version (dst) = af;

  switch (af)
    {
    case AF_IP4:
      ip_addr_v4 (dst) = *(ip4_address_t *) src;
      break;
    case AF_IP6:
      ip_addr_v6 (dst) = *(ip6_address_t *) src;
      break;
    }
}

fib_protocol_t
ip_address_family_to_fib_proto (ip_address_family_t af)
{
  switch (af)
    {
    case AF_IP4:
      return (FIB_PROTOCOL_IP4);
    case AF_IP6:
      return (FIB_PROTOCOL_IP6);
    }
  ASSERT (0);
  return (FIB_PROTOCOL_IP4);
}

ip_address_family_t
ip_address_family_from_fib_proto (fib_protocol_t fp)
{
  switch (fp)
    {
    case FIB_PROTOCOL_IP4:
      return (AF_IP4);
    case FIB_PROTOCOL_IP6:
      return (AF_IP6);
    case FIB_PROTOCOL_MPLS:
      ASSERT (0);
    }
  return (AF_IP4);
}

fib_protocol_t
ip_address_to_46 (const ip_address_t * addr, ip46_address_t * a)
{
  *a = ip_addr_46 (addr);
  return (ip_address_family_to_fib_proto (ip_addr_version (addr)));
}

void
ip_address_from_46 (const ip46_address_t * nh,
		    fib_protocol_t fproto, ip_address_t * ip)
{
  ip_addr_46 (ip) = *nh;
  ip_addr_version (ip) = ip_address_family_from_fib_proto (fproto);
}

/**
 * convert from a IP address to a FIB prefix
 */
void
ip_address_to_fib_prefix (const ip_address_t * addr, fib_prefix_t * prefix)
{
  if (addr->version == AF_IP4)
    {
      prefix->fp_len = 32;
      prefix->fp_proto = FIB_PROTOCOL_IP4;
      clib_memset (&prefix->fp_addr.pad, 0, sizeof (prefix->fp_addr.pad));
      memcpy (&prefix->fp_addr.ip4, &addr->ip.ip4,
	      sizeof (prefix->fp_addr.ip4));
    }
  else
    {
      prefix->fp_len = 128;
      prefix->fp_proto = FIB_PROTOCOL_IP6;
      memcpy (&prefix->fp_addr.ip6, &addr->ip.ip6,
	      sizeof (prefix->fp_addr.ip6));
    }
  prefix->___fp___pad = 0;
}

void
ip_address_increment (ip_address_t * ip)
{
  ip46_address_increment ((ip_addr_version (ip) == AF_IP4 ?
			   IP46_TYPE_IP4 : IP46_TYPE_IP6), &ip_addr_46 (ip));
}

void
ip_address_reset (ip_address_t * ip)
{
  clib_memset (ip, 0, sizeof (*ip));
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

/**
 * convert from a LISP to a FIB prefix
 */
void
ip_prefix_to_fib_prefix (const ip_prefix_t * ip_prefix,
			 fib_prefix_t * fib_prefix)
{
  ip_address_to_fib_prefix (&ip_prefix->addr, fib_prefix);
  fib_prefix->fp_len = ip_prefix->len;
}

static bool
ip4_prefix_validate (const ip_prefix_t * ip)
{
  ip4_address_t ip4_addr, ip4_mask;

  if (ip_prefix_len (ip) > 32)
    return (false);

  ip4_addr = ip_prefix_v4 (ip);
  ip4_preflen_to_mask (ip_prefix_len (ip), &ip4_mask);

  return ((ip4_addr.as_u32 & ip4_mask.as_u32) == ip4_addr.as_u32);
}

static bool
ip6_prefix_validate (const ip_prefix_t * ip)
{
  ip6_address_t ip6_addr, ip6_mask;

  if (ip_prefix_len (ip) > 128)
    return (false);

  ip6_addr = ip_prefix_v6 (ip);
  ip6_preflen_to_mask (ip_prefix_len (ip), &ip6_mask);

  return (((ip6_addr.as_u64[0] & ip6_mask.as_u64[0]) == ip6_addr.as_u64[0]) &&
	  ((ip6_addr.as_u64[1] & ip6_mask.as_u64[1]) == ip6_addr.as_u64[1]));
}

bool
ip_prefix_validate (const ip_prefix_t * ip)
{
  switch (ip_prefix_version (ip))
    {
    case AF_IP4:
      return (ip4_prefix_validate (ip));
    case AF_IP6:
      return (ip6_prefix_validate (ip));
    }
  ASSERT (0);
  return (false);
}

void
ip4_address_normalize (ip4_address_t * ip4, u8 preflen)
{
  ASSERT (preflen <= 32);
  if (preflen == 0)
    ip4->data_u32 = 0;
  else
    ip4->data_u32 &= clib_net_to_host_u32 (0xffffffff << (32 - preflen));
}

void
ip6_address_normalize (ip6_address_t * ip6, u8 preflen)
{
  ASSERT (preflen <= 128);
  if (preflen == 0)
    {
      ip6->as_u64[0] = 0;
      ip6->as_u64[1] = 0;
    }
  else if (preflen <= 64)
    {
      ip6->as_u64[0] &=
	clib_host_to_net_u64 (0xffffffffffffffffL << (64 - preflen));
      ip6->as_u64[1] = 0;
    }
  else
    ip6->as_u64[1] &=
      clib_host_to_net_u64 (0xffffffffffffffffL << (128 - preflen));
}

void
ip4_preflen_to_mask (u8 pref_len, ip4_address_t * ip)
{
  if (pref_len == 0)
    ip->as_u32 = 0;
  else
    ip->as_u32 = clib_host_to_net_u32 (~((1 << (32 - pref_len)) - 1));
}

u32
ip4_mask_to_preflen (ip4_address_t * mask)
{
  if (mask->as_u32 == 0)
    return 0;
  return (32 - log2_first_set (clib_net_to_host_u32 (mask->as_u32)));
}

void
ip4_prefix_max_address_host_order (ip4_address_t * ip, u8 plen,
				   ip4_address_t * res)
{
  u32 not_mask;
  not_mask = (1 << (32 - plen)) - 1;
  res->as_u32 = clib_net_to_host_u32 (ip->as_u32) + not_mask;
}

void
ip6_preflen_to_mask (u8 pref_len, ip6_address_t * mask)
{
  if (pref_len == 0)
    {
      mask->as_u64[0] = 0;
      mask->as_u64[1] = 0;
    }
  else if (pref_len <= 64)
    {
      mask->as_u64[0] =
	clib_host_to_net_u64 (0xffffffffffffffffL << (64 - pref_len));
      mask->as_u64[1] = 0;
    }
  else
    {
      mask->as_u64[0] = 0xffffffffffffffffL;
      mask->as_u64[1] =
	clib_host_to_net_u64 (0xffffffffffffffffL << (128 - pref_len));
    }
}

void
ip6_prefix_max_address_host_order (ip6_address_t * ip, u8 plen,
				   ip6_address_t * res)
{
  u64 not_mask;
  if (plen == 0)
    {
      res->as_u64[0] = 0xffffffffffffffffL;
      res->as_u64[1] = 0xffffffffffffffffL;
    }
  else if (plen <= 64)
    {
      not_mask = ((u64) 1 << (64 - plen)) - 1;
      res->as_u64[0] = clib_net_to_host_u64 (ip->as_u64[0]) + not_mask;
      res->as_u64[1] = 0xffffffffffffffffL;
    }
  else
    {
      not_mask = ((u64) 1 << (128 - plen)) - 1;
      res->as_u64[1] = clib_net_to_host_u64 (ip->as_u64[1]) + not_mask;
    }
}

u32
ip6_mask_to_preflen (ip6_address_t * mask)
{
  if (mask->as_u64[1] != 0)
    return 128 - log2_first_set (clib_net_to_host_u64 (mask->as_u64[1]));
  if (mask->as_u64[0] != 0)
    return 64 - log2_first_set (clib_net_to_host_u64 (mask->as_u64[0]));
  return 0;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
