/*
 *------------------------------------------------------------------
 * Copyright (c) 2018 Cisco and/or its affiliates.
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

#include <vlib/vlib.h>
#include <vpp/api/types.h>
#include <vnet/ip/ip46_address.h>

const vl_api_mac_address_t VL_API_ZERO_MAC_ADDRESS;
const vl_api_address_t VL_API_ZERO_ADDRESS;

u8 *
format_vl_api_address_family (u8 * s, va_list * args)
{
  vl_api_address_family_t af = va_arg (*args, int);

  if (ADDRESS_IP6 == af)
      s = format (s, "ip4");
  else
      s = format (s, "ip6");

  return s;
}

u8 *
format_vl_api_address (u8 * s, va_list * args)
{
  const vl_api_address_t *addr = va_arg (*args, vl_api_address_t *);

  if (ADDRESS_IP6 == addr->af)
    s = format (s, "%U", format_ip6_address, addr->un.ip6);
  else
    s = format (s, "%U", format_ip4_address, addr->un.ip4);

  return s;
}

u8 *
format_vl_api_address_union (u8 * s, va_list * args)
{
  const vl_api_address_union_t *addr =
    va_arg (*args, vl_api_address_union_t *);
  vl_api_address_family_t af = va_arg (*args, int);

  if (ADDRESS_IP6 == af)
    s = format (s, "%U", format_ip6_address, addr->ip6);
  else
    s = format (s, "%U", format_ip4_address, addr->ip4);

  return s;
}

u8 *
format_vl_api_ip4_address (u8 * s, va_list * args)
{
  const vl_api_ip4_address_t *addr = va_arg (*args, vl_api_ip4_address_t *);

  s = format (s, "%U", format_ip4_address, addr);

  return s;
}

u8 *
format_vl_api_ip6_address (u8 * s, va_list * args)
{
  const vl_api_ip6_address_t *addr = va_arg (*args, vl_api_ip6_address_t *);

  s = format (s, "%U", format_ip6_address, addr);

  return s;
}

u8 *
format_vl_api_prefix (u8 * s, va_list * args)
{
  const vl_api_prefix_t *pfx = va_arg (*args, vl_api_prefix_t *);

  s = format (s, "%U/%d", format_vl_api_address,
	      &pfx->address, pfx->len);

  return s;
}

u8 *
format_vl_api_mac_address (u8 * s, va_list * args)
{
  vl_api_mac_address_t *mac = va_arg (*args, vl_api_mac_address_t *);

  return (format (s, "%U", format_ethernet_address, mac));
}

u8 *
format_vl_api_version (u8 * s, va_list * args)
{
  vl_api_version_t *ver = va_arg (*args, vl_api_version_t *);
  s = format(s, "%d.%d.%d", ver->major, ver->minor, ver->patch);
  if (ver->pre_release[0] != 0)
  {
    s = format(s, "-%v", ver->pre_release);
    if (ver->build_metadata[0] != 0)
    s = format(s, "+%v", ver->build_metadata);
    }
  return s;
}

uword
unformat_vl_api_mac_address (unformat_input_t * input, va_list * args)
{
  vl_api_mac_address_t *mac = va_arg (*args, vl_api_mac_address_t *);

  return (unformat (input, "%U",unformat_ethernet_address, mac));
}

uword
unformat_vl_api_address (unformat_input_t * input, va_list * args)
{
  vl_api_address_t *ip = va_arg (*args, vl_api_address_t *);

  if (unformat (input, "%U", unformat_ip4_address, &ip->un.ip4))
      ip->af = ADDRESS_IP4;
  else if (unformat (input, "%U", unformat_ip6_address, &ip->un.ip6))
      ip->af = ADDRESS_IP6;
  else
      return (0);

  return (1);
}

uword
unformat_vl_api_address_family (unformat_input_t * input,
                                va_list * args)
{
  vl_api_address_family_t *af = va_arg (*args, vl_api_address_family_t *);

  if (unformat (input, "ip4") || unformat (input, "ipv4"))
      *af = ADDRESS_IP4;
  else if (unformat (input, "ip6") || unformat (input, "ipv6"))
      *af = ADDRESS_IP6;
  else
      return (0);

  return (1);
}

uword
unformat_vl_api_ip4_address (unformat_input_t * input, va_list * args)
{
  vl_api_ip4_address_t *ip = va_arg (*args, vl_api_ip4_address_t *);

  if (unformat (input, "%U", unformat_ip4_address, ip))
      return (1);
  return (0);
}

uword
unformat_vl_api_ip6_address (unformat_input_t * input, va_list * args)
{
  vl_api_ip6_address_t *ip = va_arg (*args, vl_api_ip6_address_t *);

  if (unformat (input, "%U", unformat_ip6_address, ip))
      return (1);
  return (0);
}

uword
unformat_vl_api_prefix (unformat_input_t * input, va_list * args)
{
   vl_api_prefix_t *pfx = va_arg (*args, vl_api_prefix_t *);

  if (unformat (input, "%U/%d", unformat_vl_api_address, &pfx->address,
                &pfx->len))
      return (1);
  return (0);
}

uword
unformat_vl_api_mprefix (unformat_input_t * input, va_list * args)
{
   vl_api_mprefix_t *pfx = va_arg (*args, vl_api_mprefix_t *);

   if (unformat (input, "%U/%d",
                 unformat_vl_api_ip4_address, &pfx->grp_address.ip4,
                 &pfx->grp_address_length))
       pfx->af = ADDRESS_IP4;
   else if (unformat (input, "%U/%d",
                 unformat_vl_api_ip6_address, &pfx->grp_address.ip6,
                 &pfx->grp_address_length))
       pfx->af = ADDRESS_IP6;
   else if (unformat (input, "%U %U",
                      unformat_vl_api_ip4_address, &pfx->src_address.ip4,
                      unformat_vl_api_ip4_address, &pfx->grp_address.ip4))
   {
       pfx->af = ADDRESS_IP4;
       pfx->grp_address_length = 64;
   }
   else if (unformat (input, "%U %U",
                      unformat_vl_api_ip6_address, &pfx->src_address.ip6,
                      unformat_vl_api_ip6_address, &pfx->grp_address.ip6))
   {
       pfx->af = ADDRESS_IP6;
       pfx->grp_address_length = 256;
   }
   else if (unformat (input, "%U",
                      unformat_vl_api_ip4_address, &pfx->grp_address.ip4))
   {
       pfx->af = ADDRESS_IP4;
       pfx->grp_address_length = 32;
       clib_memset(&pfx->src_address, 0, sizeof(pfx->src_address));
   }
   else if (unformat (input, "%U",
                      unformat_vl_api_ip6_address, &pfx->grp_address.ip6))
   {
       pfx->af = ADDRESS_IP6;
       pfx->grp_address_length = 128;
       clib_memset(&pfx->src_address, 0, sizeof(pfx->src_address));
   }
   else
       return (0);

   return (1);
}

uword unformat_vl_api_version (unformat_input_t * input, va_list * args)
{
vl_api_version_t *ver = va_arg (*args, vl_api_version_t *);

if (unformat (input, "%d.%d.%d-%s+%s",  ver->major, ver->minor, ver->patch, ver->pre_release, ver->build_metadata
                ))
      return (1);
else if (unformat (input, "%d.%d.%d-%s",  ver->major, ver->minor, ver->patch, ver->pre_release
                ))
      return (1);
else if (unformat (input, "%d.%d.%d",  ver->major, ver->minor, ver->patch
                ))
      return (1);

  return (0);
}

u8 *
format_ip46_address (u8 * s, va_list * args)
{
  ip46_address_t *ip46 = va_arg (*args, ip46_address_t *);
  ip46_type_t type = va_arg (*args, ip46_type_t);
  int is_ip4 = 1;

  switch (type)
    {
    case IP46_TYPE_ANY:
      is_ip4 = ip46_address_is_ip4 (ip46);
      break;
    case IP46_TYPE_IP4:
      is_ip4 = 1;
      break;
    case IP46_TYPE_IP6:
      is_ip4 = 0;
      break;
    }

  return is_ip4 ?
    format (s, "%U", format_ip4_address, &ip46->ip4) :
    format (s, "%U", format_ip6_address, &ip46->ip6);
}

u8 *
format_ethernet_address (u8 * s, va_list * args)
{
  u8 *a = va_arg (*args, u8 *);

  return format (s, "%02x:%02x:%02x:%02x:%02x:%02x",
                a[0], a[1], a[2], a[3], a[4], a[5]);
}

u8 *
format_ip6_address (u8 * s, va_list * args)
{
  ip6_address_t *a = va_arg (*args, ip6_address_t *);
  u32 i, i_max_n_zero, max_n_zeros, i_first_zero, n_zeros, last_double_colon;

  i_max_n_zero = ARRAY_LEN (a->as_u16);
  max_n_zeros = 0;
  i_first_zero = i_max_n_zero;
  n_zeros = 0;
  for (i = 0; i < ARRAY_LEN (a->as_u16); i++)
    {
      u32 is_zero = a->as_u16[i] == 0;
      if (is_zero && i_first_zero >= ARRAY_LEN (a->as_u16))
       {
         i_first_zero = i;
         n_zeros = 0;
       }
      n_zeros += is_zero;
      if ((!is_zero && n_zeros > max_n_zeros)
         || (i + 1 >= ARRAY_LEN (a->as_u16) && n_zeros > max_n_zeros))
       {
         i_max_n_zero = i_first_zero;
         max_n_zeros = n_zeros;
         i_first_zero = ARRAY_LEN (a->as_u16);
         n_zeros = 0;
       }
    }

  last_double_colon = 0;
  for (i = 0; i < ARRAY_LEN (a->as_u16); i++)
    {
      if (i == i_max_n_zero && max_n_zeros > 1)
       {
         s = format (s, "::");
         i += max_n_zeros - 1;
         last_double_colon = 1;
       }
      else
       {
         s = format (s, "%s%x",
                     (last_double_colon || i == 0) ? "" : ":",
                     clib_net_to_host_u16 (a->as_u16[i]));
         last_double_colon = 0;
       }
    }

  return s;
}

u8 *
format_ip4_address (u8 * s, va_list * args)
{
  u8 *a = va_arg (*args, u8 *);
  return format (s, "%d.%d.%d.%d", a[0], a[1], a[2], a[3]);
}

uword
unformat_ip6_address (unformat_input_t * input, va_list * args)
{
  ip6_address_t *result = va_arg (*args, ip6_address_t *);
  u16 hex_quads[8];
  uword hex_quad, n_hex_quads, hex_digit, n_hex_digits;
  uword c, n_colon, double_colon_index;

  n_hex_quads = hex_quad = n_hex_digits = n_colon = 0;
  double_colon_index = ARRAY_LEN (hex_quads);
  while ((c = unformat_get_input (input)) != UNFORMAT_END_OF_INPUT)
    {
      hex_digit = 16;
      if (c >= '0' && c <= '9')
       hex_digit = c - '0';
      else if (c >= 'a' && c <= 'f')
       hex_digit = c + 10 - 'a';
      else if (c >= 'A' && c <= 'F')
       hex_digit = c + 10 - 'A';
      else if (c == ':' && n_colon < 2)
       n_colon++;
      else
       {
         unformat_put_input (input);
         break;
       }

      /* Too many hex quads. */
      if (n_hex_quads >= ARRAY_LEN (hex_quads))
       return 0;

      if (hex_digit < 16)
       {
         hex_quad = (hex_quad << 4) | hex_digit;

         /* Hex quad must fit in 16 bits. */
         if (n_hex_digits >= 4)
           return 0;

         n_colon = 0;
         n_hex_digits++;
       }

      /* Save position of :: */
      if (n_colon == 2)
       {
         /* More than one :: ? */
         if (double_colon_index < ARRAY_LEN (hex_quads))
           return 0;
         double_colon_index = n_hex_quads;
       }

      if (n_colon > 0 && n_hex_digits > 0)
       {
         hex_quads[n_hex_quads++] = hex_quad;
         hex_quad = 0;
         n_hex_digits = 0;
       }
    }

  if (n_hex_digits > 0)
    hex_quads[n_hex_quads++] = hex_quad;

  {
    word i;

    /* Expand :: to appropriate number of zero hex quads. */
    if (double_colon_index < ARRAY_LEN (hex_quads))
      {
       word n_zero = ARRAY_LEN (hex_quads) - n_hex_quads;

       for (i = n_hex_quads - 1; i >= (signed) double_colon_index; i--)
         hex_quads[n_zero + i] = hex_quads[i];

       for (i = 0; i < n_zero; i++)
         hex_quads[double_colon_index + i] = 0;

       n_hex_quads = ARRAY_LEN (hex_quads);
      }

    /* Too few hex quads given. */
    if (n_hex_quads < ARRAY_LEN (hex_quads))
      return 0;

    for (i = 0; i < ARRAY_LEN (hex_quads); i++)
      result->as_u16[i] = clib_host_to_net_u16 (hex_quads[i]);

    return 1;
  }
}

uword
unformat_ethernet_address (unformat_input_t * input, va_list * args)
{
  u8 *result = va_arg (*args, u8 *);
  u32 i, a[6];

  if (!unformat (input, "%_%x:%x:%x:%x:%x:%x%_",
                &a[0], &a[1], &a[2], &a[3], &a[4], &a[5]))
    return 0;

  /* Check range. */
  for (i = 0; i < 6; i++)
    if (a[i] >= (1 << 8))
      return 0;

  for (i = 0; i < 6; i++)
    result[i] = a[i];

  return 1;
}

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

