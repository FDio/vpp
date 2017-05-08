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
#include <vat/vat.h>
#include <vnet/ip/ip.h>

uword
unformat_sw_if_index (unformat_input_t * input, va_list * args)
{
  vat_main_t *vam = va_arg (*args, vat_main_t *);
  u32 *result = va_arg (*args, u32 *);
  u8 *if_name;
  uword *p;

  if (!unformat (input, "%s", &if_name))
    return 0;

  p = hash_get_mem (vam->sw_if_index_by_interface_name, if_name);
  if (p == 0)
    return 0;
  *result = p[0];
  return 1;
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

/* Returns ethernet type as an int in host byte order. */
uword
unformat_ethernet_type_host_byte_order (unformat_input_t * input,
					va_list * args)
{
  u16 *result = va_arg (*args, u16 *);
  int type;

  /* Numeric type. */
  if (unformat (input, "0x%x", &type) || unformat (input, "%d", &type))
    {
      if (type >= (1 << 16))
	return 0;
      *result = type;
      return 1;
    }
  return 0;
}

/* Parse an IP6 address. */
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

u8 *
format_ip4_address (u8 * s, va_list * args)
{
  u8 *a = va_arg (*args, u8 *);
  return format (s, "%d.%d.%d.%d", a[0], a[1], a[2], a[3]);
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

/* Format an IP46 address. */
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

void
vat_plugin_api_reference (void)
{
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
