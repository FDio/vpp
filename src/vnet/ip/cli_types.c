/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Damjan Marion
 */

#include <vnet/vnet.h>
#include <vnet/ip/cli_types.h>
#include <vnet/ip/ip_types.h>
#include <vnet/ip/format.h>

static u8 *
parse_ip_prefix (const cli_arg_t *a, u8 *tok, cli_value_t *v)
{
  unformat_input_t in;
  ip4_address_t a4;
  ip6_address_t a6;
  u32 len;
  u8 *err = 0;

  unformat_init_vector (&in, vec_dup (tok));
  if (unformat (&in, "%U/%d", unformat_ip4_address, &a4, &len) &&
      unformat_check_input (&in) == UNFORMAT_END_OF_INPUT)
    {
      if (len > 32)
	err = format (0, "IPv4 prefix length %u is larger than 32", len);
      else
	{
	  clib_memcpy (v->prefix.addr, &a4, 4);
	  v->prefix.len = len;
	  v->prefix.is_ip6 = 0;
	}
    }
  else
    {
      unformat_free (&in);
      unformat_init_vector (&in, vec_dup (tok));
      if (unformat (&in, "%U/%d", unformat_ip6_address, &a6, &len) &&
	  unformat_check_input (&in) == UNFORMAT_END_OF_INPUT)
	{
	  if (len > 128)
	    err = format (0, "IPv6 prefix length %u is larger than 128", len);
	  else
	    {
	      clib_memcpy (v->prefix.addr, &a6, 16);
	      v->prefix.len = len;
	      v->prefix.is_ip6 = 1;
	    }
	}
      else
	err = format (0, "'%v' is not an IP address/length", tok);
    }
  unformat_free (&in);
  return err;
}

CLIB_CLI_TYPE (cli_type_ip_prefix) = {
  .name = "ip-prefix",
  .help = "IPv4 or IPv6 address/length",
  .parse = parse_ip_prefix,
};

static u8 *
parse_ip_address (const cli_arg_t *a, u8 *tok, cli_value_t *v)
{
  unformat_input_t in;
  ip4_address_t a4;
  ip6_address_t a6;
  u8 *err = 0;

  unformat_init_vector (&in, vec_dup (tok));
  if (unformat (&in, "%U", unformat_ip4_address, &a4) &&
      unformat_check_input (&in) == UNFORMAT_END_OF_INPUT)
    {
      clib_memcpy (v->prefix.addr, &a4, 4);
      v->prefix.is_ip6 = 0;
    }
  else
    {
      unformat_free (&in);
      unformat_init_vector (&in, vec_dup (tok));
      if (unformat (&in, "%U", unformat_ip6_address, &a6) &&
	  unformat_check_input (&in) == UNFORMAT_END_OF_INPUT)
	{
	  clib_memcpy (v->prefix.addr, &a6, 16);
	  v->prefix.is_ip6 = 1;
	}
      else
	err = format (0, "'%v' is not an IP address", tok);
    }
  unformat_free (&in);
  return err;
}

CLIB_CLI_TYPE (cli_type_ip_address) = {
  .name = "ip-address",
  .help = "IPv4 or IPv6 address",
  .parse = parse_ip_address,
};

static u8 *
parse_ip_range (const cli_arg_t *a, u8 *tok, cli_value_t *v)
{
  cli_value_t lo = {}, hi = {};
  u8 *err, *first = 0, *second = 0;
  u32 i;

  for (i = 0; i < vec_len (tok); i++)
    if (tok[i] == '-')
      break;
  if (i == 0 || i >= vec_len (tok) - 1)
    return format (0, "'%v' is not an address range, expected <first>-<last>", tok);

  vec_add (first, tok, i);
  vec_add (second, tok + i + 1, vec_len (tok) - i - 1);
  err = parse_ip_address (a, first, &lo);
  if (!err)
    err = parse_ip_address (a, second, &hi);
  if (!err && lo.prefix.is_ip6 != hi.prefix.is_ip6)
    err = format (0, "both ends of the range must be of the same address family");
  if (!err)
    {
      clib_memcpy (v->ip_range.start, lo.prefix.addr, 16);
      clib_memcpy (v->ip_range.stop, hi.prefix.addr, 16);
      v->ip_range.is_ip6 = lo.prefix.is_ip6;
    }
  vec_free (first);
  vec_free (second);
  return err;
}

CLIB_CLI_TYPE (cli_type_ip_range) = {
  .name = "ip-range",
  .help = "IPv4 or IPv6 address range, <first>-<last>",
  .parse = parse_ip_range,
};
