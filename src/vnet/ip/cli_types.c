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
