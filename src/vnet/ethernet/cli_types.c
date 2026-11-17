/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Damjan Marion
 */

#include <vnet/vnet.h>
#include <vnet/ethernet/cli_types.h>
#include <vnet/ethernet/ethernet.h>

static u8 *
parse_mac_address (const cli_arg_t *a, u8 *tok, cli_value_t *v)
{
  unformat_input_t in;
  u8 mac[6];
  int ok;

  unformat_init_vector (&in, vec_dup (tok));
  ok = unformat (&in, "%U", unformat_ethernet_address, mac) &&
       unformat_check_input (&in) == UNFORMAT_END_OF_INPUT;
  unformat_free (&in);

  if (!ok)
    return format (0, "'%v' is not a MAC address", tok);

  clib_memcpy (v->prefix.addr, mac, sizeof (mac));
  return 0;
}

CLIB_CLI_TYPE (cli_type_mac_address) = {
  .name = "mac-address",
  .help = "MAC address, aa:bb:cc:dd:ee:ff",
  .parse = parse_mac_address,
};
