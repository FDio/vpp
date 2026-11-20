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

static u8 *
parse_vlan_id (const cli_arg_t *a, u8 *tok, cli_value_t *v)
{
  u64 id = 0;

  if (vec_len (tok) == 3 && memcmp (tok, "any", 3) == 0)
    {
      v->u64 = VLAN_ID_ANY;
      return 0;
    }

  for (u32 i = 0; i < vec_len (tok); i++)
    {
      if (!cli_is_digit (tok[i]) || id > 4095)
	return format (0, "'%v' is not a vlan id or any", tok);
      id = id * 10 + tok[i] - '0';
    }
  if (vec_len (tok) == 0 || id > 4095)
    return format (0, "'%v' is not a vlan id or any", tok);

  v->u64 = id;
  return 0;
}

static void
complete_vlan_id (const cli_arg_t *a, u8 *prefix, cli_candidate_t **out)
{
  if (cli_prefix_match ("any", prefix))
    cli_candidate_add (out, "any", "any vlan id");
}

CLIB_CLI_TYPE (cli_type_vlan_id) = {
  .name = "vlan-id",
  .help = "vlan id, or any",
  .parse = parse_vlan_id,
  .complete = complete_vlan_id,
};
