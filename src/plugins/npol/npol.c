/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2025 Cisco Systems, Inc.
 */

#include <npol/npol.h>
#include <npol/npol_match.h>
#include <npol/npol_format.h>

static clib_error_t *
npol_match_fn (vlib_main_t *vm, unformat_input_t *input,
	       vlib_cli_command_t *cmd)
{
  vnet_main_t *vnm = vnet_get_main ();
  u32 sw_if_index = NPOL_INVALID_INDEX;
  u8 _r_action = NPOL_ACTION_UNKNOWN, *r_action = &_r_action;
  fa_5tuple_t _pkt_5tuple = { 0 }, *pkt_5tuple = &_pkt_5tuple;
  clib_error_t *error = 0;
  u32 is_inbound = 0;
  int is_ip6 = 0;
  u32 sport = 0, dport = 0, proto = 0;
  int rv;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%U", unformat_vnet_sw_interface, vnm,
		    &sw_if_index))
	;
      else if (unformat (input, "sw_if_index %u", &sw_if_index))
	;
      else if (unformat (input, "inbound"))
	is_inbound = 1;
      else if (unformat (input, "outbound"))
	is_inbound = 0;
      else if (unformat (input, "ip6"))
	is_ip6 = 1;
      else if (unformat (input, "ip4"))
	is_ip6 = 0;
      else if (unformat (input, "%U;%u->%U;%u", unformat_ip4_address,
			 &pkt_5tuple->ip4_addr[SRC], &sport,
			 unformat_ip4_address, &pkt_5tuple->ip4_addr[DST],
			 &dport))
	{
	  pkt_5tuple->l4.port[SRC] = sport;
	  pkt_5tuple->l4.port[DST] = dport;
	}
      else if (unformat (input, "%U;%u->%U;%u", unformat_ip6_address,
			 &pkt_5tuple->ip6_addr[SRC], &sport,
			 unformat_ip6_address, &pkt_5tuple->ip6_addr[DST],
			 &dport))
	{
	  pkt_5tuple->l4.port[SRC] = sport;
	  pkt_5tuple->l4.port[DST] = dport;
	}
      else if (unformat (input, "%U", unformat_ip_protocol, &proto))
	pkt_5tuple->l4.proto = proto;
      else
	{
	  error = clib_error_return (0, "unknown input '%U'",
				     format_unformat_error, input);
	  goto done;
	}
    }

  if (sw_if_index == NPOL_INVALID_INDEX)
    {
      error = clib_error_return (0, "interface not specified");
      goto done;
    }

  rv = npol_match_func (sw_if_index, is_inbound, pkt_5tuple, is_ip6, r_action);

  vlib_cli_output (vm, "matched:%d action:%U", rv, format_npol_action,
		   *r_action);

done:
  return error;
}

VLIB_CLI_COMMAND (npol_match, static) = {
  .path = "npol match",
  .function = npol_match_fn,
  .short_help =
    "npol match [ip4|ip6] [inbound|outbound] 1.1.1.1;65000->3.3.3.3;8080 tcp",
};
