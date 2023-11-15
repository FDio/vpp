/*
 * Copyright (c) 2021 Marvell.
 * SPDX-License-Identifier: Apache-2.0
 * https://spdx.org/licenses/Apache-2.0.html
 */

/**
 * @file
 * @brief ONP pktio CLI implementation.
 */

#include <onp/onp.h>

static clib_error_t *
onp_pktio_flow_dump_command_fn (vlib_main_t *vm, unformat_input_t *input,
				vlib_cli_command_t *cmd)
{
  onp_main_t *om = onp_get_main ();
  onp_pktio_t *pktio;

  vec_foreach (pktio, om->onp_pktios)
    cnxk_drv_pktio_flow_dump (vm, pktio->cnxk_pktio_index);

  return NULL;
}

/*?
 *
 * @cliexpar
 * Show the information of flow rules programmed in OCTEON hardware
 * ingress classifier:
 * @cliexstart{show onp pktio flow}
 * MCAM Index:192
 * Interface :NIX-RX (0)
 * Priority  :1
 * NPC RX Action:0X00000000204011
 *         ActionOp:NIX_RX_ACTIONOP_UCAST (1)
 *         PF_FUNC: 0X401
 *         RQ Index:0X002
 *         Match Id:0000
 *         Flow Key Alg:0
 * NPC RX VTAG Action:0000000000000000
 * Patterns:
 *         NPC_PARSE_NIBBLE_CHAN:0X800
 *         NPC_PARSE_NIBBLE_ERRCODE:00
 *         NPC_PARSE_NIBBLE_LA_LTYPE:NONE
 *         NPC_PARSE_NIBBLE_LB_LTYPE:NONE
 *         NPC_PARSE_NIBBLE_LC_LTYPE:NONE
 *         NPC_PARSE_NIBBLE_LD_LTYPE:NONE
 *         NPC_PARSE_NIBBLE_LE_LTYPE:LE_ESP
 * @cliexend
?*/
VLIB_CLI_COMMAND (onp_pktio_flow_dump_command, static) = {
  .path = "show onp pktio flow",
  .short_help = "show onp pktio flow",
  .function = onp_pktio_flow_dump_command_fn,
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
