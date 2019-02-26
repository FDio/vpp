/*
 * l2e.c : Extract L3 packets from the L2 input and feed
 *                   them into the L3 path.
 *
 * Copyright (c) 2013 Cisco and/or its affiliates.
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

#include <plugins/l2e/l2e.h>
#include <vnet/l2/l2_input.h>
#include <vnet/l2/feat_bitmap.h>

l2_emulation_main_t l2_emulation_main;

/**
 * A zero'd out struct we can use in the vec_validate
 */
static const l2_emulation_t ezero = { };

void
l2_emulation_enable (u32 sw_if_index)
{
  l2_emulation_main_t *em = &l2_emulation_main;
  vec_validate_init_empty (em->l2_emulations, sw_if_index, ezero);

  l2_emulation_t *l23e = &em->l2_emulations[sw_if_index];

  l23e->enabled = 1;

  /*
   * L3 enable the interface - using IP unnumbered from the control
   * plane may not be possible since there may be no BVI interface
   * to which to unnumber
   */
  ip4_sw_interface_enable_disable (sw_if_index, 1);
  ip6_sw_interface_enable_disable (sw_if_index, 1);

  l2input_intf_bitmap_enable (sw_if_index, L2INPUT_FEAT_L2_EMULATION, 1);
}


void
l2_emulation_disable (u32 sw_if_index)
{
  l2_emulation_main_t *em = &l2_emulation_main;
  if (vec_len (em->l2_emulations) >= sw_if_index)
    {
      l2_emulation_t *l23e = &em->l2_emulations[sw_if_index];
      clib_memset (l23e, 0, sizeof (*l23e));

      l2input_intf_bitmap_enable (sw_if_index, L2INPUT_FEAT_L2_EMULATION, 0);
      ip4_sw_interface_enable_disable (sw_if_index, 0);
      ip6_sw_interface_enable_disable (sw_if_index, 0);
    }
}

static clib_error_t *
l2_emulation_interface_add_del (vnet_main_t * vnm,
				u32 sw_if_index, u32 is_add)
{
  l2_emulation_main_t *em = &l2_emulation_main;
  if (is_add)
    {
      vec_validate_init_empty (em->l2_emulations, sw_if_index, ezero);
    }

  return (NULL);
}

VNET_SW_INTERFACE_ADD_DEL_FUNCTION (l2_emulation_interface_add_del);

static clib_error_t *
l2_emulation_cli (vlib_main_t * vm,
		  unformat_input_t * input, vlib_cli_command_t * cmd)
{
  vnet_main_t *vnm = vnet_get_main ();
  u32 sw_if_index = ~0;
  u8 enable = 1;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%U", unformat_vnet_sw_interface,
		    vnm, &sw_if_index))
	;
      else if (unformat (input, "enable"))
	enable = 1;
      else if (unformat (input, "disable"))
	enable = 0;
      else
	break;
    }

  if (~0 == sw_if_index)
    return clib_error_return (0, "interface must be specified");

  if (enable)
    l2_emulation_enable (sw_if_index);
  else
    l2_emulation_disable (sw_if_index);

  return (NULL);
}

/*?
 * Configure l2 emulation.
 *  When the interface is in L2 mode, configure the extraction of L3
 *  packets out of the L2 path and into the L3 path.
 *
 * @cliexpar
 * @cliexstart{set interface l2 input l2-emulation <interface-name> [disable]}
 * @cliexend
 ?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (l2_emulation_cli_node, static) = {
  .path = "set interface l2 l2-emulation",
  .short_help =
  "set interface l2 l2-emulation <interface-name> [disable|enable]\n",
  .function = l2_emulation_cli,
};
/* *INDENT-ON* */

static clib_error_t *
l2_emulation_show (vlib_main_t * vm,
		   unformat_input_t * input, vlib_cli_command_t * cmd)
{
  l2_emulation_main_t *em = &l2_emulation_main;
  vnet_main_t *vnm = vnet_get_main ();
  l2_emulation_t *l23e;
  u32 sw_if_index;

  vec_foreach_index (sw_if_index, em->l2_emulations)
  {
    l23e = &em->l2_emulations[sw_if_index];
    if (l23e->enabled)
      {
	vlib_cli_output (vm, "%U\n",
			 format_vnet_sw_if_index_name, vnm, sw_if_index);
      }
  }
  return (NULL);
}

/*?
 * Show l2 emulation.
 *  When the interface is in L2 mode, configure the extraction of L3
 *  packets out of the L2 path and into the L3 path.
 *
 * @cliexpar
 * @cliexstart{show interface l2 l2-emulation}
 * @cliexend
 ?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (l2_emulation_show_node, static) = {
  .path = "show interface l2 l2-emulation",
  .short_help = "show interface l2 l2-emulation\n",
  .function = l2_emulation_show,
};
/* *INDENT-ON* */

static clib_error_t *
l2_emulation_init (vlib_main_t * vm)
{
  l2_emulation_main_t *em = &l2_emulation_main;
  vlib_node_t *node;

  node = vlib_get_node_by_name (vm, (u8 *) "l2-emulation");
  em->l2_emulation_node_index = node->index;

  /* Initialize the feature next-node indexes */
  feat_bitmap_init_next_nodes (vm,
			       em->l2_emulation_node_index,
			       L2INPUT_N_FEAT,
			       l2input_get_feat_names (),
			       em->l2_input_feat_next);

  return 0;
}

VLIB_INIT_FUNCTION (l2_emulation_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
