/*
 *------------------------------------------------------------------
 * Copyright (c) 2017 Cisco and/or its affiliates.
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

#include <stdint.h>
#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/bonding/lacp/node.h>
#include <vnet/bonding/node.h>

static void
bond_delete_neighbor (bond_if_t * bif, lacp_neighbor_t * n)
{
  bond_main_t *bm = &bond_main;
  int i;

  bif->port_number_bitmap =
    clib_bitmap_set (bif->port_number_bitmap,
		     ntohs (n->actor_admin.port_number) - 1, 0);
  hash_unset (bm->neighbor_by_sw_if_index, n->sw_if_index);
  vec_free (n->last_rx_pkt);
  vec_foreach_index (i, bif->slaves)
  {
    uword p = *vec_elt_at_index (bif->slaves, i);
    if (p == n->sw_if_index)
      {
	vec_del1 (bif->slaves, i);
	break;
      }
  }
  pool_put (bm->neighbors, n);
}

static int
bond_delete_if (vlib_main_t * vm, u32 sw_if_index)
{
  bond_main_t *bm = &bond_main;
  vnet_main_t *vnm = vnet_get_main ();
  bond_if_t *bif;
  lacp_neighbor_t *n;
  vnet_hw_interface_t *hw;
  int i;
  lacp_neighbor_t **n_list = 0;

  hw = vnet_get_sup_hw_interface (vnm, sw_if_index);
  if (hw == NULL || bond_dev_class.index != hw->dev_class_index)
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  bif = pool_elt_at_index (bm->interfaces, hw->dev_instance);

  /* bring down the interface */
  vnet_hw_interface_set_flags (vnm, bif->hw_if_index, 0);
  vnet_sw_interface_set_flags (vnm, bif->sw_if_index, 0);

  ethernet_delete_interface (vnm, bif->hw_if_index);

  /* *INDENT-OFF* */
  pool_foreach (n, bm->neighbors,
  ({
    vec_add1 (n_list, n);
  }));
  /* *INDENT-ON* */

  for (i = 0; i < vec_len (n_list); i++)
    {
      n = n_list[i];
      bond_delete_neighbor (bif, n);
    }

  clib_bitmap_free (bif->port_number_bitmap);
  memset (bif, 0, sizeof (*bif));
  pool_put (bm->interfaces, bif);
  vec_free (n_list);

  return 0;
}

static void
bond_create_if (vlib_main_t * vm, bond_create_if_args_t * args)
{
  bond_main_t *bm = &bond_main;
  vnet_main_t *vnm = vnet_get_main ();
  vnet_sw_interface_t *sw;
  bond_if_t *bif = 0;
  vnet_hw_interface_t *hw;

  pool_get (bm->interfaces, bif);
  memset (bif, 0, sizeof (*bif));
  bif->dev_instance = bif - bm->interfaces;
  bif->group = args->group;

  if (!args->hw_addr_set)
    {
      f64 now = vlib_time_now (vm);
      u32 rnd;
      rnd = (u32) (now * 1e6);
      rnd = random_u32 (&rnd);

      memcpy (args->hw_addr + 2, &rnd, sizeof (rnd));
      args->hw_addr[0] = 2;
      args->hw_addr[1] = 0xfe;
    }
  memcpy (bif->hw_address, args->hw_addr, 6);
  args->error = ethernet_register_interface
    (vnm, bond_dev_class.index, bif - bm->interfaces /* device instance */ ,
     bif->hw_address /* ethernet address */ ,
     &bif->hw_if_index, 0 /* flag change */ );

  if (args->error)
    return;

  sw = vnet_get_hw_sw_interface (vnm, bif->hw_if_index);
  bif->sw_if_index = sw->sw_if_index;
  hw = vnet_get_hw_interface (vnm, bif->hw_if_index);
  hw->flags |= VNET_HW_INTERFACE_FLAG_SUPPORTS_INT_MODE;
  vnet_hw_interface_set_input_node (vnm, bif->hw_if_index,
				    bond_input_node.index);
  vnet_hw_interface_assign_rx_thread (vnm, bif->hw_if_index, 0, ~0);
  vnet_hw_interface_set_flags (vnm, bif->hw_if_index,
			       VNET_HW_INTERFACE_FLAG_LINK_UP);
  if (args->rv)
    args->error =
      clib_error_return (0, "Warning: unable to set rx mode for interface %d",
			 bif->hw_if_index);

  // for return
  args->sw_if_index = bif->sw_if_index;
}

static clib_error_t *
bond_create_command_fn (vlib_main_t * vm, unformat_input_t * input,
			vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  bond_create_if_args_t args = { 0 };
  u8 group_is_set = 0;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return clib_error_return (0, "Missing required arguments.");

  args.mode = -1;
  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%d", &args.group))
	group_is_set = 1;
      else if (unformat (line_input, "mode lacp"))
	args.mode = BOND_MODE_LACP;
      else if (unformat (line_input, "hw-addr %U",
			 unformat_ethernet_address, args.hw_addr))
	args.hw_addr_set = 1;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }
  unformat_free (line_input);

  if (args.mode != BOND_MODE_LACP)
    return clib_error_return (0, "Missing mode lacp");

  if (group_is_set == 0)
    return clib_error_return (0, "Missing bundle id");

  bond_create_if (vm, &args);

  return args.error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (bond_create_command, static) = {
  .path = "create bundle",
  .short_help = "create bundle <id> mode lacp [hw-addr <mac-address>]",
  .function = bond_create_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
bond_delete_command_fn (vlib_main_t * vm, unformat_input_t * input,
			vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u32 sw_if_index = ~0;
  vnet_main_t *vnm = vnet_get_main ();
  int rv;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return clib_error_return (0, "Missing <interface>");

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "sw_if_index %d", &sw_if_index))
	;
      else if (unformat (line_input, "%U", unformat_vnet_hw_interface,
			 vnm, &sw_if_index))
	;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }
  unformat_free (line_input);

  if (sw_if_index == ~0)
    return clib_error_return (0,
			      "please specify interface name or sw_if_index");

  rv = bond_delete_if (vm, sw_if_index);
  if (rv == VNET_API_ERROR_INVALID_SW_IF_INDEX)
    return clib_error_return (0, "not a bundle interface");
  else if (rv != 0)
    return clib_error_return (0, "error on deleting bundle interface");

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (bond_delete__command, static) =
{
  .path = "delete bundle",
  .short_help = "delete bundle {<interface> | sw_if_index <sw_idx>}",
  .function = bond_delete_command_fn,
};
/* *INDENT-ON* */

static void
bond_create_slave (vlib_main_t * vm, bond_create_slave_args_t * args)
{
  bond_main_t *bm = &bond_main;
  vnet_main_t *vnm = vnet_get_main ();
  vnet_sw_interface_t *sw;
  bond_if_t *bif = 0, *loop_bif = 0;
  lacp_neighbor_t *n;
  vnet_interface_main_t *im = &vnm->interface_main;
  uword port_number;
  vnet_hw_interface_t *hw, *hw2;

  /* *INDENT-OFF* */
  pool_foreach (loop_bif, bm->interfaces,
  {
    if (loop_bif->group == args->group)
      bif = loop_bif;
  });
  /* *INDENT-ON* */

  if (!bif)
    {
      args->error = clib_error_return (0, "bundle interface not found");
      return;
    }
  // make sure the interface is not already added
  sw = pool_elt_at_index (im->sw_interfaces, args->slave);
  if (hash_get (bm->neighbor_by_sw_if_index, sw->sw_if_index))
    {
      args->error = clib_error_return (0, "interface was already enslaved");
      return;
    }
  pool_get (bm->neighbors, n);
  memset (n, 0, sizeof (*n));
  n->sw_if_index = sw->sw_if_index;
  n->hw_if_index = sw->hw_if_index;
  n->packet_template_index = (u8) ~ 0;
  n->is_passive = args->is_passive;

  if (args->is_long_timeout)
    n->ttl_in_seconds = LACP_LONG_TIMOUT_TIME;
  else
    n->ttl_in_seconds = LACP_SHORT_TIMOUT_TIME;

  hash_set (bm->neighbor_by_sw_if_index, n->sw_if_index, n - bm->neighbors);
  vec_add1 (bif->slaves, n->sw_if_index);
  hw = vnet_get_sup_hw_interface (vnm, n->sw_if_index);
  // bond interface gets the mac address from the first slave
  if (vec_len (bif->slaves) == 1)
    {
      memcpy (bif->hw_address, hw->hw_address, 6);
      // TODO create inteface API for this
      hw2 = vnet_get_sup_hw_interface (vnm, bif->sw_if_index);
      memcpy (hw2->hw_address, hw->hw_address, 6);
    }
  else
    {
      // TODO change MAC address of subsequent slaves to be the same as first
    }
  port_number = clib_bitmap_first_clear (bif->port_number_bitmap);
  bif->port_number_bitmap = clib_bitmap_set (bif->port_number_bitmap,
					     port_number, 1);
  // bitmap starts at 0. Our port number starts at 1.
  lacp_init_neighbor (n, bif->hw_address, port_number + 1, args->group);
  lacp_init_state_machines (vm, n);
  n->begin = 0;

  args->rv = vnet_feature_enable_disable ("device-input", "bond-input",
					  hw->hw_if_index, 1, 0, 0);

  if (args->rv)
    {
      args->error =
	clib_error_return (0,
			   "Error encountered on input feature arc enable");
      return;
    }

  args->rv = vnet_feature_enable_disable ("interface-output", "bond-output",
					  bif->hw_if_index, 1, 0, 0);
  if (args->rv)
    {
      args->error =
	clib_error_return (0,
			   "Error encountered on output feature arc enable");
    }
}

static clib_error_t *
enslave_interface_command_fn (vlib_main_t * vm, unformat_input_t * input,
			      vlib_cli_command_t * cmd)
{
  bond_create_slave_args_t args = { 0 };
  unformat_input_t _line_input, *line_input = &_line_input;
  u8 group_is_set = 0;
  vnet_main_t *vnm = vnet_get_main ();

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return clib_error_return (0, "Missing required arguments.");

  args.slave = ~0;
  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "bundle %d", &args.group))
	group_is_set = 1;
      else if (unformat (line_input, "interface %U",
			 unformat_vnet_hw_interface, vnm, &args.slave))
	;
      else if (unformat (line_input, "passive"))
	args.is_passive = 1;
      else if (unformat (line_input, "long-timeout"))
	args.is_long_timeout = 1;
      else
	{
	  args.error = clib_error_return (0, "unknown input `%U'",
					  format_unformat_error, input);
	  break;
	}
    }
  unformat_free (line_input);

  if (args.error)
    return args.error;
  if (group_is_set == 0)
    return clib_error_return (0, "Missing bundle id");
  if (args.slave == ~0)
    return clib_error_return (0, "please specify valid interface name");

  bond_create_slave (vm, &args);

  return args.error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (enslave_interface_command, static) = {
  .path = "enslave",
  .short_help = "enslave interface <interface> bundle <id> [passive] [long-timeout]",
  .function = enslave_interface_command_fn,
};
/* *INDENT-ON* */

static void
bond_detach_slave (vlib_main_t * vm, bond_create_slave_args_t * args)
{
  bond_main_t *bm = &bond_main;
  vnet_main_t *vnm = vnet_get_main ();
  vnet_sw_interface_t *sw;
  bond_if_t *bif = 0, *loop_bif = 0;
  lacp_neighbor_t *n;
  vnet_interface_main_t *im = &vnm->interface_main;
  uword *p;

  /* *INDENT-OFF* */
  pool_foreach (loop_bif, bm->interfaces,
  {
    if (loop_bif->group == args->group)
      bif = loop_bif;
  });
  /* *INDENT-ON* */

  if (!bif)
    {
      args->error = clib_error_return (0, "bundle interface not found");
      return;
    }

  sw = pool_elt_at_index (im->sw_interfaces, args->slave);
  p = hash_get (bm->neighbor_by_sw_if_index, sw->sw_if_index);
  if (!p)
    {
      args->error = clib_error_return (0, "interface was not enslaved");
      return;
    }

  n = pool_elt_at_index (bm->neighbors, p[0]);
  bond_delete_neighbor (bif, n);
}

static clib_error_t *
detach_interface_command_fn (vlib_main_t * vm, unformat_input_t * input,
			     vlib_cli_command_t * cmd)
{
  bond_create_slave_args_t args = { 0 };
  unformat_input_t _line_input, *line_input = &_line_input;
  u8 group_is_set = 0;
  vnet_main_t *vnm = vnet_get_main ();

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return clib_error_return (0, "Missing required arguments.");

  args.slave = ~0;
  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "bundle %d", &args.group))
	group_is_set = 1;
      else if (unformat (line_input, "interface %U",
			 unformat_vnet_hw_interface, vnm, &args.slave))
	;
      else
	{
	  args.error = clib_error_return (0, "unknown input `%U'",
					  format_unformat_error, input);
	  break;
	}
    }
  unformat_free (line_input);

  if (args.error)
    return args.error;
  if (group_is_set == 0)
    return clib_error_return (0, "Missing bundle id");
  if (args.slave == ~0)
    return clib_error_return (0, "please specify valid interface name");

  bond_detach_slave (vm, &args);

  return args.error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (detach_interface_command, static) = {
  .path = "detach",
  .short_help = "detach interface <interface> bundle <id>",
  .function = detach_interface_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
show_bundle (vlib_main_t * vm, unformat_input_t * input,
	     vlib_cli_command_t * cmd)
{
  bond_main_t *bm = &bond_main;
  bond_if_t *bif;
  u32 *sw_if_index;
  vnet_hw_interface_t *hw;
  vnet_main_t *vnm = vnet_get_main ();

  /* *INDENT-OFF* */
  pool_foreach (bif, bm->interfaces,
  ({
    vlib_cli_output (vm, "%U", format_bond_interface_name, bif->dev_instance);
    vlib_cli_output (vm, "  number of slaves: %d", vec_len (bif->slaves));
    vec_foreach (sw_if_index, bif->slaves)
      {
	hw = vnet_get_sup_hw_interface (vnm, *sw_if_index);
        vlib_cli_output (vm, "    %s", hw->name);
      }
    vlib_cli_output (vm, "  device instance: %d", bif->dev_instance);
    vlib_cli_output (vm, "  sw_if_index: %d", bif->sw_if_index);
    vlib_cli_output (vm, "  hw_if_index: %d", bif->hw_if_index);
  }));
  /* *INDENT-ON* */

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_lacp_command, static) = {
  .path = "show bundle",
  .short_help = "Show bundle command",
  .function = show_bundle,
};
/* *INDENT-ON* */

clib_error_t *
bond_cli_init (vlib_main_t * vm)
{
  bond_main_t *bm = &bond_main;

  bm->vlib_main = vm;
  bm->vnet_main = vnet_get_main ();
  bm->neighbor_by_sw_if_index = hash_create (0, sizeof (uword));

  return 0;
}

VLIB_INIT_FUNCTION (bond_cli_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
