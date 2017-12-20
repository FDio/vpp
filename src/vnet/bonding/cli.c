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
#include <vnet/bonding/lacp/mux_machine.h>

static void
bond_delete_neighbor (vlib_main_t * vm, bond_if_t * bif, slave_if_t * sif)
{
  bond_main_t *bm = &bond_main;
  vnet_main_t *vnm = vnet_get_main ();
  int i;
  vnet_hw_interface_t *hw;

  bif->port_number_bitmap =
    clib_bitmap_set (bif->port_number_bitmap,
		     ntohs (sif->actor_admin.port_number) - 1, 0);
  hash_unset (bm->neighbor_by_sw_if_index, sif->sw_if_index);
  vec_free (sif->last_marker_pkt);
  vec_free (sif->last_rx_pkt);
  vec_foreach_index (i, bif->slaves)
  {
    uword p = *vec_elt_at_index (bif->slaves, i);
    if (p == sif->sw_if_index)
      {
	vec_del1 (bif->slaves, i);
	break;
      }
  }

  lacp_disable_collecting_distributing (vm, sif);


  /* Put back the old mac */
  hw = vnet_get_sup_hw_interface (vnm, sif->sw_if_index);
  vnet_hw_interface_change_mac_address (vnm, hw->hw_if_index,
					sif->persistent_hw_address);

  pool_put (bm->neighbors, sif);

  /* Bring down the bond interface if no active slaves */
  if (vec_len (bif->active_slaves) == 0)
    vnet_hw_interface_set_flags (vnm, bif->hw_if_index, 0);
}

static int
bond_delete_if (vlib_main_t * vm, u32 sw_if_index)
{
  bond_main_t *bm = &bond_main;
  vnet_main_t *vnm = vnet_get_main ();
  bond_if_t *bif;
  slave_if_t *sif;
  vnet_hw_interface_t *hw;
  int i;
  slave_if_t **sif_list = 0;

  hw = vnet_get_sup_hw_interface (vnm, sw_if_index);
  if (hw == NULL || bond_dev_class.index != hw->dev_class_index)
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  bif = pool_elt_at_index (bm->interfaces, hw->dev_instance);

  /* bring down the interface */
  vnet_hw_interface_set_flags (vnm, bif->hw_if_index, 0);
  vnet_sw_interface_set_flags (vnm, bif->sw_if_index, 0);

  ethernet_delete_interface (vnm, bif->hw_if_index);

  /* *INDENT-OFF* */
  pool_foreach (sif, bm->neighbors,
  ({
    vec_add1 (sif_list, sif);
  }));
  /* *INDENT-ON* */

  for (i = 0; i < vec_len (sif_list); i++)
    {
      sif = sif_list[i];
      bond_delete_neighbor (vm, bif, sif);
    }
  vec_free (sif_list);

  clib_bitmap_free (bif->port_number_bitmap);
  hash_unset (bm->dev_instance_by_group_id, bif->group);
  hash_unset (bm->bundle_by_sw_if_index, bif->sw_if_index);
  memset (bif, 0, sizeof (*bif));
  pool_put (bm->interfaces, bif);

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

  if (hash_get (bm->dev_instance_by_group_id, args->group))
    {
      args->error = clib_error_return (0, "bundle id already existed");
      return;
    }
  pool_get (bm->interfaces, bif);
  memset (bif, 0, sizeof (*bif));
  bif->dev_instance = bif - bm->interfaces;
  bif->group = args->group;
  bif->lb = args->lb;
  bif->mode = args->mode;

  // Special load-balance mode used for rr and bc
  if (bif->mode == BOND_MODE_ROUND_ROBIN)
    bif->lb = BOND_LB_RR;
  else if (bif->mode == BOND_MODE_BROADCAST)
    bif->lb = BOND_LB_BC;

  bif->use_custom_mac = args->hw_addr_set;
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
  if (args->rv)
    args->error =
      clib_error_return (0, "Warning: unable to set rx mode for interface %d",
			 bif->hw_if_index);

  hash_set (bm->dev_instance_by_group_id, bif->group, bif->dev_instance);

  hash_set (bm->bundle_by_sw_if_index, bif->sw_if_index, bif->dev_instance);


  args->rv = vnet_feature_enable_disable ("interface-output", "bond-output",
					  bif->hw_if_index, 1, 0, 0);
  if (args->rv)
    {
      args->error =
	clib_error_return (0,
			   "Error encountered on output feature arc enable");
    }

  // for return
  args->sw_if_index = bif->sw_if_index;
}

static uword
unformat_bond_mode (unformat_input_t * input, va_list * args)
{
  int *r = va_arg (*args, int *);

  if (0);
#define _(v, f, s) else if (unformat (input, s)) *r = BOND_MODE_##f;
  foreach_bond_mode
#undef _
    else
    return 0;

  return 1;
}

static u8 *
format_bond_mode (u8 * s, va_list * args)
{
  int i = va_arg (*args, int);
  u8 *t = 0;

  switch (i)
    {
#define _(v, f, s) case BOND_MODE_##f: t = (u8 *) s; break;
      foreach_bond_mode
#undef _
    default:
      return format (s, "unknown");
    }
  return format (s, "%s", t);
}

static uword
unformat_bond_load_balance (unformat_input_t * input, va_list * args)
{
  int *r = va_arg (*args, int *);

  if (0);
#define _(v, f, s, p) else if (unformat (input, s)) *r = BOND_LB_##f;
  foreach_bond_lb
#undef _
    else
    return 0;

  return 1;
}

static u8 *
format_bond_load_balance (u8 * s, va_list * args)
{
  int i = va_arg (*args, int);
  u8 *t = 0;

  switch (i)
    {
#define _(v, f, s, p) case BOND_LB_##f: t = (u8 *) s; break;
      foreach_bond_lb_algo
#undef _
    default:
      return format (s, "unknown");
    }
  return format (s, "%s", t);
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
  args.lb = BOND_LB_L2;
  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "bundle %d", &args.group))
	group_is_set = 1;
      else
	if (unformat (line_input, "mode %U", unformat_bond_mode, &args.mode))
	;
      else if (((args.mode == BOND_MODE_LACP) || (args.mode == BOND_MODE_XOR))
	       && unformat (line_input, "load-balance %U",
			    unformat_bond_load_balance, &args.lb))
	;
      else if (unformat (line_input, "hw-addr %U",
			 unformat_ethernet_address, args.hw_addr))
	args.hw_addr_set = 1;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }
  unformat_free (line_input);

  if (args.mode == -1)
    return clib_error_return (0, "Missing bond mode");

  if (group_is_set == 0)
    return clib_error_return (0, "Missing bundle id");

  bond_create_if (vm, &args);

  return args.error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (bond_create_command, static) = {
  .path = "create",
  .short_help = "create bundle <id> [hw-addr <mac-address>] mode {round-robin | active-backup | broadcast | {lacp | xor} [load-balance { l2 | l23 | l34 }]}",
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
  bond_if_t *bif;
  slave_if_t *sif;
  vnet_interface_main_t *im = &vnm->interface_main;
  uword port_number;
  vnet_hw_interface_t *hw, *hw2;
  uword *p;

  p = hash_get (bm->dev_instance_by_group_id, args->group);
  if (!p)
    {
      args->error = clib_error_return (0, "bundle interface not found");
      return;
    }
  bif = pool_elt_at_index (bm->interfaces, p[0]);
  // make sure the interface is not already added
  sw = pool_elt_at_index (im->sw_interfaces, args->slave);
  if (hash_get (bm->neighbor_by_sw_if_index, sw->sw_if_index))
    {
      args->error = clib_error_return (0, "interface was already enslaved");
      return;
    }
  pool_get (bm->neighbors, sif);
  memset (sif, 0, sizeof (*sif));
  sif->port_enabled = sw->flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP;
  sif->sw_if_index = sw->sw_if_index;
  sif->hw_if_index = sw->hw_if_index;
  sif->packet_template_index = (u8) ~ 0;
  sif->is_passive = args->is_passive;
  sif->group = args->group;
  sif->bif_dev_instance = bif->dev_instance;

  sif->is_long_timeout = args->is_long_timeout;
  if (args->is_long_timeout)
    sif->ttl_in_seconds = LACP_LONG_TIMOUT_TIME;
  else
    sif->ttl_in_seconds = LACP_SHORT_TIMOUT_TIME;

  hash_set (bm->neighbor_by_sw_if_index, sif->sw_if_index,
	    sif - bm->neighbors);
  vec_add1 (bif->slaves, sif->sw_if_index);

  hw = vnet_get_sup_hw_interface (vnm, sif->sw_if_index);
  /* Save the old mac */
  memcpy (sif->persistent_hw_address, hw->hw_address, 6);
  if (bif->use_custom_mac)
    {
      memcpy (hw->hw_address, bif->hw_address, 6);
    }
  else
    {
      // bond interface gets the mac address from the first slave
      if (vec_len (bif->slaves) == 1)
	{
	  memcpy (bif->hw_address, hw->hw_address, 6);
	  hw2 = vnet_get_sup_hw_interface (vnm, bif->sw_if_index);
	  vnet_hw_interface_change_mac_address (vnm, hw2->hw_if_index,
						hw->hw_address);
	}
      else
	{
	  // subsequent slaves gets the mac address of the bond interface
	  vnet_hw_interface_change_mac_address (vnm, hw->hw_if_index,
						bif->hw_address);
	}
    }

  if (bif->mode == BOND_MODE_LACP)
    {
      port_number = clib_bitmap_first_clear (bif->port_number_bitmap);
      bif->port_number_bitmap = clib_bitmap_set (bif->port_number_bitmap,
						 port_number, 1);
      // bitmap starts at 0. Our port number starts at 1.
      lacp_init_neighbor (sif, bif->hw_address, port_number + 1, args->group);
      lacp_init_state_machines (vm, sif);
    }
  else
    {
      lacp_enable_collecting_distributing (vm, sif);
    }

  args->rv = vnet_feature_enable_disable ("device-input", "bond-input",
					  hw->hw_if_index, 1, 0, 0);

  if (args->rv)
    {
      args->error =
	clib_error_return (0,
			   "Error encountered on input feature arc enable");
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
bond_detach_slave (vlib_main_t * vm, bond_detach_slave_args_t * args)
{
  bond_main_t *bm = &bond_main;
  vnet_main_t *vnm = vnet_get_main ();
  vnet_sw_interface_t *sw;
  bond_if_t *bif;
  slave_if_t *sif;
  vnet_interface_main_t *im = &vnm->interface_main;
  uword *p;

  sw = pool_elt_at_index (im->sw_interfaces, args->slave);
  p = hash_get (bm->neighbor_by_sw_if_index, sw->sw_if_index);
  if (!p)
    {
      args->error = clib_error_return (0, "interface was not enslaved");
      return;
    }

  sif = pool_elt_at_index (bm->neighbors, p[0]);
  bif = pool_elt_at_index (bm->interfaces, sif->bif_dev_instance);
  bond_delete_neighbor (vm, bif, sif);
}

static clib_error_t *
detach_interface_command_fn (vlib_main_t * vm, unformat_input_t * input,
			     vlib_cli_command_t * cmd)
{
  bond_detach_slave_args_t args = { 0 };
  unformat_input_t _line_input, *line_input = &_line_input;
  vnet_main_t *vnm = vnet_get_main ();

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return clib_error_return (0, "Missing required arguments.");

  args.slave = ~0;
  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "interface %U",
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
  if (args.slave == ~0)
    return clib_error_return (0, "please specify valid interface name");

  bond_detach_slave (vm, &args);

  return args.error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (detach_interface_command, static) = {
  .path = "detach",
  .short_help = "detach interface <interface>",
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

  /* *INDENT-OFF* */
  pool_foreach (bif, bm->interfaces,
  ({
    vlib_cli_output (vm, "%U", format_bond_interface_name, bif->dev_instance);
    vlib_cli_output (vm, "  mode: %U",
		     format_bond_mode, bif->mode);
    vlib_cli_output (vm, "  load balance: %U",
		     format_bond_load_balance, bif->lb);
    if (bif->mode == BOND_MODE_ROUND_ROBIN)
      vlib_cli_output (vm, "  last xmit slave index: %u",
		       bif->lb_rr_last_index);
    vlib_cli_output (vm, "  number of active slaves: %d",
		     vec_len (bif->active_slaves));
    vec_foreach (sw_if_index, bif->active_slaves)
      {
        vlib_cli_output (vm, "    %U", format_vnet_sw_if_index_name,
			 vnet_get_main (), *sw_if_index);
      }
    vlib_cli_output (vm, "  number of slaves: %d", vec_len (bif->slaves));
    vec_foreach (sw_if_index, bif->slaves)
      {
        vlib_cli_output (vm, "    %U", format_vnet_sw_if_index_name,
			 vnet_get_main (), *sw_if_index);
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
