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
#include <vnet/bonding/node.h>

void
bond_disable_collecting_distributing (vlib_main_t * vm, slave_if_t * sif)
{
  bond_main_t *bm = &bond_main;
  bond_if_t *bif;
  int i;
  uword p;
  u8 switching_active = 0;

  bif = bond_get_master_by_dev_instance (sif->bif_dev_instance);
  clib_spinlock_lock_if_init (&bif->lockp);
  vec_foreach_index (i, bif->active_slaves)
  {
    p = *vec_elt_at_index (bif->active_slaves, i);
    if (p == sif->sw_if_index)
      {
	/* Are we disabling the very 1st slave? */
	if (sif->sw_if_index == *vec_elt_at_index (bif->active_slaves, 0))
	  switching_active = 1;

	vec_del1 (bif->active_slaves, i);
	hash_unset (bif->active_slave_by_sw_if_index, sif->sw_if_index);

	/* We got a new slave just becoming active? */
	if ((vec_len (bif->active_slaves) >= 1) &&
	    (bif->mode == BOND_MODE_ACTIVE_BACKUP) && switching_active)
	  vlib_process_signal_event (bm->vlib_main, bond_process_node.index,
				     BOND_SEND_GARP_NA, bif->hw_if_index);
	break;
      }
  }
  clib_spinlock_unlock_if_init (&bif->lockp);
}

void
bond_enable_collecting_distributing (vlib_main_t * vm, slave_if_t * sif)
{
  bond_if_t *bif;
  bond_main_t *bm = &bond_main;

  bif = bond_get_master_by_dev_instance (sif->bif_dev_instance);
  clib_spinlock_lock_if_init (&bif->lockp);
  if (!hash_get (bif->active_slave_by_sw_if_index, sif->sw_if_index))
    {
      hash_set (bif->active_slave_by_sw_if_index, sif->sw_if_index,
		sif->sw_if_index);
      vec_add1 (bif->active_slaves, sif->sw_if_index);

      /* First slave becomes active? */
      if ((vec_len (bif->active_slaves) == 1) &&
	  (bif->mode == BOND_MODE_ACTIVE_BACKUP))
	vlib_process_signal_event (bm->vlib_main, bond_process_node.index,
				   BOND_SEND_GARP_NA, bif->hw_if_index);
    }
  clib_spinlock_unlock_if_init (&bif->lockp);
}

int
bond_dump_ifs (bond_interface_details_t ** out_bondifs)
{
  vnet_main_t *vnm = vnet_get_main ();
  bond_main_t *bm = &bond_main;
  bond_if_t *bif;
  vnet_hw_interface_t *hi;
  bond_interface_details_t *r_bondifs = NULL;
  bond_interface_details_t *bondif = NULL;

  /* *INDENT-OFF* */
  pool_foreach (bif, bm->interfaces,
    vec_add2(r_bondifs, bondif, 1);
    clib_memset (bondif, 0, sizeof (*bondif));
    bondif->user_instance = bif->user_instance;
    bondif->sw_if_index = bif->sw_if_index;
    hi = vnet_get_hw_interface (vnm, bif->hw_if_index);
    clib_memcpy(bondif->interface_name, hi->name,
                MIN (ARRAY_LEN (bondif->interface_name) - 1,
                     strlen ((const char *) hi->name)));
    bondif->mode = bif->mode;
    bondif->lb = bif->lb;
    bondif->active_slaves = vec_len (bif->active_slaves);
    bondif->slaves = vec_len (bif->slaves);
  );
  /* *INDENT-ON* */

  *out_bondifs = r_bondifs;

  return 0;
}

int
bond_dump_slave_ifs (slave_interface_details_t ** out_slaveifs,
		     u32 bond_sw_if_index)
{
  vnet_main_t *vnm = vnet_get_main ();
  bond_if_t *bif;
  vnet_hw_interface_t *hi;
  vnet_sw_interface_t *sw;
  slave_interface_details_t *r_slaveifs = NULL;
  slave_interface_details_t *slaveif = NULL;
  u32 *sw_if_index = NULL;
  slave_if_t *sif;

  bif = bond_get_master_by_sw_if_index (bond_sw_if_index);
  if (!bif)
    return 1;

  vec_foreach (sw_if_index, bif->slaves)
  {
    vec_add2 (r_slaveifs, slaveif, 1);
    clib_memset (slaveif, 0, sizeof (*slaveif));
    sif = bond_get_slave_by_sw_if_index (*sw_if_index);
    if (sif)
      {
	sw = vnet_get_sw_interface (vnm, sif->sw_if_index);
	hi = vnet_get_hw_interface (vnm, sw->hw_if_index);
	clib_memcpy (slaveif->interface_name, hi->name,
		     MIN (ARRAY_LEN (slaveif->interface_name) - 1,
			  strlen ((const char *) hi->name)));
	slaveif->sw_if_index = sif->sw_if_index;
	slaveif->is_passive = sif->is_passive;
	slaveif->is_long_timeout = sif->is_long_timeout;
      }
  }
  *out_slaveifs = r_slaveifs;

  return 0;
}

static void
bond_delete_neighbor (vlib_main_t * vm, bond_if_t * bif, slave_if_t * sif)
{
  bond_main_t *bm = &bond_main;
  vnet_main_t *vnm = vnet_get_main ();
  int i;
  vnet_hw_interface_t *sif_hw;

  sif_hw = vnet_get_sup_hw_interface (vnm, sif->sw_if_index);

  bif->port_number_bitmap =
    clib_bitmap_set (bif->port_number_bitmap,
		     ntohs (sif->actor_admin.port_number) - 1, 0);
  bm->slave_by_sw_if_index[sif->sw_if_index] = 0;
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

  bond_disable_collecting_distributing (vm, sif);

  vnet_feature_enable_disable ("device-input", "bond-input",
			       sif_hw->hw_if_index, 0, 0, 0);

  /* Put back the old mac */
  vnet_hw_interface_change_mac_address (vnm, sif_hw->hw_if_index,
					sif->persistent_hw_address);

  if ((bif->mode == BOND_MODE_LACP) && bm->lacp_enable_disable)
    (*bm->lacp_enable_disable) (vm, bif, sif, 0);

  pool_put (bm->neighbors, sif);
}

int
bond_delete_if (vlib_main_t * vm, u32 sw_if_index)
{
  bond_main_t *bm = &bond_main;
  vnet_main_t *vnm = vnet_get_main ();
  bond_if_t *bif;
  slave_if_t *sif;
  vnet_hw_interface_t *hw;
  u32 *sif_sw_if_index;
  u32 **s_list = 0;
  u32 i;

  hw = vnet_get_sup_hw_interface (vnm, sw_if_index);
  if (hw == NULL || bond_dev_class.index != hw->dev_class_index)
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  bif = bond_get_master_by_dev_instance (hw->dev_instance);

  vec_foreach (sif_sw_if_index, bif->slaves)
  {
    vec_add1 (s_list, sif_sw_if_index);
  }

  for (i = 0; i < vec_len (s_list); i++)
    {
      sif_sw_if_index = s_list[i];
      sif = bond_get_slave_by_sw_if_index (*sif_sw_if_index);
      if (sif)
	bond_delete_neighbor (vm, bif, sif);
    }

  if (s_list)
    vec_free (s_list);

  /* bring down the interface */
  vnet_hw_interface_set_flags (vnm, bif->hw_if_index, 0);
  vnet_sw_interface_set_flags (vnm, bif->sw_if_index, 0);

  ethernet_delete_interface (vnm, bif->hw_if_index);

  clib_bitmap_free (bif->port_number_bitmap);
  hash_unset (bm->bond_by_sw_if_index, bif->sw_if_index);
  hash_unset (bm->instance_used, bif->user_instance);
  clib_memset (bif, 0, sizeof (*bif));
  pool_put (bm->interfaces, bif);

  return 0;
}

void
bond_create_if (vlib_main_t * vm, bond_create_if_args_t * args)
{
  bond_main_t *bm = &bond_main;
  vnet_main_t *vnm = vnet_get_main ();
  vnet_sw_interface_t *sw;
  bond_if_t *bif;

  if ((args->mode == BOND_MODE_LACP) && bm->lacp_plugin_loaded == 0)
    {
      args->rv = VNET_API_ERROR_FEATURE_DISABLED;
      args->error = clib_error_return (0, "LACP plugin is not loaded");
      return;
    }
  if (args->mode > BOND_MODE_LACP || args->mode < BOND_MODE_ROUND_ROBIN)
    {
      args->rv = VNET_API_ERROR_INVALID_ARGUMENT;
      args->error = clib_error_return (0, "Invalid mode");
      return;
    }
  if (args->lb > BOND_LB_L23)
    {
      args->rv = VNET_API_ERROR_INVALID_ARGUMENT;
      args->error = clib_error_return (0, "Invalid load-balance");
      return;
    }
  pool_get (bm->interfaces, bif);
  clib_memset (bif, 0, sizeof (*bif));
  bif->dev_instance = bif - bm->interfaces;	/* actual */
  bif->user_instance = args->instance;	/* name */
  bif->lb = args->lb;
  bif->mode = args->mode;

  // Adjust requested instance
  if (bif->user_instance == ~0)
    bif->user_instance = bif->dev_instance;
  if (hash_get (bm->instance_used, bif->user_instance))
    {
      args->rv = VNET_API_ERROR_INSTANCE_IN_USE;
      pool_put (bm->interfaces, bif);
      return;
    }
  hash_set (bm->instance_used, bif->user_instance, 1);

  // Special load-balance mode used for rr and bc
  if (bif->mode == BOND_MODE_ROUND_ROBIN)
    bif->lb = BOND_LB_RR;
  else if (bif->mode == BOND_MODE_BROADCAST)
    bif->lb = BOND_LB_BC;
  else if (bif->mode == BOND_MODE_ACTIVE_BACKUP)
    bif->lb = BOND_LB_AB;

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
    (vnm, bond_dev_class.index, bif->dev_instance /* device instance */ ,
     bif->hw_address /* ethernet address */ ,
     &bif->hw_if_index, 0 /* flag change */ );

  if (args->error)
    {
      args->rv = VNET_API_ERROR_INVALID_REGISTRATION;
      hash_unset (bm->instance_used, bif->user_instance);
      pool_put (bm->interfaces, bif);
      return;
    }

  sw = vnet_get_hw_sw_interface (vnm, bif->hw_if_index);
  bif->sw_if_index = sw->sw_if_index;
  bif->group = bif->sw_if_index;
  if (vlib_get_thread_main ()->n_vlib_mains > 1)
    clib_spinlock_init (&bif->lockp);

  vnet_hw_interface_set_flags (vnm, bif->hw_if_index,
			       VNET_HW_INTERFACE_FLAG_LINK_UP);

  hash_set (bm->bond_by_sw_if_index, bif->sw_if_index, bif->dev_instance);

  // for return
  args->sw_if_index = bif->sw_if_index;
}

static clib_error_t *
bond_create_command_fn (vlib_main_t * vm, unformat_input_t * input,
			vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  bond_create_if_args_t args = { 0 };
  u8 mode_is_set = 0;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return clib_error_return (0, "Missing required arguments.");

  args.instance = ~0;
  args.mode = -1;
  args.lb = BOND_LB_L2;
  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "mode %U", unformat_bond_mode, &args.mode))
	mode_is_set = 1;
      else if (((args.mode == BOND_MODE_LACP) || (args.mode == BOND_MODE_XOR))
	       && unformat (line_input, "load-balance %U",
			    unformat_bond_load_balance, &args.lb))
	;
      else if (unformat (line_input, "hw-addr %U",
			 unformat_ethernet_address, args.hw_addr))
	args.hw_addr_set = 1;
      else if (unformat (line_input, "instance %d", &args.instance))
	;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }
  unformat_free (line_input);

  if (mode_is_set == 0)
    return clib_error_return (0, "Missing bond mode");

  bond_create_if (vm, &args);

  return args.error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (bond_create_command, static) = {
  .path = "create bond",
  .short_help = "create bond mode {round-robin | active-backup | broadcast | "
    "{lacp | xor} [load-balance { l2 | l23 | l34 }]} [hw-addr <mac-address>] "
    "[instance <instance>]",
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
      else if (unformat (line_input, "%U", unformat_vnet_sw_interface,
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
    return clib_error_return (0, "not a bond interface");
  else if (rv != 0)
    return clib_error_return (0, "error on deleting bond interface");

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (bond_delete__command, static) =
{
  .path = "delete bond",
  .short_help = "delete bond {<interface> | sw_if_index <sw_idx>}",
  .function = bond_delete_command_fn,
};
/* *INDENT-ON* */

void
bond_enslave (vlib_main_t * vm, bond_enslave_args_t * args)
{
  bond_main_t *bm = &bond_main;
  vnet_main_t *vnm = vnet_get_main ();
  bond_if_t *bif;
  slave_if_t *sif;
  vnet_interface_main_t *im = &vnm->interface_main;
  vnet_hw_interface_t *bif_hw, *sif_hw;
  vnet_sw_interface_t *sw;
  u32 thread_index;
  u32 sif_if_index;

  bif = bond_get_master_by_sw_if_index (args->group);
  if (!bif)
    {
      args->rv = VNET_API_ERROR_INVALID_INTERFACE;
      args->error = clib_error_return (0, "bond interface not found");
      return;
    }
  // make sure the interface is not already enslaved
  if (bond_get_slave_by_sw_if_index (args->slave))
    {
      args->rv = VNET_API_ERROR_VALUE_EXIST;
      args->error = clib_error_return (0, "interface was already enslaved");
      return;
    }
  sif_hw = vnet_get_sup_hw_interface (vnm, args->slave);
  if (sif_hw->dev_class_index == bond_dev_class.index)
    {
      args->rv = VNET_API_ERROR_INVALID_INTERFACE;
      args->error =
	clib_error_return (0, "bond interface cannot be enslaved");
      return;
    }
  pool_get (bm->neighbors, sif);
  clib_memset (sif, 0, sizeof (*sif));
  sw = pool_elt_at_index (im->sw_interfaces, args->slave);
  sif->port_enabled = sw->flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP;
  sif->sw_if_index = sw->sw_if_index;
  sif->hw_if_index = sw->hw_if_index;
  sif->packet_template_index = (u8) ~ 0;
  sif->is_passive = args->is_passive;
  sif->group = args->group;
  sif->bif_dev_instance = bif->dev_instance;
  sif->mode = bif->mode;

  sif->is_long_timeout = args->is_long_timeout;
  if (args->is_long_timeout)
    sif->ttl_in_seconds = LACP_LONG_TIMOUT_TIME;
  else
    sif->ttl_in_seconds = LACP_SHORT_TIMOUT_TIME;

  vec_validate_aligned (bm->slave_by_sw_if_index, sif->sw_if_index,
			CLIB_CACHE_LINE_BYTES);
  /*
   * sif - bm->neighbors may be 0
   * Left shift it by 1 bit to distinguish the valid entry that we actually
   * store from the null entries
   */
  bm->slave_by_sw_if_index[sif->sw_if_index] =
    (uword) (((sif - bm->neighbors) << 1) | 1);
  vec_add1 (bif->slaves, sif->sw_if_index);

  sif_hw = vnet_get_sup_hw_interface (vnm, sif->sw_if_index);

  /* Save the old mac */
  memcpy (sif->persistent_hw_address, sif_hw->hw_address, 6);
  bif_hw = vnet_get_sup_hw_interface (vnm, bif->sw_if_index);
  if (bif->use_custom_mac)
    {
      vnet_hw_interface_change_mac_address (vnm, sif_hw->hw_if_index,
					    bif->hw_address);
    }
  else
    {
      // bond interface gets the mac address from the first slave
      if (vec_len (bif->slaves) == 1)
	{
	  memcpy (bif->hw_address, sif_hw->hw_address, 6);
	  vnet_hw_interface_change_mac_address (vnm, bif_hw->hw_if_index,
						sif_hw->hw_address);
	}
      else
	{
	  // subsequent slaves gets the mac address of the bond interface
	  vnet_hw_interface_change_mac_address (vnm, sif_hw->hw_if_index,
						bif->hw_address);
	}
    }

  if (bif_hw->l2_if_count)
    {
      ethernet_set_flags (vnm, sif_hw->hw_if_index,
			  ETHERNET_INTERFACE_FLAG_ACCEPT_ALL);
      /* ensure all packets go to ethernet-input */
      ethernet_set_rx_redirect (vnm, sif_hw, 1);
    }

  if ((bif->mode == BOND_MODE_LACP) && bm->lacp_enable_disable)
    {
      (*bm->lacp_enable_disable) (vm, bif, sif, 1);
    }
  else
    {
      bond_enable_collecting_distributing (vm, sif);
    }

  vec_foreach_index (thread_index, bm->per_thread_data)
  {
    bond_per_thread_data_t *ptd = vec_elt_at_index (bm->per_thread_data,
						    thread_index);

    vec_validate_aligned (ptd->per_port_queue, vec_len (bif->slaves) - 1,
			  CLIB_CACHE_LINE_BYTES);

    vec_foreach_index (sif_if_index, ptd->per_port_queue)
    {
      ptd->per_port_queue[sif_if_index].n_buffers = 0;
    }
  }

  args->rv = vnet_feature_enable_disable ("device-input", "bond-input",
					  sif_hw->hw_if_index, 1, 0, 0);

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
  bond_enslave_args_t args = { 0 };
  unformat_input_t _line_input, *line_input = &_line_input;
  vnet_main_t *vnm = vnet_get_main ();

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return clib_error_return (0, "Missing required arguments.");

  args.slave = ~0;
  args.group = ~0;
  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%U %U",
		    unformat_vnet_sw_interface, vnm, &args.group,
		    unformat_vnet_sw_interface, vnm, &args.slave))
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
  if (args.group == ~0)
    return clib_error_return (0, "Missing bond interface");
  if (args.slave == ~0)
    return clib_error_return (0, "please specify valid slave interface name");

  bond_enslave (vm, &args);

  return args.error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (enslave_interface_command, static) = {
  .path = "bond add",
  .short_help = "bond add <BondEthernetx> <slave-interface> "
                "[passive] [long-timeout]",
  .function = enslave_interface_command_fn,
};
/* *INDENT-ON* */

void
bond_detach_slave (vlib_main_t * vm, bond_detach_slave_args_t * args)
{
  bond_if_t *bif;
  slave_if_t *sif;

  sif = bond_get_slave_by_sw_if_index (args->slave);
  if (!sif)
    {
      args->rv = VNET_API_ERROR_INVALID_INTERFACE;
      args->error = clib_error_return (0, "interface was not enslaved");
      return;
    }
  bif = bond_get_master_by_dev_instance (sif->bif_dev_instance);
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
      if (unformat (line_input, "%U",
		    unformat_vnet_sw_interface, vnm, &args.slave))
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
    return clib_error_return (0, "please specify valid slave interface name");

  bond_detach_slave (vm, &args);

  return args.error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (detach_interface_command, static) = {
  .path = "bond del",
  .short_help = "bond del <slave-interface>",
  .function = detach_interface_command_fn,
};
/* *INDENT-ON* */

static void
show_bond (vlib_main_t * vm)
{
  bond_main_t *bm = &bond_main;
  bond_if_t *bif;

  vlib_cli_output (vm, "%-16s %-12s %-13s %-13s %-14s %s",
		   "interface name", "sw_if_index", "mode",
		   "load balance", "active slaves", "slaves");

  /* *INDENT-OFF* */
  pool_foreach (bif, bm->interfaces,
  ({
    vlib_cli_output (vm, "%-16U %-12d %-13U %-13U %-14u %u",
		     format_bond_interface_name, bif->dev_instance,
		     bif->sw_if_index, format_bond_mode, bif->mode,
		     format_bond_load_balance, bif->lb,
		     vec_len (bif->active_slaves), vec_len (bif->slaves));
  }));
  /* *INDENT-ON* */
}

static void
show_bond_details (vlib_main_t * vm)
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
    vlib_cli_output (vm, "  user instance: %d", bif->user_instance);
    vlib_cli_output (vm, "  sw_if_index: %d", bif->sw_if_index);
    vlib_cli_output (vm, "  hw_if_index: %d", bif->hw_if_index);
  }));
  /* *INDENT-ON* */
}

static clib_error_t *
show_bond_fn (vlib_main_t * vm, unformat_input_t * input,
	      vlib_cli_command_t * cmd)
{
  u8 details = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "details"))
	details = 1;
      else
	{
	  return clib_error_return (0, "unknown input `%U'",
				    format_unformat_error, input);
	}
    }

  if (details)
    show_bond_details (vm);
  else
    show_bond (vm);

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_bond_command, static) = {
  .path = "show bond",
  .short_help = "show bond [details]",
  .function = show_bond_fn,
};
/* *INDENT-ON* */

clib_error_t *
bond_cli_init (vlib_main_t * vm)
{
  bond_main_t *bm = &bond_main;

  bm->vlib_main = vm;
  bm->vnet_main = vnet_get_main ();
  vec_validate_aligned (bm->slave_by_sw_if_index, 1, CLIB_CACHE_LINE_BYTES);
  vec_validate_aligned (bm->per_thread_data,
			vlib_get_thread_main ()->n_vlib_mains - 1,
			CLIB_CACHE_LINE_BYTES);

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
