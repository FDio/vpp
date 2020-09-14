/*
 * l2_input.c : layer 2 input packet processing
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

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/ethernet/packet.h>
#include <vnet/ip/ip_packet.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/fib/fib_node.h>
#include <vnet/ethernet/arp_packet.h>
#include <vlib/cli.h>
#include <vnet/l2/l2_input.h>
#include <vnet/l2/l2_output.h>
#include <vnet/l2/feat_bitmap.h>
#include <vnet/l2/l2_bvi.h>
#include <vnet/l2/l2_fib.h>
#include <vnet/l2/l2_bd.h>

#include <vppinfra/error.h>
#include <vppinfra/hash.h>
#include <vppinfra/cache.h>

/**
 * @file
 * @brief Interface Input Mode (Layer 2 Cross-Connect or Bridge / Layer 3).
 *
 * This file contains the CLI Commands that modify the input mode of an
 * interface. For interfaces in a Layer 2 cross-connect, all packets
 * received on one interface will be transmitted to the other. For
 * interfaces in a bridge-domain, packets will be forwarded to other
 * interfaces in the same bridge-domain based on destination mac address.
 * For interfaces in Layer 3 mode, the packets will be routed.
 */

/* Feature graph node names */
static char *l2input_feat_names[] = {
#define _(sym,name) name,
  foreach_l2input_feat
#undef _
};

char **
l2input_get_feat_names (void)
{
  return l2input_feat_names;
}

u8 *
format_l2_input_feature_bitmap (u8 * s, va_list * args)
{
  static char *display_names[] = {
#define _(sym,name) #sym,
    foreach_l2input_feat
#undef _
  };
  u32 feature_bitmap = va_arg (*args, u32);
  u32 verbose = va_arg (*args, u32);

  if (feature_bitmap == 0)
    {
      s = format (s, "  none configured");
      return s;
    }

  feature_bitmap &= ~L2INPUT_FEAT_DROP;	/* Not a feature */
  int i;
  for (i = L2INPUT_N_FEAT - 1; i >= 0; i--)
    {
      if (feature_bitmap & (1 << i))
	{
	  if (verbose)
	    s = format (s, "%17s (%s)\n",
			display_names[i], l2input_feat_names[i]);
	  else
	    s = format (s, "%s ", l2input_feat_names[i]);
	}
    }
  return s;
}

u8 *
format_l2_input_features (u8 * s, va_list * args)
{
  u32 sw_if_index = va_arg (*args, u32);
  u32 verbose = va_arg (*args, u32);
  
  l2_input_config_t *l2_input = l2input_intf_config (sw_if_index);
  u32 fb = l2_input->feature_bitmap;

  /* intf input features are masked by bridge domain */
  if (l2_input_is_bridge (l2_input))
    fb &= l2_input->bd_feature_bitmap;

  s =
    format (s, "\nl2-input:\n%U", format_l2_input_feature_bitmap, fb,
	    verbose);

  return (s);
}

u8 *
format_l2_input (u8 * s, va_list * args)
{
  u32 sw_if_index = va_arg (*args, u32);
  l2_input_config_t *l2_input = l2input_intf_config (sw_if_index);

  /* intf input features are masked by bridge domain */
  if (l2_input_is_bridge (l2_input))
    {
      bd_main_t *bdm = &bd_main;
      u32 bd_id = l2input_main.bd_configs[l2_input->bd_index].bd_id;

      s = format (s, "  L2 bridge bd-id %d idx %d shg %d %s",
		  bd_id, bd_find_index (bdm, bd_id), l2_input->shg,
		  l2_input_is_bvi (l2_input) ? "bvi" : " ");
    }
  else if (l2_input_is_xconnect (l2_input))
    s = format (s, "  L2 xconnect %U",
		format_vnet_sw_if_index_name, vnet_get_main (),
		l2_input->output_sw_if_index);

  return (s);
}

clib_error_t *
l2input_init (vlib_main_t * vm)
{
  l2input_main_t *mp = &l2input_main;

  mp->vlib_main = vm;
  mp->vnet_main = vnet_get_main ();

  /* Get packets RX'd from L2 interfaces */
  ethernet_register_l2_input (vm, l2input_node.index);

  /* Initialize the feature next-node indexes */
  feat_bitmap_init_next_nodes (vm,
			       l2input_node.index,
			       L2INPUT_N_FEAT,
			       l2input_get_feat_names (),
			       mp->feat_next_node_index);

  return 0;
}

VLIB_INIT_FUNCTION (l2input_init);


/** Get a pointer to the config for the given interface. */
l2_input_config_t *
l2input_intf_config (u32 sw_if_index)
{
  l2input_main_t *mp = &l2input_main;

  vec_validate (mp->configs, sw_if_index);
  return vec_elt_at_index (mp->configs, sw_if_index);
}

/** Enable (or disable) the feature in the bitmap for the given interface. */
u32
l2input_intf_bitmap_enable (u32 sw_if_index,
			    l2input_feat_masks_t feature_bitmap, u32 enable)
{
  l2_input_config_t *config = l2input_intf_config (sw_if_index);

  if (enable)
    config->feature_bitmap |= feature_bitmap;
  else
    config->feature_bitmap &= ~feature_bitmap;

  return config->feature_bitmap;
}

u32
l2input_set_bridge_features (u32 bd_index, u32 feat_mask, u32 feat_value)
{
  l2_bridge_domain_t *bd_config = l2input_bd_config (bd_index);;
  bd_validate (bd_config);
  bd_config->feature_bitmap =
    (bd_config->feature_bitmap & ~feat_mask) | feat_value;
  return bd_config->feature_bitmap;
}

void
l2input_interface_mac_change (u32 sw_if_index,
			      const u8 * old_address, const u8 * new_address)
{
  /* check if the sw_if_index passed is a BVI in a BD */
  l2_input_config_t *intf_config;

  intf_config = l2input_intf_config (sw_if_index);

  if (l2_input_is_bridge (intf_config) && l2_input_is_bvi (intf_config))
    {
      /* delete and re-add l2fib entry for the bvi interface */
      l2fib_del_entry (old_address, intf_config->bd_index, sw_if_index);
      l2fib_add_entry (new_address,
		       intf_config->bd_index,
		       sw_if_index,
		       L2FIB_ENTRY_RESULT_FLAG_BVI |
		       L2FIB_ENTRY_RESULT_FLAG_STATIC);
    }
}

walk_rc_t
l2input_recache (u32 bd_index, u32 sw_if_index)
{
  l2_input_config_t *input;
  l2_bridge_domain_t *bd;

  bd = bd_get (bd_index);
  input = l2input_intf_config (sw_if_index);

  input->bd_mac_age = bd->mac_age;
  input->bd_seq_num = bd->seq_num;
  input->bd_feature_bitmap = bd->feature_bitmap;

  return (WALK_CONTINUE);
}

void
l2_input_seq_num_inc (u32 sw_if_index)
{
  l2_input_config_t *input;

  input = vec_elt_at_index (l2input_main.configs, sw_if_index);

  input->seq_num++;
}

/**
 * Set the subinterface to run in l2 or l3 mode.
 * For L3 mode, just the sw_if_index is specified.
 * For bridged mode, the bd id and bvi flag are also specified.
 * For xconnect mode, the peer sw_if_index is also specified.
 * Return 0 if ok, or non-0 if there was an error.
 */

u32
set_int_l2_mode (vlib_main_t * vm, vnet_main_t * vnet_main,	/*           */
		 u32 mode,	/* One of L2 modes or back to L3 mode        */
		 u32 sw_if_index,	/* sw interface index                */
		 u32 bd_index,	/* for bridged interface                     */
		 l2_bd_port_type_t port_type,	/* port_type */
		 u32 shg,	/* the bridged interface split horizon group */
		 u32 xc_sw_if_index)	/* peer interface for xconnect       */
{
  l2output_main_t *l2om = &l2output_main;
  vnet_main_t *vnm = vnet_get_main ();
  vnet_hw_interface_t *hi;
  l2_output_config_t *out_config;
  l2_input_config_t *config;
  l2_bridge_domain_t *bd_config;
  i32 l2_if_adjust = 0;
  vnet_device_class_t *dev_class;

  hi = vnet_get_sup_hw_interface (vnet_main, sw_if_index);
  config = l2input_intf_config (sw_if_index);

  if (l2fib_main.mac_table_initialized == 0)
    l2fib_table_init ();

  if (l2_input_is_bridge (config))
    {
      /* Interface is already in bridge mode. Undo the existing config. */
      bd_config = bd_get (config->bd_index);

      /* remove interface from flood vector */
      bd_remove_member (bd_config, sw_if_index);

      /* undo any BVI-related config */
      if (bd_config->bvi_sw_if_index == sw_if_index)
	{
	  vnet_sw_interface_t *si;

	  bd_config->bvi_sw_if_index = ~0;
	  config->flags &= ~L2_INPUT_FLAG_BVI;

	  /* delete the l2fib entry for the bvi interface */
	  l2fib_del_entry (hi->hw_address, config->bd_index, sw_if_index);

	  /* since this is a no longer BVI interface do not to flood to it */
	  si = vnet_get_sw_interface (vnm, sw_if_index);
	  si->flood_class = VNET_FLOOD_CLASS_NO_FLOOD;
	}
      if (bd_config->uu_fwd_sw_if_index == sw_if_index)
	{
	  bd_config->uu_fwd_sw_if_index = ~0;
	  bd_config->feature_bitmap &= ~L2INPUT_FEAT_UU_FWD;
	}

      /* Clear MACs learned on the interface */
      if ((config->feature_bitmap & L2INPUT_FEAT_LEARN) ||
	  (bd_config->feature_bitmap & L2INPUT_FEAT_LEARN))
	l2fib_flush_int_mac (vm, sw_if_index);

      bd_input_walk (config->bd_index, l2input_recache, NULL);
      l2_if_adjust--;
    }
  else if (l2_input_is_xconnect (config))
    {
      l2_if_adjust--;
    }

  /* Make sure vector is big enough */
  vec_validate_init_empty (l2om->output_node_index_vec, sw_if_index,
			   L2OUTPUT_NEXT_DROP);

  /* Initialize the l2-input configuration for the interface */
  if (mode == MODE_L3)
    {
      /* Set L2 config to BD index 0 so that if any packet accidentally
       * came in on L2 path, it will be dropped in BD 0 */
      config->flags = L2_INPUT_FLAG_NONE;
      config->shg = 0;
      config->bd_index = 0;
      config->feature_bitmap = L2INPUT_FEAT_DROP;

      /* Clear L2 output config */
      out_config = l2output_intf_config (sw_if_index);
      clib_memset (out_config, 0, sizeof (l2_output_config_t));

      /* Make sure any L2-output packet to this interface now in L3 mode is
       * dropped. This may happen if L2 FIB MAC entry is stale */
      l2om->output_node_index_vec[sw_if_index] = L2OUTPUT_NEXT_BAD_INTF;
    }
  else
    {
      /* Add or update l2-output node next-arc and output_node_index_vec table
       * for the interface */
      l2output_create_output_node_mapping (vm, vnet_main, sw_if_index);

      if (mode == MODE_L2_BRIDGE)
	{
	  u8 member_flags;

	  /*
	   * Remove a check that the interface must be an Ethernet.
	   * Specifically so we can bridge to L3 tunnel interfaces.
	   * Here's the check:
	   * if (hi->hw_class_index != ethernet_hw_interface_class.index)
	   *
	   */
	  if (!hi)
	    return MODE_ERROR_ETH;	/* non-ethernet */

	  config->flags = L2_INPUT_FLAG_BRIDGE;
	  config->bd_index = bd_index;
	  l2_input_seq_num_inc (sw_if_index);

	  /*
	   * Enable forwarding, flooding, learning and ARP termination by default
	   * (note that ARP term is disabled on BD feature bitmap by default)
	   */
	  config->feature_bitmap |= (L2INPUT_FEAT_FWD |
				     L2INPUT_FEAT_UU_FLOOD |
				     L2INPUT_FEAT_UU_FWD |
				     L2INPUT_FEAT_FLOOD |
				     L2INPUT_FEAT_LEARN |
				     L2INPUT_FEAT_ARP_UFWD |
				     L2INPUT_FEAT_ARP_TERM);

	  /* Make sure last-chance drop is configured */
	  config->feature_bitmap |= L2INPUT_FEAT_DROP;

	  /* Make sure xconnect is disabled */
	  config->feature_bitmap &= ~L2INPUT_FEAT_XCONNECT;

	  /* Set up bridge domain */
	  bd_config = l2input_bd_config (bd_index);
	  bd_validate (bd_config);

	  /* TODO: think: add l2fib entry even for non-bvi interface? */

	  /* Do BVI interface initializations */
	  if (L2_BD_PORT_TYPE_BVI == port_type)
	    {
	      vnet_sw_interface_t *si;

	      /* ensure BD has no bvi interface (or replace that one with this??) */
	      if (bd_config->bvi_sw_if_index != ~0)
		{
		  return MODE_ERROR_BVI_DEF;	/* bd already has a bvi interface */
		}
	      bd_config->bvi_sw_if_index = sw_if_index;
	      config->flags |= L2_INPUT_FLAG_BVI;

	      /* create the l2fib entry for the bvi interface */
	      l2fib_add_entry (hi->hw_address, bd_index, sw_if_index,
			       L2FIB_ENTRY_RESULT_FLAG_BVI |
			       L2FIB_ENTRY_RESULT_FLAG_STATIC);

	      /* Disable learning by default. no use since l2fib entry is static. */
	      config->feature_bitmap &= ~L2INPUT_FEAT_LEARN;

	      /* since this is a BVI interface we want to flood to it */
	      si = vnet_get_sw_interface (vnm, sw_if_index);
	      si->flood_class = VNET_FLOOD_CLASS_BVI;
	      member_flags = L2_FLOOD_MEMBER_BVI;
	    }
	  else if (L2_BD_PORT_TYPE_UU_FWD == port_type)
	    {
	      bd_config->uu_fwd_sw_if_index = sw_if_index;
	      bd_config->feature_bitmap |= L2INPUT_FEAT_UU_FWD;
	    }
	  else
	    {
	      member_flags = L2_FLOOD_MEMBER_NORMAL;
	    }

	  if (L2_BD_PORT_TYPE_NORMAL == port_type ||
	      L2_BD_PORT_TYPE_BVI == port_type)
	    {
	      /* Add interface to bridge-domain flood vector */
	      l2_flood_member_t member = {
		.sw_if_index = sw_if_index,
		.flags = member_flags,
		.shg = shg,
	      };
	      bd_add_member (bd_config, &member);
	    }
	}
      else if (mode == MODE_L2_XC)
	{
	  config->flags = L2_INPUT_FLAG_XCONNECT;
	  config->output_sw_if_index = xc_sw_if_index;

	  /* Make sure last-chance drop is configured */
	  config->feature_bitmap |= L2INPUT_FEAT_DROP;

	  /* Make sure bridging features are disabled */
	  config->feature_bitmap &=
	    ~(L2INPUT_FEAT_LEARN | L2INPUT_FEAT_FWD | L2INPUT_FEAT_FLOOD);

	  config->feature_bitmap |= L2INPUT_FEAT_XCONNECT;
	  shg = 0;		/* not used in xconnect */
	}
      else if (mode == MODE_L2_CLASSIFY)
	{
	  config->flags = L2_INPUT_FLAG_XCONNECT;
	  config->output_sw_if_index = xc_sw_if_index;

	  /* Make sure last-chance drop is configured */
	  config->feature_bitmap |=
	    L2INPUT_FEAT_DROP | L2INPUT_FEAT_INPUT_CLASSIFY;

	  /* Make sure bridging features are disabled */
	  config->feature_bitmap &=
	    ~(L2INPUT_FEAT_LEARN | L2INPUT_FEAT_FWD | L2INPUT_FEAT_FLOOD);
	  shg = 0;		/* not used in xconnect */
	}

      /* set up split-horizon group and set output feature bit */
      config->shg = shg;
      out_config = l2output_intf_config (sw_if_index);
      out_config->shg = shg;
      out_config->feature_bitmap |= L2OUTPUT_FEAT_OUTPUT;

      /*
       * Test: remove this when non-IP features can be configured.
       * Enable a non-IP feature to test IP feature masking
       * config->feature_bitmap |= L2INPUT_FEAT_CTRL_PKT;
       */

      l2_if_adjust++;

      bd_input_walk (bd_index, l2input_recache, NULL);
    }

  /* Adjust count of L2 interfaces */
  hi->l2_if_count += l2_if_adjust;

  if (hi->hw_class_index == ethernet_hw_interface_class.index)
    {
      if ((hi->l2_if_count == 1) && (l2_if_adjust == 1))
	{
	  /* Just added first L2 interface on this port
	   * Set promiscuous mode on the l2 interface */
	  ethernet_set_flags (vnet_main, hi->hw_if_index,
			      ETHERNET_INTERFACE_FLAG_ACCEPT_ALL);
	}
      else if ((hi->l2_if_count == 0) && (l2_if_adjust == -1))
	{
	  /* Just removed only L2 subinterface on this port
	   * Disable promiscuous mode on the l2 interface */
	  ethernet_set_flags (vnet_main, hi->hw_if_index,
			      /*ETHERNET_INTERFACE_FLAG_DEFAULT_L3 */ 0);

	}
    }

  /* Set up the L2/L3 flag in the interface parsing tables */
  ethernet_sw_interface_set_l2_mode (vnm, sw_if_index, (mode != MODE_L3));

  dev_class = vnet_get_device_class (vnet_main, hi->dev_class_index);
  if (dev_class->set_l2_mode_function)
    {
      dev_class->set_l2_mode_function (vnet_main, hi, l2_if_adjust);
    }

  return 0;
}

static clib_error_t *
l2_input_interface_add_del (vnet_main_t * vnm, u32 sw_if_index, u32 is_add)
{
  if (!is_add)
    {
      vlib_main_t *vm = vlib_get_main ();
      l2_input_config_t *config;

      if (sw_if_index < vec_len (l2input_main.configs))
	{
	  config = vec_elt_at_index (l2input_main.configs, sw_if_index);
	  if (l2_input_is_xconnect (config))
	    set_int_l2_mode (vm, vnm, MODE_L3, config->output_sw_if_index, 0,
			     L2_BD_PORT_TYPE_NORMAL, 0, 0);
	  if (l2_input_is_xconnect (config) || l2_input_is_bridge (config))
	    set_int_l2_mode (vm, vnm, MODE_L3, sw_if_index, 0,
			     L2_BD_PORT_TYPE_NORMAL, 0, 0);
	}
    }

  return (NULL);
}

VNET_SW_INTERFACE_ADD_DEL_FUNCTION (l2_input_interface_add_del);

/**
 * Set subinterface in bridging mode with a bridge-domain ID.
 * The CLI format is:
 *   set interface l2 bridge <interface> <bd> [bvi] [split-horizon-group]
 */
static clib_error_t *
int_l2_bridge (vlib_main_t * vm,
	       unformat_input_t * input, vlib_cli_command_t * cmd)
{
  vnet_main_t *vnm = vnet_get_main ();
  l2_bd_port_type_t port_type;
  clib_error_t *error = 0;
  u32 bd_index, bd_id;
  u32 sw_if_index;
  u32 rc;
  u32 shg;

  if (!unformat_user (input, unformat_vnet_sw_interface, vnm, &sw_if_index))
    {
      error = clib_error_return (0, "unknown interface `%U'",
				 format_unformat_error, input);
      goto done;
    }

  if (!unformat (input, "%d", &bd_id))
    {
      error = clib_error_return (0, "expected bridge domain ID `%U'",
				 format_unformat_error, input);
      goto done;
    }

  if (bd_id > L2_BD_ID_MAX)
    {
      error = clib_error_return (0, "bridge domain ID exceed 16M limit",
				 format_unformat_error, input);
      goto done;
    }
  bd_index = bd_find_or_add_bd_index (&bd_main, bd_id);

  /* optional bvi  */
  port_type = L2_BD_PORT_TYPE_NORMAL;
  if (unformat (input, "bvi"))
    port_type = L2_BD_PORT_TYPE_BVI;
  if (unformat (input, "uu-fwd"))
    port_type = L2_BD_PORT_TYPE_UU_FWD;

  /* optional split horizon group */
  shg = 0;
  (void) unformat (input, "%d", &shg);

  /* set the interface mode */
  if ((rc =
       set_int_l2_mode (vm, vnm, MODE_L2_BRIDGE, sw_if_index, bd_index,
			port_type, shg, 0)))
    {
      if (rc == MODE_ERROR_ETH)
	{
	  error = clib_error_return (0, "bridged interface must be ethernet",
				     format_unformat_error, input);
	}
      else if (rc == MODE_ERROR_BVI_DEF)
	{
	  error =
	    clib_error_return (0, "bridge-domain already has a bvi interface",
			       format_unformat_error, input);
	}
      else
	{
	  error = clib_error_return (0, "invalid configuration for interface",
				     format_unformat_error, input);
	}
      goto done;
    }

done:
  return error;
}

/*?
 * Use this command put an interface into Layer 2 bridge domain. If a
 * bridge-domain with the provided bridge-domain-id does not exist, it
 * will be created. Interfaces in a bridge-domain forward packets to
 * other interfaces in the same bridge-domain based on destination mac
 * address. To remove an interface from a the Layer 2 bridge domain,
 * put the interface in a different mode, for example Layer 3 mode.
 *
 * Optionally, an interface can be added to a Layer 2 bridge-domain as
 * a Bridged Virtual Interface (bvi). Only one interface in a Layer 2
 * bridge-domain can be a bvi.
 *
 * Optionally, a split-horizon group can also be specified. This defaults
 * to 0 if not specified.
 *
 * @cliexpar
 * Example of how to configure a Layer 2 bridge-domain with three
 * interfaces (where 200 is the bridge-domain-id):
 * @cliexcmd{set interface l2 bridge GigabitEthernet0/8/0.200 200}
 * This interface is added a BVI interface:
 * @cliexcmd{set interface l2 bridge GigabitEthernet0/9/0.200 200 bvi}
 * This interface also has a split-horizon group of 1 specified:
 * @cliexcmd{set interface l2 bridge GigabitEthernet0/a/0.200 200 1}
 * Example of how to remove an interface from a Layer2 bridge-domain:
 * @cliexcmd{set interface l3 GigabitEthernet0/a/0.200}
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (int_l2_bridge_cli, static) = {
  .path = "set interface l2 bridge",
  .short_help = "set interface l2 bridge <interface> <bridge-domain-id> [bvi|uu-fwd] [shg]",
  .function = int_l2_bridge,
};
/* *INDENT-ON* */

/**
 * Set subinterface in xconnect mode with another interface.
 * The CLI format is:
 *   set interface l2 xconnect <interface> <peer interface>
 */
static clib_error_t *
int_l2_xc (vlib_main_t * vm,
	   unformat_input_t * input, vlib_cli_command_t * cmd)
{
  vnet_main_t *vnm = vnet_get_main ();
  clib_error_t *error = 0;
  u32 sw_if_index;
  u32 xc_sw_if_index;

  if (!unformat_user (input, unformat_vnet_sw_interface, vnm, &sw_if_index))
    {
      error = clib_error_return (0, "unknown interface `%U'",
				 format_unformat_error, input);
      goto done;
    }

  if (!unformat_user
      (input, unformat_vnet_sw_interface, vnm, &xc_sw_if_index))
    {
      error = clib_error_return (0, "unknown peer interface `%U'",
				 format_unformat_error, input);
      goto done;
    }

  /* set the interface mode */
  if (set_int_l2_mode
      (vm, vnm, MODE_L2_XC, sw_if_index, 0, L2_BD_PORT_TYPE_NORMAL,
       0, xc_sw_if_index))
    {
      error = clib_error_return (0, "invalid configuration for interface",
				 format_unformat_error, input);
      goto done;
    }

done:
  return error;
}

/*?
 * Use this command put an interface into Layer 2 cross-connect mode.
 * Both interfaces must be in this mode for bi-directional traffic. All
 * packets received on one interface will be transmitted to the other.
 * To remove the Layer 2 cross-connect, put the interface in a different
 * mode, for example Layer 3 mode.
 *
 * @cliexpar
 * Example of how to configure a Layer2 cross-connect between two interfaces:
 * @cliexcmd{set interface l2 xconnect GigabitEthernet0/8/0.300 GigabitEthernet0/9/0.300}
 * @cliexcmd{set interface l2 xconnect GigabitEthernet0/9/0.300 GigabitEthernet0/8/0.300}
 * Example of how to remove a Layer2 cross-connect:
 * @cliexcmd{set interface l3 GigabitEthernet0/8/0.300}
 * @cliexcmd{set interface l3 GigabitEthernet0/9/0.300}
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (int_l2_xc_cli, static) = {
  .path = "set interface l2 xconnect",
  .short_help = "set interface l2 xconnect <interface> <peer interface>",
  .function = int_l2_xc,
};
/* *INDENT-ON* */

/**
 * Set subinterface in L3 mode.
 * The CLI format is:
 *   set interface l3 <interface>
 */
static clib_error_t *
int_l3 (vlib_main_t * vm, unformat_input_t * input, vlib_cli_command_t * cmd)
{
  vnet_main_t *vnm = vnet_get_main ();
  clib_error_t *error = 0;
  u32 sw_if_index;

  if (!unformat_user (input, unformat_vnet_sw_interface, vnm, &sw_if_index))
    {
      error = clib_error_return (0, "unknown interface `%U'",
				 format_unformat_error, input);
      goto done;
    }

  /* set the interface mode */
  if (set_int_l2_mode (vm, vnm, MODE_L3, sw_if_index, 0,
		       L2_BD_PORT_TYPE_NORMAL, 0, 0))
    {
      error = clib_error_return (0, "invalid configuration for interface",
				 format_unformat_error, input);
      goto done;
    }

done:
  return error;
}

/*?
 * Modify the packet processing mode of the interface to Layer 3, which
 * implies packets will be routed. This is the default mode of an interface.
 * Use this command to remove an interface from a Layer 2 cross-connect or a
 * Layer 2 bridge.
 *
 * @cliexpar
 * Example of how to set the mode of an interface to Layer 3:
 * @cliexcmd{set interface l3 GigabitEthernet0/8/0.200}
?*/
/* *INDENT-OFF* */
     VLIB_CLI_COMMAND (int_l3_cli, static) = {
  .path = "set interface l3",
  .short_help = "set interface l3 <interface>",
  .function = int_l3,
};
/* *INDENT-ON* */

/**
 * Show interface mode.
 * The CLI format is:
 *    show mode [<if-name1> <if-name2> ...]
 */
static clib_error_t *
show_int_mode (vlib_main_t * vm,
	       unformat_input_t * input, vlib_cli_command_t * cmd)
{
  vnet_main_t *vnm = vnet_get_main ();
  clib_error_t *error = 0;
  char *mode;
  u8 *args;
  vnet_interface_main_t *im = &vnm->interface_main;

  vnet_sw_interface_t *si, *sis = 0;
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      u32 sw_if_index;

      /* See if user wants to show specific interface */
      if (unformat
	  (input, "%U", unformat_vnet_sw_interface, vnm, &sw_if_index))
	{
	  si = pool_elt_at_index (im->sw_interfaces, sw_if_index);
	  vec_add1 (sis, si[0]);
	}
      else
	{
	  error = clib_error_return (0, "unknown input `%U'",
				     format_unformat_error, input);
	  goto done;
	}
    }

  if (vec_len (sis) == 0)	/* Get all interfaces */
    {
      /* Gather interfaces. */
      sis = vec_new (vnet_sw_interface_t, pool_elts (im->sw_interfaces));
      _vec_len (sis) = 0;
      /* *INDENT-OFF* */
      pool_foreach (si, im->sw_interfaces, ({ vec_add1 (sis, si[0]); }));
      /* *INDENT-ON* */
    }

  vec_foreach (si, sis)
  {
    l2_input_config_t *config = l2input_intf_config (si->sw_if_index);
    if (l2_input_is_bridge (config))
      {
	u32 bd_id;
	mode = "l2 bridge";
	bd_id = l2input_main.bd_configs[config->bd_index].bd_id;

	args = format (0, "bd_id %d%s shg %d", bd_id,
		       l2_input_is_bvi (config) ? " bvi" : "", config->shg);
      }
    else if (l2_input_is_xconnect (config))
      {
	mode = "l2 xconnect";
	args = format (0, "%U",
		       format_vnet_sw_if_index_name,
		       vnm, config->output_sw_if_index);
      }
    else
      {
	mode = "l3";
	args = format (0, " ");
      }
    vlib_cli_output (vm, "%s %U %v\n",
		     mode,
		     format_vnet_sw_if_index_name,
		     vnm, si->sw_if_index, args);
    vec_free (args);
  }

done:
  vec_free (sis);

  return error;
}

/*?
 * Show the packet processing mode (Layer2 cross-connect, Layer 2 bridge,
 * Layer 3 routed) of all interfaces and sub-interfaces, or limit the
 * output to just the provided list of interfaces and sub-interfaces.
 * The output shows the mode, the interface, and if the interface is
 * a member of a bridge, the bridge-domain-id and the split horizon group (shg).
 *
 * @cliexpar
 * Example of displaying the mode of all interfaces:
 * @cliexstart{show mode}
 * l3 local0
 * l3 GigabitEthernet0/8/0
 * l3 GigabitEthernet0/9/0
 * l3 GigabitEthernet0/a/0
 * l2 bridge GigabitEthernet0/8/0.200 bd_id 200 shg 0
 * l2 bridge GigabitEthernet0/9/0.200 bd_id 200 shg 0
 * l2 bridge GigabitEthernet0/a/0.200 bd_id 200 shg 0
 * l2 xconnect GigabitEthernet0/8/0.300 GigabitEthernet0/9/0.300
 * l2 xconnect GigabitEthernet0/9/0.300 GigabitEthernet0/8/0.300
 * @cliexend
 * Example of displaying the mode of a selected list of interfaces:
 * @cliexstart{show mode GigabitEthernet0/8/0 GigabitEthernet0/8/0.200}
 * l3 GigabitEthernet0/8/0
 * l2 bridge GigabitEthernet0/8/0.200 bd_id 200 shg 0
 * @cliexend
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_l2_mode, static) = {
  .path = "show mode",
  .short_help = "show mode [<if-name1> <if-name2> ...]",
  .function = show_int_mode,
};
/* *INDENT-ON* */

#define foreach_l2_init_function                \
_(feat_bitmap_drop_init)                        \
_(l2fib_init)                                   \
_(l2_input_classify_init)                             \
_(l2bd_init)                                    \
_(l2fwd_init)                                   \
_(l2_in_out_acl_init)                           \
_(l2input_init)                                 \
_(l2_vtr_init)                                  \
_(l2_invtr_init)                                \
_(l2_efp_filter_init)                           \
_(l2learn_init)                                 \
_(l2flood_init)                                 \
_(l2output_init)				\
_(l2_patch_init)				\
_(l2_xcrw_init)

clib_error_t *
l2_init (vlib_main_t * vm)
{
  clib_error_t *error;

#define _(a) do {                                                       \
  if ((error = vlib_call_init_function (vm, a))) return error; }        \
while (0);
  foreach_l2_init_function;
#undef _
  return 0;
}

VLIB_INIT_FUNCTION (l2_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
