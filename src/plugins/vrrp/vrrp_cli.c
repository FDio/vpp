/*
 * vrrp_cli.c - vrrp plugin debug CLI commands
 *
 * Copyright 2019-2020 Rubicon Communications, LLC (Netgate)
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include <vrrp/vrrp.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vpp/app/version.h>


static clib_error_t *
vrrp_vr_add_del_command_fn (vlib_main_t * vm,
			    unformat_input_t * input,
			    vlib_cli_command_t * cmd, u8 is_add)
{
  vrrp_main_t *vmp = &vrrp_main;
  vrrp_vr_config_t vr_conf;
  u32 sw_if_index, vr_id, priority, interval;
  ip46_address_t addr, *addrs;
  u8 n_addrs4, n_addrs6;
  clib_error_t *ret = 0;
  int rv;

  clib_memset (&vr_conf, 0, sizeof (vr_conf));

  /* RFC 5798 - preempt enabled by default */
  vr_conf.flags = VRRP_VR_PREEMPT;

  addrs = 0;
  n_addrs4 = n_addrs6 = 0;

  /* defaults */
  sw_if_index = ~0;
  vr_id = 0;
  priority = 100;
  interval = 100;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      clib_memset (&addr, 0, sizeof (addr));

      if (unformat (input, "%U", unformat_vnet_sw_interface, vmp->vnet_main,
		    &sw_if_index))
	;
      else if (unformat (input, "vr_id %u", &vr_id))
	;
      else if (unformat (input, "ipv6"))
	vr_conf.flags |= VRRP_VR_IPV6;
      else if (unformat (input, "priority %u", &priority))
	;
      else if (unformat (input, "interval %u", &interval))
	;
      else if (unformat (input, "no_preempt"))
	vr_conf.flags &= ~VRRP_VR_PREEMPT;
      else if (unformat (input, "accept_mode"))
	vr_conf.flags |= VRRP_VR_ACCEPT;
      else if (unformat (input, "unicast"))
	vr_conf.flags |= VRRP_VR_UNICAST;
      else if (unformat (input, "%U", unformat_ip4_address, &addr.ip4))
	{
	  n_addrs4++;
	  vec_add1 (addrs, addr);
	}
      else if (unformat (input, "%U", unformat_ip6_address, &addr.ip6))
	{
	  n_addrs6++;
	  vec_add1 (addrs, addr);
	}
      else
	break;
    }

  if (sw_if_index == ~0)
    ret = clib_error_return (0, "Please specify an interface...");
  else if (!vr_id || vr_id > 0xff)
    ret = clib_error_return (0, "VR ID must be between 1 and 255...");

  if (is_add)
    {
      if (!priority || priority > 0xff)
	ret = clib_error_return (0, "priority must be between 1 and 255...");
      else if (interval > 0xffff)
	ret = clib_error_return (0, "interval must be <= 65535...");
      else if (n_addrs4 && (n_addrs6 || vr_conf.flags & VRRP_VR_IPV6))
	ret = clib_error_return (0, "Mismatched address families");
    }

  if (ret)			/* data validation failed */
    goto done;

  vr_conf.sw_if_index = sw_if_index;
  vr_conf.vr_id = (u8) vr_id;
  vr_conf.priority = (u8) priority;
  vr_conf.adv_interval = (u16) interval;
  vr_conf.vr_addrs = addrs;

  rv = vrrp_vr_add_del (is_add, &vr_conf);

  switch (rv)
    {
    case 0:
      break;

      /* adding */
    case VNET_API_ERROR_ENTRY_ALREADY_EXISTS:
      ret = clib_error_return (0, "Failed to add VR that already exists");
      goto done;
      break;

    case VNET_API_ERROR_INVALID_SRC_ADDRESS:
      ret = clib_error_return (0, "Failed to add VR with no IP addresses");
      goto done;
      break;

    case VNET_API_ERROR_ADDRESS_NOT_FOUND_FOR_INTERFACE:
      ret = clib_error_return (0, "Failed to add VR with priority 255 - "
			       "VR IP addresses not configured on interface");
      goto done;
      break;

      /* deleting */
    case VNET_API_ERROR_NO_SUCH_ENTRY:
      ret = clib_error_return (0, "Failed to delete VR which does not exist");
      goto done;
      break;

    default:
      ret = clib_error_return (0, "vrrp_vr_add_del returned %d", rv);
      goto done;
      break;
    }

done:
  vec_free (addrs);

  return ret;
}

static clib_error_t *
vrrp_vr_add_command_fn (vlib_main_t * vm, unformat_input_t * input,
			vlib_cli_command_t * cmd)
{
  return vrrp_vr_add_del_command_fn (vm, input, cmd, 1 /* is_add */ );
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (vrrp_vr_add_command, static) =
{
  .path = "vrrp vr add",
  .short_help =
  "vrrp vr add <interface> [vr_id <n>] [ipv6] [priority <value>] [interval <value>] [no_preempt] [accept_mode] [unicast] [<ip_addr> ...]",
  .function = vrrp_vr_add_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
vrrp_vr_del_command_fn (vlib_main_t * vm, unformat_input_t * input,
			vlib_cli_command_t * cmd)
{
  return vrrp_vr_add_del_command_fn (vm, input, cmd, 0 /* is_add */ );
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (vrrp_vr_del_command, static) =
{
  .path = "vrrp vr del",
  .short_help = "vrrp vr del <interface> [vr_id <n>] [ipv6]",
  .function = vrrp_vr_del_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
vrrp_show_vr_command_fn (vlib_main_t * vm,
			 unformat_input_t * input, vlib_cli_command_t * cmd)
{
  vrrp_main_t *vmp = &vrrp_main;
  vrrp_vr_t *vr;
  u32 sw_if_index = ~0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%U", unformat_vnet_sw_interface, vmp->vnet_main,
		    &sw_if_index))
	;
      else if (unformat (input, "sw_if_index %u", &sw_if_index))
	;
      else
	break;
    }

  pool_foreach (vr, vmp->vrs, (
				{

				if (sw_if_index && (sw_if_index != ~0) &&
				    (sw_if_index != vr->config.sw_if_index))
				continue;
				vlib_cli_output (vm, "%U", format_vrrp_vr,
						 vr);}
		));

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (vrrp_show_vr_command, static) =
{
  .path = "show vrrp vr",
  .short_help =
  "show vrrp vr [(<intf_name>|sw_if_index <n>)]",
  .function = vrrp_show_vr_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
vrrp_proto_start_stop_command_fn (vlib_main_t * vm,
				  unformat_input_t * input,
				  vlib_cli_command_t * cmd)
{
  vrrp_main_t *vmp = &vrrp_main;
  vrrp_vr_key_t vr_key;
  u32 sw_if_index;
  u32 vr_id;
  u8 is_ipv6, is_start, is_stop;
  int rv;

  clib_memset (&vr_key, 0, sizeof (vr_key));

  /* defaults */
  sw_if_index = ~0;
  vr_id = 0;
  is_ipv6 = is_start = is_stop = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%U", unformat_vnet_sw_interface, vmp->vnet_main,
		    &sw_if_index))
	;
      else if (unformat (input, "vr_id %u", &vr_id))
	;
      else if (unformat (input, "ipv6"))
	is_ipv6 = 1;
      else if (unformat (input, "start"))
	is_start = 1;
      else if (unformat (input, "stop"))
	is_stop = 1;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }

  if (is_start == is_stop)
    return clib_error_return (0, "One of start or stop must be specified");
  else if (sw_if_index == ~0)
    return clib_error_return (0, "Please specify an interface...");
  else if (!vr_id)
    return clib_error_return (0, "Invalid VR ID...");

  vr_key.sw_if_index = sw_if_index;
  vr_key.vr_id = vr_id;
  vr_key.is_ipv6 = (is_ipv6 != 0);

  rv = vrrp_vr_start_stop (is_start, &vr_key);

  switch (rv)
    {
    case 0:
      break;
    case VNET_API_ERROR_INIT_FAILED:
      return clib_error_return (0, "Cannot start unicast VR without peers");
      break;
    default:
      return clib_error_return (0, "vrrp_vr_start_stop returned %d", rv);
      break;
    }

  return 0;
}

static clib_error_t *
vrrp_peers_command_fn (vlib_main_t * vm, unformat_input_t * input,
		       vlib_cli_command_t * cmd)
{
  vrrp_main_t *vmp = &vrrp_main;
  vrrp_vr_key_t vr_key;
  u32 sw_if_index;
  u32 vr_id;
  u8 is_ipv6;
  int rv;
  ip46_address_t addr, *addrs;
  u8 n_addrs4, n_addrs6;
  clib_error_t *ret = 0;

  clib_memset (&vr_key, 0, sizeof (vr_key));

  /* defaults */
  addrs = 0;
  n_addrs4 = n_addrs6 = 0;
  sw_if_index = ~0;
  vr_id = 0;
  is_ipv6 = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%U", unformat_vnet_sw_interface, vmp->vnet_main,
		    &sw_if_index))
	;
      else if (unformat (input, "vr_id %u", &vr_id))
	;
      else if (unformat (input, "ipv6"))
	is_ipv6 = 1;
      else if (unformat (input, "%U", unformat_ip4_address, &addr.ip4))
	{
	  n_addrs4++;
	  vec_add1 (addrs, addr);
	}
      else if (unformat (input, "%U", unformat_ip6_address, &addr.ip6))
	{
	  n_addrs6++;
	  vec_add1 (addrs, addr);
	}
      else
	{
	  ret = clib_error_return (0, "unknown input `%U'",
				   format_unformat_error, input);
	  goto done;
	}
    }

  if (sw_if_index == ~0)
    ret = clib_error_return (0, "Please specify an interface...");
  else if (!vr_id)
    ret = clib_error_return (0, "Invalid VR ID...");
  else if (n_addrs4 && (n_addrs6 || is_ipv6))
    ret = clib_error_return (0, "Mismatched address families");

  if (ret)			/* data validation failed */
    goto done;

  vr_key.sw_if_index = sw_if_index;
  vr_key.vr_id = vr_id;
  vr_key.is_ipv6 = (is_ipv6 != 0);

  rv = vrrp_vr_set_peers (&vr_key, addrs);

  switch (rv)
    {
    case 0:
      break;
    case VNET_API_ERROR_INVALID_ARGUMENT:
      ret = clib_error_return (0, "Peers can only be set on a unicast VR");
      break;
    case VNET_API_ERROR_RSRC_IN_USE:
      ret = clib_error_return (0, "Cannot set peers on a running VR");
      break;
    case VNET_API_ERROR_INVALID_DST_ADDRESS:
      ret = clib_error_return (0, "No peer addresses provided");
      break;
    default:
      ret = clib_error_return (0, "vrrp_vr_set_peers returned %d", rv);
      break;
    }

done:
  vec_free (addrs);

  return ret;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (vrrp_proto_start_stop_command, static) =
{
  .path = "vrrp proto",
  .short_help =
  "vrrp proto (start|stop) (<intf_name>|sw_if_index <n>) vr_id <n> [ipv6]",
  .function = vrrp_proto_start_stop_command_fn,
};
/* *INDENT-ON* */

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (vrrp_peers_command, static) =
{
  .path = "vrrp peers",
  .short_help =
  "vrrp peers (<intf_name>|sw_if_index <n>) vr_id <n> [ipv6] <peer1_addr> [<peer2_addr> ...]",
  .function = vrrp_peers_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
vrrp_vr_track_if_command_fn (vlib_main_t * vm,
			     unformat_input_t * input,
			     vlib_cli_command_t * cmd)
{
  vnet_main_t *vnm = vnet_get_main ();
  vrrp_main_t *vmp = &vrrp_main;
  u32 sw_if_index, track_if_index, vr_id, priority;
  u8 is_ipv6 = 0;
  clib_error_t *ret = 0;
  vrrp_vr_tracking_if_t *track_intfs = 0, *track_intf;
  vrrp_vr_t *vr;
  u8 is_add, is_del;
  int rv;

  /* defaults */
  sw_if_index = ~0;
  vr_id = 0;
  is_add = is_del = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%U", unformat_vnet_sw_interface, vmp->vnet_main,
		    &sw_if_index))
	;
      else if (unformat (input, "add"))
	is_add = 1;
      else if (unformat (input, "del"))
	is_del = 1;
      else if (unformat (input, "vr_id %u", &vr_id))
	;
      else if (unformat (input, "ipv6"))
	is_ipv6 = 1;
      else if (unformat (input, "track-index %u priority %u", &track_if_index,
			 &priority))
	{
	  vec_add2 (track_intfs, track_intf, 1);;
	  track_intf->sw_if_index = track_if_index;
	  track_intf->priority = priority;
	}
      else
	break;
    }

  if (sw_if_index == ~0)
    ret = clib_error_return (0, "Please specify an interface");
  else if (!vr_id || vr_id > 0xff)
    ret = clib_error_return (0, "VR ID must be between 1 and 255");
  else if (is_add == is_del)
    ret = clib_error_return (0, "One of add,delete must be specified");

  if (ret)
    goto done;

  vr = vrrp_vr_lookup (sw_if_index, vr_id, is_ipv6);
  if (!vr)
    {
      ret = clib_error_return (0, "VR not found");
      goto done;
    }

  vec_foreach (track_intf, track_intfs)
  {
    if (!vnet_sw_interface_is_valid (vnm, track_intf->sw_if_index))
      {
	ret = clib_error_return (0, "tracked intf sw_if_index %u invalid",
				 track_intf->sw_if_index);
	goto done;
      }
    if (!track_intf->priority)
      {
	ret = clib_error_return (0, "tracked intf priority must be > 0");
	goto done;
      }
    if (track_intf->priority >= vr->config.priority)
      {
	ret = clib_error_return (0, "tracked intf priority must be less "
				 "than VR priority (%u)",
				 vr->config.priority);
	goto done;
      }
  }

  rv = vrrp_vr_tracking_ifs_add_del (vr, track_intfs, is_add);
  if (rv)
    ret = clib_error_return (0, "vrrp_vr_tracking_ifs_add_del returned %d",
			     rv);

done:
  vec_free (track_intfs);

  return ret;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (vrrp_vr_track_if_command, static) =
{
  .path = "vrrp vr track-if",
  .short_help =
  "vrrp vr track-if (add|del) (<intf_name>|sw_if_index <n>) vr_id <n> [ipv6] track-index <n> priority <n> [ track-index <n> priority <n> ...]",
  .function = vrrp_vr_track_if_command_fn,
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
