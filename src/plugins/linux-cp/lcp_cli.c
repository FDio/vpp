/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2020 Rubicon Communications, LLC.
 */

#include <sys/socket.h>
#include <linux/if.h>

#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vpp/app/version.h>
#include <vnet/format_fns.h>

#include <plugins/linux-cp/lcp_interface.h>

static clib_error_t *
lcp_itf_pair_create_command_fn (vlib_main_t *vm, unformat_input_t *input,
				vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  vnet_main_t *vnm = vnet_get_main ();
  u32 sw_if_index = ~0;
  u8 *host_if_name = NULL;
  lip_host_type_t host_if_type = LCP_ITF_HOST_TAP;
  u8 *ns = NULL;
  clib_error_t *error = NULL;

  if (unformat_user (input, unformat_line_input, line_input))
    {
      while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
	{
	  if (unformat (line_input, "%d", &sw_if_index))
	    ;
	  else if (unformat (line_input, "%U", unformat_vnet_sw_interface, vnm,
			     &sw_if_index))
	    ;
	  else if (unformat (line_input, "host-if %s", &host_if_name))
	    ;
	  else if (unformat (line_input, "netns %s", &ns))
	    ;
	  else if (unformat (line_input, "tun"))
	    host_if_type = LCP_ITF_HOST_TUN;
	  else
	    {
	      error = clib_error_return (0, "unknown input `%U'",
					 format_unformat_error, line_input);
	      break;
	    }
	}
      unformat_free (line_input);
    }

  if (error)
    ;
  else if (sw_if_index == ~0)
    error = clib_error_return (0, "interface name or sw_if_index required");
  else if (!host_if_name)
    error = clib_error_return (0, "host interface name required");
  else if (vec_len (ns) >= LCP_NS_LEN)
    error = clib_error_return (
      0, "Namespace name should be fewer than %d characters", LCP_NS_LEN);
  else
    {
      int r;

      r = lcp_itf_pair_create (sw_if_index, host_if_name, host_if_type, ns,
			       NULL);
      if (r)
	error = clib_error_return (0, "linux-cp pair creation failed (%d)", r);
    }

  vec_free (host_if_name);
  vec_free (ns);

  return error;
}

VLIB_CLI_COMMAND (lcp_itf_pair_create_command, static) = {
  .path = "lcp create",
  .short_help = "lcp create <sw_if_index>|<if-name> host-if <host-if-name> "
		"netns <namespace> [tun]",
  .function = lcp_itf_pair_create_command_fn,
};

static clib_error_t *
lcp_sync_command_fn (vlib_main_t *vm, unformat_input_t *input,
		     vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "on") || unformat (line_input, "enable"))
	lcp_set_sync (1);
      else if (unformat (line_input, "off") ||
	       unformat (line_input, "disable"))
	lcp_set_sync (0);
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, line_input);
    }

  unformat_free (line_input);
  return 0;
}

VLIB_CLI_COMMAND (lcp_sync_command, static) = {
  .path = "lcp lcp-sync",
  .short_help = "lcp lcp-sync [on|enable|off|disable]",
  .function = lcp_sync_command_fn,
};

static clib_error_t *
lcp_sync_unnumbered_command_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "on") || unformat (line_input, "enable"))
	lcp_set_sync_unnumbered (1);
      else if (unformat (line_input, "off") || unformat (line_input, "disable"))
	lcp_set_sync_unnumbered (0);
      else
	return clib_error_return (0, "unknown input `%U'", format_unformat_error, line_input);
    }

  unformat_free (line_input);
  return 0;
}

VLIB_CLI_COMMAND (lcp_sync_unnumbered_command, static) = {
  .path = "lcp lcp-sync-unnumbered",
  .short_help = "lcp lcp-sync-unnumbered [on|enable|off|disable]",
  .function = lcp_sync_unnumbered_command_fn,
};

static clib_error_t *
lcp_auto_subint_command_fn (vlib_main_t *vm, unformat_input_t *input,
			    vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "on") || unformat (line_input, "enable"))
	lcp_set_auto_subint (1);
      else if (unformat (line_input, "off") ||
	       unformat (line_input, "disable"))
	lcp_set_auto_subint (0);
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, line_input);
    }

  unformat_free (line_input);
  return 0;
}

VLIB_CLI_COMMAND (lcp_auto_subint_command, static) = {
  .path = "lcp lcp-auto-subint",
  .short_help = "lcp lcp-auto-subint [on|enable|off|disable]",
  .function = lcp_auto_subint_command_fn,
};

static clib_error_t *
lcp_param_command_fn (vlib_main_t *vm, unformat_input_t *input,
		      vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "del-static-on-link-down"))
	{
	  if (unformat (line_input, "on") || unformat (line_input, "enable"))
	    lcp_set_del_static_on_link_down (1 /* is_del */);
	  else if (unformat (line_input, "off") ||
		   unformat (line_input, "disable"))
	    lcp_set_del_static_on_link_down (0 /* is_del */);
	  else
	    return clib_error_return (0, "unknown input `%U'",
				      format_unformat_error, line_input);
	}
      else if (unformat (line_input, "del-dynamic-on-link-down"))
	{
	  if (unformat (line_input, "on") || unformat (line_input, "enable"))
	    lcp_set_del_dynamic_on_link_down (1 /* is_del */);
	  else if (unformat (line_input, "off") ||
		   unformat (line_input, "disable"))
	    lcp_set_del_dynamic_on_link_down (0 /* is_del */);
	  else
	    return clib_error_return (0, "unknown input `%U'",
				      format_unformat_error, line_input);
	}
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, line_input);
    }

  unformat_free (line_input);
  return 0;
}

VLIB_CLI_COMMAND (lcp_param_command, static) = {
  .path = "lcp param",
  .short_help = "lcp param [del-static-on-link-down (on|enable|off|disable)] "
		"[del-dynamic-on-link-down (on|enable|off|disable)]",
  .function = lcp_param_command_fn,
};

static clib_error_t *
lcp_default_netns_command_fn (vlib_main_t *vm, unformat_input_t *input,
			      vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u8 *ns;
  int r;
  clib_error_t *error = NULL;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  ns = 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "netns %s", &ns))
	;
      else if (unformat (line_input, "clear netns"))
	;
      else
	{
	  vec_free (ns);
	  error = clib_error_return (0, "unknown input `%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  vlib_cli_output (vm, "lcp set default netns '%s'\n", (char *) ns);

  r = lcp_set_default_ns (ns);

  if (r)
    return clib_error_return (0, "linux-cp set default netns failed (%d)", r);

done:
  unformat_free (line_input);

  return error;
}

VLIB_CLI_COMMAND (lcp_default_netns_command, static) = {
  .path = "lcp default",
  .short_help = "lcp default netns [<namespace>]",
  .function = lcp_default_netns_command_fn,
};

static clib_error_t *
lcp_itf_pair_delete_command_fn (vlib_main_t *vm, unformat_input_t *input,
				vlib_cli_command_t *cmd)
{
  vnet_main_t *vnm = vnet_get_main ();
  unformat_input_t _line_input, *line_input = &_line_input;
  u32 sw_if_index = ~0;
  clib_error_t *error = NULL;

  if (unformat_user (input, unformat_line_input, line_input))
    {
      while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
	{
	  if (unformat (line_input, "%d", &sw_if_index))
	    ;
	  else if (unformat (line_input, "%U", unformat_vnet_sw_interface, vnm,
			     &sw_if_index))
	    ;
	  else
	    {
	      error = clib_error_return (0, "unknown input `%U'",
					 format_unformat_error, line_input);
	      break;
	    }
	}
      unformat_free (line_input);
    }

  if (error)
    ;
  else if (sw_if_index == ~0)
    error = clib_error_return (0, "interface name or sw_if_index required");
  else
    {
      int r;

      r = lcp_itf_pair_delete (sw_if_index);
      if (r)
	error = clib_error_return (0, "linux-cp pair deletion failed (%d)", r);
    }

  return error;
}

VLIB_CLI_COMMAND (lcp_itf_pair_delete_command, static) = {
  .path = "lcp delete",
  .short_help = "lcp delete <sw_if_index>|<if-name>",
  .function = lcp_itf_pair_delete_command_fn,
};

static clib_error_t *
lcp_itf_pair_show_cmd (vlib_main_t *vm, unformat_input_t *input,
		       vlib_cli_command_t *cmd)
{
  vnet_main_t *vnm = vnet_get_main ();
  u32 phy_sw_if_index;

  phy_sw_if_index = ~0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "phy %U", unformat_vnet_sw_interface, vnm,
		    &phy_sw_if_index))
	;
      else
	return clib_error_return (0, "unknown input '%U'",
				  format_unformat_error, input);
    }

  lcp_itf_pair_show (phy_sw_if_index);

  return 0;
}

VLIB_CLI_COMMAND (lcp_itf_pair_show_cmd_node, static) = {
  .path = "show lcp",
  .function = lcp_itf_pair_show_cmd,
  .short_help = "show lcp [phy <interface>]",
  .is_mp_safe = 1,
};

static clib_error_t *
lcp_ethertype_enable_cmd (vlib_main_t *vm, unformat_input_t *input,
			  vlib_cli_command_t *cmd)
{
  ethernet_type_t ethertype;
  int rv;

  if (!unformat (input, "%U", unformat_ethernet_type_host_byte_order,
		 &ethertype))
    return clib_error_return (0, "Invalid ethertype");

  rv = lcp_ethertype_enable (ethertype);
  if (rv)
    return clib_error_return (0, "Failed to enable ethertype (%d)", rv);

  return 0;
}

VLIB_CLI_COMMAND (lcp_ethertype_enable_command, static) = {
  .path = "lcp ethertype enable",
  .short_help =
    "lcp ethertype enable (<hex_ethertype_num>|<uc_ethertype_name>)",
  .function = lcp_ethertype_enable_cmd,
};

static clib_error_t *
lcp_ethertype_show_cmd (vlib_main_t *vm, unformat_input_t *input,
			vlib_cli_command_t *cmd)
{
  ethernet_type_t *ethertypes = vec_new (ethernet_type_t, 0);
  ethernet_type_t *etype;
  int rv;

  rv = lcp_ethertype_get_enabled (&ethertypes);
  if (rv)
    {
      vec_free (ethertypes);
      return clib_error_return (0, "Failed to get enabled ethertypes (%d)",
				rv);
    }

  vec_foreach (etype, ethertypes)
    {
      vlib_cli_output (vm, "0x%04x", *etype);
    }

  vec_free (ethertypes);
  return 0;
}

VLIB_CLI_COMMAND (lcp_ethertype_show_command, static) = {
  .path = "show lcp ethertype",
  .short_help = "show lcp ethertype",
  .function = lcp_ethertype_show_cmd,
};

static clib_error_t *
lcp_osi_proto_enable_cmd (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  u32 proto = ~0;
  int rv;

  if (unformat (input, "0x%x", &proto) || unformat (input, "%u", &proto))
    ;
  else
    return clib_error_return (0, "No OSI proto entered");

  if (proto > 255)
    return clib_error_return (0, "Invalid OSI proto");

  rv = lcp_osi_proto_enable ((u8) proto);
  if (rv)
    return clib_error_return (0, "Failed to enable OSI proto (%d)", rv);

  return 0;
}

VLIB_CLI_COMMAND (lcp_osi_proto_enable_command, static) = {
  .path = "lcp osi-proto enable",
  .short_help = "lcp osi-proto enable <proto_num>",
  .function = lcp_osi_proto_enable_cmd,
};

static clib_error_t *
lcp_osi_proto_show_cmd (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  u8 *proto, *protos = NULL;
  clib_error_t *error = NULL;
  int rv;

  rv = lcp_osi_proto_get_enabled (&protos);
  if (rv)
    error = clib_error_return (0, "Failed to get enabled ethertypes (%d)", rv);
  else
    vec_foreach (proto, protos)
      vlib_cli_output (vm, "0x%02x", *proto);

  vec_free (protos);

  return error;
}

VLIB_CLI_COMMAND (lcp_osi_proto_show_command, static) = {
  .path = "show lcp osi-proto",
  .short_help = "show lcp osi-proto",
  .function = lcp_osi_proto_show_cmd,
};

clib_error_t *
lcp_cli_init (vlib_main_t *vm)
{
  return 0;
}

VLIB_INIT_FUNCTION (lcp_cli_init);
