/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2021 Cisco and/or its affiliates.
 */

#include <vlib/vlib.h>
#include <vlib/file.h>

#include <vppinfra/file.h>

#include <plugins/linux-cp/lcp_interface.h>

static u32 host_vif;
const static char *host_template = "tap%d";

/* Description the linux_nl plugin uses when it registers the notification
 * netlink socket with the vlib file poller.
 */
#define LCP_NETLINK_ROUTE_FILE "linux-cp netlink route socket"

static clib_error_t *
lcp_add_pair_command_fn (vlib_main_t *vm, unformat_input_t *input,
			 vlib_cli_command_t *cmd)
{
  u32 phy_sw_if_index, host_sw_if_index;
  u8 is_add, *host_name;
  vnet_main_t *vnm = vnet_get_main ();

  ++host_vif;
  host_name = format (NULL, host_template, host_vif);
  phy_sw_if_index = host_sw_if_index = ~0;
  is_add = 1;
  lcp_main.test_mode = 1;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "add"))
	is_add = 1;
      else if (unformat (input, "del"))
	is_add = 0;
      else if (unformat (input, "phy %U", unformat_vnet_sw_interface, vnm,
			 &phy_sw_if_index))
	;
      else if (unformat (input, "host %U", unformat_vnet_sw_interface, vnm,
			 &host_sw_if_index))
	;
      else
	return clib_error_return (0, "unknown input:%U", format_unformat_error,
				  input);
    }

  if (phy_sw_if_index == ~0)
    return clib_error_return (0, "ERROR; no phy:%U", format_unformat_error,
			      input);

  lip_host_type_t host_type =
    (vnet_sw_interface_is_p2p (vnm, phy_sw_if_index) ? LCP_ITF_HOST_TUN :
						       LCP_ITF_HOST_TAP);

  int rv;

  if (is_add)
    {
      if (host_sw_if_index == ~0)
	return clib_error_return (0, "ERROR no-host:%U", format_unformat_error,
				  input);

      rv = lcp_itf_pair_add (host_sw_if_index, phy_sw_if_index, host_name,
			     host_vif, host_type, NULL);
    }
  else
    rv = lcp_itf_pair_del (phy_sw_if_index);

  if (rv)
    return clib_error_return (0, "ERROR rv:%d", rv);

  return (NULL);
}

VLIB_CLI_COMMAND (test_time_range_command, static) = {
  .path = "test lcp",
  .short_help = "lcp [add|del] phy <SW_IF_INDEX> host <SW_IF_INDEX>",
  .function = lcp_add_pair_command_fn,
};

static clib_file_t *
lcp_nl_route_file_get (void)
{
  clib_file_main_t *fm = &file_main;
  u32 description_len = sizeof (LCP_NETLINK_ROUTE_FILE) - 1;
  clib_file_t **fp;

  pool_foreach (fp, fm->file_pool)
    {
      clib_file_t *f = fp[0];

      if (!f || !f->description || !f->error_function)
	continue;

      if (strncmp ((char *) f->description, LCP_NETLINK_ROUTE_FILE, description_len) == 0)
	return f;
    }

  return 0;
}

static clib_error_t *
lcp_nl_error_cmd (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  clib_file_t *file, *target;
  clib_file_t file_copy;
  clib_error_t *error;
  u8 use_invalid_fd = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "invalid-fd"))
	use_invalid_fd = 1;
      else
	return clib_error_return (0, "unknown input:%U", format_unformat_error, input);
    }

  file = lcp_nl_route_file_get ();
  if (!file)
    return clib_error_return (0, "no file \"%s\" is registered", LCP_NETLINK_ROUTE_FILE);

  target = file;
  if (use_invalid_fd)
    {
      /* Only the copy gets an unusable descriptor, the registered file and
       * its descriptor are left untouched. */
      file_copy = *file;
      file_copy.file_descriptor = (u32) ~0;
      target = &file_copy;
    }

  vlib_cli_output (vm, "netlink-error: target fd %d%s", (int) target->file_descriptor,
		   use_invalid_fd ? " (copy with invalid-fd)" : "");

  /* Mirror the vlib file poller: count the error event, then invoke the
   * registered callback. */
  target->error_events++;

  error = target->error_function (target);
  if (error)
    {
      vlib_cli_output (vm, "netlink-error: callback error: %v", error->what);
      clib_error_free (error);
    }
  else
    vlib_cli_output (vm, "netlink-error: callback returned no error");

  return 0;
}

VLIB_CLI_COMMAND (test_lcp_netlink_error_command, static) = {
  .path = "test lcp netlink-error",
  .short_help = "test lcp netlink-error [invalid-fd]",
  .function = lcp_nl_error_cmd,
};

#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>
VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "Linux Control Plane - Unit Test",
  .default_disabled = 1,
};
