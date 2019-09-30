/* Hey Emacs use -*- mode: C -*- */
/*
 * Copyright 2020 Rubicon Communications, LLC.
 *
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
lcp_itf_pair_create_command_fn (vlib_main_t * vm,
				unformat_input_t * input,
				vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  vnet_main_t *vnm = vnet_get_main ();
  u32 sw_if_index;
  u8 *host_if_name;
  lip_host_type_t host_if_type;
  u8 *ns;
  int r;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  sw_if_index = ~0;
  host_if_name = ns = 0;
  host_if_type = LCP_ITF_HOST_TAP;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%d", &sw_if_index))
	;
      else if (unformat (line_input, "%U",
			 unformat_vnet_sw_interface, vnm, &sw_if_index))
	;
      else if (unformat (line_input, "host-if %s", &host_if_name))
	;
      else if (unformat (line_input, "netns %s", &ns))
	;
      else if (unformat (line_input, "tun"))
	host_if_type = LCP_ITF_HOST_TUN;
      else
	{
	  unformat_free (line_input);
	  vec_free (host_if_name);
	  vec_free (ns);
	  return clib_error_return (0, "unknown input `%U'",
				    format_unformat_error, input);
	}
    }

  unformat_free (line_input);

  if (sw_if_index == ~0)
    {
      vec_free (host_if_name);
      vec_free (ns);
      return clib_error_return (0, "interface name or sw_if_index required");
    }

  if (clib_strnlen ((char *) ns, LCP_NS_LEN) >= LCP_NS_LEN)
    {
      vec_free (host_if_name);
      vec_free (ns);
      return clib_error_return (0,
				"Namespace name should be fewer than %d characters",
				LCP_NS_LEN);
    }

  r = lcp_itf_pair_create (sw_if_index, host_if_name, host_if_type, ns);

  vec_free (host_if_name);
  vec_free (ns);

  if (r)
    return clib_error_return (0, "linux-cp pair creation failed (%d)", r);

  return 0;
}


/* *INDENT-OFF* */
VLIB_CLI_COMMAND (lcp_itf_pair_create_command, static) = {
  .path = "lcp create",
  .short_help =
    "lcp create <sw_if_index>|<if-name> host-if <host-if-name> netns <namespace> [tun]",
  .function = lcp_itf_pair_create_command_fn,
};
/* *INDENT-ON* */


static clib_error_t *
lcp_default_netns_command_fn (vlib_main_t * vm,
			      unformat_input_t * input,
			      vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u8 *ns;
  int r;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  ns = 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "netns %s", &ns))
	;
      else if (unformat (line_input, "clear netns"))
	;
    }

  unformat_free (line_input);

  vlib_cli_output (vm, "lcp set default netns '%s'\n", (char *) ns);

  r = lcp_set_default_ns (ns);

  if (r)
    return clib_error_return (0, "linux-cp set default netns failed (%d)", r);

  return 0;
}


/* *INDENT-OFF* */
VLIB_CLI_COMMAND (lcp_default_netns_command, static) = {
  .path = "lcp default",
  .short_help = "lcp default netns [<namespace>]",
  .function = lcp_default_netns_command_fn,
};
/* *INDENT-ON* */


static clib_error_t *
lcp_itf_pair_delete_command_fn (vlib_main_t * vm,
				unformat_input_t * input,
				vlib_cli_command_t * cmd)
{
  vnet_main_t *vnm = vnet_get_main ();
  unformat_input_t _line_input, *line_input = &_line_input;
  u32 sw_if_index;
  int r;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  sw_if_index = ~0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%d", &sw_if_index))
	;
      else if (unformat (line_input, "%U",
			 unformat_vnet_sw_interface, vnm, &sw_if_index))
	;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }

  unformat_free (line_input);

  if (sw_if_index == ~0)
    return clib_error_return (0, "interface name or sw_if_index required");

  r = lcp_itf_pair_delete (sw_if_index);

  if (r)
    return clib_error_return (0, "linux-cp pair deletion failed (%d)", r);
  return 0;
}


/* *INDENT-OFF* */
VLIB_CLI_COMMAND (lcp_itf_pair_delete_command, static) = {
  .path = "lcp delete",
  .short_help = "lcp delete <sw_if_index>|<if-name>",
  .function = lcp_itf_pair_delete_command_fn,
};
/* *INDENT-ON* */


static clib_error_t *
lcp_itf_pair_show_cmd (vlib_main_t * vm,
		       unformat_input_t * input, vlib_cli_command_t * cmd)
{
  vnet_main_t *vnm = vnet_get_main ();
  u32 phy_sw_if_index;

  phy_sw_if_index = ~0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "phy %U",
		    unformat_vnet_sw_interface, vnm, &phy_sw_if_index))
	;
      else
	return clib_error_return (0, "unknown input '%U'",
				  format_unformat_error, input);
    }

  lcp_itf_pair_show (phy_sw_if_index);

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (lcp_itf_pair_show_cmd_node, static) = {
  .path = "show lcp",
  .function = lcp_itf_pair_show_cmd,
  .short_help = "show lcp [phy <interface>]",
  .is_mp_safe = 1,
};
/* *INDENT-ON* */




clib_error_t *
lcp_cli_init (vlib_main_t * vm)
{
  return 0;
}

VLIB_INIT_FUNCTION (lcp_cli_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
