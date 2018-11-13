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
#include <sys/ioctl.h>
#include <inttypes.h>

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vnet/ip/ip.h>
#include <vnet/fib/fib_entry.h>
#include <vnet/fib/fib_table.h>
#include <vnet/mfib/mfib_table.h>

#include <igmp/igmp.h>

static clib_error_t *
igmp_clear_interface_command_fn (vlib_main_t * vm, unformat_input_t * input,
				 vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = NULL;
  vnet_main_t *vnm = vnet_get_main ();
  u32 sw_if_index;

  igmp_config_t *config;

  if (!unformat_user (input, unformat_line_input, line_input))
    {
      error =
	clib_error_return (0, "'help clear igmp' or 'clear igmp ?' for help");
      return error;
    }

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat
	  (line_input, "int %U", unformat_vnet_sw_interface, vnm,
	   &sw_if_index));
      else
	{
	  error =
	    clib_error_return (0, "unknown input '%U'", format_unformat_error,
			       line_input);
	  goto done;
	}
    }

  config = igmp_config_lookup (sw_if_index);
  if (config)
    igmp_clear_config (config);

done:
  unformat_free (line_input);
  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (igmp_clear_interface_command, static) = {
  .path = "clear igmp",
  .short_help = "clear igmp int <interface>",
  .function = igmp_clear_interface_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
igmp_listen_command_fn (vlib_main_t * vm, unformat_input_t * input,
			vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = NULL;
  u8 enable = 1;
  ip46_address_t saddr, *saddrs = NULL, gaddr;
  vnet_main_t *vnm = vnet_get_main ();
  u32 sw_if_index;
  int rv;

  if (!unformat_user (input, unformat_line_input, line_input))
    {
      error =
	clib_error_return (0,
			   "'help igmp listen' or 'igmp listen ?' for help");
      return error;
    }

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "enable"))
	enable = 1;
      else if (unformat (line_input, "disable"))
	enable = 0;
      else
	if (unformat
	    (line_input, "int %U", unformat_vnet_sw_interface, vnm,
	     &sw_if_index));
      else
	if (unformat (line_input, "saddr %U", unformat_ip46_address, &saddr))
	vec_add1 (saddrs, saddr);
      else
	if (unformat (line_input, "gaddr %U", unformat_ip46_address, &gaddr));
      else
	{
	  error =
	    clib_error_return (0, "unknown input '%U'", format_unformat_error,
			       line_input);
	  goto done;
	}
    }

  if ((vnet_sw_interface_get_flags (vnm, sw_if_index)
       && VNET_SW_INTERFACE_FLAG_ADMIN_UP) == 0)
    {
      error = clib_error_return (0, "Interface is down");
      goto done;
    }

  rv = igmp_listen (vm, enable, sw_if_index, saddrs, &gaddr);

  if (rv == -1)
    {
      if (enable)
	error =
	  clib_error_return (0, "This igmp configuration already exists");
      else
	error =
	  clib_error_return (0, "This igmp configuration does not exist");
    }
  else if (rv == -2)
    error =
      clib_error_return (0,
			 "Failed to add configuration, interface is in router mode");

done:
  unformat_free (line_input);
  vec_free (saddrs);
  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (igmp_listen_command, static) = {
  .path = "igmp listen",
  .short_help = "igmp listen [<enable|disable>] "
                "int <interface> saddr <ip4-address> gaddr <ip4-address>",
  .function = igmp_listen_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
igmp_enable_cli (vlib_main_t * vm,
		 unformat_input_t * input, vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  igmp_mode_t mode = IGMP_MODE_ROUTER;
  vnet_main_t *vnm = vnet_get_main ();
  clib_error_t *error = NULL;
  u32 sw_if_index = ~0;
  u8 enable = 1;
  int rv;

  if (!unformat_user (input, unformat_line_input, line_input))
    return error;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "enable"))
	enable = 1;
      else if (unformat (line_input, "disable"))
	enable = 0;
      if (unformat (line_input, "host"))
	mode = IGMP_MODE_HOST;
      else if (unformat (line_input, "router"))
	mode = IGMP_MODE_ROUTER;
      else if (unformat (line_input, "%U",
			 unformat_vnet_sw_interface, vnm, &sw_if_index));
      else
	{
	  error =
	    clib_error_return (0, "unknown input '%U'", format_unformat_error,
			       line_input);
	  goto done;
	}
    }

  if (~0 == sw_if_index)
    {
      error = clib_error_return (0, "interface must be specified");
      goto done;
    }

  rv = igmp_enable_disable (sw_if_index, enable, mode);

  if (0 != rv)
    error = clib_error_return (0, "result: %d", rv);

done:
  unformat_free (line_input);
  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (igmp_enable_command, static) = {
  .path = "igmp",
  .short_help = "igmp <enable|disable> <host|router> <interface>",
  .function = igmp_enable_cli,
};
/* *INDENT-ON* */

static clib_error_t *
igmp_proxy_device_add_del_command_fn (vlib_main_t * vm,
				      unformat_input_t * input,
				      vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  vnet_main_t *vnm = vnet_get_main ();
  clib_error_t *error = NULL;
  u32 sw_if_index = ~0;
  u32 vrf_id = ~0;
  u8 add = 1;
  int rv;

  if (!unformat_user (input, unformat_line_input, line_input))
    return error;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "add"))
	add = 1;
      else if (unformat (line_input, "del"))
	add = 0;
      else if (unformat (line_input, "vrf-id %u", &vrf_id))
	;
      else if (unformat (line_input, "%U",
			 unformat_vnet_sw_interface, vnm, &sw_if_index));
      else
	{
	  error =
	    clib_error_return (0, "unknown input '%U'", format_unformat_error,
			       line_input);
	  goto done;
	}
    }

  if (~0 == sw_if_index)
    {
      error = clib_error_return (0, "interface must be specified");
      goto done;
    }

  if (~0 == vrf_id)
    {
      error = clib_error_return (0, "VRF must be specified");
      goto done;
    }

  rv = igmp_proxy_device_add_del (vrf_id, sw_if_index, add);

  if (0 != rv)
    error = clib_error_return (0, "result: %d", rv);

done:
  unformat_free (line_input);
  return error;
}
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (igmp_proxy_device_add_del_command, static) = {
  .path = "igmp proxy-dev",
  .short_help = "igmp proxy-dev <add|del> vrf-id <table-id> <interface>",
  .function = igmp_proxy_device_add_del_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
igmp_proxy_device_add_del_interface_command_fn (vlib_main_t * vm,
						unformat_input_t * input,
						vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  vnet_main_t *vnm = vnet_get_main ();
  clib_error_t *error = NULL;
  u32 sw_if_index = ~0;
  u32 vrf_id = ~0;
  u8 add = 1;
  int rv;

  if (!unformat_user (input, unformat_line_input, line_input))
    return error;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "add"))
	add = 1;
      else if (unformat (line_input, "del"))
	add = 0;
      else if (unformat (line_input, "vrf-id %u", &vrf_id))
	;
      else if (unformat (line_input, "%U",
			 unformat_vnet_sw_interface, vnm, &sw_if_index));
      else
	{
	  error =
	    clib_error_return (0, "unknown input '%U'", format_unformat_error,
			       line_input);
	  goto done;
	}
    }

  if (~0 == sw_if_index)
    {
      error = clib_error_return (0, "interface must be specified");
      goto done;
    }

  if (~0 == vrf_id)
    {
      error = clib_error_return (0, "VRF must be specified");
      goto done;
    }

  rv = igmp_proxy_device_add_del_interface (vrf_id, sw_if_index, add);

  if (0 != rv)
    error = clib_error_return (0, "result: %d", rv);

done:
  unformat_free (line_input);
  return error;
}
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (igmp_proxy_device_add_del_interface_command, static) = {
  .path = "igmp proxy-dev itf",
  .short_help = "igmp proxy-dev itf <add|del> vrf-id <table-id> <interface>",
  .function = igmp_proxy_device_add_del_interface_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
igmp_show_command_fn (vlib_main_t * vm, unformat_input_t * input,
		      vlib_cli_command_t * cmd)
{
  clib_error_t *error = NULL;
  igmp_main_t *im = &igmp_main;
  igmp_config_t *config;

  /* *INDENT-OFF* */
  pool_foreach (config, im->configs,
    ({
      vlib_cli_output (vm, "%U", format_igmp_config, config);
    }));
  /* *INDENT-ON* */

  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (igmp_show_command, static) = {
  .path = "show igmp config",
  .short_help = "show igmp config",
  .function = igmp_show_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
igmp_show_timers_command_fn (vlib_main_t * vm,
			     unformat_input_t * input,
			     vlib_cli_command_t * cmd)
{
#define _(n,f) vlib_cli_output (vm, "%s: %d", #f, igmp_timer_type_get(n));
  foreach_igmp_timer_type
#undef _
    return (NULL);
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (igmp_show_timers_command, static) = {
  .path = "show igmp timers",
  .short_help = "show igmp timers",
  .function = igmp_show_timers_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
test_igmp_command_fn (vlib_main_t * vm,
		      unformat_input_t * input, vlib_cli_command_t * cmd)
{
  clib_error_t *error = NULL;
  u32 value;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "query %d", &value))
	igmp_timer_type_set (IGMP_TIMER_QUERY, value);
      else if (unformat (input, "src %d", &value))
	igmp_timer_type_set (IGMP_TIMER_SRC, value);
      else if (unformat (input, "leave %d", &value))
	igmp_timer_type_set (IGMP_TIMER_LEAVE, value);
      else
	error = clib_error_return (0, "query or src timers only");
    }

  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (test_igmp_command, static) = {
  .path = "test igmp timers",
  .short_help = "Change the default values for IGMP timers - only sensible during unit tests",
  .function = test_igmp_command_fn,
};
/* *INDENT-ON* */


clib_error_t *
igmp_cli_init (vlib_main_t * vm)
{
  return 0;
}

VLIB_INIT_FUNCTION (igmp_cli_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
