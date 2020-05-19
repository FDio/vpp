/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
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

#include <stddef.h>

#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include <calico/calico_translation.h>
#include <calico/calico_session.h>
#include <calico/calico_client.h>
#include <calico/calico_snat.h>

#include <vnet/ip/ip_types_api.h>

#include <vpp/app/version.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>

uword
unformat_calico_ep (unformat_input_t * input, va_list * args)
{
  calico_endpoint_t *a = va_arg (*args, calico_endpoint_t *);
  int port = 0;

  clib_memset (a, 0, sizeof (*a));
  if (unformat (input, "%U %d", unformat_ip_address, &a->ce_ip, &port))
    ;
  else if (unformat_user (input, unformat_ip_address, &a->ce_ip))
    ;
  else if (unformat (input, "%d", &port))
    ;
  else
    return 0;
  a->ce_port = (u16) port;
  return 1;
}

uword
unformat_calico_ep_tuple (unformat_input_t * input, va_list * args)
{
  calico_endpoint_tuple_t *a = va_arg (*args, calico_endpoint_tuple_t *);
  if (unformat (input, "%U->%U", unformat_calico_ep, &a->src_ep,
		unformat_calico_ep, &a->dst_ep))
    ;
  else if (unformat (input, "->%U", unformat_calico_ep, &a->dst_ep))
    ;
  else if (unformat (input, "%U->", unformat_calico_ep, &a->src_ep))
    ;
  else
    return 0;
  return 1;
}

static clib_error_t *
calico_translation_cli_add_del (vlib_main_t * vm,
				unformat_input_t * input,
				vlib_cli_command_t * cmd)
{
  u32 del_index = INDEX_INVALID;
  ip_protocol_t proto = IP_PROTOCOL_TCP;
  calico_endpoint_t vip;
  u8 flags = CALICO_FLAG_EXCLUSIVE;
  calico_endpoint_tuple_t tmp, *paths = NULL, *path;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "add"))
	del_index = INDEX_INVALID;
      else if (unformat (input, "del %d", &del_index))
	;
      else if (unformat (input, "proto %U", unformat_ip_protocol, &proto))
	;
      else if (unformat (input, "vip %U", unformat_calico_ep, &vip))
	flags = CALICO_FLAG_EXCLUSIVE;
      else if (unformat (input, "real %U", unformat_calico_ep, &vip))
	flags = 0;
      else if (unformat (input, "to %U", unformat_calico_ep_tuple, &tmp))
	{
	  pool_get (paths, path);
	  clib_memcpy (path, &tmp, sizeof (calico_endpoint_tuple_t));
	}
      else
	return (clib_error_return (0, "unknown input '%U'",
				   format_unformat_error, input));
    }

  if (INDEX_INVALID == del_index)
    calico_translation_update (&vip, proto, paths, flags);
  else
    calico_translation_delete (del_index);

  pool_free (paths);
  return (NULL);
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (calico_translation_cli_add_del_command, static) =
{
  .path = "calico translation",
  .short_help = "calico translation [add|del] proto [TCP|UDP] [vip|real] [ip] [port] [to [ip] [port]->[ip] [port]]",
  .function = calico_translation_cli_add_del,
};
/* *INDENT-ON* */

static clib_error_t *
calico_set_snat (vlib_main_t * vm,
		 unformat_input_t * input, vlib_cli_command_t * cmd)
{
  ip_address_t addr;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%U", unformat_ip_address, &addr))
	{
	  if (ip_addr_version (&addr) == AF_IP4)
	    clib_memcpy (&calico_main.snat_ip4, &ip_addr_v4 (&addr),
			 sizeof (ip4_address_t));
	  else
	    clib_memcpy (&calico_main.snat_ip6, &ip_addr_v6 (&addr),
			 sizeof (ip6_address_t));
	}
      else
	return (clib_error_return (0, "unknown input '%U'",
				   format_unformat_error, input));
    }

  return (NULL);
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (calico_set_snat_command, static) =
{
  .path = "calico snat with",
  .short_help = "calico snat with [ip]",
  .function = calico_set_snat,
};
/* *INDENT-ON* */

static clib_error_t *
calico_snat_exclude (vlib_main_t * vm,
		     unformat_input_t * input, vlib_cli_command_t * cmd)
{
  ip_prefix_t pfx;
  u8 is_add = 1;
  int rv;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%U", unformat_ip_prefix, &pfx))
	;
      else if (unformat (input, "del"))
	is_add = 0;
      else
	return (clib_error_return (0, "unknown input '%U'",
				   format_unformat_error, input));
    }

  if (is_add)
    rv = calico_add_snat_prefix (&pfx);
  else
    rv = calico_del_snat_prefix (&pfx);

  if (rv)
    {
      return (clib_error_return (0, "error %d", rv, input));
    }

  return (NULL);
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (calico_snat_exclude_command, static) =
{
  .path = "calico snat exclude",
  .short_help = "calico snat exclude [ip]",
  .function = calico_snat_exclude,
};
/* *INDENT-ON* */

static clib_error_t *
calico_show_snat (vlib_main_t * vm,
		  unformat_input_t * input, vlib_cli_command_t * cmd)
{
  calico_snat_pfx_table_t *table = &calico_main.snat_pfx_table;
  vlib_cli_output (vm, "Source NAT\nip4: %U\nip6: %U\n",
		   format_ip4_address, &calico_main.snat_ip4,
		   format_ip6_address, &calico_main.snat_ip6);
  vlib_cli_output (vm, "Prefixes:\n%U\n",
		   format_bihash_24_8, &table->ip_hash, 1);
  return (NULL);
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (calico_show_snat_command, static) =
{
  .path = "show calico snat",
  .short_help = "show calico snat",
  .function = calico_show_snat,
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
