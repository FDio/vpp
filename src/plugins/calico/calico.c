/*
 * Copyright (c) 2020 Cisco and/or its affiliates.
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
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>
#include <calico/calico.h>

#include <cnat/cnat_src_policy.h>

calico_main_t calico_main;

int
calico_enable_disable_snat (u32 sw_if_index, u8 is_ip6, u8 enable)
{
  calico_main_t *cm = &calico_main;

  clib_bitmap_t **map = &cm->ip4_snat_interfaces;
  if (is_ip6)
    map = &cm->ip6_snat_interfaces;

  *map = clib_bitmap_set (*map, sw_if_index, enable);
  return 0;
}


int
calico_register_pod_interface (u32 sw_if_index, u8 is_add)
{
  calico_main_t *cm = &calico_main;
  cm->pod_interfaces = clib_bitmap_set (cm->pod_interfaces, sw_if_index, is_add);
  return 0;
}

int 
calico_add_del_pod_cidr (ip_prefix_t *pfx, u8 is_add)
{
  calico_main_t *cm = &calico_main;
  u32 i = 0;
 
  if (is_add)
    vec_add1(cm->pod_cidrs, *pfx);
  else
    {
      vec_foreach_index (i, cm->pod_cidrs)
        {
          if (!ip_prefix_cmp (pfx, &cm->pod_cidrs[i]))
            {
              if (i != vec_len(cm->pod_cidrs) - 1)
                cm->pod_cidrs[i] = cm->pod_cidrs[vec_len(cm->pod_cidrs) - 1];
              vec_pop (cm->pod_cidrs);
              return 0;
            }
        }
    }
  return 0;
}


cnat_source_policy_errors_t
calico_snat_policy (vlib_main_t * vm,
		    vlib_buffer_t * b,
		    cnat_session_t * session,
		    cnat_node_ctx_t * ctx,
                    u8 * do_snat)
{
  calico_main_t *cm = &calico_main;
  ip46_address_t *src_addr = &session->key.cs_ip[VLIB_RX];
  ip46_address_t *dst_addr = &session->key.cs_ip[VLIB_TX];
  u32 in_if = vnet_buffer (b)->sw_if_index[VLIB_RX];
  u32 out_if = vnet_buffer (b)->sw_if_index[VLIB_TX];
  int rv = 0;
 
  /* source nat for outgoing connections */
  if (calico_interface_snat_enabled (in_if, AF_IP6 == ctx->af))
    {
      rv = calico_main.cnat_search_snat_prefix (dst_addr, ctx->af);
      if (rv)
        {
          /* Destination is not in the prefixes that don't require snat */
          *do_snat = 1;
          return 0;
        }
    }

  /* source nat for translations that come from the outside:
     src not not a pod interface, dst not a pod interface */
  if (!clib_bitmap_get (cm->pod_interfaces, in_if) &&
        !clib_bitmap_get (cm->pod_interfaces, out_if))
    {
      *do_snat = 1;
      return 0;
    }

  /* handle the case where a container is connecting to itself via a service */
  if (ip46_address_is_equal (src_addr, dst_addr))
    *do_snat = 1;
  
  return 0;
}

static clib_error_t *
calico_snat (vlib_main_t * vm,
	     unformat_input_t * input, vlib_cli_command_t * cmd)
{
  int rv;
  int is_ip6 = 0;
  int is_enable = 1;
  u32 sw_if_index = ~0;
  vnet_main_t *vnm = vnet_get_main ();

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "disable"))
	is_enable = 0;
      else if (unformat (input, "ip6"))
	is_ip6 = 1;
      else
	if (unformat
	    (input, "%U", unformat_vnet_sw_interface, vnm, &sw_if_index))
	;
      else
	return clib_error_return (0, "unknown input '%U'",
				  format_unformat_error, input);
    }

  if (sw_if_index == ~0)
    return clib_error_return (0, "Interface not specified");

  vlib_cli_output (vm, "Calico snat: sw_if %d enable %d ip6 %d", sw_if_index,
		   is_enable, is_ip6);

  rv = calico_enable_disable_snat (sw_if_index, is_ip6, is_enable);

  if (rv)
    return clib_error_return (0, "Error %d", rv);

  return NULL;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (calico_snat_command, static) =
{
  .path = "calico snat",
  .short_help = "calico snat [disable] [ip6] sw_if_index",
  .function = calico_snat,
};
/* *INDENT-ON* */

static clib_error_t *
calico_show_snat (vlib_main_t * vm,
		  unformat_input_t * input, vlib_cli_command_t * cmd)
{
  u8 *s;
  int i;
/* *INDENT-OFF* */
  s = format(0, "Interfaces with IPv4 SNAT enabled:");
  clib_bitmap_foreach (i, calico_main.ip4_snat_interfaces, {
    s = format (s, " %d", i);
  });
  vlib_cli_output (vm, (char *) s);

  s = format(0, "Interfaces with IPv6 SNAT enabled:");
  clib_bitmap_foreach (i, calico_main.ip6_snat_interfaces, {
    s = format (s, " %d", i);
  });
  vlib_cli_output (vm, (char *) s);
/* *INDENT-ON* */
  return (NULL);
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (calico_show_snat_command, static) =
{
  .path = "show calico snat",
  .short_help = "",
  .function = calico_show_snat,
};
/* *INDENT-ON* */


static clib_error_t *
calico_pods (vlib_main_t * vm,
	     unformat_input_t * input, vlib_cli_command_t * cmd)
{
  int rv;
  int is_add = 1;
  u32 sw_if_index = ~0;
  vnet_main_t *vnm = vnet_get_main ();

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "remove"))
	is_add = 0;
      else
	if (unformat
	    (input, "%U", unformat_vnet_sw_interface, vnm, &sw_if_index))
	;
      else
	return clib_error_return (0, "unknown input '%U'",
				  format_unformat_error, input);
    }

  if (sw_if_index == ~0)
    return clib_error_return (0, "Interface not specified");

  vlib_cli_output (vm, "Calico pods: sw_if %d enable %d", sw_if_index, is_add);

  rv = calico_register_pod_interface (sw_if_index, is_add);

  if (rv)
    return clib_error_return (0, "Error %d", rv);

  return NULL;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (calico_pods_command, static) =
{
  .path = "calico pods",
  .short_help = "calico pods [remove] sw_if_index",
  .function = calico_pods,
};
/* *INDENT-ON* */

static clib_error_t *
calico_show_pods (vlib_main_t * vm,
		  unformat_input_t * input, vlib_cli_command_t * cmd)
{
  u8 *s;
  int i;
/* *INDENT-OFF* */
  s = format(0, "Pod interfaces:");
  clib_bitmap_foreach (i, calico_main.pod_interfaces, {
    s = format (s, " %d", i);
  });
  vlib_cli_output (vm, (char *) s);
/* *INDENT-ON* */
  return (NULL);
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (calico_show_pods_command, static) =
{
  .path = "show calico pod interfaces",
  .short_help = "",
  .function = calico_show_pods,
};
/* *INDENT-ON* */


static clib_error_t *
calico_show_pod_cidrs (vlib_main_t * vm,
		  unformat_input_t * input, vlib_cli_command_t * cmd)
{
  u8 *s;
  ip_prefix_t *pfx;
  s = format(0, "Pod CIDRs:");
  vec_foreach (pfx, calico_main.pod_cidrs)
    {
      s = format (s, " %U", format_ip_prefix, pfx);
    }
  vlib_cli_output (vm, (char *) s);
  return (NULL);
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (calico_show_pod_cidrs_command, static) =
{
  .path = "show calico pod cidrs",
  .short_help = "",
  .function = calico_show_pod_cidrs,
};
/* *INDENT-ON* */

static clib_error_t *
calico_init (vlib_main_t * vm)
{
  calico_main_t *cm = &calico_main;
  clib_bitmap_validate (cm->ip4_snat_interfaces, 4096);
  clib_bitmap_validate (cm->ip6_snat_interfaces, 4096);
  clib_bitmap_validate (cm->pod_interfaces, 4096);

  /* Look up the required functions from the cnat plugin */
  cm->cnat_search_snat_prefix = vlib_get_plugin_symbol ("cnat_plugin.so",
							"cnat_search_snat_prefix");
  cm->register_snat_policy = vlib_get_plugin_symbol ("cnat_plugin.so",
                                                     "cnat_register_snat_policy");

  if (cm->cnat_search_snat_prefix == NULL
      || cm->register_snat_policy == NULL)
    return clib_error_return (0, "Symbols not found in CNAT plugin");
  /* Most likely, the cnat plugin isn't loaded. */
  cm->register_snat_policy (calico_snat_policy);

  return (NULL);
}

VLIB_INIT_FUNCTION (calico_init);

/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () = {
    .version = VPP_BUILD_VER,
    .description = "Calico specific NAT extensions",
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
