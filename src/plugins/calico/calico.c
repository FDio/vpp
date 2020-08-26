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

#include <cnat/cnat_session.h>
#include <cnat/cnat_snat.h>

calico_main_t calico_main;

int
calico_enable_disable_snat (u32 sw_if_index, u8 is_ip6, u8 enable)
{
  calico_main_t *cm = &calico_main;
  vnet_feature_registration_t *reg;
  char *arc_name, *feature_name;
  clib_error_t *err;
  int rv;

  clib_bitmap_t **map = &cm->ip4_snat_interfaces;
  if (is_ip6)
    map = &cm->ip6_snat_interfaces;

  if (is_ip6)
    {
      arc_name = "ip6-unicast";
      feature_name = "ip6-cnat-snat";
    }
  else
    {
      arc_name = "ip4-unicast";
      feature_name = "ip4-cnat-snat";
    }

  reg = vnet_get_feature_reg (arc_name, feature_name);
  if (!reg)
    return VNET_API_ERROR_FEATURE_DISABLED;
  if (reg->enable_disable_cb)
    {
      err = reg->enable_disable_cb (sw_if_index, enable);
      if (err)
	return VNET_API_ERROR_UNSPECIFIED;
    }
  rv = vnet_feature_enable_disable (arc_name, feature_name, sw_if_index,
				    enable, 0, 0);
  if (rv)
    return rv;

  *map = clib_bitmap_set (*map, sw_if_index, enable);
  return 0;
}

cnat_source_policy_errors_t
calico_vip_source_policy (cnat_session_t * session,
			  vlib_buffer_t * b, ip4_header_t * ip4,
			  ip6_header_t * ip6, udp_header_t * udp0,
			  u32 rsession_flags, const cnat_translation_t * ct,
			  cnat_node_ctx_t * ctx, cnat_main_t * cm,
			  vlib_main_t * vm)
{
  u32 input_if = UINT32_MAX;
  u16 sport = UINT16_MAX;
  int rv = 0;

  input_if = vnet_buffer (b)->sw_if_index[VLIB_RX];
  if (!calico_interface_snat_enabled (input_if, AF_IP6 == ctx->af))
    return 0;

  rv =
    calico_main.cnat_search_snat_prefix (&session->value.cs_ip[VLIB_TX],
					 ctx->af);
  if (!rv)
    /* Destination is in the prefixes that don't require snat */
    return 0;

  /* Port allocation, first try to use the original port, allocate one
     if it is already used */
  sport = udp0->src_port;
  rv = calico_main.cnat_allocate_port (cm, &sport);
  if (rv)
    return CNAT_SOURCE_ERROR_EXHAUSTED_PORTS;

  session->value.cs_port[VLIB_RX] = sport;
  /* Session config for source address update */
  if (AF_IP6 == ctx->af)
    ip46_address_set_ip6 (&session->value.cs_ip[VLIB_RX], &cm->snat_ip6);
  else
    ip46_address_set_ip4 (&session->value.cs_ip[VLIB_RX], &cm->snat_ip4);
  return 0;
}


static clib_error_t *
calico_snat (vlib_main_t * vm,
	     unformat_input_t * input, vlib_cli_command_t * cmd)
{
  int rv;
  u8 is_ip6 = 0;
  u8 is_enable = 1;
  u32 sw_if_index = ~0;
  vnet_main_t *vnm = vnet_get_main ();

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "disable"))
	is_enable = 0;
      else if (unformat (input, "ipv6"))
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

  vlib_cli_output (vm, "Calico snat: if %d enable %d ip6 %d", sw_if_index,
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
  char *s;
  u32 i;
/* *INDENT-OFF* */
  s = "Interfaces with IPv4 SNAT enabled:";
  clib_bitmap_foreach (i, calico_main.ip4_snat_interfaces, {
    s = (char *) format ((u8 *) s, " %u", i);
  });
  vlib_cli_output (vm, s);

  s = "Interfaces with IPv6 SNAT enabled:";
  clib_bitmap_foreach (i, calico_main.ip6_snat_interfaces, {
    s = (char *) format ((u8 *) s, " %u", i);
  });
  vlib_cli_output (vm, s);
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
calico_init (vlib_main_t * vm)
{
  cnat_main_t *(*fp) (void);

  clib_bitmap_validate (calico_main.ip4_snat_interfaces, 4096);
  clib_bitmap_validate (calico_main.ip6_snat_interfaces, 4096);

  /* Look up the required functions from the cnat plugin */
  calico_main.cnat_search_snat_prefix =
    vlib_get_plugin_symbol ("cnat_plugin.so", "cnat_search_snat_prefix");
  calico_main.cnat_allocate_port =
    vlib_get_plugin_symbol ("cnat_plugin.so", "cnat_allocate_port");
  if (calico_main.cnat_search_snat_prefix == NULL
      || calico_main.cnat_allocate_port == NULL)
    return clib_error_return (0, "Symbols not found in CNAT plugin");

  /* Look up the cnat plugin main */
  fp = vlib_get_plugin_symbol ("cnat_plugin.so", "cnat_get_main");

  /* Most likely, the http_static plugin isn't loaded. Done. */
  if (fp == NULL)
    return clib_error_return (0, "CNAT plugin not found");

  // Plug-in. Not racy as the cnat plugin sets this in an early_init_fn
  calico_main.cnat_main = fp ();
  calico_main.cnat_main->vip_source_policy = calico_vip_source_policy;

  return (NULL);
}

VLIB_INIT_FUNCTION (calico_init);

/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () = {
    .version = VPP_BUILD_VER,
    .description = "Calico specific NAT",
    .default_disabled = 1,
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
