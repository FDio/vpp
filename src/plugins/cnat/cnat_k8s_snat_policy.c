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
#include <cnat/cnat_snat.h>
#include <cnat/cnat_k8s_snat_policy.h>
#include <cnat/cnat_src_policy.h>

cnat_k8s_main_t cnat_k8s_main;

int
cnat_k8s_enable_disable_snat (u32 sw_if_index, u8 is_ip6, u8 enable)
{
  cnat_k8s_main_t *ckm = &cnat_k8s_main;

  clib_bitmap_t **map = &ckm->ip4_snat_interfaces;
  if (is_ip6)
    map = &ckm->ip6_snat_interfaces;

  *map = clib_bitmap_set (*map, sw_if_index, enable);
  return 0;
}

int
cnat_k8s_register_pod_interface (u32 sw_if_index, u8 is_add)
{
  cnat_k8s_main_t *ckm = &cnat_k8s_main;
  ckm->pod_interfaces =
    clib_bitmap_set (ckm->pod_interfaces, sw_if_index, is_add);
  return 0;
}

int
cnat_k8s_add_del_pod_cidr (ip_prefix_t *pfx, u8 is_add)
{
  cnat_k8s_main_t *ckm = &cnat_k8s_main;
  u32 i = 0;

  if (is_add)
    vec_add1 (ckm->pod_cidrs, *pfx);
  else
    {
      vec_foreach_index (i, ckm->pod_cidrs)
	{
	  if (!ip_prefix_cmp (pfx, &ckm->pod_cidrs[i]))
	    {
	      if (i != vec_len (ckm->pod_cidrs) - 1)
		ckm->pod_cidrs[i] =
		  ckm->pod_cidrs[vec_len (ckm->pod_cidrs) - 1];
	      vec_pop (ckm->pod_cidrs);
	      return 0;
	    }
	}
    }
  return 0;
}

void
cnat_k8s_snat_policy (vlib_main_t *vm, vlib_buffer_t *b,
		      cnat_session_t *session, cnat_node_ctx_t *ctx,
		      u8 *do_snat)
{
  cnat_k8s_main_t *ckm = &cnat_k8s_main;
  ip46_address_t *src_addr = &session->key.cs_ip[VLIB_RX];
  ip46_address_t *dst_addr = &session->key.cs_ip[VLIB_TX];
  u32 in_if = vnet_buffer (b)->sw_if_index[VLIB_RX];
  u32 out_if = vnet_buffer (b)->sw_if_index[VLIB_TX];
  int rv = 0;

  /* source nat for outgoing connections */
  if (cnat_k8s_interface_snat_enabled (in_if, AF_IP6 == ctx->af))
    {
      rv = cnat_search_snat_prefix (dst_addr, ctx->af);
      if (rv)
	{
	  /* Destination is not in the prefixes that don't require snat */
	  *do_snat = 1;
	  return;
	}
    }

  /* source nat for translations that come from the outside:
     src not not a pod interface, dst not a pod interface */
  if (!clib_bitmap_get (ckm->pod_interfaces, in_if) &&
      !clib_bitmap_get (ckm->pod_interfaces, out_if))
    {
      *do_snat = 1;
      return;
    }

  /* handle the case where a container is connecting to itself via a service */
  if (ip46_address_is_equal (src_addr, dst_addr))
    *do_snat = 1;

  return;
}

static clib_error_t *
cnat_k8s_snat (vlib_main_t *vm, unformat_input_t *input,
	       vlib_cli_command_t *cmd)
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
      else if (unformat (input, "%U", unformat_vnet_sw_interface, vnm,
			 &sw_if_index))
	;
      else
	return clib_error_return (0, "unknown input '%U'",
				  format_unformat_error, input);
    }

  if (sw_if_index == ~0)
    return clib_error_return (0, "Interface not specified");

  vlib_cli_output (vm, "cnat k8s snat: sw_if %d enable %d ip6 %d", sw_if_index,
		   is_enable, is_ip6);

  rv = cnat_k8s_enable_disable_snat (sw_if_index, is_ip6, is_enable);

  if (rv)
    return clib_error_return (0, "Error %d", rv);

  return NULL;
}

VLIB_CLI_COMMAND (cnat_k8s_snat_command, static) = {
  .path = "cnat k8s snat",
  .short_help = "cnat k8s snat [disable] [ip6] sw_if_index",
  .function = cnat_k8s_snat,
};

static clib_error_t *
cnat_k8s_show_snat (vlib_main_t *vm, unformat_input_t *input,
		    vlib_cli_command_t *cmd)
{
  u8 *s;
  int i;
  s = format (0, "Interfaces with IPv4 SNAT enabled:");
  clib_bitmap_foreach (i, cnat_k8s_main.ip4_snat_interfaces)
    s = format (s, " %d", i);
  vlib_cli_output (vm, (char *) s);

  s = format (0, "Interfaces with IPv6 SNAT enabled:");
  clib_bitmap_foreach (i, cnat_k8s_main.ip6_snat_interfaces)
    s = format (s, " %d", i);
  vlib_cli_output (vm, (char *) s);
  return (NULL);
}

VLIB_CLI_COMMAND (cnat_k8s_show_snat_command, static) = {
  .path = "show cnat k8s snat",
  .short_help = "",
  .function = cnat_k8s_show_snat,
};

static clib_error_t *
cnat_k8s_pods (vlib_main_t *vm, unformat_input_t *input,
	       vlib_cli_command_t *cmd)
{
  int rv;
  int is_add = 1;
  u32 sw_if_index = ~0;
  vnet_main_t *vnm = vnet_get_main ();

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "remove"))
	is_add = 0;
      else if (unformat (input, "%U", unformat_vnet_sw_interface, vnm,
			 &sw_if_index))
	;
      else
	return clib_error_return (0, "unknown input '%U'",
				  format_unformat_error, input);
    }

  if (sw_if_index == ~0)
    return clib_error_return (0, "Interface not specified");

  vlib_cli_output (vm, "cnat k8s pods: sw_if %d enable %d", sw_if_index,
		   is_add);

  rv = cnat_k8s_register_pod_interface (sw_if_index, is_add);

  if (rv)
    return clib_error_return (0, "Error %d", rv);

  return NULL;
}

VLIB_CLI_COMMAND (cnat_k8s_pods_command, static) = {
  .path = "cnat k8s pods",
  .short_help = "cnat k8s pods [remove] sw_if_index",
  .function = cnat_k8s_pods,
};

static clib_error_t *
cnat_k8s_show_pods (vlib_main_t *vm, unformat_input_t *input,
		    vlib_cli_command_t *cmd)
{
  u8 *s;
  int i;
  s = format (0, "Pod interfaces:");
  clib_bitmap_foreach (i, cnat_k8s_main.pod_interfaces)
    s = format (s, " %d", i);
  vlib_cli_output (vm, (char *) s);
  return (NULL);
}

VLIB_CLI_COMMAND (cnat_k8s_show_pods_command, static) = {
  .path = "show cnat k8s pod interfaces",
  .short_help = "",
  .function = cnat_k8s_show_pods,
};

static clib_error_t *
cnat_k8s_show_pod_cidrs (vlib_main_t *vm, unformat_input_t *input,
			 vlib_cli_command_t *cmd)
{
  u8 *s;
  ip_prefix_t *pfx;
  s = format (0, "Pod CIDRs:");
  vec_foreach (pfx, cnat_k8s_main.pod_cidrs)
    {
      s = format (s, " %U", format_ip_prefix, pfx);
    }
  vlib_cli_output (vm, (char *) s);
  return (NULL);
}

VLIB_CLI_COMMAND (cnat_k8s_show_pod_cidrs_command, static) = {
  .path = "show cnat k8s pod cidrs",
  .short_help = "",
  .function = cnat_k8s_show_pod_cidrs,
};

static clib_error_t *
cnat_k8s_init (vlib_main_t *vm)
{
  cnat_k8s_main_t *ckm = &cnat_k8s_main;
  clib_bitmap_validate (ckm->ip4_snat_interfaces, 4096);
  clib_bitmap_validate (ckm->ip6_snat_interfaces, 4096);
  clib_bitmap_validate (ckm->pod_interfaces, 4096);

  return (NULL);
}

VLIB_INIT_FUNCTION (cnat_k8s_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
