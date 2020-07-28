/*
 * Copyright (c) 2016-2018 Cisco and/or its affiliates.
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
#include <netinet/in.h>

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/pg/pg.h>
#include <vppinfra/error.h>

#include <acl/acl.h>
#include <vnet/ip/icmp46_packet.h>

#include <plugins/acl/fa_node.h>
#include <plugins/acl/acl.h>
#include <plugins/acl/lookup_context.h>
#include <plugins/acl/public_inlines.h>
#include <plugins/acl/session_inlines.h>
#include <plugins/acl/acl_util.h>
#include <plugins/acl/acl_caiop.h>

int
is_acl_caiop_enabled_on_sw_if_index (u32 sw_if_index, int is_input)
{
  acl_main_t *am = &acl_main;
  int ret = 0;
  if (is_input)
    {
      ret = clib_bitmap_get (am->caip_on_sw_if_index, sw_if_index);
    }
  else
    {
      ret = clib_bitmap_get (am->caop_on_sw_if_index, sw_if_index);
    }
  return ret;
}

void
acl_caiop_enable_disable (u32 sw_if_index, int is_input, int enable_disable)
{
  acl_main_t *am = &acl_main;

  if (is_input)
    {
      ASSERT (clib_bitmap_get (am->caip_on_sw_if_index, sw_if_index) !=
	      enable_disable);
      am->caip_on_sw_if_index =
	clib_bitmap_set (am->caip_on_sw_if_index, sw_if_index, enable_disable);
    }
  else
    {
      ASSERT (clib_bitmap_get (am->caop_on_sw_if_index, sw_if_index) !=
	      enable_disable);
      am->caop_on_sw_if_index =
	clib_bitmap_set (am->caop_on_sw_if_index, sw_if_index, enable_disable);
    }
}

static int
not_found (u32 index)
{
  return (index == ((u32) ~0));
}

static int
caiop_add (u32 sw_if_index, int is_input,
	   acl_plugin_private_caiop_match_5tuple_func_t func)
{
  acl_main_t *am = &acl_main;
  acl_plugin_private_caiop_match_5tuple_func_t ***pvecvec =
    is_input ? &am->caip_match_func_by_sw_if_index :
	       &am->caop_match_func_by_sw_if_index;
  uword **pbitmap =
    is_input ? &am->caip_on_sw_if_index : &am->caop_on_sw_if_index;
  int *pcount = is_input ? &am->custom_access_input_policies_count :
			   &am->custom_access_output_policies_count;

  vec_validate (*pvecvec, sw_if_index);
  u32 index = vec_search ((*pvecvec)[sw_if_index], func);
  if (not_found (index))
    {
      vec_add1 ((*pvecvec)[sw_if_index], func);
      *pbitmap = clib_bitmap_set (*pbitmap, sw_if_index, 1);
      (*pcount)++;
      return acl_interface_inout_enable_disable (am, sw_if_index, is_input, 1);
    }
  else
    {
      clib_warning ("Existing Index: %d", index);
      return -2;
    }
}

static int
caiop_del (u32 sw_if_index, int is_input,
	   acl_plugin_private_caiop_match_5tuple_func_t func)
{
  acl_main_t *am = &acl_main;
  acl_plugin_private_caiop_match_5tuple_func_t ***pvecvec =
    is_input ? &am->caip_match_func_by_sw_if_index :
	       &am->caop_match_func_by_sw_if_index;
  uword **pbitmap =
    is_input ? &am->caip_on_sw_if_index : &am->caop_on_sw_if_index;
  int *pcount = is_input ? &am->custom_access_input_policies_count :
			   &am->custom_access_output_policies_count;

  if (sw_if_index >= vec_len (*pvecvec))
    {
      return -2;
    }
  else
    {
      u32 index = vec_search ((*pvecvec)[sw_if_index], func);
      if (not_found (index))
	{
	  return -3;
	}
      else
	{
	  vec_del1 ((*pvecvec)[sw_if_index], index);
	  *pbitmap = clib_bitmap_set (*pbitmap, sw_if_index, 0);
	  (*pcount)--;
	  int enable = (*pcount > 0) ||
		       is_acl_enabled_on_sw_if_index (sw_if_index, is_input);
	  return acl_interface_inout_enable_disable (am, sw_if_index, is_input,
						     enable);
	}
    }
}

int
acl_caiop_add_del (int is_add, u32 sw_if_index, int is_input,
		   acl_plugin_private_caiop_match_5tuple_func_t func)
{
  acl_main_t *am = &acl_main;
  if (!vnet_sw_interface_is_api_valid (am->vnet_main, sw_if_index))
    {
      return -1;
    }
  return is_add ? caiop_add (sw_if_index, is_input, func) :
		  caiop_del (sw_if_index, is_input, func);
}

void
show_custom_access_policies (vlib_main_t *vm, u32 verbose)
{
  acl_main_t *am = &acl_main;
  int i;
  vlib_cli_output (vm, "\nCustom access policies:");
  acl_cli_output_u (vm, am->custom_access_input_policies_count);
  acl_cli_output_u (vm, am->custom_access_output_policies_count);
  acl_cli_output_bitmap (vm, am->caip_on_sw_if_index);
  acl_cli_output_bitmap (vm, am->caop_on_sw_if_index);
  for (i = 0; i < vec_len (am->caip_match_func_by_sw_if_index); i++)
    {
      if (i == 0)
	{
	  vlib_cli_output (vm, "\n input function pointers:");
	}
      vlib_cli_output (vm, "sw_if_index: %d vector: %U", i, format_vec_uword,
		       am->caip_match_func_by_sw_if_index[i], "%p");
    }
  for (i = 0; i < vec_len (am->caop_match_func_by_sw_if_index); i++)
    {
      if (i == 0)
	{
	  vlib_cli_output (vm, "\n output function pointers:");
	}
      vlib_cli_output (vm, "sw_if_index: %d vector: %U", i, format_vec_uword,
		       am->caop_match_func_by_sw_if_index[i], "%p");
    }
}

static clib_error_t *
acl_show_custom_access_policies_fn (vlib_main_t *vm, unformat_input_t *input,
				    vlib_cli_command_t *cmd)
{
  clib_error_t *error = 0;

  u32 show_policies_verbose = 0;
  (void) unformat (input, "verbose %u", &show_policies_verbose);

  show_custom_access_policies (vm, show_policies_verbose);
  return error;
}

static int
dummy_match_5tuple_fun (void *p_acl_main, u32 sw_if_index, u32 is_inbound,
			fa_5tuple_opaque_t *pkt_5tuple, int is_ip6,
			u8 *r_action, u32 *trace_bitmap)
{
  /* permit and create connection */
  *r_action = 2;
  return 1;
}

static clib_error_t *
acl_test_custom_access_policy_fn (vlib_main_t *vm, unformat_input_t *input,
				  vlib_cli_command_t *cmd)
{
  clib_error_t *error = 0;
  int is_del = unformat (input, "del");
  int is_input = unformat (input, "input");
  u32 sw_if_index = ~0;
  (void) unformat (input, "sw_if_index %u", &sw_if_index);
  vlib_cli_output (vm, "Test %s %s sw_if_index: %d", is_del ? "del" : "add",
		   is_input ? "input" : "output", sw_if_index);
  u32 ret =
    acl_caiop_add_del (!is_del, sw_if_index, is_input, dummy_match_5tuple_fun);
  if (ret != 0)
    {
      error = clib_error_return (0, "non-zero ret code: %d", ret);
    }

  return error;
}

VLIB_CLI_COMMAND (aclplugin_set_custom_policy_command, static) = {
  .path = "show acl-plugin custom-access-policies",
  .short_help = "show acl-plugin custom-access-policies [verbose]",
  .function = acl_show_custom_access_policies_fn,
};

VLIB_CLI_COMMAND (aclplugin_test_custom_policy_command, static) = {
  .path = "test acl-plugin custom-access-policy",
  .short_help =
    "test acl-plugin custom-access-policy [del] [input] [sw_if_index <N>]",
  .function = acl_test_custom_access_policy_fn,
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
