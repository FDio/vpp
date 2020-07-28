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
  if (enable_disable)
    {
    }
  else
    {
    }

  if (is_input)
    {
      ASSERT (clib_bitmap_get (am->caip_on_sw_if_index, sw_if_index) !=
	      enable_disable);
      am->caip_on_sw_if_index =
	clib_bitmap_set (am->caip_on_sw_if_index, sw_if_index,
			 enable_disable);
    }
  else
    {
      ASSERT (clib_bitmap_get (am->caop_on_sw_if_index, sw_if_index) !=
	      enable_disable);
      am->caop_on_sw_if_index =
	clib_bitmap_set (am->caop_on_sw_if_index, sw_if_index,
			 enable_disable);
    }
}


void
show_custom_access_policies (vlib_main_t * vm, u32 verbose)
{
  acl_main_t *am = &acl_main;
  vlib_cli_output (vm, "\nCustom access policies:");
  acl_cli_output_u (vm, am->custom_access_input_policies_count);
  acl_cli_output_u (vm, am->custom_access_output_policies_count);
  acl_cli_output_bitmap (vm, am->caip_on_sw_if_index);
  acl_cli_output_bitmap (vm, am->caop_on_sw_if_index);
}

static clib_error_t *
acl_show_custom_access_policies_fn (vlib_main_t * vm,
				    unformat_input_t * input,
				    vlib_cli_command_t * cmd)
{
  clib_error_t *error = 0;
  // acl_main_t *am = &acl_main;

  u32 show_policies_verbose = 0;
  (void) unformat (input, "verbose %u", &show_policies_verbose);

  show_custom_access_policies (vm, show_policies_verbose);
  return error;
}

static clib_error_t *
acl_test_custom_access_policy_fn (vlib_main_t * vm,
				  unformat_input_t * input,
				  vlib_cli_command_t * cmd)
{
  clib_error_t *error = 0;
  // acl_main_t *am = &acl_main;
  //
  //
  int is_del = unformat (input, "del");
  u32 sw_if_index = ~0;
  (void) unformat (input, "sw_if_index %u", &sw_if_index);
  vlib_cli_output (vm, "Test add/del: %d sw_if_index: %d", is_del,
		   sw_if_index);


  return error;
}

 /* *INDENT-OFF* */
VLIB_CLI_COMMAND (aclplugin_set_custom_policy_command, static) = {
    .path = "show acl-plugin custom-access-policies",
    .short_help = "show acl-plugin custom-access-policies [verbose]",
    .function = acl_show_custom_access_policies_fn,
};

VLIB_CLI_COMMAND (aclplugin_test_custom_policy_command, static) = {
    .path = "test acl-plugin custom-access-policy",
    .short_help = "test acl-plugin custom-access-policy [del] [sw_if_index <N>]",
    .function = acl_test_custom_access_policy_fn,
};

/* *INDENT-ON* */




/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
