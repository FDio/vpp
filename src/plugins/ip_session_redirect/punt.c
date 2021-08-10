/*
 * Copyright (c) 2021 Cisco and/or its affiliates.
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
#include <vnet/feature/feature.h>
#include <vnet/classify/in_out_acl.h>
#include "ip_session_redirect.h"

VNET_FEATURE_INIT (ip4_session_redirect_punt) = {
  .arc_name = "ip4-punt",
  .node_name = "ip4-inacl",
  .runs_after = VNET_FEATURES ("ip4-punt-policer"),
};

VNET_FEATURE_INIT (ip6_session_redirect_punt) = {
  .arc_name = "ip6-punt",
  .node_name = "ip6-inacl",
  .runs_after = VNET_FEATURES ("ip6-punt-policer"),
};

void
ip_session_redirect_punt_add_del (vlib_main_t *vm, u32 sw_if_index,
				  u32 table_index, int is_add, int is_ip4)
{
  const char *unicast_arc = "ip4-unicast";
  const char *punt_arc = "ip4-punt";
  const char *node = "ip4-inacl";
  u32 ip4_table_index = table_index;
  u32 ip6_table_index = ~0;
  in_out_acl_table_id_t tid = IN_OUT_ACL_TABLE_IP4;

  if (!is_ip4)
    {
      unicast_arc = "ip6-unicast";
      punt_arc = "ip6-punt";
      node = "ip6-inacl";
      ip4_table_index = ~0;
      ip6_table_index = table_index;
      tid = IN_OUT_ACL_TABLE_IP6;
    }

  vnet_feature_enable_disable (punt_arc, node, 0 /* sw_if_index */, is_add, 0,
			       0);
  vnet_set_input_acl_intfc (vm, sw_if_index, ip4_table_index, ip6_table_index,
			    ~0 /* l2_table_index */, is_add);
  if (is_add)
    {
      /* fixup ip-unicast arc config done in
       * vnet_in_out_acl_ip_feature_enable() */
      u8 arc_index = vnet_get_feature_arc_index (punt_arc);
      vnet_feature_config_main_t *fcm =
	vnet_get_feature_arc_config_main (arc_index);
      vnet_feature_enable_disable (unicast_arc, node, sw_if_index, 0, 0, 0);
      in_out_acl_main.vnet_config_main[0 /* is_output */][tid] =
	&fcm->config_main;
    }
}

static clib_error_t *
ip_session_redirect_punt_cmd (vlib_main_t *vm, unformat_input_t *main_input,
			      vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  vnet_main_t *vnm = vnet_get_main ();
  clib_error_t *error = 0;
  u32 table_index = ~0;
  u32 sw_if_index = ~0;
  int is_add = 1;
  int is_ip4 = 1;

  if (!unformat_user (main_input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "add"))
	is_add = 1;
      else if (unformat (line_input, "del"))
	is_add = 0;
      else if (unformat (line_input, "ip4"))
	is_ip4 = 1;
      else if (unformat (line_input, "ip6"))
	is_ip4 = 0;
      else if (unformat (line_input, "table %d", &table_index))
	;
      else if (unformat (line_input, "%U", unformat_vnet_sw_interface, vnm,
			 &sw_if_index))
	;
      else
	{
	  error = unformat_parse_error (line_input);
	  goto out;
	}
    }

  ip_session_redirect_punt_add_del (vm, sw_if_index, table_index, is_add,
				    is_ip4);

out:
  unformat_free (line_input);
  return error;
}

VLIB_CLI_COMMAND (ip_session_redirect_punt_command, static) = {
  .path = "ip session redirect punt",
  .function = ip_session_redirect_punt_cmd,
  .short_help =
    "ip session redirect punt [add|del] [ip4|ip6] <interface> table <index>",
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
