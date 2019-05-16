/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
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
#include <vnet/ip/ip.h>
#include <vnet/classify/vnet_classify.h>
#include <vnet/classify/in_out_acl.h>
#include <vnet/l2/l2_output.h>
#include <vnet/l2/l2_input.h>

in_out_acl_main_t in_out_acl_main;

static int
vnet_in_out_acl_ip_feature_enable (vlib_main_t * vnm,
				   in_out_acl_main_t * am,
				   u32 sw_if_index,
				   in_out_acl_table_id_t tid,
				   int feature_enable, int is_output)
{

  if (tid == IN_OUT_ACL_TABLE_L2)
    {
      if (is_output)
	l2output_intf_bitmap_enable (sw_if_index, L2OUTPUT_FEAT_ACL,
				     feature_enable);
      else
	l2input_intf_bitmap_enable (sw_if_index, L2INPUT_FEAT_ACL,
				    feature_enable);
    }
  else
    {				/* IP[46] */
      vnet_feature_config_main_t *fcm;
      u8 arc;

      if (tid == IN_OUT_ACL_TABLE_IP4)
	{
	  char *arc_name = is_output ? "ip4-output" : "ip4-unicast";
	  vnet_feature_enable_disable (arc_name,
				       is_output ? "ip4-outacl" : "ip4-inacl",
				       sw_if_index, feature_enable, 0, 0);
	  arc = vnet_get_feature_arc_index (arc_name);
	}
      else
	{
	  char *arc_name = is_output ? "ip6-output" : "ip6-unicast";
	  vnet_feature_enable_disable (arc_name,
				       is_output ? "ip6-outacl" : "ip6-inacl",
				       sw_if_index, feature_enable, 0, 0);
	  arc = vnet_get_feature_arc_index (arc_name);
	}

      fcm = vnet_get_feature_arc_config_main (arc);
      am->vnet_config_main[is_output][tid] = &fcm->config_main;
    }

  return 0;
}

int
vnet_set_in_out_acl_intfc (vlib_main_t * vm, u32 sw_if_index,
			   u32 ip4_table_index,
			   u32 ip6_table_index, u32 l2_table_index,
			   u32 is_add, u32 is_output)
{
  in_out_acl_main_t *am = &in_out_acl_main;
  vnet_classify_main_t *vcm = am->vnet_classify_main;
  u32 acl[IN_OUT_ACL_N_TABLES] = { ip4_table_index, ip6_table_index,
    l2_table_index
  };
  u32 ti;

  /* Assume that we've validated sw_if_index in the API layer */

  for (ti = 0; ti < IN_OUT_ACL_N_TABLES; ti++)
    {
      if (acl[ti] == ~0)
	continue;

      if (pool_is_free_index (vcm->tables, acl[ti]))
	return VNET_API_ERROR_NO_SUCH_TABLE;

      vec_validate_init_empty
	(am->classify_table_index_by_sw_if_index[is_output][ti], sw_if_index,
	 ~0);

      /* Reject any DEL operation with wrong sw_if_index */
      if (!is_add &&
	  (acl[ti] !=
	   am->classify_table_index_by_sw_if_index[is_output][ti]
	   [sw_if_index]))
	{
	  clib_warning
	    ("Non-existent intf_idx=%d with table_index=%d for delete",
	     sw_if_index, acl[ti]);
	  return VNET_API_ERROR_NO_SUCH_TABLE;
	}

      /* Return ok on ADD operaton if feature is already enabled */
      if (is_add &&
	  am->classify_table_index_by_sw_if_index[is_output][ti][sw_if_index]
	  != ~0)
	return 0;

      vnet_in_out_acl_ip_feature_enable (vm, am, sw_if_index, ti, is_add,
					 is_output);

      if (is_add)
	am->classify_table_index_by_sw_if_index[is_output][ti][sw_if_index] =
	  acl[ti];
      else
	am->classify_table_index_by_sw_if_index[is_output][ti][sw_if_index] =
	  ~0;
    }

  return 0;
}

int
vnet_set_input_acl_intfc (vlib_main_t * vm, u32 sw_if_index,
			  u32 ip4_table_index,
			  u32 ip6_table_index, u32 l2_table_index, u32 is_add)
{
  return vnet_set_in_out_acl_intfc (vm, sw_if_index, ip4_table_index,
				    ip6_table_index, l2_table_index, is_add,
				    IN_OUT_ACL_INPUT_TABLE_GROUP);
}

int
vnet_set_output_acl_intfc (vlib_main_t * vm, u32 sw_if_index,
			   u32 ip4_table_index,
			   u32 ip6_table_index, u32 l2_table_index,
			   u32 is_add)
{
  return vnet_set_in_out_acl_intfc (vm, sw_if_index, ip4_table_index,
				    ip6_table_index, l2_table_index, is_add,
				    IN_OUT_ACL_OUTPUT_TABLE_GROUP);
}

static clib_error_t *
set_in_out_acl_command_fn (vlib_main_t * vm,
			   unformat_input_t * input, vlib_cli_command_t * cmd,
			   u32 is_output)
{
  vnet_main_t *vnm = vnet_get_main ();
  u32 sw_if_index = ~0;
  u32 ip4_table_index = ~0;
  u32 ip6_table_index = ~0;
  u32 l2_table_index = ~0;
  u32 is_add = 1;
  u32 idx_cnt = 0;
  int rv;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "intfc %U", unformat_vnet_sw_interface,
		    vnm, &sw_if_index))
	;
      else if (unformat (input, "ip4-table %d", &ip4_table_index))
	idx_cnt++;
      else if (unformat (input, "ip6-table %d", &ip6_table_index))
	idx_cnt++;
      else if (unformat (input, "l2-table %d", &l2_table_index))
	idx_cnt++;
      else if (unformat (input, "del"))
	is_add = 0;
      else
	break;
    }

  if (sw_if_index == ~0)
    return clib_error_return (0, "Interface must be specified.");

  if (!idx_cnt)
    return clib_error_return (0, "Table index should be specified.");

  if (idx_cnt > 1)
    return clib_error_return (0, "Only one table index per API is allowed.");

  rv = vnet_set_in_out_acl_intfc (vm, sw_if_index, ip4_table_index,
				  ip6_table_index, l2_table_index, is_add,
				  is_output);

  switch (rv)
    {
    case 0:
      break;

    case VNET_API_ERROR_NO_MATCHING_INTERFACE:
      return clib_error_return (0, "No such interface");

    case VNET_API_ERROR_NO_SUCH_ENTRY:
      return clib_error_return (0, "No such classifier table");
    }
  return 0;
}

static clib_error_t *
set_input_acl_command_fn (vlib_main_t * vm,
			  unformat_input_t * input, vlib_cli_command_t * cmd)
{
  return set_in_out_acl_command_fn (vm, input, cmd,
				    IN_OUT_ACL_INPUT_TABLE_GROUP);
}

static clib_error_t *
set_output_acl_command_fn (vlib_main_t * vm,
			   unformat_input_t * input, vlib_cli_command_t * cmd)
{
  return set_in_out_acl_command_fn (vm, input, cmd,
				    IN_OUT_ACL_OUTPUT_TABLE_GROUP);
}

/*
 * Configure interface to enable/disble input/output ACL features:
 * intfc - interface name to be configured as input ACL
 * Ip4-table <index> [del] - enable/disable IP4 input ACL
 * Ip6-table <index> [del] - enable/disable IP6 input ACL
 * l2-table <index> [del] - enable/disable Layer2 input ACL
 *
 * Note: Only one table index per API call is allowed.
 *
 */
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (set_input_acl_command, static) = {
    .path = "set interface input acl",
    .short_help =
    "set interface input acl intfc <int> [ip4-table <index>]\n"
    "  [ip6-table <index>] [l2-table <index>] [del]",
    .function = set_input_acl_command_fn,
};
VLIB_CLI_COMMAND (set_output_acl_command, static) = {
    .path = "set interface output acl",
    .short_help =
    "set interface output acl intfc <int> [ip4-table <index>]\n"
    "  [ip6-table <index>] [l2-table <index>] [del]",
    .function = set_output_acl_command_fn,
};
/* *INDENT-ON* */

clib_error_t *
in_out_acl_init (vlib_main_t * vm)
{
  in_out_acl_main_t *am = &in_out_acl_main;

  am->vlib_main = vm;
  am->vnet_main = vnet_get_main ();
  am->vnet_classify_main = &vnet_classify_main;

  return 0;
}
/* *INDENT-OFF* */
VLIB_INIT_FUNCTION (in_out_acl_init) =
{
  .runs_after = VLIB_INITS("ip_in_out_acl_init"),
};
/* *INDENT-ON* */

uword
unformat_acl_type (unformat_input_t * input, va_list * args)
{
  u32 *acl_type = va_arg (*args, u32 *);
  u32 tid = IN_OUT_ACL_N_TABLES;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "ip4"))
	tid = IN_OUT_ACL_TABLE_IP4;
      else if (unformat (input, "ip6"))
	tid = IN_OUT_ACL_TABLE_IP6;
      else if (unformat (input, "l2"))
	tid = IN_OUT_ACL_TABLE_L2;
      else
	break;
    }

  *acl_type = tid;
  return 1;
}

u8 *
format_vnet_in_out_acl_info (u8 * s, va_list * va)
{
  in_out_acl_main_t *am = va_arg (*va, in_out_acl_main_t *);
  int sw_if_idx = va_arg (*va, int);
  u32 tid = va_arg (*va, u32);

  if (tid == ~0)
    {
      s = format (s, "%10s%20s\t\t%s", "Intfc idx", "Classify table",
		  "Interface name");
      return s;
    }

  s = format (s, "%10d%20d\t\t%U", sw_if_idx, tid,
	      format_vnet_sw_if_index_name, am->vnet_main, sw_if_idx);

  return s;
}

static clib_error_t *
show_in_out_acl_command_fn (vlib_main_t * vm,
			    unformat_input_t * input,
			    vlib_cli_command_t * cmd, u32 is_output)
{
  in_out_acl_main_t *am = &in_out_acl_main;
  u32 type = IN_OUT_ACL_N_TABLES;
  int i;
  u32 *vec_tbl;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "type %U", unformat_acl_type, &type))
	;
      else
	break;
    }

  if (type == IN_OUT_ACL_N_TABLES)
    return clib_error_return (0, is_output ? "Invalid output ACL table type."
			      : "Invalid input ACL table type.");

  vec_tbl = am->classify_table_index_by_sw_if_index[is_output][type];

  if (vec_len (vec_tbl))
    vlib_cli_output (vm, "%U", format_vnet_in_out_acl_info, am, ~0 /* hdr */ ,
		     ~0);
  else
    vlib_cli_output (vm, is_output ? "No output ACL tables configured"
		     : "No input ACL tables configured");

  for (i = 0; i < vec_len (vec_tbl); i++)
    {
      if (vec_elt (vec_tbl, i) == ~0)
	continue;

      vlib_cli_output (vm, "%U", format_vnet_in_out_acl_info,
		       am, i, vec_elt (vec_tbl, i));
    }

  return 0;
}

static clib_error_t *
show_inacl_command_fn (vlib_main_t * vm,
		       unformat_input_t * input, vlib_cli_command_t * cmd)
{
  return show_in_out_acl_command_fn (vm, input, cmd,
				     IN_OUT_ACL_INPUT_TABLE_GROUP);
}

static clib_error_t *
show_outacl_command_fn (vlib_main_t * vm,
			unformat_input_t * input, vlib_cli_command_t * cmd)
{
  return show_in_out_acl_command_fn (vm, input, cmd,
				     IN_OUT_ACL_OUTPUT_TABLE_GROUP);
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_inacl_command, static) = {
    .path = "show inacl",
    .short_help = "show inacl type [ip4|ip6|l2]",
    .function = show_inacl_command_fn,
};
VLIB_CLI_COMMAND (show_outacl_command, static) = {
    .path = "show outacl",
    .short_help = "show outacl type [ip4|ip6|l2]",
    .function = show_outacl_command_fn,
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
