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
#include <vnet/classify/policer_classify.h>

policer_classify_main_t policer_classify_main;

static void
vnet_policer_classify_feature_enable (vlib_main_t * vnm,
                                      policer_classify_main_t * pcm,
                                      u32 sw_if_index,
                                      policer_classify_table_id_t tid,
                                      int feature_enable)
{
  if (tid == POLICER_CLASSIFY_TABLE_L2)
    {
      l2input_intf_bitmap_enable (sw_if_index, L2INPUT_FEAT_POLICER_CLAS,
                                  feature_enable);
    }
  else
    {
      vnet_feature_config_main_t * fcm;
      u8 arc;

      if (tid == POLICER_CLASSIFY_TABLE_IP4)
	{
	  vnet_feature_enable_disable ("ip4-unicast", "ip4-policer-classify",
				       sw_if_index, feature_enable, 0, 0);
	  arc = vnet_get_feature_arc_index ("ip4-unicast");
	}
      
      else
	{
	  vnet_feature_enable_disable ("ip6-unicast", "ip6-policer-classify",
				       sw_if_index, feature_enable, 0, 0);
	  arc = vnet_get_feature_arc_index ("ip6-unicast");
	}

      fcm = vnet_get_feature_arc_config_main (arc);
      pcm->vnet_config_main[tid] = &fcm->config_main;
    }
}

int vnet_set_policer_classify_intfc (vlib_main_t * vm, u32 sw_if_index,
                                     u32 ip4_table_index, u32 ip6_table_index,
                                     u32 l2_table_index, u32 is_add)
{
  policer_classify_main_t * pcm = &policer_classify_main;
  vnet_classify_main_t * vcm = pcm->vnet_classify_main;
  u32 pct[POLICER_CLASSIFY_N_TABLES] = {ip4_table_index, ip6_table_index,
                                        l2_table_index};
  u32 ti;

  /* Assume that we've validated sw_if_index in the API layer */

  for (ti = 0; ti < POLICER_CLASSIFY_N_TABLES; ti++)
    {
      if (pct[ti] == ~0)
        continue;

      if (pool_is_free_index (vcm->tables, pct[ti]))
        return VNET_API_ERROR_NO_SUCH_TABLE;

      vec_validate_init_empty
        (pcm->classify_table_index_by_sw_if_index[ti], sw_if_index, ~0);

      /* Reject any DEL operation with wrong sw_if_index */
      if (!is_add &&
          (pct[ti] != pcm->classify_table_index_by_sw_if_index[ti][sw_if_index]))
        {
          clib_warning ("Non-existent intf_idx=%d with table_index=%d for delete",
                        sw_if_index, pct[ti]);
          return VNET_API_ERROR_NO_SUCH_TABLE;
        }

      /* Return ok on ADD operaton if feature is already enabled */
      if (is_add &&
          pcm->classify_table_index_by_sw_if_index[ti][sw_if_index] != ~0)
          return 0;

      vnet_policer_classify_feature_enable (vm, pcm, sw_if_index, ti, is_add);

      if (is_add)
        pcm->classify_table_index_by_sw_if_index[ti][sw_if_index] = pct[ti];
      else
        pcm->classify_table_index_by_sw_if_index[ti][sw_if_index] = ~0;
    }


  return 0;
}

static clib_error_t *
set_policer_classify_command_fn (vlib_main_t * vm,
                                 unformat_input_t * input,
                                 vlib_cli_command_t * cmd)
{
  vnet_main_t * vnm = vnet_get_main();
  u32 sw_if_index = ~0;
  u32 ip4_table_index = ~0;
  u32 ip6_table_index = ~0;
  u32 l2_table_index = ~0;
  u32 is_add = 1;
  u32 idx_cnt = 0;
  int rv;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "interface %U", unformat_vnet_sw_interface,
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

  rv = vnet_set_policer_classify_intfc(vm, sw_if_index, ip4_table_index,
                                       ip6_table_index, l2_table_index, is_add);

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

VLIB_CLI_COMMAND (set_policer_classify_command, static) = {
    .path = "set policer classify",
    .short_help =
    "set policer classify interface <int> [ip4-table <index>]\n"
    "  [ip6-table <index>] [l2-table <index>] [del]",
    .function = set_policer_classify_command_fn,
};

static uword
unformat_table_type (unformat_input_t * input, va_list * va)
{
  u32 * r = va_arg (*va, u32 *);
  u32 tid;

  if (unformat (input, "ip4"))
    tid = POLICER_CLASSIFY_TABLE_IP4;
  else if (unformat (input, "ip6"))
    tid = POLICER_CLASSIFY_TABLE_IP6;
  else if (unformat (input, "l2"))
    tid = POLICER_CLASSIFY_TABLE_L2;
  else
    return 0;

  *r = tid;
  return 1;
}
static clib_error_t *
show_policer_classify_command_fn (vlib_main_t * vm,
                                  unformat_input_t * input,
                                  vlib_cli_command_t * cmd)
{
  policer_classify_main_t * pcm = &policer_classify_main;
  u32 type = POLICER_CLASSIFY_N_TABLES;
  u32 * vec_tbl;
  int i;

  if (unformat (input, "type %U", unformat_table_type, &type))
    ;
  else
    return clib_error_return (0, "Type must be specified.");;

  if (type == POLICER_CLASSIFY_N_TABLES)
    return clib_error_return (0, "Invalid table type.");

  vec_tbl = pcm->classify_table_index_by_sw_if_index[type];

  if (vec_len(vec_tbl))
      vlib_cli_output (vm, "%10s%20s\t\t%s", "Intfc idx", "Classify table",
                       "Interface name");
  else
    vlib_cli_output (vm, "No tables configured.");

  for (i = 0; i < vec_len (vec_tbl); i++)
    {
      if (vec_elt(vec_tbl, i) == ~0)
        continue;

      vlib_cli_output (vm, "%10d%20d\t\t%U", i, vec_elt(vec_tbl, i),
                       format_vnet_sw_if_index_name, pcm->vnet_main, i);
    }

  return 0;
}

VLIB_CLI_COMMAND (show_policer_classify_command, static) = {
    .path = "show classify policer",
    .short_help = "show classify policer type [ip4|ip6|l2]",
    .function = show_policer_classify_command_fn,
};
