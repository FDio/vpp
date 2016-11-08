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

#include <vnet/feature/feature.h>

vnet_feature_main_t feature_main;

static clib_error_t *
vnet_feature_init (vlib_main_t * vm)
{
  vnet_feature_main_t *fm = &feature_main;
  vnet_feature_registration_t *freg;
  vnet_feature_arc_registration_t *areg;
  u32 arc_index = 0;

  fm->arc_index_by_name = hash_create_string (0, sizeof (uword));
  areg = fm->next_arc;

  /* process feature arc registrations */
  while (areg)
    {
      char *s;
      int i = 0;
      areg->feature_arc_index = arc_index;
      hash_set_mem (fm->arc_index_by_name, areg->arc_name,
		    pointer_to_uword (areg));

      /* process start nodes */
      while ((s = areg->start_nodes[i]))
	{
	  i++;
	}
      areg->n_start_nodes = i;

      /* next */
      areg = areg->next;
      arc_index++;
    }

  vec_validate (fm->next_feature_by_arc, arc_index - 1);
  vec_validate (fm->feature_nodes, arc_index - 1);
  vec_validate (fm->feature_config_mains, arc_index - 1);
  vec_validate (fm->next_feature_by_name, arc_index - 1);
  vec_validate (fm->sw_if_index_has_features, arc_index - 1);
  vec_validate (fm->feature_count_by_sw_if_index, arc_index - 1);

  freg = fm->next_feature;
  while (freg)
    {
      uword *p = hash_get_mem (fm->arc_index_by_name, freg->arc_name);
      if (p == 0)
	return clib_error_return (0, "Unknown feature arc '%s'",
				  freg->arc_name);

      areg = uword_to_pointer (p[0], vnet_feature_arc_registration_t *);
      arc_index = areg->feature_arc_index;

      vec_add1 (fm->next_feature_by_arc[arc_index], *freg);

      /* next */
      freg = freg->next;
    }

  while (areg)
    {
      clib_error_t *error;
      vnet_feature_config_main_t *cm;
      vnet_config_main_t *vcm;

      arc_index = areg->feature_arc_index;
      cm = &fm->feature_config_mains[arc_index];
      vcm = &cm->config_main;
      if ((error = vnet_feature_arc_init (vm, vcm,
					  areg->start_nodes,
					  areg->n_start_nodes,
					  fm->next_feature_by_arc[arc_index],
					  &fm->feature_nodes[arc_index])))
	{
	  return error;
	}

      fm->next_feature_by_name[arc_index] =
	hash_create_string (0, sizeof (uword));
      freg = fm->next_feature_by_arc[arc_index];

      while (freg)
	{
	  hash_set_mem (fm->next_feature_by_name[arc_index],
			freg->node_name, pointer_to_uword (freg));
	  freg = freg->next;
	}

      /* next */
      areg = areg->next;
      arc_index++;
    }

  fm->device_input_feature_arc_index =
    vnet_get_feature_arc_index ("device-input");
  return 0;
}

VLIB_INIT_FUNCTION (vnet_feature_init);

void
vnet_config_update_feature_count (vnet_feature_main_t * fm, u8 arc,
				  u32 sw_if_index, int is_add)
{
  uword bit_value;

  vec_validate (fm->feature_count_by_sw_if_index[arc], sw_if_index);

  fm->feature_count_by_sw_if_index[arc][sw_if_index] += is_add ? 1 : -1;

  ASSERT (fm->feature_count_by_sw_if_index[arc][sw_if_index] >= 0);

  bit_value = fm->feature_count_by_sw_if_index[arc][sw_if_index] > 0;

  fm->sw_if_index_has_features[arc] =
    clib_bitmap_set (fm->sw_if_index_has_features[arc], sw_if_index,
		     bit_value);
}

u8
vnet_get_feature_arc_index (const char *s)
{
  vnet_feature_main_t *fm = &feature_main;
  vnet_feature_arc_registration_t *reg;
  uword *p;

  p = hash_get_mem (fm->arc_index_by_name, s);
  if (p == 0)
    return ~0;

  reg = uword_to_pointer (p[0], vnet_feature_arc_registration_t *);
  return reg->feature_arc_index;
}

u32
vnet_get_feature_index (u8 arc, const char *s)
{
  vnet_feature_main_t *fm = &feature_main;
  vnet_feature_registration_t *reg;
  uword *p;

  p = hash_get_mem (fm->next_feature_by_name[arc], s);
  if (p == 0)
    return ~0;

  reg = uword_to_pointer (p[0], vnet_feature_registration_t *);
  return reg->feature_index_u32;
}

void
vnet_feature_enable_disable (const char *arc_name, const char *node_name,
			     u32 sw_if_index, int enable_disable,
			     void *feature_config, u32 n_feature_config_bytes)
{
  vnet_feature_main_t *fm = &feature_main;
  vnet_feature_config_main_t *cm;
  u32 feature_index, ci;
  u8 arc_index;

  arc_index = vnet_get_feature_arc_index (arc_name);

  if (arc_index == (u8) ~ 0)
    return;

  cm = &fm->feature_config_mains[arc_index];
  vec_validate_init_empty (cm->config_index_by_sw_if_index, sw_if_index, ~0);
  feature_index = vnet_get_feature_index (arc_index, node_name);
  if (feature_index == ~0)
    return;
  ci = cm->config_index_by_sw_if_index[sw_if_index];

  ci = (enable_disable
	? vnet_config_add_feature
	: vnet_config_del_feature)
    (vlib_get_main (), &cm->config_main, ci, feature_index, feature_config,
     n_feature_config_bytes);
  cm->config_index_by_sw_if_index[sw_if_index] = ci;

  vnet_config_update_feature_count (fm, arc_index, sw_if_index,
				    enable_disable);

}


/** Display the set of available driver features.
    Useful for verifying that expected features are present
*/

static clib_error_t *
show_features_command_fn (vlib_main_t * vm,
			  unformat_input_t * input, vlib_cli_command_t * cmd)
{
  vnet_feature_main_t *fm = &feature_main;
  vnet_feature_arc_registration_t *areg;
  vnet_feature_registration_t *freg;

  vlib_cli_output (vm, "Available feature paths");

  areg = fm->next_arc;
  while (areg)
    {
      vlib_cli_output (vm, "%s:", areg->arc_name);
      vec_foreach (freg, fm->next_feature_by_arc[areg->feature_arc_index])
      {
	vlib_cli_output (vm, "  %s\n", freg->node_name);
      }


      /* next */
      areg = areg->next;
    }

  return 0;
}

/*?
 * Display the set of available driver features
 *
 * @cliexpar
 * Example:
 * @cliexcmd{show ip features}
 * @cliexend
 * @endparblock
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_features_command, static) = {
  .path = "show features",
  .short_help = "show features",
  .function = show_features_command_fn,
};
/* *INDENT-ON* */

/** Display the set of driver features configured on a specific interface
  * Called by "show interface" handler
 */

void
vnet_interface_features_show (vlib_main_t * vm, u32 sw_if_index)
{
  vnet_feature_main_t *fm = &feature_main;
  u32 node_index, current_config_index;
  u16 feature_arc;
  vnet_feature_config_main_t *cm = fm->feature_config_mains;
  vnet_feature_arc_registration_t *areg;
  vnet_config_main_t *vcm;
  vnet_config_t *cfg;
  u32 cfg_index;
  vnet_config_feature_t *feat;
  vlib_node_t *n;
  int i;

  vlib_cli_output (vm, "Driver feature paths configured on %U...",
		   format_vnet_sw_if_index_name,
		   vnet_get_main (), sw_if_index);

  areg = fm->next_arc;
  while (areg)
    {
      feature_arc = areg->feature_arc_index;
      vcm = &(cm[feature_arc].config_main);

      vlib_cli_output (vm, "\n%s:", areg->arc_name);
      areg = areg->next;

      if (NULL == cm[feature_arc].config_index_by_sw_if_index ||
	  vec_len (cm[feature_arc].config_index_by_sw_if_index) <=
	  sw_if_index)
	{
	  vlib_cli_output (vm, "  none configured");
	  continue;
	}

      current_config_index =
	vec_elt (cm[feature_arc].config_index_by_sw_if_index, sw_if_index);

      if (current_config_index == ~0)
	{
	  vlib_cli_output (vm, "  none configured");
	  continue;
	}

      ASSERT (current_config_index
	      < vec_len (vcm->config_pool_index_by_user_index));

      cfg_index = vcm->config_pool_index_by_user_index[current_config_index];
      cfg = pool_elt_at_index (vcm->config_pool, cfg_index);

      for (i = 0; i < vec_len (cfg->features); i++)
	{
	  feat = cfg->features + i;
	  node_index = feat->node_index;
	  n = vlib_get_node (vm, node_index);
	  vlib_cli_output (vm, "  %v", n->name);
	}
    }
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
