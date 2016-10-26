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

#include <vnet/feature/feature.h>

vnet_feature_main_t feature_main;

#define _(n, l) \
extern char * n##_feature_start_nodes[]; \
extern int n##_feature_num_start_nodes;
foreach_vnet_feature_arc
#undef _
static const char *vnet_feature_arc_names[] = {
#define _(n, l) [VNET_FEAT_##n] = #l,
  foreach_vnet_feature_arc
#undef _
};

static clib_error_t *
vnet_feature_init (vlib_main_t * vm)
{
  vnet_feature_main_t *fm = &feature_main;
  clib_error_t *error;
  vnet_feature_arc_t feature_arc;
  vnet_feature_config_main_t *cm;
  vnet_config_main_t *vcm;
  char **feature_start_nodes;
  int feature_start_len;

  for (feature_arc = 0; feature_arc < VNET_N_FEAT_ARCS; feature_arc++)
    {
      cm = &fm->feature_config_mains[feature_arc];
      vcm = &cm->config_main;

      switch (feature_arc)
	{
#define _(n, l)								\
	case VNET_FEAT_##n:						\
	  feature_start_nodes = n##_feature_start_nodes;		\
	  feature_start_len = n##_feature_num_start_nodes;		\
	  break;
	  foreach_vnet_feature_arc
#undef _
	default:
	  return clib_error_return (0, "BUG");
	  break;
	}
      if ((error = vnet_feature_arc_init (vm, vcm,
					  feature_start_nodes,
					  feature_start_len,
					  fm->next_feature[feature_arc],
					  &fm->feature_nodes[feature_arc])))
	{
	  return error;
	}
      fm->next_feature_by_name[feature_arc] =
	hash_create_string (0, sizeof (uword));
      vnet_feature_registration_t *reg;
      reg = fm->next_feature[feature_arc];

      while (reg)
	{
	  hash_set_mem (fm->next_feature_by_name[feature_arc],
			reg->node_name, pointer_to_uword (reg));
	  reg = reg->next;
	}
    }

  return 0;
}

VLIB_INIT_FUNCTION (vnet_feature_init);

void
vnet_config_update_feature_count (vnet_feature_main_t * fm,
				  vnet_feature_arc_t arc,
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

u32
vnet_feature_index_from_node_name (vnet_feature_arc_t arc, const char *s)
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
vnet_feature_enable_disable (vnet_feature_arc_t arc, const char *node_name,
			     u32 sw_if_index, int enable_disable,
			     void *feature_config, u32 n_feature_config_bytes)
{
  vnet_feature_main_t *fm = &feature_main;
  vnet_feature_config_main_t *cm = &fm->feature_config_mains[arc];
  u32 feature_index, ci;

  vec_validate_init_empty (cm->config_index_by_sw_if_index, sw_if_index, ~0);
  feature_index = vnet_feature_index_from_node_name (arc, node_name);
  if (feature_index == ~0)
    return;
  ci = cm->config_index_by_sw_if_index[sw_if_index];

  ci = (enable_disable
	? vnet_config_add_feature
	: vnet_config_del_feature)
    (vlib_get_main (), &cm->config_main, ci, feature_index, feature_config,
     n_feature_config_bytes);
  cm->config_index_by_sw_if_index[sw_if_index] = ci;

  vnet_config_update_feature_count (fm, sw_if_index, arc, enable_disable);

}


/** Display the set of available driver features.
    Useful for verifying that expected features are present
*/

static clib_error_t *
show_features_command_fn (vlib_main_t * vm,
			  unformat_input_t * input, vlib_cli_command_t * cmd)
{
  vnet_feature_main_t *fm = &feature_main;
  int i;
  char **features;

  vlib_cli_output (vm, "Available feature paths");

#define _(f, l)								\
  do {									\
    features = fm->feature_nodes[VNET_FEAT_##f];			\
    vlib_cli_output (vm, "%U:", format_replace_char, #l, "_", "-");	\
    for (i = 0; i < vec_len(features); i++)				\
      vlib_cli_output (vm, "  %s\n", features[i]);			\
  } while(0);
  foreach_vnet_feature_arc;
#undef _

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
  vnet_feature_arc_t feature_arc;
  vnet_feature_config_main_t *cm = fm->feature_config_mains;
  vnet_config_main_t *vcm;
  vnet_config_t *cfg;
  u32 cfg_index;
  vnet_config_feature_t *feat;
  vlib_node_t *n;
  int i;

  vlib_cli_output (vm, "Driver feature paths configured on %U...",
		   format_vnet_sw_if_index_name,
		   vnet_get_main (), sw_if_index);

  for (feature_arc = 0; feature_arc < VNET_N_FEAT_ARCS; feature_arc++)
    {
      vcm = &(cm[feature_arc].config_main);

      vlib_cli_output (vm, "\n%U:", format_replace_char,
		       vnet_feature_arc_names[feature_arc], "_", "-");

      if (NULL == cm[feature_arc].config_index_by_sw_if_index ||
	  vec_len (cm[feature_arc].config_index_by_sw_if_index) < sw_if_index)
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
