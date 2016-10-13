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

/* *INDENT-OFF* */
VNET_FEATURE_INIT (DEVICE_INPUT, l2_patch, static) = {
  .node_name = "l2_patch",
  .runs_before = ORDER_CONSTRAINTS {"ethernet-input", 0},
};

VNET_FEATURE_INIT (DEVICE_INPUT, worker_handoff, static) = {
  .node_name = "worker-handoff",
  .runs_before = ORDER_CONSTRAINTS {"ethernet-input", 0},
};

VNET_FEATURE_INIT (DEVICE_INPUT, ethernet_input, static) = {
  .node_name = "ethernet-input",
  .runs_before = 0, /* not before any other features */
};
/* *INDENT-ON* */

static char *driver_rx_feature_start_nodes[] = {
#if DPDK > 0
  "dpdk-input",
#endif
  "tuntap-rx",
  "vhost-user-input",
  "af-packet-input",
  "netmap-input",
};

static const char *vnet_driver_feat_names[] = {
#define _(n, s) [VNET_FEAT_##n] = s,
  foreach_vnet_feature_type
#undef _
};

static clib_error_t *
vnet_feature_init (vlib_main_t * vm)
{
  vnet_feature_main_t *fm = &feature_main;
  clib_error_t *error;
  vnet_feature_type_t feature_type;
  ip_config_main_t *cm;
  vnet_config_main_t *vcm;
  char **feature_start_nodes;
  int feature_start_len;

  for (feature_type = 0; feature_type < VNET_N_FEAT_TYPES; feature_type++)
    {
      cm = &fm->feature_config_mains[feature_type];
      vcm = &cm->config_main;

      switch (feature_type)
	{
	case VNET_FEAT_DEVICE_INPUT:
	  feature_start_nodes = driver_rx_feature_start_nodes;
	  feature_start_len = ARRAY_LEN (driver_rx_feature_start_nodes);
	  break;
	default:
	  return clib_error_return (0, "BUG");
	  break;
	}
      if ((error = vnet_feature_arc_init (vm, vcm,
					  feature_start_nodes,
					  feature_start_len,
					  fm->next_feature[feature_type],
					  &fm->feature_nodes[feature_type])))
	{
	  return error;
	}
      fm->next_feature_by_name[feature_type] =
	hash_create_string (0, sizeof (uword));
      vnet_feature_registration_t *reg;
      reg = fm->next_feature[feature_type];

      while (reg)
	{
	  u8 *node_name = format (0, "%s%c", reg->node_name, 0);
	  hash_set_mem (fm->next_feature_by_name[feature_type], node_name,
			pointer_to_uword (reg));
	  vec_free (node_name);

	  reg = reg->next;
	}
    }

  return 0;
}

VLIB_INIT_FUNCTION (vnet_feature_init);

void
vnet_config_update_driver_rx_feature_count (vnet_feature_main_t * fm,
					    u32 sw_if_index, int is_add)
{
  uword bit_value;

  vec_validate (fm->driver_rx_feature_count_by_sw_if_index, sw_if_index);

  fm->driver_rx_feature_count_by_sw_if_index += is_add ? 1 : -1;

  ASSERT (fm->driver_rx_feature_count_by_sw_if_index >= 0);

  bit_value = fm->driver_rx_feature_count_by_sw_if_index[sw_if_index] > 0;

  fm->sw_if_index_has_driver_rx_features =
    clib_bitmap_set (fm->sw_if_index_has_driver_rx_features, sw_if_index,
		     bit_value);
}

u32
vnet_feature_index_from_node_name (const char *s)
{
  vnet_feature_main_t *fm = &feature_main;
  vnet_feature_registration_t *reg;
  uword *p;

  p = hash_get_mem (fm->next_feature_by_name[VNET_FEAT_DEVICE_INPUT], s);
  if (p == 0)
    return ~0;

  reg = uword_to_pointer (p[0], vnet_feature_registration_t *);
  return reg->feature_index_u32;
}

void
vnet_feature_device_input_enable_disable (const char *node_name,
					  u32 sw_if_index, int enable_disable)
{
  vnet_feature_main_t *fm = &feature_main;
  ip_config_main_t *cm = &fm->feature_config_mains[VNET_FEAT_DEVICE_INPUT];
  u32 feature_index, ci;

  vec_validate_init_empty (cm->config_index_by_sw_if_index, sw_if_index, ~0);
  feature_index = vnet_feature_index_from_node_name ("worker-handoff");
  ci = cm->config_index_by_sw_if_index[sw_if_index];

  ci = (enable_disable
	? vnet_config_add_feature
	: vnet_config_del_feature)
    (vlib_get_main (), &cm->config_main, ci, feature_index, 0, 0);
  cm->config_index_by_sw_if_index[sw_if_index] = ci;

  vnet_config_update_driver_rx_feature_count (fm, sw_if_index,
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
  int i;
  char **features;

  vlib_cli_output (vm, "Available feature paths");

#define _(f,s)                                          \
  do {                                                  \
    features = fm->feature_nodes[VNET_FEAT_##f];        \
    vlib_cli_output (vm, "%s:", s);                     \
    for (i = 0; i < vec_len(features); i++)             \
      vlib_cli_output (vm, "  %s\n", features[i]);      \
  } while(0);
  foreach_vnet_feature_type;
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
 */

void
driver_interface_features_show (vlib_main_t * vm,
				ip_config_main_t * cm, u32 sw_if_index)
{
  u32 node_index, current_config_index;
  vnet_feature_type_t feature_type;
  vnet_config_main_t *vcm;
  vnet_config_t *cfg;
  u32 cfg_index;
  vnet_config_feature_t *feat;
  vlib_node_t *n;
  int i;

  vlib_cli_output (vm, "Driver feature paths configured on %U...",
		   format_vnet_sw_if_index_name,
		   vnet_get_main (), sw_if_index);

  for (feature_type = VNET_FEAT_DEVICE_INPUT;
       feature_type < VNET_N_FEAT_TYPES; feature_type++)
    {
      vcm = &(cm[feature_type].config_main);

      vlib_cli_output (vm, "\n%s:", vnet_driver_feat_names[feature_type]);

      if (NULL == cm[feature_type].config_index_by_sw_if_index ||
	  vec_len (cm[feature_type].config_index_by_sw_if_index)
	  < sw_if_index)
	{
	  vlib_cli_output (vm, "none configured");
	  continue;
	}

      current_config_index =
	vec_elt (cm[feature_type].config_index_by_sw_if_index, sw_if_index);

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

static clib_error_t *
show_driver_interface_features_command_fn (vlib_main_t * vm,
					   unformat_input_t * input,
					   vlib_cli_command_t * cmd)
{
  vnet_main_t *vnm = vnet_get_main ();
  vnet_feature_main_t *fm = &feature_main;
  u32 sw_if_index;

  if (!unformat (input, "%U", unformat_vnet_sw_interface, vnm, &sw_if_index))
    return clib_error_return (0, "Interface not specified...");

  driver_interface_features_show (vm, fm->feature_config_mains, sw_if_index);
  return 0;
}

/*?
 * Display the driver features configured on a specific interface
 *
 * @cliexpar
 * Example:
 * @cliexcmd{show driver interface features GigabitEthernet2/0/0}
 * @cliexend
 * @endparblock
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_features_inteface_command, static) = {
  .path = "show features interface",
  .short_help = "show features interfaces <intfc>",
  .function = show_driver_interface_features_command_fn,
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
