/*
 * mpls_features.c: MPLS input and output features
 *
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

#include <vnet/mpls/mpls.h>

always_inline uword
mpls_terminate (vlib_main_t * vm,
                vlib_node_runtime_t * node,
                vlib_frame_t * frame,
                int error_code)
{
  u32 * buffers = vlib_frame_vector_args (frame);
  uword n_packets = frame->n_vectors;

  vlib_error_drop_buffers (vm, node,
                           buffers,
                           /* stride */ 1,
                           n_packets,
                           /* next */ 0,
                           mpls_input_node.index,
                           error_code);

  return n_packets;
}

static uword
mpls_punt (vlib_main_t * vm,
           vlib_node_runtime_t * node,
           vlib_frame_t * frame)
{
    return (mpls_terminate(vm, node, frame, MPLS_ERROR_PUNT));
}

VLIB_REGISTER_NODE (mpls_punt_node) = {
  .function = mpls_punt,
  .name = "mpls-punt",
  .vector_size = sizeof (u32),

  .n_next_nodes = 1,
  .next_nodes = {
    [0] = "error-punt",
  },
};

VLIB_NODE_FUNCTION_MULTIARCH (mpls_punt_node, mpls_punt)

static uword
mpls_drop (vlib_main_t * vm,
           vlib_node_runtime_t * node,
           vlib_frame_t * frame)
{
    return (mpls_terminate(vm, node, frame, MPLS_ERROR_DROP));
}

VLIB_REGISTER_NODE (mpls_drop_node) = {
  .function = mpls_drop,
  .name = "mpls-drop",
  .vector_size = sizeof (u32),

  .n_next_nodes = 1,
  .next_nodes = {
    [0] = "error-drop",
  },
};

VLIB_NODE_FUNCTION_MULTIARCH (mpls_drop_node, mpls_drop)

static uword
mpls_not_enabled (vlib_main_t * vm,
                  vlib_node_runtime_t * node,
                  vlib_frame_t * frame)
{
    return (mpls_terminate(vm, node, frame, MPLS_ERROR_NOT_ENABLED));
}

VLIB_REGISTER_NODE (mpls_not_enabled_node) = {
  .function = mpls_not_enabled,
  .name = "mpls-not-enabled",
  .vector_size = sizeof (u32),

  .n_next_nodes = 1,
  .next_nodes = {
    [0] = "error-drop",
  },
};

VLIB_NODE_FUNCTION_MULTIARCH (mpls_not_enabled_node, mpls_not_enabled)

VNET_MPLS_FEATURE_INIT (mpls_lookup, static) = {
  .node_name = "mpls-lookup",
  .runs_before = ORDER_CONSTRAINTS {"mpls-not-enabled", 0},
  .feature_index = &mpls_main.mpls_rx_feature_lookup,
};

VNET_MPLS_FEATURE_INIT (mpls_not_enabled, static) = {
  .node_name = "mpls-not-enabled",
  .runs_before = ORDER_CONSTRAINTS {0}, /* not before any other features */
  .feature_index = &mpls_main.mpls_rx_feature_not_enabled,
};

/* Built-in ip4 tx feature path definition */
VNET_MPLS_TX_FEATURE_INIT (interface_output, static) = {
  .node_name = "interface-output",
  .runs_before = 0, /* not before any other features */
  .feature_index = &mpls_main.mpls_tx_feature_interface_output,
};


static char * rx_feature_start_nodes[] =
{
    "mpls-input",
};
static char * tx_feature_start_nodes[] = 
{
    "mpls-output",
    "mpls-midchain",
};

clib_error_t *
mpls_feature_init (vlib_main_t * vm)
{
  ip_config_main_t * cm = &mpls_main.feature_config_mains[VNET_IP_RX_UNICAST_FEAT];
  vnet_config_main_t * vcm = &cm->config_main;
  clib_error_t *error;

  if ((error = ip_feature_init_cast (vm, cm, vcm,
				     rx_feature_start_nodes,
				     ARRAY_LEN(rx_feature_start_nodes),
				     mpls_main.next_feature[VNET_IP_RX_UNICAST_FEAT],
				     &mpls_main.feature_nodes[VNET_IP_RX_UNICAST_FEAT])))
      return error;

  cm  = &mpls_main.feature_config_mains[VNET_IP_TX_FEAT];
  vcm = &cm->config_main;

  if ((error = ip_feature_init_cast (vm, cm, vcm,
				     tx_feature_start_nodes,
				     ARRAY_LEN(tx_feature_start_nodes),
				     mpls_main.next_feature[VNET_IP_TX_FEAT],
				     &mpls_main.feature_nodes[VNET_IP_TX_FEAT])))
      return error;

  return error;
}

static clib_error_t *
mpls_sw_interface_add_del (vnet_main_t * vnm,
                           u32 sw_if_index,
                           u32 is_add)
{
  vlib_main_t * vm = vnm->vlib_main;
  mpls_main_t * mm = &mpls_main;
  u32 feature_index;
  u32 ci, cast;

  for (cast = 0; cast < VNET_N_IP_FEAT; cast++)
  {
      ip_config_main_t * cm = &mm->feature_config_mains[cast];
      vnet_config_main_t * vcm = &cm->config_main;

      if (VNET_IP_RX_MULTICAST_FEAT == cast)
	  continue;

      vec_validate_init_empty (mm->mpls_enabled_by_sw_if_index, sw_if_index, 0);
      vec_validate_init_empty (mm->fib_index_by_sw_if_index, sw_if_index, 0);
      vec_validate_init_empty (cm->config_index_by_sw_if_index, sw_if_index, ~0);
      ci = cm->config_index_by_sw_if_index[sw_if_index];

       if (cast == VNET_IP_RX_UNICAST_FEAT)
	   feature_index = mm->mpls_rx_feature_not_enabled;
       else
	   feature_index = mm->mpls_tx_feature_interface_output;


      if (is_add)
	  ci = vnet_config_add_feature (vm, vcm, ci,
					feature_index,
					/* config data */ 0,
					/* # bytes of config data */ 0);
      else
      {
	  ci = vnet_config_del_feature (vm, vcm, ci,
					feature_index,
					/* config data */ 0,
					/* # bytes of config data */ 0);
	  mm->mpls_enabled_by_sw_if_index[sw_if_index] = 0;;
      }
      cm->config_index_by_sw_if_index[sw_if_index] = ci;
  }

  return /* no error */ 0;
}

VNET_SW_INTERFACE_ADD_DEL_FUNCTION (mpls_sw_interface_add_del);

#define foreach_af_cast                         \
_(VNET_IP_RX_UNICAST_FEAT, "mpls input")        \
_(VNET_IP_TX_FEAT, "mpls output")               \

static clib_error_t *
show_mpls_features_command_fn (vlib_main_t * vm,
                               unformat_input_t * input,
                               vlib_cli_command_t * cmd)
{
  mpls_main_t * mm = &mpls_main;
  int i;
  char ** features;

  vlib_cli_output (vm, "Available MPLS feature nodes");

#define _(c,s)                                          \
  do {                                                  \
    features = mm->feature_nodes[c];                    \
    vlib_cli_output (vm, "%s:", s);                     \
    for (i = 0; i < vec_len(features); i++)             \
      vlib_cli_output (vm, "  %s\n", features[i]);      \
  } while(0);
  foreach_af_cast;
#undef _

  return 0;
}

VLIB_CLI_COMMAND (show_ip_features_command, static) = {
  .path = "show mpls features",
  .short_help = "show mpls features",
  .function = show_mpls_features_command_fn,
};

static clib_error_t *
show_mpls_interface_features_command_fn (vlib_main_t * vm,
                                         unformat_input_t * input,
                                         vlib_cli_command_t * cmd)
{
  vnet_main_t * vnm = vnet_get_main();
  u32 sw_if_index;

  if (! unformat (input, "%U", unformat_vnet_sw_interface,
                  vnm, &sw_if_index))
    return clib_error_return (0, "Interface not specified...");

  vlib_cli_output (vm, "MPLS feature paths configured on %U...",
                   format_vnet_sw_if_index_name, vnm, sw_if_index);

  ip_interface_features_show (vm, "MPLS", 
			      mpls_main.feature_config_mains,
			      sw_if_index);

  return 0;
}

VLIB_CLI_COMMAND (show_mpls_interface_features_command, static) = {
  .path = "show mpls interface features",
  .short_help = "show mpls interface features <intfc>",
  .function = show_mpls_interface_features_command_fn,
};

