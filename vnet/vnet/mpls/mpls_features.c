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

static char * feature_start_nodes[] =
{
    "mpls-input",
};

clib_error_t *
mpls_feature_init (vlib_main_t * vm)
{
  ip_config_main_t * cm = &mpls_main.rx_config_mains;
  vnet_config_main_t * vcm = &cm->config_main;

  return (ip_feature_init_cast (vm, cm, vcm,
                                feature_start_nodes,
                                ARRAY_LEN(feature_start_nodes),
                                VNET_IP_RX_UNICAST_FEAT,
                                VNET_L3_PACKET_TYPE_MPLS_UNICAST));
}

static clib_error_t *
mpls_sw_interface_add_del (vnet_main_t * vnm,
                           u32 sw_if_index,
                           u32 is_add)
{
  vlib_main_t * vm = vnm->vlib_main;
  mpls_main_t * mm = &mpls_main;
  ip_config_main_t * cm = &mm->rx_config_mains;
  vnet_config_main_t * vcm = &cm->config_main;
  u32 drop_feature_index;
  u32 ci;

  vec_validate_init_empty (mm->mpls_enabled_by_sw_if_index, sw_if_index, 0);
  vec_validate_init_empty (mm->fib_index_by_sw_if_index, sw_if_index, 0);
  vec_validate_init_empty (cm->config_index_by_sw_if_index, sw_if_index, ~0);
  ci = cm->config_index_by_sw_if_index[sw_if_index];

  drop_feature_index = mm->mpls_rx_feature_not_enabled;

  if (is_add)
    ci = vnet_config_add_feature (vm, vcm, ci,
                                  drop_feature_index,
                                  /* config data */ 0,
                                  /* # bytes of config data */ 0);
  else
   {
     ci = vnet_config_del_feature (vm, vcm, ci,
                                   drop_feature_index,
                                   /* config data */ 0,
                                   /* # bytes of config data */ 0);
     mm->mpls_enabled_by_sw_if_index[sw_if_index] = 0;;
   }

  cm->config_index_by_sw_if_index[sw_if_index] = ci;

  return /* no error */ 0;
}

VNET_SW_INTERFACE_ADD_DEL_FUNCTION (mpls_sw_interface_add_del);

static clib_error_t *
show_mpls_features_command_fn (vlib_main_t * vm,
                               unformat_input_t * input,
                               vlib_cli_command_t * cmd)
{
  mpls_main_t * mm = &mpls_main;
  int i;
  char ** features;

  vlib_cli_output (vm, "Available MPLS feature nodes");

  do {
    features = mm->feature_nodes;
    for (i = 0; i < vec_len(features); i++)
      vlib_cli_output (vm, "  %s\n", features[i]);
  } while(0);

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
  mpls_main_t * mm = &mpls_main;

  ip_config_main_t * cm;
  vnet_config_main_t * vcm;
  vnet_config_t * cfg;
  u32 cfg_index;
  vnet_config_feature_t * feat;
  vlib_node_t * n;
  u32 sw_if_index;
  u32 node_index;
  u32 current_config_index;
  int i;

  if (! unformat (input, "%U", unformat_vnet_sw_interface,
                  vnm, &sw_if_index))
    return clib_error_return (0, "Interface not specified...");

  vlib_cli_output (vm, "MPLS feature paths configured on %U...",
                   format_vnet_sw_if_index_name, vnm, sw_if_index);

  cm = &mm->rx_config_mains;
  vcm = &cm->config_main;

  current_config_index = vec_elt (cm->config_index_by_sw_if_index,
                                  sw_if_index);

  ASSERT(current_config_index
         < vec_len (vcm->config_pool_index_by_user_index));

  cfg_index =
      vcm->config_pool_index_by_user_index[current_config_index];
  cfg = pool_elt_at_index (vcm->config_pool, cfg_index);

  for (i = 0; i < vec_len(cfg->features); i++)
  {
      feat = cfg->features + i;
      node_index = feat->node_index;
      n = vlib_get_node (vm, node_index);
      vlib_cli_output (vm, "  %v", n->name);
  }

  return 0;
}

VLIB_CLI_COMMAND (show_mpls_interface_features_command, static) = {
  .path = "show mpls interface features",
  .short_help = "show mpls interface features <intfc>",
  .function = show_mpls_interface_features_command_fn,
};

