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

VNET_FEATURE_START_NODES (MPLS_INPUT, "mpls-input");
VNET_FEATURE_START_NODES (MPLS_OUTPUT, "mpls-output", "mpls-midchain");

/* *INDENT-OFF* */
VNET_FEATURE_INIT (MPLS_INPUT, mpls_lookup, static) = {
  .node_name = "mpls-lookup",
  .runs_before = ORDER_CONSTRAINTS {"mpls-not-enabled", 0},
};

VNET_FEATURE_INIT (MPLS_INPUT, mpls_not_enabled, static) = {
  .node_name = "mpls-not-enabled",
  .runs_before = ORDER_CONSTRAINTS {0},
};

VNET_FEATURE_INIT (MPLS_OUTPUT, interface_output, static) = {
  .node_name = "interface-output",
  .runs_before = 0, /* not before any other features */
};

static clib_error_t *
mpls_sw_interface_add_del (vnet_main_t * vnm,
                           u32 sw_if_index,
                           u32 is_add)
{
  vlib_main_t * vm = vnm->vlib_main;
  mpls_main_t * mm = &mpls_main;
  vnet_feature_main_t *fm = &feature_main;
  u32 feature_index;
  u32 ci, cast;

  ASSERT (VNET_FEAT_MPLS_INPUT + 1 == VNET_FEAT_MPLS_OUTPUT);

  for (cast = VNET_FEAT_MPLS_INPUT; cast <= VNET_FEAT_MPLS_OUTPUT; cast++)
  {
      vnet_feature_config_main_t * cm = &fm->feature_config_mains[cast];
      vnet_config_main_t * vcm = &cm->config_main;

      vec_validate_init_empty (mm->mpls_enabled_by_sw_if_index, sw_if_index, 0);
      vec_validate_init_empty (mm->fib_index_by_sw_if_index, sw_if_index, 0);
      vec_validate_init_empty (cm->config_index_by_sw_if_index, sw_if_index, ~0);
      ci = cm->config_index_by_sw_if_index[sw_if_index];

       if (cast == VNET_FEAT_MPLS_INPUT)
	   feature_index = vnet_feature_index_from_node_name (VNET_FEAT_MPLS_INPUT, "mpls-not-enabled");
       else
	   feature_index = vnet_feature_index_from_node_name (VNET_FEAT_MPLS_OUTPUT, "interface-output");

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

