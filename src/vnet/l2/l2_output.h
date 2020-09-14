/*
 * l2_output.h : layer 2 output packet processing
 *
 * Copyright (c) 2013 Cisco and/or its affiliates.
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

#ifndef included_vnet_l2_output_h
#define included_vnet_l2_output_h

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/l2/feat_bitmap.h>
#include <vnet/l2/l2_vtr.h>


/* The L2 output feature configuration, a per-interface struct */
typedef struct
{

  /*
   * vlan tag rewrite for ingress and egress
   * ingress vtr is located here because the same config data is used for
   * the egress EFP filter check
   */
  vtr_config_t input_vtr;
  vtr_config_t output_vtr;
  ptr_config_t input_pbb_vtr;
  ptr_config_t output_pbb_vtr;

  u32 feature_bitmap;

  /* split horizon group */
  u8 shg;

  /* flag for output vtr operation */
  u8 out_vtr_flag;

} l2_output_config_t;

typedef struct
{
  /*
   * vector of output next node index, indexed by sw_if_index.
   * used when all output features have been executed and the
   * next nodes are the interface output nodes.
   */
  u32 *output_node_index_vec;

  /*
   * array of next node index for each output feature, indexed
   * by l2output_feat_t. Used to determine next feature node.
   */
  u32 l2_out_feat_next[32];

  /* config vector indexed by sw_if_index */
  l2_output_config_t *configs;

  /* Convenience variables */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;
} l2output_main_t;

extern l2output_main_t l2output_main;

extern vlib_node_registration_t l2output_node;

/* L2 output features */

/* Mappings from feature ID to graph node name in reverse order */
#define foreach_l2output_feat \
 _(OUTPUT,            "interface-output")           \
 _(SPAN,              "span-l2-output")             \
 _(CFM,               "feature-bitmap-drop")        \
 _(QOS,               "feature-bitmap-drop")        \
 _(ACL,               "l2-output-acl")              \
 _(L2PT,              "feature-bitmap-drop")        \
 _(EFP_FILTER,        "l2-efp-filter")              \
 _(IPIW,              "feature-bitmap-drop")        \
 _(STP_BLOCKED,       "feature-bitmap-drop")        \
 _(LINESTATUS_DOWN,   "feature-bitmap-drop")        \
 _(OUTPUT_CLASSIFY,   "l2-output-classify")	    \
 _(OUTPUT_FEAT_ARC,   "l2-output-feat-arc")	    \
 _(XCRW,	      "l2-xcrw")

/* Feature bitmap positions */
typedef enum
{
#define _(sym,str) L2OUTPUT_FEAT_##sym##_BIT,
  foreach_l2output_feat
#undef _
    L2OUTPUT_N_FEAT,
} l2output_feat_t;

STATIC_ASSERT (L2OUTPUT_N_FEAT <= 32, "too many l2 output features");

/* Feature bit masks */
typedef enum
{
  L2OUTPUT_FEAT_NONE = 0,
#define _(sym,str) L2OUTPUT_FEAT_##sym = (1<<L2OUTPUT_FEAT_##sym##_BIT),
  foreach_l2output_feat
#undef _
} l2output_feat_masks_t;

#define foreach_l2output_error				\
_(L2OUTPUT,     "L2 output packets")			\
_(EFP_DROP,     "L2 EFP filter pre-rewrite drops")	\
_(VTR_DROP,     "L2 output tag rewrite drops")		\
_(SHG_DROP,     "L2 split horizon drops")		\
_(DROP,         "L2 output drops")			\
_(MAPPING_DROP, "L2 Output interface not valid")

typedef enum
{
  L2OUTPUT_NEXT_DROP,
  L2OUTPUT_NEXT_BAD_INTF,
  L2OUTPUT_N_NEXT,
} l2output_next_t;

typedef enum
{
#define _(sym,str) L2OUTPUT_ERROR_##sym,
  foreach_l2output_error
#undef _
    L2OUTPUT_N_ERROR,
} l2output_error_t;

/* Return an array of strings containing graph node names of each feature */
char **l2output_get_feat_names (void);

/* arg0 - u32 feature_bitmap, arg1 - u32 verbose */
u8 *format_l2_output_features (u8 * s, va_list * args);

/**
 * The next set of functions is for use by output feature graph nodes.
 * When the last bit has been cleared from the output feature bitmap,
 * the next node is the output graph node for the TX sw_if_index.
 * These functions help the feature nodes get that node index.
 */

/* Create a mapping to the output graph node for the given sw_if_index */
void l2output_create_output_node_mapping (vlib_main_t * vlib_main,
					  vnet_main_t * vnet_main,
					  u32 sw_if_index);

/** Get a pointer to the config for the given interface */
l2_output_config_t *l2output_intf_config (u32 sw_if_index);

/** Enable (or disable) the feature in the bitmap for the given interface */
void l2output_intf_bitmap_enable (u32 sw_if_index,
				  l2output_feat_masks_t feature_bitmap,
				  u32 enable);

#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
