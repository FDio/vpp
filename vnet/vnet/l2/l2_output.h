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

  u32 feature_bitmap;

  /*
   * vlan tag rewrite for ingress and egress
   * ingress vtr is located here because the same config data is used for
   * the egress EFP filter check
   */
  vtr_config_t input_vtr;
  vtr_config_t output_vtr;
  ptr_config_t input_pbb_vtr;
  ptr_config_t output_pbb_vtr;

  /* some of these flags may get integrated into the feature bitmap */
  u8 fwd_enable;
  u8 flood_enable;

  /* split horizon group */
  u8 shg;

  /* flag for output vtr operation */
  u8 out_vtr_flag;

} l2_output_config_t;


/*
 * The set of next nodes for features and interface output.
 * Each output feature node should include this.
 */
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
  u32 feat_next_node_index[32];

} l2_output_next_nodes_st;


typedef struct
{
  /* Next nodes for features and output interfaces */
  l2_output_next_nodes_st next_nodes;

  /* config vector indexed by sw_if_index */
  l2_output_config_t *configs;

  /* Convenience variables */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;
} l2output_main_t;

l2output_main_t l2output_main;

/* L2 output features */

/* Mappings from feature ID to graph node name */
#define foreach_l2output_feat \
 _(OUTPUT,            "interface-output")           \
 _(SPAN,              "feature-bitmap-drop")        \
 _(CFM,               "feature-bitmap-drop")        \
 _(QOS,               "feature-bitmap-drop")        \
 _(ACL,               "l2-output-acl")              \
 _(L2PT,              "feature-bitmap-drop")        \
 _(EFP_FILTER,        "l2-efp-filter")              \
 _(IPIW,              "feature-bitmap-drop")        \
 _(STP_BLOCKED,       "feature-bitmap-drop")        \
 _(LINESTATUS_DOWN,   "feature-bitmap-drop")        \
 _(OUTPUT_CLASSIFY,   "l2-output-classify")	    \
 _(XCRW,	      "l2-xcrw")

/* Feature bitmap positions */
typedef enum
{
#define _(sym,str) L2OUTPUT_FEAT_##sym##_BIT,
  foreach_l2output_feat
#undef _
    L2OUTPUT_N_FEAT,
} l2output_feat_t;

/* Feature bit masks */
typedef enum
{
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
_(MAPPING_DROP, "L2 Output interface mapping in progress")

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


/**
 * The next set of functions is for use by output feature graph nodes.
 * When the last bit has been cleared from the output feature bitmap,
 * the next node is the output graph node for the TX sw_if_index.
 * These functions help the feature nodes get that node index.
 */

/* Create a mapping to the output graph node for the given sw_if_index */
u32 l2output_create_output_node_mapping (vlib_main_t * vlib_main, vnet_main_t * vnet_main, u32 node_index,	/* index of current node */
					 u32 * output_node_index_vec,
					 u32 sw_if_index);

/* Initialize the next node mapping table */
always_inline void
l2output_init_output_node_vec (u32 ** output_node_index_vec)
{

  /*
   * Size it at 100 sw_if_indexes initially
   * Uninitialized mappings are set to ~0
   */
  vec_validate_init_empty (*output_node_index_vec, 100, ~0);
}


/**
 *  Get a mapping from the output node mapping table,
 * creating the entry if necessary.
 */
always_inline u32
l2output_get_output_node (vlib_main_t * vlib_main, vnet_main_t * vnet_main, u32 node_index,	/* index of current node */
			  u32 sw_if_index, u32 ** output_node_index_vec)	/* may be updated */
{
  u32 next;			/* index of next graph node */

  /* Insure the vector is big enough */
  vec_validate_init_empty (*output_node_index_vec, sw_if_index, ~0);

  /* Get the mapping for the sw_if_index */
  next = vec_elt (*output_node_index_vec, sw_if_index);

  if (next == ~0)
    {
      /* Mapping doesn't exist so create it */
      next = l2output_create_output_node_mapping (vlib_main,
						  vnet_main,
						  node_index,
						  *output_node_index_vec,
						  sw_if_index);
    }

  return next;
}


/** Determine the next L2 node based on the output feature bitmap */
always_inline void
l2_output_dispatch (vlib_main_t * vlib_main,
		    vnet_main_t * vnet_main,
		    vlib_node_runtime_t * node,
		    u32 node_index,
		    u32 * cached_sw_if_index,
		    u32 * cached_next_index,
		    l2_output_next_nodes_st * next_nodes,
		    vlib_buffer_t * b0,
		    u32 sw_if_index, u32 feature_bitmap, u32 * next0)
{
  /*
   * The output feature bitmap always have at least the output feature bit set
   * for a normal L2 interface (or all 0's if the interface is changed from L2
   * to L3 mode). So if next_nodes specified is that from the l2-output node and
   * the bitmap is all clear except output feature bit, we know there is no more
   * feature and will fall through to output packet. If next_nodes is from a L2
   * output feature node (and not l2-output), we always want to get the node for
   * the next L2 output feature, including the last feature being interface-
   * output node to output packet.
   */
  if ((next_nodes != &l2output_main.next_nodes)
      || ((feature_bitmap & ~L2OUTPUT_FEAT_OUTPUT) != 0))
    {
      /* There are some features to execute */
      ASSERT (feature_bitmap != 0);

      /* Save bitmap for the next feature graph nodes */
      vnet_buffer (b0)->l2.feature_bitmap = feature_bitmap;

      /* Determine the next node */
      *next0 =
	feat_bitmap_get_next_node_index (next_nodes->feat_next_node_index,
					 feature_bitmap);
    }
  else
    {
      /*
       * There are no features. Send packet to TX node for sw_if_index0
       * This is a little tricky in that the output interface next node indexes
       * are not precomputed at init time.
       */

      if (sw_if_index == *cached_sw_if_index)
	{
	  /* We hit in the one-entry cache. Use it. */
	  *next0 = *cached_next_index;
	}
      else
	{
	  /* Look up the output TX node */
	  *next0 = l2output_get_output_node (vlib_main,
					     vnet_main,
					     node_index,
					     sw_if_index,
					     &next_nodes->output_node_index_vec);

	  if (*next0 == L2OUTPUT_NEXT_DROP)
	    {
	      vnet_hw_interface_t *hw0;
	      hw0 = vnet_get_sup_hw_interface (vnet_main, sw_if_index);

	      if (hw0->flags & VNET_HW_INTERFACE_FLAG_L2OUTPUT_MAPPED)
		b0->error = node->errors[L2OUTPUT_ERROR_MAPPING_DROP];
	    }

	  /* Update the one-entry cache */
	  *cached_sw_if_index = sw_if_index;
	  *cached_next_index = *next0;
	}
    }
}

/** Get a pointer to the config for the given interface */
l2_output_config_t *l2output_intf_config (u32 sw_if_index);

/** Enable (or disable) the feature in the bitmap for the given interface */
void l2output_intf_bitmap_enable (u32 sw_if_index,
				  u32 feature_bitmap, u32 enable);

#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
