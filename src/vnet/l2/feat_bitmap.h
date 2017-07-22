/*
 * feat_bitmap.h: bitmap for managing feature invocation
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

#ifndef included_vnet_l2_feat_bitmap_h
#define included_vnet_l2_feat_bitmap_h

#include <vlib/vlib.h>
#include <vnet/vnet.h>

/*
 * The feature bitmap is a way of organizing input and output feature graph nodes.
 * The set of features to be executed are arranged in a bitmap with one bit per
 * feature and each bit positioned in the same order that the features should be
 * executed. Features can be dynamically removed from the set by masking off their
 * corresponding bits. The bitmap is stored in packet context. Each feature clears
 * its bit and then calls feat_bitmap_get_next_node_index() to go to the next
 * graph node.
 */


/* 32 features in a u32 bitmap */
#define FEAT_MAX 32

/**
 Initialize the feature next-node indexes of a graph node.
 Should be called by the init function of each feature graph node.
*/
always_inline void
feat_bitmap_init_next_nodes (vlib_main_t * vm, u32 node_index,	/* the current graph node index  */
			     u32 num_features,	/* number of entries in feat_names */
			     char **feat_names,	/* array of feature graph node names */
			     u32 * next_nodes)	/* array of 32 next indexes to init */
{
  u32 idx;

  ASSERT (num_features <= FEAT_MAX);

  for (idx = 0; idx < num_features; idx++)
    {
      if (vlib_get_node_by_name (vm, (u8 *) feat_names[idx]))
	{
	  next_nodes[idx] =
	    vlib_node_add_named_next (vm, node_index, feat_names[idx]);
	}
      else
	{			// Node may be in plugin which is not installed, use drop node
	  next_nodes[idx] =
	    vlib_node_add_named_next (vm, node_index, "feature-bitmap-drop");
	}
    }

  /* All unassigned bits go to the drop node */
  for (; idx < FEAT_MAX; idx++)
    {
      next_nodes[idx] = vlib_node_add_named_next (vm, node_index,
						  "feature-bitmap-drop");
    }
}

/**
 Return the graph node index for the feature corresponding to the
 first set bit in the bitmap.
*/
always_inline u32
feat_bitmap_get_next_node_index (u32 * next_nodes, u32 bitmap)
{
  u32 first_bit;

  count_leading_zeros (first_bit, bitmap);
  first_bit = uword_bits - 1 - first_bit;
  return next_nodes[first_bit];
}

/**
 Return the graph node index for the feature corresponding to the next
 set bit after clearing the current feature bit in the feature_bitmap
 of the current packet.
*/
always_inline u32
vnet_l2_feature_next (vlib_buffer_t * b, u32 * next_nodes, u32 feat_bit)
{
  vnet_buffer (b)->l2.feature_bitmap &= ~feat_bit;
  u32 fb = vnet_buffer (b)->l2.feature_bitmap;
  ASSERT (fb != 0);
  return feat_bitmap_get_next_node_index (next_nodes, fb);
}

#endif /* included_vnet_l2_feat_bitmap_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
