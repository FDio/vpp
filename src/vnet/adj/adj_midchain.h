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
/**
 * Midchain Adjacency sub-type. These adjs represent an L3 peer on a
 * tunnel interface. The tunnel's adjacency is thus not the end of the chain,
 * and needs to stack on/link to another chain (or portion of the graph) to
 * reach the tunnel's destination.
 */

#ifndef __ADJ_MIDCHAIN_H__
#define __ADJ_MIDCHAIN_H__

#include <vnet/adj/adj.h>

/**
 * @brief
 *  Convert an existing neighbour adjacency into a midchain
 *
 * @param adj_index
 *  The index of the neighbour adjacency.
 *
 * @param post_rewrite_node
 *  The VLIB graph node that provides the post-encap fixup.
 *  where 'fixup' is e.g., correcting chksum, length, etc.
 *
 * @param rewrite
 *  The rewrite.
 */
extern void adj_nbr_midchain_update_rewrite(adj_index_t adj_index,
					    adj_midchain_fixup_t fixup,
					    adj_flags_t flags,
					    u8 *rewrite);

/**
 * @brief
 *  [re]stack a midchain. 'Stacking' is the act of forming parent-child
 *  relationships in the data-plane graph.
 *
 * @param adj_index
 *  The index of the midchain to stack
 *
 * @param dpo
 *  The parent DPO to stack onto (i.e. become a child of).
 */
extern void adj_nbr_midchain_stack(adj_index_t adj_index,
				   const dpo_id_t *dpo);

/**
 * @brief
 *  unstack a midchain. This will break the chain between the midchain and
 *  the next graph section. This is a implemented as stack-on-drop
 *
 * @param adj_index
 *  The index of the midchain to stack
 */
extern void adj_nbr_midchain_unstack(adj_index_t adj_index);

/**
 * @brief
 *  Module initialisation
 */
extern void adj_midchain_module_init(void);

/**
 * @brief
 * Format a midchain adjacency
 */
extern u8* format_adj_midchain(u8* s, va_list *ap);

#endif
