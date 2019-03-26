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
 * @param fixup
 *  The function that will be invoked at paket switch time to 'fixup'
 *  the rewrite applied with necessary per-packet info (i.e. length, checksums).
 * @param fixup_data
 *  Context data set by the caller that is provided as an argument in the
 *  fixup function.
 *
 * @param flags
 *  Flags controlling the adjacency behaviour
 *
 * @param rewrite
 *  The rewrite.
 */
extern void adj_nbr_midchain_update_rewrite(adj_index_t adj_index,
					    adj_midchain_fixup_t fixup,
                                            const void *fixup_data,
					    adj_flags_t flags,
					    u8 *rewrite);

/**
 * @brief
 *  [re]stack a midchain. 'Stacking' is the act of forming parent-child
 *  relationships in the data-plane graph. Do NOT use this function to
 *  stack on a DPO type that might form a loop.
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
 *  [re]stack a midchain. 'Stacking' is the act of forming parent-child
 *  relationships in the data-plane graph. Since function performs recursive
 *  loop detection.
 *
 * @param adj_index
 *  The index of the midchain to stack
 *
 * @param fei
 *  The FIB entry to stack on
 *
 * @param fct
 *  The chain type to use from the fib entry fowarding
 */
extern void adj_nbr_midchain_stack_on_fib_entry(adj_index_t adj_index,
                                                fib_node_index_t fei,
                                                fib_forward_chain_type_t fct);

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
 * @brief descend the FIB graph looking for loops
 *
 * @param ai
 *  The adj index to traverse
 *
 * @param entry_indicies)
 *  A pointer to a vector of FIB entries already visited.
 */
extern int adj_ndr_midchain_recursive_loop_detect(adj_index_t ai,
                                                  fib_node_index_t **entry_indicies);

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

/**
 * @brief
 *  create/attach a midchain delegate and stack it on the prefix passed
 * @param ai - the index of the adjacency to stack
 * @param fib_index - The FIB index of the prefix on which to stack
 * @param pfx - The prefix on which to stack
 */
extern void adj_midchain_delegate_stack(adj_index_t ai,
                                        u32 fib_index,
                                        const fib_prefix_t *pfx);

/**
 * @brief restack a midchain delegate
 */
extern void adj_midchain_delegate_restack(adj_index_t ai);

/**
 * @brief unstack a midchain delegate (this stacks it on a drop)
 */
extern void adj_midchain_delegate_unstack(adj_index_t ai);

#endif
