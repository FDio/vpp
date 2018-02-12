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
 * A Delagate is a means to implement the Delagation design pattern;
 * the extension of an object's functionality through the composition of,
 * and delgation to, other objects.
 * These 'other' objects are delegates. Delagates are thus attached to
 * ADJ objects to extend their functionality.
 */

#ifndef __ADJ_DELEGATE_T__
#define __ADJ_DELEGATE_T__

#include <vnet/adj/adj.h>

/**
 * Built-in delegate types.
 * When adding new types, if your code is within the vnet subsystem, then add a
 * new  type here. If not then use the adj_delegate_register_new_type API to
 * register a new type.
 */
typedef enum adj_delegate_type_t_ {
    /**
     * BFD session state
     */
    ADJ_DELEGATE_BFD,
} adj_delegate_type_t;

/**
 * Adj delegate. This object should be contained within all type specific
 * delegates.  i.e. this is the base class to all type specific derived classes.
 * With this model the delegate provider is free to manage the memory of the
 * delegate in the way it chooses. Specifically it can assign them from its own
 * pools and thus, for example, add the delegates to the FIB node graph.
 */
typedef struct adj_delegate_t_
{
    /**
     * The ADJ entry object to which the delagate is attached
     */
    adj_index_t ad_adj_index;

    /**
     * The delagate type
     */
    adj_delegate_type_t ad_type;
} adj_delegate_t;

/**
 * Indication that the adjacency has been deleted. The delegate provider should free
 * the delegate.
 */
typedef void (*adj_delegate_adj_deleted_t)(adj_delegate_t *aed);

/**
 * Format function for the delegate
 */
typedef u8 * (*adj_delegate_format_t)(const adj_delegate_t *aed, u8 *s);

/**
 * An ADJ delegate virtual function table
 */
typedef struct adj_delegate_vft_t_ {
    adj_delegate_format_t adv_format;
    adj_delegate_adj_deleted_t adv_adj_deleted;
} adj_delegate_vft_t;

/**
 * @brief Remove a delegate from an adjacency
 *
 * @param ai The adjacency to remove the delegate from
 * @param type The type of delegate being removed
 */
extern void adj_delegate_remove(adj_index_t ai,
                                adj_delegate_type_t type);

/**
 * @brief Add a delegate to an adjacency
 *
 * @param ai The adjacency to add the delegate to
 * @param type The type of delegate being added
 * @param ad The delegate. The provider should allocate memory for this object
 *                         Typically this is a 'derived' class with the
 *                         adj_delegate_t struct embedded within.
 */
extern int adj_delegate_add(ip_adjacency_t *adj,
                            adj_delegate_type_t fdt,
                            adj_delegate_t *ad);

/**
 * @brief Get a delegate from an adjacency
 *
 * @param ai The adjacency to get the delegate from
 * @param type The type of delegate being sought
 */
extern adj_delegate_t *adj_delegate_get(const ip_adjacency_t *adj,
                                        adj_delegate_type_t type);

/**
 * @brief Register a VFT for one of the built-in types
 */
extern void adj_delegate_register_type(adj_delegate_type_t type,
                                       const adj_delegate_vft_t *vft);

/**
 * @brief create a new delegate type and register a new VFT
 */
extern adj_delegate_type_t adj_delegate_register_new_type(
    const adj_delegate_vft_t *vft);

#endif
