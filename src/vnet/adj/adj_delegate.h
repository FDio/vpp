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

#ifndef __ADJ_DELEGATE_T__
#define __ADJ_DELEGATE_T__

#include <vnet/adj/adj.h>

/**
 * Delegate types
 */
typedef enum adj_delegate_type_t_ {
    /**
     * BFD session state
     */
    ADJ_DELEGATE_BFD,
} adj_delegate_type_t;

#define FOR_EACH_ADJ_DELEGATE(_adj, _adt, _aed, _body)        \
{                                                             \
    for (_adt = ADJ_DELEGATE_BFD;                             \
         _adt <= ADJ_DELEGATE_BFD;                            \
         _adt++)                                              \
    {                                                         \
        _aed = adj_delegate_get(_adj, _adt);                  \
        if (NULL != _aed) {                                   \
            _body;                                            \
        }                                                     \
    }                                                         \
}

/**
 * Distillation of the BFD session states into a go/no-go for using
 * the associated tracked adjacency
 */
typedef enum adj_bfd_state_t_
{
    ADJ_BFD_STATE_DOWN,
    ADJ_BFD_STATE_UP,
} adj_bfd_state_t;

/**
 * A Delagate is a means to implement the Delagation design pattern;
 * the extension of an object's functionality through the composition of,
 * and delgation to, other objects.
 * These 'other' objects are delegates. Delagates are thus attached to
 * ADJ objects to extend their functionality.
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

    /**
     * A union of data for the different delegate types
     */
    union
    {
        /**
         * BFD delegate daa
         */
        struct {
            /**
             * BFD session state
             */
            adj_bfd_state_t ad_bfd_state;
            /**
             * BFD session index
             */
            u32 ad_bfd_index;
        };
    };
} adj_delegate_t;

extern void adj_delegate_remove(ip_adjacency_t *adj,
                                adj_delegate_type_t type);

extern adj_delegate_t *adj_delegate_find_or_add(ip_adjacency_t *adj,
                                                adj_delegate_type_t fdt);
extern adj_delegate_t *adj_delegate_get(const ip_adjacency_t *adj,
                                        adj_delegate_type_t type);

extern u8 *format_adj_deletegate(u8 * s, va_list * args);

#endif
