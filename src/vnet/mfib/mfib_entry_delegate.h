/*
 * Copyright (c) 2018 Cisco and/or its affiliates.
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

#ifndef __MFIB_ENTRY_DELEGATE_T__
#define __MFIB_ENTRY_DELEGATE_T__

#include <vnet/fib/fib_node.h>

/**
 * Delegate types
 */
typedef enum mfib_entry_delegate_type_t_ {
    /**
     * Dependency list of covered entries.
     * these are more specific entries that are interested in changes
     * to their respective cover
     */
    MFIB_ENTRY_DELEGATE_COVERED,
} mfib_entry_delegate_type_t;

#define FOR_EACH_MFIB_DELEGATE(_entry, _fdt, _fed, _body)      \
{                                                              \
    for (_fdt = MFIB_ENTRY_DELEGATE_CHAIN_UNICAST_IP4;         \
         _fdt <= MFIB_ENTRY_DELEGATE_ATTACHED_EXPORT;          \
         _fdt++)                                               \
    {                                                          \
        _fed = mfib_entry_delegate_get(_entry, _fdt);          \
        if (NULL != _fed) {                                    \
            _body;                                             \
        }                                                      \
    }                                                          \
}

/**
 * A Delagate is a means to implmenet the Delagation design pattern; the extension of an
 * objects functionality through the composition of, and delgation to, other objects.
 * These 'other' objects are delegates. Delagates are thus attached to other MFIB objects
 * to extend their functionality.
 */
typedef struct mfib_entry_delegate_t_
{
    /**
     * The MFIB entry object to which the delagate is attached
     */
    fib_node_index_t mfd_entry_index;

    /**
     * The delagate type
     */
    mfib_entry_delegate_type_t mfd_type;

    /**
     * A union of data for the different delegate types
     * These delegates are stored in a sparse vector on the entry, so they
     * must all be of the same size.
     */
    union
    {
        /**
         * For the cover tracking. The node list;
         */
        fib_node_list_t mfd_list;
    };
} mfib_entry_delegate_t;

struct mfib_entry_t_;

extern void mfib_entry_delegate_remove(struct mfib_entry_t_ *mfib_entry,
                                      mfib_entry_delegate_type_t type);

extern mfib_entry_delegate_t *mfib_entry_delegate_find_or_add(struct mfib_entry_t_ *mfib_entry,
                                                            mfib_entry_delegate_type_t fdt);
extern mfib_entry_delegate_t *mfib_entry_delegate_get(const struct mfib_entry_t_ *mfib_entry,
                                                    mfib_entry_delegate_type_t type);

extern u8 *format_mfib_entry_deletegate(u8 * s, va_list * args);

#endif
