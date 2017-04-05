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

#ifndef __FIB_ENTRY_DELEGATE_T__
#define __FIB_ENTRY_DELEGATE_T__

#include <vnet/fib/fib_node.h>

/**
 * Delegate types
 */
typedef enum fib_entry_delegate_type_t_ {
    /**
     * Forwarding chain types:
     * for the vast majority of FIB entries only one chain is required - the
     * one that forwards traffic matching the fib_entry_t's fib_prefix_t. For those
     * fib_entry_t that are a resolution target for other fib_entry_t's they will also
     * need the chain to provide forwarding for those children. We store these additional
     * chains in delegates to save memory in the common case.
     */
    FIB_ENTRY_DELEGATE_CHAIN_UNICAST_IP4 = FIB_FORW_CHAIN_TYPE_UNICAST_IP4,
    FIB_ENTRY_DELEGATE_CHAIN_UNICAST_IP6 = FIB_FORW_CHAIN_TYPE_UNICAST_IP6,
    FIB_ENTRY_DELEGATE_CHAIN_MPLS_EOS = FIB_FORW_CHAIN_TYPE_MPLS_EOS,
    FIB_ENTRY_DELEGATE_CHAIN_MPLS_NON_EOS = FIB_FORW_CHAIN_TYPE_MPLS_NON_EOS,
    FIB_ENTRY_DELEGATE_CHAIN_ETHERNET = FIB_FORW_CHAIN_TYPE_ETHERNET,
    FIB_ENTRY_DELEGATE_CHAIN_NSH = FIB_FORW_CHAIN_TYPE_NSH,
    /**
     * Dependency list of covered entries.
     * these are more specific entries that are interested in changes
     * to their respective cover
     */
    FIB_ENTRY_DELEGATE_COVERED,
    /**
     * BFD session state
     */
    FIB_ENTRY_DELEGATE_BFD,
    /**
     * Attached import/export functionality
     */
    FIB_ENTRY_DELEGATE_ATTACHED_IMPORT,
    FIB_ENTRY_DELEGATE_ATTACHED_EXPORT,
} fib_entry_delegate_type_t;

#define FOR_EACH_DELEGATE_CHAIN(_entry, _fdt, _fed, _body)    \
{                                                             \
    for (_fdt = FIB_ENTRY_DELEGATE_CHAIN_UNICAST_IP4;         \
         _fdt <= FIB_ENTRY_DELEGATE_CHAIN_NSH;                \
         _fdt++)                                              \
    {                                                         \
        _fed = fib_entry_delegate_get(_entry, _fdt);          \
        if (NULL != _fed) {                                   \
            _body;                                            \
        }                                                     \
    }                                                         \
}
#define FOR_EACH_DELEGATE(_entry, _fdt, _fed, _body)          \
{                                                             \
    for (_fdt = FIB_ENTRY_DELEGATE_CHAIN_UNICAST_IP4;         \
         _fdt <= FIB_ENTRY_DELEGATE_ATTACHED_EXPORT;          \
         _fdt++)                                              \
    {                                                         \
        _fed = fib_entry_delegate_get(_entry, _fdt);          \
        if (NULL != _fed) {                                   \
            _body;                                            \
        }                                                     \
    }                                                         \
}

/**
 * Distillation of the BFD session states into a go/no-go for using
 * the associated tracked FIB entry
 */
typedef enum fib_bfd_state_t_
{
    FIB_BFD_STATE_UP,
    FIB_BFD_STATE_DOWN,
} fib_bfd_state_t;

/**
 * A Delagate is a means to implmenet the Delagation design pattern; the extension of an
 * objects functionality through the composition of, and delgation to, other objects.
 * These 'other' objects are delegates. Delagates are thus attached to other FIB objects
 * to extend their functionality.
 */
typedef struct fib_entry_delegate_t_
{
    /**
     * The FIB entry object to which the delagate is attached
     */
    fib_node_index_t fd_entry_index;

    /**
     * The delagate type
     */
    fib_entry_delegate_type_t fd_type;

    /**
     * A union of data for the different delegate types
     * These delegates are stored in a sparse vector on the entry, so they
     * must all be of the same size. We could use indirection here for all types,
     * i.e. store an index, that's ok for large delegates, like the attached export
     * but for the chain delegates it's excessive
     */
    union
    {
        /**
         * Valid for the forwarding chain delegates. The LB that is built.
         */
        dpo_id_t fd_dpo;

        /**
         * Valid for the attached import cases. An index of the importer/exporter
         */
        fib_node_index_t fd_index;

        /**
         * For the cover tracking. The node list;
         */
        fib_node_list_t fd_list;

        /**
         * BFD state
         */
        fib_bfd_state_t fd_bfd_state;
    };
} fib_entry_delegate_t;

struct fib_entry_t_;

extern void fib_entry_delegate_remove(struct fib_entry_t_ *fib_entry,
                                      fib_entry_delegate_type_t type);

extern fib_entry_delegate_t *fib_entry_delegate_find_or_add(struct fib_entry_t_ *fib_entry,
                                                            fib_entry_delegate_type_t fdt);
extern fib_entry_delegate_t *fib_entry_delegate_get(const struct fib_entry_t_ *fib_entry,
                                                    fib_entry_delegate_type_t type);

extern fib_forward_chain_type_t fib_entry_delegate_type_to_chain_type(
    fib_entry_delegate_type_t type);

extern fib_entry_delegate_type_t fib_entry_chain_type_to_delegate_type(
     fib_forward_chain_type_t type);

extern u8 *format_fib_entry_deletegate(u8 * s, va_list * args);

#endif
