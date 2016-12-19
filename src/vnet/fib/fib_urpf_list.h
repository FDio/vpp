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
 * @brief A unicast RPF list.
 * The uRPF list is the set of interfaces that a prefix can be reached through.
 * There are 3 levels of RPF check:
 *   - do we have any route to the source (i.e. it's not drop)
 *   - did the packet arrive on an interface that the source is reachable through
 *   - did the packet arrive from a peer that the source is reachable through
 * we don't support the last. But it could be done by storing adjs in the uPRF
 * list rather than interface indices.
 *
 * these conditions are checked against the list by:
 *   - the list is not empty
 *   - there is an interface in the list that is on the input interface.
 *   - there is an adj in the list whose MAC address matches the packet's
 *     source MAC and input interface.
 *
 * To speed the last two checks the interface list only needs to have the unique
 * interfaces present. If the uRPF check was instead implemented by forward
 * walking the DPO chain, then that walk would encounter a great deal of
 * non-adjacency objects (i.e. load-balances, mpls-labels, etc) and potentially
 * the same adjacency many times (esp. when UCMP is used).
 * To that end the uRPF list is a collapsed, unique interface only list.
 */

#ifndef __FIB_URPF_LIST_H__
#define __FIB_URPF_LIST_H__

#include <vnet/fib/fib_types.h>
#include <vnet/adj/adj.h>

/**
 * @brief flags
 */
typedef enum fib_urpf_list_flag_t_
{
    /**
     * @brief Set to indicated that the uRPF list has already been baked.
     * This is protection against it being baked more than once. These
     * are not chunky fries - once is enough.
     */
    FIB_URPF_LIST_BAKED = (1 << 0),
} fib_urpf_list_flag_t;

typedef struct fib_urpf_list_t_
{
    /**
     * The list of interfaces that comprise the allowed accepting interfaces
     */
    adj_index_t *furpf_itfs;

    /**
     * flags
     */
    fib_urpf_list_flag_t furpf_flags;

    /**
     * uRPF lists are shared amongst many entries so we require a locking
     * mechanism.
     */
    u32 furpf_locks;
} fib_urpf_list_t;

extern index_t fib_urpf_list_alloc_and_lock(void);
extern void fib_urpf_list_unlock(index_t urpf);
extern void fib_urpf_list_lock(index_t urpf);

extern void fib_urpf_list_append(index_t urpf, adj_index_t adj);
extern void fib_urpf_list_combine(index_t urpf1, index_t urpf2);

extern void fib_urpf_list_bake(index_t urpf);

extern u8 *format_fib_urpf_list(u8 *s, va_list ap);

extern void fib_urpf_list_show_mem(void);

/**
 * @brief pool of all fib_urpf_list
 */
extern fib_urpf_list_t *fib_urpf_list_pool;

static inline fib_urpf_list_t *
fib_urpf_list_get (index_t index)
{
    return (pool_elt_at_index(fib_urpf_list_pool, index));
}

/**
 * @brief Data-Plane function to check an input interface against an uRPF list
 *
 * @param ui The uRPF list index to check against. Get this from the load-balance
 *             object that is the result of the FIB lookup
 * @param sw_if_index The SW interface index to validate
 *
 * @return 1 if the interface is found, 0 otherwise
 */
always_inline int
fib_urpf_check (index_t ui, u32 sw_if_index)
{
    fib_urpf_list_t *urpf;
    u32 *swi;

    urpf = fib_urpf_list_get(ui);

    vec_foreach(swi, urpf->furpf_itfs)
    {
	if (*swi == sw_if_index)
	    return (1);
    }

    return (0);
}

/**
 * @brief Data-Plane function to check the size of an uRPF list, (i.e. the number
 *        of interfaces in the list).
 *
 * @param ui The uRPF list index to check against. Get this from the load-balance
 *             object that is the result of the FIB lookup
 *
 * @return the number of interfaces in the list
 */
always_inline int
fib_urpf_check_size (index_t ui)
{
    fib_urpf_list_t *urpf;

    urpf = fib_urpf_list_get(ui);

    return (vec_len(urpf->furpf_itfs));
}

#endif
