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
 * @brief bier_fmask : The BIER fmask
 *
 * The BIER fmask contains the bitString that is applied to packets that
 * egress towards the next-hop. As such the fmask is part of the rewrite
 * (adj) for that next-hop. It it thus an extension of the next-hop and in
 * no way associated with the bit-position(s) that are reachable through it.
 * Fmasks are thus shared by bit-positions that egress throught the same
 * nh (BFR-NBR).
 * Deag fmasks are also shread in the event that a router has local
 * bit-positions. This is necessary to prevent the router recieving two copies
 * of each packet. Consequently it also means that they share the same
 * disposition data for the global data.
 */

#ifndef __BIER_FMASK_H__
#define __BIER_FMASK_H__

#include <vlib/vlib.h>

#include <vnet/fib/fib_node.h>
#include <vnet/mpls/packet.h>
#include <vnet/dpo/dpo.h>

#include <vnet/bier/bier_types.h>
#include <vnet/bier/bier_fmask_db.h>

/**
 * A struct that represents the reference counting of the bits
 */
typedef struct bier_fmask_bits_t_ {
    /**
     * each bit in the mask needs to be reference counted
     * and set/cleared on the 0->1 and 1->0 transitions.
     */
    bier_bit_string_t bfmb_input_reset_string;
    u32 *bfmb_refs;

    /**
     * The total number of references to bits set on this mask
     * in effect a count of the number of children.
     */
    u32 bfmb_count;
} bier_fmask_bits_t;

/**
 * Flags on fmask
 */
typedef enum bier_fmask_attributes_t_
{
    BIER_FMASK_ATTR_FIRST,
    BIER_FMASK_ATTR_FORWARDING = BIER_FMASK_ATTR_FIRST,
    BIER_FMASK_ATTR_DISP,
    BIER_FMASK_ATTR_LAST = BIER_FMASK_ATTR_DISP,
} bier_fmask_attributes_t;

#define BIER_FMASK_ATTR_NAMES {                         \
     [BIER_FMASK_ATTR_FORWARDING] = "forwarding",       \
     [BIER_FMASK_ATTR_DISP] = "disposition",            \
}

#define FOR_EACH_BIER_FMASK_ATTR(_item)          \
    for (_item =  BIER_FMASK_ATTR_FIRST;         \
         _item <= BIER_FMASK_ATTR_LAST;          \
         _item++)

typedef enum bier_fmask_flags_t_
{
    BIER_FMASK_FLAG_FORWARDING = (1 << BIER_FMASK_ATTR_FORWARDING),
    BIER_FMASK_FLAG_DISP = (1 << BIER_FMASK_ATTR_DISP),
} bier_fmask_flags_t;

/**
 * An outgoing BIER mask. aka forwarding bit mask (in the RFCs)
 *
 * This mask's function is two-fold
 *  1 - it is logical-AND with the input packet header to produce the
 *      output packet header
 *  2 - it is logical NAND with the input packet header to modify the bit-mask
 *      for the next lookup
 */
typedef struct bier_fmask_t_ {
    /**
     * The BIER fmask is a child of a FIB entry in the FIB graph.
     */
    fib_node_t bfm_node;

    /**
     * operational/state flags on the fmask
     */
    bier_fmask_flags_t bfm_flags;

    /**
     * The bits, and their ref counts, that are set on this mask
     * This mask changes as BIER entries link to and from this fmask
     */
    bier_fmask_bits_t bfm_bits;

    struct
    {
        /**
         * The key to this fmask - used for store/lookup in the DB
         */
        bier_fmask_id_t bfm_id;

        /**
         * The BIER Table this Fmask is used in
         */
        index_t bfm_fib_index;
    };

    union
    {
        /**
         * For forwarding via a next-hop
         */
        struct
        {
            /**
             * The parent fib entry
             */
            fib_node_index_t bfm_fei;
            /**
             * The MPLS label to paint on the header during forwarding
             */
            mpls_label_t bfm_label;
        };

        /**
         * For disposition
         */
        struct
        {
            /**
             * The parent disposition table object
             */
            index_t bfm_disp;
        };
    };

    /**
     * the index of this fmask in the parent's child list.
     */
    u32 bfm_sibling;

    /**
     * The index into the adj table for the adj that
     * this fmask resolves via
     */
    dpo_id_t bfm_dpo;
} bier_fmask_t;

extern void bier_fmask_link(index_t bfmi, bier_bp_t bp);
extern void bier_fmask_unlink(index_t bfmi, bier_bp_t bp);
extern void bier_fmask_unlock(index_t bfmi);
extern void bier_fmask_lock(index_t bfmi);

extern index_t bier_fmask_create_and_lock(const bier_fmask_id_t *fmid,
                                          index_t bti,
                                          const fib_route_path_t *rpath);

extern u8* format_bier_fmask(u8 *s, va_list *ap);

extern void bier_fmask_contribute_forwarding(index_t bfmi,
                                             dpo_id_t *dpo);

extern u32 bier_fmask_child_add (fib_node_index_t fib_entry_index,
                                 fib_node_type_t child_type,
                                 fib_node_index_t child_index);
extern void bier_fmask_child_remove (fib_node_index_t fib_entry_index,
                                     u32 sibling_index);

/*
 * provided for fast data-path access
 */
bier_fmask_t *bier_fmask_pool;

static inline bier_fmask_t *
bier_fmask_get (u32 index)
{
    return (pool_elt_at_index(bier_fmask_pool, index));
}

#endif
