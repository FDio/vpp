/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2016 Cisco and/or its affiliates.
 */

#ifndef __MPLS_DISP_DPO_H__
#define __MPLS_DISP_DPO_H__

#include <vnet/vnet.h>
#include <vnet/mpls/packet.h>
#include <vnet/dpo/dpo.h>
#include <vnet/mfib/mfib_types.h>

/**
 * A representation of an MPLS label for imposition in the data-path
 */
typedef struct mpls_disp_dpo_t
{
    /**
     * required for pool_get_aligned.
     *  memebers used in the switch path come first!
     */
    CLIB_CACHE_LINE_ALIGN_MARK(cacheline0);

    /**
     * Next DPO in the graph
     */
    dpo_id_t mdd_dpo;

    /**
     * The protocol of the payload/packets that are being encapped
     */
    dpo_proto_t mdd_payload_proto;

    /**
     * RPF-ID (if this is an mcast disposition)
     */
    fib_rpf_id_t mdd_rpf_id;

    /**
     * Number of locks/users of the label
     */
    u16 mdd_locks;

    /**
     * LSP mode
     */
    fib_mpls_lsp_mode_t mdd_mode;
} mpls_disp_dpo_t;

/**
 * @brief Assert that the MPLS label object is less than a cache line in size.
 * Should this get any bigger then we will need to reconsider how many labels
 * can be pushed in one object.
 */
_Static_assert((sizeof(mpls_disp_dpo_t) <= CLIB_CACHE_LINE_BYTES),
	       "MPLS Disposition DPO is larger than one cache line.");

/**
 * @brief Create an MPLS label object
 *
 * @param payload_proto The ptocool of the payload packets that will
 *                      be imposed with this label header.
 * @param rpf_id The RPF ID the packet will aquire - only for mcast
 * @param mode The LSP mode; pipe or uniform
 * @param dpo The parent of the created MPLS label object
 */
extern void mpls_disp_dpo_create(dpo_proto_t payload_proto,
                                 fib_rpf_id_t rpf_id,
                                 fib_mpls_lsp_mode_t mode,
                                 const dpo_id_t *parent,
                                 dpo_id_t *dpo);

extern u8* format_mpls_disp_dpo(u8 *s, va_list *args);


/*
 * Encapsulation violation for fast data-path access
 */
extern mpls_disp_dpo_t *mpls_disp_dpo_pool;

static inline mpls_disp_dpo_t *
mpls_disp_dpo_get (index_t index)
{
    return (pool_elt_at_index(mpls_disp_dpo_pool, index));
}

extern void mpls_disp_dpo_module_init(void);

#endif
