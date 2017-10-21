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
 * bier_imposition : The BIER imposition object
 *
 * A BIER imposition object is present in the IP mcast output list
 * and represents the imposition of a BIER bitmask. After BIER header
 * imposition the packet is forward within the appropriate/specifid
 * BIER table
 */

#ifndef __BIER_IMPOSITION_H__
#define __BIER_IMPOSITION_H__

#include <vnet/bier/bier_types.h>
#include <vnet/fib/fib_types.h>
#include <vnet/dpo/dpo.h>

/**
 * The BIER imposition object
 */
typedef struct bier_imp_t_ {
    /**
     * The BIER table into which to forward the post imposed packet
     */
    bier_table_id_t bi_tbl;

    /**
     * number of locks
     */
    u32 bi_locks;

    /**
     * The DPO contirubted from the resolving BIER table.
     * One per-IP protocol. This allows us to share a BIER imposition
     * object for a IPv4 and IPv6 mfib path.
     */
    dpo_id_t bi_dpo[FIB_PROTOCOL_IP_MAX];

    /**
     * The Header to impose.
     */
    bier_hdr_t bi_hdr;

    /**
     * The bit string.
     *  This is a memory v. speed tradeoff. We inline here the
     *  largest header type so as the bitstring is on the same
     *  cacheline as the header.
     */
    bier_bit_mask_4096_t bi_bits;
} bier_imp_t;

extern index_t bier_imp_add_or_lock(const bier_table_id_t *bt,
                                    bier_bp_t sender,
                                    const bier_bit_string_t *bs);

extern void bier_imp_unlock(index_t bii);
extern void bier_imp_lock(index_t bii);

extern u8* format_bier_imp(u8* s, va_list *ap);

extern void bier_imp_contribute_forwarding(index_t bii,
                                           dpo_proto_t proto,
                                           dpo_id_t *dpo);

extern bier_imp_t *bier_imp_pool;

always_inline bier_imp_t*
bier_imp_get (index_t bii)
{
    return (pool_elt_at_index(bier_imp_pool, bii));
}

#endif
