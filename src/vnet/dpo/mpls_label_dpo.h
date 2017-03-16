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

#ifndef __MPLS_LABEL_DPO_H__
#define __MPLS_LABEL_DPO_H__

#include <vnet/vnet.h>
#include <vnet/mpls/packet.h>
#include <vnet/dpo/dpo.h>

/**
 * A representation of an MPLS label for imposition in the data-path
 */
typedef struct mpls_label_dpo_t
{
    /**
     * The MPLS label header to impose. Outer most label first.
     */
    mpls_unicast_header_t mld_hdr[8];

    /**
     * Next DPO in the graph
     */
    dpo_id_t mld_dpo;

    /**
     * The protocol of the payload/packets that are being encapped
     */
    dpo_proto_t mld_payload_proto;

    /**
     * Size of the label stack
     */
    u16 mld_n_labels;

    /**
     * Cached amount of header bytes to paint
     */
    u16 mld_n_hdr_bytes;

    /**
     * Number of locks/users of the label
     */
    u16 mld_locks;
} mpls_label_dpo_t;

/**
 * @brief Assert that the MPLS label object is less than a cache line in size.
 * Should this get any bigger then we will need to reconsider how many labels
 * can be pushed in one object.
 */
STATIC_ASSERT((sizeof(mpls_label_dpo_t) <= CLIB_CACHE_LINE_BYTES),
              "MPLS label DPO is larger than one cache line.");

/**
 * @brief Create an MPLS label object
 *
 * @param label_stack The stack if labels to impose, outer most label first
 * @param eos The inner most label's EOS bit
 * @param ttl The inner most label's TTL bit
 * @param exp The inner most label's EXP bit
 * @param payload_proto The ptocool of the payload packets that will
 *                      be imposed with this label header.
 * @param dpo The parent of the created MPLS label object
 */
extern index_t mpls_label_dpo_create(mpls_label_t *label_stack,
                                     mpls_eos_bit_t eos,
                                     u8 ttl,
                                     u8 exp,
                                     dpo_proto_t payload_proto,
				     const dpo_id_t *dpo);

extern u8* format_mpls_label_dpo(u8 *s, va_list *args);


/*
 * Encapsulation violation for fast data-path access
 */
extern mpls_label_dpo_t *mpls_label_dpo_pool;

static inline mpls_label_dpo_t *
mpls_label_dpo_get (index_t index)
{
    return (pool_elt_at_index(mpls_label_dpo_pool, index));
}

extern void mpls_label_dpo_module_init(void);

#endif
