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
 * Flags present on an MPLS label sourced path-extension
 */
typedef enum mpls_label_dpo_attr_t_
{
    /**
     * Do not decrement the TTL of IP packet during imposition
     */
    MPLS_LABEL_DPO_ATTR_NO_IP_TTL_DECR,
    MPLS_LABEL_DPO_ATTR_UNIFORM_MODE,
} mpls_label_dpo_attr_t;

#define MPLS_LABEL_DPO_ATTR_MAX (MPLS_LABEL_DPO_ATTR_UNIFORM_MODE+1)

typedef enum mpls_label_dpo_flags_t_
{
    MPLS_LABEL_DPO_FLAG_NONE = 0,
    MPLS_LABEL_DPO_FLAG_NO_IP_TTL_DECR = (1 << MPLS_LABEL_DPO_ATTR_NO_IP_TTL_DECR),
    MPLS_LABEL_DPO_FLAG_UNIFORM_MODE = (1 << MPLS_LABEL_DPO_ATTR_UNIFORM_MODE),
} __attribute__ ((packed)) mpls_label_dpo_flags_t;

#define MPLS_LABEL_DPO_ATTR_NAMES {                               \
    [MPLS_LABEL_DPO_ATTR_NO_IP_TTL_DECR] = "no-ip-tll-decr",      \
    [MPLS_LABEL_DPO_ATTR_UNIFORM_MODE]   = "uniform-mode",        \
}

#define FOR_EACH_MPLS_LABEL_DPO_ATTR(_item)                \
    for (_item = MPLS_LABEL_DPO_ATTR_NO_IP_TTL_DECR;       \
         _item <= MPLS_LABEL_DPO_ATTR_UNIFORM_MODE;        \
         _item++)

/**
 * Format the flags variable
 */
extern u8* format_mpls_label_dpo_flags(u8 *s, va_list *args);

/**
 * Maximum number of labels in one DPO
 */
#define MPLS_LABEL_DPO_MAX_N_LABELS 12

/**
 * A representation of an MPLS label for imposition in the data-path
 */
typedef struct mpls_label_dpo_t
{
    /**
     * The MPLS label header to impose. Outer most label first.
     * Each DPO will occupy one cache line, stuff that many labels in.
     */
    mpls_unicast_header_t mld_hdr[MPLS_LABEL_DPO_MAX_N_LABELS];

    /**
     * Next DPO in the graph
     */
    dpo_id_t mld_dpo;

    /**
     * The protocol of the payload/packets that are being encapped
     */
    dpo_proto_t mld_payload_proto;

    /**
     * Flags
     */
    mpls_label_dpo_flags_t mld_flags;

    /**
     * Size of the label stack
     */
    u8 mld_n_labels;

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
 * @param payload_proto The ptocool of the payload packets that will
 *                      be imposed with this label header.
 * @param parent The parent of the created MPLS label object
 * @param dpo The MPLS label DPO created
 */
extern void mpls_label_dpo_create(fib_mpls_label_t *label_stack,
                                  mpls_eos_bit_t eos,
                                  dpo_proto_t payload_proto,
                                  mpls_label_dpo_flags_t flags,
                                  const dpo_id_t *paremt,
                                  dpo_id_t *dpo);

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

/*
 * test function to get the registered DPO type for the flags
 */
extern dpo_type_t mpls_label_dpo_get_type(mpls_label_dpo_flags_t flags);

#endif
