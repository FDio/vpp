/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Cisco and/or its affiliates.
 */

#ifndef __PW_CW_DPO_H__
#define __PW_CW_DPO_H__

#include <vnet/vnet.h>
#include <vnet/mpls/packet.h>
#include <vnet/dpo/dpo.h>

/**
 * A Psuedo Wire Control Word is 4 bytes
 */
typedef u32 pw_cw_t;

/**
 * A representation of a Psuedo Wire Control Word pop DPO
 */
typedef struct pw_cw_dpo_t
{
    /**
     * Next DPO in the graph
     */
    dpo_id_t pwcw_parent;

    /**
     * Number of locks/users of the label
     */
    u16 pwcw_locks;
} pw_cw_dpo_t;

/**
 * @brief Assert that the MPLS label object is less than a cache line in size.
 * Should this get any bigger then we will need to reconsider how many labels
 * can be pushed in one object.
 */
STATIC_ASSERT_SIZEOF(pw_cw_dpo_t, 2 * sizeof(u64));

/* #define STATIC_ASSERT_ALIGNOF(d, s)                                      \ */
/*     STATIC_ASSERT (alignof (d) == sizeof(s), "Align of " #d " must be " # s " bytes") */

/* STATIC_ASSERT_AIGNOF(pw_cw_dpo_t, u64); */

/**
 * @brief Create an PW CW pop
 *
 * @param parent The parent of the created MPLS label object
 * @param dpo The PW CW DPO created
 */
extern void pw_cw_dpo_create(const dpo_id_t *paremt,
                             dpo_id_t *dpo);

extern u8* format_pw_cw_dpo(u8 *s, va_list *args);

/*
 * Encapsulation violation for fast data-path access
 */
extern pw_cw_dpo_t *pw_cw_dpo_pool;

static inline pw_cw_dpo_t *
pw_cw_dpo_get (index_t index)
{
    return (pool_elt_at_index(pw_cw_dpo_pool, index));
}

extern void pw_cw_dpo_module_init(void);

#endif
