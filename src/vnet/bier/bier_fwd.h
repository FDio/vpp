/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2018 Cisco and/or its affiliates.
 */

#ifndef __BIER_FWD_H__
#define __BIER_FWD_H__

#include <vnet/bier/bier_types.h>
#include <vnet/bier/bier_hdr_inlines.h>

static_always_inline u32
bier_compute_flow_hash (const bier_hdr_t *hdr)
{
    u32 first_word = clib_net_to_host_u32(hdr->bh_first_word);

    return ((first_word &
             BIER_HDR_ENTROPY_FIELD_MASK) >>
            BIER_HDR_ENTROPY_FIELD_SHIFT);
}

#endif
