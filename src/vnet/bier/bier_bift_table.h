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

#ifndef __BIER_BIFT_TABLE_H__
#define __BIER_BIFT_TABLE_H__

#include <vnet/dpo/dpo.h>
#include <vnet/bier/bier_types.h>
#include <vnet/mpls/packet.h>

/*
 * the lookup table used to get from a BFIT_ID to a load-balance.
 * As per-draft draft-ietf-bier-mpls-encapsulation-10 this isthe
 * use case for non-MPLS networks
 */
#define BIER_BIFT_N_ENTRIES (1 << 20)
typedef struct bier_bfit_table_t_
{
    /**
     * Forwarding information for each BIFT ID
     */
    dpo_id_t bblt_dpos[BIER_BIFT_N_ENTRIES];

    /**
     * The number of entries in the table
     */
    u32 bblt_n_entries;
} bier_bfit_table_t;


extern void bier_bift_table_entry_add(bier_bift_id_t id,
                                      const dpo_id_t *dpo);

extern void bier_bift_table_entry_remove(bier_bift_id_t id);

/**
 * Global BIFT table
 */
extern bier_bfit_table_t *bier_bift_table;

static inline const dpo_id_t*
bier_bift_dp_lookup (bier_bift_id_t key_host_order)
{
    return (&bier_bift_table->bblt_dpos[vnet_mpls_uc_get_label(key_host_order)]);
}
#endif
