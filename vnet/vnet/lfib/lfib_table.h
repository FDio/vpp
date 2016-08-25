/*
 * lfib.h: The Label/MPLS FIB
 *
 * Copyright (c) 2012 Cisco and/or its affiliates.
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

#ifndef __LFIB_TABLE_H__
#define __LFIB_TABLE_H__

#include <vnet/vnet.h>
#include <vnet/mpls/mpls.h>
#include <vnet/fib/fib_types.h>
#include <vnet/dpo/dpo.h>
#include <vnet/lfib/lfib.h>

#define LFIB_DEFAULT_TABLE_ID 0

/**
 * Type exposure is to allow the DP fast/inlined access
 */
#define LFIB_KEY_SIZE 21
#define LFIB_DB_SIZE (1 << (LFIB_KEY_SIZE-1))

typedef struct lfib_table_t_
{
    /**
     * A hash table of entries. 21 bit key
     * Hash table for reduced memory footprint
     */
    uword * lft_entries; 

    /**
     * The load-balance indeices keyed by 21 bit label+eos bit.
     * A flat array for maximum lookup performace.
     */
    index_t lft_lbs[LFIB_DB_SIZE];
} lfib_table_t;

extern fib_node_index_t lfib_table_entry_add_from_ip_fib_entry (
    u32 table_id,
    mpls_label_t label,
    mpls_eos_bit_t eos,
    fib_node_index_t fib_entry_index);

extern fib_node_index_t lfib_table_entry_special_create (u32 lfib_index,
                                                         mpls_label_t label,
                                                         mpls_eos_bit_t eos,
                                                         const dpo_id_t *dpo);

extern fib_node_index_t lfib_table_entry_path_add(u32 fib_index,
                                                  mpls_label_t label,
                                                  mpls_eos_bit_t eos,
                                                  fib_protocol_t next_hop_proto,
                                                  const ip46_address_t *next_hop,
                                                  u32 next_hop_sw_if_index,
                                                  u32 next_hop_fib_index,
                                                  u32 next_hop_weight,
                                                  mpls_label_t next_hop_label,
                                                  fib_route_path_flags_t pf);

extern fib_node_index_t lfib_table_entry_path_add2(u32 fib_index,
						  mpls_label_t label,
                                                   mpls_eos_bit_t eos,
                                                   const fib_route_path_t *rpath);

extern void lfib_table_entry_path_remove(u32 fib_index,
					 mpls_label_t label,
					 const ip46_address_t *next_hop,
					 u32 next_hop_sw_if_index,
					 u32 next_hop_fib_index,
					 u32 next_hop_weight,
					 fib_route_path_flags_t pf);
extern void lfib_table_entry_path_remove2(u32 fib_index,
					  mpls_label_t label,
					  const fib_route_path_t *paths);

extern fib_node_index_t lfib_table_entry_update(u32 fib_index,
						mpls_label_t label,
						const fib_route_path_t *paths);
extern fib_node_index_t lfib_table_entry_update_one_path(u32 fib_index,
							 mpls_label_t label,
							 const ip46_address_t *next_hop,
							 u32 next_hop_sw_if_index,
							 u32 next_hop_fib_index,
							 u32 next_hop_weight,
							 fib_route_path_flags_t pf);
extern lfib_table_t *lfib_table_create(void);
extern void lfib_table_delete(lfib_table_t *lft);

extern void lfib_table_entry_delete(fib_node_index_t lfei);


extern fib_node_index_t lfib_table_lookup(fib_node_index_t lfib_index,
					  mpls_label_t label,
					  mpls_eos_bit_t eos);

static inline u32
lfib_entry_mk_key (mpls_label_t label,
                   mpls_eos_bit_t eos)
{
    ASSERT(eos <= 1);
    return (label << 1 | eos);
}


extern void lfib_forwarding_table_update(u32 index,
					 mpls_label_t label,
					 mpls_eos_bit_t eos,
					 const dpo_id_t *dpo);
extern void lfib_forwarding_table_reset(u32 index,
					 mpls_label_t label,
                                        mpls_eos_bit_t eos);

/**
 * \brief
 *  Lookup a label and EOS bit in the LFIB table to retrieve the load-balance index
 *  to be used for packet forwarding.
 */
static inline const index_t
lfib_table_forwarding_lookup (u32 lfib_index,
			      const mpls_unicast_header_t *hdr)
{
    lfib_table_t *lft;
    mpls_label_t label;
    u32 key;

    label = clib_net_to_host_u32(hdr->label_exp_s_ttl);
    key = (vnet_mpls_uc_get_label(label) << 1) | vnet_mpls_uc_get_s(label);

    lft = pool_elt_at_index(lfib_main.lfibs, lfib_index)->lf_table;

    return (lft->lft_lbs[key]);
}

static inline u32
lfib_table_get_index_for_sw_if_index (u32 sw_if_index)
{
    mpls_main_t *mm = &mpls_main;

    ASSERT(vec_len(mm->fib_index_by_sw_if_index) < sw_if_index);

    return (mm->fib_index_by_sw_if_index[sw_if_index]);
}

#endif
