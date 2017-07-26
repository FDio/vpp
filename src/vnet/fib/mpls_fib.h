/*
 * mpls_fib.h: The Label/MPLS FIB
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

#ifndef __MPLS_FIB_TABLE_H__
#define __MPLS_FIB_TABLE_H__

#include <vnet/vnet.h>
#include <vnet/mpls/mpls.h>
#include <vnet/fib/fib_types.h>
#include <vnet/dpo/dpo.h>
#include <vnet/mpls/mpls.h>
#include <vnet/fib/fib_table.h>

#define MPLS_FIB_DEFAULT_TABLE_ID 0

/**
 * Type exposure is to allow the DP fast/inlined access
 */
#define MPLS_FIB_KEY_SIZE 21
#define MPLS_FIB_DB_SIZE (1 << (MPLS_FIB_KEY_SIZE-1))

/**
 * There are no options for controlling the MPLS flow hash
 */
#define MPLS_FLOW_HASH_DEFAULT 0

typedef struct mpls_fib_t_
{
  /**
   * A hash table of entries. 21 bit key
   * Hash table for reduced memory footprint
   */
  uword * mf_entries;

  /**
   * The load-balance indices keyed by 21 bit label+eos bit.
   * A flat array for maximum lookup performace.
   */
  index_t mf_lbs[MPLS_FIB_DB_SIZE];
} mpls_fib_t;

static inline mpls_fib_t*
mpls_fib_get (fib_node_index_t index)
{
    return (pool_elt_at_index(mpls_main.mpls_fibs, index));
}

extern u32 mpls_fib_table_find_or_create_and_lock(u32 table_id,
                                                  fib_source_t src);
extern u32 mpls_fib_table_create_and_lock(fib_source_t src);
// extern mpls_fib_t * mpls_fib_find(u32 table_id);
extern u32 mpls_fib_index_from_table_id(u32 table_id);

extern u8 *format_mpls_fib_table_name(u8 * s, va_list * args);

extern fib_node_index_t mpls_fib_table_entry_add_from_ip_fib_entry (
    u32 table_id,
    mpls_label_t label,
    mpls_eos_bit_t eos,
    fib_node_index_t fib_entry_index);


extern fib_node_index_t mpls_fib_table_lookup(const mpls_fib_t *mf,
					      mpls_label_t label,
					      mpls_eos_bit_t eos);

extern void mpls_fib_table_entry_remove(mpls_fib_t *mf,
					mpls_label_t label,
					mpls_eos_bit_t eos);
extern void mpls_fib_table_entry_insert(mpls_fib_t *mf,
					mpls_label_t label,
					mpls_eos_bit_t eos,
					fib_node_index_t fei);
extern void mpls_fib_table_destroy(u32 fib_index);


extern void mpls_fib_forwarding_table_update(mpls_fib_t *mf,
					     mpls_label_t label,
					     mpls_eos_bit_t eos,
					     const dpo_id_t *dpo);
extern void mpls_fib_forwarding_table_reset(mpls_fib_t *mf,
					    mpls_label_t label,
					    mpls_eos_bit_t eos);

/**
 * @brief Walk all entries in a FIB table
 * N.B: This is NOT safe to deletes. If you need to delete walk the whole
 * table and store elements in a vector, then delete the elements
 */
extern void mpls_fib_table_walk(mpls_fib_t *fib,
                                fib_table_walk_fn_t fn,
                                void *ctx);

/**
 * @brief
 *  Lookup a label and EOS bit in the MPLS_FIB table to retrieve the
 *  load-balance index to be used for packet forwarding.
 */
static inline index_t
mpls_fib_table_forwarding_lookup (u32 mpls_fib_index,
				  const mpls_unicast_header_t *hdr)
{
    mpls_label_t label;
    mpls_fib_t *mf;
    u32 key;

    label = clib_net_to_host_u32(hdr->label_exp_s_ttl);
    key = (vnet_mpls_uc_get_label(label) << 1) | vnet_mpls_uc_get_s(label);

    mf = mpls_fib_get(mpls_fib_index);

    return (mf->mf_lbs[key]);
}

static inline u32
mpls_fib_table_get_index_for_sw_if_index (u32 sw_if_index)
{
    mpls_main_t *mm = &mpls_main;

    ASSERT(vec_len(mm->fib_index_by_sw_if_index) > sw_if_index);

    return (mm->fib_index_by_sw_if_index[sw_if_index]);
}

#endif
