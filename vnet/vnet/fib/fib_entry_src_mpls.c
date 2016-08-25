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

#include <vnet/mpls/mpls_types.h>
#include <vnet/lfib/lfib_table.h>
#include <vnet/lfib/lfib_entry.h>
#include <vnet/dpo/drop_dpo.h>

#include "fib_entry.h"
#include "fib_entry_src.h"

/**
 * Source initialisation Function 
 */
static void
fib_entry_src_mpls_init (fib_entry_src_t *src)
{
    src->fes_flags = FIB_ENTRY_FLAG_NONE;
    src->mpls.fesm_label = MPLS_LABEL_INVALID;
}

/**
 * Source deinitialisation Function 
 */
static void
fib_entry_src_mpls_deinit (fib_entry_src_t *src)
{
}

static void
fib_entry_src_mpls_remove (fib_entry_src_t *src)
{
    src->fes_pl = FIB_NODE_INDEX_INVALID;
    src->mpls.fesm_label = MPLS_LABEL_INVALID;
}

static void
fib_entry_src_mpls_add (fib_entry_src_t *src,
                        const fib_entry_t *entry,
                        fib_entry_flag_t flags,
                        fib_protocol_t proto,
                        const dpo_id_t *dpo)
{
    src->fes_pl =
	fib_path_list_create_special(proto,
				     FIB_PATH_LIST_FLAG_DROP,
				     drop_dpo_get(fib_proto_to_dpo(proto)));
}

static void
fib_entry_src_mpls_set_data (fib_entry_src_t *src,
                             const fib_entry_t *entry,
                             const void *data)
{
    mpls_eos_bit_t eos;
    mpls_label_t label;

    label = *(mpls_label_t*)data;

    if (MPLS_LABEL_INVALID == label)
    {
        /*
         * removing the local label
         */
        FOR_EACH_MPLS_EOS_BIT(eos)
        {
            lfib_table_entry_delete(src->mpls.fesm_lfes[eos]);
        }
        lfib_unlock(LFIB_DEFAULT_TABLE_ID);
        src->mpls.fesm_label = label;
    }
    else
    {
        /*
         * adding a new local label. make sure the lfib exists.
         */
        if (MPLS_LABEL_INVALID == src->mpls.fesm_label)
        {
            lfib_find_or_create_and_lock(LFIB_DEFAULT_TABLE_ID);
        }

        src->mpls.fesm_label = label;

        FOR_EACH_MPLS_EOS_BIT(eos)
        {
            src->mpls.fesm_lfes[eos] = 
                lfib_table_entry_add_from_ip_fib_entry(LFIB_DEFAULT_TABLE_ID,
                                                       src->mpls.fesm_label,
                                                       eos,
                                                       fib_entry_get_index(entry));
        }
    }
}

static const void *
fib_entry_src_mpls_get_data (fib_entry_src_t *src,
                             const fib_entry_t *entry)
{
    return (&(src->mpls.fesm_label));
}

static void
fib_entry_src_mpls_fwd_update (fib_entry_src_t *src,
			       const fib_entry_t *fib_entry,
			       fib_source_t best_source)
{
    mpls_eos_bit_t eos;

    FOR_EACH_MPLS_EOS_BIT(eos)
    {
	lfib_entry_update_from_ip_fib_entry(src->mpls.fesm_lfes[eos]);
    }
}

static u8*
fib_entry_src_mpls_format (fib_entry_src_t *src,
			   u8* s)
{
    return (format(s, "MPLS local-label:%d", src->mpls.fesm_label));
}

const static fib_entry_src_vft_t mpls_src_vft = {
    .fesv_init = fib_entry_src_mpls_init,
    .fesv_deinit = fib_entry_src_mpls_deinit,
    .fesv_add = fib_entry_src_mpls_add,
    .fesv_remove = fib_entry_src_mpls_remove,
    .fesv_format = fib_entry_src_mpls_format,
    .fesv_fwd_update = fib_entry_src_mpls_fwd_update,
    .fesv_set_data = fib_entry_src_mpls_set_data,
    .fesv_get_data = fib_entry_src_mpls_get_data,
};

void
fib_entry_src_mpls_register (void)
{
    fib_entry_src_register(FIB_SOURCE_MPLS, &mpls_src_vft);    
}


