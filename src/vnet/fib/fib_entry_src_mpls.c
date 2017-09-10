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
#include <vnet/dpo/drop_dpo.h>

#include <vnet/fib/fib_table.h>
#include <vnet/fib/fib_entry.h>
#include <vnet/fib/fib_entry_src.h>
#include <vnet/fib/mpls_fib.h>

/**
 * Source initialisation Function 
 */
static void
fib_entry_src_mpls_init (fib_entry_src_t *src)
{
    mpls_eos_bit_t eos;

    src->fes_flags = FIB_ENTRY_SRC_FLAG_NONE;
    src->mpls.fesm_label = MPLS_LABEL_INVALID;

    FOR_EACH_MPLS_EOS_BIT(eos)
    {
	src->mpls.fesm_lfes[eos] = FIB_NODE_INDEX_INVALID;
    }
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
                        dpo_proto_t proto,
                        const dpo_id_t *dpo)
{
    src->fes_pl =
	fib_path_list_create_special(proto,
				     FIB_PATH_LIST_FLAG_DROP,
				     drop_dpo_get(proto));
}

static void
fib_entry_src_mpls_set_data (fib_entry_src_t *src,
                             const fib_entry_t *entry,
                             const void *data)
{
    fib_protocol_t payload_proto;
    fib_node_index_t fei;
    mpls_label_t label;
    mpls_eos_bit_t eos;

    /*
     * post MPLS table alloc and the possible rea-alloc of fib entrys
     * the entry pointer will no longer be valid. so save its index
     */
    payload_proto = entry->fe_prefix.fp_proto;
    fei = fib_entry_get_index(entry);
    label = *(mpls_label_t*)data;

    if (MPLS_LABEL_INVALID == label)
    {
        /*
         * removing the local label
         */
        FOR_EACH_MPLS_EOS_BIT(eos)
        {
	    fib_table_entry_delete_index(src->mpls.fesm_lfes[eos],
					 FIB_SOURCE_SPECIAL);
        }
        fib_table_unlock(MPLS_FIB_DEFAULT_TABLE_ID,
                         FIB_PROTOCOL_MPLS,
                         FIB_SOURCE_MPLS);
        src->mpls.fesm_label = label;
    }
    else
    {
	fib_prefix_t prefix = {
	    .fp_proto = FIB_PROTOCOL_MPLS,
	    .fp_label = label,
	};
	fib_node_index_t fib_index;
	dpo_id_t dpo = DPO_INVALID;

        /*
         * adding a new local label. make sure the MPLS fib exists.
         */
        if (MPLS_LABEL_INVALID == src->mpls.fesm_label)
        {
            fib_index =
		fib_table_find_or_create_and_lock(FIB_PROTOCOL_MPLS,
						  MPLS_FIB_DEFAULT_TABLE_ID,
                                                  FIB_SOURCE_MPLS);
        }
	else
	{
	    fib_index = mpls_fib_index_from_table_id(MPLS_FIB_DEFAULT_TABLE_ID);

	    /*
	     * if this is a change in label, reomve the old one first
	     */
	    if (src->mpls.fesm_label != label)
	    {
		FOR_EACH_MPLS_EOS_BIT(eos)
		{
		    ASSERT(FIB_NODE_INDEX_INVALID != src->mpls.fesm_lfes[eos]);
		    fib_table_entry_delete_index(src->mpls.fesm_lfes[eos],
						 FIB_SOURCE_SPECIAL);
		}
	    }
	}

        src->mpls.fesm_label = label;

	FOR_EACH_MPLS_EOS_BIT(eos)
	{
	    prefix.fp_eos = eos;
	    prefix.fp_payload_proto = fib_proto_to_dpo(payload_proto);

	    fib_entry_contribute_forwarding(fei,
					    (eos ?
					     FIB_FORW_CHAIN_TYPE_MPLS_EOS :
					     FIB_FORW_CHAIN_TYPE_MPLS_NON_EOS),
					    &dpo);
	    src->mpls.fesm_lfes[eos] = 
		fib_table_entry_special_dpo_add(fib_index,
						&prefix,
						FIB_SOURCE_SPECIAL,
						FIB_ENTRY_FLAG_EXCLUSIVE,
						&dpo);
	    dpo_reset(&dpo);
	}
    }
}

static const void *
fib_entry_src_mpls_get_data (fib_entry_src_t *src,
                             const fib_entry_t *entry)
{
    return (&(src->mpls.fesm_label));
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
    .fesv_set_data = fib_entry_src_mpls_set_data,
    .fesv_get_data = fib_entry_src_mpls_get_data,
    /*
     * .fesv_fwd_update = fib_entry_src_mpls_fwd_update,
     *  When the forwarding for the IP entry is updated, any MPLS chains
     * it has created are also updated. Since the MPLS entry will have already
     * installed that chain/load-balance there is no need to update the netry
     * FIXME: later: propagate any walk to the children of the MPLS entry. for SR
     */
};

void
fib_entry_src_mpls_register (void)
{
    fib_entry_src_register(FIB_SOURCE_MPLS, &mpls_src_vft);    
}


