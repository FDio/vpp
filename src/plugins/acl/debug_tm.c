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
#include <stddef.h>
#include <netinet/in.h>

#include <vlibapi/api.h>
/*
#include <vlibmemory/api.h>
#include <vlibsocket/api.h>
*/

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/pg/pg.h>
#include <vppinfra/error.h>
#include <vnet/plugin/plugin.h>
#include <acl/acl.h>

#include "hash_lookup.h"






clib_error_t*
acl_describe_partition (vlib_main_t * vm,
                                   unformat_input_t * i,
                                   vlib_cli_command_t * cmd){

    clib_error_t *error = 0;
    acl_main_t * sm = &acl_main;
    u32 lc_index = ~0;
    u8 verbose = 0;


    /* Parse args required to build the message */
    while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT) {
        if (unformat (i, "lc_index %d", &lc_index))
            ;
        else if (unformat (i, "verbose"))
            verbose = 1;
        else
            break;
    }

    if (lc_index == ~0) {
	    return error = clib_error_return(0, "missing explicit lc_index number \n");
    }

    hash_applied_mask_info_t **hash_applied_mask_pool = vec_elt_at_index(sm->hash_applied_mask_pool_by_lc_index, lc_index);


    ace_mask_type_entry_t *mte;

    u32 order_index=0;
    u32 priority=0;
    u32 mask_type_index=0;
    vlib_cli_output(vm, "mask type: 'id' (best_priority) - max collisions hosted, number of entries");

    for(order_index = 0; order_index < pool_len((*hash_applied_mask_pool)); order_index++) {
	    hash_applied_mask_info_t *minfo = vec_elt_at_index((*hash_applied_mask_pool), order_index);
	    mask_type_index = minfo->mask_type_index;

	    mte = vec_elt_at_index(sm->ace_mask_type_pool, mask_type_index);
	    priority = minfo->max_priority;

	    u32 max_collisions = minfo->max_collisions;
	    u32 num_entries = minfo->num_entries;

	    if(verbose){
		    vlib_cli_output(vm, "Mask type: %d (%d)", mask_type_index, priority);
		    print_mask(&mte->mask);
	    }

	    vlib_cli_output(vm, "Mask type: %d (%d) - %d %d", mask_type_index, priority, max_collisions, num_entries);
    }



    return error;
}





clib_error_t*
acl_show_collision (vlib_main_t * vm,
                                   unformat_input_t * i,
                                   vlib_cli_command_t * cmd){

    clib_error_t *error = 0;
    acl_main_t * sm = &acl_main;
    u32 lc_index = ~0;
    u8 verbose = 0;

//  acl_interface_set_acl_list <intfc> | lc_index <if-idx> input [acl-idx list] output [acl-idx list]

    /* Parse args required to build the message */
    while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT) {
        if (unformat (i, "lc_index %d", &lc_index))
            ;
        else if (unformat (i, "verbose"))
            verbose = 1;
        else
            break;
    }

    if (lc_index == ~0) {
	    return error = clib_error_return(0, "missing interface name / explicit lc_index number \n");
    }


    applied_hash_ace_entry_t **applied_hash_aces = vec_elt_at_index(sm->hash_entry_vec_by_lc_index, lc_index);


    vlib_cli_output(vm,"Collisions in mask: 'applied-id' ('number of collisions in this entry) - 'ace-id' (entry in the hash)");
 
    u32 hash_ace_info;
    for(hash_ace_info=0; hash_ace_info < vec_len(*applied_hash_aces); hash_ace_info++) {

	    applied_hash_ace_entry_t *pae = vec_elt_at_index((*applied_hash_aces), hash_ace_info);

	    if(pae->prev_applied_entry_index == ~0){
	    u32 applied_mask_type_index = pae->mask_type_index;
	    u64 collisions = pae->collision;

	    ace_mask_type_entry_t *mte = vec_elt_at_index(sm->ace_mask_type_pool, applied_mask_type_index);


	    vlib_cli_output(vm,"Collisions in mask: %d (%ld) - ace: %d", applied_mask_type_index, 
			    collisions, pae->ace_index);

	    if(verbose){
		    print_mask(&mte->mask);
	    }
	}

    }



    return error;
}






clib_error_t*
acl_compare_partition (vlib_main_t * vm,
                                   unformat_input_t * i,
                                   vlib_cli_command_t * cmd){

    clib_error_t *error = 0;
    acl_main_t * sm = &acl_main;
    u32 lc_index = ~0;
    u32 acl_index = ~0;
    u8 verbose = 0;

    /* Parse args required to build the message */
    while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT) {
        if (unformat (i, "lc_index %d", &lc_index))
            ;
        else if (unformat (i, "acl %d", &acl_index))
            ;
        else if (unformat (i, "verbose"))
            verbose = 1;
        else
            break;
    }

    if (lc_index == ~0) {
	    return error = clib_error_return(0, "missing explicit lc_index number \n");
    }

    hash_acl_info_t *ha = vec_elt_at_index(sm->hash_acl_infos, acl_index);

    applied_hash_ace_entry_t **applied_hash_aces = vec_elt_at_index(sm->hash_entry_vec_by_lc_index, lc_index);

    vlib_cli_output(vm,"Comparing mask: 'base_id' ('applied-id') - 'ace'");

    u32 hash_ace_info;
    for(hash_ace_info=0; hash_ace_info < vec_len(*applied_hash_aces); hash_ace_info++) {

	    applied_hash_ace_entry_t *pae = vec_elt_at_index((*applied_hash_aces), hash_ace_info);

	    u32 base_mask_type_index = (vec_elt_at_index((ha->rules), pae->hash_ace_info_index))->base_mask_type_index;
	    u32 applied_mask_type_index = pae->mask_type_index;

	    ace_mask_type_entry_t *mte1 = vec_elt_at_index(sm->ace_mask_type_pool, base_mask_type_index);
	    ace_mask_type_entry_t *mte2 = vec_elt_at_index(sm->ace_mask_type_pool, applied_mask_type_index);


	    vlib_cli_output(vm,"Comparing mask: %d (applied:%d) - ace: %d", base_mask_type_index, applied_mask_type_index, 
			    pae->ace_index);

	    if(verbose){
		    print_mask(&mte1->mask);
		    print_mask(&mte2->mask);
	    }

    }



    return error;
}

