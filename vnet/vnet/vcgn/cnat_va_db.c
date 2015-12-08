/*
 *------------------------------------------------------------------
 * cnat_va_db.c - virtual assembly database
 *
 * Copyright (c) 2009, 2013 Cisco and/or its affiliates.
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
 *------------------------------------------------------------------
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cnat_va_db.h>
#include <format.h>
#include <spp_node.h>
#include <spp_alloc.h>
#include <spp_byteorder.h>
#include <spp_main.h>
#include <spp_cache.h>
#include <spp_interface.h>
#include <spp_api.h>
#include <spp_client_api.h>
#include <spp_timers.h>
#include <cnat_db.h>
#include <spp_plugin.h>
#include <cnat_v4_functions.h>


va_bucket_t va_bucket[VA_BUCKETS];

void va_bucket_init () {

    u32 i;

    /* 
     * set the pointer in each bucket
     * points to nowhere
     */
    for (i=0; i<VA_BUCKETS; i++) {
        va_bucket[i].next_available_entry = ~0;
    }

}

inline void va_db_add_new_entry (u32 bucket_index, 
                                 va_lookup_key * key ) 
{

    va_entry_t * entry_p;
    u32 head, next;

    entry_p = va_db_lookup(bucket_index, key);

    if (PREDICT_FALSE(entry_p)) { 
        FRAG_DEBUG_PRINTF6(
	  "\nVA_ADD_NEW: Bucket %d fnd Existng entry [%d, %d] -> [%d, %d]\n", 
	  bucket_index, entry_p->src_port, 
	  entry_p->dst_port, key->e.src_port, key->e.dst_port)

        /* found match entry, update it */
        entry_p->src_port = key->e.src_port; 
        entry_p->dst_port = key->e.dst_port; 

        FRAG_DEBUG_PRINTF3("VA_ADD_NEW: Existing bucket %d, counter %d\n", 
	                    bucket_index, 
			    va_bucket[bucket_index].new_entry_counter)

    } else { 
 
        /* no match, add a new one */
        head = va_bucket[bucket_index].head_entry;
        next = va_bucket[bucket_index].next_available_entry;

        FRAG_DEBUG_PRINTF5(
	    "\nVA_ADD_NEW: Filling bucket %d, index %d with key 0x%llx %x\n",
	    bucket_index, next, key->k.key64, key->k.key32)

        va_bucket[bucket_index].va_entry[next] = key->e;

        /* increase next pointer */
        va_bucket[bucket_index].next_available_entry = (next+1) & VA_BUCKET_MASK;

        if (PREDICT_FALSE(head == va_bucket[bucket_index].next_available_entry))  { 
            /* adjust head circular pointer */
            va_bucket[bucket_index].head_entry = (head+1) & VA_BUCKET_MASK;
        }

	va_bucket[bucket_index].new_entry_counter++;

        FRAG_DEBUG_PRINTF4(
	    "VA_ADD_NEW: NEW bucket %d, entry %d counter %d\n", 
	    bucket_index, next, va_bucket[bucket_index].new_entry_counter)
    }
} 


/* 
 * use the key, 
 * return pointer to the entry if found, 
 * NULL if not 
 */

inline 
va_entry_t * va_db_lookup (u32 bucket_index, va_lookup_key * key) 
{

    u32 index, next;
    va_entry_t * entry_p;
    va_bucket_t * bucket;
 
    bucket  = &va_bucket[bucket_index];
    index   = bucket->head_entry;
    next    = bucket->next_available_entry;
    entry_p = NULL;

    FRAG_DEBUG_PRINTF4(
        "\nVA_DB_LOOKUP: bucket index %d head %d next %d\n",
	bucket_index, index, next)

    /* loop through the entries in the bucket */
    while( index != next) {

        if(PREDICT_TRUE(memcmp(&bucket->va_entry[index], key, VA_KEY_SIZE)==0)) {

            entry_p = &bucket->va_entry[index];
	    /*In add frag entry function we are again assigning key's src 
	      port to entry_p's src port. So when a main DB entry is deleted/
	      timed out, and again another entry is created for the same
	      src ip and src port pair, the frag's entry_p will have the
	      previous port info stored and not updated. Hence the below 
	      line is not required*/
	      
            /* *(u32*)&key->e.src_port = *(u32*)&entry_p->src_port; */
	    /* do two ports as u32 :) */
	    
            break;
        }

        index = (index +1) & VA_BUCKET_MASK;

    }

#ifdef FRAG_DEBUG
    if (PREDICT_TRUE(entry_p)) {
        FRAG_DEBUG_PRINTF3("VA_DB_LOOKUP: bucket index %d entry index %d\n",
	                   bucket_index, index)
        FRAG_DEBUG_PRINTF5("VA_DB_LOOKUP: SRC-->DST [0x%x, %d] [0x%x, %d]\n",
	                    entry_p->src_ip, entry_p->src_port, 
			    entry_p->dst_ip, entry_p->dst_port)
        FRAG_DEBUG_PRINTF3("[vrf 0x%x, id 0x%x]\n", 
	                   entry_p->vrf, entry_p->ip_id)
    } else {
        FRAG_DEBUG_PRINTF1("\nNULL ENTRY\n")
    }
#endif

    return entry_p;

}

inline 
int va_db_delete_entry (u32 bucket_index, va_lookup_key * key) 
{

    u32 index, next;
    int entry_found = 0;
    va_bucket_t * bucket;
 
    bucket  = &va_bucket[bucket_index];
    index   = bucket->head_entry;
    next    = bucket->next_available_entry;

    FRAG_DEBUG_PRINTF4(
        "\nVA_DB_DELETE_ENTRY: bucket index %d head %d next %d\n",
	bucket_index, index, next);

    /* loop through the entries in the bucket */
    while( index != next) {
        if(PREDICT_TRUE(memcmp(&bucket->va_entry[index], key,
	                       VA_KEY_SIZE)==0)) {
            /* Clear the entry */
	    FRAG_DEBUG_PRINTF1("Entry found in delete API");
 	    memset(&bucket->va_entry[index], 0, sizeof(va_entry_t));
 	    entry_found = 1;
            break;
        }
        index = (index +1) & VA_BUCKET_MASK;
    }
    return entry_found;
}    
  


void cnat_va_bucket_used (int argc, unsigned long * argv) 
{

    u32 i, sum = 0;;

    for(i=0;i<VA_BUCKETS;i++)  {

        if(PREDICT_TRUE(va_bucket[i].new_entry_counter)) sum++;

    }

    if (PREDICT_FALSE(!sum)) {
        printf("no bucket in use\n");
        return;
    }

    printf("index head next counter (%d bucket in use)\n", sum);

    for(i=0;i<VA_BUCKETS;i++) {

        if (PREDICT_FALSE(!va_bucket[i].new_entry_counter)) continue; 

        printf(" %04d %04d %04d %d\n", i,
                va_bucket[i].head_entry,
                va_bucket[i].next_available_entry,
                va_bucket[i].new_entry_counter);

    }
}

void cnat_va_dump (int argc, unsigned long * argv) 
{

    u32 i, sum, index ;

    PLATFORM_DEBUG_PRINT("====== SUMMARY ======\n");
    PLATFORM_DEBUG_PRINT("Total buckets:      %d\n", VA_BUCKETS);
    PLATFORM_DEBUG_PRINT("Entries per bucket: %d\n", VA_ENTRY_PER_BUCKET);

    sum = 0;

    for(i=0; i<VA_BUCKETS; i++) {
        if (PREDICT_TRUE(va_bucket[i].new_entry_counter > 0)) sum ++;
    }

    PLATFORM_DEBUG_PRINT("buckets in use:     %d\n", sum); 

    sum = 0;
    for(i=0; i<VA_BUCKETS; i++) {

        if ( PREDICT_FALSE(((va_bucket[i].next_available_entry+1) & VA_BUCKET_MASK)  
               == va_bucket[i].head_entry)) {

            sum ++;
        }
    }

    PLATFORM_DEBUG_PRINT("bucket full:        %d\n", sum); 

    /* dump per bucket info */

    if (argc == 0 ) return;

    index = (u32) argv[0];

    if (PREDICT_FALSE(index >= VA_BUCKETS)) {
        PLATFORM_DEBUG_PRINT("invalid bucket index %d\n", index);
        return;
    }

    PLATFORM_DEBUG_PRINT("\n====== Bucket %d ======\n", index);

    PLATFORM_DEBUG_PRINT("bucket head index %d\n", va_bucket[index].head_entry);

    PLATFORM_DEBUG_PRINT("bucket next index %d\n", va_bucket[index].next_available_entry);

    PLATFORM_DEBUG_PRINT(" source IP     dest IP     VRF  ip-id   srcP  dstP\n");

    for(i=0;i<VA_ENTRY_PER_BUCKET;i++) {
        hex_dump((u8*)&va_bucket[index].va_entry[i], sizeof(va_entry_t));
    }

}
