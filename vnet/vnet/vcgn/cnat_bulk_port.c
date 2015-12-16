/* 
 *------------------------------------------------------------------
 * cnat_bulk_ports.c - wrappers for bulk port allocation
 *
 * Copyright (c) 2011-2013 Cisco and/or its affiliates.
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


#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vppinfra/error.h>
#include <vnet/buffer.h>
#include <vppinfra/vec.h>
#include <vppinfra/hash.h>
#include <vppinfra/pool.h>
#include <vppinfra/bitmap.h>

#include "cnat_db.h"
#include "cnat_config.h"
#include "cnat_global.h"
#include "cnat_logging.h"
#include "spp_timers.h"
#include "platform_common.h"
#include "cgn_bitmap.h"
#include "spp_platform_trace_log.h"
#include "cnat_ports.h"

#ifndef NO_BULK_LOGGING

#define PORT_TO_CACHE(y, z)   ((y)/(z))
/* The last bit (MSB) is used to indicate whether the cache entry is full */
#define CACHE_TO_PORT(x, z)   (((x)& 0x7FFF) * (z))
#define IS_CACHE_ENTRY_FULL(x) ((x) & 0x8000)
#define MARK_CACHE_ENTRY_AS_FULL(x) ((x) = ((x) | 0x8000))
#define UNMARK_CACHE_ENTRY_AS_FULL(x) ((x) = ((x) & 0x7FFF))
#define CACHE_ENTRY_WITHOUT_FULL_STAT(x) ((x) & 0x7FFF) 


#define NUM_BULK_CHECK  128 /* max number of previous chache to check.
    * somewhat orbirtrary.. assume 64 as bulk size.. can handle up 
    * to 128*64 ports allocated by a single subscriber */

/* #define DEBUG_BULK_PORT 1 */
/* #define DEBUG_BULK_PORT_DETAIL   1   */
#define HAVE_BULK_PORT_STATS    1 

#ifdef HAVE_BULK_PORT_STATS
static uword bulk_cache_hit_count;
static uword bulk_port_use_count;
static uword bulk_port_alloc_count;
static uword mapped_port_alloc_count;
#endif /* HAVE_BULK_PORT_STATS */

static u32 bulk_port_rand_across;

void show_bulk_port_allocation(u16 in_vrfid, u32 inside_ip)
{
    cnat_db_key_bucket_t u_ki;
    cnat_user_db_entry_t *udb;
    int i;
    u32 head;
    cnat_main_db_entry_t *db = NULL;
    i16 printed_so_far = 0; /* entries printed so far */
    u16 prev_bulks[NUM_BULK_CHECK]; 
    cnat_vrfmap_t *my_vrfmap = 0;
    cnat_vrfmap_t *vrfmap = 0;
    bulk_alloc_size_t bulk_size;

    u_ki.k.k.vrf = in_vrfid;
    u_ki.k.k.ipv4 = inside_ip; 
    u_ki.k.k.port = 0;

    PLATFORM_DEBUG_PRINT("Searching for user %x in invrf %d\n",
        inside_ip, in_vrfid);
    udb = cnat_user_db_lookup_entry(&u_ki);
    if(!udb) {
        PLATFORM_DEBUG_PRINT("No such user\n"); return; 
    }

    pool_foreach (vrfmap, cnat_map_by_vrf, ({
        if(vrfmap->i_vrf == in_vrfid) {
            my_vrfmap = vrfmap;
            break;
        }}));

    if(!my_vrfmap) {
        PLATFORM_DEBUG_PRINT("Vrf map not found\n");
        return;
    }
    bulk_size = BULKSIZE_FROM_VRFMAP(my_vrfmap);

    if(bulk_size == BULK_ALLOC_SIZE_NONE) {  
        PLATFORM_DEBUG_PRINT("Bulk allocation not enabled\n"); 
        return;
    }
    
    PLATFORM_DEBUG_PRINT("\nBulk cache for subscriber 0x%x: ", inside_ip);
    for(i=0; i < BULK_RANGE_CACHE_SIZE; i++) {
        PLATFORM_DEBUG_PRINT("%d , ", 
            CACHE_TO_PORT(udb->bulk_port_range_cache[i], bulk_size));
    }
    PLATFORM_DEBUG_PRINT("\nNon cached bulk allocation for subscriber 0x%x:\n", 
            inside_ip);
    ASSERT(udb);
    memset(prev_bulks, 0,sizeof(prev_bulks));

    head = udb->translation_list_head_index;
    if(PREDICT_FALSE(head == EMPTY)) {
        return;
    }
    db = cnat_main_db + head;
    while (1) { 
        /* skip static ports - static ports may not belong to bulk pool*/
        if(db->out2in_key.k.port < cnat_static_port_range) goto next_entry;

        u16 bm_index = PORT_TO_CACHE(db->out2in_key.k.port, bulk_size);

        /*Check if we have already tested this bulk */
        for(i=0; i < printed_so_far; i++) {
            if(prev_bulks[i] == bm_index) goto next_entry;
        }

        /*Check if this base port is already part of cache */
        for(i=0; i < BULK_RANGE_CACHE_SIZE; i++) {
            if(CACHE_ENTRY_WITHOUT_FULL_STAT(udb->bulk_port_range_cache[i])
                == bm_index) {
                goto next_entry;
            }
        }
        /* this is not in chache already */
        PLATFORM_DEBUG_PRINT("%d ", CACHE_TO_PORT(bm_index, bulk_size));
        if(printed_so_far <  NUM_BULK_CHECK) {
            prev_bulks[printed_so_far] = bm_index;
            printed_so_far++;
        }

next_entry:
        db = cnat_main_db + db->user_ports.next;
        /*
         * its a circular list, so if we have reached the head again
         * all the entries for that user have been read
         */
        if (db == (cnat_main_db + head)) {
            break;
        }
    } /* while loop for db entries */

    PLATFORM_DEBUG_PRINT("\n");
    return;
}

void show_bulk_port_stats()
{

    cnat_vrfmap_t *my_vrfmap = 0;
    PLATFORM_DEBUG_PRINT("Bulk size settings of each inside vrf ...\n");
    pool_foreach (my_vrfmap, cnat_map_by_vrf, ({
        PLATFORM_DEBUG_PRINT("vrf id %d, bulk size %d\n", my_vrfmap->i_vrf,
                BULKSIZE_FROM_VRFMAP(my_vrfmap));
        }));

#ifdef HAVE_BULK_PORT_STATS
    PLATFORM_DEBUG_PRINT("\nBulk port allocation, use and cache hit statistics\n");
    PLATFORM_DEBUG_PRINT("Number of times bulk ports allocated %lld\n", 
            bulk_port_alloc_count);
    PLATFORM_DEBUG_PRINT("Number of times pre-allocated ports used %lld\n",
            bulk_port_use_count);
    PLATFORM_DEBUG_PRINT(
        "Number of times pre-allocated bulk port found from cache %lld\n",
        bulk_cache_hit_count);
    PLATFORM_DEBUG_PRINT(
        "Number of times mapped port (static) allocations made %lld\n", 
         mapped_port_alloc_count);
#else 
    PLATFORM_DEBUG_PRINT("\nNat44 bulk port statistics not turned on\n");
#endif /* HAVE_BULK_PORT_STATS */
}

void clear_bulk_port_stats()
{
#ifdef HAVE_BULK_PORT_STATS
    bulk_port_alloc_count = 0;
    bulk_port_use_count = 0;
    bulk_cache_hit_count = 0;
    mapped_port_alloc_count = 0;
#endif /* HAVE_BULK_PORT_STATS */
    return;
}

void cnat_update_bulk_range_cache(cnat_user_db_entry_t *udb, u16 o_port, 
        bulk_alloc_size_t bulk_size)
{
    i16 i;
    if(!udb) {
#ifdef DEBUG_BULK_PORT    
        PLATFORM_DEBUG_PRINT("%s, null udb!\n", __func__);
#endif
        return;        
     }
    if(BULK_ALLOC_SIZE_NONE == bulk_size) { /* no bulk logging */
        return;
    }

    /* Take care of caching */
    if(o_port & 0x1) {
        o_port--;
    }
    if(PREDICT_FALSE(o_port <= 0)) {
#ifdef DEBUG_BULK_PORT
        PLATFORM_DEBUG_PRINT("%s invalid port: %d\n", __func__, o_port);
#endif 
        return;
    }

    /* First preference is for the cache entry's that are not used yet */
    for(i=0; i < BULK_RANGE_CACHE_SIZE; i++) {
        if(PREDICT_FALSE(
            udb->bulk_port_range_cache[i] == (i16)BULK_RANGE_INVALID)) {
            udb->bulk_port_range_cache[i] = PORT_TO_CACHE(o_port, bulk_size); 
            return;
        }
    }

    /* Now check if any cache entry is full and if it can be replaced */
    for(i=0; i < BULK_RANGE_CACHE_SIZE; i++) {
        if(PREDICT_FALSE(IS_CACHE_ENTRY_FULL(udb->bulk_port_range_cache[i]))) {
            udb->bulk_port_range_cache[i] = PORT_TO_CACHE(o_port, bulk_size); 
            return;
        }
    }

    return;
}


void cnat_port_free_v2_bulk (
            cnat_portmap_v2_t    *pm,
            int                index,
            port_pair_t        ptype,
            u16                base_port,
            cnat_user_db_entry_t *udb,
            u16               static_port_range,
            bulk_alloc_size_t    bulk_size,
            int                *nfv9_log_req)
{
    cnat_portmap_v2_t *my_pm;
    i16 bm_index;
    i16 i;
    int unmark_full_status = 0;

    *nfv9_log_req = BULK_ALLOC_NOT_ATTEMPTED;
    
    /* First free up the port */
    cnat_port_free_v2(pm, index, ptype, base_port, static_port_range);
    if(BULK_ALLOC_SIZE_NONE == bulk_size) /* no bulk logging */
        return;
    if(PREDICT_FALSE(!udb)) {
#ifdef DEBUG_BULK_PORT
        PLATFORM_DEBUG_PRINT("%s udb is null\n", __func__);
#endif
    }

    if(PREDICT_FALSE(base_port < static_port_range)) {
        return;
    }
    /* Now check if cache needs to be removed */
    my_pm = pm + index;
    base_port = base_port/bulk_size;
    base_port = base_port * bulk_size; /*Align it to multiples of bulk_size */
    if(PREDICT_TRUE(!cgn_clib_bitmap_check_if_all(
        my_pm->bm, base_port, bulk_size))) {
        *nfv9_log_req = CACHE_ALLOC_NO_LOG_REQUIRED;
        unmark_full_status = 1;
        /* One or more ports are still in use */
    } else {
        *nfv9_log_req = base_port; /* logging required now. indicate base port*/
    }
    bm_index = PORT_TO_CACHE(base_port, bulk_size);
    /* Now check if this is in the cache */
    for(i=0; i < BULK_RANGE_CACHE_SIZE; i++) {
        if(PREDICT_FALSE(
            CACHE_ENTRY_WITHOUT_FULL_STAT(udb->bulk_port_range_cache[i]))
            == bm_index) {
            if(unmark_full_status) {
                /* Unmark full stat.. if it was marked so..*/
                UNMARK_CACHE_ENTRY_AS_FULL(udb->bulk_port_range_cache[i]);
            } else {
                udb->bulk_port_range_cache[i] = (i16)BULK_RANGE_INVALID; 
#ifdef DEBUG_BULK_PORT
                PLATFORM_DEBUG_PRINT(
                    "Clearing cache for client 0x%x, bulk port %d\n", 
                    my_pm->ipv4_address, base_port);
#endif
            }
            break; 
        }
    }
    return;
}


/* Get suitable port from range */
static i16 get_suiting_port_pos_from_range(cnat_portmap_v2_t *my_pm, 
    u16 bulk_start, i16 bulk_size, port_pair_t pair_type)
{
    i16 num_pos = 0, num_bits, iterations;
    uword bulk_ports;
    i16 inc = 0;
    i16 num_uwords = bulk_size/BITS(my_pm->bm[0]);

    if(PREDICT_FALSE(!num_uwords)) {
        iterations = 0;
        num_bits = bulk_size;
        bulk_size = 0;
    } else {
        bulk_port_rand_across = randq1(bulk_port_rand_across);    
        iterations = bulk_port_rand_across % num_uwords;
        num_bits = BITS(my_pm->bm[0]);
    }

    do {
        bulk_ports = cgn_clib_bitmap_get_bits(my_pm->bm, 
            (bulk_start + iterations * BITS(my_pm->bm[0])), num_bits);
#ifdef DEBUG_BULK_PORT_DETAIL
        PLATFORM_DEBUG_PRINT("%s %d, bulk start %d, num_bits %d, ports %lld \n",
            __func__, __LINE__, bulk_start, num_bits, bulk_ports);
#endif /* DEBUG_BULK_PORT_DETAIL */
        if(PREDICT_FALSE(!bulk_ports)) goto next_uword;
        if(PREDICT_TRUE((pair_type == PORT_SINGLE)
            || (pair_type == PORT_PAIR))) {
            num_pos =0;
            inc = 1;
        } else if(pair_type == PORT_S_ODD) {
            num_pos = 1;
            inc = 2;
        } else if(pair_type == PORT_S_EVEN) {
            num_pos =0;
            inc = 2;
        }    

        for(; num_pos < num_bits; num_pos = num_pos + inc) {
            if(!((bulk_ports >> num_pos) & 1))
                continue; /* In use */
            /* Check if the available port meets our
             * criteria such as add, even, pair etc */
            else if(PREDICT_FALSE(
                (pair_type == PORT_PAIR) && ((num_pos & 0x1) ||
                (!((bulk_ports >> (num_pos + 1)) & 1)))))
                    continue;
            else break; /* Found one that meets the criteria */
        }
        if(num_pos < num_bits) 
            return (num_pos + iterations * BITS(my_pm->bm[0]));
next_uword:        
        num_bits = BITS(my_pm->bm[0]);
        bulk_size -= BITS(my_pm->bm[0]);
        iterations++;
        if(iterations >= num_uwords) iterations = 0;
    } while (bulk_size >  0);

    return -2; /* nothing found */
}

static cnat_errno_t try_bulk_port_from_non_cache(
            cnat_user_db_entry_t *udb,
            cnat_portmap_v2_t *my_pm,
            port_pair_t pair_type,
            bulk_alloc_size_t bulk_size,
            u16 *port_available,
            u16  static_port_range
    )
{
    /****
    1. user should have existing translations.. otherwise, we wouldn't get here.
    2. For each, get the outside port. get the base port. 
       check if it is already in cache
    3. if not, we stand chance.
    4. Check for availability from this non cached pool.
    5. if found, repalce this with one of the cache that is invalid or full??
    6. if we are replacing the cache.. it has to be governed by user 
        preference on prefer oldest pool or prefer newest pool
    ********/
    u32 head;
    cnat_main_db_entry_t *db = NULL;
    u16 bulk_start; /* start point in 64 bitmap array to search for port */
    i16 port_pos; /* indicates the position of available port in bulk */
    i16 i; /* just a counter */
    i16 attempts_so_far = 0; /* (futile-;) attemps so far..*/
    u16 prev_bulks[NUM_BULK_CHECK]; 
    ASSERT(udb);
    memset(prev_bulks, 0,sizeof(prev_bulks));

    head = udb->translation_list_head_index;
    if(PREDICT_FALSE(head == EMPTY)) return CNAT_NO_PRE_ALLOCATED_BULK_PORTS;

    db = cnat_main_db + head;
    while (1) { //what should be the limit??

        /* skip static ports - static ports may not belong to bulk pool*/
        if(db->out2in_key.k.port < static_port_range) goto next_entry;

        u16 bm_index = PORT_TO_CACHE(db->out2in_key.k.port, bulk_size);

        /*Check if we have already tested this bulk */
        for(i=0; i < attempts_so_far; i++) {
            if(prev_bulks[i] == bm_index) { 
                goto next_entry;
            }
        }

        /*Check if this base port is already part of cache */
        for(i=0; i < BULK_RANGE_CACHE_SIZE; i++) {
            if(CACHE_ENTRY_WITHOUT_FULL_STAT(udb->bulk_port_range_cache[i])
                == bm_index)
                goto next_entry;
        }

        /* this is not in chache already */
        bulk_start = CACHE_TO_PORT(bm_index, bulk_size);
        port_pos = get_suiting_port_pos_from_range(my_pm, 
                bulk_start, bulk_size, pair_type);

        if(port_pos < 0) { /* no port available in this range */
            /* Mark this bulk so that we don't have to try this again */
            if(attempts_so_far <  NUM_BULK_CHECK) {
                prev_bulks[attempts_so_far] = bm_index;
                attempts_so_far++;
            }
            goto next_entry;
        }

        /* Got one...Get the port number */
        *port_available = bulk_start + port_pos;

        /* Check to see if we shoud replace one of the cache */
        for(i=0; i < BULK_RANGE_CACHE_SIZE; i++) {
            if(PREDICT_FALSE((udb->bulk_port_range_cache[i] 
                == (i16)BULK_RANGE_INVALID) || (
                IS_CACHE_ENTRY_FULL(udb->bulk_port_range_cache[i])))) {
                udb->bulk_port_range_cache[i] = bm_index;
                return CNAT_SUCCESS;
            }
        }
        /* Check to replace an existing (in use) entry */
        /* TODO: enforce policy */
        /* order of looping should depend on policy */

        return CNAT_SUCCESS;

next_entry:
        db = cnat_main_db + db->user_ports.next;
        /*
         * its a circular list, so if we have reached the head again
         * all the entries for that user have been read
         */
        if (db == (cnat_main_db + head)) {
            break;
        }
    } /* while loop for db entries */
    /* no ports available from pre allocated bulk pool */
    return CNAT_NO_PORT_FROM_BULK;
}

cnat_errno_t
cnat_dynamic_port_alloc_v2_bulk (
                 cnat_portmap_v2_t    *pm,
                 port_alloc_t         atype,
                 port_pair_t          pair_type,
                 u32                  *index,
                 u32                  *o_ipv4_address,
                 u16                  *o_port,
                 u16                  static_port_range,
                 cnat_user_db_entry_t *udb,
                 bulk_alloc_size_t    bulk_size,
                 int                  *nfv9_log_req,
                 u16                  ip_n_to_1,
                 u32                  *rseed_ip
                 )
{

    cnat_errno_t rv;
    u16 port_available = 0;
    i16  i;
    cnat_portmap_v2_t *my_pm;

    if((BULK_ALLOC_SIZE_NONE != bulk_size) /* bulk logging enabled */
        &&  (udb)) {  /* This user does have translations already */
        u16 bulk_start;
        i16 port_pos;

        my_pm = pm + *index;
        /* We have a case to check if bulk allocated ports can be used */
        /* TODO: order of looping to be based on policy
         * like prefer older or prefer newer ?? 
         * For now, start with most recent cache entry
         * so that we stand a better chance of 
         * finding a port
         */
        for(i= 0; i < BULK_RANGE_CACHE_SIZE; i++) {
            if(PREDICT_TRUE((udb->bulk_port_range_cache[i] == 
                (i16)BULK_RANGE_INVALID) || 
                IS_CACHE_ENTRY_FULL(udb->bulk_port_range_cache[i]))) {
                continue; /* This range is not initialized yet or it is full */
            }
            bulk_start = CACHE_TO_PORT(udb->bulk_port_range_cache[i], 
                    bulk_size);
            port_pos = get_suiting_port_pos_from_range(my_pm, 
                bulk_start, bulk_size, pair_type);
            if(PREDICT_FALSE(port_pos < 0)) { 
                /* Mark this cache entry as full so that we do not 
                 * waste time on this entry again */
                MARK_CACHE_ENTRY_AS_FULL(udb->bulk_port_range_cache[i]);
#ifdef DEBUG_BULK_PORT 
                PLATFORM_DEBUG_PRINT("Marked bulk cache entry %d as full for %x \n",
                i, my_pm->ipv4_address);
#endif /*  #ifdef DEBUG_BULK_PORT */
                continue;
            }
            /* Get the port number */
            port_available = bulk_start+ port_pos;
#ifdef DEBUG_BULK_PORT
            PLATFORM_DEBUG_PRINT(
                "Found port from cache : IP 0x%x, port %d %d iterations\n",
                my_pm->ipv4_address, port_available, i)
#endif 
#ifdef HAVE_BULK_PORT_STATS
            bulk_cache_hit_count++;
#endif /* HAVE_BULK_PORT_STATS */
            break;
        } /* end of for loop for cache check */
        /* If we have not found a port yet, check if we can have 
         *   pre allocated bulk port from non-cache */
        if(PREDICT_FALSE(i == BULK_RANGE_CACHE_SIZE)) { 
            if( try_bulk_port_from_non_cache(udb, my_pm, pair_type,
                bulk_size, &port_available, 
                static_port_range) != CNAT_SUCCESS ) {
                goto ALLCOATE_NEW_BULK;
            }
#ifdef DEBUG_BULK_PORT
            PLATFORM_DEBUG_PRINT("Found port from non-cache : IP 0x%x, port %d\n",
                my_pm->ipv4_address, port_available);
#endif 
        }
        /* Assign the port, mark it as in use */
        cgn_clib_bitmap_clear_no_check(my_pm->bm, port_available);
        (my_pm->inuse)++;
        if(PREDICT_FALSE(pair_type == PORT_PAIR)) {/* Mark the next one too */
            cgn_clib_bitmap_clear_no_check(my_pm->bm, port_available + 1);
            (my_pm->inuse)++;
        }
        *o_ipv4_address = my_pm->ipv4_address;
        *o_port = port_available;
        *nfv9_log_req = CACHE_ALLOC_NO_LOG_REQUIRED;
#ifdef HAVE_BULK_PORT_STATS
        bulk_port_use_count++;
#endif /* HAVE_BULK_PORT_STATS */
        return (CNAT_SUCCESS);
    } 
ALLCOATE_NEW_BULK:
#ifdef DEBUG_BULK_PORT
    if(BULK_ALLOC_SIZE_NONE != bulk_size) {
        PLATFORM_DEBUG_PRINT(
            "No port available from bulk cache, bulk size %d\n", bulk_size);
    }
#endif 
    /* For whatever reason, we have not got a port yet */
    rv = cnat_dynamic_port_alloc_v2(pm, atype, pair_type, index,
            o_ipv4_address, o_port, static_port_range, bulk_size, nfv9_log_req,
            ip_n_to_1, rseed_ip);
    if (PREDICT_FALSE(rv != CNAT_SUCCESS)) {
        return rv;
    }
    /* Take care of caching */
    if(PREDICT_FALSE(udb != NULL)) { 
        /* Predict false because, we usually allocate for new users */
        cnat_update_bulk_range_cache(udb, *o_port, bulk_size);
    }
#ifdef HAVE_BULK_PORT_STATS
        bulk_port_alloc_count++;
#endif /* HAVE_BULK_PORT_STATS */
    return (CNAT_SUCCESS);
}


cnat_errno_t
cnat_static_port_alloc_v2_bulk (
                 cnat_portmap_v2_t    *pm,
                 port_alloc_t         atype,
                 port_pair_t          pair_type,
                 u32                  i_ipv4_address,
                 u16                  i_port,
                 u32                  *index,
                 u32                  *o_ipv4_address,
                 u16                  *o_port,
                 u16                  static_port_range,
                 cnat_user_db_entry_t *udb,
                 bulk_alloc_size_t    bulk_size,
                 int                  *nfv9_log_req,
		 u16                  ip_n_to_1
		 )
{

    /***
     * Requirements - 
     * 1. If the port allocated is below dyn start, it should be individual 
     * port (not bulk)
     * 2.  If NOT, it should be bulk allocated
     * 3.  Try and keep the inside port same as outside port in both the 
     * cases (best effort)

     * Algorithm
     * 1.  Check if it is below stat port start or user is new or bulk is 
     * disabled. If yes, call existing function
     * 2.  If not, see if we can pick from bulk and yet try to keep the port 
     * same - difficult thing - check if the port is free - then check if the 
     * entire bulk is free - if not check if bulk is owned by the user already.
     * If all of these fail, call existing function to allocate a new bulk
     * 3.  Update cache, etc return log requirements
     *****/

    cnat_errno_t rv;
    i16  i;
    u32 head;
    cnat_portmap_v2_t *my_pm;
    uword bit_test_result, start_bit;
    cnat_main_db_entry_t *db = NULL;

    if((BULK_ALLOC_SIZE_NONE != bulk_size) /* bulk logging enabled */
        &&  (udb) && /* This user does have translations already */
        i_port >= static_port_range ) { /* It is outside stat port range*/

        my_pm = pm + *index;
        /* We have a case to check if bulk allocated ports can be used */

        /* First check if the required port is available. */
        if(PREDICT_FALSE(clib_bitmap_get_no_check(my_pm->bm, i_port) == 0)) {
            goto ALLOCATE_NEW_BULK_STATIC;
        }

        /* Port is free.. check if the bulk is also free */
        start_bit= ((i_port/bulk_size) * bulk_size);
        bit_test_result = cgn_clib_bitmap_check_if_all(my_pm->bm,
                            start_bit, bulk_size);
        if(PREDICT_TRUE(bit_test_result)) { /* bulk is available, grab it */
            goto ALLOCATE_NEW_BULK_STATIC;
        }

        /* else, bulk is taken by someone. check if it is me */
        /* Check if we own the bulk by any chance */
        for(i=0; i < BULK_RANGE_CACHE_SIZE; i++) {
            if(udb->bulk_port_range_cache[i] == start_bit) break;
        }
        if(i == BULK_RANGE_CACHE_SIZE) { /* no luck with cache */        
            head = udb->translation_list_head_index;
            if(PREDICT_FALSE(head == EMPTY)) 
                goto ALLOCATE_NEW_BULK_STATIC;
            db = cnat_main_db + head;
            i = 0;
            while(1) {
                if((db->out2in_key.k.port/bulk_size) * bulk_size ==                                             start_bit) {    
                        i = 1; /* Just to indicate it is found */
                        break;
                }
                db = cnat_main_db + db->user_ports.next;
                /*
                 * its a circular list, so if we have reached the head again
                 * all the entries for that user have been read
                 */
                if (db == (cnat_main_db + head)) break;
            } /* while loop for db entries */
            if(!i) {
                goto ALLOCATE_NEW_BULK_STATIC;    
            }
        }        
        /* Assign the port, mark it as in use */
        cgn_clib_bitmap_clear_no_check(my_pm->bm, i_port);
        (my_pm->inuse)++;
        *o_ipv4_address = my_pm->ipv4_address;
        *o_port = i_port;
        *nfv9_log_req = CACHE_ALLOC_NO_LOG_REQUIRED;
#ifdef HAVE_BULK_PORT_STATS
        bulk_port_use_count++;
#endif /* HAVE_BULK_PORT_STATS */

#ifdef DEBUG_BULK_PORT
        PLATFORM_DEBUG_PRINT("%s, %d, found stat port from bulk: %x, %d\n", 
            __func__, 
            __LINE__, *o_ipv4_address, *o_port);
#endif /* DEBUG_BULK_PORT */
        return (CNAT_SUCCESS);
    } 

ALLOCATE_NEW_BULK_STATIC:
#ifdef DEBUG_BULK_PORT
    PLATFORM_DEBUG_PRINT("%s No port available from bulk cache, bulk size %d\n", 
            __func__,bulk_size);
#endif 
    /* For whatever reason, we have not got a port yet */
    rv = cnat_static_port_alloc_v2(pm, atype, pair_type, i_ipv4_address,
            i_port, index, o_ipv4_address, o_port, static_port_range,
            bulk_size, nfv9_log_req,ip_n_to_1);
    if (PREDICT_FALSE(rv != CNAT_SUCCESS)) {
        return rv;
    }
    /* Take care of caching only if it was a bulk alloc */
    if(PREDICT_FALSE(udb && (BULK_ALLOC_NOT_ATTEMPTED != *nfv9_log_req))) {
        cnat_update_bulk_range_cache(udb, *o_port, bulk_size);
    }
#ifdef HAVE_BULK_PORT_STATS
    bulk_port_alloc_count++;
#endif /* HAVE_BULK_PORT_STATS */
    return (CNAT_SUCCESS);

}

cnat_errno_t
cnat_mapped_static_port_alloc_v2_bulk (
            cnat_portmap_v2_t    *pm,
            port_alloc_t         atype,
            u32                  *index,
            u32                   ipv4_address,
            u16                   port,
            cnat_user_db_entry_t *udb,
            bulk_alloc_size_t    bulk_size,
            int                  *nfv9_log_req,
	    u16                  ip_n_to_1
	    )
{
    /* Requirements : 
     * 1. Check if bulk allocation is required.
     * 2. Call cnat_mapped_static_port_alloc_v2 to allocate
     * 3. Decide if alloc has to be cached
     * 4. Update nfv9_log_req
     */
    cnat_errno_t rv; 
    rv = cnat_mapped_static_port_alloc_v2 (pm,
        atype, index, ipv4_address, port, nfv9_log_req, bulk_size, ip_n_to_1);
    if (PREDICT_FALSE(rv != CNAT_SUCCESS)) {
        return rv;
    }
    /* Take care of caching only if it was a bulk alloc */
    if(PREDICT_FALSE(udb && (BULK_ALLOC_NOT_ATTEMPTED != *nfv9_log_req))) {
        int i;
        port = port*bulk_size;
        port = port/bulk_size; /* align it to bulk size boundary */
        for(i=0; i < BULK_RANGE_CACHE_SIZE; i++) {
            if(CACHE_ENTRY_WITHOUT_FULL_STAT(udb->bulk_port_range_cache[i])
                == PORT_TO_CACHE(port, bulk_size))
                break; 
        }
        if( i == BULK_RANGE_CACHE_SIZE) { /* else, it is alredy in cache */
            cnat_update_bulk_range_cache(udb, port, bulk_size);
        }
    }
#ifdef HAVE_BULK_PORT_STATS
    mapped_port_alloc_count++;
#endif /* HAVE_BULK_PORT_STATS */
    return (CNAT_SUCCESS);
}


cnat_errno_t
cnat_dynamic_port_alloc_rtsp_bulk (
                 cnat_portmap_v2_t    *pm,
                 port_alloc_t         atype,
                 port_pair_t          pair_type,
                 u16                  i_port,
                 u32                  *index,
                 u32                  *o_ipv4_address,
                 u16                  *o_port,
                 u16                  static_port_range,
                 cnat_user_db_entry_t *udb,
                 bulk_alloc_size_t    bulk_size,
                 int                  *nfv9_log_req,
                 u32                  *rseed_ip)
{

    /***
     * Algorithm
     * 1. Compute the range of ports required based on the number of digits
     * in the port request made by the client.
     * 2. Check if bulk logging is enabled. If not, use the existing method.
     * 3. Check if there are 2 adjacent ports available that meet the above
     * criteria in any of the bulk allocations made already.
     * 4. If yes, mark them in use and return.
     * 5. If not allocate a new bulk and pick 2 ports in it
     ***/

    i16  i;
    cnat_portmap_v2_t *my_pm = 0;
    u32 start_port1, end_port1, start_port2, end_port2;
    int range_loop;
    u16 bulk_start;
    i16 port_pos;
    u16 port_available = 0;
    
    ASSERT(index);
    ASSERT(o_ipv4_address);
    ASSERT(o_port);
    
    /*
     * Check if the port is 4 digit or 5 digit.   I am assuming we are
     * not getting 3 (or 2 or 1) digit ports, which we cannot anyway
     * allocate same sized outside ports - as outside ports start from 1024
     *
     * Static Port has its own reserved range.  Ensure that the range is
     * such that atleast few 4 digit ports are available for RTSP.  If
     * not it does not make sense to do special allocation for RTSP.
     */
    if (PREDICT_TRUE(static_port_range < MIN_STATIC_PORT_RANGE_FOR_RTSP)) {
        /*
         * 4 digit port or less
         */
        if (i_port <= 9999) {
            start_port1  = static_port_range;
            end_port1    = 9999;
            
            start_port2 = 10000;
            end_port2   = PORTS_PER_ADDR - 1;
        } else { /* 5 digit port */
            start_port1 = 10000;
            end_port1   = PORTS_PER_ADDR - 1;
            
            start_port2 = static_port_range;
            end_port2   = 9999;
        }
    } else { /* Static port range is too big */
        start_port1 = static_port_range;
        end_port1   = PORTS_PER_ADDR - 1;
        
        /*
         * PORTS_PER_ADDR is just a placeholder for
         * INVALID_PORT, valid ports are b/w 1 and PORTS_PER_ADDR
         */
        start_port2 = PORTS_PER_ADDR;
        end_port2   = PORTS_PER_ADDR;
    }


    if(PREDICT_TRUE(udb != NULL)) {
        my_pm = pm + *index;
    }

    /* Now check if this user already owns a bulk range that is 
     * within start range 1 
     */

    u32 start_range = start_port1;
    u32 end_range = end_port1;
    for(range_loop = 0; range_loop < 2; range_loop++) {
        if((BULK_ALLOC_SIZE_NONE == bulk_size) || (!udb)) {
            goto ALLOCATE_NEW_RTSP_PORTS;
        }
        for(i= 0; i < BULK_RANGE_CACHE_SIZE; i++) {
            if(PREDICT_TRUE((udb->bulk_port_range_cache[i] == 
                (i16)BULK_RANGE_INVALID) || 
                IS_CACHE_ENTRY_FULL(udb->bulk_port_range_cache[i]))) {
                continue; /* This range is not initialized yet or it is full */ 
            }

            bulk_start = CACHE_TO_PORT(udb->bulk_port_range_cache[i], 
                        bulk_size);
            if(bulk_start < start_port1 || bulk_start >= end_port1) {
                continue; /* Not in the range */
            }

            port_pos = get_suiting_port_pos_from_range(my_pm, 
                bulk_start, bulk_size, pair_type);
            if(PREDICT_FALSE(port_pos < 0)) { 
                /*  Not Marking  this cache entry as full as it failed 
                 * for pair type. It might have individual entries
                 */
                continue;
            }
            /* Get the port number */
            port_available = bulk_start+ port_pos;
#ifdef DEBUG_BULK_PORT
            PLATFORM_DEBUG_PRINT(
                "Found port from cache : IP 0x%x, port %d %d iterations\n",
                my_pm->ipv4_address, port_available, i)
#endif 
#ifdef HAVE_BULK_PORT_STATS
            bulk_cache_hit_count += 2;
#endif /* HAVE_BULK_PORT_STATS */
            break;
        } /* end of for loop for cache check */

        if(PREDICT_FALSE(i == BULK_RANGE_CACHE_SIZE)) { 
            /* we have not found a port yet, but to do not want to try 
             * non-cache bulks.. because, it is a very low probability and 
             * do not want to tweak that code for this special case
             * The impact of non checking the non-cache is, we give this 
             * user few  extra ports .. which is OK
             */
            goto ALLOCATE_NEW_RTSP_PORTS;
        }
#ifdef DEBUG_BULK_PORT
        PLATFORM_DEBUG_PRINT("RTSP: Found port from non-cache : IP 0x%x, port %d\n",
                my_pm->ipv4_address, port_available);
#endif 

        /* Assign the port, mark it as in use */
        cgn_clib_bitmap_clear_no_check(my_pm->bm, port_available);
        (my_pm->inuse)++;
        cgn_clib_bitmap_clear_no_check(my_pm->bm, port_available + 1);
        (my_pm->inuse)++;

        *o_ipv4_address = my_pm->ipv4_address;
        *o_port = port_available;
        *nfv9_log_req = CACHE_ALLOC_NO_LOG_REQUIRED;
#ifdef HAVE_BULK_PORT_STATS
        bulk_port_use_count += 2;
#endif /* HAVE_BULK_PORT_STATS */
        return (CNAT_SUCCESS);

ALLOCATE_NEW_RTSP_PORTS:
        /* No luck. Let's try allocating new bulk.. */
        if(PREDICT_TRUE(CNAT_SUCCESS == cnat_dynamic_port_alloc_rtsp 
            (pm, atype, pair_type,
                start_range, end_range,index, o_ipv4_address, 
                o_port, bulk_size, nfv9_log_req,rseed_ip))) {
            if(PREDICT_FALSE(udb && 
                (BULK_ALLOC_NOT_ATTEMPTED != *nfv9_log_req))) {
                cnat_update_bulk_range_cache(udb, *o_port, bulk_size);
            }
#ifdef HAVE_BULK_PORT_STATS
            bulk_port_alloc_count++;
#endif /* HAVE_BULK_PORT_STATS */
            return CNAT_SUCCESS; 
        }

        /* Could not allocate in range 1.. so move to range 2. */
        start_range = start_port2;
        end_range = end_port2;

    }

    return (CNAT_NOT_FOUND_DIRECT); /* if we are here, we could not get any ports */

}

#else /* Dummy definitions */
void show_bulk_port_stats()
{
    PLATFORM_DEBUG_PRINT("\nBulk logging feature not included\n");
}

 void clear_bulk_port_stats()
{
    PLATFORM_DEBUG_PRINT("\nBulk logging feature not included\n");
}
#endif /* NO_BULK_LOGGING */
