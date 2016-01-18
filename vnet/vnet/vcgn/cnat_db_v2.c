/* 
 *------------------------------------------------------------------
 * cnat_db_v2.c - translation database definitions
 *
 * Copyright (c) 2007-2013 Cisco and/or its affiliates.
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
#include <vppinfra/vec.h>
#include <vppinfra/bitmap.h>
#include <vppinfra/hash.h>
#include <vppinfra/pool.h>
#include <vppinfra/clib.h>
#include <vppinfra/error.h>

#include "cnat_db.h"
#include "cnat_config.h"
#include "cnat_global.h"
#include "cnat_v4_functions.h"
#include "cnat_log_api.h"
#include "cnat_cli.h"
#include "spp_platform_trace_log.h"
#include "cnat_bulk_port.h"
#include "nat64_db.h"
#include "dslite_db.h"
#include "cnat_config_api.h"

#define HASH_TABLE_SIZE  8192 // hash table size
#define THROTTLE_TIME  180 // throttle time value for out of port msg/user

u8 cnat_db_init_done = 0;

typedef struct {
  u32 cached_next_index;
  /* $$$$ add data here */

  /* convenience variables */
  vlib_main_t * vlib_main;
  vnet_main_t * vnet_main;
} cnat_db_v2_main_t;

cnat_db_v2_main_t cnat_db_v2_main;

#if 1
/* TOBE_PORTED : Remove the following once fixed */
#undef PREDICT_TRUE
#undef PREDICT_FALSE
#define PREDICT_TRUE(x) (x)
#define PREDICT_FALSE(x) (x)
#endif

#define foreach_cnat_db_v2_error \
_(DROP, "error-drop packets")

typedef enum {
#define _(sym,str) CNAT_DB_V2_##sym,
  foreach_cnat_db_v2_error
#undef _
  CNAT_DB_V2_N_ERROR,
} cnat_db_v2_error_t;

static char * cnat_db_v2_error_strings[] __attribute__((unused)) = {
#define _(sym,string) string,
  foreach_cnat_db_v2_error
#undef _
};


void cnat_table_entry_fill_map(u32 start_addr, u32 end_addr,
        cnat_portmap_v2_t **port_map_holder)
{
    u32 this_start_addr, this_end_addr, this_addr, new;
    u32 loop_count;
    u32 pm_len, i;
    cnat_portmap_v2_t *my_pm =0;
    cnat_portmap_v2_t *pm = 0;
    
    my_instance_number = 0; 

    this_start_addr = start_addr;
    this_end_addr   = end_addr;    

    /*
     * How many new addresses are getting added ??
     */
     /* commenting this. Right now end - start will be for this vCGN instance */
    //new = ((this_end_addr - this_start_addr) / MAX_CORES_PER_PARTITION) + 1;
    new = (this_end_addr - this_start_addr) + 1;

    pm = *port_map_holder;
    pm_len = vec_len(pm);
#if DEBUG_NOT_COMMENTED
    printf("this_start_addr = 0x%08X, this_end_addr = 0x%08X, Num Addr = %d\n",
        this_start_addr, this_end_addr, new);
    printf("pm_len = %d\n", pm_len);
#endif
    /* Check whether the address pool add requested already exists */
    my_pm = pm;
    for(i = 0; i< pm_len; i++) {
        if(my_pm->ipv4_address == this_start_addr) {
            printf("address pool with addr 0x%08X exists\n", this_start_addr);
            return;
        }
        my_pm++;
    }

    /*
     * For now give a warning message only....
     */
#if 0
    if ((total_address_pool_allocated + new) >
        CNAT_MAX_ADDR_POOL_SIZE_PER_CORE) {
        printf("address pool size (%d) would cross permissible limit (%u) \n",
            (total_address_pool_allocated + new),
            CNAT_MAX_ADDR_POOL_SIZE_PER_CORE);
    }
#endif

    total_address_pool_allocated += new;
    vec_add2(pm, my_pm, new);

#if DEBUG_NOT_COMMENTED
    printf("total_address_pool_allocated changed from %d to %d (added %d)",
        (total_address_pool_allocated - new),
        total_address_pool_allocated, new);
    printf("vec add is ok\n");
#endif

    memset(my_pm, 0, new*sizeof(*my_pm));
    this_addr = this_start_addr;
    loop_count = 0; /* Sanity counter */

    while (this_addr <= this_end_addr) {
#if DEBUG_NOT_COMMENTED
        printf("loop %d: this addr = 0x%08X\n", loop_count+1, this_addr);
#endif
        my_pm->ipv4_address = this_addr;
        /*
         * Set all bits to "1" indicating all ports are free
         */
        memset(my_pm->bm, 0xff,
            (((BITS_PER_INST + BITS(uword)-1)/BITS(uword))*(sizeof(uword))));
        //this_addr += MAX_CORES_PER_PARTITION;
        this_addr += 1;
        my_pm++;
        loop_count++;
    }
    /*
     * We should have loop_count same as the new value
     */
    if (loop_count != new) {
        printf("Mismatch in loop_count (%d) != new (%d)\n",
            loop_count, new);
    }

    *port_map_holder = pm;

#if DEBUG_NOT_COMMENTED
    printf("revised pm len %d\n", vec_len(*port_map_holder));
#endif

    return;
}

 
void cnat_delete_session_db_entry (cnat_session_entry_t *ep, u8 log);
void handle_cnat_port_exceeded_logging(
    cnat_user_db_entry_t *udb,
    cnat_key_t   * key,
    cnat_vrfmap_t *vrfmap);

cnat_global_counters_t cnat_global_counters;
u32  last_log_timestamp = 0;
u32  last_user_dyn_port_exc_timestamp = 0;
u32  last_user_stat_port_exc_timestamp = 0; 

index_slist_t *cnat_out2in_hash;
index_slist_t *cnat_in2out_hash;
index_slist_t *cnat_user_hash;
index_slist_t *cnat_timeout_hash;
index_slist_t *cnat_session_hash;

cnat_main_db_entry_t *cnat_main_db;
cnat_user_db_entry_t *cnat_user_db;
cnat_session_entry_t *cnat_session_db;
cnat_timeout_db_entry_t *cnat_timeout_db;

cgse_nat_db_entry_t   *cgse_nat_db;
cgse_nat_user_db_entry_t *cgse_user_db;
cgse_nat_session_db_entry_t *cgse_session_db;

nat44_dslite_common_stats_t nat44_dslite_common_stats[255]; /* 0 is for nat44 */
nat44_dslite_global_stats_t nat44_dslite_global_stats[2]; /* 0 for nat44 and 1 for dslite */
nat44_counters_stats_t      nat44_counters_stats[CNAT_MAX_VRFMAP_ENTRIES];
/*For displaying show cgn <cgn-name> inside-vrf <vrf-name> counters */

/*
 * This is the pool of vrf map structures used by latest main-db functions
 */
cnat_vrfmap_t *cnat_map_by_vrf;

/*
 * Have a mapping table of vrf_id-->vrf_map_index
 * This helps in easily getting the vrf_map structure during
 * main-db create paths
 */
u16 vrf_map_array[CNAT_MAX_VRFMAP_ENTRIES];
cnat_svi_params_entry svi_params_array[CNAT_MAX_VRFMAP_ENTRIES];
cnat_ingress_vrfid_name_entry vrfid_name_map[MAX_VRFID] = {{0}};
u64 in2out_drops_port_limit_exceeded;
u64 in2out_drops_system_limit_reached;
u64 in2out_drops_resource_depletion;
u64 no_translation_entry_drops;
u32 no_sessions;

#define CNAT_SET_ICMP_MSG_INFO \
if (PREDICT_TRUE((my_vrfmap->i_vrf < CNAT_MAX_VRFMAP_ENTRIES) &&             \
    (svi_params_array[my_vrfmap->i_vrf].ipv4_addr))) {                       \
    info->gen_icmp_msg = icmp_msg_gen_allowed();  \
    info->svi_addr = svi_params_array[my_vrfmap->i_vrf].ipv4_addr;           \
}

#define CNAT_DEBUG_INSIDE_ERR(err) \
if (((protocol == CNAT_UDP) && \
     (debug_i_flag & CNAT_DEBUG_ERR_UDP)) || \
    ((protocol == CNAT_TCP) && \
     (debug_i_flag & CNAT_DEBUG_ERR_TCP)) || \
    ((protocol == CNAT_ICMP) && \
     (debug_i_flag & CNAT_DEBUG_ERR_ICMP))) { \
    cnat_db_debug_error(&u_ki, err); \
}

#define DSLITE_DEBUG_INSIDE_ERR(err) \
if (((protocol == CNAT_UDP) && \
     (debug_i_flag & CNAT_DEBUG_ERR_UDP)) || \
    ((protocol == CNAT_TCP) && \
     (debug_i_flag & CNAT_DEBUG_ERR_TCP)) || \
    ((protocol == CNAT_ICMP) && \
     (debug_i_flag & CNAT_DEBUG_ERR_ICMP))) { \
    dslite_db_debug_error(&u_ki, err); \
}

#define PORT_LIMIT_LOW_THRESHOLD_FOR_SYSLOG    7
/* If the max_limit is less than 10, no meaningful throttling can be 
 * done.. so, log only once per user and never clear the flag 
 * once the user exceeds limit
 */
#define CHECK_CLEAR_PORT_LIMIT_EXCEED_FLAG(udb, max_limit) \
    if(PREDICT_FALSE(udb->flags & CNAT_USER_DB_PORT_LIMIT_EXCEEDED)) { \
        if(udb->ntranslations < \
            ((max_limit/10)*PORT_LIMIT_LOW_THRESHOLD_FOR_SYSLOG) && \
            max_limit >= 10) { \
            udb->flags = udb->flags & (~CNAT_USER_DB_PORT_LIMIT_EXCEEDED); \
        } \
    } 

#ifdef TOBE_PORTED
/* Commented to remove unused variable warning */
static char *debug_db_error[] = {
    "no error", /* CNAT_SUCCESS */
    "no config", /*CNAT_NO_CONFIG*/
    "not in run state", /*CNAT_NO_VRF_RUN*/
    "no pool for any", /*CNAT_NO_POOL_ANY*/
    "no port for any", /*CNAT_NO_PORT_ANY*/
    "bad in use for any", /*CNAT_BAD_INUSE_ANY*/
    "not found for any", /*CNAT_NOT_FOUND_ANY*/
    "invalid index for direct", /*CNAT_INV_PORT_DIRECT*/
    "deleted addr for direct", /*CNAT_DEL_PORT_DIRECT*/
    "bad in use for direct",/*CNAT_BAD_INUSE_DIRECT*/
    "not found for direct",/*CNAT_NOT_FOUND_DIRECT*/
    "out of port limit", /*CNAT_OUT_LIMIT*/
    "main db limit", /*CNAT_MAIN_DB_LIMIT*/
    "user db limit", /*CNAT_USER_DB_LIMIT*/
    "not static port", /*CNAT_NOT_STATIC_PORT*/
    "bad static port request", /*CNAT_BAD_STATIC_PORT_REQ*/
    "not this core", /*CNAT_NOT_THIS_CORE*/
    "parser error", /*CNAT_ERR_PARSER*/
    "invalid msg id", /*CNAT_ERR_INVALID_MSG_ID*/
    "invalid msg size", /*CNAT_ERR_INVALID_MSG_SIZE*/
    "invalid payload size", /*CNAT_ERR_INVALID_PAYLOAD_SIZE*/
    "bad tcp udp port", /*CNAT_ERR_BAD_TCP_UDP_PORT*/
    "bulk single failure", /*CNAT_ERR_BULK_SINGLE_FAILURE*/
    "xlat id invalid", /*CNAT_ERR_XLAT_ID_INVALID*/
    "xlat v6 prefix invalid", /*CNAT_ERR_XLAT_V6_PREFIX_INVALID*/
    "xlat v4 prefix invalid", /*CNAT_ERR_XLAT_V4_PREFIX_INVALID*/
    "xlat tcp mss invalid", /*CNAT_ERR_XLAT_TCP_MSS_INVALID*/
    "6rd id invalid", /*CNAT_ERR_6RD_ID_INVALID*/
    "6rd v4 tunnel src invalid", /*CNAT_ERR_6RD_V4_TUNNEL_SRC_INVALID*/
    "6rd v6 prefix invalid", /*CNAT_ERR_6RD_V6_PREFIX_INVALID*/
    "6rd v6 BR unicast invalid", /*CNAT_ERR_6RD_V6_BR_UNICAST_INVALID*/
    "6rd v4 prefix masklen invalid", /*CNAT_ERR_6RD_V4_PREFIX_MASK_LEN_INVALID*/
    "6rd v4 suffix masklen invalid", /*CNAT_ERR_6RD_V4_SUFFIX_MASK_LEN_INVALID*/
    "6rd v4 combo masklen invalid", /*CNAT_ERR_6RD_V4_COMBO_MASK_LEN_INVALID*/
    "6rd tunnel mtu invalid", /*CNAT_ERR_6RD_TUNNEL_MTU_INVALID*/
    "6rd tunnel ttl invalid", /*CNAT_ERR_6RD_TUNNEL_TTL_INVALID*/
    "6rd tunnel tos invalid", /*CNAT_ERR_6RD_TUNNEL_TOS_INVALID*/
};
#endif

f64 port_log_timestamps[HASH_TABLE_SIZE]; /* 32 KB array per core */

void port_exceeded_msg_log (u32 src_addr, u16 i_vrf)
{
    u32 hash_value;
    f64 current_timestamp;
    vlib_main_t  *vlib_main;

    vlib_main = vlib_get_main();
    current_timestamp = vlib_time_now((vlib_main_t *) vlib_main);

    hash_value = ((src_addr >> 16) ^ ((src_addr & 0xffff) ^ i_vrf)) % (1024*8); 

    if (PREDICT_FALSE((current_timestamp - port_log_timestamps[hash_value]) > THROTTLE_TIME)) {
        u32 arg[2] = {i_vrf, src_addr};
        /* update timestamp */
        port_log_timestamps[hash_value] = current_timestamp;
        spp_printf(CNAT_USER_OUT_OF_PORTS, 2, arg);
    }

    return ;
}

static void log_port_alloc_error(cnat_errno_t error, cnat_key_t *k)
{
    u32 error_code;
    u32 arr[] = {k->k.vrf, k->k.ipv4, k->k.port};
    switch (error)
    {
    case CNAT_NO_POOL_ANY:
        error_code = CNAT_NO_POOL_FOR_ANY_ERROR;
        break;
    case CNAT_NO_PORT_ANY:
        error_code = CNAT_NO_PORT_FOR_ANY_ERROR;
        break;
    case CNAT_ERR_PARSER:
        error_code = CNAT_WRONG_PORT_ALLOC_TYPE;
        break;
    case CNAT_BAD_INUSE_ANY:
        error_code = CNAT_BAD_INUSE_ANY_ERROR;
        break;
    case CNAT_BAD_INUSE_DIRECT:
        error_code = CNAT_BAD_INUSE_DIRECT_ERROR;
        break;
    case CNAT_NOT_FOUND_ANY:
        error_code = CNAT_NOT_FOUND_ANY_ERROR;
        break;
    case CNAT_NOT_FOUND_DIRECT:
        error_code = CNAT_NOT_FOUND_DIRECT_ERROR;
        break;
    case CNAT_INV_PORT_DIRECT:
        error_code = CNAT_INV_PORT_FOR_DIRECT_ERROR;
        break;
    default:
        error_code = CNAT_NEW_PORT_ALLOC_ERROR; /* If this code is seen in the log,
       it means, new error codes are to be added here */
       break;
    }
    spp_printf(error_code, 3, arr);
}

void cnat_db_debug_error(cnat_db_key_bucket_t *u_ki, 
                         cnat_errno_t  error)
{
    if (PREDICT_FALSE((u_ki->k.k.vrf == debug_i_vrf) &&
        ((u_ki->k.k.ipv4 >= debug_i_addr_start) &&
         (u_ki->k.k.ipv4 <= debug_i_addr_end)))) { 
#ifdef DEBUG_PRINTF_ENABLED
            PLATFORM_DEBUG_PRINT("failed to allocate port due to %s "
           "for i-vrf 0x%x addr 0x%x port 0x%x\n",
            debug_db_error[error], u_ki->k.k.vrf,
               u_ki->k.k.ipv4, u_ki->k.k.port);
#endif
        {
            u32 arg[] = {u_ki->k.k.vrf, u_ki->k.k.ipv4,  u_ki->k.k.port};
            spp_printf(error, 3, arg);
        }
    }
}

void dslite_db_debug_error(dslite_db_key_bucket_t *u_ki,
                         cnat_errno_t  error)
{
    if (PREDICT_FALSE((u_ki->dk.ipv4_key.k.vrf == debug_i_vrf) &&
        ((u_ki->dk.ipv4_key.k.ipv4 >= debug_i_addr_start) &&
         (u_ki->dk.ipv4_key.k.ipv4 <= debug_i_addr_end)))) {
#ifdef DEBUG_PRINTF_ENABLED
            PLATFORM_DEBUG_PRINT("failed to allocate port due to %s "
           "for i-vrf 0x%x addr 0x%x port 0x%x\n",
            debug_db_error[error], u_ki->dk.ipv4_key.k.vrf,
               u_ki->dk.ipv4_key.k.ipv4, u_ki->dk.ipv4_key.k.port);
#endif
        {
            u32 arg[] = {u_ki->dk.ipv4_key.k.vrf, u_ki->dk.ipv4_key.k.ipv4,  u_ki->dk.ipv4_key.k.port};
            spp_printf(error, 3, arg);
        }
    }
}

void cnat_db_debug_i2o_drop(cnat_db_key_bucket_t *ki)
{
    if (PREDICT_FALSE(((ki->k.k.vrf & CNAT_VRF_MASK) == debug_i_vrf) && 
        ((ki->k.k.ipv4 >= debug_i_addr_start) &&
        (ki->k.k.ipv4 <= debug_i_addr_end)))) {
#ifdef DEBUG_PRINTF_ENABLED
        PLATFORM_DEBUG_PRINT("pakcet[i-vrf 0x%x addr 0x%x port 0x%x] dropped\n", 
           ki->k.k.vrf, ki->k.k.ipv4, ki->k.k.port);
#endif
        {
            u32 arg[] = {ki->k.k.vrf, ki->k.k.ipv4, ki->k.k.port};
            spp_printf(CNAT_PACKET_DROP_ERROR, 3, arg);
        }
    }
}

void cnat_db_in2out_hash_delete (cnat_main_db_entry_t *ep, cnat_user_db_entry_t *up)
{
    u64 a, b, c;
    u32 index, bucket;
    cnat_main_db_entry_t *this, *prev;

#ifdef DSLITE_DEF
    if (PREDICT_FALSE(ep->flags & CNAT_DB_DSLITE_FLAG)) {
        dslite_key_t dk = { 
                              {up->ipv6[0], up->ipv6[1], up->ipv6[2], up->ipv6[3]} ,
                              {ep->in2out_key.k.ipv4, ep->in2out_key.k.port, ep->in2out_key.k.vrf}
                          };
        DSLITE_V6_GET_HASH((&dk),
                     bucket,
                     CNAT_MAIN_HASH_MASK);
        DSLITE_PRINTF(1, "Delete1 DSL main hash bucket ..%u\n", bucket);
    } else {
        CNAT_V4_GET_HASH(ep->in2out_key.key64,
                         bucket, CNAT_MAIN_HASH_MASK)
        DSLITE_PRINTF(1, "Delete1 NAT44 main hash bucket ..%u\n", bucket);
    }
#else
    CNAT_V4_GET_HASH(ep->in2out_key.key64,
                     bucket, CNAT_MAIN_HASH_MASK)
#endif
    
    index = cnat_in2out_hash[bucket].next;

    ASSERT(index != EMPTY);

    prev = 0;
    do {
        this = cnat_main_db + index;
        if (PREDICT_TRUE(this == ep)) {
            if (prev == 0) {
                cnat_in2out_hash[bucket].next = ep->in2out_hash.next;
                return;
            } else {
                prev->in2out_hash.next = ep->in2out_hash.next;
                return;
            }
        }
        prev = this;
        index = this->in2out_hash.next;
    } while (index != EMPTY);

    ASSERT(0);
}

void cnat_db_out2in_hash_delete (cnat_main_db_entry_t *ep)
{
    u64 a, b, c;
    u32 index, bucket;
    cnat_main_db_entry_t *this, *prev;

    CNAT_V4_GET_HASH(ep->out2in_key.key64,
                        bucket, CNAT_MAIN_HASH_MASK)

    index = cnat_out2in_hash[bucket].next;

    ASSERT(index != EMPTY);

    prev = 0;
    do {
        this = cnat_main_db + index;
        if (PREDICT_TRUE(this == ep)) {
            if (prev == 0) {
                cnat_out2in_hash[bucket].next = ep->out2in_hash.next;
                return;
            } else {
                prev->out2in_hash.next = ep->out2in_hash.next;
                return;
            }
        }
        prev = this;
        index = this->out2in_hash.next;
    } while (index != EMPTY);

    ASSERT(0);
}

cnat_main_db_entry_t*
cnat_main_db_lookup_entry(cnat_db_key_bucket_t *ki)
{
    u64 a, b, c;
    u32 index;
    cnat_main_db_entry_t *db;

    CNAT_V4_GET_HASH(ki->k.key64, 
                     ki->bucket,
                     CNAT_MAIN_HASH_MASK);
 
    index = cnat_in2out_hash[ki->bucket].next;
    if (PREDICT_TRUE(index == EMPTY)) {
        return (NULL);
    }

    do {
        db = cnat_main_db + index;
        if (PREDICT_TRUE(db->in2out_key.key64 == ki->k.key64)) {
            return db;
        }
        index = db->in2out_hash.next;
    } while (index != EMPTY);

    return (NULL);
}

void cnat_user_db_delete (cnat_user_db_entry_t *up)
{
    u64 a, b, c;
    u32 index, bucket;
    cnat_user_db_entry_t *this, *prev;
    
    if (PREDICT_FALSE(up->flags & CNAT_USER_DB_NAT64_FLAG) != 0) {
       /* Preventive check - Not a NAT44 entry */
        return;
    }

#if 1
    if(PREDICT_FALSE(up->flags & CNAT_USER_DB_DSLITE_FLAG)) {
        dslite_key_t dk = {
                              {up->ipv6[0], up->ipv6[1], up->ipv6[2], up->ipv6[3]} ,
                              {{up->key.k.ipv4, up->key.k.port, up->key.k.vrf}}
                          };

        DSLITE_V6_GET_HASH((&dk),
                     bucket,
                     CNAT_USER_HASH_MASK); 
        DSLITE_PRINTF(1, "Delete1 DSL user hash bucket ..%u\n", bucket);
    } else {
        CNAT_V4_GET_HASH(up->key.key64,
                       bucket, CNAT_USER_HASH_MASK)
        DSLITE_PRINTF(1, "Delete1 NAT44 user hash bucket ..%u\n", bucket);
    }
#else
    CNAT_V4_GET_HASH(up->key.key64,
                     bucket, CNAT_USER_HASH_MASK)
    DSLITE_PRINTF(1, "Delete2 NAT44 user hash bucket ..%u\n", bucket);
#endif

    index = cnat_user_hash[bucket].next;

    ASSERT(index != EMPTY);

    prev = 0;
    do {
        this = cnat_user_db + index;
        if (PREDICT_TRUE(this == up)) {
            if (prev == 0) {
                cnat_user_hash[bucket].next = up->user_hash.next;
                goto found;
            } else {
                prev->user_hash.next = up->user_hash.next;
                goto found;
            }
        }
        prev = this;
        index = this->user_hash.next;
    } while (index != EMPTY);

    ASSERT(0);

 found:
    pool_put(cnat_user_db, up);    
}

cnat_user_db_entry_t*
cnat_user_db_lookup_entry(cnat_db_key_bucket_t *uki) 
{
    u64 a, b, c;
    u32 index;
    cnat_user_db_entry_t *udb=NULL;

    CNAT_V4_GET_HASH(uki->k.key64, 
                     uki->bucket,
                     CNAT_USER_HASH_MASK)

    /* now: index in user vector */
    index = cnat_user_hash[uki->bucket].next;
    if (PREDICT_TRUE(index != EMPTY)) {
        do {
            udb = cnat_user_db + index;
            if (PREDICT_FALSE(udb->key.key64 == uki->k.key64)) {
                return udb;
            }
            index = udb->user_hash.next;
        } while (index != EMPTY);
    }
    return (NULL);
}

cnat_user_db_entry_t*
cnat_user_db_create_entry(cnat_db_key_bucket_t *uki,
                          u32 portmap_index)
{
    cnat_user_db_entry_t *udb = NULL;

    pool_get(cnat_user_db, udb);
    memset(udb, 0, sizeof(*udb));

    udb->ntranslations = 1; 
    udb->portmap_index = portmap_index;
    udb->key.key64 = uki->k.key64;
    /* Add this user to the head of the bucket chain */
    udb->user_hash.next = 
             cnat_user_hash[uki->bucket].next;
    cnat_user_hash[uki->bucket].next = udb - cnat_user_db;

#ifndef NO_BULK_LOGGING
    INIT_BULK_CACHE(udb)
#endif /* NO_BULK_LOGGING */
    return udb;
}

cnat_main_db_entry_t*
cnat_create_main_db_entry_and_hash(cnat_db_key_bucket_t *ki,
                                   cnat_db_key_bucket_t *ko,
                                   cnat_user_db_entry_t *udb)
{
    u64 a, b, c;
    u32 db_index;
    cnat_main_db_entry_t *db = NULL;

    pool_get(cnat_main_db, db);
    memset(db, 0, sizeof(*db));

    db_index = db - cnat_main_db;
    db->in2out_key.k.ipv4 = ki->k.k.ipv4;
    db->in2out_key.k.port = ki->k.k.port;
    db->in2out_key.k.vrf = ki->k.k.vrf;
    db->out2in_key.k.ipv4 = ko->k.k.ipv4;
    db->out2in_key.k.port = ko->k.k.port;
    db->out2in_key.k.vrf = ko->k.k.vrf;

    db->user_ports.next = db_index;
    db->user_ports.prev = db_index;
    db->user_index = udb - cnat_user_db;
    //db->portmap_index = udb->portmap_index;
    db->flags &= ~(CNAT_DB_DSLITE_FLAG); // Mark that it is not dslite
    if (PREDICT_FALSE(udb->ntranslations == 1)) {
        /*
         * first port for this src vrf/src ip addr
         */
        udb->translation_list_head_index = db_index;
    } else {
        index_dlist_addtail(udb->translation_list_head_index,
                            (u8 *)cnat_main_db, sizeof(cnat_main_db[0]),
                            STRUCT_OFFSET_OF(cnat_main_db_entry_t, user_ports),
                            db_index);
    }

    /* 
     * setup o2i hash key
     */
    CNAT_V4_GET_HASH(ko->k.key64, 
                     ko->bucket,
                     CNAT_MAIN_HASH_MASK)
    db->out2in_hash.next = cnat_out2in_hash[ko->bucket].next;
    cnat_out2in_hash[ko->bucket].next = db_index;
    /*
     * setup i2o hash key, bucket is already calculate
     */
    db->in2out_hash.next = cnat_in2out_hash[ki->bucket].next;
    cnat_in2out_hash[ki->bucket].next = db_index;

#if DEBUG > 1
    printf("\nMy_Instance_Number %d: Bucket %d, Db_Index %d",
           my_instance_number, ki->bucket, db_index);
    printf("\nInside (VRF 0x%x, IP 0x%x, PORT 0x%x)",
           db->in2out_key.k.vrf, db->in2out_key.k.ipv4, db->in2out_key.k.port);
    printf("\nOutside (VRF 0x%x, IP 0x%x, PORT 0x%x)",
           db->out2in_key.k.vrf, db->out2in_key.k.ipv4, db->out2in_key.k.port);
    printf("\nUser Index %d, IP 0x%x",
           db->user_index, udb->key.k.ipv4);
#endif

    NAT44_COMMON_STATS.active_translations++;

    return db;
}

static inline void pptp_clear_all_channels(
         cnat_main_db_entry_t *db)
{
   u32 db_index, current_db_index;
   cnat_main_db_entry_t *temp_db;

   /* clear all channels */
  
   db_index = db->proto_data.pptp_list.next;
   current_db_index  = db - cnat_main_db;

   while( db_index != EMPTY) {
       temp_db = cnat_main_db + db_index;
       db_index = temp_db->proto_data.pptp_list.next;
       temp_db->entry_expires = 0;
       if(PREDICT_FALSE(temp_db->proto_data.pptp_list.prev 
           == current_db_index)) { // Decouple child GREs from parent
           temp_db->proto_data.pptp_list.prev = EMPTY; 
       }
   }

   db->proto_data.pptp_list.next = EMPTY;
}

void pptp_remove_channel_from_tunnel(cnat_main_db_entry_t *db) {
   
    cnat_main_db_entry_t *prev_db, *next_db;
    
    prev_db = cnat_main_db + db->proto_data.pptp_list.prev;
    next_db = cnat_main_db + db->proto_data.pptp_list.next;
  
    /* remove entry from the tunnel list */ 
    if(PREDICT_TRUE(db->proto_data.pptp_list.prev != EMPTY)) {
        prev_db->proto_data.pptp_list.next =
                 db->proto_data.pptp_list.next ;  
    }

    if(db->proto_data.pptp_list.next != EMPTY) {
       next_db->proto_data.pptp_list.prev
                = db->proto_data.pptp_list.prev;
    }

}

void cnat_delete_main_db_entry_v2 (cnat_main_db_entry_t *ep)
{
    u32 main_db_index;
    u32 vrfmap_len, udb_len;
    cnat_user_db_entry_t *up =0;
    cnat_portmap_v2_t *pm =0;
    cnat_portmap_v2_t *my_pm =0;
    cnat_vrfmap_t       *my_vrfmap =0;
    u16 static_port_range;
#ifndef NO_BULK_LOGGING
    bulk_alloc_size_t bulk_size;
    int nfv9_log_req = BULK_ALLOC_NOT_ATTEMPTED;
#endif
    pool_header_t *h = pool_header(cnat_user_db);
    u16 instance = 0;
    u32                 my_index;


    if (PREDICT_FALSE(ep->flags & CNAT_DB_NAT64_FLAG) != 0) {
        /* Preventive check - Not a NAT44 entry */
        return;
    }

   if(PREDICT_FALSE(ep->flags & 
        CNAT_DB_FLAG_PPTP_TUNNEL_ACTIVE)) {
      pptp_clear_all_channels(ep);
      PPTP_DECR(active_tunnels);
   }

   if(PREDICT_FALSE(ep->flags &
        CNAT_DB_FLAG_PPTP_GRE_ENTRY)) {
        pptp_remove_channel_from_tunnel(ep);
        PPTP_DECR(active_channels);
   }

    /* This function gets called from various locations..
     * many times from config handler.. so we
     * to ensure that multiple sessions if any are
     * released
     */

    if(PREDICT_FALSE(ep->nsessions > 1)) {
        cnat_session_entry_t *sdb;
        while(ep->nsessions > 1 &&
            ep->session_head_index != EMPTY) {
            sdb = cnat_session_db + ep->session_head_index;
            cnat_delete_session_db_entry(sdb, TRUE);
        }
    }

    /* Find the set of portmaps for the outside vrf */
    vrfmap_len = vec_len(cnat_map_by_vrf);
    udb_len = vec_len(cnat_user_db);

    /* In case of invalid user just return, deleting only main db
     * is not a good idea, since some valid user db entry might be pointing 
     * to that main db and hence leave the dbs in a inconsistent state
     */
    if (PREDICT_FALSE((ep->user_index >= udb_len) || 
                    (clib_bitmap_get(h->free_bitmap, ep->user_index)))) {
#ifdef DEBUG_PRINTF_ENABLED
        printf("invalid/unused user index in db %d\n", ep->user_index);
#endif
        spp_printf(CNAT_INV_UNUSED_USR_INDEX, 1, (u32 *) &(ep->user_index));
        cnat_main_db_entry_dump(ep);
        return;
    }

    up = cnat_user_db + ep->user_index;

/* Point to the right portmap list */
if (PREDICT_FALSE(ep->flags & CNAT_DB_DSLITE_FLAG)) {
    instance = ep->dslite_nat44_inst_id;
    pm = dslite_table_db_ptr[instance].portmap_list;
    if(PREDICT_FALSE((pm == NULL))) {
        DSLITE_PRINTF(3, "NULL portmap list for dslite_id %u, state %u\n",
                      instance,  dslite_table_db_ptr[instance].state);
        cnat_main_db_entry_dump(ep);
        goto delete_entry;
    }
    static_port_range = 
    STAT_PORT_RANGE_FROM_INST_PTR(&(dslite_table_db_ptr[instance]));
    /*
     * Netflow logging API for delete event 
     */
    bulk_size = 
        BULKSIZE_FROM_VRFMAP(&(dslite_table_db_ptr[instance]));
} else {
    if (PREDICT_FALSE(ep->vrfmap_index >= vrfmap_len)) {
#ifdef DEBUG_PRINTF_ENABLED
        printf("invalid vrfmap index in db\n");
#endif
        spp_printf(CNAT_INVALID_VRFMAP_INDEX, 0, NULL);
        cnat_main_db_entry_dump(ep);
        goto delete_entry;
    }
    instance = NAT44_RESERVED_INST_ID;
    my_vrfmap = cnat_map_by_vrf + ep->vrfmap_index;
    pm = my_vrfmap->portmap_list;
    static_port_range = cnat_static_port_range;
    bulk_size = BULKSIZE_FROM_VRFMAP(my_vrfmap);
}
 
    if (PREDICT_FALSE(ep->flags & CNAT_DB_FLAG_PORT_PAIR)) {
        /* Give back the port(s) */
        cnat_port_free_v2_bulk(pm, up->portmap_index,
            PORT_PAIR, ep->out2in_key.k.port, up, static_port_range
#ifndef NO_BULK_LOGGING
            , bulk_size, &nfv9_log_req
#endif
            );
    } else {
        /* Give back the port(s) */
        cnat_port_free_v2_bulk (pm, up->portmap_index,
            PORT_SINGLE, ep->out2in_key.k.port, up, static_port_range
#ifndef NO_BULK_LOGGING
            , bulk_size, &nfv9_log_req
#endif
            );
    }

    if (PREDICT_TRUE(!(ep->flags & CNAT_DB_DSLITE_FLAG))) {
        if(PREDICT_FALSE(nfv9_log_req != CACHE_ALLOC_NO_LOG_REQUIRED)) {
            if(PREDICT_FALSE(my_vrfmap->nf_logging_policy == SESSION_LOG_ENABLE)) {
                if(ep->nsessions != 0) {
                    cnat_nfv9_nat44_log_session_delete(ep, NULL, my_vrfmap);
                }
            } else {
                cnat_nfv9_log_mapping_delete(ep, my_vrfmap
#ifndef NO_BULK_LOGGING
                , nfv9_log_req
#endif
                );
            }
            if(PREDICT_TRUE((my_vrfmap->syslog_logging_policy != SESSION_LOG_ENABLE) ||
                            (ep->nsessions != 0))) {
                cnat_syslog_nat44_mapping_delete(ep, my_vrfmap, NULL
#ifndef NO_BULK_LOGGING
                , nfv9_log_req
#endif
                );
            }
        }
    } else {
        if(PREDICT_FALSE(nfv9_log_req != CACHE_ALLOC_NO_LOG_REQUIRED)) {
            if(PREDICT_FALSE( dslite_table_db_ptr[instance].nf_logging_policy ==
                                      SESSION_LOG_ENABLE)) {
                cnat_nfv9_ds_lite_log_session_delete(ep, 
				(dslite_table_db_ptr + instance),NULL);
            } else {
                cnat_nfv9_ds_lite_mapping_delete(ep,
                                (dslite_table_db_ptr + instance)
#ifndef NO_BULK_LOGGING
                , nfv9_log_req
#endif
                );
            }
#ifdef TOBE_PORTED
	    cnat_syslog_ds_lite_mapping_delete(ep,
                		(dslite_table_db_ptr + instance), NULL
#ifndef NO_BULK_LOGGING
            , nfv9_log_req
#endif
            );
#endif /* TOBE_PORTED */
        }
    }

delete_entry:

    main_db_index = ep - cnat_main_db;

    up->ntranslations--;

    /*
     * when user reaches max allowed port limit
     * we generate icmp msg and inc the counter
     * when counter reach the icmp msg rate limit
     * we stop icmp msg gen
     * when a user port is freed
     * that means we need to clear the msg gen counter
     * so that next time 
     * reach max port limit, we can generate new icmp msg again
     */
    up->icmp_msg_count = 0;

    up->translation_list_head_index = index_dlist_remelem (
        up->translation_list_head_index, (u8 *)cnat_main_db,
        sizeof (cnat_main_db[0]),
        STRUCT_OFFSET_OF(cnat_main_db_entry_t, user_ports),
        main_db_index);

    cnat_db_in2out_hash_delete(ep, up);

    if (PREDICT_FALSE(up->ntranslations == 0)) {
        ASSERT(up->translation_list_head_index == EMPTY);
        nat44_dslite_common_stats[instance].num_subscribers--;
	my_index = up->portmap_index;
	my_pm = pm + my_index;
	if(PREDICT_TRUE(my_pm->private_ip_users_count)) {
	    my_pm->private_ip_users_count--;
#ifdef DEBUG_PRINTF_IP_N_TO_1_ENABLED
	    PLATFORM_DEBUG_PRINT("\n cnat_delete_main_db_entry_v2 "
				 "private_ip_users_count = %d",
				 my_pm->private_ip_users_count);
#endif
	    
	}
        cnat_user_db_delete(up);
	
    }

    /* Remove from main DB hashes */
    //cnat_db_in2out_hash_delete(ep);
    cnat_db_out2in_hash_delete(ep);

    pool_put(cnat_main_db, ep);

    if(PREDICT_FALSE(ep->flags & CNAT_DB_FLAG_STATIC_PORT)) {
            nat44_dslite_common_stats[instance].num_static_translations--;
    } else {
            nat44_dslite_common_stats[instance].num_dynamic_translations--;
    }
    nat44_dslite_common_stats[instance].active_translations--;
    nat44_dslite_global_stats[!!(instance - 1)].translation_delete_count ++;
}

cnat_main_db_entry_t*
cnat_main_db_lookup_entry_out2in (cnat_db_key_bucket_t *ko)
{
    u64 a, b, c;
    u32 index;
    cnat_main_db_entry_t *db;

    CNAT_V4_GET_HASH(ko->k.key64,
                     ko->bucket,
                     CNAT_MAIN_HASH_MASK);

    index = cnat_out2in_hash[ko->bucket].next;
    if (PREDICT_TRUE(index == EMPTY)) {
        return (NULL);
    }

    do {
        db = cnat_main_db + index;
        if (PREDICT_TRUE(db->out2in_key.key64 == ko->k.key64)) {
            return db;
        }
        index = db->out2in_hash.next;
    } while (index != EMPTY);

    return (NULL);
}

/* Creates 2 sessions.
 * Moves the default dest info from mdb to first session
 * Fills the dest_info details in to second session and
 * returns the pointer to second session
 */
cnat_session_entry_t *cnat_handle_1to2_session(
    cnat_main_db_entry_t *mdb,
    cnat_key_t *dest_info)
{
    cnat_key_t old_dest_info;
    pool_header_t        *h;
    u32 free_session = 0;
    u16 instance;
    cnat_session_entry_t *session_db1 = NULL, *session_db2 = NULL;

    h = pool_header(cnat_session_db);
    free_session = vec_len(h->free_indices) - 1;

    if (PREDICT_FALSE(free_session < 2)) {
       if (mdb->flags & CNAT_DB_DSLITE_FLAG) {
        instance = mdb->dslite_nat44_inst_id;
       } else {
        instance = NAT44_RESERVED_INST_ID;
       }

        /* we need 2 sessions here, return NULL */
        nat44_dslite_common_stats[instance].drops_sessiondb_limit_exceeded++;
        return NULL;
    }

    old_dest_info.k.ipv4 = mdb->dst_ipv4;
    old_dest_info.k.port = mdb->dst_port;
    old_dest_info.k.vrf = mdb->in2out_key.k.vrf;

    /* create 2 new sessions */
    session_db1 = cnat_create_session_db_entry(&old_dest_info,
            mdb, FALSE);

    if(PREDICT_FALSE(session_db1 == NULL)) {
        return NULL;
    }

    /* update pkt info to session 2 */
    session_db2 = cnat_create_session_db_entry(dest_info,
            mdb, TRUE);

    if(PREDICT_FALSE(session_db2 == NULL)) {
        cnat_delete_session_db_entry(session_db1, FALSE);
        return NULL;
    }
    /* update main db info to session 1 */
    cnat_dest_update_main2session(mdb, session_db1);

    return session_db2;
}

/* The below function shold be called only
 * when a NAT44 STATIC entry received traffic
 * for the first time. This is to ensure
 * the destination is noted and logged
 */
void cnat_add_dest_n_log(
    cnat_main_db_entry_t *mdb,
    cnat_key_t *dest_info)
{

    if(PREDICT_FALSE(mdb->nsessions != 0)) {
        return; /* Should not have been called */
    }

    mdb->dst_ipv4 = dest_info->k.ipv4;
    mdb->dst_port = dest_info->k.port;
    mdb->nsessions = 1;
    mdb->entry_expires = cnat_current_time;
    u16 instance;

    if (mdb->flags & CNAT_DB_DSLITE_FLAG) {
	instance = mdb->dslite_nat44_inst_id;
        cnat_session_log_ds_lite_mapping_create(mdb,
             (dslite_table_db_ptr + instance),NULL);
    } else {
	instance = NAT44_RESERVED_INST_ID;
	cnat_vrfmap_t *my_vrfmap = cnat_map_by_vrf + mdb->vrfmap_index;
	cnat_session_log_nat44_mapping_create(mdb, 0, my_vrfmap);
    }
}

/*
 * this function is called by exception node
 * when lookup is fialed in i2o node
 *
 * if reash per user port limit, 
 * set user_db_entry pointer, and error == CNAT_OUT_LIMIT
 */
cnat_main_db_entry_t*
cnat_get_main_db_entry_v2(cnat_db_key_bucket_t *ki,
                          port_pair_t port_pair_type,
                          port_type_t port_type,
                          cnat_gen_icmp_info *info,
                          cnat_key_t *dest_info)
{
    u16 protocol;
    cnat_errno_t rv;
    cnat_db_key_bucket_t u_ki, ko;
    u32                 my_index, free_main, free_user;
    u32                 current_timestamp;
    u16                 my_vrfmap_index;
    u16                 my_vrfmap_entry_found = 0;
    cnat_vrfmap_t       *my_vrfmap =0;
    cnat_portmap_v2_t   *pm =0;
    cnat_user_db_entry_t *udb = 0;
    cnat_main_db_entry_t *db = 0;
    pool_header_t        *h;
    u16                 port_limit;
    cnat_portmap_v2_t *my_pm = 0;

#ifndef NO_BULK_LOGGING
    int                 nfv9_log_req = BULK_ALLOC_NOT_ATTEMPTED;
#endif


    /* 
     * need to try lookup again because 
     * second pkt may come here before the entry is created
     * by receiving first pkt due to high line rate.
     */
    info->gen_icmp_msg = CNAT_NO_ICMP_MSG;
    info->error = CNAT_SUCCESS;
    db = cnat_main_db_lookup_entry(ki);
    if (PREDICT_TRUE(db)) {
        /* what if the source is talking to a
         * new dest now? We will have to handle this case and
         * take care of - creating session db and logging
         */
        if(PREDICT_FALSE((!dest_info->k.ipv4) && (!dest_info->k.port))) {
            return db;  /* if dest_info is null don't create session */
        }
        if(PREDICT_TRUE((db->dst_ipv4 == dest_info->k.ipv4) &&
            (db->dst_port == dest_info->k.port))) {
            return db;
        }
        dest_info->k.vrf = db->in2out_key.k.vrf;
        /* Src is indeed talking to a different dest */
        cnat_session_entry_t *session_db2 = NULL;
        if(PREDICT_TRUE(db->nsessions == 1)) {
            session_db2 = cnat_handle_1to2_session(db, dest_info);
            if(PREDICT_TRUE(session_db2 != NULL)) {
                CNAT_DB_TIMEOUT_RST(session_db2);
                return db;
            } else {
                info->error = CNAT_ERR_NO_SESSION_DB;
                return NULL;
            }
        } else if(PREDICT_FALSE(db->nsessions == 0)) {
            /* Should be static entry.. should never happen
             */
            if(PREDICT_TRUE(dest_info->k.ipv4 != 0)) {
                cnat_add_dest_n_log(db, dest_info);
            }
            return db;
        } else {
            /* The src has already created multiple sessions.. very rare
             */
            session_db2 = cnat_create_session_db_entry(dest_info,
                        db, TRUE);
            if(PREDICT_TRUE(session_db2 != NULL)) {
                CNAT_DB_TIMEOUT_RST(session_db2);
               return db;
            } else {
                info->error = CNAT_ERR_NO_SESSION_DB;
                return NULL;
            }
        }

    }

    /* 
     * step 1. check if outside vrf is configured or not
     *         and Find the set of portmaps for the outside vrf
     * insider vrf is one to one mappted to outside vrf
     * key is vrf and ip only
     * ki.k.k.vrf has protocol bits, mask out 
     */
    protocol = ki->k.k.vrf & CNAT_PRO_MASK;
    u_ki.k.k.vrf = ki->k.k.vrf & CNAT_VRF_MASK;
    u_ki.k.k.ipv4 = ki->k.k.ipv4;
    u_ki.k.k.port = 0;

    my_vrfmap_index = vrf_map_array[u_ki.k.k.vrf];
    my_vrfmap = cnat_map_by_vrf + my_vrfmap_index;

    my_vrfmap_entry_found = ((my_vrfmap_index != VRF_MAP_ENTRY_EMPTY) &&
                             (my_vrfmap->status == S_RUN) &&
			     (my_vrfmap->i_vrf == u_ki.k.k.vrf));

    if (PREDICT_FALSE(!my_vrfmap_entry_found)) {
        u32 arr[] = {ki->k.k.vrf, ki->k.k.ipv4, ki->k.k.port};
        if ((my_vrfmap_index == VRF_MAP_ENTRY_EMPTY) || 
	    (my_vrfmap->i_vrf == u_ki.k.k.vrf)) {
	    info->error = CNAT_NO_CONFIG;
	    CNAT_DEBUG_INSIDE_ERR(CNAT_NO_CONFIG)
        spp_printf(CNAT_NO_CONFIG_ERROR, 3, arr);
	} else {
	    info->error = CNAT_NO_VRF_RUN;
	    CNAT_DEBUG_INSIDE_ERR(CNAT_NO_VRF_RUN)
        spp_printf(CNAT_NO_VRF_RUN_ERROR, 3, arr);
	}

	return (NULL);
    }

    pm = my_vrfmap->portmap_list;

    port_limit = my_vrfmap->port_limit;
    if(PREDICT_FALSE(!port_limit)) {
      port_limit = cnat_main_db_max_ports_per_user;
    }
    /*
     * set o2i key with protocl bits
     */
    ko.k.k.vrf = my_vrfmap->o_vrf | protocol;

    /*
     * step 2. check if src vrf, src ip addr is alreay 
     *         in the user db
     * if yes, use PORT_ALLOC_DIRECTED
     * if no, use PORT_ALLOC_ANY since it is first time
     */
    udb = cnat_user_db_lookup_entry(&u_ki);
    if (PREDICT_TRUE(udb)) {
        /*
         * not first time allocate port for this user
         * check limit
         */
          if (PREDICT_FALSE(udb->ntranslations >=
                port_limit)) { 
            /* Check for the port type here. If we are getting
             * a STATIC PORT, allow the config.
             */
            if (PREDICT_TRUE(port_type != PORT_TYPE_STATIC)) {
               info->error = CNAT_OUT_LIMIT;
               CNAT_SET_ICMP_MSG_INFO
               CNAT_DEBUG_INSIDE_ERR(CNAT_OUT_LIMIT)
               port_exceeded_msg_log(u_ki.k.k.ipv4, u_ki.k.k.vrf);
               in2out_drops_port_limit_exceeded ++;
	       u_ki.k.k.port = ki->k.k.port;
	       u_ki.k.k.vrf = ki->k.k.vrf;
	       handle_cnat_port_exceeded_logging(udb, &u_ki.k, my_vrfmap);
               return (NULL);
            }
        }
        CHECK_CLEAR_PORT_LIMIT_EXCEED_FLAG(udb,
		port_limit)

        /* 
         * check if main db has space to accomodate new entry
         */
        h = pool_header(cnat_main_db);

        free_main = vec_len(h->free_indices) - 1;
        if (PREDICT_FALSE(!free_main)) {
            info->error = CNAT_MAIN_DB_LIMIT;
            CNAT_SET_ICMP_MSG_INFO
            in2out_drops_system_limit_reached ++;
            CNAT_DEBUG_INSIDE_ERR(CNAT_MAIN_DB_LIMIT)

            current_timestamp = spp_trace_log_get_unix_time_in_seconds();
            if (PREDICT_FALSE((current_timestamp - last_log_timestamp) >
                    1800)) {
                spp_printf(CNAT_SESSION_THRESH_EXCEEDED, 0, NULL);
                last_log_timestamp = current_timestamp;
            }

#ifdef UT_TEST_CODE
            printf("Limit reached : OLD USER");
#endif
            return NULL;
        }

        /*
         * allocate port, from existing mapping 
         */
        my_index = udb->portmap_index;

        if (PREDICT_FALSE(port_type == PORT_TYPE_STATIC)) {
            rv = cnat_static_port_alloc_v2_bulk(pm,
                        PORT_ALLOC_DIRECTED,
                        port_pair_type,
                        ki->k.k.ipv4,
                        ki->k.k.port,
                        &my_index,
                        &(ko.k.k.ipv4),
                        &(ko.k.k.port),
                        cnat_static_port_range
#ifndef NO_BULK_LOGGING
                        ,
                        udb, BULKSIZE_FROM_VRFMAP(my_vrfmap),
                        &nfv9_log_req
#endif
			, my_vrfmap->ip_n_to_1
                        );

        }  else if (PREDICT_TRUE(port_type != PORT_TYPE_RTSP) ) {

            rv = cnat_dynamic_port_alloc_v2_bulk(pm,
                        PORT_ALLOC_DIRECTED,
                        port_pair_type,
                        &my_index,
                        &(ko.k.k.ipv4),
                        &(ko.k.k.port),
                        cnat_static_port_range
#ifndef NO_BULK_LOGGING
                        ,
                        udb, BULKSIZE_FROM_VRFMAP(my_vrfmap),
                        &nfv9_log_req
#endif
                        , my_vrfmap->ip_n_to_1,
                        &(my_vrfmap->rseed_ip)
                        );

        } else {
            /*
             * For RTSP, two translation entries are created, 
             * check if main db has space to accomodate two new entry
             */
            free_main =  free_main - 1;
            if (PREDICT_FALSE(!free_main)) {
                info->error = CNAT_MAIN_DB_LIMIT;
                CNAT_SET_ICMP_MSG_INFO
                in2out_drops_system_limit_reached ++;
                CNAT_DEBUG_INSIDE_ERR(CNAT_MAIN_DB_LIMIT)

                return NULL;
            } else {
                rv = cnat_dynamic_port_alloc_rtsp_bulk(pm,
                            PORT_ALLOC_DIRECTED,
                            port_pair_type,
                            ki->k.k.port,
                            &my_index,
                            &(ko.k.k.ipv4),
                            &(ko.k.k.port),
                            cnat_static_port_range
#ifndef NO_BULK_LOGGING
                            ,
                            udb, BULKSIZE_FROM_VRFMAP(my_vrfmap),
                            &nfv9_log_req
#endif
                            , &(my_vrfmap->rseed_ip)
                            );
            }
        }


        if (PREDICT_FALSE(rv != CNAT_SUCCESS)) {
            info->error = rv;
            CNAT_SET_ICMP_MSG_INFO
            CNAT_DEBUG_INSIDE_ERR(rv)
            in2out_drops_resource_depletion++;
            log_port_alloc_error(rv, &(ki->k));
            return (NULL);
        }
        /*
         * increment port in use for this user
         */
        udb->ntranslations += 1;
	
    } else {
        /*
         * first time allocate port for this user
         */
     
        /*
         * Do not create entry if port limit is invalid
         */
        
        if (PREDICT_FALSE(!port_limit)) {
            if (PREDICT_TRUE(port_type != PORT_TYPE_STATIC)) {
                info->error = CNAT_OUT_LIMIT;
                in2out_drops_port_limit_exceeded ++;
                port_exceeded_msg_log(u_ki.k.k.ipv4, u_ki.k.k.vrf);
                CNAT_SET_ICMP_MSG_INFO
                CNAT_DEBUG_INSIDE_ERR(CNAT_OUT_LIMIT)
                return (NULL);
            }
        }

        /*
         * Check if main db has space for new entry
         * Allowing a user db entry to be created if main db is not free
         * will cause a port to be allocated to that user, which results in  
         * wastage of that port, hence the check is done here.
         */
        h = pool_header(cnat_main_db);
        free_main = vec_len(h->free_indices) - 1;
        h = pool_header(cnat_user_db);
	    free_user = vec_len(h->free_indices) - 1;

	   /*
	    * If either main_db or user_db does not have entries
	    * bail out, with appropriate error
	    */
        if (PREDICT_FALSE(!(free_main && free_user))) {
            u32 log_error;
            if(free_main) {
                info->error = CNAT_USER_DB_LIMIT;
                log_error = CNAT_USER_DB_LIMIT_ERROR;
            } else {
                   info->error = CNAT_MAIN_DB_LIMIT;
                   log_error = CNAT_MAIN_DB_LIMIT_ERROR;
            }
            in2out_drops_system_limit_reached ++;
            CNAT_SET_ICMP_MSG_INFO 
            CNAT_DEBUG_INSIDE_ERR(info->error)
            spp_printf(log_error, 0, 0);
            return NULL;
        }

        if (PREDICT_FALSE(port_type == PORT_TYPE_STATIC)) {
            rv = cnat_static_port_alloc_v2_bulk(pm,
                        PORT_ALLOC_ANY,
                        port_pair_type,
                        ki->k.k.ipv4,
                        ki->k.k.port,
                        &my_index,
                        &(ko.k.k.ipv4),
                        &(ko.k.k.port),
                        cnat_static_port_range
#ifndef NO_BULK_LOGGING
                        ,
                        udb, BULKSIZE_FROM_VRFMAP(my_vrfmap),
                        &nfv9_log_req
#endif
			, my_vrfmap->ip_n_to_1
                        );

        }  else if (PREDICT_TRUE(port_type != PORT_TYPE_RTSP)) {
            rv = cnat_dynamic_port_alloc_v2_bulk(pm,
                        PORT_ALLOC_ANY,
                        port_pair_type,
                        &my_index,
                        &(ko.k.k.ipv4),
                        &(ko.k.k.port),
                        cnat_static_port_range
#ifndef NO_BULK_LOGGING
                        , NULL, BULKSIZE_FROM_VRFMAP(my_vrfmap),
                        &nfv9_log_req
#endif
                        , my_vrfmap->ip_n_to_1,
                        &(my_vrfmap->rseed_ip)
                        );
        } else {
            /*
             * For RTSP, two translation entries are created,
             * check if main db has space to accomodate two new entry
             */
            free_main =  free_main - 1;
            if (PREDICT_FALSE(!free_main)) {
                info->error = CNAT_MAIN_DB_LIMIT;
                CNAT_SET_ICMP_MSG_INFO
                in2out_drops_system_limit_reached ++;
                CNAT_DEBUG_INSIDE_ERR(CNAT_MAIN_DB_LIMIT)

                return NULL;
            } else {

                rv = cnat_dynamic_port_alloc_rtsp_bulk(pm,
                            PORT_ALLOC_ANY,
                            port_pair_type,
                            ki->k.k.port,
                            &my_index,
                            &(ko.k.k.ipv4),
                            &(ko.k.k.port),
                            cnat_static_port_range
#ifndef NO_BULK_LOGGING
                            , NULL, BULKSIZE_FROM_VRFMAP(my_vrfmap),
                            &nfv9_log_req
#endif
                            , &(my_vrfmap->rseed_ip)
                    );
                /* TODO: Add the port pair flag here */
            }
        }



        if (PREDICT_FALSE(rv != CNAT_SUCCESS)) {
            info->error = rv;
            in2out_drops_resource_depletion ++;
            CNAT_SET_ICMP_MSG_INFO
            CNAT_DEBUG_INSIDE_ERR(rv) 
            log_port_alloc_error(rv, &(ki->k));
            return (NULL);
        }
        /* 
         * create entry in user db
         */
        udb = cnat_user_db_create_entry(&u_ki, my_index);
        NAT44_COMMON_STATS.num_subscribers++;
	my_pm = pm + my_index;
	if(PREDICT_TRUE(my_pm->private_ip_users_count < PORTS_PER_ADDR)) {
	    my_pm->private_ip_users_count++;
#ifdef DEBUG_PRINTF_IP_N_TO_1_ENABLED
	    PLATFORM_DEBUG_PRINT("\n cnat_get_main_db_entry_v2 "
				 "dynamic alloc private_ip_users_count = %d",
				 my_pm->private_ip_users_count);
#endif
	} else {
	    PLATFORM_DEBUG_PRINT("\n ERROR: private_ip_users_count has "
				 "reached MAX PORTS_PER_ADDR");
	}
#ifndef NO_BULK_LOGGING
        if(PREDICT_TRUE(udb && (BULK_ALLOC_NOT_ATTEMPTED != nfv9_log_req))) {
            cnat_update_bulk_range_cache(udb, ko.k.k.port,
                BULKSIZE_FROM_VRFMAP(my_vrfmap));
        }
#endif /*  #ifndef NO_BULK_LOGGING */

    }

    /*
     * step 3:
     * outside port is allocated for this src vrf/src ip addr
     * 1)create a new entry in main db
     * 2)setup cnat_out2in_hash key
     * 3)setup cnat_in2out_hash key
     */
    db = cnat_create_main_db_entry_and_hash(ki, &ko, udb);

    translation_create_count ++;
#ifdef DSLITE_DEF 
    db->dslite_nat44_inst_id = NAT44_RESERVED_INST_ID;
#endif
    db->vrfmap_index = my_vrfmap - cnat_map_by_vrf;

    /*
     * don't forget logging
     * logging API is unconditional, 
     * logging configuration check is done inside the inline function
     */

    db->dst_ipv4 = dest_info->k.ipv4;
    db->dst_port = dest_info->k.port;
    if(PREDICT_TRUE(db->dst_ipv4 || db->dst_port)) {
        db->nsessions++;
    }

    if(PREDICT_FALSE(nfv9_log_req != CACHE_ALLOC_NO_LOG_REQUIRED)) {
    	if(PREDICT_FALSE(my_vrfmap->nf_logging_policy == SESSION_LOG_ENABLE)) {
        	/* do not log for static entries.. we will log when traffic flows */
        	if(PREDICT_TRUE(db->dst_ipv4 || db->dst_port)) {
            		cnat_nfv9_nat44_log_session_create(db, 0, my_vrfmap);
        	}
    	} else {
         	cnat_nfv9_log_mapping_create(db, my_vrfmap
#ifndef NO_BULK_LOGGING
                , nfv9_log_req
#endif
                );
        }
        if(PREDICT_TRUE((my_vrfmap->syslog_logging_policy != SESSION_LOG_ENABLE) ||
                        (db->dst_ipv4 || db->dst_port))) {
            cnat_syslog_nat44_mapping_create(db, my_vrfmap, 0
#ifndef NO_BULK_LOGGING
            , nfv9_log_req
#endif
            );
        }
    }
    if (PREDICT_FALSE(port_pair_type == PORT_PAIR)) {
       cnat_main_db_entry_t *db2 = 0;
       cnat_db_key_bucket_t new_ki = *ki;
       u64 a, b, c;

       new_ki.k.k.port += 1;
       ko.k.k.port += 1;

       CNAT_V4_GET_HASH(new_ki.k.key64, new_ki.bucket, 
                        CNAT_MAIN_HASH_MASK);

       db2 = cnat_create_main_db_entry_and_hash(&new_ki, &ko, udb);

       translation_create_count ++;
#ifdef DSLITE_DEF 
       db2->dslite_nat44_inst_id = NAT44_RESERVED_INST_ID;
#endif
       db2->vrfmap_index = my_vrfmap - cnat_map_by_vrf;
       db2->entry_expires = cnat_current_time;
       db2->flags |= CNAT_DB_FLAG_ALG_ENTRY;
       udb->ntranslations += 1;
       db2->dst_ipv4 = dest_info->k.ipv4;
       db2->dst_port = dest_info->k.port;
       db2->nsessions = 0; /* For ALG db, set sessions to 0 - CSCuf78420 */

       if(PREDICT_FALSE(nfv9_log_req != CACHE_ALLOC_NO_LOG_REQUIRED)) {
           if(PREDICT_FALSE(my_vrfmap->nf_logging_policy == SESSION_LOG_ENABLE)) {
               /* do not log for static entries.. we will log when traffic flows */
               if(PREDICT_TRUE(db2->dst_ipv4 || db2->dst_port)) {
                   cnat_nfv9_nat44_log_session_create(db2, 0, my_vrfmap);
               }
           } else {
               cnat_nfv9_log_mapping_create(db2, my_vrfmap
#ifndef NO_BULK_LOGGING
               , nfv9_log_req
#endif
               );
           }
           if(PREDICT_TRUE((my_vrfmap->syslog_logging_policy != SESSION_LOG_ENABLE) ||
                           (db2->dst_ipv4 || db2->dst_port))) {
               cnat_syslog_nat44_mapping_create(db2, my_vrfmap, 0
#ifndef NO_BULK_LOGGING
               , nfv9_log_req
#endif
               );
           }
       }
    }

    return db;
}

/*
 * this function is called from config handler only
 * to allocate a static port based db entry
 *
 * the actual mapped address and port are already specified
 */
cnat_main_db_entry_t*
cnat_create_static_main_db_entry_v2 (cnat_db_key_bucket_t *ki,
                                     cnat_db_key_bucket_t *ko,
                                     cnat_vrfmap_t        *my_vrfmap,
                                     cnat_gen_icmp_info   *info)
{
    u16 protocol;
    u32 head;
    cnat_errno_t rv;
    cnat_db_key_bucket_t u_ki;
    u32                 my_index, free_main, free_user;
    cnat_portmap_v2_t   *pm =0;
    cnat_portmap_v2_t   *my_pm =0;
    cnat_user_db_entry_t *udb = 0;
    cnat_main_db_entry_t *db = 0;
    pool_header_t        *h;
#ifndef NO_BULK_LOGGING
    int                 nfv9_log_req = BULK_ALLOC_NOT_ATTEMPTED;
#endif

    /* 
     * need to try lookup again because 
     * second pkt may come here before the entry is created
     * by receiving first pkt due to high line rate.
     */
    info->gen_icmp_msg = CNAT_NO_ICMP_MSG;
    info->error = CNAT_SUCCESS;
    db = cnat_main_db_lookup_entry(ki);

    /*
     * If we already have an entry with this inside address, port
     * check delete the entry and proceed further.  This should
     * If yes, something is terribly wrong.  Bail out
     */
    if (PREDICT_FALSE(db)) {

        if (db->flags & CNAT_DB_FLAG_STATIC_PORT) {

            if ((db->out2in_key.k.ipv4 == ko->k.k.ipv4) &&
                (db->out2in_key.k.port == ko->k.k.port) &&
                (db->out2in_key.k.vrf  == ko->k.k.vrf)) {

#ifdef DEBUG_PRINTF_ENABLED
                printf("Same Static Port Exists ki 0x%16llx ko 0x%16llx",
                       ki->k, ko->k);
#endif
                /*
                 * We have already programmed this, return
                 */
                return (db);
            }

            /*
             * We already have a static port with different mapping
             * Return an error for this case.
             */
            info->error = CNAT_ERR_PARSER;

#ifdef DEBUG_PRINTF_ENABLED
	    printf("Static Port Existing and Diff ki 0x%16llx ko 0x%16llx",
                       ki, db->out2in_key);
#endif
        {
            u32 arr[] = {STAT_PORT_CONFIG_IN_USE, (ki->k.k.vrf & CNAT_VRF_MASK),
                ki->k.k.ipv4, ki->k.k.port, (ki->k.k.vrf & CNAT_PRO_MASK) };
            spp_printf(CNAT_CONFIG_ERROR, 5, arr);
        }
            return (db);
        }

#ifdef DEBUG_PRINTF_ENABLED
	printf("Deleting Dynamic entry  ki 0x%16llx ko 0x%16llx",
                       ki, db->out2in_key);
#endif

        /*
         * If for some reason we have dynamic entries, just delete them
         * and proceed.
         */
        cnat_delete_main_db_entry_v2(db);
        
        db = NULL;
    }

    protocol = ki->k.k.vrf & CNAT_PRO_MASK;
    u_ki.k.k.vrf = ki->k.k.vrf & CNAT_VRF_MASK;
    u_ki.k.k.ipv4 = ki->k.k.ipv4;
    u_ki.k.k.port = 0;

    pm = my_vrfmap->portmap_list;

    /*
     * check if src vrf, src ip addr is already 
     *         in the user db
     * if yes, use PORT_ALLOC_DIRECTED
     * if no, use PORT_ALLOC_ANY since it is first time
     */
    udb = cnat_user_db_lookup_entry(&u_ki);
    if (PREDICT_TRUE(udb)) {
        /* 
         * check if main db has space to accomodate new entry
         */
        h = pool_header(cnat_main_db);

        free_main = vec_len(h->free_indices) - 1;
        if (PREDICT_FALSE(!free_main)) {
            info->error = CNAT_MAIN_DB_LIMIT;
            CNAT_SET_ICMP_MSG_INFO
            in2out_drops_system_limit_reached ++;
            CNAT_DEBUG_INSIDE_ERR(CNAT_MAIN_DB_LIMIT)
#ifdef UT_TEST_CODE
            printf("Limit reached : OLD USER");
#endif
            spp_printf(CNAT_MAIN_DB_LIMIT_ERROR, 0, 0);
            return NULL;
        }

        /*
         * allocate port, from existing mapping 
         */
        my_index = udb->portmap_index;
        my_pm = pm + my_index;
       /* It is quite possible that we hit the scenario of CSCtj17774.
        * Delete all the main db entries and add the ipv4 address sent by
        * CGN-MA as Static port alloc any
        */

        if (PREDICT_FALSE(my_pm->ipv4_address != ko->k.k.ipv4)) {
            if (PREDICT_FALSE(global_debug_flag && CNAT_DEBUG_GLOBAL_ALL)) {
                printf("Delete Main db entry and check for"
                        " ipv4 address sanity pm add = 0x%x ip add = 0x%x\n",
                        my_pm->ipv4_address,  ko->k.k.ipv4);
            }
            do {
                 /* udb is not NULL when we begin with for sure */
                 head = udb->translation_list_head_index;
                 db = cnat_main_db + head;
                 cnat_delete_main_db_entry_v2(db);
            } while (!pool_is_free(cnat_user_db, udb));

            rv = cnat_mapped_static_port_alloc_v2_bulk (pm,
                 PORT_ALLOC_ANY, &my_index, ko->k.k.ipv4, ko->k.k.port,
                 udb, BULKSIZE_FROM_VRFMAP(my_vrfmap), &nfv9_log_req, 
							my_vrfmap->ip_n_to_1);

            if (PREDICT_FALSE(rv != CNAT_SUCCESS)) {
             info->error = rv;
             in2out_drops_resource_depletion ++;
             CNAT_SET_ICMP_MSG_INFO
             CNAT_DEBUG_INSIDE_ERR(rv)
             return (NULL);
            }
	 /*
         * create entry in user db
         */
        udb = cnat_user_db_create_entry(&u_ki, my_index);
	my_pm = pm + my_index;
	if(PREDICT_TRUE(my_pm->private_ip_users_count < PORTS_PER_ADDR)) {
	    my_pm->private_ip_users_count++;
#ifdef DEBUG_PRINTF_IP_N_TO_1_ENABLED
	    PLATFORM_DEBUG_PRINT("\n cnat_create_static_main_db_entry_v2 "
				 "static del n alloc private_ip_users_count = "
				 "%d",my_pm->private_ip_users_count);
#endif
	} else {
	    PLATFORM_DEBUG_PRINT("\n ERROR: private_ip_users_count has "
				 "reached MAX PORTS_PER_ADDR");
	}
        NAT44_COMMON_STATS.num_subscribers++;
#ifndef NO_BULK_LOGGING
        cnat_update_bulk_range_cache(udb, ko->k.k.port,
            BULKSIZE_FROM_VRFMAP(my_vrfmap));
#endif /*  #ifndef NO_BULK_LOGGING */
      } else {

        rv = cnat_mapped_static_port_alloc_v2_bulk (pm,
            PORT_ALLOC_DIRECTED, &my_index, ko->k.k.ipv4, ko->k.k.port,
            udb, BULKSIZE_FROM_VRFMAP(my_vrfmap), &nfv9_log_req, 
						    my_vrfmap->ip_n_to_1);

        if (PREDICT_FALSE(rv != CNAT_SUCCESS)) {
            info->error = rv;
            CNAT_SET_ICMP_MSG_INFO
            CNAT_DEBUG_INSIDE_ERR(rv)
            log_port_alloc_error(rv, &(ki->k));
            return (NULL);
        }

        /*
         * increment port in use for this user
         */
        udb->ntranslations += 1;
      }
    } else {
        if (PREDICT_FALSE(global_debug_flag && CNAT_DEBUG_GLOBAL_ALL)) {
            printf ("Static port alloc any\n");
        }
        /*
         * first time allocate port for this user
         */
     
        /*
         * Check if main db has space for new entry
         * Allowing a user db entry to be created if main db is not free
         * will cause a port to be allocated to that user, which results in  
         * wastage of that port, hence the check is done here.
         */
        h = pool_header(cnat_main_db);
        free_main = vec_len(h->free_indices) - 1;
        h = pool_header(cnat_user_db);
	    free_user = vec_len(h->free_indices) - 1;

	/*
	 * If either main_db or user_db does not have entries
	 * bail out, with appropriate error
	 */
        if (PREDICT_FALSE(!(free_main && free_user))) {
            u32 log_error;
            if(free_main) {
                info->error = CNAT_USER_DB_LIMIT;
                log_error = CNAT_USER_DB_LIMIT_ERROR;
            } else {
                info->error = CNAT_MAIN_DB_LIMIT;
                log_error = CNAT_MAIN_DB_LIMIT_ERROR;
            }
            in2out_drops_system_limit_reached ++;
            CNAT_SET_ICMP_MSG_INFO 
            CNAT_DEBUG_INSIDE_ERR(info->error)
            spp_printf(log_error, 0, 0);
            return NULL;
        }

        rv = cnat_mapped_static_port_alloc_v2_bulk (pm,
            PORT_ALLOC_ANY, &my_index, ko->k.k.ipv4, ko->k.k.port,
            udb, BULKSIZE_FROM_VRFMAP(my_vrfmap), &nfv9_log_req, 
						    my_vrfmap->ip_n_to_1);

        if (PREDICT_FALSE(rv != CNAT_SUCCESS)) {
            info->error = rv;
            in2out_drops_resource_depletion ++;
            CNAT_SET_ICMP_MSG_INFO
            CNAT_DEBUG_INSIDE_ERR(rv) 
            log_port_alloc_error(rv, &(ki->k));
            return (NULL);
        }
        /* 
         * create entry in user db
         */
        udb = cnat_user_db_create_entry(&u_ki, my_index);
	my_pm = pm + my_index;
	if(PREDICT_TRUE(my_pm->private_ip_users_count < PORTS_PER_ADDR)) {
	    my_pm->private_ip_users_count++;
#ifdef DEBUG_PRINTF_IP_N_TO_1_ENABLED
	    PLATFORM_DEBUG_PRINT("\n cnat_create_static_main_db_entry_v2 "
				 "static alloc private_ip_users_count = %d",
				 my_pm->private_ip_users_count);
#endif
	} else {
	    PLATFORM_DEBUG_PRINT("\n ERROR: private_ip_users_count has "
				 "reached MAX PORTS_PER_ADDR");
	}
        NAT44_COMMON_STATS.num_subscribers++;
#ifndef NO_BULK_LOGGING
        cnat_update_bulk_range_cache(udb, ko->k.k.port,
            BULKSIZE_FROM_VRFMAP(my_vrfmap));
#endif /*  #ifndef NO_BULK_LOGGING */
    }

    /*
     * step 3:
     * outside port is allocated for this src vrf/src ip addr
     * 1)create a new entry in main db
     * 2)setup cnat_out2in_hash key
     * 3)setup cnat_in2out_hash key
     */
    db = cnat_create_main_db_entry_and_hash(ki, ko, udb);

    translation_create_count ++;
    db->vrfmap_index = my_vrfmap - cnat_map_by_vrf;

    /*
     * don't forget logging
     * logging API is unconditional, 
     * logging configuration check is done inside the inline function
     */

        if(PREDICT_FALSE(nfv9_log_req != CACHE_ALLOC_NO_LOG_REQUIRED)) {
        /* if session logging is enabled .. do not log  as there is no
         * traffic yet
         */
            if(PREDICT_FALSE(my_vrfmap->nf_logging_policy != SESSION_LOG_ENABLE)) {
		cnat_nfv9_log_mapping_create(db, my_vrfmap
#ifndef NO_BULK_LOGGING
                , nfv9_log_req
#endif
                );
            }
            if(PREDICT_FALSE(my_vrfmap->syslog_logging_policy != SESSION_LOG_ENABLE)) {
                cnat_syslog_nat44_mapping_create(db, my_vrfmap, 0
#ifndef NO_BULK_LOGGING
                , nfv9_log_req
#endif
                );
	    }
        }

    return db;
}


cnat_main_db_entry_t*
dslite_main_db_lookup_entry(dslite_db_key_bucket_t *ki);

cnat_user_db_entry_t*
dslite_user_db_lookup_entry(dslite_db_key_bucket_t *uki);

cnat_user_db_entry_t*
dslite_user_db_create_entry(dslite_db_key_bucket_t *uki, u32 portmap_index);

cnat_main_db_entry_t*
dslite_create_main_db_entry_and_hash(dslite_db_key_bucket_t *ki,
                                   cnat_db_key_bucket_t *ko,
                                   cnat_user_db_entry_t *udb);

#ifdef TOBE_PORTED
/*
 * this function is called from config handler only
 * to allocate a static port based db entry
 *
 * the actual mapped address and port are already specified
 */
cnat_main_db_entry_t*
dslite_create_static_main_db_entry_v2 (dslite_db_key_bucket_t *ki,
                                     cnat_db_key_bucket_t *ko,
                                     dslite_table_entry_t *dslite_entry_ptr,
                                     cnat_gen_icmp_info   *info)
{
    u16 protocol;
    u32 head;
    cnat_errno_t rv;
    dslite_db_key_bucket_t u_ki;
    u32                 my_index, free_main, free_user;
    cnat_portmap_v2_t   *pm =0;
    cnat_portmap_v2_t   *my_pm =0;
    cnat_user_db_entry_t *udb = 0;
    cnat_main_db_entry_t *db = 0;
    pool_header_t        *h;
    u16 dslite_id = dslite_entry_ptr->dslite_id;
#ifndef NO_BULK_LOGGING
    int                 nfv9_log_req = BULK_ALLOC_NOT_ATTEMPTED;
#endif
    cnat_vrfmap_t       *my_vrfmap =0;
    u16                 my_vrfmap_index;    

    /* 
     * need to try lookup again because 
     * second pkt may come here before the entry is created
     * by receiving first pkt due to high line rate.
     */
    info->gen_icmp_msg = CNAT_NO_ICMP_MSG;
    info->error = CNAT_SUCCESS;
    db = dslite_main_db_lookup_entry(ki);

    /*
     * If we already have an entry with this inside address, port
     * check delete the entry and proceed further.  This should
     * If yes, something is terribly wrong.  Bail out
     */
    if (PREDICT_FALSE(db)) {

        if (db->flags & CNAT_DB_FLAG_STATIC_PORT) {

            if ((db->out2in_key.k.ipv4 == ko->k.k.ipv4) &&
                (db->out2in_key.k.port == ko->k.k.port) &&
                (db->out2in_key.k.vrf  == ko->k.k.vrf)) {

#ifdef DEBUG_PRINTF_ENABLED
                printf("Same Static Port Exists ki 0x%16llx ko 0x%16llx",
                       ki->k, ko->k);
#endif
                /*
                 * We have already programmed this, return
                 */
                return (db);
            }

            /*
             * We already have a static port with different mapping
             * Return an error for this case.
             */
            info->error = CNAT_ERR_PARSER;

#ifdef DEBUG_PRINTF_ENABLED
	    printf("Static Port Existing and Diff ki 0x%16llx ko 0x%16llx",
                       ki, db->out2in_key);
#endif
        {
            u32 arr[] = {STAT_PORT_CONFIG_IN_USE, (ki->dk.ipv4_key.k.vrf & CNAT_VRF_MASK),
                ki->dk.ipv4_key.k.ipv4, ki->dk.ipv4_key.k.port, (ki->dk.ipv4_key.k.vrf & CNAT_PRO_MASK) };
            spp_printf(CNAT_CONFIG_ERROR, 5, arr);
        }
            return (db);
        }

#ifdef DEBUG_PRINTF_ENABLED
	printf("Deleting Dynamic entry  ki 0x%16llx ko 0x%16llx",
                       ki, db->out2in_key);
#endif

        /*
         * If for some reason we have dynamic entries, just delete them
         * and proceed.
         */
        cnat_delete_main_db_entry_v2(db);
        
        db = NULL;
    }
    

    protocol = ki->dk.ipv4_key.k.vrf & CNAT_PRO_MASK;
    u_ki.dk.ipv4_key.k.vrf = ki->dk.ipv4_key.k.vrf & CNAT_VRF_MASK;
    u_ki.dk.ipv4_key.k.ipv4 = ki->dk.ipv4_key.k.ipv4;
    u_ki.dk.ipv4_key.k.port = 0;
    u_ki.dk.ipv6[0] =       ki->dk.ipv6[0];
    u_ki.dk.ipv6[1] =       ki->dk.ipv6[1];
    u_ki.dk.ipv6[2] =       ki->dk.ipv6[2];
    u_ki.dk.ipv6[3] =       ki->dk.ipv6[3];

    my_vrfmap_index = vrf_map_array[u_ki.dk.ipv4_key.k.vrf];
    my_vrfmap = cnat_map_by_vrf + my_vrfmap_index;

    pm = dslite_entry_ptr->portmap_list;

    /*
     * check if src vrf, src ip addr is already 
     *         in the user db
     * if yes, use PORT_ALLOC_DIRECTED
     * if no, use PORT_ALLOC_ANY since it is first time
     */
    udb = dslite_user_db_lookup_entry(&u_ki);
    if (PREDICT_TRUE(udb)) {
        /* 
         * check if main db has space to accomodate new entry
         */
        h = pool_header(cnat_main_db);

        free_main = vec_len(h->free_indices) - 1;
        if (PREDICT_FALSE(!free_main)) {
            info->error = CNAT_MAIN_DB_LIMIT;
            nat44_dslite_common_stats[dslite_id].in2out_drops_port_limit_exceeded ++;
            DSLITE_DEBUG_INSIDE_ERR(CNAT_MAIN_DB_LIMIT)
#ifdef UT_TEST_CODE
            printf("Limit reached : OLD USER");
#endif
            spp_printf(CNAT_MAIN_DB_LIMIT_ERROR, 0, 0);
            return NULL;
        }

        /*
         * allocate port, from existing mapping 
         */
        my_index = udb->portmap_index;
        my_pm = pm + my_index;
       /* It is quite possible that we hit the scenario of CSCtj17774.
        * Delete all the main db entries and add the ipv4 address sent by
        * CGN-MA as Static port alloc any
        */

        if (PREDICT_FALSE(my_pm->ipv4_address != ko->k.k.ipv4)) {
            if (PREDICT_FALSE(global_debug_flag && CNAT_DEBUG_GLOBAL_ALL)) {
                printf("Delete Main db entry and check for"
                        " ipv4 address sanity pm add = 0x%x ip add = 0x%x\n",
                        my_pm->ipv4_address,  ko->k.k.ipv4);
            }
            do {
                 /* udb is not NULL when we begin with for sure */
                 head = udb->translation_list_head_index;
                 db = cnat_main_db + head;
                 cnat_delete_main_db_entry_v2(db);
            } while (!pool_is_free(cnat_user_db, udb));

            rv = cnat_mapped_static_port_alloc_v2_bulk (pm,
                 PORT_ALLOC_ANY, &my_index, ko->k.k.ipv4, ko->k.k.port,
                 udb, BULKSIZE_FROM_VRFMAP(dslite_entry_ptr), &nfv9_log_req, 
							my_vrfmap->ip_n_to_1);

            if (PREDICT_FALSE(rv != CNAT_SUCCESS)) {
             info->error = rv;
             nat44_dslite_common_stats[dslite_id].in2out_drops_port_limit_exceeded ++;
             DSLITE_DEBUG_INSIDE_ERR(rv)
             return (NULL);
            }
        /*
         * create entry in user db
         */
        udb = dslite_user_db_create_entry(&u_ki, my_index);
        nat44_dslite_common_stats[dslite_id].num_subscribers++;
#ifndef NO_BULK_LOGGING
        if(PREDICT_FALSE(udb && (BULK_ALLOC_NOT_ATTEMPTED != nfv9_log_req))) {
            cnat_update_bulk_range_cache(udb, ko->k.k.port,
            BULKSIZE_FROM_VRFMAP(dslite_entry_ptr));
        }
#endif /*  #ifndef NO_BULK_LOGGING */
      } else {

        rv = cnat_mapped_static_port_alloc_v2_bulk (pm,
            PORT_ALLOC_DIRECTED, &my_index, ko->k.k.ipv4, ko->k.k.port,
            udb, BULKSIZE_FROM_VRFMAP(dslite_entry_ptr), &nfv9_log_req, 
	    my_vrfmap->ip_n_to_1);

        if (PREDICT_FALSE(rv != CNAT_SUCCESS)) {
            info->error = rv;
            DSLITE_DEBUG_INSIDE_ERR(rv)
            log_port_alloc_error(rv, &(ki->dk.ipv4_key));
            return (NULL);
        }

        /*
         * increment port in use for this user
         */
        udb->ntranslations += 1;
      }
    } else {
        if (PREDICT_FALSE(global_debug_flag && CNAT_DEBUG_GLOBAL_ALL)) {
            printf ("Static port alloc any\n");
        }
        /*
         * first time allocate port for this user
         */
     
        /*
         * Check if main db has space for new entry
         * Allowing a user db entry to be created if main db is not free
         * will cause a port to be allocated to that user, which results in  
         * wastage of that port, hence the check is done here.
         */
        h = pool_header(cnat_main_db);
        free_main = vec_len(h->free_indices) - 1;
        h = pool_header(cnat_user_db);
	    free_user = vec_len(h->free_indices) - 1;

	/*
	 * If either main_db or user_db does not have entries
	 * bail out, with appropriate error
	 */
        if (PREDICT_FALSE(!(free_main && free_user))) {
            u32 log_error;
            if(free_main) {
                info->error = CNAT_USER_DB_LIMIT;
                log_error = CNAT_USER_DB_LIMIT_ERROR;
            } else {
                info->error = CNAT_MAIN_DB_LIMIT;
                log_error = CNAT_MAIN_DB_LIMIT_ERROR;
            }
            nat44_dslite_common_stats[dslite_id].in2out_drops_port_limit_exceeded ++;
            DSLITE_DEBUG_INSIDE_ERR(info->error)
            spp_printf(log_error, 0, 0);
            return NULL;
        }

        rv = cnat_mapped_static_port_alloc_v2_bulk (pm,
            PORT_ALLOC_ANY, &my_index, ko->k.k.ipv4, ko->k.k.port,
            udb, BULKSIZE_FROM_VRFMAP(dslite_entry_ptr), &nfv9_log_req,
	    my_vrfmap->ip_n_to_1);

        if (PREDICT_FALSE(rv != CNAT_SUCCESS)) {
            info->error = rv;
            nat44_dslite_common_stats[dslite_id].in2out_drops_port_limit_exceeded ++;
            DSLITE_DEBUG_INSIDE_ERR(rv) 
            log_port_alloc_error(rv, &(ki->dk.ipv4_key));
            return (NULL);
        }
        /* 
         * create entry in user db
         */
        udb = dslite_user_db_create_entry(&u_ki, my_index);
        nat44_dslite_common_stats[dslite_id].num_subscribers++;
#ifndef NO_BULK_LOGGING
        if(PREDICT_FALSE(udb && (BULK_ALLOC_NOT_ATTEMPTED != nfv9_log_req))) {
            cnat_update_bulk_range_cache(udb, ko->k.k.port,
            BULKSIZE_FROM_VRFMAP(dslite_entry_ptr));
        }
#endif /*  #ifndef NO_BULK_LOGGING */
    }

    /*
     * step 3:
     * outside port is allocated for this src vrf/src ip addr
     * 1)create a new entry in main db
     * 2)setup cnat_out2in_hash key
     * 3)setup cnat_in2out_hash key
     */
    db = dslite_create_main_db_entry_and_hash(ki, ko, udb);
    db->dslite_nat44_inst_id = dslite_id;
    nat44_dslite_common_stats[dslite_id].active_translations++;
    dslite_translation_create_count++;

    /*
     * don't forget logging
     * logging API is unconditional, 
     * logging configuration check is done inside the inline function
     */
#if 0 /* TBD - NEED TO DECIDE ON LOGGING */
        if(PREDICT_FALSE(nfv9_log_req != CACHE_ALLOC_NO_LOG_REQUIRED)) {
        /* if session logging is enabled .. do not log  as there is no
         * traffic yet
         */
#endif /* #if 0 - this has to be removed later */

    return db;
}
#endif /* TOBE_PORTED */


/* Per port/ip timeout related routines */
static
u32 cnat_timeout_db_hash_lookup (cnat_key_t t_key)
{
    cnat_key_t key;
    u64 a, b, c;
    u32 index;
    cnat_timeout_db_entry_t *db;

    key.k.ipv4 = t_key.k.ipv4;
    key.k.port = t_key.k.port;
    key.k.vrf = t_key.k.vrf;

    CNAT_V4_GET_HASH(key.key64,
                     index, CNAT_TIMEOUT_HASH_MASK)


    index = cnat_timeout_hash[index].next;

    if (PREDICT_FALSE(index == EMPTY))
        return EMPTY;

    do {
        db = cnat_timeout_db + index;
        if (PREDICT_TRUE((db->t_key.timeout_key.key64 & CNAT_TIMEOUT_FULL_MASK)
               == (key.key64 & CNAT_TIMEOUT_FULL_MASK)))
            break;
        index = db->t_hash.next;
    } while (index != EMPTY);

    return index;
}

/* Pass db_type as MAIN_DB_TYPE if you are passing
 * cnat_main_db_entry_t * casted as void * for db
 * else pass db_type as SESSION_DB_TYPE
 */
u16
query_and_update_db_timeout(void *db, u8 db_type)
{
    cnat_key_t t_search_key;
    u32 index;
    cnat_timeout_db_entry_t *timeout_db_entry;
    pool_header_t     *h;
    u32  free;

    cnat_main_db_entry_t *mdb = NULL;
    cnat_session_entry_t *sdb = NULL;

    if(PREDICT_TRUE(db_type == MAIN_DB_TYPE)) {
        mdb = (cnat_main_db_entry_t *)db;
    } else if(db_type == SESSION_DB_TYPE) {
        sdb = (cnat_session_entry_t *)db;
    } else {
        return 0;
    }

    h = pool_header(cnat_timeout_db);
    free = vec_len(h->free_indices) - 1;

    if(free == CNAT_TIMEOUT_HASH_SIZE) {
        /* No timeout db configured */
        return 0; 
    }

    /* First search for ip/port pair */
    if(PREDICT_TRUE(db_type == MAIN_DB_TYPE)) {
        t_search_key.k.ipv4 = mdb->dst_ipv4;
        t_search_key.k.port = mdb->dst_port;
        t_search_key.k.vrf = mdb->in2out_key.k.vrf;
    } else {
        t_search_key.k.ipv4 = sdb->v4_dest_key.k.ipv4;
        t_search_key.k.port = sdb->v4_dest_key.k.port;
        t_search_key.k.vrf = sdb->v4_dest_key.k.vrf;
    }

    index = cnat_timeout_db_hash_lookup(t_search_key);

    if(index == EMPTY) {
        /* Search for port map */
        t_search_key.k.ipv4 = 0;

        index = cnat_timeout_db_hash_lookup(t_search_key);

        if(index == EMPTY) {
            /* Search for ip only map */
            if(PREDICT_TRUE(db_type == MAIN_DB_TYPE)) {
                t_search_key.k.ipv4 = mdb->dst_ipv4;
            } else {
                t_search_key.k.ipv4 = sdb->v4_dest_key.k.ipv4;
            }
            t_search_key.k.port = 0; 

            index = cnat_timeout_db_hash_lookup(t_search_key);
            if(index != EMPTY) {
#ifdef DEBUG_PRINTF_ENABLED
              printf("%s: ip only map sucess\n","query_and_update_db_timeout");
#endif
            }
        } else {
#ifdef DEBUG_PRINTF_ENABLED
            printf("%s: port only map sucess\n", "query_and_update_db_timeout");
#endif
        }

    } else {
#ifdef DEBUG_PRINTF_ENABLED
        printf("%s: ip  port map sucess\n","query_and_update_db_timeout");
#endif

    }

    if(index == EMPTY) {
        /* No match found, clear timeout */
        if(PREDICT_TRUE(db_type == MAIN_DB_TYPE)) {
            mdb->timeout = 0;
        } else {
            sdb->timeout = 0;
        }
#ifdef DEBUG_PRINTF_ENABLED
        printf("%s: No match\n","query_and_update_db_timeout");
#endif
    } else {
        /* Match found, update timeout */
        timeout_db_entry = cnat_timeout_db + index;
        if(PREDICT_TRUE(db_type == MAIN_DB_TYPE)) {
            mdb->timeout = timeout_db_entry->t_key.timeout_value;
        } else {
            sdb->timeout =  timeout_db_entry->t_key.timeout_value;
        }
        return timeout_db_entry->t_key.timeout_value;
    }
    return 0;
}



static
void cnat_timeout_db_hash_add (cnat_timeout_db_entry_t *t_entry)
{
    cnat_key_t key;
    u64 a, b, c;
    u32 index, bucket;
    cnat_key_t t_key = t_entry->t_key.timeout_key;

    key.k.ipv4 = t_key.k.ipv4;
    key.k.port = t_key.k.port;
    key.k.vrf = t_key.k.vrf;

    CNAT_V4_GET_HASH(key.key64,
                     bucket, CNAT_TIMEOUT_HASH_MASK)


    index = cnat_timeout_hash[bucket].next;

    /* Add this db entry to the head of the bucket chain */
    t_entry->t_hash.next = index;
    cnat_timeout_hash[bucket].next = t_entry - cnat_timeout_db;
}



u16
cnat_timeout_db_create (cnat_timeout_t t_entry)
{
    cnat_timeout_db_entry_t *db;
    cnat_key_t t_key = t_entry.timeout_key;
    u32 db_index;

    pool_header_t        *h;
    u32                  free;

    db_index = cnat_timeout_db_hash_lookup(t_key);

    if(db_index != EMPTY) {
        /* Entry already exists. Check if it is replay or update */
        db = cnat_timeout_db + db_index;
        db->t_key.timeout_value = t_entry.timeout_value;
        return CNAT_SUCCESS;
    }

    h = pool_header(cnat_timeout_db);
    free = vec_len(h->free_indices) - 1;
    
    if(free == 0) {
        return CNAT_OUT_LIMIT;
    }


    pool_get(cnat_timeout_db, db);
    ASSERT(db);

    memset(db, 0, sizeof(*db));

    db_index = db - cnat_timeout_db;

    db->t_key.timeout_key.k.ipv4 = t_key.k.ipv4;
    db->t_key.timeout_key.k.port = t_key.k.port;
    db->t_key.timeout_key.k.vrf = t_key.k.vrf;
    db->t_key.timeout_value  = t_entry.timeout_value;


    cnat_timeout_db_hash_add(db);
    return CNAT_SUCCESS;
}

void cnat_timeout_db_delete(cnat_key_t t_key)
{
    cnat_key_t key;
    u64 a, b, c;
    u32 index, bucket;
    cnat_timeout_db_entry_t *this, *prev;

    key.k.ipv4 = t_key.k.ipv4;
    key.k.port = t_key.k.port;
    key.k.vrf = t_key.k.vrf;


    CNAT_V4_GET_HASH(key.key64,
                     bucket, CNAT_TIMEOUT_HASH_MASK)


    index = cnat_timeout_hash[bucket].next;

    if(index == EMPTY) return;

    prev = 0;
    do {
        this = cnat_timeout_db + index;
        if (PREDICT_TRUE(
            (this->t_key.timeout_key.key64 & CNAT_TIMEOUT_FULL_MASK) ==
                  (key.key64 & CNAT_TIMEOUT_FULL_MASK))) {
            if (prev == 0) {
                cnat_timeout_hash[bucket].next = this->t_hash.next;
                goto found;
	     } else {
                prev->t_hash.next = this->t_hash.next;
                goto found;
            }
        }

        prev = this;
        index = this->t_hash.next;
    } while (index != EMPTY);

    if(index == EMPTY) return;

 found:
    pool_put(cnat_timeout_db, this);

}

void cnat_session_db_hash_delete (cnat_session_entry_t *ep)
{
    u32 a, b, c;
    u32 index, bucket;
    cnat_session_entry_t *this, *prev;

    CNAT_V4_GET_SESSION_HASH(ep->main_db_index, ep->v4_dest_key.k.ipv4,
                    ep->v4_dest_key.k.port, ep->v4_dest_key.k.vrf, bucket,
                    CNAT_SESSION_HASH_MASK)


    index = cnat_session_hash[bucket].next;

    ASSERT(index != EMPTY);

    prev = 0;
    do {
        this = cnat_session_db + index;
        if (PREDICT_TRUE(this == ep)) {
            if (prev == 0) {
                cnat_session_hash[bucket].next =
                              ep->cnat_session_hash.next;
                return;
            } else {
                prev->cnat_session_hash.next =
                              ep->cnat_session_hash.next;
                return;
            }
        }
        prev = this;
        index = this->cnat_session_hash.next;
    } while (index != EMPTY);

    ASSERT(0);

}

cnat_session_entry_t *
cnat_session_db_edm_lookup_entry(cnat_key_t *ko,u32 session_head_index, 
                                 u32 main_db_index)
{
    u32 index;
    cnat_session_entry_t *db;


    index = session_head_index;
    if (PREDICT_TRUE(index == EMPTY)) {
        return (NULL);
    }

    do {
        db = cnat_session_db + index;
        if(PREDICT_TRUE((db->main_db_index == main_db_index) &&
              (db->v4_dest_key.k.vrf == ko->k.vrf) &&
              (db->v4_dest_key.k.ipv4 == ko->k.ipv4))) {

                return db;
        }
        index = db->cnat_session_hash.next;
    } while (index != EMPTY);
 
    return (NULL);
}



cnat_session_entry_t *
cnat_session_db_lookup_entry(cnat_key_t *ko,u32 main_db_index)
{
    u32 a, b, c;
    u32 index, bucket;
    cnat_session_entry_t *db;

    CNAT_V4_GET_SESSION_HASH(main_db_index, ko->k.ipv4, ko->k.port,
                     ko->k.vrf, bucket, CNAT_SESSION_HASH_MASK)


    index = cnat_session_hash[bucket].next;
    if (PREDICT_TRUE(index == EMPTY)) {
        return (NULL);
    }

    do {
        db = cnat_session_db + index;
        if(PREDICT_TRUE((db->main_db_index == main_db_index) &&
              (db->v4_dest_key.k.vrf == ko->k.vrf) &&
              (db->v4_dest_key.k.port == ko->k.port) &&
              (db->v4_dest_key.k.ipv4 == ko->k.ipv4))) {

                return db;
        }
        index = db->cnat_session_hash.next;
    } while (index != EMPTY);

    return (NULL);
}

cnat_session_entry_t *
cnat_create_session_db_entry(cnat_key_t *ko,
                             cnat_main_db_entry_t *bdb, u8 log)
{
    u32 a, b, c;
    u32 db_index, bucket_out;
    cnat_session_entry_t *db = NULL;
    pool_header_t        *h;
    u32 free_session;
    u16 instance;

    db = cnat_session_db_lookup_entry(ko, bdb - cnat_main_db);
    if (PREDICT_FALSE(db != NULL)) {
        /*printf("Create Session - Entry already Exists\n");*/
        return db;
    }

    h = pool_header(cnat_session_db);
    free_session = vec_len(h->free_indices) - 1;

    if (bdb->flags & CNAT_DB_DSLITE_FLAG) {
        instance = bdb->dslite_nat44_inst_id;
    } else {
        instance = NAT44_RESERVED_INST_ID;
    }

    if (PREDICT_FALSE(!free_session)) {
      nat44_dslite_common_stats[instance].drops_sessiondb_limit_exceeded++;
        return NULL;
    }

    if( PREDICT_FALSE(bdb->nsessions == CNAT_MAX_SESSIONS_PER_BIB)) {
        /* printf("Create Session - Max sessions per BIB reached\n"); */
        return NULL;
    }

    pool_get(cnat_session_db, db);
    memset(db, 0, sizeof(*db));

    db_index = db - cnat_session_db;
    db->v4_dest_key.k.port = ko->k.port;
    db->v4_dest_key.k.ipv4 = ko->k.ipv4;
    db->v4_dest_key.k.vrf = ko->k.vrf;

    db->main_list.next = db_index;
    db->main_list.prev = db_index;
    db->main_db_index = bdb - cnat_main_db;

    db->tcp_seq_num = 0;
    db->ack_no      = 0;
    db->window      = 0;

    if(PREDICT_FALSE(log)) {
        bdb->nsessions++;
        query_and_update_db_timeout(db, SESSION_DB_TYPE);
    }

    if (PREDICT_FALSE(bdb->nsessions == 1)) {
        /*
         * first port for this src vrf/src ip addr
         */
        bdb->session_head_index = db_index;
    } else {
        index_dlist_addtail(bdb->session_head_index,
                            (u8 *)cnat_session_db, sizeof(cnat_session_db[0]),
                            STRUCT_OFFSET_OF(cnat_session_entry_t, main_list),
                            db_index);
    }

    /*
     * setup o2i hash key
     */
    CNAT_V4_GET_SESSION_HASH(db->main_db_index, ko->k.ipv4, ko->k.port,
                     ko->k.vrf, bucket_out, CNAT_SESSION_HASH_MASK)


    db->cnat_session_hash.next =
                          cnat_session_hash[bucket_out].next;
    cnat_session_hash[bucket_out].next = db_index;


    if(PREDICT_FALSE(log)) {
        if (bdb->flags & CNAT_DB_DSLITE_FLAG) {
            cnat_session_log_ds_lite_mapping_create(bdb,
             			(dslite_table_db_ptr + instance),db);
        } else {
	    cnat_vrfmap_t *my_vrfmap = cnat_map_by_vrf + bdb->vrfmap_index;
            cnat_session_log_nat44_mapping_create(bdb, db, my_vrfmap);
        }
    }

    /* Need to set entry_expires here, as we need to override 0 check for
       newly established sessions */
    db->entry_expires = cnat_current_time;
    nat44_dslite_common_stats[instance].sessions++;
    return db;
}

void
cnat_dest_update_main2session(cnat_main_db_entry_t *mdb,
                 cnat_session_entry_t *sdb)
{

    sdb->flags = mdb->flags;
    sdb->timeout = mdb->timeout;
    sdb->entry_expires = mdb->entry_expires;
    sdb->alg.delta = mdb->alg.delta;
    sdb->tcp_seq_num = mdb->proto_data.seq_pcp.tcp_seq_num;

    /* Reset Main db values to 0 */
    /* Reset only session specific flags */
    mdb->flags &= ~(CNAT_DB_FLAG_TCP_ACTIVE | CNAT_DB_FLAG_UDP_ACTIVE
                        | CNAT_DB_FLAG_ALG_ENTRY | CNAT_DB_FLAG_ALG_CTRL_FLOW);
    mdb->timeout = 0;
    mdb->entry_expires = 0;
    mdb->alg.delta = 0;
    if(PREDICT_FALSE(!((mdb->flags & CNAT_DB_FLAG_PPTP_TUNNEL_ACTIVE) ||
            (mdb->flags & CNAT_DB_FLAG_PPTP_TUNNEL_INIT)))) {
        mdb->proto_data.seq_pcp.tcp_seq_num = 0;
    }

    mdb->dst_ipv4 = 0;
    mdb->dst_port = 0;
}


void
cnat_dest_update_session2main(cnat_main_db_entry_t *mdb,
                 cnat_session_entry_t *sdb)
{

    u16 flags = sdb->flags & (CNAT_DB_FLAG_TCP_ACTIVE |
        CNAT_DB_FLAG_UDP_ACTIVE | CNAT_DB_FLAG_ALG_ENTRY |
        CNAT_DB_FLAG_ALG_CTRL_FLOW);
    mdb->flags |= flags;
    mdb->timeout = sdb->timeout;
    mdb->entry_expires = sdb->entry_expires;
    mdb->alg.delta = sdb->alg.delta;
    if(PREDICT_FALSE(!((mdb->flags & CNAT_DB_FLAG_PPTP_TUNNEL_ACTIVE) ||
            (mdb->flags & CNAT_DB_FLAG_PPTP_TUNNEL_INIT)))) {
	    mdb->proto_data.seq_pcp.tcp_seq_num = sdb->tcp_seq_num;
    }
    mdb->dst_ipv4 = sdb->v4_dest_key.k.ipv4;
    mdb->dst_port = sdb->v4_dest_key.k.port;
}

void cnat_delete_session_db_entry (cnat_session_entry_t *ep, u8 log)
{
    u32  session_db_index;
    u32  bdb_len;
    cnat_main_db_entry_t *be =0;
    cnat_session_entry_t *sdb_last = NULL;
    u16 instance;

    if (PREDICT_FALSE(ep->flags & CNAT_DB_NAT64_FLAG) != 0) {
        /* Preventive check - Not a NAT44 entry */
        return;
    }

    pool_header_t *h = pool_header(cnat_main_db);

     /* Validate .. just in case we are trying to delete a non existing one */
    bdb_len = vec_len(cnat_main_db);

    /* In case of invalid user just return, deleting only main db
     * is not a good idea, since some valid user db entry might be pointing
     * to that main db and hence leave the dbs in a inconsistent state
     */
    if (PREDICT_FALSE((ep->main_db_index >= bdb_len) ||
                    (clib_bitmap_get(h->free_bitmap, ep->main_db_index)))) {
#ifdef DEBUG_PRINTF_ENABLED
        printf("invalid/unused user index in db %d\n", ep->main_db_index);
#endif
        spp_printf(CNAT_INV_UNUSED_USR_INDEX, 1, (u32 *) &(ep->main_db_index));
        return;
    }

    be = cnat_main_db + ep->main_db_index;

    session_db_index = ep - cnat_session_db;

    be->session_head_index = index_dlist_remelem (
        be->session_head_index, (u8 *)cnat_session_db,
        sizeof (cnat_session_db[0]),
        STRUCT_OFFSET_OF(cnat_session_entry_t, main_list),
        session_db_index);

    if (be->flags & CNAT_DB_DSLITE_FLAG) {
	instance = be->dslite_nat44_inst_id;
    } else {
	instance = NAT44_RESERVED_INST_ID;
    }    

    if(PREDICT_TRUE(log)) {
        if (be->flags & CNAT_DB_DSLITE_FLAG) {
            cnat_session_log_ds_lite_mapping_delete(be, 
                                (dslite_table_db_ptr + instance),ep);
        } else {
            cnat_vrfmap_t *my_vrfmap = cnat_map_by_vrf + be->vrfmap_index;
      	    cnat_session_log_nat44_mapping_delete(be, ep, my_vrfmap);
        }
        be->nsessions--;
    }

    if (PREDICT_FALSE(be->nsessions == 1 && log)) {
        /* There is only 1 session left
         * Copy the info back to main db and release the last
         * existing session
         */

        sdb_last = cnat_session_db + be->session_head_index;
        ASSERT(sdb_last != NULL);

        cnat_dest_update_session2main(be, sdb_last);
        cnat_delete_session_db_entry(sdb_last, FALSE);
    }

    /* Remove from session DB hashes */
    cnat_session_db_hash_delete(ep);
    nat44_dslite_common_stats[instance].sessions--;

    pool_put(cnat_session_db, ep);
}

cnat_main_db_entry_t*
dslite_main_db_lookup_entry(dslite_db_key_bucket_t *ki)
{
    u64 a, b, c;
    u32 index;
    cnat_main_db_entry_t *db;
    cnat_user_db_entry_t *userdb;

    DSLITE_V6_GET_HASH((&(ki->dk)),
                     ki->bucket,
                     CNAT_MAIN_HASH_MASK);

    DSLITE_PRINTF(1,"MDBLU hash..%u\n", ki->bucket);
 
    index = cnat_in2out_hash[ki->bucket].next;
    if (PREDICT_TRUE(index == EMPTY)) {
        DSLITE_PRINTF(1,"MDBLU index MT..\n");
        return (NULL);
    }

    do {
/* We can add a flag here to indicate if the db entry is for nat44 or 
 * dslite. If the db entry is for nat44 then we can simply move to the
 * one.
 */
        db = cnat_main_db + index;
        userdb = cnat_user_db + db->user_index;
        if (PREDICT_TRUE(db->in2out_key.key64 == ki->dk.ipv4_key.key64)
            && userdb->ipv6[0] == ki->dk.ipv6[0]
            && userdb->ipv6[1] == ki->dk.ipv6[1]
            && userdb->ipv6[2] == ki->dk.ipv6[2]
            && userdb->ipv6[3] == ki->dk.ipv6[3]) {
            DSLITE_PRINTF(1,"MDBLU success..%u\n", index);
            return db;
        }
        index = db->in2out_hash.next;
    } while (index != EMPTY);

    DSLITE_PRINTF(1,"MDBLU Entry does not exist..\n");
    return (NULL);
}

cnat_user_db_entry_t*
dslite_user_db_lookup_entry(dslite_db_key_bucket_t *uki) 
{
    u64 a, b, c;
    u32 index;
    cnat_user_db_entry_t *udb=NULL;

    DSLITE_V6_GET_HASH((&(uki->dk)), 
                     uki->bucket,
                     CNAT_USER_HASH_MASK)

    DSLITE_PRINTF(1,"UDBLU hash..%u\n", uki->bucket);

    /* now: index in user vector */
    index = cnat_user_hash[uki->bucket].next;
    if (PREDICT_TRUE(index != EMPTY)) {
        DSLITE_PRINTF(1,"UDBLU hash table entry not MT..\n");
        do {
            udb = cnat_user_db + index;
            if (PREDICT_FALSE(udb->key.key64 == uki->dk.ipv4_key.key64)
             && udb->ipv6[0] == uki->dk.ipv6[0]
             && udb->ipv6[1] == uki->dk.ipv6[1]
             && udb->ipv6[2] == uki->dk.ipv6[2]
             && udb->ipv6[3] == uki->dk.ipv6[3]) {
                DSLITE_PRINTF(1,"UDBLU success..%u\n", index);
                return udb;
            }
            index = udb->user_hash.next;
        } while (index != EMPTY);
    }
    DSLITE_PRINTF(1,"UDBLU Entry doesnt exist..\n");
    return (NULL);
}

cnat_user_db_entry_t*
dslite_user_db_create_entry(dslite_db_key_bucket_t *uki,
                          u32 portmap_index)
{
    cnat_user_db_entry_t *udb = NULL;

    pool_get(cnat_user_db, udb);
    memset(udb, 0, sizeof(*udb));

    udb->ntranslations = 1; 
    udb->portmap_index = portmap_index;
//    udb->key.key64 = uki->k.key64;

    udb->key.key64 = uki->dk.ipv4_key.key64;
    udb->ipv6[0] = uki->dk.ipv6[0];
    udb->ipv6[1] = uki->dk.ipv6[1];
    udb->ipv6[2] = uki->dk.ipv6[2];
    udb->ipv6[3] = uki->dk.ipv6[3];
 
    udb->flags |= CNAT_USER_DB_DSLITE_FLAG;
    /* Add this user to the head of the bucket chain */
    udb->user_hash.next = 
             cnat_user_hash[uki->bucket].next;
    cnat_user_hash[uki->bucket].next = udb - cnat_user_db;

#ifndef NO_BULK_LOGGING
    INIT_BULK_CACHE(udb)
#endif /* NO_BULK_LOGGING */

    return udb;
}

#ifndef TOBE_PORTED
cnat_main_db_entry_t*
dslite_create_main_db_entry_and_hash(dslite_db_key_bucket_t *ki,
                                   cnat_db_key_bucket_t *ko,
                                   cnat_user_db_entry_t *udb)
{
    return 0;
}
#else
cnat_main_db_entry_t*
dslite_create_main_db_entry_and_hash(dslite_db_key_bucket_t *ki,
                                   cnat_db_key_bucket_t *ko,
                                   cnat_user_db_entry_t *udb)
{
    u64 a, b, c;
    u32 db_index;
    cnat_main_db_entry_t *db = NULL;

    pool_get(cnat_main_db, db);
    memset(db, 0, sizeof(*db));

    db_index = db - cnat_main_db;
    db->in2out_key.k.ipv4 = ki->dk.ipv4_key.k.ipv4;
    db->in2out_key.k.port = ki->dk.ipv4_key.k.port;
    db->in2out_key.k.vrf =  ki->dk.ipv4_key.k.vrf;
    db->out2in_key.k.ipv4 = ko->k.k.ipv4;
    db->out2in_key.k.port = ko->k.k.port;
    db->out2in_key.k.vrf = ko->k.k.vrf;

    db->user_ports.next = db_index;
    db->user_ports.prev = db_index;
    db->user_index = udb - cnat_user_db;
    //db->portmap_index = udb->portmap_index;
   db->flags |= CNAT_DB_DSLITE_FLAG;

    if (PREDICT_FALSE(udb->ntranslations == 1)) {
        /*
         * first port for this src vrf/src ip addr
         */
        udb->translation_list_head_index = db_index;
        DSLITE_PRINTF(1,"First translation of this user..\n");
    } else {
        index_dlist_addtail(udb->translation_list_head_index,
                            (u8 *)cnat_main_db, sizeof(cnat_main_db[0]),
                            STRUCT_OFFSET_OF(cnat_main_db_entry_t, user_ports),
                            db_index);
    }

    /* 
     * setup o2i hash key
     */
    CNAT_V4_GET_HASH(ko->k.key64, 
                     ko->bucket,
                     CNAT_MAIN_HASH_MASK)
    db->out2in_hash.next = cnat_out2in_hash[ko->bucket].next;
    cnat_out2in_hash[ko->bucket].next = db_index;
    /*
     * setup i2o hash key, bucket is already calculate
     */
    db->in2out_hash.next = cnat_in2out_hash[ki->bucket].next;
    cnat_in2out_hash[ki->bucket].next = db_index;

    DSLITE_PRINTF(1,"Create main db and hash..%u %u %u %u %x\n", 
                  ki->bucket, ko->bucket, 
                  db_index, db->user_index, ko->k.key64);

#if DEBUG > 1
    printf("\nMy_Instance_Number %d: Bucket %d, Db_Index %d",
           my_instance_number, ki->bucket, db_index);
    printf("\nInside (VRF 0x%x, IP 0x%x, PORT 0x%x)",
           db->in2out_key.k.vrf, db->in2out_key.k.ipv4, db->in2out_key.k.port);
    printf("\nOutside (VRF 0x%x, IP 0x%x, PORT 0x%x)",
           db->out2in_key.k.vrf, db->out2in_key.k.ipv4, db->out2in_key.k.port);
    printf("\nUser Index %d, IP 0x%x",
           db->user_index, udb->key.k.ipv4);
#endif

    //nat44_dslite_common_stats[DSLITE_COMMON_STATS].active_translations++;

    return db;
}

static inline void handle_dslite_port_exceeded_logging(
    cnat_user_db_entry_t *udb, 
    dslite_key_t   * key,
    dslite_table_entry_t *dslite_entry_ptr)
{

    if(PREDICT_TRUE(udb->flags & CNAT_USER_DB_PORT_LIMIT_EXCEEDED)) {
        /* Already logged ..*/
        return;
    }

    /* else, set the flag and call the log API */
    udb->flags = udb->flags | CNAT_USER_DB_PORT_LIMIT_EXCEEDED;
    cnat_log_ds_lite_port_limit_exceeded(key, dslite_entry_ptr);
    return;
}
#endif

void handle_cnat_port_exceeded_logging(
    cnat_user_db_entry_t *udb,
    cnat_key_t   * key,
    cnat_vrfmap_t *vrfmap)
{

    if(PREDICT_TRUE(udb->flags & CNAT_USER_DB_PORT_LIMIT_EXCEEDED)) {
        /* Already logged ..*/
        return;
    }

    /* else, set the flag and call the log API */
    udb->flags = udb->flags | CNAT_USER_DB_PORT_LIMIT_EXCEEDED;
    cnat_log_nat44_port_limit_exceeded(key,vrfmap);
    return;
}

#ifndef TOBE_PORTED
cnat_main_db_entry_t*
dslite_get_main_db_entry_v2(dslite_db_key_bucket_t *ki,
                          port_pair_t port_pair_type,
                          port_type_t port_type,
                          cnat_gen_icmp_info *info,
                          dslite_table_entry_t *dslite_entry_ptr,
                          cnat_key_t *dest_info)
{
    return 0;
}
#else
/*
 * this function is called by exception node
 * when lookup is fialed in i2o node
 *
 * if reash per user port limit, 
 * set user_db_entry pointer, and error == CNAT_OUT_LIMIT
 */
cnat_main_db_entry_t*
dslite_get_main_db_entry_v2(dslite_db_key_bucket_t *ki,
                          port_pair_t port_pair_type,
                          port_type_t port_type,
                          cnat_gen_icmp_info *info,
                          dslite_table_entry_t *dslite_entry_ptr,
			  cnat_key_t *dest_info)
{
    u16 protocol;
    cnat_errno_t rv;
    dslite_db_key_bucket_t u_ki;
    cnat_db_key_bucket_t ko;
    u32                 my_index, free_main, free_user;
    u32                 current_timestamp;
    cnat_vrfmap_t       *my_vrfmap =0;
    u16                 my_vrfmap_index;
    cnat_portmap_v2_t   *pm =0;
    cnat_user_db_entry_t *udb = 0;
    cnat_main_db_entry_t *db = 0;
    pool_header_t        *h;
    u16 dslite_id = dslite_entry_ptr->dslite_id;

#ifndef NO_BULK_LOGGING
    int nfv9_log_req = BULK_ALLOC_NOT_ATTEMPTED;
#endif
    /* 
     * need to try lookup again because 
     * second pkt may come here before the entry is created
     * by receiving first pkt due to high line rate.
     */
    info->gen_icmp_msg = CNAT_NO_ICMP_MSG;
    info->error = CNAT_SUCCESS;
    db = dslite_main_db_lookup_entry(ki);
    if (PREDICT_TRUE(db)) {
        /* what if the source is talking to a
         * new dest now? We will have to handle this case and
         * take care of - creating session db and logging
         */
        if(PREDICT_FALSE((!dest_info->k.ipv4) && (!dest_info->k.port))) {
            return db;  /* if dest_info is null don't create session */
        }

        if(PREDICT_TRUE((db->dst_ipv4 == dest_info->k.ipv4) &&
            (db->dst_port == dest_info->k.port))) {
            return db;
        }
        dest_info->k.vrf = db->in2out_key.k.vrf;
        /* Src is indeed talking to a different dest */
        cnat_session_entry_t *session_db2 = NULL;
        if(PREDICT_TRUE(db->nsessions == 1)) {
            session_db2 = cnat_handle_1to2_session(db, dest_info);
            if(PREDICT_TRUE(session_db2 != NULL)) {
                CNAT_DB_TIMEOUT_RST(session_db2);
                return db;
            } else {
                info->error = CNAT_ERR_NO_SESSION_DB;
                return NULL;
            }
        } else if(PREDICT_FALSE(db->nsessions == 0)) {
            /* Should be static entry.. should never happen
             */
            if(PREDICT_TRUE(dest_info->k.ipv4 != 0)) {
                cnat_add_dest_n_log(db, dest_info);
            }
            return db;
        } else {
            /* The src has already created multiple sessions.. very rare
             */
            session_db2 = cnat_create_session_db_entry(dest_info,
                        db, TRUE);
            if(PREDICT_TRUE(session_db2 != NULL)) {
                CNAT_DB_TIMEOUT_RST(session_db2);
               return db;
            } else {
                info->error = CNAT_ERR_NO_SESSION_DB;
                return NULL;
            }
        }

    }

    /* 
     * step 1. check if outside vrf is configured or not
     *         and Find the set of portmaps for the outside vrf
     * insider vrf is one to one mappted to outside vrf
     * key is vrf and ip only
     * ki.k.k.vrf has protocol bits, mask out 
     */
    protocol =              ki->dk.ipv4_key.k.vrf & CNAT_PRO_MASK;
    u_ki.dk.ipv4_key.k.vrf =  ki->dk.ipv4_key.k.vrf & CNAT_VRF_MASK;
#ifdef DSLITE_USER_IPV4
    u_ki.dk.ipv4_key.k.ipv4 = ki->dk.ipv4_key.k.ipv4;
#else
   /*
    * Inside ipv4 address should be masked, if port limit
    * need to be done at B4 element level.
    */ 
    u_ki.dk.ipv4_key.k.ipv4 = 0;
#endif
    u_ki.dk.ipv4_key.k.port = 0;

    u_ki.dk.ipv6[0] =       ki->dk.ipv6[0];
    u_ki.dk.ipv6[1] =       ki->dk.ipv6[1];
    u_ki.dk.ipv6[2] =       ki->dk.ipv6[2];
    u_ki.dk.ipv6[3] =       ki->dk.ipv6[3];

    my_vrfmap_index = vrf_map_array[u_ki.dk.ipv4_key.k.vrf];
    my_vrfmap = cnat_map_by_vrf + my_vrfmap_index;
/*  Checking if the inst entry is active or not is done much earlier
 */
#if 0
    my_vrfmap_index = vrf_map_array[u_ki.k.k.vrf];
    my_vrfmap = cnat_map_by_vrf + my_vrfmap_index;
    my_vrfmap_entry_found = ((my_vrfmap_index != VRF_MAP_ENTRY_EMPTY) &&
                             (my_vrfmap->status == S_RUN) &&
			     (my_vrfmap->i_vrf == u_ki.k.k.vrf));

    if (PREDICT_FALSE(!my_vrfmap_entry_found)) {
        u32 arr[] = {ki->k.k.vrf, ki->k.k.ipv4, ki->k.k.port};
        if ((my_vrfmap_index == VRF_MAP_ENTRY_EMPTY) || 
	    (my_vrfmap->i_vrf == u_ki.k.k.vrf)) {
	    info->error = CNAT_NO_CONFIG;
	    CNAT_DEBUG_INSIDE_ERR(CNAT_NO_CONFIG)
        spp_printf(CNAT_NO_CONFIG_ERROR, 3, arr);
	} else {
	    info->error = CNAT_NO_VRF_RUN;
	    CNAT_DEBUG_INSIDE_ERR(CNAT_NO_VRF_RUN)
        spp_printf(CNAT_NO_VRF_RUN_ERROR, 3, arr);
	}

	return (NULL);
    }
#endif
/*
    dslite_inst_ptr = dslite_nat44_config_table[dslite_inst_id];
*/
    pm = dslite_entry_ptr->portmap_list;
    //pm = my_vrfmap->portmap_list;

    /*
     * set o2i key with protocl bits
     */
    ko.k.k.vrf = dslite_entry_ptr->o_vrf | protocol;
    //ko.k.k.vrf = my_vrfmap->o_vrf | protocol;

    /*
     * step 2. check if src vrf, src ip addr is alreay 
     *         in the user db
     * if yes, use PORT_ALLOC_DIRECTED
     * if no, use PORT_ALLOC_ANY since it is first time
     */
    udb = dslite_user_db_lookup_entry(&u_ki);
    if (PREDICT_TRUE(udb)) {
        /*
         * not first time allocate port for this user
         * check limit
         */
        if (PREDICT_FALSE(udb->ntranslations >= 
             dslite_entry_ptr->cnat_main_db_max_ports_per_user)) {
             //cnat_main_db_max_ports_per_user)) 

            /* Check for the port type here. If we are getting
             * a STATIC PORT, allow the config.
             */
            if (PREDICT_TRUE(port_type != PORT_TYPE_STATIC)) {
               info->error = CNAT_OUT_LIMIT;
               DSLITE_DEBUG_INSIDE_ERR(CNAT_OUT_LIMIT)
               port_exceeded_msg_log(u_ki.dk.ipv4_key.k.ipv4, u_ki.dk.ipv4_key.k.vrf);
               nat44_dslite_common_stats[dslite_id].in2out_drops_port_limit_exceeded ++;
               u_ki.dk.ipv4_key.k.vrf =  ki->dk.ipv4_key.k.vrf;
               u_ki.dk.ipv4_key.k.port = ki->dk.ipv4_key.k.port;
               handle_dslite_port_exceeded_logging(udb, &u_ki.dk, dslite_entry_ptr); 
               return (NULL);
            }
        }

        CHECK_CLEAR_PORT_LIMIT_EXCEED_FLAG(udb, 
            dslite_entry_ptr->cnat_main_db_max_ports_per_user)

        /* 
         * check if main db has space to accomodate new entry
         */
        h = pool_header(cnat_main_db);

        free_main = vec_len(h->free_indices) - 1;
        if (PREDICT_FALSE(!free_main)) {
            info->error = CNAT_MAIN_DB_LIMIT;
            nat44_dslite_common_stats[dslite_id].in2out_drops_system_limit_reached ++;
            DSLITE_DEBUG_INSIDE_ERR(CNAT_MAIN_DB_LIMIT)

            current_timestamp = spp_trace_log_get_unix_time_in_seconds();
            if (PREDICT_FALSE((current_timestamp - last_log_timestamp) >
                    1800)) {
                spp_printf(CNAT_SESSION_THRESH_EXCEEDED, 0, NULL);
                last_log_timestamp = current_timestamp;
            }

#ifdef UT_TEST_CODE
            printf("Limit reached : OLD USER");
#endif
            return NULL;
        }

        /*
         * allocate port, from existing mapping 
         */
        my_index = udb->portmap_index;

        if (PREDICT_FALSE(port_type == PORT_TYPE_STATIC)) {
            rv = cnat_static_port_alloc_v2_bulk(pm,
                        PORT_ALLOC_DIRECTED,
                        port_pair_type,
                        ki->dk.ipv4_key.k.ipv4,
                        ki->dk.ipv4_key.k.port,
                        &my_index,
                        &(ko.k.k.ipv4),
                        &(ko.k.k.port),
                        STAT_PORT_RANGE_FROM_INST_PTR(dslite_entry_ptr)
#ifndef NO_BULK_LOGGING
                        , udb,
                        BULKSIZE_FROM_VRFMAP(dslite_entry_ptr),
                        &nfv9_log_req
#endif
			, my_vrfmap->ip_n_to_1
                        );
        }  else if (PREDICT_TRUE(port_type != PORT_TYPE_RTSP) ) {

            rv = cnat_dynamic_port_alloc_v2_bulk(pm,
                        PORT_ALLOC_DIRECTED,
                        port_pair_type,
                        &my_index,
                        &(ko.k.k.ipv4),
                        &(ko.k.k.port), 
                        STAT_PORT_RANGE_FROM_INST_PTR(dslite_entry_ptr)
#ifndef NO_BULK_LOGGING
                        , udb,
                        BULKSIZE_FROM_VRFMAP(dslite_entry_ptr),
                        &nfv9_log_req
#endif
                        , 0,
                        &(dslite_entry_ptr->rseed_ip)
                        );
            DSLITE_PRINTF(1,"D_PORT_ALLOC %x %u\n", ko.k.k.ipv4, ko.k.k.port);
        } else {
            /*
             * For RTSP, two translation entries are created, 
             * check if main db has space to accomodate two new entry
             */
            free_main = free_main  - 1; 

            if (PREDICT_FALSE(!free_main)) {
                info->error = CNAT_MAIN_DB_LIMIT;
                nat44_dslite_common_stats[dslite_id].in2out_drops_system_limit_reached ++;
                DSLITE_DEBUG_INSIDE_ERR(CNAT_MAIN_DB_LIMIT)

                return NULL;
            } else {    

                rv = cnat_dynamic_port_alloc_rtsp_bulk(pm,
                            PORT_ALLOC_DIRECTED,
                            port_pair_type,
                            ki->dk.ipv4_key.k.port,
                            &my_index,
                            &(ko.k.k.ipv4),
                            &(ko.k.k.port),
                            STAT_PORT_RANGE_FROM_INST_PTR(dslite_entry_ptr)
#ifndef NO_BULK_LOGGING
                            , udb,
                            BULKSIZE_FROM_VRFMAP(dslite_entry_ptr),
                            &nfv9_log_req
#endif
                         , &(dslite_entry_ptr->rseed_ip)
                        );
            }
        }

        if (PREDICT_FALSE(rv != CNAT_SUCCESS)) {
            DSLITE_PRINTF(1,"D_PORT_ALLOC port alloc error\n");
            info->error = rv;
            DSLITE_DEBUG_INSIDE_ERR(rv)
            nat44_dslite_common_stats[dslite_id].in2out_drops_resource_depletion ++;
            log_port_alloc_error(rv, &(ki->dk.ipv4_key));
            return (NULL);
        }
        /*
         * increment port in use for this user
         */
        udb->ntranslations += 1;
    } else {
        /*
         * first time allocate port for this user
         */
     
        /*
         * Do not create entry if port limit is invalid
         */
        if (PREDICT_FALSE(!(dslite_entry_ptr->cnat_main_db_max_ports_per_user))) {
            if (PREDICT_TRUE(port_type != PORT_TYPE_STATIC)) {
                info->error = CNAT_OUT_LIMIT;
                nat44_dslite_common_stats[dslite_id].in2out_drops_port_limit_exceeded ++;
                port_exceeded_msg_log(u_ki.dk.ipv4_key.k.ipv4, u_ki.dk.ipv4_key.k.vrf);
                DSLITE_DEBUG_INSIDE_ERR(CNAT_OUT_LIMIT)
                return (NULL);
            }
        }

        /*
         * Check if main db has space for new entry
         * Allowing a user db entry to be created if main db is not free
         * will cause a port to be allocated to that user, which results in  
         * wastage of that port, hence the check is done here.
         */
        h = pool_header(cnat_main_db);
        free_main = vec_len(h->free_indices) - 1;

        h = pool_header(cnat_user_db);
	    free_user = vec_len(h->free_indices) - 1;

	/*
	 * If either main_db or user_db does not have entries
	 * bail out, with appropriate error
	 */
        if (PREDICT_FALSE(!(free_main && free_user))) {
            u32 log_error;
            if(free_main) {
                info->error = CNAT_USER_DB_LIMIT;
                log_error = CNAT_USER_DB_LIMIT_ERROR;
            } else {
                   info->error = CNAT_MAIN_DB_LIMIT;
                   log_error = CNAT_MAIN_DB_LIMIT_ERROR;
            }
            nat44_dslite_common_stats[dslite_id].in2out_drops_system_limit_reached ++;
            DSLITE_DEBUG_INSIDE_ERR(info->error)
            spp_printf(log_error, 0, 0);
            return NULL;
        }

        if (PREDICT_FALSE(port_type == PORT_TYPE_STATIC)) {
            rv = cnat_static_port_alloc_v2_bulk(pm,
                        PORT_ALLOC_ANY,
                        port_pair_type,
                        ki->dk.ipv4_key.k.ipv4,
                        ki->dk.ipv4_key.k.port,
                        &my_index,
                        &(ko.k.k.ipv4),
                        &(ko.k.k.port),
                        STAT_PORT_RANGE_FROM_INST_PTR(dslite_entry_ptr)
#ifndef NO_BULK_LOGGING
                        , NULL,
                        BULKSIZE_FROM_VRFMAP(dslite_entry_ptr), 
                        &nfv9_log_req
#endif
			, my_vrfmap->ip_n_to_1
                      
                        );
        }  else if (PREDICT_TRUE(port_type != PORT_TYPE_RTSP)) {
            rv = cnat_dynamic_port_alloc_v2_bulk(pm,
                        PORT_ALLOC_ANY,
                        port_pair_type,
                        &my_index,
                        &(ko.k.k.ipv4),
                        &(ko.k.k.port),
                        STAT_PORT_RANGE_FROM_INST_PTR(dslite_entry_ptr)
#ifndef NO_BULK_LOGGING
                        , NULL,
                        BULKSIZE_FROM_VRFMAP(dslite_entry_ptr),
                        &nfv9_log_req
#endif
                        , 0,
                        &(dslite_entry_ptr->rseed_ip)
                        );
            DSLITE_PRINTF(1,"NU:D PORT ALLOC..%x %u\n", ko.k.k.ipv4,
                             ko.k.k.port);

        } else {
            /*
             * For RTSP, two translation entries are created,
             * check if main db has space to accomodate two new entry
             */
            free_main = free_main  - 1;

            if (PREDICT_FALSE(!free_main)) {
                info->error = CNAT_MAIN_DB_LIMIT;
                nat44_dslite_common_stats[dslite_id].in2out_drops_system_limit_reached ++;
                DSLITE_DEBUG_INSIDE_ERR(CNAT_MAIN_DB_LIMIT)

                return NULL;
            } else {

                rv = cnat_dynamic_port_alloc_rtsp_bulk(pm,
                            PORT_ALLOC_DIRECTED,
                            port_pair_type,
                            ki->dk.ipv4_key.k.port,
                            &my_index,
                            &(ko.k.k.ipv4),
                            &(ko.k.k.port),
                            STAT_PORT_RANGE_FROM_INST_PTR(dslite_entry_ptr)
#ifndef NO_BULK_LOGGING
                            , NULL,
                            BULKSIZE_FROM_VRFMAP(dslite_entry_ptr),
                            &nfv9_log_req
#endif
                            , &(dslite_entry_ptr->rseed_ip)
                        );
            /* TODO: Add the port pair flag here */
            }
        }



        if (PREDICT_FALSE(rv != CNAT_SUCCESS)) {
            DSLITE_PRINTF(1,"NU:D_PORT_ALLOC port alloc error\n");
            info->error = rv;
            nat44_dslite_common_stats[dslite_id].in2out_drops_resource_depletion ++;
            DSLITE_DEBUG_INSIDE_ERR(rv) 
            log_port_alloc_error(rv, &(ki->dk.ipv4_key));
            return (NULL);
        }
        /* 
         * create entry in user db
         */
        udb = dslite_user_db_create_entry(&u_ki, my_index);
        nat44_dslite_common_stats[dslite_id].num_subscribers++;
        DSLITE_PRINTF(1,"UDB crete entry done..\n");
#ifndef NO_BULK_LOGGING
        if(PREDICT_TRUE(udb && (BULK_ALLOC_NOT_ATTEMPTED != nfv9_log_req))) {
            cnat_update_bulk_range_cache(udb, ko.k.k.port,
            BULKSIZE_FROM_VRFMAP(dslite_entry_ptr));
        }
#endif /*  #ifndef NO_BULK_LOGGING */
    }

    /*
     * step 3:
     * outside port is allocated for this src vrf/src ip addr
     * 1)create a new entry in main db
     * 2)setup cnat_out2in_hash key
     * 3)setup cnat_in2out_hash key
     */
    db = dslite_create_main_db_entry_and_hash(ki, &ko, udb);
    DSLITE_PRINTF(1,"dslite_create_main_db_entry_and_hash done..\n");
    //db->vrfmap_index = my_vrfmap - cnat_map_by_vrf;
    db->dslite_nat44_inst_id = dslite_id;
    nat44_dslite_common_stats[dslite_id].active_translations++;
    if (PREDICT_FALSE(port_type == PORT_TYPE_STATIC)) {
        nat44_dslite_common_stats[dslite_id].num_static_translations++;
    } else {
        nat44_dslite_common_stats[dslite_id].num_dynamic_translations++;
    }

    dslite_translation_create_count++;

    db->dst_ipv4 = dest_info->k.ipv4;
    db->dst_port = dest_info->k.port;
    if(PREDICT_TRUE(db->dst_ipv4 || db->dst_port)) {
        /* for static fwding, let the nsessions remain zero */
        db->nsessions++;
    }

    /*
     * don't forget logging
     * logging API is unconditional, 
     * logging configuration check is done inside the inline function
     */
    if(PREDICT_FALSE(nfv9_log_req != CACHE_ALLOC_NO_LOG_REQUIRED)) {
	if(PREDICT_FALSE( dslite_entry_ptr->nf_logging_policy == 
            SESSION_LOG_ENABLE)) {
       	    if(PREDICT_TRUE(db->dst_ipv4 || db->dst_port)) {
                cnat_nfv9_ds_lite_log_session_create(db, 
                 	dslite_entry_ptr,NULL);
            }
	} else {
        	cnat_nfv9_ds_lite_mapping_create(db,dslite_entry_ptr
#ifndef NO_BULK_LOGGING
                ,nfv9_log_req
#endif
                );
        }
        if(PREDICT_TRUE((dslite_entry_ptr->syslog_logging_policy != SESSION_LOG_ENABLE) ||
                        (db->dst_ipv4 || db->dst_port))) {
            cnat_syslog_ds_lite_mapping_create(db,dslite_entry_ptr,NULL
#ifndef NO_BULK_LOGGING
            ,nfv9_log_req
#endif
            );
        }
    }

#if 0
    if (PREDICT_FALSE(port_pair_type == PORT_PAIR)) {
       cnat_main_db_entry_t *db2 = 0;
       dslite_db_key_bucket_t new_ki = *ki;
       u64 a, b, c;

       new_ki.k.k.port += 1;
       ko.k.k.port += 1;

       CNAT_V4_GET_HASH(new_ki.k.key64, new_ki.bucket, 
                        CNAT_MAIN_HASH_MASK);

       db2 = cnat_create_main_db_entry_and_hash(&new_ki, &ko, udb);

       translation_create_count ++;
       db2->dslite_nat44_inst_id = dslite_id;
       db2->entry_expires = cnat_current_time;
       db2->flags |= CNAT_DB_FLAG_ALG_ENTRY;
       udb->ntranslations += 1;
#ifndef NO_BULK_LOGGING
       if(PREDICT_FALSE(nfv9_log_req == BULK_ALLOC_NOT_ATTEMPTED))
           cnat_nfv9_log_mapping_create(db2, my_vrfmap, nfv9_log_req);
#else 
        cnat_nfv9_log_mapping_create(db2, my_vrfmap);
#endif
    }
#endif
    return db;
}
#endif /* TOBE_PORTED */

#if 0
/* TOBE_PORTED */
uword
cnat_db_v2_node_fn (vlib_main_t * vm,
                  vlib_node_runtime_t * node,
                  vlib_frame_t * frame)
{
    return 0;
}
VLIB_REGISTER_NODE (cnat_db_v2_node) = {
    .function = cnat_db_v2_node_fn,
    .name = "vcgn-db-v2",
    .vector_size = sizeof (u32),
    .type = VLIB_NODE_TYPE_INTERNAL,
  
    .n_errors = ARRAY_LEN(cnat_db_v2_error_strings),
    .error_strings = cnat_db_v2_error_strings,
  
    .n_next_nodes = CNAT_DB_V2_DROP,
  
    /* edit / add dispositions here */
    .next_nodes = {
        [CNAT_DB_V2_DROP] = "error-drop",
    },
};
#endif
void cnat_db_v2_init (void)
{

    u32 i, n;
    cnat_timeout_db_entry_t * tdb __attribute__((unused));

    cgse_nat_db_entry_t *comb_db __attribute__((unused));
    cgse_nat_user_db_entry_t *comb_user __attribute__((unused));
    cgse_nat_session_db_entry_t *comb_session __attribute__((unused));

    n = CNAT_DB_SIZE*1.15;    /* add 15% LB margin */

    /*
     * We also make it multiple of NUM_BITS_IN_UWORD for better
     * DB scanning algorithm
     */
    if (n % NUM_BITS_IN_UWORD)
        n += (NUM_BITS_IN_UWORD - (n % NUM_BITS_IN_UWORD));

    pool_alloc(cgse_nat_db,n);
    for(i=0; i< n; i++) {
         pool_get(cgse_nat_db, comb_db);
    }

    for(i=0; i< n; i++) {
        pool_put(cgse_nat_db, cgse_nat_db + i);
    }

    cnat_main_db = &cgse_nat_db->nat44_main_db; 

    /* For Sessions */
    if(PLATFORM_DBL_SUPPORT) {
        /* create session table for NAT44 and NAT64 itself */
        printf("DBL Support exist %d\n", PLATFORM_DBL_SUPPORT);
        n = CNAT_SESSION_DB_SIZE * 1.15;    /* add 15% LB margin */
    } else {
        /* Create session table for NAT64 only */
        printf("DBL Support Not exist\n");
        n = NAT64_MAIN_DB_SIZE * 1.15;    /* add 15% LB margin */
    }

    /*
     * We also make it multiple of NUM_BITS_IN_UWORD for better
     * DB scanning algorithm
     */
    if (n % NUM_BITS_IN_UWORD)
        n += (NUM_BITS_IN_UWORD - (n % NUM_BITS_IN_UWORD));

    pool_alloc(cgse_session_db,n);
    for(i=0; i< n; i++) {
         pool_get(cgse_session_db, comb_session);
    }

    for(i=0; i< n; i++) {
        pool_put(cgse_session_db, cgse_session_db + i);
    }

    cnat_session_db = &cgse_session_db->nat44_session_db;

    vec_validate(cnat_out2in_hash, CNAT_MAIN_HASH_MASK);
    memset(cnat_out2in_hash, 0xff, CNAT_MAIN_HASH_SIZE*sizeof(index_slist_t));

    vec_validate(cnat_in2out_hash, CNAT_MAIN_HASH_MASK);
    memset(cnat_in2out_hash, 0xff, CNAT_MAIN_HASH_SIZE*sizeof(index_slist_t));

    vec_validate(cnat_session_hash, CNAT_SESSION_HASH_MASK);
    memset(cnat_session_hash, 0xff, CNAT_SESSION_HASH_SIZE*sizeof(index_slist_t));

    n = CNAT_USER_DB_SIZE * 1.15;  /* use hash size as db size for LB margin */
    if (n % NUM_BITS_IN_UWORD)
        n += (NUM_BITS_IN_UWORD - (n % NUM_BITS_IN_UWORD));

    pool_alloc(cgse_user_db,n);
    for(i=0; i< n; i++) {
        pool_get(cgse_user_db, comb_user);
    }

    for(i=0; i< n; i++) {
        pool_put(cgse_user_db, cgse_user_db + i);
    }

    cnat_user_db = &cgse_user_db->nat44_user_db;

    vec_validate(cnat_user_hash, CNAT_USER_HASH_MASK);
    memset(cnat_user_hash, 0xff, CNAT_USER_HASH_SIZE*sizeof(index_slist_t));

    n = CNAT_TIMEOUT_HASH_SIZE;  /* use hash size as db size for LB margin */
    for(i=0; i< n; i++) {
        pool_get(cnat_timeout_db, tdb);
    }

    for(i=0; i< n; i++) {
        pool_put(cnat_timeout_db, cnat_timeout_db + i);
    }

    vec_validate(cnat_timeout_hash, CNAT_TIMEOUT_HASH_MASK);
    memset(cnat_timeout_hash, 0xff, CNAT_TIMEOUT_HASH_SIZE*sizeof(index_slist_t));

#ifdef TOBE_PORTED
    for (i=0;i<CNAT_MAX_VRFMAP_ENTRIES; i++) {
        svi_params_array[i].svi_type = CGSE_SVI_TYPE_INFRA;
    }
#endif
    cnat_db_init_done = 1;
    printf("CNAT DB init is successful\n");
    return;
    //return 0;
}
