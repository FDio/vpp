/*
 *------------------------------------------------------------------
 * dslite_db.h - Stateful DSLITE translation database definitions
 *
 * Copyright (c) 2010-2013 Cisco and/or its affiliates.
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
#ifndef __DSLITE_DB_H__
#define __DSLITE_DB_H__

#include "cnat_cli.h"
#include "index_list.h"
#include "cnat_ports.h"
#include "cnat_db.h"
#include "dslite_defs.h"

#define DSLITE_PRINTF(level, ...)  \
    if (dslite_debug_level > level) PLATFORM_DEBUG_PRINT(__VA_ARGS__);
/*
#define DSLITE_PRINTF(lvl, ...)                 \
{                                                     \
        avsm_dispatlib_debug (__VA_ARGS__);           \
}
*/

#define HASH_ENHANCE 4
//#define DSLITE_DEF
#define DSLITE_MAIN_DB_SIZE (20000000 / PLATFORM_CNAT_INSTS)
#define DSLITE_MAIN_HASH_SIZE \
         (HASH_ENHANCE * PLATFORM_CNAT_MAIN_PRELIM_HASH_SIZE) 

#define DSLITE_MAIN_HASH_MASK (DSLITE_MAIN_HASH_SIZE-1)


/* nb: 200000 users / 64 CNAT = 3125, 76% occupancy */
#define DSLITE_USER_HASH_SIZE CNAT_USER_HASH_SIZE
#define DSLITE_USER_HASH_MASK (DSLITE_USER_HASH_SIZE-1)

/* No. of per ip/port config will be limited to 1000 */
#define DSLITE_TIMEOUT_HASH_SIZE 1000
#define DSLITE_TIMEOUT_HASH_MASK (DSLITE_TIMEOUT_HASH_SIZE - 1)
#define DSLITE_TIMEOUT_FULL_MASK 0xFFFFFFFFFFFFFFFF

#define CNAT_MAX_SESSIONS_PER_BIB  0xFFFF

#define FORCE_DEL 1 /* Delete static BIB entries as well */

/* default timeout values */
#define DSLITE_UDP_DEFAULT          300  /* 5 min */
#define DSLITE_UDP_MIN              120  /* 2 min */
#define DSLITE_TCP_TRANS            240  /* 4 min */
#define DSLITE_TCP_EST             7200  /* 2 hrs */
#define DSLITE_TCP_V4_SYN             6  /* 6 sec */
#define DSLITE_FRAG_MIN               2  /* 2 sec */
#define DSLITE_ICMP_DEFAULT          60  /* 1 min */

extern u32 dslite_translation_create_count;
extern u32 dslite_translation_delete_count;
extern u32 dslite_translation_create_rate;
extern u32 dslite_translation_delete_rate;
extern u32 dslite_in2out_forwarding_count;
extern u32 dslite_in2out_forwarding_rate;
extern u32 dslite_out2in_forwarding_count;
extern u32 dslite_out2in_forwarding_rate;

#define DSLITE_V6_GET_HASH(in_key, hash, mask) \
    a = in_key->ipv6[0] ^ in_key->ipv6[1] ^ in_key->ipv6[2] ^ in_key->ipv6[3] \
         ^ in_key->ipv4_key.k.ipv4 ^ ((in_key->ipv4_key.k.port << 16) | in_key->ipv4_key.k.vrf); \
    DSLITE_PRINTF(1, "%x:%x:%x:%x:%x:%x:%x\n", in_key->ipv6[0], in_key->ipv6[1], in_key->ipv6[2], in_key->ipv6[3], \
                  in_key->ipv4_key.k.ipv4, in_key->ipv4_key.k.port, in_key->ipv4_key.k.vrf);  \
    b = c = 0x9e3779b9;\
    /* Jenkins hash, arbitrarily use c as the "answer" */ \
    hash_mix32(a, b, c); \
    hash = c & mask; \


#define DSLITE_V6_GET_USER_HASH(ipv6, hash, mask) \
    a = ipv6[0] ^ ipv6[1] ^ ipv6[2] ^ ipv6[3]; \
    b = c = 0x9e3779b9;\
    /* Jenkins hash, arbitrarily use c as the "answer" */ \
    hash_mix32(a, b, c); \
    hash = c & mask; \

#define DSLITE_V4_GET_HASH(in_key, hash, mask) \
    a = in_key.ipv4 ^ ((in_key.port << 16) | in_key.vrf); \
    b = c = 0x9e3779b9; \
    /* Jenkins hash, arbitrarily use c as the "answer" */ \
    hash_mix32(a, b, c); \
    hash = c & mask;

#define PRIVATE_V4_ADDR_CHECK(addr, invalid) \
    invalid = 0; \
    int range1 = ((addr & 0xFF000000) >> 24); \
    int range2 = ((addr & 0xFFF00000) >> 20); \
    int range3 = ((addr & 0xFFFF0000) >> 16); \
    int range4 = ((addr & 0xFFFFFFF8) >> 3);  \
    if(range1 != 0xa && range2 != 0xac1 && range3 != 0xc0a8  && range4 != 0x18000000) \
        invalid = 1;

#define V4_MAPPED_V6_CHECK(v6_addr, invalid) \
    invalid = 0; \
    int word1 = v6_addr[0]; \
    int word2 = v6_addr[1]; \
    int word3 = v6_addr[2]; \
    if(!((word1 == 0) && (word2 == 0) && (word3 == 0x0000FFFF))) \
        invalid = 1;


extern dslite_table_entry_t         dslite_table_array[DSLITE_MAX_DSLITE_ENTRIES];
extern dslite_table_entry_t         *dslite_table_ptr;

#define DSLITE_CMP_V6_KEY(key1, key2) \
       memcmp(key1, key2, sizeof(dslite_v6_key_t))

#define DSLITE_CMP_V4_KEY(key1, key2) \
       memcmp(key1, key2, sizeof(dslite_v4_key_t))


#define DSLITE_CMP_V6_IP(ip1, ip2) \
       memcmp(ip1, ip2, (sizeof(u32) * 4))


#define DSLITE_CMP_V6_KEY1(key1, key2) \
    (key1.ipv6[0] == key2.ipv6[0]) && (key1.ipv6[1] == key2.ipv6[1]) && \
    (key1.ipv6[2] == key2.ipv6[2]) &&  (key1.ipv6[3] == key2.ipv6[3]) && \
    (key1.port == key2.port) && (key1.vrf == key2.vrf) 


#define DSLITE_CMP_V6_IP1(ip1, ip2) \
    ((ip1[0] == ip2[0]) && (ip1[1] == ip2[1]) && \
    (ip1[2] == ip2[2]) && (ip1[3] == ip2[3]))

#define DSLITE_CMP_V4_KEY1(key1, key2) \
       (key1.key64 == key2.key64)

cnat_main_db_entry_t*
dslite_get_main_db_entry_v2(dslite_db_key_bucket_t *ki,
                       port_pair_t port_pair_type,
                       port_type_t port_type,
                       cnat_gen_icmp_info *info,
                       dslite_table_entry_t *dslite_entry_ptr,
                       cnat_key_t *dest_info);

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

#endif
