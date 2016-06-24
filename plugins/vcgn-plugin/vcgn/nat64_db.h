/*
 *------------------------------------------------------------------
 * nat64_db.h - Stateful NAT64 translation database definitions
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
#ifndef __NAT64_DB_H__
#define __NAT64_DB_H__

#include "cnat_cli.h"
#include "index_list.h"
#include "cnat_ports.h"
#include "cnat_db.h"
#include "nat64_defs.h"
#include "cnat_bulk_port_defs.h"

nat64_vrfmap_t *nat64_map_by_vrf;

#define SESSION_OPT

#define HASH_ENHANCE 4


#define NAT64_MAIN_DB_SIZE \
               (PLATFORM_NAT64_MAX_SESSIONS / PLATFORM_CNAT_INSTS)
#define NAT64_MAIN_HASH_SIZE \
         (HASH_ENHANCE * PLATFORM_CNAT_MAIN_PRELIM_HASH_SIZE) 

#define NAT64_MAIN_HASH_MASK (NAT64_MAIN_HASH_SIZE-1)


/* nb: 200000 users / 64 CNAT = 3125, 76% occupancy */
#define NAT64_USER_HASH_SIZE CNAT_USER_HASH_SIZE
#define NAT64_USER_HASH_MASK (NAT64_USER_HASH_SIZE-1)

/* Number of sessions per BIB entry/NAT64 translation
   - nsessions is u16 type. So selected 0xFFFF
   - Ideally Sessions per transltion will not reach the limit
   - Only DoS can possible. It can take care of it   */
#define NAT64_MAX_SESSIONS_PER_BIB  0xFFFF

/* No. of per ip/port config will be limited to 1000 */
/* totally 25K across all instances) */
#define NAT64_TIMEOUT_HASH_SIZE \
                       PLATFORM_NAT64_TIMEOUT_HASH_SIZE 

#define NAT64_TIMEOUT_HASH_MASK (NAT64_TIMEOUT_HASH_SIZE - 1)
#define NAT64_TIMEOUT_FULL_MASK 0xFFFFFFFFFFFFFFFF


#define FORCE_DEL 1 /* Delete static BIB entries as well */

/* default timeout values */
#define NAT64_UDP_DEFAULT          300  /* 5 min */
#define NAT64_UDP_MIN              120  /* 2 min */
#define NAT64_TCP_TRANS            240  /* 4 min */
#define NAT64_TCP_EST             7200  /* 2 hrs */
#define NAT64_TCP_V4_SYN             6  /* 6 sec */
#define NAT64_FRAG_MIN               2  /* 2 sec */
#define NAT64_ICMP_DEFAULT          60  /* 1 min */


#define NAT64_V6_GET_HASH(in_key, hash, mask) \
    a = in_key->ipv6[0] ^ in_key->ipv6[1] ^ in_key->ipv6[2] ^ in_key->ipv6[3] \
         ^ ((in_key->port << 16) | in_key->vrf); \
    b = c = 0x9e3779b9;\
    /* Jenkins hash, arbitrarily use c as the "answer" */ \
    hash_mix32(a, b, c); \
    hash = c & mask; \


#define NAT64_V4_GET_HASH(in_key, hash, mask) \
    a = in_key.ipv4 ^ ((in_key.port << 16) | in_key.vrf); \
    b = c = 0x9e3779b9; \
    /* Jenkins hash, arbitrarily use c as the "answer" */ \
    hash_mix32(a, b, c); \
    hash = c & mask;



#define NAT64_V6_GET_SESSION_HASH(bib_index, in_addr, port, vrf, hash, mask) \
    a = bib_index ^ in_addr[0] ^ in_addr[1] ^ in_addr[2] ^ in_addr[3] \
            ^ port ^ vrf; \
    b = c = 0x9e3779b9; \
    /* Jenkins hash, arbitrarily use c as the "answer" */ \
    hash_mix32(a, b, c); \
    hash = c & mask;

#define NAT64_V4_GET_SESSION_HASH(bib_index, in_addr, port, vrf, hash, mask) \
    a = bib_index ^ in_addr ^ port ^ vrf; \
    b = c = 0x9e3779b9; \
    /* Jenkins hash, arbitrarily use c as the "answer" */ \
    hash_mix32(a, b, c); \
    hash = c & mask;


extern index_slist_t        *nat64_bib_out2in_hash;
extern index_slist_t        *nat64_bib_in2out_hash;
extern index_slist_t        *nat64_bib_user_hash;
extern index_slist_t        *nat64_session_out2in_hash;
#ifndef SESSION_OPT
extern index_slist_t        *nat64_session_in2out_hash;
#endif
extern index_slist_t        *nat64_frag_out2in_hash;
extern index_slist_t        *nat64_frag_in2out_hash;
extern index_slist_t        *nat64_timeout_hash;


/*
 * nat64_ bib_entry_t
 * This structure depicts Binding Information Base of NAT64 sessions. 
 * It stores information about the inside v6 source transport address and 
 * corresponding outside v4 source transport address for each protocol.
 */

typedef struct {

    index_slist_t     nat64_bib_out2in_hash;
    index_slist_t     nat64_bib_in2out_hash;

    /* 0x08 */
    u16               flags; /* flags in cnat_db.h (cnat_main_db_entry_t) */
#define NAT64_DB_FLAG_STATIC_PORT CNAT_DB_FLAG_STATIC_PORT
#define NAT64_DB_NAT64_FLAG       CNAT_DB_NAT64_FLAG
#define NAT64_DB_FLAG_ALG_ENTRY   CNAT_DB_FLAG_ALG_ENTRY
#define NAT64_DB_FLAG_PCPI        CNAT_DB_FLAG_PCPI 
#define NAT64_DB_FLAG_PCPE        CNAT_DB_FLAG_PCPE

    /* 0x0A */
    u16              nat64_inst_id;
    /* 0x0C */
    u32              user_index;

    /* 0x10 */
    nat64_v4_key_t     v4_out_key;

    /* 0x18 */
    nat64_v6_key_t     v6_in_key;      

    /* 0x2C */
    index_dlist_t    user_ports;   
    /* 0x34 */
    u32              session_head_index;
     /* 0x38 - 56B*/
    u16              nsessions;
    u16              pad2;

    /* 0x3C - 60B */
    u32              in2outpkts;
    u32              out2inpkts;
    /* 0x44 - 68B */

    /* 0x42 - 70B */
    union {                     /* used by FTP ALG, pkt len delta due to FTP PORT cmd */
    u16 delta;
    i8  alg_dlt[2];             /* two delta values, 0 for previous, 1 for current */
    u16 il;                     /* Used to indicate if interleaved mode is used
                                   in case of RTSP ALG */
    } alg;

    u16 temp1;

    u32 entry_expires;

    u32 temp3;
    /* unused, temp1 ,temp2 and temp3 put to make it in sync with nat44 main db entry size */
    /* size of = 0x54 = 84 B */
    u32 unused;

} nat64_bib_entry_t ;

/* 
 * nat64_bib_user_entry_t
 * This structure stores information about translations of a particular user 
 * (User here refers to a same inside source address)
 */
typedef struct {
    /* 0x00 */
    index_slist_t user_hash;    
     /* 0x04 */
    u16 ntranslations;          
    /* 0x06 */
    u8 icmp_msg_count;
    /* 0x07 */
    u8 flags;                
#define NAT64_USER_DB_NAT64_FLAG CNAT_USER_DB_NAT64_FLAG

    /* 0x08 */ 
    u32 translation_list_head_index;
    /* 0x0C */
    u32 portmap_index;          
    /* 0x10 */
    nat64_v6_key_t     v6_in_key;      
    /* 0x24 = 36 B */

    u32 align1; /* Make it 8B boundary  and in sync with nat44 user db entry size */
#ifndef NO_BULK_LOGGING
    /* size of = 0x28 = 40 B */
    /* Now adding 8 more bytes for bulk allocation.. This makes it
     * 0x30 (48).  For nat64 stful, we may support bulk allocation
     * later */
    /* Indicates the currently used bulk port range */
    i16 bulk_port_range_cache[BULK_RANGE_CACHE_SIZE];
#endif /*  NO_BULK_LOGGING */
} nat64_bib_user_entry_t;

/*
 * nat64_session_entry_t
 * This structure represents the session table. It maintains the information 
 * about the flow of the packets. It would consist of source and destination 
 * (inside and outside) ipv4 and ipv4 transport addresses. 
 */
typedef struct {

    /* 0x00 */
    index_slist_t   nat64_session_out2in_hash;

    /* 0x04 */ 
    u32 bib_index; /* would point to v4/v6 src transport address */

    /* 0x08 */
    nat64_v4_key_t     v4_dest_key;

#ifndef SESSION_OPT
   index_slist_t   nat64_session_in2out_hash;
   nat64_v6_key_t     v6_dest_key;
#endif

    /* 0x10 */
    u16  flags;/* Will be used for flags same as nat44 session */ 

    /* 0x12 */
    u16 timeout; 

    /* 0x14 */
    u32 entry_expires;
    /* 0x18 */
    index_dlist_t    bib_list;
    /* 0x20 = 32 B */

    union {                     /* alg same as cnat_main_db_t */
    u16 delta;
    i8  alg_dlt[2];
    u16 il;
    } alg;

    /* 0x22 */
    u16  tcp_flags; /* Mainly TCP events - check nat64_tcp_sm.h */

    /* 0x24  */
    u32 tcp_seq_num;

    /* 0x28 */      /* unused1, unused2 and unused3 are put to make it in sync with 
                     * cnat_session_db */
    u32 unused1;

    /* 0x2C */
    u32 unused2;

    /* 0x30 */
    u16 unused3;

    /* 0x32 - 50B */

} nat64_session_entry_t;

/*
 * nat64_session_tcp_init_entry_t 
 * This structure will be used to store information about v4 initiation 
 * tcp entries.
 */
typedef struct {
    nat64_v6_key_t     v6_in_key;      
    nat64_v4_key_t     v4_out_key;
} nat64_session_tcp_init_entry_t;

/* 
 * nat64_in_v6_frag_entry_t 
 * This structure will be used to store information about fragment flows 
 * that are coming from inside v6 hosts.
 */
typedef struct {
     index_slist_t  nat64_frag_in2out_hash;

     u32 v6_src_addr[4];
     u32 v6_destn_addr[4];
     u32 frag_iden;
     u16  vrf;
     u16  pad1;
} nat64_in_v6_frag_entry_t ;

/*
 * nat64_out_v4_frag_entry_t 
 * This structure will be used to store information about fragment flows 
 * that are coming from outside v4 machines.
 */
typedef struct {
     index_slist_t  nat64_frag_out2in_hash;

     u32 v4_src_addr;
     u32 v4_destn_addr;
     u16 frag_iden;
     u16  vrf;
} nat64_out_v4_frag_entry_t ;

/*
 * nat64_timeout _t 
 * These following structures will be used to store information destination 
 * timeouts configured.
 */
typedef struct {
    nat64_v4_key_t timeout_key;
    u16        timeout_value;
} nat64_timeout_t;

/*
 * nat64_timeout_db_entry_t 
 */
typedef struct {
    nat64_timeout_t  t_key;
    index_slist_t  t_hash;
} nat64_timeout_db_entry_t;


typedef union {
    cnat_main_db_entry_t nat44_main_db;
    nat64_bib_entry_t nat64_bib_db; 
} cgse_nat_db_entry_t;

typedef union {
    cnat_session_entry_t   nat44_session_db;
    nat64_session_entry_t     nat64_session_db;
} cgse_nat_session_db_entry_t;

typedef union {
    cnat_user_db_entry_t   nat44_user_db;
    nat64_bib_user_entry_t nat64_user_db;
} cgse_nat_user_db_entry_t;

extern index_slist_t        *nat64_bib_out2in_hash;
extern index_slist_t        *nat64_bib_in2out_hash;
extern index_slist_t        *nat64_bib_user_hash;
extern index_slist_t        *nat64_session_out2in_hash;
extern index_slist_t        *nat64_session_in2out_hash;
extern index_slist_t        *nat64_frag_out2in_hash;
extern index_slist_t        *nat64_frag_in2out_hash;
extern index_slist_t        *nat64_timeout_hash;

extern nat64_bib_entry_t               *nat64_bib_db;
extern nat64_bib_user_entry_t          *nat64_bib_user_db;
extern nat64_session_entry_t           *nat64_session_db;
extern nat64_in_v6_frag_entry_t        *nat64_in_frag_db;
extern nat64_out_v4_frag_entry_t       *nat64_out_frag_db;
extern nat64_session_tcp_init_entry_t  *nat64_tcp_init_db ;
extern nat64_timeout_db_entry_t        *nat64_timeout_db;

extern nat64_table_entry_t         nat64_table_array[NAT64_MAX_NAT64_ENTRIES];
extern nat64_table_entry_t         *nat64_table_ptr;

extern cgse_nat_db_entry_t         *cgse_nat_db;
extern cgse_nat_user_db_entry_t    *cgse_user_db;
extern cgse_nat_session_db_entry_t *cgse_session_db;

void nat64_bib_user_db_delete (nat64_bib_user_entry_t *up);

nat64_bib_user_entry_t*
nat64_bib_user_db_create_entry(nat64_v6_key_t *uki, u32 bucket,
                          u32 portmap_index);

nat64_bib_user_entry_t*
nat64_bib_user_db_lookup_entry(nat64_v6_key_t *uki, u32 *bucket);


nat64_bib_entry_t*
nat64_bib_db_lookup_entry(nat64_v6_key_t *ki);

void nat64_bib_db_in2out_hash_delete (nat64_bib_entry_t *ep);

void nat64_bib_db_out2in_hash_delete (nat64_bib_entry_t *ep);

nat64_bib_entry_t *
nat64_create_bib_db_entry_and_hash(nat64_v6_key_t *ki,
                                   nat64_v4_key_t *ko,
                                   nat64_bib_user_entry_t *udb);


void nat64_delete_bib_db_entry (nat64_bib_entry_t *ep, u8 force);

nat64_bib_entry_t *
nat64_bib_db_lookup_entry_out2in (nat64_v4_key_t *ko);

nat64_bib_entry_t *
nat64_get_bib_db_entry (nat64_v6_key_t *ki,
                        port_pair_t port_pair_type,
                        port_type_t port_type,
                        cnat_gen_icmp_info *info);


nat64_bib_entry_t*
nat64_create_static_bib_db_entry (nat64_v6_key_t *ki,
                                  nat64_v4_key_t *ko,
                                  nat64_table_entry_t *my_table,
                                  cnat_gen_icmp_info   *info);



//void nat64_session_db_in2out_hash_delete (nat64_session_entry_t *ep);
void nat64_session_db_out2in_hash_delete (nat64_session_entry_t *ep);

/*nat64_session_entry_t *
nat64_session_db_lookup_entry(nat64_v6_key_t *ki, u32 bib_index); */


nat64_session_entry_t *
nat64_session_db_lookup_entry_out2in (nat64_v4_key_t *ko,u32 bib_index);

/*
nat64_session_entry_t *
nat64_create_session_db_entry(nat64_v6_key_t *ki,
                              nat64_v4_key_t *ko,
                              nat64_bib_entry_t *bdb);
*/
nat64_session_entry_t *
nat64_create_session_db_entry_v2( nat64_v4_key_t *ko,
                              nat64_bib_entry_t *bdb);


//void nat64_delete_session_db_entry (nat64_session_entry_t *ep);
void nat64_delete_session_db_entry_v2 (nat64_session_entry_t *ep, u8 force);

u32 nat64_timeout_db_hash_lookup (nat64_v4_key_t t_key);

u16 query_and_update_db_timeout_nat64(nat64_session_entry_t *db);

void nat64_timeout_db_hash_add (nat64_timeout_db_entry_t *t_entry);

u16 nat64_timeout_db_create (nat64_timeout_t t_entry);

void nat64_timeout_db_delete(nat64_v4_key_t t_key);

#define NAT64_CMP_V6_KEY(key1, key2) \
       memcmp(key1, key2, sizeof(nat64_v6_key_t))

#define NAT64_CMP_V4_KEY(key1, key2) \
       memcmp(key1, key2, sizeof(nat64_v4_key_t))


#define NAT64_CMP_V6_IP(ip1, ip2) \
       memcmp(ip1, ip2, (sizeof(u32) * 4))


#define NAT64_CMP_V6_KEY1(key1, key2) \
    (key1.ipv6[0] == key2.ipv6[0]) && (key1.ipv6[1] == key2.ipv6[1]) && \
    (key1.ipv6[2] == key2.ipv6[2]) &&  (key1.ipv6[3] == key2.ipv6[3]) && \
    (key1.port == key2.port) && (key1.vrf == key2.vrf) 


#define NAT64_CMP_V6_IP1(ip1, ip2) \
    ((ip1[0] == ip2[0]) && (ip1[1] == ip2[1]) && \
    (ip1[2] == ip2[2]) && (ip1[3] == ip2[3]))

#define NAT64_CMP_V4_KEY1(key1, key2) \
       (key1.key64 == key2.key64)


extern u8  nat64_timeout_dirty_flag[NAT64_MAX_NAT64_ENTRIES];

#endif
