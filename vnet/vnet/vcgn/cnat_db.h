/* 
 *------------------------------------------------------------------
 * cnat_db.h - translation database definitions
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

#ifndef __CNAT_DB_H__
#define __CNAT_DB_H__

#include "cnat_cli.h"
#include "cnat_ports.h"
#include "index_list.h"

#define VRF_NAME_LEN_STORED     12
#define MAX_VRFID               400
typedef struct _cnat_svi_params_entry {
    u16 svi_type;
    u16 pad;

    u32 vrf_id;
    u16 if_num;

    u32 ipv6_addr[4];
    u32 ipv4_addr;
    
    u8  direction;
    u32 tbl_id; /* vrf */
    u32 vrf_override_id; /* tbl_id for override vrf */
    u8  vrf_override_flag;
    u8  partition_id;
} cnat_svi_params_entry;

typedef struct _cnat_ingress_vrfid_name_entry {
    u32 vrf_id;
    u16 ref_count;  /*no# of serviceApps under a single vrf*/
    u8  vrf_name[VRF_NAME_LEN_STORED];
    u16 pad1;
} cnat_ingress_vrfid_name_entry;
#define HASH_ENHANCE 4

#define CNAT_DB_SIZE	(PLATFORM_MAX_NAT_ENTRIES / PLATFORM_CNAT_INSTS)
#define CNAT_MAIN_HASH_SIZE (HASH_ENHANCE * PLATFORM_CNAT_MAIN_PRELIM_HASH_SIZE)
#define CNAT_MAIN_HASH_MASK (CNAT_MAIN_HASH_SIZE-1)

#define CNAT_USER_DB_SIZE (PLATFORM_MAX_USER_ENTRIES / PLATFORM_CNAT_INSTS)
#define CNAT_USER_HASH_SIZE (HASH_ENHANCE * PLATFORM_CNAT_USER_PRELIM_HASH_SIZE)
#define CNAT_USER_HASH_MASK (CNAT_USER_HASH_SIZE-1)

#define CNAT_SESSION_DB_SIZE  (PLATFORM_MAX_NAT_ENTRIES / PLATFORM_CNAT_INSTS)
#define CNAT_SESSION_HASH_SIZE (HASH_ENHANCE * PLATFORM_CNAT_MAIN_PRELIM_HASH_SIZE)
#define CNAT_SESSION_HASH_MASK (CNAT_SESSION_HASH_SIZE-1)


#define CNAT_MAX_SESSIONS_PER_BIB  0xFFFF

#define NUM_BITS_IN_UWORD   (8*sizeof(uword))

/* No. of per ip/port config will be limited to 1024 */
#define CNAT_TIMEOUT_HASH_SIZE 1024
#define CNAT_TIMEOUT_HASH_MASK (CNAT_TIMEOUT_HASH_SIZE - 1)
#define CNAT_TIMEOUT_FULL_MASK 0xFFFFFFFFFFFFFFFF
#define CNAT_TIMEOUT_IPPROT_MASK PLATFORM_CNAT_TIMEOUT_IPPROT_MASK
#define CNAT_TIMEOUT_PORTPROT_MASK PLATFORM_CNAT_TIMEOUT_PORTPROT_MASK

#define TRUE    1
#define FALSE   0

/*
 * The key structure. All fields are in NETWORK byte order! 
 */
typedef struct {
    u32 ipv4;
    u16 port;
    u16 vrf;  //bit0-12:vrf, bit13:unused, bit14-15:protocol
} cnat_db_key_t;

/* bit14-15:protocol in cnat_db_key_t */
#define CNAT_INVALID_PROTO     0x0000
#define CNAT_PPTP     0x0000 
#define CNAT_UDP      0x4000
#define CNAT_TCP      0x8000
#define CNAT_ICMP     0xc000
#define CNAT_VRF_MASK 0x3fff
#define CNAT_PRO_MASK 0xc000
#define CNAT_PRO_SHIFT 14

/*
 * Maximum number of VRF entries supported
 */
#define CNAT_MAX_VRFMAP_ENTRIES  (CNAT_VRF_MASK + 1)
/*
 * for hashing purposes, fetch the key in one instr.
 */
typedef union {
    cnat_db_key_t k;
    u64 key64;
} cnat_key_t;

typedef struct {
    cnat_key_t k; 
    u32 bucket; 
} cnat_db_key_bucket_t;

typedef struct {
    u32 ipv6[4];
    cnat_key_t ipv4_key;
} dslite_key_t;

typedef struct {
/*
    cnat_db_key_bucket_t ck;
    u32 ipv6[4];
*/
    dslite_key_t dk;
    u32 bucket;
} dslite_db_key_bucket_t;


/* Per port/ip timeout related strucutres */
extern index_slist_t *cnat_timeout_hash;

typedef struct {
    cnat_key_t timeout_key;
    u16        timeout_value;
} cnat_timeout_t;

typedef struct {
    cnat_timeout_t t_key; 
    index_slist_t t_hash;
} cnat_timeout_db_entry_t;

extern cnat_timeout_db_entry_t *cnat_timeout_db;

/*
 * Main translation database entries. Currently 0x5A = 90 bytes in length.
 * Given 20,000,000 entries, it saves nearly 1gb of SDRAM to pack the entries
 * and pay the extra prefetch. So, that's what we do.
 */

typedef struct {
    /* 0x00 */
    index_slist_t out2in_hash;  /* hash-and-chain, x2 */
    index_slist_t in2out_hash; 

    /* 0x08 */
    u16 flags;                  /* Always need flags... */
#define CNAT_DB_FLAG_PORT_PAIR              (1<<0)
#define CNAT_DB_FLAG_TCP_ACTIVE             (1<<1)
#define CNAT_DB_FLAG_ENTRY_FREE             (1<<2)
#define CNAT_DB_FLAG_UDP_ACTIVE             (1<<3)
#define CNAT_DB_FLAG_STATIC_PORT            (1<<4)
/* This alg entry is set for FTP data connection */
#define CNAT_DB_FLAG_ALG_ENTRY              (1<<5)

/* Will be set for TCP connection with destination port - 1723
 * note - here CNAT_DB_FLAG_TCP_ACTIVE is also set */
#define CNAT_DB_FLAG_PPTP_TUNNEL_INIT       (1<<6)
#define CNAT_DB_FLAG_PPTP_TUNNEL_ACTIVE     (1<<7)

/* for PPTP GRE  packtes */
#define CNAT_DB_FLAG_PPTP_GRE_ENTRY         (1<<8)

/* for PCP support */
#define CNAT_DB_FLAG_PCPI                   (1<<9)
#define CNAT_DB_FLAG_PCPE                   (1<<10)
#define CNAT_PCP_FLAG  (CNAT_DB_FLAG_PCPI | CNAT_DB_FLAG_PCPE)

#define CNAT_TAC_SEQ_MISMATCH               (1<<11)
/* This alg entry is set for ftp control connection */
#define CNAT_DB_FLAG_ALG_CTRL_FLOW          (1<<12)

/* This is for marking the state where connection is closing */
#define CNAT_DB_FLAG_TCP_CLOSING            (1<<13)

#define CNAT_DB_DSLITE_FLAG                 (1<<14)
#define CNAT_DB_NAT64_FLAG                  (1<<15)

    /* 0x0A */
    u16 vrfmap_index;           /* index of vrfmap */

    /* 0x0C */
    u32 user_index;             /* index of user that owns this entry */

    /* 0x10 */
    cnat_key_t out2in_key;      /* network-to-user, outside-to-inside key */

    /* 0x18 */
    cnat_key_t in2out_key;      /* user-to-network, inside-to-outside key */

    /* 0x20 */
    index_dlist_t user_ports;   /* per-user translation list */

    /* 0x28 */
    u32 out2in_pkts;            /* pkt counters */

    /* 0x2C */
    u32 in2out_pkts;

    /* 0x30 */
    u32 entry_expires;     /* timestamp used to expire translations */
   
    /* 0x34 */
    union {                     /* used by FTP ALG, pkt len delta due to FTP PORT cmd */
    u16 delta;             
    i8  alg_dlt[2];             /* two delta values, 0 for previous, 1 for current */
    u16 il;                     /* Used to indicate if interleaved mode is used
                                   in case of RTSP ALG */
    } alg;

    /* 0x36 */
    u16 timeout;

    /* 0x38 */
    union {
      struct seq_pcp_t { 
        u32 tcp_seq_num;            /* last tcp (FTP) seq # that has pkt len change due to PORT */
        u32 pcp_lifetime;     /* peer and map life time value sent in reply*/
      } seq_pcp; 

      /* This is for TCP seq check */
      struct tcp_seq_chk_t {
	 u32 seq_no;
	 u32 ack_no;
      } tcp_seq_chk;	 

     /* used for pptp alg entries
         1. only tunnel     : prev and next = 0xFFFFFFFF
         2. first gre entry : prev = tunnel db, next = next gre db 
         3. last gre entry  : prev = previous gre/tunnel db, next= 0xFFFFFFFF;  

         *while adding gre entry- updated at the begining of head
         *while deleting gre entry -  hash look up will be done and prev and next are adjusted
         * while deleting need not traverse throufgh the list, as done in index_dlist_remelem
  
      */
      index_dlist_t pptp_list; 

    } proto_data; 

    /* 0x40 */ 
    u32 dst_ipv4;               /* pointer to ipv4 dst list, used in evil mode */

    /* 0x44 */
    u16 dst_port;

    /* 0x46  */
    u16 dslite_nat44_inst_id;

    /* 0x48  */
    u32 session_head_index;

    /* 0x4C */
    u16 nsessions;

    /* 0x4E */
    u8 unused;

    /* 0x4F */
    u8 scale;

    /* 0x50 */
    u32 diff_window;

    /* Sizeof cnat_main_db_entry_t = 0x54  */
} cnat_main_db_entry_t;

/* Caution ...
 * 1. The size of this structure should be same as that of 
 * nat64_bib_user_entry_t 
 * 2. Do not alter the position of first four fields
 */
typedef struct {
    /* 0x00 */
    index_slist_t user_hash;    /* hash 'n chain bucket chain */

    /* 0x04 */
    u16 ntranslations;          /* translations hold by this user */

    /* 0x06 */
    u8 icmp_msg_count;          /* use to rate limit imcp send to this user */
 
    /* 0x07 */
    u8 flags;                  /* To identfiy whether it is NAT64 or NAT44 etc */
#define CNAT_USER_DB_NAT44_FLAG 0
#define CNAT_USER_DB_NAT64_FLAG 1
#define CNAT_USER_DB_DSLITE_FLAG 2
#define CNAT_USER_DB_PORT_LIMIT_EXCEEDED  0X80

    /* 0x08 */
    u32 translation_list_head_index;

    /* 0x0C */
    u32 portmap_index;          /* index of bound port-map */

    /* 0x10 */
    cnat_key_t key; /* For dslite this should store IPv6 address */
    u32 ipv6[4]; // B4 ipv6 address
    /* 0x18 */
#if 0
    u32 temp1; 
    u32 temp2; 
    u32 temp3; 
#endif 
    /* 0x28 same as nat64_user_db */
#ifndef NO_BULK_LOGGING
    /* Now adding 8 more bytes for bulk allocation.. This makes it
     * 0x30 (48). Added the same to nat64_bib_user_entry_t make the
     * the sizes equal. For nat64 stful, we may support bulk allocation
     * later.
     */
     /* Indicates the currently used bulk port range */
    i16 bulk_port_range_cache[BULK_RANGE_CACHE_SIZE];
#endif /* #ifndef NO_BULK_LOGGING */
} cnat_user_db_entry_t;

/*
 * cnat_session_entry_t
 * This structure represents the cnat session table. It maintains the
 * information about the destination of a given translation (main db)
 * There would be entry here only if packets are send to more than 1 destn
 * from the same source.
 */
typedef struct {

    /* 0x00 */
    index_slist_t   cnat_session_hash;

    /* 0x04 */
    u32 main_db_index; /* would point to v4 src transport address */

    /* 0x08 */
    cnat_key_t     v4_dest_key;

    /* 0x10 */
    u16  flags;  /* Same as cnat_main_db_t */

    /* 0x12 */
    u16 timeout;

    /* 0x14 */
    u32 entry_expires;
    /* 0x18 */
    index_dlist_t    main_list;
    /* 0x20 = 32 B */

    union {                     /* alg same as cnat_main_db_t */
    u16 delta;
    i8  alg_dlt[2];
    u16 il;
    } alg;

    /* 0x22 */
    u16  tcp_flags;

    /* 0x24  */
    u32 tcp_seq_num;

    /* 0x28  */
    u32 ack_no;

    /* 0x2C  */
    u32 window;

    /* 0x30  */
    u8  scale;

    /* 0x31 */
    u8 pad;

    /* 0x32 */
} cnat_session_entry_t;



/* 
 * out2in and in2out hash bucket arrays are simply arrays of index_slist_t's
 */

typedef enum {
    CNAT_DB_CREATE_DEFAULT=0,   /* honor cnat_main_db_max_ports_per_user */
    CNAT_DB_CREATE_OVERRIDE,    /* just do it. */
} cnat_db_create_policy_t;

typedef struct {
    cnat_key_t in2out_key;
    cnat_key_t out2in_key;
    u32 dst_ipv4;           /* evil for mode only */
    u16 cnat_instance;
    cnat_portmap_t *portmap;
    u16 *portmap_inuse;
    cnat_main_db_entry_t *db;
    cnat_db_create_policy_t policy;
    port_pair_t pair_of_ports;
} cnat_db_create_args_t;

extern cnat_main_db_entry_t *cnat_main_db;
extern cnat_user_db_entry_t *cnat_user_db;
extern cnat_session_entry_t *cnat_session_db;

#define S_WAO    0
#define S_WA     1 /* waiting for address pool */
#define S_WO     2 /* waiting for outside vrf  */
#define S_RUN    3 /* got everything */
#define S_DEL    4 /* just delete */

#define INVALID_UIDX 0xffff /*invalid svi app uidb index */
#define INVALID_VRFID 0xffffffff /*invalid vrf id */

typedef struct {
    u16 status;
    u16 tcp_mss;   //tcp max segment size for this inside vrf */
    u32 delete_time;
    u16 i_vrf; //inside SVI uidx
    u16 o_vrf; //outside SVI uidx
    u32 i_vrf_id;  //inside vrf id
    u32 o_vrf_id;  //outside vrf id
    cnat_portmap_v2_t *portmap_list;
    u32 nfv9_logging_index;
    u32 syslog_logging_index;
    u16 ip_n_to_1;
#ifndef NO_BULK_LOGGING
    bulk_alloc_size_t bulk_size;
#endif /*  #ifndef NO_BULK_LOGGING */
    u32 pcp_server_addr;
    u32 pcp_server_port;

    u8  nf_logging_policy;
    u8  syslog_logging_policy;
    u8  frag_tout;
    u32 rseed_ip;
    u16 port_limit;
    u8  tcp_seq_check_enable;
    u8  pad;
    u32 tcp_seq_user_window;
    u8  filter_policy;
    u8  ignore_port;
} cnat_vrfmap_t;

/*
 * When creating cnat_vrfmap entry, ensure that any already
 * configured logging info is taken into account
 */
#define CNAT_SET_VRFMAP_NFV9_LOGGING_INDEX(logging_index, i_vrf) \
do { \
    cnat_nfv9_logging_info_t *my_nfv9_logging_info = 0; \
    pool_foreach (my_nfv9_logging_info, cnat_nfv9_logging_info, ({ \
        if (my_nfv9_logging_info->i_vrf == i_vrf) { \
	    logging_index = my_nfv9_logging_info - cnat_nfv9_logging_info; \
	    break; \
        } \
    })); \
while (0)


typedef struct {
    /*
     * spp_ctx_alloc() call failed
     */
    u64 nfv9_logging_context_creation_fail_count;
    
    /*
     * Cannot send the existing logging pkt, so cannot create
     * any additional packets for logging purposes
     */
    u64 nfv9_logging_context_creation_deferred_count;

    /*
     * Cannot send the existing logging pkt due to cnat_rewrite_output
     * superframe being full.
     */
    u64 nfv9_downstream_constipation_count;

    /*
     * buffer for spp_ctx_alloc() call failed
     */
    u64 nfv9_logging_context_buffer_allocation_fail_count;

} cnat_global_counters_t;


extern cnat_global_counters_t cnat_global_counters;

extern u16 *cnat_portmap_indices_by_vrf;
extern cnat_vrfmap_t *cnat_portmap_by_vrf;
extern cnat_portmap_t **cnat_portmaps;
extern u16 **cnat_portmaps_inuse;

extern cnat_vrfmap_t *cnat_map_by_vrf;

/*
 * Special define to indicate that the VRF map index entry is empty
 */
#define VRF_MAP_ENTRY_EMPTY 0xffff
extern u16 vrf_map_array[CNAT_MAX_VRFMAP_ENTRIES];

extern cnat_svi_params_entry svi_params_array[CNAT_MAX_VRFMAP_ENTRIES];
extern cnat_ingress_vrfid_name_entry vrfid_name_map[MAX_VRFID];

extern index_slist_t *cnat_out2in_hash;
extern index_slist_t *cnat_in2out_hash;
extern index_slist_t *cnat_user_hash;
extern index_slist_t *cnat_session_hash;

typedef enum {
    CNAT_DB_IN2OUT = 0,
    CNAT_DB_OUT2IN,
} cnat_db_which_t;

typedef enum {
    CNAT_NO_ICMP_MSG =0,
    CNAT_ICMP_MSG,
} cnat_icmp_msg_t;

typedef struct {
    cnat_errno_t    error;
    cnat_icmp_msg_t gen_icmp_msg;
    u32             svi_addr;
} cnat_gen_icmp_info;

typedef cnat_vrfmap_t nat64_vrfmap_t;
typedef cnat_portmap_v2_t nat64_portmap_v2_t;

#define CNAT_V4_GET_HASH(key64, hash, mask) \
    a = key64; \
    b = c = 0x9e3779b97f4a7c13LL; \
    /* Jenkins hash, arbitrarily use c as the "answer" */ \
    hash_mix64(a, b, c); \
    hash = c & mask;

#define CNAT_V4_GET_SESSION_HASH(main_index, in_addr, port, vrf, hash, mask) \
    a = main_index ^ in_addr ^ port ^ vrf; \
    b = c = 0x9e3779b9; \
    /* Jenkins hash, arbitrarily use c as the "answer" */ \
    hash_mix32(a, b, c); \
    hash = c & mask;

#define CNAT_V4_GET_FRAG_HASH(key64, key32, hash, mask) \
    a = key64; \
    b = key32; \
    c = 0x9e3779b97f4a7c13LL; \
    hash_mix64(a, b, c); \
    hash = c % mask;

#define CNAT_DB_UPDATE_IN2OUT_TIMER \
   db->entry_expires = cnat_current_time; \
   db->in2out_pkts++; 

#define CNAT_DB_TIMEOUT_RST(db) \
	if(PREDICT_TRUE(db->entry_expires != 0 )) \
		db->entry_expires = cnat_current_time;

#define DEBUG_I2O_DROP(debug_flag) \
if (debug_i_flag & debug_flag) { \
    cnat_db_debug_i2o_drop(&ki); \
}


cnat_main_db_entry_t *cnat_main_db_create (cnat_db_create_args_t *a);
void cnat_main_db_entry_delete(cnat_main_db_entry_t *ep);

void cnat_delete_main_db_entry(cnat_main_db_entry_t *ep);
void cnat_delete_main_db_entry_v2(cnat_main_db_entry_t *ep);


cnat_main_db_entry_t*
cnat_get_main_db_entry(cnat_db_key_bucket_t *ki,
                       port_pair_t port_type,
                       cnat_errno_t *error,
                       cnat_user_db_entry_t ** user_db_entry);

cnat_main_db_entry_t*
cnat_get_main_db_entry_v2(cnat_db_key_bucket_t *ki,
                       port_pair_t port_pair_type,
                       port_type_t port_type,
                       cnat_gen_icmp_info *info,
                       cnat_key_t *dest_info);

cnat_main_db_entry_t*
cnat_create_static_main_db_entry_v2(cnat_db_key_bucket_t *ki,
                                    cnat_db_key_bucket_t *ko,
				    cnat_vrfmap_t        *my_vrfmap,
				    cnat_gen_icmp_info   *info);

cnat_main_db_entry_t*
cnat_create_main_db_entry_and_hash(cnat_db_key_bucket_t *ki,
                                   cnat_db_key_bucket_t *ko,
                                   cnat_user_db_entry_t *udb);

cnat_user_db_entry_t*
cnat_user_db_create_entry(cnat_db_key_bucket_t *uki,
                          u32 portmap_index);

cnat_user_db_entry_t*
cnat_user_db_lookup_entry(cnat_db_key_bucket_t *uki);

cnat_main_db_entry_t*
cnat_main_db_lookup_entry(cnat_db_key_bucket_t *ki);

cnat_main_db_entry_t*
cnat_main_db_lookup_entry_out2in (cnat_db_key_bucket_t *ko);

void cnat_main_db_entry_dump (cnat_main_db_entry_t *db);
void cnat_db_in2out_hash_delete (cnat_main_db_entry_t *ep, cnat_user_db_entry_t *up);
void cnat_db_out2in_hash_delete (cnat_main_db_entry_t *ep);
void cnat_user_db_delete (cnat_user_db_entry_t *up);
void cnat_db_debug_i2o_drop(cnat_db_key_bucket_t *ki);

/*
 * Function to dump the Hash Table that maps if_num to uidb_index
 */
extern void cnat_if_num_hash_table_dump(void);

#define MAIN_DB_TYPE        0
#define SESSION_DB_TYPE     1
u16 query_and_update_db_timeout(void *db, u8 db_type);

u16 cnat_timeout_db_create (cnat_timeout_t t_entry);
void cnat_timeout_db_delete(cnat_key_t t_key);

cnat_session_entry_t *
cnat_create_session_db_entry(cnat_key_t *ko,
    cnat_main_db_entry_t *bdb, u8 log);

void cnat_dest_update_main2session(cnat_main_db_entry_t *mdb,
      cnat_session_entry_t *sdb);

cnat_session_entry_t *cnat_handle_1to2_session(
        cnat_main_db_entry_t *mdb,
        cnat_key_t *dest_info);

void cnat_add_dest_n_log(
        cnat_main_db_entry_t *mdb,
        cnat_key_t *dest_info);

cnat_session_entry_t *
   cnat_session_db_lookup_entry(cnat_key_t *ko,u32 main_db_index);

cnat_session_entry_t *
   cnat_session_db_edm_lookup_entry(cnat_key_t *ko,
                                    u32 session_head_index,
				    u32 main_db_index);


typedef struct{
    u32 sessions;
    u32 active_translations;
    u32 num_dynamic_translations;
    u32 num_static_translations;
    u64 in2out_drops_port_limit_exceeded;
    u64 in2out_drops_system_limit_reached;
    u64 in2out_drops_resource_depletion;
    u64 no_translation_entry_drops;
    u32 num_subscribers;
    u32 dummy;
    u64 drops_sessiondb_limit_exceeded;
} nat44_dslite_common_stats_t;

typedef struct {
    u32 translation_delete_count;
    u32 translation_create_count;
    u32 out2in_forwarding_count;
} nat44_dslite_global_stats_t;

typedef struct {
    u64 v4_to_v6_tcp_seq_mismatch_drop_count;
    u64 v4_to_v6_tcp_seq_mismatch_count;
    u64 v4_to_v6_out2in_session_create_count;
    u64 v4_to_v6_end_point_filter_drop_count;
} nat44_counters_stats_t;

#define NAT44_STATS 0
#define DSLITE_STATS 1
extern nat44_dslite_common_stats_t nat44_dslite_common_stats[255]; /* 0 is for nat44 */
extern nat44_dslite_global_stats_t nat44_dslite_global_stats[2]; /* 0 for nat44 and 1 for dslite */
extern nat44_counters_stats_t     nat44_counters_stats[CNAT_MAX_VRFMAP_ENTRIES];/*For displaying show cgn <cgn-name> inside-vrf <vrf-name> counters */

#define NAT44_COMMON_STATS nat44_dslite_common_stats[NAT44_RESERVED_INST_ID] 
#define NAT44_GLOBAL_STATS nat44_dslite_global_stats[NAT44_STATS] 
#define DSLITE_GLOBAL_STATS nat44_dslite_global_stats[DSLITE_STATS] 
#define SESSION_LOG_ENABLE    1
#define ALG_ENABLED_DB(db) \
    ((db->flags & CNAT_PCP_FLAG) || \
    (db->flags & CNAT_DB_FLAG_ALG_CTRL_FLOW) || \
    (db->flags & (CNAT_DB_FLAG_PPTP_TUNNEL_INIT | \
                  CNAT_DB_FLAG_PPTP_TUNNEL_ACTIVE)))


#endif /* __CNAT_DB_H__ */
