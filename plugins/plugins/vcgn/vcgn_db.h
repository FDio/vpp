/*
 *------------------------------------------------------------------
 * vcgn_db.h - translation database definitions
 *
 * Copyright (c) 2007-2014 Cisco and/or its affiliates.
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

#ifndef __VCGN_DB_H__
#define __VCGN_DB_H__

#include "index_list.h"

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

/*
 * Main translation database entries. Currently 0x50 = 80 bytes in length.
 * Given 20,000,000 entries, it saves nearly 1gb of SDRAM to pack the entries
 * and pay the extra prefetch. So, that's what we do.
 */

typedef struct {
    /* 0x00 */
    index_slist_t out2in_hash;  /* hash-and-chain, x2 */
    index_slist_t in2out_hash; 

    /* 0x08 */
    cnat_key_t out2in_key;      /* network-to-user, outside-to-inside key */

    /* 0x10 */
    cnat_key_t in2out_key;      /* user-to-network, inside-to-outside key */

    /* 0x18 */
    index_dlist_t user_ports;   /* per-user translation list */

    /* 0x20 */
    u32 user_index;             /* index of user that owns this entry */

    /* 0x24 */
    u16 vrfmap_index;           /* index of vrfmap */

    /* 0x26 */
    u16 flags;                  /* Always need flags... */
#define CNAT_DB_FLAG_PORT_PAIR (1<<0)
#define CNAT_DB_FLAG_TCP_ACTIVE (1<<1)
#define CNAT_DB_FLAG_ENTRY_FREE (1<<2)
#define CNAT_DB_FLAG_UDP_ACTIVE (1<<3)
#define CNAT_DB_FLAG_STATIC_PORT (1<<4)
#define CNAT_DB_FLAG_ALG_ENTRY  (1<<5)
    
    /* 0x28 */
    u32 dst_ipv4;               /* pointer to ipv4 dst list, used in evil mode */

    /* 0x2C */
    u32 out2in_pkts;            /* pkt counters */

    /* 0x30 */
    u32 in2out_pkts;

    /* 0x34 */
    u32 entry_expires;     /* timestamp used to expire translations */

    /* 0x38 */
    union {                     /* used by FTP ALG, pkt len delta due to FTP PORT cmd */
    u16 delta;             
    i8  alg_dlt[2];             /* two delta values, 0 for previous, 1 for current */
    u16 il;                     /* Used to indicate if interleaved mode is used
                                   in case of RTSP ALG */
    } alg;

    /* 0x 48 */
    u32 tcp_seq_num;            /* last tcp (FTP) seq # that has pkt len change due to PORT */

    cnat_timeout_t destn_key;  

    /* 0x4C... last byte -- 72 total */
} cnat_main_db_entry_t;
#endif
