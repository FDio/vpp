/*
 *------------------------------------------------------------------
 * cnat_v4_ftp_alg.h
 *
 * Copyright (c) 2012-2013 Cisco and/or its affiliates.
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

#ifndef __CNAT_V4_FTP_ALG_H__
#define __CNAT_V4_FTP_ALG_H__


#include <vlib/vlib.h>
#include <vnet/vnet.h>

#include "tcp_header_definitions.h"
#include "dslite_defs.h"
#include "dslite_db.h"

/* shorter form of byte order functions */

#define net2host16(x) clib_net_to_host_u16( x)
#define net2host32(x) clib_net_to_host_u32( x)
#define net2host64(x) clib_net_to_host_u64( x)
#define host2net16(x) clib_host_to_net_u16(x)
#define host2net32(x) clib_host_to_net_u32(x)
#define host2net64(x) clib_host_to_net_u64(x)

//#define BIGENDIAN

typedef struct iphdrtype_ {
    u8  v_ihl;            /* version and IP header length */ 
    u8  tos;            /* type of service */ 
    u16 tl;                  /* total length */ 
    u16 id;                  /* identifier */ 
    u16 ipreserved: 1; 
    u16 dontfragment: 1; 
    u16 morefragments: 1; 
    u16 fo: 13;            /* fragment offset */ 
    u8  ttl;                  /* time to live */ 
    u8  prot;                 /* protocol type */ 
    u16 checksum;            /* checksum */ 
    u32 srcadr;          /* IP source address */ 
    u32 dstadr;          /* IP destination address */
} iphdrtype;


typedef struct tcptype_ {
    u16 sourceport;
    u16 destinationport;
    u32 sequencenumber;
    u32 acknowledgementnumber;
    u8  dataoffset;
    u8  flags;
#if 0
/* bypass the ENDIAN part */
#ifdef BIGENDIAN
    u8  reserved: 2;
    u8  urg: 1;
    u8  ack: 1;
    u8  psh: 1;
    u8  rst: 1;
    u8  syn: 1;
    u8  fin: 1;
#else
    u8  fin: 1;
    u8  syn: 1;
    u8  rst: 1;
    u8  psh: 1;
    u8  ack: 1;
    u8  urg: 1;
    u8  reserved2: 2;
#endif
#endif

    u16 window;
    u16 checksum;
    u16 urgentpointer;
    u8  data[0];
} tcptype ;


int watch_ftp_port_cmd (iphdrtype *ip,
                        tcptype *tcp,
                        u32 * ip_addr,
                        u16 * port);


u8 * ftp_test_pkt_gen (u32 ip_addr, u16 port);

int update_ftp_port(u8 * pkt, u32 new_ip, u16 new_port, i8 * delta,
                    cnat_main_db_entry_t *db_tcp_control,
                    dslite_table_entry_t   *dslite_entry_ptr,
                    ipv6_header_t *ipv6_hdr);
/*
 * caller needs to check if it's a ftp packet
 * this function returns 1
 * if packet being updated for PORT
 * otherwise return 0.
 * Assume IP header DOES NOT have option fields
 */

int cnat_ftp_alg ( u8* pkt, i8 * delta, cnat_main_db_entry_t *db,
                   dslite_table_entry_t *dslite_entry_ptr,
                   ipv6_header_t *ipv6_hdr);

#define FTP_ALG_DEBUG_PRINTF_ENABLED 1

#ifdef FTP_ALG_DEBUG_PRINTF_ENABLED

#define FTP_ALG_DEBUG_PRINTF(...) {                   \
    if (global_debug_flag & CNAT_DEBUG_FTP_ALG) {     \
        printf(__VA_ARGS__);                          \
    } }

#else

#define FTP_ALG_DEBUG_PRINTF(...)

#endif

#endif /* __CNAT_V4_FTP_ALG_H__ */
