/*
 *------------------------------------------------------------------
 * cnat_pcp_server.h
 *
 * Copyright (c) 2009-2012 Cisco and/or its affiliates.
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

#ifndef __CNAT_PCP_SERVER_H__
#define __CNAT_PCP_SERVER_H__ 

#include "dslite_defs.h"

/* Debug utils of PCP */
#define PCP_DBG(debug, ...)  \
            if(PREDICT_FALSE(cnat_pcp_debug_flag >= debug)) { \
                    printf("%s:%s:%d - ", \
                           __FILE__, __FUNCTION__, __LINE__);\
                    printf(__VA_ARGS__);\
                    printf("\n"); \
            } 

#define PCP_DUMP_PDATA \
   if(PREDICT_FALSE(cnat_pcp_debug_flag >= 100)) { \
     printf("%s:%s:%d - \n", \
           __FILE__, __FUNCTION__, __LINE__);\
     printf("src - ip = %X, proto = %d, port = %d i_vrf = %d, o_vrf = %d\n", \
      pcp_data.src_ip[3], pcp_data.proto, pcp_data.src_port, pcp_data.i_vrf,  pcp_data.o_vrf); \
     printf(" third party ip = %X\n", pcp_data.third_party_ip[3]); \
     printf("map - ip = %X, port = %d \n", \
      pcp_data.ext_ip[3], pcp_data.ext_port);\
     printf("remote - ip = %X, port = %d \n", \
      pcp_data.peer_ip[3], pcp_data.peer_port); \
     printf("req life time = %d \n", pcp_data.req_lifetime); \
     printf("drop = %d \n", pcp_data.drop);\
     printf("udp_len = %d \n", pcp_data.udp_len); \
     printf("pm = %p \n", pcp_data.pm); \
     printf("cnat_proto = %X \n", pcp_data.cnat_proto); \
     printf("inst_id = %X \n", pcp_data.inst_id); \
     printf("======================================================\n"); \
  }

#define PCP_DUMP_PACKET(ip, len) pcp_hex_dump(ip, len)

#ifdef TOBE_PORTED
#define PCP_INCR(counter) pcp_counters.pcp_##counter++  ;
#else
#define PCP_INCR(counter) 
#endif

typedef struct pcp_debug_counters {
   u64 pcp_input;
   u64 pcp_output;
   u64 pcp_service_nat44;
   u64 pcp_service_dslite;
   /* below all are drops */
   u64 pcp_drops;
   u64 pcp_i2o_key_inuse;
   u64 pcp_throttle_drops;
   u64 pcp_udp_len;
   u64 pcp_nrequest;
   u64 pcp_min_udp_len;
   u64 pcp_max_udp_len;
   u64 pcp_mod4_len;
   u64 pcp_invalid_3rd_len;  
   u64 pcp_invalid_option;  
   u64 pcp_version;
   u64 pcp_invalid_opcode;
   u64 pcp_invalid_client_ip;
   u64 pcp_invalid_proto;
   u64 pcp_invalid_port;
   u64 pcp_invalid_vrfmap;
   u64 pcp_invalid_ext_addr;
   u64 pcp_out_addr_inuse;
   u64 pcp_exact_match;
   u64 pcp_exact_entry_created;
   u64 pcp_exact_db_alloc_failed;
   u64 pcp_udb_mismatch;
   u64 pcp_noexact_db_allocated;
   u64 pcp_static_entry_present;
   u64 pcp_entry_deleted;
   u64 pcp_3rd_party_option;

   /* map counters */
   u64 pcp_map_input;
   u64 pcp_map_min_len;
   u64 pcp_map_max_len;
   u64 pcp_map_invalid_option;
   u64 pcp_map_invalid_option_len;
   u64 pcp_map_pref_fail_option;
   u64 pcp_map_invalid_delete_req;
   u64 pcp_map_delete_req;
   u64 pcp_map_create_req;
   u64 pcp_map_refresh;

   /* peer counters */
   u64 pcp_peer_input;
   u64 pcp_peer_invalid_len;
   u64 pcp_peer_delete_req;
   u64 pcp_peer_create_req;
   u64 pcp_peer_addr_mistmatch;
   u64 pcp_peer_refresh;

} pcp_debug_counters_t;

typedef struct {
    u16 msg_id;
    u8 rc;
    u8 pad[5];

    /* better to have a group structures rather than individual
       variables, any change in counters is will automatically
       reflect here */
    pcp_debug_counters_t counters;
} pcp_show_counters_resp_t ;



/* PCP opcodes */
typedef enum pcp_opcode  {
  PCP_OPCODE_MAP = 1, 
  PCP_OPCODE_PEER = 2 
}pcp_opcode_t;


/* PCP opcodes */
typedef enum pcp_options  {
  PCP_OPTION_3RD_PARTY = 1,
  PCP_OPTION_PREF_FAIL = 2, 
  PCP_OPTION_FILTER = 3
} pcp_options_t;

/* PCP Result codes */
typedef enum pcp_result_codes  {
    PCP_SUCCESS = 0,
    PCP_ERR_UNSUPP_VERSION = 1,
    PCP_ERR_NOT_AUTHORIZED = 2,
    PCP_ERR_MALFORMED_REQUEST = 3,
    PCP_ERR_UNSUPP_OPCODE = 4,
    PCP_ERR_UNSUPP_OPTION = 5,
    PCP_ERR_MALFORMED_OPTION = 6,
    PCP_ERR_NETWORK_FAILURE = 7,
    PCP_ERR_NO_RESOURCES = 8,
    PCP_ERR_UNSUPP_PROTOCOL = 9,
    PCP_ERR_USER_EX_QUOTA = 10,
    PCP_ERR_CANNOT_PROVIDE_EXTERNAL = 11,
    PCP_ERR_ADDRESS_MISMATCH = 12,
    PCP_ERR_EXCESSIVE_REMOTE_PEERS = 13
} pcp_result_codes_t;

#define PCP_DISABLED  0 
#define PCP_ENABLED   1

#define PCP_DROP  1

#define PCP_STATIC_LIFETIME  0xFFFFFFFF
#define PCP_MAX_LIFETIME 0x00015180       /* 24 hours = 86400 seconds*/

#define PCP_VERSION_SUPPORTED    1

#define PCP_NO_PREF_FAIL_OPTION     0 
#define PCP_PREF_FAIL_OPTION        1 
 
#define CNAT_DEF_PCP_PORT 5351  

#define PCP_REQ_RESP_BIT          0x80
#define PCP_RESPONSE(r_opcode)   (r_opcode & PCP_REQ_RESP_BIT)  
#define PCP_REQUEST(r_opcode)    !(PCP_RESPONSE(r_opcode)) 

#define PCP_REQ_OPCODE(r_opcode)  (r_opcode & 0x7F)

/* 24 bytes */
#define PCP_COMMON_HDR_LEN   sizeof(pcp_request_t)  

/* 8 bytes */
#define UDP_HDR_LEN          sizeof(udp_hdr_type_t)

#define PCP_PREF_FAIL_OPTION_SIZE    \
                       sizeof(pcp_prefer_fail_option_t) 

#define PCP_3RD_PARTY_OPTION_SIZE   \
                       sizeof(pcp_3rd_party_option_t) 

#define PCP_MIN_LEN          PCP_COMMON_HDR_LEN 

/* 24+8=32 bytes */ 
#define PCP_MIN_UDP_LEN      (PCP_MIN_LEN + UDP_HDR_LEN)

#define PCP_MAX_LEN          1024

/* 1024+8 = 1032 bytes */
#define PCP_MAX_UDP_LEN      (PCP_MAX_LEN + UDP_HDR_LEN) 

/* 24+ 24 = 48 bytes */
#define PCP_MAP_OPCODE_MIN_LEN  (PCP_COMMON_HDR_LEN + \
               sizeof( pcp_map_option_specific_data_t))

/* 24 + 44 = 68 bytes */
#define PCP_PEER_OPCODE_MIN_LEN  (PCP_COMMON_HDR_LEN + \
               sizeof( pcp_peer_option_specific_data_t))

/* 48 + 8 = 56 bytes */
#define PCP_MAP_OPCODE_MIN_UDP_LEN (PCP_MAP_OPCODE_MIN_LEN + \
                    UDP_HDR_LEN )

#define PCP_GET_MAP_OPTION_OFFSET(req)   \
             ((u8*)req + PCP_MAP_OPCODE_MIN_LEN)

#define PCP_GET_PEER_OPTION_OFFSET(req)   \
             ((u8*)req + PCP_PEER_OPCODE_MIN_LEN)


#define PCP_REQ_TOTAL_LEN(udp)  (udp->udp_length - \
                                 UDP_HDR_LEN) 
/* 56 + 4 = 60 bytes */
#define PCP_MAP_OPCODE_PREF_FAIL_OPTION_LEN \
                      (PCP_MAP_OPCODE_MIN_UDP_LEN + \
                     sizeof(pcp_prefer_fail_option_t))


/* 68 + 8 = 76 bytes */
#define PCP_PEER_OPCODE_MIN_UDP_LEN  (PCP_PEER_OPCODE_MIN_LEN + \
                                        UDP_HDR_LEN)

#define PCP_MUST_OPTION(option_code)  (option_code & 0x80)



/* 56 + 20 = 76*/
#define PCP_DSLITE_MAP_OPCODE_MIN_UDP_LEN \
            ( PCP_MAP_OPCODE_MIN_UDP_LEN + \
              PCP_3RD_PARTY_OPTION_SIZE)

/* 60 + 20 = 80 */
#define PCP_DSLITE_MAP_OPCODE_MAX_UDP_LEN \
        ( PCP_MAP_OPCODE_PREF_FAIL_OPTION_LEN + \
          PCP_3RD_PARTY_OPTION_SIZE)

/* 76 + 20 = 96 */ 
#define PCP_DSLITE_PEER_OPCODE_MIN_UDP_LEN \
            ( PCP_PEER_OPCODE_MIN_UDP_LEN + \
              PCP_3RD_PARTY_OPTION_SIZE)


#define PCP_SET_CNAT_PROTO(proto)    \
                  pcp_data.cnat_proto = (proto == TCP_PROT) ? CNAT_TCP: \
                      (proto == UDP_PROT)?  CNAT_UDP : CNAT_ICMP;

#define PCP_SET_REQ_LIFETIME() \
        if(pcp_data.db->flags & CNAT_DB_FLAG_STATIC_PORT) { \
            pcp_data.db->proto_data.seq_pcp.pcp_lifetime = \
            PCP_STATIC_LIFETIME; \
            pcp_data.req_lifetime = PCP_STATIC_LIFETIME; \
        } else { \
            pcp_data.db->proto_data.seq_pcp.pcp_lifetime = \
            pcp_data.req_lifetime + cnat_current_time ; \
        }


/* per second not more than PCP_THROTTLE_LIMIT
 * delete requests will be handled. 
 * this excludes , specific entries, in which 
 * only one entry needs to be deleted
 */
#define PCP_THROTTLE_LIMIT    2

typedef struct pcp_request {
  u8     ver;
  u8     r_opcode;
  u16    reserved;
  u32    req_lifetime;
  u32    ip[4]; /* ipv4 will be represented 
                 by the ipv4 mapped ipv6 */
} pcp_request_t;

typedef struct pcp_response {
  u8     ver;
  u8     r_opcode;
  u8     reserved;
  u8     result_code;
  u32    lifetime;
  u32    epochtime;
  u32    reserved1[3];
} pcp_response_t;


typedef struct pcp_options_hdr {
  u8     code;
  u8     reserved;
  u16    len;
  u8     data[0];
} pcp_options_hdr_t;


/* same for both request and response */
typedef struct pcp_map_option_specific_data {
  u8     protocol; 
  u8     reserved[3];
  u16    int_port;
  u16    ext_port;
  u32    ext_ip[4]; /* ipv4 will be represnted
                 by the ipv4 mapped ipv6 */
} pcp_map_option_specific_data_t;

/* same for both request and response */
typedef struct pcp_peer_option_specific_data {
  u8     protocol;
  u8     reserved[3];
  u16    int_port;
  u16    ext_port;
  u32    ext_ip[4]; /* ipv4 will be represented
                 by the ipv4 mapped ipv6 */
  u16    peer_port;
  u16    reserved1;
  u32    peer_ip[4];
} pcp_peer_option_specific_data_t;

typedef struct pcp_prefer_fail_option {
   u8 option;
   u8 reserved;
   u16 len;
} pcp_prefer_fail_option_t;


typedef struct pcp_3rd_party_option{
   u8 option;
   u8 reserved;
   u16 len;
   u32 ip[4];
} pcp_3rd_party_option_t;

/* structure used as pipeline data */

typedef struct pcp_pipeline_data {

   union {

    u8 *p;
    ipv4_header *ip ;
    ipv6_header_t *ipv6 ;

   } l3addr; 

   udp_hdr_type_t *udp;
   pcp_request_t *req;
   pcp_response_t *resp;
   pcp_opcode_t opcode;
   u32   src_ip[4];
   u16   src_port;
   u8    proto;
   u16   i_vrf;
   u16   o_vrf;
   u32   ext_ip[4];
   u16   ext_port;
   u32   third_party_ip[4];
   
   /* valid for peer opcode */
   u32   peer_ip[4];
   u32   peer_port;
   u32   req_lifetime;
   u32 udp_len;
   pcp_options_t  pref_fail;
   pcp_options_t  third_party;
   u8             *option_spec;
   pcp_result_codes_t ret_code;
   cnat_portmap_v2_t *pm;
   cnat_main_db_entry_t *db;
   cnat_vrfmap_t  *vrfmap;
   dslite_table_entry_t *inst_ptr;
   u16 inst_id;
   u32  flags;
   u16  cnat_proto;

  /* is packet needs to be dropped ? */
   u8   drop;
   /* nat44, dslite, nat64 */
#define PCP_SERVICE_NAT44    1
#define PCP_SERVICE_DSLITE   2 
#define PCP_SERVICE_NAT64    3 
   u8   service_type;

#define PCP_REQ_ENTRY_PRESENT  1
#define PCP_REQ_EXT_MAP_PRESENT  1
   u8   state;
} pcp_pipeline_data_t; 

#endif /* __CNAT_PCP_sERVER_H__ */
