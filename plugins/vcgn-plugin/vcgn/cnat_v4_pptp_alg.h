/*
 *------------------------------------------------------------------
 * cnat_v4_pptp_alg.h
 *
 * Copyright (c) 2009-2013 Cisco and/or its affiliates.
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

#ifndef __CNAT_V4_PPTP_ALG_H__
#define __CNAT_V4_PPTP_ALG_H__

/* Debug utils of PPTP */
#define PPTP_DBG(debug, ...)  \
            if(PREDICT_FALSE(cnat_pptp_debug_flag >= debug)) { \
                    PLATFORM_DEBUG_PRINT("%s:%s:%d - ", \
                           __FILE__, __FUNCTION__, __LINE__);\
                    PLATFORM_DEBUG_PRINT(__VA_ARGS__);\
                    PLATFORM_DEBUG_PRINT("\n"); \
            } 

#define PPTP_DUMP_PACKET(ip, len) pptp_hex_dump(ip, len)


#define PPTP_DISABLED  0 
#define PPTP_ENABLED   1

#define PPTP_GRE_TIMEOUT  60 /*sec */

#define TCP_PPTP_PORT 1723

#define PPTP_PAC 0 
#define PPTP_PNS 1

/* PPTP MSG TYPE */

#define PPTP_MSG_TYPE_CONTROL  1
#define PPTP_MSG_TYPE_MGMT     2 

/* PPTP control messages */

/* control connection mgmt */ 
#define PPTP_START_CC_RQ           1 
#define PPTP_START_CC_RP           2 
#define PPTP_STOP_CC_RQ            3 
#define PPTP_STOP_CC_RP            4 
#define PPTP_ECHO_RQ               5 
#define PPTP_ECHO_RP               6 

/* call mgmt */
#define PPTP_OBOUND_CALL_RQ        7 
#define PPTP_OBOUND_CALL_RP        8 
#define PPTP_IBOUND_CALL_RQ        9 
#define PPTP_IBOUND_CALL_RP        10 
#define PPTP_IBOUND_CALL_CN        11 
#define PPTP_CALL_CLEAR_RQ         12 
#define PPTP_CALL_DISCON_NT        13 

/* other */

#define PPTP_WAN_ERR_NT            14
#define PPTP_SET_LINK_INF          15

#define PPTP_MIN_HDR_LEN           8

/* Byte offsets from start of TCP Data(PPTP header) */ 

#define PPTP_CTRL_MGMT_TYPE_OFFSET   0x02 
#define PPTP_CC_TYPE_OFFSET          0x08
#define PPTP_HDR_CALL_ID_OFFSET      0x0c 
#define PPTP_HDR_PEER_CALL_ID_OFFSET 0x0e 

#define PPTP_HDR_RESULT_CODE_OFFSET_STCCRP 0x0e 
#define PPTP_HDR_RESULT_CODE_OFFSET        0x10 


/* Offset of control/mgmt msg types 
            from start of TCP header */ 

#define TCP_HEADER_SIZE(tcp)   \
                  ((tcp->hdr_len>>4) << 2)

  
#define PPTP_MSG_START_OFFSET(tcp)    \
                  ((u8*)tcp + TCP_HEADER_SIZE(tcp))


#define PPTP_CC_MSG_TYPE_OFFSET(tcp) \
                  (PPTP_MSG_START_OFFSET(tcp) + \
                  PPTP_CC_TYPE_OFFSET )

#define PPTP_MGMT_MSG_TYPE_OFFSET(tcp) \
                  ( PPTP_MSG_START_OFFSET(tcp) + \
                  PPTP_CTRL_MGMT_TYPE_OFFSET )

#define PPTP_CALL_ID_OFFSET(tcp) \
                   ( PPTP_MSG_START_OFFSET(tcp) + \
                   PPTP_HDR_CALL_ID_OFFSET )

#define PPTP_PEER_CALL_ID_OFFSET(tcp) \
                   ( PPTP_MSG_START_OFFSET(tcp) + \
                   PPTP_HDR_PEER_CALL_ID_OFFSET )

#define PPTP_RESULT_CODE_OFFSET(tcp) \
                   ( PPTP_MSG_START_OFFSET(tcp) + \
                   PPTP_HDR_RESULT_CODE_OFFSET )

#define PPTP_RESULT_CODE_OFFSET_STCCRP(tcp) \
                   ( PPTP_MSG_START_OFFSET(tcp) + \
                   PPTP_HDR_RESULT_CODE_OFFSET_STCCRP)

/* values */
#define PPTP_CC_MSG_TYPE(tcp) \
              (u16*)PPTP_CC_MSG_TYPE_OFFSET(tcp)

#define PPTP_MGMT_MSG_TYPE(tcp) \
              (u16*)PPTP_MGMT_MSG_TYPE_OFFSET(tcp)

#define PPTP_CALL_ID(tcp) \
              (u16*)PPTP_CALL_ID_OFFSET(tcp)

#define PPTP_PEER_CALL_ID(tcp) \
              (u16*)PPTP_PEER_CALL_ID_OFFSET(tcp)

#define PPTP_RESULT_CODE(tcp) \
              *(u8*)PPTP_RESULT_CODE_OFFSET(tcp);
              
#define PPTP_RESULT_CODE_STCCRP(tcp) \
              *(u8*)PPTP_RESULT_CODE_OFFSET_STCCRP(tcp);


/* other code */
#define PPTP_CHAN_SUCCESS   1


/* Data structures */

extern u32 cnat_pptp_debug_flag;

#endif /* __CNAT_V4_PPTP_ALG_H__ */
