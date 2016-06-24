/*
 *------------------------------------------------------------------
 * spp_ctx.h - packet / context definitions
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

#ifndef __SPP_CTX_H__
#define __SPP_CTX_H__

/* Packet header / data */

/* Any change to spp_ctx_t structure should be updated in vnet/buffer.h
 * as well.
 */
typedef struct _spp_ctx {
#ifdef TOBE_PORTED
        /* Following fields are required to handle multibuffer */
        u32   num_buffers; /* Number of buffers part of packet */
        vlib_buffer_t *next_ctx_this_packet;

        /* Following is used by non-UDP protocols */
#define SPP_CTX_FEATURE_DATA_SIZE 16

        u8 feature_data[SPP_CTX_FEATURE_DATA_SIZE];
#endif

    union { /* Roddick specific */
        u32 roddick_info;
        struct __tx_pkt_info  { /* Used by PI to PI communication for TX */
            u32 uidb_index:16;       /* uidb_index to transmit */
            u32  packet_type:2;   /* 1-IPv4, 2-Ipv6, - 0,3 - Unused */
            u32  ipv4_defrag:1;    /* 0 - Normal, 1 - update first
                                    * segment size
                                    * (set by 6rd defrag node)
                                    */

            u32  dst_ip_port_idx:4;/* Index to dst_ip_port_table */
            u32  from_node:4;
            u32  calc_chksum:1;
            u32  reserved:4;
        } tx;
        struct __rx_pkt_info { /* Used by PD / PI communication */
            u32 uidb_index:16;    /* uidb_index received in packet */
            u32  packet_type:2;   /* 1-IPv4, 2-Ipv6, - 0,3 - Unused */
            u32  icmp_type:1;     /* 0-ICMP query type, 1-ICMP error type */
            u32  protocol_type:2; /* 1-TCP, 2-UDP, 3-ICMP, 0 - Unused */
            u32  ipv4_defrag:1;    /* 0 - Normal, 1 - update first
                                    * segment size
                                    * (set by 6rd defrag node)
                                    */

            u32  direction:1;     /* 0-Outside, 1-Inside */
            u32  frag:1;          /*IP fragment-1, Otherwise-0*/
            u32  option:1;        /* 0-No IP option (v4) present, non-fragHdr
                                   * option hdr present (v6)
                                   */
            u32  df_bit:1;        /* IPv4 DF bit copied here */
            u32  reserved1:6;
        } rx;
    } ru;
} spp_ctx_t;

#endif
