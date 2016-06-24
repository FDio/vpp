/*
 *------------------------------------------------------------------
 * cnat_v4_functions.h  
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

#ifndef __CNAT_V4_FUNCTOINS__
#define __CNAT_V4_FUNCTOINS__

#include "tcp_header_definitions.h"
#include "cnat_db.h"
#include "spp_ctx.h"

#include "platform_common.h"

/*
 * Defines and structures to enable TCP packet logging 
 */
#define TCP_LOGGING_DISABLE      0
#define TCP_LOGGING_ENABLE       1
#define TCP_LOGGING_PACKET_DUMP  2
#define TCP_LOGGING_SUMMARY_DUMP 3

#define MAX_TCP_LOGGING_COUNT 1024

typedef struct tcp_logging_struct {
    u32 seq_num;
    u32 ack_num;
    u32 old_ip;
    u32 new_ip;
    u16 old_port;
    u16 new_port;
    u16 old_ip_crc;
    u16 new_ip_crc;
    u16 old_tcp_crc;
    u16 new_tcp_crc;
} tcp_logging_struct_t;

void tcp_debug_logging_dump (void);
void tcp_debug_logging_enable_disable (u32 enable_flag);

void
tcp_debug_logging (
    u32 seq_num,
    u32 ack_num,
    u32 old_ip,
    u32 new_ip,
    u16 old_port,
    u16 new_port,
    u16 old_ip_crc,
    u16 new_ip_crc,
    u16 old_tcp_crc,
    u16 new_tcp_crc);

#define JLI printf("%s %s %d\n", __FILE__, __FUNCTION__, __LINE__); fflush(stdout);

#define CNAT_ICMP_DEST_UNREACHABLE 100
#define INCREMENT_NODE_COUNTER(c) \
    em->counters[node_counter_base_index + c] += 1;

#define V4_TCP_UPDATE_SESSION_FLAG(db, tcp) \
if ((tcp->flags & TCP_FLAG_ACK) && (tcp->flags & TCP_FLAG_SYN)) { \
     db->flags |= CNAT_DB_FLAG_TCP_ACTIVE; \
} \
if ((tcp->flags & TCP_FLAG_RST) || (tcp->flags & TCP_FLAG_FIN)) { \
     db->flags &= ~CNAT_DB_FLAG_TCP_ACTIVE; \
     db->flags |= CNAT_DB_FLAG_TCP_CLOSING; \
} 

#define V4_TCP_UPDATE_SESSION_DB_FLAG(sdb, tcp) \
if ((tcp->flags & TCP_FLAG_ACK) && (tcp->flags & TCP_FLAG_SYN)) { \
     sdb->flags |= CNAT_DB_FLAG_TCP_ACTIVE; \
} \
if ((tcp->flags & TCP_FLAG_RST) || (tcp->flags & TCP_FLAG_FIN)) { \
     sdb->flags &= ~CNAT_DB_FLAG_TCP_ACTIVE; \
     sdb->flags |= CNAT_DB_FLAG_TCP_CLOSING; \
} 

/*
 * Code to recalculate checksum after ACK/SEQ number changes
 * This macro assumes, we have pointer to tcp structure
 * referenced by the name "tcp"
 */
#define CNAT_UPDATE_TCP_SEQ_ACK_CHECKSUM(old_val32, new_val32) \
{                                                              \
    u16 old_val_lower, old_val_upper, old_tcp_cr;              \
    u16 new_val_lower, new_val_upper, new_tcp_cr;              \
    u32 sum32;                                                 \
                                                               \
    old_val_lower = ~((u16) old_val32);                        \
    old_val_upper = ~((u16) (old_val32 >> 16));                \
    old_tcp_cr    = ~net2host16(&tcp->tcp_checksum);           \
    new_val_lower = (u16) new_val32;                           \
    new_val_upper = (u16) (new_val32 >> 16);                   \
                                                               \
    sum32 = old_val_lower + old_val_upper + old_tcp_cr +       \
            new_val_lower + new_val_upper;                     \
                                                               \
    sum32 = (sum32 & 0xffff) + ((sum32 >> 16) & 0xffff);       \
    sum32 = (sum32 & 0xffff) + ((sum32 >> 16) & 0xffff);       \
    new_tcp_cr = ~((u16)sum32);                                \
                                                               \
    tcp->tcp_checksum = host2net16(new_tcp_cr);                \
}

/*
 * newchecksum = ~(~oldchecksum + ~old + new)
 * old/new for l3 checksum:  ip address
 */
#define CNAT_UPDATE_L3_CHECKSUM_DECLARE \
u16  old_l3_1r, old_l3_2r; \
u16  old_l3_cr, new_l3_c; \
u32  new32;

#define CNAT_UPDATE_L3_CHECKSUM(old_l3_1, old_l3_2, old_l3_c,  \
                                new_l3_1, new_l3_2) \
old_l3_1r = ~(old_l3_1); \
old_l3_2r = ~(old_l3_2); \
old_l3_cr = ~(old_l3_c); \
new32 = old_l3_cr + old_l3_1r + old_l3_2r + new_l3_1 + new_l3_2; \
new32 = (new32 & 0xffff) + ((new32 >> 16) & 0xffff); \
new32 = (new32 & 0xffff) + ((new32 >> 16) & 0xffff); \
new_l3_c = ~((u16)new32); 


/*
 * newchecksum = ~(~oldchecksum + ~old + new)
 * old/new for l3 checksum:  ip address
 * old/new for l4 checksum:  ip address and port
 */
#define CNAT_UPDATE_L3_L4_CHECKSUM_DECLARE \
u16  old_l3_1r, old_l3_2r, old_l4r; \
u16  old_l3_cr, old_l4_cr; \
u16  new_l3_c, new_l4_c; \
u32  sum32, new32;

#define CNAT_UPDATE_L3_L4_CHECKSUM(old_l3_1, old_l3_2, old_l4, \
                                   old_l3_c, old_l4_c, \
                                   new_l3_1, new_l3_2, new_l4) \
old_l3_1r = ~(old_l3_1); \
old_l3_2r = ~(old_l3_2); \
old_l3_cr = ~(old_l3_c); \
sum32 = old_l3_1r + old_l3_2r + new_l3_1 + new_l3_2; \
new32 = old_l3_cr + sum32; \
new32 = (new32 & 0xffff) + ((new32 >> 16) & 0xffff); \
new32 = (new32 & 0xffff) + ((new32 >> 16) & 0xffff); \
new_l3_c = ~((u16)new32); \
old_l4r = ~(old_l4); \
old_l4_cr = ~(old_l4_c); \
sum32 += old_l4r + new_l4; \
new32 = old_l4_cr + sum32; \
new32 = (new32 & 0xffff) + ((new32 >> 16) & 0xffff); \
new32 = (new32 & 0xffff) + ((new32 >> 16) & 0xffff); \
new_l4_c = ~((u16)new32);

/*
 * For ICMP checksums, we don't use the top IP header for checksum calculation
 */
#define CNAT_UPDATE_L3_ICMP_CHECKSUM(old_l3_1, old_l3_2, old_l4, \
                                     old_l3_c, old_l4_c, \
                                     new_l3_1, new_l3_2, new_l4) \
old_l3_1r = ~(old_l3_1); \
old_l3_2r = ~(old_l3_2); \
old_l3_cr = ~(old_l3_c); \
sum32 = old_l3_1r + old_l3_2r + new_l3_1 + new_l3_2; \
new32 = old_l3_cr + sum32; \
new32 = (new32 & 0xffff) + ((new32 >> 16) & 0xffff); \
new32 = (new32 & 0xffff) + ((new32 >> 16) & 0xffff); \
new_l3_c = ~((u16)new32); \
old_l4r = ~(old_l4); \
old_l4_cr = ~(old_l4_c); \
sum32 = old_l4r + new_l4; \
new32 = old_l4_cr + sum32; \
new32 = (new32 & 0xffff) + ((new32 >> 16) & 0xffff); \
new32 = (new32 & 0xffff) + ((new32 >> 16) & 0xffff); \
new_l4_c = ~((u16)new32);


/*
 * icmp error type message:
 * newchecksum = ~(~oldchecksum + ~old + new)
 * old/new for outlayer ip checksum: ip address
 * old/new for outlayer icmp checksum: 
 *    out-layer: ip address
 *    inner-layer: ip addr, port, l3 checksum, l4 checksum
 */
#define CNAT_UPDATE_ICMP_ERR_CHECKSUM_DECLARE \
u16  old_ip_1r, old_ip_2r, old_ip_port_r, old_ip_cr, old_icmp_cr; \
u16  new_icmp_c; \
u32  sum32;


#define CNAT_UPDATE_ICMP_ERR_CHECKSUM(old_ip_1, old_ip_2, old_ip_port, old_ip_c, old_icmp_c, \
                                      new_ip_1, new_ip_2, new_ip_port, new_ip_c) \
old_ip_1r     = ~(old_ip_1); \
old_ip_2r     = ~(old_ip_2); \
old_ip_port_r = ~(old_ip_port); \
old_ip_cr     = ~(old_ip_c); \
old_icmp_cr   = ~(old_icmp_c); \
sum32 = old_ip_1r + old_ip_2r + new_ip_1 + new_ip_2 + \
        old_ip_port_r + new_ip_port + old_ip_cr + new_ip_c; \
new32 = old_icmp_cr + sum32; \
new32 = (new32 & 0xffff) + ((new32 >> 16) & 0xffff); \
new32 = (new32 & 0xffff) + ((new32 >> 16) & 0xffff); \
new_icmp_c = ~((u16)new32); \

/*
 * Add the two 16 bit parts of the 32 bit field
 * Repeat it one more time to take care of any overflow
 * Complement the u16 value and store it in network format
 */
#define FILL_CHECKSUM(checksum_field, sum32) {                         \
    sum32 = (sum32 & 0xffff) + ((sum32>>16) & 0xffff);                 \
    sum32 = (sum32 & 0xffff) + ((sum32>>16) & 0xffff);                 \
    checksum_field = clib_host_to_net_u16(~((u16) sum32));    \
}

static inline void
cnat_v4_recalculate_tcp_checksum (ipv4_header *ip,
				  tcp_hdr_type *tcp,
                                  u32 *ip_addr_ptr,
                                  u16 *tcp_port_addr_ptr,
				  u32 new_ip,
				  u16 new_port)
{
    u32 old_ip_addr, old_ip32_r, new_ip32, sum32;
    u16 old_port_r, old_ip_checksum_r, old_tcp_checksum_r;

    u16 *p16;

    p16 = (u16*) ip_addr_ptr;

    old_ip_addr = *ip_addr_ptr;
    old_ip32_r = (((u16) ~clib_net_to_host_u16(*p16)) +
                  ((u16) ~clib_net_to_host_u16(*(p16+1))));

    old_port_r = ~clib_net_to_host_u16(*tcp_port_addr_ptr);

    *ip_addr_ptr       = clib_host_to_net_u32(new_ip);

    new_ip32 = (new_ip & 0xffff) + ((new_ip >> 16) & 0xffff);

    old_ip_checksum_r  = ~clib_net_to_host_u16(ip->checksum);

    /*
     * Recalculate the new IP checksum
     */
    sum32 = old_ip32_r + new_ip32 + old_ip_checksum_r;

    FILL_CHECKSUM(ip->checksum, sum32);

    u16 frag_offset =
            clib_net_to_host_u16((ip->frag_flags_offset));

    if(PREDICT_FALSE(frag_offset & IP_FRAG_OFFSET_MASK)) {
        return; /* No need to update TCP fields */
    }
    
    *tcp_port_addr_ptr = clib_host_to_net_u16(new_port);
    old_tcp_checksum_r = ~clib_net_to_host_u16(tcp->tcp_checksum);

    /*
     * Recalculate the new TCP checksum
     */
    sum32 = old_ip32_r + new_ip32 +
            old_port_r + new_port + old_tcp_checksum_r;

    FILL_CHECKSUM(tcp->tcp_checksum, sum32);

    if (PREDICT_FALSE(tcp_logging_enable_flag)) {
        tcp_debug_logging(
	    clib_net_to_host_u32(tcp->seq_num),
	    clib_net_to_host_u32(tcp->ack_num),
	    clib_net_to_host_u32(old_ip_addr),
	    clib_net_to_host_u32(*ip_addr_ptr),
	    ~old_port_r,
	    clib_net_to_host_u16(*tcp_port_addr_ptr),
	    ~old_ip_checksum_r,
	    clib_net_to_host_u16(ip->checksum),
	    ~old_tcp_checksum_r,
	    clib_net_to_host_u16(tcp->tcp_checksum));
    }
}


extern void tcp_in2out_nat_mss_n_checksum (ipv4_header *ip,
                                      tcp_hdr_type *tcp,
                                      u32 ipv4_addr,
                                      u16 port,
                                      cnat_main_db_entry_t * db);

void hex_dump(u8 * p, int len);

u32 get_my_svi_intf_ip_addr();

/* 
 * in cnat_v4_icmp_gen.c,
 * return 1 if icmp msg allow to generate
 * for this user
 */

u32 icmp_msg_gen_allowed ();

cnat_icmp_msg_t v6_icmp_msg_gen_allowed();

int v4_crc_zero_udp_allowed();
void ipv4_decr_ttl_n_calc_csum(ipv4_header *ipv4);
int icmpv4_generate_with_throttling (spp_ctx_t *ctx, ipv4_header *ipv4,
                                     u16 rx_uidb_index);
                                            
int icmpv6_generate_with_throttling (spp_ctx_t *ctx, ipv6_header_t *ipv4,
                                     u16 rx_uidb_index);
                                            
void icmp_error_generate_v6(spp_ctx_t *ctx, u8 icmp_type,
                            u8 icmp_code, u16 uidb_index);

void calculate_window_scale(tcp_hdr_type *tcp_header, u8 *scale);

void cnat_log_nat44_tcp_seq_mismatch(
                   cnat_main_db_entry_t *db,
		   cnat_vrfmap_t *vrfmap);
void print_icmp_pkt (ipv4_header *ip);
void print_udp_pkt (ipv4_header *ip);
void print_tcp_pkt (ipv4_header *ip);
void print_ipv6_pkt (ipv6_header_t *ip);


#endif

