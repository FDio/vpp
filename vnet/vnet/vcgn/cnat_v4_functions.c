/*
 *---------------------------------------------------------------------------
 * cnat_v4_funtions.c
 *
 * Copyright (c) 2008-2013 Cisco and/or its affiliates.
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
 *---------------------------------------------------------------------------
 */
#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/pg/pg.h>
#include <vppinfra/error.h>


#include "tcp_header_definitions.h"
#include "cnat_db.h"
#include "cnat_config.h"
#include "cnat_v4_functions.h"
#include "dslite_defs.h"
#include "dslite_db.h"

static u32 tcp_logging_count;
static u32 tcp_logging_overflow;

static tcp_logging_struct_t tcp_logging_array[MAX_TCP_LOGGING_COUNT];

/*
 * Function to log TCP pkts checksum changes..
 */
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
    u16 new_tcp_crc)
{
    tcp_logging_array[tcp_logging_count].seq_num      = seq_num;
    tcp_logging_array[tcp_logging_count].ack_num      = ack_num;
    tcp_logging_array[tcp_logging_count].old_ip       = old_ip;
    tcp_logging_array[tcp_logging_count].new_ip       = new_ip;
    tcp_logging_array[tcp_logging_count].old_port     = old_port;
    tcp_logging_array[tcp_logging_count].new_port     = new_port;
    tcp_logging_array[tcp_logging_count].old_ip_crc   = old_ip_crc;
    tcp_logging_array[tcp_logging_count].new_ip_crc   = new_ip_crc;
    tcp_logging_array[tcp_logging_count].old_tcp_crc  = old_tcp_crc;
    tcp_logging_array[tcp_logging_count].new_tcp_crc  = new_tcp_crc;

    tcp_logging_count++;

    if (tcp_logging_count >= MAX_TCP_LOGGING_COUNT) {
	tcp_logging_overflow = 1;
	tcp_logging_count    = 0;
    }
}

/*
 * Function to dmp TCP pkts logged..
 */
void
tcp_debug_logging_dump (void)
{
    u32 i, total_count, start_entry;

    if (tcp_logging_overflow) {
        total_count = MAX_TCP_LOGGING_COUNT;
        start_entry = tcp_logging_count;
        printf("Logging Entries Wrapped Around, displaying %d entries\n",
               total_count);
    } else {
        total_count = tcp_logging_count;
        start_entry = 0;
        printf("Displaying %d entries\n", total_count);
    }

    printf("SEQ ACK IP_O IP_N PORT_O PORT_N L3_CRC_O L3_CRC_N L4_CRC_O L4_CRC_N\n");

    for (i = 0; i < total_count; i++) {
        u32 entry = (i + start_entry) % MAX_TCP_LOGGING_COUNT;

        printf("%04d: 0x%08x 0x%08x 0x%08x 0x%08x 0x%04x 0x%04x 0x%04x 0x%04x 0x%04x 0x%04x\n",
               entry, 
               tcp_logging_array[entry].seq_num,
               tcp_logging_array[entry].ack_num,
               tcp_logging_array[entry].old_ip,
               tcp_logging_array[entry].new_ip,
               tcp_logging_array[entry].old_port,
               tcp_logging_array[entry].new_port,
               tcp_logging_array[entry].old_ip_crc,
               tcp_logging_array[entry].new_ip_crc,
               tcp_logging_array[entry].old_tcp_crc,
               tcp_logging_array[entry].new_tcp_crc);
    }
}

/*
 * Function to enable TCP logging
 */
void
tcp_debug_logging_enable_disable (u32 enable_flag)
{
    switch (enable_flag) { 

    case TCP_LOGGING_DISABLE:
        if (tcp_logging_enable_flag == TCP_LOGGING_DISABLE) {
            printf("\nTCP Logging ALREADY DISABLED\n");
        } else {
            printf("\nTCP Logging DISABLED\n");
        }
        tcp_logging_enable_flag = 0;
        break;

    case TCP_LOGGING_ENABLE:
        if (tcp_logging_enable_flag == TCP_LOGGING_ENABLE) {
            printf("\nTCP Logging ALREADY ENABLED\n");
        } else {
	    tcp_logging_enable_flag = 1;
	    tcp_logging_count    = 0;
	    tcp_logging_overflow = 0;

            printf("\nTCP Logging ENABLED\n");
        }
        break;

    case TCP_LOGGING_PACKET_DUMP:
        tcp_debug_logging_dump();
        break;

    case TCP_LOGGING_SUMMARY_DUMP:
    default:
        printf("\ntcp_logging_enable_flag %d, tcp_log_count %d\n",
               tcp_logging_enable_flag, tcp_logging_count);
        printf("To Enable TCP LOGGING provide a flag value of %d\n",
	       TCP_LOGGING_ENABLE);
        break;
    }
}

void hex_dump (u8 * p, int len) {
    int i;
    for (i=0;i<len;i++) {
        if(i && (i & 0x3 ) == 0) printf(" ");
        if(i && (i & 0xf ) == 0) printf("\n");
        PLATFORM_DEBUG_PRINT("%02X ", p[i]);
    }
    PLATFORM_DEBUG_PRINT("\n");
}

void
print_icmp_pkt (ipv4_header *ip)
{
    u32 i, total_len;

    u8 *pkt = (u8 *) ip;

    total_len = clib_net_to_host_u16(ip->total_len_bytes);

    printf("\n======== PRINTING PKT START======\n");
    printf("======== IP PACKET LEN %d ===========\n", total_len);
    for (i=0; i < 20; i++) {
       printf(" %02X ", *(pkt + i));
    }

    printf("\n======== ICMP HEADER =================\n");
    for (i=20; i < 28; i++) {
       printf(" %02X ", *(pkt + i));
    }

    printf("\n======== ICMP BODY ===================\n");
    for (i=28; i < total_len; i++) {
       printf(" %02X ", *(pkt + i));
    }

    printf("\n======== PRINTING PKT END =======\n");
}

void
print_udp_pkt (ipv4_header *ip)
{
    u32 i, total_len, udp_len;

    u8 *pkt = (u8 *) ip;

    total_len = clib_net_to_host_u16(ip->total_len_bytes);
    udp_len = total_len - 20;

    printf("\n======== PRINTING PKT START======\n");
    printf("======== IP PACKET LEN %d ===========\n", total_len);
    for (i=0; i < 20; i++) {
       printf(" %02X ", *(pkt + i));
    }
    printf("\n======== UDP PSEUDO HEADER ==========\n");
    for (i=12; i < 20; i++) {
       printf(" %02X ", *(pkt + i));
    }
    printf(" 00 11 %02X %02X ", udp_len >> 8, udp_len & 0xff);

    printf("\n======== UDP HEADER =================\n");
    for (i=20; i < 28; i++) {
       printf(" %02X ", *(pkt + i));
    }
    printf("\n======== UDP BODY ===================\n");
    for (i=28; i < total_len; i++) {
       printf(" %02X ", *(pkt + i));
    }

    printf("\n======== PRINTING PKT END =======\n");
}

void
print_tcp_pkt (ipv4_header *ip)
{
    u32 i, total_len, tcp_len;

    u8 *pkt = (u8 *) ip;

    total_len = clib_net_to_host_u16(ip->total_len_bytes);
    tcp_len = total_len - 20;

    printf("\n======== PRINTING PKT START======\n");
    printf("======== IP PACKET LEN %d ===========\n", total_len);
    for (i=0; i < 20; i++) {
       printf(" %02X ", *(pkt + i));
    }
    printf("\n======== TCP PSEUDO HEADER ==========\n");
    for (i=12; i < 20; i++) {
       printf(" %02X ", *(pkt + i));
    }
    printf(" 00 06 %02X %02X ", tcp_len >> 8, tcp_len & 0xff);

    printf("\n======== TCP HEADER =================\n");
    for (i=20; i < 40; i++) {
       printf(" %02X ", *(pkt + i));
    }
    printf("\n======== TCP BODY ===================\n");
    for (i=40; i < total_len; i++) {
       printf(" %02X ", *(pkt + i));
    }

    printf("\n======== PRINTING PKT END =======\n");
}

/* IN: ipv4 and tcp header pointer,
 *     new ipv4 addr and port value
 *     main db index for accessing per vrf mss value 
 * DO:
 *     NAT
 *     mss adjust if needed
 *     ip & tcp checksum update (incremental)
 */ 

inline void tcp_in2out_nat_mss_n_checksum (ipv4_header * ip, 
                                           tcp_hdr_type * tcp, 
                                           u32 ipv4_addr, 
                                           u16 port,
                                           cnat_main_db_entry_t * db)
{
    u8 *mss_ptr;
    u8 check_mss = 0;
    u16 mss_old, mss_new;
    cnat_vrfmap_t * vrf_map_p;

    cnat_v4_recalculate_tcp_checksum(ip,
                                     tcp,
                                     &(ip->src_addr),
                                     &(tcp->src_port),
                                     ipv4_addr,
                                     port);
    u16 frag_offset =
        clib_net_to_host_u16(ip->frag_flags_offset);

    if(PREDICT_FALSE(frag_offset & IP_FRAG_OFFSET_MASK)) {
        return; /* No TCP Header at all */
    }

    /*
     * check SYN bit and if options field is present
     * If yes, proceed to extract the options and get TCP MSS value
     */
    check_mss = ((tcp->flags & TCP_FLAG_SYN) && 
                 (((tcp->hdr_len>>4) << 2) > sizeof(tcp_hdr_type)));

    if (PREDICT_FALSE(check_mss)) {

	/* get per VRF mss config */
        if(PREDICT_FALSE(db->flags & (CNAT_DB_DSLITE_FLAG))) {
            mss_new = dslite_table_db_ptr[db->dslite_nat44_inst_id].tcp_mss;
        } else {
	    vrf_map_p = cnat_map_by_vrf + db->vrfmap_index;
	    mss_new = vrf_map_p->tcp_mss;
        }
        DSLITE_PRINTF(1, "Check MSS true..%u\n", mss_new);
	/*
	 * If TCP MSS is not configured, skip the MSS checks
	 */
	if (PREDICT_FALSE(mss_new != V4_TCP_MSS_NOT_CONFIGURED_VALUE)) {

	    /* if mss_ptr != NULL, then it points to MSS option */
	    mss_ptr = tcp_findoption(tcp, TCP_OPTION_MSS);

	    /* 
	     * TCP option field: | kind 1B | len 1B | value 2B|  
	     *    where kind != [0,1] 
	     */
	    if (PREDICT_TRUE(mss_ptr && (mss_ptr[1] == 4))) {

		u16 *ptr = (u16*)(mss_ptr + 2);

		mss_old = clib_net_to_host_u16(*ptr);

		if (PREDICT_FALSE(mss_old > mss_new)) {
		    u32 sum32;
		    u16 mss_old_r, old_tcp_checksum_r;

		    *ptr = clib_host_to_net_u16(mss_new);

		    mss_old_r = ~mss_old;

		    old_tcp_checksum_r =
		        ~clib_net_to_host_u16(tcp->tcp_checksum);

		    /*
		     * Revise the TCP checksum
		     */
		    sum32 = old_tcp_checksum_r + mss_old_r + mss_new;
		    FILL_CHECKSUM(tcp->tcp_checksum, sum32)

		    if (PREDICT_FALSE(tcp_logging_enable_flag)) {
                        tcp_debug_logging(
                            clib_net_to_host_u32(tcp->seq_num),
                            clib_net_to_host_u32(tcp->ack_num),
                            0,
                            0,
                            mss_old,
                            mss_new,
                            0,
                            0,
                            ~old_tcp_checksum_r,
                            clib_net_to_host_u16(tcp->tcp_checksum));
		    }
		}
	    }
        }
    }
}

u32 get_my_svi_intf_ip_addr() {
    return 0x01010101;
}
