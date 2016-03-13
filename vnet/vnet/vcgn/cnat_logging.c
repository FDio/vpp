/*
 *------------------------------------------------------------------
 * cnat_logging.c 
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

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vppinfra/error.h>
#include <vnet/buffer.h>
#include <vnet/ip/ip.h>
#include <vnet/ip/ip4.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/format.h>
#include <vnet/ip/udp.h>


#include "cnat_config.h"
#include "cnat_global.h"
#include "cnat_v4_functions.h"
#include "tcp_header_definitions.h"
#include "cnat_v4_ftp_alg.h"
#include "cnat_logging.h"
#include "platform_common.h"

#define CNAT_NFV9_DEBUG_CODE 2
#if CNAT_NFV9_DEBUG_CODE > 3

#define NFV9_COND if ((my_instance_number != 0) && (my_instance_number != 15))

#define NFV9_DEBUG_PRINTF1(a) NFV9_COND printf(a);
#define NFV9_DEBUG_PRINTF2(a, b) NFV9_COND printf(a, b);
#define NFV9_DEBUG_PRINTF3(a, b, c) NFV9_COND printf(a, b, c);
#define NFV9_DEBUG_PRINTF4(a, b, c, d) NFV9_COND printf(a, b, c, d);

#else

#define NFV9_DEBUG_PRINTF1(a) 
#define NFV9_DEBUG_PRINTF2(a, b)
#define NFV9_DEBUG_PRINTF3(a, b, c)
#define NFV9_DEBUG_PRINTF4(a, b, c, d)

#endif

static void cnat_nfv9_insert_ingress_vrfid_name_record(cnat_nfv9_logging_info_t *nfv9_logging_info, u16 index);
void cnat_nfv9_ingress_vrfid_name_mapping_create(
                cnat_nfv9_logging_info_t *nfv9_logging_info);


cnat_nfv9_global_info_t cnat_nfv9_global_info;

cnat_nfv9_template_t cnat_nfv9_template_info;

#define CNAT_NFV9_OPTION_TEMPLATE cnat_nfv9_template_info.cnat_nfv9_option_template

u16 cnat_template_id[MAX_RECORDS] =
  {0, CNAT_NFV9_ADD_TEMPLATE_ID, CNAT_NFV9_DEL_TEMPLATE_ID, 
   CNAT_NFV9_NAT64_ADD_BIB_TEMPLATE_ID,CNAT_NFV9_NAT64_DEL_BIB_TEMPLATE_ID,
   CNAT_NFV9_NAT64_ADD_SESSION_TEMPLATE_ID, 
   CNAT_NFV9_NAT64_DEL_SESSION_TEMPLATE_ID,
   CNAT_NFV9_DS_LITE_ADD_TEMPLATE_ID,
   CNAT_NFV9_DS_LITE_DEL_TEMPLATE_ID
#ifndef NO_BULK_LOGGING
    , CNAT_NFV9_NAT44_BULK_ADD_TEMPLATE_ID,
    CNAT_NFV9_NAT44_BULK_DEL_TEMPLATE_ID,
    CNAT_NFV9_DS_LITE_BULK_ADD_TEMPLATE_ID,
    CNAT_NFV9_DS_LITE_BULK_DEL_TEMPLATE_ID
#endif /* #ifndef NO_BULK_LOGGING */
    , CNAT_NFV9_INGRESS_VRF_ID_NAME_TEMPLATE_ID,
   CNAT_NFV9_NAT44_ADD_SESSION_TEMPLATE_ID,
   CNAT_NFV9_NAT44_DEL_SESSION_TEMPLATE_ID,
   CNAT_NFV9_DS_LITE_ADD_SESSION_TEMPLATE_ID,
   CNAT_NFV9_DS_LITE_DEL_SESSION_TEMPLATE_ID
   };

/*
 * Logging information structures
 */
cnat_nfv9_logging_info_t cnat_default_nfv9_logging_info;
cnat_nfv9_logging_info_t *cnat_nfv9_logging_info_pool;
#define NFV9_SERVER_POOL_SIZE   16
nfv9_server_info_t *nfv9_server_info_pool;

u32 nfv9_src_id = 0;

u32
cnat_get_sys_up_time_in_ms (void)
{
    vlib_main_t * vm = vlib_get_main();
    u32 cnat_curr_time;

    cnat_curr_time = (u32)vlib_time_now (vm);
    return cnat_curr_time;
}

void
cnat_dump_time_change_logs (void)
{
    return;
}

inline void cnat_nfv9_handle_sys_time_change(time_t current_unix_time)
{
    return;
    #if 0
    cnat_handle_sys_time_change(current_unix_time);
    #endif
}

void cnat_nfv9_update_sys_time_change()
{
    cnat_nfv9_logging_info_t *my_nfv9_logging_info = NULL;
    pool_foreach (my_nfv9_logging_info, cnat_nfv9_logging_info_pool, ({
        nfv9_server_info_t *server =  nfv9_server_info_pool +
            my_nfv9_logging_info->server_index;
        server->last_template_sent_time = 0;
        }));
}

void nfv9_params_show(u32 logging_index)
{
    cnat_nfv9_logging_info_t *log_info;
    if(logging_index == EMPTY) {
        PLATFORM_DEBUG_PRINT("\nNetflow logging not configured\n");
        return;
    }
    
    log_info = cnat_nfv9_logging_info_pool + logging_index;
    nfv9_server_info_t *server __attribute__((unused)) 
        =  nfv9_server_info_pool + log_info->server_index;
    

    PLATFORM_DEBUG_PRINT("\nNetflow parameters --\n");
    PLATFORM_DEBUG_PRINT("Server index %d IPV4 address: %x, port %d, max log size %d\n", 
        log_info->server_index, server->ipv4_address,
        server->port, log_info->max_length_minus_max_record_size);

    PLATFORM_DEBUG_PRINT("Server ref count %d Refresh rate %d timeout rate %d\n",
        server->ref_count, server->refresh_rate,
        server->timeout_rate);
        
}

/*
 * Code to dump NFV9 packets before they are sent
 */
void
cnat_nfv9_dump_logging_context (u32 value1, 
                                cnat_nfv9_logging_info_t *nfv9_logging_info,
				u32 value2)
{
    u8 *pkt_ptr;
    u32 i;
    u32 next_nfv9_template_data_index = 0xffff;
    u32 next_data_flow_index = 0xffff;
    u32 next_data_record = 0xffff;
    u32 data_record_size = 0;
    vlib_main_t                  *vm =  vlib_get_main();

    nfv9_server_info_t *server =  nfv9_server_info_pool + 
        nfv9_logging_info->server_index;

    vlib_cli_output(vm,"\nDumping %s packet at locn %d: time 0x%x", 
	    (value2 == 1) ? "CURRENT" : "QUEUED",
            value1,
	    cnat_nfv9_get_unix_time_in_seconds());

    vlib_cli_output(vm, "\ni_vrf 0x%x, ip_address 0x%x, port %d",
             nfv9_logging_info->i_vrf,
             server->ipv4_address,
             server->port);

    vlib_cli_output(vm,"\nseq_num %d",
             server->sequence_num);

    vlib_cli_output(vm,"\nlast_template_sent time 0x%x, pkts_since_last_template %d",
             server->last_template_sent_time,
             server->pkts_since_last_template);

    vlib_cli_output(vm, "\npkt_len %d, add_rec_len %d, del_rec_len %d, total_rec_count %d",
             nfv9_logging_info->pkt_length,
             nfv9_logging_info->record_length[NAT44_ADD_RECORD],
             nfv9_logging_info->record_length[NAT44_DEL_RECORD],
             nfv9_logging_info->total_record_count);

    vlib_cli_output(vm,"\nbulk_add_rec_len %d, bulk_del_rec_len %d",
             nfv9_logging_info->record_length[NAT44_BULK_ADD_RECORD],
             nfv9_logging_info->record_length[NAT44_BULK_DEL_RECORD]);

    vlib_cli_output(vm,"\ncurr_logging_ctx 0x%p, timestamp 0x%x, queued_logging_ctx 0x%p",
             nfv9_logging_info->current_logging_context,
             nfv9_logging_info->current_logging_context_timestamp,
             nfv9_logging_info->queued_logging_context);

    vlib_cli_output(vm,"\nnfv9_hdr 0x%p, tmpl_hdr 0x%p, dataflow_hdr 0x%p",
             nfv9_logging_info->nfv9_header,
             nfv9_logging_info->nfv9_template_header,
             nfv9_logging_info->dataflow_header);

    vlib_cli_output(vm,"\nadd_rec 0x%p, del_rec 0x%p, next_data_ptr 0x%p",
             nfv9_logging_info->record[NAT44_ADD_RECORD],
             nfv9_logging_info->record[NAT44_DEL_RECORD],
             nfv9_logging_info->next_data_ptr);

    vlib_cli_output(vm,"\n");

    pkt_ptr = vlib_buffer_get_current(nfv9_logging_info->current_logging_context); 
    /*
     * Dump along with 8 bytes of SHIM header
     */
    for (i = 0; i < (nfv9_logging_info->pkt_length + CNAT_NFV9_IP_HDR_OFFSET); 
         i = i + 1) {
	u8 c1, c2, c3;
        if (i == CNAT_NFV9_IP_HDR_OFFSET) {
	    vlib_cli_output(vm,"\nIP_HEADER: \n");
	} else if (i == CNAT_NFV9_UDP_HDR_OFFSET) {
	    vlib_cli_output(vm,"\nUDP_HEADER: \n");
	} else if (i == CNAT_NFV9_HDR_OFFSET) {
	    vlib_cli_output(vm,"\nNFV9 Header: Version:Count: \n");
	} else if (i == (CNAT_NFV9_HDR_OFFSET+4)) {
	    vlib_cli_output(vm,"\nBoot_Up_Time_In_ms: \n");
	} else if (i == (CNAT_NFV9_HDR_OFFSET+8)) {
	    vlib_cli_output(vm, "\nUNIX_Time: \n");
	} else if (i == (CNAT_NFV9_HDR_OFFSET+12)) {
	    vlib_cli_output(vm,"\nSeq_Num: \n");
	} else if (i == (CNAT_NFV9_HDR_OFFSET+16)) {
	    vlib_cli_output(vm,"\nSource ID: \n");
	} else if (i == (CNAT_NFV9_HDR_OFFSET+20)) {
	    if (nfv9_logging_info->nfv9_template_header) {
		vlib_cli_output(vm,"\nNFV9 TEMPLATE HDR: \n");
		next_nfv9_template_data_index = i + 4;
	    } else {
	        next_data_flow_index = i;	
	    }
	} else if (i == (CNAT_NFV9_TEMPLATE_OFFSET+CNAT_NFV9_TEMPLATE_LENGTH)) {
	    if (nfv9_logging_info->nfv9_template_header) {
	        next_data_flow_index = i;	
	    }
	}

	if (i == next_nfv9_template_data_index) {
	    vlib_cli_output(vm,"\nNFV9 TEMPLATE DATA: \n");
	} else if (i == next_data_flow_index) {
	    if (*(pkt_ptr + i) == 0x01) {
	        if (*(pkt_ptr + i + 1) == 0x00) {
		    data_record_size = 21;
		    next_data_record = i + 4;
		    next_data_flow_index = i + *(pkt_ptr + i + 3) +
		                               *(pkt_ptr + i + 2)*0x100;
		    vlib_cli_output(vm,"\nADD_RECORD (total %d): next_data_flow_index (%d->%d)\n", (next_data_flow_index - i), i, next_data_flow_index);
	        } else if (*(pkt_ptr + i + 1) == 0x01) {
		    data_record_size = 11;
		    next_data_record = i + 4;
		    next_data_flow_index = i + *(pkt_ptr + i + 3) +
		                               *(pkt_ptr + i + 2)*0x100;
		    vlib_cli_output(vm,"\nDEL_RECORD (total %d) : next_data_flow_index (%d->%d)\n", (next_data_flow_index - i), i, next_data_flow_index);
	        } else if (*(pkt_ptr + i + 1) == 0x09) {
		    data_record_size = 20;
		    next_data_record = i + 4;
		    next_data_flow_index = i + *(pkt_ptr + i + 3) +
		                               *(pkt_ptr + i + 2)*0x100;
		    vlib_cli_output(vm,"\nBULK_ADD_RECORD (total %d) : next_data_flow_index (%d->%d)\n", (next_data_flow_index - i), i, next_data_flow_index);
	        } else if (*(pkt_ptr + i + 1) == 0x0a) {
		    data_record_size = 10;
		    next_data_record = i + 4;
		    next_data_flow_index = i + *(pkt_ptr + i + 3) +
		                               *(pkt_ptr + i + 2)*0x100;
		    vlib_cli_output(vm,"\nBULK_DEL_RECORD (total %d) : next_data_flow_index (%d->%d)\n", (next_data_flow_index - i), i, next_data_flow_index);
	        }

	    }
	} else if (i == next_data_record) {
	    vlib_cli_output(vm,"\n");
	    next_data_record += data_record_size;
	}

	c3 = *(pkt_ptr + i);

	c2 = c3 & 0xf;
	c1 = (c3 >> 4) & 0xf;


	vlib_cli_output(vm,"%c%c ", 
	        ((c1 <= 9) ? (c1 + '0') : (c1 - 10 + 'a')),
	        ((c2 <= 9) ? (c2 + '0') : (c2 - 10 + 'a')));

    }
    vlib_cli_output(vm,"\n");
}

/*
 * edt: * * cnat_nfv9_pad_added_to_an_addr
 *
 * Returns the difference (no# of bytes) between new_addr
 * & org_addr
 *
 * Argument: u8 *new_addr, u8 *org_addr
 * returns the difference
 */

static inline
int cnat_nfv9_pad_added_to_an_addr(u8 *new_addr, u8 *org_addr)
{
    uword addr1 = (uword) new_addr;
    uword addr2 = (uword) org_addr;
    return (addr1 - addr2);
}

/*
 * edt: * * cnat_nfv9_add_end_of_record_padding
 *
 * Tries to add padding to data_ptr to ensure it is word aligned
 *
 * Argument: u8 * data_ptr
 * pointer to the data pointer
 */

static inline
u8 *cnat_nfv9_add_end_of_record_padding (u8 *data_ptr)
{
    uword tmp       = (uword) data_ptr;
    uword pad_value = (uword) NFV9_PAD_VALUE;

    tmp = (tmp + pad_value) & (~pad_value);

    return ((u8 *) tmp);
}

/*
 * edt: * * cnat_nfv9_pad_end_of_record_length
 *
 * Tries to add padding to data_ptr to ensure it is word aligned
 *
 * Argument: u8 * data_ptr
 * pointer to the data pointer
 */

static inline
u16 cnat_nfv9_pad_end_of_record_length (u16 record_length)
{
    u16 pad_value = NFV9_PAD_VALUE;

    return ((record_length + pad_value) & (~pad_value));
}

/* get first interface address */
static ip4_address_t *
ip4_interface_first_address (ip4_main_t * im, u32 sw_if_index)
{
  ip_lookup_main_t * lm = &im->lookup_main;
  ip_interface_address_t * ia = 0;
  ip4_address_t * result = 0;

  foreach_ip_interface_address (lm, ia, sw_if_index,
                                1 /* honor unnumbered */,
  ({
    ip4_address_t * a = ip_interface_address_get_address (lm, ia);
    result = a;
    break;
  }));
  return result;
}

void fill_ip_n_udp_hdr (u32 ipv4_addr, u16 port, 
                       cnat_nfv9_logging_info_t *nfv9_logging_info)
{ 
    vlib_buffer_t * b0 = nfv9_logging_info->current_logging_context;
    ipv4_header    *ip_header = vlib_buffer_get_current(b0);
    udp_hdr_type_t *udp_header = (udp_hdr_type_t *)((u8*)ip_header + sizeof(ipv4_header));
    vlib_main_t                  *vm =  vlib_get_main();
    u16 ip_length __attribute__((unused));
    u16 pkt_len = nfv9_logging_info->pkt_length;
    ip4_address_t *ia0 = 0;
    u16 src_port = 0x0a0a;

    /*
     * Clear the SHIM header fields.  The PD nodes will set it
     * appropriately.
     */
    PLATFORM_MEMSET_CNAT_LOG_PKT_DATA

    /*
     * Don't need a special define for 0x45 - IP version and hdr len
     */
    ip_header->version_hdr_len_words = 0x45;
    ip_header->tos                   = 0;
    ip_header->frag_flags_offset            = 0;
    ip_header->ttl                   = 0xff;
    ip_header->protocol              = UDP_PROT;
    ip_header->dest_addr =  clib_host_to_net_u32(ipv4_addr);
    ip_length = vlib_buffer_length_in_chain (vm, b0);
    ip_header->total_len_bytes = clib_host_to_net_u16(pkt_len);
    ia0 = ip4_interface_first_address(&ip4_main, nfv9_logging_info->i_vrf_id);
    ip_header->src_addr =  ia0->as_u32;
    udp_header->src_port = clib_host_to_net_u16(src_port);
    udp_header->dest_port = clib_host_to_net_u16(port);
    udp_header->udp_checksum = 0;
    udp_header->udp_length =
        clib_host_to_net_u16(pkt_len - sizeof(ipv4_header));
    ip_header->checksum = ip4_header_checksum((ip4_header_t *)ip_header);
}

/*
 * edt: * * cnat_nfv9_fill_nfv9_ip_header
 *
 * Tries to fill the fields of the IP header before it
 * is sent to the L3 infra node.
 *
 * Argument: cnat_nfv9_logging_info_t *nfv9_logging_info
 * structure that contains the packet context
 */

static inline 
void cnat_nfv9_fill_nfv9_ip_header (cnat_nfv9_logging_info_t *nfv9_logging_info)
{
    u16             new_record_length  = 0;
    u16             orig_record_length = 0;
    vlib_buffer_t * b0 = nfv9_logging_info->current_logging_context;

    /*
     * Fill in the IP header and port number of the Netflow collector
     * The L3 Infra node will fill in the rest of the fields
     */

    nfv9_logging_info->nfv9_header->count = 
	    clib_host_to_net_u16(nfv9_logging_info->total_record_count);

    /*
     * Pad the last add/del record to ensure multiple of 4 bytes
     */

    if(nfv9_logging_info->last_record != RECORD_INVALID) {

        orig_record_length = 
           nfv9_logging_info->record_length[nfv9_logging_info->last_record];

         new_record_length = cnat_nfv9_pad_end_of_record_length(
                                              orig_record_length);

         nfv9_logging_info->dataflow_header->dataflow_length =
              clib_host_to_net_u16(new_record_length);
    } 

    /*
     * If the record is padded, ensure the padded bytes are ZERO
     */
    if (PREDICT_TRUE(new_record_length - orig_record_length)) {
        u8 *pkt_ptr = (u8 *) (b0 + nfv9_logging_info->pkt_length); 

	/*
	 * Blindly copy 3 bytes of data to Zero to avoid for loops
	 * We have sufficient padding bytes for safety and we won't
	 * go over buffer limits
	 */
        *pkt_ptr++ =  0;
        *pkt_ptr++ =  0;
        *pkt_ptr++ =  0;

        nfv9_logging_info->pkt_length += 
	    (new_record_length - orig_record_length);
    }
    nfv9_server_info_t *server =  nfv9_server_info_pool + 
        nfv9_logging_info->server_index;
    fill_ip_n_udp_hdr(server->ipv4_address, 
        server->port, nfv9_logging_info);
    /*
     * It is important to set the sw_if_index for the new buffer create
     */
    vnet_buffer(b0)->sw_if_index[VLIB_TX] = (u32)~0;

}

/*
 * edt: * * cnat_nfv9_send_queued_pkt
 *
 * Tries to send a logging pkt that has been queued earlier
 * because it could not be sent due to downstream constipation
 *
 * Argument: cnat_nfv9_logging_info_t *nfv9_logging_info
 * structure that contains the packet context
 */

static inline 
void cnat_nfv9_send_queued_pkt (cnat_nfv9_logging_info_t *nfv9_logging_info)
{
    return;
}

/*
 * edt: * * cnat_nfv9_send_pkt
 *
 * Tries to send a logging pkt.  If the packet cannot be sent
 * because of rewrite_output node cannot process it, queue
 * it temporarily and try to send it later.
 *
 * Argument: cnat_nfv9_logging_info_t *nfv9_logging_info
 * structure that contains the packet context
 */

static inline
void cnat_nfv9_send_pkt (cnat_nfv9_logging_info_t *nfv9_logging_info)
{
    cnat_nfv9_fill_nfv9_ip_header(nfv9_logging_info);

    nfv9_server_info_t *server =  nfv9_server_info_pool + 
        nfv9_logging_info->server_index;

    /* Update sequence number just before sending.
     * So that, multiple NAT44/NAT64/DSLite instances sharing a 
     * a single server instance can stamp the sequence number
     * in the right sequence (as seen by the server).
     */
    server->sequence_num += 1;
    nfv9_logging_info->nfv9_header->sequence_num  = 
	    clib_host_to_net_u32(server->sequence_num);

#if DEBUG
    cnat_nfv9_dump_logging_context (2, nfv9_logging_info, 1);
#endif
#if 0 /* commented out below */
    send_vpp3_nfv9_pkt(nfv9_logging_info);
#endif
    nfv9_logging_info->current_logging_context = NULL;
    /*
     * Increase last packet sent count
     */
     server->pkts_since_last_template++;

    /*
     * If we are sending an nfv9 tempate with this packet
     * log this timestamp
     */
     if (nfv9_logging_info->nfv9_template_header) {
         server->last_template_sent_time = 
               cnat_nfv9_get_unix_time_in_seconds();
         server->pkts_since_last_template = 0;
     }

    return;
}

/*
 * send_vpp3_nfv9_pkt: to send multiple b0 in a frame
 */

static inline
void send_vpp3_nfv9_pkt (cnat_nfv9_logging_info_t *nfv9_logging_info)
{
    vlib_node_t                  *output_node;
    vlib_main_t                  *vm =  vlib_get_main();
    vlib_frame_t                 *f;
    vlib_buffer_t                *b0; 
    u32 *to_next;
    u32 bi=0;
    ipv4_header *ip;

    //Lets check and send it to ip4-lookup node
    output_node =  vlib_get_node_by_name (vm, (u8 *) "ip4-lookup");
    f = vlib_get_frame_to_node (vm, output_node->index);
   
    if ( nfv9_logging_info->current_logging_context != NULL) {
        /* Build a pkt from whole cloth */
        b0 = nfv9_logging_info->current_logging_context;
        ip = vlib_buffer_get_current(b0);
        to_next = vlib_frame_vector_args (f);
        bi =  vlib_get_buffer_index (vm, b0);
        to_next[0] =  bi;

        f->n_vectors = 1;
        b0->current_length = clib_net_to_host_u16(ip->total_len_bytes);
        vlib_put_frame_to_node (vm, output_node->index, f);  
     }
     return;
}
/*
 * edt: * * cnat_nfv9_send_pkt_always_success
 *
 * Tries to send a logging pkt.  This cannot fail due to downstream
 * constipation because we have already checked if the rewrite_output
 * node can accept it.
 *
 * Argument: cnat_nfv9_logging_info_t *nfv9_logging_info
 * structure that contains the packet context
 *
 * Argument: vlib_node_t *output_node
 * vlib_node_t structure for rewrite_output node
 */

static inline
void cnat_nfv9_send_pkt_always_success (
                         cnat_nfv9_logging_info_t *nfv9_logging_info,
                         vlib_node_t               *output_node)
{
    nfv9_server_info_t *server =  nfv9_server_info_pool + 
        nfv9_logging_info->server_index;
    vlib_main_t * vm = vlib_get_main();

    /*
     * At this point we either have a current or queued logging context
     */
    if (PREDICT_TRUE(nfv9_logging_info->current_logging_context != NULL)) { 
        server->sequence_num += 1;
        nfv9_logging_info->nfv9_header->sequence_num  = 
	        clib_host_to_net_u32(server->sequence_num);
	    cnat_nfv9_fill_nfv9_ip_header(nfv9_logging_info);

        nfv9_logging_info->current_logging_context->current_length =
                                            nfv9_logging_info->pkt_length;
        vlib_cli_output(vm, "\nNFV9: 3. Sending Current packet\n");
#if DEBUG
       cnat_nfv9_dump_logging_context (3, nfv9_logging_info, 1);
#endif
       send_vpp3_nfv9_pkt(nfv9_logging_info);
       nfv9_logging_info->current_logging_context = NULL;
    } else {
	/*
	 * For queued logging context, nfv9_header-> count is already set
	 */
        nfv9_logging_info->queued_logging_context->current_length =
                                             nfv9_logging_info->pkt_length;
        vlib_cli_output(vm,"\nNFV9: 4. Sending Queued packet\n");
#if DEBUG
	cnat_nfv9_dump_logging_context (4, nfv9_logging_info, 2);
#endif
        send_vpp3_nfv9_pkt(nfv9_logging_info);

	nfv9_logging_info->queued_logging_context = NULL;
    }

    /*
     * NF Logging info already deleted, just free it and return
     */
    if (PREDICT_FALSE(nfv9_logging_info->deleted)) {
	pool_put(cnat_nfv9_logging_info_pool, nfv9_logging_info);
	return;
    }

    /*
     * Increase last packet sent count and timestamp
     */
    server->pkts_since_last_template++;

    /*
     * If we are sending an nfv9 tempate with this packet
     * log this timestamp
     */
    if (nfv9_logging_info->nfv9_template_header) {
	    server->last_template_sent_time = 
	    cnat_nfv9_get_unix_time_in_seconds();
	    server->pkts_since_last_template = 0;
    }
}

/*
 * edt: * * cnat_nfv9_create_logging_context
 *
 * Tries to create a logging context with packet buffer
 * to send a new logging packet
 *
 * Argument: cnat_nfv9_logging_info_t *nfv9_logging_info
 * structure that contains the nfv9 logging info and will store
 * the packet context as well.
 */

static inline
void cnat_nfv9_create_logging_context (
                              cnat_nfv9_logging_info_t      *nfv9_logging_info,
                              cnat_nfv9_template_add_flag_t  template_flag)
{
    vlib_main_t     *vm =  vlib_get_main();
    vlib_buffer_t   *b0;
    static u32       bi; 
    u8 i;

    /*
     * If queued_logging_context_index is non-EMPTY, we already have a logging
     * packet queued to be sent.  First try sending this before allocating
     * a new context.  We can have only one active packet context per
     * nfv9_logging_info structure
     */
    if (PREDICT_FALSE(nfv9_logging_info->queued_logging_context != NULL)) {
        cnat_nfv9_send_queued_pkt(nfv9_logging_info);
        /*
         * If we cannot still send the queued pkt, just return 
         * Downstream Constipation count would have increased anyway
         */
        if (nfv9_logging_info->queued_logging_context != NULL) {
	    cnat_global_counters.nfv9_logging_context_creation_deferred_count++;
	    return;
        }
    }


    /*
     * No context can be allocated, return silently
     * calling routine will handle updating the error counters
     */
    if (vlib_buffer_alloc (vm, &bi, 1) != 1) {
        vlib_cli_output(vm, "buffer allocation failure");
        return;
    }
    /* Build a  pkt from whole cloth */
    b0 = vlib_get_buffer (vm, bi);
    b0->current_data = 0;

    nfv9_server_info_t *server =  nfv9_server_info_pool + 
        nfv9_logging_info->server_index;

    nfv9_logging_info->current_logging_context = b0; 
    nfv9_logging_info->current_logging_context_timestamp =
        cnat_nfv9_get_sys_up_time_in_ms();


    nfv9_logging_info->nfv9_header = 
        (nfv9_header_t *) (vlib_buffer_get_current(b0) + 
                           (sizeof(ipv4_header)) + 
                           (sizeof(udp_hdr_type_t)));

    nfv9_logging_info->nfv9_header->version = 
	clib_host_to_net_u16(CNAT_NFV9_VERSION_NUMBER);

    nfv9_logging_info->nfv9_header->sys_up_time  = 
	clib_host_to_net_u32(cnat_nfv9_get_sys_up_time_in_ms());

    nfv9_logging_info->nfv9_header->timestamp  = 
	clib_host_to_net_u32(cnat_nfv9_get_unix_time_in_seconds());


    nfv9_logging_info->nfv9_header->source_id  = 
	clib_host_to_net_u32(nfv9_src_id);

    nfv9_logging_info->dataflow_header = 0;

    for(i = 0; i < MAX_RECORDS;i++) {
        nfv9_logging_info->record[i] = NULL;
	nfv9_logging_info->record_length[i] = 0;
    }
    nfv9_logging_info->last_record = 0;


    nfv9_logging_info->nfv9_template_header = 0;
    nfv9_logging_info->next_data_ptr = 
        (u8 *) (vlib_buffer_get_current(b0) +
               sizeof(ipv4_header) + sizeof(udp_hdr_type_t) +
               sizeof(nfv9_header_t));

    nfv9_logging_info->pkt_length = (CNAT_NFV9_TEMPLATE_OFFSET - 
                                     CNAT_NFV9_IP_HDR_OFFSET);


    /*
     * Now we have 0 records to start with
     */

    nfv9_logging_info->total_record_count = 0;

    if ((template_flag == cnat_nfv9_template_add_always) ||
        (server->pkts_since_last_template >
	              server->refresh_rate) ||
        ((cnat_nfv9_get_unix_time_in_seconds() -
          server->last_template_sent_time) >
		     server->timeout_rate)) {

	/*
	 * Send a new template
	 */
       nfv9_logging_info->nfv9_template_header = 
           (cnat_nfv9_template_t *) nfv9_logging_info->next_data_ptr;

       clib_memcpy(nfv9_logging_info->nfv9_template_header,
              &cnat_nfv9_template_info,
              sizeof(cnat_nfv9_template_info));

       /*
        * Templates are sent irrespective of particular service-type config
        */
       nfv9_logging_info->total_record_count = MAX_RECORDS - 1;

       nfv9_logging_info->pkt_length += CNAT_NFV9_TEMPLATE_LENGTH;

       /*
        * Set the data pointer beyond the template field
        */
       nfv9_logging_info->next_data_ptr = 
           (u8 *) (nfv9_logging_info->nfv9_template_header + 1);
        /*
         * Setting template_sent flag as TRUE. this will be checked in
         * handle_vrfid_name_mapping()
         */
        server->template_sent = TEMPLATE_SENT_TRUE;
    }
}

void cnat_nfv9_record_create (
       	cnat_nfv9_logging_info_t *nfv9_logging_info, u16 cur_record)
{
    int byte_diff = 0;
    u16 last_record = nfv9_logging_info->last_record;

    if(last_record != 0 && last_record != cur_record) {
        u16 orig_length, new_length;

        orig_length = nfv9_logging_info->record_length[last_record];
        new_length  = cnat_nfv9_pad_end_of_record_length(orig_length);

        /*
         * The padding bytes are required after the last record
         * Ensure length of last record accounts for padding bytes
         */
        nfv9_logging_info->dataflow_header->dataflow_length =
            clib_host_to_net_u16(new_length);

        /*
         * Since we are working on the del record, set add record to 0
         */
        nfv9_logging_info->record[last_record] = 0;

        nfv9_logging_info->record_length[last_record] = 0;

        nfv9_logging_info->last_record = 0;
    }

    nfv9_logging_info->last_record = cur_record;

    /*
     * The padding bytes are required after the last record
     * Ensure that we skip over the padding bytes
     */
    nfv9_logging_info->dataflow_header = (nfv9_dataflow_record_header_t *)
        cnat_nfv9_add_end_of_record_padding(nfv9_logging_info->next_data_ptr);
    /*
     * Get the difference 
     */       
    byte_diff = cnat_nfv9_pad_added_to_an_addr(
                        (u8 *)nfv9_logging_info->dataflow_header,
                        nfv9_logging_info->next_data_ptr); 
    if(byte_diff > 0) {
        /*
         * Update the packet length to account for the pad bytes
         */
        nfv9_logging_info->pkt_length += byte_diff;           
        u8 *pkt_ptr =  nfv9_logging_info->next_data_ptr;

        /*
         * Blindly copy 3 bytes of data to Zero to avoid for loops
         * We have sufficient padding bytes for safety and we won't
         * go over buffer limits
         */
        *pkt_ptr++ =  0;
        *pkt_ptr++ =  0;
        *pkt_ptr++ =  0;
    }
    /*
     * Initialize the template_id and the length of the add record
     */
    nfv9_logging_info->dataflow_header->dataflow_template_id =
        clib_host_to_net_u16(cnat_template_id[cur_record]);

    nfv9_logging_info->record[cur_record]  =
        (u8 *) (nfv9_logging_info->dataflow_header + 1);

    nfv9_logging_info->record_length[cur_record] =
        CNAT_NFV9_DATAFLOW_RECORD_HEADER_LENGTH;

    /*
     * Update the length of the total NFV9 record
     */
    nfv9_logging_info->pkt_length +=
    CNAT_NFV9_DATAFLOW_RECORD_HEADER_LENGTH;

    /*
     * Set the data pointer beyond the dataflow header field
     */
    nfv9_logging_info->next_data_ptr =
        (u8 *) (nfv9_logging_info->dataflow_header + 1);

}

static void cnat_nfv9_insert_add_record(
        cnat_nfv9_logging_info_t *nfv9_logging_info,
        cnat_main_db_entry_t *db,
        cnat_vrfmap_t *vrfmap)
{
    u16 my_proto_mask;
    u8 my_protocol;
    nfv9_add_record_t nfv9_logging_add_record;
    if (PREDICT_FALSE(nfv9_logging_info->record[NAT44_ADD_RECORD] == NULL)) {
        cnat_nfv9_record_create(nfv9_logging_info, NAT44_ADD_RECORD);
    }

   /*
    * We should definitely have add_record now, no need to sanitize
    */

    nfv9_logging_add_record.inside_vrf_id =
        clib_host_to_net_u32(vrfmap->i_vrf_id);

    nfv9_logging_add_record.outside_vrf_id =
        clib_host_to_net_u32(vrfmap->o_vrf_id);

    nfv9_logging_add_record.inside_ip_addr =
        clib_host_to_net_u32(db->in2out_key.k.ipv4);
    nfv9_logging_add_record.outside_ip_addr =
        clib_host_to_net_u32(db->out2in_key.k.ipv4);

    nfv9_logging_add_record.inside_ip_port =
        clib_host_to_net_u16(db->in2out_key.k.port);
    nfv9_logging_add_record.outside_ip_port =
        clib_host_to_net_u16(db->out2in_key.k.port);

    my_proto_mask = db->in2out_key.k.vrf & CNAT_PRO_MASK;
    my_protocol = ((my_proto_mask == CNAT_UDP) ? UDP_PROT :
                ((my_proto_mask == CNAT_TCP) ? TCP_PROT :
                ((my_proto_mask == CNAT_ICMP) ? ICMP_PROT : GRE_PROT)));

    nfv9_logging_add_record.protocol = my_protocol;

    clib_memcpy(nfv9_logging_info->record[NAT44_ADD_RECORD], 
            &nfv9_logging_add_record, CNAT_NFV9_ADD_RECORD_LENGTH);

    nfv9_logging_info->record_length[NAT44_ADD_RECORD] 
            += CNAT_NFV9_ADD_RECORD_LENGTH;

    nfv9_logging_info->pkt_length += CNAT_NFV9_ADD_RECORD_LENGTH;

    nfv9_logging_info->record[NAT44_ADD_RECORD] 
                      += CNAT_NFV9_ADD_RECORD_LENGTH;
    nfv9_logging_info->next_data_ptr = 
                      nfv9_logging_info->record[NAT44_ADD_RECORD];

    nfv9_logging_info->dataflow_header->dataflow_length =
	clib_host_to_net_u32(
        nfv9_logging_info->record_length[NAT44_ADD_RECORD]);

}


static void cnat_nfv9_ds_lite_insert_add_record(
        cnat_nfv9_logging_info_t *nfv9_logging_info,
        cnat_main_db_entry_t *db,
        dslite_table_entry_t *dslite_entry)
{

    nfv9_ds_lite_add_record_t   nfv9_logging_add_record = {0};
    cnat_user_db_entry_t        *udb = NULL;
    u16     my_proto_mask;
    u8      my_protocol;

    udb = cnat_user_db + db->user_index; 
    if (PREDICT_FALSE(!udb)) {
        return;
    }
    if (PREDICT_FALSE(nfv9_logging_info->record[DS_LITE_ADD_RECORD] == NULL)) {
        cnat_nfv9_record_create(nfv9_logging_info, DS_LITE_ADD_RECORD);
    }
    /*
     * We should definitely have add_record now, no need to sanitize
     */
    nfv9_logging_add_record.inside_vrf_id =
		    clib_host_to_net_u32(dslite_entry->i_vrf_id);
    nfv9_logging_add_record.outside_vrf_id = 
		    clib_host_to_net_u32(dslite_entry->o_vrf_id);

#ifdef DSLITE_USER_IPV4
    nfv9_logging_add_record.inside_ip_addr = 
		    clib_host_to_net_u32(db->in2out_key.k.ipv4);
#else
    /*
     * Inside ipv4 address is sent as 0.0.0.0 for ds-lite case as 
     * ipv6 is user here. 
     */
    nfv9_logging_add_record.inside_ip_addr = 0; 
#endif

    nfv9_logging_add_record.inside_v6_src_addr[0] = 
		    clib_host_to_net_u32(udb->ipv6[0]);
    nfv9_logging_add_record.inside_v6_src_addr[1] = 
		    clib_host_to_net_u32(udb->ipv6[1]);
    nfv9_logging_add_record.inside_v6_src_addr[2] = 
		    clib_host_to_net_u32(udb->ipv6[2]);
    nfv9_logging_add_record.inside_v6_src_addr[3] = 
		    clib_host_to_net_u32(udb->ipv6[3]);

    nfv9_logging_add_record.outside_ip_addr = 
		    clib_host_to_net_u32(db->out2in_key.k.ipv4);

    nfv9_logging_add_record.inside_ip_port = 
		    clib_host_to_net_u16(db->in2out_key.k.port);
    nfv9_logging_add_record.outside_ip_port = 
		    clib_host_to_net_u16(db->out2in_key.k.port);

    my_proto_mask = db->in2out_key.k.vrf & CNAT_PRO_MASK;

    my_protocol = ((my_proto_mask == CNAT_UDP) ? UDP_PROT :
		   ((my_proto_mask == CNAT_TCP) ? TCP_PROT :
		   ((my_proto_mask == CNAT_ICMP) ? ICMP_PROT : 0)));
    nfv9_logging_add_record.protocol = my_protocol;

    clib_memcpy(nfv9_logging_info->record[DS_LITE_ADD_RECORD], 
            &nfv9_logging_add_record, CNAT_NFV9_DS_LITE_ADD_RECORD_LENGTH);

    nfv9_logging_info->record_length[DS_LITE_ADD_RECORD] 
                                  += CNAT_NFV9_DS_LITE_ADD_RECORD_LENGTH;

    nfv9_logging_info->pkt_length += CNAT_NFV9_DS_LITE_ADD_RECORD_LENGTH;
    nfv9_logging_info->total_record_count += 1;

    nfv9_logging_info->record[DS_LITE_ADD_RECORD] 
                      += CNAT_NFV9_DS_LITE_ADD_RECORD_LENGTH;
    nfv9_logging_info->next_data_ptr = 
                         nfv9_logging_info->record[DS_LITE_ADD_RECORD];

    nfv9_logging_info->dataflow_header->dataflow_length =
	clib_host_to_net_u32(
        nfv9_logging_info->record_length[DS_LITE_ADD_RECORD]);
}


static void cnat_nfv9_ds_lite_insert_del_record(
        cnat_nfv9_logging_info_t *nfv9_logging_info,
        cnat_main_db_entry_t *db,
        dslite_table_entry_t *dslite_entry)
{

    nfv9_ds_lite_del_record_t   nfv9_logging_del_record = {0};
    cnat_user_db_entry_t        *udb = NULL;
    u16     my_proto_mask;
    u8      my_protocol;

    udb = cnat_user_db + db->user_index; 
    if (PREDICT_FALSE(!udb)) {
        return;
    }
    if (PREDICT_FALSE(nfv9_logging_info->record[DS_LITE_DEL_RECORD] == NULL)) {
        cnat_nfv9_record_create(nfv9_logging_info, DS_LITE_DEL_RECORD);
    }
    /*
     * We should definitely have a del record now.
     * No need to sanitize
     */
    nfv9_logging_del_record.inside_vrf_id = 
		    clib_host_to_net_u32(dslite_entry->i_vrf_id);

#ifdef DSLITE_USER_IPV4
    nfv9_logging_del_record.inside_ip_addr = 
		    clib_host_to_net_u32(db->in2out_key.k.ipv4);
#else
    /*
     * Inside ipv4 address is sent as 0.0.0.0 for ds-lite case as 
     * ipv6 is user here. 
     */
    nfv9_logging_del_record.inside_ip_addr = 0;
#endif

    nfv9_logging_del_record.inside_v6_src_addr[0] = 
		    clib_host_to_net_u32(udb->ipv6[0]);
    nfv9_logging_del_record.inside_v6_src_addr[1] = 
		    clib_host_to_net_u32(udb->ipv6[1]);
    nfv9_logging_del_record.inside_v6_src_addr[2] = 
		    clib_host_to_net_u32(udb->ipv6[2]);
    nfv9_logging_del_record.inside_v6_src_addr[3] = 
		    clib_host_to_net_u32(udb->ipv6[3]);

    nfv9_logging_del_record.inside_ip_port = 
		    clib_host_to_net_u16(db->in2out_key.k.port);

    my_proto_mask = db->in2out_key.k.vrf & CNAT_PRO_MASK;

    my_protocol = ((my_proto_mask == CNAT_UDP) ? UDP_PROT :
		   ((my_proto_mask == CNAT_TCP) ? TCP_PROT :
		   ((my_proto_mask == CNAT_ICMP) ? ICMP_PROT : 0)));
    nfv9_logging_del_record.protocol = my_protocol;

    clib_memcpy(nfv9_logging_info->record[DS_LITE_DEL_RECORD], 
            &nfv9_logging_del_record, CNAT_NFV9_DS_LITE_DEL_RECORD_LENGTH);

    nfv9_logging_info->record_length[DS_LITE_DEL_RECORD] += 
                             CNAT_NFV9_DS_LITE_DEL_RECORD_LENGTH;

    nfv9_logging_info->pkt_length += CNAT_NFV9_DS_LITE_DEL_RECORD_LENGTH;
    nfv9_logging_info->total_record_count += 1;

    nfv9_logging_info->record[DS_LITE_DEL_RECORD] 
                                += CNAT_NFV9_DS_LITE_DEL_RECORD_LENGTH;
    nfv9_logging_info->next_data_ptr = 
            nfv9_logging_info->record[DS_LITE_DEL_RECORD];

    nfv9_logging_info->dataflow_header->dataflow_length =
	clib_host_to_net_u32(
           nfv9_logging_info->record_length[DS_LITE_DEL_RECORD]);
}

#ifndef NO_BULK_LOGGING
static void cnat_nfv9_insert_bulk_add_record(
        cnat_nfv9_logging_info_t *nfv9_logging_info,
        cnat_main_db_entry_t *db,
        cnat_vrfmap_t *vrfmap,
        int bulk_alloc_start_port)
{
    nfv9_bulk_add_record_t nfv9_logging_bulk_add_record;
    bulk_alloc_size_t bulk_size = BULKSIZE_FROM_VRFMAP(vrfmap);
    if (PREDICT_FALSE(nfv9_logging_info->record[NAT44_BULK_ADD_RECORD] == NULL)) {
        cnat_nfv9_record_create(nfv9_logging_info, NAT44_BULK_ADD_RECORD);
    }

   /*
    * We should definitely have add_record now, no need to sanitize
    */

    nfv9_logging_bulk_add_record.inside_vrf_id =
        clib_host_to_net_u32(vrfmap->i_vrf_id);
    nfv9_logging_bulk_add_record.outside_vrf_id =
        clib_host_to_net_u32(vrfmap->o_vrf_id);

    nfv9_logging_bulk_add_record.inside_ip_addr =
        clib_host_to_net_u32(db->in2out_key.k.ipv4);
    nfv9_logging_bulk_add_record.outside_ip_addr =
        clib_host_to_net_u32(db->out2in_key.k.ipv4);

    nfv9_logging_bulk_add_record.outside_ip_port_start =
        clib_host_to_net_u16(bulk_alloc_start_port);
    nfv9_logging_bulk_add_record.outside_ip_port_end =
        clib_host_to_net_u16(bulk_alloc_start_port + bulk_size -1);

    clib_memcpy(nfv9_logging_info->record[NAT44_BULK_ADD_RECORD], 
            &nfv9_logging_bulk_add_record, CNAT_NFV9_BULK_ADD_RECORD_LENGTH);

    nfv9_logging_info->record_length[NAT44_BULK_ADD_RECORD] 
            += CNAT_NFV9_BULK_ADD_RECORD_LENGTH;

    nfv9_logging_info->pkt_length += CNAT_NFV9_BULK_ADD_RECORD_LENGTH;

    nfv9_logging_info->record[NAT44_BULK_ADD_RECORD] 
                      += CNAT_NFV9_BULK_ADD_RECORD_LENGTH;
    nfv9_logging_info->next_data_ptr = 
                      nfv9_logging_info->record[NAT44_BULK_ADD_RECORD];

    nfv9_logging_info->dataflow_header->dataflow_length =
	clib_host_to_net_u32(
        nfv9_logging_info->record_length[NAT44_BULK_ADD_RECORD]);

}


static void cnat_nfv9_ds_lite_insert_bulk_add_record(
        cnat_nfv9_logging_info_t *nfv9_logging_info,
        cnat_main_db_entry_t *db,
        dslite_table_entry_t *dslite_entry,
        int bulk_alloc_start_port)
{

    nfv9_ds_lite_bulk_add_record_t  nfv9_logging_bulk_add_record = {0};
    cnat_user_db_entry_t            *udb = NULL;
    bulk_alloc_size_t               bulk_size = BULKSIZE_FROM_VRFMAP(dslite_entry);

    if (PREDICT_FALSE(nfv9_logging_info->record[DS_LITE_BULK_ADD_RECORD] == NULL)) {
        cnat_nfv9_record_create(nfv9_logging_info, DS_LITE_BULK_ADD_RECORD);
    }
    udb = cnat_user_db + db->user_index; 
    if (PREDICT_FALSE(!udb)) {
        return;
    }
    /*
     * We should definitely have add_record now, no need to sanitize
     */

    nfv9_logging_bulk_add_record.inside_vrf_id =
        clib_host_to_net_u32(dslite_entry->i_vrf_id);
    nfv9_logging_bulk_add_record.outside_vrf_id =
        clib_host_to_net_u32(dslite_entry->o_vrf_id);

#ifdef DSLITE_USER_IPV4
    nfv9_logging_bulk_add_record.inside_ip_addr =
        clib_host_to_net_u32(db->in2out_key.k.ipv4);
#else
    /*
     * Inside ipv4 address is sent as 0.0.0.0 for ds-lite case as 
     * ipv6 is user here. 
     */
    nfv9_logging_bulk_add_record.inside_ip_addr = 0;
#endif

    nfv9_logging_bulk_add_record.inside_v6_src_addr[0] = 
		    clib_host_to_net_u32(udb->ipv6[0]);
    nfv9_logging_bulk_add_record.inside_v6_src_addr[1] = 
		    clib_host_to_net_u32(udb->ipv6[1]);
    nfv9_logging_bulk_add_record.inside_v6_src_addr[2] = 
		    clib_host_to_net_u32(udb->ipv6[2]);
    nfv9_logging_bulk_add_record.inside_v6_src_addr[3] = 
		    clib_host_to_net_u32(udb->ipv6[3]);

    nfv9_logging_bulk_add_record.outside_ip_addr =
        clib_host_to_net_u32(db->out2in_key.k.ipv4);

    nfv9_logging_bulk_add_record.outside_ip_port_start =
        clib_host_to_net_u16(bulk_alloc_start_port);
    nfv9_logging_bulk_add_record.outside_ip_port_end =
        clib_host_to_net_u16(bulk_alloc_start_port + bulk_size -1);

    clib_memcpy(nfv9_logging_info->record[DS_LITE_BULK_ADD_RECORD], 
            &nfv9_logging_bulk_add_record, CNAT_NFV9_DS_LITE_BULK_ADD_RECORD_LENGTH);

    nfv9_logging_info->record_length[DS_LITE_BULK_ADD_RECORD] 
            += CNAT_NFV9_DS_LITE_BULK_ADD_RECORD_LENGTH;

    nfv9_logging_info->pkt_length += CNAT_NFV9_DS_LITE_BULK_ADD_RECORD_LENGTH;
    nfv9_logging_info->total_record_count += 1;
    nfv9_logging_info->record[DS_LITE_BULK_ADD_RECORD] 
                      += CNAT_NFV9_DS_LITE_BULK_ADD_RECORD_LENGTH;
    nfv9_logging_info->next_data_ptr = 
                      nfv9_logging_info->record[DS_LITE_BULK_ADD_RECORD];
    nfv9_logging_info->dataflow_header->dataflow_length =
	clib_host_to_net_u32(
        nfv9_logging_info->record_length[DS_LITE_BULK_ADD_RECORD]);
}


static void cnat_nfv9_ds_lite_insert_bulk_del_record(
        cnat_nfv9_logging_info_t *nfv9_logging_info,
        cnat_main_db_entry_t *db,
        dslite_table_entry_t *dslite_entry,
        int bulk_alloc_start_port)
{

    nfv9_ds_lite_bulk_del_record_t nfv9_logging_bulk_del_record = {0};
    cnat_user_db_entry_t           *udb = NULL;

    if (PREDICT_FALSE(nfv9_logging_info->record[DS_LITE_BULK_DEL_RECORD] == NULL)) {
        cnat_nfv9_record_create(nfv9_logging_info, DS_LITE_BULK_DEL_RECORD);
    }
    udb = cnat_user_db + db->user_index; 
    if (PREDICT_FALSE(!udb)) {
        return;
    }
    /*
     * We should definitely have add_record now, no need to sanitize
     */

    nfv9_logging_bulk_del_record.inside_vrf_id =
        clib_host_to_net_u32(dslite_entry->i_vrf_id);

#ifdef DSLITE_USER_IPV4
    nfv9_logging_bulk_del_record.inside_ip_addr =
        clib_host_to_net_u32(db->in2out_key.k.ipv4);
#else
    nfv9_logging_bulk_del_record.inside_ip_addr =
        clib_host_to_net_u32(0);
#endif

    nfv9_logging_bulk_del_record.inside_v6_src_addr[0] = 
        clib_host_to_net_u32(udb->ipv6[0]);
    nfv9_logging_bulk_del_record.inside_v6_src_addr[1] = 
        clib_host_to_net_u32(udb->ipv6[1]);
    nfv9_logging_bulk_del_record.inside_v6_src_addr[2] = 
        clib_host_to_net_u32(udb->ipv6[2]);
    nfv9_logging_bulk_del_record.inside_v6_src_addr[3] = 
        clib_host_to_net_u32(udb->ipv6[3]);

    nfv9_logging_bulk_del_record.outside_ip_port_start =
        clib_host_to_net_u16(bulk_alloc_start_port);

    clib_memcpy(nfv9_logging_info->record[DS_LITE_BULK_DEL_RECORD], 
        &nfv9_logging_bulk_del_record, 
        CNAT_NFV9_DS_LITE_BULK_DEL_RECORD_LENGTH);
    nfv9_logging_info->record_length[DS_LITE_BULK_DEL_RECORD] += 
        CNAT_NFV9_DS_LITE_BULK_DEL_RECORD_LENGTH;
    nfv9_logging_info->pkt_length += 
        CNAT_NFV9_DS_LITE_BULK_DEL_RECORD_LENGTH;
    nfv9_logging_info->total_record_count += 1;
    nfv9_logging_info->record[DS_LITE_BULK_DEL_RECORD] += 
        CNAT_NFV9_DS_LITE_BULK_DEL_RECORD_LENGTH;
    nfv9_logging_info->next_data_ptr = 
        nfv9_logging_info->record[DS_LITE_BULK_DEL_RECORD];
    nfv9_logging_info->dataflow_header->dataflow_length =
	clib_host_to_net_u32(
        nfv9_logging_info->record_length[DS_LITE_BULK_DEL_RECORD]);
}
#endif /* #ifndef NO_BULK_LOGGING */

static void cnat_nfv9_insert_del_record(
        cnat_nfv9_logging_info_t *nfv9_logging_info,
        cnat_main_db_entry_t *db,
        cnat_vrfmap_t *vrfmap)
{
    u16 my_proto_mask;
    u8 my_protocol;
    nfv9_del_record_t nfv9_logging_del_record;

    if (PREDICT_FALSE(nfv9_logging_info->record[NAT44_DEL_RECORD] == NULL)) {
        cnat_nfv9_record_create(nfv9_logging_info, NAT44_DEL_RECORD);
    }

   /*
    * We should definitely have add_record now, no need to sanitize
    */

    nfv9_logging_del_record.inside_vrf_id =
        clib_host_to_net_u32(vrfmap->i_vrf_id);

    nfv9_logging_del_record.inside_ip_addr =
        clib_host_to_net_u32(db->in2out_key.k.ipv4);

    nfv9_logging_del_record.inside_ip_port =
        clib_host_to_net_u16(db->in2out_key.k.port);

    my_proto_mask = db->in2out_key.k.vrf & CNAT_PRO_MASK;
    my_protocol = ((my_proto_mask == CNAT_UDP) ? UDP_PROT :
                ((my_proto_mask == CNAT_TCP) ? TCP_PROT :
                ((my_proto_mask == CNAT_ICMP) ? ICMP_PROT : GRE_PROT)));

    nfv9_logging_del_record.protocol = my_protocol;

    clib_memcpy(nfv9_logging_info->record[NAT44_DEL_RECORD], 
            &nfv9_logging_del_record, CNAT_NFV9_DEL_RECORD_LENGTH);

    nfv9_logging_info->record_length[NAT44_DEL_RECORD] 
            += CNAT_NFV9_DEL_RECORD_LENGTH;

    nfv9_logging_info->pkt_length += CNAT_NFV9_DEL_RECORD_LENGTH;

    nfv9_logging_info->record[NAT44_DEL_RECORD] 
                      += CNAT_NFV9_DEL_RECORD_LENGTH;
    nfv9_logging_info->next_data_ptr = 
                      nfv9_logging_info->record[NAT44_DEL_RECORD];

    nfv9_logging_info->dataflow_header->dataflow_length =
	clib_host_to_net_u32(
        nfv9_logging_info->record_length[NAT44_DEL_RECORD]);

}

#ifndef NO_BULK_LOGGING
static void cnat_nfv9_insert_bulk_del_record(
        cnat_nfv9_logging_info_t *nfv9_logging_info,
        cnat_main_db_entry_t *db,
        cnat_vrfmap_t *vrfmap,
        int bulk_alloc_start_port)
{
    nfv9_bulk_del_record_t nfv9_logging_bulk_del_record;
    if (PREDICT_FALSE(nfv9_logging_info->record[NAT44_BULK_DEL_RECORD] == NULL)) {
        cnat_nfv9_record_create(nfv9_logging_info, NAT44_BULK_DEL_RECORD);
    }

   /*
    * We should definitely have add_record now, no need to sanitize
    */

    nfv9_logging_bulk_del_record.inside_vrf_id =
        clib_host_to_net_u32(vrfmap->i_vrf_id);

    nfv9_logging_bulk_del_record.inside_ip_addr =
        clib_host_to_net_u32(db->in2out_key.k.ipv4);

    nfv9_logging_bulk_del_record.outside_ip_port_start =
        clib_host_to_net_u16(bulk_alloc_start_port);

    clib_memcpy(nfv9_logging_info->record[NAT44_BULK_DEL_RECORD], 
            &nfv9_logging_bulk_del_record, CNAT_NFV9_BULK_DEL_RECORD_LENGTH);

    nfv9_logging_info->record_length[NAT44_BULK_DEL_RECORD] 
            += CNAT_NFV9_BULK_DEL_RECORD_LENGTH;

    nfv9_logging_info->pkt_length += CNAT_NFV9_BULK_DEL_RECORD_LENGTH;

    nfv9_logging_info->record[NAT44_BULK_DEL_RECORD] 
                      += CNAT_NFV9_BULK_DEL_RECORD_LENGTH;
    nfv9_logging_info->next_data_ptr = 
                      nfv9_logging_info->record[NAT44_BULK_DEL_RECORD];

    nfv9_logging_info->dataflow_header->dataflow_length =
	clib_host_to_net_u32(
        nfv9_logging_info->record_length[NAT44_BULK_DEL_RECORD]);

}

#endif /* #ifndef NO_BULK_LOGGING */
/*
 * edt: * * cnat_nfv9_log_mapping_create
 *
 * Tries to log a creation of mapping record
 *
 * Argument: cnat_main_db_entry_t *db
 * Main DB entry being created
 *
 * Argument: cnat_vrfmap_t *vrfmap
 * VRF Map for the Main DB entry being created
 */
void cnat_nfv9_log_mapping_create (cnat_main_db_entry_t *db,
			           cnat_vrfmap_t *vrfmap
#ifndef NO_BULK_LOGGING
                       , int bulk_alloc
#endif
                       )
{
    cnat_nfv9_logging_info_t *nfv9_logging_info = 0; 
    vlib_main_t * vm = vlib_get_main();

    if (PREDICT_FALSE(vrfmap->nfv9_logging_index == EMPTY)) {

        //vlib_cli_output(vm, "\n1. Log Mapping failed");
	/*
	 * No logging configured, silently return
	 */
	return;
    }

    if (cnat_nfv9_logging_info_pool == NULL) {
	vlib_cli_output(vm, "%s: info_pool pointer is NULL !!!!\n", __func__);
	return;
    }
    nfv9_logging_info = 
        cnat_nfv9_logging_info_pool + vrfmap->nfv9_logging_index;

    if (PREDICT_FALSE(nfv9_logging_info->current_logging_context == NULL)) {
        cnat_nfv9_create_logging_context(nfv9_logging_info,
	                                 cnat_nfv9_template_add_default);

	/*
	 * If still empty, return after increasing the count
	 */
	if (PREDICT_FALSE(nfv9_logging_info->current_logging_context == NULL)) {
            //vlib_cli_output(vm, "\n2. Log Mapping failed");
	    return;
	}
	
    }

#ifndef NO_BULK_LOGGING
    if(bulk_alloc > 0) { /* new bulk alloc - use bulk add template */
        cnat_nfv9_insert_bulk_add_record(nfv9_logging_info, db, vrfmap,
            bulk_alloc);
    } else if(bulk_alloc == CACHE_ALLOC_NO_LOG_REQUIRED)
        return; /* No logging required.. bulk port usage */
    else /* Individual logging .. fall back to old method */
#endif
    cnat_nfv9_insert_add_record(nfv9_logging_info, db, vrfmap);

    nfv9_logging_info->total_record_count += 1;

    /*
     * If we have exceeded the packet length, let us send the
     * packet now.  There is buffer of additional bytes beyond
     * max_pkt_length to ensure that the last add/delete record
     * can be stored safely.
     */
    if (PREDICT_FALSE(nfv9_logging_info->pkt_length > 
            nfv9_logging_info->max_length_minus_max_record_size)) {
	    cnat_nfv9_send_pkt(nfv9_logging_info);
    }
}

/*
 * edt: * * cnat_nfv9_log_mapping_delete
 *
 * Tries to log a deletion of mapping record
 *
 * Argument: cnat_main_db_entry_t *db
 * Main DB entry being deleted
 *
 * Argument: cnat_vrfmap_t *vrfmap
 * VRF Map for the Main DB entry being deleted
 */
void cnat_nfv9_log_mapping_delete (cnat_main_db_entry_t * db,
                              cnat_vrfmap_t *vrfmap
#ifndef NO_BULK_LOGGING
                              , int bulk_alloc
#endif
                              )
{
    cnat_nfv9_logging_info_t *nfv9_logging_info = 0; 

    if (PREDICT_FALSE(vrfmap->nfv9_logging_index == EMPTY)) {
        //vlib_cli_output(vm, "\n3. Log Mapping failed");
	/*
	 * No logging configured, silently return
	 */
	return;
    }

    nfv9_logging_info = 
        cnat_nfv9_logging_info_pool + vrfmap->nfv9_logging_index;

    if (PREDICT_FALSE(nfv9_logging_info->current_logging_context == NULL)) {
        cnat_nfv9_create_logging_context(nfv9_logging_info,
	                                 cnat_nfv9_template_add_default);

	/*
	 * If still empty, return after increasing the count
	 */
	if (PREDICT_FALSE(nfv9_logging_info->current_logging_context == NULL)) {
            //vlib_cli_output(vm, "\n4. Log Mapping failed");
	    return;
	}
    }
#ifndef NO_BULK_LOGGING
    if(bulk_alloc > 0) { /* new bulk alloc - use bulk add template */
        cnat_nfv9_insert_bulk_del_record(nfv9_logging_info, db, vrfmap,
            bulk_alloc);
    } else if(bulk_alloc == CACHE_ALLOC_NO_LOG_REQUIRED)
        return; /* No logging required.. bulk port usage */
    else /* Individual logging .. fall back to old method */
#endif
    cnat_nfv9_insert_del_record(nfv9_logging_info, db, vrfmap);

    nfv9_logging_info->total_record_count += 1;

    /*
     * If we have exceeded the packet length, let us send the
     * packet now.  There is buffer of additional bytes beyond
     * max_pkt_length to ensure that the last add/delete record
     * can be stored safely.
     */
    if (PREDICT_FALSE(nfv9_logging_info->pkt_length > 
        nfv9_logging_info->max_length_minus_max_record_size)) {
	    cnat_nfv9_send_pkt(nfv9_logging_info);
    }
}


/* NAT64 Related routines */

/*
 * edt: * * cnat_nfv9_bib_mapping_create
 *
 * Tries to log a creation of Bib mapping record
 *
 * Argument: nat64_bib_entry_t *db
 * BIB DB entry being created
 *
 * Argument: nat64_table_entry_t *nat64_entry
 * NAT64 Instance where this BIB belongs 
 */
void cnat_nfv9_bib_mapping_create (nat64_bib_entry_t *db,
                       nat64_table_entry_t *nat64_entry)
{
    cnat_nfv9_logging_info_t *nfv9_logging_info = 0;
    u16 my_proto_mask;
    u8 my_protocol;
    nfv9_nat64_add_bib_record_t nfv9_logging_add_record;

    if (PREDICT_FALSE(nat64_entry->logging_index == EMPTY)) {
        /*
         * No logging configured, silently return
         */
        return;
    }

    nfv9_logging_info =
        cnat_nfv9_logging_info_pool + nat64_entry->logging_index;


    if (PREDICT_FALSE(nfv9_logging_info->current_logging_context == NULL)) {
        cnat_nfv9_create_logging_context(nfv9_logging_info,
                                        cnat_nfv9_template_add_default);

        /*
         * If still empty, return after increasing the count
         */
        if (PREDICT_FALSE(nfv9_logging_info->current_logging_context == NULL)) {
            return;
        }
    }

    if (PREDICT_FALSE(nfv9_logging_info->record[NAT64_ADD_BIB_RECORD] == NULL)){
        cnat_nfv9_record_create(nfv9_logging_info,NAT64_ADD_BIB_RECORD);
    }


    nfv9_logging_add_record.inside_v6_src_addr[0] = 
            clib_host_to_net_u32(db->v6_in_key.ipv6[0]);
    nfv9_logging_add_record.inside_v6_src_addr[1] = 
            clib_host_to_net_u32(db->v6_in_key.ipv6[1]);
    nfv9_logging_add_record.inside_v6_src_addr[2] = 
            clib_host_to_net_u32(db->v6_in_key.ipv6[2]);
    nfv9_logging_add_record.inside_v6_src_addr[3] = 
            clib_host_to_net_u32(db->v6_in_key.ipv6[3]);


    nfv9_logging_add_record.outside_v4_src_addr =
            clib_host_to_net_u32(db->v4_out_key.k.ipv4);

    nfv9_logging_add_record.inside_src_port =
            clib_host_to_net_u16(db->v6_in_key.port);
    nfv9_logging_add_record.outside_src_port =
            clib_host_to_net_u16(db->v4_out_key.k.port);

    my_proto_mask = db->v6_in_key.vrf & CNAT_PRO_MASK;

    my_protocol = ((my_proto_mask == CNAT_UDP) ? UDP_PROT :
           ((my_proto_mask == CNAT_TCP) ? TCP_PROT :
           ((my_proto_mask == CNAT_ICMP) ? IPV6_PROTO_ICMPV6 : 0)));
    nfv9_logging_add_record.protocol = my_protocol;


    clib_memcpy(nfv9_logging_info->record[NAT64_ADD_BIB_RECORD], 
            &nfv9_logging_add_record, CNAT_NFV9_NAT64_ADD_BIB_RECORD_LENGTH);

    nfv9_logging_info->record_length[NAT64_ADD_BIB_RECORD] += 
                         CNAT_NFV9_NAT64_ADD_BIB_RECORD_LENGTH;
    nfv9_logging_info->pkt_length += CNAT_NFV9_NAT64_ADD_BIB_RECORD_LENGTH;
    nfv9_logging_info->total_record_count += 1;

    nfv9_logging_info->record[NAT64_ADD_BIB_RECORD] 
                           += CNAT_NFV9_NAT64_ADD_BIB_RECORD_LENGTH;

    nfv9_logging_info->next_data_ptr = 
                      nfv9_logging_info->record[NAT64_ADD_BIB_RECORD];

    nfv9_logging_info->dataflow_header->dataflow_length =
    clib_host_to_net_u32(
            nfv9_logging_info->record_length[NAT64_ADD_BIB_RECORD]);

    /*
     * If we have exceeded the packet length, let us send the
     * packet now.  There is buffer of additional bytes beyond
     * max_pkt_length to ensure that the last add/delete record
     * can be stored safely.
     */
    if (PREDICT_FALSE(nfv9_logging_info->pkt_length >
        nfv9_logging_info->max_length_minus_max_record_size)) {
        cnat_nfv9_send_pkt(nfv9_logging_info);
    }
}


/*
 * edt: * * cnat_nfv9_session_mapping_create
 *
 * Tries to log a creation of Bib mapping record
 *
 * Argument: nat64_bib_entry_t *bdb
 * BIB DB entry for the session that is created
 *
 * Argument: nat64_session_entry_t *sdb
 * Session DB entry being created
 * 
 * Argument: nat64_table_entry_t *nat64_entry
 * NAT64 Instance where this BIB and Session belongs 
 */
void cnat_nfv9_session_mapping_create (nat64_bib_entry_t *bdb,
                       nat64_session_entry_t *sdb,
                       nat64_table_entry_t *nat64_entry_ptr)
{
    cnat_nfv9_logging_info_t *nfv9_logging_info = 0;
    u16 my_proto_mask;
    u8 my_protocol;
    u32 dest_v6[4];
    nfv9_nat64_add_session_record_t nfv9_logging_add_record;
    u8            *ipv6_addr_ptr;
    u8            *ipv4_addr_ptr;


    if (PREDICT_FALSE(nat64_entry_ptr->logging_index == EMPTY)) {
        /*
         * No logging configured, silently return
         */
        return;
    }

    nfv9_logging_info =
        cnat_nfv9_logging_info_pool + nat64_entry_ptr->logging_index;


    if (PREDICT_FALSE(nfv9_logging_info->current_logging_context == NULL)) {
        cnat_nfv9_create_logging_context(nfv9_logging_info,
                                        cnat_nfv9_template_add_default);

        /*
         * If still empty, return after increasing the count
         */
        if (PREDICT_FALSE(nfv9_logging_info->current_logging_context == NULL)){
            return;
        }
    }

    if (PREDICT_FALSE(nfv9_logging_info->record[NAT64_ADD_SESSION_RECORD] 
                                                  == NULL)){
        cnat_nfv9_record_create(nfv9_logging_info, NAT64_ADD_SESSION_RECORD);
    }


    nfv9_logging_add_record.inside_v6_src_addr[0] =
            clib_host_to_net_u32(bdb->v6_in_key.ipv6[0]);
    nfv9_logging_add_record.inside_v6_src_addr[1] =
            clib_host_to_net_u32(bdb->v6_in_key.ipv6[1]);
    nfv9_logging_add_record.inside_v6_src_addr[2] =
            clib_host_to_net_u32(bdb->v6_in_key.ipv6[2]);
    nfv9_logging_add_record.inside_v6_src_addr[3] =
            clib_host_to_net_u32(bdb->v6_in_key.ipv6[3]);


    nfv9_logging_add_record.outside_v4_src_addr =
            clib_host_to_net_u32(bdb->v4_out_key.k.ipv4);


    nfv9_logging_add_record.outside_v4_dest_addr =
          clib_host_to_net_u32(sdb->v4_dest_key.k.ipv4);

    /* Need to create the V6 address using prefix */
    dest_v6[0] = nat64_entry_ptr->v6_prefix[0];
    dest_v6[1] = nat64_entry_ptr->v6_prefix[1];
    dest_v6[2] = nat64_entry_ptr->v6_prefix[2];
    dest_v6[3] = nat64_entry_ptr->v6_prefix[3];

    ipv6_addr_ptr = (u8 *) (&(dest_v6[0]));
    ipv4_addr_ptr = (u8 *) (&(sdb->v4_dest_key.k.ipv4));

    *(ipv6_addr_ptr + nat64_entry_ptr->octet0_position) = *(ipv4_addr_ptr);
    *(ipv6_addr_ptr + nat64_entry_ptr->octet1_position) = *(ipv4_addr_ptr + 1);
    *(ipv6_addr_ptr + nat64_entry_ptr->octet2_position) = *(ipv4_addr_ptr + 2);
    *(ipv6_addr_ptr + nat64_entry_ptr->octet3_position) = *(ipv4_addr_ptr + 3);

    nfv9_logging_add_record.inside_v6_dest_addr[0] =
          clib_host_to_net_u32(dest_v6[0]);
    nfv9_logging_add_record.inside_v6_dest_addr[1] =
          clib_host_to_net_u32(dest_v6[1]);
    nfv9_logging_add_record.inside_v6_dest_addr[2] =
          clib_host_to_net_u32(dest_v6[2]);
    nfv9_logging_add_record.inside_v6_dest_addr[3] =
          clib_host_to_net_u32(dest_v6[3]);

    nfv9_logging_add_record.outside_v4_dest_addr =
          clib_host_to_net_u32(sdb->v4_dest_key.k.ipv4);

    nfv9_logging_add_record.inside_src_port =
            clib_host_to_net_u16(bdb->v6_in_key.port);
    nfv9_logging_add_record.outside_src_port =
            clib_host_to_net_u16(bdb->v4_out_key.k.port);

    nfv9_logging_add_record.dest_port =
            clib_host_to_net_u16(sdb->v4_dest_key.k.port);


    my_proto_mask = bdb->v6_in_key.vrf & CNAT_PRO_MASK;

    my_protocol = ((my_proto_mask == CNAT_UDP) ? UDP_PROT :
           ((my_proto_mask == CNAT_TCP) ? TCP_PROT :
           ((my_proto_mask == CNAT_ICMP) ? IPV6_PROTO_ICMPV6 : 0)));
    nfv9_logging_add_record.protocol = my_protocol;


    clib_memcpy(nfv9_logging_info->record[NAT64_ADD_SESSION_RECORD],
       &nfv9_logging_add_record, CNAT_NFV9_NAT64_ADD_SESSION_RECORD_LENGTH);

    nfv9_logging_info->record_length[NAT64_ADD_SESSION_RECORD] +=
                         CNAT_NFV9_NAT64_ADD_SESSION_RECORD_LENGTH;
    nfv9_logging_info->pkt_length += CNAT_NFV9_NAT64_ADD_SESSION_RECORD_LENGTH;
    nfv9_logging_info->total_record_count += 1;

    nfv9_logging_info->record[NAT64_ADD_SESSION_RECORD]
                           += CNAT_NFV9_NAT64_ADD_SESSION_RECORD_LENGTH;

    nfv9_logging_info->next_data_ptr =
                      nfv9_logging_info->record[NAT64_ADD_SESSION_RECORD];

    nfv9_logging_info->dataflow_header->dataflow_length =
    clib_host_to_net_u32(
            nfv9_logging_info->record_length[NAT64_ADD_SESSION_RECORD]);

    /*
     * If we have exceeded the packet length, let us send the
     * packet now.  There is buffer of additional bytes beyond
     * max_pkt_length to ensure that the last add/delete record
     * can be stored safely.
     */
    if (PREDICT_FALSE(nfv9_logging_info->pkt_length >
        nfv9_logging_info->max_length_minus_max_record_size)) {
        cnat_nfv9_send_pkt(nfv9_logging_info);
    }
}


/*
 * edt: * * cnat_nfv9_bib_mapping_delete
 *
 * Tries to log a deletion of Bib mapping record
 *
 * Argument: nat64_bib_entry_t *db
 * BIB DB entry being created
 *
 * Argument: nat64_table_entry_t *nat64_entry
 * NAT64 Instance where this BIB belongs 
 */
void cnat_nfv9_bib_mapping_delete (nat64_bib_entry_t *db,
                       nat64_table_entry_t *nat64_entry)
{
    cnat_nfv9_logging_info_t *nfv9_logging_info = 0;
    u16 my_proto_mask;
    u8 my_protocol;
    nfv9_nat64_del_bib_record_t nfv9_logging_del_record;
    if (PREDICT_FALSE(nat64_entry->logging_index == EMPTY)) {
        /*
         * No logging configured, silently return
         */
        return;
    }

    nfv9_logging_info =
        cnat_nfv9_logging_info_pool + nat64_entry->logging_index;


    if (PREDICT_FALSE(nfv9_logging_info->current_logging_context == NULL)) {
        cnat_nfv9_create_logging_context(nfv9_logging_info,
                                         cnat_nfv9_template_add_default);

        /*
         * If still empty, return after increasing the count
         */
        if (PREDICT_FALSE(nfv9_logging_info->current_logging_context == NULL)){
            return;
        }
    }

    if (PREDICT_FALSE(nfv9_logging_info->record[NAT64_DEL_BIB_RECORD] == NULL)){
        cnat_nfv9_record_create(nfv9_logging_info,NAT64_DEL_BIB_RECORD);
    }


    nfv9_logging_del_record.inside_v6_src_addr[0] =
            clib_host_to_net_u32(db->v6_in_key.ipv6[0]);
    nfv9_logging_del_record.inside_v6_src_addr[1] =
            clib_host_to_net_u32(db->v6_in_key.ipv6[1]);
    nfv9_logging_del_record.inside_v6_src_addr[2] =
            clib_host_to_net_u32(db->v6_in_key.ipv6[2]);
    nfv9_logging_del_record.inside_v6_src_addr[3] =
            clib_host_to_net_u32(db->v6_in_key.ipv6[3]);


    nfv9_logging_del_record.inside_src_port =
            clib_host_to_net_u16(db->v6_in_key.port);

    my_proto_mask = db->v6_in_key.vrf & CNAT_PRO_MASK;

    my_protocol = ((my_proto_mask == CNAT_UDP) ? UDP_PROT :
           ((my_proto_mask == CNAT_TCP) ? TCP_PROT :
           ((my_proto_mask == CNAT_ICMP) ? IPV6_PROTO_ICMPV6 : 0)));
    nfv9_logging_del_record.protocol = my_protocol;


    clib_memcpy(nfv9_logging_info->record[NAT64_DEL_BIB_RECORD],
            &nfv9_logging_del_record, CNAT_NFV9_NAT64_DEL_BIB_RECORD_LENGTH);

    nfv9_logging_info->record_length[NAT64_DEL_BIB_RECORD] +=
                         CNAT_NFV9_NAT64_DEL_BIB_RECORD_LENGTH;
    nfv9_logging_info->pkt_length += CNAT_NFV9_NAT64_DEL_BIB_RECORD_LENGTH;
    nfv9_logging_info->total_record_count += 1;

    nfv9_logging_info->record[NAT64_DEL_BIB_RECORD]
                           += CNAT_NFV9_NAT64_DEL_BIB_RECORD_LENGTH;

    nfv9_logging_info->next_data_ptr =
                      nfv9_logging_info->record[NAT64_DEL_BIB_RECORD];

    nfv9_logging_info->dataflow_header->dataflow_length =
    clib_host_to_net_u32(
            nfv9_logging_info->record_length[NAT64_DEL_BIB_RECORD]);

    /*
     * If we have exceeded the packet length, let us send the
     * packet now.  There is buffer of additional bytes beyond
     * max_pkt_length to ensure that the last add/delete record
     * can be stored safely.
     */
    if (PREDICT_FALSE(nfv9_logging_info->pkt_length >
        nfv9_logging_info->max_length_minus_max_record_size)) {
        cnat_nfv9_send_pkt(nfv9_logging_info);
    }
}


/*
 * edt: * * cnat_nfv9_session_mapping_delete
 *
 * Tries to log a deletion of Bib mapping record
 *
 * Argument: nat64_bib_entry_t *bdb
 * BIB DB entry for the session that is created
 *
 * Argument: nat64_session_entry_t *sdb
 * Session DB entry being created
 * 
 * Argument: nat64_table_entry_t *nat64_entry
 * NAT64 Instance where this BIB and Session belongs 
 */
void cnat_nfv9_session_mapping_delete (nat64_bib_entry_t *bdb,
                       nat64_session_entry_t *sdb,
                       nat64_table_entry_t *nat64_entry_ptr)
{
    cnat_nfv9_logging_info_t *nfv9_logging_info = 0;
    u16 my_proto_mask;
    u8 my_protocol;
    u32 dest_v6[4];
    nfv9_nat64_del_session_record_t nfv9_logging_del_record;
    u8            *ipv6_addr_ptr;
    u8            *ipv4_addr_ptr;

    if (PREDICT_FALSE(nat64_entry_ptr->logging_index == EMPTY)) {
        /*
         * No logging configured, silently return
         */
        return;
    }

    nfv9_logging_info =
        cnat_nfv9_logging_info_pool + nat64_entry_ptr->logging_index;


    if (PREDICT_FALSE(nfv9_logging_info->current_logging_context == NULL)) {
        cnat_nfv9_create_logging_context(nfv9_logging_info,
                                        cnat_nfv9_template_add_default);

        /*
         * If still empty, return after increasing the count
         */
        if (PREDICT_FALSE(nfv9_logging_info->current_logging_context == NULL)){
            return;
        }
    }

    if (PREDICT_FALSE(nfv9_logging_info->record[NAT64_DEL_SESSION_RECORD]
                                                  == NULL)){
        cnat_nfv9_record_create(nfv9_logging_info, NAT64_DEL_SESSION_RECORD);
    }


    nfv9_logging_del_record.inside_v6_src_addr[0] =
            clib_host_to_net_u32(bdb->v6_in_key.ipv6[0]);
    nfv9_logging_del_record.inside_v6_src_addr[1] =
            clib_host_to_net_u32(bdb->v6_in_key.ipv6[1]);
    nfv9_logging_del_record.inside_v6_src_addr[2] =
            clib_host_to_net_u32(bdb->v6_in_key.ipv6[2]);
    nfv9_logging_del_record.inside_v6_src_addr[3] =
            clib_host_to_net_u32(bdb->v6_in_key.ipv6[3]);

    /* Need to create the V6 address using prefix */
    dest_v6[0] = nat64_entry_ptr->v6_prefix[0];
    dest_v6[1] = nat64_entry_ptr->v6_prefix[1];
    dest_v6[2] = nat64_entry_ptr->v6_prefix[2];
    dest_v6[3] = nat64_entry_ptr->v6_prefix[3];

    ipv6_addr_ptr = (u8 *) (&(dest_v6[0]));
    ipv4_addr_ptr = (u8 *) (&(sdb->v4_dest_key.k.ipv4));

    *(ipv6_addr_ptr + nat64_entry_ptr->octet0_position) = *(ipv4_addr_ptr);
    *(ipv6_addr_ptr + nat64_entry_ptr->octet1_position) = *(ipv4_addr_ptr + 1);
    *(ipv6_addr_ptr + nat64_entry_ptr->octet2_position) = *(ipv4_addr_ptr + 2);
    *(ipv6_addr_ptr + nat64_entry_ptr->octet3_position) = *(ipv4_addr_ptr + 3);

    nfv9_logging_del_record.inside_v6_dest_addr[0] =
          clib_host_to_net_u32(dest_v6[0]);
    nfv9_logging_del_record.inside_v6_dest_addr[1] =
          clib_host_to_net_u32(dest_v6[1]);
    nfv9_logging_del_record.inside_v6_dest_addr[2] =
          clib_host_to_net_u32(dest_v6[2]);
    nfv9_logging_del_record.inside_v6_dest_addr[3] =
          clib_host_to_net_u32(dest_v6[3]);

    nfv9_logging_del_record.inside_src_port =
            clib_host_to_net_u16(bdb->v6_in_key.port);

    nfv9_logging_del_record.dest_port =
            clib_host_to_net_u16(sdb->v4_dest_key.k.port);


    my_proto_mask = bdb->v6_in_key.vrf & CNAT_PRO_MASK;

    my_protocol = ((my_proto_mask == CNAT_UDP) ? UDP_PROT :
           ((my_proto_mask == CNAT_TCP) ? TCP_PROT :
           ((my_proto_mask == CNAT_ICMP) ? IPV6_PROTO_ICMPV6 : 0)));
    nfv9_logging_del_record.protocol = my_protocol;

    clib_memcpy(nfv9_logging_info->record[NAT64_DEL_SESSION_RECORD],
       &nfv9_logging_del_record, CNAT_NFV9_NAT64_DEL_SESSION_RECORD_LENGTH);

    nfv9_logging_info->record_length[NAT64_DEL_SESSION_RECORD] +=
                         CNAT_NFV9_NAT64_DEL_SESSION_RECORD_LENGTH;
    nfv9_logging_info->pkt_length += CNAT_NFV9_NAT64_DEL_SESSION_RECORD_LENGTH;
    nfv9_logging_info->total_record_count += 1;

    nfv9_logging_info->record[NAT64_DEL_SESSION_RECORD]
                           += CNAT_NFV9_NAT64_DEL_SESSION_RECORD_LENGTH;

    nfv9_logging_info->next_data_ptr =
                      nfv9_logging_info->record[NAT64_DEL_SESSION_RECORD];

    nfv9_logging_info->dataflow_header->dataflow_length =
    clib_host_to_net_u32(
            nfv9_logging_info->record_length[NAT64_DEL_SESSION_RECORD]);

    /*
     * If we have exceeded the packet length, let us send the
     * packet now.  There is buffer of additional bytes beyond
     * max_pkt_length to ensure that the last add/delete record
     * can be stored safely.
     */
    if (PREDICT_FALSE(nfv9_logging_info->pkt_length >
        nfv9_logging_info->max_length_minus_max_record_size)) {
        cnat_nfv9_send_pkt(nfv9_logging_info);
    }
}

/*
 * edt: * * cnat_nfv9_nat44_log_session_create
 *
 * Tries to log a creation of mapping record (session based)
 *
 * Argument: cnat_main_db_entry_t *db
 * Main DB entry being created
 * Arugment: cnat_session_entry_t *sdb
 * Session DB entry if the destination is not the first dest
 * Argument: cnat_vrfmap_t *vrfmap
 * VRF Map for the Main DB entry being created
 */

void cnat_nfv9_nat44_log_session_create(cnat_main_db_entry_t *db,
                cnat_session_entry_t *sdb,
                cnat_vrfmap_t *vrfmap)
{
    cnat_nfv9_logging_info_t *nfv9_logging_info = 0;
    u16 my_proto_mask;
    u8 my_protocol;
    nfv9_add_session_record_t nfv9_logging_add_session_record;

    if (PREDICT_FALSE(vrfmap->nfv9_logging_index == EMPTY)) {
        //vlib_cli_output(vm,"\n1. Log Mapping failed");
        /*
         * No logging configured, silently return
         */
        return;
    }

    nfv9_logging_info =
        cnat_nfv9_logging_info_pool + vrfmap->nfv9_logging_index;

    if (PREDICT_FALSE(nfv9_logging_info->current_logging_context == NULL)) {
        cnat_nfv9_create_logging_context(nfv9_logging_info,
                    cnat_nfv9_template_add_default);

        /*
         * If still empty, return after increasing the count
         */
        if (PREDICT_FALSE(nfv9_logging_info->current_logging_context == NULL)) {
            //vlib_cli_output(vm,"\n2. Log Mapping failed");
            return;
        }
    }

    if(PREDICT_FALSE(nfv9_logging_info->record[
            NAT44_ADD_SESSION_RECORD] == NULL)) {
        cnat_nfv9_record_create(nfv9_logging_info, NAT44_ADD_SESSION_RECORD);
    }

    /*
     * We should definitely have add_record now, no need to sanitize
     */
    nfv9_logging_add_session_record.inside_vrf_id =
            clib_host_to_net_u32(vrfmap->i_vrf_id);
    nfv9_logging_add_session_record.outside_vrf_id =
            clib_host_to_net_u32(vrfmap->o_vrf_id);

    nfv9_logging_add_session_record.inside_ip_addr =
            clib_host_to_net_u32(db->in2out_key.k.ipv4);
    nfv9_logging_add_session_record.outside_ip_addr =
        clib_host_to_net_u32(db->out2in_key.k.ipv4);

    /* If sdb is null, it is assumed that logging is being done
     * for the first destination which is held in the main db

     * itself
     */
    if(PREDICT_TRUE(sdb == NULL)) {
        nfv9_logging_add_session_record.dest_ip_addr =
            clib_host_to_net_u32(db->dst_ipv4);
        nfv9_logging_add_session_record.dest_port =
            clib_host_to_net_u16(db->dst_port);
    } else {
        nfv9_logging_add_session_record.dest_ip_addr =
            clib_host_to_net_u32(sdb->v4_dest_key.k.ipv4);
        nfv9_logging_add_session_record.dest_port =
            clib_host_to_net_u16(sdb->v4_dest_key.k.port);
    }

    nfv9_logging_add_session_record.inside_ip_port =
            clib_host_to_net_u16(db->in2out_key.k.port);
    nfv9_logging_add_session_record.outside_ip_port =
            clib_host_to_net_u16(db->out2in_key.k.port);


    my_proto_mask = db->in2out_key.k.vrf & CNAT_PRO_MASK;

    my_protocol = ((my_proto_mask == CNAT_UDP) ? UDP_PROT :
            ((my_proto_mask == CNAT_TCP) ? TCP_PROT :
            ((my_proto_mask == CNAT_ICMP) ? ICMP_PROT : GRE_PROT)));
    nfv9_logging_add_session_record.protocol = my_protocol;

    clib_memcpy(nfv9_logging_info->record[NAT44_ADD_SESSION_RECORD],
            &nfv9_logging_add_session_record,
            CNAT_NFV9_NAT44_ADD_SESSION_RECORD_LENGTH);

    nfv9_logging_info->record_length[NAT44_ADD_SESSION_RECORD]
            += CNAT_NFV9_NAT44_ADD_SESSION_RECORD_LENGTH;
    nfv9_logging_info->pkt_length += CNAT_NFV9_NAT44_ADD_SESSION_RECORD_LENGTH;
    nfv9_logging_info->total_record_count += 1;


    nfv9_logging_info->record[NAT44_ADD_SESSION_RECORD]
            += CNAT_NFV9_NAT44_ADD_SESSION_RECORD_LENGTH;

    nfv9_logging_info->next_data_ptr =
            nfv9_logging_info->record[NAT44_ADD_SESSION_RECORD];

    nfv9_logging_info->dataflow_header->dataflow_length =
        clib_host_to_net_u32(
    nfv9_logging_info->record_length[NAT44_ADD_SESSION_RECORD]);

    /*
     * If we have exceeded the packet length, let us send the
     * packet now.  There is buffer of additional bytes beyond
     * max_pkt_length to ensure that the last add/delete record
     * can be stored safely.
     */
    if (PREDICT_FALSE(nfv9_logging_info->pkt_length >
        nfv9_logging_info->max_length_minus_max_record_size)) {
        cnat_nfv9_send_pkt(nfv9_logging_info);
    }
}

/*
 * edt: * * cnat_nfv9_nat44_log_session_delete
 *
 * Tries to log a deletion of mapping record (session based)
 *
 * Argument: cnat_main_db_entry_t *db
 * Main DB entry being created
 * Arugment: cnat_session_entry_t *sdb
 * Session DB entry if the destination is not the first dest
 * Argument: cnat_vrfmap_t *vrfmap
 * VRF Map for the Main DB entry being deleted
 */

void cnat_nfv9_nat44_log_session_delete(cnat_main_db_entry_t *db,
                cnat_session_entry_t *sdb,
                cnat_vrfmap_t *vrfmap)
{
    cnat_nfv9_logging_info_t *nfv9_logging_info = 0;
    u16 my_proto_mask;
    u8 my_protocol;
    nfv9_del_session_record_t nfv9_logging_del_session_record;

    if (PREDICT_FALSE(vrfmap->nfv9_logging_index == EMPTY)) {
        //vlib_cli_output(vm, "\n1. Log Mapping failed");
        /*
         * No logging configured, silently return
         */
        return;
    }

    nfv9_logging_info =
        cnat_nfv9_logging_info_pool + vrfmap->nfv9_logging_index;

    if (PREDICT_FALSE(nfv9_logging_info->current_logging_context == NULL)) {
        cnat_nfv9_create_logging_context(nfv9_logging_info,
                    cnat_nfv9_template_add_default);

        /*
         * If still empty, return after increasing the count
         */
        if (PREDICT_FALSE(nfv9_logging_info->current_logging_context == NULL)) {
            //vlib_cli_output(vm, "\n2. Log Mapping failed");
            return;
        }
    }

    if(PREDICT_FALSE(nfv9_logging_info->record[
            NAT44_DEL_SESSION_RECORD] == NULL)) {
        cnat_nfv9_record_create(nfv9_logging_info, NAT44_DEL_SESSION_RECORD);
    }

    /*
     * We should definitely have add_record now, no need to sanitize
     */
    nfv9_logging_del_session_record.inside_vrf_id =
            clib_host_to_net_u32(vrfmap->i_vrf_id);

    nfv9_logging_del_session_record.inside_ip_addr =
            clib_host_to_net_u32(db->in2out_key.k.ipv4);

    /* If sdb is null, it is assumed that logging is being done
     * for the first destination which is held in the main db
     * itself
     */
    if(PREDICT_TRUE(sdb == NULL)) {
        nfv9_logging_del_session_record.dest_ip_addr =
            clib_host_to_net_u32(db->dst_ipv4);
        nfv9_logging_del_session_record.dest_port =
            clib_host_to_net_u16(db->dst_port);
    } else {
        nfv9_logging_del_session_record.dest_ip_addr =
            clib_host_to_net_u32(sdb->v4_dest_key.k.ipv4);
        nfv9_logging_del_session_record.dest_port =
            clib_host_to_net_u16(sdb->v4_dest_key.k.port);
    }

    nfv9_logging_del_session_record.inside_ip_port =
            clib_host_to_net_u16(db->in2out_key.k.port);

    my_proto_mask = db->in2out_key.k.vrf & CNAT_PRO_MASK;
    my_protocol = ((my_proto_mask == CNAT_UDP) ? UDP_PROT :
            ((my_proto_mask == CNAT_TCP) ? TCP_PROT :
            ((my_proto_mask == CNAT_ICMP) ? ICMP_PROT : GRE_PROT)));

    nfv9_logging_del_session_record.protocol = my_protocol;

    clib_memcpy(nfv9_logging_info->record[NAT44_DEL_SESSION_RECORD],
            &nfv9_logging_del_session_record,
            CNAT_NFV9_NAT44_DEL_SESSION_RECORD_LENGTH);

    nfv9_logging_info->record_length[NAT44_DEL_SESSION_RECORD]
            += CNAT_NFV9_NAT44_DEL_SESSION_RECORD_LENGTH;
    nfv9_logging_info->pkt_length += CNAT_NFV9_NAT44_DEL_SESSION_RECORD_LENGTH;
    nfv9_logging_info->total_record_count += 1;

    nfv9_logging_info->record[NAT44_DEL_SESSION_RECORD]
            += CNAT_NFV9_NAT44_DEL_SESSION_RECORD_LENGTH;

    nfv9_logging_info->next_data_ptr =
            nfv9_logging_info->record[NAT44_DEL_SESSION_RECORD];

    nfv9_logging_info->dataflow_header->dataflow_length =
        clib_host_to_net_u32(
    nfv9_logging_info->record_length[NAT44_DEL_SESSION_RECORD]);

    /*
     * If we have exceeded the packet length, let us send the
     * packet now.  There is buffer of additional bytes beyond
     * max_pkt_length to ensure that the last add/delete record
     * can be stored safely.
     */
    if (PREDICT_FALSE(nfv9_logging_info->pkt_length >
        nfv9_logging_info->max_length_minus_max_record_size)) {
        cnat_nfv9_send_pkt(nfv9_logging_info);
    }
}

/*
 * DS-Lite APIs for netflow logging
 */

/*
 * edt: * * cnat_nfv9_ds_lite_mapping_create
 *
 * Tries to log a creation of mapping record
 *
 * Argument: cnat_main_db_entry_t *db
 * Main DB entry being created
 *
 * Argument: dslite_table_entry_t *dslite_entry
 * ds-lite instance for the Main DB entry being created
 */
void cnat_nfv9_ds_lite_mapping_create(cnat_main_db_entry_t *db,
                        dslite_table_entry_t *dslite_entry
#ifndef NO_BULK_LOGGING
                        , int bulk_alloc
#endif
                       )
{
    
    cnat_nfv9_logging_info_t    *nfv9_logging_info = NULL; 

    if (PREDICT_FALSE(!(db && dslite_entry))) {
        return;
    }
    if (PREDICT_FALSE(dslite_entry->nfv9_logging_index == EMPTY)) {
        /*
         * no logging configured, silently return
         */
        return;
    }

    nfv9_logging_info = 
        cnat_nfv9_logging_info_pool + dslite_entry->nfv9_logging_index;
    if (PREDICT_FALSE(nfv9_logging_info->current_logging_context == NULL)) {
        cnat_nfv9_create_logging_context(nfv9_logging_info,
                                        cnat_nfv9_template_add_default);
        /*
         * If still empty, return after increasing the count
         */
        if (PREDICT_FALSE(nfv9_logging_info->current_logging_context == NULL)) {
            return;
        }
    }
#ifndef NO_BULK_LOGGING
    if(bulk_alloc > 0) { /* new bulk alloc - use bulk add template */
        cnat_nfv9_ds_lite_insert_bulk_add_record(nfv9_logging_info, 
                db, dslite_entry, bulk_alloc);
    } else if(bulk_alloc == CACHE_ALLOC_NO_LOG_REQUIRED)
        return; /* No logging required.. bulk port usage */
    else  /* Individual logging .. fall back to old method */
#endif /*NO_BULK_LOGGING*/
    cnat_nfv9_ds_lite_insert_add_record(nfv9_logging_info, db, dslite_entry);
    /*
     * If we have exceeded the packet length, let us send the
     * packet now.  There is buffer of additional bytes beyond
     * max_pkt_length to ensure that the last add/delete record
     * can be stored safely.
     */
    if (PREDICT_FALSE(nfv9_logging_info->pkt_length > 
        nfv9_logging_info->max_length_minus_max_record_size)) {
        cnat_nfv9_send_pkt(nfv9_logging_info);
    }
}

/*
 * edt: * * cnat_nfv9_ds_lite_mapping_delete
 *
 * Tries to log a deletion of mapping record
 *
 * Argument: cnat_main_db_entry_t *db
 * Main DB entry being deleted
 *
 * Argument: dslite_table_entry_t *dslite_entry
 * ds-lite instance for the Main DB entry being deleted
 */
void cnat_nfv9_ds_lite_mapping_delete(cnat_main_db_entry_t *db,
                           dslite_table_entry_t *dslite_entry
#ifndef NO_BULK_LOGGING
                           , int bulk_alloc
#endif
                              )
{

    cnat_nfv9_logging_info_t    *nfv9_logging_info = NULL; 
    if (PREDICT_FALSE(!(db && dslite_entry))) {
        return;
    }
    if (PREDICT_FALSE(dslite_entry->nfv9_logging_index == EMPTY)) {
	/*
	 * No logging configured, silently return
	 */
        return;
    }
    nfv9_logging_info = 
        cnat_nfv9_logging_info_pool + dslite_entry->nfv9_logging_index;


    if (PREDICT_FALSE(nfv9_logging_info->current_logging_context == NULL)) {
        cnat_nfv9_create_logging_context(nfv9_logging_info,
	                                 cnat_nfv9_template_add_default);
        /*
         * If still empty, return after increasing the count
         */
        if (PREDICT_FALSE(nfv9_logging_info->current_logging_context == NULL)) {
            return;
        }
    }
#ifndef NO_BULK_LOGGING
    if(bulk_alloc > 0) { /* new bulk alloc - use bulk add template */
        cnat_nfv9_ds_lite_insert_bulk_del_record(nfv9_logging_info, 
                    db, dslite_entry, bulk_alloc);
    } else if(bulk_alloc == CACHE_ALLOC_NO_LOG_REQUIRED)
        return; /* No logging required.. bulk port usage */
    else  /* Individual logging .. fall back to old method */
#endif /*NO_BULK_LOGGING*/
    cnat_nfv9_ds_lite_insert_del_record(nfv9_logging_info, db, dslite_entry);
    /*
     * If we have exceeded the packet length, let us send the
     * packet now.  There is buffer of additional bytes beyond
     * max_pkt_length to ensure that the last add/delete record
     * can be stored safely.
     */
    if (PREDICT_FALSE(nfv9_logging_info->pkt_length > 
        nfv9_logging_info->max_length_minus_max_record_size)) {
        cnat_nfv9_send_pkt(nfv9_logging_info);
    }
}

/*
 * edt: * * cnat_nfv9_dslite_log_session_create
 *
 * Tries to log a creation of mapping record (session based)
 * Argument: cnat_main_db_entry_t *db
 * Main DB entry being created
 * Arugment: cnat_session_entry_t *sdb
 * Session DB entry if the destination is not the first dest
 * Argument: dslite_table_entry_t *dslite_entry,
 * dslite table entry for dslite instance
 */

void cnat_nfv9_ds_lite_log_session_create(
        	cnat_main_db_entry_t *db,
        	dslite_table_entry_t *dslite_entry,
                cnat_session_entry_t *sdb)
{

    nfv9_ds_lite_add_session_record_t   nfv9_logging_add_record ;
    cnat_user_db_entry_t        *udb = NULL;
    u16     my_proto_mask;
    u8      my_protocol;
    cnat_nfv9_logging_info_t  *nfv9_logging_info = 0;

    if (PREDICT_FALSE(dslite_entry->nfv9_logging_index == EMPTY)) {
        /*
         * no logging configured, silently return
         */
        return;
    }

    nfv9_logging_info =
        cnat_nfv9_logging_info_pool + dslite_entry->nfv9_logging_index;
    udb = cnat_user_db + db->user_index;

    if (PREDICT_FALSE(nfv9_logging_info->current_logging_context == NULL)) {
        cnat_nfv9_create_logging_context(nfv9_logging_info,
                    cnat_nfv9_template_add_default);

        /*
         * If still empty, return after increasing the count
         */
        if (PREDICT_FALSE(nfv9_logging_info->current_logging_context == NULL)) {
            return;
        }
    }

    udb = cnat_user_db + db->user_index;
    if (PREDICT_FALSE(!udb)) {
	 return;
    }
    if (PREDICT_FALSE(nfv9_logging_info->record[DS_LITE_ADD_SESSION_RECORD] == NULL)) {
        cnat_nfv9_record_create(nfv9_logging_info, DS_LITE_ADD_SESSION_RECORD);
    }
    /*
     * We should definitely have add_record now, no need to sanitize
     */
    nfv9_logging_add_record.inside_vrf_id =
                    clib_host_to_net_u32(dslite_entry->i_vrf_id);
    nfv9_logging_add_record.outside_vrf_id =
                    clib_host_to_net_u32(dslite_entry->o_vrf_id);

    nfv9_logging_add_record.inside_ip_addr =
                    clib_host_to_net_u32(db->in2out_key.k.ipv4);

    nfv9_logging_add_record.inside_v6_src_addr[0] =
                    clib_host_to_net_u32(udb->ipv6[0]);
    nfv9_logging_add_record.inside_v6_src_addr[1] =
                    clib_host_to_net_u32(udb->ipv6[1]);
    nfv9_logging_add_record.inside_v6_src_addr[2] =
                    clib_host_to_net_u32(udb->ipv6[2]);
    nfv9_logging_add_record.inside_v6_src_addr[3] =
                    clib_host_to_net_u32(udb->ipv6[3]);

    nfv9_logging_add_record.outside_ip_addr =
                    clib_host_to_net_u32(db->out2in_key.k.ipv4);

    nfv9_logging_add_record.inside_ip_port =
                    clib_host_to_net_u16(db->in2out_key.k.port);
    nfv9_logging_add_record.outside_ip_port =
                    clib_host_to_net_u16(db->out2in_key.k.port);

    /* If sdb is null, it is assumed that logging is being done
     * for the first destination which is held in the main db

     * itself
     */
    if(PREDICT_TRUE(sdb == NULL)) {
        nfv9_logging_add_record.dest_ip_addr =
            clib_host_to_net_u32(db->dst_ipv4);
        nfv9_logging_add_record.dest_port =
            clib_host_to_net_u16(db->dst_port);
    } else {
        nfv9_logging_add_record.dest_ip_addr =
            clib_host_to_net_u32(sdb->v4_dest_key.k.ipv4);
        nfv9_logging_add_record.dest_port =
            clib_host_to_net_u16(sdb->v4_dest_key.k.port);
    }


    my_proto_mask = db->in2out_key.k.vrf & CNAT_PRO_MASK;

    my_protocol = ((my_proto_mask == CNAT_UDP) ? UDP_PROT :
                   ((my_proto_mask == CNAT_TCP) ? TCP_PROT :
                   ((my_proto_mask == CNAT_ICMP) ? ICMP_PROT : 0)));
    nfv9_logging_add_record.protocol = my_protocol;

    clib_memcpy(nfv9_logging_info->record[DS_LITE_ADD_SESSION_RECORD],
            &nfv9_logging_add_record, CNAT_NFV9_DS_LITE_ADD_SESSION_RECORD_LENGTH);

    nfv9_logging_info->record_length[DS_LITE_ADD_SESSION_RECORD]
                                  += CNAT_NFV9_DS_LITE_ADD_SESSION_RECORD_LENGTH;

    nfv9_logging_info->pkt_length += CNAT_NFV9_DS_LITE_ADD_SESSION_RECORD_LENGTH;
    nfv9_logging_info->total_record_count += 1;

    nfv9_logging_info->record[DS_LITE_ADD_SESSION_RECORD]
                      += CNAT_NFV9_DS_LITE_ADD_SESSION_RECORD_LENGTH;
    nfv9_logging_info->next_data_ptr =
                         nfv9_logging_info->record[DS_LITE_ADD_SESSION_RECORD];

    nfv9_logging_info->dataflow_header->dataflow_length =
        clib_host_to_net_u32(
        nfv9_logging_info->record_length[DS_LITE_ADD_SESSION_RECORD]);

    /*
     * If we have exceeded the packet length, let us send the
     * packet now.  There is buffer of additional bytes beyond
     * max_pkt_length to ensure that the last add/delete record
     * can be stored safely.
     */
    if (PREDICT_FALSE(nfv9_logging_info->pkt_length >
        nfv9_logging_info->max_length_minus_max_record_size)) {
        cnat_nfv9_send_pkt(nfv9_logging_info);
    }

}

/*
 * edt: * * cnat_nfv9_dslite_log_session_delete
 *
 * Tries to log a creation of mapping record (session based)
 * Argument: cnat_main_db_entry_t *db
 * Main DB entry being created
 * Arugment: cnat_session_entry_t *sdb
 * Session DB entry if the destination is not the first dest
 * Argument: dslite_table_entry_t *dslite_entry,
 * dslite table entry for dslite instance
 */

void cnat_nfv9_ds_lite_log_session_delete(
                cnat_main_db_entry_t *db,
                dslite_table_entry_t *dslite_entry,
                cnat_session_entry_t *sdb)
{

    nfv9_ds_lite_del_session_record_t   nfv9_logging_add_record = {0};
    cnat_user_db_entry_t        *udb = NULL;
    u16     my_proto_mask;
    u8      my_protocol;
    cnat_nfv9_logging_info_t  *nfv9_logging_info = NULL;

    if (PREDICT_FALSE(dslite_entry->nfv9_logging_index == EMPTY)) {
        /*
         * no logging configured, silently return
         */
        return;
    }

    nfv9_logging_info =
        cnat_nfv9_logging_info_pool + dslite_entry->nfv9_logging_index;
    udb = cnat_user_db + db->user_index;

    if (PREDICT_FALSE(!udb)) {
        return;
    }

    if (PREDICT_FALSE(nfv9_logging_info->current_logging_context == NULL)) {
        cnat_nfv9_create_logging_context(nfv9_logging_info,
                    cnat_nfv9_template_add_default);

        /*
         * If still empty, return after increasing the count
         */
        if (PREDICT_FALSE(nfv9_logging_info->current_logging_context == NULL)) {
            return;
        }
    }

    if (PREDICT_FALSE(nfv9_logging_info->record[DS_LITE_DEL_SESSION_RECORD] == NULL)) {
        cnat_nfv9_record_create(nfv9_logging_info, DS_LITE_DEL_SESSION_RECORD);
    }
    /*
     * We should definitely have add_record now, no need to sanitize
     */
    nfv9_logging_add_record.inside_vrf_id =
                    clib_host_to_net_u32(dslite_entry->i_vrf_id);

    nfv9_logging_add_record.inside_ip_addr =
                    clib_host_to_net_u32(db->in2out_key.k.ipv4);

    nfv9_logging_add_record.inside_v6_src_addr[0] =
                    clib_host_to_net_u32(udb->ipv6[0]);
    nfv9_logging_add_record.inside_v6_src_addr[1] =
                    clib_host_to_net_u32(udb->ipv6[1]);
    nfv9_logging_add_record.inside_v6_src_addr[2] =
                    clib_host_to_net_u32(udb->ipv6[2]);
    nfv9_logging_add_record.inside_v6_src_addr[3] =
                    clib_host_to_net_u32(udb->ipv6[3]);

    nfv9_logging_add_record.inside_ip_port =
                    clib_host_to_net_u16(db->in2out_key.k.port);

    /* If sdb is null, it is assumed that logging is being done
     * for the first destination which is held in the main db
     * itself
     */
    if(PREDICT_TRUE(sdb == NULL)) {
        nfv9_logging_add_record.dest_ip_addr =
            clib_host_to_net_u32(db->dst_ipv4);
        nfv9_logging_add_record.dest_port = 
            clib_host_to_net_u16(db->dst_port);
    } else {
        nfv9_logging_add_record.dest_ip_addr =
            clib_host_to_net_u32(sdb->v4_dest_key.k.ipv4);
        nfv9_logging_add_record.dest_port =
            clib_host_to_net_u16(sdb->v4_dest_key.k.port);
    }


    my_proto_mask = db->in2out_key.k.vrf & CNAT_PRO_MASK;

    my_protocol = ((my_proto_mask == CNAT_UDP) ? UDP_PROT :
                   ((my_proto_mask == CNAT_TCP) ? TCP_PROT :
                   ((my_proto_mask == CNAT_ICMP) ? ICMP_PROT : 0)));
    nfv9_logging_add_record.protocol = my_protocol;
    
    clib_memcpy(nfv9_logging_info->record[DS_LITE_DEL_SESSION_RECORD],
            &nfv9_logging_add_record, CNAT_NFV9_DS_LITE_DEL_SESSION_RECORD_LENGTH);

    nfv9_logging_info->record_length[DS_LITE_DEL_SESSION_RECORD]
                                  += CNAT_NFV9_DS_LITE_DEL_SESSION_RECORD_LENGTH;

    nfv9_logging_info->pkt_length += CNAT_NFV9_DS_LITE_DEL_SESSION_RECORD_LENGTH;
    nfv9_logging_info->total_record_count += 1;

    nfv9_logging_info->record[DS_LITE_DEL_SESSION_RECORD]
                      += CNAT_NFV9_DS_LITE_DEL_SESSION_RECORD_LENGTH;
    nfv9_logging_info->next_data_ptr = 
                         nfv9_logging_info->record[DS_LITE_DEL_SESSION_RECORD];

    nfv9_logging_info->dataflow_header->dataflow_length =
        clib_host_to_net_u32(
        nfv9_logging_info->record_length[DS_LITE_DEL_SESSION_RECORD]);

    /*
     * If we have exceeded the packet length, let us send the
     * packet now.  There is buffer of additional bytes beyond
     * max_pkt_length to ensure that the last add/delete record
     * can be stored safely.
     */
    if (PREDICT_FALSE(nfv9_logging_info->pkt_length >
        nfv9_logging_info->max_length_minus_max_record_size)) {
        cnat_nfv9_send_pkt(nfv9_logging_info);
    }

}


/*
 * netflow logging API for ingress vrf_id to name mapping
 */

/*
 * edt: * * handle_vrfid_name_mapping
 * It will search for valid natflow entry in netflow pool,
 * once found one, will send all vrfid name mapping info
 * using that entry
 */


static inline
void handle_vrfid_name_mapping(void)
{
    cnat_nfv9_logging_info_t    *nfv9_logging_info = NULL;

    pool_foreach (nfv9_logging_info, cnat_nfv9_logging_info_pool, ({
        if(PREDICT_FALSE(nfv9_logging_info == NULL)) {
            continue;
        }
        nfv9_server_info_t *server =  nfv9_server_info_pool + 
            nfv9_logging_info->server_index;
        if(server->template_sent == TEMPLATE_SENT_TRUE) {
            cnat_nfv9_ingress_vrfid_name_mapping_create(nfv9_logging_info);
            server->template_sent = TEMPLATE_SENT_FALSE;
        }
    }));
}

/*
 * edt: * * cnat_nfv9_ingress_vrfid_name_mapping_create
 * 
 * Tries to log vrfid-name mapping record
 * Argument: netflow pointer
 */


void cnat_nfv9_ingress_vrfid_name_mapping_create(
                cnat_nfv9_logging_info_t *nfv9_logging_info)
{
    u16 index = 0;

    for (index = 0; index < MAX_VRFID; index++) {
        if(vrfid_name_map[index].ref_count == 0) {
            continue;
        }
        if (PREDICT_FALSE(
                    nfv9_logging_info->current_logging_context == NULL)) {
            cnat_nfv9_create_logging_context(nfv9_logging_info,
                    cnat_nfv9_template_add_default);
        }
        cnat_nfv9_insert_ingress_vrfid_name_record(
                nfv9_logging_info,index);
        if (PREDICT_FALSE(nfv9_logging_info->pkt_length >
                    nfv9_logging_info->max_length_minus_max_record_size) ||
                    PREDICT_FALSE(index == MAX_VRFID - 1)) {
            if (PREDICT_TRUE(nfv9_logging_info->current_logging_context
                        != NULL)) {
                cnat_nfv9_send_pkt(nfv9_logging_info);
            }
        }
    }/*for()*/
    return;
}

static void cnat_nfv9_insert_ingress_vrfid_name_record(
        cnat_nfv9_logging_info_t *nfv9_logging_info, u16 index)
{
    nfv9_ingress_vrfid_name_record_t  nfv9_ingress_vrfid_name_record = {0};
 
    if (PREDICT_FALSE(
            nfv9_logging_info->record[INGRESS_VRF_ID_NAME_RECORD] == NULL)) {
        cnat_nfv9_record_create(nfv9_logging_info, INGRESS_VRF_ID_NAME_RECORD);
    }
    nfv9_ingress_vrfid_name_record.ingress_vrf_id = 
		    clib_host_to_net_u32(vrfid_name_map[index].vrf_id);

    clib_memcpy(nfv9_ingress_vrfid_name_record.ingress_vrf_name,
            vrfid_name_map[index].vrf_name, NFV9_VRF_NAME_LEN);

    clib_memcpy(nfv9_logging_info->record[INGRESS_VRF_ID_NAME_RECORD], 
            &nfv9_ingress_vrfid_name_record, 
            CNAT_NFV9_INGRESS_VRFID_NAME_RECORD_LENGTH);

    nfv9_logging_info->record_length[INGRESS_VRF_ID_NAME_RECORD] 
            += CNAT_NFV9_INGRESS_VRFID_NAME_RECORD_LENGTH;

    nfv9_logging_info->pkt_length += 
            CNAT_NFV9_INGRESS_VRFID_NAME_RECORD_LENGTH;

    nfv9_logging_info->total_record_count += 1;

    nfv9_logging_info->record[INGRESS_VRF_ID_NAME_RECORD] 
            += CNAT_NFV9_INGRESS_VRFID_NAME_RECORD_LENGTH;

    nfv9_logging_info->next_data_ptr = 
            nfv9_logging_info->record[INGRESS_VRF_ID_NAME_RECORD];

    nfv9_logging_info->dataflow_header->dataflow_length =
	clib_host_to_net_u32(
        nfv9_logging_info->record_length[INGRESS_VRF_ID_NAME_RECORD]);
    return;
}
/*
 * edt: * * cnat_log_timer_handler
 *
 * Timer handler for sending any pending NFV9 record
 *
 * Argument: spp_timer_t * timer_p
 * Timer handler structure
 */
void handle_pending_nfv9_pkts()
{
    vlib_node_t *output_node;
    vlib_main_t * vm = vlib_get_main();
    cnat_nfv9_logging_info_t *my_nfv9_logging_info = 0;
    u32 current_timestamp = cnat_nfv9_get_sys_up_time_in_ms();
    u32 current_unix_time_in_seconds = cnat_nfv9_get_unix_time_in_seconds();
    
    output_node =  vlib_get_node_by_name (vm, (u8 *) "ip4-lookup");

    pool_foreach (my_nfv9_logging_info, cnat_nfv9_logging_info_pool, ({
        nfv9_server_info_t *server =  nfv9_server_info_pool + 
                                      my_nfv9_logging_info->server_index;
        if (my_nfv9_logging_info->queued_logging_context ||
            (my_nfv9_logging_info->current_logging_context &&
             (current_timestamp - 
              my_nfv9_logging_info->current_logging_context_timestamp) 
             > 1000)) {
            /*
             * If there is a current logging context and timestamp
             * indicates it is pending for long, send it out
             * Also if there is a queued context send it out as well
              */
	      vlib_cli_output(vm, "\nNFV9_TIMER: queued %p, curr %p",
			       my_nfv9_logging_info->queued_logging_context, 
			       my_nfv9_logging_info->current_logging_context);


              cnat_nfv9_send_pkt_always_success(my_nfv9_logging_info,
                                              output_node);
        } else {
            /*
             * If the last_template_sent_time is too far back in time
             * send the template even if there is no NFv9 records to send
             */
            if ((my_nfv9_logging_info->queued_logging_context == NULL) &&
                 (my_nfv9_logging_info->current_logging_context == NULL) &&
                 ((current_unix_time_in_seconds -
                 server->last_template_sent_time) >
                 server->timeout_rate)) {
                 cnat_nfv9_create_logging_context(my_nfv9_logging_info,
                                                 cnat_nfv9_template_add_always);
                 if (PREDICT_TRUE(my_nfv9_logging_info->current_logging_context
                                  != NULL)) {
                     cnat_nfv9_send_pkt(my_nfv9_logging_info);
                 }
            }
        }
    }));
}

/*
 * Code to initialize NFV9 Template.  This is done when a NFV9 is enabled
 * It is done only once and later used when sending NFV9 template records.
 */
static void
cnat_nfv9_template_init (void)
{
    cnat_nfv9_template_info.flowset_id =
        clib_host_to_net_u16(CNAT_NFV9_TEMPLATE_FLOWSET_ID);
    cnat_nfv9_template_info.length =
        clib_host_to_net_u16(CNAT_NFV9_TEMPLATE_LENGTH - 
                        CNAT_NFV9_OPTION_TEMPLATE_LENGTH);
    /*
     * Create the add Template
     */
    cnat_nfv9_template_info.add_template_id =
        clib_host_to_net_u16(CNAT_NFV9_ADD_TEMPLATE_ID);
    cnat_nfv9_template_info.add_field_count =
        clib_host_to_net_u16(CNAT_NFV9_ADD_FIELD_COUNT);

    cnat_nfv9_template_info.add_inside_vrf_id_field_type =
        clib_host_to_net_u16(CNAT_NFV9_INSIDE_VRFID_FIELD_TYPE);
    cnat_nfv9_template_info.add_inside_vrf_id_field_size =
        clib_host_to_net_u16(CNAT_NFV9_INSIDE_VRFID_FIELD_SIZE);

    cnat_nfv9_template_info.add_outside_vrf_id_field_type =
        clib_host_to_net_u16(CNAT_NFV9_OUTSIDE_VRFID_FIELD_TYPE);
    cnat_nfv9_template_info.add_outside_vrf_id_field_size =
        clib_host_to_net_u16(CNAT_NFV9_OUTSIDE_VRFID_FIELD_SIZE);

    cnat_nfv9_template_info.add_inside_ip_addr_field_type =
        clib_host_to_net_u16(CNAT_NFV9_INSIDE_IP_ADDR_FIELD_TYPE);
    cnat_nfv9_template_info.add_inside_ip_addr_field_size =
        clib_host_to_net_u16(CNAT_NFV9_INSIDE_IP_ADDR_FIELD_SIZE);

    cnat_nfv9_template_info.add_outside_ip_addr_field_type =
        clib_host_to_net_u16(CNAT_NFV9_OUTSIDE_IP_ADDR_FIELD_TYPE);
    cnat_nfv9_template_info.add_outside_ip_addr_field_size =
        clib_host_to_net_u16(CNAT_NFV9_OUTSIDE_IP_ADDR_FIELD_SIZE);

    cnat_nfv9_template_info.add_inside_ip_port_field_type =
        clib_host_to_net_u16(CNAT_NFV9_INSIDE_IP_PORT_FIELD_TYPE);
    cnat_nfv9_template_info.add_inside_ip_port_field_size =
        clib_host_to_net_u16(CNAT_NFV9_INSIDE_IP_PORT_FIELD_SIZE);

    cnat_nfv9_template_info.add_outside_ip_port_field_type =
        clib_host_to_net_u16(CNAT_NFV9_OUTSIDE_IP_PORT_FIELD_TYPE);
    cnat_nfv9_template_info.add_outside_ip_port_field_size =
        clib_host_to_net_u16(CNAT_NFV9_OUTSIDE_IP_PORT_FIELD_SIZE);

    cnat_nfv9_template_info.add_protocol_field_type = 
        clib_host_to_net_u16(CNAT_NFV9_PROTOCOL_FIELD_TYPE);
    cnat_nfv9_template_info.add_protocol_field_size =
        clib_host_to_net_u16(CNAT_NFV9_PROTOCOL_FIELD_SIZE);

    /*
     * Create the delete Template
     */
    cnat_nfv9_template_info.del_template_id =
        clib_host_to_net_u16(CNAT_NFV9_DEL_TEMPLATE_ID);
    cnat_nfv9_template_info.del_field_count =
        clib_host_to_net_u16(CNAT_NFV9_DEL_FIELD_COUNT);

    cnat_nfv9_template_info.del_inside_vrf_id_field_type =
        clib_host_to_net_u16(CNAT_NFV9_INSIDE_VRFID_FIELD_TYPE);
    cnat_nfv9_template_info.del_inside_vrf_id_field_size =
        clib_host_to_net_u16(CNAT_NFV9_INSIDE_VRFID_FIELD_SIZE);

    cnat_nfv9_template_info.del_inside_ip_addr_field_type =
        clib_host_to_net_u16(CNAT_NFV9_INSIDE_IP_ADDR_FIELD_TYPE);
    cnat_nfv9_template_info.del_inside_ip_addr_field_size =
        clib_host_to_net_u16(CNAT_NFV9_INSIDE_IP_ADDR_FIELD_SIZE);

    cnat_nfv9_template_info.del_inside_ip_port_field_type =
        clib_host_to_net_u16(CNAT_NFV9_INSIDE_IP_PORT_FIELD_TYPE);
    cnat_nfv9_template_info.del_inside_ip_port_field_size =
        clib_host_to_net_u16(CNAT_NFV9_INSIDE_IP_PORT_FIELD_SIZE);

    cnat_nfv9_template_info.del_protocol_field_type =
        clib_host_to_net_u16(CNAT_NFV9_PROTOCOL_FIELD_TYPE);
    cnat_nfv9_template_info.del_protocol_field_size =
        clib_host_to_net_u16(CNAT_NFV9_PROTOCOL_FIELD_SIZE);


    /* Create NAT64 BIB Add template */
#if 0
    cnat_nfv9_template_info.nat64_add_bib_template_id =
        clib_host_to_net_u16(CNAT_NFV9_NAT64_ADD_BIB_TEMPLATE_ID);
    cnat_nfv9_template_info.nat64_add_bib_field_count =
        clib_host_to_net_u16(CNAT_NFV9_NAT64_ADD_BIB_FIELD_COUNT);


    cnat_nfv9_template_info.nat64_add_bib_inside_ipv6_addr_field_type =
      clib_host_to_net_u16(CNAT_NFV9_INSIDE_IPV6_SRC_ADDR_FIELD_TYPE);
    cnat_nfv9_template_info.nat64_add_bib_inside_ipv6_addr_field_size =
      clib_host_to_net_u16(CNAT_NFV9_INSIDE_IPV6_SRC_ADDR_FIELD_SIZE);

    cnat_nfv9_template_info.nat64_add_bib_outside_ip_addr_field_type =
        clib_host_to_net_u16(CNAT_NFV9_OUTSIDE_IP_ADDR_FIELD_TYPE);
    cnat_nfv9_template_info.nat64_add_bib_outside_ip_addr_field_size =
        clib_host_to_net_u16(CNAT_NFV9_OUTSIDE_IP_ADDR_FIELD_SIZE);

    cnat_nfv9_template_info.nat64_add_bib_inside_ip_port_field_type =
      clib_host_to_net_u16(CNAT_NFV9_INSIDE_IP_PORT_FIELD_TYPE);
    cnat_nfv9_template_info.nat64_add_bib_inside_ip_port_field_size =
      clib_host_to_net_u16(CNAT_NFV9_INSIDE_IP_PORT_FIELD_SIZE);

    cnat_nfv9_template_info.nat64_add_bib_outside_ip_port_field_type =
        clib_host_to_net_u16(CNAT_NFV9_OUTSIDE_IP_PORT_FIELD_TYPE);
    cnat_nfv9_template_info.nat64_add_bib_outside_ip_port_field_size =
        clib_host_to_net_u16(CNAT_NFV9_OUTSIDE_IP_PORT_FIELD_SIZE);

    cnat_nfv9_template_info.nat64_add_bib_protocol_field_type =
        clib_host_to_net_u16(CNAT_NFV9_PROTOCOL_FIELD_TYPE);
    cnat_nfv9_template_info.nat64_add_bib_protocol_field_size =
        clib_host_to_net_u16(CNAT_NFV9_PROTOCOL_FIELD_SIZE);

 
    /* NAT64 BIB Delete */
    cnat_nfv9_template_info.nat64_del_bib_template_id =
        clib_host_to_net_u16(CNAT_NFV9_NAT64_DEL_BIB_TEMPLATE_ID);
    cnat_nfv9_template_info.nat64_del_bib_field_count =
        clib_host_to_net_u16(CNAT_NFV9_NAT64_DEL_BIB_FIELD_COUNT);

    cnat_nfv9_template_info.nat64_del_bib_inside_ip_addr_field_type =
      clib_host_to_net_u16(CNAT_NFV9_INSIDE_IPV6_SRC_ADDR_FIELD_TYPE);
    cnat_nfv9_template_info.nat64_del_bib_inside_ip_addr_field_size =
      clib_host_to_net_u16(CNAT_NFV9_INSIDE_IPV6_SRC_ADDR_FIELD_SIZE);

    cnat_nfv9_template_info.nat64_del_bib_inside_ip_port_field_type =
      clib_host_to_net_u16(CNAT_NFV9_INSIDE_IP_PORT_FIELD_TYPE);
    cnat_nfv9_template_info.nat64_del_bib_inside_ip_port_field_size =
      clib_host_to_net_u16(CNAT_NFV9_INSIDE_IP_PORT_FIELD_SIZE);

    cnat_nfv9_template_info.nat64_del_bib_protocol_field_type =
        clib_host_to_net_u16(CNAT_NFV9_PROTOCOL_FIELD_TYPE);
    cnat_nfv9_template_info.nat64_del_bib_protocol_field_size =
        clib_host_to_net_u16(CNAT_NFV9_PROTOCOL_FIELD_SIZE);


    /* NAt64 SESSION ADD */

    cnat_nfv9_template_info.nat64_add_session_template_id =
        clib_host_to_net_u16(CNAT_NFV9_NAT64_ADD_SESSION_TEMPLATE_ID);
    cnat_nfv9_template_info.nat64_add_session_field_count =
        clib_host_to_net_u16(CNAT_NFV9_NAT64_ADD_SESSION_FIELD_COUNT);


    cnat_nfv9_template_info.nat64_add_session_inside_ipv6_src_addr_field_type =
      clib_host_to_net_u16(CNAT_NFV9_INSIDE_IPV6_SRC_ADDR_FIELD_TYPE);
    cnat_nfv9_template_info.nat64_add_session_inside_ipv6_src_addr_field_size =
      clib_host_to_net_u16(CNAT_NFV9_INSIDE_IPV6_SRC_ADDR_FIELD_SIZE);

    cnat_nfv9_template_info.nat64_add_session_outside_ip_src_addr_field_type =
        clib_host_to_net_u16(CNAT_NFV9_OUTSIDE_IP_ADDR_FIELD_TYPE);
    cnat_nfv9_template_info.nat64_add_session_outside_ip_src_addr_field_size =
        clib_host_to_net_u16(CNAT_NFV9_OUTSIDE_IP_ADDR_FIELD_SIZE);


    cnat_nfv9_template_info.nat64_add_session_inside_ipv6_dst_addr_field_type =
      clib_host_to_net_u16(CNAT_NFV9_INSIDE_IPV6_DST_ADDR_FIELD_TYPE);
    cnat_nfv9_template_info.nat64_add_session_inside_ipv6_dst_addr_field_size =
      clib_host_to_net_u16(CNAT_NFV9_INSIDE_IPV6_DST_ADDR_FIELD_SIZE);


    cnat_nfv9_template_info.nat64_add_session_outside_ip_dst_addr_field_type =
      clib_host_to_net_u16(CNAT_NFV9_OUTSIDE_IP_DST_ADDR_FIELD_TYPE);
    cnat_nfv9_template_info.nat64_add_session_outside_ip_dst_addr_field_size =
      clib_host_to_net_u16(CNAT_NFV9_OUTSIDE_IP_DST_ADDR_FIELD_SIZE);

    cnat_nfv9_template_info.nat64_add_session_inside_ip_src_port_field_type =
      clib_host_to_net_u16(CNAT_NFV9_INSIDE_IP_PORT_FIELD_TYPE);
    cnat_nfv9_template_info.nat64_add_session_inside_ip_src_port_field_size =
      clib_host_to_net_u16(CNAT_NFV9_INSIDE_IP_PORT_FIELD_SIZE);


    cnat_nfv9_template_info.nat64_add_session_outside_ip_src_port_field_type =
        clib_host_to_net_u16(CNAT_NFV9_OUTSIDE_IP_PORT_FIELD_TYPE);
    cnat_nfv9_template_info.nat64_add_session_outside_ip_src_port_field_size =
        clib_host_to_net_u16(CNAT_NFV9_OUTSIDE_IP_PORT_FIELD_SIZE);
   

    cnat_nfv9_template_info.nat64_add_session_ip_dest_port_field_type =
      clib_host_to_net_u16(CNAT_NFV9_INSIDE_DST_PORT_FIELD_TYPE);
    cnat_nfv9_template_info.nat64_add_session_ip_dest_port_field_size =
      clib_host_to_net_u16(CNAT_NFV9_INSIDE_DST_PORT_FIELD_SIZE);
 
    cnat_nfv9_template_info.nat64_add_session_protocol_field_type =
        clib_host_to_net_u16(CNAT_NFV9_PROTOCOL_FIELD_TYPE);
    cnat_nfv9_template_info.nat64_add_session_protocol_field_size =
        clib_host_to_net_u16(CNAT_NFV9_PROTOCOL_FIELD_SIZE);



    /* Session Delete */
    cnat_nfv9_template_info.nat64_del_session_template_id =
        clib_host_to_net_u16(CNAT_NFV9_NAT64_DEL_SESSION_TEMPLATE_ID);
    cnat_nfv9_template_info.nat64_del_session_field_count =
        clib_host_to_net_u16(CNAT_NFV9_NAT64_DEL_SESSION_FIELD_COUNT);

    cnat_nfv9_template_info.nat64_del_session_inside_ip_src_addr_field_type =
      clib_host_to_net_u16(CNAT_NFV9_INSIDE_IPV6_SRC_ADDR_FIELD_TYPE);
    cnat_nfv9_template_info.nat64_del_session_inside_ip_src_addr_field_size =
      clib_host_to_net_u16(CNAT_NFV9_INSIDE_IPV6_SRC_ADDR_FIELD_SIZE);

    cnat_nfv9_template_info.nat64_del_session_inside_ip_dst_addr_field_type =
      clib_host_to_net_u16(CNAT_NFV9_INSIDE_IPV6_DST_ADDR_FIELD_TYPE);
    cnat_nfv9_template_info.nat64_del_session_inside_ip_dst_addr_field_size =
      clib_host_to_net_u16(CNAT_NFV9_INSIDE_IPV6_DST_ADDR_FIELD_SIZE);

    cnat_nfv9_template_info.nat64_del_session_inside_ip_src_port_field_type =
      clib_host_to_net_u16(CNAT_NFV9_INSIDE_IP_PORT_FIELD_TYPE);
    cnat_nfv9_template_info.nat64_del_session_inside_ip_src_port_field_size =
      clib_host_to_net_u16(CNAT_NFV9_INSIDE_IP_PORT_FIELD_SIZE);

    cnat_nfv9_template_info.nat64_del_session_inside_ip_dst_port_field_type =
      clib_host_to_net_u16(CNAT_NFV9_INSIDE_DST_PORT_FIELD_TYPE);
    cnat_nfv9_template_info.nat64_del_session_inside_ip_dst_port_field_size =
      clib_host_to_net_u16(CNAT_NFV9_INSIDE_DST_PORT_FIELD_SIZE);

    cnat_nfv9_template_info.nat64_del_session_protocol_field_type =
        clib_host_to_net_u16(CNAT_NFV9_PROTOCOL_FIELD_TYPE);
    cnat_nfv9_template_info.nat64_del_session_protocol_field_size =
        clib_host_to_net_u16(CNAT_NFV9_PROTOCOL_FIELD_SIZE);
#endif
    /*
     * Create the nat44 session add Template
     */
    cnat_nfv9_template_info.nat44_session_add_template_id =
        clib_host_to_net_u16(CNAT_NFV9_NAT44_ADD_SESSION_TEMPLATE_ID);
    cnat_nfv9_template_info.nat44_session_add_field_count =
        clib_host_to_net_u16(CNAT_NFV9_NAT44_ADD_SESSION_FIELD_COUNT);

    cnat_nfv9_template_info.nat44_session_add_inside_vrf_id_field_type =
        clib_host_to_net_u16(CNAT_NFV9_INSIDE_VRFID_FIELD_TYPE);
    cnat_nfv9_template_info.nat44_session_add_inside_vrf_id_field_size =
        clib_host_to_net_u16(CNAT_NFV9_INSIDE_VRFID_FIELD_SIZE);

    cnat_nfv9_template_info.nat44_session_add_outside_vrf_id_field_type =
        clib_host_to_net_u16(CNAT_NFV9_OUTSIDE_VRFID_FIELD_TYPE);
    cnat_nfv9_template_info.nat44_session_add_outside_vrf_id_field_size =
        clib_host_to_net_u16(CNAT_NFV9_OUTSIDE_VRFID_FIELD_SIZE);

    cnat_nfv9_template_info.nat44_session_add_inside_ip_addr_field_type =
        clib_host_to_net_u16(CNAT_NFV9_INSIDE_IP_ADDR_FIELD_TYPE);
    cnat_nfv9_template_info.nat44_session_add_inside_ip_addr_field_size =
        clib_host_to_net_u16(CNAT_NFV9_INSIDE_IP_ADDR_FIELD_SIZE);

    cnat_nfv9_template_info.nat44_session_add_outside_ip_addr_field_type =
        clib_host_to_net_u16(CNAT_NFV9_OUTSIDE_IP_ADDR_FIELD_TYPE);
    cnat_nfv9_template_info.nat44_session_add_outside_ip_addr_field_size =
        clib_host_to_net_u16(CNAT_NFV9_OUTSIDE_IP_ADDR_FIELD_SIZE);

    cnat_nfv9_template_info.nat44_session_add_inside_ip_port_field_type =
        clib_host_to_net_u16(CNAT_NFV9_INSIDE_IP_PORT_FIELD_TYPE);
    cnat_nfv9_template_info.nat44_session_add_inside_ip_port_field_size =
        clib_host_to_net_u16(CNAT_NFV9_INSIDE_IP_PORT_FIELD_SIZE);

    cnat_nfv9_template_info.nat44_session_add_outside_ip_port_field_type =
        clib_host_to_net_u16(CNAT_NFV9_OUTSIDE_IP_PORT_FIELD_TYPE);
   cnat_nfv9_template_info.nat44_session_add_outside_ip_port_field_size =
        clib_host_to_net_u16(CNAT_NFV9_OUTSIDE_IP_PORT_FIELD_SIZE);

    cnat_nfv9_template_info.nat44_session_add_dest_ip_addr_field_type =
        clib_host_to_net_u16(CNAT_NFV9_DESTINATION_IP_ADDR_FIELD_TYPE);
    cnat_nfv9_template_info.nat44_session_add_dest_ip_addr_field_size =
        clib_host_to_net_u16(CNAT_NFV9_DESTINATION_IP_ADDR_FIELD_SIZE);

    cnat_nfv9_template_info.nat44_session_add_dest_port_field_type =
        clib_host_to_net_u16(CNAT_NFV9_INSIDE_DST_PORT_FIELD_TYPE);
    cnat_nfv9_template_info.nat44_session_add_dest_port_field_size =
        clib_host_to_net_u16(CNAT_NFV9_INSIDE_DST_PORT_FIELD_SIZE);

    cnat_nfv9_template_info.nat44_session_add_protocol_field_type =
        clib_host_to_net_u16(CNAT_NFV9_PROTOCOL_FIELD_TYPE);
    cnat_nfv9_template_info.nat44_session_add_protocol_field_size =
        clib_host_to_net_u16(CNAT_NFV9_PROTOCOL_FIELD_SIZE);

    /*
     * Create the nat44 session del Template
     */
    cnat_nfv9_template_info.nat44_session_del_template_id =
        clib_host_to_net_u16(CNAT_NFV9_NAT44_DEL_SESSION_TEMPLATE_ID);
    cnat_nfv9_template_info.nat44_session_del_field_count =
        clib_host_to_net_u16(CNAT_NFV9_NAT44_DEL_SESSION_FIELD_COUNT);

    cnat_nfv9_template_info.nat44_session_del_inside_vrf_id_field_type =
        clib_host_to_net_u16(CNAT_NFV9_INSIDE_VRFID_FIELD_TYPE);
    cnat_nfv9_template_info.nat44_session_del_inside_vrf_id_field_size =
        clib_host_to_net_u16(CNAT_NFV9_INSIDE_VRFID_FIELD_SIZE);

    cnat_nfv9_template_info.nat44_session_del_inside_ip_addr_field_type =
        clib_host_to_net_u16(CNAT_NFV9_INSIDE_IP_ADDR_FIELD_TYPE);
    cnat_nfv9_template_info.nat44_session_del_inside_ip_addr_field_size =
        clib_host_to_net_u16(CNAT_NFV9_INSIDE_IP_ADDR_FIELD_SIZE);

    cnat_nfv9_template_info.nat44_session_del_dest_ip_addr_field_type =
        clib_host_to_net_u16(CNAT_NFV9_DESTINATION_IP_ADDR_FIELD_TYPE);
    cnat_nfv9_template_info.nat44_session_del_dest_ip_addr_field_size =
        clib_host_to_net_u16(CNAT_NFV9_DESTINATION_IP_ADDR_FIELD_SIZE);

    cnat_nfv9_template_info.nat44_session_del_inside_ip_port_field_type =
        clib_host_to_net_u16(CNAT_NFV9_INSIDE_IP_PORT_FIELD_TYPE);
    cnat_nfv9_template_info.nat44_session_del_inside_ip_port_field_size =
        clib_host_to_net_u16(CNAT_NFV9_INSIDE_IP_PORT_FIELD_SIZE);

    cnat_nfv9_template_info.nat44_session_del_dest_port_field_type =
        clib_host_to_net_u16(CNAT_NFV9_INSIDE_DST_PORT_FIELD_TYPE);
    cnat_nfv9_template_info.nat44_session_del_dest_port_field_size =
        clib_host_to_net_u16(CNAT_NFV9_INSIDE_DST_PORT_FIELD_SIZE);

    cnat_nfv9_template_info.nat44_session_del_protocol_field_type =
        clib_host_to_net_u16(CNAT_NFV9_PROTOCOL_FIELD_TYPE);
    cnat_nfv9_template_info.nat44_session_del_protocol_field_size =
        clib_host_to_net_u16(CNAT_NFV9_PROTOCOL_FIELD_SIZE);
    /*
     * Ds-lite add template
     */
#if 0
    cnat_nfv9_template_info.add_dslite_template_id =
        clib_host_to_net_u16(CNAT_NFV9_DS_LITE_ADD_TEMPLATE_ID);
    cnat_nfv9_template_info.add_dslite_field_count =
        clib_host_to_net_u16(CNAT_NFV9_DS_LITE_ADD_FIELD_COUNT);

    cnat_nfv9_template_info.add_dslite_inside_vrf_id_field_type =
        clib_host_to_net_u16(CNAT_NFV9_INSIDE_VRFID_FIELD_TYPE);
    cnat_nfv9_template_info.add_dslite_inside_vrf_id_field_size =
        clib_host_to_net_u16(CNAT_NFV9_INSIDE_VRFID_FIELD_SIZE);

    cnat_nfv9_template_info.add_dslite_outside_vrf_id_field_type =
        clib_host_to_net_u16(CNAT_NFV9_OUTSIDE_VRFID_FIELD_TYPE);
    cnat_nfv9_template_info.add_dslite_outside_vrf_id_field_size =
        clib_host_to_net_u16(CNAT_NFV9_OUTSIDE_VRFID_FIELD_SIZE);

    cnat_nfv9_template_info.add_dslite_inside_ip_addr_field_type =
        clib_host_to_net_u16(CNAT_NFV9_INSIDE_IP_ADDR_FIELD_TYPE);
    cnat_nfv9_template_info.add_dslite_inside_ip_addr_field_size =
        clib_host_to_net_u16(CNAT_NFV9_INSIDE_IP_ADDR_FIELD_SIZE);

    cnat_nfv9_template_info.add_dslite_inside_ipv6_addr_field_type =
      clib_host_to_net_u16(CNAT_NFV9_INSIDE_IPV6_SRC_ADDR_FIELD_TYPE);
    cnat_nfv9_template_info.add_dslite_inside_ipv6_addr_field_size =
      clib_host_to_net_u16(CNAT_NFV9_INSIDE_IPV6_SRC_ADDR_FIELD_SIZE);

    cnat_nfv9_template_info.add_dslite_outside_ip_addr_field_type =
        clib_host_to_net_u16(CNAT_NFV9_OUTSIDE_IP_ADDR_FIELD_TYPE);
    cnat_nfv9_template_info.add_dslite_outside_ip_addr_field_size =
        clib_host_to_net_u16(CNAT_NFV9_OUTSIDE_IP_ADDR_FIELD_SIZE);

    cnat_nfv9_template_info.add_dslite_inside_ip_port_field_type =
        clib_host_to_net_u16(CNAT_NFV9_INSIDE_IP_PORT_FIELD_TYPE);
    cnat_nfv9_template_info.add_dslite_inside_ip_port_field_size =
        clib_host_to_net_u16(CNAT_NFV9_INSIDE_IP_PORT_FIELD_SIZE);

    cnat_nfv9_template_info.add_dslite_outside_ip_port_field_type =
        clib_host_to_net_u16(CNAT_NFV9_OUTSIDE_IP_PORT_FIELD_TYPE);
    cnat_nfv9_template_info.add_dslite_outside_ip_port_field_size =
        clib_host_to_net_u16(CNAT_NFV9_OUTSIDE_IP_PORT_FIELD_SIZE);

    cnat_nfv9_template_info.add_dslite_protocol_field_type = 
        clib_host_to_net_u16(CNAT_NFV9_PROTOCOL_FIELD_TYPE);
    cnat_nfv9_template_info.add_dslite_protocol_field_size =
        clib_host_to_net_u16(CNAT_NFV9_PROTOCOL_FIELD_SIZE);

    /*
     * Ds-lite delete template 
     */
    cnat_nfv9_template_info.del_dslite_template_id =
        clib_host_to_net_u16(CNAT_NFV9_DS_LITE_DEL_TEMPLATE_ID);
    cnat_nfv9_template_info.del_dslite_field_count =
        clib_host_to_net_u16(CNAT_NFV9_DS_LITE_DEL_FIELD_COUNT);

    cnat_nfv9_template_info.del_dslite_inside_vrf_id_field_type =
        clib_host_to_net_u16(CNAT_NFV9_INSIDE_VRFID_FIELD_TYPE);
    cnat_nfv9_template_info.del_dslite_inside_vrf_id_field_size =
        clib_host_to_net_u16(CNAT_NFV9_INSIDE_VRFID_FIELD_SIZE);

    cnat_nfv9_template_info.del_dslite_inside_ip_addr_field_type =
        clib_host_to_net_u16(CNAT_NFV9_INSIDE_IP_ADDR_FIELD_TYPE);
    cnat_nfv9_template_info.del_dslite_inside_ip_addr_field_size =
        clib_host_to_net_u16(CNAT_NFV9_INSIDE_IP_ADDR_FIELD_SIZE);

    cnat_nfv9_template_info.del_dslite_inside_ipv6_addr_field_type =
      clib_host_to_net_u16(CNAT_NFV9_INSIDE_IPV6_SRC_ADDR_FIELD_TYPE);
    cnat_nfv9_template_info.del_dslite_inside_ipv6_addr_field_size =
      clib_host_to_net_u16(CNAT_NFV9_INSIDE_IPV6_SRC_ADDR_FIELD_SIZE);

    cnat_nfv9_template_info.del_dslite_inside_ip_port_field_type =
        clib_host_to_net_u16(CNAT_NFV9_INSIDE_IP_PORT_FIELD_TYPE);
    cnat_nfv9_template_info.del_dslite_inside_ip_port_field_size =
        clib_host_to_net_u16(CNAT_NFV9_INSIDE_IP_PORT_FIELD_SIZE);

    cnat_nfv9_template_info.del_dslite_protocol_field_type =
        clib_host_to_net_u16(CNAT_NFV9_PROTOCOL_FIELD_TYPE);
    cnat_nfv9_template_info.del_dslite_protocol_field_size =
        clib_host_to_net_u16(CNAT_NFV9_PROTOCOL_FIELD_SIZE);

    /*
     * Ds-lite session add template
     */

    cnat_nfv9_template_info.add_dslite_session_template_id =
        clib_host_to_net_u16(CNAT_NFV9_DS_LITE_ADD_SESSION_TEMPLATE_ID);
    cnat_nfv9_template_info.add_dslite_session_field_count =
        clib_host_to_net_u16(CNAT_NFV9_DS_LITE_ADD_SESSION_FIELD_COUNT);

    cnat_nfv9_template_info.add_dslite_session_inside_vrf_id_field_type =
        clib_host_to_net_u16(CNAT_NFV9_INSIDE_VRFID_FIELD_TYPE);
    cnat_nfv9_template_info.add_dslite_session_inside_vrf_id_field_size =
        clib_host_to_net_u16(CNAT_NFV9_INSIDE_VRFID_FIELD_SIZE);

    cnat_nfv9_template_info.add_dslite_session_outside_vrf_id_field_type =
        clib_host_to_net_u16(CNAT_NFV9_OUTSIDE_VRFID_FIELD_TYPE);
    cnat_nfv9_template_info.add_dslite_session_outside_vrf_id_field_size =
        clib_host_to_net_u16(CNAT_NFV9_OUTSIDE_VRFID_FIELD_SIZE);

    cnat_nfv9_template_info.add_dslite_session_inside_ip_addr_field_type =
        clib_host_to_net_u16(CNAT_NFV9_INSIDE_IP_ADDR_FIELD_TYPE);
    cnat_nfv9_template_info.add_dslite_session_inside_ip_addr_field_size =
        clib_host_to_net_u16(CNAT_NFV9_INSIDE_IP_ADDR_FIELD_SIZE);

    cnat_nfv9_template_info.add_dslite_session_inside_ipv6_addr_field_type =
      clib_host_to_net_u16(CNAT_NFV9_INSIDE_IPV6_SRC_ADDR_FIELD_TYPE);
    cnat_nfv9_template_info.add_dslite_session_inside_ipv6_addr_field_size =
      clib_host_to_net_u16(CNAT_NFV9_INSIDE_IPV6_SRC_ADDR_FIELD_SIZE);

    cnat_nfv9_template_info.add_dslite_session_outside_ip_addr_field_type =
        clib_host_to_net_u16(CNAT_NFV9_OUTSIDE_IP_ADDR_FIELD_TYPE);
    cnat_nfv9_template_info.add_dslite_session_outside_ip_addr_field_size =
        clib_host_to_net_u16(CNAT_NFV9_OUTSIDE_IP_ADDR_FIELD_SIZE);

    cnat_nfv9_template_info.add_dslite_session_inside_ip_port_field_type =
        clib_host_to_net_u16(CNAT_NFV9_INSIDE_IP_PORT_FIELD_TYPE);
    cnat_nfv9_template_info.add_dslite_session_inside_ip_port_field_size =
        clib_host_to_net_u16(CNAT_NFV9_INSIDE_IP_PORT_FIELD_SIZE);

    cnat_nfv9_template_info.add_dslite_session_outside_ip_port_field_type =
        clib_host_to_net_u16(CNAT_NFV9_OUTSIDE_IP_PORT_FIELD_TYPE);
    cnat_nfv9_template_info.add_dslite_session_outside_ip_port_field_size =
        clib_host_to_net_u16(CNAT_NFV9_OUTSIDE_IP_PORT_FIELD_SIZE);

     cnat_nfv9_template_info.add_dslite_session_dest_ip_addr_field_type =
         clib_host_to_net_u16(CNAT_NFV9_DESTINATION_IP_ADDR_FIELD_TYPE);
     cnat_nfv9_template_info.add_dslite_session_dest_ip_addr_field_size =
         clib_host_to_net_u16(CNAT_NFV9_DESTINATION_IP_ADDR_FIELD_SIZE);
 
     cnat_nfv9_template_info.add_dslite_session_dest_port_field_type =
         clib_host_to_net_u16(CNAT_NFV9_INSIDE_DST_PORT_FIELD_TYPE);
     cnat_nfv9_template_info.add_dslite_session_dest_port_field_size =
         clib_host_to_net_u16(CNAT_NFV9_INSIDE_DST_PORT_FIELD_SIZE);

    cnat_nfv9_template_info.add_dslite_session_protocol_field_type =
        clib_host_to_net_u16(CNAT_NFV9_PROTOCOL_FIELD_TYPE);
    cnat_nfv9_template_info.add_dslite_session_protocol_field_size =
        clib_host_to_net_u16(CNAT_NFV9_PROTOCOL_FIELD_SIZE);

    /*
     * Ds-lite session delete template 
     */
    cnat_nfv9_template_info.del_dslite_session_template_id =
        clib_host_to_net_u16(CNAT_NFV9_DS_LITE_DEL_SESSION_TEMPLATE_ID);
    cnat_nfv9_template_info.del_dslite_session_field_count =
        clib_host_to_net_u16(CNAT_NFV9_DS_LITE_DEL_SESSION_FIELD_COUNT);

    cnat_nfv9_template_info.del_dslite_session_inside_vrf_id_field_type =
        clib_host_to_net_u16(CNAT_NFV9_INSIDE_VRFID_FIELD_TYPE);
    cnat_nfv9_template_info.del_dslite_session_inside_vrf_id_field_size =
        clib_host_to_net_u16(CNAT_NFV9_INSIDE_VRFID_FIELD_SIZE);

    cnat_nfv9_template_info.del_dslite_session_inside_ip_addr_field_type =
        clib_host_to_net_u16(CNAT_NFV9_INSIDE_IP_ADDR_FIELD_TYPE);
    cnat_nfv9_template_info.del_dslite_session_inside_ip_addr_field_size =
        clib_host_to_net_u16(CNAT_NFV9_INSIDE_IP_ADDR_FIELD_SIZE);

    cnat_nfv9_template_info.del_dslite_session_inside_ipv6_addr_field_type =
      clib_host_to_net_u16(CNAT_NFV9_INSIDE_IPV6_SRC_ADDR_FIELD_TYPE);
    cnat_nfv9_template_info.del_dslite_session_inside_ipv6_addr_field_size =
      clib_host_to_net_u16(CNAT_NFV9_INSIDE_IPV6_SRC_ADDR_FIELD_SIZE);
    
    cnat_nfv9_template_info.del_dslite_session_inside_ip_port_field_type =
        clib_host_to_net_u16(CNAT_NFV9_INSIDE_IP_PORT_FIELD_TYPE);
    cnat_nfv9_template_info.del_dslite_session_inside_ip_port_field_size =
        clib_host_to_net_u16(CNAT_NFV9_INSIDE_IP_PORT_FIELD_SIZE);

    cnat_nfv9_template_info.del_dslite_session_dest_ip_addr_field_type =
        clib_host_to_net_u16(CNAT_NFV9_DESTINATION_IP_ADDR_FIELD_TYPE);
    cnat_nfv9_template_info.del_dslite_session_dest_ip_addr_field_size =
        clib_host_to_net_u16(CNAT_NFV9_DESTINATION_IP_ADDR_FIELD_SIZE);

    cnat_nfv9_template_info.del_dslite_session_dest_port_field_type =
        clib_host_to_net_u16(CNAT_NFV9_INSIDE_DST_PORT_FIELD_TYPE);
    cnat_nfv9_template_info.del_dslite_session_dest_port_field_size =
        clib_host_to_net_u16(CNAT_NFV9_INSIDE_DST_PORT_FIELD_SIZE);
   
    cnat_nfv9_template_info.del_dslite_session_protocol_field_type =
        clib_host_to_net_u16(CNAT_NFV9_PROTOCOL_FIELD_TYPE);
    cnat_nfv9_template_info.del_dslite_session_protocol_field_size =
        clib_host_to_net_u16(CNAT_NFV9_PROTOCOL_FIELD_SIZE);

    /* Create add bulk template */
    cnat_nfv9_template_info.bulk_add_template_id =
        clib_host_to_net_u16(CNAT_NFV9_NAT44_BULK_ADD_TEMPLATE_ID);
    cnat_nfv9_template_info.bulk_add_field_count =
        clib_host_to_net_u16(CNAT_NFV9_NAT44_BULK_ADD_FIELD_COUNT);

    cnat_nfv9_template_info.bulk_add_inside_vrf_id_field_type =
        clib_host_to_net_u16(CNAT_NFV9_INSIDE_VRFID_FIELD_TYPE);
    cnat_nfv9_template_info.bulk_add_inside_vrf_id_field_size =
        clib_host_to_net_u16(CNAT_NFV9_INSIDE_VRFID_FIELD_SIZE);

    cnat_nfv9_template_info.bulk_add_outside_vrf_id_field_type =
        clib_host_to_net_u16(CNAT_NFV9_OUTSIDE_VRFID_FIELD_TYPE);
    cnat_nfv9_template_info.bulk_add_outside_vrf_id_field_size =
        clib_host_to_net_u16(CNAT_NFV9_OUTSIDE_VRFID_FIELD_SIZE);

    cnat_nfv9_template_info.bulk_add_inside_ip_addr_field_type =
        clib_host_to_net_u16(CNAT_NFV9_INSIDE_IP_ADDR_FIELD_TYPE);
    cnat_nfv9_template_info.bulk_add_inside_ip_addr_field_size =
        clib_host_to_net_u16(CNAT_NFV9_INSIDE_IP_ADDR_FIELD_SIZE);

    cnat_nfv9_template_info.bulk_add_outside_ip_addr_field_type =
        clib_host_to_net_u16(CNAT_NFV9_OUTSIDE_IP_ADDR_FIELD_TYPE);
    cnat_nfv9_template_info.bulk_add_outside_ip_addr_field_size =
        clib_host_to_net_u16(CNAT_NFV9_OUTSIDE_IP_ADDR_FIELD_SIZE);

    cnat_nfv9_template_info.bulk_add_outside_start_port_field_type =
        clib_host_to_net_u16(CNAT_NFV9_OUTSIDE_IP_PORT_START_FIELD_TYPE);
    cnat_nfv9_template_info.bulk_add_outside_start_port_field_size =
        clib_host_to_net_u16(CNAT_NFV9_OUTSIDE_IP_PORT_START_FIELD_SIZE);

    cnat_nfv9_template_info.bulk_add_outside_end_port_field_type =
        clib_host_to_net_u16(CNAT_NFV9_OUTSIDE_IP_PORT_END_FIELD_TYPE);
    cnat_nfv9_template_info.bulk_add_outside_end_port_field_size =
        clib_host_to_net_u16(CNAT_NFV9_OUTSIDE_IP_PORT_END_FIELD_SIZE);

    /*
     * Create the bulk delete Template
     */
    cnat_nfv9_template_info.bulk_del_template_id =
        clib_host_to_net_u16(CNAT_NFV9_NAT44_BULK_DEL_TEMPLATE_ID);
    cnat_nfv9_template_info.bulk_del_field_count =
        clib_host_to_net_u16(CNAT_NFV9_NAT44_BULK_DEL_FIELD_COUNT);

    cnat_nfv9_template_info.bulk_del_inside_vrf_id_field_type =
        clib_host_to_net_u16(CNAT_NFV9_INSIDE_VRFID_FIELD_TYPE);
    cnat_nfv9_template_info.bulk_del_inside_vrf_id_field_size =
        clib_host_to_net_u16(CNAT_NFV9_INSIDE_VRFID_FIELD_SIZE);

    cnat_nfv9_template_info.bulk_del_inside_ip_addr_field_type =
        clib_host_to_net_u16(CNAT_NFV9_INSIDE_IP_ADDR_FIELD_TYPE);
    cnat_nfv9_template_info.bulk_del_inside_ip_addr_field_size =
        clib_host_to_net_u16(CNAT_NFV9_INSIDE_IP_ADDR_FIELD_SIZE);

    cnat_nfv9_template_info.bulk_del_outside_start_port_field_type =
        clib_host_to_net_u16(CNAT_NFV9_OUTSIDE_IP_PORT_START_FIELD_TYPE);
    cnat_nfv9_template_info.bulk_del_outside_start_port_field_size =
        clib_host_to_net_u16(CNAT_NFV9_OUTSIDE_IP_PORT_START_FIELD_SIZE);

    /*
     * Ds-lite bulk add template
     */
    cnat_nfv9_template_info.bulk_dslite_add_template_id =
        clib_host_to_net_u16(CNAT_NFV9_DS_LITE_BULK_ADD_TEMPLATE_ID);
    cnat_nfv9_template_info.bulk_dslite_add_field_count =
        clib_host_to_net_u16(CNAT_NFV9_DS_LITE_BULK_ADD_FIELD_COUNT);

    cnat_nfv9_template_info.bulk_dslite_add_inside_vrf_id_field_type =
        clib_host_to_net_u16(CNAT_NFV9_INSIDE_VRFID_FIELD_TYPE);
    cnat_nfv9_template_info.bulk_dslite_add_inside_vrf_id_field_size =
        clib_host_to_net_u16(CNAT_NFV9_INSIDE_VRFID_FIELD_SIZE);

    cnat_nfv9_template_info.bulk_dslite_add_outside_vrf_id_field_type =
        clib_host_to_net_u16(CNAT_NFV9_OUTSIDE_VRFID_FIELD_TYPE);
    cnat_nfv9_template_info.bulk_dslite_add_outside_vrf_id_field_size =
        clib_host_to_net_u16(CNAT_NFV9_OUTSIDE_VRFID_FIELD_SIZE);

    cnat_nfv9_template_info.bulk_dslite_add_inside_ip_addr_field_type =
        clib_host_to_net_u16(CNAT_NFV9_INSIDE_IP_ADDR_FIELD_TYPE);
    cnat_nfv9_template_info.bulk_dslite_add_inside_ip_addr_field_size =
        clib_host_to_net_u16(CNAT_NFV9_INSIDE_IP_ADDR_FIELD_SIZE);

    cnat_nfv9_template_info.bulk_dslite_add_inside_ipv6_addr_field_type =
      clib_host_to_net_u16(CNAT_NFV9_INSIDE_IPV6_SRC_ADDR_FIELD_TYPE);
    cnat_nfv9_template_info.bulk_dslite_add_inside_ipv6_addr_field_size =
      clib_host_to_net_u16(CNAT_NFV9_INSIDE_IPV6_SRC_ADDR_FIELD_SIZE);

    cnat_nfv9_template_info.bulk_dslite_add_outside_ip_addr_field_type =
        clib_host_to_net_u16(CNAT_NFV9_OUTSIDE_IP_ADDR_FIELD_TYPE);
    cnat_nfv9_template_info.bulk_dslite_add_outside_ip_addr_field_size =
        clib_host_to_net_u16(CNAT_NFV9_OUTSIDE_IP_ADDR_FIELD_SIZE);

    cnat_nfv9_template_info.bulk_dslite_add_outside_start_port_field_type =
        clib_host_to_net_u16(CNAT_NFV9_OUTSIDE_IP_PORT_START_FIELD_TYPE);
    cnat_nfv9_template_info.bulk_dslite_add_outside_start_port_field_size =
        clib_host_to_net_u16(CNAT_NFV9_OUTSIDE_IP_PORT_START_FIELD_SIZE);

    cnat_nfv9_template_info.bulk_dslite_add_outside_end_port_field_type =
        clib_host_to_net_u16(CNAT_NFV9_OUTSIDE_IP_PORT_END_FIELD_TYPE);
    cnat_nfv9_template_info.bulk_dslite_add_outside_end_port_field_size =
        clib_host_to_net_u16(CNAT_NFV9_OUTSIDE_IP_PORT_END_FIELD_SIZE);

    /*
     * Ds-lite bulk delete template
     */

    cnat_nfv9_template_info.bulk_dslite_del_template_id =
        clib_host_to_net_u16(CNAT_NFV9_DS_LITE_BULK_DEL_TEMPLATE_ID);
    cnat_nfv9_template_info.bulk_dslite_del_field_count =
        clib_host_to_net_u16(CNAT_NFV9_DS_LITE_BULK_DEL_FIELD_COUNT);

    cnat_nfv9_template_info.bulk_dslite_del_inside_vrf_id_field_type =
        clib_host_to_net_u16(CNAT_NFV9_INSIDE_VRFID_FIELD_TYPE);
    cnat_nfv9_template_info.bulk_dslite_del_inside_vrf_id_field_size =
        clib_host_to_net_u16(CNAT_NFV9_INSIDE_VRFID_FIELD_SIZE);

    cnat_nfv9_template_info.bulk_dslite_del_inside_ip_addr_field_type =
        clib_host_to_net_u16(CNAT_NFV9_INSIDE_IP_ADDR_FIELD_TYPE);
    cnat_nfv9_template_info.bulk_dslite_del_inside_ip_addr_field_size =
        clib_host_to_net_u16(CNAT_NFV9_INSIDE_IP_ADDR_FIELD_SIZE);

    cnat_nfv9_template_info.bulk_dslite_del_inside_ipv6_addr_field_type =
      clib_host_to_net_u16(CNAT_NFV9_INSIDE_IPV6_SRC_ADDR_FIELD_TYPE);
    cnat_nfv9_template_info.bulk_dslite_del_inside_ipv6_addr_field_size =
      clib_host_to_net_u16(CNAT_NFV9_INSIDE_IPV6_SRC_ADDR_FIELD_SIZE);

    cnat_nfv9_template_info.bulk_dslite_del_outside_start_port_field_type =
        clib_host_to_net_u16(CNAT_NFV9_OUTSIDE_IP_PORT_START_FIELD_TYPE);
    cnat_nfv9_template_info.bulk_dslite_del_outside_start_port_field_size =
        clib_host_to_net_u16(CNAT_NFV9_OUTSIDE_IP_PORT_START_FIELD_SIZE);

#endif /* NO_BULK_LOGGING */

    /*
     * Ingress vrfid - name mapping  
     */ 
    CNAT_NFV9_OPTION_TEMPLATE.flowset_id =
        clib_host_to_net_u16(CNAT_NFV9_OPTION_TEMPLATE_FLOWSET_ID);
    CNAT_NFV9_OPTION_TEMPLATE.length =
        clib_host_to_net_u16(CNAT_NFV9_OPTION_TEMPLATE_LENGTH);

    CNAT_NFV9_OPTION_TEMPLATE.ingress_vrfid_name_map_template_id =
        clib_host_to_net_u16(CNAT_NFV9_INGRESS_VRF_ID_NAME_TEMPLATE_ID);
    /* currently no scope field supported */
    CNAT_NFV9_OPTION_TEMPLATE.ingress_vrfid_name_map_scope_len = 0;
    CNAT_NFV9_OPTION_TEMPLATE.ingress_vrfid_name_map_option_len =
        clib_host_to_net_u16(CNAT_NFV9_INGRESS_VRF_ID_NAME_OPTION_LEN);
    CNAT_NFV9_OPTION_TEMPLATE.ingress_vrfid_name_map_vrfid_option_type =
        clib_host_to_net_u16(CNAT_NFV9_INSIDE_VRFID_FIELD_TYPE);
    CNAT_NFV9_OPTION_TEMPLATE.ingress_vrfid_name_map_vrfid_option_len =
        clib_host_to_net_u16(CNAT_NFV9_INSIDE_VRFID_FIELD_SIZE);
    CNAT_NFV9_OPTION_TEMPLATE.ingress_vrfid_name_map_vrfname_option_type =
        clib_host_to_net_u16(CNAT_NFV9_INGRESS_VRF_NAME_FIELD_TYPE);
    CNAT_NFV9_OPTION_TEMPLATE.ingress_vrfid_name_map_vrfname_option_len =
        clib_host_to_net_u16(CNAT_NFV9_INGRESS_VRF_NAME_FIELD_SIZE);

    /*
     * Set the padding (which was added to make the size of template 
     * multiple of 4) to zero
     */
    CNAT_NFV9_OPTION_TEMPLATE.padding1 = 0;
}

/*
 * one time function
 * has to be called at the init time
 */
void cnat_nfv9_logging_init()
{
    if (!cnat_nfv9_global_info.cnat_nfv9_init_done) {
	cnat_nfv9_template_init();

        /* Pre allocate for NFV9_SERVER_POOL_SIZE. Will be good 
         * enough for most deployments 
         */
        pool_alloc(nfv9_server_info_pool, NFV9_SERVER_POOL_SIZE);
        int i;
        nfv9_server_info_t *server __attribute__((unused));
        for(i = 0; i < NFV9_SERVER_POOL_SIZE; i++) {
            pool_get(nfv9_server_info_pool, server);
        }

        for(i = 0; i < NFV9_SERVER_POOL_SIZE; i++) {
            pool_put(nfv9_server_info_pool, nfv9_server_info_pool + i);
        }

        memset(&cnat_nfv9_global_info, 0 , sizeof(cnat_nfv9_global_info_t));    
	ASSERT(cnat_nfv9_global_info.cnat_nfv9_disp_node_index != (u16)~0);

	cnat_nfv9_global_info.cnat_nfv9_global_collector_index = EMPTY;
	cnat_nfv9_global_info.cnat_nfv9_init_done = 1;

	/*
	 * src id is set to infra IPv4 address + octeon core number
	 */
        nfv9_src_id = my_instance_number;
    }
}
