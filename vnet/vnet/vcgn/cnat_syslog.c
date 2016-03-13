/*
 *------------------------------------------------------------------
 * cnat_syslog.c
 *
 * Copyright (c) 2011-2013 Cisco and/or its affiliates.
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

#include <arpa/inet.h>
#include "cnat_syslog.h"
#include "platform_common.h"
#include "cnat_db.h"
#include "cnat_log_common.h"
#include <vppinfra/pool.h>

#define SYSLOG_DELIMITER    ' '
#define SYSLOG_FIELD_ABSENT '-' 
/* #define SHOW_SYSLOG_TIMESTAMP 1  TO DO. Remove this later */
/* 
 * Defining the below macro here for now. Assumption is, syslog packets 
 * are sent out via same channel as that of NFV9.
 * Has to be overridden if this assumption is false.
 */
#define PLATFORM_SYSLOG_DISP_NODE_IDX PLATFORM_NFV9_DISP_NODE_IDX

cnat_syslog_global_info_t cnat_syslog_global_info;
cnat_syslog_logging_info_t *cnat_syslog_logging_info_pool;
cnat_syslog_global_counters_t   cnat_syslog_global_counter;
extern u32 syslog_debug_flag;

#define CNAT_SYSLOG_DEBUG_CODE 2

#if CNAT_SYSLOG_DEBUG_CODE > 3
#define SYSLOG_COND if(my_instance_number == 0)

#define SYSLOG_DEBUG_PRINTF1(a) SYSLOG_COND printf(a);
#define SYSLOG_DEBUG_PRINTF2(a, b) SYSLOG_COND printf(a, b);
#define SYSLOG_DEBUG_PRINTF3(a, b, c) SYSLOG_COND printf(a, b, c);
#define SYSLOG_DEBUG_PRINTF4(a, b, c, d) SYSLOG_COND printf(a, b, c, d);

#else

#define SYSLOG_DEBUG_PRINTF1(a)
#define SYSLOG_DEBUG_PRINTF2(a, b)
#define SYSLOG_DEBUG_PRINTF3(a, b, c)
#define SYSLOG_DEBUG_PRINTF4(a, b, c, d)

#endif


void syslog_params_show(u32 logging_index)
{
    cnat_syslog_logging_info_t *log_info __attribute__((unused));
    if(logging_index == EMPTY) {
        PLATFORM_DEBUG_PRINT("\nSyslog logging not configured\n");
        return;
    }

    log_info = cnat_syslog_logging_info_pool + logging_index;

    PLATFORM_DEBUG_PRINT("\nSyslog parameters --\n");
    PLATFORM_DEBUG_PRINT("IPV4 address: %x, port %d, max log size %d\n",
        log_info->ipv4_address,
        log_info->port, log_info->max_length_minus_max_record_size);
    PLATFORM_DEBUG_PRINT("Host name: %s, priority %d", 
        log_info->header_hostname, log_info->header_priority);

}

/* Util function to copy a number as ASCII in to a buf in a
 * faster way (should be faster than sprintf)
 */

const unsigned char ascii_numbers[][3] = 
                {   {'0', '0', '0'},
                    {'1', '0', '0'},
                    {'2', '0', '0'},
                    {'3', '0', '0'},
                    {'4', '0', '0'},
                    {'5', '0', '0'},
                    {'6', '0', '0'},
                    {'7', '0', '0'},
                    {'8', '0', '0'},
                    {'9', '0', '0'},
                    {'1', '0', '0'},
                    {'1', '1', '0'},
                    {'1', '2', '0'},
                    {'1', '3', '0'},
                    {'1', '4', '0'},
                    {'1', '5', '0'},
                    {'1', '6', '0'},
                    {'1', '7', '0'},
                    {'1', '8', '0'},
                    {'1', '9', '0'},
                    {'2', '0', '0'},
                    {'2', '1', '0'},
                    {'2', '2', '0'},
                    {'2', '3', '0'},
                    {'2', '4', '0'},
                    {'2', '5', '0'},
                    {'2', '6', '0'},
                    {'2', '7', '0'},
                    {'2', '8', '0'},
                    {'2', '9', '0'},
                    {'3', '0', '0'},
                    {'3', '1', '0'},
                    {'3', '2', '0'},
                    {'3', '3', '0'},
                    {'3', '4', '0'},
                    {'3', '5', '0'},
                    {'3', '6', '0'},
                    {'3', '7', '0'},
                    {'3', '8', '0'},
                    {'3', '9', '0'},
                    {'4', '0', '0'},
                    {'4', '1', '0'},
                    {'4', '2', '0'},
                    {'4', '3', '0'},
                    {'4', '4', '0'},
                    {'4', '5', '0'},
                    {'4', '6', '0'},
                    {'4', '7', '0'},
                    {'4', '8', '0'},
                    {'4', '9', '0'},
                    {'5', '0', '0'},
                    {'5', '1', '0'},
                    {'5', '2', '0'},
                    {'5', '3', '0'},
                    {'5', '4', '0'},
                    {'5', '5', '0'},
                    {'5', '6', '0'},
                    {'5', '7', '0'},
                    {'5', '8', '0'},
                    {'5', '9', '0'},
                    {'6', '0', '0'},
                    {'6', '1', '0'},
                    {'6', '2', '0'},
                    {'6', '3', '0'},
                    {'6', '4', '0'},
                    {'6', '5', '0'},
                    {'6', '6', '0'},
                    {'6', '7', '0'},
                    {'6', '8', '0'},
                    {'6', '9', '0'},
                    {'7', '0', '0'},
                    {'7', '1', '0'},
                    {'7', '2', '0'},
                    {'7', '3', '0'},
                    {'7', '4', '0'},
                    {'7', '5', '0'},
                    {'7', '6', '0'},
                    {'7', '7', '0'},
                    {'7', '8', '0'},
                    {'7', '9', '0'},
                    {'8', '0', '0'},
                    {'8', '1', '0'},
                    {'8', '2', '0'},
                    {'8', '3', '0'},
                    {'8', '4', '0'},
                    {'8', '5', '0'},
                    {'8', '6', '0'},
                    {'8', '7', '0'},
                    {'8', '8', '0'},
                    {'8', '9', '0'},
                    {'9', '0', '0'},
                    {'9', '1', '0'},
                    {'9', '2', '0'},
                    {'9', '3', '0'},
                    {'9', '4', '0'},
                    {'9', '5', '0'},
                    {'9', '6', '0'},
                    {'9', '7', '0'},
                    {'9', '8', '0'},
                    {'9', '9', '0'},
                    {'1', '0', '0'},
                    {'1', '0', '1'},
                    {'1', '0', '2'},
                    {'1', '0', '3'},
                    {'1', '0', '4'},
                    {'1', '0', '5'},
                    {'1', '0', '6'},
                    {'1', '0', '7'},
                    {'1', '0', '8'},
                    {'1', '0', '9'},
                    {'1', '1', '0'},
                    {'1', '1', '1'},
                    {'1', '1', '2'},
                    {'1', '1', '3'},
                    {'1', '1', '4'},
                    {'1', '1', '5'},
                    {'1', '1', '6'},
                    {'1', '1', '7'},
                    {'1', '1', '8'},
                    {'1', '1', '9'},
                    {'1', '2', '0'},
                    {'1', '2', '1'},
                    {'1', '2', '2'},
                    {'1', '2', '3'},
                    {'1', '2', '4'},
                    {'1', '2', '5'},
                    {'1', '2', '6'},
                    {'1', '2', '7'},
                    {'1', '2', '8'},
                    {'1', '2', '9'},
                    {'1', '3', '0'},
                    {'1', '3', '1'},
                    {'1', '3', '2'},
                    {'1', '3', '3'},
                    {'1', '3', '4'},
                    {'1', '3', '5'},
                    {'1', '3', '6'},
                    {'1', '3', '7'},
                    {'1', '3', '8'},
                    {'1', '3', '9'},
                    {'1', '4', '0'},
                    {'1', '4', '1'},
                    {'1', '4', '2'},
                    {'1', '4', '3'},
                    {'1', '4', '4'},
                    {'1', '4', '5'},
                    {'1', '4', '6'},
                    {'1', '4', '7'},
                    {'1', '4', '8'},
                    {'1', '4', '9'},
                    {'1', '5', '0'},
                    {'1', '5', '1'},
                    {'1', '5', '2'},
                    {'1', '5', '3'},
                    {'1', '5', '4'},
                    {'1', '5', '5'},
                    {'1', '5', '6'},
                    {'1', '5', '7'},
                    {'1', '5', '8'},
                    {'1', '5', '9'},
                    {'1', '6', '0'},
                    {'1', '6', '1'},
                    {'1', '6', '2'},
                    {'1', '6', '3'},
                    {'1', '6', '4'},
                    {'1', '6', '5'},
                    {'1', '6', '6'},
                    {'1', '6', '7'},
                    {'1', '6', '8'},
                    {'1', '6', '9'},
                    {'1', '7', '0'},
                    {'1', '7', '1'},
                    {'1', '7', '2'},
                    {'1', '7', '3'},
                    {'1', '7', '4'},
                    {'1', '7', '5'},
                    {'1', '7', '6'},
                    {'1', '7', '7'},
                    {'1', '7', '8'},
                    {'1', '7', '9'},
                    {'1', '8', '0'},
                    {'1', '8', '1'},
                    {'1', '8', '2'},
                    {'1', '8', '3'},
                    {'1', '8', '4'},
                    {'1', '8', '5'},
                    {'1', '8', '6'},
                    {'1', '8', '7'},
                    {'1', '8', '8'},
                    {'1', '8', '9'},
                    {'1', '9', '0'},
                    {'1', '9', '1'},
                    {'1', '9', '2'},
                    {'1', '9', '3'},
                    {'1', '9', '4'},
                    {'1', '9', '5'},
                    {'1', '9', '6'},
                    {'1', '9', '7'},
                    {'1', '9', '8'},
                    {'1', '9', '9'},
                    {'2', '0', '0'},
                    {'2', '0', '1'},
                    {'2', '0', '2'},
                    {'2', '0', '3'},
                    {'2', '0', '4'},
                    {'2', '0', '5'},
                    {'2', '0', '6'},
                    {'2', '0', '7'},
                    {'2', '0', '8'},
                    {'2', '0', '9'},
                    {'2', '1', '0'},
                    {'2', '1', '1'},
                    {'2', '1', '2'},
                    {'2', '1', '3'},
                    {'2', '1', '4'},
                    {'2', '1', '5'},
                    {'2', '1', '6'},
                    {'2', '1', '7'},
                    {'2', '1', '8'},
                    {'2', '1', '9'},
                    {'2', '2', '0'},
                    {'2', '2', '1'},
                    {'2', '2', '2'},
                    {'2', '2', '3'},
                    {'2', '2', '4'},
                    {'2', '2', '5'},
                    {'2', '2', '6'},
                    {'2', '2', '7'},
                    {'2', '2', '8'},
                    {'2', '2', '9'},
                    {'2', '3', '0'},
                    {'2', '3', '1'},
                    {'2', '3', '2'},
                    {'2', '3', '3'},
                    {'2', '3', '4'},
                    {'2', '3', '5'},
                    {'2', '3', '6'},
                    {'2', '3', '7'},
                    {'2', '3', '8'},
                    {'2', '3', '9'},
                    {'2', '4', '0'},
                    {'2', '4', '1'},
                    {'2', '4', '2'},
                    {'2', '4', '3'},
                    {'2', '4', '4'},
                    {'2', '4', '5'},
                    {'2', '4', '6'},
                    {'2', '4', '7'},
                    {'2', '4', '8'},
                    {'2', '4', '9'},
                    {'2', '5', '0'},
                    {'2', '5', '1'},
                    {'2', '5', '2'},
                    {'2', '5', '3'},
                    {'2', '5', '4'},
                    {'2', '5', '5'}
            };

inline static int 
byte_to_ascii_decimal_unaligned(
    unsigned char *ptr, unsigned char num)
{
    *ptr++ = ascii_numbers[num][0];
    if(PREDICT_FALSE(num < 10)) {
        return 1;
    }
    *ptr++ = ascii_numbers[num][1];
    if(PREDICT_FALSE(num < 100)) {
        return 2;
    }
    *ptr++ = ascii_numbers[num][2];
    return 3; 
}

/* Copies the dotted decimal format of ipv4 
 * in to the space provided and 
 * returns the number of bytes copied
 */
inline static int 
copy_ipv4_addr(unsigned char *ptr, u32 ipv4) 
{
    unsigned char *temp = ptr; 
    temp += byte_to_ascii_decimal_unaligned(temp, (ipv4 >> 24));
    *temp++ = '.';
    temp += byte_to_ascii_decimal_unaligned(temp, ((ipv4 >> 16) & 0xFF));
    *temp++ = '.';
    temp += byte_to_ascii_decimal_unaligned(temp, ((ipv4 >> 8) & 0xFF));
    *temp++ = '.';
    temp += byte_to_ascii_decimal_unaligned(temp, (ipv4 & 0xFF));

    return (temp - ptr);
}

#ifdef TOBE_PORTED
/*
 * edt: * * cnat_syslog_fill_ip_header
 *
 * Tries to fill the fields of the IP header before it
 * is sent to the L3 infra node.
 *
 * Argument: cnat_syslog_logging_info_t *logging_info
 * structure that contains the packet context
 */
inline
void cnat_syslog_fill_ip_header (cnat_syslog_logging_info_t *logging_info)
{
    spp_ctx_t      *ctx;
    
    /*
     * Fill in the IP header and port number of the Netflow collector
     * The L3 Infra node will fill in the rest of the fields
     */
    ctx = logging_info->current_logging_context;
    fill_ip_n_udp_hdr(ctx, logging_info->ipv4_address,
        logging_info->port, logging_info->pkt_length);
        
}
#else
inline
void cnat_syslog_fill_ip_header (cnat_syslog_logging_info_t *logging_info)
{
    return;
}
#endif

#ifndef TOBE_PORTED
void cnat_syslog_logging_init()
{
    return;
}

void cnat_syslog_log_mapping_create(cnat_main_db_entry_t * db,
                                  cnat_vrfmap_t *vrfmap)
{
    return;
}

void cnat_syslog_log_mapping_delete(cnat_main_db_entry_t * db,
                                  cnat_vrfmap_t *vrfmap)
{
    return;
}

void cnat_syslog_ds_lite_port_limit_exceeded(
   dslite_key_t   * key,
   dslite_table_entry_t *dslite_entry)
{
    return;
}

void cnat_syslog_nat44_mapping_create(cnat_main_db_entry_t *db,
        cnat_vrfmap_t *vrfmap, cnat_session_entry_t * sdb
#ifndef NO_BULK_LOGGING
                       , int bulk_alloc
#endif
                       )
{
    return;
}

/* Following are in cnat_util.c which are not ported */
/* This function is defined in cnat_util.c which need to be ported */
cnat_icmp_msg_t icmp_msg_gen_allowed ()
{
    return 1;
}

void cnat_syslog_nat44_mapping_delete(cnat_main_db_entry_t *db,
        cnat_vrfmap_t *vrfmap, cnat_session_entry_t *sdb
#ifndef NO_BULK_LOGGING
        , int bulk_alloc
#endif
        )
{
    return;
}

u32
cnat_get_unix_time_in_seconds (void)
{
    return 0;
}
#else /* TOBE_PORTED */
void
cnat_syslog_dump_logging_context (u32 value1, 
                                cnat_syslog_logging_info_t *logging_info,
				u32 value2)
{
    u8 *pkt_ptr;
    u32 i;

    if (PREDICT_TRUE(syslog_debug_flag == 0)) {
        return;
    }
    /*
     * Reduce the logging to few cores, to enable easier debugging
     */
    if ((my_instance_number & 0x7) != 0) {
        return;
    }
    printf("\nDumping %s packet at locn %d: time 0x%x", 
	    (value2 == 1) ? "CURRENT" : "QUEUED",
            value1,
	    cnat_get_unix_time_in_seconds());

    printf("\ni_vrf 0x%x, ip_address 0x%x, port %d, pkt len %d",
             0 /* TO DP Add vrf like nfv9_logging_info->i_vrf */,
             logging_info->ipv4_address,
             logging_info->port,
             logging_info->pkt_length);
    printf("\n");

    if (value2 == 1) {
        pkt_ptr = logging_info->current_logging_context->packet_data;
    } else {
        pkt_ptr = logging_info->queued_logging_context->packet_data;
    }
 
    /*
     * Dump along with 8 bytes of SHIM header
     */
    for (i = 0; i < 
        (logging_info->pkt_length + CNAT_NFV9_IP_HDR_OFFSET); 
         i = i + 1) {
	u8 c1, c2, c3;

	if (i == 0) {
	    printf("\nL2_HEADER + SHIM_HEADER: \n");
	} else if (i == CNAT_NFV9_IP_HDR_OFFSET) {
	    printf("\nIP_HEADER: \n");
	} else if (i == CNAT_NFV9_UDP_HDR_OFFSET) {
	    printf("\nUDP_HEADER: \n");
	} else if (i == CNAT_NFV9_HDR_OFFSET) {
        printf("\nSyslog content..\n");
        while(i < 
            (logging_info->pkt_length + CNAT_NFV9_HDR_OFFSET)) {
            printf("%c", (u8)(*(pkt_ptr + i)));
            i++;
            if((u8)(*(pkt_ptr + i)) == '[') /* new record begins */
                printf("\n");
        }
        return;
    }

    c3 = *(pkt_ptr + i);
    c2 = c3 & 0xf;
    c1 = (c3 >> 4) & 0xf;
    
    printf("%c%c ",
        ((c1 <= 9) ? (c1 + '0') : (c1 - 10 + 'a')),
        ((c2 <= 9) ? (c2 + '0') : (c2 - 10 + 'a')));
        
    }

    printf("\n");
}


/*
 * edt: * * cnat_syslog_send_pkt
 *
 * Tries to send a logging pkt.  If the packet cannot be sent
 * because of rewrite_output node cannot process it, queue
 * it temporarily and try to send it later.
 *
 * Argument: cnat_syslog_logging_info_t *logging_info
 * structure that contains the packet context
 */
inline
void cnat_syslog_send_pkt (cnat_syslog_logging_info_t *logging_info)
{
    spp_node_t                  *output_node;

    cnat_syslog_fill_ip_header(logging_info);

    output_node = spp_get_nodes() + 
	    cnat_syslog_global_info.cnat_syslog_disp_node_index;

    cnat_syslog_dump_logging_context (2, logging_info, 1);

    if (PREDICT_TRUE(output_node->sf.nused < SPP_MAXDISPATCH)) {
        /*
         * Move the logging context to output node
         */
        logging_info->current_logging_context->current_length =
                                 logging_info->pkt_length;
        PLATFORM_SET_CTX_RU_TX_FROM_NODE(logging_info->current_logging_context, \
                                NODE_LOGGING);
        spp_dispatch_make_node_runnable(output_node);
        output_node->sf.ctxs[output_node->sf.nused++] = 
            logging_info->current_logging_context;

        if(PREDICT_FALSE(syslog_debug_flag > 10))
            printf("\nSyslog: 2. Sending Current packet\n");
    } else {
	    /*
	     * Queue the context into the logging_info structure,
	     * We will try to send it later.  Currently, we will
         * restrict to only one context queued.
	     */
        cnat_syslog_global_counter.downstream_constipation_count++;
        if(PREDICT_FALSE(syslog_debug_flag > 10)) 
            printf("\nSyslog: 2. Downstream congestion \n");

	    /*
	     * Attach the current logging context which is full to the
	     * queued context list in logging_info structure
	     */
	    logging_info->queued_logging_context = 
            logging_info->current_logging_context;
    }

    /*
     * Whether the context is queued or not, set the current context index
     * to EMPTY, as the earlier context can no more be used to send
     * more logging records.
     */
    logging_info->current_logging_context = NULL;
}


/*
 * edt: * * cnat_syslog_send_queued_pkt
 *
 * Tries to send a logging pkt that has been queued earlier
 * because it could not be sent due to downstream constipation
 *
 * Argument: cnat_syslog_logging_info_t *logging_info
 * structure that contains the packet context
 */
inline
void cnat_syslog_send_queued_pkt (cnat_syslog_logging_info_t *logging_info)
{
    spp_node_t                  *output_node;

    output_node = spp_get_nodes() + 
	    cnat_syslog_global_info.cnat_syslog_disp_node_index;

    cnat_syslog_dump_logging_context(1, logging_info, 2);

    if(PREDICT_TRUE(output_node->sf.nused < SPP_MAXDISPATCH)) {
        /*
         * Move the logging context to output node
         */
         /** This looks like a bug to me .. need to confirm *****
        logging_info->queued_logging_context->current_length = 
                                 nfv9_logging_info->pkt_length; ***/
        PLATFORM_SET_CTX_RU_TX_FROM_NODE(logging_info->queued_logging_context, 
                                NODE_LOGGING)
        spp_dispatch_make_node_runnable(output_node);
        output_node->sf.ctxs[output_node->sf.nused++] = 
            logging_info->queued_logging_context;

        SYSLOG_DEBUG_PRINTF1("\nSYSLOG: 1. Sending Queued packet\n")

        /*
         * Context has been queued, it will be freed after the pkt
         * is sent.  Clear this from the logging_context_info structure
         */
	    logging_info->queued_logging_context = NULL;

    } else {
        cnat_syslog_global_counter.downstream_constipation_count++;
    }
}

/*
 * edt: * * handle_pending_syslog_pkts
 *
 * Timer handler for sending any pending syslog record
 *
 */
inline
void handle_pending_syslog_pkts()
{
    spp_node_t *output_node;
    cnat_syslog_logging_info_t *my_logging_info = 0;
    u32 current_timestamp = cnat_get_sys_up_time_in_ms();
    i16 sf_nused;
    
    output_node = spp_get_nodes() + 
	    cnat_syslog_global_info.cnat_syslog_disp_node_index;

    sf_nused = output_node->sf.nused;
   
    pool_foreach (my_logging_info, cnat_syslog_logging_info_pool, ({
        /*
         * Check if no more logging contexts can be queued
         */
	if (PREDICT_FALSE(sf_nused >= SPP_MAXDISPATCH)) {
	    break;
	}
    if (my_logging_info->queued_logging_context)
        cnat_syslog_send_queued_pkt (my_logging_info);

    if(my_logging_info->current_logging_context &&
             ((current_timestamp - 
              my_logging_info->current_logging_context_timestamp) 
             > 1000)) {
        /*
         * If there is a current logging context and timestamp
         * indicates it is pending for long, send it out
         * Also if there is a queued context send it out as well
         */
	    SYSLOG_DEBUG_PRINTF4("\nLOG_TIMER: queued %p, curr %p, sf_nused %d",
			       my_logging_info->queued_logging_context, 
			       my_logging_info->current_logging_context, 
			       sf_nused);
        cnat_syslog_send_pkt(my_logging_info);
    }        
    }));
}

const unsigned char hex_numbers_single_digit[] = 
    { '0', '1', '2', '3', '4', '5', '6', '7', '8', 
        '9', 'a', 'b', 'c', 'd', 'e', 'f' };

inline static int u16_to_ascii_decimal_aligned(
    unsigned char *ptr, u16 num, u16 min_digits)
{
    /* The logic below is replicated in 
     * function u16_to_ascii_decimal_unaligned 
     * except the use of min_digits
     * Replication is done to optimize run time
     * if you fix a bug here, check u16_to_ascii_decimal_unaligned
     * as well (and vice versa)
     */
    unsigned char *temp = ptr; 
    int no_leading_zeros = 0;

    if(num > 9999 || min_digits == 5) {
        *temp++ = hex_numbers_single_digit[num/10000];
        num = num%10000;
        no_leading_zeros = 1;
    }
    
    if(no_leading_zeros || num > 999 || min_digits == 4) {
        *temp++ = hex_numbers_single_digit[num/1000];
        num = num%1000;
        no_leading_zeros = 1;
    }

    if(no_leading_zeros || num > 99 || min_digits == 3) {
        *temp++ = hex_numbers_single_digit[num/100];
        num = num%100;
        no_leading_zeros = 1;
    }

    if(no_leading_zeros || num > 9 || min_digits == 2) {
        *temp++ = hex_numbers_single_digit[num/10];
        num = num%10;
    }

    *temp++ = hex_numbers_single_digit[num];
    
    return temp-ptr;
}

inline static int u16_to_ascii_decimal_unaligned(
    unsigned char *ptr, u16 num)
{
    /* 
     * return u16_to_ascii_decimal_aligned(ptr, num, 0);
     * should do the job.. however, to opimize the run time
     * the code of u16_to_ascii_decimal_aligned is being
     * repeated here without the use of min_digits
     * if you fix a bug here, please check 
     * u16_to_ascii_decimal_aligned as well (and vice versa)
     */
    unsigned char *temp = ptr; 
    int no_leading_zeros = 0;

    if(num > 9999) {
        *temp++ = hex_numbers_single_digit[num/10000];
        num = num%10000;
        no_leading_zeros = 1;
    }
    
    if(no_leading_zeros || num > 999) {
        *temp++ = hex_numbers_single_digit[num/1000];
        num = num%1000;
        no_leading_zeros = 1;
    }

    if(no_leading_zeros || num > 99) {
        *temp++ = hex_numbers_single_digit[num/100];
        num = num%100;
        no_leading_zeros = 1;
    }

    if(no_leading_zeros || num > 9) {
        *temp++ = hex_numbers_single_digit[num/10];
        num = num%10;
    }

    *temp++ = hex_numbers_single_digit[num];
    
    return temp-ptr;
}

static int syslog_get_timestamp(unsigned char *ts)
{
    static const char *months[] = {"Jan ", "Feb ", "Mar ", "Apr ", "May ",
            "Jun ", "Jul ", "Aug ", "Sep ", "Oct ", "Nov ", "Dec " };

    unsigned char *temp = ts;
    /* Inserts time stamp in the syslog format and returns lenght
     * assumes that ts has sufficient space
     */
    /* China Telecom has demanded that the time stamp has to be 
     * in the format '2011 Jun 7 12:34:08'
     */
    time_t time = (time_t)cnat_get_unix_time_in_seconds();
    struct tm tm1;

    gmtime_r(&time, &tm1);
    /* Now put the pieces together */
    /* Year */
    ts += u16_to_ascii_decimal_unaligned(ts, (tm1.tm_year + 1900));
    *ts++ = SYSLOG_DELIMITER;
    /* Month */
    clib_memcpy(ts, months[tm1.tm_mon], 4);
    ts += 4; /* DELIMITER taken care */
    /* day */
    ts += u16_to_ascii_decimal_unaligned(ts, tm1.tm_mday);
    *ts++ = SYSLOG_DELIMITER;
    /* hours */ 
    ts += u16_to_ascii_decimal_aligned(ts, tm1.tm_hour, 2);
    *ts++ = ':';
    /* minutes */ 
    ts += u16_to_ascii_decimal_aligned(ts, tm1.tm_min, 2);
    *ts++ = ':';
    /* seconds */ 
    ts += u16_to_ascii_decimal_aligned(ts, tm1.tm_sec, 2);
    return ts - temp;
}

/* Ensure that the order of the below array matches with 
 * syslog_service_type enum
 */
static char *syslog_service_string[] = { "NAT44", "DSLITE" };

/* Ensure that the order of below array matches with 
 * syslog_event_type_t enum
 */
typedef struct {
    char *event_name;
    int name_length;
} syslog_event_description_type;

const static syslog_event_description_type sys_log_event[] = { 
    { "UserbasedA", 10 }, /* yes, 10 is strlen of "UserbasedA" */
    { "UserbasedW", 10 },
    { "SessionbasedA", 13 },
    { "SessionbasedW", 13 },
    { "SessionbasedAD", 14 },
    { "SessionbasedWD", 14 },
    { "Portblockrunout", 15 },
    { "TCPseqmismatch", 14},
    { "Invalid", 7 }
};

inline static int syslog_fill_header(const cnat_syslog_logging_info_t *log_info,
        syslog_service_type_t s_type)
{
    /* Forms the syslog header and returns the lenght 
     * Assumes that header has sufficient space 
     */

    /* Sample header (as agreed for China Telecom requirements  --
     * <134> 1 2011 May 31 10:30:45 192.168.2.3 - -   NAT44 -  
     */

    unsigned char *temp, *header;
    int count;
    temp = header = (unsigned char *)
        &(log_info->current_logging_context->packet_data[CNAT_NFV9_HDR_OFFSET]);
    *temp++ = '<';
    temp += byte_to_ascii_decimal_unaligned(temp, 
        log_info->header_priority);
    *temp++ = '>';
    *temp++ = SYSLOG_DELIMITER;
    *temp++ = '1'; /* Syslog version -- always set to 1 */
    *temp++ = SYSLOG_DELIMITER;
    temp += syslog_get_timestamp(temp);
    *temp++ = SYSLOG_DELIMITER;
    count = strlen(log_info->header_hostname);
    clib_memcpy(temp, log_info->header_hostname, count);
    temp += count;
    *temp++ = SYSLOG_DELIMITER;
    *temp++ = SYSLOG_FIELD_ABSENT; /* App name - nil value */
    *temp++ = SYSLOG_DELIMITER;
    *temp++ = SYSLOG_FIELD_ABSENT; /* Proc ID - nil value for now */
    *temp++ = SYSLOG_DELIMITER;
    /* Now the msg id */
    count = strlen(syslog_service_string[s_type]);
    clib_memcpy(temp, syslog_service_string[s_type], count);
    temp += count;
    *temp++ = SYSLOG_DELIMITER;
    *temp++ = SYSLOG_FIELD_ABSENT; /* No structured elements */
    *temp++ = SYSLOG_DELIMITER;
#ifdef SHOW_SYSLOG_TIMESTAMP
    printf("\nSysLog TS: %s : Length %d", header, temp - header);
#endif /*  SHOW_SYSLOG_TIMESTAMP */
    return temp-header;
}

extern void cnat_logging_init();

/* one time call at the beginning */
void cnat_syslog_logging_init() 
{
    if(PREDICT_TRUE(cnat_syslog_global_info.cnat_syslog_init_done))
        return; /* Already done */

    cnat_logging_init();
    cnat_syslog_global_info.cnat_syslog_disp_node_index = 
        spp_lookup_node_index(PLATFORM_SYSLOG_DISP_NODE_IDX);
    ASSERT(cnat_syslog_global_info.cnat_syslog_disp_node_index != (u16)~0);

    cnat_syslog_global_info.cnat_syslog_init_done = 1;
}

/*
 * edt: * * cnat_syslog_create_logging_context
 *
 * Tries to create a logging context with packet buffer
 * to send a new logging packet
 *
 * Argument: cnat_syslog_logging_info_t *logging_info
 * structure that contains the logging info and will store
 * the packet context as well.
 */
inline
void cnat_syslog_create_logging_context (
     cnat_syslog_logging_info_t      *logging_info,
     syslog_service_type_t s_type)
{
    spp_ctx_t *ctx;

    /*
     * If queued_logging_context_index is non-EMPTY, we already have a logging
     * packet queued to be sent.  First try sending this before allocating
     * a new context.  We can have only one active packet context per
     * logging_info structure
     */

    if (PREDICT_FALSE(logging_info->queued_logging_context != NULL)) {
        cnat_syslog_send_queued_pkt(logging_info);
        /*
         * If we cannot still send the queued pkt, just return 
         * Downstream Constipation count would have increased anyway
         */
        if (logging_info->queued_logging_context != NULL) {
	        cnat_syslog_global_counter.logging_context_creation_deferred_count++;
	    return;
        }
    }

    /*
     * If no context can be allocated, return silently
     * calling routine will handle updating the error counters
     */
    if (spp_ctx_alloc(&ctx, 1) < 1) {
        cnat_syslog_global_counter.logging_context_creation_fail_count++;
        SYSLOG_DEBUG_PRINTF1("\nCould not allocate ctx for syslog");
        return;
    }

    // Allocate packet buffer (used for AVSM currently)
    PLATFORM_ALLOC_NFV9_PKT_BUFFER(ctx, 0); 

    logging_info->current_logging_context = ctx;

    PLATFORM_SET_CTX_RU_TX_FROM_NODE(ctx, NODE_LOGGING);

    ctx->flags = SPP_CTX_END_OF_PACKET;
    ctx->next_ctx_this_packet = (spp_ctx_t*) SPP_CTX_NO_NEXT_CTX;
    ctx->current_header = &ctx->packet_data[CNAT_NFV9_HDR_OFFSET];

    logging_info->pkt_length = syslog_fill_header(logging_info, s_type);
    logging_info->pkt_length += (CNAT_NFV9_HDR_OFFSET - 
                                    CNAT_NFV9_IP_HDR_OFFSET); 
    logging_info->current_logging_context_timestamp =
        cnat_get_sys_up_time_in_ms();

}

inline static int u16_to_ascii_hex_unaligned(
    unsigned char *ptr, u16 num)
{
    unsigned char nibble, *temp;
    int no_leading_zeros = 0;
    temp = ptr;
    nibble = (num >> 12);
    if(nibble) {
        *temp++ = hex_numbers_single_digit[nibble];
        no_leading_zeros = 1;
    }

    nibble = (num >> 8) & 0xF;
    if(nibble || no_leading_zeros) {
        *temp++ = hex_numbers_single_digit[nibble];
        no_leading_zeros = 1;
    }
    
    nibble = (num >> 4) & 0xF;
    if(nibble || no_leading_zeros) {
        *temp++ = hex_numbers_single_digit[nibble];
    }
    
    *temp++ = hex_numbers_single_digit[num & 0xF]; 

    return temp-ptr;
}

inline static int ipv6_int_2_str(u32 ipv6[], unsigned char *ipv6_str)
{
/* DC stands for Double Colon.
 * Refer http://tools.ietf.org/html/rfc5952 for 
 * more details on text representations of 
 * IPV6 address
 */
#define DC_NOT_USED_YET 0
#define DC_IN_USE       1 /* Zeros are skipped */
#define DC_ALREADY_USED 2 /* Cannot skip zeros anymore */
    int i;
    u16 *ipv6_temp = (u16 *)ipv6;
    unsigned char *temp = ipv6_str;
    int double_colon = DC_NOT_USED_YET;
    for(i = 0; i < 7; i++) {
        if(ipv6_temp[i]) {
            ipv6_str += u16_to_ascii_hex_unaligned(ipv6_str, ipv6_temp[i]);
            *ipv6_str++ = ':';
            if(double_colon == DC_IN_USE) { /* Cannot use DC anymore */
                double_colon = DC_ALREADY_USED;
            }
        } else {
            if(double_colon == DC_IN_USE) {
                /* Skip this zero as well */
                continue;
            } else if((ipv6_temp[i+1]) 
            /* DC makes sense if there is more than one contiguous zero */
                || (double_colon != DC_NOT_USED_YET)) {
                ipv6_str += u16_to_ascii_hex_unaligned(ipv6_str, 
                        ipv6_temp[i]);
                *ipv6_str++ = ':';
            } else  { /* Start using DC */
                *ipv6_str++ = ':'; /* The 2nd colon */
                double_colon = DC_IN_USE;
            }                
        }                
    }
    if(ipv6_temp[7]) {
        ipv6_str += u16_to_ascii_hex_unaligned(ipv6_str, ipv6_temp[7]);
    } else if(double_colon != DC_IN_USE) {
        *ipv6_str++ = '0';
    }
    *ipv6_str = 0;

    return ipv6_str - temp;
}

/* insert syslog record for nat44 */

void cnat_syslog_insert_nat44_record(
    cnat_syslog_logging_info_t *log_info,
    cnat_main_db_entry_t *db, cnat_vrfmap_t *vrfmap,
    cnat_session_entry_t *sdb, int bulk_alloc, syslog_event_type_t e_type)
{
    /* This record should like this - 
     * [EventName <L4> <Original Source IP> <Inside VRF Name> 
     *   <Original Source IPv6> < Translated Source IP> <Original Port> 
     *   <Translated First Source Port> <Translated Last Source Port>
     *   <Destination ip address> <destination port>]
     */
    u32 original_source = db->in2out_key.k.ipv4;
    u32 translated_ip = db->out2in_key.k.ipv4;
    cnat_user_db_entry_t  *udb = cnat_user_db + db->user_index;
    unsigned char *temp, *record;  
    u32 network_order_ipv6[4];

    SYSLOG_CONFIG_DEBUG_PRINTF(4,"In Function %s\n", __func__);
    temp = record =  &(log_info->current_logging_context->packet_data[
            CNAT_NFV9_IP_HDR_OFFSET + log_info->pkt_length]);

    if (PREDICT_FALSE(!udb)) {
        SYSLOG_DEBUG_PRINTF1("\nnull udb!");
        return;
    }

    /* Now we point to the location where record needs to be inserted */
    *record++ = '['; /* Open the record */

    /* Copy the record type */
    clib_memcpy(record, sys_log_event[e_type].event_name, 
        sys_log_event[e_type].name_length);
    record += sys_log_event[e_type].name_length;
    *record++ = SYSLOG_DELIMITER;
   
    /* Copy the Protocol type */
    if(PREDICT_FALSE(
        e_type == sessionbased_assign || e_type == sessionbased_withdraw ||
        e_type == sessionbased_assignD || e_type == sessionbased_withdrawD)) {
        u16 my_proto_mask;
        my_proto_mask = db->in2out_key.k.vrf & CNAT_PRO_MASK;
        if(PREDICT_TRUE(my_proto_mask == CNAT_TCP)) {
            *record++ = '6';
        } else if(PREDICT_TRUE(my_proto_mask == CNAT_UDP)) {
            *record++ = '1'; 
            *record++ = '7'; 
        } else if(PREDICT_TRUE(my_proto_mask == CNAT_ICMP)) {
            *record++ = '1';
        } else { /* Default, assume GRE (for PPTP) */
            *record++ = '4';
            *record++ = '7';
        }
    } else {
        *record++ = SYSLOG_FIELD_ABSENT;        
    }
    *record++ = SYSLOG_DELIMITER;

    /* Copy the Original Source IP */
    record += copy_ipv4_addr(record, original_source);
    *record++ = SYSLOG_DELIMITER;

    /* copy configured VRF NAME */
    clib_memcpy(record, log_info->vrf_name, log_info->vrf_name_len);
    record += log_info->vrf_name_len;
    *record++ = SYSLOG_DELIMITER;
    
    /* No IPV6 source address for nat44 */
    *record++ = SYSLOG_FIELD_ABSENT;        
    *record++ = SYSLOG_DELIMITER;

    /* Copy the translated IP address */
    record += copy_ipv4_addr(record, translated_ip);
    *record++ = SYSLOG_DELIMITER;
    
    /* Copy the Original port */
    if(e_type == sessionbased_assign || e_type == sessionbased_withdraw ||
       e_type == sessionbased_assignD || e_type == sessionbased_withdrawD) {
        record += u16_to_ascii_decimal_unaligned(
        record, db->in2out_key.k.port); 
    } else {
       *record++ = SYSLOG_FIELD_ABSENT; 
    }
    *record++ = SYSLOG_DELIMITER;

    /* Copy the start outside port */
    record += u16_to_ascii_decimal_unaligned(record, bulk_alloc);
    *record++ = SYSLOG_DELIMITER;

    /* Copy the last outside port */
    if(e_type == userbased_assign || e_type == userbased_withdraw) {
       record += u16_to_ascii_decimal_unaligned(record,
            (bulk_alloc + BULKSIZE_FROM_VRFMAP(vrfmap) - 1));
    } else {
        *record++ = SYSLOG_FIELD_ABSENT;
    }
    *record++ = SYSLOG_DELIMITER;

    /* Copy destination ip and port in case for DBL*/
    if(PREDICT_FALSE(e_type == sessionbased_assignD || e_type == sessionbased_withdrawD)) {
        if(PREDICT_TRUE(sdb == NULL)) {
            record += copy_ipv4_addr(record,db->dst_ipv4);
            *record++ = SYSLOG_DELIMITER;
            record += u16_to_ascii_decimal_unaligned(record, db->dst_port);
        } else {
            record += copy_ipv4_addr(record, sdb->v4_dest_key.k.ipv4);
            *record++ = SYSLOG_DELIMITER;
            record += u16_to_ascii_decimal_unaligned(record, sdb->v4_dest_key.k.port);
        }
    } else {
        *record++ = '-';
        *record++ = SYSLOG_DELIMITER;
        *record++ = '-';
    }
    *record++ = SYSLOG_DELIMITER;
     
    *record++ = ']'; /* End of the reocrd */

    log_info->pkt_length += record - temp;
}

void cnat_syslog_insert_record(
    cnat_syslog_logging_info_t *log_info,
    cnat_main_db_entry_t *db, dslite_table_entry_t *dslite_entry,
    cnat_session_entry_t *sdb, int bulk_alloc, syslog_event_type_t e_type)
{
    /* This record should like this - 
     * [EventName <L4> <Original Source IP> <Inside VRF Name> 
     *   <Original Source IPv6> < Translated Source IP> <Original Port> 
     *   <Translated First Source Port> <Translated Last Source Port>
     *   <Destination ip address> <destination port>]
     */
    u32 original_source = db->in2out_key.k.ipv4;
    u32 translated_ip = db->out2in_key.k.ipv4;
    cnat_user_db_entry_t  *udb = cnat_user_db + db->user_index;
    unsigned char *temp, *record;  
    u32 network_order_ipv6[4];

    temp = record =  &(log_info->current_logging_context->packet_data[
            CNAT_NFV9_IP_HDR_OFFSET + log_info->pkt_length]);

    if (PREDICT_FALSE(!udb)) {
        SYSLOG_DEBUG_PRINTF1("\nnull udb!");
        return;
    }

    /* Now we point to the location where record needs to be inserted */
    *record++ = '['; /* Open the record */

    /* Copy the record type */
    clib_memcpy(record, sys_log_event[e_type].event_name, 
        sys_log_event[e_type].name_length);
    record += sys_log_event[e_type].name_length;
    *record++ = SYSLOG_DELIMITER;
   
    /* Copy the Protocol type */
    if(PREDICT_FALSE(
        e_type == sessionbased_assign || e_type == sessionbased_withdraw ||
        e_type == sessionbased_assignD || e_type == sessionbased_withdrawD)) {
        u16 my_proto_mask;
        my_proto_mask = db->in2out_key.k.vrf & CNAT_PRO_MASK;
        if(PREDICT_TRUE(my_proto_mask == CNAT_TCP)) {
            *record++ = '6';
        } else if(PREDICT_TRUE(my_proto_mask == CNAT_UDP)) {
            *record++ = '1'; 
            *record++ = '7'; 
        } else {
            *record++ = '1'; 
        }
    } else {
        *record++ = SYSLOG_FIELD_ABSENT;        
    }

    *record++ = SYSLOG_DELIMITER;

     /* Copy the Original Source IP */
#ifdef DSLITE_USER_IPV4
     record += copy_ipv4_addr(record, original_source);
#else
    /*
     * Do not include inside ipv4 address for B4 element level port limiting
     */
     *record++ = SYSLOG_FIELD_ABSENT;        
#endif
     *record++ = SYSLOG_DELIMITER;
 
    /* copy configured VRF NAME */
    clib_memcpy(record, log_info->vrf_name, log_info->vrf_name_len);
    record += log_info->vrf_name_len;
    *record++ = SYSLOG_DELIMITER;
    
    /* Copy the IPV6 source address */
    /* CSCtt16960 Fix. */
    network_order_ipv6[0] = htonl(udb->ipv6[0]);
    network_order_ipv6[1] = htonl(udb->ipv6[1]);
    network_order_ipv6[2] = htonl(udb->ipv6[2]);
    network_order_ipv6[3] = htonl(udb->ipv6[3]);

    inet_ntop(AF_INET6,network_order_ipv6,record,INET6_ADDRSTRLEN);
    record += strlen(record);
    *record++ = SYSLOG_DELIMITER;

    /* Copy the translated IP address */
    record += copy_ipv4_addr(record, translated_ip);
    *record++ = SYSLOG_DELIMITER;
    
    /* Copy the Original port */
    if(e_type == sessionbased_assign || e_type == sessionbased_withdraw ||
       e_type == sessionbased_assignD || e_type == sessionbased_withdrawD) {
        record += u16_to_ascii_decimal_unaligned(
        record, db->in2out_key.k.port); 
    } else {
       *record++ = SYSLOG_FIELD_ABSENT; 
    }
    *record++ = SYSLOG_DELIMITER;

    /* Copy the start outside port */
    record += u16_to_ascii_decimal_unaligned(record, bulk_alloc);
    *record++ = SYSLOG_DELIMITER;

    /* Copy the last outside port */
    if(e_type == userbased_assign || e_type == userbased_withdraw) {
       record += u16_to_ascii_decimal_unaligned(record,
            (bulk_alloc + BULKSIZE_FROM_VRFMAP(dslite_entry) - 1));
    } else {
        *record++ = SYSLOG_FIELD_ABSENT;
    }
    *record++ = SYSLOG_DELIMITER;

    if(PREDICT_FALSE(e_type == sessionbased_assignD || e_type == sessionbased_withdrawD)) {
        if(sdb == NULL) {
            record += copy_ipv4_addr(record, db->dst_ipv4);
            *record++ = SYSLOG_DELIMITER;
            record += u16_to_ascii_decimal_unaligned(record, db->dst_port);
        } else {
            record += copy_ipv4_addr(record, sdb->v4_dest_key.k.ipv4);
            *record++ = SYSLOG_DELIMITER;
            record += u16_to_ascii_decimal_unaligned(record, sdb->v4_dest_key.k.port);
        }
    } else {
        *record++ = '-';
        *record++ = SYSLOG_DELIMITER;
        *record++ = '-';
    }
    *record++ = SYSLOG_DELIMITER;

    *record++ = ']'; /* End of the reocrd */

    log_info->pkt_length += record - temp;
}

#define SYSLOG_PRECHECK(entry, s_type)  \
    if(PREDICT_FALSE((entry)->syslog_logging_index == EMPTY)) { \
        SYSLOG_DEBUG_PRINTF1("\n1. Log Mapping failed") \
	    return; \
    } \
    logging_info = \
        cnat_syslog_logging_info_pool + (entry)->syslog_logging_index; \
    if(PREDICT_FALSE(logging_info->current_logging_context == NULL)) { \
        cnat_syslog_create_logging_context(logging_info, s_type); \
        if(PREDICT_FALSE(logging_info->current_logging_context == NULL)) { \
            SYSLOG_DEBUG_PRINTF1("\n2. Log Mapping failed") \
            return; \
        } \
    } 

void cnat_syslog_nat44_mapping_create(cnat_main_db_entry_t *db,
        cnat_vrfmap_t *vrfmap, cnat_session_entry_t * sdb
#ifndef NO_BULK_LOGGING
                       , int bulk_alloc
#endif
                       )
{
    cnat_syslog_logging_info_t *logging_info = 0; 
    syslog_event_type_t e_type;
    int start_port;

    SYSLOG_CONFIG_DEBUG_PRINTF(4,"In Function %s\n", __func__);
    SYSLOG_PRECHECK(vrfmap, NAT44)

#ifndef NO_BULK_LOGGING
    if(bulk_alloc > 0) { /* new bulk alloc - use bulk add template */
        e_type = userbased_assign;
        start_port = bulk_alloc;
    } else if(bulk_alloc == CACHE_ALLOC_NO_LOG_REQUIRED) {
        return; /* No logging required.. bulk port usage */
    }
    else { /* Individual logging .. fall back to old method */
#endif
    if(vrfmap->syslog_logging_policy == SESSION_LOG_ENABLE) {
        e_type = sessionbased_assignD;
    } else {
        e_type = sessionbased_assign;
    }
    start_port = db->out2in_key.k.port;
#ifndef NO_BULK_LOGGING
    }
#endif

    cnat_syslog_insert_nat44_record(logging_info, db, vrfmap, sdb, 
            start_port, e_type);

    /*
     * If we have exceeded the packet length, let us send the
     * packet now.  There is buffer of additional bytes beyond
     * max_pkt_length to ensure that the last add/delete record
     * can be stored safely.
     */

    if (PREDICT_FALSE(logging_info->pkt_length >
        logging_info->max_length_minus_max_record_size)) {
        cnat_syslog_send_pkt(logging_info);
    }
}

void cnat_syslog_ds_lite_mapping_create(cnat_main_db_entry_t *db,
        dslite_table_entry_t *dslite_entry, cnat_session_entry_t *sdb
#ifndef NO_BULK_LOGGING
                       , int bulk_alloc
#endif
                       )
{
    cnat_syslog_logging_info_t *logging_info = 0; 
    syslog_event_type_t e_type;
    int start_port;

    SYSLOG_PRECHECK(dslite_entry, DSLite)

#ifndef NO_BULK_LOGGING
    if(bulk_alloc > 0) { /* new bulk alloc - use bulk add template */
        e_type = userbased_assign;
        start_port = bulk_alloc;
    } else if(bulk_alloc == CACHE_ALLOC_NO_LOG_REQUIRED) {
        return; /* No logging required.. bulk port usage */
    }
    else { /* Individual logging .. fall back to old method */
#endif
    if(PREDICT_FALSE(dslite_entry->syslog_logging_policy == SESSION_LOG_ENABLE)) {
        e_type = sessionbased_assignD;
    } else {
        e_type = sessionbased_assign;
    }
    start_port = db->out2in_key.k.port;  
#ifndef NO_BULK_LOGGING
    }
#endif

    cnat_syslog_insert_record(logging_info, db, dslite_entry, sdb, 
            start_port, e_type);

    /*
     * If we have exceeded the packet length, let us send the
     * packet now.  There is buffer of additional bytes beyond
     * max_pkt_length to ensure that the last add/delete record
     * can be stored safely.
     */

    if (PREDICT_FALSE(logging_info->pkt_length >
        logging_info->max_length_minus_max_record_size)) {
        cnat_syslog_send_pkt(logging_info);
    }
}

void cnat_syslog_nat44_mapping_delete(cnat_main_db_entry_t *db,
        cnat_vrfmap_t *vrfmap, cnat_session_entry_t *sdb
#ifndef NO_BULK_LOGGING
        , int bulk_alloc
#endif
        )
{
    cnat_syslog_logging_info_t *logging_info = 0; 
    syslog_event_type_t e_type;
    int start_port;

    SYSLOG_CONFIG_DEBUG_PRINTF(4,"In Function %s\n", __func__);
    SYSLOG_PRECHECK(vrfmap, NAT44)

#ifndef NO_BULK_LOGGING
    if(bulk_alloc > 0) { /* new bulk alloc - use bulk add template */
        e_type = userbased_withdraw;
        start_port = bulk_alloc;
    } else if(bulk_alloc == CACHE_ALLOC_NO_LOG_REQUIRED) {
        return; /* No logging required.. bulk port usage */
    }
    else { /* Individual logging .. fall back to old method */
#endif
    if(vrfmap->syslog_logging_policy == SESSION_LOG_ENABLE) {
        e_type = sessionbased_withdrawD;
    } else {
        e_type = sessionbased_withdraw;
    }
    start_port = db->out2in_key.k.port;  
#ifndef NO_BULK_LOGGING
    }
#endif
    cnat_syslog_insert_nat44_record(logging_info, db, vrfmap, sdb, 
            start_port, e_type);
    /*
     * If we have exceeded the packet length, let us send the
     * packet now.  There is buffer of additional bytes beyond
     * max_pkt_length to ensure that the last add/delete record
     * can be stored safely.
     */
    if (PREDICT_FALSE(logging_info->pkt_length >
        logging_info->max_length_minus_max_record_size)) {
        cnat_syslog_send_pkt(logging_info);
    }
}

void cnat_syslog_ds_lite_mapping_delete(cnat_main_db_entry_t *db,
        dslite_table_entry_t *dslite_entry, cnat_session_entry_t *sdb
#ifndef NO_BULK_LOGGING
        , int bulk_alloc
#endif
        )
{
    cnat_syslog_logging_info_t *logging_info = 0; 
    syslog_event_type_t e_type;
    int start_port;

    SYSLOG_PRECHECK(dslite_entry, DSLite)

#ifndef NO_BULK_LOGGING
    if(bulk_alloc > 0) { /* new bulk alloc - use bulk add template */
        e_type = userbased_withdraw;
        start_port = bulk_alloc;
    } else if(bulk_alloc == CACHE_ALLOC_NO_LOG_REQUIRED) {
        return; /* No logging required.. bulk port usage */
    }
    else { /* Individual logging .. fall back to old method */
#endif
    if(PREDICT_FALSE(dslite_entry->syslog_logging_policy == SESSION_LOG_ENABLE)) {
        e_type = sessionbased_withdrawD;
    } else {
        e_type = sessionbased_withdraw;
    }
    start_port = db->out2in_key.k.port;  
#ifndef NO_BULK_LOGGING
    }
#endif
    cnat_syslog_insert_record(logging_info, db, dslite_entry, sdb, 
        start_port, e_type);

    /*
     * If we have exceeded the packet length, let us send the
     * packet now.  There is buffer of additional bytes beyond
     * max_pkt_length to ensure that the last add/delete record
     * can be stored safely.
     */

    if (PREDICT_FALSE(logging_info->pkt_length >
        logging_info->max_length_minus_max_record_size)) {
        cnat_syslog_send_pkt(logging_info);
    }
}

void cnat_syslog_dslite_insert_port_exceeded(
     cnat_syslog_logging_info_t *log_info,
     dslite_key_t   * key)
{
    /* This record should like this - 
     * [Portblockrunout <L4> <Original Source IP> <Inside VRF Name> 
     *   <Original Source IPv6> - <Original Port> - - - -]
     */
    u32 network_order_ipv6[4];
    unsigned char *temp, *record;  

    temp = record =  &(log_info->current_logging_context->packet_data[
            CNAT_NFV9_IP_HDR_OFFSET + log_info->pkt_length]);

    /* Now we point to the location where record needs to be inserted */
    *record++ = '['; /* Open the record */

    /* Copy the record type */
    clib_memcpy(record, sys_log_event[port_block_runout].event_name, 
        sys_log_event[port_block_runout].name_length);
    record += sys_log_event[port_block_runout].name_length;
    *record++ = SYSLOG_DELIMITER;
   
    u16 my_proto_mask;
    my_proto_mask = key->ipv4_key.k.vrf & CNAT_PRO_MASK;
    if(PREDICT_TRUE(my_proto_mask == CNAT_TCP)) {
        *record++ = '6';
    } else if(PREDICT_TRUE(my_proto_mask == CNAT_UDP)) {
        *record++ = '1'; 
        *record++ = '7'; 
    } else {
        *record++ = '1'; 
    }
    *record++ = SYSLOG_DELIMITER;

    /* Copy the Original Source IP */
    record += copy_ipv4_addr(record, key->ipv4_key.k.ipv4);
    *record++ = SYSLOG_DELIMITER;

    /* copy configured VRF NAME */
    clib_memcpy(record, log_info->vrf_name, log_info->vrf_name_len);
    record += log_info->vrf_name_len;
    *record++ = SYSLOG_DELIMITER;
    
    /* Copy the IPV6 source address */
    network_order_ipv6[0] = htonl(key->ipv6[0]);
    network_order_ipv6[1] = htonl(key->ipv6[1]);
    network_order_ipv6[2] = htonl(key->ipv6[2]);
    network_order_ipv6[3] = htonl(key->ipv6[3]);

    inet_ntop(AF_INET6,network_order_ipv6,record,INET6_ADDRSTRLEN);
    record += strlen(record);
    *record++ = SYSLOG_DELIMITER;

    *record++ = SYSLOG_FIELD_ABSENT; /* No translated source ip */
    *record++ = SYSLOG_DELIMITER;
    
    record += u16_to_ascii_decimal_unaligned(
        record, key->ipv4_key.k.port); 
    *record++ = SYSLOG_DELIMITER;
   
    *record++ = SYSLOG_FIELD_ABSENT; /* No translated start port */
    *record++ = SYSLOG_DELIMITER;

    *record++ = SYSLOG_FIELD_ABSENT; /* No translated end port */
    *record++ = SYSLOG_DELIMITER;

    /*No Destination Info*/
    *record++ = '-';
    *record++ = SYSLOG_DELIMITER;
    *record++ = '-';
    *record++ = SYSLOG_DELIMITER;

    *record++ = ']'; /* End of the reocrd */

    log_info->pkt_length += record - temp;
}

void cnat_syslog_ds_lite_port_limit_exceeded(
        dslite_key_t   * key,
        dslite_table_entry_t *dslite_entry)
{
    cnat_syslog_logging_info_t *logging_info = 0; 

    SYSLOG_PRECHECK(dslite_entry, DSLite)

    cnat_syslog_dslite_insert_port_exceeded(logging_info, key);

    /*
     * If we have exceeded the packet length, let us send the
     * packet now.  There is buffer of additional bytes beyond
     * max_pkt_length to ensure that the last add/delete record
     * can be stored safely.
     */

    if (PREDICT_FALSE(logging_info->pkt_length >
        logging_info->max_length_minus_max_record_size)) {
        cnat_syslog_send_pkt(logging_info);
    }
}

void cnat_syslog_nat44_insert_port_exceeded(
     cnat_syslog_logging_info_t *log_info,
     cnat_key_t   * key)
{
    /* This record should like this - 
     * [Portblockrunout <L4> <Original Source IP> <Inside VRF Name> 
     *  - - <Original Port> - - - -]
     */
    unsigned char *temp, *record;

    temp = record =  &(log_info->current_logging_context->packet_data[
            CNAT_NFV9_IP_HDR_OFFSET + log_info->pkt_length]);

    /* Now we point to the location where record needs to be inserted */
    *record++ = '['; /* Open the record */

    /* Copy the record type */
    clib_memcpy(record, sys_log_event[port_block_runout].event_name,
        sys_log_event[port_block_runout].name_length);
    record += sys_log_event[port_block_runout].name_length;
    *record++ = SYSLOG_DELIMITER;

    u16 my_proto_mask;
    my_proto_mask = key->k.vrf & CNAT_PRO_MASK;
    if(PREDICT_TRUE(my_proto_mask == CNAT_TCP)) {
        *record++ = '6';
    } else if(PREDICT_TRUE(my_proto_mask == CNAT_UDP)) {
        *record++ = '1';
        *record++ = '7';
    } else {
        *record++ = '1';
    }
    *record++ = SYSLOG_DELIMITER;

    /* Copy the Original Source IP */
    record += copy_ipv4_addr(record, key->k.ipv4);
    *record++ = SYSLOG_DELIMITER;

    /* copy configured VRF NAME */
    clib_memcpy(record, log_info->vrf_name, log_info->vrf_name_len);
    record += log_info->vrf_name_len;
    *record++ = SYSLOG_DELIMITER;

    /* No IPV6 source address for nat44 */
    *record++ = '-';
    *record++ = SYSLOG_DELIMITER;

    *record++ = '-'; /* No translated source ip */
    *record++ = SYSLOG_DELIMITER;

    record += u16_to_ascii_decimal_unaligned(
        record, key->k.port);
    *record++ = SYSLOG_DELIMITER;

    *record++ = '-'; /* No translated start port */
    *record++ = SYSLOG_DELIMITER;

    *record++ = '-'; /* No translated end port */
    *record++ = SYSLOG_DELIMITER;

    /*No Destination Info*/
    *record++ = '-';
    *record++ = SYSLOG_DELIMITER;
    *record++ = '-';
    *record++ = SYSLOG_DELIMITER;

    *record++ = ']'; /* End of the reocrd */

    log_info->pkt_length += record - temp;
}

void cnat_syslog_nat44_port_limit_exceeded(
        cnat_key_t   * key,
        cnat_vrfmap_t *vrfmap)
{   
    cnat_syslog_logging_info_t *logging_info = 0;
    
    SYSLOG_PRECHECK(vrfmap, NAT44)

    cnat_syslog_nat44_insert_port_exceeded(logging_info, key);
    
    /*
     * If we have exceeded the packet length, let us send the
     * packet now.  There is buffer of additional bytes beyond
     * max_pkt_length to ensure that the last add/delete record
     * can be stored safely.
     */

    if (PREDICT_FALSE(logging_info->pkt_length >
        logging_info->max_length_minus_max_record_size)) {
        cnat_syslog_send_pkt(logging_info);
    }
}

void cnat_syslog_nat44_insert_tcp_seq_mismatch(
     cnat_syslog_logging_info_t *log_info,
     cnat_main_db_entry_t *db)
{
    /* This record should like this - 
     * [TCPseqmismatch <L4> <Original Source IP> <Inside VRF Name> 
     *  - <Translated Source IP> <Original Port> <Translated Source Port> - - -]
     */
    unsigned char *temp, *record;

    temp = record =  &(log_info->current_logging_context->packet_data[
            CNAT_NFV9_IP_HDR_OFFSET + log_info->pkt_length]);

    /* Now we point to the location where record needs to be inserted */
    *record++ = '['; /* Open the record */

    /* Copy the record type */
    clib_memcpy(record, sys_log_event[tcp_seq_mismatch].event_name,
        sys_log_event[tcp_seq_mismatch].name_length);
    record += sys_log_event[tcp_seq_mismatch].name_length;
    *record++ = SYSLOG_DELIMITER;

    /*  Next field is TCP */
    *record++ = '6';
    *record++ = SYSLOG_DELIMITER;

    /* Copy the Original Source IP */
    record += copy_ipv4_addr(record, db->in2out_key.k.ipv4);
    *record++ = SYSLOG_DELIMITER;

    /* copy configured VRF NAME */
    clib_memcpy(record, log_info->vrf_name, log_info->vrf_name_len);
    record += log_info->vrf_name_len;
    *record++ = SYSLOG_DELIMITER;

    /* No IPV6 source address for nat44 */
    *record++ = '-';
    *record++ = SYSLOG_DELIMITER;

    record += copy_ipv4_addr(record, db->out2in_key.k.ipv4);
    *record++ = SYSLOG_DELIMITER;

    record += u16_to_ascii_decimal_unaligned(
        record,  db->in2out_key.k.port);
    *record++ = SYSLOG_DELIMITER;

    record += u16_to_ascii_decimal_unaligned(
        record,  db->out2in_key.k.port);
    *record++ = SYSLOG_DELIMITER;

    *record++ = '-'; /* No translated end port */
    *record++ = SYSLOG_DELIMITER;

    /*No Destination Info*/
    *record++ = '-';
    *record++ = SYSLOG_DELIMITER;
    *record++ = '-';
    *record++ = SYSLOG_DELIMITER;

    *record++ = ']'; /* End of the reocrd */

    log_info->pkt_length += record - temp;
}

void cnat_syslog_nat44_tcp_seq_mismatch(
        cnat_main_db_entry_t *db,
        cnat_vrfmap_t *vrfmap)
{   
    cnat_syslog_logging_info_t *logging_info = 0;
    
    SYSLOG_PRECHECK(vrfmap, NAT44)

    cnat_syslog_nat44_insert_tcp_seq_mismatch(logging_info, db);
    
    /*
     * If we have exceeded the packet length, let us send the
     * packet now.  There is buffer of additional bytes beyond
     * max_pkt_length to ensure that the last add/delete record
     * can be stored safely.
     */

    if (PREDICT_FALSE(logging_info->pkt_length >
        logging_info->max_length_minus_max_record_size)) {
        cnat_syslog_send_pkt(logging_info);
    }
}
#endif
