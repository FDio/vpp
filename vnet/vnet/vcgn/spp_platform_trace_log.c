/*
 *------------------------------------------------------------------
 * spp_platform_trace_log.c 
 *
 * Copyright (c) 2008-2011, 2013 Cisco and/or its affiliates.
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
#include <stdio.h>
#include <vppinfra/vec.h>
#include <vppinfra/bitmap.h>
#include <vppinfra/hash.h>
#include <vppinfra/pool.h>
#include <vppinfra/clib.h>
#include <vlib/main.h>

#include "tcp_header_definitions.h"
#include "platform_common.h"
#include "spp_platform_trace_log.h"

#define WORD_SIZE sizeof(u32)

int temperature_read_blocked = 1;

spp_cnat_logger_tbl_t spp_cnat_logger_table[] =
{
  { CNAT_ERROR_SUCCESS,
    3,
    0,
    {"i-vrf",
    "ipv4 addr",
     "port"}
  },
  { CNAT_NO_CONFIG_ERROR,
    3,
    180,
    {"i-vrf",
    "ipv4 addr",
     "port"}
  },
  { CNAT_NO_VRF_RUN_ERROR,
    3,
    180,
    {"i-vrf",
    "ipv4 addr",
     "port"}
  },
  { CNAT_NO_POOL_FOR_ANY_ERROR,
    3,
    180,
    {"i-vrf",
    "ipv4 addr",
     "port"}
  },
  { CNAT_NO_PORT_FOR_ANY_ERROR,
    3,
    60,
    {"i-vrf",
    "ipv4 addr",
     "port"}
  },
  { CNAT_BAD_INUSE_ANY_ERROR,
    3,
    60,
    {"i-vrf",
    "ipv4 addr",
     "port"}
  },
  { CNAT_NOT_FOUND_ANY_ERROR,
    3,
    60,
    {"i-vrf",
    "ipv4 addr",
     "port"}
  },
  { CNAT_INV_PORT_FOR_DIRECT_ERROR,
    3,
    60,
    {"i-vrf",
    "ipv4 addr",
     "port"}
  },
  { CNAT_BAD_INUSE_DIRECT_ERROR,
    3,
    1,
    {"i-vrf",
    "ipv4 addr",
     "port"}
  },
  { CNAT_NOT_FOUND_DIRECT_ERROR,
    3,
    1,
    {"i-vrf",
    "ipv4 addr",
     "port"}
  },
  { CNAT_OUT_OF_PORT_LIMIT_ERROR,
    3,
    60,
    {"i-vrf",
    "ipv4 addr",
     "port"}
  },
  { CNAT_MAIN_DB_CREATE_ERROR, 
    0,
    30,
    {""}
  },
  { CNAT_LOOKUP_ERROR,
    1,
    30,
    {"Type"}
  },
  { CNAT_INDEX_MISMATCH_ERROR,
    2,
    30,
    {"in2out_index",
     "out2in_index"}
  },
  { CNAT_PACKET_DROP_ERROR,
    3,
    15,
    {"i-vrf",
    "ipv4 addr",
     "port"}
  },
  { CNAT_INV_UNUSED_USR_INDEX,
    1,
    10,
    {"invalid/unused user index"}
  },
  { CNAT_INVALID_VRFMAP_INDEX,
    0,
    60,
    {""}
  },
  { CNAT_USER_OUT_OF_PORTS,
    2,
    1800,
    {"i-vrf",
     "ipv4 addr"}
  },
  { CNAT_EXT_PORT_THRESH_EXCEEDED,
    2,
    180,
    {"i-vrf",
     "ipv4 address"}
  },
  { CNAT_EXT_PORT_THRESH_NORMAL,
    2,
    180,
    {"vrf",
     "ipv4 address"}
  },
  { CNAT_NO_EXT_PORT_AVAILABLE,
    0,
    1,
    {"",}
  },
  { CNAT_SESSION_THRESH_EXCEEDED,
    2,
    1800, 
    {"vrf",
     "ipv4 address"}
  },
  { CNAT_SESSION_THRESH_NORMAL,
    2,
    30, /* changed to 30 */
    {"vrf",
     "ipv4 address"}
  },
  { WQE_ALLOCATION_ERROR,
    0,
    180, /* changed to 180 */
    {""}
  },
  { ERROR_PKT_DROPPED,
    2,
    60, /* changed to 60 */
    {"spi-port",
     "error-code"}
  },
  { SYSMGR_PD_KEY_CREATION_ERROR,
    0,
    30,
    {""}
  },
  { SYSMGR_PD_SHMEM_ID_ERROR,
    0,
    1,
    {""}
  },
  { SYSMGR_PD_SHMEM_ATTACH_ERROR,
    0,
    1,
    {""}
  },
  { OCTEON_CKHUM_SKIPPED,
    2,
    60, /* changed to 60 */
    {"version",
     "protocol"}
  },
  { PK0_SEND_STATUS,
    1,
    15,
    {"status"}
  },
  { CMD_BUF_ALLOC_ERR,
    0,
    60,
    {""}
  },
  { SPP_CTX_ALLOC_FAILED,
    1,
    300, /* every 5 min  */
    {"node"}
  },
  { SPP_MAX_DISPATCH_REACHED,
    1,
    60,
    {"node"}
  },
  { HA_SIGCHILD_RECV,
    3,
    1,
    {"pid",
    "uid",
     "signal",}
  },
  { SIGACTION_ERR,
    0,
    1,
    {""}
  },
  { HA_INVALID_SEQ_OR_CONFIG_OR_TYPE,
    2,
    10,
    {"seq-id or config option",
     "Type"}
  },
  { NODE_CREATION_ERROR,
    1,
    1,
    {"node"}
  },

  { CNAT_CLI_INVALID_INPUT,
      4,
      0,
    {"Error Type",
      "Passed",
      "Expected",
     "Type"}
  },
  { CNAT_DUMMY_HANDLER_HIT,
      1,
      0,
    {"Handler"}
  },
  { CNAT_CONFIG_ERROR,
      5,
      0,
    {"Sub code",
      "Param 1",
      "Param 2",
      "Param 3",
     "Param 4"}
  },
  { CNAT_NFV9_ERROR,
      1,
      180, /* changed to 180 */
    {"Sub code"}
  },
  { CNAT_CMVX_TWSI_READ_WRITE_FAIL,
     3,
     180,
    {"Operation",
     "Location",
     "Data"}
  },
  { CNAT_TEMP_SENSOR_TIMEOUT,
      0,
      180,
    {""}
  },
  { CNAT_TEMP_SENSOR_DATA_MISMATCH,
      2,
      180,
    {"Actual",
     "Expected"}
  },
  { CNAT_TEMP_SENSOR_CONFIG_FAILED,
      1,
      180,
    {"Glik"}
  },
  { HA_APP_NOT_RESPONDING,
      2,
      180,
    {"CPU",
     "Core"}
  },
  { HA_DATA_PATH_TEST_FAILED,
      0,
      30,
    {""}
  },
  { CNAT_WRONG_PORT_ALLOC_TYPE,
      3,
      60,
    {"i-vrf",
      "ipv4 addr",
     "port"}
  },
  { CNAT_NEW_PORT_ALLOC_ERROR,
      3,
      60,
    {"i-vrf",
      "ipv4 addr",
     "port"}
  },
  { CNAT_INVALID_INDEX_TO_FREE_PORT,
      0,
      60,
    {""}
  },
  { CNAT_DELETE_DB_ENTRY_NO_PORTMAP,
      0,
      60,
    {""}
  },
  { CNAT_MAIN_DB_LIMIT_ERROR,
      0,
      180,
    {""}
  },
  { CNAT_USER_DB_LIMIT_ERROR,
      0,
      180,
    {""}
  },
  { CNAT_FRAG_DB_ERROR,
      1,
      180,
    {"Type"}
  },

  { DROP_PKT_DUMP,
    0,
    20,
    {""}
  }
};

#define LOG_TABLE_MAX_ENTRIES \
   (sizeof(spp_cnat_logger_table)/sizeof(spp_cnat_logger_table[0]))

u32 error_code_timestamps[LOG_TABLE_MAX_ENTRIES];
spp_timer_t sensor_timer;
spp_trace_log_global_info_t spp_trace_log_global_info;
spp_global_counters_t spp_global_counters;

/*
 * Logging information structures
 */
spp_trace_log_info_t spp_default_trace_log_info;
spp_trace_log_info_t *spp_trace_log_info_pool;

#ifdef TOBE_PORTED
/*
 * The following 2 functions are temporary hacks until
 * we have RTC support from the PD nodes
 */
inline
u32 spp_trace_log_get_sys_up_time_in_ms (void)
{
    spp_node_main_vector_t *nmv;
    u32 sys_up_time;

    nmv = spp_get_node_main_vectorized_inline();
		    
    sys_up_time = (u32) (nmv->ticks / nmv->ticks_per_ms);

    return (sys_up_time);
}

u32 spp_trace_log_get_unix_time_in_seconds (void)
{
    spp_node_main_vector_t *nmv;
    u32 unix_time;

    nmv = spp_get_node_main_vectorized_inline();
		    
    unix_time = (u32) (nmv->ticks / nmv->ticks_per_second);

    return (unix_time);
}

/*
 * edt: * * spp_trace_log_send_queued_pkt
 *
 * Tries to send a logging pkt that has been queued earlier
 * because it could not be sent due to downstream constipation
 *
 * Argument: spp_trace_log_info_t *trace_logging_info
 * structure that contains the packet context
 */
inline
void spp_trace_log_send_queued_pkt (spp_trace_log_info_t *trace_logging_info)
{
    spp_node_t                  *output_node;

    output_node = spp_get_nodes() + 
       	spp_trace_log_global_info.spp_trace_log_disp_node_index;

    if (PREDICT_TRUE(output_node->sf.nused < SPP_MAXDISPATCH)) {
        /*
         * Move the logging context to output node
         */
        spp_dispatch_make_node_runnable(output_node);
        output_node->sf.ctxs[output_node->sf.nused++] = 
            trace_logging_info->queued_logging_context;

        /*
         * Context has been queued, it will be freed after the pkt
         * is sent.  Clear this from the logging_context_info structure
         */
	    trace_logging_info->queued_logging_context = NULL;

    } else {
	    /*
	     * Can't do much, just return, may be we can send it later
	     */
        spp_global_counters.spp_trace_log_downstream_constipation_count++;
    }
}

/*
 * edt: * * spp_trace_log_send_pkt
 *
 * Tries to send a logging pkt.  If the packet cannot be sent
 * because of rewrite_output node cannot process it, queue
 * it temporarily and try to send it later.
 *
 * Argument: spp_trace_log_info_t *trace_logging_info
 * structure that contains the packet context
 */
inline
void spp_trace_log_send_pkt (spp_trace_log_info_t *trace_logging_info)
{
    spp_node_t                  *output_node;


    output_node = spp_get_nodes() + 
     	spp_trace_log_global_info.spp_trace_log_disp_node_index;

    if (PREDICT_TRUE(output_node->sf.nused < SPP_MAXDISPATCH)) {
        /*
         * Move the logging context to output node
         */
        spp_dispatch_make_node_runnable(output_node);
        output_node->sf.ctxs[output_node->sf.nused++] = 
            trace_logging_info->current_logging_context;

    } else {
     	/*
	     * Queue the context into the logging_info structure,
	     * We will try to send it later.  Currently, we will
         * restrict to only one context queued.
	     */
        spp_global_counters.spp_trace_log_downstream_constipation_count++;

	    /*
	     * Attach the current logging context which is full to the
	     * queued context list in trace_logging_info structure
	     */
	    trace_logging_info->queued_logging_context =
	            trace_logging_info->current_logging_context;

	    /*
	     * Whether the context is queued or not, set the current context index
	     * to EMPTY, as the earlier context can no more be used to send
	     * more logging records.
	     */
    }

    trace_logging_info->current_logging_context = NULL;
}

/*
 * edt: * * spp_trace_log_send_pkt_always_success
 *
 * Tries to send a logging pkt.  This cannot fail due to downstream
 * constipation because we have already checked if the rewrite_output
 * node can accept it.
 *
 * Argument: spp_trace_log_info_t *trace_logging_info
 * structure that contains the packet context
 *
 * Argument: spp_node_t *output_node
 * spp_node_t structure for rewrite_output node
 */
inline
void spp_trace_log_send_pkt_always_success (
                         spp_trace_log_info_t *trace_logging_info,
                         spp_node_t               *output_node)
{
    /*
     * At this point we either have a current or queued logging context
     */
    if (PREDICT_TRUE(trace_logging_info->current_logging_context != NULL)) { 

    	output_node->sf.ctxs[output_node->sf.nused++] = 
	    trace_logging_info->current_logging_context;

        trace_logging_info->current_logging_context = NULL;
    } else {
    	/*
     	 * For queued logging context
	     */
	    output_node->sf.ctxs[output_node->sf.nused++] = 
	         trace_logging_info->queued_logging_context;

	    trace_logging_info->queued_logging_context = NULL;
    }

    /*
     * Move the logging context to output node
     */
    spp_dispatch_make_node_runnable(output_node);

}

/*
 * edt: * * spp_create_trace_log_context
 *
 * Tries to create a logging context with packet buffer
 * to send a new logging packet
 *
 * Argument: spp_trace_log_info_t *trace_logging_info
 * structure that contains the nfv9 logging info and will store
 * the packet context as well.
 */
inline
void spp_create_trace_log_context (
                              spp_trace_log_info_t *trace_logging_info)
{
    spp_ctx_t *ctx;

    /*
     * If queued_logging_context_index is non-EMPTY, we already have a logging
     * packet queued to be sent.  First try sending this before allocating
     * a new context.  We can have only one active packet context per
     * trace_logging_info structure
     */
    if (PREDICT_FALSE(trace_logging_info->queued_logging_context != NULL)) {
        spp_trace_log_send_queued_pkt(trace_logging_info);
        /*
         * If we cannot still send the queued pkt, just return 
         * Downstream Constipation count would have increased anyway
         */
        if (trace_logging_info->queued_logging_context != NULL) {
	        spp_global_counters.spp_trace_log_context_creation_deferred_count++;
	        return;
        }
    }


    /*
     * No context can be allocated, return silently
     * calling routine will handle updating the error counters
     */
    if (spp_ctx_alloc(&ctx, 1) < 1) {
        spp_global_counters.spp_trace_log_context_creation_fail_count++;
	    return;
    }

    trace_logging_info->current_logging_context = ctx;
    trace_logging_info->pkt_length = 0;

    trace_logging_info->current_logging_context_timestamp =
                       spp_trace_log_get_sys_up_time_in_ms();

    ctx->flags = SPP_CTX_END_OF_PACKET;
    ctx->ru.tx.from_node = NODE_TRACE_BACKUP;
    ctx->ru.tx.dst_ip_port_idx = EXT_TRACE_BACKUP_INDEX;
    ctx->next_ctx_this_packet = (spp_ctx_t*) SPP_CTX_NO_NEXT_CTX;
    ctx->current_header = &ctx->packet_data[SPP_TRACE_LOG_HDR_OFFSET];
    ctx->current_length = 0;

    trace_logging_info->log_record = 0;
    trace_logging_info->total_record_count = 0;
    trace_logging_info->next_data_ptr = 
        (u8 *) &ctx->packet_data[SPP_TRACE_LOG_HDR_OFFSET];

}

/*
 * edt: * * spp_trace_log_add_record_create
 *
 * Tries to create an add record to the NFV9 packet
 *
 * Argument: spp_trace_log_info_t *trace_logging_info
 * structure that contains the nfv9 logging info and will store
 * the packet context as well.
 */
inline
void spp_trace_log_add_record_create (spp_trace_log_info_t *trace_logging_info)
{

    trace_logging_info->log_header =
    (spp_trace_log_hdr_t *) (trace_logging_info->next_data_ptr);

    /*
     * Initialize the number of traces recorded
     */
    trace_logging_info->log_header->num_traces =
    spp_host_to_net_byte_order_32(0);


    trace_logging_info->log_record  =
    (spp_trace_log_t *) (trace_logging_info->log_header + 1);

    /*
     * Update the length of the total pkt 
     */
    trace_logging_info->pkt_length +=
        SPP_LOG_TRACE_HEADER_LENGTH; 

    /*
     * Set the data pointer beyond the trace header field
     */
    trace_logging_info->next_data_ptr =
        (u8 *) (trace_logging_info->log_header + 1);

}

/*
 * edt: * * spp_trace_logger
 *
 * Tries to log  spp/cnat event/errors
 *
 * Argument: u8 *error_code
 *  Error code passed
 *
 * Argument: optional arguments
 */
void spp_trace_logger (u16 error_code, u16 num_args, u32 *arg)
{
    spp_trace_log_info_t *trace_logging_info = 0; 
    u8 i;

    trace_logging_info = 
        spp_trace_log_info_pool + 
        spp_trace_log_global_info.spp_log_pool_index[SPP_LOG_LTRACE];

    if (PREDICT_FALSE(trace_logging_info->current_logging_context == NULL)) {
        spp_create_trace_log_context(trace_logging_info);

	    /*
	     * If still empty, return after increasing the count
	     */
	    if (PREDICT_FALSE(trace_logging_info->current_logging_context == NULL)) {
	        return;
	    }
    }

    if (PREDICT_FALSE(trace_logging_info->log_record == NULL)) {
        spp_trace_log_add_record_create(trace_logging_info);
    }

    /*
     * We should definitely have add_record now, no need to sanitize
     */
    trace_logging_info->log_record->error_code = 
		    spp_host_to_net_byte_order_16(error_code);
    trace_logging_info->log_record->num_args = 
		    spp_host_to_net_byte_order_16(num_args);

    for (i = 0; i < num_args; i++) {
        trace_logging_info->log_record->arg[i] = 
                spp_host_to_net_byte_order_32(*(arg + i));
    }

    trace_logging_info->pkt_length += SPP_TRACE_LOG_RECORD_LENGTH + WORD_SIZE*num_args;
    trace_logging_info->current_logging_context->current_length =
                  trace_logging_info->pkt_length;
    trace_logging_info->total_record_count += 1;

    trace_logging_info->next_data_ptr =
        (u8 *) (trace_logging_info->next_data_ptr + WORD_SIZE + WORD_SIZE*num_args);

    trace_logging_info->log_record = 
           (spp_trace_log_t *) (trace_logging_info->next_data_ptr);

    /*
     * Initialize the number of traces recorded
     */
    trace_logging_info->log_header->num_traces =
             spp_host_to_net_byte_order_32(trace_logging_info->total_record_count);



    /*
     * If we have exceeded the packet length, let us send the
     * packet now.  There is buffer of additional bytes beyond
     * max_pkt_length to ensure that the last add/delete record
     * can be stored safely.
     */
    if (trace_logging_info->pkt_length > 
            trace_logging_info->max_length_minus_max_record_size) {
	    spp_trace_log_send_pkt(trace_logging_info);
    }
}


/*
 * edt: * * spp_trace_log_timer_handler
 *
 * Timer handler for sending any pending NFV9 record
 *
 * Argument: spp_timer_t * timer_p
 * Timer handler structure
 */
inline 
void spp_trace_log_timer_handler (spp_timer_t * timer_p)
{
    spp_node_t *output_node;
    spp_trace_log_info_t *trace_logging_info = 0;
    u32 current_timestamp = spp_trace_log_get_sys_up_time_in_ms();
    i16 sf_nused;
    
    output_node = spp_get_nodes() + 
	              spp_trace_log_global_info.spp_trace_log_disp_node_index;

    sf_nused = output_node->sf.nused;

    pool_foreach (trace_logging_info, spp_trace_log_info_pool, ({
        /*
         * Check if no more logging contexts can be queued
         */
	    if (PREDICT_FALSE(sf_nused >= SPP_MAXDISPATCH)) {
	        break;
	    }

	    /*
	     * If there is a current logging context and timestamp
	     * indicates it is pending for long, send it out
	     * Also if there is a queued context send it out as well
	     */
        if (trace_logging_info->queued_logging_context ||
            (trace_logging_info->current_logging_context &&
	        (current_timestamp - 
	         trace_logging_info->current_logging_context_timestamp) 
	                                                        > 1000)) {
            spp_trace_log_send_pkt_always_success(trace_logging_info,
                                                    output_node);
            sf_nused++;
        }
    }));

    timer_p->expires =
        spp_timer_in_n_ms_inline(1000); /* every 1 sec */
    spp_timer_start(timer_p);

}
inline
void spp_sensor_timer_handler (spp_timer_t * timer_p)
{
#ifdef TARGET_RODDICK
    if (!temperature_read_blocked) {
        Init_temperature_sensors();
        read_octeon_sensors(TEMPERATURE_SENSOR_QUIET_MODE);
    }

    timer_p->expires =
                spp_timer_in_n_ms_inline(60000); /* every 1 sec */
    spp_timer_start(timer_p);

#endif
}
void init_trace_log_buf_pool (void)
{   
    spp_trace_log_info_t *my_spp_log_info;
    u8            found;
    spp_log_type_t log_type;

    /* 
     * Init SPP logging info as needed, this will be done only once
     */
    spp_trace_log_init();

    found = 0;

    for (log_type = SPP_LOG_LTRACE; log_type < SPP_LOG_MAX; log_type++ ) {
        /* Do we already have a map for this log type? */
        pool_foreach (my_spp_log_info, spp_trace_log_info_pool, ({
            if (my_spp_log_info->log_type == log_type) {
                found = 1;
                break;
            }
        }));

        /*
         * Entry not present
         */
        if (!found) {
            pool_get(spp_trace_log_info_pool, my_spp_log_info);
            memset(my_spp_log_info, 0, sizeof(*my_spp_log_info));

            /*
             * Make the current and head logging context indeices as EMPTY.
             * When first logging happens, these get set correctly
             */
            my_spp_log_info->current_logging_context = NULL;
            my_spp_log_info->queued_logging_context  = NULL;

            my_spp_log_info->log_type = log_type;
            my_spp_log_info->max_length_minus_max_record_size =
                                SPP_TRACE_LOG_MAX_PKT_LENGTH;

            spp_trace_log_global_info.spp_log_pool_index[log_type] = 
                           my_spp_log_info - spp_trace_log_info_pool;
        }

    }

    return;
}


/*
 * one time function
 * has to be called at the init time
 */
void spp_trace_log_init (void)
{
    if (!spp_trace_log_global_info.spp_trace_log_init_done) {

#ifdef TARGET_RODDICK
   	    spp_trace_log_global_info.spp_trace_log_disp_node_index =
	         spp_lookup_node_index("roddick_infra_l3_tx");
#elif defined(TARGET_BOOSTER)
   	    spp_trace_log_global_info.spp_trace_log_disp_node_index =
	         spp_lookup_node_index("booster_infra_l3_tx");
#endif
	    ASSERT(spp_trace_log_global_info.spp_trace_log_disp_node_index != (u16)~0);

	    spp_trace_log_global_info.log_timer.cb_index = 
	    spp_timer_register_callback(spp_trace_log_timer_handler);
	    spp_trace_log_global_info.log_timer.expires = 
	         spp_timer_in_n_ms_inline(1000); /* every 1 sec */
	    spp_timer_start(&spp_trace_log_global_info.log_timer);

        if (!my_core_id) {
            sensor_timer.cb_index =
                    spp_timer_register_callback(spp_sensor_timer_handler);
            sensor_timer.expires =
                    spp_timer_in_n_ms_inline(60000); /* every 1 sec */
            spp_timer_start(&sensor_timer);
        }

	    spp_trace_log_global_info.spp_trace_log_init_done = 1;

        /*
         *  Set MSC ip_addr, port values
         */
#ifdef TARGET_RODDICK
        dst_ipv4_port_table[EXT_TRACE_BACKUP_INDEX].ipv4_address =
                                        vpp_boot_params.msc_ip_address;
        switch(vpp_boot_params.octeon_number) {
            case 0:
                    dst_ipv4_port_table[EXT_TRACE_BACKUP_INDEX].port = 0x15BF;
                    break;
            case 1:
                    dst_ipv4_port_table[EXT_TRACE_BACKUP_INDEX].port = 0x15BF;
                    break;
            case 2:
                    dst_ipv4_port_table[EXT_TRACE_BACKUP_INDEX].port = 0x15BF;
                    break;
            case 3:
                    dst_ipv4_port_table[EXT_TRACE_BACKUP_INDEX].port = 0x15BF;
                    break;
        }
#else
        dst_ipv4_port_table[EXT_TRACE_BACKUP_INDEX].ipv4_address = 0x01020304;
        dst_ipv4_port_table[EXT_TRACE_BACKUP_INDEX].port = 0x15BF;
#endif

    }
}

void spp_printf (u16 error_code, u16 num_args, u32 *arg)
{
    u32 current_timestamp;
    spp_node_main_vector_t *nmv;

    if (PREDICT_FALSE(error_code >= LOG_TABLE_MAX_ENTRIES))
    {
       /*  printf("Error code invalid %d, %d, %d, %d\n",
            error_code, LOG_TABLE_MAX_ENTRIES,
            sizeof(spp_cnat_logger_table), sizeof(spp_cnat_logger_table[0]));
            */
        return; /* Should not happen */
    }

    nmv = spp_get_node_main_vectorized_inline();
    current_timestamp = nmv->ticks / nmv->ticks_per_second;

    /* Check if any further hashing is required */

    if (PREDICT_FALSE(error_code == DUMP_PKT_IDX)) {
#ifdef TARGET_RODDICK || defined(TARGET_BOOSTER)
        spp_trace_logger(error_code, num_args, arg);
#else
        u8 j ;

        printf("PKT DUMP :: ");
        for (j = 0 ; j < num_args; j++) {
            printf("0x%x ", arg[j]);
            if (j == (num_args - 1)) {
                printf("\n");
            }
        }
#endif
    } else if (PREDICT_TRUE((current_timestamp - error_code_timestamps[error_code]) >=  
               spp_cnat_logger_table[error_code].rate_limit_time)) {
        /* update timestamp */
        error_code_timestamps[error_code] = current_timestamp;

#ifdef TARGET_RODDICK || defined(TARGET_BOOSTER)
        spp_trace_logger(error_code, num_args, arg);     
#else
        u8 j ;
   
        for (j = 0 ; j < num_args; j++) {
            printf("%s: %d ", spp_cnat_logger_table[error_code].param_name[j], arg[j]);
            if (j == (num_args - 1)) {
                printf("\n");
            }
        }
#endif
    }
}
    
#else /* TOBE_PORTEED */
void spp_trace_logger(u16 error_code, u16 num_args, u32 *arg)
{
  /* To be filled */
}

void spp_trace_log_init(void)
{
  /* To be filled */
}

void init_trace_log_buf_pool(void)
{
  /* To be filled */
}

void spp_printf(u16 error_code, u16 num_args, u32 *arg)
{
  /* To be filled */
}

u32 spp_trace_log_get_unix_time_in_seconds (void)
{
    vlib_main_t  *vlib_main;

    vlib_main = vlib_get_main();
    return(vlib_time_now((vlib_main_t *) vlib_main));
}

#endif /* TOBE_PORTED */

