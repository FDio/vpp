/* 
 *---------------------------------------------------------------------------
 * cnat_ipv4_tcp_inside_input_exceptions.c -
 * cnat_ipv4_tcp_inside_input_exceptions node pipeline stage functions
 *
 *
 * Copyright (c) 2008-2014 Cisco and/or its affiliates.
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
#include <vppinfra/error.h>
#include <vnet/buffer.h>

#include "cnat_db.h"
#include "tcp_header_definitions.h"
#include "cnat_config.h"
#include "cnat_global.h"
#include "cnat_v4_functions.h"


#define foreach_cnat_ipv4_tcp_inside_input_exc_error                  	\
_(CNAT_V4_TCP_I2O_E_T_PKT, "v4 tcp i2o-e transmit natted pkt")                         \
_(CNAT_V4_TCP_I2O_E_D_NON_SYN_PKT, "v4 tcp i2o-e non syn drop")                             \
_(CNAT_V4_TCP_I2O_E_D_INVALID_PKT, "v4 tcp i2o-e invalid pkt drop")                  \
_(CNAT_V4_TCP_I2O_E_DROP,    "v4 tcp i2o-e drop")                \
_(CNAT_V4_TCP_I2O_E_GEN_ICMP, "v4 tcp i2o-e gen icmp msg")         \
_(CNAT_V4_TCP_I2O_E_D_NO_SESSION, "v4 tcp i2o-e no session db entry drop")

typedef enum {
#define _(sym,str) sym,
  foreach_cnat_ipv4_tcp_inside_input_exc_error
#undef _
  CNAT_IPV4_TCP_INSIDE_INPUT_EXCEPTIONS_N_ERROR,
} cnat_ipv4_tcp_inside_input_exc_error_t;


static char * cnat_ipv4_tcp_inside_input_exc_error_strings[] = {
#define _(sym,string) string,
  foreach_cnat_ipv4_tcp_inside_input_exc_error
#undef _
};

typedef struct {
  u32 cached_next_index;
  /* $$$$ add data here */

  /* convenience variables */
  vlib_main_t * vlib_main;
  vnet_main_t * vnet_main;
} cnat_ipv4_tcp_inside_input_exc_main_t;

typedef enum {
    CNAT_V4_TCP_I2O_E_T,
    //CNAT_V4_TCP_I2O_E_ICMP,
    CNAT_V4_TCP_I2O_E_D, 
    CNAT_V4_TCP_I2O_E_NEXT,
} cnat_ipv4_udp_inside_input_exc_next_t;

#define CNAT_V4_TCP_I2O_E_ICMP CNAT_V4_TCP_I2O_E_D

cnat_ipv4_tcp_inside_input_exc_main_t cnat_ipv4_tcp_inside_input_exc_main;
vlib_node_registration_t cnat_ipv4_tcp_inside_input_exc_node;

#define NSTAGES 2

/*
 * Use the generic buffer metadata + first line of packet data prefetch
 * stage function from <api/pipeline.h>. This is usually a Good Idea.
 */
#define stage0 generic_stage0


static inline u32 last_stage (vlib_main_t *vm, vlib_node_runtime_t *node,
                              u32 bi)
{
    vlib_buffer_t *b0 = vlib_get_buffer (vm, bi);
    vlib_node_t *n = 
        vlib_get_node (vm, cnat_ipv4_tcp_inside_input_exc_node.index);
    u32 node_counter_base_index = n->error_heap_index;
    vlib_error_main_t * em = &vm->error_main;

    cnat_gen_icmp_info info;
    cnat_db_key_bucket_t ki;
    cnat_main_db_entry_t *db = NULL;
    ipv4_header *ip = (ipv4_header *)vlib_buffer_get_current(b0);
    u8   ipv4_hdr_len = (ip->version_hdr_len_words & 0xf) << 2;
    tcp_hdr_type *tcp = (tcp_hdr_type *)((u8*)ip + ipv4_hdr_len);
    int disposition = CNAT_V4_TCP_I2O_E_T;
    int counter = CNAT_V4_TCP_I2O_E_T_PKT;
    cnat_key_t dest_info;
    u32 window;
    u8 scale;

    window = (u32)clib_net_to_host_u16(tcp->window_size);
    calculate_window_scale(tcp, &scale);
  
    dest_info.k.port = clib_net_to_host_u16(tcp->dest_port);
    dest_info.k.ipv4 = clib_net_to_host_u32(ip->dest_addr);

    PLATFORM_CNAT_SET_RX_VRF(vnet_buffer(b0)->sw_if_index[VLIB_RX],
                             dest_info.k.vrf, CNAT_TCP)

    /* for TCP if not SYN or if src_port is 0, silently drop the packet */
    if (PREDICT_FALSE(!((tcp->flags & TCP_FLAG_SYN) && (tcp->src_port)))) {

        /*
         * If the packet is dropped due to both reasons,
	 * count it as invalid packet drop
	 */
        if (!tcp->src_port) {
            counter = CNAT_V4_TCP_I2O_E_D_INVALID_PKT;
        } else {
            counter = CNAT_V4_TCP_I2O_E_D_NON_SYN_PKT;
        }
        disposition = CNAT_V4_TCP_I2O_E_D;
        goto in2out_e;
    }

    PLATFORM_CNAT_SET_RX_VRF(vnet_buffer(b0)->sw_if_index[VLIB_RX],
                             ki.k.k.vrf, CNAT_TCP)

    ki.k.k.ipv4 = clib_net_to_host_u32(ip->src_addr);
    ki.k.k.port = clib_net_to_host_u16(tcp->src_port);

    db = cnat_get_main_db_entry_v2(&ki, PORT_SINGLE, PORT_TYPE_DYNAMIC, &info,
                &dest_info);


#if DEBUG > 1
        if(PREDICT_TRUE(db)) {
            printf("create db %x ip %x->%x port %x->%x dst_ip %x\n", db,
                   db->in2out_key.k.ipv4, db->out2in_key.k.ipv4,
                   db->in2out_key.k.port, db->out2in_key.k.port, db->dst_ipv4);
        }
#endif


    if (PREDICT_FALSE(db == 0)) {
        /* failed to create new db entry due to either no more port, or user limit reached,
         * need to generate ICMP type=3,code=13 msg here,
         */

        /*
         * we rate limit the icmp msg per private user,
         * so we don't flood a user with icmp msg
         * in case the per user port limit reached
         */
        if (PREDICT_TRUE(info.gen_icmp_msg == CNAT_ICMP_MSG)) {
            /* KEEPING THINGS COMMENTED HERE..MAY NEED TO REVISIT AGAIN */
            #if 0
            u32 *fd = (u32*)ctx->feature_data;
            fd[0] = info.svi_addr;
            fd[1] = CNAT_ICMP_DEST_UNREACHABLE;

            /* 
             * Let's reverse the direction from i2o to o2i.
             * This will help using the correct VRF in the fib lookup (AVSM)
             * especially for the o2i_vrf_override case
             */
            ctx->ru.rx.direction = 0; // 0 - o2i, 1 - i2o
            #endif
            disposition = CNAT_V4_TCP_I2O_E_ICMP;
            counter = CNAT_V4_TCP_I2O_E_GEN_ICMP;

        } else {
            disposition = CNAT_V4_TCP_I2O_E_D;
            counter = CNAT_V4_TCP_I2O_E_DROP;
        }
        //DEBUG_I2O_DROP(CNAT_DEBUG_DROP_TCP)
    } else {

        if (PLATFORM_HANDLE_TTL_DECREMENT) {
            /*
             * Decrement TTL and update IPv4 checksum
             */
            ipv4_decr_ttl_n_calc_csum(ip);
        }

        /* NAT the packet and fix checksum */

        tcp_in2out_nat_mss_n_checksum(ip, 
                                      tcp, 
                                      db->out2in_key.k.ipv4, 
                                      db->out2in_key.k.port, 
                                      db 
				      /*, db->in2out_key.k.vrf */);

        /* this must be inside to outside SYN, do mss here */

        /* update translation counters */
        db->in2out_pkts++;

        /* set keepalive timer */

        if(PREDICT_TRUE((dest_info.k.ipv4 == db->dst_ipv4) &&
            (dest_info.k.port == db->dst_port))) {
	    if(PREDICT_FALSE(!ALG_ENABLED_DB(db))) {
            //This check is done since proto_data is part of union in main
            //db entry
					
            db->proto_data.tcp_seq_chk.seq_no = 
                clib_net_to_host_u32(tcp->seq_num);
            db->proto_data.tcp_seq_chk.ack_no = 
                clib_net_to_host_u32(tcp->ack_num);
            db->scale              = scale;
            db->diff_window        = window;
        }		
#if DEBUG > 1
            PLATFORM_DEBUG_PRINT("\nMain DB seq no = %u," 
	                            "ack no = %u, window = %u,"
                                    "scale = %u",
	                            db->proto_data.tcp_seq_chk.seq_no,
				    db->proto_data.tcp_seq_chk.ack_no,
				    db->diff_window
				    db->scale);
#endif	    
	    V4_TCP_UPDATE_SESSION_FLAG(db, tcp);
            /* Check timeout db if there is config for this */
            (void) query_and_update_db_timeout((void *)db, MAIN_DB_TYPE);
            db->entry_expires = cnat_current_time;
        } else {
            /* Got to find out the session entry corresponding to this..*/
            cnat_session_entry_t *sdb;
            sdb = cnat_session_db_lookup_entry(
                &dest_info, db - cnat_main_db);
            if(PREDICT_FALSE(sdb == NULL)) {
                disposition = CNAT_V4_TCP_I2O_E_D;
                counter = CNAT_V4_TCP_I2O_E_D_NO_SESSION;
                goto in2out_e;
            }
            sdb->tcp_seq_num = clib_net_to_host_u32(tcp->seq_num);
            sdb->ack_no      = clib_net_to_host_u32(tcp->ack_num);
            sdb->scale       = scale;
            sdb->window      = window;

#if DEBUG > 1
	    PLATFORM_DEBUG_PRINT("\nSDB seq no = %u, ack no = %u, window = %u"
	                         "\nSDB scale  = %u" ,
	                          sdb->tcp_seq_num,
				  sdb->ack_no,
				  sdb->window,
				  sdb->scale);
#endif	    
            V4_TCP_UPDATE_SESSION_DB_FLAG(sdb, tcp);
            /* Check timeout db if there is config for this */
            (void) query_and_update_db_timeout((void *)sdb, SESSION_DB_TYPE);
            sdb->entry_expires = cnat_current_time;
        }

        //PLATFORM_CNAT_SET_TX_VRF(ctx,db->out2in_key.k.vrf)

        counter = CNAT_V4_TCP_I2O_E_T_PKT;
        in2out_forwarding_count++;
    }

in2out_e:

    em->counters[node_counter_base_index + counter] += 1;
    
    return disposition;
}

#include <vnet/pipeline.h>

static uword cnat_ipv4_tcp_inside_input_exc_node_fn (vlib_main_t * vm,
                              vlib_node_runtime_t * node,
                              vlib_frame_t * frame)
{
    return dispatch_pipeline (vm, node, frame);
}

VLIB_REGISTER_NODE (cnat_ipv4_tcp_inside_input_exc_node) = {
  .function = cnat_ipv4_tcp_inside_input_exc_node_fn,
  .name = "vcgn-v4-tcp-i2o-e",
  .vector_size = sizeof (u32),
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(cnat_ipv4_tcp_inside_input_exc_error_strings),
  .error_strings = cnat_ipv4_tcp_inside_input_exc_error_strings,

  .n_next_nodes = CNAT_V4_TCP_I2O_E_NEXT,

  /* edit / add dispositions here */
  .next_nodes = {
        [CNAT_V4_TCP_I2O_E_T] = "ip4-input",
        [CNAT_V4_TCP_I2O_E_D] = "error-drop",
  },
};


clib_error_t *cnat_ipv4_tcp_inside_input_exc_init (vlib_main_t *vm)
{
  cnat_ipv4_tcp_inside_input_exc_main_t * mp = &cnat_ipv4_tcp_inside_input_exc_main;

  mp->vlib_main = vm;
  mp->vnet_main = vnet_get_main();

  return 0;
}

VLIB_INIT_FUNCTION (cnat_ipv4_tcp_inside_input_exc_init);
