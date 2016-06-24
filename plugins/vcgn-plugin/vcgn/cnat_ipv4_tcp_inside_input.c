/* 
 *---------------------------------------------------------------------------
 * cnat_ipv4_tcp_inside_input.c - cnat_ipv4_tcp_inside_input node pipeline 
 * stage functions
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

#define foreach_cnat_ipv4_tcp_inside_input_error 		\
_(CNAT_V4_TCP_I2O_PKT_IN, "tcp i2o packets received")			\
_(CNAT_V4_TCP_I2O_PKT_T, "tcp i2o packets natted")		\
_(CNAT_V4_TCP_I2O_EXCEPTION, "packets to tcp i2o exception")		\
_(CNAT_V4_TCP_I2O_TTL_GEN, "generated TTL expiry ICMP packets")		\
_(CNAT_V4_TCP_I2O_TTL_GEN_DROP, "could not generate TTL expiry ICMP packets")		\
_(CNAT_V4_TCP_I2O_SESSION_DROP, "could not generate session")				\
_(CNAT_V4_UDP_I2O_FRAG_DROP, "non-first fragment drop")

typedef enum {
#define _(sym,str) sym,
  foreach_cnat_ipv4_tcp_inside_input_error 
#undef _
  CNAT_IPV4_TCP_INSIDE_INPUT_N_ERROR,
} cnat_ipv4_tcp_inside_input_t;

static char * cnat_ipv4_tcp_inside_input_error_strings[] = {
#define _(sym,string) string,
  foreach_cnat_ipv4_tcp_inside_input_error
#undef _
};

typedef struct {
  u32 cached_next_index;
  /* $$$$ add data here */

  /* convenience variables */
  vlib_main_t * vlib_main;
  vnet_main_t * vnet_main;
} cnat_ipv4_tcp_inside_input_main_t;

typedef enum {
    CNAT_V4_TCP_I2O_E,
    CNAT_V4_TCP_I2O_T,
    CNAT_V4_TCP_I2O_D,
    CNAT_V4_TCP_I2O_NEXT,
} cnat_ipv4_tcp_inside_input_next_t;

#define CNAT_REWRITE_OUTPUT CNAT_V4_TCP_I2O_T
#define CNAT_V4_ICMP_GEN CNAT_V4_TCP_I2O_D

//#define CNAT_V4_TCP_I2O_E CNAT_V4_TCP_I2O_D //remove it once exception node is created
cnat_ipv4_tcp_inside_input_main_t cnat_ipv4_tcp_inside_input_main;
vlib_node_registration_t cnat_ipv4_tcp_inside_input_node;

#define NSTAGES 6

/*
 * Use the generic buffer metadata + first line of packet data prefetch
 * stage function from <api/pipeline.h>. This is usually a Good Idea.
 */
#define stage0 generic_stage0


static inline void
stage1(vlib_main_t * vm, vlib_node_runtime_t * node, u32 buffer_index)
{
    u64 a, b, c;
    u32 bucket;
    u8 *prefetch_target;
    //cnat_feature_data_t *fd = (cnat_feature_data_t *)ctx->feature_data;


    vlib_buffer_t * b0 = vlib_get_buffer (vm, buffer_index);
    ipv4_header *ip = vlib_buffer_get_current (b0);
    u8   ipv4_hdr_len = (ip->version_hdr_len_words & 0xf) << 2;
    tcp_hdr_type *tcp = (tcp_hdr_type *)((u8*)ip + ipv4_hdr_len);
  
    u64 tmp = 0;
    tmp = vnet_buffer(b0)->vcgn_uii.key.k.ipv4 =
            clib_net_to_host_u32(ip->src_addr);
    vnet_buffer(b0)->vcgn_uii.key.k.port =
            clib_net_to_host_u16 (tcp->src_port);

    tmp |= ((u64)vnet_buffer(b0)->vcgn_uii.key.k.port) << 32;

    PLATFORM_CNAT_SET_RX_VRF(vnet_buffer(b0)->sw_if_index[VLIB_RX],
                             vnet_buffer(b0)->vcgn_uii.key.k.vrf,
                             CNAT_TCP)
    tmp |= ((u64)vnet_buffer(b0)->vcgn_uii.key.k.vrf) << 48;

    CNAT_V4_GET_HASH(tmp, bucket, CNAT_MAIN_HASH_MASK)

    prefetch_target = (u8 *)(&cnat_in2out_hash[bucket]);
    vnet_buffer(b0)->vcgn_uii.bucket = bucket;

    /* Prefetch the hash bucket */
    CLIB_PREFETCH(prefetch_target, CLIB_CACHE_LINE_BYTES, LOAD);
}

static inline void
stage2(vlib_main_t * vm, vlib_node_runtime_t * node, u32 buffer_index)
{ /* nothing */ }


#define SPP_LOG2_CACHE_LINE_BYTES 6
#define SPP_CACHE_LINE_BYTES (1 << SPP_LOG2_CACHE_LINE_BYTES)

static inline void
stage3(vlib_main_t * vm, vlib_node_runtime_t * node, u32 buffer_index)
{
    vlib_buffer_t * b0 = vlib_get_buffer(vm, buffer_index);
    uword prefetch_target0, prefetch_target1;
    u32 bucket = vnet_buffer(b0)->vcgn_uii.bucket;
  
    /* read the hash bucket */
    u32 db_index = vnet_buffer(b0)->vcgn_uii.bucket
                 = cnat_in2out_hash[bucket].next;

    if (PREDICT_TRUE(db_index != EMPTY)) {
        /*
         * Prefetch database keys. We save space by not cache-line
         * aligning the DB entries. We don't want to waste LSU
         * bandwidth prefetching stuff we won't need.
         */
        prefetch_target0 = (uword)(cnat_main_db + db_index);
        CLIB_PREFETCH((void*)prefetch_target0, CLIB_CACHE_LINE_BYTES, LOAD);
        /* Just beyond DB key #2 */
        prefetch_target1 = prefetch_target0 +
        STRUCT_OFFSET_OF(cnat_main_db_entry_t, user_ports);
        /* If the targets are in different lines, do the second prefetch */
        if (PREDICT_FALSE((prefetch_target0 & ~(SPP_CACHE_LINE_BYTES-1)) !=
                      (prefetch_target1 & ~(SPP_CACHE_LINE_BYTES-1)))) {
            CLIB_PREFETCH((void *)prefetch_target1, CLIB_CACHE_LINE_BYTES, LOAD);
        }
    }
}

static inline void
stage4(vlib_main_t * vm, vlib_node_runtime_t * node, u32 buffer_index)
{
  cnat_main_db_entry_t *db;
  vlib_buffer_t * b0 = vlib_get_buffer(vm, buffer_index);
  u32 db_index = vnet_buffer(b0)->vcgn_uii.bucket;

  /*
   * Note: if the search already failed (empty bucket),
   * the answer is already in the pipeline context structure
   */
  if (PREDICT_TRUE(db_index != EMPTY)) {

    /*
     * Note: hash collisions suck. We can't easily prefetch around them.
     * The first trip around the track will be fast. After that, maybe
     * not so much...
     */
    do {
      db = cnat_main_db + db_index;
      if (PREDICT_TRUE(db->in2out_key.key64 ==
                  vnet_buffer(b0)->vcgn_uii.key.key64)) {
        break;
      }
      db_index = db->in2out_hash.next;
    } while (db_index != EMPTY);

    /* Stick the answer back into the pipeline context structure */
    vnet_buffer(b0)->vcgn_uii.bucket = db_index;
  }
}


static inline u32 last_stage (vlib_main_t *vm, vlib_node_runtime_t *node,
                              u32 bi)
{
    vlib_buffer_t *b0 = vlib_get_buffer (vm, bi);
    u32 db_index = vnet_buffer(b0)->vcgn_uii.bucket;
    spp_ctx_t *ctx = (spp_ctx_t *) &vnet_buffer(b0)->vcgn_uii;
    int disposition = CNAT_V4_TCP_I2O_T;
    int counter = CNAT_V4_TCP_I2O_PKT_T;

    ipv4_header *ip = (ipv4_header *)vlib_buffer_get_current(b0);
    u8   ipv4_hdr_len = (ip->version_hdr_len_words & 0xf) << 2;
    tcp_hdr_type *tcp = (tcp_hdr_type *)((u8*)ip + ipv4_hdr_len);
    vlib_node_t *n = vlib_get_node (vm, cnat_ipv4_tcp_inside_input_node.index);
    u32 node_counter_base_index = n->error_heap_index;
    vlib_error_main_t * em = &vm->error_main;
    cnat_session_entry_t *session_db = NULL;
    cnat_main_db_entry_t *db = NULL;
    cnat_key_t dest_info;
    u32 window;
    u8 scale;


    INCREMENT_NODE_COUNTER(CNAT_V4_TCP_I2O_PKT_IN);

    if (PLATFORM_HANDLE_TTL_DECREMENT) {
        if (PREDICT_FALSE(ip->ttl <= 1)) {
            /* Try to generate ICMP error msg, as TTL is <= 1 */

            if (icmpv4_generate_with_throttling
                    (ctx, ip, ctx->ru.rx.uidb_index)) {

                /* Generated ICMP */
                disposition = CNAT_REWRITE_OUTPUT;
                counter = CNAT_V4_TCP_I2O_TTL_GEN;
            } else {
                /* Could not generated ICMP - drop the packet */
                disposition = CNAT_V4_TCP_I2O_D; 
                counter = CNAT_V4_TCP_I2O_TTL_GEN_DROP;
            }
            goto drop_pkt;
        }
    }

    if (PREDICT_FALSE(db_index == EMPTY)) {
    /* Deleted fragment code from here */
	    disposition = CNAT_V4_TCP_I2O_E;
        counter = CNAT_V4_TCP_I2O_EXCEPTION;
    } else {
        db = cnat_main_db + db_index;

        /* Handle destination sessions */
        dest_info.k.port = clib_net_to_host_u16(tcp->dest_port);
        dest_info.k.ipv4 = clib_net_to_host_u32(ip->dest_addr);

        if(PREDICT_TRUE(!PLATFORM_DBL_SUPPORT)) {

            /* No DBL support, so just update the destn and proceed */
            db->dst_ipv4 = dest_info.k.ipv4;
            db->dst_port = dest_info.k.port;
            goto update_pkt;
        }

        if(PREDICT_FALSE(db->dst_ipv4 != dest_info.k.ipv4 ||
            db->dst_port != dest_info.k.port)) {
            if(PREDICT_TRUE(db->nsessions == 0)) {
                /* Should be a static entry
                 * Note this session as the first session and log
                 */
                cnat_add_dest_n_log(db, &dest_info);
            } else if(PREDICT_FALSE(db->nsessions == 1)) {
                /* Destn is not same as in main db. Multiple session
                 * scenario
                 */
                dest_info.k.vrf = db->in2out_key.k.vrf;
                session_db = cnat_handle_1to2_session(db, &dest_info);
                if(PREDICT_FALSE(session_db == NULL)) {
                    disposition = CNAT_V4_TCP_I2O_D;
                    counter = CNAT_V4_TCP_I2O_SESSION_DROP;
                    goto drop_pkt;
                }
            } else { /* There are already multiple destinations */
                dest_info.k.vrf = db->in2out_key.k.vrf;
                /* If session already exists,
                 * cnat_create_session_db_entry will return the existing db
                 * else create a new db
                 * If could not create, return NULL
                 */
                session_db = cnat_create_session_db_entry(&dest_info,
                        db, TRUE);
                if(PREDICT_FALSE(session_db == NULL)) {
                    disposition = CNAT_V4_TCP_I2O_D;
                    counter = CNAT_V4_TCP_I2O_SESSION_DROP;
                    goto drop_pkt;
                }
            }
            if(PREDICT_TRUE(session_db != 0)) {
                /* Have to repeat the window size check for new destinations */
                window = (u32)clib_net_to_host_u16(tcp->window_size);
                window = window << session_db->scale;
                if(PREDICT_TRUE(!session_db->window)) {
                    calculate_window_scale(tcp, &scale);
                    session_db->scale       = scale;
                    session_db->window      = window;
                } else if (PREDICT_FALSE(session_db->window < 
                            window)) { 
                    /* Update the db entry with window option from packet */
                    session_db->window  = window;
                } else {
                    /* Do nothing */
                }    
                session_db->tcp_seq_num = clib_net_to_host_u32(tcp->seq_num);
                session_db->ack_no      = clib_net_to_host_u32(tcp->ack_num);
#if DEBUG > 1
                printf("\n In2out SDB stages seq no = %u," 
                        "   ack no = %u, window = %u\n",
                        session_db->tcp_seq_num,
                        session_db->ack_no,
                        session_db->window);
#endif
                    
            }
        } else {
            //Update the seq no and ack no for subsequent communication
            //after connection establishment
            //No need to update window here. Window is already updated 
            //during connection establishment
            window = (u32)clib_net_to_host_u16(tcp->window_size);
            window = window << db->scale;
            if(PREDICT_FALSE(!ALG_ENABLED_DB(db))) {
                //This check is done since proto_data is part of union in main 
                //db entry
                db->proto_data.tcp_seq_chk.seq_no  = 
                    clib_net_to_host_u32(tcp->seq_num);
                db->proto_data.tcp_seq_chk.ack_no  = 
                    clib_net_to_host_u32(tcp->ack_num);
            }			      
            if (PREDICT_FALSE(db->diff_window < window)) { 
                /* Update the db entry with window option from packet */
                db->diff_window = window; 
            }
#if DEBUG > 1
            printf("\n In2out MainDB seq no = %u,"
                    "\n ack no = %u\n",
                    db->proto_data.tcp_seq_chk.seq_no,
                    db->proto_data.tcp_seq_chk.ack_no);
            printf("\n In2out MAINDB window = %u\n",
                    db->diff_window);
#endif            	
        }
update_pkt:

        counter = CNAT_V4_TCP_I2O_PKT_T;
        disposition = CNAT_V4_TCP_I2O_T;

        /* NO FRAGMENT & ALG HANDLING. DELETING THE CODE */

        if (PLATFORM_HANDLE_TTL_DECREMENT) {
            /*
             * Decrement TTL and update IPv4 checksum
             */
            ipv4_decr_ttl_n_calc_csum(ip);
        }

        tcp_in2out_nat_mss_n_checksum(ip, 
                                      tcp, 
                                      db->out2in_key.k.ipv4, 
                                      db->out2in_key.k.port, 
                                      db 
				      /*, db->in2out_key.k.vrf */);

        /* update transaltion counters */
        db->in2out_pkts++;
        in2out_forwarding_count++;

        /* update the timer for good mode, or evil mode dst_ip match */

        if(PREDICT_FALSE(session_db != NULL)) {
            V4_TCP_UPDATE_SESSION_DB_FLAG(session_db, tcp);
            CNAT_DB_TIMEOUT_RST(session_db);
        } else {
            V4_TCP_UPDATE_SESSION_FLAG(db, tcp);
            CNAT_DB_TIMEOUT_RST(db);
        }
    }

drop_pkt:

    em->counters[node_counter_base_index + counter] += 1;
    return  disposition;
}

#include <vnet/pipeline.h>

static uword cnat_ipv4_tcp_inside_input_node_fn (vlib_main_t * vm,
                              vlib_node_runtime_t * node,
                              vlib_frame_t * frame)
{
    return dispatch_pipeline (vm, node, frame);
}


VLIB_REGISTER_NODE (cnat_ipv4_tcp_inside_input_node) = {
  .function = cnat_ipv4_tcp_inside_input_node_fn,
  .name = "vcgn-v4-tcp-i2o",
  .vector_size = sizeof (u32),
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(cnat_ipv4_tcp_inside_input_error_strings),
  .error_strings = cnat_ipv4_tcp_inside_input_error_strings,

  .n_next_nodes = CNAT_V4_TCP_I2O_NEXT,

  /* edit / add dispositions here */
  .next_nodes = {
      [CNAT_V4_TCP_I2O_E] = "vcgn-v4-tcp-i2o-e",
      [CNAT_V4_TCP_I2O_T] = "ip4-input",
      [CNAT_V4_TCP_I2O_D] = "error-drop",
  },
};

clib_error_t *cnat_ipv4_tcp_inside_input_init (vlib_main_t *vm)
{
  cnat_ipv4_tcp_inside_input_main_t * mp = &cnat_ipv4_tcp_inside_input_main;

  mp->vlib_main = vm;
  mp->vnet_main = vnet_get_main();

  return 0;
}

VLIB_INIT_FUNCTION (cnat_ipv4_tcp_inside_input_init);
