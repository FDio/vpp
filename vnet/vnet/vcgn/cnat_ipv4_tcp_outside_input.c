/* 
 *---------------------------------------------------------------------------
 * cnat_ipv4_tcp_outside_input.c - cnat_v4_tcp_out2in node pipeline stage functions
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
#include "cnat_ipv4_udp.h"
#include "cnat_v4_functions.h"


#define foreach_cnat_ipv4_tcp_outside_input_error 		\
_(CNAT_V4_TCP_O2I_R_PKT, "v4 tcp o2i pkt received")			\
_(CNAT_V4_TCP_O2I_T_PKT, "v4 tcp o2i pkt natted & transmitted")			\
_(CNAT_V4_TCP_O2I_LOOKUP_FAILED, "v4 tcp o2i lookup failed")			\
_(CNAT_V4_TCP_O2I_TTL_GEN, "v4 tcp o2i generated TTL Expiry ICMP packet")		\
_(CNAT_V4_TCP_O2I_TTL_DROP, "v4 tcp o2i drop due to failure in creating TTL expiry ICMP msg")		\
_(CNAT_V4_TCP_O2I_PTB_GEN, "v4 tcp o2i PTB ICMP pkt generation")		\
_(CNAT_V4_UDP_O2I_PTB_DROP, "v4 tcp o2i drop due to failure in creating PTB ICMP pkt")		\
_(CNAT_V4_TCP_O2I_SESSION_DROP, "v4 tcp o2i drop due to failure in creating session db")		\
_(CNAT_V4_TCP_O2I_SEQ_MISMATCH_DROP, "v4 tcp o2i drop due to TCP sequence mismatch")		\
_(CNAT_V4_TCP_O2I_FILTER_DROP, "v4 tcp o2i drop due to endpoint filtering")		\
_(CNAT_V4_TCP_O2I_NON_SYN_RST_DROP, "v4 tcp o2i drop due no syn/rst flag")  \
_(CNAT_V4_TCP_O2I_FIRST_FRAG_DROP, "v4 tcp o2i first fragment drop")  \
_(CNAT_V4_TCP_O2I_SUB_FRAG_NO_DB_DROP, "v4 tcp o2i subsequest frag no DB drop")

typedef enum {
#define _(sym,str) sym,
  foreach_cnat_ipv4_tcp_outside_input_error 
#undef _
  CNAT_IPV4_TCP_OUTSIDE_INPUT_N_ERROR,
} cnat_ipv4_tcp_outside_input_t;

static char * cnat_ipv4_tcp_outside_input_error_strings[] = {
#define _(sym,string) string,
  foreach_cnat_ipv4_tcp_outside_input_error
#undef _
};

typedef struct {
  u32 cached_next_index;
  /* $$$$ add data here */

  /* convenience variables */
  vlib_main_t * vlib_main;
  vnet_main_t * vnet_main;
} cnat_ipv4_tcp_outside_input_main_t;

typedef enum {
    //CNAT_V4_TCP_O2I_E,
    CNAT_V4_TCP_O2I_T,
    CNAT_V4_TCP_O2I_D,
    CNAT_V4_TCP_O2I_NEXT,
} cnat_ipv4_tcp_outside_input_next_t;

cnat_ipv4_tcp_outside_input_main_t cnat_ipv4_tcp_outside_input_main;
vlib_node_registration_t cnat_ipv4_tcp_outside_input_node;

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


    vlib_buffer_t * b0 = vlib_get_buffer (vm, buffer_index);
    ipv4_header *ip = vlib_buffer_get_current (b0);
    u8   ipv4_hdr_len = (ip->version_hdr_len_words & 0xf) << 2;
    tcp_hdr_type *tcp = (tcp_hdr_type *)((u8*)ip + ipv4_hdr_len);
  
    u64 tmp = 0;
    tmp = vnet_buffer(b0)->vcgn_uii.key.k.ipv4 =
            clib_net_to_host_u32(ip->dest_addr);
    vnet_buffer(b0)->vcgn_uii.key.k.port =
            clib_net_to_host_u16 (tcp->dest_port);

    tmp |= ((u64)vnet_buffer(b0)->vcgn_uii.key.k.port) << 32;

    PLATFORM_CNAT_SET_RX_VRF(vnet_buffer(b0)->sw_if_index[VLIB_RX],
                             vnet_buffer(b0)->vcgn_uii.key.k.vrf,
                             CNAT_TCP)
    tmp |= ((u64)vnet_buffer(b0)->vcgn_uii.key.k.vrf) << 48;

    CNAT_V4_GET_HASH(tmp, bucket, CNAT_MAIN_HASH_MASK)

    prefetch_target = (u8 *)(&cnat_out2in_hash[bucket]);
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
                 = cnat_out2in_hash[bucket].next;

    if (PREDICT_TRUE(db_index != EMPTY)) {
        /*
         * Prefetch database keys. We save space by not cache-line
         * aligning the DB entries. We don't want to waste LSU
         * bandwidth prefetching stuff we won't need.
         */
        prefetch_target0 = (uword)(cnat_main_db + db_index);
        CLIB_PREFETCH((void*)prefetch_target0, CLIB_CACHE_LINE_BYTES, STORE);
        /* Just beyond DB key #2 */
        prefetch_target1 = prefetch_target0 +
        STRUCT_OFFSET_OF(cnat_main_db_entry_t, user_ports);
        /* If the targets are in different lines, do the second prefetch */
        if (PREDICT_FALSE((prefetch_target0 & ~(SPP_CACHE_LINE_BYTES-1)) !=
                      (prefetch_target1 & ~(SPP_CACHE_LINE_BYTES-1)))) {
            CLIB_PREFETCH((void *)prefetch_target1, CLIB_CACHE_LINE_BYTES, STORE);
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
      if (PREDICT_TRUE(db->out2in_key.key64 ==
                  vnet_buffer(b0)->vcgn_uii.key.key64)) {
        break;
      }
      db_index = db->out2in_hash.next;
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
    int disposition = CNAT_V4_TCP_O2I_T;
    int counter = CNAT_V4_TCP_O2I_T_PKT;

    ipv4_header *ip = (ipv4_header *)vlib_buffer_get_current(b0);
    u8   ipv4_hdr_len = (ip->version_hdr_len_words & 0xf) << 2;
    tcp_hdr_type *tcp = (tcp_hdr_type *)((u8*)ip + ipv4_hdr_len);
    vlib_node_t *n = vlib_get_node (vm, cnat_ipv4_tcp_outside_input_node.index);
    u32 node_counter_base_index = n->error_heap_index;
    vlib_error_main_t * em = &vm->error_main;
    cnat_session_entry_t *session_db = NULL;
    cnat_main_db_entry_t *db = NULL;
    cnat_key_t dest_info;

    INCREMENT_NODE_COUNTER(CNAT_V4_TCP_O2I_R_PKT);

    if (PREDICT_FALSE(db_index == EMPTY)) {
        nat44_dslite_common_stats[0].no_translation_entry_drops ++; 
        counter = CNAT_V4_TCP_O2I_LOOKUP_FAILED;
        disposition = CNAT_V4_TCP_O2I_D;
    } else {
        if (PLATFORM_HANDLE_TTL_DECREMENT) {
            if (PREDICT_FALSE(ip->ttl <= 1)) {
                /* Try to generate ICMP error msg, as TTL is <= 1 */
                if (icmpv4_generate_with_throttling(ctx, 
                        ip, ctx->ru.rx.uidb_index)) {
                    /* Generated ICMP */
                    disposition = CNAT_V4_TCP_O2I_T_PKT; //CNAT_REWRITE_OUTPUT;
                    counter = CNAT_V4_TCP_O2I_TTL_GEN;
                } else {
                /* Could not generated ICMP - drop the packet */
                    disposition = CNAT_V4_TCP_O2I_D;
                    counter = CNAT_V4_TCP_O2I_TTL_DROP;
                } 
                goto drop_pkt;
            } 
        }
        db = cnat_main_db + db_index;
#if 0
        window        = db->diff_window;
        stored_seq_no = db->proto_data.tcp_seq_chk.seq_no;
        stored_ack_no = db->proto_data.tcp_seq_chk.ack_no;
        vrf_map_p     = cnat_map_by_vrf + db->vrfmap_index;
        vrf_index     = (db->in2out_key.k.vrf & CNAT_VRF_MASK);
#endif
        /* For Out2In packet, the dest info is src address and port */
        dest_info.k.port = clib_net_to_host_u16(tcp->src_port);
        dest_info.k.ipv4 = clib_net_to_host_u32(ip->src_addr);

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
                //goto packet_upd;
            } else if(PREDICT_FALSE(db->nsessions == 1)) {
                /* Destn is not same as in main db. Multiple session
                 * scenario
                 */
                dest_info.k.vrf = db->in2out_key.k.vrf;
                session_db = cnat_handle_1to2_session(db, &dest_info);
                if(PREDICT_FALSE(session_db == NULL)) {
                    disposition = CNAT_V4_TCP_O2I_D;
                    counter = CNAT_V4_TCP_O2I_SESSION_DROP;
                    goto drop_pkt;
                }
            } else { /* There are already multiple destinations */
                dest_info.k.vrf = db->in2out_key.k.vrf;
                /* If session already exists,
                 * cnat_create_session_db_entry will return the existing db
                 * else create a new db
                 * If could not create, return NULL
                 */
                session_db = cnat_create_session_db_entry(&dest_info, db, TRUE);
                if(PREDICT_FALSE(session_db == NULL)) {
                    disposition = CNAT_V4_TCP_O2I_D;
                    counter = CNAT_V4_TCP_O2I_SESSION_DROP;
                    goto drop_pkt;
                }
            }
            /* useful for ALG only */
            #if 0
            if(PREDICT_TRUE(session_db)) {
                stored_seq_no = session_db->tcp_seq_num;
                stored_ack_no = session_db->ack_no;
                window        = session_db->window;
            }	
            #endif 	
        }

        
update_pkt:
        
        counter = CNAT_V4_TCP_O2I_T_PKT;

        if (PLATFORM_HANDLE_TTL_DECREMENT) {
            /*
             * Decrement TTL and update IPv4 checksum
             */
            ipv4_decr_ttl_n_calc_csum(ip);
        }

        /* update ip checksum, newchecksum = ~(~oldchecksum + ~old + new) */
        cnat_v4_recalculate_tcp_checksum(ip, tcp,
                                         &(ip->dest_addr),
                                         &(tcp->dest_port),
                                         db->in2out_key.k.ipv4,
                                         db->in2out_key.k.port);

        /* CNAT_PPTP_ALG_SUPPORT */
        db->out2in_pkts++;

        nat44_dslite_global_stats[0].out2in_forwarding_count++;;

        V4_TCP_UPDATE_SESSION_FLAG(db, tcp);

	
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

static uword cnat_ipv4_tcp_outside_input_node_fn (vlib_main_t * vm,
                              vlib_node_runtime_t * node,
                              vlib_frame_t * frame)
{
    return dispatch_pipeline (vm, node, frame);
}


VLIB_REGISTER_NODE (cnat_ipv4_tcp_outside_input_node) = {
  .function = cnat_ipv4_tcp_outside_input_node_fn,
  .name = "vcgn-v4-tcp-o2i",
  .vector_size = sizeof (u32),
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(cnat_ipv4_tcp_outside_input_error_strings),
  .error_strings = cnat_ipv4_tcp_outside_input_error_strings,

  .n_next_nodes = CNAT_V4_TCP_O2I_NEXT,

  /* edit / add dispositions here */
  .next_nodes = {
      //[CNAT_V4_TCP_O2I_E] = "vcgn-v4-tcp-o2i-e",
      [CNAT_V4_TCP_O2I_T] = "ip4-input",
      [CNAT_V4_TCP_O2I_D] = "error-drop",
  },
};

clib_error_t *cnat_ipv4_tcp_outside_input_init (vlib_main_t *vm)
{
  cnat_ipv4_tcp_outside_input_main_t * mp = &cnat_ipv4_tcp_outside_input_main;

  mp->vlib_main = vm;
  mp->vnet_main = vnet_get_main();

  return 0;
}

VLIB_INIT_FUNCTION (cnat_ipv4_tcp_outside_input_init);
