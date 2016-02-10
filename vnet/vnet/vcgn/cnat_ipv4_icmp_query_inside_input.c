/* 
 *---------------------------------------------------------------------------
 * cnat_ipv4_icmp_query_inside_input.c - cnat_ipv4_icmp_query_inside_input node pipeline stage functions
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

#include "cnat_ipv4_icmp.h"

#define foreach_cnat_ipv4_icmp_q_inside_input_error 		\
_(CNAT_V4_ICMP_Q_I2O_T_PKT, "cnat v4 icmp_q i2o packet transmit")			\
_(CNAT_V4_ICMP_Q_I2O_MISS_PKT, "cnat v4 icmp_q i2o db miss")			\
_(CNAT_V4_ICMP_Q_I2O_TTL_GEN, "cnat v4 icmp_q i2o ttl generate")			\
_(CNAT_V4_ICMP_Q_I2O_TTL_DROP, "cnat v4 icmp_q i2o ttl drop")			\
_(CNAT_V4_ICMP_Q_I2O_NO_SESSION_DROP, "cnat v4 icmp_q i2o no session drop")

typedef enum {
#define _(sym,str) sym,
  foreach_cnat_ipv4_icmp_q_inside_input_error 
#undef _
  CNAT_IPV4_ICMP_Q_INSIDE_INPUT_N_ERROR,
} cnat_ipv4_icmp_q_inside_input_t;

static char * cnat_ipv4_icmp_q_inside_input_error_strings[] = {
#define _(sym,string) string,
  foreach_cnat_ipv4_icmp_q_inside_input_error
#undef _
};

typedef struct {
  u32 cached_next_index;
  /* $$$$ add data here */

  /* convenience variables */
  vlib_main_t * vlib_main;
  vnet_main_t * vnet_main;
} cnat_ipv4_icmp_q_inside_input_main_t;

typedef enum {
    CNAT_V4_ICMP_Q_I2O_T,
    CNAT_V4_ICMP_Q_I2O_E,
    CNAT_V4_ICMP_Q_I2O_D,
    CNAT_V4_ICMP_Q_I2O_NEXT,
} cnat_ipv4_icmp_q_inside_input_next_t;

cnat_ipv4_icmp_q_inside_input_main_t cnat_ipv4_icmp_q_inside_input_main;
vlib_node_registration_t cnat_ipv4_icmp_q_inside_input_node;

#define NSTAGES 5

inline void swap_ip_src_icmp_id(ipv4_header *ip,
                                icmp_v4_t *icmp,
                                cnat_main_db_entry_t *db, u16 vrf)
{
#if 0
    u32 postmap_ip;
    u8 direction;
    u32 old_ip;
    u32 old_postmap_ip;


    if(is_static_dest_nat_enabled(vrf) == CNAT_SUCCESS) {
	direction = 0;
	if(cnat_static_dest_db_get_translation(ip->dest_addr, &postmap_ip, vrf, direction) ==  CNAT_SUCCESS) {
	    CNAT_UPDATE_L3_CHECKSUM_DECLARE 
		
            old_ip = spp_net_to_host_byte_order_32(&(ip->dest_addr));
	    old_postmap_ip = spp_net_to_host_byte_order_32(&postmap_ip);

	    CNAT_UPDATE_L3_CHECKSUM(((u16)(old_ip & 0xFFFF)),
				    ((u16)(old_ip >> 16)),
				    (spp_net_to_host_byte_order_16(&(ip->checksum))),
				    ((u16)(old_postmap_ip & 0xFFFF)),
				    ((u16)(old_postmap_ip >> 16)))
	    ip->dest_addr = postmap_ip;

	    ip->checksum =
		spp_host_to_net_byte_order_16(new_l3_c);
	}
    }
#endif /* if 0 */
    /*
     * declare variable
     */
    CNAT_UPDATE_L3_L4_CHECKSUM_DECLARE
    /*
     * calculate checksum
     */
    CNAT_UPDATE_L3_ICMP_CHECKSUM(((u16)(db->in2out_key.k.ipv4)),
                               ((u16)(db->in2out_key.k.ipv4 >> 16)),
                               (db->in2out_key.k.port),
                               (clib_net_to_host_u16(ip->checksum)),
                               (clib_net_to_host_u16(icmp->checksum)),
                               ((u16)(db->out2in_key.k.ipv4)),
                               ((u16)(db->out2in_key.k.ipv4 >> 16)),
                               (db->out2in_key.k.port))
    //set ip header
    ip->src_addr =
        clib_host_to_net_u32(db->out2in_key.k.ipv4);
    ip->checksum =
        clib_host_to_net_u16(new_l3_c);

    //set icmp header
    icmp->identifier =
        clib_host_to_net_u16(db->out2in_key.k.port);
    icmp->checksum =
        clib_host_to_net_u16(new_l4_c);
}

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
    icmp_v4_t *icmp = (icmp_v4_t *)((u8*)ip + ipv4_hdr_len);
  
    u64 tmp = 0;
    tmp = vnet_buffer(b0)->vcgn_uii.key.k.ipv4 =
            clib_net_to_host_u32(ip->src_addr);
    vnet_buffer(b0)->vcgn_uii.key.k.port =
            clib_net_to_host_u16 (icmp->identifier);

    tmp |= ((u64)vnet_buffer(b0)->vcgn_uii.key.k.port) << 32;

    PLATFORM_CNAT_SET_RX_VRF(vnet_buffer(b0)->sw_if_index[VLIB_RX],
                             vnet_buffer(b0)->vcgn_uii.key.k.vrf,
                             CNAT_ICMP)
    tmp |= ((u64)vnet_buffer(b0)->vcgn_uii.key.k.vrf) << 48;

    CNAT_V4_GET_HASH(tmp, bucket, CNAT_MAIN_HASH_MASK)

    prefetch_target = (u8 *)(&cnat_in2out_hash[bucket]);
    vnet_buffer(b0)->vcgn_uii.bucket = bucket;

    /* Prefetch the hash bucket */
    CLIB_PREFETCH(prefetch_target, CLIB_CACHE_LINE_BYTES, LOAD);
}

#define SPP_LOG2_CACHE_LINE_BYTES 6
#define SPP_CACHE_LINE_BYTES (1 << SPP_LOG2_CACHE_LINE_BYTES)

static inline void
stage2(vlib_main_t * vm, vlib_node_runtime_t * node, u32 buffer_index)
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
stage3(vlib_main_t * vm, vlib_node_runtime_t * node, u32 buffer_index)
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
    int disposition = CNAT_V4_ICMP_Q_I2O_T;
    int counter = CNAT_V4_ICMP_Q_I2O_T_PKT;

    ipv4_header *ip = (ipv4_header *)vlib_buffer_get_current(b0);
    u8   ipv4_hdr_len = (ip->version_hdr_len_words & 0xf) << 2;
    icmp_v4_t *icmp = (icmp_v4_t *)((u8*)ip + ipv4_hdr_len);
    vlib_node_t *n = vlib_get_node (vm, cnat_ipv4_icmp_q_inside_input_node.index);
    u32 node_counter_base_index = n->error_heap_index;
    vlib_error_main_t * em = &vm->error_main;
    cnat_session_entry_t *session_db = NULL;
    cnat_main_db_entry_t *db = NULL;
    cnat_key_t dest_info;

    if (PLATFORM_HANDLE_TTL_DECREMENT) {
        if (PREDICT_FALSE(ip->ttl <= 1)) {
            /* Try to generate ICMP error msg, as TTL is <= 1 */

            if (icmpv4_generate_with_throttling
                    (ctx, ip, ctx->ru.rx.uidb_index)) {

                /* Generated ICMP */
                disposition = CNAT_V4_ICMP_Q_I2O_T;
                counter = CNAT_V4_ICMP_Q_I2O_TTL_GEN;
            } else {
                /* Could not generated ICMP - drop the packet */
                disposition = CNAT_V4_ICMP_Q_I2O_D; 
                counter = CNAT_V4_ICMP_Q_I2O_TTL_DROP;
            }
            goto drop_pkt;
        }
    }

    if (PREDICT_TRUE(db_index != EMPTY)) {
        db = cnat_main_db + db_index;
        dest_info.k.port = 0;
        dest_info.k.ipv4 = clib_net_to_host_u32(ip->dest_addr);

        if(PREDICT_TRUE(!PLATFORM_DBL_SUPPORT)) {

            /* No DBL support, so just update the destn and proceed */
            db->dst_ipv4 = dest_info.k.ipv4;
            db->dst_port = dest_info.k.port;
            goto update_pkt;
        }

        if(PREDICT_FALSE(db->dst_ipv4 != dest_info.k.ipv4)) {
            if(PREDICT_TRUE(db->nsessions == 1)) {
                /* Handle one to 2 dest scenarion */
                dest_info.k.vrf = db->in2out_key.k.vrf;
                session_db = cnat_handle_1to2_session(db, &dest_info);

                if(PREDICT_FALSE(session_db == NULL)) {
                    disposition = CNAT_V4_ICMP_Q_I2O_D;
                    counter = CNAT_V4_ICMP_Q_I2O_NO_SESSION_DROP;
                    goto drop_pkt;
                }
            } else if (PREDICT_FALSE(db->nsessions == 0)) {
                /* Should be a static entry
                 * Note this session as the first session and log
                 */
                cnat_add_dest_n_log(db, &dest_info);
            } else { /* Many translations exist already */
                dest_info.k.vrf = db->in2out_key.k.vrf;
                /* If session already exists,
                 * cnat_create_session_db_entry will return the existing db
                 * else create a new db
                 * If could not create, return NULL
                 */
                session_db = cnat_create_session_db_entry(&dest_info,
                        db, TRUE);

                if(PREDICT_FALSE(session_db == NULL)) {
                    disposition = CNAT_V4_ICMP_Q_I2O_D;
                    counter = CNAT_V4_ICMP_Q_I2O_NO_SESSION_DROP;
                    goto drop_pkt;
                }
            }
        }

update_pkt:

        if (PREDICT_FALSE(icmp_debug_flag)) {
            printf("\nDUMPING ICMP PKT BEFORE\n");
            print_icmp_pkt(ip);
        }

        if (PLATFORM_HANDLE_TTL_DECREMENT) {
            /*
             * Decrement TTL and update IPv4 checksum
             */
            ipv4_decr_ttl_n_calc_csum(ip);
        }

        /*
         * 1. update src ipv4 addr and src icmp identifier
         * 2. update ipv4 checksum and icmp checksum
         */
        swap_ip_src_icmp_id(ip, icmp, db, db->in2out_key.k.vrf);

        if (PREDICT_FALSE(icmp_debug_flag)) {
            printf("\nDUMPING ICMP PKT AFTER\n");
            print_icmp_pkt(ip);
        }

        /*
         * update db counter, timer
         */

        if(PREDICT_FALSE(session_db != 0)) {
            CNAT_DB_TIMEOUT_RST(session_db);
        } else {
            CNAT_DB_TIMEOUT_RST(db);
        }
        db->in2out_pkts++;
        in2out_forwarding_count++;

    } else {
        disposition = CNAT_V4_ICMP_Q_I2O_E;
        counter = CNAT_V4_ICMP_Q_I2O_MISS_PKT;
    }

drop_pkt:

    em->counters[node_counter_base_index + counter] += 1;
    return  disposition;
}

#include <vnet/pipeline.h>

static uword cnat_ipv4_icmp_q_inside_input_node_fn (vlib_main_t * vm,
                              vlib_node_runtime_t * node,
                              vlib_frame_t * frame)
{
    return dispatch_pipeline (vm, node, frame);
}


VLIB_REGISTER_NODE (cnat_ipv4_icmp_q_inside_input_node) = {
  .function = cnat_ipv4_icmp_q_inside_input_node_fn,
  .name = "vcgn-v4-icmp-q-i2o",
  .vector_size = sizeof (u32),
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(cnat_ipv4_icmp_q_inside_input_error_strings),
  .error_strings = cnat_ipv4_icmp_q_inside_input_error_strings,

  .n_next_nodes = CNAT_V4_ICMP_Q_I2O_NEXT,

  /* edit / add dispositions here */
  .next_nodes = {
      [CNAT_V4_ICMP_Q_I2O_E] = "vcgn-v4-icmp-q-i2o-e",
      [CNAT_V4_ICMP_Q_I2O_T] = "ip4-input",
      [CNAT_V4_ICMP_Q_I2O_D] = "error-drop",
  },
};

clib_error_t *cnat_ipv4_icmp_q_inside_input_init (vlib_main_t *vm)
{
  cnat_ipv4_icmp_q_inside_input_main_t * mp = &cnat_ipv4_icmp_q_inside_input_main;

  mp->vlib_main = vm;
  mp->vnet_main = vnet_get_main();

  return 0;
}

VLIB_INIT_FUNCTION (cnat_ipv4_icmp_q_inside_input_init);
