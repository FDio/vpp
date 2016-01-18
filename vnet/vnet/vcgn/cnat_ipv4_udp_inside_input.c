/*
 *---------------------------------------------------------------------------
 * cnat_ipv4_udp_inside_input.c - cnat_ipv4_udp_inside_input node functions
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

#include "cnat_global.h"
#include "cnat_db.h"
#include "cnat_ipv4_udp.h"
#include "cnat_pcp_server.h"


#define foreach_cnat_ipv4_udp_inside_input_error 		\
_(CNAT_V4_UDP_I2O_T_PKT, "v4 udp i2o transmit")			\
_(CNAT_V4_UDP_I2O_MISS_PKT, "v4 udp i2o db miss")		\
_(CNAT_V4_UDP_I2O_TTL_GEN, "v4 udp i2o TTL gen")		\
_(CNAT_V4_UDP_I2O_TTL_DROP, "v4 udp i2o TTL drop")		\
_(CNAT_V4_PCP_PKT, "v4 pcp pkt")				\
_(CNAT_V4_UDP_I2O_SESSION_DROP, "v4 udp i2o session drop")

typedef enum {
#define _(sym,str) sym,
  foreach_cnat_ipv4_udp_inside_input_error 
#undef _
  CNAT_IPV4_UDP_INSIDE_INPUT_N_ERROR,
} cnat_ipv4_udp_inside_input_t;

static char * cnat_ipv4_udp_inside_input_error_strings[] = {
#define _(sym,string) string,
  foreach_cnat_ipv4_udp_inside_input_error
#undef _
};

typedef struct {
  u32 cached_next_index;
  /* $$$$ add data here */

  /* convenience variables */
  vlib_main_t * vlib_main;
  vnet_main_t * vnet_main;
} cnat_ipv4_udp_inside_input_main_t;

typedef enum {
    CNAT_V4_I2O_FIXME,
    CNAT_V4_UDP_I2O_E,
    CNAT_REWRITE_OUTPUT,
    CNAT_V4_UDP_I2O_T = CNAT_REWRITE_OUTPUT, 
    CNAT_N_NEXT,
} cnat_ipv4_udp_inside_input_next_t;

#define CNAT_V4_UDP_I2O_D CNAT_V4_I2O_FIXME
#define CNAT_V4_PCP_T CNAT_V4_I2O_FIXME

cnat_ipv4_udp_inside_input_main_t cnat_ipv4_udp_inside_input_main;
vlib_node_registration_t cnat_ipv4_udp_inside_input_node;

#define NSTAGES 6

/*
 * Use the generic buffer metadata + first line of packet data prefetch
 * stage function from <api/pipeline.h>. This is usually a Good Idea.
 */
#define stage0 generic_stage0

#ifndef TOBE_PORTED
static inline u32
is_pcp_pkt(u32 addr, u16 port)
{
    return CNAT_NO_CONFIG;
}
#else
static inline u32
is_pcp_pkt(spp_ctx_t *ctx, u32 addr, u16 port)
{
    cnat_vrfmap_t *my_vrfmap = NULL;
    u16  my_vrfmap_index;

    my_vrfmap_index = vrf_map_array[ctx->ru.rx.uidb_index];

    if (PREDICT_TRUE(my_vrfmap_index != VRF_MAP_ENTRY_EMPTY)) {

      my_vrfmap = cnat_map_by_vrf + my_vrfmap_index;

      if (PREDICT_FALSE( port ==  my_vrfmap->pcp_server_port)) {
             if(PREDICT_TRUE(addr == my_vrfmap->pcp_server_addr)) {
               return CNAT_SUCCESS;
             }
      }
    }

    return CNAT_NO_CONFIG;
}
#endif

void swap_ip_src_udp_port(ipv4_header *ip,
                                 udp_hdr_type_t *udp,
                                 cnat_main_db_entry_t *db)
{
    /*
     * declare varibale
     */
    CNAT_UPDATE_L3_L4_CHECKSUM_DECLARE
    /*
     * calculate checksum
     */
    CNAT_UPDATE_L3_L4_CHECKSUM(((u16)(db->in2out_key.k.ipv4)),
                               ((u16)(db->in2out_key.k.ipv4 >> 16)),
                               (db->in2out_key.k.port),
                               (clib_net_to_host_u16(ip->checksum)),
                               (clib_net_to_host_u16(udp->udp_checksum)),
                               ((u16)(db->out2in_key.k.ipv4)),
                               ((u16)(db->out2in_key.k.ipv4 >> 16)),
                               (db->out2in_key.k.port))

/* #define UDP_PACKET_DEBUG 1 */

// Temporary debugs which will be suppressed later
#ifdef UDP_PACKET_DEBUG
    if (PREDICT_FALSE(udp_inside_packet_dump_enable)) {
    printf("\nIn2Out UDP packet before translation");
    print_udp_pkt(ip);
    }
#endif

    //set ip header
    ip->src_addr =
        clib_host_to_net_u32(db->out2in_key.k.ipv4);
    ip->checksum =
        clib_host_to_net_u16(new_l3_c);

    u16 frag_offset =
        clib_net_to_host_u16(ip->frag_flags_offset);

    if(PREDICT_FALSE(frag_offset & IP_FRAG_OFFSET_MASK)) {
        return; /* No need to update UDP fields */
    }
    //set udp header
    udp->src_port =
        clib_host_to_net_u16(db->out2in_key.k.port);

    /*
     * No easy way to avoid this if check except by using
     * complex logic - may not be worth it.
     */
    if (PREDICT_TRUE(udp->udp_checksum)) {
    udp->udp_checksum =
        clib_host_to_net_u16(new_l4_c);
    }

// Temporary debugs which will be suppressed later
#ifdef UDP_PACKET_DEBUG
    if (PREDICT_FALSE(udp_inside_checksum_disable)) {
    printf("\nIn2Out UDP checksum 0x%x disabled by force", new_l4_c);
    udp->udp_checksum = 0;
    }
    if (PREDICT_FALSE(udp_inside_packet_dump_enable)) {
    printf("\nIn2Out UDP packet after translation");
    print_udp_pkt(ip);
    }
#endif
}

static inline void
stage1(vlib_main_t * vm, vlib_node_runtime_t * node, u32 buffer_index)
{
    u64 a, b, c;
    u32 bucket;
    u8 *prefetch_target;

    vlib_buffer_t * b0 = vlib_get_buffer (vm, buffer_index);
    ipv4_header *ip = vlib_buffer_get_current (b0);
    u8   ipv4_hdr_len = (ip->version_hdr_len_words & 0xf) << 2;
    udp_hdr_type_t *udp = (udp_hdr_type_t *)((u8*)ip + ipv4_hdr_len);
  
    u64 tmp = 0;
    tmp = vnet_buffer(b0)->vcgn_uii.key.k.ipv4 =
            clib_net_to_host_u32(ip->src_addr);
    vnet_buffer(b0)->vcgn_uii.key.k.port =
            clib_net_to_host_u16 (udp->src_port);

    tmp |= ((u64)vnet_buffer(b0)->vcgn_uii.key.k.port) << 32;

    PLATFORM_CNAT_SET_RX_VRF(vnet_buffer(b0)->sw_if_index[VLIB_RX],
                             vnet_buffer(b0)->vcgn_uii.key.k.vrf,
                             CNAT_UDP)
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

static u64 pkt_num = 0;
static inline u32 last_stage (vlib_main_t *vm, vlib_node_runtime_t *node,
                              u32 bi)
{
    vlib_buffer_t *b0 = vlib_get_buffer (vm, bi);
    u32 db_index = vnet_buffer(b0)->vcgn_uii.bucket;
    spp_ctx_t *ctx = (spp_ctx_t *) &vnet_buffer(b0)->vcgn_uii;
    int disposition = CNAT_V4_UDP_I2O_T;
    int counter = CNAT_V4_UDP_I2O_T_PKT;
    ipv4_header *ip = (ipv4_header *)vlib_buffer_get_current(b0);
    u8   ipv4_hdr_len = (ip->version_hdr_len_words & 0xf) << 2;
    udp_hdr_type_t *udp = (udp_hdr_type_t *)((u8*)ip + ipv4_hdr_len);
    vlib_node_t *n = vlib_get_node (vm, cnat_ipv4_udp_inside_input_node.index);
    u32 node_counter_base_index = n->error_heap_index;
    vlib_error_main_t * em = &vm->error_main;
    cnat_session_entry_t *session_db = NULL;
    cnat_key_t dest_info;

    pkt_num++;

    if(PREDICT_FALSE(is_pcp_pkt(ip->dest_addr, udp->dest_port) == 
                     CNAT_SUCCESS)) 
    {
        PCP_INCR(input);
        disposition = CNAT_V4_PCP_T;
        counter = CNAT_V4_PCP_PKT;

        goto pcp_pkt;
    }

    if (PLATFORM_HANDLE_TTL_DECREMENT) {
        if (PREDICT_FALSE(ip->ttl <= 1)) {
            /* Try to generate ICMP error msg, as TTL is <= 1 */

            if (icmpv4_generate_with_throttling
                    (ctx, ip, ctx->ru.rx.uidb_index)) {
                /* Generated ICMP */
                disposition = CNAT_REWRITE_OUTPUT;
                counter = CNAT_V4_UDP_I2O_TTL_GEN;
            } else {
                /* Could not generated ICMP - drop the packet */
                disposition = CNAT_V4_UDP_I2O_D;
                counter = CNAT_V4_UDP_I2O_TTL_DROP;
            }
            goto drop_pkt;
        }
    }
    if (PREDICT_TRUE(db_index != EMPTY)) {
        cnat_main_db_entry_t *db = cnat_main_db + db_index;

         dest_info.k.ipv4 = clib_net_to_host_u32(ip->dest_addr);

         /* MUST revisit: it seems farg is set to 1 for few packets & because of
          * this the port is not updated & it becomes 0. Commenting teporarily 
          * this fargment check & setting dst port with udp dst port value */
         dest_info.k.port = clib_net_to_host_u16(udp->dest_port);
          #if 0  // DONOT REMOVE THIS if 0
         if(PREDICT_FALSE(ctx->ru.rx.frag)) {
#ifdef TOBE_PORTED
             /* Must have routed through cnat_v4_frag_in2out node */
             u16 *feature_data_ports = (u16 *)&ctx->feature_data[4];
             dest_info.k.port = *feature_data_ports;
#endif
         } else {
             dest_info.k.port = clib_net_to_host_u16(udp->dest_port);
         }
         #endif


        if (PLATFORM_HANDLE_TTL_DECREMENT) {
            /*
             * Decrement TTL and update IPv4 checksum
             */
            ipv4_decr_ttl_n_calc_csum(ip);
        }

        if(PREDICT_TRUE(!PLATFORM_DBL_SUPPORT)) {

            /* No DBL support, so just update the destn and proceed */
            db->dst_ipv4 = dest_info.k.ipv4;
            db->dst_port = dest_info.k.port;
            CNAT_DB_TIMEOUT_RST(db);
            goto update_pkt;
        }

        if(PREDICT_TRUE((db->dst_ipv4 == dest_info.k.ipv4) &&
                          (db->dst_port == dest_info.k.port))) {

            CNAT_DB_TIMEOUT_RST(db);
            goto update_pkt;
        } else {
            if (PREDICT_FALSE(db->nsessions == 0)) {
                /* Should be a static entry
                 * Note this session as the first session and log
                 */
                cnat_add_dest_n_log(db, &dest_info);
                /*
                 * update db counter, timer
                 */

                CNAT_DB_TIMEOUT_RST(db);

            } else if(PREDICT_TRUE(db->nsessions == 1)) {
                /* Destn is not same as in main db. Multiple session
                 * scenario
                 */
                //printf(">>> [pkt# %lu] src_ip: 0x%x, db ip: 0x%x, db port: %u; dest ip: 0x%x, dest port: %u\n",
                //    pkt_num, ntohl(ip->src_addr), db->dst_ipv4, db->dst_port, dest_info.k.ipv4, dest_info.k.port);

                dest_info.k.vrf = db->in2out_key.k.vrf;
                session_db = cnat_handle_1to2_session(db, &dest_info);

                if(PREDICT_TRUE(session_db != NULL)) {
                    /* session exists */
                    CNAT_DB_TIMEOUT_RST(session_db);
                } else {
                    /* could not create session db - drop packet */
                    disposition = CNAT_V4_UDP_I2O_D;
                    counter = CNAT_V4_UDP_I2O_SESSION_DROP;
                    goto drop_pkt;
                }

            } else {
                /* More than 2 sessions exists */

                dest_info.k.vrf = db->in2out_key.k.vrf;

                /* If session already exists,
                 * cnat_create_session_db_entry will return the existing db
                 * else create a new db
                 * If could not create, return NULL
                 */
                session_db = cnat_create_session_db_entry(&dest_info,
                                                             db, TRUE);

                if(PREDICT_FALSE(session_db != NULL)) {
                    /* session exists */
                    CNAT_DB_TIMEOUT_RST(session_db);
                } else {
                    /* could not create session db - drop packet */
                    disposition = CNAT_V4_UDP_I2O_D;
                    counter = CNAT_V4_UDP_I2O_SESSION_DROP;
                    goto drop_pkt;
                }
            }
        }

update_pkt:
        /*
         * 1. update src ipv4 addr and src udp port
         * 2. update ipv4 checksum and udp checksum
         */
        swap_ip_src_udp_port(ip, udp, db);
        /*
         * update db counter, timer
         */

        db->in2out_pkts++;

        /*
         * need to set outside vrf
         * from db->out2in_key.k.vrf
         */
		
	/* Temporarily keeping this commented */
        //PLATFORM_CNAT_SET_TX_VRF(vnet_buffer(b0)->sw_if_index[VLIB_TX], 
        //		db->out2in_key.k.vrf)

        in2out_forwarding_count++;

    } else {
        disposition = CNAT_V4_UDP_I2O_E;
        counter = CNAT_V4_UDP_I2O_MISS_PKT;
    }

drop_pkt:
pcp_pkt:

    em->counters[node_counter_base_index + counter] += 1;

    return  disposition;
}

#include <vnet/pipeline.h>

static uword cnat_ipv4_udp_inside_input_node_fn (vlib_main_t * vm,
                              vlib_node_runtime_t * node,
                              vlib_frame_t * frame)
{
    return dispatch_pipeline (vm, node, frame);
}


VLIB_REGISTER_NODE (cnat_ipv4_udp_inside_input_node) = {
  .function = cnat_ipv4_udp_inside_input_node_fn,
  .name = "vcgn-v4-udp-i2o",
  .vector_size = sizeof (u32),
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(cnat_ipv4_udp_inside_input_error_strings),
  .error_strings = cnat_ipv4_udp_inside_input_error_strings,

  .n_next_nodes = CNAT_N_NEXT,

  /* edit / add dispositions here */
  .next_nodes = {
	[CNAT_V4_I2O_FIXME] = "error-drop",
        // [CNAT_V4_UDP_I2O_T] = "ip4-input",
        [CNAT_V4_UDP_I2O_E] = "vcgn-v4-udp-i2o-e",
        [CNAT_REWRITE_OUTPUT] = "ip4-input",
  },
};

clib_error_t *cnat_ipv4_udp_inside_input_init (vlib_main_t *vm)
{
  cnat_ipv4_udp_inside_input_main_t * mp = &cnat_ipv4_udp_inside_input_main;

  mp->vlib_main = vm;
  mp->vnet_main = vnet_get_main();

  return 0;
}

VLIB_INIT_FUNCTION (cnat_ipv4_udp_inside_input_init);
