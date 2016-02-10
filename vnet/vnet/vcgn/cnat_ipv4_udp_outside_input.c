
/* 
 *---------------------------------------------------------------------------
 * cnat_ipv4_udp_outside_input_stages.c - cnat_ipv4_udp_outside_input node pipeline stage functions
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

#include "cnat_ipv4_udp.h"
#include "dslite_db.h"
#include "cnat_db.h"
#include "cnat_v4_functions.h"

//#include <dslite_v6_functions.h>
//#include <pool.h>
//#include "cnat_va_db.h"

#define foreach_cnat_ipv4_udp_outside_input_error 		\
_(CNAT_V4_UDP_O2I_T_PKT, "v4 udp o2i transmit")			\
_(CNAT_V4_DSLITE_ENCAP_CTR, "to dslite encap")			\
_(CNAT_V4_UDP_O2I_MISS_PKT, "v4 udp o2i db miss drop")		\
_(CNAT_V4_UDP_O2I_TTL_GEN, "v4 udp o2i TTL gen")		\
_(CNAT_V4_UDP_O2I_TTL_DROP, "v4 udp o2i TTL drop")		\
_(CNAT_V4_UDP_O2I_PTB_GEN, "v4 ptb gen")		\
_(CNAT_V4_UDP_O2I_PTB_DROP, "v4 ptb throttle drop")		\
_(CNAT_V4_UDP_O2I_SESSION_DROP, "v4 udp o2i session drop")		\
_(CNAT_V4_UDP_O2I_FILTER_DROP, "v4 udp o2i drop: end point filtering")		\
_(CNAT_V4_UDP_O2I_SUB_FRAG_NO_DB_DROP, "v4 udp o2i subsequent frag no DB drop")		\
_(CNAT_V4_UDP_O2I_1ST_FRAG_FILTER_DROP, "v4 udp i2o 1st frag filter drop")

typedef enum {
#define _(sym,str) sym,
  foreach_cnat_ipv4_udp_outside_input_error 
#undef _
  CNAT_IPV4_UDP_OUTSIDE_INPUT_N_ERROR,
} cnat_ipv4_udp_outside_input_t;

static char * cnat_ipv4_udp_outside_input_error_strings[] = {
#define _(sym,string) string,
  foreach_cnat_ipv4_udp_outside_input_error
#undef _
};

typedef struct {
  u32 cached_next_index;
  /* $$$$ add data here */

  /* convenience variables */
  vlib_main_t * vlib_main;
  vnet_main_t * vnet_main;
} cnat_ipv4_udp_outside_input_main_t;

typedef enum {
    //CNAT_V4_O2I_FIXME,
    CNAT_V4_UDP_O2I_E,
    CNAT_V4_UDP_O2I_T,
    CNAT_V4_UDP_O2I_NEXT,
} cnat_ipv4_udp_outside_input_next_t;

//#define CNAT_V4_DSLITE_ENCAP CNAT_V4_O2I_FIXME
//#define CNAT_V4_UDP_O2I_E    CNAT_V4_O2I_FIXME

cnat_ipv4_udp_outside_input_main_t cnat_ipv4_udp_outside_input_main;
vlib_node_registration_t cnat_ipv4_udp_outside_input_node;

#define NSTAGES 6

/*
 * Use the generic buffer metadata + first line of packet data prefetch
 * stage function from <api/pipeline.h>. This is usually a Good Idea.
 */
#define stage0 generic_stage0


#if 0
typedef struct cnat_ipv4_udp_outside_input_pipeline_data_ {
    //spp_node_main_vector_t *nmv;
    dslite_common_pipeline_data_t common_data;
    /* Add additional pipeline stage data here... */
    u32 bucket;
#ifdef DSLITE_DEF
    u32 user_bucket;
    dslite_v4_to_v6_udp_counter_t  *udp_counter;
    dslite_icmp_gen_counter_t      *icmp_gen_counter;

#endif
    cnat_key_t ki;
    udp_hdr_type_t *udp;
    u8 frag_pkt;
} cnat_ipv4_udp_outside_input_pipeline_data_t;

#endif

#define CNAT_UDP_OUTSIDE_UPDATE_FLAG_TIMER(db,dslite_nat44_inst_id) \
        if (PREDICT_FALSE(!(db->flags & CNAT_DB_FLAG_UDP_ACTIVE))) { \
            db->flags |= CNAT_DB_FLAG_UDP_ACTIVE; \
            CNAT_DB_TIMEOUT_RST(db); \
        } else if (PREDICT_FALSE(db->flags & CNAT_DB_DSLITE_FLAG)) { \
	    if (PREDICT_TRUE(dslite_table_db_ptr[dslite_nat44_inst_id].mapping_refresh_both_direction)) { \
		CNAT_DB_TIMEOUT_RST(db); \
	    } \
        } else if (PREDICT_TRUE(mapping_refresh_both_direction)) { \
            CNAT_DB_TIMEOUT_RST(db); \
        } \

#if 0
static cnat_ipv4_udp_outside_input_pipeline_data_t pctx_data[SPP_MAXDISPATCH];
#define EXTRA_PIPELINE_ARGS_PROTO , cnat_ipv4_udp_outside_input_pipeline_data_t *pctx
#define EXTRA_PIPELINE_ARGS , pctx

#endif

/*inline u32
is_static_dest_nat_enabled(u16 vrf)
{
    if(static_dest_vrf_map_array[vrf] == 1) {
	return CNAT_SUCCESS;
    }
    return CNAT_NO_CONFIG;
}*/

static inline void swap_ip_dst(ipv4_header *ip, 
                        cnat_main_db_entry_t *db, u16 vrf)
{

    CNAT_UPDATE_L3_CHECKSUM_DECLARE
    /*
     * calculate checksum
     */
    CNAT_UPDATE_L3_CHECKSUM(((u16)(db->out2in_key.k.ipv4)),
                            ((u16)(db->out2in_key.k.ipv4 >> 16)),
                            (clib_host_to_net_u16(ip->checksum)),
                            ((u16)(db->in2out_key.k.ipv4)),
                            ((u16)(db->in2out_key.k.ipv4 >> 16)))
    //set ip header
    ip->dest_addr =
        clib_host_to_net_u32(db->in2out_key.k.ipv4);
    ip->checksum =
        clib_host_to_net_u16(new_l3_c);

#if 0
    
    if(is_static_dest_nat_enabled(vrf) == CNAT_SUCCESS) {
	direction = 1;
	if(cnat_static_dest_db_get_translation(ip->src_addr, &postmap_ip, vrf, direction) ==  CNAT_SUCCESS) {
	    old_ip = spp_net_to_host_byte_order_32(&(ip->src_addr));
	    old_postmap_ip = spp_net_to_host_byte_order_32(&postmap_ip);

	    CNAT_UPDATE_L3_CHECKSUM(((u16)(old_ip & 0xFFFF)),
				    ((u16)(old_ip >> 16)),
				    (spp_net_to_host_byte_order_16(&(ip->checksum))),
				    ((u16)(old_postmap_ip & 0xFFFF)),
				    ((u16)(old_postmap_ip >> 16)))	    
	    ip->checksum =
		clib_host_to_net_u16(new_l3_c);
	    ip->src_addr = postmap_ip;
	}
    }
#endif 
}

inline void swap_ip_dst_udp_port(ipv4_header *ip,
                                 udp_hdr_type_t *udp,
                                 cnat_main_db_entry_t *db, u16 vrf)
{

#define UDP_PACKET_DEBUG 1

// Temporary debugs which will be suppressed later
#ifdef UDP_PACKET_DEBUG
    if (PREDICT_FALSE(udp_outside_packet_dump_enable)) {
	printf("\nOut2In UDP packet before translation");
	print_udp_pkt(ip);
    }
#endif

#if 0
    if(is_static_dest_nat_enabled(vrf) == CNAT_SUCCESS) {
	direction = 1;
	if(cnat_static_dest_db_get_translation(ip->src_addr, &postmap_ip, vrf, direction) ==  CNAT_SUCCESS) {
	   
	    CNAT_UPDATE_L3_L4_CHECKSUM_DECLARE
		
	    old_ip = spp_net_to_host_byte_order_32(&(ip->src_addr));
	    old_postmap_ip = spp_net_to_host_byte_order_32(&postmap_ip);

	    CNAT_UPDATE_L3_L4_CHECKSUM(((u16)(old_ip & 0xFFFF)),
                               ((u16)(old_ip >> 16)),
                               (spp_net_to_host_byte_order_16(&(udp->src_port))),
                               (spp_net_to_host_byte_order_16(&(ip->checksum))),
                               (spp_net_to_host_byte_order_16(&(udp->udp_checksum))),
                               ((u16)(old_postmap_ip & 0xFFFF)),
                               ((u16)(old_postmap_ip >> 16)),
                               (spp_net_to_host_byte_order_16(&(udp->src_port))))

	    ip->checksum =
		clib_host_to_net_u16(new_l3_c);
	    ip->src_addr = postmap_ip;
	    if (PREDICT_TRUE(udp->udp_checksum)) {
		udp->udp_checksum = clib_host_to_net_u16(new_l4_c);
	    }
	}
    }
#endif
    /*
     * declare variable
     */
    CNAT_UPDATE_L3_L4_CHECKSUM_DECLARE
    /*
     * calculate checksum
     */
    CNAT_UPDATE_L3_L4_CHECKSUM(((u16)(db->out2in_key.k.ipv4)),
                               ((u16)(db->out2in_key.k.ipv4 >> 16)),
                               (db->out2in_key.k.port),
                               (clib_net_to_host_u16(ip->checksum)),
                               (clib_net_to_host_u16(udp->udp_checksum)),
                               ((u16)(db->in2out_key.k.ipv4)),
                               ((u16)(db->in2out_key.k.ipv4 >> 16)),
                               (db->in2out_key.k.port))




    //set ip header
    ip->dest_addr =
        clib_host_to_net_u32(db->in2out_key.k.ipv4);
    ip->checksum =
        clib_host_to_net_u16(new_l3_c);

    //set udp header
    udp->dest_port =
        clib_host_to_net_u16(db->in2out_key.k.port);

    /*
     * No easy way to avoid this if check except by using
     * complex logic - may not be worth it.
     */
    if (PREDICT_TRUE(udp->udp_checksum)) {
	udp->udp_checksum = clib_host_to_net_u16(new_l4_c);
    }

    

// Temporary debugs which will be suppressed later
#ifdef UDP_PACKET_DEBUG
    if (PREDICT_FALSE(udp_outside_checksum_disable)) {
	printf("\nOut2In UDP checksum 0x%x disabled by force", new_l4_c);
	udp->udp_checksum = 0;
    }
    if (PREDICT_FALSE(udp_outside_packet_dump_enable)) {
	printf("\nOut2In UDP packet after translation");
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
            clib_net_to_host_u32(ip->dest_addr);
    vnet_buffer(b0)->vcgn_uii.key.k.port =
            clib_net_to_host_u16 (udp->dest_port);

    tmp |= ((u64)vnet_buffer(b0)->vcgn_uii.key.k.port) << 32;

    PLATFORM_CNAT_SET_RX_VRF(vnet_buffer(b0)->sw_if_index[VLIB_RX],
                             vnet_buffer(b0)->vcgn_uii.key.k.vrf,
                             CNAT_UDP)
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

#if 0

ALWAYS_INLINE(
static inline void
stage5(spp_ctx_t **ctxs, int index, spp_node_t *np,
       u8 *disp_used EXTRA_PIPELINE_ARGS_PROTO))
{
    spp_ctx_t *ctx = ctxs[index];
    u32 db_index = pctx[index].bucket;
    /* for nat44, dslite_id will be 1 */
    u16 dslite_id = *(pctx[index].common_data.dslite_id_ptr);

    DSLITE_PREFETCH_COUNTER(pctx[index].udp_counter,
                          &dslite_all_counters[dslite_id].v46_udp_counters,
                          dslite_v4_to_v6_udp_counter_t,
                          v4_to_v6_udp_output_count,
                          "V4_TO_V6_UDP")

    DSLITE_PREFETCH_COUNTER(pctx[index].icmp_gen_counter,
                          &dslite_all_counters[dslite_id].dslite_icmp_gen_counters,
                          dslite_icmp_gen_counter_t,
                          v6_icmp_gen_count,
                          "V4_TO_V6_icmp")

if (PREDICT_TRUE(db_index != EMPTY)) {
    cnat_main_db_entry_t *db = cnat_main_db + db_index;

    u32 user_db_index = db->user_index;
    DSLITE_PRINTF(1, "UDP o2i, db entry found %u %u %u\n", 
                      db_index,  user_db_index,
                      db->dslite_nat44_inst_id);
    uword prefetch_target0 = (uword)(cnat_user_db + user_db_index);
    SPP_PREFETCH(prefetch_target0, 0, LOAD);
    pctx[index].user_bucket = user_db_index;
    DSLITE_PRINTF(1, "UDP: Done with prefetch..\n");
} else { 
    DSLITE_PRINTF(1, "UDP: Stage 5, db_index empty...\n");
}
}

#endif


static inline u32 last_stage (vlib_main_t *vm, vlib_node_runtime_t *node,
                              u32 bi)
{

    vlib_buffer_t *b0 = vlib_get_buffer (vm, bi);
    u32 db_index = vnet_buffer(b0)->vcgn_uii.bucket;
    //spp_ctx_t *ctx = (spp_ctx_t *) &vnet_buffer(b0)->vcgn_uii;
    int disposition = CNAT_V4_UDP_O2I_T;
    int counter = CNAT_V4_UDP_O2I_T_PKT;
    ipv4_header *ip = (ipv4_header *)vlib_buffer_get_current(b0);
    u8   ipv4_hdr_len = (ip->version_hdr_len_words & 0xf) << 2;
    udp_hdr_type_t *udp = (udp_hdr_type_t *)((u8*)ip + ipv4_hdr_len);
    vlib_node_t *n = vlib_get_node (vm, cnat_ipv4_udp_outside_input_node.index);
    u32 node_counter_base_index = n->error_heap_index;
    vlib_error_main_t * em = &vm->error_main;
    cnat_session_entry_t *session_db = NULL;
    cnat_main_db_entry_t *db = NULL;
    cnat_key_t dest_info;
    u16 dslite_nat44_inst_id __attribute__((unused)) = 0;

    dest_info.k.port = clib_net_to_host_u16(udp->src_port);
    dest_info.k.ipv4 = clib_net_to_host_u32(ip->src_addr);

    if (PREDICT_TRUE(db_index != EMPTY)) {
        /* TTL gen was disabled for nat44 earlier
         * But since dslite has got integrated in this
         * TTL gen is enabled 
         */

        db = cnat_main_db + db_index;
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
            CNAT_UDP_OUTSIDE_UPDATE_FLAG_TIMER(db, 0)
            goto update_pkt;
        }
    

        if(PREDICT_TRUE((db->dst_ipv4 == dest_info.k.ipv4) &&
                          (db->dst_port == dest_info.k.port))) {

            CNAT_UDP_OUTSIDE_UPDATE_FLAG_TIMER(db, 0)
            goto update_pkt;
        } else {
	    /* The session entries belonging to this entry are checked to find 
	     * if an entry exist whose destination IP and port match with the 
	     * source IP and port of the packet being processed 
	     */
            dest_info.k.vrf = db->in2out_key.k.vrf;

            if (PREDICT_FALSE(db->nsessions == 0)) {
                /* Should be a static entry
                 * Note this session as the first session and log
                 */
                cnat_add_dest_n_log(db, &dest_info);
                CNAT_UDP_OUTSIDE_UPDATE_FLAG_TIMER(db, 0)

            } else if(PREDICT_TRUE(db->nsessions == 1)) {

                /* Destn is not same as in main db. Multiple session
                 * scenario
                 */
                dest_info.k.vrf = db->in2out_key.k.vrf;
                session_db = cnat_handle_1to2_session(db, &dest_info);

                if(PREDICT_FALSE(session_db == NULL)) {
                    disposition = CNAT_V4_UDP_O2I_E;
                    counter = CNAT_V4_UDP_O2I_SESSION_DROP;
                    goto drop_pkt;
                }

                /* update session_db(cur packet) timer */
                CNAT_UDP_OUTSIDE_UPDATE_FLAG_TIMER(session_db, 0)
            } else {
                /* More 2 sessions exists */

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
                    CNAT_UDP_OUTSIDE_UPDATE_FLAG_TIMER(session_db, 0)
                } else {
                    /* could not create session db - drop packet */
                    disposition = CNAT_V4_UDP_O2I_E;
                    counter = CNAT_V4_UDP_O2I_SESSION_DROP;
                    goto drop_pkt;
                }
            }
        }

update_pkt:

        /*
         * 1. update dest ipv4 addr and dest udp port
         * 2. update ipv4 checksum and udp checksum
         */
            //swap_ip_dst(ip, db, db->in2out_key.k.vrf);
            swap_ip_dst_udp_port(ip, udp, db, db->in2out_key.k.vrf);
            //DSLITE_PRINTF(1, "Done with swap_ip_dst_udp_port..\n");

        db->out2in_pkts++;

        nat44_dslite_global_stats[0].out2in_forwarding_count++;

        /* #### Temporarily COMMENTED FOR IP ROUTE LOOKUP ISSUE #### */

        //PLATFORM_CNAT_SET_TX_VRF(vnet_buffer(b0)->sw_if_index[VLIB_TX], 
        //    db->in2out_key.k.vrf)
    } else {
        disposition = CNAT_V4_UDP_O2I_E;
        counter = CNAT_V4_UDP_O2I_MISS_PKT;
       /* for NAT44 dslite_id would be 1 */
       nat44_dslite_common_stats[0].no_translation_entry_drops ++;
    }

drop_pkt:

    em->counters[node_counter_base_index + counter] += 1;
    return disposition;
}

#include <vnet/pipeline.h>

static uword cnat_ipv4_udp_outside_input_node_fn (vlib_main_t * vm,
                              vlib_node_runtime_t * node,
                              vlib_frame_t * frame)
{
    return dispatch_pipeline (vm, node, frame);
}


VLIB_REGISTER_NODE (cnat_ipv4_udp_outside_input_node) = {
  .function = cnat_ipv4_udp_outside_input_node_fn,
  .name = "vcgn-v4-udp-o2i",
  .vector_size = sizeof (u32),
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(cnat_ipv4_udp_outside_input_error_strings),
  .error_strings = cnat_ipv4_udp_outside_input_error_strings,

  .n_next_nodes = CNAT_V4_UDP_O2I_NEXT,

  /* edit / add dispositions here */
#if 0
  .next_nodes = {
	//[CNAT_V4_O2I_FIXME] = "error-drop",
        //[CNAT_V4_UDP_O2I_E] = "vcgn-v4-udp-o2i-e",
        [CNAT_V4_UDP_O2I_E] = "vcgn-v4-udp-o2i-e",
        [CNAT_V4_UDP_O2I_T] = "ip4-input",
  },
#endif
  .next_nodes = {
    [CNAT_V4_UDP_O2I_E] = "error-drop",
    [CNAT_V4_UDP_O2I_T] = "ip4-input",
 },

};

clib_error_t *cnat_ipv4_udp_outside_input_init (vlib_main_t *vm)
{
  cnat_ipv4_udp_outside_input_main_t * mp = &cnat_ipv4_udp_outside_input_main;

  mp->vlib_main = vm;
  mp->vnet_main = vnet_get_main();

  return 0;
}

VLIB_INIT_FUNCTION (cnat_ipv4_udp_outside_input_init);
