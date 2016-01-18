/* 
 *---------------------------------------------------------------------------
 * cnat_ipv4_icmp_error_outside_input.c - cnat_ipv4_icmp_error_outside_input node pipeline stage functions
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

#define foreach_cnat_ipv4_icmp_e_outside_input_error 		\
_(CNAT_V4_ICMP_E_O2I_T_PKT, "cnat v4 icmp_e o2i packet transmit")			\
_(CNAT_V4_ICMP_E_O2I_D_PKT, "cnat v4 icmp_e o2i packet drop")			\
_(CNAT_V4_ICMP_E_O2I_TTL_DROP, "cnat v4 icmp_e o2i ttl drop")

typedef enum {
#define _(sym,str) sym,
  foreach_cnat_ipv4_icmp_e_outside_input_error 
#undef _
  CNAT_IPV4_ICMP_E_OUTSIDE_INPUT_N_ERROR,
} cnat_ipv4_icmp_e_outside_input_t;

static char * cnat_ipv4_icmp_e_outside_input_error_strings[] = {
#define _(sym,string) string,
  foreach_cnat_ipv4_icmp_e_outside_input_error
#undef _
};

typedef struct {
  u32 cached_next_index;
  /* $$$$ add data here */

  /* convenience variables */
  vlib_main_t * vlib_main;
  vnet_main_t * vnet_main;
} cnat_ipv4_icmp_e_outside_input_main_t;

typedef enum {
    CNAT_V4_ICMP_E_O2I_T,
    CNAT_V4_ICMP_E_O2I_D,
    CNAT_V4_ICMP_E_O2I_NEXT,
} cnat_ipv4_icmp_e_outside_input_next_t;

cnat_ipv4_icmp_e_outside_input_main_t cnat_ipv4_icmp_e_outside_input_main;
vlib_node_registration_t cnat_ipv4_icmp_e_outside_input_node;

#define NSTAGES 5

void swap_ip_dst_emip_src(ipv4_header *ip,
                                 icmp_em_ip_info *icmp_info,
                                 cnat_main_db_entry_t *db, u16 vrf)
{
    icmp_v4_t   *icmp;
    ipv4_header *em_ip;
    u16 *em_port;
    u32 old_ip;
    u16 old_port;
    u16 old_ip_checksum;

    /*
     * declear variable
     */
    CNAT_UPDATE_L3_CHECKSUM_DECLARE
    CNAT_UPDATE_ICMP_ERR_CHECKSUM_DECLARE

    /*
     * fix inner layer ip & l4 checksum
     */
    em_ip = icmp_info->em_ip;
    em_port = icmp_info->em_port;

    CNAT_UPDATE_L3_CHECKSUM(((u16)(db->out2in_key.k.ipv4)),
                               ((u16)(db->out2in_key.k.ipv4 >> 16)),
                               (clib_net_to_host_u16(em_ip->checksum)),
                               ((u16)(db->in2out_key.k.ipv4)),
                               ((u16)(db->in2out_key.k.ipv4 >> 16)))

    old_ip          = clib_net_to_host_u32(em_ip->src_addr);
    old_port        = clib_net_to_host_u16(*em_port);
    old_ip_checksum = clib_net_to_host_u16(em_ip->checksum);

    em_ip->src_addr =
        clib_host_to_net_u32(db->in2out_key.k.ipv4);
    em_ip->checksum =
        clib_host_to_net_u16(new_l3_c);
    *em_port =
        clib_host_to_net_u16(db->in2out_key.k.port);

    /*
     * fix outter layer ip & icmp checksum
     */
    icmp = icmp_info->icmp;
    CNAT_UPDATE_ICMP_ERR_CHECKSUM(((u16)(old_ip & 0xFFFF)),
                                 ((u16)(old_ip >> 16)),
                                 (old_port),
                                 (old_ip_checksum),
                                 (clib_net_to_host_u16(icmp->checksum)),
                                 ((u16)(db->in2out_key.k.ipv4 & 0xffff)),
                                 ((u16)(db->in2out_key.k.ipv4 >> 16)),
                                 ((u16)(db->in2out_key.k.port)), 
                                 ((u16)(new_l3_c)))

    icmp->checksum =
        clib_host_to_net_u16(new_icmp_c); 

    old_ip = clib_net_to_host_u32(ip->dest_addr);

    ip->dest_addr = 
        clib_host_to_net_u32(db->in2out_key.k.ipv4);

    CNAT_UPDATE_L3_CHECKSUM(((u16)(old_ip & 0xFFFF)),
                            ((u16)(old_ip >> 16)),
                            (clib_net_to_host_u16(ip->checksum)),
                            ((u16)(db->in2out_key.k.ipv4)),
                            ((u16)(db->in2out_key.k.ipv4 >> 16)))
    ip->checksum = 
        clib_host_to_net_u16(new_l3_c);

#if 0
    if(is_static_dest_nat_enabled(vrf) == CNAT_SUCCESS) {
	/*
	 * fix inner layer ip & l4 checksum
	 */
	em_snat_ip = icmp_info->em_ip;
	em_snat_port = icmp_info->em_port;

	old_ip          = spp_net_to_host_byte_order_32(&(em_snat_ip->dest_addr));
	old_port        = spp_net_to_host_byte_order_16(em_snat_port);
	old_ip_checksum = spp_net_to_host_byte_order_16(&(em_snat_ip->checksum));
	direction = 1;
	if(cnat_static_dest_db_get_translation(em_snat_ip->dest_addr, &postmap_ip, vrf, direction) ==  CNAT_SUCCESS) {
	    old_postmap_ip = spp_net_to_host_byte_order_32(&postmap_ip);

	    CNAT_UPDATE_L3_CHECKSUM(((u16)(old_ip)),
                               ((u16)(old_ip >> 16)),
                               (spp_net_to_host_byte_order_16(&(em_snat_ip->checksum))),
                               ((u16)(old_postmap_ip)),
                               ((u16)(old_postmap_ip >> 16)))
	    em_snat_ip->dest_addr = postmap_ip;
	    em_snat_ip->checksum =
		spp_host_to_net_byte_order_16(new_l3_c);

	    /*
	     * fix outter layer ip & icmp checksum
	     */
	    icmp = icmp_info->icmp;
	    CNAT_UPDATE_ICMP_ERR_CHECKSUM(((u16)(old_ip & 0xFFFF)),
                                 ((u16)(old_ip >> 16)),
                                 (old_port),
                                 (old_ip_checksum),
				 (spp_net_to_host_byte_order_16(&(icmp->checksum))),
                                 ((u16)(old_postmap_ip & 0xffff)),
                                 ((u16)(old_postmap_ip >> 16)),
                                 ((u16)(old_port)), 
                                 ((u16)(new_l3_c)))

	    icmp->checksum =
		spp_host_to_net_byte_order_16(new_icmp_c); 

	}
    }

    if(is_static_dest_nat_enabled(vrf) == CNAT_SUCCESS) {
	direction = 1;
	if(cnat_static_dest_db_get_translation(ip->src_addr, &postmap_ip, vrf, direction) ==  CNAT_SUCCESS) {
	    CNAT_UPDATE_L3_CHECKSUM_DECLARE 
		
	    old_ip = spp_net_to_host_byte_order_32(&(ip->src_addr));
	    old_postmap_ip = spp_net_to_host_byte_order_32(&postmap_ip);

	    CNAT_UPDATE_L3_CHECKSUM(((u16)(old_ip & 0xFFFF)),
				    ((u16)(old_ip >> 16)),
				    (spp_net_to_host_byte_order_16(&(ip->checksum))),
				    ((u16)(old_postmap_ip & 0xFFFF)),
				    ((u16)(old_postmap_ip >> 16)))	    
	    ip->checksum =
		spp_host_to_net_byte_order_16(new_l3_c);
	    ip->src_addr = postmap_ip;
	}
    }
#endif /* if 0 */
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
    ipv4_header *em_ip = (ipv4_header*)((u8*)icmp + 8); /* embedded pkt's v4 hdr */
    u8 em_ip_hdr_len = (em_ip->version_hdr_len_words & 0xf) << 2;
  
    u64 tmp = 0;
    u32 protocol = CNAT_ICMP;

    /* Check L4 header for embedded packet */
    if (em_ip->protocol == TCP_PROT) {
        tcp_hdr_type *tcp = (tcp_hdr_type*)((u8 *)em_ip + em_ip_hdr_len);
        vnet_buffer(b0)->vcgn_uii.key.k.port = 
            clib_net_to_host_u16(tcp->src_port);
        protocol = CNAT_TCP;

    } else if (em_ip->protocol == UDP_PROT) {
        udp_hdr_type_t *udp = (udp_hdr_type_t *)((u8 *)em_ip + em_ip_hdr_len);
        vnet_buffer(b0)->vcgn_uii.key.k.port = 
            clib_net_to_host_u16(udp->src_port);
        protocol = CNAT_UDP;

    } else {
        icmp_v4_t *icmp = (icmp_v4_t*)((u8 *)em_ip + em_ip_hdr_len);
        vnet_buffer(b0)->vcgn_uii.key.k.port = 
            clib_net_to_host_u16(icmp->identifier);

        if (PREDICT_FALSE((icmp->type != ICMPV4_ECHOREPLY) &&
			   (icmp->type != ICMPV4_ECHO))) {
	    /*
	     * Try to set invalid protocol for these cases, so that
	     * hash lookup does not return valid main_db.  This approach
	     * may optimize the regular cases with valid protocols
	     * as it avoids one more check for regular cases in stage3
	     */
            protocol = CNAT_INVALID_PROTO;
        } 
    }

    tmp = vnet_buffer(b0)->vcgn_uii.key.k.ipv4 =
            clib_net_to_host_u32(em_ip->src_addr);

    tmp |= ((u64)vnet_buffer(b0)->vcgn_uii.key.k.port) << 32;

    PLATFORM_CNAT_SET_RX_VRF(vnet_buffer(b0)->sw_if_index[VLIB_RX],
                             vnet_buffer(b0)->vcgn_uii.key.k.vrf,
                             protocol)
    tmp |= ((u64)vnet_buffer(b0)->vcgn_uii.key.k.vrf) << 48;

    CNAT_V4_GET_HASH(tmp, bucket, CNAT_MAIN_HASH_MASK)

    prefetch_target = (u8 *)(&cnat_out2in_hash[bucket]);
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
                 = cnat_out2in_hash[bucket].next;

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
    int disposition = CNAT_V4_ICMP_E_O2I_T;
    int counter = CNAT_V4_ICMP_E_O2I_T_PKT;

    ipv4_header *ip = (ipv4_header *)vlib_buffer_get_current(b0);
    u8   ipv4_hdr_len = (ip->version_hdr_len_words & 0xf) << 2;
    icmp_v4_t *icmp = (icmp_v4_t *)((u8*)ip + ipv4_hdr_len);
    ipv4_header *em_ip = (ipv4_header*)((u8*)icmp + 8); /* embedded pkt's v4 hdr */
    u8 em_ip_hdr_len = (em_ip->version_hdr_len_words & 0xf) << 2;
    vlib_node_t *n = vlib_get_node (vm, cnat_ipv4_icmp_e_outside_input_node.index);
    u32 node_counter_base_index = n->error_heap_index;
    vlib_error_main_t * em = &vm->error_main;
    cnat_main_db_entry_t *db = NULL;
    icmp_em_ip_info icmp_info;


    if (PREDICT_TRUE(db_index != EMPTY)) {

         icmp_info.em_ip = em_ip;
         icmp_info.icmp = icmp;

         /* Note: This could have been done in stage1 itself, 
          * but we need to introduce one u16 * in vnet_buffer_opaque_t 
          * Since this flow is expected to be very rare in actual 
          * deployment scenario, we may afford to do these steps here 
          * as well. Lets confirm during core review. */

         if (em_ip->protocol == TCP_PROT) {
             tcp_hdr_type *tcp = (tcp_hdr_type*)((u8 *)em_ip + em_ip_hdr_len);
             icmp_info.em_port = &(tcp->src_port); 
         } else if (em_ip->protocol == UDP_PROT) {
             udp_hdr_type_t *udp = (udp_hdr_type_t *)
                 ((u8 *)em_ip + em_ip_hdr_len);
             icmp_info.em_port = &(udp->src_port); 
         } else {
             icmp_v4_t *icmp_inner = (icmp_v4_t*)((u8 *)em_ip + em_ip_hdr_len);
             icmp_info.em_port = &(icmp_inner->identifier);
         }

         db = cnat_main_db + db_index;

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

        swap_ip_dst_emip_src(ip, &icmp_info,
                             db, db->in2out_key.k.vrf);

        if (PREDICT_FALSE(icmp_debug_flag)) {
            printf("\nDUMPING ICMP PKT AFTER\n");
            print_icmp_pkt(ip);
        }

    } else {
        disposition = CNAT_V4_ICMP_E_O2I_D;
        counter = CNAT_V4_ICMP_E_O2I_D_PKT;
    }

    em->counters[node_counter_base_index + counter] += 1;
    return  disposition;
}

#include <vnet/pipeline.h>

static uword cnat_ipv4_icmp_e_outside_input_node_fn (vlib_main_t * vm,
                              vlib_node_runtime_t * node,
                              vlib_frame_t * frame)
{
    return dispatch_pipeline (vm, node, frame);
}


VLIB_REGISTER_NODE (cnat_ipv4_icmp_e_outside_input_node) = {
  .function = cnat_ipv4_icmp_e_outside_input_node_fn,
  .name = "vcgn-v4-icmp-e-o2i",
  .vector_size = sizeof (u32),
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(cnat_ipv4_icmp_e_outside_input_error_strings),
  .error_strings = cnat_ipv4_icmp_e_outside_input_error_strings,

  .n_next_nodes = CNAT_V4_ICMP_E_O2I_NEXT,

  /* edit / add dispositions here */
  .next_nodes = {
      [CNAT_V4_ICMP_E_O2I_T] = "ip4-input",
      [CNAT_V4_ICMP_E_O2I_D] = "error-drop",
  },
};

clib_error_t *cnat_ipv4_icmp_e_outside_input_init (vlib_main_t *vm)
{
  cnat_ipv4_icmp_e_outside_input_main_t * mp = &cnat_ipv4_icmp_e_outside_input_main;

  mp->vlib_main = vm;
  mp->vnet_main = vnet_get_main();

  return 0;
}

VLIB_INIT_FUNCTION (cnat_ipv4_icmp_e_outside_input_init);
