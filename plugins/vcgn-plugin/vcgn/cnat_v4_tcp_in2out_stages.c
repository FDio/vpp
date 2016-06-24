/* 
 *---------------------------------------------------------------------------
 * cnat_v4_tcp_in2out_stages.c - cnat_v4_tcp_in2out node pipeline stage functions
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
/* #include <cnat_feature_data.h> */
#include "ipv4_packet.h"
#include "tcp_header_definitions.h"
#include "cnat_config.h"
#include "cnat_global.h"
#include "cnat_v4_functions.h"
#include "cnat_v4_ftp_alg.h"
#include "cnat_v4_pptp_alg.h"

#define foreach_cnat_ipv4_tcp_inside_input_error                \
_(TCP_NAT_IN, "packets received")				\
_(TCP_NAT, "packets NATed")					\
_(TCP_EXCEPTION, "packets to exception")			\
_(TCP_TTL_GEN, "Generated TTL Expiry ICMP packet")		\
_(TCP_TTL_DROP, "Could not generate TTL Expiry ICMP packet")	\
_(TCP_SESSION_DROP, "Could not generate session")		\
_(TCP_FRAG_DROP, "Non-first Fragment received")

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



typedef struct cnat_v4_tcp_in2out_pipeline_data_ {
    spp_node_main_vector_t *nmv;
    /* Add additional pipeline stage data here... */
    u32 bucket;
    u16 src_port; /* Added for handling fragments */
    u16 dst_port; /* Added for handling fragments */
} cnat_v4_tcp_in2out_pipeline_data_t;

static cnat_v4_tcp_in2out_pipeline_data_t pctx_data[SPP_MAXDISPATCH];

#define EXTRA_PIPELINE_ARGS_PROTO , cnat_v4_tcp_in2out_pipeline_data_t *pctx
#define EXTRA_PIPELINE_ARGS , pctx

ALWAYS_INLINE(
static inline void
stage0(spp_ctx_t **ctxs, int index, spp_node_t *np,
       u8 *disp_used EXTRA_PIPELINE_ARGS_PROTO))
{
    spp_ctx_t *ctx = ctxs[index];
    /*
     * Prefetch the context header. This is almost always
     * the right thing to do
     */
    SPP_PREFETCH_CTX(ctx);
}

ALWAYS_INLINE(
static inline void
stage1(spp_ctx_t **ctxs, int index, spp_node_t *np,
       u8 *disp_used EXTRA_PIPELINE_ARGS_PROTO))
{
    spp_ctx_t *ctx = ctxs[index];
    /* got ctx, prefetch packet data separately */
    SPP_PREFETCH_CTX_DATA(ctx, 1*CACHE_DATA_QUANTUM);
}

ALWAYS_INLINE(
static inline void
stage2(spp_ctx_t **ctxs, int index, spp_node_t *np,
       u8 *disp_used EXTRA_PIPELINE_ARGS_PROTO))
{
    spp_ctx_t *ctx = ctxs[index];
    u64 a, b, c;
    u32 bucket;
    cnat_feature_data_t *fd = (cnat_feature_data_t *)ctx->feature_data;
    ipv4_header *ip;
    tcp_hdr_type * tcp;
    u8 *prefetch_target;

    INCREMENT_NODE_COUNTER(np, TCP_NAT_IN);

    /* extract the key from ctx and save it to feature_data */

    ip = (ipv4_header *)(ctx->current_header);
    ctx->application_start = (ip->version_hdr_len_words & 0xf) << 2;
    tcp = (tcp_hdr_type*) ((u8 *)ip + ctx->application_start);

    PLATFORM_CNAT_SET_RX_VRF(ctx,fd->dbl.k.k.vrf, CNAT_TCP, 1);
    fd->dbl.k.k.ipv4 = spp_net_to_host_byte_order_32(&ip->src_addr);

    if(PREDICT_FALSE(ctx->ru.rx.frag)) {
        /* Must have routed through cnat_v4_frag_in2out node
         * Since feature data of the ctx is being used for other
         * purposes here, copy them to extra stage argument
         */
        u16 *feature_data_ports = (u16 *)&ctx->feature_data[2];
        pctx[index].src_port = fd->dbl.k.k.port = *feature_data_ports;
        feature_data_ports++;
        pctx[index].dst_port = *feature_data_ports;
    } else {
        fd->dbl.k.k.port = spp_net_to_host_byte_order_16(&tcp->src_port);
        pctx[index].dst_port =
            spp_net_to_host_byte_order_16(&tcp->dest_port);
    }

#if 0
    /* extra info for evil mode, or default value for dst_ipv4 field in good mode */
    fd->dbl.dst_ipv4 = address_dependent_filtering ? 
                       spp_net_to_host_byte_order_32(&ip->dest_addr) : 0;
#endif

    CNAT_V4_GET_HASH(fd->dbl.k.key64, 
                     bucket, CNAT_MAIN_HASH_MASK)

    prefetch_target = (u8 *)(&cnat_in2out_hash[bucket]);
    pctx[index].bucket = bucket;

    /* Prefetch the hash bucket */
    SPP_PREFETCH(prefetch_target, 0, LOAD);

}

ALWAYS_INLINE(
static inline void
stage3(spp_ctx_t **ctxs, int index, spp_node_t *np,
       u8 *disp_used EXTRA_PIPELINE_ARGS_PROTO))
{
    u32 db_index;
    u32 bucket;
    uword prefetch_target0, prefetch_target1;

    bucket = pctx[index].bucket;

    /* read the hash bucket */
    db_index = pctx[index].bucket = cnat_in2out_hash[bucket].next;
    if (PREDICT_TRUE(db_index != EMPTY)) {

        /*
         * Prefetch database keys. We save space by not cache-line
         * aligning the DB entries. We don't want to waste LSU
         * bandwidth prefetching stuff we won't need.
         */

        prefetch_target0 = (uword)(cnat_main_db + db_index);

        SPP_PREFETCH(prefetch_target0, 0, LOAD);

        /* Just beyond DB key #2 */

        prefetch_target1 = prefetch_target0 +
            STRUCT_OFFSET_OF(cnat_main_db_entry_t, user_ports);

        /* If the targets are in different lines, do the second prefetch */

        if (PREDICT_FALSE((prefetch_target0 & ~(SPP_CACHE_LINE_BYTES-1)) !=
             (prefetch_target1 & ~(SPP_CACHE_LINE_BYTES-1)))) {

            SPP_PREFETCH(prefetch_target1, 0, LOAD);

        }
    }
}

static inline void
stage4(spp_ctx_t **ctxs, int index, spp_node_t *np,
       u8 *disp_used EXTRA_PIPELINE_ARGS_PROTO)
{
    spp_ctx_t *ctx = ctxs[index];
    u32 db_index = pctx[index].bucket;
    cnat_main_db_entry_t *db;
    cnat_feature_data_t *fd;

    /*
     * Note: if the search already failed (empty bucket),
     * the answer is already in the pipeline context structure
     */
    if (PREDICT_FALSE(db_index == EMPTY)) {
        return;
    }

    fd = (cnat_feature_data_t *)ctx->feature_data;

    /*
     * Note: hash collisions suck. We can't easily prefetch around them.
     * The first trip around the track will be fast. After that, maybe
     * not so much...
     */
    do {

        db = cnat_main_db + db_index;
        if (PREDICT_TRUE(db->in2out_key.key64 == fd->dbl.k.key64))
            break;
        db_index = db->in2out_hash.next;

    } while (db_index != EMPTY);

    /* even in evil mode, for in2out, we nat all packets regardless mode and dst_ip */

    /* Stick the answer back into the pipeline context structure */
    pctx[index].bucket = db_index;
}

ALWAYS_INLINE(
static inline void
stage5(spp_ctx_t **ctxs, int index, spp_node_t *np,
       u8 *disp_used EXTRA_PIPELINE_ARGS_PROTO))
{
    spp_ctx_t *ctx = ctxs[index];
    u32 db_index = pctx[index].bucket;
    cnat_feature_data_t *fd = (cnat_feature_data_t *)ctx->feature_data;
    int disposition;
    cnat_main_db_entry_t *db;
    /* Below two pointers are just to keep the cnat_ftp_alg call happy*/
    dslite_table_entry_t *dslite_entry_ptr = NULL;
    ipv6_header_t *ipv6_hdr = NULL;
    tcp_hdr_type *tcp;
    ipv4_header *ip;
    i8 delta;
    u32 seq, seq1;
    u32 window;
    u8 scale;
    int rc;

    ip = (ipv4_header *) ctx->current_header;

    if (PLATFORM_HANDLE_TTL_DECREMENT) {
        if (PREDICT_FALSE(ip->ttl <= 1)) {
            /* Try to generate ICMP error msg, as TTL is <= 1 */

            if (icmpv4_generate_with_throttling
                    (ctx, ip, ctx->ru.rx.uidb_index)) {
                /* Generated ICMP */
                disposition = CNAT_REWRITE_OUTPUT;
                INCREMENT_NODE_COUNTER(np, TCP_TTL_GEN);
            } else {
                /* Could not generated ICMP - drop the packet */
                disposition = CNAT_DROP; 
                INCREMENT_NODE_COUNTER(np, TCP_TTL_DROP);
            }
            goto drop_pkt;
        }
    }

    if (PREDICT_FALSE(db_index == EMPTY)) {
	if(PREDICT_FALSE(ctx->ru.rx.frag)) {
            /* Must have routed through cnat_v4_frag_in2out node */
            u16 frag_offset =
                spp_net_to_host_byte_order_16(&(ip->frag_flags_offset));
    	    if(PREDICT_FALSE(frag_offset & IP_FRAG_OFFSET_MASK)) {
                INCREMENT_NODE_COUNTER(np, TCP_FRAG_DROP);
                disposition = CNAT_DROP;
		goto drop_pkt;
    	    } else {
		INCREMENT_NODE_COUNTER(np, TCP_EXCEPTION);
                disposition = CNAT_V4_TCP_IE;
	    }
        } else {
	    INCREMENT_NODE_COUNTER(np, TCP_EXCEPTION);
	    disposition = CNAT_V4_TCP_IE;
	}
    } else {
        cnat_key_t dest_info;
        cnat_session_entry_t *session_db = NULL;
        db = cnat_main_db + db_index;
        /* Handle destination sessions */
        tcp = (tcp_hdr_type*) ((u8*)ip + ctx->application_start);
        dest_info.k.port = pctx[index].dst_port;
        dest_info.k.ipv4 = spp_net_to_host_byte_order_32(&(ip->dest_addr));

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
                    disposition = CNAT_DROP;
                    INCREMENT_NODE_COUNTER(np, TCP_SESSION_DROP);
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
                    disposition = CNAT_DROP;
                    INCREMENT_NODE_COUNTER(np, TCP_SESSION_DROP);
                    goto drop_pkt;
                }
            }
	    if(PREDICT_TRUE(session_db)) {
		/* Have to repeat the window size check for new destinations */
                window = (u32)spp_net_to_host_byte_order_16(
		                                     &tcp->window_size);
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
                session_db->tcp_seq_num = spp_net_to_host_byte_order_32(
	                                                  &tcp->seq_num);
	        session_db->ack_no      = spp_net_to_host_byte_order_32(
	                                                  &tcp->ack_num);
		if (PREDICT_FALSE(global_debug_flag && CNAT_DEBUG_GLOBAL_ALL)) {
	            PLATFORM_DEBUG_PRINT("\n In2out SDB stages seq no = %u," 
		                         "   ack no = %u, window = %u\n",
	                                 session_db->tcp_seq_num,
			                 session_db->ack_no,
				         session_db->window);
		}    
            }
        } else {
            //Update the seq no and ack no for subsequent communication
	    //after connection establishment
	    //No need to update window here. Window is already updated 
	    //during connection establishment
            window = (u32)spp_net_to_host_byte_order_16(
		                                     &tcp->window_size);
	    window = window << db->scale;
	    if(PREDICT_FALSE(!ALG_ENABLED_DB(db))) {
            //This check is done since proto_data is part of union in main 
	    //db entry
                db->proto_data.tcp_seq_chk.seq_no  = 
		                      spp_net_to_host_byte_order_32(
	                                              &tcp->seq_num);
                db->proto_data.tcp_seq_chk.ack_no  = 
		                      spp_net_to_host_byte_order_32(
	                                             &tcp->ack_num);
	    }			      
            if (PREDICT_FALSE(db->diff_window < window)) { 
		/* Update the db entry with window option from packet */
                db->diff_window = window; 
            }
	    if (PREDICT_FALSE(global_debug_flag && CNAT_DEBUG_GLOBAL_ALL)) {
	        PLATFORM_DEBUG_PRINT("\n In2out MainDB seq no = %u,"
	                             "\n ack no = %u\n",
	                                 db->proto_data.tcp_seq_chk.seq_no,
			         	 db->proto_data.tcp_seq_chk.ack_no);
	        PLATFORM_DEBUG_PRINT("\n In2out MAINDB window = %u\n",
	                                 db->diff_window);
	    }	
        }
update_pkt:

        INCREMENT_NODE_COUNTER(np, TCP_NAT);

        disposition = CNAT_REWRITE_OUTPUT;

        /* NAT the packet and update checksum (increamental) */

        /* If it is a non-first fragment, we need not worry about
         * ALGs as the packet does not have TCP header..
         * However, under a very race scenario when this non-first
         * fragment is containing an FTP PORT command OR RTSP command
         * we cannot handle that case.. in that case the ALG will fail
         * Do not want to add a lot of complexity to handle one in million
         * of such ALG case
         */
        u16 frag_offset =
            spp_net_to_host_byte_order_16(&(ip->frag_flags_offset));

        if(PREDICT_FALSE(frag_offset & IP_FRAG_OFFSET_MASK)) {
            /* Non first fragment.. no TCP header  */
            FTP_ALG_DEBUG_PRINTF("Non first frag.. cannot handle ALG");
            goto handle_ttl_n_checksum;
        }

        FTP_ALG_DEBUG_PRINTF("src port 0x%x, dst_port 0x%x",
                              spp_net_to_host_byte_order_16(&tcp->src_port), 
                              spp_net_to_host_byte_order_16(&tcp->dest_port))
        
        /* handle FTP ALG */
        if (PREDICT_FALSE(ftp_alg_enabled && 
            (spp_net_to_host_byte_order_16(&tcp->src_port) == 21 || 
             spp_net_to_host_byte_order_16(&tcp->dest_port) == 21))) { 

            if(PREDICT_FALSE((db->flags & CNAT_DB_FLAG_PPTP_TUNNEL_ACTIVE) ||
                (db->flags & CNAT_DB_FLAG_PPTP_TUNNEL_INIT)))
            {
                /* FTP on a PPTP Control session? Ignore FTP */
                goto handle_ttl_n_checksum;
            }

             if (PREDICT_FALSE(tcp->flags & (TCP_FLAG_SYN | TCP_FLAG_RST |
                 TCP_FLAG_FIN))) {

                 FTP_ALG_DEBUG_PRINTF("SYN Case setting delta = 0")

                /* reset the delta */
                if(PREDICT_FALSE(session_db != NULL)) {
                    session_db->alg.delta = 0;
                } else {
                    db->alg.delta = 0;
                }

             } else {

                 /* need to adjust seq # for in2out pkt if delta is not 0 */
                 if (PREDICT_TRUE((session_db && (session_db->alg.delta != 0))
                    || ((!session_db) && (db->alg.delta != 0)))) {
                     seq = net2host32(&tcp->seq_num);

                     FTP_ALG_DEBUG_PRINTF("Orig Seq Num 0x%x", seq)
                     /*
                      * for ftp packets, due to PORT command translation,
                      * we may have cases that a packet/payload len gets 
                      * changed for tcp, we need to adjust the packet's 
                      * sequence numbers to match the changes. The delta 
                      * of orig pkt len and new len is in alg_dlt[1] together 
                      * with the sequence number that cuased the delta.  When
                      * there are multiple len changes, we keep theprevious 
                      * delta in alg_dlt[0] for case like pkt retransmission.
                      * So depends on packet seq number, we decide to use 
                      * either latest delta or previous delta ([0])
                      * We won't be here if both delta values are 0
                      */
                     if(PREDICT_FALSE(session_db != NULL)) {
                         seq1 = seq > session_db->tcp_seq_num ?
                             (seq + session_db->alg.alg_dlt[1]):
                             (seq + session_db->alg.alg_dlt[0]);
                     } else {
                         seq1 = seq > db->proto_data.seq_pcp.tcp_seq_num ?
                             (seq + db->alg.alg_dlt[1]):
                             (seq + db->alg.alg_dlt[0]);
                     }

                     FTP_ALG_DEBUG_PRINTF("Old_seq_num 0x%x New Seq Num 0x%x",
                                            seq, seq1)

                     if (PREDICT_TRUE(seq1 != seq)) {

                         tcp->seq_num = host2net32(seq1);

                         FTP_ALG_DEBUG_PRINTF("Old TCP Checksum 0x%x", 
                                               net2host16(&tcp->tcp_checksum))

                         /* 
                          * fix checksum incremental for seq # changes
                          * newchecksum = ~(~oldchecksum + ~old + new)
                          */
                         CNAT_UPDATE_TCP_SEQ_ACK_CHECKSUM(seq, seq1)
                     } /* There is a diff in seq */

                 } /* ALG Delta is non zero */

                 rc = cnat_ftp_alg((u8*) ip, &delta, db, dslite_entry_ptr, ipv6_hdr);

                 FTP_ALG_DEBUG_PRINTF("cnat_ftp_alg rc 0x%x", rc)

                 /*if located PORT cmd, packet being updated, take the delta and seq # */
                 if (PREDICT_FALSE(rc)) {

                     /* set alg flag for this ftp control connection */
                     if(PREDICT_FALSE(session_db != NULL)) {
                         session_db->flags |= CNAT_DB_FLAG_ALG_CTRL_FLOW;
                     } else {
                         db->flags |= CNAT_DB_FLAG_ALG_CTRL_FLOW;
                     }

                     /* 
                      * rc != 0 indicates this packet has triggered a new pkt len delta
                      * we need to update db entry's seq# with seq# of this packet.
                      *
                      * Move alg_dlt[1] to [0], (current delta -> previous delta)
                      * then apply latest delta to alg_dlt[1] (keep [1] as latest delta)
                      */
                     if(PREDICT_FALSE(session_db != NULL)) {
                        session_db->tcp_seq_num = net2host32(&tcp->seq_num);
                        session_db->alg.alg_dlt[0] = session_db->alg.alg_dlt[1];

                        /* accumulate the delta ! */
                        session_db->alg.alg_dlt[1] += delta;
                        FTP_ALG_DEBUG_PRINTF(
                            "cnat_ftp_alg seq_num 0x%x, dlt0 0x%x, dlt1 0x%x",
                            session_db->tcp_seq_num,
                            session_db->alg.alg_dlt[0],
                            session_db->alg.alg_dlt[1])

                     } else {
                        db->proto_data.seq_pcp.tcp_seq_num = net2host32(&tcp->seq_num);
                        db->alg.alg_dlt[0] = db->alg.alg_dlt[1];

                        /* accumulate the delta ! */
                        db->alg.alg_dlt[1] += delta; 

                        FTP_ALG_DEBUG_PRINTF(
                          "cnat_ftp_alg seq_num 0x%x, dlt0 0x%x, dlt1 0x%x",
                          db->proto_data.seq_pcp.tcp_seq_num, 
                          db->alg.alg_dlt[0], 
                          db->alg.alg_dlt[1])
                      }
                      ctx->current_length += delta;
                 }/* cnat_ftp_alg returned non zero */
             } /* It is not a SYN, RST or FIN */
        } else if (PREDICT_FALSE(rtsp_alg_port_num &&
         ((spp_net_to_host_byte_order_16(&tcp->dest_port) == rtsp_alg_port_num) ||
          (spp_net_to_host_byte_order_16(&tcp->src_port) == rtsp_alg_port_num))) ) { 

             if (PREDICT_FALSE(tcp->flags & (TCP_FLAG_SYN | TCP_FLAG_RST |
                 TCP_FLAG_FIN))) {

                 FTP_ALG_DEBUG_PRINTF("SYN Case setting delta = 0")

                 /* reset the delta */
                if(PREDICT_FALSE(session_db != NULL)) {
                    session_db->alg.delta = 0;
                } else {
                    db->alg.delta = 0;
                }

             } else {
#define RTSP_ALG_DELTA_MASK 0xFF
                 /* need to adjust seq # for in2out pkt if delta is not 0 */
                 if (PREDICT_FALSE((session_db &&
                    	(session_db->alg.delta & RTSP_ALG_DELTA_MASK) != 0) ||
                    	((!session_db) &&
                    	(db->alg.delta & RTSP_ALG_DELTA_MASK) != 0))) {
                     seq = net2host32(&tcp->seq_num);

                    if(PREDICT_FALSE(session_db != NULL)) {
                        seq1 = seq > session_db->tcp_seq_num ?
                           (seq + db->alg.alg_dlt[1]):
                            (seq + db->alg.alg_dlt[0]);
                    } else {
                        seq1 = seq > db->proto_data.seq_pcp.tcp_seq_num ?
                            (seq + db->alg.alg_dlt[1]):
                            (seq + db->alg.alg_dlt[0]);
                    }

                     FTP_ALG_DEBUG_PRINTF("Old_seq_num 0x%x New Seq Num 0x%x",
                                            seq, seq1)

                     if (PREDICT_TRUE(seq1 != seq)) {

                         tcp->seq_num = host2net32(seq1);

                         FTP_ALG_DEBUG_PRINTF("Old TCP Checksum 0x%x",
                                               net2host16(&tcp->tcp_checksum))

                         /*
                          * fix checksum incremental for seq # changes
                          * newchecksum = ~(~oldchecksum + ~old + new)
                          */
                         CNAT_UPDATE_TCP_SEQ_ACK_CHECKSUM(seq, seq1)
                     }

                 }
            }
            if ((session_db && (!session_db->alg.il)) ||
                ((!session_db) && (!db->alg.il))) {
                cnat_rtsp_alg((u8*) ip,
                               &delta, 
                               db, 
                               ctx->current_length,
                               NULL,
                               NULL);
            }
        }
handle_ttl_n_checksum:
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
                                      db);
/* CNAT_PPTP_ALG_SUPPORT  */
        /* code to handle pptp control msgs */
        if(PREDICT_FALSE(
               (spp_net_to_host_byte_order_16(&tcp->dest_port) ==
               TCP_PPTP_PORT))) {

             u32 ret; 

             PPTP_DBG(3, "PPTP mgmt/ctrl msg recieved");

              ret = cnat_handle_pptp_msg(ctx, db , tcp, PPTP_PNS );

              if( PREDICT_FALSE( ret != CNAT_SUCCESS) ) {
                   PPTP_DBG(3, "PPTP mgmt/ctrl msg drop");
                   disposition = CNAT_DROP;
                   PPTP_INCR(ctrl_msg_drops); 
                   goto drop_pkt;
              }
         }

/* CNAT_PPTP_ALG_SUPPORT */

        /* update transaltion counters */
        db->in2out_pkts++;

        in2out_forwarding_count++;

        PLATFORM_CNAT_SET_TX_VRF(ctx,db->out2in_key.k.vrf);

        /* update the timer for good mode, or evil mode dst_ip match */

//        if (!address_dependent_filtering || fd->dbl.dst_ipv4 == db->dst_ipv4) {
        if(PREDICT_FALSE(session_db != NULL)) {
            V4_TCP_UPDATE_SESSION_DB_FLAG(session_db, tcp);
            CNAT_DB_TIMEOUT_RST(session_db);
        } else {
            V4_TCP_UPDATE_SESSION_FLAG(db, tcp);
            CNAT_DB_TIMEOUT_RST(db);
        }

//      }

    }

    /* Pick up the answer and put it into the context */
    fd->dbl.db_index = db_index;

drop_pkt:

    DISP_PUSH_CTX(np, ctx, disposition, disp_used, last_disposition, last_contexts_ptr, last_nused_ptr);

}

