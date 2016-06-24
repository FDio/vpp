/*
 *---------------------------------------------------------------------------
 * cnat_ipv4_udp_inside_input_exception_stages.c - cnat_ipv4_udp_inside_input_exception node pipeline stage functions
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

/*
 * Dump these counters via the "show error" CLI command
 */

#define foreach_cnat_ipv4_udp_inside_input_exc_error                  	\
_(CNAT_V4_UDP_I2O_T_PKT, "v4 udp i2o transmit")                         \
_(CNAT_V4_UDP_I2O_D_PKT, "v4 udp i2o drop")                             \
_(CNAT_V4_ICMP_G_I2O_T_PKT, "v4 udp i2o icmp msg gen")                  \
_(CNAT_V4_UDP_I2O_DC_PKT, "v4 udp i2o (no config) drop")                \
_(CNAT_V4_UDP_I2O_DR_PKT, "v4 udp i2o (not in run state) drop")         \
_(CNAT_V4_UDP_I2O_DD_PKT, "v4 udp i2o (no direct port) drop")           \
_(CNAT_V4_UDP_I2O_DA_PKT, "v4 udp i2o (no any port) drop")              \
_(CNAT_V4_UDP_I2O_DO_PKT, "v4 udp i2o (out of port limit) drop")        \
_(CNAT_V4_UDP_I2O_DI_PKT, "v4 udp i2o (invalid packet) drop")           \
_(CNAT_V4_UDP_I2O_DS_PKT, "v4 udp i2o (no sessoon db) drop")

typedef enum {
#define _(sym,str) sym,
  foreach_cnat_ipv4_udp_inside_input_exc_error
#undef _
  CNAT_IPV4_UDP_INSIDE_INPUT_EXCEPTIONS_N_ERROR,
} cnat_ipv4_udp_inside_input_exc_error_t;


static char * cnat_ipv4_udp_inside_input_exc_error_strings[] = {
#define _(sym,string) string,
  foreach_cnat_ipv4_udp_inside_input_exc_error
#undef _
};

typedef struct {
  u32 cached_next_index;
  /* $$$$ add data here */

  /* convenience variables */
  vlib_main_t * vlib_main;
  vnet_main_t * vnet_main;
} cnat_ipv4_udp_inside_input_exc_main_t;

typedef enum {
    CNAT_V4_UDP_I2O_T,
    CNAT_V4_UDP_I2O_D,
    CNAT_V4_ICMP_G_I2O_T = CNAT_V4_UDP_I2O_D, /* TOBE_PORTED */
    CNAT_V4_UDP_INSIDE_INPUT_EXC_N_NEXT,
} cnat_ipv4_udp_inside_input_exc_next_t;

cnat_ipv4_udp_inside_input_exc_main_t cnat_ipv4_udp_inside_input_exc_main;
vlib_node_registration_t cnat_ipv4_udp_inside_input_exc_node;

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
        vlib_get_node (vm, cnat_ipv4_udp_inside_input_exc_node.index);
    u32 node_counter_base_index = n->error_heap_index;
    vlib_error_main_t * em = &vm->error_main;

    cnat_gen_icmp_info info;
    cnat_db_key_bucket_t ki;
    spp_ctx_t *ctx __attribute__((unused))
        = (spp_ctx_t *) &vnet_buffer(b0)->vcgn_uii;
    cnat_main_db_entry_t *db = NULL;
    ipv4_header *ip = (ipv4_header *)vlib_buffer_get_current(b0);
    u8   ipv4_hdr_len = (ip->version_hdr_len_words & 0xf) << 2;
    udp_hdr_type_t *udp = (udp_hdr_type_t *)((u8*)ip + ipv4_hdr_len);
    int disposition = CNAT_V4_UDP_I2O_T;
    int counter = CNAT_V4_UDP_I2O_T_PKT;

    cnat_key_t dest_info;

    PLATFORM_CNAT_SET_RX_VRF(vnet_buffer(b0)->sw_if_index[VLIB_RX],
                             vnet_buffer(b0)->vcgn_uii.key.k.vrf,
                             CNAT_UDP)

    vnet_buffer(b0)->vcgn_uii.key.k.ipv4 = clib_net_to_host_u32(ip->src_addr);

    PLATFORM_CNAT_SET_RX_VRF(vnet_buffer(b0)->sw_if_index[VLIB_RX],
                             ki.k.k.vrf, CNAT_UDP)

    ki.k.k.ipv4 = clib_net_to_host_u32(ip->src_addr);

    
    /* MUST REVISIT: commentting frag check. Unconditional destination port 
     * update. DONOT remove this #if 0 */
    ki.k.k.port =
        clib_net_to_host_u16(udp->src_port);
    dest_info.k.port =
        clib_net_to_host_u16(udp->dest_port);
#if 0
    if(PREDICT_FALSE(ctx->ru.rx.frag)) {
#ifdef TOBE_PORTED
        /* Must have routed through cnat_v4_frag_in2out node */
        u16 *feature_data_ports = (u16 *)&ctx->feature_data[2];
        ki.k.k.port = *feature_data_ports;
        feature_data_ports++;
        dest_info.k.port = *feature_data_ports;
#endif
    } else {
        ki.k.k.port =
            clib_net_to_host_u16(udp->src_port);
        dest_info.k.port =
            clib_net_to_host_u16(udp->dest_port);
    }
#endif /* if 0 */

    dest_info.k.ipv4 = clib_net_to_host_u32(ip->dest_addr);
    PLATFORM_CNAT_SET_RX_VRF(vnet_buffer(b0)->sw_if_index[VLIB_RX],
                             dest_info.k.vrf, CNAT_UDP)

    if (PREDICT_TRUE(ki.k.k.port)) {
        if (ki.k.k.port & 0x1) {
            db = cnat_get_main_db_entry_v2(&ki, PORT_S_ODD, PORT_TYPE_DYNAMIC,
                                           &info, &dest_info);
        } else {
            db = cnat_get_main_db_entry_v2(&ki, PORT_S_EVEN, PORT_TYPE_DYNAMIC,
                                           &info, &dest_info);
        }
    } else {
        /*
     * No UDP port value of 0 - drop it
     */
        db = NULL;
        info.error = CNAT_ERR_BAD_TCP_UDP_PORT;
    }

    if (PREDICT_TRUE((u64)db)) {

        if (PLATFORM_HANDLE_TTL_DECREMENT) {
            /*
             * Decrement TTL and update IPv4 checksum
             */
            ipv4_decr_ttl_n_calc_csum(ip);
        }

        /*
         * step 6 do nat before fwd pkt
         */
        swap_ip_src_udp_port(ip, udp, db);
        /*
         * update db for this pkt
         */
        CNAT_DB_UPDATE_IN2OUT_TIMER

        /* Check timeout db if there is config for this */
        (void) query_and_update_db_timeout((void *)db, MAIN_DB_TYPE);

/* Temporarily keeping it commented */
        //PLATFORM_CNAT_SET_TX_VRF(vnet_buffer(b0)->sw_if_index[VLIB_TX],
        //                         db->out2in_key.k.vrf)
        in2out_forwarding_count++;

    } else {
        switch (info.error) {
        case (CNAT_NO_VRF_RUN):
            em->counters[node_counter_base_index + CNAT_V4_UDP_I2O_DR_PKT] += 1;
            break;
        case (CNAT_OUT_LIMIT):
            em->counters[node_counter_base_index + CNAT_V4_UDP_I2O_DO_PKT] += 1;
            break;
        case (CNAT_NO_PORT_ANY):
        case (CNAT_NO_POOL_ANY):
        case (CNAT_BAD_INUSE_ANY):
        case (CNAT_NOT_FOUND_ANY):
            em->counters[node_counter_base_index + CNAT_V4_UDP_I2O_DA_PKT] += 1;
            break;
        case (CNAT_INV_PORT_DIRECT):
        case (CNAT_DEL_PORT_DIRECT):
        case (CNAT_BAD_INUSE_DIRECT):
        case (CNAT_NOT_FOUND_DIRECT):
            em->counters[node_counter_base_index + CNAT_V4_UDP_I2O_DD_PKT] += 1;
            break;
        case (CNAT_ERR_BAD_TCP_UDP_PORT):
            em->counters[node_counter_base_index + CNAT_V4_UDP_I2O_DI_PKT] += 1;
            break;
        case (CNAT_ERR_NO_SESSION_DB):
            em->counters[node_counter_base_index + CNAT_V4_UDP_I2O_DS_PKT] += 1;
            break;
        default:
            em->counters[node_counter_base_index + CNAT_V4_UDP_I2O_DC_PKT] += 1;
            break;
        }
        /*
         * send to icmp msg generate node
         */
        if (info.gen_icmp_msg == CNAT_ICMP_MSG) {
#ifdef TOBE_PORTED
            u32 *fd = (u32*)ctx->feature_data;
            fd[0] = info.svi_addr;
            fd[1] = CNAT_ICMP_DEST_UNREACHABLE;
#endif
            disposition = CNAT_V4_ICMP_G_I2O_T;
            counter = CNAT_V4_ICMP_G_I2O_T_PKT;
        } else {
            disposition = CNAT_V4_UDP_I2O_D;
            counter = CNAT_V4_UDP_I2O_D_PKT;
        }
        DEBUG_I2O_DROP(CNAT_DEBUG_DROP_UDP)
    }

    em->counters[node_counter_base_index + counter] += 1;
    
    return disposition;
}


#include <vnet/pipeline.h>

static uword cnat_ipv4_udp_inside_input_exc_node_fn (vlib_main_t * vm,
                              vlib_node_runtime_t * node,
                              vlib_frame_t * frame)
{
    return dispatch_pipeline (vm, node, frame);
}

VLIB_REGISTER_NODE (cnat_ipv4_udp_inside_input_exc_node) = {
  .function = cnat_ipv4_udp_inside_input_exc_node_fn,
  .name = "vcgn-v4-udp-i2o-e",
  .vector_size = sizeof (u32),
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(cnat_ipv4_udp_inside_input_exc_error_strings),
  .error_strings = cnat_ipv4_udp_inside_input_exc_error_strings,

  .n_next_nodes = CNAT_V4_UDP_INSIDE_INPUT_EXC_N_NEXT,

  /* edit / add dispositions here */
  .next_nodes = {
        [CNAT_V4_UDP_I2O_T] = "ip4-input",
        [CNAT_V4_UDP_I2O_D] = "error-drop",
  },
};


clib_error_t *cnat_ipv4_udp_inside_input_exc_init (vlib_main_t *vm)
{
  cnat_ipv4_udp_inside_input_exc_main_t * mp = &cnat_ipv4_udp_inside_input_exc_main;

  mp->vlib_main = vm;
  mp->vnet_main = vnet_get_main();

  return 0;
}

VLIB_INIT_FUNCTION (cnat_ipv4_udp_inside_input_exc_init);

