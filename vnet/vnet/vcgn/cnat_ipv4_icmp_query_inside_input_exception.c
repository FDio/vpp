/* 
 *---------------------------------------------------------------------------
 * cnat_ipv4_icmp_query_inside_input_exception.c - cnat_ipv4_icmp_query_inside_input_exception node pipeline stage functions
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

#define foreach_cnat_ipv4_icmp_q_inside_input_exc_error                  	\
_(CNAT_V4_ICMP_Q_I2O_E_T_PKT, "v4 icmp query i2o-e transmit")                         \
_(CNAT_V4_ICMP_Q_I2O_E_G_PKT, "v4 icmp query i2o-e gen icmp msg")                             \
_(CNAT_V4_ICMP_Q_I2O_E_D_PKT, "v4 icmp query i2o-e pkt drop")                  \
_(CNAT_V4_ICMP_Q_I2O_E_DC_PKT, "v4 icmp query i2o-e drop (no config)")                \
_(CNAT_V4_ICMP_Q_I2O_E_DR_PKT, "v4 icmp query i2o-e drop (not in run state)")         \
_(CNAT_V4_ICMP_Q_I2O_E_DD_PKT, "v4 icmp query i2o-e drop (no direct port)")         \
_(CNAT_V4_ICMP_Q_I2O_E_DA_PKT, "v4 icmp query i2o-e drop (no any port)")         \
_(CNAT_V4_ICMP_Q_I2O_E_DO_PKT, "v4 icmp query i2o-e drop (out of port limit)")         \
_(CNAT_V4_ICMP_Q_I2O_E_DS_PKT, "v4 icmp query i2o_e drop (out of session db)")

typedef enum {
#define _(sym,str) sym,
  foreach_cnat_ipv4_icmp_q_inside_input_exc_error
#undef _
  CNAT_IPV4_ICMP_Q_INSIDE_INPUT_EXCEPTIONS_N_ERROR,
} cnat_ipv4_icmp_q_inside_input_exc_error_t;


static char * cnat_ipv4_icmp_q_inside_input_exc_error_strings[] = {
#define _(sym,string) string,
  foreach_cnat_ipv4_icmp_q_inside_input_exc_error
#undef _
};

typedef struct {
  u32 cached_next_index;
  /* $$$$ add data here */

  /* convenience variables */
  vlib_main_t * vlib_main;
  vnet_main_t * vnet_main;
} cnat_ipv4_icmp_q_inside_input_exc_main_t;

typedef enum {
    CNAT_V4_ICMP_Q_E_I2O_T,
    //CNAT_V4_ICMP_Q_E_I2O_GEN,
    CNAT_V4_ICMP_Q_E_I2O_D, 
    CNAT_V4_ICMP_Q_E_I2O_NEXT,
} cnat_ipv4_icmp_q_inside_input_exc_next_t;

#define CNAT_V4_ICMP_Q_E_I2O_GEN CNAT_V4_ICMP_Q_E_I2O_T

cnat_ipv4_icmp_q_inside_input_exc_main_t cnat_ipv4_icmp_q_inside_input_exc_main;
vlib_node_registration_t cnat_ipv4_icmp_q_inside_input_exc_node;

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
    int disposition = CNAT_V4_ICMP_Q_E_I2O_T;
    int counter = CNAT_V4_ICMP_Q_I2O_E_T_PKT;

    ipv4_header *ip = (ipv4_header *)vlib_buffer_get_current(b0);
    u8 ipv4_hdr_len = (ip->version_hdr_len_words & 0xf) << 2;
    icmp_v4_t *icmp = (icmp_v4_t *)((u8*)ip + ipv4_hdr_len);
    vlib_node_t *n = vlib_get_node (vm, cnat_ipv4_icmp_q_inside_input_exc_node.index);
    u32 node_counter_base_index = n->error_heap_index;
    vlib_error_main_t * em = &vm->error_main;

    cnat_key_t dest_info;
    cnat_gen_icmp_info info;
    cnat_db_key_bucket_t ki;
    cnat_main_db_entry_t *db = NULL;

    PLATFORM_CNAT_SET_RX_VRF(vnet_buffer(b0)->sw_if_index[VLIB_RX],
                        ki.k.k.vrf, CNAT_ICMP)

    ki.k.k.ipv4  =
         clib_net_to_host_u32(ip->src_addr);
    ki.k.k.port = 
         clib_net_to_host_u16(icmp->identifier);

    dest_info.k.port = 0;
    dest_info.k.ipv4 = clib_net_to_host_u32(ip->dest_addr);
    PLATFORM_CNAT_SET_RX_VRF(vnet_buffer(b0)->sw_if_index[VLIB_RX],
                            dest_info.k.vrf, CNAT_ICMP)

    db = cnat_get_main_db_entry_v2(&ki, PORT_SINGLE, PORT_TYPE_DYNAMIC,
                                &info, &dest_info);
    if (PREDICT_TRUE(db != 0)) {

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
         * step 6 do nat before fwd pkt
         */
        swap_ip_src_icmp_id(ip, icmp, db, db->in2out_key.k.vrf);

        if (PREDICT_FALSE(icmp_debug_flag)) {
            printf("\nDUMPING ICMP PKT AFTER\n");
            print_icmp_pkt(ip);
        }

        /*
         * update db for this pkt
         */
        CNAT_DB_UPDATE_IN2OUT_TIMER 
        in2out_forwarding_count++;

    } else {
        switch (info.error) {
        case (CNAT_NO_VRF_RUN):
            counter = CNAT_V4_ICMP_Q_I2O_E_DR_PKT;
            break;
        case (CNAT_OUT_LIMIT):
            counter = CNAT_V4_ICMP_Q_I2O_E_DO_PKT;
            break;
        case (CNAT_NO_PORT_ANY):
        case (CNAT_NO_POOL_ANY):
        case (CNAT_BAD_INUSE_ANY):
        case (CNAT_NOT_FOUND_ANY):
            counter = CNAT_V4_ICMP_Q_I2O_E_DA_PKT;
            break;
        case (CNAT_INV_PORT_DIRECT):
        case (CNAT_DEL_PORT_DIRECT):
        case (CNAT_BAD_INUSE_DIRECT):
        case (CNAT_NOT_FOUND_DIRECT):
            counter = CNAT_V4_ICMP_Q_I2O_E_DD_PKT;
            break;
        case (CNAT_ERR_NO_SESSION_DB):
            counter = CNAT_V4_ICMP_Q_I2O_E_DS_PKT;
            break;
        default:
            counter = CNAT_V4_ICMP_Q_I2O_E_DC_PKT;
            break;
        }
        /*
         * send to icmp msg generate node
         */
        if (info.gen_icmp_msg == CNAT_ICMP_MSG) {
            #if 0
            u32 *fd = (u32*)ctx->feature_data;
            fd[0] = info.svi_addr;
            fd[1] = CNAT_ICMP_DEST_UNREACHABLE;
            #endif
            disposition = CNAT_V4_ICMP_Q_E_I2O_GEN;
            counter = CNAT_V4_ICMP_Q_I2O_E_G_PKT;
        } else {
            disposition = CNAT_V4_ICMP_Q_E_I2O_D;
            counter = CNAT_V4_ICMP_Q_I2O_E_D_PKT;
        }
        DEBUG_I2O_DROP(CNAT_DEBUG_DROP_ICMP)
    }
            
    em->counters[node_counter_base_index + counter] += 1;
    
    return disposition;
}

#include <vnet/pipeline.h>

static uword cnat_ipv4_icmp_q_inside_input_exc_node_fn (vlib_main_t * vm,
                              vlib_node_runtime_t * node,
                              vlib_frame_t * frame)
{
    return dispatch_pipeline (vm, node, frame);
}

VLIB_REGISTER_NODE (cnat_ipv4_icmp_q_inside_input_exc_node) = {
  .function = cnat_ipv4_icmp_q_inside_input_exc_node_fn,
  .name = "vcgn-v4-icmp-q-i2o-e",
  .vector_size = sizeof (u32),
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(cnat_ipv4_icmp_q_inside_input_exc_error_strings),
  .error_strings = cnat_ipv4_icmp_q_inside_input_exc_error_strings,

  .n_next_nodes = CNAT_V4_ICMP_Q_E_I2O_NEXT,

  /* edit / add dispositions here */
  .next_nodes = {
        //[CNAT_V4_ICMP_Q_E_I2O_GEN] = "icmp_msg_gen", /* Currently it will go
        //to ip4-input node. We have to port icmp msg generator node */
        [CNAT_V4_ICMP_Q_E_I2O_T] = "ip4-input",
        [CNAT_V4_ICMP_Q_E_I2O_D] = "error-drop",
  },
};


clib_error_t *cnat_ipv4_icmp_q_inside_input_exc_init (vlib_main_t *vm)
{
  cnat_ipv4_icmp_q_inside_input_exc_main_t * mp = &cnat_ipv4_icmp_q_inside_input_exc_main;

  mp->vlib_main = vm;
  mp->vnet_main = vnet_get_main();

  return 0;
}

VLIB_INIT_FUNCTION (cnat_ipv4_icmp_q_inside_input_exc_init);
