/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
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
 */
#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>

#if DPDK == 0
#include <vnet/devices/pci/ixgev.h>
#include <vnet/devices/pci/ixge.h>
#include <vnet/devices/pci/ige.h>
#else
#include <vnet/devices/dpdk/dpdk.h>
#endif

#include <vppinfra/error.h>
#include <vppinfra/hash.h>
#include <app/l2t.h>

l2t_main_t l2t_main;

/* Statistics (not really errors) */
#define foreach_l2t_l2_error                       \
_(NETWORK_TO_USER, "L2 network to user (ip6) pkts")  

static char * l2t_l2_error_strings[] = {
#define _(sym,string) string,
  foreach_l2t_l2_error
#undef _
};

typedef enum {
#define _(sym,str) L2T_L2_ERROR_##sym,
    foreach_l2t_l2_error
#undef _
    L2T_L2_N_ERROR,
} l2t_l2_error_t;

/*
 * Packets go to ethernet-input when they don't match a mapping
 */
typedef enum { 
    L2T_L2_NEXT_DROP,
    L2T_L2_NEXT_ETHERNET_INPUT,
    L2T_L2_NEXT_IP6_LOOKUP,
    L2T_L2_N_NEXT,
} l2t_l2_next_t;

vlib_node_registration_t l2t_l2_node;

#define NSTAGES 3

static inline void stage0 (vlib_main_t * vm,
                           vlib_node_runtime_t * node,
                           u32 buffer_index)
{
    vlib_buffer_t *b = vlib_get_buffer (vm, buffer_index);
    vlib_prefetch_buffer_header (b, STORE);
    CLIB_PREFETCH (b->data, 2*CLIB_CACHE_LINE_BYTES, STORE);
}

static inline void stage1 (vlib_main_t * vm,
                           vlib_node_runtime_t * node,
                           u32 bi)
{
    vlib_buffer_t *b = vlib_get_buffer (vm, bi);
    l2t_main_t *lm = &l2t_main;
    ethernet_header_t * eh;
    ethernet_vlan_header_t *vh;
    u32 session_index;
    uword *p;
    uword vlan_and_sw_if_index_key;

    /* just in case, needed to test with the tun/tap device */
    vlib_buffer_reset(b);

    eh = vlib_buffer_get_current (b);

    /* Not a VLAN pkt? send to ethernet-input... */
    if (PREDICT_FALSE(eh->type != clib_host_to_net_u16 (0x8100))) {
        vnet_buffer(b)->l2t.next_index = L2T_L2_NEXT_ETHERNET_INPUT;
        return;
    }
    vh = (ethernet_vlan_header_t *)(eh+1);

    /* look up session */
    vlan_and_sw_if_index_key = ((uword)(vh->priority_cfi_and_id)<<32) 
        | vnet_buffer(b)->sw_if_index[VLIB_RX];

    p = hash_get (lm->session_by_vlan_and_rx_sw_if_index, 
                  vlan_and_sw_if_index_key);

    if (PREDICT_FALSE(p == 0)) {
        /* $$$ drop here if not for our MAC? */
        vnet_buffer(b)->l2t.next_index = L2T_L2_NEXT_ETHERNET_INPUT;
        return;
    } else {
        session_index = p[0];
    }

    /* Remember mapping index, prefetch the mini counter */
    vnet_buffer(b)->l2t.next_index = L2T_L2_NEXT_IP6_LOOKUP;
    vnet_buffer(b)->l2t.session_index = session_index;

    /* Each mapping has 2 x (pkt, byte) counters, hence the shift */
    CLIB_PREFETCH(lm->counter_main.mini + (p[0]<<1), CLIB_CACHE_LINE_BYTES,
                  STORE);
}

static inline u32 last_stage (vlib_main_t *vm, vlib_node_runtime_t *node,
                              u32 bi)
{
    vlib_buffer_t *b = vlib_get_buffer (vm, bi);
    l2t_main_t *lm = &l2t_main;
    ethernet_header_t * eh = vlib_buffer_get_current (b);
    vlib_node_t *n = vlib_get_node (vm, l2t_l2_node.index);
    u32 node_counter_base_index = n->error_heap_index;
    vlib_error_main_t * em = &vm->error_main;
    l2tpv3_header_t * l2t;      /* l2 header */
    ethernet_vlan_header_t * vh; /* 802.1q vlan header */
    u32 counter_index;
    l2t_session_t *s;
    ip6_header_t *ip6;
    u16 payload_ethertype;
    u8 dst_mac_address[6];
    u8 src_mac_address[6];
    u16 payload_length;
    i32 backup;
    
    /* Other-than-output pkt? We're done... */
    if (vnet_buffer(b)->l2t.next_index != L2T_L2_NEXT_IP6_LOOKUP)
        return vnet_buffer(b)->l2t.next_index;

    vh = (ethernet_vlan_header_t *)(eh+1);

    em->counters[node_counter_base_index + L2T_L2_ERROR_NETWORK_TO_USER] += 1;
    
    counter_index = 
        session_index_to_counter_index (vnet_buffer(b)->l2t.session_index,
                                        SESSION_COUNTER_NETWORK_TO_USER);
    
    /* per-mapping byte stats include the ethernet header */
    vlib_increment_combined_counter (&lm->counter_main, counter_index,
                                     1 /* packet_increment */,
                                     vlib_buffer_length_in_chain (vm, b) +
                                     sizeof (ethernet_header_t));
    
    s = pool_elt_at_index (lm->sessions, vnet_buffer(b)->l2t.session_index);

    /* Save src/dst MAC addresses */
#define _(i)  dst_mac_address[i] = eh->dst_address[i];
    _(0) _(1) _(2) _(3) _(4) _(5);
#undef _
#define _(i)  src_mac_address[i] = eh->src_address[i];
    _(0) _(1) _(2) _(3) _(4) _(5);
#undef _
    
    payload_ethertype = vh->type;

    /* Splice out the 802.1q vlan tag */
    vlib_buffer_advance (b, 4);
    eh = vlib_buffer_get_current (b);

    /* restore src/dst MAC addresses */
#define _(i)   eh->dst_address[i] = dst_mac_address[i];
    _(0) _(1) _(2) _(3) _(4) _(5);
#undef _
#define _(i)  eh->src_address[i] = src_mac_address[i];
    _(0) _(1) _(2) _(3) _(4) _(5);
#undef _
    eh->type = payload_ethertype;
    
    /* Paint on an l2tpv3 hdr */
    backup = sizeof(*l2t);
#if 0
    /* back up 4 bytes less if no l2 sublayer */
    backup -= s->l2_sublayer_present ? 0 : 4;
#endif
    
    vlib_buffer_advance (b, -backup);
    l2t = vlib_buffer_get_current (b);

    l2t->session_id = s->remote_session_id;
    l2t->cookie = s->remote_cookie;

#if 0
    if (s->l2_sublayer_present)
        l2t->l2_specific_sublayer = 0;
#endif

    /* Paint on an ip6 header */
    vlib_buffer_advance (b, -(sizeof (*ip6)));
    ip6 = vlib_buffer_get_current (b);

    ip6->ip_version_traffic_class_and_flow_label = 
        clib_host_to_net_u32 (0x6<<28);

    /* calculate ip6 payload length */
    payload_length = vlib_buffer_length_in_chain (vm, b);
    payload_length -= sizeof (*ip6);

    ip6->payload_length = clib_host_to_net_u16 (payload_length);
    ip6->protocol = 0x73; /* l2tpv3 */
    ip6->hop_limit = 0xff;
    ip6->src_address.as_u64[0] = s->our_address.as_u64[0];
    ip6->src_address.as_u64[1] = s->our_address.as_u64[1];
    ip6->dst_address.as_u64[0] = s->client_address.as_u64[0];
    ip6->dst_address.as_u64[1] = s->client_address.as_u64[1];

    return L2T_L2_NEXT_IP6_LOOKUP;
}

#include <vnet/pipeline.h>

static uword l2t_l2_node_fn (vlib_main_t * vm,
                             vlib_node_runtime_t * node,
                             vlib_frame_t * frame)
{
    return dispatch_pipeline (vm, node, frame);
}

VLIB_REGISTER_NODE (l2t_l2_node) = {
  .function = l2t_l2_node_fn,
  .name = "l2t-l2-input",
  .vector_size = sizeof (u32),
  .format_trace = format_l2t_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  
  .n_errors = ARRAY_LEN(l2t_l2_error_strings),
  .error_strings = l2t_l2_error_strings,

  .n_next_nodes = L2T_L2_N_NEXT,

  /* edit / add dispositions here */
  .next_nodes = {
        [L2T_L2_NEXT_IP6_LOOKUP] = "ip6-lookup",
        [L2T_L2_NEXT_ETHERNET_INPUT] = "ethernet-input",
        [L2T_L2_NEXT_DROP] = "error-drop",
  },
};

VLIB_NODE_FUNCTION_MULTIARCH (l2t_l2_node, l2t_l2_node_fn)

