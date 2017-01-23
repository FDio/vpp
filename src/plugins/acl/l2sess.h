/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
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
#ifndef __included_l2sess_h__
#define __included_l2sess_h__

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>

#include <vppinfra/hash.h>
#include <vppinfra/error.h>
#include <vppinfra/elog.h>
#include <vppinfra/timing_wheel.h>

#include <vnet/l2/l2_output.h>
#include <vnet/l2/l2_input.h>

#define _(node_name, node_var, is_out, is_ip6, is_track)
#undef _
#define foreach_l2sess_node \
  _("aclp-l2s-input-ip4-add", l2sess_in_ip4_add, 0, 0, 0)  \
  _("aclp-l2s-input-ip6-add", l2sess_in_ip6_add, 0, 1, 0)  \
  _("aclp-l2s-output-ip4-add", l2sess_out_ip4_add, 1, 0, 0) \
  _("aclp-l2s-output-ip6-add", l2sess_out_ip6_add, 1, 1, 0) \
  _("aclp-l2s-input-ip4-track", l2sess_in_ip4_track, 0, 0, 1) \
  _("aclp-l2s-input-ip6-track", l2sess_in_ip6_track, 0, 1, 1) \
  _("aclp-l2s-output-ip4-track",l2sess_out_ip4_track, 1, 0, 1) \
  _("aclp-l2s-output-ip6-track", l2sess_out_ip6_track, 1, 1, 1)

#define _(node_name, node_var, is_out, is_ip6, is_track)  \
  extern vlib_node_registration_t node_var;
foreach_l2sess_node
#undef _

#define TCP_FLAG_FIN    0x01
#define TCP_FLAG_SYN    0x02
#define TCP_FLAG_RST    0x04
#define TCP_FLAG_PUSH   0x08
#define TCP_FLAG_ACK    0x10
#define TCP_FLAG_URG    0x20
#define TCP_FLAG_ECE    0x40
#define TCP_FLAG_CWR    0x80
#define TCP_FLAGS_RSTFINACKSYN (TCP_FLAG_RST + TCP_FLAG_FIN + TCP_FLAG_SYN + TCP_FLAG_ACK)
#define TCP_FLAGS_ACKSYN (TCP_FLAG_SYN + TCP_FLAG_ACK)

typedef struct {
  ip46_address_t addr;
  u64 active_time;
  u64 n_packets;
  u64 n_bytes;
  u16 port;
} l2s_session_side_t;

enum {
  L2S_SESSION_SIDE_IN = 0,
  L2S_SESSION_SIDE_OUT,
  L2S_N_SESSION_SIDES
};

typedef struct {
  u64 create_time;
  l2s_session_side_t side[L2S_N_SESSION_SIDES];
  u8 l4_proto;
  u8 is_ip6;
  u16 tcp_flags_seen; /* u16 because of two sides */
} l2s_session_t;

#define PROD
#ifdef PROD
#define UDP_SESSION_IDLE_TIMEOUT_SEC 600
#define TCP_SESSION_IDLE_TIMEOUT_SEC (3600*24)
#define TCP_SESSION_TRANSIENT_TIMEOUT_SEC 120
#else
#define UDP_SESSION_IDLE_TIMEOUT_SEC 15
#define TCP_SESSION_IDLE_TIMEOUT_SEC 15
#define TCP_SESSION_TRANSIENT_TIMEOUT_SEC 5
#endif

typedef struct {
    /*
     * the next two fields are present for all nodes, but
     *  only one of them is used per node - depending
     * on whether the node is an input or output one.
     */
#define _(node_name, node_var, is_out, is_ip6, is_track) \
    u32 node_var ## _input_next_node_index[32]; \
    l2_output_next_nodes_st node_var ## _next_nodes;
foreach_l2sess_node
#undef _
    l2_output_next_nodes_st output_next_nodes;

    /* Next indices of the tracker nodes */
    u32 next_slot_track_node_by_is_ip6_is_out[2][2];

    /* 
     * Pairing of "forward" and "reverse" tables by table index.
     * Each relationship has two entries - for one and the other table,
     * so it is bidirectional.
     */
     
    u32 *fwd_to_rev_by_table_index;

    /*
     * The vector of per-interface session pools
     */

    l2s_session_t *sessions;

    /* The session timeouts */
    u64 tcp_session_transient_timeout;
    u64 tcp_session_idle_timeout;
    u64 udp_session_idle_timeout;

    /* Timing wheel to time out the idle sessions */
    timing_wheel_t timing_wheel;
    u32 *data_from_advancing_timing_wheel;
    u64 timer_wheel_next_expiring_time;
    u64 timer_wheel_tick;

    /* convenience */
    vlib_main_t * vlib_main;
    vnet_main_t * vnet_main;

    /* Counter(s) */
    u64 counter_attempted_delete_free_session;
} l2sess_main_t;

l2sess_main_t l2sess_main;

/* Just exposed for acl.c */

void
l2sess_vlib_plugin_register (vlib_main_t * vm, void * hh,
                      int from_early_init);


#endif /* __included_l2sess_h__ */
