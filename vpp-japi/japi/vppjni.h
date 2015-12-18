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
#ifndef __included_vppjni_h__
#define __included_vppjni_h__

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/api_errno.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <jni.h>
#include <japi/vppjni_bridge_domain.h>

typedef struct {
    u8 * name;
    u32 value;
} name_sort_t;

typedef struct {
    u8 valid; // used in a vector of sw_interface_details_t

    u8 interface_name[64];
    u32 sw_if_index;
    u32 sup_sw_if_index;
    u32 l2_address_length;
    u8 l2_address[8];
    u8 admin_up_down;
    u8 link_up_down;
    u8 link_duplex;
    u8 link_speed;
    u32 sub_id;
    u8 sub_dot1ad;
    u8 sub_number_of_tags;
    u16 sub_outer_vlan_id;
    u16 sub_inner_vlan_id;
    u8 sub_exact_match;
    u8 sub_default;
    u8 sub_outer_vlan_id_any;
    u8 sub_inner_vlan_id_any;
    u32 vtr_op;
    u32 vtr_push_dot1q;
    u32 vtr_tag1;
    u32 vtr_tag2;
} sw_interface_details_t;

typedef struct {
    u8 * interface_name;
    u32 sw_if_index;
    /* 
     * Subinterface ID. A number 0-N to uniquely identify 
     * this subinterface under the super interface
     */
    u32 sub_id;

    /* 0 = dot1q, 1=dot1ad */
    u8 sub_dot1ad;

    /* Number of tags 0-2 */
    u8 sub_number_of_tags;
    u16 sub_outer_vlan_id;
    u16 sub_inner_vlan_id;
    u8 sub_exact_match;
    u8 sub_default;
    u8 sub_outer_vlan_id_any;
    u8 sub_inner_vlan_id_any;

    /* vlan tag rewrite */
    u32 vtr_op;
    u32 vtr_push_dot1q;
    u32 vtr_tag1;
    u32 vtr_tag2;
} sw_interface_subif_t;

typedef struct {
    u8 *desc;
} sw_if_config_t;

typedef struct {
    u32 ip;
    u8 prefix_length;
} ipv4_address_t;

typedef struct {
    u8 ip[16];
    u8 prefix_length;
} ipv6_address_t;

typedef struct {
  u64 ip4;
  u64 ip6;
  u64 unicast;
  u64 multicast;
  u64 broadcast;
  u64 discard;
  u64 fifo_full;
  u64 error;
  u64 unknown_proto;
  u64 miss;
} packet_counters_t;

typedef struct {
  u64 octets;
  packet_counters_t pkts;
} if_counters_t;

typedef struct {
  u8 valid;
  u32 sw_if_index;
  if_counters_t rx;
  if_counters_t tx;
} sw_interface_stats_t;

typedef struct {
    u32 src_address;
    u32 dst_address;
    u32 encap_vrf_id;
    u32 vni;
    u32 decap_next_index;
} vxlan_tunnel_details_t;


typedef struct {
  /* Context IDs */
  volatile u32 context_id_sent;
  volatile u32 context_id_received;

  /* Spinlock */
  volatile u32 lock;
  u32 tag;

  /* To recycle pseudo-synchronous message code from vpe_api_test... */
  volatile u32 result_ready;
  volatile i32 retval;
  volatile u8 *shmem_result;

  /* thread cleanup */
  pthread_key_t cleanup_rx_thread_key;
  /* attachment of rx thread to java thread */
  JNIEnv *jenv;
  JavaVM *jvm;
  jclass jcls;
  jmethodID jmtdIfDetails;  // interfaceDetails method
  uword *callback_hash;     // map context_id => jobject
  uword *ping_hash;         // map ping context_id => msg type called

  /* Timestamp */
  clib_time_t clib_time;

  /* connected indication */
  u8 is_connected;

  /* context -> non-trivial reply hash */
  uword * reply_hash;
  u32 saved_reply_count;

  /* interface name map */
  uword * sw_if_index_by_interface_name;

  /* interface counters */
  sw_interface_stats_t * sw_if_stats_by_sw_if_index;

  /* interface table */
  sw_interface_details_t * sw_if_table;

  uword * sw_if_config_by_sw_if_index;

  /* interface indices of responses to one sw_if_dump request */
  u8 collect_indices;
  u32 * sw_if_dump_if_indices;

  /* program name, build_dir, version */
  u8 program_name[32];
  u8 build_directory[256];
  u8 version[32];
  u8 build_date[32];

  /* subinterface table */
  sw_interface_subif_t * sw_if_subif_table;

  /* used in ip_address_dump request and response handling */
  ipv4_address_t *ipv4_addresses;
  ipv6_address_t *ipv6_addresses;
  u8 is_ipv6;

  /* used in vxlan_tunnel_dump request and response handling */
  vxlan_tunnel_details_t *vxlan_tunnel_details;

  /* main heap */
  u8 * heap;

  /* convenience */
  unix_shared_memory_queue_t * vl_input_queue;
  api_main_t * api_main;
  u32 my_client_index;

  vjbd_main_t vjbd_main;
} vppjni_main_t;

vppjni_main_t vppjni_main __attribute__((aligned (64)));


static inline u32 vppjni_get_context_id (vppjni_main_t * jm)
{
  u32 my_context_id;
  my_context_id = __sync_add_and_fetch (&jm->context_id_sent, 1);
  return my_context_id;
}

static inline void vppjni_lock (vppjni_main_t * jm, u32 tag)
{
  while (__sync_lock_test_and_set (&jm->lock, 1))
    ;
  jm->tag = tag;
}

static inline void vppjni_unlock (vppjni_main_t * jm)
{
  jm->tag = 0;
  CLIB_MEMORY_BARRIER();
  jm->lock = 0;
}

static inline f64 vppjni_time_now (vppjni_main_t *jm)
{
  return clib_time_now (&jm->clib_time);
}

static inline int vppjni_sanity_check (vppjni_main_t * jm)
{
  if (!jm->is_connected)
    return VNET_API_ERROR_NOT_CONNECTED;
  return 0;
}

#define __PACKED(x) x __attribute__((packed))

typedef __PACKED(struct _vl_api_generic_reply {
  u16 _vl_msg_id;
  u32 context;
  i32 retval;
  u8 data[0];
}) vl_api_generic_reply_t;

void vl_api_generic_reply_handler (vl_api_generic_reply_t *mp);

/* M: construct, but don't yet send a message */

#define M(T,t)                                  \
do {                                            \
  jm->result_ready = 0;                         \
  mp = vl_msg_api_alloc(sizeof(*mp));           \
  memset (mp, 0, sizeof (*mp));                 \
  mp->_vl_msg_id = ntohs (VL_API_##T);          \
  mp->client_index = jm->my_client_index;       \
 } while(0);

#define M2(T,t,n)                               \
do {                                            \
  jm->result_ready = 0;                         \
  mp = vl_msg_api_alloc(sizeof(*mp)+(n));       \
  memset (mp, 0, sizeof (*mp));                 \
  mp->_vl_msg_id = ntohs (VL_API_##T);          \
  mp->client_index = jm->my_client_index;       \
 } while(0);


/* S: send a message */
#define S (vl_msg_api_send_shmem (jm->vl_input_queue, (u8 *)&mp))

/* W: wait for results, with timeout */
#define W                                       \
  do {                                          \
    timeout = vppjni_time_now (jm) + 1.0;       \
                                                \
    while (vppjni_time_now (jm) < timeout) {    \
      if (jm->result_ready == 1) {              \
        return (jm->retval);                    \
      }                                         \
    }                                           \
    return -99;                                 \
} while(0);

/* WNR: wait for results, with timeout (without returning) */
#define WNR                                     \
  do {                                          \
    timeout = vppjni_time_now (jm) + 1.0;       \
                                                \
    rv = -99;                                   \
    while (vppjni_time_now (jm) < timeout) {    \
      if (jm->result_ready == 1) {              \
        rv = (jm->retval);                      \
        break;                                  \
      }                                         \
    }                                           \
} while(0);

#endif /* __included_vppjni_h__ */
