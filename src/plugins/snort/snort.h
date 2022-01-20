/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2021 Cisco Systems, Inc.
 */

#ifndef __snort_snort_h__
#define __snort_snort_h__

#include <vppinfra/error.h>
#include <vppinfra/socket.h>
#include <vppinfra/vector/toeplitz.h>
#include <vlib/vlib.h>
#include <vnet/ip/ip4_inlines.h>
#include <snort/daq_vpp.h>

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  u8 log2_queue_size;
  daq_vpp_desc_t *descriptors;
  volatile u32 *enq_head;
  volatile u32 *deq_head;
  volatile u32 *enq_ring;
  volatile u32 *deq_ring;
  u32 next_desc;
  int enq_fd, deq_fd;
  u32 deq_fd_file_index;
  u32 *buffer_indices;
  u16 *next_indices;
  u32 *freelist;
  u32 ready;

  /* temporary storeage used by enqueue node */
  u32 n_pending;
  u16 pending_nexts[VLIB_FRAME_SIZE];
  u32 pending_buffers[VLIB_FRAME_SIZE];
  daq_vpp_desc_t pending_descs[VLIB_FRAME_SIZE];
} snort_qpair_t;

typedef struct
{
  u32 index;
  u32 client_index;
  void *shm_base;
  u32 shm_size;
  int shm_fd;
  snort_qpair_t *qpairs;
  u8 *name;
  u8 drop_on_disconnect;
} snort_instance_t;

typedef struct
{
  daq_vpp_msg_t msg;
  int fds[2];
  int n_fds;
} snort_client_msg_queue_elt;

typedef struct
{
  clib_socket_t socket;
  u32 instance_index;
  u32 file_index;
  snort_client_msg_queue_elt *msg_queue;
} snort_client_t;

typedef struct
{
  /* per-instance dequeue interrupts */
  void *interrupts;
} snort_per_thread_data_t;

typedef enum snort_hash_config_
{
  SNORT_HASH_L3_ADDRS = 0,
  SNORT_HASH_L3_L4_ADDRS = 1
} snort_hash_config_t;

typedef struct
{
  u32 *instances_per_iface;
  u32 n_instances;
  u32 flow_hash_config;
} snort_instance_context_t;

typedef struct
{
  clib_socket_t *listener;
  snort_client_t *clients;
  snort_instance_t *instances;
  snort_instance_context_t *contexts;
  uword *instance_by_name;
  u32 *context_by_sw_if_index;
  u32 **instance_vec_by_sw_if_index;
  u8 **buffer_pool_base_addrs;
  snort_per_thread_data_t *per_thread_data;
  u32 input_mode;
  u8 *socket_name;
  clib_toeplitz_hash_key_t *key_s;
  snort_hash_config_t hash_config;
} snort_main_t;

extern snort_main_t snort_main;
extern vlib_node_registration_t snort_enq_node;
extern vlib_node_registration_t snort_deq_node;

typedef enum
{
  SNORT_ENQ_NEXT_DROP,
  SNORT_ENQ_N_NEXT_NODES,
} snort_enq_next_t;

#define SNORT_ENQ_NEXT_NODES                                                  \
  {                                                                           \
    [SNORT_ENQ_NEXT_DROP] = "error-drop",                                     \
  }

/* functions */
clib_error_t *snort_instance_create (vlib_main_t *vm, char *name,
				     u8 log2_queue_sz, u8 drop_on_disconnect);
clib_error_t *snort_interface_enable_disable (vlib_main_t *vm,
					      u8 **instance_vec,
					      u32 sw_if_index, int is_enable);
clib_error_t *snort_set_node_mode (vlib_main_t *vm, u32 mode);

always_inline void
snort_freelist_init (u32 *fl)
{
  for (int j = 0; j < vec_len (fl); j++)
    fl[j] = j;
}

/* Compute flow hash. */
typedef struct
{
  u32 sip, dip;
  u16 sport, dport;
} __clib_packed ip4_key_t;

always_inline u32
snort4_compute_flow_hash (snort_main_t *sm, snort_hash_config_t config,
			  const ip4_header_t *ip)
{
  ip4_key_t data;
  u32 data_len = 8;

  tcp_header_t *tcp = (void *) (ip + 1);
  uword is_tcp_udp =
    (ip->protocol == IP_PROTOCOL_TCP || ip->protocol == IP_PROTOCOL_UDP);

  data.sip = ip->src_address.data_u32;
  data.dip = ip->dst_address.data_u32;
  if (config & SNORT_HASH_L3_L4_ADDRS)
    {
      data.sport = is_tcp_udp ? tcp->src : 0;
      data.dport = is_tcp_udp ? tcp->dst : 0;
      data_len += 4;
    }

  return clib_toeplitz_hash (sm->key_s, (u8 *) &data, data_len);
}
#endif /* __snort_snort_h__ */
