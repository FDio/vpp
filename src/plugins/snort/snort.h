/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2021 Cisco Systems, Inc.
 */

#ifndef __snort_snort_h__
#define __snort_snort_h__

#include <vppinfra/error.h>
#include <vppinfra/socket.h>
#include <vlib/vlib.h>
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

typedef struct
{
  clib_socket_t *listener;
  snort_client_t *clients;
  snort_instance_t *instances;
  uword *instance_by_name;
  u32 *instance_by_sw_if_index;
  u8 **buffer_pool_base_addrs;
  snort_per_thread_data_t *per_thread_data;
  u32 input_mode;
  u8 *socket_name;
} snort_main_t;

extern snort_main_t snort_main;
extern vlib_node_registration_t snort_enq_node;
extern vlib_node_registration_t snort_deq_node;

typedef enum
{
  SNORT_ENQ_NEXT_DROP,
  SNORT_ENQ_N_NEXT_NODES,
} snort_enq_next_t;

typedef enum
{
  SNORT_INPUT = 1,
  SNORT_OUTPUT = 2,
  SNORT_INOUT = 3
} snort_attach_dir_t;

#define SNORT_ENQ_NEXT_NODES                                                  \
  {                                                                           \
    [SNORT_ENQ_NEXT_DROP] = "error-drop",                                     \
  }

/* functions */
clib_error_t *snort_instance_create (vlib_main_t *vm, char *name,
				     u8 log2_queue_sz, u8 drop_on_disconnect);
clib_error_t *snort_interface_enable_disable (vlib_main_t *vm,
					      char *instance_name,
					      u32 sw_if_index, int is_enable,
					      snort_attach_dir_t dir);
clib_error_t *snort_set_node_mode (vlib_main_t *vm, u32 mode);

always_inline void
snort_freelist_init (u32 *fl)
{
  for (int j = 0; j < vec_len (fl); j++)
    fl[j] = j;
}

#endif /* __snort_snort_h__ */
