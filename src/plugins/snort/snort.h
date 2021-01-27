/*
 *------------------------------------------------------------------
 * Copyright (c) 2021 Cisco and/or its affiliates.
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
 *------------------------------------------------------------------
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
  int enq_fd, deq_fd;
  u32 *buffer_indices;
  u32 *freelist;
} snort_qpair_t;

typedef struct
{
  u32 index;
  clib_socket_t *client_socket;
  u32 client_index;
  void *shm_base;
  u32 shm_size;
  int shm_fd;
  snort_qpair_t *qpairs;
  u8 *name;
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
  clib_socket_t *listener;
  snort_client_t *clients;
  snort_instance_t *instances;
  uword *instance_by_name;
  u32 *instance_by_sw_if_index;
  u8 **buffer_pool_base_addrs;
} snort_main_t;

extern snort_main_t snort_main;

/* functions */
clib_error_t *snort_instance_create (vlib_main_t *vm, char *name,
				     u8 log2_queue_sz);
clib_error_t *snort_interface_enable_disable (vlib_main_t *vm,
					      char *instance_name,
					      u32 sw_if_index, int is_enable);

#endif /* __snort_snort_h__ */
