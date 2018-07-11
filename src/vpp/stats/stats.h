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
#ifndef __included_stats_h__
#define __included_stats_h__

#include <time.h>
#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/interface.h>
#include <pthread.h>
#include <vlib/threads.h>
#include <vnet/fib/fib_table.h>
#include <vnet/mfib/mfib_table.h>
#include <vlib/unix/unix.h>
#include <vlibmemory/api.h>
#include <vlibapi/api_helper_macros.h>
#include <svm/queue.h>
#include <svm/ssvm.h>

/* Default socket to exchange segment fd */
#define STAT_SEGMENT_SOCKET_FILE "/run/vpp/stats.sock"

typedef struct
{
  volatile u32 lock;
  volatile u32 release_hint;
  u32 thread_index;
  u32 count;
  int tag;
} data_structure_lock_t;

/**
 * @brief stats request registration indexes
 *
 */
/* from .../vnet/vnet/ip/lookup.c. Yuck */
/* *INDENT-OFF* */
typedef CLIB_PACKED (struct
{
  ip4_address_t address;
  u32 address_length: 6;
  u32 index:	     26;
}) ip4_route_t;
/* *INDENT-ON* */

typedef struct
{
  ip6_address_t address;
  u32 address_length;
  u32 index;
} ip6_route_t;

typedef struct
{
  ip4_route_t *ip4routes;
  ip6_route_t *ip6routes;
  mfib_prefix_t *mroutes;
  fib_table_t **fibs;
  mfib_table_t **mfibs;
  hash_pair_t **pvec;
  uword *results;
} do_ip46_fibs_t;

typedef struct
{
  u16 msg_id;
  u32 size;
  u32 client_index;
  u32 context;
  i32 retval;
} client_registration_reply_t;

typedef enum
{
#define stats_reg(n) IDX_##n,
#include <vpp/stats/stats.reg>
#undef stats_reg
  STATS_REG_N_IDX,
} stats_reg_index_t;

typedef struct
{
  //Standard client information
  uword *client_hash;
  vpe_client_registration_t *clients;
  u32 item;

} vpe_client_stats_registration_t;


typedef struct
{
  void *mheap;
  pthread_t thread_self;
  pthread_t thread_handle;

  u32 stats_poll_interval_in_seconds;
  u32 enable_poller;

  /*
   * stats_registrations is a vector, indexed by
   * IDX_xxxx_COUNTER generated for each streaming
   * stat a client can register for. (see stats.reg)
   *
   * The values in the vector refer to pools.
   *
   * The pool is of type vpe_client_stats_registration_t
   *
   * This typedef consists of:
   *
   * u32 item: This is the instance of the IDX_xxxx_COUNTER a
   *           client is interested in.
   * vpe_client_registration_t *clients: The list of clients interested.
   *
   * e.g.
   * stats_registrations[IDX_INTERFACE_SIMPLE_COUNTERS] refers to a pool
   * containing elements:
   *
   * u32 item = sw_if_index1
   * clients = ["clienta","clientb"]
   *
   * When clients == NULL the pool element is freed. When the pool is empty
   *
   * ie
   * 0 == pool_elts(stats_registrations[IDX_INTERFACE_SIMPLE_COUNTERS]
   *
   * then there is no need to process INTERFACE_SIMPLE_COUNTERS
   *
   * Note that u32 item = ~0 is the simple case for ALL interfaces or fibs.
   *
   */

  uword **stats_registration_hash;
  vpe_client_stats_registration_t **stats_registrations;

  /* control-plane data structure lock */
  data_structure_lock_t *data_structure_lock;

  /* bail out of FIB walk if set */
  clib_longjmp_t jmp_buf;

  /* Vectors for Distribution funcs: do_ip4_fibs and do_ip6_fibs. */
  do_ip46_fibs_t do_ip46_fibs;

  /*
     Working vector vars so as to not thrash memory allocator.
     Has effect of making "static"
   */
  vpe_client_stats_registration_t **regs_tmp;
  vpe_client_registration_t **clients_tmp;

  /* statistics segment */
  ssvm_private_t stat_segment;
  uword *counter_vector_by_name;
  clib_spinlock_t *stat_segment_lockp;
  clib_socket_t *socket;
  u8 *socket_name;
  uword memory_size;
  u8 serialize_nodes;

  /* Pointers to scalar stats maintained by the stat thread */
  f64 *input_rate_ptr;
  f64 *last_runtime_ptr;
  f64 *last_runtime_stats_clear_ptr;
  f64 *vector_rate_ptr;
  u64 last_input_packets;

  /* Pointers to vector stats maintained by the stat thread */
  u8 *serialized_nodes;
  vlib_main_t **stat_vms;
  vlib_node_t ***node_dups;

  f64 *vectors_per_node;
  f64 *vector_rate_in;
  f64 *vector_rate_out;
  f64 *vector_rate_drop;
  f64 *vector_rate_punt;

  /* convenience */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;
  vnet_interface_main_t *interface_main;
  api_main_t *api_main;
} stats_main_t;

extern stats_main_t stats_main;

/* Default stat segment 32m */
#define STAT_SEGMENT_DEFAULT_SIZE	(32<<20)

#define STAT_SEGMENT_OPAQUE_LOCK	0
#define STAT_SEGMENT_OPAQUE_DIR		1
#define STAT_SEGMENT_OPAQUE_EPOCH	2

typedef enum
{
  STAT_DIR_TYPE_ILLEGAL = 0,
  STAT_DIR_TYPE_SCALAR_POINTER,
  STAT_DIR_TYPE_VECTOR_POINTER,
  STAT_DIR_TYPE_COUNTER_VECTOR,
  STAT_DIR_TYPE_ERROR_INDEX,
  STAT_DIR_TYPE_SERIALIZED_NODES,
} stat_directory_type_t;

typedef struct
{
  stat_directory_type_t type;
  void *value;
} stat_segment_directory_entry_t;

void do_stat_segment_updates (stats_main_t * sm);

#endif /* __included_stats_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
