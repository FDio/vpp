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
#include <vlib/unix/unix.h>
#include <vlibmemory/api.h>
#include <vlibmemory/unix_shared_memory_queue.h>
#include <vlibapi/api_helper_macros.h>

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
typedef CLIB_PACKED (struct
		     {
		     ip4_address_t address;
u32 address_length: 6;
u32 index:	     26;
		     }) ip4_route_t;

/* see interface.api */
typedef struct
{
  u32 sw_if_index;
  u64 drop;
  u64 punt;
  u64 rx_ip4;
  u64 rx_ip6;
  u64 rx_no_buffer;
  u64 rx_miss;
  u64 rx_error;
  u64 tx_error;
  u64 rx_mpls;
} vnet_simple_counter_t;

typedef struct
{
  u32 sw_if_index;
  u64 rx_packets;			/**< packet counter */
  u64 rx_bytes;			/**< byte counter  */
  u64 tx_packets;			/**< packet counter */
  u64 tx_bytes;			/**< byte counter  */
} vnet_combined_counter_t;

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
  fib_table_t **fibs;
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

  /* convenience */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;
  vnet_interface_main_t *interface_main;
  api_main_t *api_main;
} stats_main_t;

extern stats_main_t stats_main;

void dslock (stats_main_t * sm, int release_hint, int tag);
void dsunlock (stats_main_t * sm);

#endif /* __included_stats_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
