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

typedef struct
{
  vpe_client_registration_t client;
  u8 stats_registrations;
#define INTERFACE_SIMPLE_COUNTERS (1 << 0)
#define INTERFACE_COMBINED_COUNTERS (1 << 1)
#define IP4_FIB_COUNTERS (1 << 2)
#define IP4_NBR_COUNTERS (1 << 3)
#define IP6_FIB_COUNTERS (1 << 4)
#define IP6_NBR_COUNTERS (1 << 5)

} vpe_client_stats_registration_t;

/* from .../vnet/vnet/ip/lookup.c. Yuck */
typedef CLIB_PACKED (struct
		     {
		     ip4_address_t address;
u32 address_length: 6;
u32 index:	     26;
		     }) ip4_route_t;

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
  void *mheap;
  pthread_t thread_self;
  pthread_t thread_handle;

  u32 stats_poll_interval_in_seconds;
  u32 enable_poller;

  uword *stats_registration_hash;
  vpe_client_stats_registration_t *stats_registrations;
  vpe_client_stats_registration_t **regs;

  /* control-plane data structure lock */
  data_structure_lock_t *data_structure_lock;

  /* bail out of FIB walk if set */
  clib_longjmp_t jmp_buf;

  /* Vectors for Distribution funcs: do_ip4_fibs and do_ip6_fibs. */
  do_ip46_fibs_t do_ip46_fibs;

  /* convenience */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;
  vnet_interface_main_t *interface_main;
  api_main_t *api_main;
} stats_main_t;

stats_main_t stats_main;

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
