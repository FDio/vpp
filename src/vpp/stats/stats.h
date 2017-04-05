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
  void *mheap;
  pthread_t thread_self;
  pthread_t thread_handle;

  u32 stats_poll_interval_in_seconds;
  u32 enable_poller;

  uword *stats_registration_hash;
  vpe_client_registration_t *stats_registrations;

  /* control-plane data structure lock */
  data_structure_lock_t *data_structure_lock;

  /* bail out of FIB walk if set */
  clib_longjmp_t jmp_buf;

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
