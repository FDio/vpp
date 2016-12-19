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
#ifndef __included_ssvm_eth_h__
#define __included_ssvm_eth_h__

#include <vnet/vnet.h>

#include <vppinfra/elog.h>
#include <vppinfra/error.h>
#include <vppinfra/format.h>
#include <vppinfra/hash.h>
#include <vppinfra/vec.h>
#include <vppinfra/elog.h>
#include <vlib/vlib.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/devices/devices.h>
#include <vnet/ip/ip.h>
#include <vnet/pg/pg.h>
#include <vlibmemory/unix_shared_memory_queue.h>

#include <svm/ssvm.h>

extern vnet_device_class_t ssvm_eth_device_class;
extern vlib_node_registration_t ssvm_eth_input_node;

#define SSVM_BUFFER_SIZE  \
  (VLIB_BUFFER_DATA_SIZE + VLIB_BUFFER_PRE_DATA_SIZE)
#define SSVM_PACKET_TYPE 1

typedef struct
{
  /* Type of queue element */
  u8 type;
  u8 flags;
#define SSVM_BUFFER_NEXT_PRESENT (1<<0)
  u8 owner;
  u8 tag;
  i16 current_data_hint;
  u16 length_this_buffer;
  u16 total_length_not_including_first_buffer;
  u16 pad;
  u32 next_index;
  /* offset 16 */
  u8 data[SSVM_BUFFER_SIZE];
  /* pad to an even multiple of 64 octets */
  u8 pad2[CLIB_CACHE_LINE_BYTES - 16];
} ssvm_eth_queue_elt_t;

typedef struct
{
  /* vector of point-to-point connections */
  ssvm_private_t *intfcs;

  u32 *buffer_cache;
  u32 *chunk_cache;

  /* Configurable parameters */
  /* base address for next placement */
  u64 next_base_va;
  u64 segment_size;
  u64 nbuffers;
  u64 queue_elts;

  /* Segment names */
  u8 **names;

  /* convenience */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;
  elog_main_t *elog_main;
} ssvm_eth_main_t;

ssvm_eth_main_t ssvm_eth_main;

typedef enum
{
  CHUNK_POOL_FREELIST_INDEX = 0,
  CHUNK_POOL_INDEX,
  CHUNK_POOL_NFREE,
  TO_MASTER_Q_INDEX,
  TO_SLAVE_Q_INDEX,
  MASTER_ADMIN_STATE_INDEX,
  SLAVE_ADMIN_STATE_INDEX,
} ssvm_eth_opaque_index_t;

/*
 * debug scaffolding.
 */
static inline void
ssvm_eth_validate_freelists (int need_lock)
{
#if CLIB_DEBUG > 0
  ssvm_eth_main_t *em = &ssvm_eth_main;
  ssvm_private_t *intfc;
  ssvm_shared_header_t *sh;
  u32 *elt_indices;
  u32 n_available;
  int i;

  for (i = 0; i < vec_len (em->intfcs); i++)
    {
      intfc = em->intfcs + i;
      sh = intfc->sh;
      u32 my_pid = intfc->my_pid;

      if (need_lock)
	ssvm_lock (sh, my_pid, 15);

      elt_indices = (u32 *) (sh->opaque[CHUNK_POOL_FREELIST_INDEX]);
      n_available = (u32) (uword) (sh->opaque[CHUNK_POOL_NFREE]);

      for (i = 0; i < n_available; i++)
	ASSERT (elt_indices[i] < 2048);

      if (need_lock)
	ssvm_unlock (sh);
    }
#endif
}

#endif /* __included_ssvm_eth_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
