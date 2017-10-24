/*
 *------------------------------------------------------------------
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
 *------------------------------------------------------------------
 */
/*
 * Copyright (C) 2011-2014 Universita` di Pisa. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   1. Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *   2. Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *      documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <vppinfra/lock.h>

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  clib_spinlock_t lockp;
  u8 *host_if_name;
  uword if_index;
  u32 hw_if_index;
  u32 sw_if_index;
  u32 clib_file_index;

  u32 per_interface_next_index;
  u8 is_admin_up;

  /* netmap */
  struct nmreq *req;
  u16 mem_region;
  int fd;
  struct netmap_if *nifp;
  u16 first_tx_ring;
  u16 last_tx_ring;
  u16 first_rx_ring;
  u16 last_rx_ring;

} netmap_if_t;

typedef struct
{
  char *mem;
  u32 region_size;
  int refcnt;
} netmap_mem_region_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  netmap_if_t *interfaces;

  /* bitmap of pending rx interfaces */
  uword *pending_input_bitmap;

  /* rx buffer cache */
  u32 **rx_buffers;

  /* hash of host interface names */
  mhash_t if_index_by_host_if_name;

  /* vector of memory regions */
  netmap_mem_region_t *mem_regions;

  /* first cpu index */
  u32 input_cpu_first_index;

  /* total cpu count */
  u32 input_cpu_count;
} netmap_main_t;

extern netmap_main_t netmap_main;
extern vnet_device_class_t netmap_device_class;
extern vlib_node_registration_t netmap_input_node;

int netmap_create_if (vlib_main_t * vm, u8 * host_if_name, u8 * hw_addr_set,
		      u8 is_pipe, u8 is_master, u32 * sw_if_index);
int netmap_delete_if (vlib_main_t * vm, u8 * host_if_name);


/* Macros and helper functions from sys/net/netmap_user.h */

#ifdef _NET_NETMAP_H_

#define _NETMAP_OFFSET(type, ptr, offset) \
	((type)(void *)((char *)(ptr) + (offset)))

#define NETMAP_IF(_base, _ofs)	_NETMAP_OFFSET(struct netmap_if *, _base, _ofs)

#define NETMAP_TXRING(nifp, index) _NETMAP_OFFSET(struct netmap_ring *, \
	nifp, (nifp)->ring_ofs[index] )

#define NETMAP_RXRING(nifp, index) _NETMAP_OFFSET(struct netmap_ring *,	\
	nifp, (nifp)->ring_ofs[index + (nifp)->ni_tx_rings + 1] )

#define NETMAP_BUF(ring, index)				\
	((char *)(ring) + (ring)->buf_ofs + ((index)*(ring)->nr_buf_size))

#define NETMAP_BUF_IDX(ring, buf)			\
	( ((char *)(buf) - ((char *)(ring) + (ring)->buf_ofs) ) / \
		(ring)->nr_buf_size )

static inline uint32_t
nm_ring_next (struct netmap_ring *ring, uint32_t i)
{
  return (PREDICT_FALSE (i + 1 == ring->num_slots) ? 0 : i + 1);
}


/*
 * Return 1 if we have pending transmissions in the tx ring.
 * When everything is complete ring->head = ring->tail + 1 (modulo ring size)
 */
static inline int
nm_tx_pending (struct netmap_ring *ring)
{
  return nm_ring_next (ring, ring->tail) != ring->head;
}

static inline uint32_t
nm_ring_space (struct netmap_ring *ring)
{
  int ret = ring->tail - ring->cur;
  if (ret < 0)
    ret += ring->num_slots;
  return ret;
}
#endif


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
