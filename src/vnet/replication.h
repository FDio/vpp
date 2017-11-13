/*
 * replication.h : packet replication
 *
 * Copyright (c) 2013 Cisco and/or its affiliates.
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

#ifndef included_replication_h
#define included_replication_h


#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/replication.h>


typedef struct
{
  /* The entire vnet buffer header restored for each replica */
  u8 vnet_buffer[40];		/* 16B aligned to allow vector unit copy */
  u8 reserved[24];		/* space for future expansion of vnet buffer header */

  /* feature state used during this replication */
  u64 feature_replicas;		/* feature's id for its set of replicas */
  u32 feature_counter;		/* feature's current index into set of replicas */
  u32 recycle_node_index;	/* feature's recycle node index */

  /*
   * data saved from the start of replication and restored
   * at the end of replication
   */
  u32 saved_free_list_index;	/* from vlib buffer */

  /* data saved from the original packet and restored for each replica */
  u64 l2_header[3];		/*  24B (must be at least 22B for l2 packets) */
  u32 flags;			/* vnet buffer flags */
  u16 ip_tos;			/* v4 and v6 */
  u16 ip4_checksum;		/* needed for v4 only */

  /* data saved from the vlib buffer header and restored for each replica */
  i16 current_data;		/* offset of first byte of packet in packet data */
  u8 pad[2];			/* to 64B */
  u8 l2_packet;			/* flag for l2 vs l3 packet data */

} replication_context_t;	/* 128B */


typedef struct
{

  u32 recycle_list_index;

  /* per-thread pools of replication contexts */
  replication_context_t **contexts;

  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;

} replication_main_t;


extern replication_main_t replication_main;


/* Return 1 if this buffer just came from the replication recycle handler. */
always_inline u32
replication_is_recycled (vlib_buffer_t * b0)
{
  return b0->flags & VLIB_BUFFER_IS_RECYCLED;
}

/*
 * Clear the recycle flag. If buffer came from the replication recycle
 * handler, this flag must be cleared before the packet is transmitted again.
 */
always_inline void
replication_clear_recycled (vlib_buffer_t * b0)
{
  b0->flags &= ~VLIB_BUFFER_IS_RECYCLED;
}

/*
 * Return the active replication context if this buffer has
 * been recycled, otherwise return 0. (Note that this essentially
 * restricts access to the replication context to the replication
 * feature's prep and recycle nodes.)
 */
always_inline replication_context_t *
replication_get_ctx (vlib_buffer_t * b0)
{
  replication_main_t *rm = &replication_main;

  return replication_is_recycled (b0) ?
    pool_elt_at_index (rm->contexts[vlib_get_thread_index ()],
		       b0->recycle_count) : 0;
}

/* Prefetch the replication context for this buffer, if it exists */
always_inline void
replication_prefetch_ctx (vlib_buffer_t * b0)
{
  replication_context_t *ctx = replication_get_ctx (b0);

  if (ctx)
    {
      CLIB_PREFETCH (ctx, (2 * CLIB_CACHE_LINE_BYTES), STORE);
    }
}

replication_context_t *replication_prep (vlib_main_t * vm,
					 vlib_buffer_t * b0,
					 u32 recycle_node_index,
					 u32 l2_packet);

replication_context_t *replication_recycle (vlib_main_t * vm,
					    vlib_buffer_t * b0, u32 is_last);


#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
