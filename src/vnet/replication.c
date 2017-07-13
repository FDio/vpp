/*
 * replication.c : packet replication
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

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vppinfra/error.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/replication.h>


replication_main_t replication_main;


replication_context_t *
replication_prep (vlib_main_t * vm,
		  vlib_buffer_t * b0, u32 recycle_node_index, u32 l2_packet)
{
  replication_main_t *rm = &replication_main;
  replication_context_t *ctx;
  uword thread_index = vm->thread_index;
  ip4_header_t *ip;
  u32 ctx_id;

  /* Allocate a context, reserve context 0 */
  if (PREDICT_FALSE (rm->contexts[thread_index] == 0))
    pool_get_aligned (rm->contexts[thread_index], ctx, CLIB_CACHE_LINE_BYTES);

  pool_get_aligned (rm->contexts[thread_index], ctx, CLIB_CACHE_LINE_BYTES);
  ctx_id = ctx - rm->contexts[thread_index];

  /* Save state from vlib buffer */
  ctx->saved_free_list_index = vlib_buffer_get_free_list_index (b0);
  ctx->current_data = b0->current_data;

  /* Set up vlib buffer hooks */
  b0->recycle_count = ctx_id;
  vlib_buffer_set_free_list_index (b0, rm->recycle_list_index);
  b0->flags |= VLIB_BUFFER_RECYCLE;

  /* Save feature state */
  ctx->recycle_node_index = recycle_node_index;

  /* Save vnet state */
  clib_memcpy (ctx->vnet_buffer, vnet_buffer (b0),
	       sizeof (vnet_buffer_opaque_t));

  /* Save packet contents */
  ctx->l2_packet = l2_packet;
  ip = (ip4_header_t *) vlib_buffer_get_current (b0);
  if (l2_packet)
    {
      /* Save ethernet header */
      ctx->l2_header[0] = ((u64 *) ip)[0];
      ctx->l2_header[1] = ((u64 *) ip)[1];
      ctx->l2_header[2] = ((u64 *) ip)[2];
      /* set ip to the true ip header */
      ip = (ip4_header_t *) (((u8 *) ip) + vnet_buffer (b0)->l2.l2_len);
    }

  /*
   * Copy L3 fields.
   * We need to save TOS for ip4 and ip6 packets.
   * Fortunately the TOS field is
   * in the first two bytes of both the ip4 and ip6 headers.
   */
  ctx->ip_tos = *((u16 *) (ip));

  /*
   * Save the ip4 checksum as well. We just blindly save the corresponding two
   * bytes even for ip6 packets.
   */
  ctx->ip4_checksum = ip->checksum;

  return ctx;
}


replication_context_t *
replication_recycle (vlib_main_t * vm, vlib_buffer_t * b0, u32 is_last)
{
  replication_main_t *rm = &replication_main;
  replication_context_t *ctx;
  uword thread_index = vm->thread_index;
  ip4_header_t *ip;

  /* Get access to the replication context */
  ctx = pool_elt_at_index (rm->contexts[thread_index], b0->recycle_count);

  /* Restore vnet buffer state */
  clib_memcpy (vnet_buffer (b0), ctx->vnet_buffer,
	       sizeof (vnet_buffer_opaque_t));

  /* Restore the packet start (current_data) and length */
  vlib_buffer_advance (b0, ctx->current_data - b0->current_data);

  /* Restore packet contents */
  ip = (ip4_header_t *) vlib_buffer_get_current (b0);
  if (ctx->l2_packet)
    {
      /* Restore ethernet header */
      ((u64 *) ip)[0] = ctx->l2_header[0];
      ((u64 *) ip)[1] = ctx->l2_header[1];
      ((u64 *) ip)[2] = ctx->l2_header[2];
      /* set ip to the true ip header */
      ip = (ip4_header_t *) (((u8 *) ip) + vnet_buffer (b0)->l2.l2_len);
    }

  // Restore L3 fields
  *((u16 *) (ip)) = ctx->ip_tos;
  ip->checksum = ctx->ip4_checksum;

  if (is_last)
    {
      /*
       * This is the last replication in the list.
       * Restore original buffer free functionality.
       */
      vlib_buffer_set_free_list_index (b0, ctx->saved_free_list_index);
      b0->flags &= ~VLIB_BUFFER_RECYCLE;

      /* Free context back to its pool */
      pool_put (rm->contexts[thread_index], ctx);
    }

  return ctx;
}



/*
 * fish pkts back from the recycle queue/freelist
 * un-flatten the context chains
 */
static void
replication_recycle_callback (vlib_main_t * vm, vlib_buffer_free_list_t * fl)
{
  vlib_frame_t *f = 0;
  u32 n_left_from;
  u32 n_left_to_next = 0;
  u32 n_this_frame = 0;
  u32 *from;
  u32 *to_next = 0;
  u32 bi0, pi0;
  vlib_buffer_t *b0;
  int i;
  replication_main_t *rm = &replication_main;
  replication_context_t *ctx;
  u32 feature_node_index = 0;
  uword thread_index = vm->thread_index;

  /*
   * All buffers in the list are destined to the same recycle node.
   * Pull the recycle node index from the first buffer.
   * Note: this could be sped up if the node index were stuffed into
   * the freelist itself.
   */
  if (vec_len (fl->buffers) > 0)
    {
      bi0 = fl->buffers[0];
      b0 = vlib_get_buffer (vm, bi0);
      ctx = pool_elt_at_index (rm->contexts[thread_index], b0->recycle_count);
      feature_node_index = ctx->recycle_node_index;
    }

  /* buffers */
  for (i = 0; i < 2; i++)
    {
      if (i == 0)
	{
	  from = fl->buffers;
	  n_left_from = vec_len (from);
	}

      while (n_left_from > 0)
	{
	  if (PREDICT_FALSE (n_left_to_next == 0))
	    {
	      if (f)
		{
		  f->n_vectors = n_this_frame;
		  vlib_put_frame_to_node (vm, feature_node_index, f);
		}

	      f = vlib_get_frame_to_node (vm, feature_node_index);
	      to_next = vlib_frame_vector_args (f);
	      n_left_to_next = VLIB_FRAME_SIZE;
	      n_this_frame = 0;
	    }

	  bi0 = from[0];
	  if (PREDICT_TRUE (n_left_from > 1))
	    {
	      pi0 = from[1];
	      vlib_prefetch_buffer_with_index (vm, pi0, LOAD);
	    }

	  b0 = vlib_get_buffer (vm, bi0);

	  /* Mark that this buffer was just recycled */
	  b0->flags |= VLIB_BUFFER_IS_RECYCLED;

#if (CLIB_DEBUG > 0)
	  if (vm->buffer_main->callbacks_registered == 0)
	    vlib_buffer_set_known_state (vm, bi0,
					 VLIB_BUFFER_KNOWN_ALLOCATED);
#endif

	  /* If buffer is traced, mark frame as traced */
	  if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	    f->flags |= VLIB_FRAME_TRACE;

	  to_next[0] = bi0;

	  from++;
	  to_next++;
	  n_this_frame++;
	  n_left_to_next--;
	  n_left_from--;
	}
    }

  vec_reset_length (fl->buffers);

  if (f)
    {
      ASSERT (n_this_frame);
      f->n_vectors = n_this_frame;
      vlib_put_frame_to_node (vm, feature_node_index, f);
    }
}

clib_error_t *
replication_init (vlib_main_t * vm)
{
  replication_main_t *rm = &replication_main;
  vlib_buffer_main_t *bm = vm->buffer_main;
  vlib_buffer_free_list_t *fl;
  __attribute__ ((unused)) replication_context_t *ctx;
  vlib_thread_main_t *tm = vlib_get_thread_main ();

  rm->vlib_main = vm;
  rm->vnet_main = vnet_get_main ();
  rm->recycle_list_index =
    vlib_buffer_create_free_list (vm, 1024 /* fictional */ ,
				  "replication-recycle");

  fl = pool_elt_at_index (bm->buffer_free_list_pool, rm->recycle_list_index);

  fl->buffers_added_to_freelist_function = replication_recycle_callback;

  /* Verify the replication context is the expected size */
  ASSERT (sizeof (replication_context_t) == 128);	/* 2 cache lines */

  vec_validate (rm->contexts, tm->n_vlib_mains - 1);
  return 0;
}

VLIB_INIT_FUNCTION (replication_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
