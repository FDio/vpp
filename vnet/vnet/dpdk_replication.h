#ifndef __included_dpdk_replication_h__
#define __included_dpdk_replication_h__
#include <vnet/devices/dpdk/dpdk.h>

/*
 * vlib_dpdk_clone_buffer - clone a buffer
 * for port mirroring, lawful intercept, etc.
 * rte_pktmbuf_clone (...) requires that the forwarding path
 * not touch any of the cloned data. The hope is that we'll
 * figure out how to relax that restriction.
 *
 * For the moment, copy packet data.
 */

static inline vlib_buffer_t *
vlib_dpdk_clone_buffer (vlib_main_t * vm, vlib_buffer_t * b)
{
  u32 new_buffers_needed = 1;
  unsigned socket_id = rte_socket_id ();
  struct rte_mempool *rmp = vm->buffer_main->pktmbuf_pools[socket_id];
  struct rte_mbuf *rte_mbufs[5];
  vlib_buffer_free_list_t *fl;
  vlib_buffer_t *rv;
  u8 *copy_src, *copy_dst;
  vlib_buffer_t *src_buf, *dst_buf;

  fl = vlib_buffer_get_free_list (vm, VLIB_BUFFER_DEFAULT_FREE_LIST_INDEX);

  if (PREDICT_FALSE (b->flags & VLIB_BUFFER_NEXT_PRESENT))
    {
      vlib_buffer_t *tmp = b;
      int i;

      while (tmp->flags & VLIB_BUFFER_NEXT_PRESENT)
	{
	  new_buffers_needed++;
	  tmp = vlib_get_buffer (vm, tmp->next_buffer);
	}

      /* Should never happen... */
      if (PREDICT_FALSE (new_buffers_needed > ARRAY_LEN (rte_mbufs)))
	{
	  clib_warning ("need %d buffers", new_buffers_needed);
	  return 0;
	}

      if (rte_mempool_get_bulk (rmp, (void **) rte_mbufs,
				new_buffers_needed) < 0)
	return 0;

      src_buf = b;
      rv = dst_buf = vlib_buffer_from_rte_mbuf (rte_mbufs[0]);
      vlib_buffer_init_for_free_list (dst_buf, fl);
      copy_src = b->data + src_buf->current_data;
      copy_dst = dst_buf->data + src_buf->current_data;

      for (i = 0; i < new_buffers_needed; i++)
	{
	  clib_memcpy (copy_src, copy_dst, src_buf->current_length);
	  dst_buf->current_data = src_buf->current_data;
	  dst_buf->current_length = src_buf->current_length;
	  dst_buf->flags = src_buf->flags;

	  if (i == 0)
	    {
	      dst_buf->total_length_not_including_first_buffer =
		src_buf->total_length_not_including_first_buffer;
	      vnet_buffer (dst_buf)->sw_if_index[VLIB_RX] =
		vnet_buffer (src_buf)->sw_if_index[VLIB_RX];
	      vnet_buffer (dst_buf)->sw_if_index[VLIB_TX] =
		vnet_buffer (src_buf)->sw_if_index[VLIB_TX];
	      vnet_buffer (dst_buf)->l2 = vnet_buffer (b)->l2;
	    }

	  if (i < new_buffers_needed - 1)
	    {
	      src_buf = vlib_get_buffer (vm, src_buf->next_buffer);
	      dst_buf = vlib_buffer_from_rte_mbuf (rte_mbufs[i + 1]);
	      vlib_buffer_init_for_free_list (dst_buf, fl);
	      copy_src = src_buf->data;
	      copy_dst = dst_buf->data;
	    }
	}
      return rv;
    }

  if (rte_mempool_get_bulk (rmp, (void **) rte_mbufs, 1) < 0)
    return 0;

  rte_pktmbuf_refcnt_update (rte_mbufs[0], 1);
  rv = vlib_buffer_from_rte_mbuf (rte_mbufs[0]);
  vlib_buffer_init_for_free_list (rv, fl);

  clib_memcpy (rv->data + b->current_data, b->data + b->current_data,
	       b->current_length);
  rv->current_data = b->current_data;
  rv->current_length = b->current_length;
  vnet_buffer (rv)->sw_if_index[VLIB_RX] =
    vnet_buffer (b)->sw_if_index[VLIB_RX];
  vnet_buffer (rv)->sw_if_index[VLIB_TX] =
    vnet_buffer (b)->sw_if_index[VLIB_TX];
  vnet_buffer (rv)->l2 = vnet_buffer (b)->l2;

  return (rv);
}


#endif /* __included_dpdk_replication_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
