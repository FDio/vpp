/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>
#include <vnet/dev/dev.h>
#include <vnet/ethernet/ethernet.h>
#include <vppinfra/vector/mask_compare.h>
#include <vppinfra/vector/compress.h>

#include <dev_armada/pp2/pp2.h>

static_always_inline vlib_buffer_t *
desc_to_vlib_buffer (vlib_main_t *vm, struct pp2_ppio_desc *d)
{
  return vlib_get_buffer (vm, pp2_ppio_inq_desc_get_cookie (d));
}

static_always_inline u64
mrvl_pp2_rx_one_if (vlib_main_t *vm, vlib_node_runtime_t *node,
		    vnet_dev_rx_queue_if_rt_data_t *if_rt_data,
		    struct pp2_ppio_desc **desc_ptrs, u32 n_desc,
		    i32 current_data, i32 len_adj, mv_dsa_tag_t tag)
{
  vnet_main_t *vnm = vnet_get_main ();
  u64 n_rx_bytes = 0;
  vlib_buffer_t *b0, *b1;
  u32 n_trace, n_left = n_desc;
  u32 buffer_indices[VLIB_FRAME_SIZE], *bi = buffer_indices;
  struct pp2_ppio_desc **dp = desc_ptrs;
  u32 next_index = if_rt_data->next_index;
  vlib_buffer_template_t bt = if_rt_data->buffer_template;
  u32 sw_if_index = if_rt_data->sw_if_index;

  bt.current_data = current_data;

  for (; n_left >= 4; dp += 2, bi += 2, n_left -= 2)
    {
      clib_prefetch_store (desc_to_vlib_buffer (vm, dp[2]));
      clib_prefetch_store (desc_to_vlib_buffer (vm, dp[3]));
      b0 = desc_to_vlib_buffer (vm, dp[0]);
      b1 = desc_to_vlib_buffer (vm, dp[1]);
      bi[0] = pp2_ppio_inq_desc_get_cookie (dp[0]);
      bi[1] = pp2_ppio_inq_desc_get_cookie (dp[1]);
      b0->template = bt;
      b1->template = bt;

      n_rx_bytes += b0->current_length =
	pp2_ppio_inq_desc_get_pkt_len (dp[0]) + len_adj;
      n_rx_bytes += b1->current_length =
	pp2_ppio_inq_desc_get_pkt_len (dp[1]) + len_adj;
    }

  for (; n_left; dp++, bi++, n_left--)
    {
      b0 = desc_to_vlib_buffer (vm, dp[0]);
      bi[0] = pp2_ppio_inq_desc_get_cookie (dp[0]);
      b0->template = bt;

      n_rx_bytes += b0->current_length =
	pp2_ppio_inq_desc_get_pkt_len (dp[0]) + len_adj;
    }

  /* trace */
  n_trace = vlib_get_trace_count (vm, node);
  if (PREDICT_FALSE (n_trace > 0))
    {
      for (u32 i = 0; i < n_desc && n_trace > 0; i++)
	{
	  vlib_buffer_t *b = desc_to_vlib_buffer (vm, desc_ptrs[i]);
	  if (PREDICT_TRUE (vlib_trace_buffer (vm, node, next_index, b,
					       /* follow_chain */ 0)))
	    {
	      mvpp2_rx_trace_t *tr;
	      tr = vlib_add_trace (vm, node, b, sizeof (*tr));
	      tr->desc = *desc_ptrs[i];
	      tr->next_index = next_index;
	      tr->sw_if_index = sw_if_index;
	      tr->dsa_tag = tag;
	      n_trace--;
	    }
	}
      vlib_set_trace_count (vm, node, n_trace);
    }
  vlib_buffer_enqueue_to_single_next (vm, node, buffer_indices, next_index,
				      n_desc);

  vlib_increment_combined_counter (
    vnm->interface_main.combined_sw_if_counters + VNET_INTERFACE_COUNTER_RX,
    vm->thread_index, sw_if_index, n_desc, n_rx_bytes);

  return n_rx_bytes;
}

static_always_inline uword
mrvl_pp2_rx_inline (vlib_main_t *vm, vlib_node_runtime_t *node,
		    vnet_dev_rx_queue_t *rxq)
{
  vnet_dev_port_t *port = rxq->port;
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  mvpp2_rxq_t *mrq = vnet_dev_get_rx_queue_data (rxq);
  mv_dsa_tag_t dsa_tags[VLIB_FRAME_SIZE];
  u16 n_desc = VLIB_FRAME_SIZE;
  vlib_buffer_t *b;
  u32 i;

  if (PREDICT_FALSE (
	pp2_ppio_recv (mp->ppio, 0, rxq->queue_id, mrq->descs, &n_desc)))
    {
      vlib_error_count (vm, node->node_index, MVPP2_RX_NODE_CTR_PPIO_RECV, 1);
      return 0;
    }

  if (mp->is_dsa)
    {
      for (i = 0; i < n_desc; i++)
	{
	  b = desc_to_vlib_buffer (vm, mrq->descs + i);
	  u8 *start = b->data;
	  mv_dsa_tag_t tag = mv_dsa_tag_read (start + 14);
	  dsa_tags[i] = tag;
	  clib_memmove (start + 6, start + 2, 12);
	}

      vlib_frame_bitmap_t avail_bmp = {};
      vlib_frame_bitmap_init (avail_bmp, n_desc);
      u32 n_avail = n_desc;

      while (n_avail)
	{
	  vlib_frame_bitmap_t selected_bmp = {};
	  struct pp2_ppio_desc *sel_descs[VLIB_FRAME_SIZE];
	  mv_dsa_tag_t tag;
	  u32 n_sel, index;

	  tag = dsa_tags[vlib_frame_bitmap_find_first_set (avail_bmp)];
	  index = tag.src_dev << 5 | tag.src_port_or_lag;

	  clib_mask_compare_u32 (tag.as_u32, (u32 *) dsa_tags, selected_bmp,
				 n_desc);
	  n_sel = vlib_frame_bitmap_count_set_bits (selected_bmp);
	  n_avail -= n_sel;
	  vlib_frame_bitmap_xor (avail_bmp, selected_bmp);

	  if (uword_bitmap_is_bit_set (mp->valid_dsa_src_bitmap, index))
	    {
	      clib_compress_u64 ((uword *) sel_descs, (uword *) mrq->desc_ptrs,
				 selected_bmp, n_desc);
	      mrvl_pp2_rx_one_if (vm, node,
				  vnet_dev_get_rx_queue_sec_if_rt_data (
				    rxq, mp->dsa_to_sec_if[index]),
				  sel_descs, n_sel, 6, -4, tag);
	    }
	  else
	    {
	      u32 n_free = 0, buffer_indices[VLIB_FRAME_SIZE];

	      foreach_vlib_frame_bitmap_set_bit_index (i, selected_bmp)
		buffer_indices[n_free++] =
		  pp2_ppio_inq_desc_get_cookie (mrq->descs + i);

	      u32 n_trace = vlib_get_trace_count (vm, node);
	      if (PREDICT_FALSE (n_trace > 0))
		{
		  foreach_vlib_frame_bitmap_set_bit_index (i, selected_bmp)
		    {
		      vlib_buffer_t *b =
			desc_to_vlib_buffer (vm, mrq->descs + i);

		      if (PREDICT_TRUE (vlib_trace_buffer (
			    vm, node, VNET_DEV_ETH_RX_PORT_NEXT_DROP, b,
			    /* follow_chain */ 0)))
			{
			  mvpp2_rx_trace_t *tr;
			  tr = vlib_add_trace (vm, node, b, sizeof (*tr));
			  tr->desc = mrq->descs[i];
			  tr->next_index = VNET_DEV_ETH_RX_PORT_NEXT_DROP;
			  tr->sw_if_index = CLIB_U32_MAX;
			  tr->dsa_tag = dsa_tags[i];
			  n_trace--;
			}
		      if (n_trace == 0)
			break;
		    }
		  vlib_set_trace_count (vm, node, n_trace);
		}

	      vlib_buffer_free (vm, buffer_indices, n_free);
	      vlib_error_count (vm, node->node_index,
				MVPP2_RX_NODE_CTR_UNKNOWN_DSA_SRC, n_free);
	    }
	}
    }
  else
    {
      mrvl_pp2_rx_one_if (vm, node, vnet_dev_get_rx_queue_if_rt_data (rxq),
			  mrq->desc_ptrs, n_desc, 2, 0, (mv_dsa_tag_t){});
    }

  mrq->n_bpool_refill += n_desc;
  return n_desc;
}

static_always_inline u32
mrvl_pp2_bpool_put (vlib_main_t *vm, u32 node_index, vnet_dev_rx_queue_t *rxq)
{
  mvpp2_rxq_t *mrq = vnet_dev_get_rx_queue_data (rxq);
  mvpp2_device_t *md = vnet_dev_get_data (rxq->port->dev);
  struct pp2_hif *hif = md->hif[vm->thread_index];
  struct buff_release_entry *bre = mrq->bre;
  u32 buffer_indices[MRVL_PP2_BUFF_BATCH_SZ];
  vlib_buffer_t *buffers[MRVL_PP2_BUFF_BATCH_SZ];
  u32 i, n_put = 0;
  u32 n_bufs = mrq->n_bpool_refill;

  while (n_bufs >= MRVL_PP2_BUFF_BATCH_SZ)
    {
      u16 n_alloc;
      struct buff_release_entry *e = bre;

      n_alloc = vlib_buffer_alloc (vm, buffer_indices, MRVL_PP2_BUFF_BATCH_SZ);

      if (PREDICT_FALSE (n_alloc < MRVL_PP2_BUFF_BATCH_SZ))
	{
	  if (n_alloc > 0)
	    vlib_buffer_free (vm, buffer_indices, n_alloc);
	  if (node_index != CLIB_U32_MAX)
	    vlib_error_count (vm, node_index, MVPP2_RX_NODE_CTR_BUFFER_ALLOC,
			      1);

	  break;
	}

      vlib_get_buffers (vm, buffer_indices, buffers, MRVL_PP2_BUFF_BATCH_SZ);

      for (i = 0, e = bre; i < MRVL_PP2_BUFF_BATCH_SZ; i++, e++)
	{
	  e->buff.addr = vlib_buffer_get_pa (vm, buffers[i]) - 64;
	  e->buff.cookie = buffer_indices[i];
	}

      if (PREDICT_FALSE (pp2_bpool_put_buffs (hif, bre, &n_alloc)))
	{
	  vlib_buffer_free (vm, buffer_indices, n_alloc);
	  if (node_index != CLIB_U32_MAX)
	    vlib_error_count (vm, node_index,
			      MVPP2_RX_NODE_CTR_BPOOL_PUT_BUFFS, 1);
	  break;
	}

      n_put += MRVL_PP2_BUFF_BATCH_SZ;
      n_bufs -= n_alloc;
    }

  mrq->n_bpool_refill -= n_put;
  return n_put;
}

u32
mrvl_pp2_bpool_put_no_inline (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq)
{
  return mrvl_pp2_bpool_put (vm, CLIB_U32_MAX, rxq);
}

VNET_DEV_NODE_FN (mvpp2_rx_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  u32 n_rx = 0;
  u32 node_index = node->node_index;
  foreach_vnet_dev_rx_queue_runtime (rxq, node)
    {
      n_rx += mrvl_pp2_rx_inline (vm, node, rxq);
      mrvl_pp2_bpool_put (vm, node_index, rxq);
    }
  return n_rx;
}
