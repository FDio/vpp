/* SPDX-License-Identifier: BSD-3-Clause AND Apache-2.0
 * Copyright (c) 2025 Marvell.
 * Copyright (c) 2024 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>
#include <vnet/dev/dev.h>
#include <vnet/ethernet/ethernet.h>
#include <vppinfra/vector/mask_compare.h>
#include <vppinfra/vector/compress.h>

#include <pp2/pp2.h>
#include <pp2/pp2_hw.h>

static_always_inline u32
mvpp2_rx_reg_read (uintptr_t hif_base, u32 reg)
{
  u32 value = __atomic_load_n ((u32 *) (hif_base + reg), __ATOMIC_RELAXED);

  asm volatile ("dsb ld" : : : "memory");
  return value;
}

static_always_inline void
mvpp2_rx_reg_write_relaxed (uintptr_t hif_base, u32 reg, u32 value)
{
  __atomic_store_n ((u32 *) (hif_base + reg), value, __ATOMIC_RELAXED);
}

static_always_inline void
mvpp2_rx_reg_write (uintptr_t hif_base, u32 reg, u32 value)
{
  asm volatile ("dsb st" : : : "memory");
  mvpp2_rx_reg_write_relaxed (hif_base, reg, value);
}

static_always_inline u64
mvpp2_rx_desc_get_cookie (mvpp2_rx_desc_t *desc)
{
  return ((u64) desc->buf_virt_ptr_hi << 32) | desc->buf_virt_ptr_lo;
}

static_always_inline u16
mvpp2_rx_desc_get_pkt_len (mvpp2_rx_desc_t *desc)
{
  return desc->byte_count - MV_MH_SIZE;
}

static_always_inline vlib_buffer_t *
desc_to_vlib_buffer (vlib_main_t *vm, mvpp2_rx_desc_t *d)
{
  return vlib_get_buffer (vm, mvpp2_rx_desc_get_cookie (d));
}

static_always_inline u64
mrvl_pp2_rx_one_if (vlib_main_t *vm, vlib_node_runtime_t *node,
		    vnet_dev_rx_queue_if_rt_data_t *if_rt_data, mvpp2_rx_desc_t **desc_ptrs,
		    u32 n_desc, i32 current_data, i32 len_adj, mv_dsa_tag_t tag)
{
  vnet_main_t *vnm = vnet_get_main ();
  u64 n_rx_bytes = 0;
  vlib_buffer_t *b0, *b1;
  u32 n_trace, n_left = n_desc;
  u32 buffer_indices[VLIB_FRAME_SIZE], *bi = buffer_indices;
  mvpp2_rx_desc_t **dp = desc_ptrs;
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
      bi[0] = mvpp2_rx_desc_get_cookie (dp[0]);
      bi[1] = mvpp2_rx_desc_get_cookie (dp[1]);
      b0->template = bt;
      b1->template = bt;

      n_rx_bytes += b0->current_length = mvpp2_rx_desc_get_pkt_len (dp[0]) + len_adj;
      n_rx_bytes += b1->current_length = mvpp2_rx_desc_get_pkt_len (dp[1]) + len_adj;
    }

  for (; n_left; dp++, bi++, n_left--)
    {
      b0 = desc_to_vlib_buffer (vm, dp[0]);
      bi[0] = mvpp2_rx_desc_get_cookie (dp[0]);
      b0->template = bt;

      n_rx_bytes += b0->current_length = mvpp2_rx_desc_get_pkt_len (dp[0]) + len_adj;
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
  u32 desc_index;
  u32 i;

  if (n_desc > mrq->desc_received)
    {
      mrq->desc_received = mvpp2_rx_reg_read (mp->hif_base, MVPP2_RXQ_STATUS_REG (mrq->hw_id)) &
			   MVPP2_RXQ_OCCUPIED_MASK;
      n_desc = clib_min (n_desc, mrq->desc_received);
    }

  desc_index = mrq->desc_next_idx;
  for (i = 0; i < n_desc; i++)
    {
      mrq->desc_ptrs[i] = mrq->hw_descs + desc_index;
      if (++desc_index == mrq->desc_total)
	desc_index = 0;
    }
  mrq->desc_next_idx = desc_index;

  if (mp->is_dsa)
    {
      for (i = 0; i < n_desc; i++)
	{
	  b = desc_to_vlib_buffer (vm, mrq->desc_ptrs[i]);
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
	  mvpp2_rx_desc_t *sel_descs[VLIB_FRAME_SIZE];
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
		buffer_indices[n_free++] = mvpp2_rx_desc_get_cookie (mrq->desc_ptrs[i]);

	      u32 n_trace = vlib_get_trace_count (vm, node);
	      if (PREDICT_FALSE (n_trace > 0))
		{
		  foreach_vlib_frame_bitmap_set_bit_index (i, selected_bmp)
		    {
		      vlib_buffer_t *b = desc_to_vlib_buffer (vm, mrq->desc_ptrs[i]);

		      if (PREDICT_TRUE (vlib_trace_buffer (
			    vm, node, VNET_DEV_ETH_RX_PORT_NEXT_DROP, b,
			    /* follow_chain */ 0)))
			{
			  mvpp2_rx_trace_t *tr = vlib_add_trace (vm, node, b, sizeof (*tr));
			  tr->desc = *mrq->desc_ptrs[i];
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

  mvpp2_rx_reg_write (mp->hif_base, MVPP2_RXQ_STATUS_UPDATE_REG (mrq->hw_id),
		      n_desc | (n_desc << MVPP2_RXQ_NUM_NEW_OFFSET));
  mrq->desc_received -= n_desc;
  mrq->n_bpool_refill += n_desc;
  return n_desc;
}

static_always_inline u32
mrvl_pp2_bpool_put (vlib_main_t *vm, u32 node_index, vnet_dev_rx_queue_t *rxq)
{
  mvpp2_device_t *md = vnet_dev_get_data (rxq->port->dev);
  mvpp2_rxq_t *mrq = vnet_dev_get_rx_queue_data (rxq);
  mvpp2_tx_desc_t desc = mrq->bpool_desc_template;
  mvpp2_dev_thread_t *thread = md->threads + vm->thread_index;
  mvpp2_dm_if_t *dm_if = &thread->dm_if;
  u32 *desc_rsrvd = md->lbk_desc_rsrvd + vm->thread_index;
  uintptr_t hif = thread->hif_base;
  const u32 batch_size = MRVL_PP2_BUFF_BATCH_SZ;
  u32 free_count = dm_if->free_count;
  u32 desc_total = dm_if->desc_total;
  u32 desc_next_idx = dm_if->desc_next_idx;
  u32 buffer_indices[batch_size];
  vlib_buffer_t *buffers[batch_size];
  u8 buffer_pool_index = vnet_dev_get_rx_queue_buffer_pool_index (rxq);
  u32 n_desc;
  u32 i, n_put = 0;

  if (mrq->n_bpool_refill < batch_size)
    return 0;

  if (free_count < mrq->n_bpool_refill)
    {
      u32 occ_desc = mvpp2_rx_reg_read (hif, MVPP2_AGGR_TXQ_STATUS_REG (thread->hif_id));
      free_count = desc_total - (occ_desc & MVPP2_AGGR_TXQ_PENDING_MASK);
    }

  n_desc = clib_min (mrq->n_bpool_refill, free_count);

  if (n_desc >= batch_size && *desc_rsrvd < n_desc)
    {
      u32 val = clib_max (n_desc - *desc_rsrvd, MVPP2_CPU_DESC_CHUNK);

      val |= MVPP2_LOOPBACK_TXQ_ID << MVPP2_TXQ_RSVD_REQ_Q_OFFSET;
      mvpp2_rx_reg_write_relaxed (hif, MVPP2_TXQ_RSVD_REQ_REG, val);
      asm volatile ("dsb sy" : : : "memory");
      val = mvpp2_rx_reg_read (hif, MVPP2_TXQ_RSVD_RSLT_REG);
      val &= MVPP2_TXQ_RSVD_RSLT_MASK;
      val += *desc_rsrvd;
      *desc_rsrvd = val;
      n_desc = clib_min (n_desc, val);
    }

  for (; n_desc >= batch_size; n_desc -= batch_size)
    {
      if (PREDICT_FALSE (!vlib_buffer_strict_alloc_from_pool (vm, buffer_indices, batch_size,
							      buffer_pool_index)))
	{
	  vlib_error_count (vm, node_index, MVPP2_RX_NODE_CTR_BUFFER_ALLOC, 1);
	  break;
	}

      vlib_get_buffers (vm, buffer_indices, buffers, batch_size);

      for (i = 0; i < batch_size; i++)
	{
	  u64 addr = vlib_buffer_get_pa (vm, buffers[i]) - 64;

	  desc.cmds[4] = addr;
	  desc.cmds[5] = addr >> 32 & TXD_BUF_PHYS_HI_MASK;
	  desc.cmds[6] = buffer_indices[i];
	  dm_if->descs[desc_next_idx] = desc;
	  if (++desc_next_idx == desc_total)
	    desc_next_idx = 0;
	}
      n_put += batch_size;
    }

  *desc_rsrvd -= n_put;
  dm_if->free_count = free_count - n_put;
  dm_if->desc_next_idx = desc_next_idx;

  if (n_put)
    mvpp2_rx_reg_write (hif, MVPP2_AGGR_TXQ_UPDATE_REG, n_put);

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
