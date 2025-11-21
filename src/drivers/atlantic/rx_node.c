/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Damjan Marion
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <atlantic.h>

VNET_DEV_NODE_FN (atl_rx_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  vnet_dev_rx_node_runtime_t *rtd = vnet_dev_get_rx_node_runtime (node);
  vnet_dev_rx_queue_t *rxq = rtd->first_rx_queue;
  atl_rxq_t *aq = vnet_dev_get_rx_queue_data (rxq);
  atl_rx_desc_t *d = aq->descs + aq->next_index;
  u32 n_desc = 0;
  u32 hw_head;
  u32 hw_tail;
  u32 len_reg;
  u32 cache_init_done;
  u32 base_l;
  u32 base_h;
  u32 data_size;
  u32 reg_tail;
  u32 buf_lo;
  u32 buf_hi;
  static f64 last_log_time;

  while ((d->status & 1) && n_desc < VLIB_FRAME_SIZE) /* DD bit set */
    {
      fformat (stderr, "RX desc: %U\n", format_atl_rx_desc, d, 0);
      d->status = 0; /* clear DD bit for next use (simulated) */

      /* Move to next descriptor */
      aq->next_index++;
      if (aq->next_index >= rxq->size)
	aq->next_index = 0;
      d = aq->descs + aq->next_index;
      n_desc++;
    }

  if (n_desc == 0)
    {
      f64 now = vlib_time_now (vm);

      if (now - last_log_time > 0.5)
	{
	  hw_head = atl_reg_rd_u32 (rxq->port->dev, ATL_REG_RX_DMA_DESC_HEAD_PTR (rxq->queue_id));
	  hw_tail = __atomic_load_n (aq->tail_reg, __ATOMIC_RELAXED);
	  len_reg = atl_reg_rd_u32 (rxq->port->dev, ATL_REG_RX_DMA_DESC_LEN (rxq->queue_id));
	  cache_init_done =
	    atl_reg_rd_u32 (rxq->port->dev, ATL_REG_RDM_RX_DMA_DESC_CACHE_INIT_DONE);
	  base_l =
	    atl_reg_rd_u32 (rxq->port->dev, ATL_REG_RX_DMA_DESC_BASE_ADDRLSW (rxq->queue_id));
	  base_h =
	    atl_reg_rd_u32 (rxq->port->dev, ATL_REG_RX_DMA_DESC_BASE_ADDRMSW (rxq->queue_id));
	  data_size = atl_reg_rd_u32 (rxq->port->dev,
				      ATL_REG_RX_DMA_DESC_BASE_ADDRLSW (rxq->queue_id) + 0x18);
	  u32 drop_cnt = atl_reg_rd_u32 (rxq->port->dev, ATL_REG_RPB_RX_DMA_DROP_PKT_CNT);
	  reg_tail = atl_reg_rd_u32 (rxq->port->dev, ATL_REG_RX_DMA_DESC_TAIL_PTR (rxq->queue_id));
	  u32 reg_stat =
	    atl_reg_rd_u32 (rxq->port->dev, ATL_REG_RX_DMA_DESC_STAT0 + rxq->queue_id * 0x20);
	  buf_lo = d->buf_addr;
	  buf_hi = d->buf_addr >> 32;

	  if (hw_head)
	    fformat (stderr,
		     "RX poll: no DD, next %u hw_head %u hw_tail %u status 0x%04x "
		     "len 0x%08x cache_done %u base %08x:%08x data_sz 0x%08x "
		     "drop %u reg_tail %u reg_stat 0x%08x buf %08x:%08x\n",
		     aq->next_index, hw_head, hw_tail, d->status, len_reg, cache_init_done, base_h,
		     base_l, data_size, drop_cnt, reg_tail, reg_stat, buf_hi, buf_lo);
	  last_log_time = now;
	}
    }

  return n_desc;
}
