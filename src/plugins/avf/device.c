/*
 *------------------------------------------------------------------
 * Copyright (c) 2018 Cisco and/or its affiliates.
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

#include <vlib/vlib.h>
#include <vppinfra/ring.h>
#include <vlib/unix/unix.h>
#include <vlib/pci/pci.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/interface/rx_queue_funcs.h>
#include <vnet/interface/tx_queue_funcs.h>

#include <avf/avf.h>

#define AVF_MBOX_LEN 64
#define AVF_MBOX_BUF_SZ 4096
#define AVF_RXQ_SZ 512
#define AVF_TXQ_SZ 512
#define AVF_ITR_INT 250

#define PCI_VENDOR_ID_INTEL			0x8086
#define PCI_DEVICE_ID_INTEL_AVF			0x1889
#define PCI_DEVICE_ID_INTEL_X710_VF		0x154c
#define PCI_DEVICE_ID_INTEL_X722_VF		0x37cd

VLIB_REGISTER_LOG_CLASS (avf_log) = {
  .class_name = "avf",
};

VLIB_REGISTER_LOG_CLASS (avf_stats_log) = {
  .class_name = "avf",
  .subclass_name = "stats",
};

avf_main_t avf_main;
void avf_delete_if (vlib_main_t * vm, avf_device_t * ad, int with_barrier);

static pci_device_id_t avf_pci_device_ids[] = {
  {.vendor_id = PCI_VENDOR_ID_INTEL,.device_id = PCI_DEVICE_ID_INTEL_AVF},
  {.vendor_id = PCI_VENDOR_ID_INTEL,.device_id = PCI_DEVICE_ID_INTEL_X710_VF},
  {.vendor_id = PCI_VENDOR_ID_INTEL,.device_id = PCI_DEVICE_ID_INTEL_X722_VF},
  {0},
};

const static char *virtchnl_event_names[] = {
#define _(v, n) [v] = #n,
  foreach_virtchnl_event_code
#undef _
};

typedef enum
{
  AVF_IRQ_STATE_DISABLED,
  AVF_IRQ_STATE_ENABLED,
  AVF_IRQ_STATE_WB_ON_ITR,
} avf_irq_state_t;

static inline void
avf_irq_0_set_state (avf_device_t * ad, avf_irq_state_t state)
{
  u32 dyn_ctl0 = 0, icr0_ena = 0;

  dyn_ctl0 |= (3 << 3);		/* 11b = No ITR update */

  avf_reg_write (ad, AVFINT_ICR0_ENA1, icr0_ena);
  avf_reg_write (ad, AVFINT_DYN_CTL0, dyn_ctl0);
  avf_reg_flush (ad);

  if (state == AVF_IRQ_STATE_DISABLED)
    return;

  dyn_ctl0 = 0;
  icr0_ena = 0;

  icr0_ena |= (1 << 30);	/* [30] Admin Queue Enable */

  dyn_ctl0 |= (1 << 0);		/* [0] Interrupt Enable */
  dyn_ctl0 |= (1 << 1);		/* [1] Clear PBA */
  dyn_ctl0 |= (2 << 3);		/* [4:3] ITR Index, 11b = No ITR update */
  dyn_ctl0 |= ((AVF_ITR_INT / 2) << 5);	/* [16:5] ITR Interval in 2us steps */

  avf_reg_write (ad, AVFINT_ICR0_ENA1, icr0_ena);
  avf_reg_write (ad, AVFINT_DYN_CTL0, dyn_ctl0);
  avf_reg_flush (ad);
}

static inline void
avf_irq_n_set_state (avf_device_t * ad, u8 line, avf_irq_state_t state)
{
  u32 dyn_ctln = 0;

  /* disable */
  avf_reg_write (ad, AVFINT_DYN_CTLN (line), dyn_ctln);
  avf_reg_flush (ad);

  if (state == AVF_IRQ_STATE_DISABLED)
    return;

  dyn_ctln |= (1 << 1);		/* [1] Clear PBA */
  if (state == AVF_IRQ_STATE_WB_ON_ITR)
    {
      /* minimal ITR interval, use ITR1 */
      dyn_ctln |= (1 << 3);	/* [4:3] ITR Index */
      dyn_ctln |= ((32 / 2) << 5);	/* [16:5] ITR Interval in 2us steps */
      dyn_ctln |= (1 << 30);	/* [30] Writeback on ITR */
    }
  else
    {
      /* configured ITR interval, use ITR0 */
      dyn_ctln |= (1 << 0);	/* [0] Interrupt Enable */
      dyn_ctln |= ((AVF_ITR_INT / 2) << 5);	/* [16:5] ITR Interval in 2us steps */
    }

  avf_reg_write (ad, AVFINT_DYN_CTLN (line), dyn_ctln);
  avf_reg_flush (ad);
}


clib_error_t *
avf_aq_desc_enq (vlib_main_t * vm, avf_device_t * ad, avf_aq_desc_t * dt,
		 void *data, int len)
{
  clib_error_t *err = 0;
  avf_aq_desc_t *d, dc;
  f64 t0, suspend_time = AVF_AQ_ENQ_SUSPEND_TIME;

  d = &ad->atq[ad->atq_next_slot];
  clib_memcpy_fast (d, dt, sizeof (avf_aq_desc_t));
  d->flags |= AVF_AQ_F_RD | AVF_AQ_F_SI;
  if (len)
    d->datalen = len;
  if (len)
    {
      u64 pa;
      pa = ad->atq_bufs_pa + ad->atq_next_slot * AVF_MBOX_BUF_SZ;
      d->addr_hi = (u32) (pa >> 32);
      d->addr_lo = (u32) pa;
      clib_memcpy_fast (ad->atq_bufs + ad->atq_next_slot * AVF_MBOX_BUF_SZ,
			data, len);
      d->flags |= AVF_AQ_F_BUF;
    }

  if (ad->flags & AVF_DEVICE_F_ELOG)
    clib_memcpy_fast (&dc, d, sizeof (avf_aq_desc_t));

  CLIB_MEMORY_BARRIER ();
  ad->atq_next_slot = (ad->atq_next_slot + 1) % AVF_MBOX_LEN;
  avf_reg_write (ad, AVF_ATQT, ad->atq_next_slot);
  avf_reg_flush (ad);

  t0 = vlib_time_now (vm);
retry:
  vlib_process_suspend (vm, suspend_time);

  if (((d->flags & AVF_AQ_F_DD) == 0) || ((d->flags & AVF_AQ_F_CMP) == 0))
    {
      f64 t = vlib_time_now (vm) - t0;
      if (t > AVF_AQ_ENQ_MAX_WAIT_TIME)
	{
	  avf_log_err (ad, "aq_desc_enq failed (timeout %.3fs)", t);
	  err = clib_error_return (0, "adminq enqueue timeout [opcode 0x%x]",
				   d->opcode);
	  goto done;
	}
      suspend_time *= 2;
      goto retry;
    }

  clib_memcpy_fast (dt, d, sizeof (avf_aq_desc_t));
  if (d->flags & AVF_AQ_F_ERR)
    return clib_error_return (0, "adminq enqueue error [opcode 0x%x, retval "
			      "%d]", d->opcode, d->retval);

done:
  if (ad->flags & AVF_DEVICE_F_ELOG)
    {
      ELOG_TYPE_DECLARE (el) =
	{
	  .format = "avf[%d] aq enq: s_flags 0x%x r_flags 0x%x opcode 0x%x "
	    "datalen %d retval %d",
	  .format_args = "i4i2i2i2i2i2",
	};
      struct
	{
	  u32 dev_instance;
	  u16 s_flags;
	  u16 r_flags;
	  u16 opcode;
	  u16 datalen;
	  u16 retval;
	} *ed;
	ed = ELOG_DATA (&vlib_global_main.elog_main, el);
	ed->dev_instance = ad->dev_instance;
	ed->s_flags = dc.flags;
	ed->r_flags = d->flags;
	ed->opcode = dc.opcode;
	ed->datalen = dc.datalen;
	ed->retval = d->retval;
    }

  return err;
}

clib_error_t *
avf_cmd_rx_ctl_reg_write (vlib_main_t * vm, avf_device_t * ad, u32 reg,
			  u32 val)
{
  clib_error_t *err;
  avf_aq_desc_t d = {.opcode = 0x207,.param1 = reg,.param3 = val };
  err = avf_aq_desc_enq (vm, ad, &d, 0, 0);

  if (ad->flags & AVF_DEVICE_F_ELOG)
    {
      ELOG_TYPE_DECLARE (el) =
	{
	  .format = "avf[%d] rx ctl reg write: reg 0x%x val 0x%x ",
	  .format_args = "i4i4i4",
	};
      struct
	{
	  u32 dev_instance;
	  u32 reg;
	  u32 val;
	} *ed;
	ed = ELOG_DATA (&vlib_global_main.elog_main, el);
	ed->dev_instance = ad->dev_instance;
	ed->reg = reg;
	ed->val = val;
    }
  return err;
}

clib_error_t *
avf_rxq_init (vlib_main_t * vm, avf_device_t * ad, u16 qid, u16 rxq_size)
{
  clib_error_t *err;
  avf_rxq_t *rxq;
  u32 n_alloc, i;

  vec_validate_aligned (ad->rxqs, qid, CLIB_CACHE_LINE_BYTES);
  rxq = vec_elt_at_index (ad->rxqs, qid);
  rxq->size = rxq_size;
  rxq->next = 0;
  rxq->descs = vlib_physmem_alloc_aligned_on_numa (vm, rxq->size *
						   sizeof (avf_rx_desc_t),
						   2 * CLIB_CACHE_LINE_BYTES,
						   ad->numa_node);

  rxq->buffer_pool_index =
    vlib_buffer_pool_get_default_for_numa (vm, ad->numa_node);

  if (rxq->descs == 0)
    return vlib_physmem_last_error (vm);

  if ((err = vlib_pci_map_dma (vm, ad->pci_dev_handle, (void *) rxq->descs)))
    return err;

  clib_memset ((void *) rxq->descs, 0, rxq->size * sizeof (avf_rx_desc_t));
  vec_validate_aligned (rxq->bufs, rxq->size, CLIB_CACHE_LINE_BYTES);
  rxq->qrx_tail = ad->bar0 + AVF_QRX_TAIL (qid);

  n_alloc = vlib_buffer_alloc_from_pool (vm, rxq->bufs, rxq->size - 8,
					 rxq->buffer_pool_index);

  if (n_alloc == 0)
    return clib_error_return (0, "buffer allocation error");

  rxq->n_enqueued = n_alloc;
  avf_rx_desc_t *d = rxq->descs;
  for (i = 0; i < n_alloc; i++)
    {
      vlib_buffer_t *b = vlib_get_buffer (vm, rxq->bufs[i]);
      if (ad->flags & AVF_DEVICE_F_VA_DMA)
	d->qword[0] = vlib_buffer_get_va (b);
      else
	d->qword[0] = vlib_buffer_get_pa (vm, b);
      d++;
    }

  return 0;
}

clib_error_t *
avf_txq_init (vlib_main_t * vm, avf_device_t * ad, u16 qid, u16 txq_size)
{
  clib_error_t *err;
  avf_txq_t *txq;
  u16 n;
  u8 bpi = vlib_buffer_pool_get_default_for_numa (vm,
						  ad->numa_node);

  vec_validate_aligned (ad->txqs, qid, CLIB_CACHE_LINE_BYTES);
  txq = vec_elt_at_index (ad->txqs, qid);
  txq->size = txq_size;
  txq->next = 0;
  clib_spinlock_init (&txq->lock);

  /* Prepare a placeholder buffer(s) to maintain a 1-1 relationship between
   * bufs and descs when a context descriptor is added in descs. Worst case
   * every second descriptor is context descriptor and due to b->ref_count
   * being u8 we need one for each block of 510 descriptors */

  n = (txq->size / 510) + 1;
  vec_validate_aligned (txq->ph_bufs, n, CLIB_CACHE_LINE_BYTES);

  if (!vlib_buffer_alloc_from_pool (vm, txq->ph_bufs, n, bpi))
    return clib_error_return (0, "buffer allocation error");

  txq->descs = vlib_physmem_alloc_aligned_on_numa (vm, txq->size *
						   sizeof (avf_tx_desc_t),
						   2 * CLIB_CACHE_LINE_BYTES,
						   ad->numa_node);
  if (txq->descs == 0)
    return vlib_physmem_last_error (vm);

  if ((err = vlib_pci_map_dma (vm, ad->pci_dev_handle, (void *) txq->descs)))
    return err;

  vec_validate_aligned (txq->bufs, txq->size, CLIB_CACHE_LINE_BYTES);
  txq->qtx_tail = ad->bar0 + AVF_QTX_TAIL (qid);

  /* initialize ring of pending RS slots */
  clib_ring_new_aligned (txq->rs_slots, 32, CLIB_CACHE_LINE_BYTES);

  vec_validate_aligned (txq->tmp_descs, txq->size, CLIB_CACHE_LINE_BYTES);
  vec_validate_aligned (txq->tmp_bufs, txq->size, CLIB_CACHE_LINE_BYTES);

  return 0;
}

typedef struct
{
  u16 vsi_id;
  u16 flags;
} virtchnl_promisc_info_t;

void
avf_arq_slot_init (avf_device_t * ad, u16 slot)
{
  avf_aq_desc_t *d;
  u64 pa = ad->arq_bufs_pa + slot * AVF_MBOX_BUF_SZ;
  d = &ad->arq[slot];
  clib_memset (d, 0, sizeof (avf_aq_desc_t));
  d->flags = AVF_AQ_F_BUF;
  d->datalen = AVF_MBOX_BUF_SZ;
  d->addr_hi = (u32) (pa >> 32);
  d->addr_lo = (u32) pa;
}

static inline uword
avf_dma_addr (vlib_main_t * vm, avf_device_t * ad, void *p)
{
  return (ad->flags & AVF_DEVICE_F_VA_DMA) ?
    pointer_to_uword (p) : vlib_physmem_get_pa (vm, p);
}

static void
avf_adminq_init (vlib_main_t * vm, avf_device_t * ad)
{
  u64 pa;
  int i;

  /* VF MailBox Transmit */
  clib_memset (ad->atq, 0, sizeof (avf_aq_desc_t) * AVF_MBOX_LEN);
  ad->atq_bufs_pa = avf_dma_addr (vm, ad, ad->atq_bufs);

  pa = avf_dma_addr (vm, ad, ad->atq);
  avf_reg_write (ad, AVF_ATQT, 0);	/* Tail */
  avf_reg_write (ad, AVF_ATQH, 0);	/* Head */
  avf_reg_write (ad, AVF_ATQLEN, AVF_MBOX_LEN | (1ULL << 31));	/* len & ena */
  avf_reg_write (ad, AVF_ATQBAL, (u32) pa);	/* Base Address Low */
  avf_reg_write (ad, AVF_ATQBAH, (u32) (pa >> 32));	/* Base Address High */

  /* VF MailBox Receive */
  clib_memset (ad->arq, 0, sizeof (avf_aq_desc_t) * AVF_MBOX_LEN);
  ad->arq_bufs_pa = avf_dma_addr (vm, ad, ad->arq_bufs);

  for (i = 0; i < AVF_MBOX_LEN; i++)
    avf_arq_slot_init (ad, i);

  pa = avf_dma_addr (vm, ad, ad->arq);

  avf_reg_write (ad, AVF_ARQH, 0);	/* Head */
  avf_reg_write (ad, AVF_ARQT, 0);	/* Head */
  avf_reg_write (ad, AVF_ARQLEN, AVF_MBOX_LEN | (1ULL << 31));	/* len & ena */
  avf_reg_write (ad, AVF_ARQBAL, (u32) pa);	/* Base Address Low */
  avf_reg_write (ad, AVF_ARQBAH, (u32) (pa >> 32));	/* Base Address High */
  avf_reg_write (ad, AVF_ARQT, AVF_MBOX_LEN - 1);	/* Tail */

  ad->atq_next_slot = 0;
  ad->arq_next_slot = 0;
}

clib_error_t *
avf_send_to_pf (vlib_main_t * vm, avf_device_t * ad, virtchnl_ops_t op,
		void *in, int in_len, void *out, int out_len)
{
  clib_error_t *err;
  avf_aq_desc_t *d, dt = {.opcode = 0x801,.v_opcode = op };
  u32 head;
  f64 t0, suspend_time = AVF_SEND_TO_PF_SUSPEND_TIME;

  /* adminq operations should be only done from process node after device
   * is initialized */
  ASSERT ((ad->flags & AVF_DEVICE_F_INITIALIZED) == 0 ||
	  vlib_get_current_process_node_index (vm) == avf_process_node.index);

  /* suppress interrupt in the next adminq receive slot
     as we are going to wait for response
     we only need interrupts when event is received */
  d = &ad->arq[ad->arq_next_slot];
  d->flags |= AVF_AQ_F_SI;

  if ((err = avf_aq_desc_enq (vm, ad, &dt, in, in_len)))
    return err;

  t0 = vlib_time_now (vm);
retry:
  head = avf_get_u32 (ad->bar0, AVF_ARQH);

  if (ad->arq_next_slot == head)
    {
      f64 t = vlib_time_now (vm) - t0;
      if (t > AVF_SEND_TO_PF_MAX_WAIT_TIME)
	{
	  avf_log_err (ad, "send_to_pf failed (timeout %.3fs)", t);
	  return clib_error_return (0, "timeout");
	}
      vlib_process_suspend (vm, suspend_time);
      suspend_time *= 2;
      goto retry;
    }

  d = &ad->arq[ad->arq_next_slot];

  if (d->v_opcode == VIRTCHNL_OP_EVENT)
    {
      void *buf = ad->arq_bufs + ad->arq_next_slot * AVF_MBOX_BUF_SZ;
      virtchnl_pf_event_t *e;

      if ((d->datalen != sizeof (virtchnl_pf_event_t)) ||
	  ((d->flags & AVF_AQ_F_BUF) == 0))
	return clib_error_return (0, "event message error");

      vec_add2 (ad->events, e, 1);
      clib_memcpy_fast (e, buf, sizeof (virtchnl_pf_event_t));
      avf_arq_slot_init (ad, ad->arq_next_slot);
      ad->arq_next_slot++;
      /* reset timer */
      t0 = vlib_time_now (vm);
      suspend_time = AVF_SEND_TO_PF_SUSPEND_TIME;
      goto retry;
    }

  if (d->v_opcode != op)
    {
      err = clib_error_return (0,
			       "unexpected message received [v_opcode = %u, "
			       "expected %u, v_retval %d]",
			       d->v_opcode, op, d->v_retval);
      goto done;
    }

  if (d->v_retval)
    {
      err = clib_error_return (0, "error [v_opcode = %u, v_retval %d]",
			       d->v_opcode, d->v_retval);
      goto done;
    }

  if (out_len && d->flags & AVF_AQ_F_BUF)
    {
      void *buf = ad->arq_bufs + ad->arq_next_slot * AVF_MBOX_BUF_SZ;
      clib_memcpy_fast (out, buf, out_len);
    }

  avf_arq_slot_init (ad, ad->arq_next_slot);
  avf_reg_write (ad, AVF_ARQT, ad->arq_next_slot);
  avf_reg_flush (ad);
  ad->arq_next_slot = (ad->arq_next_slot + 1) % AVF_MBOX_LEN;

done:

  if (ad->flags & AVF_DEVICE_F_ELOG)
    {
      ELOG_TYPE_DECLARE (el) =
	{
	  .format = "avf[%d] send to pf: v_opcode %s (%d) v_retval 0x%x",
	  .format_args = "i4t4i4i4",
	  .n_enum_strings = VIRTCHNL_N_OPS,
	  .enum_strings = {
#define _(v, n) [v] = #n,
	      foreach_virtchnl_op
#undef _
	  },
	};
      struct
	{
	  u32 dev_instance;
	  u32 v_opcode;
	  u32 v_opcode_val;
	  u32 v_retval;
	} *ed;
	ed = ELOG_DATA (&vlib_global_main.elog_main, el);
	ed->dev_instance = ad->dev_instance;
	ed->v_opcode = op;
	ed->v_opcode_val = op;
	ed->v_retval = d->v_retval;
    }
  return err;
}

clib_error_t *
avf_op_version (vlib_main_t * vm, avf_device_t * ad,
		virtchnl_version_info_t * ver)
{
  clib_error_t *err = 0;
  virtchnl_version_info_t myver = {
    .major = VIRTCHNL_VERSION_MAJOR,
    .minor = VIRTCHNL_VERSION_MINOR,
  };

  avf_log_debug (ad, "version: major %u minor %u", myver.major, myver.minor);

  err = avf_send_to_pf (vm, ad, VIRTCHNL_OP_VERSION, &myver,
			sizeof (virtchnl_version_info_t), ver,
			sizeof (virtchnl_version_info_t));

  if (err)
    return err;

  return err;
}

clib_error_t *
avf_op_get_vf_resources (vlib_main_t * vm, avf_device_t * ad,
			 virtchnl_vf_resource_t * res)
{
  clib_error_t *err = 0;
  u32 bitmap = (VIRTCHNL_VF_OFFLOAD_L2 | VIRTCHNL_VF_OFFLOAD_RSS_PF |
		VIRTCHNL_VF_OFFLOAD_WB_ON_ITR | VIRTCHNL_VF_OFFLOAD_VLAN |
		VIRTCHNL_VF_OFFLOAD_RX_POLLING |
		VIRTCHNL_VF_CAP_ADV_LINK_SPEED | VIRTCHNL_VF_OFFLOAD_FDIR_PF |
		VIRTCHNL_VF_OFFLOAD_ADV_RSS_PF | VIRTCHNL_VF_OFFLOAD_VLAN_V2);

  avf_log_debug (ad, "get_vf_resources: bitmap 0x%x (%U)", bitmap,
		 format_avf_vf_cap_flags, bitmap);
  err = avf_send_to_pf (vm, ad, VIRTCHNL_OP_GET_VF_RESOURCES, &bitmap,
			sizeof (u32), res, sizeof (virtchnl_vf_resource_t));

  if (err == 0)
    {
      int i;
      avf_log_debug (ad,
		     "get_vf_resources: num_vsis %u num_queue_pairs %u "
		     "max_vectors %u max_mtu %u vf_cap_flags 0x%x (%U) "
		     "rss_key_size %u rss_lut_size %u",
		     res->num_vsis, res->num_queue_pairs, res->max_vectors,
		     res->max_mtu, res->vf_cap_flags, format_avf_vf_cap_flags,
		     res->vf_cap_flags, res->rss_key_size, res->rss_lut_size);
      for (i = 0; i < res->num_vsis; i++)
	avf_log_debug (
	  ad,
	  "get_vf_resources_vsi[%u]: vsi_id %u num_queue_pairs %u vsi_type %u "
	  "qset_handle %u default_mac_addr %U",
	  i, res->vsi_res[i].vsi_id, res->vsi_res[i].num_queue_pairs,
	  res->vsi_res[i].vsi_type, res->vsi_res[i].qset_handle,
	  format_ethernet_address, res->vsi_res[i].default_mac_addr);
    }

  return err;
}

clib_error_t *
avf_op_config_rss_lut (vlib_main_t * vm, avf_device_t * ad)
{
  int msg_len = sizeof (virtchnl_rss_lut_t) + ad->rss_lut_size - 1;
  int i;
  u8 msg[msg_len];
  virtchnl_rss_lut_t *rl;

  clib_memset (msg, 0, msg_len);
  rl = (virtchnl_rss_lut_t *) msg;
  rl->vsi_id = ad->vsi_id;
  rl->lut_entries = ad->rss_lut_size;
  for (i = 0; i < ad->rss_lut_size; i++)
    rl->lut[i] = i % ad->n_rx_queues;

  avf_log_debug (ad, "config_rss_lut: vsi_id %u rss_lut_size %u lut 0x%U",
		 rl->vsi_id, rl->lut_entries, format_hex_bytes_no_wrap,
		 rl->lut, rl->lut_entries);

  return avf_send_to_pf (vm, ad, VIRTCHNL_OP_CONFIG_RSS_LUT, msg, msg_len, 0,
			 0);
}

clib_error_t *
avf_op_config_rss_key (vlib_main_t * vm, avf_device_t * ad)
{
  /* from DPDK i40e... */
  static uint32_t rss_key_default[] = { 0x6b793944, 0x23504cb5, 0x5bea75b6,
					0x309f4f12, 0x3dc0a2b8, 0x024ddcdf,
					0x339b8ca0, 0x4c4af64a, 0x34fac605,
					0x55d85839, 0x3a58997d, 0x2ec938e1,
					0x66031581 };
  int msg_len = sizeof (virtchnl_rss_key_t) + ad->rss_key_size - 1;
  u8 msg[msg_len];
  virtchnl_rss_key_t *rk;

  if (sizeof (rss_key_default) != ad->rss_key_size)
    return clib_error_create ("unsupported RSS key size (expected %d, got %d)",
			      sizeof (rss_key_default), ad->rss_key_size);

  clib_memset (msg, 0, msg_len);
  rk = (virtchnl_rss_key_t *) msg;
  rk->vsi_id = ad->vsi_id;
  rk->key_len = ad->rss_key_size;
  memcpy_s (rk->key, rk->key_len, rss_key_default, sizeof (rss_key_default));

  avf_log_debug (ad, "config_rss_key: vsi_id %u rss_key_size %u key 0x%U",
		 rk->vsi_id, rk->key_len, format_hex_bytes_no_wrap, rk->key,
		 rk->key_len);

  return avf_send_to_pf (vm, ad, VIRTCHNL_OP_CONFIG_RSS_KEY, msg, msg_len, 0,
			 0);
}

clib_error_t *
avf_op_disable_vlan_stripping (vlib_main_t * vm, avf_device_t * ad)
{
  avf_log_debug (ad, "disable_vlan_stripping");

  return avf_send_to_pf (vm, ad, VIRTCHNL_OP_DISABLE_VLAN_STRIPPING, 0, 0, 0,
			 0);
}

clib_error_t *
avf_op_config_promisc_mode (vlib_main_t * vm, avf_device_t * ad,
			    int is_enable)
{
  virtchnl_promisc_info_t pi = { 0 };

  pi.vsi_id = ad->vsi_id;

  if (is_enable)
    pi.flags = FLAG_VF_UNICAST_PROMISC | FLAG_VF_MULTICAST_PROMISC;

  avf_log_debug (ad, "config_promisc_mode: unicast %s multicast %s",
		 pi.flags & FLAG_VF_UNICAST_PROMISC ? "on" : "off",
		 pi.flags & FLAG_VF_MULTICAST_PROMISC ? "on" : "off");

  return avf_send_to_pf (vm, ad, VIRTCHNL_OP_CONFIG_PROMISCUOUS_MODE, &pi,
			 sizeof (virtchnl_promisc_info_t), 0, 0);
}


clib_error_t *
avf_op_config_vsi_queues (vlib_main_t * vm, avf_device_t * ad)
{
  int i;
  int n_qp = clib_max (vec_len (ad->rxqs), vec_len (ad->txqs));
  int msg_len = sizeof (virtchnl_vsi_queue_config_info_t) + n_qp *
    sizeof (virtchnl_queue_pair_info_t);
  u8 msg[msg_len];
  virtchnl_vsi_queue_config_info_t *ci;

  clib_memset (msg, 0, msg_len);
  ci = (virtchnl_vsi_queue_config_info_t *) msg;
  ci->vsi_id = ad->vsi_id;
  ci->num_queue_pairs = n_qp;

  avf_log_debug (ad, "config_vsi_queues: vsi_id %u num_queue_pairs %u",
		 ad->vsi_id, ci->num_queue_pairs);

  for (i = 0; i < n_qp; i++)
    {
      virtchnl_txq_info_t *txq = &ci->qpair[i].txq;
      virtchnl_rxq_info_t *rxq = &ci->qpair[i].rxq;

      rxq->vsi_id = ad->vsi_id;
      rxq->queue_id = i;
      rxq->max_pkt_size = ETHERNET_MAX_PACKET_BYTES;
      if (i < vec_len (ad->rxqs))
	{
	  avf_rxq_t *q = vec_elt_at_index (ad->rxqs, i);
	  rxq->ring_len = q->size;
	  rxq->databuffer_size = vlib_buffer_get_default_data_size (vm);
	  rxq->dma_ring_addr = avf_dma_addr (vm, ad, (void *) q->descs);
	  avf_reg_write (ad, AVF_QRX_TAIL (i), q->size - 1);
	}
      avf_log_debug (ad, "config_vsi_queues_rx[%u]: max_pkt_size %u "
		     "ring_len %u databuffer_size %u dma_ring_addr 0x%llx",
		     i, rxq->max_pkt_size, rxq->ring_len,
		     rxq->databuffer_size, rxq->dma_ring_addr);

      txq->vsi_id = ad->vsi_id;
      txq->queue_id = i;
      if (i < vec_len (ad->txqs))
	{
	  avf_txq_t *q = vec_elt_at_index (ad->txqs, i);
	  txq->ring_len = q->size;
	  txq->dma_ring_addr = avf_dma_addr (vm, ad, (void *) q->descs);
	}
      avf_log_debug (ad, "config_vsi_queues_tx[%u]: ring_len %u "
		     "dma_ring_addr 0x%llx", i, txq->ring_len,
		     txq->dma_ring_addr);
    }

  return avf_send_to_pf (vm, ad, VIRTCHNL_OP_CONFIG_VSI_QUEUES, msg, msg_len,
			 0, 0);
}

clib_error_t *
avf_op_config_irq_map (vlib_main_t * vm, avf_device_t * ad)
{
  int msg_len = sizeof (virtchnl_irq_map_info_t) +
    (ad->n_rx_irqs) * sizeof (virtchnl_vector_map_t);
  u8 msg[msg_len];
  virtchnl_irq_map_info_t *imi;

  clib_memset (msg, 0, msg_len);
  imi = (virtchnl_irq_map_info_t *) msg;
  imi->num_vectors = ad->n_rx_irqs;

  for (int i = 0; i < ad->n_rx_irqs; i++)
    {
      imi->vecmap[i].vector_id = i + 1;
      imi->vecmap[i].vsi_id = ad->vsi_id;
      if (ad->n_rx_irqs == ad->n_rx_queues)
	imi->vecmap[i].rxq_map = 1 << i;
      else
	imi->vecmap[i].rxq_map = pow2_mask (ad->n_rx_queues);;

      avf_log_debug (ad, "config_irq_map[%u/%u]: vsi_id %u vector_id %u "
		     "rxq_map %u", i, ad->n_rx_irqs - 1, ad->vsi_id,
		     imi->vecmap[i].vector_id, imi->vecmap[i].rxq_map);
    }


  return avf_send_to_pf (vm, ad, VIRTCHNL_OP_CONFIG_IRQ_MAP, msg, msg_len, 0,
			 0);
}

clib_error_t *
avf_op_add_del_eth_addr (vlib_main_t * vm, avf_device_t * ad, u8 count,
			 u8 * macs, int is_add)
{
  int msg_len =
    sizeof (virtchnl_ether_addr_list_t) +
    count * sizeof (virtchnl_ether_addr_t);
  u8 msg[msg_len];
  virtchnl_ether_addr_list_t *al;
  int i;

  clib_memset (msg, 0, msg_len);
  al = (virtchnl_ether_addr_list_t *) msg;
  al->vsi_id = ad->vsi_id;
  al->num_elements = count;

  avf_log_debug (ad, "add_del_eth_addr: vsi_id %u num_elements %u is_add %u",
		 ad->vsi_id, al->num_elements, is_add);

  for (i = 0; i < count; i++)
    {
      clib_memcpy_fast (&al->list[i].addr, macs + i * 6, 6);
      avf_log_debug (ad, "add_del_eth_addr[%u]: %U", i,
		     format_ethernet_address, &al->list[i].addr);
    }
  return avf_send_to_pf (vm, ad, is_add ? VIRTCHNL_OP_ADD_ETH_ADDR :
			 VIRTCHNL_OP_DEL_ETH_ADDR, msg, msg_len, 0, 0);
}

clib_error_t *
avf_op_enable_queues (vlib_main_t * vm, avf_device_t * ad, u32 rx, u32 tx)
{
  virtchnl_queue_select_t qs = { 0 };
  int i = 0;
  qs.vsi_id = ad->vsi_id;
  qs.rx_queues = rx;
  qs.tx_queues = tx;

  avf_log_debug (ad, "enable_queues: vsi_id %u rx_queues %u tx_queues %u",
		 ad->vsi_id, qs.rx_queues, qs.tx_queues);

  while (rx)
    {
      if (rx & (1 << i))
	{
	  avf_rxq_t *rxq = vec_elt_at_index (ad->rxqs, i);
	  avf_reg_write (ad, AVF_QRX_TAIL (i), rxq->n_enqueued);
	  rx &= ~(1 << i);
	}
      i++;
    }
  return avf_send_to_pf (vm, ad, VIRTCHNL_OP_ENABLE_QUEUES, &qs,
			 sizeof (virtchnl_queue_select_t), 0, 0);
}

clib_error_t *
avf_op_get_stats (vlib_main_t * vm, avf_device_t * ad,
		  virtchnl_eth_stats_t * es)
{
  virtchnl_queue_select_t qs = { 0 };
  clib_error_t *err;
  qs.vsi_id = ad->vsi_id;

  err = avf_send_to_pf (vm, ad, VIRTCHNL_OP_GET_STATS, &qs,
			sizeof (virtchnl_queue_select_t), es,
			sizeof (virtchnl_eth_stats_t));

  avf_stats_log_debug (ad, "get_stats: vsi_id %u\n  %U", ad->vsi_id,
		       format_avf_eth_stats, es);

  return err;
}

clib_error_t *
avf_op_get_offload_vlan_v2_caps (vlib_main_t *vm, avf_device_t *ad,
				 virtchnl_vlan_caps_t *vc)
{
  clib_error_t *err;

  err = avf_send_to_pf (vm, ad, VIRTCHNL_OP_GET_OFFLOAD_VLAN_V2_CAPS, 0, 0, vc,
			sizeof (virtchnl_vlan_caps_t));

  avf_log_debug (ad, "get_offload_vlan_v2_caps:\n%U%U", format_white_space, 16,
		 format_avf_vlan_caps, vc);

  return err;
}

clib_error_t *
avf_op_disable_vlan_stripping_v2 (vlib_main_t *vm, avf_device_t *ad, u32 outer,
				  u32 inner)
{
  virtchnl_vlan_setting_t vs = {
    .outer_ethertype_setting = outer,
    .inner_ethertype_setting = inner,
    .vport_id = ad->vsi_id,
  };

  avf_log_debug (ad, "disable_vlan_stripping_v2: outer: %U, inner %U",
		 format_avf_vlan_support, outer, format_avf_vlan_support,
		 inner);

  return avf_send_to_pf (vm, ad, VIRTCHNL_OP_DISABLE_VLAN_STRIPPING_V2, &vs,
			 sizeof (virtchnl_vlan_setting_t), 0, 0);
}

clib_error_t *
avf_device_reset (vlib_main_t * vm, avf_device_t * ad)
{
  avf_aq_desc_t d = { 0 };
  clib_error_t *error;
  u32 rstat;
  f64 t0, t = 0, suspend_time = AVF_RESET_SUSPEND_TIME;

  avf_log_debug (ad, "reset");

  d.opcode = 0x801;
  d.v_opcode = VIRTCHNL_OP_RESET_VF;
  if ((error = avf_aq_desc_enq (vm, ad, &d, 0, 0)))
    return error;

  t0 = vlib_time_now (vm);
retry:
  vlib_process_suspend (vm, suspend_time);

  rstat = avf_get_u32 (ad->bar0, AVFGEN_RSTAT);

  if (rstat == 2 || rstat == 3)
    {
      avf_log_debug (ad, "reset completed in %.3fs", t);
      return 0;
    }

  t = vlib_time_now (vm) - t0;
  if (t > AVF_RESET_MAX_WAIT_TIME)
    {
      avf_log_err (ad, "reset failed (timeout %.3fs)", t);
      return clib_error_return (0, "reset failed (timeout)");
    }

  suspend_time *= 2;
  goto retry;
}

clib_error_t *
avf_request_queues (vlib_main_t * vm, avf_device_t * ad, u16 num_queue_pairs)
{
  virtchnl_vf_res_request_t res_req = { 0 };
  clib_error_t *error;
  u32 rstat;
  f64 t0, t, suspend_time = AVF_RESET_SUSPEND_TIME;

  res_req.num_queue_pairs = num_queue_pairs;

  avf_log_debug (ad, "request_queues: num_queue_pairs %u", num_queue_pairs);

  error = avf_send_to_pf (vm, ad, VIRTCHNL_OP_REQUEST_QUEUES, &res_req,
			  sizeof (virtchnl_vf_res_request_t), &res_req,
			  sizeof (virtchnl_vf_res_request_t));

  /*
   * if PF responds, the request failed
   * else PF initializes restart and avf_send_to_pf returns an error
   */
  if (!error)
    {
      return clib_error_return (0, "requested more than %u queue pairs",
				res_req.num_queue_pairs);
    }

  t0 = vlib_time_now (vm);
retry:
  vlib_process_suspend (vm, suspend_time);
  t = vlib_time_now (vm) - t0;

  rstat = avf_get_u32 (ad->bar0, AVFGEN_RSTAT);

  if ((rstat == VIRTCHNL_VFR_COMPLETED) || (rstat == VIRTCHNL_VFR_VFACTIVE))
    goto done;

  if (t > AVF_RESET_MAX_WAIT_TIME)
    {
      avf_log_err (ad, "request queues failed (timeout %.3f seconds)", t);
      return clib_error_return (0, "request queues failed (timeout)");
    }

  suspend_time *= 2;
  goto retry;

done:
  return NULL;
}

clib_error_t *
avf_device_init (vlib_main_t * vm, avf_main_t * am, avf_device_t * ad,
		 avf_create_if_args_t * args)
{
  virtchnl_version_info_t ver = { 0 };
  virtchnl_vf_resource_t res = { 0 };
  clib_error_t *error;
  int i, wb_on_itr;
  u16 rxq_num, txq_num;

  avf_adminq_init (vm, ad);

  rxq_num = args->rxq_num ? args->rxq_num : 1;
  txq_num = args->txq_num ? args->txq_num : vlib_get_n_threads ();

  if ((error = avf_request_queues (vm, ad, clib_max (txq_num, rxq_num))))
    {
      /* we failed to get more queues, but still we want to proceed */
      clib_error_free (error);

      if ((error = avf_device_reset (vm, ad)))
	return error;
    }

  avf_adminq_init (vm, ad);

  /*
   * OP_VERSION
   */
  if ((error = avf_op_version (vm, ad, &ver)))
    return error;

  if (ver.major != VIRTCHNL_VERSION_MAJOR ||
      ver.minor != VIRTCHNL_VERSION_MINOR)
    return clib_error_return (0, "incompatible protocol version "
			      "(remote %d.%d)", ver.major, ver.minor);

  /*
   * OP_GET_VF_RESOURCES
   */
  if ((error = avf_op_get_vf_resources (vm, ad, &res)))
    return error;

  if (res.num_vsis != 1 || res.vsi_res[0].vsi_type != VIRTCHNL_VSI_SRIOV)
    return clib_error_return (0, "unexpected GET_VF_RESOURCE reply received");

  ad->vsi_id = res.vsi_res[0].vsi_id;
  ad->cap_flags = res.vf_cap_flags;
  ad->num_queue_pairs = res.num_queue_pairs;
  ad->n_rx_queues = clib_min (rxq_num, res.num_queue_pairs);
  ad->n_tx_queues = clib_min (txq_num, res.num_queue_pairs);
  ad->max_vectors = res.max_vectors;
  ad->max_mtu = res.max_mtu;
  ad->rss_key_size = res.rss_key_size;
  ad->rss_lut_size = res.rss_lut_size;
  ad->n_rx_irqs = ad->max_vectors > ad->n_rx_queues ? ad->n_rx_queues : 1;

  if (ad->max_vectors > ad->n_rx_queues)
    ad->flags |= AVF_DEVICE_F_RX_INT;

  wb_on_itr = (ad->cap_flags & VIRTCHNL_VF_OFFLOAD_WB_ON_ITR) != 0;

  clib_memcpy_fast (ad->hwaddr, res.vsi_res[0].default_mac_addr, 6);

  if (args->rxq_num != 0 && ad->n_rx_queues != args->rxq_num)
    return clib_error_return (0,
			      "Number of requested RX queues (%u) is "
			      "higher than mumber of available queues (%u)",
			      args->rxq_num, ad->num_queue_pairs);

  if (args->txq_num != 0 && ad->n_tx_queues != args->txq_num)
    return clib_error_return (0,
			      "Number of requested TX queues (%u) is "
			      "higher than mumber of available queues (%u)",
			      args->txq_num, ad->num_queue_pairs);

  /*
   * Disable VLAN stripping
   */
  if (ad->cap_flags & VIRTCHNL_VF_OFFLOAD_VLAN_V2)
    {
      virtchnl_vlan_caps_t vc = {};
      u32 outer = VIRTCHNL_VLAN_UNSUPPORTED, inner = VIRTCHNL_VLAN_UNSUPPORTED;
      u32 mask = VIRTCHNL_VLAN_ETHERTYPE_8100;

      if ((error = avf_op_get_offload_vlan_v2_caps (vm, ad, &vc)))
	return error;

      outer = vc.offloads.stripping_support.outer & mask;
      inner = vc.offloads.stripping_support.inner & mask;

      if ((outer || inner) &&
	  (error = avf_op_disable_vlan_stripping_v2 (vm, ad, outer, inner)))
	return error;
    }
  else if ((error = avf_op_disable_vlan_stripping (vm, ad)))
    return error;

  /*
   * Init Queues
   */
  for (i = 0; i < ad->n_rx_queues; i++)
    if ((error = avf_rxq_init (vm, ad, i, args->rxq_size)))
      return error;

  for (i = 0; i < ad->n_tx_queues; i++)
    if ((error = avf_txq_init (vm, ad, i, args->txq_size)))
      return error;

  if ((ad->cap_flags & VIRTCHNL_VF_OFFLOAD_RSS_PF) &&
      (error = avf_op_config_rss_lut (vm, ad)))
    return error;

  if ((ad->cap_flags & VIRTCHNL_VF_OFFLOAD_RSS_PF) &&
      (error = avf_op_config_rss_key (vm, ad)))
    return error;

  if ((error = avf_op_config_vsi_queues (vm, ad)))
    return error;

  if ((error = avf_op_config_irq_map (vm, ad)))
    return error;

  avf_irq_0_set_state (ad, AVF_IRQ_STATE_ENABLED);

  for (i = 0; i < ad->n_rx_irqs; i++)
    avf_irq_n_set_state (ad, i, wb_on_itr ? AVF_IRQ_STATE_WB_ON_ITR :
			 AVF_IRQ_STATE_ENABLED);

  if ((error = avf_op_add_del_eth_addr (vm, ad, 1, ad->hwaddr, 1 /* add */ )))
    return error;

  if ((error = avf_op_enable_queues (vm, ad, pow2_mask (ad->n_rx_queues),
				     pow2_mask (ad->n_tx_queues))))
    return error;

  ad->flags |= AVF_DEVICE_F_INITIALIZED;
  return error;
}

void
avf_process_one_device (vlib_main_t * vm, avf_device_t * ad, int is_irq)
{
  vnet_main_t *vnm = vnet_get_main ();
  virtchnl_pf_event_t *e;
  u32 r;

  if (ad->flags & AVF_DEVICE_F_ERROR)
    return;

  if ((ad->flags & AVF_DEVICE_F_INITIALIZED) == 0)
    return;

  ASSERT (ad->error == 0);

  /* do not process device in reset state */
  r = avf_get_u32 (ad->bar0, AVFGEN_RSTAT);
  if (r != VIRTCHNL_VFR_VFACTIVE)
    return;

  r = avf_get_u32 (ad->bar0, AVF_ARQLEN);
  if ((r & 0xf0000000) != (1ULL << 31))
    {
      ad->error = clib_error_return (0, "arq not enabled, arqlen = 0x%x", r);
      avf_log_err (ad, "error: %U", format_clib_error, ad->error);
      goto error;
    }

  r = avf_get_u32 (ad->bar0, AVF_ATQLEN);
  if ((r & 0xf0000000) != (1ULL << 31))
    {
      ad->error = clib_error_return (0, "atq not enabled, atqlen = 0x%x", r);
      avf_log_err (ad, "error: %U", format_clib_error, ad->error);
      goto error;
    }

  if (is_irq == 0)
    avf_op_get_stats (vm, ad, &ad->eth_stats);

  /* *INDENT-OFF* */
  vec_foreach (e, ad->events)
    {
      avf_log_debug (ad, "event: %s (%u) sev %d",
		     virtchnl_event_names[e->event], e->event, e->severity);
      if (e->event == VIRTCHNL_EVENT_LINK_CHANGE)
	{
	  int link_up;
	  virtchnl_link_speed_t speed = e->event_data.link_event.link_speed;
	  u32 flags = 0;
	  u32 mbps = 0;

	  if (ad->cap_flags & VIRTCHNL_VF_CAP_ADV_LINK_SPEED)
	    link_up = e->event_data.link_event_adv.link_status;
	  else
	    link_up = e->event_data.link_event.link_status;

	  if (ad->cap_flags & VIRTCHNL_VF_CAP_ADV_LINK_SPEED)
	    mbps = e->event_data.link_event_adv.link_speed;
	  if (speed == VIRTCHNL_LINK_SPEED_40GB)
	    mbps = 40000;
	  else if (speed == VIRTCHNL_LINK_SPEED_25GB)
	    mbps = 25000;
	  else if (speed == VIRTCHNL_LINK_SPEED_10GB)
	    mbps = 10000;
	  else if (speed == VIRTCHNL_LINK_SPEED_5GB)
	    mbps = 5000;
	  else if (speed == VIRTCHNL_LINK_SPEED_2_5GB)
	    mbps = 2500;
	  else if (speed == VIRTCHNL_LINK_SPEED_1GB)
	    mbps = 1000;
	  else if (speed == VIRTCHNL_LINK_SPEED_100MB)
	    mbps = 100;

	  avf_log_debug (ad, "event_link_change: status %d speed %u mbps",
			 link_up, mbps);

	  if (link_up && (ad->flags & AVF_DEVICE_F_LINK_UP) == 0)
	    {
	      ad->flags |= AVF_DEVICE_F_LINK_UP;
	      flags |= (VNET_HW_INTERFACE_FLAG_FULL_DUPLEX |
			VNET_HW_INTERFACE_FLAG_LINK_UP);
	      vnet_hw_interface_set_flags (vnm, ad->hw_if_index, flags);
	      vnet_hw_interface_set_link_speed (
		vnm, ad->hw_if_index,
		(mbps == UINT32_MAX) ? UINT32_MAX : mbps * 1000);
	      ad->link_speed = mbps;
	    }
	  else if (!link_up && (ad->flags & AVF_DEVICE_F_LINK_UP) != 0)
	    {
	      ad->flags &= ~AVF_DEVICE_F_LINK_UP;
	      ad->link_speed = 0;
	    }

	  if (ad->flags & AVF_DEVICE_F_ELOG)
	    {
	      ELOG_TYPE_DECLARE (el) =
		{
		  .format = "avf[%d] link change: link_status %d "
		    "link_speed %d mbps",
		  .format_args = "i4i1i4",
		};
	      struct
		{
		  u32 dev_instance;
		  u8 link_status;
		  u32 link_speed;
		} *ed;
		ed = ELOG_DATA (&vlib_global_main.elog_main, el);
		ed->dev_instance = ad->dev_instance;
		ed->link_status = link_up;
		ed->link_speed = mbps;
	    }
	}
      else
	{
	  if (ad->flags & AVF_DEVICE_F_ELOG)
	    {
	      ELOG_TYPE_DECLARE (el) =
		{
		  .format = "avf[%d] unknown event: event %d severity %d",
		  .format_args = "i4i4i1i1",
		};
	      struct
		{
		  u32 dev_instance;
		  u32 event;
		  u32 severity;
		} *ed;
		ed = ELOG_DATA (&vlib_global_main.elog_main, el);
		ed->dev_instance = ad->dev_instance;
		ed->event = e->event;
		ed->severity = e->severity;
	    }
	}
    }
  /* *INDENT-ON* */
  vec_reset_length (ad->events);

  return;

error:
  ad->flags |= AVF_DEVICE_F_ERROR;
  ASSERT (ad->error != 0);
  vlib_log_err (avf_log.class, "%U", format_clib_error, ad->error);
}

clib_error_t *
avf_op_program_flow (vlib_main_t *vm, avf_device_t *ad, int is_create,
		     u8 *rule, u32 rule_len, u8 *program_status,
		     u32 status_len)
{
  avf_log_debug (ad, "avf_op_program_flow: vsi_id %u is_create %u", ad->vsi_id,
		 is_create);

  return avf_send_to_pf (vm, ad,
			 is_create ? VIRTCHNL_OP_ADD_FDIR_FILTER :
				     VIRTCHNL_OP_DEL_FDIR_FILTER,
			 rule, rule_len, program_status, status_len);
}

static void
avf_process_handle_request (vlib_main_t * vm, avf_process_req_t * req)
{
  avf_device_t *ad = avf_get_device (req->dev_instance);

  if (req->type == AVF_PROCESS_REQ_ADD_DEL_ETH_ADDR)
    req->error = avf_op_add_del_eth_addr (vm, ad, 1, req->eth_addr,
					  req->is_add);
  else if (req->type == AVF_PROCESS_REQ_CONFIG_PROMISC_MDDE)
    req->error = avf_op_config_promisc_mode (vm, ad, req->is_enable);
  else if (req->type == AVF_PROCESS_REQ_PROGRAM_FLOW)
    req->error =
      avf_op_program_flow (vm, ad, req->is_add, req->rule, req->rule_len,
			   req->program_status, req->status_len);
  else
    clib_panic ("BUG: unknown avf proceess request type");

  if (req->calling_process_index != avf_process_node.index)
    vlib_process_signal_event (vm, req->calling_process_index, 0, 0);
}

static clib_error_t *
avf_process_request (vlib_main_t * vm, avf_process_req_t * req)
{
  uword *event_data = 0;
  req->calling_process_index = vlib_get_current_process_node_index (vm);

  if (req->calling_process_index != avf_process_node.index)
    {
      vlib_process_signal_event_pointer (vm, avf_process_node.index,
					 AVF_PROCESS_EVENT_REQ, req);

      vlib_process_wait_for_event_or_clock (vm, 5.0);

      if (vlib_process_get_events (vm, &event_data) != 0)
	clib_panic ("avf process node failed to reply in 5 seconds");
      vec_free (event_data);
    }
  else
    avf_process_handle_request (vm, req);

  return req->error;
}

static u32
avf_flag_change (vnet_main_t * vnm, vnet_hw_interface_t * hw, u32 flags)
{
  avf_process_req_t req;
  vlib_main_t *vm = vlib_get_main ();
  avf_device_t *ad = avf_get_device (hw->dev_instance);
  clib_error_t *err;

  switch (flags)
    {
    case ETHERNET_INTERFACE_FLAG_DEFAULT_L3:
      ad->flags &= ~AVF_DEVICE_F_PROMISC;
      break;
    case ETHERNET_INTERFACE_FLAG_ACCEPT_ALL:
      ad->flags |= AVF_DEVICE_F_PROMISC;
      break;
    default:
      return ~0;
    }

  req.is_enable = ((ad->flags & AVF_DEVICE_F_PROMISC) != 0);
  req.type = AVF_PROCESS_REQ_CONFIG_PROMISC_MDDE;
  req.dev_instance = hw->dev_instance;

  if ((err = avf_process_request (vm, &req)))
    {
      avf_log_err (ad, "error: %U", format_clib_error, err);
      clib_error_free (err);
      return ~0;
    }
  return 0;
}

static uword
avf_process (vlib_main_t * vm, vlib_node_runtime_t * rt, vlib_frame_t * f)
{
  avf_main_t *am = &avf_main;
  uword *event_data = 0, event_type;
  int enabled = 0, irq;
  f64 last_run_duration = 0;
  f64 last_periodic_time = 0;
  avf_device_t **dev_pointers = 0;
  u32 i;

  while (1)
    {
      if (enabled)
	vlib_process_wait_for_event_or_clock (vm, 5.0 - last_run_duration);
      else
	vlib_process_wait_for_event (vm);

      event_type = vlib_process_get_events (vm, &event_data);
      irq = 0;

      switch (event_type)
	{
	case ~0:
	  last_periodic_time = vlib_time_now (vm);
	  break;
	case AVF_PROCESS_EVENT_START:
	  enabled = 1;
	  break;
	case AVF_PROCESS_EVENT_DELETE_IF:
	  for (int i = 0; i < vec_len (event_data); i++)
	    {
	      avf_device_t *ad = avf_get_device (event_data[i]);
	      avf_delete_if (vm, ad, /* with_barrier */ 1);
	    }
	  if (pool_elts (am->devices) < 1)
	    enabled = 0;
	  break;
	case AVF_PROCESS_EVENT_AQ_INT:
	  irq = 1;
	  break;
	case AVF_PROCESS_EVENT_REQ:
	  for (int i = 0; i < vec_len (event_data); i++)
	    avf_process_handle_request (vm, (void *) event_data[i]);
	  break;

	default:
	  ASSERT (0);
	}

      vec_reset_length (event_data);

      if (enabled == 0)
	continue;

      /* create local list of device pointers as device pool may grow
       * during suspend */
      vec_reset_length (dev_pointers);
      /* *INDENT-OFF* */
      pool_foreach_index (i, am->devices)
        {
	  vec_add1 (dev_pointers, avf_get_device (i));
	}

      vec_foreach_index (i, dev_pointers)
        {
	  avf_process_one_device (vm, dev_pointers[i], irq);
        };
      /* *INDENT-ON* */
      last_run_duration = vlib_time_now (vm) - last_periodic_time;
    }
  return 0;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (avf_process_node)  = {
  .function = avf_process,
  .type = VLIB_NODE_TYPE_PROCESS,
  .name = "avf-process",
};
/* *INDENT-ON* */

static void
avf_irq_0_handler (vlib_main_t * vm, vlib_pci_dev_handle_t h, u16 line)
{
  uword pd = vlib_pci_get_private_data (vm, h);
  avf_device_t *ad = avf_get_device (pd);
  u32 icr0;

  icr0 = avf_reg_read (ad, AVFINT_ICR0);

  if (ad->flags & AVF_DEVICE_F_ELOG)
    {
      /* *INDENT-OFF* */
      ELOG_TYPE_DECLARE (el) =
	{
	  .format = "avf[%d] irq 0: icr0 0x%x",
	  .format_args = "i4i4",
	};
      /* *INDENT-ON* */
      struct
      {
	u32 dev_instance;
	u32 icr0;
      } *ed;

      ed = ELOG_DATA (&vlib_global_main.elog_main, el);
      ed->dev_instance = ad->dev_instance;
      ed->icr0 = icr0;
    }

  avf_irq_0_set_state (ad, AVF_IRQ_STATE_ENABLED);

  /* bit 30 - Send/Receive Admin queue interrupt indication */
  if (icr0 & (1 << 30))
    vlib_process_signal_event (vm, avf_process_node.index,
			       AVF_PROCESS_EVENT_AQ_INT, 0);
}

static void
avf_irq_n_handler (vlib_main_t * vm, vlib_pci_dev_handle_t h, u16 line)
{
  vnet_main_t *vnm = vnet_get_main ();
  uword pd = vlib_pci_get_private_data (vm, h);
  avf_device_t *ad = avf_get_device (pd);
  avf_rxq_t *rxq = vec_elt_at_index (ad->rxqs, line - 1);

  if (ad->flags & AVF_DEVICE_F_ELOG)
    {
      /* *INDENT-OFF* */
      ELOG_TYPE_DECLARE (el) =
	{
	  .format = "avf[%d] irq %d: received",
	  .format_args = "i4i2",
	};
      /* *INDENT-ON* */
      struct
      {
	u32 dev_instance;
	u16 line;
      } *ed;

      ed = ELOG_DATA (&vlib_global_main.elog_main, el);
      ed->dev_instance = ad->dev_instance;
      ed->line = line;
    }

  line--;

  if (ad->flags & AVF_DEVICE_F_RX_INT && rxq->int_mode)
    vnet_hw_if_rx_queue_set_int_pending (vnm, rxq->queue_index);
  avf_irq_n_set_state (ad, line, AVF_IRQ_STATE_ENABLED);
}

void
avf_delete_if (vlib_main_t * vm, avf_device_t * ad, int with_barrier)
{
  vnet_main_t *vnm = vnet_get_main ();
  avf_main_t *am = &avf_main;
  int i;
  u32 dev_instance;

  ad->flags &= ~AVF_DEVICE_F_ADMIN_UP;

  if (ad->hw_if_index)
    {
      if (with_barrier)
	vlib_worker_thread_barrier_sync (vm);
      vnet_hw_interface_set_flags (vnm, ad->hw_if_index, 0);
      ethernet_delete_interface (vnm, ad->hw_if_index);
      if (with_barrier)
	vlib_worker_thread_barrier_release (vm);
    }

  vlib_pci_device_close (vm, ad->pci_dev_handle);

  vlib_physmem_free (vm, ad->atq);
  vlib_physmem_free (vm, ad->arq);
  vlib_physmem_free (vm, ad->atq_bufs);
  vlib_physmem_free (vm, ad->arq_bufs);

  /* *INDENT-OFF* */
  vec_foreach_index (i, ad->rxqs)
    {
      avf_rxq_t *rxq = vec_elt_at_index (ad->rxqs, i);
      vlib_physmem_free (vm, (void *) rxq->descs);
      if (rxq->n_enqueued)
	vlib_buffer_free_from_ring (vm, rxq->bufs, rxq->next, rxq->size,
				    rxq->n_enqueued);
      vec_free (rxq->bufs);
    }
  /* *INDENT-ON* */
  vec_free (ad->rxqs);

  /* *INDENT-OFF* */
  vec_foreach_index (i, ad->txqs)
    {
      avf_txq_t *txq = vec_elt_at_index (ad->txqs, i);
      vlib_physmem_free (vm, (void *) txq->descs);
      if (txq->n_enqueued)
	{
	  u16 first = (txq->next - txq->n_enqueued) & (txq->size -1);
	  vlib_buffer_free_from_ring (vm, txq->bufs, first, txq->size,
				      txq->n_enqueued);
	}
      /* Free the placeholder buffer */
      vlib_buffer_free (vm, txq->ph_bufs, vec_len (txq->ph_bufs));
      vec_free (txq->ph_bufs);
      vec_free (txq->bufs);
      clib_ring_free (txq->rs_slots);
      vec_free (txq->tmp_bufs);
      vec_free (txq->tmp_descs);
      clib_spinlock_free (&txq->lock);
    }
  /* *INDENT-ON* */
  vec_free (ad->txqs);
  vec_free (ad->name);

  clib_error_free (ad->error);
  dev_instance = ad->dev_instance;
  clib_memset (ad, 0, sizeof (*ad));
  pool_put_index (am->devices, dev_instance);
  clib_mem_free (ad);
}

static u8
avf_validate_queue_size (avf_create_if_args_t * args)
{
  clib_error_t *error = 0;

  args->rxq_size = (args->rxq_size == 0) ? AVF_RXQ_SZ : args->rxq_size;
  args->txq_size = (args->txq_size == 0) ? AVF_TXQ_SZ : args->txq_size;

  if ((args->rxq_size > AVF_QUEUE_SZ_MAX)
      || (args->txq_size > AVF_QUEUE_SZ_MAX))
    {
      args->rv = VNET_API_ERROR_INVALID_VALUE;
      args->error =
	clib_error_return (error, "queue size must not be greater than %u",
			   AVF_QUEUE_SZ_MAX);
      return 1;
    }
  if ((args->rxq_size < AVF_QUEUE_SZ_MIN)
      || (args->txq_size < AVF_QUEUE_SZ_MIN))
    {
      args->rv = VNET_API_ERROR_INVALID_VALUE;
      args->error =
	clib_error_return (error, "queue size must not be smaller than %u",
			   AVF_QUEUE_SZ_MIN);
      return 1;
    }
  if ((args->rxq_size & (args->rxq_size - 1)) ||
      (args->txq_size & (args->txq_size - 1)))
    {
      args->rv = VNET_API_ERROR_INVALID_VALUE;
      args->error =
	clib_error_return (error, "queue size must be a power of two");
      return 1;
    }
  return 0;
}

void
avf_create_if (vlib_main_t * vm, avf_create_if_args_t * args)
{
  vnet_main_t *vnm = vnet_get_main ();
  vnet_eth_interface_registration_t eir = {};
  avf_main_t *am = &avf_main;
  avf_device_t *ad, **adp;
  vlib_pci_dev_handle_t h;
  clib_error_t *error = 0;
  int i;

  /* check input args */
  if (avf_validate_queue_size (args) != 0)
    return;

  /* *INDENT-OFF* */
  pool_foreach (adp, am->devices)  {
	if ((*adp)->pci_addr.as_u32 == args->addr.as_u32)
      {
	args->rv = VNET_API_ERROR_ADDRESS_IN_USE;
	args->error =
	  clib_error_return (error, "%U: %s", format_vlib_pci_addr,
			     &args->addr, "pci address in use");
	return;
      }
  }
  /* *INDENT-ON* */

  pool_get (am->devices, adp);
  adp[0] = ad = clib_mem_alloc_aligned (sizeof (avf_device_t),
					CLIB_CACHE_LINE_BYTES);
  clib_memset (ad, 0, sizeof (avf_device_t));
  ad->dev_instance = adp - am->devices;
  ad->per_interface_next_index = ~0;
  ad->name = vec_dup (args->name);

  if (args->enable_elog)
    {
      ad->flags |= AVF_DEVICE_F_ELOG;
      avf_elog_init ();
    }

  if ((error = vlib_pci_device_open (vm, &args->addr, avf_pci_device_ids,
				     &h)))
    {
      pool_put (am->devices, adp);
      clib_mem_free (ad);
      args->rv = VNET_API_ERROR_INVALID_INTERFACE;
      args->error =
	clib_error_return (error, "pci-addr %U", format_vlib_pci_addr,
			   &args->addr);
      return;
    }
  ad->pci_dev_handle = h;
  ad->pci_addr = args->addr;
  ad->numa_node = vlib_pci_get_numa_node (vm, h);

  vlib_pci_set_private_data (vm, h, ad->dev_instance);

  if ((error = vlib_pci_bus_master_enable (vm, h)))
    goto error;

  if ((error = vlib_pci_map_region (vm, h, 0, &ad->bar0)))
    goto error;

  ad->atq = vlib_physmem_alloc_aligned_on_numa (vm, sizeof (avf_aq_desc_t) *
						AVF_MBOX_LEN,
						CLIB_CACHE_LINE_BYTES,
						ad->numa_node);
  if (ad->atq == 0)
    {
      error = vlib_physmem_last_error (vm);
      goto error;
    }

  if ((error = vlib_pci_map_dma (vm, h, ad->atq)))
    goto error;

  ad->arq = vlib_physmem_alloc_aligned_on_numa (vm, sizeof (avf_aq_desc_t) *
						AVF_MBOX_LEN,
						CLIB_CACHE_LINE_BYTES,
						ad->numa_node);
  if (ad->arq == 0)
    {
      error = vlib_physmem_last_error (vm);
      goto error;
    }

  if ((error = vlib_pci_map_dma (vm, h, ad->arq)))
    goto error;

  ad->atq_bufs = vlib_physmem_alloc_aligned_on_numa (vm, AVF_MBOX_BUF_SZ *
						     AVF_MBOX_LEN,
						     CLIB_CACHE_LINE_BYTES,
						     ad->numa_node);
  if (ad->atq_bufs == 0)
    {
      error = vlib_physmem_last_error (vm);
      goto error;
    }

  if ((error = vlib_pci_map_dma (vm, h, ad->atq_bufs)))
    goto error;

  ad->arq_bufs = vlib_physmem_alloc_aligned_on_numa (vm, AVF_MBOX_BUF_SZ *
						     AVF_MBOX_LEN,
						     CLIB_CACHE_LINE_BYTES,
						     ad->numa_node);
  if (ad->arq_bufs == 0)
    {
      error = vlib_physmem_last_error (vm);
      goto error;
    }

  if ((error = vlib_pci_map_dma (vm, h, ad->arq_bufs)))
    goto error;

  if (vlib_pci_supports_virtual_addr_dma (vm, h))
    ad->flags |= AVF_DEVICE_F_VA_DMA;

  if ((error = avf_device_init (vm, am, ad, args)))
    goto error;

  if ((error = vlib_pci_register_msix_handler (vm, h, 0, 1,
					       &avf_irq_0_handler)))
    goto error;

  if ((error = vlib_pci_register_msix_handler (vm, h, 1, ad->n_rx_irqs,
					       &avf_irq_n_handler)))
    goto error;

  if ((error = vlib_pci_enable_msix_irq (vm, h, 0, ad->n_rx_irqs + 1)))
    goto error;

  if ((error = vlib_pci_intr_enable (vm, h)))
    goto error;

  /* create interface */
  eir.dev_class_index = avf_device_class.index;
  eir.dev_instance = ad->dev_instance;
  eir.address = ad->hwaddr;
  eir.cb.flag_change = avf_flag_change;
  ad->hw_if_index = vnet_eth_register_interface (vnm, &eir);

  ethernet_set_flags (vnm, ad->hw_if_index,
		      ETHERNET_INTERFACE_FLAG_DEFAULT_L3);

  vnet_sw_interface_t *sw = vnet_get_hw_sw_interface (vnm, ad->hw_if_index);
  args->sw_if_index = ad->sw_if_index = sw->sw_if_index;

  vnet_hw_if_set_input_node (vnm, ad->hw_if_index, avf_input_node.index);

  /* set hw interface caps */
  vnet_hw_if_set_caps (vnm, ad->hw_if_index,
		       VNET_HW_IF_CAP_INT_MODE | VNET_HW_IF_CAP_MAC_FILTER |
			 VNET_HW_IF_CAP_L4_TX_CKSUM | VNET_HW_IF_CAP_TCP_GSO);

  for (i = 0; i < ad->n_rx_queues; i++)
    {
      u32 qi, fi;
      qi = vnet_hw_if_register_rx_queue (vnm, ad->hw_if_index, i,
					 VNET_HW_IF_RXQ_THREAD_ANY);

      if (ad->flags & AVF_DEVICE_F_RX_INT)
	{
	  fi = vlib_pci_get_msix_file_index (vm, ad->pci_dev_handle, i + 1);
	  vnet_hw_if_set_rx_queue_file_index (vnm, qi, fi);
	}
      ad->rxqs[i].queue_index = qi;
    }

  for (i = 0; i < ad->n_tx_queues; i++)
    {
      u32 qi = vnet_hw_if_register_tx_queue (vnm, ad->hw_if_index, i);
      ad->txqs[i].queue_index = qi;
    }

  for (i = 0; i < vlib_get_n_threads (); i++)
    {
      u32 qi = ad->txqs[i % ad->n_tx_queues].queue_index;
      vnet_hw_if_tx_queue_assign_thread (vnm, qi, i);
    }

  vnet_hw_if_update_runtime_data (vnm, ad->hw_if_index);

  if (pool_elts (am->devices) == 1)
    vlib_process_signal_event (vm, avf_process_node.index,
			       AVF_PROCESS_EVENT_START, 0);

  return;

error:
  avf_delete_if (vm, ad, /* with_barrier */ 0);
  args->rv = VNET_API_ERROR_INVALID_INTERFACE;
  args->error = clib_error_return (error, "pci-addr %U",
				   format_vlib_pci_addr, &args->addr);
  avf_log_err (ad, "error: %U", format_clib_error, args->error);
}

static clib_error_t *
avf_interface_admin_up_down (vnet_main_t * vnm, u32 hw_if_index, u32 flags)
{
  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, hw_if_index);
  avf_device_t *ad = avf_get_device (hi->dev_instance);
  uword is_up = (flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP) != 0;

  if (ad->flags & AVF_DEVICE_F_ERROR)
    return clib_error_return (0, "device is in error state");

  if (is_up)
    {
      vnet_hw_interface_set_flags (vnm, ad->hw_if_index,
				   VNET_HW_INTERFACE_FLAG_LINK_UP);
      ad->flags |= AVF_DEVICE_F_ADMIN_UP;
    }
  else
    {
      vnet_hw_interface_set_flags (vnm, ad->hw_if_index, 0);
      ad->flags &= ~AVF_DEVICE_F_ADMIN_UP;
    }
  return 0;
}

static clib_error_t *
avf_interface_rx_mode_change (vnet_main_t * vnm, u32 hw_if_index, u32 qid,
			      vnet_hw_if_rx_mode mode)
{
  vnet_hw_interface_t *hw = vnet_get_hw_interface (vnm, hw_if_index);
  avf_device_t *ad = avf_get_device (hw->dev_instance);
  avf_rxq_t *rxq = vec_elt_at_index (ad->rxqs, qid);

  if (mode == VNET_HW_IF_RX_MODE_POLLING)
    {
      if (rxq->int_mode == 0)
	return 0;
      if (ad->cap_flags & VIRTCHNL_VF_OFFLOAD_WB_ON_ITR)
	avf_irq_n_set_state (ad, qid, AVF_IRQ_STATE_WB_ON_ITR);
      else
	avf_irq_n_set_state (ad, qid, AVF_IRQ_STATE_ENABLED);
      rxq->int_mode = 0;
    }
  else
    {
      if (rxq->int_mode == 1)
	return 0;
      if (ad->n_rx_irqs != ad->n_rx_queues)
	return clib_error_return (0, "not enough interrupt lines");
      rxq->int_mode = 1;
      avf_irq_n_set_state (ad, qid, AVF_IRQ_STATE_ENABLED);
    }

  return 0;
}

static void
avf_set_interface_next_node (vnet_main_t * vnm, u32 hw_if_index,
			     u32 node_index)
{
  vnet_hw_interface_t *hw = vnet_get_hw_interface (vnm, hw_if_index);
  avf_device_t *ad = avf_get_device (hw->dev_instance);

  /* Shut off redirection */
  if (node_index == ~0)
    {
      ad->per_interface_next_index = node_index;
      return;
    }

  ad->per_interface_next_index =
    vlib_node_add_next (vlib_get_main (), avf_input_node.index, node_index);
}

static clib_error_t *
avf_add_del_mac_address (vnet_hw_interface_t * hw,
			 const u8 * address, u8 is_add)
{
  vlib_main_t *vm = vlib_get_main ();
  avf_process_req_t req;

  req.dev_instance = hw->dev_instance;
  req.type = AVF_PROCESS_REQ_ADD_DEL_ETH_ADDR;
  req.is_add = is_add;
  clib_memcpy (req.eth_addr, address, 6);

  return avf_process_request (vm, &req);
}

static char *avf_tx_func_error_strings[] = {
#define _(n,s) s,
  foreach_avf_tx_func_error
#undef _
};

static void
avf_clear_hw_interface_counters (u32 instance)
{
  avf_device_t *ad = avf_get_device (instance);
  clib_memcpy_fast (&ad->last_cleared_eth_stats,
		    &ad->eth_stats, sizeof (ad->eth_stats));
}

clib_error_t *
avf_program_flow (u32 dev_instance, int is_add, u8 *rule, u32 rule_len,
		  u8 *program_status, u32 status_len)
{
  vlib_main_t *vm = vlib_get_main ();
  avf_process_req_t req;

  req.dev_instance = dev_instance;
  req.type = AVF_PROCESS_REQ_PROGRAM_FLOW;
  req.is_add = is_add;
  req.rule = rule;
  req.rule_len = rule_len;
  req.program_status = program_status;
  req.status_len = status_len;

  return avf_process_request (vm, &req);
}

/* *INDENT-OFF* */
VNET_DEVICE_CLASS (avf_device_class, ) = {
  .name = "Adaptive Virtual Function (AVF) interface",
  .clear_counters = avf_clear_hw_interface_counters,
  .format_device = format_avf_device,
  .format_device_name = format_avf_device_name,
  .admin_up_down_function = avf_interface_admin_up_down,
  .rx_mode_change_function = avf_interface_rx_mode_change,
  .rx_redirect_to_node = avf_set_interface_next_node,
  .mac_addr_add_del_function = avf_add_del_mac_address,
  .tx_function_n_errors = AVF_TX_N_ERROR,
  .tx_function_error_strings = avf_tx_func_error_strings,
  .flow_ops_function = avf_flow_ops_fn,
};
/* *INDENT-ON* */

clib_error_t *
avf_init (vlib_main_t * vm)
{
  avf_main_t *am = &avf_main;
  vlib_thread_main_t *tm = vlib_get_thread_main ();

  vec_validate_aligned (am->per_thread_data, tm->n_vlib_mains - 1,
			CLIB_CACHE_LINE_BYTES);

  return 0;
}

/* *INDENT-OFF* */
VLIB_INIT_FUNCTION (avf_init) =
{
  .runs_after = VLIB_INITS ("pci_bus_init"),
};
/* *INDENT-OFF* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
