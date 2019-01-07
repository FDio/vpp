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

#include <avf/avf.h>

#define AVF_MBOX_LEN 64
#define AVF_MBOX_BUF_SZ 512
#define AVF_RXQ_SZ 512
#define AVF_TXQ_SZ 512
#define AVF_ITR_INT 8160

#define PCI_VENDOR_ID_INTEL			0x8086
#define PCI_DEVICE_ID_INTEL_AVF			0x1889
#define PCI_DEVICE_ID_INTEL_X710_VF		0x154c
#define PCI_DEVICE_ID_INTEL_X722_VF		0x37cd

avf_main_t avf_main;

static pci_device_id_t avf_pci_device_ids[] = {
  {.vendor_id = PCI_VENDOR_ID_INTEL,.device_id = PCI_DEVICE_ID_INTEL_AVF},
  {.vendor_id = PCI_VENDOR_ID_INTEL,.device_id = PCI_DEVICE_ID_INTEL_X710_VF},
  {.vendor_id = PCI_VENDOR_ID_INTEL,.device_id = PCI_DEVICE_ID_INTEL_X722_VF},
  {0},
};

static inline void
avf_irq_0_disable (avf_device_t * ad)
{
  u32 dyn_ctl0 = 0, icr0_ena = 0;

  dyn_ctl0 |= (3 << 3);		/* 11b = No ITR update */

  avf_reg_write (ad, AVFINT_ICR0_ENA1, icr0_ena);
  avf_reg_write (ad, AVFINT_DYN_CTL0, dyn_ctl0);
  avf_reg_flush (ad);
}

static inline void
avf_irq_0_enable (avf_device_t * ad)
{
  u32 dyn_ctl0 = 0, icr0_ena = 0;

  icr0_ena |= (1 << 30);	/* [30] Admin Queue Enable */

  dyn_ctl0 |= (1 << 0);		/* [0] Interrupt Enable */
  dyn_ctl0 |= (1 << 1);		/* [1] Clear PBA */
  //dyn_ctl0 |= (3 << 3);               /* [4:3] ITR Index, 11b = No ITR update */
  dyn_ctl0 |= ((AVF_ITR_INT / 2) << 5);	/* [16:5] ITR Interval in 2us steps */

  avf_irq_0_disable (ad);
  avf_reg_write (ad, AVFINT_ICR0_ENA1, icr0_ena);
  avf_reg_write (ad, AVFINT_DYN_CTL0, dyn_ctl0);
  avf_reg_flush (ad);
}

static inline void
avf_irq_n_disable (avf_device_t * ad, u8 line)
{
  u32 dyn_ctln = 0;

  avf_reg_write (ad, AVFINT_DYN_CTLN (line), dyn_ctln);
  avf_reg_flush (ad);
}

static inline void
avf_irq_n_enable (avf_device_t * ad, u8 line)
{
  u32 dyn_ctln = 0;

  dyn_ctln |= (1 << 0);		/* [0] Interrupt Enable */
  dyn_ctln |= (1 << 1);		/* [1] Clear PBA */
  dyn_ctln |= ((AVF_ITR_INT / 2) << 5);	/* [16:5] ITR Interval in 2us steps */

  avf_irq_n_disable (ad, line);
  avf_reg_write (ad, AVFINT_DYN_CTLN (line), dyn_ctln);
  avf_reg_flush (ad);
}


clib_error_t *
avf_aq_desc_enq (vlib_main_t * vm, avf_device_t * ad, avf_aq_desc_t * dt,
		 void *data, int len)
{
  avf_main_t *am = &avf_main;
  clib_error_t *err = 0;
  avf_aq_desc_t *d, dc;
  int n_retry = 5;

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
  vlib_log_debug (am->log_class, "%U", format_hexdump, data, len);
  ad->atq_next_slot = (ad->atq_next_slot + 1) % AVF_MBOX_LEN;
  avf_reg_write (ad, AVF_ATQT, ad->atq_next_slot);
  avf_reg_flush (ad);

retry:
  vlib_process_suspend (vm, 10e-6);

  if (((d->flags & AVF_AQ_F_DD) == 0) || ((d->flags & AVF_AQ_F_CMP) == 0))
    {
      if (--n_retry == 0)
	{
	  err = clib_error_return (0, "adminq enqueue timeout [opcode 0x%x]",
				   d->opcode);
	  goto done;
	}
      goto retry;
    }

  clib_memcpy_fast (dt, d, sizeof (avf_aq_desc_t));
  if (d->flags & AVF_AQ_F_ERR)
    return clib_error_return (0, "adminq enqueue error [opcode 0x%x, retval "
			      "%d]", d->opcode, d->retval);

done:
  if (ad->flags & AVF_DEVICE_F_ELOG)
    {
      /* *INDENT-OFF* */
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
      ed = ELOG_DATA (&vm->elog_main, el);
      ed->dev_instance = ad->dev_instance;
      ed->s_flags = dc.flags;
      ed->r_flags = d->flags;
      ed->opcode = dc.opcode;
      ed->datalen = dc.datalen;
      ed->retval = d->retval;
      /* *INDENT-ON* */
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
      /* *INDENT-OFF* */
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
      ed = ELOG_DATA (&vm->elog_main, el);
      ed->dev_instance = ad->dev_instance;
      ed->reg = reg;
      ed->val = val;
      /* *INDENT-ON* */
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

  if (rxq->descs == 0)
    return vlib_physmem_last_error (vm);

  if ((err = vlib_pci_map_dma (vm, ad->pci_dev_handle, (void *) rxq->descs)))
    return err;

  clib_memset ((void *) rxq->descs, 0, rxq->size * sizeof (avf_rx_desc_t));
  vec_validate_aligned (rxq->bufs, rxq->size, CLIB_CACHE_LINE_BYTES);
  rxq->qrx_tail = ad->bar0 + AVF_QRX_TAIL (qid);

  n_alloc = vlib_buffer_alloc (vm, rxq->bufs, rxq->size - 8);

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

  ad->n_rx_queues = clib_min (ad->num_queue_pairs, qid + 1);
  return 0;
}

clib_error_t *
avf_txq_init (vlib_main_t * vm, avf_device_t * ad, u16 qid, u16 txq_size)
{
  clib_error_t *err;
  avf_txq_t *txq;

  if (qid >= ad->num_queue_pairs)
    {
      qid = qid % ad->num_queue_pairs;
      txq = vec_elt_at_index (ad->txqs, qid);
      if (txq->lock == 0)
	clib_spinlock_init (&txq->lock);
      ad->flags |= AVF_DEVICE_F_SHARED_TXQ_LOCK;
      return 0;
    }

  vec_validate_aligned (ad->txqs, qid, CLIB_CACHE_LINE_BYTES);
  txq = vec_elt_at_index (ad->txqs, qid);
  txq->size = txq_size;
  txq->next = 0;
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

  ad->n_tx_queues = clib_min (ad->num_queue_pairs, qid + 1);
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
  int n_retry = 5;


  /* supppres interrupt in the next adminq receive slot
     as we are going to wait for response
     we only need interrupts when event is received */
  d = &ad->arq[ad->arq_next_slot];
  d->flags |= AVF_AQ_F_SI;

  if ((err = avf_aq_desc_enq (vm, ad, &dt, in, in_len)))
    return err;

retry:
  head = avf_get_u32 (ad->bar0, AVF_ARQH);

  if (ad->arq_next_slot == head)
    {
      if (--n_retry == 0)
	return clib_error_return (0, "timeout");
      vlib_process_suspend (vm, 10e-3);
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
      n_retry = 5;
      goto retry;
    }

  if (d->v_opcode != op)
    {
      err =
	clib_error_return (0,
			   "unexpected message receiver [v_opcode = %u, "
			   "expected %u, v_retval %d]", d->v_opcode, op,
			   d->v_retval);
      goto done;
    }

  if (d->v_retval)
    {
      err = clib_error_return (0, "error [v_opcode = %u, v_retval %d]",
			       d->v_opcode, d->v_retval);
      goto done;
    }

  if (d->flags & AVF_AQ_F_BUF)
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
      /* *INDENT-OFF* */
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
      ed = ELOG_DATA (&vm->elog_main, el);
      ed->dev_instance = ad->dev_instance;
      ed->v_opcode = op;
      ed->v_opcode_val = op;
      ed->v_retval = d->v_retval;
      /* *INDENT-ON* */
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
  u32 bitmap = (VIRTCHNL_VF_OFFLOAD_L2 | VIRTCHNL_VF_OFFLOAD_RSS_PF |
		VIRTCHNL_VF_OFFLOAD_WB_ON_ITR | VIRTCHNL_VF_OFFLOAD_VLAN |
		VIRTCHNL_VF_OFFLOAD_RX_POLLING);

  return avf_send_to_pf (vm, ad, VIRTCHNL_OP_GET_VF_RESOURCES, &bitmap,
			 sizeof (u32), res, sizeof (virtchnl_vf_resource_t));
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

  return avf_send_to_pf (vm, ad, VIRTCHNL_OP_CONFIG_RSS_LUT, msg, msg_len, 0,
			 0);
}

clib_error_t *
avf_op_config_rss_key (vlib_main_t * vm, avf_device_t * ad)
{
  int msg_len = sizeof (virtchnl_rss_key_t) + ad->rss_key_size - 1;
  int i;
  u8 msg[msg_len];
  virtchnl_rss_key_t *rk;

  clib_memset (msg, 0, msg_len);
  rk = (virtchnl_rss_key_t *) msg;
  rk->vsi_id = ad->vsi_id;
  rk->key_len = ad->rss_key_size;
  u32 seed = random_default_seed ();
  for (i = 0; i < ad->rss_key_size; i++)
    rk->key[i] = (u8) random_u32 (&seed);

  return avf_send_to_pf (vm, ad, VIRTCHNL_OP_CONFIG_RSS_KEY, msg, msg_len, 0,
			 0);
}

clib_error_t *
avf_op_disable_vlan_stripping (vlib_main_t * vm, avf_device_t * ad)
{
  return avf_send_to_pf (vm, ad, VIRTCHNL_OP_DISABLE_VLAN_STRIPPING, 0, 0, 0,
			 0);
}

clib_error_t *
avf_config_promisc_mode (vlib_main_t * vm, avf_device_t * ad)
{
  virtchnl_promisc_info_t pi = { 0 };

  pi.vsi_id = ad->vsi_id;
  pi.flags = 1;
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
	  rxq->databuffer_size = VLIB_BUFFER_DEFAULT_FREE_LIST_BYTES;
	  rxq->dma_ring_addr = avf_dma_addr (vm, ad, (void *) q->descs);
	  avf_reg_write (ad, AVF_QRX_TAIL (i), q->size - 1);
	}

      avf_txq_t *q = vec_elt_at_index (ad->txqs, i);
      txq->vsi_id = ad->vsi_id;
      if (i < vec_len (ad->txqs))
	{
	  txq->queue_id = i;
	  txq->ring_len = q->size;
	  txq->dma_ring_addr = avf_dma_addr (vm, ad, (void *) q->descs);
	}
    }

  return avf_send_to_pf (vm, ad, VIRTCHNL_OP_CONFIG_VSI_QUEUES, msg, msg_len,
			 0, 0);
}

clib_error_t *
avf_op_config_irq_map (vlib_main_t * vm, avf_device_t * ad)
{
  int count = 1;
  int msg_len = sizeof (virtchnl_irq_map_info_t) +
    count * sizeof (virtchnl_vector_map_t);
  u8 msg[msg_len];
  virtchnl_irq_map_info_t *imi;

  clib_memset (msg, 0, msg_len);
  imi = (virtchnl_irq_map_info_t *) msg;
  imi->num_vectors = count;

  imi->vecmap[0].vector_id = 1;
  imi->vecmap[0].vsi_id = ad->vsi_id;
  imi->vecmap[0].rxq_map = 1;
  return avf_send_to_pf (vm, ad, VIRTCHNL_OP_CONFIG_IRQ_MAP, msg, msg_len, 0,
			 0);
}

clib_error_t *
avf_op_add_eth_addr (vlib_main_t * vm, avf_device_t * ad, u8 count, u8 * macs)
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
  for (i = 0; i < count; i++)
    clib_memcpy_fast (&al->list[i].addr, macs + i * 6, 6);
  return avf_send_to_pf (vm, ad, VIRTCHNL_OP_ADD_ETH_ADDR, msg, msg_len, 0,
			 0);
}

clib_error_t *
avf_op_enable_queues (vlib_main_t * vm, avf_device_t * ad, u32 rx, u32 tx)
{
  virtchnl_queue_select_t qs = { 0 };
  int i;
  qs.vsi_id = ad->vsi_id;
  qs.rx_queues = rx;
  qs.tx_queues = tx;
  for (i = 0; i < ad->n_rx_queues; i++)
    {
      avf_rxq_t *rxq = vec_elt_at_index (ad->rxqs, i);
      avf_reg_write (ad, AVF_QRX_TAIL (i), rxq->n_enqueued);
    }
  return avf_send_to_pf (vm, ad, VIRTCHNL_OP_ENABLE_QUEUES, &qs,
			 sizeof (virtchnl_queue_select_t), 0, 0);
}

clib_error_t *
avf_op_get_stats (vlib_main_t * vm, avf_device_t * ad,
		  virtchnl_eth_stats_t * es)
{
  virtchnl_queue_select_t qs = { 0 };
  qs.vsi_id = ad->vsi_id;
  return avf_send_to_pf (vm, ad, VIRTCHNL_OP_GET_STATS,
			 &qs, sizeof (virtchnl_queue_select_t),
			 es, sizeof (virtchnl_eth_stats_t));
}

clib_error_t *
avf_device_reset (vlib_main_t * vm, avf_device_t * ad)
{
  avf_aq_desc_t d = { 0 };
  clib_error_t *error;
  u32 rstat;
  int n_retry = 20;

  d.opcode = 0x801;
  d.v_opcode = VIRTCHNL_OP_RESET_VF;
  if ((error = avf_aq_desc_enq (vm, ad, &d, 0, 0)))
    return error;

retry:
  vlib_process_suspend (vm, 10e-3);
  rstat = avf_get_u32 (ad->bar0, AVFGEN_RSTAT);

  if (rstat == 2 || rstat == 3)
    return 0;

  if (--n_retry == 0)
    return clib_error_return (0, "reset failed (timeout)");

  goto retry;
}

clib_error_t *
avf_request_queues (vlib_main_t * vm, avf_device_t * ad, u16 num_queue_pairs)
{
  virtchnl_vf_res_request_t res_req = { 0 };
  clib_error_t *error;
  u32 rstat;
  int n_retry = 20;

  res_req.num_queue_pairs = num_queue_pairs;

  error = avf_send_to_pf (vm, ad, VIRTCHNL_OP_REQUEST_QUEUES, &res_req,
			  sizeof (virtchnl_vf_res_request_t), &res_req,
			  sizeof (virtchnl_vf_res_request_t));

  /*
   * if PF respondes, the request failed
   * else PF initializes restart and avf_send_to_pf returns an error
   */
  if (!error)
    {
      return clib_error_return (0, "requested more than %u queue pairs",
				res_req.num_queue_pairs);
    }

retry:
  vlib_process_suspend (vm, 10e-3);
  rstat = avf_get_u32 (ad->bar0, AVFGEN_RSTAT);

  if ((rstat == VIRTCHNL_VFR_COMPLETED) || (rstat == VIRTCHNL_VFR_VFACTIVE))
    goto done;

  if (--n_retry == 0)
    return clib_error_return (0, "reset failed (timeout)");

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
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  int i;

  avf_adminq_init (vm, ad);

  /* request more queues only if we need them */
  if ((error = avf_request_queues (vm, ad, tm->n_vlib_mains)))
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
   * OP_GET_VF_RESOUCES
   */
  if ((error = avf_op_get_vf_resources (vm, ad, &res)))
    return error;

  if (res.num_vsis != 1 || res.vsi_res[0].vsi_type != VIRTCHNL_VSI_SRIOV)
    return clib_error_return (0, "unexpected GET_VF_RESOURCE reply received");

  ad->vsi_id = res.vsi_res[0].vsi_id;
  ad->feature_bitmap = res.vf_offload_flags;
  ad->num_queue_pairs = res.num_queue_pairs;
  ad->max_vectors = res.max_vectors;
  ad->max_mtu = res.max_mtu;
  ad->rss_key_size = res.rss_key_size;
  ad->rss_lut_size = res.rss_lut_size;

  clib_memcpy_fast (ad->hwaddr, res.vsi_res[0].default_mac_addr, 6);

  /*
   * Disable VLAN stripping
   */
  if ((error = avf_op_disable_vlan_stripping (vm, ad)))
    return error;

  if ((error = avf_config_promisc_mode (vm, ad)))
    return error;

  /*
   * Init Queues
   */
  if (args->rxq_num == 0)
    {
      args->rxq_num = 1;
    }
  else if (args->rxq_num > ad->num_queue_pairs)
    {
      args->rxq_num = ad->num_queue_pairs;
      vlib_log_warn (am->log_class, "Requested more rx queues than"
		     "queue pairs available. Using %u rx queues.",
		     args->rxq_num);
    }

  for (i = 0; i < args->rxq_num; i++)
    if ((error = avf_rxq_init (vm, ad, i, args->rxq_size)))
      return error;

  for (i = 0; i < tm->n_vlib_mains; i++)
    if ((error = avf_txq_init (vm, ad, i, args->txq_size)))
      return error;

  if ((ad->feature_bitmap & VIRTCHNL_VF_OFFLOAD_RSS_PF) &&
      (error = avf_op_config_rss_lut (vm, ad)))
    return error;

  if ((ad->feature_bitmap & VIRTCHNL_VF_OFFLOAD_RSS_PF) &&
      (error = avf_op_config_rss_key (vm, ad)))
    return error;

  if ((error = avf_op_config_vsi_queues (vm, ad)))
    return error;

  if ((error = avf_op_config_irq_map (vm, ad)))
    return error;

  avf_irq_0_enable (ad);
  for (i = 0; i < ad->n_rx_queues; i++)
    avf_irq_n_enable (ad, i);

  if ((error = avf_op_add_eth_addr (vm, ad, 1, ad->hwaddr)))
    return error;

  if ((error = avf_op_enable_queues (vm, ad, ad->n_rx_queues, 0)))
    return error;

  if ((error = avf_op_enable_queues (vm, ad, 0, ad->n_tx_queues)))
    return error;

  ad->flags |= AVF_DEVICE_F_INITIALIZED;
  return error;
}

void
avf_process_one_device (vlib_main_t * vm, avf_device_t * ad, int is_irq)
{
  avf_main_t *am = &avf_main;
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
      goto error;
    }

  r = avf_get_u32 (ad->bar0, AVF_ATQLEN);
  if ((r & 0xf0000000) != (1ULL << 31))
    {
      ad->error = clib_error_return (0, "atq not enabled, atqlen = 0x%x", r);
      goto error;
    }

  if (is_irq == 0)
    avf_op_get_stats (vm, ad, &ad->eth_stats);

  /* *INDENT-OFF* */
  vec_foreach (e, ad->events)
    {
      if (e->event == VIRTCHNL_EVENT_LINK_CHANGE)
	{
	  int link_up = e->event_data.link_event.link_status;
	  virtchnl_link_speed_t speed = e->event_data.link_event.link_speed;
	  u32 flags = 0;
	  u32 kbps = 0;

	  if (link_up && (ad->flags & AVF_DEVICE_F_LINK_UP) == 0)
	    {
	      ad->flags |= AVF_DEVICE_F_LINK_UP;
	      flags |= (VNET_HW_INTERFACE_FLAG_FULL_DUPLEX |
			VNET_HW_INTERFACE_FLAG_LINK_UP);
	      if (speed == VIRTCHNL_LINK_SPEED_40GB)
		kbps = 40000000;
	      else if (speed == VIRTCHNL_LINK_SPEED_25GB)
		kbps = 25000000;
	      else if (speed == VIRTCHNL_LINK_SPEED_10GB)
		kbps = 10000000;
	      else if (speed == VIRTCHNL_LINK_SPEED_1GB)
		kbps = 1000000;
	      else if (speed == VIRTCHNL_LINK_SPEED_100MB)
		kbps = 100000;
	      vnet_hw_interface_set_flags (vnm, ad->hw_if_index, flags);
	      vnet_hw_interface_set_link_speed (vnm, ad->hw_if_index, kbps);
	      ad->link_speed = speed;
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
		    "link_speed %d",
		  .format_args = "i4i1i1",
		};
	      struct
		{
		  u32 dev_instance;
		  u8 link_status;
		  u8 link_speed;
		} *ed;
	      ed = ELOG_DATA (&vm->elog_main, el);
              ed->dev_instance = ad->dev_instance;
	      ed->link_status = link_up;
	      ed->link_speed = speed;
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
	      ed = ELOG_DATA (&vm->elog_main, el);
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
  vlib_log_err (am->log_class, "%U", format_clib_error, ad->error);
}

static u32
avf_flag_change (vnet_main_t * vnm, vnet_hw_interface_t * hw, u32 flags)
{
  avf_main_t *am = &avf_main;
  vlib_log_warn (am->log_class, "TODO");
  return 0;
}

static uword
avf_process (vlib_main_t * vm, vlib_node_runtime_t * rt, vlib_frame_t * f)
{
  avf_main_t *am = &avf_main;
  avf_device_t *ad;
  uword *event_data = 0, event_type;
  int enabled = 0, irq;
  f64 last_run_duration = 0;
  f64 last_periodic_time = 0;

  while (1)
    {
      if (enabled)
	vlib_process_wait_for_event_or_clock (vm, 5.0 - last_run_duration);
      else
	vlib_process_wait_for_event (vm);

      event_type = vlib_process_get_events (vm, &event_data);
      vec_reset_length (event_data);
      irq = 0;

      switch (event_type)
	{
	case ~0:
	  last_periodic_time = vlib_time_now (vm);
	  break;
	case AVF_PROCESS_EVENT_START:
	  enabled = 1;
	  break;
	case AVF_PROCESS_EVENT_STOP:
	  enabled = 0;
	  continue;
	case AVF_PROCESS_EVENT_AQ_INT:
	  irq = 1;
	  break;
	default:
	  ASSERT (0);
	}

      /* *INDENT-OFF* */
      pool_foreach (ad, am->devices,
        {
	  avf_process_one_device (vm, ad, irq);
        });
      /* *INDENT-ON* */
      last_run_duration = vlib_time_now (vm) - last_periodic_time;
    }
  return 0;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (avf_process_node, static)  = {
  .function = avf_process,
  .type = VLIB_NODE_TYPE_PROCESS,
  .name = "avf-process",
};
/* *INDENT-ON* */

static void
avf_irq_0_handler (vlib_main_t * vm, vlib_pci_dev_handle_t h, u16 line)
{
  avf_main_t *am = &avf_main;
  uword pd = vlib_pci_get_private_data (vm, h);
  avf_device_t *ad = pool_elt_at_index (am->devices, pd);
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

      ed = ELOG_DATA (&vm->elog_main, el);
      ed->dev_instance = ad->dev_instance;
      ed->icr0 = icr0;
    }

  avf_irq_0_enable (ad);

  /* bit 30 - Send/Receive Admin queue interrupt indication */
  if (icr0 & (1 << 30))
    vlib_process_signal_event (vm, avf_process_node.index,
			       AVF_PROCESS_EVENT_AQ_INT, 0);
}

static void
avf_irq_n_handler (vlib_main_t * vm, vlib_pci_dev_handle_t h, u16 line)
{
  vnet_main_t *vnm = vnet_get_main ();
  avf_main_t *am = &avf_main;
  uword pd = vlib_pci_get_private_data (vm, h);
  avf_device_t *ad = pool_elt_at_index (am->devices, pd);
  u16 qid;
  int i;

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

      ed = ELOG_DATA (&vm->elog_main, el);
      ed->dev_instance = ad->dev_instance;
      ed->line = line;
    }

  qid = line - 1;
  if (vec_len (ad->rxqs) > qid && ad->rxqs[qid].int_mode != 0)
    vnet_device_input_set_interrupt_pending (vnm, ad->hw_if_index, qid);
  for (i = 0; i < vec_len (ad->rxqs); i++)
    avf_irq_n_enable (ad, i);
}

void
avf_delete_if (vlib_main_t * vm, avf_device_t * ad)
{
  vnet_main_t *vnm = vnet_get_main ();
  avf_main_t *am = &avf_main;
  int i;

  if (ad->hw_if_index)
    {
      vnet_hw_interface_set_flags (vnm, ad->hw_if_index, 0);
      vnet_hw_interface_unassign_rx_thread (vnm, ad->hw_if_index, 0);
      ethernet_delete_interface (vnm, ad->hw_if_index);
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
      vec_free (txq->bufs);
      clib_ring_free (txq->rs_slots);
    }
  /* *INDENT-ON* */
  vec_free (ad->txqs);
  vec_free (ad->name);

  clib_error_free (ad->error);
  clib_memset (ad, 0, sizeof (*ad));
  pool_put (am->devices, ad);
}

void
avf_create_if (vlib_main_t * vm, avf_create_if_args_t * args)
{
  vnet_main_t *vnm = vnet_get_main ();
  avf_main_t *am = &avf_main;
  avf_device_t *ad;
  vlib_pci_dev_handle_t h;
  clib_error_t *error = 0;
  int i;

  /* check input args */
  args->rxq_size = (args->rxq_size == 0) ? AVF_RXQ_SZ : args->rxq_size;
  args->txq_size = (args->txq_size == 0) ? AVF_TXQ_SZ : args->txq_size;

  if ((args->rxq_size & (args->rxq_size - 1))
      || (args->txq_size & (args->txq_size - 1)))
    {
      args->rv = VNET_API_ERROR_INVALID_VALUE;
      args->error =
	clib_error_return (error, "queue size must be a power of two");
      return;
    }

  pool_get (am->devices, ad);
  ad->dev_instance = ad - am->devices;
  ad->per_interface_next_index = ~0;
  ad->name = vec_dup (args->name);

  if (args->enable_elog)
    ad->flags |= AVF_DEVICE_F_ELOG;

  if ((error = vlib_pci_device_open (vm, &args->addr, avf_pci_device_ids,
				     &h)))
    {
      pool_put (am->devices, ad);
      args->rv = VNET_API_ERROR_INVALID_INTERFACE;
      args->error =
	clib_error_return (error, "pci-addr %U", format_vlib_pci_addr,
			   &args->addr);
      return;
    }
  ad->pci_dev_handle = h;
  ad->numa_node = vlib_pci_get_numa_node (vm, h);

  vlib_pci_set_private_data (vm, h, ad->dev_instance);

  if ((error = vlib_pci_bus_master_enable (vm, h)))
    goto error;

  if ((error = vlib_pci_map_region (vm, h, 0, &ad->bar0)))
    goto error;

  if ((error = vlib_pci_register_msix_handler (vm, h, 0, 1,
					       &avf_irq_0_handler)))
    goto error;

  if ((error = vlib_pci_register_msix_handler (vm, h, 1, 1,
					       &avf_irq_n_handler)))
    goto error;

  if ((error = vlib_pci_enable_msix_irq (vm, h, 0, 2)))
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

  if ((error = vlib_pci_intr_enable (vm, h)))
    goto error;

  if (vlib_pci_supports_virtual_addr_dma (vm, h))
    ad->flags |= AVF_DEVICE_F_VA_DMA;

  if ((error = avf_device_init (vm, am, ad, args)))
    goto error;

  /* create interface */
  error = ethernet_register_interface (vnm, avf_device_class.index,
				       ad->dev_instance, ad->hwaddr,
				       &ad->hw_if_index, avf_flag_change);

  if (error)
    goto error;

  vnet_sw_interface_t *sw = vnet_get_hw_sw_interface (vnm, ad->hw_if_index);
  args->sw_if_index = ad->sw_if_index = sw->sw_if_index;

  vnet_hw_interface_t *hw = vnet_get_hw_interface (vnm, ad->hw_if_index);
  hw->flags |= VNET_HW_INTERFACE_FLAG_SUPPORTS_INT_MODE;
  vnet_hw_interface_set_input_node (vnm, ad->hw_if_index,
				    avf_input_node.index);

  for (i = 0; i < ad->n_rx_queues; i++)
    vnet_hw_interface_assign_rx_thread (vnm, ad->hw_if_index, i, ~0);

  if (pool_elts (am->devices) == 1)
    vlib_process_signal_event (vm, avf_process_node.index,
			       AVF_PROCESS_EVENT_START, 0);

  return;

error:
  avf_delete_if (vm, ad);
  args->rv = VNET_API_ERROR_INVALID_INTERFACE;
  args->error = clib_error_return (error, "pci-addr %U",
				   format_vlib_pci_addr, &args->addr);
  vlib_log_err (am->log_class, "%U", format_clib_error, args->error);
}

static clib_error_t *
avf_interface_admin_up_down (vnet_main_t * vnm, u32 hw_if_index, u32 flags)
{
  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, hw_if_index);
  avf_main_t *am = &avf_main;
  avf_device_t *ad = vec_elt_at_index (am->devices, hi->dev_instance);
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
			      vnet_hw_interface_rx_mode mode)
{
  avf_main_t *am = &avf_main;
  vnet_hw_interface_t *hw = vnet_get_hw_interface (vnm, hw_if_index);
  avf_device_t *ad = pool_elt_at_index (am->devices, hw->dev_instance);
  avf_rxq_t *rxq = vec_elt_at_index (ad->rxqs, qid);

  if (mode == VNET_HW_INTERFACE_RX_MODE_POLLING)
    rxq->int_mode = 0;
  else
    rxq->int_mode = 1;

  return 0;
}

static void
avf_set_interface_next_node (vnet_main_t * vnm, u32 hw_if_index,
			     u32 node_index)
{
  avf_main_t *am = &avf_main;
  vnet_hw_interface_t *hw = vnet_get_hw_interface (vnm, hw_if_index);
  avf_device_t *ad = pool_elt_at_index (am->devices, hw->dev_instance);

  /* Shut off redirection */
  if (node_index == ~0)
    {
      ad->per_interface_next_index = node_index;
      return;
    }

  ad->per_interface_next_index =
    vlib_node_add_next (vlib_get_main (), avf_input_node.index, node_index);
}

static char *avf_tx_func_error_strings[] = {
#define _(n,s) s,
  foreach_avf_tx_func_error
#undef _
};

/* *INDENT-OFF* */
VNET_DEVICE_CLASS (avf_device_class,) =
{
  .name = "Adaptive Virtual Function (AVF) interface",
  .format_device = format_avf_device,
  .format_device_name = format_avf_device_name,
  .admin_up_down_function = avf_interface_admin_up_down,
  .rx_mode_change_function = avf_interface_rx_mode_change,
  .rx_redirect_to_node = avf_set_interface_next_node,
  .tx_function_n_errors = AVF_TX_N_ERROR,
  .tx_function_error_strings = avf_tx_func_error_strings,
};
/* *INDENT-ON* */

clib_error_t *
avf_init (vlib_main_t * vm)
{
  avf_main_t *am = &avf_main;
  clib_error_t *error;
  vlib_thread_main_t *tm = vlib_get_thread_main ();

  if ((error = vlib_call_init_function (vm, pci_bus_init)))
    return error;

  vec_validate_aligned (am->per_thread_data, tm->n_vlib_mains - 1,
			CLIB_CACHE_LINE_BYTES);

  am->log_class = vlib_log_register_class ("avf_plugin", 0);
  vlib_log_debug (am->log_class, "initialized");

  return 0;
}

VLIB_INIT_FUNCTION (avf_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
