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

#include <rge/rge.h>

#define PCI_VENDOR_ID_REALTEK				0x10ec
#define PCI_DEVICE_ID_REALTEK_RTL8168			0x8168

rge_main_t rge_main;

static pci_device_id_t rge_pci_device_ids[] = {
  {.vendor_id = PCI_VENDOR_ID_REALTEK,.device_id = PCI_DEVICE_ID_REALTEK_RTL8168},
  {0},
};

typedef struct {
    u16 rev;
    char *name;
} rge_device_type_t;

static rge_device_type_t rge_device_types[] = {
  {.rev = 0x4c0,.name = "RTL8168G/RTL8111G"},
  {.rev = 0x500,.name = "RTL8168EP"},
  {.rev = 0x5c8,.name = "RTL8411B"},
  {0},
};


static_always_inline u32
rge_reg_read_u32 (rge_device_t *rd, u16 reg)
{
  return * (u32 *) (rd->bar0 + reg);
}

static_always_inline u8
rge_reg_read_u8 (rge_device_t *rd, u16 reg)
{
  return * (u8 *) (rd->bar0 + reg);
}

#if 0

static inline void
rge_irq_0_disable (rge_device_t * ad)
{
  u32 dyn_ctl0 = 0, icr0_ena = 0;

  dyn_ctl0 |= (3 << 3);		/* 11b = No ITR update */

  rge_reg_write (ad, AVFINT_ICR0_ENA1, icr0_ena);
  rge_reg_write (ad, AVFINT_DYN_CTL0, dyn_ctl0);
  rge_reg_flush (ad);
}

static inline void
rge_irq_0_enable (rge_device_t * ad)
{
  u32 dyn_ctl0 = 0, icr0_ena = 0;

  icr0_ena |= (1 << 30);	/* [30] Admin Queue Enable */

  dyn_ctl0 |= (1 << 0);		/* [0] Interrupt Enable */
  dyn_ctl0 |= (1 << 1);		/* [1] Clear PBA */
  //dyn_ctl0 |= (3 << 3);               /* [4:3] ITR Index, 11b = No ITR update */
  dyn_ctl0 |= ((RGE_ITR_INT / 2) << 5);	/* [16:5] ITR Interval in 2us steps */

  rge_irq_0_disable (ad);
  rge_reg_write (ad, AVFINT_ICR0_ENA1, icr0_ena);
  rge_reg_write (ad, AVFINT_DYN_CTL0, dyn_ctl0);
  rge_reg_flush (ad);
}

static inline void
rge_irq_n_disable (rge_device_t * ad, u8 line)
{
  u32 dyn_ctln = 0;

  rge_reg_write (ad, AVFINT_DYN_CTLN (line), dyn_ctln);
  rge_reg_flush (ad);
}

static inline void
rge_irq_n_enable (rge_device_t * ad, u8 line)
{
  u32 dyn_ctln = 0;

  dyn_ctln |= (1 << 0);		/* [0] Interrupt Enable */
  dyn_ctln |= (1 << 1);		/* [1] Clear PBA */
  dyn_ctln |= ((RGE_ITR_INT / 2) << 5);	/* [16:5] ITR Interval in 2us steps */

  rge_irq_n_disable (ad, line);
  rge_reg_write (ad, AVFINT_DYN_CTLN (line), dyn_ctln);
  rge_reg_flush (ad);
}


clib_error_t *
rge_aq_desc_enq (vlib_main_t * vm, rge_device_t * ad, rge_aq_desc_t * dt,
		 void *data, int len)
{
  rge_main_t *am = &rge_main;
  clib_error_t *err = 0;
  rge_aq_desc_t *d, dc;
  int n_retry = 5;

  d = &ad->atq[ad->atq_next_slot];
  clib_memcpy_fast (d, dt, sizeof (rge_aq_desc_t));
  d->flags |= RGE_AQ_F_RD | RGE_AQ_F_SI;
  if (len)
    d->datalen = len;
  if (len)
    {
      u64 pa;
      pa = ad->atq_bufs_pa + ad->atq_next_slot * RGE_MBOX_BUF_SZ;
      d->addr_hi = (u32) (pa >> 32);
      d->addr_lo = (u32) pa;
      clib_memcpy_fast (ad->atq_bufs + ad->atq_next_slot * RGE_MBOX_BUF_SZ,
			data, len);
      d->flags |= RGE_AQ_F_BUF;
    }

  if (ad->flags & RGE_DEVICE_F_ELOG)
    clib_memcpy_fast (&dc, d, sizeof (rge_aq_desc_t));

  CLIB_MEMORY_BARRIER ();
  vlib_log_debug (am->log_class, "%U", format_hexdump, data, len);
  ad->atq_next_slot = (ad->atq_next_slot + 1) % RGE_MBOX_LEN;
  rge_reg_write (ad, RGE_ATQT, ad->atq_next_slot);
  rge_reg_flush (ad);

retry:
  vlib_process_suspend (vm, 10e-6);

  if (((d->flags & RGE_AQ_F_DD) == 0) || ((d->flags & RGE_AQ_F_CMP) == 0))
    {
      if (--n_retry == 0)
	{
	  err = clib_error_return (0, "adminq enqueue timeout [opcode 0x%x]",
				   d->opcode);
	  goto done;
	}
      goto retry;
    }

  clib_memcpy_fast (dt, d, sizeof (rge_aq_desc_t));
  if (d->flags & RGE_AQ_F_ERR)
    return clib_error_return (0, "adminq enqueue error [opcode 0x%x, retval "
			      "%d]", d->opcode, d->retval);

done:
  if (ad->flags & RGE_DEVICE_F_ELOG)
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
rge_cmd_rx_ctl_reg_write (vlib_main_t * vm, rge_device_t * ad, u32 reg,
			  u32 val)
{
  clib_error_t *err;
  rge_aq_desc_t d = {.opcode = 0x207,.param1 = reg,.param3 = val };
  err = rge_aq_desc_enq (vm, ad, &d, 0, 0);

  if (ad->flags & RGE_DEVICE_F_ELOG)
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
rge_rxq_init (vlib_main_t * vm, rge_device_t * ad, u16 qid, u16 rxq_size)
{
  clib_error_t *err;
  rge_rxq_t *rxq;
  u32 n_alloc, i;

  vec_validate_aligned (ad->rxqs, qid, CLIB_CACHE_LINE_BYTES);
  rxq = vec_elt_at_index (ad->rxqs, qid);
  rxq->size = rxq_size;
  rxq->next = 0;
  rxq->descs = vlib_physmem_alloc_aligned (vm, rxq->size *
					   sizeof (rge_rx_desc_t),
					   2 * CLIB_CACHE_LINE_BYTES);
  if (rxq->descs == 0)
    return vlib_physmem_last_error (vm);

  if ((err = vlib_pci_map_dma (vm, ad->pci_dev_handle, (void *) rxq->descs)))
    return err;

  clib_memset ((void *) rxq->descs, 0, rxq->size * sizeof (rge_rx_desc_t));
  vec_validate_aligned (rxq->bufs, rxq->size, CLIB_CACHE_LINE_BYTES);
  rxq->qrx_tail = ad->bar0 + RGE_QRX_TAIL (qid);

  n_alloc = vlib_buffer_alloc (vm, rxq->bufs, rxq->size - 8);

  if (n_alloc == 0)
    return clib_error_return (0, "buffer allocation error");

  rxq->n_enqueued = n_alloc;
  rge_rx_desc_t *d = rxq->descs;
  for (i = 0; i < n_alloc; i++)
    {
      vlib_buffer_t *b = vlib_get_buffer (vm, rxq->bufs[i]);
      if (ad->flags & RGE_DEVICE_F_VA_DMA)
	d->qword[0] = vlib_buffer_get_va (b);
      else
	d->qword[0] = vlib_buffer_get_pa (vm, b);
      d++;
    }

  ad->n_rx_queues = clib_min (ad->num_queue_pairs, qid + 1);
  return 0;
}

clib_error_t *
rge_txq_init (vlib_main_t * vm, rge_device_t * ad, u16 qid, u16 txq_size)
{
  clib_error_t *err;
  rge_txq_t *txq;

  if (qid >= ad->num_queue_pairs)
    {
      qid = qid % ad->num_queue_pairs;
      txq = vec_elt_at_index (ad->txqs, qid);
      if (txq->lock == 0)
	clib_spinlock_init (&txq->lock);
      ad->flags |= RGE_DEVICE_F_SHARED_TXQ_LOCK;
      return 0;
    }

  vec_validate_aligned (ad->txqs, qid, CLIB_CACHE_LINE_BYTES);
  txq = vec_elt_at_index (ad->txqs, qid);
  txq->size = txq_size;
  txq->next = 0;
  txq->descs = vlib_physmem_alloc_aligned (vm, txq->size *
					   sizeof (rge_tx_desc_t),
					   2 * CLIB_CACHE_LINE_BYTES);
  if (txq->descs == 0)
    return vlib_physmem_last_error (vm);

  if ((err = vlib_pci_map_dma (vm, ad->pci_dev_handle, (void *) txq->descs)))
    return err;

  vec_validate_aligned (txq->bufs, txq->size, CLIB_CACHE_LINE_BYTES);
  txq->qtx_tail = ad->bar0 + RGE_QTX_TAIL (qid);

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
rge_arq_slot_init (rge_device_t * ad, u16 slot)
{
  rge_aq_desc_t *d;
  u64 pa = ad->arq_bufs_pa + slot * RGE_MBOX_BUF_SZ;
  d = &ad->arq[slot];
  clib_memset (d, 0, sizeof (rge_aq_desc_t));
  d->flags = RGE_AQ_F_BUF;
  d->datalen = RGE_MBOX_BUF_SZ;
  d->addr_hi = (u32) (pa >> 32);
  d->addr_lo = (u32) pa;
}

static inline uword
rge_dma_addr (vlib_main_t * vm, rge_device_t * ad, void *p)
{
  return (ad->flags & RGE_DEVICE_F_VA_DMA) ?
    pointer_to_uword (p) : vlib_physmem_get_pa (vm, p);
}



clib_error_t *
rge_device_reset (vlib_main_t * vm, rge_device_t * ad)
{
  rge_aq_desc_t d = { 0 };
  clib_error_t *error;
  u32 rstat;
  int n_retry = 20;

  d.opcode = 0x801;
  d.v_opcode = VIRTCHNL_OP_RESET_VF;
  if ((error = rge_aq_desc_enq (vm, ad, &d, 0, 0)))
    return error;

retry:
  vlib_process_suspend (vm, 10e-3);
  rstat = rge_get_u32 (ad->bar0, AVFGEN_RSTAT);

  if (rstat == 2 || rstat == 3)
    return 0;

  if (--n_retry == 0)
    return clib_error_return (0, "reset failed (timeout)");

  goto retry;
}

clib_error_t *
rge_device_init (vlib_main_t * vm, rge_main_t * am, rge_device_t * ad,
		 rge_create_if_args_t * args)
{
  virtchnl_version_info_t ver = { 0 };
  virtchnl_vf_resource_t res = { 0 };
  clib_error_t *error;
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  int i;

  rge_adminq_init (vm, ad);

  /* request more queues only if we need them */
  if ((error = rge_request_queues (vm, ad, tm->n_vlib_mains)))
    {
      /* we failed to get more queues, but still we want to proceed */
      clib_error_free (error);

      if ((error = rge_device_reset (vm, ad)))
	return error;
    }

  rge_adminq_init (vm, ad);

  /*
   * OP_VERSION
   */
  if ((error = rge_op_version (vm, ad, &ver)))
    return error;

  if (ver.major != VIRTCHNL_VERSION_MAJOR ||
      ver.minor != VIRTCHNL_VERSION_MINOR)
    return clib_error_return (0, "incompatible protocol version "
			      "(remote %d.%d)", ver.major, ver.minor);

  /*
   * OP_GET_VF_RESOUCES
   */
  if ((error = rge_op_get_vf_resources (vm, ad, &res)))
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
  if ((error = rge_op_disable_vlan_stripping (vm, ad)))
    return error;

  if ((error = rge_config_promisc_mode (vm, ad)))
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
    if ((error = rge_rxq_init (vm, ad, i, args->rxq_size)))
      return error;

  for (i = 0; i < tm->n_vlib_mains; i++)
    if ((error = rge_txq_init (vm, ad, i, args->txq_size)))
      return error;

  if ((ad->feature_bitmap & VIRTCHNL_VF_OFFLOAD_RSS_PF) &&
      (error = rge_op_config_rss_lut (vm, ad)))
    return error;

  if ((ad->feature_bitmap & VIRTCHNL_VF_OFFLOAD_RSS_PF) &&
      (error = rge_op_config_rss_key (vm, ad)))
    return error;

  if ((error = rge_op_config_vsi_queues (vm, ad)))
    return error;

  if ((error = rge_op_config_irq_map (vm, ad)))
    return error;

  rge_irq_0_enable (ad);
  for (i = 0; i < ad->n_rx_queues; i++)
    rge_irq_n_enable (ad, i);

  if ((error = rge_op_add_eth_addr (vm, ad, 1, ad->hwaddr)))
    return error;

  if ((error = rge_op_enable_queues (vm, ad, ad->n_rx_queues, 0)))
    return error;

  if ((error = rge_op_enable_queues (vm, ad, 0, ad->n_tx_queues)))
    return error;

  ad->flags |= RGE_DEVICE_F_INITIALIZED;
  return error;
}

void
rge_process_one_device (vlib_main_t * vm, rge_device_t * ad, int is_irq)
{
  rge_main_t *am = &rge_main;
  vnet_main_t *vnm = vnet_get_main ();
  virtchnl_pf_event_t *e;
  u32 r;

  if (ad->flags & RGE_DEVICE_F_ERROR)
    return;

  if ((ad->flags & RGE_DEVICE_F_INITIALIZED) == 0)
    return;

  ASSERT (ad->error == 0);

  /* do not process device in reset state */
  r = rge_get_u32 (ad->bar0, AVFGEN_RSTAT);
  if (r != VIRTCHNL_VFR_VFACTIVE)
    return;

  r = rge_get_u32 (ad->bar0, RGE_ARQLEN);
  if ((r & 0xf0000000) != (1ULL << 31))
    {
      ad->error = clib_error_return (0, "arq not enabled, arqlen = 0x%x", r);
      goto error;
    }

  r = rge_get_u32 (ad->bar0, RGE_ATQLEN);
  if ((r & 0xf0000000) != (1ULL << 31))
    {
      ad->error = clib_error_return (0, "atq not enabled, atqlen = 0x%x", r);
      goto error;
    }

  if (is_irq == 0)
    rge_op_get_stats (vm, ad, &ad->eth_stats);

  /* *INDENT-OFF* */
  vec_foreach (e, ad->events)
    {
      if (e->event == VIRTCHNL_EVENT_LINK_CHANGE)
	{
	  int link_up = e->event_data.link_event.link_status;
	  virtchnl_link_speed_t speed = e->event_data.link_event.link_speed;
	  u32 flags = 0;
	  u32 kbps = 0;

	  if (link_up && (ad->flags & RGE_DEVICE_F_LINK_UP) == 0)
	    {
	      ad->flags |= RGE_DEVICE_F_LINK_UP;
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
	  else if (!link_up && (ad->flags & RGE_DEVICE_F_LINK_UP) != 0)
	    {
	      ad->flags &= ~RGE_DEVICE_F_LINK_UP;
	      ad->link_speed = 0;
	    }

	  if (ad->flags & RGE_DEVICE_F_ELOG)
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
	  if (ad->flags & RGE_DEVICE_F_ELOG)
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
  ad->flags |= RGE_DEVICE_F_ERROR;
  ASSERT (ad->error != 0);
  vlib_log_err (am->log_class, "%U", format_clib_error, ad->error);
}

#endif
static u32
rge_flag_change (vnet_main_t * vnm, vnet_hw_interface_t * hw, u32 flags)
{
  rge_main_t *am = &rge_main;
  vlib_log_warn (am->log_class, "TODO");
  return 0;
}
#if 0

static uword
rge_process (vlib_main_t * vm, vlib_node_runtime_t * rt, vlib_frame_t * f)
{
  rge_main_t *am = &rge_main;
  rge_device_t *ad;
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
	case RGE_PROCESS_EVENT_START:
	  enabled = 1;
	  break;
	case RGE_PROCESS_EVENT_STOP:
	  enabled = 0;
	  continue;
	case RGE_PROCESS_EVENT_AQ_INT:
	  irq = 1;
	  break;
	default:
	  ASSERT (0);
	}

      /* *INDENT-OFF* */
      pool_foreach (ad, am->devices,
        {
	  rge_process_one_device (vm, ad, irq);
        });
      /* *INDENT-ON* */
      last_run_duration = vlib_time_now (vm) - last_periodic_time;
    }
  return 0;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (rge_process_node, static)  = {
  .function = rge_process,
  .type = VLIB_NODE_TYPE_PROCESS,
  .name = "avf-process",
};
/* *INDENT-ON* */

#endif
static void
rge_irq_0_handler (vlib_main_t * vm, vlib_pci_dev_handle_t h, u16 line)
{
  clib_warning ("irq 0");
#if 0
  rge_main_t *am = &rge_main;
  uword pd = vlib_pci_get_private_data (vm, h);
  rge_device_t *ad = pool_elt_at_index (am->devices, pd);
  u32 icr0;

  icr0 = rge_reg_read (ad, AVFINT_ICR0);

  if (ad->flags & RGE_DEVICE_F_ELOG)
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

  rge_irq_0_enable (ad);

  /* bit 30 - Send/Receive Admin queue interrupt indication */
  if (icr0 & (1 << 30))
    vlib_process_signal_event (vm, rge_process_node.index,
			       RGE_PROCESS_EVENT_AQ_INT, 0);
#endif
}

#if 0

static void
rge_irq_n_handler (vlib_main_t * vm, vlib_pci_dev_handle_t h, u16 line)
{
  vnet_main_t *vnm = vnet_get_main ();
  rge_main_t *am = &rge_main;
  uword pd = vlib_pci_get_private_data (vm, h);
  rge_device_t *ad = pool_elt_at_index (am->devices, pd);
  u16 qid;
  int i;

  if (ad->flags & RGE_DEVICE_F_ELOG)
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
    rge_irq_n_enable (ad, i);
}
#endif

void
rge_delete_if (vlib_main_t * vm, rge_device_t * rd)
{
  vnet_main_t *vnm = vnet_get_main ();
  rge_main_t *rm = &rge_main;

  if (rd->hw_if_index != ~0)
    {
      vnet_hw_interface_set_flags (vnm, rd->hw_if_index, 0);
      vnet_hw_interface_unassign_rx_thread (vnm, rd->hw_if_index, 0);
      ethernet_delete_interface (vnm, rd->hw_if_index);
    }

  vlib_pci_device_close (vm, rd->pci_dev_handle);
#if 0
  int i;

  vlib_physmem_free (vm, ad->atq);
  vlib_physmem_free (vm, ad->arq);
  vlib_physmem_free (vm, ad->atq_bufs);
  vlib_physmem_free (vm, ad->arq_bufs);

  /* *INDENT-OFF* */
  vec_foreach_index (i, ad->rxqs)
    {
      rge_rxq_t *rxq = vec_elt_at_index (ad->rxqs, i);
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
      rge_txq_t *txq = vec_elt_at_index (ad->txqs, i);
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

#endif
  clib_error_free (rd->error);
  pool_put (rm->devices, rd);
}

void
rge_create_if (vlib_main_t * vm, rge_create_if_args_t * args)
{
  vnet_main_t *vnm = vnet_get_main ();
  rge_main_t *rm = &rge_main;
  rge_device_t *rd;
  rge_device_type_t * type = rge_device_types;
  vlib_pci_dev_handle_t h;
  clib_error_t *error = 0;
  int i;

  /* check input args */
  args->rxq_size = (args->rxq_size == 0) ? 512 : args->rxq_size;
  args->txq_size = (args->txq_size == 0) ? 512 : args->txq_size;

  if ((args->rxq_size & (args->rxq_size - 1))
      || (args->txq_size & (args->txq_size - 1)))
    {
      args->rv = VNET_API_ERROR_INVALID_VALUE;
      args->error =
	clib_error_return (error, "queue size must be a power of two");
      return;
    }

  pool_get_zero (rm->devices, rd);
  rd->dev_instance = rd - rm->devices;
  rd->per_interface_next_index = ~0;
  rd->hw_if_index = ~0;
  rd->name = vec_dup (args->name);

  if ((error = vlib_pci_device_open (vm, &args->addr, rge_pci_device_ids,
				     &h)))
    {
      pool_put (rm->devices, rd);
      args->rv = VNET_API_ERROR_INVALID_INTERFACE;
      args->error = clib_error_return (error, "failed to open pci device %U",
				       format_vlib_pci_addr, &args->addr);
      return;
    }
  rd->pci_dev_handle = h;

  vlib_pci_set_private_data (vm, h, rd->dev_instance);

  if ((error = vlib_pci_bus_master_enable (vm, h)))
    goto error;

  if ((error = vlib_pci_map_region (vm, h, 2, &rd->bar0)))
    goto error;

#define RGE_REG_IDR0       0x00
#define RGE_REG_IDR1       0x01
#define RGE_REG_IDR2       0x02
#define RGE_REG_IDR3       0x03
#define RGE_REG_IDR4       0x04
#define RGE_REG_IDR5       0x05
#define RGE_REG_TXCFG      0x40

  fformat (stderr, "\n%U\n", format_hexdump, rd->bar0, 128);
  u32 txcfg = rge_reg_read_u32 (rd, RGE_REG_TXCFG);
  u32 rev = txcfg >> 20;

  if ((rev & 0x700) == 0x100 || (rev & 0x700) == 0)
      rev &= 0xfcc;
  else
      rev &= 0x7cc;

  while (type->name)
    {
      if (type->rev == rev)
	{
	  rd->type = type->name;
	  fformat (stderr, "Found device %s", type->name);
	  break;
	}
      type++;
    }

  if (rd->type == 0)
    {
      error = clib_error_return (0, "Unsupported hw revision 0x%x", txcfg);
      goto error;
    }

  rd->hwaddr[0] = rge_reg_read_u8 (rd, RGE_REG_IDR0);
  rd->hwaddr[1] = rge_reg_read_u8 (rd, RGE_REG_IDR1);
  rd->hwaddr[2] = rge_reg_read_u8 (rd, RGE_REG_IDR2);
  rd->hwaddr[3] = rge_reg_read_u8 (rd, RGE_REG_IDR3);
  rd->hwaddr[4] = rge_reg_read_u8 (rd, RGE_REG_IDR4);
  rd->hwaddr[5] = rge_reg_read_u8 (rd, RGE_REG_IDR5);

  if (0 &&(error = vlib_pci_register_msix_handler (vm, h, 0, 1,
					       &rge_irq_0_handler)))
    goto error;

  if (0 && (error = vlib_pci_enable_msix_irq (vm, h, 0, 2)))
    goto error;
#if 0

  if (!(ad->atq = vlib_physmem_alloc (vm, sizeof (rge_aq_desc_t) *
				      RGE_MBOX_LEN)))
    {
      error = vlib_physmem_last_error (vm);
      goto error;
    }

  if ((error = vlib_pci_map_dma (vm, h, ad->atq)))
    goto error;

  if (!(ad->arq = vlib_physmem_alloc (vm, sizeof (rge_aq_desc_t) *
				      RGE_MBOX_LEN)))
    {
      error = vlib_physmem_last_error (vm);
      goto error;
    }

  if ((error = vlib_pci_map_dma (vm, h, ad->arq)))
    goto error;

  if (!(ad->atq_bufs = vlib_physmem_alloc (vm, RGE_MBOX_BUF_SZ *
					   RGE_MBOX_LEN)))
    {
      error = vlib_physmem_last_error (vm);
      goto error;
    }

  if ((error = vlib_pci_map_dma (vm, h, ad->atq_bufs)))
    goto error;

  if (!(ad->arq_bufs = vlib_physmem_alloc (vm, RGE_MBOX_BUF_SZ *
					   RGE_MBOX_LEN)))
    {
      error = vlib_physmem_last_error (vm);
      goto error;
    }

  if ((error = vlib_pci_map_dma (vm, h, ad->arq_bufs)))
    goto error;

  if ((error = vlib_pci_intr_enable (vm, h)))
    goto error;

  if (vlib_pci_supports_virtual_addr_dma (vm, h))
    ad->flags |= RGE_DEVICE_F_VA_DMA;

  if ((error = rge_device_init (vm, am, ad, args)))
    goto error;
#endif

  /* create interface */
  error = ethernet_register_interface (vnm, rge_device_class.index,
				       rd->dev_instance, rd->hwaddr,
				       &rd->hw_if_index, rge_flag_change);

  if (error)
    goto error;

  vnet_sw_interface_t *sw = vnet_get_hw_sw_interface (vnm, rd->hw_if_index);
  args->sw_if_index = rd->sw_if_index = sw->sw_if_index;

  vnet_hw_interface_t *hw = vnet_get_hw_interface (vnm, rd->hw_if_index);
  hw->flags |= VNET_HW_INTERFACE_FLAG_SUPPORTS_INT_MODE;
  vnet_hw_interface_set_input_node (vnm, rd->hw_if_index,
				    rge_input_node.index);

  for (i = 0; i < rd->n_rx_queues; i++)
    vnet_hw_interface_assign_rx_thread (vnm, rd->hw_if_index, i, ~0);
#if 0

  if (pool_elts (am->devices) == 1)
    vlib_process_signal_event (vm, rge_process_node.index,
			       RGE_PROCESS_EVENT_START, 0);

#endif
  return;

error:
  rge_delete_if (vm, rd);
  args->rv = VNET_API_ERROR_INVALID_INTERFACE;
  args->error = clib_error_return (error, "pci-addr %U",
				   format_vlib_pci_addr, &args->addr);
  vlib_log_err (rm->log_class, "%U", format_clib_error, args->error);
}

static clib_error_t *
rge_interface_admin_up_down (vnet_main_t * vnm, u32 hw_if_index, u32 flags)
{
  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, hw_if_index);
  rge_main_t *am = &rge_main;
  rge_device_t *ad = vec_elt_at_index (am->devices, hi->dev_instance);
  uword is_up = (flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP) != 0;

  if (ad->flags & RGE_DEVICE_F_ERROR)
    return clib_error_return (0, "device is in error state");

  if (is_up)
    {
      vnet_hw_interface_set_flags (vnm, ad->hw_if_index,
				   VNET_HW_INTERFACE_FLAG_LINK_UP);
      ad->flags |= RGE_DEVICE_F_ADMIN_UP;
    }
  else
    {
      vnet_hw_interface_set_flags (vnm, ad->hw_if_index, 0);
      ad->flags &= ~RGE_DEVICE_F_ADMIN_UP;
    }
  return 0;
}

static clib_error_t *
rge_interface_rx_mode_change (vnet_main_t * vnm, u32 hw_if_index, u32 qid,
			      vnet_hw_interface_rx_mode mode)
{
  rge_main_t *am = &rge_main;
  vnet_hw_interface_t *hw = vnet_get_hw_interface (vnm, hw_if_index);
  rge_device_t *ad = pool_elt_at_index (am->devices, hw->dev_instance);
  rge_rxq_t *rxq = vec_elt_at_index (ad->rxqs, qid);

  if (mode == VNET_HW_INTERFACE_RX_MODE_POLLING)
    rxq->int_mode = 0;
  else
    rxq->int_mode = 1;

  return 0;
}

static void
rge_set_interface_next_node (vnet_main_t * vnm, u32 hw_if_index,
			     u32 node_index)
{
  rge_main_t *am = &rge_main;
  vnet_hw_interface_t *hw = vnet_get_hw_interface (vnm, hw_if_index);
  rge_device_t *ad = pool_elt_at_index (am->devices, hw->dev_instance);

  /* Shut off redirection */
  if (node_index == ~0)
    {
      ad->per_interface_next_index = node_index;
      return;
    }

  ad->per_interface_next_index =
    vlib_node_add_next (vlib_get_main (), rge_input_node.index, node_index);
}

static char *rge_tx_func_error_strings[] = {
#define _(n,s) s,
  foreach_rge_tx_func_error
#undef _
};

/* *INDENT-OFF* */
VNET_DEVICE_CLASS (rge_device_class,) =
{
  .name = "Realtek Gigabit Ethernet Interface",
  .format_device = format_rge_device,
  .format_device_name = format_rge_device_name,
  .admin_up_down_function = rge_interface_admin_up_down,
  .rx_mode_change_function = rge_interface_rx_mode_change,
  .rx_redirect_to_node = rge_set_interface_next_node,
  .tx_function_n_errors = RGE_TX_N_ERROR,
  .tx_function_error_strings = rge_tx_func_error_strings,
};
/* *INDENT-ON* */

clib_error_t *
rge_init (vlib_main_t * vm)
{
  rge_main_t *am = &rge_main;
  clib_error_t *error;

  if ((error = vlib_call_init_function (vm, pci_bus_init)))
    return error;

  am->log_class = vlib_log_register_class ("rge_plugin", 0);
  vlib_log_debug (am->log_class, "initialized");

  return 0;
}

VLIB_INIT_FUNCTION (rge_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
