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
#include <vlib/unix/unix.h>
#include <vlib/pci/pci.h>
#include <vnet/ethernet/ethernet.h>

#include <avf/avf.h>

#define AVF_MBOX_LEN 64
#define AVF_MBOX_BUF_SZ 512
#define AVF_RXQ_SZ 512
#define AVF_TXQ_SZ 512

avf_main_t avf_main;

//#define avf_log_debug(fmt, ...) fformat(stderr, "%s: " fmt "\n", __func__, __VA_ARGS__)
#define avf_log_debug(fmt, ...)

void
avf_create_if (avf_create_if_args_t * args)
{
}

void
avf_delete_if (avf_device_t * ad)
{
}

clib_error_t *
avf_aq_desc_enq (vlib_main_t * vm, avf_device_t * ad, avf_aq_desc_t * dt,
		 void *data, int len)
{
  avf_aq_desc_t *d;
  int n_retry = 5;

  d = &ad->atq[ad->atq_next_slot];
  clib_memcpy (d, dt, sizeof (avf_aq_desc_t));
  d->flags |= AVF_AQ_F_RD;
  if (len)
    d->datalen = len;
  if (len)
    {
      u64 pa;
      pa = ad->atq_bufs_pa + ad->atq_next_slot * AVF_MBOX_BUF_SZ;
      d->addr_hi = (u32) (pa >> 32);
      d->addr_lo = (u32) pa;
      clib_memcpy (ad->atq_bufs + ad->atq_next_slot * AVF_MBOX_BUF_SZ, data,
		   len);
      d->flags |= AVF_AQ_F_BUF;
    }
  CLIB_MEMORY_BARRIER ();
  avf_log_debug ("%U", format_hexdump, data, len);
  ad->atq_next_slot = (ad->atq_next_slot + 1) % AVF_MBOX_LEN;
  avf_reg_write (ad, AVF_ATQT, ad->atq_next_slot);
  avf_reg_flush (ad);

retry:
  vlib_process_suspend (vm, 10e-6);

  if (((d->flags & AVF_AQ_F_DD) == 0) || ((d->flags & AVF_AQ_F_CMP) == 0))
    {
      if (--n_retry == 0)
	return clib_error_return (0, "adminq enqueue timeout [opcode 0x%x]",
				  d->opcode);
      goto retry;
    }

  clib_memcpy (dt, d, sizeof (avf_aq_desc_t));
  if (d->flags & AVF_AQ_F_ERR)
    return clib_error_return (0, "adminq enqueue error [opcode 0x%x, retval "
			      "%d]", d->opcode, d->retval);

  return 0;
}

clib_error_t *
avf_cmd_rx_ctl_reg_write (vlib_main_t * vm, avf_device_t * ad, u32 reg,
			  u32 val)
{
  avf_aq_desc_t d = {.opcode = 0x207,.param1 = reg,.param3 = val };
  return avf_aq_desc_enq (vm, ad, &d, 0, 0);
}

clib_error_t *
avf_rxq_init (vlib_main_t * vm, avf_device_t * ad, u16 qid)
{
  avf_main_t *am = &avf_main;
  avf_rxq_t *rxq;
  clib_error_t *error = 0;
  vec_validate_aligned (ad->rxqs, qid, CLIB_CACHE_LINE_BYTES);
  rxq = vec_elt_at_index (ad->rxqs, qid);
  rxq->size = AVF_RXQ_SZ;
  rxq->descs = vlib_physmem_alloc_aligned (vm, am->physmem_region, &error,
					   rxq->size * sizeof (avf_rx_desc_t),
					   CLIB_CACHE_LINE_BYTES);
  memset (rxq->descs, 0, rxq->size * sizeof (avf_rx_desc_t));
  vec_validate_aligned (rxq->bufs, rxq->size, CLIB_CACHE_LINE_BYTES);
  rxq->n_bufs = 0;
  rxq->qrx_tail = ad->bar0 + AVF_QRX_TAIL (qid);

  vlib_buffer_alloc (vm, rxq->bufs, rxq->size - 1);
  rxq->n_bufs = rxq->size - 1;
  avf_rx_desc_t *d = rxq->descs;
  for (int i = 0; i < rxq->size - 1; i++)
    {
      d->qword[0] = vlib_get_buffer_data_physical_address (vm, rxq->bufs[i]);
      d++;
    }
  return 0;
}

clib_error_t *
avf_txq_init (vlib_main_t * vm, avf_device_t * ad, u16 qid)
{
  avf_main_t *am = &avf_main;
  avf_txq_t *txq;
  clib_error_t *error = 0;
  vec_validate_aligned (ad->txqs, qid, CLIB_CACHE_LINE_BYTES);
  txq = vec_elt_at_index (ad->txqs, qid);
  txq->size = AVF_TXQ_SZ;
  txq->descs = vlib_physmem_alloc_aligned (vm, am->physmem_region, &error,
					   txq->size * sizeof (avf_tx_desc_t),
					   CLIB_CACHE_LINE_BYTES);
  txq->qtx_tail = ad->bar0 + AVF_QTX_TAIL (qid);
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
  memset (d, 0, sizeof (avf_aq_desc_t));
  d->flags = AVF_AQ_F_SI | AVF_AQ_F_BUF;
  d->datalen = AVF_MBOX_BUF_SZ;
  d->addr_hi = (u32) (pa >> 32);
  d->addr_lo = (u32) pa;
}

static void
avf_adminq_init (vlib_main_t * vm, avf_device_t * ad)
{
  avf_main_t *am = &avf_main;
  u64 pa;
  int i;

  /* VF MailBox Receive */
  memset (ad->arq, 0, sizeof (avf_aq_desc_t) * AVF_MBOX_LEN);
  ad->arq_bufs_pa = vlib_physmem_virtual_to_physical (vm, am->physmem_region,
						      ad->arq_bufs);

  /* VF MailBox Transmit */
  memset (ad->atq, 0, sizeof (avf_aq_desc_t) * AVF_MBOX_LEN);
  ad->atq_bufs_pa = vlib_physmem_virtual_to_physical (vm, am->physmem_region,
						      ad->atq_bufs);
  pa = vlib_physmem_virtual_to_physical (vm, am->physmem_region, ad->atq);
  avf_reg_write (ad, AVF_ATQT, 0);	/* Tail */
  avf_reg_write (ad, AVF_ATQH, 0);	/* Head */
  avf_reg_write (ad, AVF_ATQLEN, AVF_MBOX_LEN | (1 << 31));	/* len & ena */
  avf_reg_write (ad, AVF_ATQBAL, (u32) pa);	/* Base Address Low */
  avf_reg_write (ad, AVF_ATQBAH, (u32) (pa >> 32));	/* Base Address High */

  avf_reg_write (ad, AVF_ARQLEN, 0);	/* len & ena */
  avf_reg_write (ad, AVF_ARQT, 0);	/* Tail */
  avf_reg_write (ad, AVF_ARQH, 0);	/* Head */
  avf_reg_write (ad, AVF_ARQLEN, 0);
  avf_reg_write (ad, AVF_ARQBAL, 0);
  avf_reg_write (ad, AVF_ARQBAH, 0);
  avf_reg_flush (ad);

  for (i = 0; i < AVF_MBOX_LEN; i++)
    avf_arq_slot_init (ad, i);

  pa = vlib_physmem_virtual_to_physical (vm, am->physmem_region, ad->arq);
  avf_reg_write (ad, AVF_ARQT, 0);	/* Tail */
  avf_reg_write (ad, AVF_ARQH, 0);	/* Head */
  avf_reg_write (ad, AVF_ARQLEN, AVF_MBOX_LEN | (1 << 31));	/* len & ena */
  avf_reg_write (ad, AVF_ARQBAL, (u32) pa);	/* Base Address Low */
  avf_reg_write (ad, AVF_ARQBAH, (u32) (pa >> 32));	/* Base Address High */

  ad->atq_next_slot = 0;
  ad->arq_next_slot = 0;

  /*enqueue rx */
  avf_reg_write (ad, AVF_ARQT, AVF_MBOX_LEN - 1);	/* Tail */
}

clib_error_t *
avf_send_to_pf (vlib_main_t * vm, avf_device_t * ad, virtchnl_ops_t op,
		void *in, int in_len, void *out, int out_len)
{
  clib_error_t *err;
  avf_aq_desc_t *d, dt = {.opcode = 0x801,.v_opcode = op };
  u32 head;
  int n_retry = 5;

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
      avf_arq_slot_init (ad, ad->arq_next_slot);
      ad->arq_next_slot++;
      n_retry = 5;
      goto retry;
    }

  if (d->v_opcode != op)
    {
      return clib_error_return (0,
				"unexpected message receiver [v_opcode = %u]",
				d->v_opcode);
    }

  if (d->v_retval)
    return clib_error_return (0, "error [v_opcode = %u, v_retval %d]",
			      d->v_opcode, d->v_retval);

  if (d->flags |= AVF_AQ_F_BUF)
    {
      void *buf = ad->arq_bufs + ad->arq_next_slot * AVF_MBOX_BUF_SZ;
      clib_memcpy (out, buf, out_len);
    }

  avf_arq_slot_init (ad, ad->arq_next_slot);
  avf_reg_write (ad, AVF_ARQT, ad->arq_next_slot);
  avf_reg_flush (ad);
  ad->arq_next_slot = (ad->arq_next_slot + 1) % AVF_MBOX_LEN;
  return 0;
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
  clib_error_t *err = 0;
  u32 bitmap = (VIRTCHNL_VF_OFFLOAD_L2 | VIRTCHNL_VF_OFFLOAD_RSS_AQ |
		VIRTCHNL_VF_OFFLOAD_RSS_REG | VIRTCHNL_VF_OFFLOAD_WB_ON_ITR |
		VIRTCHNL_VF_OFFLOAD_VLAN | VIRTCHNL_VF_OFFLOAD_RX_POLLING);

  err = avf_send_to_pf (vm, ad, VIRTCHNL_OP_GET_VF_RESOURCES, &bitmap,
			sizeof (u32), res, sizeof (virtchnl_vf_resource_t)
			/*+ sizeof (virtchnl_vsi_resource_t) */ );

  if (err)
    return err;

  return err;
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
  avf_main_t *am = &avf_main;
  int i;
  int n_qp = clib_max (vec_len (ad->rxqs), vec_len (ad->txqs));
  int msg_len = sizeof (virtchnl_vsi_queue_config_info_t) + n_qp *
    sizeof (virtchnl_queue_pair_info_t);
  u8 msg[msg_len];
  virtchnl_vsi_queue_config_info_t *ci;

  memset (msg, 0, msg_len);
  ci = (virtchnl_vsi_queue_config_info_t *) msg;
  ci->vsi_id = ad->vsi_id;
  ci->num_queue_pairs = n_qp;

  for (i = 0; i < n_qp; i++)
    {
      virtchnl_txq_info_t *txq = &ci->qpair[i].txq;
      virtchnl_rxq_info_t *rxq = &ci->qpair[i].rxq;

      if (i < vec_len (ad->rxqs))
	{
	  avf_rxq_t *q = vec_elt_at_index (ad->rxqs, i);
	  rxq->vsi_id = ad->vsi_id;
	  rxq->queue_id = i;
	  rxq->ring_len = q->size;
	  rxq->databuffer_size = VLIB_BUFFER_DEFAULT_FREE_LIST_BYTES;
	  rxq->max_pkt_size = 1518;
	  rxq->dma_ring_addr =
	    vlib_physmem_virtual_to_physical (vm, am->physmem_region,
					      q->descs);
	  avf_reg_write (ad, AVF_QRX_TAIL (i), q->size - 1);
	}
      if (i < vec_len (ad->txqs))
	{
	  avf_txq_t *q = vec_elt_at_index (ad->txqs, i);
	  txq->vsi_id = ad->vsi_id;
	  txq->queue_id = i;
	  txq->ring_len = q->size;
	  txq->dma_ring_addr =
	    vlib_physmem_virtual_to_physical (vm, am->physmem_region,
					      q->descs);
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

  memset (msg, 0, msg_len);
  imi = (virtchnl_irq_map_info_t *) msg;
  imi->num_vectors = count;
  imi->vecmap[0].vsi_id = ad->vsi_id;
  imi->vecmap[0].rxq_map = 1;
  imi->vecmap[0].txitr_idx = 0x7f40;
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

  memset (msg, 0, msg_len);
  al = (virtchnl_ether_addr_list_t *) msg;
  al->vsi_id = ad->vsi_id;
  al->num_elements = count;
  for (i = 0; i < count; i++)
    clib_memcpy (&al->list[i].addr, macs + i * 6, 6);
  return avf_send_to_pf (vm, ad, VIRTCHNL_OP_ADD_ETH_ADDR, msg, msg_len, 0,
			 0);
}

clib_error_t *
avf_op_enable_queues (vlib_main_t * vm, avf_device_t * ad, u32 rx, u32 tx)
{
  virtchnl_queue_select_t qs = { 0 };
  qs.vsi_id = ad->vsi_id;
  qs.rx_queues = rx;
  qs.tx_queues = tx;
  avf_rxq_t *rxq = vec_elt_at_index (ad->rxqs, 0);
  avf_reg_write (ad, AVF_QRX_TAIL (0), rxq->size - 1);
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
avf_device_init (vlib_main_t * vm, avf_device_t * ad)
{
  vnet_main_t *vnm = vnet_get_main ();
  virtchnl_version_info_t ver = { 0 };
  virtchnl_vf_resource_t res = { 0 };
  clib_error_t *error;

  avf_adminq_init (vm, ad);

  if ((error = avf_device_reset (vm, ad)))
    return error;

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

  //FIXME check res.num_vsis
  //FIXME check res.vsi_res[0].vsi_type == 6

  ad->vsi_id = res.vsi_res[0].vsi_id;
  ad->feature_bitmap = res.vf_offload_flags;
  clib_memcpy (ad->hwaddr, res.vsi_res[0].default_mac_addr, 6);
  if ((error = vnet_hw_interface_change_mac_address (vnm, ad->hw_if_index,
						     ad->hwaddr)))
    return error;
  /*
   * Disable VLAN stripping
   */
  if ((error = avf_op_disable_vlan_stripping (vm, ad)))
    return error;

  if ((error = avf_config_promisc_mode (vm, ad)))
    return error;

  if ((error = avf_cmd_rx_ctl_reg_write (vm, ad, 0xc400, 0)))
    return error;

  if ((error = avf_cmd_rx_ctl_reg_write (vm, ad, 0xc404, 0)))
    return error;

  /*
   * Init Queues
   */
  if ((error = avf_rxq_init (vm, ad, 0)))
    return error;

  if ((error = avf_txq_init (vm, ad, 0)))
    return error;

  if ((error = avf_op_config_vsi_queues (vm, ad)))
    return error;

  if ((error = avf_op_config_irq_map (vm, ad)))
    return error;

  if ((error = avf_op_add_eth_addr (vm, ad, 1, ad->hwaddr)))
    return error;

  if ((error = avf_op_enable_queues (vm, ad, 1, 0)))
    return error;

  if ((error = avf_op_enable_queues (vm, ad, 0, 1)))
    return error;

  ad->flags |= AVF_DEVICE_F_INITIALIZED;
  return error;
}

#if 0
clib_error_t *
avf_recv_from_pf (vlib_main_t * vm, avf_device_t * ad, u16 slot)
{
  void *buf = ad->arq_bufs + slot * AVF_MBOX_BUF_SZ;
  avf_aq_desc_t *d = &ad->arq[slot];

  if (d->v_opcode == VIRTCHNL_OP_EVENT)
    {
      virtchnl_pf_event_t *e = buf;
      if (e->event == VIRTCHNL_EVENT_LINK_CHANGE)
	avf_log_debug
	  ("link change event severity %d link_speed %d link_status %d",
	   e->event, e->severity, e->event_data.link_event.link_speed,
	   e->event_data.link_event.link_status);
      else
	avf_log_debug ("event %d severity %d", e->event, e->severity);
    }

  return 0;
}
#endif

void
avf_process_one_device (vlib_main_t * vm, avf_device_t * ad)
{
  clib_error_t *error = 0;
  u32 r;

  if (ad->flags & AVF_DEVICE_F_ERROR)
    return;

  ASSERT (ad->error == 0);

  if ((ad->flags & AVF_DEVICE_F_INITIALIZED) == 0)
    if ((error = avf_device_init (vm, ad)))
      {
	clib_error_report (error);
	goto error;
      }

  r = avf_get_u32 (ad->bar0, AVF_ARQLEN);
  if ((r & 0xf0000000) != (1 << 31))
    {
      avf_log_debug ("arq not enabled, arqlen = 0x%x", r);
      goto error;
    }

  r = avf_get_u32 (ad->bar0, AVF_ATQLEN);
  if ((r & 0xf0000000) != (1 << 31))
    {
      avf_log_debug ("atq not enabled, atqlen = 0x%x", r);
      goto error;
    }

  if (ad->flags & AVF_DEVICE_F_INITIALIZED)
    avf_op_get_stats (vm, ad, &ad->eth_stats);

#if 0
  r = avf_get_u32 (ad->bar0, AVF_ARQH);
  while (ad->arq_next_slot != r)
    {
      error = avf_recv_from_pf (vm, ad, ad->arq_next_slot);
      avf_arq_slot_init (ad, ad->arq_next_slot);
      avf_reg_write (ad, AVF_ARQT, ad->arq_next_slot);
      avf_reg_flush (ad);
      ad->arq_next_slot = (ad->arq_next_slot + 1) % AVF_MBOX_LEN;
      if (error)
	goto error;
    }
#endif

  return;

error:
  ad->flags |= AVF_DEVICE_F_ERROR;
  ASSERT (ad->error == 0);
  ad->error = error;
}

static u32
avf_flag_change (vnet_main_t * vnm, vnet_hw_interface_t * hw, u32 flags)
{
  clib_warning ("TODO");
  return 0;
}

static uword
avf_process (vlib_main_t * vm, vlib_node_runtime_t * rt, vlib_frame_t * f)
{
  avf_main_t *am = &avf_main;
  avf_device_t *ad;

  while (1)
    {
      vlib_process_suspend (vm, 1.0);
      /* *INDENT-OFF* */
      pool_foreach (ad, am->devices,
        {
	  avf_process_one_device (vm, ad);
        });
      /* *INDENT-ON* */
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
avf_pci_intr_handler (vlib_pci_dev_handle_t h)
{
  clib_warning ("int");
}

static clib_error_t *
avf_pci_init (vlib_main_t * vm, vlib_pci_dev_handle_t h)
{
  clib_error_t *error = 0;
  vnet_main_t *vnm = vnet_get_main ();
  avf_main_t *am = &avf_main;
  avf_device_t *ad;
  //vlib_pci_device_info_t *d = vlib_pci_get_device_info (addr, 0);

  pool_get (am->devices, ad);
  ad->pci_dev_handle = h;
  ad->dev_instance = ad - am->devices;
  ad->per_interface_next_index = ~0;

  if ((error = vlib_pci_bus_master_enable (h)))
    goto error;

  if ((error = vlib_pci_map_resource (h, 0, &ad->bar0)))
    goto error;

  error = vlib_physmem_region_alloc (vm, "avf_pool", 2 << 20, 0,
				     VLIB_PHYSMEM_F_INIT_MHEAP,
				     &am->physmem_region);
  if (error)
    goto error;
  ad->atq = vlib_physmem_alloc_aligned (vm, am->physmem_region, &error,
					sizeof (avf_aq_desc_t) * AVF_MBOX_LEN,
					64);
  if (error)
    goto error;

  ad->arq = vlib_physmem_alloc_aligned (vm, am->physmem_region, &error,
					sizeof (avf_aq_desc_t) * AVF_MBOX_LEN,
					64);
  if (error)
    goto error;

  ad->atq_bufs = vlib_physmem_alloc_aligned (vm, am->physmem_region, &error,
					     AVF_MBOX_BUF_SZ * AVF_MBOX_LEN,
					     64);
  if (error)
    goto error;

  ad->arq_bufs = vlib_physmem_alloc_aligned (vm, am->physmem_region, &error,
					     AVF_MBOX_BUF_SZ * AVF_MBOX_LEN,
					     64);
  if (error)
    goto error;

  if ((error = vlib_pci_intr_enable (h)))
    goto error;

  /* create interface */
  u64 hwaddr = 0x554433221100;
  error = ethernet_register_interface (vnm, avf_device_class.index,
				       ad->dev_instance, (u8 *) & hwaddr,
				       &ad->hw_if_index, avf_flag_change);

  if (error)
    goto error;

  vnet_sw_interface_t *sw = vnet_get_hw_sw_interface (vnm, ad->hw_if_index);
  ad->sw_if_index = sw->sw_if_index;

  vnet_hw_interface_set_input_node (vnm, ad->hw_if_index,
				    avf_input_node.index);
  vnet_hw_interface_assign_rx_thread (vnm, ad->hw_if_index, 0, ~0);

  return 0;

error:
  if (ad->atq)
    vlib_physmem_free (vm, am->physmem_region, ad->atq);
  if (ad->arq)
    vlib_physmem_free (vm, am->physmem_region, ad->arq);
  if (ad->atq_bufs)
    vlib_physmem_free (vm, am->physmem_region, ad->atq_bufs);
  if (ad->arq_bufs)
    vlib_physmem_free (vm, am->physmem_region, ad->arq_bufs);
  memset (ad, 0, sizeof (*ad));
  pool_put (am->devices, ad);
  return error;
}

/* *INDENT-OFF* */
PCI_REGISTER_DEVICE (avf_pci_device_registration,static) = {
  .init_function = avf_pci_init,
  .interrupt_handler = avf_pci_intr_handler,
  .supported_devices = {
    { .vendor_id = 0x8086, .device_id = 0x154c, },
    { 0 },
  },
};
  /* *INDENT-ON* */

static clib_error_t *
avf_interface_admin_up_down (vnet_main_t * vnm, u32 hw_if_index, u32 flags)
{
  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, hw_if_index);
  avf_main_t *mm = &avf_main;
  avf_device_t *md = vec_elt_at_index (mm->devices, hi->dev_instance);
  uword is_up = (flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP) != 0;

  if (is_up)
    {
      vnet_hw_interface_set_flags (vnm, md->hw_if_index,
				   VNET_HW_INTERFACE_FLAG_LINK_UP);
      md->flags |= AVF_DEVICE_F_ADMIN_UP;
    }
  else
    {
      vnet_hw_interface_set_flags (vnm, md->hw_if_index, 0);
      md->flags &= ~AVF_DEVICE_F_ADMIN_UP;
    }
  return 0;
}


/* *INDENT-OFF* */
VNET_DEVICE_CLASS (avf_device_class,) =
{
  .name = "Adaptive Virtual Function (AVF) interface",
  .tx_function = avf_interface_tx,
  .format_device = format_avf_device,
  .format_device_name = format_avf_device_name,
  .admin_up_down_function = avf_interface_admin_up_down,
};
/* *INDENT-ON* */

clib_error_t *
avf_init (vlib_main_t * vm)
{
  clib_error_t *error;

  if ((error = vlib_call_init_function (vm, pci_bus_init)))
    return error;

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
