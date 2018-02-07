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
#define AVF_RXQ_SZ 1024
#define AVF_TXQ_SZ 1024

avf_main_t avf_main;

#define avf_log_debug(fmt, ...) fformat(stderr, "%s: " fmt "\n", __func__, __VA_ARGS__)

void
avf_create_if (avf_create_if_args_t * args)
{
}

void
avf_delete_if (avf_device_t * ad)
{
}

void
avf_send_to_pf (vlib_main_t * vm, avf_device_t * ad, virtchnl_ops_t op,
		void *data, int len)
{
  avf_main_t *am = &avf_main;
  avf_aq_desc_t *d;
  u64 pa;

  d = &ad->atq[ad->atq_next_slot];
  memset (d, 0, sizeof (avf_aq_desc_t));
  d->opcode = 0x801;
  d->v_opcode = op;
  //d->flags = AVF_AQ_FLAG_SI | AVF_AQ_FLAG_BUF | AVF_AQ_FLAG_RD;
  d->flags = AVF_AQ_FLAG_BUF | AVF_AQ_FLAG_RD;
  d->datalen = len;
  pa = vlib_physmem_virtual_to_physical (vm, am->physmem_region,
					 ad->atq_bufs);
  d->addr_hi = (u32) (pa >> 32);
  d->addr_lo = (u32) pa;
  clib_memcpy (ad->atq_bufs, data, len);
  CLIB_MEMORY_BARRIER ();
  avf_log_debug ("slot %u opcode %x v_opcode %x",
		 ad->atq_next_slot, d->opcode, d->v_opcode);
  avf_log_debug ("%U", format_hexdump, data, len);
  ad->atq_next_slot = (ad->atq_next_slot + 1) % AVF_MBOX_LEN;
  avf_set_u32 (ad->bar0, AVF_ATQT, ad->atq_next_slot);
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
					   rxq->size * 32, 64);
  memset (rxq->descs, 0, rxq->size * 32);
  vec_validate_aligned (rxq->bufs, rxq->size, CLIB_CACHE_LINE_BYTES);
  rxq->n_bufs = 0;
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
					   txq->size * 32, 64);
  return 0;
}

void
avf_config_vsi_queues (vlib_main_t * vm, avf_device_t * ad)
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
	  rxq->ring_len = q->size;
	  //rxq->hdr_size = 32;
	  rxq->databuffer_size = VLIB_BUFFER_DEFAULT_FREE_LIST_BYTES;
	  rxq->max_pkt_size = 1514;
	  rxq->dma_ring_addr =
	    vlib_physmem_virtual_to_physical (vm, am->physmem_region,
					      q->descs);
	}
      if (i < vec_len (ad->txqs))
	{
	  avf_txq_t *q = vec_elt_at_index (ad->txqs, i);
	  txq->vsi_id = ad->vsi_id;
	  txq->ring_len = q->size;
	  txq->dma_ring_addr =
	    vlib_physmem_virtual_to_physical (vm, am->physmem_region,
					      q->descs);
	}
    }
  avf_send_to_pf (vm, ad, VIRTCHNL_OP_CONFIG_VSI_QUEUES, msg, msg_len);
}

void
avf_enable_queues (vlib_main_t * vm, avf_device_t * ad)
{
  virtchnl_queue_select_t qs = { 0 };
  qs.vsi_id = ad->vsi_id;
  qs.rx_queues = 1;
  avf_send_to_pf (vm, ad, VIRTCHNL_OP_ENABLE_QUEUES, &qs,
		  sizeof (virtchnl_queue_select_t));
}

clib_error_t *
avf_device_init (vlib_main_t * vm, avf_device_t * ad)
{
  avf_main_t *am = &avf_main;
  avf_aq_desc_t *d;
  virtchnl_version_info_t ver;
  clib_error_t *error;
  u64 pa;
  int i;

  /* VF MailBox Receive */
  memset (ad->arq, 0, sizeof (avf_aq_desc_t) * AVF_MBOX_LEN);
  pa = vlib_physmem_virtual_to_physical (vm, am->physmem_region,
					 ad->arq_bufs);

  for (i = 0; i < AVF_MBOX_LEN; i++)
    {
      d = &ad->arq[i];
      d->flags = AVF_AQ_FLAG_SI | AVF_AQ_FLAG_BUF;
      d->datalen = AVF_MBOX_BUF_SZ;
      d->addr_hi = (u32) (pa >> 32);
      d->addr_lo = (u32) pa;
      pa += AVF_MBOX_BUF_SZ;
    }

  pa = vlib_physmem_virtual_to_physical (vm, am->physmem_region, ad->arq);
  avf_set_u32 (ad->bar0, AVF_ARQT, 8);	/* Tail */
  avf_set_u32 (ad->bar0, AVF_ARQH, 0);	/* Head */
  avf_set_u32 (ad->bar0, AVF_ARQBAL, (u32) pa);	/* Base Address Low */
  avf_set_u32 (ad->bar0, AVF_ARQBAH, (u32) (pa >> 32));	/* Base Address High */
  avf_set_u32 (ad->bar0, AVF_ARQLEN, AVF_MBOX_LEN | (1 << 31));	/* len & ena */

  /* VF MailBox Transmit */
  memset (ad->atq, 0, sizeof (avf_aq_desc_t) * AVF_MBOX_LEN);
  pa = vlib_physmem_virtual_to_physical (vm, am->physmem_region, ad->atq);
  avf_set_u32 (ad->bar0, AVF_ATQT, 0);	/* Tail */
  avf_set_u32 (ad->bar0, AVF_ATQH, 0);	/* Head */
  avf_set_u32 (ad->bar0, AVF_ATQBAL, (u32) pa);	/* Base Address Low */
  avf_set_u32 (ad->bar0, AVF_ATQBAH, (u32) (pa >> 32));	/* Base Address High */
  avf_set_u32 (ad->bar0, AVF_ATQLEN, AVF_MBOX_LEN | (1 << 31));	/* len & ena */

  ver.major = VIRTCHNL_VERSION_MAJOR;
  ver.minor = VIRTCHNL_VERSION_MINOR;
  avf_send_to_pf (vm, ad, VIRTCHNL_OP_VERSION, &ver, sizeof (ver));

  if ((error = avf_rxq_init (vm, ad, 0)))
    return error;

  if ((error = avf_txq_init (vm, ad, 0)))
    return error;

  ad->init_state = AVF_INIT_STATE_VERSION_SENT;
  return error;
}

clib_error_t *
avf_recv_from_pf (vlib_main_t * vm, avf_device_t * ad, u16 slot)
{
  void *buf = ad->arq_bufs + slot * AVF_MBOX_BUF_SZ;
  avf_aq_desc_t *d = &ad->arq[slot];

  if (d->v_opcode == VIRTCHNL_OP_VERSION)
    {
      virtchnl_version_info_t *v = buf;

      if (v->major != VIRTCHNL_VERSION_MAJOR ||
	  v->minor != VIRTCHNL_VERSION_MINOR)
	return clib_error_return (0, "incompatible protocol version "
				  "(remote %d.%d)", v->major, v->minor);

      if (ad->init_state != AVF_INIT_STATE_VERSION_SENT)
	return clib_error_return (0, "unexpected VERSION message "
				  "received");

      ad->init_state = AVF_INIT_STATE_GET_VF_RESOURCES_SENT;
      u32 bitmap = 0x00020020;
      avf_send_to_pf (vm, ad, VIRTCHNL_OP_GET_VF_RESOURCES, &bitmap,
		      sizeof (bitmap));
    }
  else if (d->v_opcode == VIRTCHNL_OP_GET_VF_RESOURCES)
    {
      virtchnl_vf_resource_t *r = buf;
      virtchnl_vsi_resource_t *v = &r->vsi_res[0];
      avf_log_debug ("GET_VF_RESOUCES reply received", 0);
      if (ad->init_state != AVF_INIT_STATE_GET_VF_RESOURCES_SENT)
	return clib_error_return (0, "unexpected GET_VF_RESOURCES message "
				  "received");
      avf_log_debug ("num_vsis %u num_queue_pairs %u max_vectors %u "
		     "max_mtu %u vf_offload_flags 0x%x",
		     r->num_vsis, r->num_queue_pairs, r->max_vectors,
		     r->max_mtu, r->vf_offload_flags);
      avf_log_debug ("  vsi %u num_queue_pairs %u vsi_type %u "
		     "qset_handle %u default_mac_addr %U",
		     v->vsi_id, v->num_queue_pairs, v->vsi_type,
		     v->qset_handle, format_hex_bytes, v->default_mac_addr,
		     6);
      ad->vsi_id = v->vsi_id;

      ad->init_state = AVF_INIT_STATE_CONFIG_VSI_QUEUES_SENT;
      avf_config_vsi_queues (vm, ad);
    }
  else if (d->v_opcode == VIRTCHNL_OP_EVENT)
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
  else if (d->v_opcode == VIRTCHNL_OP_CONFIG_VSI_QUEUES)
    {
      avf_log_debug ("CONFIG_VSI_QUEUES reply received", 0);
      if (ad->init_state != AVF_INIT_STATE_CONFIG_VSI_QUEUES_SENT)
	return clib_error_return (0, "unexpected CONFIG_VSI_QUEUES message "
				  "received");
      ad->init_state = AVF_INIT_STATE_CONFIG_VSI_QUEUES_SENT;
      avf_enable_queues (vm, ad);
    }
  else if (d->v_opcode == VIRTCHNL_OP_ENABLE_QUEUES)
    {
      avf_log_debug ("ENABLE_QUEUES reply received", 0);
      if (ad->init_state != AVF_INIT_STATE_ENABLE_QUEUES_SENT)
	return clib_error_return (0, "unexpected ENABLE_QUEUES message "
				  "received");
      ad->flags |= AVF_DEVICE_F_INITIALIZED;
    }
  else
    {
      avf_log_debug ("slot %u opcode %x v_opcode %x v_retval %d flags 0x%x",
		     slot, d->opcode, d->v_opcode, d->v_retval, d->flags);
      avf_log_debug ("  %U", format_hexdump, d, sizeof (*d));
      if (d->datalen)
	avf_log_debug ("  %U", format_hexdump, buf, d->datalen);
    }

  return 0;
}

void
avf_process_one_device (vlib_main_t * vm, avf_device_t * ad)
{
  clib_error_t *error;
  u32 r;

  if (ad->flags & AVF_DEVICE_F_ERROR)
    return;

  ASSERT (ad->error == 0);

  if ((ad->init_state == AVF_INIT_STATE_START))
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

  r = avf_get_u32 (ad->bar0, AVF_ARQH);
  while (ad->arq_next_slot != r)
    {
      error = avf_recv_from_pf (vm, ad, ad->arq_next_slot);
      ad->arq_next_slot = (ad->arq_next_slot + 1) % AVF_MBOX_LEN;
      if (error)
	goto error;
    }

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

  avf_set_u32 (ad->bar0, VFINT_DYN_CTL0, 1);
  avf_set_u32 (ad->bar0, VFINT_DYN_CTL0, 5);

  /* create interface */
  u64 hwaddr = 0;
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
