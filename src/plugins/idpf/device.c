/*
 *------------------------------------------------------------------
 * Copyright (c) 2023 Intel and/or its affiliates.
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

#include <idpf/idpf.h>
#include <vpp/app/version.h>
#include <vnet/plugin/plugin.h>

#define IDPF_RXQ_SZ 512
#define IDPF_TXQ_SZ 512

#define PCI_VENDOR_ID_INTEL	    0x8086
#define PCI_DEVICE_ID_INTEL_IDPF_PF 0x1452
#define PCI_DEVICE_ID_INTEL_IDPF_VF 0x1889

VLIB_REGISTER_LOG_CLASS (idpf_log) = {
  .class_name = "idpf",
};

VLIB_REGISTER_LOG_CLASS (idpf_stats_log) = {
  .class_name = "idpf",
  .subclass_name = "stats",
};

idpf_main_t idpf_main;
void idpf_delete_if (vlib_main_t *vm, idpf_device_t *id, int with_barrier);

static pci_device_id_t idpf_pci_device_ids[] = {
  { .vendor_id = PCI_VENDOR_ID_INTEL,
    .device_id = PCI_DEVICE_ID_INTEL_IDPF_PF },
  { .vendor_id = PCI_VENDOR_ID_INTEL,
    .device_id = PCI_DEVICE_ID_INTEL_IDPF_VF },
  { 0 },
};

static int
idpf_vc_clean (vlib_main_t *vm, idpf_device_t *id)
{
  idpf_ctlq_msg_t *q_msg[IDPF_CTLQ_LEN];
  uint16_t num_q_msg = IDPF_CTLQ_LEN;
  idpf_dma_mem_t *dma_mem;
  uint32_t i;
  int err;

  for (i = 0; i < 10; i++)
    {
      err = idpf_ctlq_clean_sq (id->asq, &num_q_msg, q_msg);
      vlib_process_suspend (vm, 0.02);
      if (num_q_msg > 0)
	break;
    }
  if (err != 0)
    return err;

  /* Empty queue is not an error */
  for (i = 0; i < num_q_msg; i++)
    {
      dma_mem = q_msg[i]->ctx.indirect.payload;
      if (dma_mem != NULL)
	idpf_free_dma_mem (id, dma_mem);
      clib_mem_free (q_msg[i]);
    }

  return 0;
}

static idpf_vc_result_t
idpf_read_msg_from_cp (idpf_device_t *id, u16 buf_len, u8 *buf)
{
  idpf_ctlq_msg_t ctlq_msg;
  idpf_dma_mem_t *dma_mem = NULL;
  idpf_vc_result_t result = IDPF_MSG_NON;
  u32 opcode;
  u16 pending = 1;
  int ret;

  ret = idpf_ctlq_recv (id->arq, &pending, &ctlq_msg);
  if (ret != 0)
    {
      idpf_log_debug (id, "Can't read msg from AQ");
      if (ret != -ENOMSG)
	result = IDPF_MSG_ERR;
      return result;
    }

  clib_memcpy_fast (buf, ctlq_msg.ctx.indirect.payload->va, buf_len);

  opcode = ctlq_msg.cookie.mbx.chnl_opcode;
  id->cmd_retval = ctlq_msg.cookie.mbx.chnl_retval;

  idpf_log_debug (id, "CQ from CP carries opcode %u, retval %d", opcode,
		  id->cmd_retval);

  if (opcode == VIRTCHNL2_OP_EVENT)
    {
      virtchnl2_event_t *ve =
	(virtchnl2_event_t *) ctlq_msg.ctx.indirect.payload->va;

      result = IDPF_MSG_SYS;
      switch (ve->event)
	{
	case VIRTCHNL2_EVENT_LINK_CHANGE:
	  break;
	default:
	  idpf_log_err (id, "%s: Unknown event %d from CP", __func__,
			ve->event);
	  break;
	}
    }
  else
    {
      /* async reply msg on command issued by pf previously */
      result = IDPF_MSG_CMD;
      if (opcode != id->pend_cmd)
	{
	  idpf_log_warn (id, "command mismatch, expect %u, get %u",
			 id->pend_cmd, opcode);
	  result = IDPF_MSG_ERR;
	}
    }

  if (ctlq_msg.data_len != 0)
    dma_mem = ctlq_msg.ctx.indirect.payload;
  else
    pending = 0;

  ret = idpf_ctlq_post_rx_buffs (id, id->arq, &pending, &dma_mem);
  if (ret != 0 && dma_mem != NULL)
    idpf_free_dma_mem (id, dma_mem);

  return result;
}

clib_error_t *
idpf_send_vc_msg (vlib_main_t *vm, idpf_device_t *id, virtchnl2_op_t op,
		  u8 *in, u16 in_len)
{
  idpf_ctlq_msg_t *ctlq_msg;
  idpf_dma_mem_t *dma_mem;
  int error = 0;

  error = idpf_vc_clean (vm, id);
  if (error)
    goto err;

  ctlq_msg = clib_mem_alloc (sizeof (idpf_ctlq_msg_t));
  if (ctlq_msg == NULL)
    goto err;
  clib_memset (ctlq_msg, 0, sizeof (idpf_ctlq_msg_t));

  dma_mem = clib_mem_alloc (sizeof (idpf_dma_mem_t));
  if (dma_mem == NULL)
    goto dma_mem_error;
  clib_memset (dma_mem, 0, sizeof (idpf_dma_mem_t));

  dma_mem->va = idpf_alloc_dma_mem (vm, id, dma_mem, IDPF_DFLT_MBX_BUF_SIZE);
  if (dma_mem->va == NULL)
    {
      clib_mem_free (dma_mem);
      goto err;
    }

  clib_memcpy (dma_mem->va, in, in_len);

  ctlq_msg->opcode = idpf_mbq_opc_send_msg_to_pf;
  ctlq_msg->func_id = 0;
  ctlq_msg->data_len = in_len;
  ctlq_msg->cookie.mbx.chnl_opcode = op;
  ctlq_msg->cookie.mbx.chnl_retval = VIRTCHNL2_STATUS_SUCCESS;
  ctlq_msg->ctx.indirect.payload = dma_mem;

  error = idpf_ctlq_send (id, id->asq, 1, ctlq_msg);
  if (error)
    goto send_error;

  return 0;

send_error:
  idpf_free_dma_mem (id, dma_mem);
dma_mem_error:
  clib_mem_free (ctlq_msg);
err:
  return clib_error_return (0, "idpf send vc msg to PF failed");
}

clib_error_t *
idpf_read_one_msg (vlib_main_t *vm, idpf_device_t *id, u32 ops, u8 *buf,
		   u16 buf_len)
{
  int i = 0, ret;
  f64 suspend_time = IDPF_SEND_TO_PF_SUSPEND_TIME;

  do
    {
      ret = idpf_read_msg_from_cp (id, buf_len, buf);
      if (ret == IDPF_MSG_CMD)
	break;
      vlib_process_suspend (vm, suspend_time);
    }
  while (i++ < IDPF_SEND_TO_PF_MAX_TRY_TIMES);
  if (i >= IDPF_SEND_TO_PF_MAX_TRY_TIMES ||
      id->cmd_retval != VIRTCHNL2_STATUS_SUCCESS)
    return clib_error_return (0, "idpf read one msg failed");

  return 0;
}

clib_error_t *
idpf_execute_vc_cmd (vlib_main_t *vm, idpf_device_t *id, idpf_cmd_info_t *args)
{
  clib_error_t *error = 0;
  f64 suspend_time = IDPF_SEND_TO_PF_SUSPEND_TIME;
  int i = 0;

  if (id->pend_cmd == VIRTCHNL2_OP_UNKNOWN)
    id->pend_cmd = args->ops;
  else
    return clib_error_return (0, "There is incomplete cmd %d", id->pend_cmd);

  if ((error = idpf_send_vc_msg (vm, id, args->ops, args->in_args,
				 args->in_args_size)))
    return error;

  switch (args->ops)
    {
    case VIRTCHNL2_OP_VERSION:
    case VIRTCHNL2_OP_GET_CAPS:
    case VIRTCHNL2_OP_CREATE_VPORT:
    case VIRTCHNL2_OP_DESTROY_VPORT:
    case VIRTCHNL2_OP_SET_RSS_KEY:
    case VIRTCHNL2_OP_SET_RSS_LUT:
    case VIRTCHNL2_OP_SET_RSS_HASH:
    case VIRTCHNL2_OP_CONFIG_RX_QUEUES:
    case VIRTCHNL2_OP_CONFIG_TX_QUEUES:
    case VIRTCHNL2_OP_ENABLE_QUEUES:
    case VIRTCHNL2_OP_DISABLE_QUEUES:
    case VIRTCHNL2_OP_ENABLE_VPORT:
    case VIRTCHNL2_OP_DISABLE_VPORT:
    case VIRTCHNL2_OP_MAP_QUEUE_VECTOR:
    case VIRTCHNL2_OP_UNMAP_QUEUE_VECTOR:
    case VIRTCHNL2_OP_ALLOC_VECTORS:
    case VIRTCHNL2_OP_DEALLOC_VECTORS:
    case VIRTCHNL2_OP_GET_STATS:
      /* for init virtchnl ops, need to poll the response */
      error = idpf_read_one_msg (vm, id, args->ops, args->out_buffer,
				 args->out_size);
      if (error)
	return clib_error_return (0, "idpf read vc message from PF failed");
      clear_cmd (id);
      break;
    case VIRTCHNL2_OP_GET_PTYPE_INFO:
      break;
    default:
      do
	{
	  if (id->pend_cmd == VIRTCHNL2_OP_UNKNOWN)
	    break;
	  vlib_process_suspend (vm, suspend_time);
	  /* If don't read msg or read sys event, continue */
	}
      while (i++ < IDPF_SEND_TO_PF_MAX_TRY_TIMES);
      /* If there's no response is received, clear command */
      if (i >= IDPF_SEND_TO_PF_MAX_TRY_TIMES ||
	  id->cmd_retval != VIRTCHNL2_STATUS_SUCCESS)
	return clib_error_return (
	  0, "No response or return failure (%d) for cmd %d", id->cmd_retval,
	  args->ops);
      break;
    }

  return error;
}

static inline uword
idpf_dma_addr (vlib_main_t *vm, idpf_device_t *id, void *p)
{
  return (id->flags & IDPF_DEVICE_F_VA_DMA) ? pointer_to_uword (p) :
						    vlib_physmem_get_pa (vm, p);
}

clib_error_t *
idpf_vc_config_irq_map_unmap (vlib_main_t *vm, idpf_device_t *id,
			      idpf_vport_t *vport, bool map)
{
  virtchnl2_queue_vector_maps_t *map_info;
  virtchnl2_queue_vector_t *vecmap;
  u16 nb_rxq = vport->id->n_rx_queues;
  idpf_cmd_info_t args;
  clib_error_t *error;
  int len, i;

  len = sizeof (virtchnl2_queue_vector_maps_t) +
	(nb_rxq - 1) * sizeof (virtchnl2_queue_vector_t);

  map_info = clib_mem_alloc_aligned (len, CLIB_CACHE_LINE_BYTES);
  clib_memset (map_info, 0, len);

  map_info->vport_id = vport->vport_id;
  map_info->num_qv_maps = nb_rxq;
  for (i = 0; i < nb_rxq; i++)
    {
      vecmap = &map_info->qv_maps[i];
      vecmap->queue_id = vport->qv_map[i].queue_id;
      vecmap->vector_id = vport->qv_map[i].vector_id;
      vecmap->itr_idx = VIRTCHNL2_ITR_IDX_0;
      vecmap->queue_type = VIRTCHNL2_QUEUE_TYPE_RX;
    }

  args.ops =
    map ? VIRTCHNL2_OP_MAP_QUEUE_VECTOR : VIRTCHNL2_OP_UNMAP_QUEUE_VECTOR;
  args.in_args = (u8 *) map_info;
  args.in_args_size = len;
  args.out_buffer = id->mbx_resp;
  args.out_size = IDPF_DFLT_MBX_BUF_SIZE;
  error = idpf_execute_vc_cmd (vm, id, &args);
  if (error != 0)
    return clib_error_return (
      0, "Failed to execute command of VIRTCHNL2_OP_%s_QUEUE_VECTOR",
      map ? "MAP" : "UNMAP");

  clib_mem_free (map_info);
  return error;
}

clib_error_t *
idpf_config_rx_queues_irqs (vlib_main_t *vm, idpf_device_t *id,
			    idpf_vport_t *vport)
{
  virtchnl2_queue_vector_t *qv_map;
  clib_error_t *error = 0;
  u32 dynctl_reg_start;
  u32 itrn_reg_start;
  u32 dynctl_val, itrn_val;
  int i;

  qv_map = clib_mem_alloc_aligned (id->n_rx_queues *
				     sizeof (virtchnl2_queue_vector_t),
				   CLIB_CACHE_LINE_BYTES);
  clib_memset (qv_map, 0, id->n_rx_queues * sizeof (virtchnl2_queue_vector_t));

  dynctl_reg_start = vport->recv_vectors->vchunks.vchunks->dynctl_reg_start;
  itrn_reg_start = vport->recv_vectors->vchunks.vchunks->itrn_reg_start;
  dynctl_val = idpf_reg_read (id, dynctl_reg_start);
  idpf_log_debug (id, "Value of dynctl_reg_start is 0x%x", dynctl_val);
  itrn_val = idpf_reg_read (id, itrn_reg_start);
  idpf_log_debug (id, "Value of itrn_reg_start is 0x%x", itrn_val);

  if (itrn_val != 0)
    idpf_reg_write (id, dynctl_reg_start,
		    VIRTCHNL2_ITR_IDX_0 << PF_GLINT_DYN_CTL_ITR_INDX_S |
		      PF_GLINT_DYN_CTL_WB_ON_ITR_M |
		      itrn_val << PF_GLINT_DYN_CTL_INTERVAL_S);
  else
    idpf_reg_write (id, dynctl_reg_start,
		    VIRTCHNL2_ITR_IDX_0 << PF_GLINT_DYN_CTL_ITR_INDX_S |
		      PF_GLINT_DYN_CTL_WB_ON_ITR_M |
		      IDPF_DFLT_INTERVAL << PF_GLINT_DYN_CTL_INTERVAL_S);

  for (i = 0; i < id->n_rx_queues; i++)
    {
      /* map all queues to the same vector */
      qv_map[i].queue_id = vport->chunks_info.rx_start_qid + i;
      qv_map[i].vector_id =
	vport->recv_vectors->vchunks.vchunks->start_vector_id;
    }
  vport->qv_map = qv_map;

  if ((error = idpf_vc_config_irq_map_unmap (vm, id, vport, true)))
    {
      idpf_log_err (id, "config interrupt mapping failed");
      goto config_irq_map_err;
    }

  return error;

config_irq_map_err:
  clib_mem_free (vport->qv_map);
  vport->qv_map = NULL;

  return error;
}

clib_error_t *
idpf_rx_split_bufq_setup (vlib_main_t *vm, idpf_device_t *id,
			  idpf_vport_t *vport, idpf_rxq_t *bufq, u16 qid,
			  u16 rxq_size)
{
  clib_error_t *err;
  u32 n_alloc, i;

  bufq->size = rxq_size;
  bufq->next = 0;
  bufq->descs = vlib_physmem_alloc_aligned_on_numa (
    vm, bufq->size * sizeof (virtchnl2_rx_desc_t), 2 * CLIB_CACHE_LINE_BYTES,
    id->numa_node);

  bufq->buffer_pool_index =
    vlib_buffer_pool_get_default_for_numa (vm, id->numa_node);

  if ((err = vlib_pci_map_dma (vm, id->pci_dev_handle, (void *) bufq->descs)))
    return err;

  clib_memset ((void *) bufq->descs, 0,
	       bufq->size * sizeof (virtchnl2_rx_desc_t));
  vec_validate_aligned (bufq->bufs, bufq->size, CLIB_CACHE_LINE_BYTES);
  bufq->qrx_tail = id->bar0 + (vport->chunks_info.rx_buf_qtail_start +
			       qid * vport->chunks_info.rx_buf_qtail_spacing);

  n_alloc = vlib_buffer_alloc_from_pool (vm, bufq->bufs, bufq->size - 8,
					 bufq->buffer_pool_index);
  if (n_alloc == 0)
    return clib_error_return (0, "buffer allocation error");

  bufq->n_enqueued = n_alloc;
  virtchnl2_rx_desc_t *d = bufq->descs;
  for (i = 0; i < n_alloc; i++)
    {
      vlib_buffer_t *b = vlib_get_buffer (vm, bufq->bufs[i]);
      if (id->flags & IDPF_DEVICE_F_VA_DMA)
	d->qword[0] = vlib_buffer_get_va (b);
      else
	d->qword[0] = vlib_buffer_get_pa (vm, b);
      d++;
    }

  return 0;
}

clib_error_t *
idpf_split_rxq_init (vlib_main_t *vm, idpf_device_t *id, idpf_vport_t *vport,
		     u16 qid, u16 rxq_size)
{
  clib_error_t *err;
  idpf_rxq_t *rxq;
  u32 n_alloc, i;

  vec_validate_aligned (vport->rxqs, qid, CLIB_CACHE_LINE_BYTES);
  rxq = vec_elt_at_index (vport->rxqs, qid);
  rxq->size = rxq_size;
  rxq->next = 0;
  rxq->descs = vlib_physmem_alloc_aligned_on_numa (
    vm, rxq->size * sizeof (virtchnl2_rx_desc_t), 2 * CLIB_CACHE_LINE_BYTES,
    id->numa_node);

  rxq->buffer_pool_index =
    vlib_buffer_pool_get_default_for_numa (vm, id->numa_node);

  if (rxq->descs == 0)
    return vlib_physmem_last_error (vm);

  if ((err = vlib_pci_map_dma (vm, id->pci_dev_handle, (void *) rxq->descs)))
    return err;

  clib_memset ((void *) rxq->descs, 0,
	       rxq->size * sizeof (virtchnl2_rx_desc_t));
  vec_validate_aligned (rxq->bufs, rxq->size, CLIB_CACHE_LINE_BYTES);
  rxq->qrx_tail = id->bar0 + (vport->chunks_info.rx_qtail_start +
			      qid * vport->chunks_info.rx_qtail_spacing);

  n_alloc = vlib_buffer_alloc_from_pool (vm, rxq->bufs, rxq->size - 8,
					 rxq->buffer_pool_index);

  if (n_alloc == 0)
    return clib_error_return (0, "buffer allocation error");

  rxq->n_enqueued = n_alloc;
  virtchnl2_rx_desc_t *d = rxq->descs;
  for (i = 0; i < n_alloc; i++)
    {
      vlib_buffer_t *b = vlib_get_buffer (vm, rxq->bufs[i]);
      if (id->flags & IDPF_DEVICE_F_VA_DMA)
	d->qword[0] = vlib_buffer_get_va (b);
      else
	d->qword[0] = vlib_buffer_get_pa (vm, b);
      d++;
    }

  err =
    idpf_rx_split_bufq_setup (vm, id, vport, rxq->bufq1, 2 * qid, rxq_size);
  if (err)
    return err;
  err =
    idpf_rx_split_bufq_setup (vm, id, vport, rxq->bufq2, 2 * qid, rxq_size);
  if (err)
    return err;

  return 0;
}

clib_error_t *
idpf_single_rxq_init (vlib_main_t *vm, idpf_device_t *id, idpf_vport_t *vport,
		      u16 qid, u16 rxq_size)
{
  clib_error_t *err;
  idpf_rxq_t *rxq;
  u32 n_alloc, i;

  vec_validate_aligned (vport->rxqs, qid, CLIB_CACHE_LINE_BYTES);
  rxq = vec_elt_at_index (vport->rxqs, qid);
  rxq->queue_index = vport->chunks_info.rx_start_qid + qid;
  rxq->size = rxq_size;
  rxq->next = 0;
  rxq->descs = vlib_physmem_alloc_aligned_on_numa (
    vm, rxq->size * sizeof (virtchnl2_rx_desc_t), 2 * CLIB_CACHE_LINE_BYTES,
    id->numa_node);

  rxq->buffer_pool_index =
    vlib_buffer_pool_get_default_for_numa (vm, id->numa_node);

  if (rxq->descs == 0)
    return vlib_physmem_last_error (vm);

  err = vlib_pci_map_dma (vm, id->pci_dev_handle, (void *) rxq->descs);
  if (err)
    return err;

  clib_memset ((void *) rxq->descs, 0,
	       rxq->size * sizeof (virtchnl2_rx_desc_t));
  vec_validate_aligned (rxq->bufs, rxq->size, CLIB_CACHE_LINE_BYTES);
  rxq->qrx_tail = id->bar0 + (vport->chunks_info.rx_qtail_start +
			      qid * vport->chunks_info.rx_qtail_spacing);

  n_alloc = vlib_buffer_alloc_from_pool (vm, rxq->bufs, rxq->size - 8,
					 rxq->buffer_pool_index);

  if (n_alloc == 0)
    return clib_error_return (0, "buffer allocation error");

  rxq->n_enqueued = n_alloc;
  virtchnl2_rx_desc_t *d = rxq->descs;
  for (i = 0; i < n_alloc; i++)
    {
      vlib_buffer_t *b = vlib_get_buffer (vm, rxq->bufs[i]);
      if (id->flags & IDPF_DEVICE_F_VA_DMA)
	d->qword[0] = vlib_buffer_get_va (b);
      else
	d->qword[0] = vlib_buffer_get_pa (vm, b);
      d++;
    }

  return 0;
}

clib_error_t *
idpf_rx_queue_setup (vlib_main_t *vm, idpf_device_t *id, idpf_vport_t *vport,
		     u16 qid, u16 rxq_size)
{
  if (vport->rxq_model == VIRTCHNL2_QUEUE_MODEL_SINGLE)
    return idpf_single_rxq_init (vm, id, vport, qid, rxq_size);
  else
    return idpf_split_rxq_init (vm, id, vport, qid, rxq_size);
}

clib_error_t *
idpf_tx_split_complq_setup (vlib_main_t *vm, idpf_device_t *id,
			    idpf_vport_t *vport, idpf_txq_t *complq, u16 qid,
			    u16 txq_size)
{
  clib_error_t *err;
  u16 n;
  u8 bpi = vlib_buffer_pool_get_default_for_numa (vm, id->numa_node);

  complq->size = txq_size;
  complq->next = 0;
  clib_spinlock_init (&complq->lock);

  n = (complq->size / 510) + 1;
  vec_validate_aligned (complq->ph_bufs, n, CLIB_CACHE_LINE_BYTES);

  if (!vlib_buffer_alloc_from_pool (vm, complq->ph_bufs, n, bpi))
    return clib_error_return (0, "buffer allocation error");

  complq->descs = vlib_physmem_alloc_aligned_on_numa (
    vm, complq->size * sizeof (idpf_tx_desc_t), 2 * CLIB_CACHE_LINE_BYTES,
    id->numa_node);
  if (complq->descs == 0)
    return vlib_physmem_last_error (vm);

  if ((err =
	 vlib_pci_map_dma (vm, id->pci_dev_handle, (void *) complq->descs)))
    return err;

  vec_validate_aligned (complq->bufs, complq->size, CLIB_CACHE_LINE_BYTES);
  complq->qtx_tail =
    id->bar0 + (vport->chunks_info.tx_compl_qtail_start +
		qid * vport->chunks_info.tx_compl_qtail_spacing);

  /* initialize ring of pending RS slots */
  clib_ring_new_aligned (complq->rs_slots, 32, CLIB_CACHE_LINE_BYTES);

  vec_validate_aligned (complq->tmp_descs, complq->size,
			CLIB_CACHE_LINE_BYTES);
  vec_validate_aligned (complq->tmp_bufs, complq->size, CLIB_CACHE_LINE_BYTES);

  return 0;
}

clib_error_t *
idpf_split_txq_init (vlib_main_t *vm, idpf_device_t *id, idpf_vport_t *vport,
		     u16 qid, u16 txq_size)
{
  clib_error_t *err;
  idpf_txq_t *txq;
  u16 n, complq_qid;
  u8 bpi = vlib_buffer_pool_get_default_for_numa (vm, id->numa_node);

  vec_validate_aligned (vport->txqs, qid, CLIB_CACHE_LINE_BYTES);
  txq = vec_elt_at_index (vport->txqs, qid);
  txq->size = txq_size;
  txq->next = 0;
  clib_spinlock_init (&txq->lock);

  n = (txq->size / 510) + 1;
  vec_validate_aligned (txq->ph_bufs, n, CLIB_CACHE_LINE_BYTES);

  if (!vlib_buffer_alloc_from_pool (vm, txq->ph_bufs, n, bpi))
    return clib_error_return (0, "buffer allocation error");

  txq->descs = vlib_physmem_alloc_aligned_on_numa (
    vm, txq->size * sizeof (idpf_tx_desc_t), 2 * CLIB_CACHE_LINE_BYTES,
    id->numa_node);
  if (txq->descs == 0)
    return vlib_physmem_last_error (vm);

  err = vlib_pci_map_dma (vm, id->pci_dev_handle, (void *) txq->descs);
  if (err)
    return err;

  vec_validate_aligned (txq->bufs, txq->size, CLIB_CACHE_LINE_BYTES);
  txq->qtx_tail = id->bar0 + (vport->chunks_info.tx_qtail_start +
			      qid * vport->chunks_info.tx_qtail_spacing);

  /* initialize ring of pending RS slots */
  clib_ring_new_aligned (txq->rs_slots, 32, CLIB_CACHE_LINE_BYTES);

  vec_validate_aligned (txq->tmp_descs, txq->size, CLIB_CACHE_LINE_BYTES);
  vec_validate_aligned (txq->tmp_bufs, txq->size, CLIB_CACHE_LINE_BYTES);

  complq_qid = vport->chunks_info.tx_compl_start_qid + qid;
  err = idpf_tx_split_complq_setup (vm, id, vport, txq->complq, complq_qid,
				    2 * txq_size);
  if (err)
    return err;

  return 0;
}

clib_error_t *
idpf_single_txq_init (vlib_main_t *vm, idpf_device_t *id, idpf_vport_t *vport,
		      u16 qid, u16 txq_size)
{
  clib_error_t *err;
  idpf_txq_t *txq;
  u16 n;
  u8 bpi = vlib_buffer_pool_get_default_for_numa (vm, id->numa_node);

  vec_validate_aligned (vport->txqs, qid, CLIB_CACHE_LINE_BYTES);
  txq = vec_elt_at_index (vport->txqs, qid);
  txq->queue_index = vport->chunks_info.tx_start_qid + qid;
  txq->size = txq_size;
  txq->next = 0;
  clib_spinlock_init (&txq->lock);

  n = (txq->size / 510) + 1;
  vec_validate_aligned (txq->ph_bufs, n, CLIB_CACHE_LINE_BYTES);

  if (!vlib_buffer_alloc_from_pool (vm, txq->ph_bufs, n, bpi))
    return clib_error_return (0, "buffer allocation error");

  txq->descs = vlib_physmem_alloc_aligned_on_numa (
    vm, txq->size * sizeof (idpf_tx_desc_t), 2 * CLIB_CACHE_LINE_BYTES,
    id->numa_node);
  if (txq->descs == 0)
    return vlib_physmem_last_error (vm);

  err = vlib_pci_map_dma (vm, id->pci_dev_handle, (void *) txq->descs);
  if (err)
    return err;

  vec_validate_aligned (txq->bufs, txq->size, CLIB_CACHE_LINE_BYTES);
  txq->qtx_tail = id->bar0 + (vport->chunks_info.tx_qtail_start +
			      qid * vport->chunks_info.tx_qtail_spacing);

  /* initialize ring of pending RS slots */
  clib_ring_new_aligned (txq->rs_slots, 32, CLIB_CACHE_LINE_BYTES);

  vec_validate_aligned (txq->tmp_descs, txq->size, CLIB_CACHE_LINE_BYTES);
  vec_validate_aligned (txq->tmp_bufs, txq->size, CLIB_CACHE_LINE_BYTES);

  return 0;
}

clib_error_t *
idpf_tx_queue_setup (vlib_main_t *vm, idpf_device_t *id, idpf_vport_t *vport,
		     u16 qid, u16 txq_size)
{
  if (vport->txq_model == VIRTCHNL2_QUEUE_MODEL_SINGLE)
    return idpf_single_txq_init (vm, id, vport, qid, txq_size);
  else
    return idpf_split_txq_init (vm, id, vport, qid, txq_size);
}

clib_error_t *
idpf_vc_config_txq (vlib_main_t *vm, idpf_device_t *id, idpf_vport_t *vport,
		    u16 qid)
{
  idpf_txq_t *txq;
  virtchnl2_config_tx_queues_t *vc_txqs = NULL;
  virtchnl2_txq_info_t *txq_info;
  idpf_cmd_info_t args;
  clib_error_t *error;
  u16 num_qs;
  int size;

  vec_validate_aligned (vport->txqs, qid, CLIB_CACHE_LINE_BYTES);
  txq = vec_elt_at_index (vport->txqs, qid);

  if (vport->txq_model == VIRTCHNL2_QUEUE_MODEL_SINGLE)
    num_qs = IDPF_TXQ_PER_GRP;
  else
    num_qs = IDPF_TXQ_PER_GRP + IDPF_TX_COMPLQ_PER_GRP;

  size = sizeof (*vc_txqs) + (num_qs - 1) * sizeof (virtchnl2_txq_info_t);
  vc_txqs = clib_mem_alloc_aligned (size, CLIB_CACHE_LINE_BYTES);
  clib_memset (vc_txqs, 0, size);

  vc_txqs->vport_id = vport->vport_id;
  vc_txqs->num_qinfo = num_qs;

  if (vport->txq_model == VIRTCHNL2_QUEUE_MODEL_SINGLE)
    {
      txq_info = &vc_txqs->qinfo[0];
      txq_info->dma_ring_addr = idpf_dma_addr (vm, id, (void *) txq->descs);
      txq_info->type = VIRTCHNL2_QUEUE_TYPE_TX;
      txq_info->queue_id = txq->queue_index;
      txq_info->model = VIRTCHNL2_QUEUE_MODEL_SINGLE;
      txq_info->sched_mode = VIRTCHNL2_TXQ_SCHED_MODE_QUEUE;
      txq_info->ring_len = txq->size;
    }
  else
    {
      /* txq info */
      txq_info = &vc_txqs->qinfo[0];
      txq_info->dma_ring_addr = idpf_dma_addr (vm, id, (void *) txq->descs);
      txq_info->type = VIRTCHNL2_QUEUE_TYPE_TX;
      txq_info->queue_id = txq->queue_index;
      txq_info->model = VIRTCHNL2_QUEUE_MODEL_SPLIT;
      txq_info->sched_mode = VIRTCHNL2_TXQ_SCHED_MODE_FLOW;
      txq_info->ring_len = txq->size;
      txq_info->tx_compl_queue_id = txq->complq->queue_index;
      txq_info->relative_queue_id = txq_info->queue_id;

      /* tx completion queue info */
      idpf_txq_t *complq = txq->complq;
      txq_info = &vc_txqs->qinfo[1];
      txq_info->dma_ring_addr = idpf_dma_addr (vm, id, (void *) complq->descs);
      txq_info->type = VIRTCHNL2_QUEUE_TYPE_TX_COMPLETION;
      txq_info->queue_id = complq->queue_index;
      txq_info->model = VIRTCHNL2_QUEUE_MODEL_SPLIT;
      txq_info->sched_mode = VIRTCHNL2_TXQ_SCHED_MODE_FLOW;
      txq_info->ring_len = complq->size;
    }

  clib_memset (&args, 0, sizeof (args));
  args.ops = VIRTCHNL2_OP_CONFIG_TX_QUEUES;
  args.in_args = (u8 *) vc_txqs;
  args.in_args_size = size;
  args.out_buffer = id->mbx_resp;
  args.out_size = IDPF_DFLT_MBX_BUF_SIZE;

  error = idpf_execute_vc_cmd (vm, id, &args);
  clib_mem_free (vc_txqs);
  if (error != 0)
    return clib_error_return (
      0, "Failed to execute command VIRTCHNL2_OP_CONFIG_TX_QUEUES");

  return error;
}

clib_error_t *
idpf_vc_config_rxq (vlib_main_t *vm, idpf_device_t *id, idpf_vport_t *vport,
		    u16 qid)
{
  idpf_rxq_t *rxq;
  virtchnl2_config_rx_queues_t *vc_rxqs = NULL;
  virtchnl2_rxq_info_t *rxq_info;
  idpf_cmd_info_t args;
  clib_error_t *error;
  u16 num_qs;
  int size, i;

  vec_validate_aligned (vport->rxqs, qid, CLIB_CACHE_LINE_BYTES);
  rxq = vec_elt_at_index (vport->rxqs, qid);

  if (vport->rxq_model == VIRTCHNL2_QUEUE_MODEL_SINGLE)
    num_qs = IDPF_RXQ_PER_GRP;
  else
    num_qs = IDPF_RXQ_PER_GRP + IDPF_RX_BUFQ_PER_GRP;

  size = sizeof (*vc_rxqs) + (num_qs - 1) * sizeof (virtchnl2_rxq_info_t);
  vc_rxqs = clib_mem_alloc_aligned (size, CLIB_CACHE_LINE_BYTES);
  clib_memset (vc_rxqs, 0, size);

  vc_rxqs->vport_id = vport->vport_id;
  vc_rxqs->num_qinfo = num_qs;

  if (vport->rxq_model == VIRTCHNL2_QUEUE_MODEL_SINGLE)
    {
      rxq_info = &vc_rxqs->qinfo[0];
      rxq_info->dma_ring_addr = idpf_dma_addr (vm, id, (void *) rxq->descs);
      rxq_info->type = VIRTCHNL2_QUEUE_TYPE_RX;
      rxq_info->queue_id = rxq->queue_index;
      rxq_info->model = VIRTCHNL2_QUEUE_MODEL_SINGLE;
      rxq_info->data_buffer_size = vlib_buffer_get_default_data_size (vm);
      rxq_info->max_pkt_size = ETHERNET_MAX_PACKET_BYTES;

      rxq_info->desc_ids = VIRTCHNL2_RXDID_2_FLEX_SQ_NIC_M;
      rxq_info->qflags |= VIRTCHNL2_RX_DESC_SIZE_32BYTE;

      rxq_info->ring_len = rxq->size;
    }
  else
    {
      /* Rx queue */
      rxq_info = &vc_rxqs->qinfo[0];
      rxq_info->dma_ring_addr = idpf_dma_addr (vm, id, (void *) rxq->descs);
      rxq_info->type = VIRTCHNL2_QUEUE_TYPE_RX;
      rxq_info->queue_id = rxq->queue_index;
      rxq_info->model = VIRTCHNL2_QUEUE_MODEL_SINGLE;
      rxq_info->data_buffer_size = vlib_buffer_get_default_data_size (vm);
      rxq_info->max_pkt_size = ETHERNET_MAX_PACKET_BYTES;

      rxq_info->desc_ids = VIRTCHNL2_RXDID_2_FLEX_SPLITQ_M;
      rxq_info->qflags |= VIRTCHNL2_RX_DESC_SIZE_32BYTE;

      rxq_info->ring_len = rxq->size;
      rxq_info->rx_bufq1_id = rxq->bufq1->queue_index;
      rxq_info->rx_bufq2_id = rxq->bufq2->queue_index;
      rxq_info->rx_buffer_low_watermark = 64;

      /* Buffer queue */
      for (i = 1; i <= IDPF_RX_BUFQ_PER_GRP; i++)
	{
	  idpf_rxq_t *bufq = (i == 1 ? rxq->bufq1 : rxq->bufq2);
	  rxq_info = &vc_rxqs->qinfo[i];
	  rxq_info->dma_ring_addr =
	    idpf_dma_addr (vm, id, (void *) bufq->descs);
	  rxq_info->type = VIRTCHNL2_QUEUE_TYPE_RX_BUFFER;
	  rxq_info->queue_id = bufq->queue_index;
	  rxq_info->model = VIRTCHNL2_QUEUE_MODEL_SPLIT;
	  rxq_info->data_buffer_size = vlib_buffer_get_default_data_size (vm);
	  rxq_info->desc_ids = VIRTCHNL2_RXDID_2_FLEX_SPLITQ_M;
	  rxq_info->ring_len = bufq->size;

	  rxq_info->buffer_notif_stride = IDPF_RX_BUF_STRIDE;
	  rxq_info->rx_buffer_low_watermark = 64;
	}
    }

  clib_memset (&args, 0, sizeof (args));
  args.ops = VIRTCHNL2_OP_CONFIG_RX_QUEUES;
  args.in_args = (u8 *) vc_rxqs;
  args.in_args_size = size;
  args.out_buffer = id->mbx_resp;
  args.out_size = IDPF_DFLT_MBX_BUF_SIZE;

  error = idpf_execute_vc_cmd (vm, id, &args);
  clib_mem_free (vc_rxqs);
  if (error != 0)
    return clib_error_return (
      0, "Failed to execute command VIRTCHNL2_OP_CONFIG_RX_QUEUES");

  return error;
}

clib_error_t *
idpf_alloc_vectors (vlib_main_t *vm, idpf_device_t *id, idpf_vport_t *vport,
		    uint16_t num_vectors)
{
  virtchnl2_alloc_vectors_t *alloc_vec;
  idpf_cmd_info_t args;
  clib_error_t *error;
  int len;

  len = sizeof (virtchnl2_alloc_vectors_t) +
	(num_vectors - 1) * sizeof (virtchnl2_vector_chunk_t);
  alloc_vec = clib_mem_alloc_aligned (len, CLIB_CACHE_LINE_BYTES);
  clib_memset (alloc_vec, 0, len);

  alloc_vec->num_vectors = num_vectors;

  args.ops = VIRTCHNL2_OP_ALLOC_VECTORS;
  args.in_args = (u8 *) alloc_vec;
  args.in_args_size = sizeof (virtchnl2_alloc_vectors_t);
  args.out_buffer = id->mbx_resp;
  args.out_size = IDPF_DFLT_MBX_BUF_SIZE;
  error = idpf_execute_vc_cmd (vm, id, &args);
  if (error != 0)
    return clib_error_return (
      0, "Failed to execute command VIRTCHNL2_OP_ALLOC_VECTORS");

  if (vport->recv_vectors == NULL)
    {
      vport->recv_vectors =
	clib_mem_alloc_aligned (len, CLIB_CACHE_LINE_BYTES);
      clib_memset (vport->recv_vectors, 0, len);
    }

  clib_memcpy (vport->recv_vectors, args.out_buffer, len);
  clib_mem_free (alloc_vec);
  return error;
}

clib_error_t *
idpf_vc_ena_dis_one_queue (vlib_main_t *vm, idpf_device_t *id,
			   idpf_vport_t *vport, u16 qid, u32 type, bool on)
{
  virtchnl2_del_ena_dis_queues_t *queue_select;
  virtchnl2_queue_chunk_t *queue_chunk;
  idpf_cmd_info_t args;
  clib_error_t *error = 0;
  int len;

  len = sizeof (virtchnl2_del_ena_dis_queues_t);
  queue_select = clib_mem_alloc_aligned (len, CLIB_CACHE_LINE_BYTES);
  clib_memset (queue_select, 0, len);

  queue_chunk = queue_select->chunks.chunks;
  queue_select->chunks.num_chunks = 1;
  queue_select->vport_id = vport->vport_id;

  queue_chunk->type = type;
  queue_chunk->start_queue_id = qid;
  queue_chunk->num_queues = 1;

  args.ops = on ? VIRTCHNL2_OP_ENABLE_QUEUES : VIRTCHNL2_OP_DISABLE_QUEUES;
  args.in_args = (u8 *) queue_select;
  args.in_args_size = len;
  args.out_buffer = id->mbx_resp;
  args.out_size = IDPF_DFLT_MBX_BUF_SIZE;
  error = idpf_execute_vc_cmd (vm, id, &args);
  if (error != 0)
    return clib_error_return (
      0, "Failed to execute command of VIRTCHNL2_OP_%s_QUEUES",
      on ? "ENABLE" : "DISABLE");

  clib_mem_free (queue_select);
  return error;
}

clib_error_t *
idpf_op_enable_queues (vlib_main_t *vm, idpf_device_t *id, idpf_vport_t *vport,
		       u16 qid, bool rx, bool on)
{
  clib_error_t *error;
  u16 queue_index;
  u32 type;

  /* switch txq/rxq */
  type = rx ? VIRTCHNL2_QUEUE_TYPE_RX : VIRTCHNL2_QUEUE_TYPE_TX;

  if (type == VIRTCHNL2_QUEUE_TYPE_RX)
    {
      queue_index = vport->chunks_info.rx_start_qid + qid;
      error = idpf_vc_ena_dis_one_queue (vm, id, vport, queue_index, type, on);
    }
  else
    {
      queue_index = vport->chunks_info.tx_start_qid + qid;
      error = idpf_vc_ena_dis_one_queue (vm, id, vport, queue_index, type, on);
    }
  if (error != 0)
    return error;

  /* switch tx completion queue */
  if (!rx && vport->txq_model == VIRTCHNL2_QUEUE_MODEL_SPLIT)
    {
      type = VIRTCHNL2_QUEUE_TYPE_TX_COMPLETION;
      queue_index = vport->chunks_info.tx_compl_start_qid + qid;
      error = idpf_vc_ena_dis_one_queue (vm, id, vport, queue_index, type, on);
      if (error != 0)
	return error;
    }

  /* switch rx buffer queue */
  if (rx && vport->rxq_model == VIRTCHNL2_QUEUE_MODEL_SPLIT)
    {
      type = VIRTCHNL2_QUEUE_TYPE_RX_BUFFER;
      queue_index = vport->chunks_info.rx_buf_start_qid + 2 * qid;
      error = idpf_vc_ena_dis_one_queue (vm, id, vport, queue_index, type, on);
      if (error != 0)
	return error;
      queue_index++;
      error = idpf_vc_ena_dis_one_queue (vm, id, vport, queue_index, type, on);
      if (error != 0)
	return error;
    }

  return error;
}

clib_error_t *
idpf_queue_init (vlib_main_t *vm, idpf_device_t *id, idpf_vport_t *vport,
		 idpf_create_if_args_t *args)
{
  clib_error_t *error = 0;
  int i;

  for (i = 0; i < id->n_rx_queues; i++)
    {
      if ((error = idpf_rx_queue_setup (vm, id, vport, i, args->rxq_size)))
	return error;
      if ((error = idpf_vc_config_rxq (vm, id, vport, i)))
	return error;
      if ((error = idpf_op_enable_queues (vm, id, vport, i, true, true)))
	return error;
    }

  for (i = 0; i < id->n_tx_queues; i++)
    {
      if ((error = idpf_tx_queue_setup (vm, id, vport, i, args->txq_size)))
	return error;
      if ((error = idpf_vc_config_txq (vm, id, vport, i)))
	return error;
      if ((error = idpf_op_enable_queues (vm, id, vport, i, false, true)))
	return error;
    }

  if ((error = idpf_alloc_vectors (vm, id, vport, IDPF_DFLT_Q_VEC_NUM)))
    return error;

  if ((error = idpf_config_rx_queues_irqs (vm, id, vport)))
    return error;

  return error;
}

clib_error_t *
idpf_op_version (vlib_main_t *vm, idpf_device_t *id)
{
  clib_error_t *error = 0;
  idpf_cmd_info_t args;
  virtchnl2_version_info_t myver = {
    .major = VIRTCHNL2_VERSION_MAJOR_2,
    .minor = VIRTCHNL2_VERSION_MINOR_0,
  };
  virtchnl2_version_info_t ver = { 0 };

  idpf_log_debug (id, "version: major %u minor %u", myver.major, myver.minor);

  args.ops = VIRTCHNL2_OP_VERSION;
  args.in_args = (u8 *) &myver;
  args.in_args_size = sizeof (myver);
  args.out_buffer = id->mbx_resp;
  args.out_size = IDPF_DFLT_MBX_BUF_SIZE;
  error = idpf_execute_vc_cmd (vm, id, &args);
  if (error != 0)
    return clib_error_return (0,
			      "Failed to execute command VIRTCHNL_OP_VERSION");

  clib_memcpy (&ver, args.out_buffer, sizeof (ver));

  if (ver.major != VIRTCHNL2_VERSION_MAJOR_2 ||
      ver.minor != VIRTCHNL2_VERSION_MINOR_0)
    return clib_error_return (0,
			      "incompatible virtchnl version "
			      "(remote %d.%d)",
			      ver.major, ver.minor);

  return 0;
}

clib_error_t *
idpf_op_get_caps (vlib_main_t *vm, idpf_device_t *id,
		  virtchnl2_get_capabilities_t *caps)
{
  virtchnl2_get_capabilities_t caps_msg = { 0 };
  idpf_cmd_info_t args;
  clib_error_t *error = 0;

  caps_msg.csum_caps =
    VIRTCHNL2_CAP_TX_CSUM_L3_IPV4 | VIRTCHNL2_CAP_TX_CSUM_L4_IPV4_TCP |
    VIRTCHNL2_CAP_TX_CSUM_L4_IPV4_UDP | VIRTCHNL2_CAP_TX_CSUM_L4_IPV4_SCTP |
    VIRTCHNL2_CAP_TX_CSUM_L4_IPV6_TCP | VIRTCHNL2_CAP_TX_CSUM_L4_IPV6_UDP |
    VIRTCHNL2_CAP_TX_CSUM_L4_IPV6_SCTP | VIRTCHNL2_CAP_TX_CSUM_GENERIC |
    VIRTCHNL2_CAP_RX_CSUM_L3_IPV4 | VIRTCHNL2_CAP_RX_CSUM_L4_IPV4_TCP |
    VIRTCHNL2_CAP_RX_CSUM_L4_IPV4_UDP | VIRTCHNL2_CAP_RX_CSUM_L4_IPV4_SCTP |
    VIRTCHNL2_CAP_RX_CSUM_L4_IPV6_TCP | VIRTCHNL2_CAP_RX_CSUM_L4_IPV6_UDP |
    VIRTCHNL2_CAP_RX_CSUM_L4_IPV6_SCTP | VIRTCHNL2_CAP_RX_CSUM_GENERIC;

  caps_msg.other_caps = VIRTCHNL2_CAP_WB_ON_ITR;

  args.ops = VIRTCHNL2_OP_GET_CAPS;
  args.in_args = (u8 *) &caps_msg;
  args.in_args_size = sizeof (caps_msg);
  args.out_buffer = id->mbx_resp;
  args.out_size = IDPF_DFLT_MBX_BUF_SIZE;
  error = idpf_execute_vc_cmd (vm, id, &args);
  if (error != 0)
    return clib_error_return (
      0, "Failed to execute command VIRTCHNL2_OP_GET_CAPS");

  clib_memcpy (caps, args.out_buffer, sizeof (*caps));
  return error;
}

#define CTLQ_NUM 2
clib_error_t *
idpf_mbx_init (vlib_main_t *vm, idpf_device_t *id)
{
  idpf_ctlq_create_info_t ctlq_info[CTLQ_NUM] = {
		{
			.type = IDPF_CTLQ_TYPE_MAILBOX_TX,
			.id = IDPF_CTLQ_ID,
			.len = IDPF_CTLQ_LEN,
			.buf_size = IDPF_DFLT_MBX_BUF_SIZE,
			.reg = {
				.head = PF_FW_ATQH,
				.tail = PF_FW_ATQT,
				.len = PF_FW_ATQLEN,
				.bah = PF_FW_ATQBAH,
				.bal = PF_FW_ATQBAL,
				.len_mask = PF_FW_ATQLEN_ATQLEN_M,
				.len_ena_mask = PF_FW_ATQLEN_ATQENABLE_M,
				.head_mask = PF_FW_ATQH_ATQH_M,
			}
		},
		{
			.type = IDPF_CTLQ_TYPE_MAILBOX_RX,
			.id = IDPF_CTLQ_ID,
			.len = IDPF_CTLQ_LEN,
			.buf_size = IDPF_DFLT_MBX_BUF_SIZE,
			.reg = {
				.head = PF_FW_ARQH,
				.tail = PF_FW_ARQT,
				.len = PF_FW_ARQLEN,
				.bah = PF_FW_ARQBAH,
				.bal = PF_FW_ARQBAL,
				.len_mask = PF_FW_ARQLEN_ARQLEN_M,
				.len_ena_mask = PF_FW_ARQLEN_ARQENABLE_M,
				.head_mask = PF_FW_ARQH_ARQH_M,
			}
		}
	};
  struct idpf_ctlq_info *ctlq;

  if (idpf_ctlq_init (vm, id, CTLQ_NUM, ctlq_info))
    return clib_error_return (0, "ctlq init failed");

  LIST_FOR_EACH_ENTRY_SAFE (ctlq, NULL, &id->cq_list_head,
			    struct idpf_ctlq_info, cq_list)
  {
    if (ctlq->q_id == IDPF_CTLQ_ID &&
	ctlq->cq_type == IDPF_CTLQ_TYPE_MAILBOX_TX)
      id->asq = ctlq;
    if (ctlq->q_id == IDPF_CTLQ_ID &&
	ctlq->cq_type == IDPF_CTLQ_TYPE_MAILBOX_RX)
      id->arq = ctlq;
  }

  if (!id->asq || !id->arq)
    {
      idpf_ctlq_deinit (id);
      return clib_error_return (0, "ctlq deinit");
    }

  return 0;
}

clib_error_t *
idpf_vc_query_ptype_info (vlib_main_t *vm, idpf_device_t *id)
{
  virtchnl2_get_ptype_info_t ptype_info;
  idpf_cmd_info_t args;
  clib_error_t *error;

  ptype_info.start_ptype_id = 0;
  ptype_info.num_ptypes = IDPF_MAX_PKT_TYPE;
  args.ops = VIRTCHNL2_OP_GET_PTYPE_INFO;
  args.in_args = (u8 *) &ptype_info;
  args.in_args_size = sizeof (virtchnl2_get_ptype_info_t);
  args.out_buffer = NULL;
  args.out_size = 0;

  error = idpf_execute_vc_cmd (vm, id, &args);
  if (error != 0)
    return clib_error_return (
      0, "Failed to execute command VIRTCHNL2_OP_GET_PTYPE_INFO");

  return error;
}

clib_error_t *
idpf_get_pkt_type (vlib_main_t *vm, idpf_device_t *id)
{
  virtchnl2_get_ptype_info_t *ptype_info;
  u16 ptype_recvd = 0, ptype_offset, i, j;
  clib_error_t *error;

  error = idpf_vc_query_ptype_info (vm, id);
  if (error != 0)
    return clib_error_return (0, "Fail to query packet type information");

  ptype_info =
    clib_mem_alloc_aligned (IDPF_DFLT_MBX_BUF_SIZE, CLIB_CACHE_LINE_BYTES);

  while (ptype_recvd < IDPF_MAX_PKT_TYPE)
    {
      error = idpf_read_one_msg (vm, id, VIRTCHNL2_OP_GET_PTYPE_INFO,
				 (u8 *) ptype_info, IDPF_DFLT_MBX_BUF_SIZE);
      if (error != 0)
	{
	  error = clib_error_return (0, "Fail to get packet type information");
	  goto free_ptype_info;
	}

      ptype_recvd += ptype_info->num_ptypes;
      ptype_offset =
	sizeof (virtchnl2_get_ptype_info_t) - sizeof (virtchnl2_ptype_t);

      for (i = 0; i < ptype_info->num_ptypes; i++)
	{
	  bool is_inner = false, is_ip = false;
	  virtchnl2_ptype_t *ptype;
	  u32 proto_hdr = 0;

	  ptype = (virtchnl2_ptype_t *) ((u8 *) ptype_info + ptype_offset);
	  ptype_offset += IDPF_GET_PTYPE_SIZE (ptype);
	  if (ptype_offset > IDPF_DFLT_MBX_BUF_SIZE)
	    {
	      error =
		clib_error_return (0, "Ptype offset exceeds mbx buffer size");
	      goto free_ptype_info;
	    }

	  if (ptype->ptype_id_10 == 0xFFFF)
	    goto free_ptype_info;

	  for (j = 0; j < ptype->proto_id_count; j++)
	    {
	      switch (ptype->proto_id[j])
		{
		case VIRTCHNL2_PROTO_HDR_GRE:
		case VIRTCHNL2_PROTO_HDR_VXLAN:
		  proto_hdr &= ~IDPF_PTYPE_L4_MASK;
		  proto_hdr |= IDPF_PTYPE_TUNNEL_GRENAT;
		  is_inner = true;
		  break;
		case VIRTCHNL2_PROTO_HDR_MAC:
		  if (is_inner)
		    {
		      proto_hdr &= ~IDPF_PTYPE_INNER_L2_MASK;
		      proto_hdr |= IDPF_PTYPE_INNER_L2_ETHER;
		    }
		  else
		    {
		      proto_hdr &= ~IDPF_PTYPE_L2_MASK;
		      proto_hdr |= IDPF_PTYPE_L2_ETHER;
		    }
		  break;
		case VIRTCHNL2_PROTO_HDR_VLAN:
		  if (is_inner)
		    {
		      proto_hdr &= ~IDPF_PTYPE_INNER_L2_MASK;
		      proto_hdr |= IDPF_PTYPE_INNER_L2_ETHER_VLAN;
		    }
		  break;
		case VIRTCHNL2_PROTO_HDR_PTP:
		  proto_hdr &= ~IDPF_PTYPE_L2_MASK;
		  proto_hdr |= IDPF_PTYPE_L2_ETHER_TIMESYNC;
		  break;
		case VIRTCHNL2_PROTO_HDR_LLDP:
		  proto_hdr &= ~IDPF_PTYPE_L2_MASK;
		  proto_hdr |= IDPF_PTYPE_L2_ETHER_LLDP;
		  break;
		case VIRTCHNL2_PROTO_HDR_ARP:
		  proto_hdr &= ~IDPF_PTYPE_L2_MASK;
		  proto_hdr |= IDPF_PTYPE_L2_ETHER_ARP;
		  break;
		case VIRTCHNL2_PROTO_HDR_PPPOE:
		  proto_hdr &= ~IDPF_PTYPE_L2_MASK;
		  proto_hdr |= IDPF_PTYPE_L2_ETHER_PPPOE;
		  break;
		case VIRTCHNL2_PROTO_HDR_IPV4:
		  if (!is_ip)
		    {
		      proto_hdr |= IDPF_PTYPE_L3_IPV4_EXT_UNKNOWN;
		      is_ip = true;
		    }
		  else
		    {
		      proto_hdr |= IDPF_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN |
				   IDPF_PTYPE_TUNNEL_IP;
		      is_inner = true;
		    }
		  break;
		case VIRTCHNL2_PROTO_HDR_IPV6:
		  if (!is_ip)
		    {
		      proto_hdr |= IDPF_PTYPE_L3_IPV6_EXT_UNKNOWN;
		      is_ip = true;
		    }
		  else
		    {
		      proto_hdr |= IDPF_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
				   IDPF_PTYPE_TUNNEL_IP;
		      is_inner = true;
		    }
		  break;
		case VIRTCHNL2_PROTO_HDR_IPV4_FRAG:
		case VIRTCHNL2_PROTO_HDR_IPV6_FRAG:
		  if (is_inner)
		    proto_hdr |= IDPF_PTYPE_INNER_L4_FRAG;
		  else
		    proto_hdr |= IDPF_PTYPE_L4_FRAG;
		  break;
		case VIRTCHNL2_PROTO_HDR_UDP:
		  if (is_inner)
		    proto_hdr |= IDPF_PTYPE_INNER_L4_UDP;
		  else
		    proto_hdr |= IDPF_PTYPE_L4_UDP;
		  break;
		case VIRTCHNL2_PROTO_HDR_TCP:
		  if (is_inner)
		    proto_hdr |= IDPF_PTYPE_INNER_L4_TCP;
		  else
		    proto_hdr |= IDPF_PTYPE_L4_TCP;
		  break;
		case VIRTCHNL2_PROTO_HDR_SCTP:
		  if (is_inner)
		    proto_hdr |= IDPF_PTYPE_INNER_L4_SCTP;
		  else
		    proto_hdr |= IDPF_PTYPE_L4_SCTP;
		  break;
		case VIRTCHNL2_PROTO_HDR_ICMP:
		  if (is_inner)
		    proto_hdr |= IDPF_PTYPE_INNER_L4_ICMP;
		  else
		    proto_hdr |= IDPF_PTYPE_L4_ICMP;
		  break;
		case VIRTCHNL2_PROTO_HDR_ICMPV6:
		  if (is_inner)
		    proto_hdr |= IDPF_PTYPE_INNER_L4_ICMP;
		  else
		    proto_hdr |= IDPF_PTYPE_L4_ICMP;
		  break;
		case VIRTCHNL2_PROTO_HDR_L2TPV2:
		case VIRTCHNL2_PROTO_HDR_L2TPV2_CONTROL:
		case VIRTCHNL2_PROTO_HDR_L2TPV3:
		  is_inner = true;
		  proto_hdr |= IDPF_PTYPE_TUNNEL_L2TP;
		  break;
		case VIRTCHNL2_PROTO_HDR_NVGRE:
		  is_inner = true;
		  proto_hdr |= IDPF_PTYPE_TUNNEL_NVGRE;
		  break;
		case VIRTCHNL2_PROTO_HDR_GTPC_TEID:
		  is_inner = true;
		  proto_hdr |= IDPF_PTYPE_TUNNEL_GTPC;
		  break;
		case VIRTCHNL2_PROTO_HDR_GTPU:
		case VIRTCHNL2_PROTO_HDR_GTPU_UL:
		case VIRTCHNL2_PROTO_HDR_GTPU_DL:
		  is_inner = true;
		  proto_hdr |= IDPF_PTYPE_TUNNEL_GTPU;
		  break;
		case VIRTCHNL2_PROTO_HDR_PAY:
		case VIRTCHNL2_PROTO_HDR_IPV6_EH:
		case VIRTCHNL2_PROTO_HDR_PRE_MAC:
		case VIRTCHNL2_PROTO_HDR_POST_MAC:
		case VIRTCHNL2_PROTO_HDR_ETHERTYPE:
		case VIRTCHNL2_PROTO_HDR_SVLAN:
		case VIRTCHNL2_PROTO_HDR_CVLAN:
		case VIRTCHNL2_PROTO_HDR_MPLS:
		case VIRTCHNL2_PROTO_HDR_MMPLS:
		case VIRTCHNL2_PROTO_HDR_CTRL:
		case VIRTCHNL2_PROTO_HDR_ECP:
		case VIRTCHNL2_PROTO_HDR_EAPOL:
		case VIRTCHNL2_PROTO_HDR_PPPOD:
		case VIRTCHNL2_PROTO_HDR_IGMP:
		case VIRTCHNL2_PROTO_HDR_AH:
		case VIRTCHNL2_PROTO_HDR_ESP:
		case VIRTCHNL2_PROTO_HDR_IKE:
		case VIRTCHNL2_PROTO_HDR_NATT_KEEP:
		case VIRTCHNL2_PROTO_HDR_GTP:
		case VIRTCHNL2_PROTO_HDR_GTP_EH:
		case VIRTCHNL2_PROTO_HDR_GTPCV2:
		case VIRTCHNL2_PROTO_HDR_ECPRI:
		case VIRTCHNL2_PROTO_HDR_VRRP:
		case VIRTCHNL2_PROTO_HDR_OSPF:
		case VIRTCHNL2_PROTO_HDR_TUN:
		case VIRTCHNL2_PROTO_HDR_VXLAN_GPE:
		case VIRTCHNL2_PROTO_HDR_GENEVE:
		case VIRTCHNL2_PROTO_HDR_NSH:
		case VIRTCHNL2_PROTO_HDR_QUIC:
		case VIRTCHNL2_PROTO_HDR_PFCP:
		case VIRTCHNL2_PROTO_HDR_PFCP_NODE:
		case VIRTCHNL2_PROTO_HDR_PFCP_SESSION:
		case VIRTCHNL2_PROTO_HDR_RTP:
		case VIRTCHNL2_PROTO_HDR_NO_PROTO:
		default:
		  continue;
		}
	      id->ptype_tbl[ptype->ptype_id_10] = proto_hdr;
	    }
	}
    }

free_ptype_info:
  clib_mem_free (ptype_info);
  clear_cmd (id);
  return error;
}

static void
idpf_reset_pf (idpf_device_t *id)
{
  u32 reg;

  reg = idpf_reg_read (id, PFGEN_CTRL);
  idpf_reg_write (id, PFGEN_CTRL, (reg | PFGEN_CTRL_PFSWR));
}

#define IDPF_RESET_WAIT_CNT 100
clib_error_t *
idpf_check_pf_reset_done (vlib_main_t *vm, idpf_device_t *id)
{
  u32 reg;
  int i;

  for (i = 0; i < IDPF_RESET_WAIT_CNT; i++)
    {
      reg = idpf_reg_read (id, PFGEN_RSTAT);
      if (reg != 0xFFFFFFFF && (reg & PFGEN_RSTAT_PFR_STATE_M))
	return 0;
      vlib_process_suspend (vm, 1.0);
    }

  return clib_error_return (0, "pf reset time out");
}

void
idpf_init_vport_req_info (idpf_device_t *id,
			  virtchnl2_create_vport_t *vport_info)
{
  vport_info->vport_type = VIRTCHNL2_VPORT_TYPE_DEFAULT;
  if (id->txq_model == 1)
    {
      vport_info->txq_model = VIRTCHNL2_QUEUE_MODEL_SPLIT;
      vport_info->num_tx_q = IDPF_DEFAULT_TXQ_NUM;
      vport_info->num_tx_complq =
	IDPF_DEFAULT_TXQ_NUM * IDPF_TX_COMPLQ_PER_GRP;
    }
  else
    {
      vport_info->txq_model = VIRTCHNL2_QUEUE_MODEL_SINGLE;
      vport_info->num_tx_q = IDPF_DEFAULT_TXQ_NUM;
      vport_info->num_tx_complq = 0;
    }
  if (id->rxq_model == 1)
    {
      vport_info->rxq_model = VIRTCHNL2_QUEUE_MODEL_SPLIT;
      vport_info->num_rx_q = IDPF_DEFAULT_RXQ_NUM;
      vport_info->num_rx_bufq = IDPF_DEFAULT_RXQ_NUM * IDPF_RX_BUFQ_PER_GRP;
    }
  else
    {
      vport_info->rxq_model = VIRTCHNL2_QUEUE_MODEL_SINGLE;
      vport_info->num_rx_q = IDPF_DEFAULT_RXQ_NUM;
      vport_info->num_rx_bufq = 0;
    }

  return;
}

clib_error_t *
idpf_vc_create_vport (vlib_main_t *vm, idpf_device_t *id, idpf_vport_t *vport,
		      virtchnl2_create_vport_t *vport_req_info)
{
  virtchnl2_create_vport_t vport_msg = { 0 };
  idpf_cmd_info_t args;
  clib_error_t *error;

  vport_msg.vport_type = vport_req_info->vport_type;
  vport_msg.txq_model = vport_req_info->txq_model;
  vport_msg.rxq_model = vport_req_info->rxq_model;
  vport_msg.num_tx_q = vport_req_info->num_tx_q;
  vport_msg.num_tx_complq = vport_req_info->num_tx_complq;
  vport_msg.num_rx_q = vport_req_info->num_rx_q;
  vport_msg.num_rx_bufq = vport_req_info->num_rx_bufq;

  clib_memset (&args, 0, sizeof (args));
  args.ops = VIRTCHNL2_OP_CREATE_VPORT;
  args.in_args = (u8 *) &vport_msg;
  args.in_args_size = sizeof (vport_msg);
  args.out_buffer = id->mbx_resp;
  args.out_size = IDPF_DFLT_MBX_BUF_SIZE;
  error = idpf_execute_vc_cmd (vm, id, &args);
  if (error != 0)
    return clib_error_return (
      0, "Failed to execute command of VIRTCHNL2_OP_CREATE_VPORT");

  clib_memcpy (vport->vport_info, args.out_buffer, IDPF_DFLT_MBX_BUF_SIZE);
  return error;
}

clib_error_t *
idpf_vc_destroy_vport (vlib_main_t *vm, idpf_device_t *id, idpf_vport_t *vport)
{
  virtchnl2_vport_t vc_vport;
  idpf_cmd_info_t args;
  clib_error_t *error = 0;

  vc_vport.vport_id = vport->vport_id;

  clib_memset (&args, 0, sizeof (args));
  args.ops = VIRTCHNL2_OP_DESTROY_VPORT;
  args.in_args = (u8 *) &vc_vport;
  args.in_args_size = sizeof (vc_vport);
  args.out_buffer = id->mbx_resp;
  args.out_size = IDPF_DFLT_MBX_BUF_SIZE;
  error = idpf_execute_vc_cmd (vm, id, &args);
  if (error != 0)
    return clib_error_return (
      0, "Failed to execute command of VIRTCHNL2_OP_DESTROY_VPORT");

  return error;
}

clib_error_t *
idpf_init_vport (idpf_device_t *id, idpf_vport_t *vport)
{
  virtchnl2_create_vport_t *vport_info = vport->vport_info;
  int i, type;

  vport->vport_id = vport_info->vport_id;
  vport->txq_model = vport_info->txq_model;
  vport->rxq_model = vport_info->rxq_model;
  vport->num_tx_q = vport_info->num_tx_q;
  vport->num_tx_complq = vport_info->num_tx_complq;
  vport->num_rx_q = vport_info->num_rx_q;
  vport->num_rx_bufq = vport_info->num_rx_bufq;
  vport->max_mtu = vport_info->max_mtu;
  clib_memcpy (vport->default_mac_addr, vport_info->default_mac_addr,
	       IDPF_ETH_ALEN);

  for (i = 0; i < vport_info->chunks.num_chunks; i++)
    {
      type = vport_info->chunks.chunks[i].type;
      switch (type)
	{
	case VIRTCHNL2_QUEUE_TYPE_TX:
	  vport->chunks_info.tx_start_qid =
	    vport_info->chunks.chunks[i].start_queue_id;
	  vport->chunks_info.tx_qtail_start =
	    vport_info->chunks.chunks[i].qtail_reg_start;
	  vport->chunks_info.tx_qtail_spacing =
	    vport_info->chunks.chunks[i].qtail_reg_spacing;
	  break;
	case VIRTCHNL2_QUEUE_TYPE_RX:
	  vport->chunks_info.rx_start_qid =
	    vport_info->chunks.chunks[i].start_queue_id;
	  vport->chunks_info.rx_qtail_start =
	    vport_info->chunks.chunks[i].qtail_reg_start;
	  vport->chunks_info.rx_qtail_spacing =
	    vport_info->chunks.chunks[i].qtail_reg_spacing;
	  break;
	case VIRTCHNL2_QUEUE_TYPE_TX_COMPLETION:
	  vport->chunks_info.tx_compl_start_qid =
	    vport_info->chunks.chunks[i].start_queue_id;
	  vport->chunks_info.tx_compl_qtail_start =
	    vport_info->chunks.chunks[i].qtail_reg_start;
	  vport->chunks_info.tx_compl_qtail_spacing =
	    vport_info->chunks.chunks[i].qtail_reg_spacing;
	  break;
	case VIRTCHNL2_QUEUE_TYPE_RX_BUFFER:
	  vport->chunks_info.rx_buf_start_qid =
	    vport_info->chunks.chunks[i].start_queue_id;
	  vport->chunks_info.rx_buf_qtail_start =
	    vport_info->chunks.chunks[i].qtail_reg_start;
	  vport->chunks_info.rx_buf_qtail_spacing =
	    vport_info->chunks.chunks[i].qtail_reg_spacing;
	  break;
	default:
	  return clib_error_return (0, "Unsupported queue type");
	}
    }

  return 0;
}

clib_error_t *
idpf_ena_dis_vport (vlib_main_t *vm, idpf_device_t *id, idpf_vport_t *vport,
		    bool enable)
{
  virtchnl2_vport_t vc_vport;
  idpf_cmd_info_t args;
  clib_error_t *error;

  vc_vport.vport_id = vport->vport_id;
  args.ops = enable ? VIRTCHNL2_OP_ENABLE_VPORT : VIRTCHNL2_OP_DISABLE_VPORT;
  args.in_args = (u8 *) &vc_vport;
  args.in_args_size = sizeof (vc_vport);
  args.out_buffer = id->mbx_resp;
  args.out_size = IDPF_DFLT_MBX_BUF_SIZE;

  error = idpf_execute_vc_cmd (vm, id, &args);
  if (error != 0)
    {
      return clib_error_return (
	0, "Failed to execute command of VIRTCHNL2_OP_%s_VPORT",
	enable ? "ENABLE" : "DISABLE");
    }

  return error;
}

clib_error_t *
idpf_dealloc_vectors (vlib_main_t *vm, idpf_device_t *id, idpf_vport_t *vport)
{
  virtchnl2_alloc_vectors_t *alloc_vec;
  virtchnl2_vector_chunks_t *vcs;
  idpf_cmd_info_t args;
  clib_error_t *error;
  int len;

  alloc_vec = vport->recv_vectors;
  vcs = &alloc_vec->vchunks;

  len = sizeof (virtchnl2_vector_chunks_t) +
	(vcs->num_vchunks - 1) * sizeof (virtchnl2_vector_chunk_t);

  args.ops = VIRTCHNL2_OP_DEALLOC_VECTORS;
  args.in_args = (u8 *) vcs;
  args.in_args_size = len;
  args.out_buffer = id->mbx_resp;
  args.out_size = IDPF_DFLT_MBX_BUF_SIZE;
  error = idpf_execute_vc_cmd (vm, id, &args);
  if (error != 0)
    return clib_error_return (
      0, "Failed to execute command VIRTCHNL2_OP_DEALLOC_VECTORS");

  return error;
}

clib_error_t *
idpf_dev_vport_init (vlib_main_t *vm, idpf_device_t *id,
		     idpf_vport_param_t *param)
{
  idpf_vport_t *vport;
  virtchnl2_create_vport_t vport_req_info = { 0 };
  clib_error_t *error = 0;

  vport = clib_mem_alloc (sizeof (idpf_vport_t));
  clib_memset (vport, 0, sizeof (idpf_vport_t));

  vport->vport_info = clib_mem_alloc (IDPF_DFLT_MBX_BUF_SIZE);
  clib_memset (vport->vport_info, 0, IDPF_DFLT_MBX_BUF_SIZE);

  id->vports[param->idx] = vport;
  vport->id = id;
  vport->idx = param->idx;

  idpf_init_vport_req_info (id, &vport_req_info);

  error = idpf_vc_create_vport (vm, id, vport, &vport_req_info);
  if (error != 0)
    {
      idpf_log_err (id, "Failed to create vport.");
      goto err_create_vport;
    }

  error = idpf_init_vport (id, vport);
  if (error != 0)
    {
      idpf_log_err (id, "Failed to init vports.");
      goto err_init_vport;
    }

  id->vports[param->idx] = vport;

  clib_memcpy (id->hwaddr, vport->default_mac_addr, IDPF_ETH_ALEN);

  return error;

err_init_vport:
  id->vports[param->idx] = NULL; /* reset */
  idpf_vc_destroy_vport (vm, id, vport);
err_create_vport:
  clib_mem_free (vport->vport_info);
  clib_mem_free (vport);
  return error;
}

/* dev configure */
clib_error_t *
idpf_device_init (vlib_main_t *vm, idpf_main_t *im, idpf_device_t *id,
		  idpf_create_if_args_t *args)
{
  idpf_vport_t *vport;
  idpf_vport_param_t vport_param = { 0 };
  virtchnl2_get_capabilities_t caps = { 0 };
  clib_error_t *error;
  u16 rxq_num, txq_num;
  int i;

  idpf_reset_pf (id);
  error = idpf_check_pf_reset_done (vm, id);
  if (error)
    return error;

  /*
   * Init mailbox configuration
   */
  if ((error = idpf_mbx_init (vm, id)))
    return error;

  /*
   * Check API version
   */
  error = idpf_op_version (vm, id);
  if (error)
    return error;

  /*
   * Get pkt type table
   */
  error = idpf_get_pkt_type (vm, id);
  if (error)
    return error;

  /* Get idpf capability */
  error = idpf_op_get_caps (vm, id, &caps);
  if (error)
    return error;

  rxq_num = args->rxq_num ? args->rxq_num : 1;
  txq_num = args->txq_num ? args->txq_num : vlib_get_n_threads ();

  /* Sync capabilities */
  id->n_rx_queues = rxq_num;
  id->n_tx_queues = txq_num;
  id->csum_caps = caps.csum_caps;
  id->seg_caps = caps.seg_caps;
  id->hsplit_caps = caps.hsplit_caps;
  id->rsc_caps = caps.rsc_caps;
  id->rss_caps = caps.rss_caps;
  id->other_caps = caps.other_caps;
  id->max_rx_q = caps.max_rx_q;
  id->max_tx_q = caps.max_tx_q;
  id->max_rx_bufq = caps.max_rx_bufq;
  id->max_tx_complq = caps.max_tx_complq;
  id->max_sriov_vfs = caps.max_sriov_vfs;
  id->max_vports = caps.max_vports;
  id->default_num_vports = caps.default_num_vports;

  id->vports = clib_mem_alloc (id->max_vports * sizeof (*id->vports));
  id->max_rxq_per_msg =
    (IDPF_DFLT_MBX_BUF_SIZE - sizeof (virtchnl2_config_rx_queues_t)) /
    sizeof (virtchnl2_rxq_info_t);
  id->max_txq_per_msg =
    (IDPF_DFLT_MBX_BUF_SIZE - sizeof (virtchnl2_config_tx_queues_t)) /
    sizeof (virtchnl2_txq_info_t);

  id->cur_vport_idx = 0;
  id->cur_vports = 0;
  id->cur_vport_nb = 0;

  if (!args->rxq_single)
    id->rxq_model = 1;
  if (!args->txq_single)
    id->txq_model = 1;

  /* Init and enable vports */
  if (args->req_vport_nb == 1)
    {
      vport_param.id = id;
      vport_param.idx = 0;
      error = idpf_dev_vport_init (vm, id, &vport_param);
      if (error)
	return error;
      vport = id->vports[vport_param.idx];
      error = idpf_ena_dis_vport (vm, id, vport, true);
      if (error)
	return error;
      id->cur_vports |= 1ULL << vport_param.idx;
      id->cur_vport_nb++;
      id->cur_vport_idx++;
      error = idpf_queue_init (vm, id, vport, args);
      if (error)
	return error;
    }
  else
    {
      for (i = 0; i < args->req_vport_nb; i++)
	{
	  vport_param.id = id;
	  vport_param.idx = i;
	  if ((error = idpf_dev_vport_init (vm, id, &vport_param)))
	    return error;
	  vport = id->vports[vport_param.idx];
	  error = idpf_ena_dis_vport (vm, id, vport, true);
	  if (error)
	    return error;
	  id->cur_vports |= 1ULL << vport_param.idx;
	  id->cur_vport_nb++;
	  id->cur_vport_idx++;
	  error = idpf_queue_init (vm, id, vport, args);
	  if (error)
	    return error;
	}
    }

  id->flags |= IDPF_DEVICE_F_INITIALIZED;
  return error;
}

static u32
idpf_flag_change (vnet_main_t *vnm, vnet_hw_interface_t *hw, u32 flags)
{
  idpf_device_t *id = idpf_get_device (hw->dev_instance);

  switch (flags)
    {
    case ETHERNET_INTERFACE_FLAG_DEFAULT_L3:
      id->flags &= ~IDPF_DEVICE_F_PROMISC;
      break;
    case ETHERNET_INTERFACE_FLAG_ACCEPT_ALL:
      id->flags |= IDPF_DEVICE_F_PROMISC;
      break;
    default:
      return ~0;
    }

  return 0;
}

void
idpf_delete_if (vlib_main_t *vm, idpf_device_t *id, int with_barrier)
{
  vnet_main_t *vnm = vnet_get_main ();
  idpf_main_t *im = &idpf_main;
  idpf_vport_t *vport;
  int i;
  u32 dev_instance;

  id->flags &= ~IDPF_DEVICE_F_ADMIN_UP;

  if (id->hw_if_index)
    {
      if (with_barrier)
	vlib_worker_thread_barrier_sync (vm);
      vnet_hw_interface_set_flags (vnm, id->hw_if_index, 0);
      ethernet_delete_interface (vnm, id->hw_if_index);
      if (with_barrier)
	vlib_worker_thread_barrier_release (vm);
    }

  for (i = 0; i < id->cur_vport_nb; i++)
    {
      vport = id->vports[i];
      if (vport->recv_vectors != NULL)
	idpf_dealloc_vectors (vm, id, vport);
    }

  vlib_pci_device_close (vm, id->pci_dev_handle);

  vlib_physmem_free (vm, id->asq);
  vlib_physmem_free (vm, id->arq);

  for (i = 0; i < id->cur_vport_nb; i++)
    {
      vport = id->vports[i];
      vec_foreach_index (i, vport->rxqs)
	{
	  idpf_rxq_t *rxq = vec_elt_at_index (vport->rxqs, i);
	  vlib_physmem_free (vm, (void *) rxq->descs);
	  if (rxq->n_enqueued)
	    vlib_buffer_free_from_ring (vm, rxq->bufs, rxq->next, rxq->size,
					rxq->n_enqueued);
	  vec_free (rxq->bufs);
	}

      vec_free (vport->rxqs);

      vec_foreach_index (i, vport->txqs)
	{
	  idpf_txq_t *txq = vec_elt_at_index (vport->txqs, i);
	  vlib_physmem_free (vm, (void *) txq->descs);
	  if (txq->n_enqueued)
	    {
	      u16 first = (txq->next - txq->n_enqueued) & (txq->size - 1);
	      vlib_buffer_free_from_ring (vm, txq->bufs, first, txq->size,
					  txq->n_enqueued);
	    }
	  vec_free (txq->ph_bufs);
	  vec_free (txq->bufs);
	  clib_ring_free (txq->rs_slots);
	  vec_free (txq->tmp_bufs);
	  vec_free (txq->tmp_descs);
	  clib_spinlock_free (&txq->lock);
	}
      vec_free (vport->txqs);
    }

  vec_free (id->name);

  clib_error_free (id->error);
  dev_instance = id->dev_instance;
  clib_mem_free (id->mbx_resp);
  clib_memset (id, 0, sizeof (*id));
  pool_put_index (im->devices, dev_instance);
  clib_mem_free (id);
}

static u8
idpf_validate_queue_size (idpf_create_if_args_t *args)
{
  clib_error_t *error = 0;

  args->rxq_size = (args->rxq_size == 0) ? IDPF_RXQ_SZ : args->rxq_size;
  args->txq_size = (args->txq_size == 0) ? IDPF_TXQ_SZ : args->txq_size;

  if ((args->rxq_size > IDPF_QUEUE_SZ_MAX) ||
      (args->txq_size > IDPF_QUEUE_SZ_MAX))
    {
      args->rv = VNET_API_ERROR_INVALID_VALUE;
      args->error = clib_error_return (
	error, "queue size must not be greater than %u", IDPF_QUEUE_SZ_MAX);
      return 1;
    }
  if ((args->rxq_size < IDPF_QUEUE_SZ_MIN) ||
      (args->txq_size < IDPF_QUEUE_SZ_MIN))
    {
      args->rv = VNET_API_ERROR_INVALID_VALUE;
      args->error = clib_error_return (
	error, "queue size must not be smaller than %u", IDPF_QUEUE_SZ_MIN);
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
idpf_process_one_device (vlib_main_t *vm, idpf_device_t *id, int is_irq)
{
  /* placeholder */
  return;
}

static uword
idpf_process (vlib_main_t *vm, vlib_node_runtime_t *rt, vlib_frame_t *f)
{
  idpf_main_t *im = &idpf_main;
  uword *event_data = 0, event_type;
  int enabled = 0, irq;
  f64 last_run_duration = 0;
  f64 last_periodic_time = 0;
  idpf_device_t **dev_pointers = 0;
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
	case IDPF_PROCESS_EVENT_START:
	  enabled = 1;
	  break;
	case IDPF_PROCESS_EVENT_DELETE_IF:
	  for (int i = 0; i < vec_len (event_data); i++)
	    {
	      idpf_device_t *id = idpf_get_device (event_data[i]);
	      idpf_delete_if (vm, id, /* with_barrier */ 1);
	    }
	  if (pool_elts (im->devices) < 1)
	    enabled = 0;
	  break;
	case IDPF_PROCESS_EVENT_AQ_INT:
	  irq = 1;
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

      pool_foreach_index (i, im->devices)
	{
	  vec_add1 (dev_pointers, idpf_get_device (i));
	}

      vec_foreach_index (i, dev_pointers)
	{
	  idpf_process_one_device (vm, dev_pointers[i], irq);
	};

      last_run_duration = vlib_time_now (vm) - last_periodic_time;
    }
  return 0;
}

VLIB_REGISTER_NODE (idpf_process_node) = {
  .function = idpf_process,
  .type = VLIB_NODE_TYPE_PROCESS,
  .name = "idpf-process",
};

void
idpf_create_if (vlib_main_t *vm, idpf_create_if_args_t *args)
{
  vnet_main_t *vnm = vnet_get_main ();
  vnet_eth_interface_registration_t eir = {};
  idpf_main_t *im = &idpf_main;
  idpf_device_t *id, **idp;
  vlib_pci_dev_handle_t h;
  clib_error_t *error = 0;
  int i, j, v;

  /* check input args */
  if (idpf_validate_queue_size (args) != 0)
    return;

  pool_foreach (idp, im->devices)
    {
      if ((*idp)->pci_addr.as_u32 == args->addr.as_u32)
	{
	  args->rv = VNET_API_ERROR_ADDRESS_IN_USE;
	  args->error =
	    clib_error_return (error, "%U: %s", format_vlib_pci_addr,
			       &args->addr, "pci address in use");
	  return;
	}
    }

  pool_get (im->devices, idp);
  idp[0] = id =
    clib_mem_alloc_aligned (sizeof (idpf_device_t), CLIB_CACHE_LINE_BYTES);
  clib_memset (id, 0, sizeof (idpf_device_t));
  id->mbx_resp = clib_mem_alloc (IDPF_DFLT_MBX_BUF_SIZE);
  id->dev_instance = idp - im->devices;
  id->per_interface_next_index = ~0;
  id->name = vec_dup (args->name);

  if ((error =
	 vlib_pci_device_open (vm, &args->addr, idpf_pci_device_ids, &h)))
    {
      pool_put (im->devices, idp);
      clib_mem_free (id);
      args->rv = VNET_API_ERROR_INVALID_INTERFACE;
      args->error = clib_error_return (error, "pci-addr %U",
				       format_vlib_pci_addr, &args->addr);
      return;
    }
  id->pci_dev_handle = h;
  id->pci_addr = args->addr;
  id->numa_node = vlib_pci_get_numa_node (vm, h);

  vlib_pci_set_private_data (vm, h, id->dev_instance);

  if ((error = vlib_pci_bus_master_enable (vm, h)))
    goto error;

  if ((error = vlib_pci_map_region (vm, h, 0, &id->bar0)))
    goto error;

  if (vlib_pci_supports_virtual_addr_dma (vm, h))
    id->flags |= IDPF_DEVICE_F_VA_DMA;

  if ((error = idpf_device_init (vm, im, id, args)))
    goto error;

  /* create interface */
  eir.dev_class_index = idpf_device_class.index;
  eir.dev_instance = id->dev_instance;
  eir.address = id->hwaddr;
  eir.cb.flag_change = idpf_flag_change;
  id->hw_if_index = vnet_eth_register_interface (vnm, &eir);

  ethernet_set_flags (vnm, id->hw_if_index,
		      ETHERNET_INTERFACE_FLAG_DEFAULT_L3);

  vnet_sw_interface_t *sw = vnet_get_hw_sw_interface (vnm, id->hw_if_index);
  args->sw_if_index = id->sw_if_index = sw->sw_if_index;

  vnet_hw_if_set_caps (vnm, id->hw_if_index,
		       VNET_HW_IF_CAP_INT_MODE | VNET_HW_IF_CAP_MAC_FILTER |
			 VNET_HW_IF_CAP_TX_CKSUM | VNET_HW_IF_CAP_TCP_GSO);

  for (v = 0; v < id->cur_vport_nb; v++)
    {
      for (j = 0; j < id->n_rx_queues; j++)
	{
	  u32 qi;
	  i = v * id->n_rx_queues + j;
	  qi = vnet_hw_if_register_rx_queue (vnm, id->hw_if_index, i,
					     VNET_HW_IF_RXQ_THREAD_ANY);
	  id->vports[v]->rxqs[j].queue_index = qi;
	}
      for (j = 0; j < id->n_tx_queues; j++)
	{
	  u32 qi;
	  i = v * id->n_tx_queues + j;
	  qi = vnet_hw_if_register_tx_queue (vnm, id->hw_if_index, i);
	  id->vports[v]->txqs[j].queue_index = qi;
	}
    }

  for (v = 0; v < id->cur_vport_nb; v++)
    for (i = 0; i < vlib_get_n_threads (); i++)
      {
	u32 qi = id->vports[v]->txqs[i % id->n_tx_queues].queue_index;
	vnet_hw_if_tx_queue_assign_thread (vnm, qi, i);
      }

  vnet_hw_if_update_runtime_data (vnm, id->hw_if_index);

  if (pool_elts (im->devices) == 1)
    vlib_process_signal_event (vm, idpf_process_node.index,
			       IDPF_PROCESS_EVENT_START, 0);

  return;

error:
  idpf_delete_if (vm, id, /* with_barrier */ 0);
  args->rv = VNET_API_ERROR_INVALID_INTERFACE;
  args->error = clib_error_return (error, "pci-addr %U", format_vlib_pci_addr,
				   &args->addr);
  idpf_log_err (id, "error: %U", format_clib_error, args->error);
}

void *
idpf_alloc_dma_mem (vlib_main_t *vm, idpf_device_t *id, idpf_dma_mem_t *mem,
		    u64 size)
{
  void *mz = NULL;
  vlib_pci_dev_handle_t h = id->pci_dev_handle;

  if (!mem)
    return NULL;

  /* Fixme */
  mz = vlib_physmem_alloc_aligned_on_numa (vm, size, CLIB_CACHE_LINE_BYTES,
					   id->numa_node);
  if (!mz)
    return NULL;
  if (vlib_pci_map_dma (vm, h, mz))
    return NULL;

  mem->size = size;
  if (id->flags & IDPF_DEVICE_F_VA_DMA)
    {
      mem->va = mz;
      clib_memset (mem->va, 0, size);
    }
  else
    {
      mem->va = NULL;
    }
  mem->pa = idpf_dma_addr (vm, id, mz);

  return mem->va;
}

void
idpf_free_dma_mem (idpf_device_t *id, idpf_dma_mem_t *mem)
{
  mem->size = 0;
  mem->va = NULL;
  mem->pa = 0;

  clib_mem_free (mem);
}

static clib_error_t *
idpf_interface_admin_up_down (vnet_main_t *vnm, u32 hw_if_index, u32 flags)
{
  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, hw_if_index);
  idpf_device_t *id = idpf_get_device (hi->dev_instance);
  uword is_up = (flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP) != 0;

  if (id->flags & IDPF_DEVICE_F_ERROR)
    return clib_error_return (0, "device is in error state");

  if (is_up)
    {
      vnet_hw_interface_set_flags (vnm, id->hw_if_index,
				   VNET_HW_INTERFACE_FLAG_LINK_UP);
      id->flags |= IDPF_DEVICE_F_ADMIN_UP;
    }
  else
    {
      vnet_hw_interface_set_flags (vnm, id->hw_if_index, 0);
      id->flags &= ~IDPF_DEVICE_F_ADMIN_UP;
    }
  return 0;
}

VNET_DEVICE_CLASS (idpf_device_class, ) = {
  .name = "Infrastructure Data Path Function (IDPF) interface",
  .format_device_name = format_idpf_device_name,
  .admin_up_down_function = idpf_interface_admin_up_down,
};

clib_error_t *
idpf_init (vlib_main_t *vm)
{
  idpf_main_t *im = &idpf_main;
  vlib_thread_main_t *tm = vlib_get_thread_main ();

  vec_validate_aligned (im->per_thread_data, tm->n_vlib_mains - 1,
			CLIB_CACHE_LINE_BYTES);

  return 0;
}

VLIB_INIT_FUNCTION (idpf_init) = {
  .runs_after = VLIB_INITS ("pci_bus_init"),
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
