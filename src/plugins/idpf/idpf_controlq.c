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

/**
 * idpf_ctlq_alloc_desc_ring - Allocate Control Queue (CQ) rings
 * @hw: pointer to hw struct
 * @cq: pointer to the specific Control queue
 */
static int
idpf_ctlq_alloc_desc_ring (vlib_main_t *vm, idpf_device_t *id,
			   struct idpf_ctlq_info *cq)
{
  size_t size = cq->ring_size * sizeof (idpf_ctlq_desc_t);

  /* Fixme: alloc dma va */
  cq->desc_ring.va = idpf_alloc_dma_mem (vm, id, &cq->desc_ring, size);
  if (!cq->desc_ring.va)
    return IDPF_ERR_NO_MEMORY;

  return IDPF_SUCCESS;
}

/**
 * idpf_ctlq_alloc_bufs - Allocate Control Queue (CQ) buffers
 * @hw: pointer to hw struct
 * @cq: pointer to the specific Control queue
 *
 * Allocate the buffer head for all control queues, and if it's a receive
 * queue, allocate DMA buffers
 */
static int
idpf_ctlq_alloc_bufs (vlib_main_t *vm, idpf_device_t *id,
		      struct idpf_ctlq_info *cq)
{
  int i = 0;
  u16 len;

  /* Do not allocate DMA buffers for transmit queues */
  if (cq->cq_type == IDPF_CTLQ_TYPE_MAILBOX_TX)
    return IDPF_SUCCESS;

  /* We'll be allocating the buffer info memory first, then we can
   * allocate the mapped buffers for the event processing
   */
  len = cq->ring_size * sizeof (idpf_dma_mem_t *);
  cq->bi.rx_buff = (idpf_dma_mem_t **) clib_mem_alloc (len);
  if (!cq->bi.rx_buff)
    return IDPF_ERR_NO_MEMORY;
  clib_memset (cq->bi.rx_buff, 0, len);

  /* allocate the mapped buffers (except for the last one) */
  for (i = 0; i < cq->ring_size - 1; i++)
    {
      idpf_dma_mem_t *bi;
      int num = 1; /* number of idpf_dma_mem to be allocated */

      cq->bi.rx_buff[i] =
	(idpf_dma_mem_t *) clib_mem_alloc (num * sizeof (idpf_dma_mem_t));
      if (!cq->bi.rx_buff[i])
	goto unwind_alloc_cq_bufs;

      bi = cq->bi.rx_buff[i];

      bi->va = idpf_alloc_dma_mem (vm, id, bi, cq->buf_size);
      if (!bi->va)
	{
	  /* unwind will not free the failed entry */
	  clib_mem_free (cq->bi.rx_buff[i]);
	  goto unwind_alloc_cq_bufs;
	}
    }

  return IDPF_SUCCESS;

unwind_alloc_cq_bufs:
  /* don't try to free the one that failed... */
  i--;
  for (; i >= 0; i--)
    {
      idpf_free_dma_mem (id, cq->bi.rx_buff[i]);
      clib_mem_free (cq->bi.rx_buff[i]);
    }
  clib_mem_free (cq->bi.rx_buff);

  return IDPF_ERR_NO_MEMORY;
}

/**
 * idpf_ctlq_free_desc_ring - Free Control Queue (CQ) rings
 * @hw: pointer to hw struct
 * @cq: pointer to the specific Control queue
 *
 * This assumes the posted send buffers have already been cleaned
 * and de-allocated
 */
static void
idpf_ctlq_free_desc_ring (idpf_device_t *id, struct idpf_ctlq_info *cq)
{
  idpf_free_dma_mem (id, &cq->desc_ring);
}

/**
 * idpf_ctlq_free_bufs - Free CQ buffer info elements
 * @hw: pointer to hw struct
 * @cq: pointer to the specific Control queue
 *
 * Free the DMA buffers for RX queues, and DMA buffer header for both RX and TX
 * queues.  The upper layers are expected to manage freeing of TX DMA buffers
 */
static void
idpf_ctlq_free_bufs (idpf_device_t *id, struct idpf_ctlq_info *cq)
{
  void *bi;

  if (cq->cq_type == IDPF_CTLQ_TYPE_MAILBOX_RX)
    {
      int i;

      /* free DMA buffers for rx queues*/
      for (i = 0; i < cq->ring_size; i++)
	{
	  if (cq->bi.rx_buff[i])
	    {
	      idpf_free_dma_mem (id, cq->bi.rx_buff[i]);
	      /* Attention */
	      clib_mem_free (cq->bi.rx_buff[i]);
	    }
	}

      bi = (void *) cq->bi.rx_buff;
    }
  else
    {
      bi = (void *) cq->bi.tx_msg;
    }

  /* free the buffer header */
  clib_mem_free (bi);
}

/**
 * idpf_ctlq_dealloc_ring_res - Free memory allocated for control queue
 * @hw: pointer to hw struct
 * @cq: pointer to the specific Control queue
 *
 * Free the memory used by the ring, buffers and other related structures
 */
void
idpf_ctlq_dealloc_ring_res (idpf_device_t *id, struct idpf_ctlq_info *cq)
{
  /* free ring buffers and the ring itself */
  idpf_ctlq_free_bufs (id, cq);
  idpf_ctlq_free_desc_ring (id, cq);
}

/**
 * idpf_ctlq_alloc_ring_res - allocate memory for descriptor ring and bufs
 * @hw: pointer to hw struct
 * @cq: pointer to control queue struct
 *
 * Do *NOT* hold the lock when calling this as the memory allocation routines
 * called are not going to be atomic context safe
 */
int
idpf_ctlq_alloc_ring_res (vlib_main_t *vm, idpf_device_t *id,
			  struct idpf_ctlq_info *cq)
{
  int ret_code;

  /* verify input for valid configuration */
  if (!cq->ring_size || !cq->buf_size)
    return IDPF_ERR_CFG;

  /* allocate the ring memory */
  ret_code = idpf_ctlq_alloc_desc_ring (vm, id, cq);
  if (ret_code)
    return ret_code;

  /* allocate buffers in the rings */
  ret_code = idpf_ctlq_alloc_bufs (vm, id, cq);
  if (ret_code)
    goto idpf_init_cq_free_ring;

  /* success! */
  return IDPF_SUCCESS;

idpf_init_cq_free_ring:
  idpf_free_dma_mem (id, &cq->desc_ring);
  return ret_code;
}

/**
 * idpf_ctlq_setup_regs - initialize control queue registers
 * @cq: pointer to the specific control queue
 * @q_create_info: structs containing info for each queue to be initialized
 */
static void
idpf_ctlq_setup_regs (struct idpf_ctlq_info *cq,
		      idpf_ctlq_create_info_t *q_create_info)
{
  /* set head and tail registers in our local struct */
  cq->reg.head = q_create_info->reg.head;
  cq->reg.tail = q_create_info->reg.tail;
  cq->reg.len = q_create_info->reg.len;
  cq->reg.bah = q_create_info->reg.bah;
  cq->reg.bal = q_create_info->reg.bal;
  cq->reg.len_mask = q_create_info->reg.len_mask;
  cq->reg.len_ena_mask = q_create_info->reg.len_ena_mask;
  cq->reg.head_mask = q_create_info->reg.head_mask;
}

/**
 * idpf_ctlq_init_regs - Initialize control queue registers
 * @hw: pointer to hw struct
 * @cq: pointer to the specific Control queue
 * @is_rxq: true if receive control queue, false otherwise
 *
 * Initialize registers. The caller is expected to have already initialized the
 * descriptor ring memory and buffer memory
 */
static void
idpf_ctlq_init_regs (vlib_main_t *vm, idpf_device_t *id,
		     struct idpf_ctlq_info *cq, bool is_rxq)
{
  /* Update tail to post pre-allocated buffers for rx queues */
  if (is_rxq)
    idpf_reg_write (id, cq->reg.tail, (u32) (cq->ring_size - 1));

  /* For non-Mailbox control queues only TAIL need to be set */
  if (cq->q_id != -1)
    return;

  /* Clear Head for both send or receive */
  idpf_reg_write (id, cq->reg.head, 0);

  /* set starting point */
  idpf_reg_write (id, cq->reg.bal, IDPF_LO_DWORD (cq->desc_ring.pa));
  idpf_reg_write (id, cq->reg.bah, IDPF_HI_DWORD (cq->desc_ring.pa));
  idpf_reg_write (id, cq->reg.len, (cq->ring_size | cq->reg.len_ena_mask));
}

/**
 * idpf_ctlq_init_rxq_bufs - populate receive queue descriptors with buf
 * @cq: pointer to the specific Control queue
 *
 * Record the address of the receive queue DMA buffers in the descriptors.
 * The buffers must have been previously allocated.
 */
static void
idpf_ctlq_init_rxq_bufs (struct idpf_ctlq_info *cq)
{
  int i = 0;

  for (i = 0; i < cq->ring_size; i++)
    {
      idpf_ctlq_desc_t *desc = IDPF_CTLQ_DESC (cq, i);
      idpf_dma_mem_t *bi = cq->bi.rx_buff[i];

      /* No buffer to post to descriptor, continue */
      if (!bi)
	continue;

      desc->flags = IDPF_CTLQ_FLAG_BUF | IDPF_CTLQ_FLAG_RD;
      desc->opcode = 0;
      desc->datalen = (u16) bi->size;
      desc->ret_val = 0;
      desc->cookie_high = 0;
      desc->cookie_low = 0;
      desc->params.indirect.addr_high = IDPF_HI_DWORD (bi->pa);
      desc->params.indirect.addr_low = IDPF_LO_DWORD (bi->pa);
      desc->params.indirect.param0 = 0;
      desc->params.indirect.param1 = 0;
    }
}

/**
 * idpf_ctlq_shutdown - shutdown the CQ
 * @hw: pointer to hw struct
 * @cq: pointer to the specific Control queue
 *
 * The main shutdown routine for any controq queue
 */
static void
idpf_ctlq_shutdown (idpf_device_t *id, struct idpf_ctlq_info *cq)
{
  clib_spinlock_init (&cq->cq_lock);

  if (!cq->ring_size)
    goto shutdown_sq_out;

  /* free ring buffers and the ring itself */
  idpf_ctlq_dealloc_ring_res (id, cq);

  /* Set ring_size to 0 to indicate uninitialized queue */
  cq->ring_size = 0;

shutdown_sq_out:
  clib_spinlock_unlock (&cq->cq_lock);
  clib_spinlock_free (&cq->cq_lock);
}

/**
 * idpf_ctlq_add - add one control queue
 * @hw: pointer to hardware struct
 * @qinfo: info for queue to be created
 * @cq_out: (output) double pointer to control queue to be created
 *
 * Allocate and initialize a control queue and add it to the control queue
 * list. The cq parameter will be allocated/initialized and passed back to the
 * caller if no errors occur.
 *
 * Note: idpf_ctlq_init must be called prior to any calls to idpf_ctlq_add
 */
int
idpf_ctlq_add (vlib_main_t *vm, idpf_device_t *id,
	       idpf_ctlq_create_info_t *qinfo, struct idpf_ctlq_info **cq_out)
{
  bool is_rxq = false;
  int status = IDPF_SUCCESS;

  if (!qinfo->len || !qinfo->buf_size ||
      qinfo->len > IDPF_CTLQ_MAX_RING_SIZE ||
      qinfo->buf_size > IDPF_CTLQ_MAX_BUF_LEN)
    return IDPF_ERR_CFG;

  /* Fixme: memory allocation */
  *cq_out = vlib_physmem_alloc_aligned_on_numa (
    vm, sizeof (struct idpf_ctlq_info), CLIB_CACHE_LINE_BYTES, id->numa_node);
  if (!(*cq_out))
    return IDPF_ERR_NO_MEMORY;

  if ((vlib_pci_map_dma (vm, id->pci_dev_handle, *cq_out)))
    {
      status = IDPF_ERR_NO_MEMORY;
      goto init_free_q;
    }

  (*cq_out)->cq_type = qinfo->type;
  (*cq_out)->q_id = qinfo->id;
  (*cq_out)->buf_size = qinfo->buf_size;
  (*cq_out)->ring_size = qinfo->len;

  (*cq_out)->next_to_use = 0;
  (*cq_out)->next_to_clean = 0;
  (*cq_out)->next_to_post = (*cq_out)->ring_size - 1;

  switch (qinfo->type)
    {
    case IDPF_CTLQ_TYPE_MAILBOX_RX:
      is_rxq = true;
    case IDPF_CTLQ_TYPE_MAILBOX_TX:
      status = idpf_ctlq_alloc_ring_res (vm, id, *cq_out);
      break;
    default:
      status = IDPF_ERR_PARAM;
      break;
    }

  if (status)
    goto init_free_q;

  if (is_rxq)
    {
      idpf_ctlq_init_rxq_bufs (*cq_out);
    }
  else
    {
      /* Allocate the array of msg pointers for TX queues */
      (*cq_out)->bi.tx_msg = (idpf_ctlq_msg_t **) clib_mem_alloc (
	qinfo->len * sizeof (idpf_ctlq_msg_t *));
      if (!(*cq_out)->bi.tx_msg)
	{
	  status = IDPF_ERR_NO_MEMORY;
	  goto init_dealloc_q_mem;
	}
    }

  idpf_ctlq_setup_regs (*cq_out, qinfo);

  idpf_ctlq_init_regs (vm, id, *cq_out, is_rxq);

  /* Fixeme: lock issue */
  clib_spinlock_init (&(*cq_out)->cq_lock);

  LIST_INSERT_HEAD (&id->cq_list_head, (*cq_out), cq_list);

  return status;

init_dealloc_q_mem:
  /* free ring buffers and the ring itself */
  idpf_ctlq_dealloc_ring_res (id, *cq_out);
init_free_q:
  clib_mem_free (*cq_out);

  return status;
}

/**
 * idpf_ctlq_remove - deallocate and remove specified control queue
 * @hw: pointer to hardware struct
 * @cq: pointer to control queue to be removed
 */
void
idpf_ctlq_remove (idpf_device_t *id, struct idpf_ctlq_info *cq)
{
  LIST_REMOVE (cq, cq_list);
  idpf_ctlq_shutdown (id, cq);
  clib_mem_free (cq);
}

/**
 * idpf_ctlq_init - main initialization routine for all control queues
 * @hw: pointer to hardware struct
 * @num_q: number of queues to initialize
 * @q_info: array of structs containing info for each queue to be initialized
 *
 * This initializes any number and any type of control queues. This is an all
 * or nothing routine; if one fails, all previously allocated queues will be
 * destroyed. This must be called prior to using the individual add/remove
 * APIs.
 */
int
idpf_ctlq_init (vlib_main_t *vm, idpf_device_t *id, u8 num_q,
		idpf_ctlq_create_info_t *q_info)
{
  struct idpf_ctlq_info *cq = NULL;
  int ret_code = IDPF_SUCCESS;
  int i = 0;

  LIST_INIT (&id->cq_list_head);

  for (i = 0; i < num_q; i++)
    {
      idpf_ctlq_create_info_t *qinfo = q_info + i;

      ret_code = idpf_ctlq_add (vm, id, qinfo, &cq);
      if (ret_code)
	goto init_destroy_qs;
    }

  return ret_code;

init_destroy_qs:
  LIST_FOR_EACH_ENTRY_SAFE (cq, NULL, &id->cq_list_head, struct idpf_ctlq_info,
			    cq_list)
  {
    idpf_ctlq_remove (id, cq);
  }

  return ret_code;
}

/**
 * idpf_ctlq_deinit - destroy all control queues
 * @hw: pointer to hw struct
 */
void
idpf_ctlq_deinit (idpf_device_t *id)
{
  struct idpf_ctlq_info *cq = NULL;

  LIST_FOR_EACH_ENTRY_SAFE (cq, NULL, &id->cq_list_head, struct idpf_ctlq_info,
			    cq_list)
  {
    idpf_ctlq_remove (id, cq);
  }

  return;
}

/**
 * idpf_ctlq_send - send command to Control Queue (CTQ)
 * @id: pointer to device struct
 * @cq: handle to control queue struct to send on
 * @num_q_msg: number of messages to send on control queue
 * @q_msg: pointer to array of queue messages to be sent
 *
 * The caller is expected to allocate DMAable buffers and pass them to the
 * send routine via the q_msg struct / control queue specific data struct.
 * The control queue will hold a reference to each send message until
 * the completion for that message has been cleaned.
 */
int
idpf_ctlq_send (idpf_device_t *id, struct idpf_ctlq_info *cq, u16 num_q_msg,
		idpf_ctlq_msg_t q_msg[])
{
  idpf_ctlq_desc_t *desc;
  int num_desc_avail = 0;
  int status = IDPF_SUCCESS;
  int i = 0;

  if (!cq || !cq->ring_size)
    return -ENOBUFS;

  clib_spinlock_lock (&cq->cq_lock);

  /* Ensure there are enough descriptors to send all messages */
  num_desc_avail = IDPF_CTLQ_DESC_UNUSED (cq);
  if (num_desc_avail == 0 || num_desc_avail < num_q_msg)
    {
      status = -ENOSPC;
      goto sq_send_command_out;
    }

  for (i = 0; i < num_q_msg; i++)
    {
      idpf_ctlq_msg_t *msg = &q_msg[i];
      u64 msg_cookie;

      desc = IDPF_CTLQ_DESC (cq, cq->next_to_use);

      /* Pay attention to CPU_TO_LE16 */
      desc->opcode = msg->opcode;
      desc->pfid_vfid = msg->func_id;

      msg_cookie = msg->cookie.cookie;
      desc->cookie_high = IDPF_HI_DWORD (msg_cookie);
      desc->cookie_low = IDPF_LO_DWORD (msg_cookie);

      desc->flags = (msg->host_id & IDPF_HOST_ID_MASK)
		    << IDPF_CTLQ_FLAG_HOST_ID_S;
      if (msg->data_len)
	{
	  idpf_dma_mem_t *buff = msg->ctx.indirect.payload;

	  desc->datalen |= msg->data_len;
	  desc->flags |= IDPF_CTLQ_FLAG_BUF;
	  desc->flags |= IDPF_CTLQ_FLAG_RD;

	  /* Update the address values in the desc with the pa
	   * value for respective buffer
	   */
	  desc->params.indirect.addr_high = IDPF_HI_DWORD (buff->pa);
	  desc->params.indirect.addr_low = IDPF_LO_DWORD (buff->pa);

	  clib_memcpy (&desc->params, msg->ctx.indirect.context,
		       IDPF_INDIRECT_CTX_SIZE);
	}
      else
	{
	  clib_memcpy (&desc->params, msg->ctx.direct, IDPF_DIRECT_CTX_SIZE);
	}

      /* Store buffer info */
      cq->bi.tx_msg[cq->next_to_use] = msg;

      (cq->next_to_use)++;
      if (cq->next_to_use == cq->ring_size)
	cq->next_to_use = 0;
    }

  /* Force memory write to complete before letting hardware
   * know that there are new descriptors to fetch.
   */
  CLIB_MEMORY_BARRIER ();

  idpf_reg_write (id, cq->reg.tail, cq->next_to_use);

sq_send_command_out:
  clib_spinlock_unlock (&cq->cq_lock);

  return status;
}

/**
 * idpf_ctlq_clean_sq - reclaim send descriptors on HW write back for the
 * requested queue
 * @cq: pointer to the specific Control queue
 * @clean_count: (input|output) number of descriptors to clean as input, and
 * number of descriptors actually cleaned as output
 * @msg_status: (output) pointer to msg pointer array to be populated; needs
 * to be allocated by caller
 *
 * Returns an array of message pointers associated with the cleaned
 * descriptors. The pointers are to the original ctlq_msgs sent on the cleaned
 * descriptors.  The status will be returned for each; any messages that failed
 * to send will have a non-zero status. The caller is expected to free original
 * ctlq_msgs and free or reuse the DMA buffers.
 */
int
idpf_ctlq_clean_sq (struct idpf_ctlq_info *cq, u16 *clean_count,
		    idpf_ctlq_msg_t *msg_status[])
{
  idpf_ctlq_desc_t *desc;
  u16 i = 0, num_to_clean;
  u16 ntc, desc_err;
  int ret = IDPF_SUCCESS;

  if (!cq || !cq->ring_size)
    return IDPF_ERR_CTLQ_EMPTY;

  if (*clean_count == 0)
    return IDPF_SUCCESS;
  if (*clean_count > cq->ring_size)
    return IDPF_ERR_PARAM;

  /* Fixme rte func */
  clib_spinlock_lock (&cq->cq_lock);

  ntc = cq->next_to_clean;

  num_to_clean = *clean_count;

  for (i = 0; i < num_to_clean; i++)
    {
      /* Fetch next descriptor and check if marked as done */
      desc = IDPF_CTLQ_DESC (cq, ntc);
      if (!(desc->flags & IDPF_CTLQ_FLAG_DD))
	break;

      desc_err = desc->ret_val;
      if (desc_err)
	{
	  /* strip off FW internal code */
	  desc_err &= 0xff;
	}

      msg_status[i] = cq->bi.tx_msg[ntc];
      msg_status[i]->status = desc_err;

      cq->bi.tx_msg[ntc] = NULL;

      /* Zero out any stale data */
      clib_memset (desc, 0, sizeof (*desc));

      ntc++;
      if (ntc == cq->ring_size)
	ntc = 0;
    }

  cq->next_to_clean = ntc;

  clib_spinlock_unlock (&cq->cq_lock);

  /* Return number of descriptors actually cleaned */
  *clean_count = i;

  return ret;
}

/**
 * idpf_ctlq_post_rx_buffs - post buffers to descriptor ring
 * @hw: pointer to hw struct
 * @cq: pointer to control queue handle
 * @buff_count: (input|output) input is number of buffers caller is trying to
 * return; output is number of buffers that were not posted
 * @buffs: array of pointers to dma mem structs to be given to hardware
 *
 * Caller uses this function to return DMA buffers to the descriptor ring after
 * consuming them; buff_count will be the number of buffers.
 *
 * Note: this function needs to be called after a receive call even
 * if there are no DMA buffers to be returned, i.e. buff_count = 0,
 * buffs = NULL to support direct commands
 */
int
idpf_ctlq_post_rx_buffs (idpf_device_t *id, struct idpf_ctlq_info *cq,
			 u16 *buff_count, idpf_dma_mem_t **buffs)
{
  idpf_ctlq_desc_t *desc;
  u16 ntp = cq->next_to_post;
  bool buffs_avail = false;
  u16 tbp = ntp + 1;
  int status = IDPF_SUCCESS;
  int i = 0;

  if (*buff_count > cq->ring_size)
    return IDPF_ERR_PARAM;

  if (*buff_count > 0)
    buffs_avail = true;

  clib_spinlock_lock (&cq->cq_lock);

  if (tbp >= cq->ring_size)
    tbp = 0;

  if (tbp == cq->next_to_clean)
    /* Nothing to do */
    goto post_buffs_out;

  /* Post buffers for as many as provided or up until the last one used */
  while (ntp != cq->next_to_clean)
    {
      desc = IDPF_CTLQ_DESC (cq, ntp);

      if (cq->bi.rx_buff[ntp])
	goto fill_desc;
      if (!buffs_avail)
	{
	  /* If the caller hasn't given us any buffers or
	   * there are none left, search the ring itself
	   * for an available buffer to move to this
	   * entry starting at the next entry in the ring
	   */
	  tbp = ntp + 1;

	  /* Wrap ring if necessary */
	  if (tbp >= cq->ring_size)
	    tbp = 0;

	  while (tbp != cq->next_to_clean)
	    {
	      if (cq->bi.rx_buff[tbp])
		{
		  cq->bi.rx_buff[ntp] = cq->bi.rx_buff[tbp];
		  cq->bi.rx_buff[tbp] = NULL;

		  /* Found a buffer, no need to
		   * search anymore
		   */
		  break;
		}

	      /* Wrap ring if necessary */
	      tbp++;
	      if (tbp >= cq->ring_size)
		tbp = 0;
	    }

	  if (tbp == cq->next_to_clean)
	    goto post_buffs_out;
	}
      else
	{
	  /* Give back pointer to DMA buffer */
	  cq->bi.rx_buff[ntp] = buffs[i];
	  i++;

	  if (i >= *buff_count)
	    buffs_avail = false;
	}

    fill_desc:
      desc->flags = IDPF_CTLQ_FLAG_BUF | IDPF_CTLQ_FLAG_RD;

      /* Post buffers to descriptor */
      desc->datalen = cq->bi.rx_buff[ntp]->size;
      desc->params.indirect.addr_high =
	IDPF_HI_DWORD (cq->bi.rx_buff[ntp]->pa);
      desc->params.indirect.addr_low = IDPF_LO_DWORD (cq->bi.rx_buff[ntp]->pa);

      ntp++;
      if (ntp == cq->ring_size)
	ntp = 0;
    }

post_buffs_out:
  /* Only update tail if buffers were actually posted */
  if (cq->next_to_post != ntp)
    {
      if (ntp)
	/* Update next_to_post to ntp - 1 since current ntp
	 * will not have a buffer
	 */
	cq->next_to_post = ntp - 1;
      else
	/* Wrap to end of end ring since current ntp is 0 */
	cq->next_to_post = cq->ring_size - 1;

      idpf_reg_write (id, cq->reg.tail, cq->next_to_post);
    }

  clib_spinlock_unlock (&cq->cq_lock);

  /* return the number of buffers that were not posted */
  *buff_count = *buff_count - i;

  return status;
}

/**
 * idpf_ctlq_recv - receive control queue message call back
 * @cq: pointer to control queue handle to receive on
 * @num_q_msg: (input|output) input number of messages that should be received;
 * output number of messages actually received
 * @q_msg: (output) array of received control queue messages on this q;
 * needs to be pre-allocated by caller for as many messages as requested
 *
 * Called by interrupt handler or polling mechanism. Caller is expected
 * to free buffers
 */
int
idpf_ctlq_recv (struct idpf_ctlq_info *cq, u16 *num_q_msg,
		idpf_ctlq_msg_t *q_msg)
{
  u16 num_to_clean, ntc, ret_val, flags;
  idpf_ctlq_desc_t *desc;
  int ret_code = 0;
  u16 i = 0;

  if (!cq || !cq->ring_size)
    return -ENOBUFS;

  if (*num_q_msg == 0)
    return 0;
  else if (*num_q_msg > cq->ring_size)
    return -EINVAL;

  /* Fixme: take the lock before we start messing with the ring */
  clib_spinlock_lock (&cq->cq_lock);

  ntc = cq->next_to_clean;

  num_to_clean = *num_q_msg;

  for (i = 0; i < num_to_clean; i++)
    {
      u64 msg_cookie;

      /* Fetch next descriptor and check if marked as done */
      desc = IDPF_CTLQ_DESC (cq, ntc);
      flags = desc->flags;

      if (!(flags & IDPF_CTLQ_FLAG_DD))
	break;

      ret_val = desc->ret_val;

      q_msg[i].vmvf_type =
	(flags & (IDPF_CTLQ_FLAG_FTYPE_VM | IDPF_CTLQ_FLAG_FTYPE_PF)) >>
	IDPF_CTLQ_FLAG_FTYPE_S;

      if (flags & IDPF_CTLQ_FLAG_ERR)
	ret_code = IDPF_ERR_CTLQ_ERROR;

      msg_cookie = (u64) desc->cookie_high << 32;
      msg_cookie |= (u64) desc->cookie_low;
      clib_memcpy_fast (&q_msg[i].cookie, &msg_cookie, sizeof (u64));

      q_msg[i].opcode = desc->opcode;
      q_msg[i].data_len = desc->datalen;
      q_msg[i].status = ret_val;

      if (desc->datalen)
	{
	  clib_memcpy_fast (q_msg[i].ctx.indirect.context,
			    &desc->params.indirect, IDPF_INDIRECT_CTX_SIZE);

	  /* Assign pointer to dma buffer to ctlq_msg array
	   * to be given to upper layer
	   */
	  q_msg[i].ctx.indirect.payload = cq->bi.rx_buff[ntc];

	  /* Zero out pointer to DMA buffer info;
	   * will be repopulated by post buffers API
	   */
	  cq->bi.rx_buff[ntc] = NULL;
	}
      else
	{
	  clib_memcpy_fast (q_msg[i].ctx.direct, desc->params.raw,
			    IDPF_DIRECT_CTX_SIZE);
	}

      /* Zero out stale data in descriptor */
      clib_memset (desc, 0, sizeof (idpf_ctlq_desc_t));

      ntc++;
      if (ntc == cq->ring_size)
	ntc = 0;
    };

  cq->next_to_clean = ntc;

  /* Fixme */
  clib_spinlock_unlock (&cq->cq_lock);

  *num_q_msg = i;
  if (*num_q_msg == 0)
    ret_code = -ENOMSG;

  return ret_code;
}
