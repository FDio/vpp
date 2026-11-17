/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Damjan Marion
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <errno.h>
#include <fcntl.h>
#include <common.h>
#include <mlx5.h>
#include <mlx5_ifc.h>

VLIB_REGISTER_LOG_CLASS (mlx5_log, static) = {
  .class_name = "mlx5",
  .subclass_name = "queue",
};

enum
{
  MLX5_CMD_OP_ALLOC_Q_COUNTER = 0x771,
  MLX5_CMD_OP_MODIFY_RQ = 0x909,
  MLX5_RQC_STATE_RDY = 0x1,
  MLX5_MODIFY_RQ_IN_MODIFY_BITMASK_RQ_COUNTER_SET_ID = 1ULL << 3,
};

static void
mlx5_rxq_q_counter_alloc (vnet_dev_rx_queue_t *rxq)
{
  vnet_dev_t *dev = rxq->port->dev;
  mlx5_dev_t *rd = vnet_dev_get_data (dev);
  mlx5_rxq_t *mq = vnet_dev_get_rx_queue_data (rxq);
  u32 in[DEVX_ST_SZ_DW (alloc_q_counter_in)] = {};
  u32 out[DEVX_ST_SZ_DW (alloc_q_counter_out)] = {};

  DEVX_SET (alloc_q_counter_in, in, opcode, MLX5_CMD_OP_ALLOC_Q_COUNTER);
  mq->q_counter_obj = mlx5dv_devx_obj_create (rd->ctx, in, sizeof (in), out, sizeof (out));
  if (mq->q_counter_obj == 0)
    {
      log_notice (dev, "rxq %u q-counter not available (errno %d), out-of-buffer drops not counted",
		  rxq->queue_id, errno);
      return;
    }

  mq->q_counter_set_id = DEVX_GET (alloc_q_counter_out, out, counter_set_id);
  log_debug (dev, "rxq %u q-counter set_id %u", rxq->queue_id, mq->q_counter_set_id);
}

static void
mlx5_rxq_q_counter_free (vnet_dev_rx_queue_t *rxq)
{
  mlx5_rxq_t *mq = vnet_dev_get_rx_queue_data (rxq);

  if (mq->q_counter_obj)
    mlx5dv_devx_obj_destroy (mq->q_counter_obj);
  mq->q_counter_obj = 0;
  mq->q_counter_valid = 0;
  mq->q_counter_query_failed = 0;
}

static void
mlx5_rxq_q_counter_attach (vnet_dev_rx_queue_t *rxq)
{
  vnet_dev_t *dev = rxq->port->dev;
  mlx5_rxq_t *mq = vnet_dev_get_rx_queue_data (rxq);
  u32 in[DEVX_ST_SZ_DW (modify_rq_in)] = {};
  u32 out[DEVX_ST_SZ_DW (modify_rq_out)] = {};
  int rv_ibv;

  mq->q_counter_valid = 0;
  if (mq->q_counter_obj == 0)
    return;

  DEVX_SET (modify_rq_in, in, opcode, MLX5_CMD_OP_MODIFY_RQ);
  DEVX_SET (modify_rq_in, in, rq_state, MLX5_RQC_STATE_RDY);
  DEVX_SET64 (modify_rq_in, in, modify_bitmask, MLX5_MODIFY_RQ_IN_MODIFY_BITMASK_RQ_COUNTER_SET_ID);
  DEVX_SET (modify_rq_in, in, ctx.state, MLX5_RQC_STATE_RDY);
  DEVX_SET (modify_rq_in, in, ctx.counter_set_id, mq->q_counter_set_id);

  DEVX_SET (modify_rq_in, in, rqn, mq->ibv_wq->wq_num);
  rv_ibv = mlx5dv_devx_wq_modify (mq->ibv_wq, in, sizeof (in), out, sizeof (out));

  if (rv_ibv || DEVX_GET (modify_rq_out, out, status))
    {
      log_notice (dev, "rxq %u q-counter attach failed rv %d status 0x%x syndrome 0x%x",
		  rxq->queue_id, rv_ibv, DEVX_GET (modify_rq_out, out, status),
		  DEVX_GET (modify_rq_out, out, syndrome));
      return;
    }

  mq->q_counter_valid = 1;
}

static void
mlx5_cq_sync (struct mlx5_cqe64 *cqes, u32 *dbrec, u32 *cq_idx, u32 cq_size, u8 log2_cq_size)
{
  u32 mask = cq_size - 1;
  u32 idx = *cq_idx;

  for (u32 n = 0; n < cq_size; n++)
    {
      struct mlx5_cqe64 *cqe = cqes + (idx & mask);
      u8 op_own = cqe->op_own;

      if ((op_own & MLX5_CQE_OWNER_MASK) != ((idx >> log2_cq_size) & MLX5_CQE_OWNER_MASK) ||
	  mlx5dv_get_cqe_opcode (cqe) == MLX5_CQE_INVALID)
	break;

      if (mlx5dv_get_cqe_format (cqe) == MLX5_CQE_FORMAT_COMPRESSED)
	idx += clib_net_to_host_u32 (cqe->byte_cnt);
      else
	idx++;
    }

  for (u32 i = 0; i < cq_size; i++)
    cqes[i].op_own = 0xff;

  *cq_idx = idx;
  __atomic_store_n (dbrec, clib_host_to_net_u32 (idx & MLX5_CQ_DB_CI_MASK), __ATOMIC_RELEASE);
}

void
mlx5_rxq_cq_sync (vnet_dev_rx_queue_t *rxq)
{
  mlx5_rxq_t *mq = vnet_dev_get_rx_queue_data (rxq);

  mlx5_cq_sync (mq->dv_cq_cqes, mq->dv_cq_dbrec, &mq->dv_cq_idx, mq->dv_cq_size, mq->dv_cq_log2);
  mq->mini_cqe_skip = 0;
}

void
mlx5_txq_cq_sync (vnet_dev_tx_queue_t *txq)
{
  mlx5_txq_t *tq = vnet_dev_get_tx_queue_data (txq);

  mlx5_cq_sync (tq->dv_cq_cqes, tq->dv_cq_dbrec, &tq->dv_cq_idx, tq->dv_cq_size, tq->dv_cq_log2);
}

void
mlx5_txq_recover (vlib_main_t *vm, vnet_dev_tx_queue_t *txq, u8 syndrome)
{
  vnet_dev_t *dev = txq->port->dev;
  mlx5_txq_t *tq = vnet_dev_get_tx_queue_data (txq);
  int rv_ibv;

  log_err (dev, "txq %u completion error syndrome 0x%x, resetting queue", txq->queue_id, syndrome);

  rdma_qp_stop (tq->ibv_qp);
  mlx5_txq_cq_sync (txq);
  mlx5_txq_free_bufs (vm, tq, tq->buf_tail);
  tq->head = 0;
  tq->tail = 0;
  tq->buf_head = tq->buf_tail = 0;
  __atomic_store_n (&tq->dv_sq_dbrec[MLX5_SND_DBR], 0, __ATOMIC_RELEASE);

  rv_ibv = rdma_qp_start (tq->ibv_qp, txq->port->port_id, 0);
  if (rv_ibv)
    log_err (dev, "txq %u restart failed rv %d", txq->queue_id, rv_ibv);
}

vnet_dev_rv_t
mlx5_rxq_irq_enable (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq)
{
  vnet_dev_t *dev = rxq->port->dev;
  mlx5_rxq_t *mq = vnet_dev_get_rx_queue_data (rxq);
  vnet_dev_rv_t rv = rdma_rxq_irq_enable (vm, &mq->irq);

  if (rv != VNET_DEV_OK)
    log_err (dev, "rxq %u irq enable failed", rxq->queue_id);
  return rv;
}

void
mlx5_rxq_irq_disable (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq)
{
  mlx5_rxq_t *mq = vnet_dev_get_rx_queue_data (rxq);

  rdma_rxq_irq_disable (vm, &mq->irq);
}

static void
mlx5_rxq_free_buffers (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq)
{
  mlx5_rxq_t *mq = vnet_dev_get_rx_queue_data (rxq);
  u32 mask = rxq->size - 1;
  u16 n = mq->tail - mq->head;

  if (n && mq->n_ds_per_wqe > 1)
    {
      u32 extras_per = mq->n_ds_per_wqe - 1;

      for (u16 i = mq->head; i != mq->tail; i++)
	vlib_buffer_free (vm, mq->second_bufs + (i & mask) * extras_per, extras_per);
    }

  if (n)
    vlib_buffer_free_from_ring (vm, mq->buffers, mq->head & mask, rxq->size, n);

  mq->head = 0;
  mq->tail = 0;
  mq->striding_wqe_tail = 0;
}

void
mlx5_rxq_wq_destroy (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq)
{
  vnet_dev_t *dev = rxq->port->dev;
  mlx5_rxq_t *mq = vnet_dev_get_rx_queue_data (rxq);
  int rv_ibv;

  if (mq->ibv_wq == 0)
    return;

  rv_ibv = ibv_destroy_wq (mq->ibv_wq);
  if (rv_ibv)
    log_err (dev, "rxq %u ibv_destroy_wq failed rv %d", rxq->queue_id, rv_ibv);
  mq->ibv_wq = 0;
  mq->dv_sq_wqes = 0;
  mq->dv_sq_dbrec = 0;
  mq->q_counter_valid = 0;

  mlx5_rxq_cq_sync (rxq);
  mlx5_rxq_free_buffers (vm, rxq);
}

vnet_dev_rv_t
mlx5_rxq_wq_create (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq)
{
  vnet_dev_t *dev = rxq->port->dev;
  mlx5_dev_t *rd = vnet_dev_get_data (dev);
  mlx5_rxq_t *mq = vnet_dev_get_rx_queue_data (rxq);
  mlx5_port_t *mp = vnet_dev_get_port_data (rxq->port);
  u32 data_sz = vnet_dev_get_rx_queue_buffer_data_size (vm, rxq);
  struct ibv_wq_init_attr wqia = {
    .wq_type = IBV_WQT_RQ,
    .pd = rd->pd,
    .cq = mq->ibv_cq,
  };
  struct ibv_wq_attr wqa = {
    .attr_mask = IBV_WQ_ATTR_STATE,
    .wq_state = IBV_WQS_RDY,
  };
  struct mlx5dv_rwq dv_rwq = {};
  struct mlx5dv_obj obj = {
    .rwq = {
      .out = &dv_rwq,
    },
  };
  u64 qw0;
  u32 wqe_cnt, wqe_sz;
  int rv_ibv;

  mq->single_buffer = rxq->port->max_rx_frame_size <= data_sz;
  mq->striding = mp->striding_rq && !mq->single_buffer;
  mq->buf_sz = mq->striding ? 1 << min_log2 (data_sz) : data_sz;
  qw0 = clib_host_to_net_u32 (mq->buf_sz) | (u64) clib_host_to_net_u32 (rd->lkey) << 32;

  if (mq->striding)
    {
      struct mlx5dv_wq_init_attr dv_wqia = {
	.comp_mask = MLX5DV_WQ_INIT_ATTR_MASK_STRIDING_RQ,
	.striding_rq_attrs = {
	  .single_wqe_log_num_of_strides = RDMA_RXQ_MAX_CHAIN_LOG_SZ,
	  .single_stride_log_num_of_bytes = min_log2 (mq->buf_sz),
	},
      };

      mq->log_stride_per_wqe = RDMA_RXQ_MAX_CHAIN_LOG_SZ;
      mq->log_wqe_sz = RDMA_RXQ_MAX_CHAIN_LOG_SZ + 1;
      mq->n_ds_per_wqe = 1;
      wqia.max_sge = 1 << mq->log_stride_per_wqe;
      wqia.max_wr = rxq->size >> mq->log_stride_per_wqe;
      mq->ibv_wq = mlx5dv_create_wq (rd->ctx, &wqia, &dv_wqia);
    }
  else
    {
      u32 n_ds = (rxq->port->max_rx_frame_size + mq->buf_sz - 1) / mq->buf_sz;

      n_ds = clib_clamp (n_ds, 1, RDMA_RXQ_LEGACY_MODE_MAX_CHAIN_SZ);
      mq->n_ds_per_wqe = n_ds;
      mq->log_wqe_sz = max_log2 (n_ds);
      mq->log_stride_per_wqe = 0;
      wqia.max_sge = 1 << mq->log_wqe_sz;
      wqia.max_wr = rxq->size;
      mq->ibv_wq = ibv_create_wq (rd->ctx, &wqia);
    }

  if (mq->ibv_wq == 0)
    {
      log_err (dev, "rxq %u create_wq failed errno %d", rxq->queue_id, errno);
      return VNET_DEV_ERR_INIT_FAILED;
    }

  obj.rwq.in = mq->ibv_wq;
  rv_ibv = mlx5dv_init_obj (&obj, MLX5DV_OBJ_RWQ);
  wqe_cnt = rxq->size >> mq->log_stride_per_wqe;
  wqe_sz = 1 << mq->log_wqe_sz;
  if (rv_ibv || dv_rwq.wqe_cnt != wqe_cnt || dv_rwq.stride != sizeof (mlx5dv_wqe_ds_t) * wqe_sz ||
      (uword) dv_rwq.buf % sizeof (mlx5dv_wqe_ds_t))
    {
      log_err (dev, "rxq %u unexpected wq layout: rv %d wqe_cnt %u stride %u", rxq->queue_id,
	       rv_ibv, dv_rwq.wqe_cnt, dv_rwq.stride);
      mlx5_rxq_wq_destroy (vm, rxq);
      return VNET_DEV_ERR_UNSUPPORTED_DEVICE;
    }

  mq->dv_sq_wqes = dv_rwq.buf;
  mq->dv_sq_dbrec = dv_rwq.dbrec;
  mq->wqe_cnt = wqe_cnt;

  if (mq->striding)
    {
      for (u32 i = 0; i < wqe_cnt; i++)
	{
	  mlx5dv_wqe_ds_t *wqe = mq->dv_sq_wqes + i * wqe_sz;
	  mlx5dv_wqe_srq_next_t *nseg = (mlx5dv_wqe_srq_next_t *) wqe;

	  for (u32 j = 1; j < wqe_sz; j++)
	    wqe[j].dsz_and_lkey = j <= (1 << mq->log_stride_per_wqe) ?
				    qw0 :
				    (u64) clib_host_to_net_u32 (rd->lkey) << 32;
	  nseg->next_wqe_index = clib_host_to_net_u16 ((i + 1) & (wqe_cnt - 1));
	}
    }
  else
    {
      u64 qw0_nullseg = (u64) clib_host_to_net_u32 (MLX5_INVALID_LKEY) << 32;

      for (u32 i = 0; i < wqe_cnt * wqe_sz; i++)
	mq->dv_sq_wqes[i].dsz_and_lkey = (i & (wqe_sz - 1)) < mq->n_ds_per_wqe ? qw0 : qw0_nullseg;
    }

  mq->head = 0;
  mq->tail = 0;
  mq->striding_wqe_tail = 0;
  mq->dv_sq_dbrec[MLX5_RCV_DBR] = 0;

  rv_ibv = ibv_modify_wq (mq->ibv_wq, &wqa);
  if (rv_ibv)
    {
      log_err (dev, "rxq %u ibv_modify_wq rdy failed rv %d", rxq->queue_id, rv_ibv);
      mlx5_rxq_wq_destroy (vm, rxq);
      return VNET_DEV_ERR_INIT_FAILED;
    }

  mlx5_rxq_q_counter_attach (rxq);
  return VNET_DEV_OK;
}

void
mlx5_rxq_free (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq)
{
  vnet_dev_t *dev = rxq->port->dev;
  mlx5_rxq_t *mq = vnet_dev_get_rx_queue_data (rxq);
  int rv_ibv;

  log_debug (dev, "mlx5_rxq_free: queue %u", rxq->queue_id);

  ASSERT (rxq->started == 0);
  mlx5_rxq_irq_disable (vm, rxq);
  mlx5_rxq_wq_destroy (vm, rxq);
  mlx5_rxq_q_counter_free (rxq);

  if (mq->ibv_cq)
    {
      rv_ibv = ibv_destroy_cq (mq->ibv_cq);
      if (rv_ibv)
	log_err (dev, "ibv_destroy_cq failed rv %d", rv_ibv);
      mq->ibv_cq = 0;
    }

  if (mq->irq.ibv_comp_ch)
    {
      rv_ibv = ibv_destroy_comp_channel (mq->irq.ibv_comp_ch);
      if (rv_ibv)
	log_err (dev, "ibv_destroy_comp_channel failed rv %d", rv_ibv);
      mq->irq.ibv_comp_ch = 0;
    }

  if (mq->buffers)
    clib_mem_free (mq->buffers);
  if (mq->second_bufs)
    clib_mem_free (mq->second_bufs);
  mq->buffers = 0;
  mq->second_bufs = 0;
}

vnet_dev_rv_t
mlx5_rxq_alloc (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq)
{
  vnet_dev_t *dev = rxq->port->dev;
  mlx5_dev_t *rd = vnet_dev_get_data (rxq->port->dev);
  mlx5_rxq_t *mq = vnet_dev_get_rx_queue_data (rxq);
  mlx5_port_t *mp = vnet_dev_get_port_data (rxq->port);
  struct ibv_cq_init_attr_ex cqa = {
    .cqe = rxq->size,
  };
  struct mlx5dv_cq_init_attr dvcq = {
    .comp_mask = MLX5DV_CQ_INIT_ATTR_MASK_CQE_SIZE,
    .cqe_size = sizeof (struct mlx5_cqe64),
  };
  struct mlx5dv_cq dv_cq = {};
  struct mlx5dv_obj obj = {
    .cq = {
      .out = &dv_cq,
    },
  };
  struct ibv_cq_ex *cqex;
  int rv_ibv;

  log_debug (dev, "mlx5_rxq_alloc: queue %u", rxq->queue_id);

  mp->striding_rq = mp->striding_rq_supported;
  mp->cqe_compression = mp->cqe_res_format_hash;
  if (rxq->port->args && clib_args_get_bool_val_by_name (rxq->port->args, "no_striding_rq"))
    mp->striding_rq = 0;
  if (rxq->port->args && clib_args_get_bool_val_by_name (rxq->port->args, "no_cqe_compression"))
    mp->cqe_compression = 0;

  mq->buffers = clib_mem_alloc_aligned (sizeof (u32) * rxq->size, CLIB_CACHE_LINE_BYTES);
  if (mp->striding_rq == 0)
    {
      u32 n = rxq->size * (RDMA_RXQ_LEGACY_MODE_MAX_CHAIN_SZ - 1);

      mq->second_bufs = clib_mem_alloc_aligned (sizeof (u32) * n, CLIB_CACHE_LINE_BYTES);
    }

  mq->irq.ibv_comp_ch = ibv_create_comp_channel (rd->ctx);
  if (mq->irq.ibv_comp_ch == 0)
    {
      log_err (dev, "ibv_create_comp_channel failed");
      return VNET_DEV_ERR_INIT_FAILED;
    }

  if (fcntl (mq->irq.ibv_comp_ch->fd, F_SETFL, O_NONBLOCK) < 0)
    {
      log_err (dev, "fcntl O_NONBLOCK failed errno %d", errno);
      return VNET_DEV_ERR_INIT_FAILED;
    }

  cqa.channel = mq->irq.ibv_comp_ch;

  if (mp->cqe_compression)
    {
      dvcq.comp_mask |= MLX5DV_CQ_INIT_ATTR_MASK_COMPRESSED_CQE;
      dvcq.cqe_comp_res_format = MLX5DV_CQE_RES_FORMAT_HASH;
    }

  cqex = mlx5dv_create_cq (rd->ctx, &cqa, &dvcq);
  if (cqex == 0)
    {
      log_err (dev, "mlx5dv_create_cq failed errno %d", errno);
      return VNET_DEV_ERR_INIT_FAILED;
    }

  mq->ibv_cq = ibv_cq_ex_to_cq (cqex);
  mq->irq = (rdma_rxq_irq_t) {
    .rxq = rxq,
    .ibv_cq = mq->ibv_cq,
    .ibv_comp_ch = mq->irq.ibv_comp_ch,
    .driver_name = (u8 *) "mlx5",
  };

  obj.cq.in = mq->ibv_cq;
  rv_ibv = mlx5dv_init_obj (&obj, MLX5DV_OBJ_CQ);
  if (rv_ibv || !is_pow2 (dv_cq.cqe_cnt) || dv_cq.cqe_cnt < rxq->size ||
      dv_cq.cqe_size != sizeof (struct mlx5_cqe64) ||
      (uword) dv_cq.buf % sizeof (struct mlx5_cqe64))
    {
      log_err (dev, "unexpected cq layout: rv %d cqe_cnt %u cqe_size %u", rv_ibv, dv_cq.cqe_cnt,
	       dv_cq.cqe_size);
      return VNET_DEV_ERR_UNSUPPORTED_DEVICE;
    }

  mq->dv_cq_cqes = dv_cq.buf;
  mq->dv_cq_dbrec = dv_cq.dbrec;
  mq->dv_cq_size = dv_cq.cqe_cnt;
  mq->dv_cq_log2 = min_log2 (dv_cq.cqe_cnt);
  for (u32 i = 0; i < mq->dv_cq_size; i++)
    mq->dv_cq_cqes[i].op_own = 0xff;

  mlx5_rxq_q_counter_alloc (rxq);
  return VNET_DEV_OK;
}

void
mlx5_txq_free (vlib_main_t *vm __clib_unused, vnet_dev_tx_queue_t *txq)
{
  vnet_dev_t *dev = txq->port->dev;
  mlx5_txq_t *tq = vnet_dev_get_tx_queue_data (txq);
  int rv_ibv;

  log_debug (dev, "mlx5_txq_free: queue %u", txq->queue_id);

  ASSERT (txq->started == 0);

  if (tq->ibv_qp)
    {
      rv_ibv = ibv_destroy_qp (tq->ibv_qp);
      if (rv_ibv)
	log_err (dev, "ibv_destroy_qp failed rv %d", rv_ibv);
    }

  if (tq->ibv_cq)
    {
      rv_ibv = ibv_destroy_cq (tq->ibv_cq);
      if (rv_ibv)
	log_err (dev, "ibv_destroy_cq failed rv %d", rv_ibv);
    }

  if (tq->buffers)
    clib_mem_free (tq->buffers);
  if (tq->wqe_n_bb)
    clib_mem_free (tq->wqe_n_bb);
  if (tq->wqe_buf_tail)
    clib_mem_free (tq->wqe_buf_tail);
  tq->buffers = 0;
  tq->wqe_n_bb = 0;
  tq->wqe_buf_tail = 0;
}

vnet_dev_rv_t
mlx5_txq_alloc (vlib_main_t *vm __clib_unused, vnet_dev_tx_queue_t *txq)
{
  vnet_dev_t *dev = txq->port->dev;
  mlx5_dev_t *rd;
  mlx5_port_t *mp;
  mlx5_txq_t *tq;
  struct ibv_cq_ex *cqex;
  struct mlx5dv_cq dv_cq = {};
  struct mlx5dv_qp dv_qp = {};
  vnet_dev_rv_t rv = VNET_DEV_OK;
  u8 ibv_port = txq->port->port_id;
  u32 sq_buf_mod, cq_buf_mod;
  int rv_ibv;

  log_debug (dev, "mlx5_txq_alloc: queue %u", txq->queue_id);

  rd = vnet_dev_get_data (txq->port->dev);
  mp = vnet_dev_get_port_data (txq->port);
  tq = vnet_dev_get_tx_queue_data (txq);
  ASSERT (tq->buffers == 0);
  tq->head = 0;
  tq->tail = 0;
  tq->buf_head = 0;
  tq->buf_tail = 0;
  tq->dv_cq_idx = 0;
  tq->empw = mp->empw_supported;
  if (txq->port->args && clib_args_get_bool_val_by_name (txq->port->args, "no_empw"))
    tq->empw = 0;

  tq->buf_mask = txq->size * (MLX5_SEND_WQE_BB / sizeof (struct mlx5_wqe_data_seg)) - 1;
  tq->buffers = clib_mem_alloc_aligned (sizeof (u32) * (tq->buf_mask + 1), CLIB_CACHE_LINE_BYTES);
  tq->wqe_n_bb = clib_mem_alloc_aligned (txq->size, CLIB_CACHE_LINE_BYTES);
  tq->wqe_buf_tail = clib_mem_alloc_aligned (sizeof (u32) * txq->size, CLIB_CACHE_LINE_BYTES);
  if (tq->buffers == 0 || tq->wqe_n_bb == 0 || tq->wqe_buf_tail == 0)
    return VNET_DEV_ERR_RESOURCE_NOT_AVAILABLE;

  cqex = mlx5dv_create_cq (rd->ctx,
			   &(struct ibv_cq_init_attr_ex) {
			     .cqe = txq->size,
			   },
			   &(struct mlx5dv_cq_init_attr) {
			     .comp_mask = MLX5DV_CQ_INIT_ATTR_MASK_CQE_SIZE,
			     .cqe_size = sizeof (struct mlx5_cqe64),
			   });
  if (cqex == 0)
    {
      rv = VNET_DEV_ERR_INIT_FAILED;
      goto err;
    }
  tq->ibv_cq = ibv_cq_ex_to_cq (cqex);
  if (tq->ibv_cq == 0)
    {
      log_err (dev, "ibv_cq_ex_to_cq failed");
      rv = VNET_DEV_ERR_INIT_FAILED;
      goto err;
    }

  tq->ibv_qp = ibv_create_qp (
    rd->pd, &(struct ibv_qp_init_attr){
	     .send_cq = tq->ibv_cq,
	     .recv_cq = tq->ibv_cq,
	     .cap = {
	       .max_send_wr = txq->size,
	       .max_send_sge = 1,
	     },
	     .qp_type = IBV_QPT_RAW_PACKET,
	   });
  if (tq->ibv_qp == 0)
    {
      log_err (dev, "ibv_create_qp failed");
      rv = VNET_DEV_ERR_INIT_FAILED;
      goto err;
    }

  rv_ibv = ibv_modify_qp (tq->ibv_qp,
			  &(struct ibv_qp_attr) {
			    .qp_state = IBV_QPS_INIT,
			    .port_num = ibv_port,
			  },
			  IBV_QP_STATE | IBV_QP_PORT);
  if (rv_ibv)
    {
      log_err (dev, "ibv_modify_qp init failed rv %d", rv_ibv);
      rv = VNET_DEV_ERR_INIT_FAILED;
      goto err;
    }

  rv_ibv = ibv_modify_qp (tq->ibv_qp,
			  &(struct ibv_qp_attr) {
			    .qp_state = IBV_QPS_RTR,
			  },
			  IBV_QP_STATE);
  if (rv_ibv)
    {
      log_err (dev, "ibv_modify_qp rtr failed rv %d", rv_ibv);
      rv = VNET_DEV_ERR_INIT_FAILED;
      goto err;
    }

  rv_ibv = ibv_modify_qp (tq->ibv_qp,
			  &(struct ibv_qp_attr) {
			    .qp_state = IBV_QPS_RTS,
			  },
			  IBV_QP_STATE);
  if (rv_ibv)
    {
      log_err (dev, "ibv_modify_qp rts failed rv %d", rv_ibv);
      rv = VNET_DEV_ERR_INIT_FAILED;
      goto err;
    }

  rv_ibv = mlx5dv_init_obj (
    &(struct mlx5dv_obj){
  .qp = {
    .in = tq->ibv_qp,
    .out = &dv_qp,
  },
  .cq = {
    .in = tq->ibv_cq,
    .out = &dv_cq,
  },
},
MLX5DV_OBJ_CQ | MLX5DV_OBJ_QP);

  if (rv_ibv)
    {
      rv = VNET_DEV_ERR_INIT_FAILED;
      goto err;
    }

  sq_buf_mod = (u32) ((uword) dv_qp.sq.buf % sizeof (mlx5_wqe_t));
  cq_buf_mod = (u32) ((uword) dv_cq.buf % sizeof (struct mlx5_cqe64));
  log_debug (dev,
	     "mlx5 txq validate: size %u sq.wqe_cnt %u sq.stride %u "
	     "sq.buf_mod %u cq.cqe_cnt %u cq.cqe_size %u cq.buf_mod %u",
	     txq->size, dv_qp.sq.wqe_cnt, dv_qp.sq.stride, sq_buf_mod, dv_cq.cqe_cnt,
	     dv_cq.cqe_size, cq_buf_mod);

  if (!is_pow2 (dv_qp.sq.wqe_cnt) || dv_qp.sq.wqe_cnt != txq->size ||
      dv_qp.sq.stride != sizeof (mlx5_wqe_t) || (uword) dv_qp.sq.buf % sizeof (mlx5_wqe_t) ||
      !is_pow2 (dv_cq.cqe_cnt) || dv_cq.cqe_cnt < txq->size ||
      dv_cq.cqe_size != sizeof (struct mlx5_cqe64) ||
      (uword) dv_cq.buf % sizeof (struct mlx5_cqe64))
    {
      rv = VNET_DEV_ERR_UNSUPPORTED_DEVICE;
      goto err;
    }

  tq->dv_sq_wqes = (mlx5_wqe_t *) dv_qp.sq.buf;
  tq->dv_sq_dbrec = (u32 *) dv_qp.dbrec;
  tq->dv_sq_db = (u64 *) dv_qp.bf.reg;
  tq->dv_cq_cqes = (struct mlx5_cqe64 *) dv_cq.buf;
  tq->dv_cq_dbrec = (u32 *) dv_cq.dbrec;
  tq->dv_cq_size = dv_cq.cqe_cnt;
  tq->dv_cq_log2 = min_log2 (dv_cq.cqe_cnt);

  for (u32 i = 0; i < tq->dv_cq_size; i++)
    tq->dv_cq_cqes[i].op_own = 0xff;

  mlx5dv_set_ctrl_seg (&tq->tmpl_ctrl.seg, 0, MLX5_OPCODE_SEND, 0, tq->ibv_qp->qp_num, 0, 0, 0, 0);
  mlx5dv_set_ctrl_seg (&tq->tmpl_empw_ctrl.seg, 0, MLX5_OPCODE_ENHANCED_MPSW, 0, tq->ibv_qp->qp_num,
		       0, 0, 0, 0);
  tq->tmpl_eseg = (struct mlx5_wqe_eth_seg) {
    .inline_hdr_sz = clib_host_to_net_u16 (MLX5_ETH_L2_INLINE_HEADER_SIZE),
  };
  tq->lkey_be = clib_host_to_net_u32 (rd->lkey);

err:
  return rv;
}
