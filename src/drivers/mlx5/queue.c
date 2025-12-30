/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <errno.h>
#include <common.h>
#include <mlx5.h>

VLIB_REGISTER_LOG_CLASS (mlx5_log, static) = {
  .class_name = "mlx5",
  .subclass_name = "queue",
};

static u8 mlx5_rss_hash_key[] = {
  0x2c, 0xc6, 0x81, 0xd1, 0x5b, 0xdb, 0xf4, 0xf7, 0xfc, 0xa2, 0x83, 0x19, 0xdb, 0x1a,
  0x3e, 0x94, 0x6b, 0x9e, 0x38, 0xd9, 0x2c, 0x9c, 0x03, 0xd1, 0xad, 0x99, 0x44, 0xa7,
  0xd9, 0x56, 0x3d, 0x59, 0x06, 0x3c, 0x25, 0xf3, 0xfc, 0x1f, 0xdc, 0x2a,
};

void
mlx5_rxq_free (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq)
{
  vnet_dev_t *dev = rxq->port->dev;
  mlx5_rxq_t *mq;
  struct ibv_flow **f;
  int rv_ibv;

  log_debug (dev, "mlx5_rxq_free: queue %u", rxq->queue_id);

  ASSERT (rxq->started == 0);
  mq = vnet_dev_get_rx_queue_data (rxq);

  vec_foreach (f, mq->flows)
    if (f[0])
      {
	rv_ibv = ibv_destroy_flow (f[0]);
	if (rv_ibv)
	  log_err (dev, "ibv_destroy_flow failed rv %d", rv_ibv);
	else
	  log_debug (dev, "ibv_destroy_flow ok");
      }
  vec_free (mq->flows);

  if (mq->ibv_qp)
    {
      rv_ibv = ibv_destroy_qp (mq->ibv_qp);
      if (rv_ibv)
	log_err (dev, "ibv_destroy_qp failed rv %d", rv_ibv);
      else
	log_debug (dev, "ibv_destroy_qp ok");
    }

  if (mq->rwq_ind_tbl)
    {
      rv_ibv = ibv_destroy_rwq_ind_table (mq->rwq_ind_tbl);
      if (rv_ibv)
	log_err (dev, "ibv_destroy_rwq_ind_table failed rv %d", rv_ibv);
      else
	log_debug (dev, "ibv_destroy_rwq_ind_table ok");
    }

  if (mq->ibv_wq)
    {
      rv_ibv = ibv_destroy_wq (mq->ibv_wq);
      if (rv_ibv)
	log_err (dev, "ibv_destroy_wq failed rv %d", rv_ibv);
      else
	log_debug (dev, "ibv_destroy_wq ok");
    }

  if (mq->ibv_cq)
    {
      rv_ibv = ibv_destroy_cq (mq->ibv_cq);
      if (rv_ibv)
	log_err (dev, "ibv_destroy_cq failed rv %d", rv_ibv);
      else
	log_debug (dev, "ibv_destroy_cq ok");
    }

  if (mq->buffers)
    {
      u32 n = mq->tail - mq->head;

      if (n)
	{
	  u32 mask = rxq->size - 1;
	  if (mq->n_ds_per_wqe > 1 && mq->second_bufs && mq->n_used_per_chain)
	    {
	      u32 extras_per = mq->n_ds_per_wqe - 1;
	      u32 slot = mq->head & mask;
	      u32 left = n;
	      u32 n_now;
	      u32 i;
	      u32 base;

	      while (left)
		{
		  n_now = clib_min (left, rxq->size - slot);
		  for (i = 0; i < n_now; i++)
		    {
		      u8 extras_alloc = mq->n_used_per_chain[slot + i];

		      base = (slot + i) * extras_per;
		      if (extras_alloc)
			vlib_buffer_free (vm, mq->second_bufs + base, extras_alloc);
		      mq->n_used_per_chain[slot + i] = 0;
		    }
		  left -= n_now;
		  slot = 0;
		}
	      mq->n_total_additional_segs = 0;
	    }
	  vlib_buffer_free_from_ring (vm, mq->buffers, mq->head & mask, rxq->size, n);
	}
      clib_mem_free (mq->buffers);
    }

  if (mq->second_bufs)
    {
      clib_mem_free (mq->second_bufs);
      mq->second_bufs = 0;
    }

  if (mq->n_used_per_chain)
    {
      clib_mem_free (mq->n_used_per_chain);
      mq->n_used_per_chain = 0;
    }
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
  struct ibv_cq_ex *cqex;
  struct mlx5dv_cq dv_cq = {};
  struct mlx5dv_qp dv_qp = {};
  u32 rq_buf_mod;
  u32 cq_buf_mod;
  u32 buf_sz;
  u32 max_chain_sz;
  u32 max_chain_log_sz;
  int rv_ibv;
  u64 qw0;
  u8 ibv_port = (u8) rxq->port->port_id;
  u8 qps_set_state = 1;
  vnet_dev_rv_t rv = VNET_DEV_OK;

  log_debug (dev, "mlx5_rxq_alloc: queue %u", rxq->queue_id);

  if (mp->striding_rq && rxq->port->args &&
      clib_args_get_bool_val_by_name (rxq->port->args, "no_striding_rq"))
    mp->striding_rq = 0;

  buf_sz = vnet_dev_get_rx_queue_buffer_data_size (vm, rxq);
  mq->buf_sz = buf_sz;

  mq->buffers = clib_mem_alloc_aligned (sizeof (u32) * rxq->size, CLIB_CACHE_LINE_BYTES);
  if (mq->buffers == 0)
    return VNET_DEV_ERR_RESOURCE_NOT_AVAILABLE;

  if (mp->cqe_res_format_hash)
    {
      dvcq.comp_mask |= MLX5DV_CQ_INIT_ATTR_MASK_COMPRESSED_CQE;
      dvcq.cqe_comp_res_format = MLX5DV_CQE_RES_FORMAT_HASH;
    }

  cqex = mlx5dv_create_cq (rd->ctx, &cqa, &dvcq);

  if (cqex == 0)
    {
      rv = VNET_DEV_ERR_INIT_FAILED;
      goto err;
    }

  mq->ibv_cq = ibv_cq_ex_to_cq (cqex);
  if (mq->ibv_cq == 0)
    {
      log_err (dev, "ibv_cq_ex_to_cq failed");
      rv = VNET_DEV_ERR_INIT_FAILED;
      goto err;
    }
  log_debug (dev, "ibv_cq_ex_to_cq ok cqe %u", rxq->size);

  if (mp->striding_rq)
    {
      struct ibv_wq_init_attr wqia = {
	.wq_type = IBV_WQT_RQ,
	.max_wr = rxq->size,
	.max_sge = 1,
	.pd = rd->pd,
	.cq = mq->ibv_cq,
      };
      struct mlx5dv_wq_init_attr dv_wqia = {};
      struct ibv_wq_attr wqa = {
	.attr_mask = IBV_WQ_ATTR_STATE,
	.wq_state = IBV_WQS_RDY,
      };
      struct ibv_rwq_ind_table_init_attr rwqia = {};
      struct ibv_qp_init_attr_ex qpia = {};
      struct ibv_wq *ind_tbl[1];
      uword data_seg_log2_sz;
      u64 rx_hash_fields = 0;

      mq->log_stride_per_wqe = RDMA_RXQ_MAX_CHAIN_LOG_SZ;
      mq->log_wqe_sz = RDMA_RXQ_MAX_CHAIN_LOG_SZ + 1;
      data_seg_log2_sz = min_log2 (vnet_dev_get_rx_queue_buffer_data_size (vm, rxq));
      mq->buf_sz = 1 << data_seg_log2_sz;

      wqia.max_sge = 1 << mq->log_stride_per_wqe;
      wqia.max_wr = rxq->size >> mq->log_stride_per_wqe;
      if (wqia.max_wr == 0)
	{
	  rv = VNET_DEV_ERR_UNSUPPORTED_DEVICE;
	  goto err;
	}

      dv_wqia.comp_mask = MLX5DV_WQ_INIT_ATTR_MASK_STRIDING_RQ;
      dv_wqia.striding_rq_attrs.two_byte_shift_en = 0;
      dv_wqia.striding_rq_attrs.single_wqe_log_num_of_strides = mq->log_stride_per_wqe;
      dv_wqia.striding_rq_attrs.single_stride_log_num_of_bytes = data_seg_log2_sz;

      mq->ibv_wq = mlx5dv_create_wq (rd->ctx, &wqia, &dv_wqia);
      if (mq->ibv_wq == 0)
	{
	  log_err (dev, "mlx5dv_create_wq failed");
	  rv = VNET_DEV_ERR_INIT_FAILED;
	  goto err;
	}
      log_debug (dev, "mlx5dv_create_wq ok");

      rv_ibv = ibv_modify_wq (mq->ibv_wq, &wqa);
      if (rv_ibv)
	{
	  log_err (dev, "ibv_modify_wq rdy failed rv %d", rv_ibv);
	  rv = VNET_DEV_ERR_INIT_FAILED;
	  goto err;
	}
      log_debug (dev, "ibv_modify_wq rdy ok");

      ind_tbl[0] = mq->ibv_wq;
      rwqia.log_ind_tbl_size = 0;
      rwqia.ind_tbl = ind_tbl;
      mq->rwq_ind_tbl = ibv_create_rwq_ind_table (rd->ctx, &rwqia);
      if (mq->rwq_ind_tbl == 0)
	{
	  log_err (dev, "ibv_create_rwq_ind_table failed");
	  rv = VNET_DEV_ERR_INIT_FAILED;
	  goto err;
	}
      log_debug (dev, "ibv_create_rwq_ind_table ok");

      qpia.qp_type = IBV_QPT_RAW_PACKET;
      qpia.comp_mask = IBV_QP_INIT_ATTR_PD | IBV_QP_INIT_ATTR_IND_TABLE | IBV_QP_INIT_ATTR_RX_HASH;
      qpia.pd = rd->pd;
      qpia.rwq_ind_tbl = mq->rwq_ind_tbl;
      if (!(rd->rss_hash_function & IBV_RX_HASH_FUNC_TOEPLITZ))
	{
	  log_err (dev, "toeplitz hash function is not supported");
	  rv = VNET_DEV_ERR_UNSUPPORTED_DEVICE;
	  goto err;
	}
      if ((rd->rss_hash_fields_mask & (IBV_RX_HASH_SRC_IPV4 | IBV_RX_HASH_DST_IPV4)) ==
	  (IBV_RX_HASH_SRC_IPV4 | IBV_RX_HASH_DST_IPV4))
	rx_hash_fields = IBV_RX_HASH_SRC_IPV4 | IBV_RX_HASH_DST_IPV4;
      else if ((rd->rss_hash_fields_mask & (IBV_RX_HASH_SRC_IPV6 | IBV_RX_HASH_DST_IPV6)) ==
	       (IBV_RX_HASH_SRC_IPV6 | IBV_RX_HASH_DST_IPV6))
	rx_hash_fields = IBV_RX_HASH_SRC_IPV6 | IBV_RX_HASH_DST_IPV6;
      if (rx_hash_fields == 0)
	{
	  log_err (dev, "cannot find a usable rx hash field profile");
	  rv = VNET_DEV_ERR_UNSUPPORTED_DEVICE;
	  goto err;
	}
      STATIC_ASSERT_SIZEOF (mlx5_rss_hash_key, 40);
      qpia.rx_hash_conf.rx_hash_key_len = sizeof (mlx5_rss_hash_key);
      qpia.rx_hash_conf.rx_hash_key = mlx5_rss_hash_key;
      qpia.rx_hash_conf.rx_hash_function = IBV_RX_HASH_FUNC_TOEPLITZ;
      qpia.rx_hash_conf.rx_hash_fields_mask = rx_hash_fields;
      mq->ibv_qp = ibv_create_qp_ex (rd->ctx, &qpia);
      if (mq->ibv_qp == 0)
	{
	  log_err (dev, "ibv_create_qp_ex failed errno %d", errno);
	  rv = VNET_DEV_ERR_INIT_FAILED;
	  goto err;
	}
      qps_set_state = 0;
      log_debug (dev, "ibv_create_qp_ex ok");
    }
  else
    {
      max_chain_sz = (rxq->port->max_rx_frame_size / buf_sz) + 1;
      if (max_chain_sz == 0)
	max_chain_sz = 1;
      max_chain_sz = clib_min (max_chain_sz, (u32) RDMA_RXQ_LEGACY_MODE_MAX_CHAIN_SZ);
      mq->n_ds_per_wqe = (u8) max_chain_sz;
      max_chain_log_sz = max_log2 (max_chain_sz);
      mq->log_wqe_sz = (u8) max_chain_log_sz;

      mq->ibv_qp = ibv_create_qp (
	rd->pd, &(struct ibv_qp_init_attr){
		 .send_cq = mq->ibv_cq,
		 .recv_cq = mq->ibv_cq,
		 .cap = {
		   .max_recv_wr = rxq->size,
		   .max_recv_sge = 1 << max_chain_log_sz,
		 },
		 .qp_type = IBV_QPT_RAW_PACKET,
	       });
      if (mq->ibv_qp == 0)
	{
	  log_err (dev, "ibv_create_qp failed");
	  rv = VNET_DEV_ERR_INIT_FAILED;
	  goto err;
	}
      log_debug (dev, "ibv_create_qp ok");
    }

  if (qps_set_state)
    {
      rv_ibv = ibv_modify_qp (mq->ibv_qp,
			      &(struct ibv_qp_attr){
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
      log_debug (dev, "ibv_modify_qp init ok");

      rv_ibv = ibv_modify_qp (mq->ibv_qp,
			      &(struct ibv_qp_attr){
				.qp_state = IBV_QPS_RTR,
			      },
			      IBV_QP_STATE);

      if (rv_ibv)
	{
	  log_err (dev, "ibv_modify_qp rtr failed rv %d", rv_ibv);
	  rv = VNET_DEV_ERR_INIT_FAILED;
	  goto err;
	}
      log_debug (dev, "ibv_modify_qp rtr ok");

      rv_ibv = ibv_modify_qp (mq->ibv_qp,
			      &(struct ibv_qp_attr){
				.qp_state = IBV_QPS_RTS,
			      },
			      IBV_QP_STATE);
      if (rv_ibv)
	{
	  log_err (dev, "ibv_modify_qp rts failed rv %d", rv_ibv);
	  rv = VNET_DEV_ERR_INIT_FAILED;
	  goto err;
	}
      log_debug (dev, "ibv_modify_qp rts ok");
    }

  if (mp->striding_rq)
    {
      struct mlx5dv_obj obj = {};
      struct mlx5dv_rwq dv_rwq = {};
      u32 expected_wqe_cnt;
      u32 wqe_stride;
      u64 qw0_nullseg;
      u32 i;
      mlx5dv_wqe_srq_next_t *nseg;

      obj.rwq.in = mq->ibv_wq;
      obj.rwq.out = &dv_rwq;
      obj.cq.in = mq->ibv_cq;
      obj.cq.out = &dv_cq;
      rv_ibv = mlx5dv_init_obj (&obj, MLX5DV_OBJ_CQ | MLX5DV_OBJ_RWQ);
      if (rv_ibv)
	{
	  log_err (dev, "mlx5dv_init_obj failed rv %d", rv_ibv);
	  rv = VNET_DEV_ERR_INIT_FAILED;
	  goto err;
	}

      rq_buf_mod = (u32) ((uword) dv_rwq.buf % sizeof (mlx5dv_wqe_ds_t));
      cq_buf_mod = (u32) ((uword) dv_cq.buf % sizeof (struct mlx5_cqe64));
      expected_wqe_cnt = rxq->size >> mq->log_stride_per_wqe;
      wqe_stride = sizeof (mlx5dv_wqe_ds_t) << mq->log_wqe_sz;

      log_debug (dev,
		 "mlx5 rxq validate: size %u rq.wqe_cnt %u rq.stride %u "
		 "rq.buf_mod %u cq.cqe_cnt %u cq.cqe_size %u cq.buf_mod %u",
		 rxq->size, dv_rwq.wqe_cnt, dv_rwq.stride, rq_buf_mod, dv_cq.cqe_cnt,
		 dv_cq.cqe_size, cq_buf_mod);

      if (!is_pow2 (dv_rwq.wqe_cnt) || dv_rwq.wqe_cnt != expected_wqe_cnt ||
	  dv_rwq.stride != wqe_stride || (uword) dv_rwq.buf % sizeof (mlx5dv_wqe_ds_t) ||
	  !is_pow2 (dv_cq.cqe_cnt) || dv_cq.cqe_cnt < rxq->size ||
	  dv_cq.cqe_size != sizeof (struct mlx5_cqe64) ||
	  (uword) dv_cq.buf % sizeof (struct mlx5_cqe64))
	{
	  rv = VNET_DEV_ERR_UNSUPPORTED_DEVICE;
	  goto err;
	}

      mq->dv_sq_wqes = (mlx5dv_wqe_ds_t *) dv_rwq.buf;
      mq->dv_sq_dbrec = (u32 *) dv_rwq.dbrec;
      mq->dv_cq_cqes = (struct mlx5_cqe64 *) dv_cq.buf;
      mq->dv_cq_dbrec = (u32 *) dv_cq.dbrec;
      mq->dv_cq_size = (u16) dv_cq.cqe_cnt;
      mq->dv_cq_log2 = (u8) min_log2 (dv_cq.cqe_cnt);
      mq->wqe_cnt = dv_rwq.wqe_cnt;

      qw0 = clib_host_to_net_u32 (mq->buf_sz);
      qw0_nullseg = 0;
      for (i = 0; i < mq->wqe_cnt << mq->log_wqe_sz; i++)
	if ((i == 0) || !(((i - 1) >> mq->log_stride_per_wqe) & 0x1))
	  mq->dv_sq_wqes[i].dsz_and_lkey = qw0;
	else
	  mq->dv_sq_wqes[i].dsz_and_lkey = qw0_nullseg;

      for (i = 0; i < mq->wqe_cnt; i++)
	{
	  nseg = (mlx5dv_wqe_srq_next_t *) (mq->dv_sq_wqes + (i << mq->log_wqe_sz));
	  nseg->next_wqe_index = clib_host_to_net_u16 ((i + 1) & (mq->wqe_cnt - 1));
	}
    }
  else
    {
      rv_ibv = mlx5dv_init_obj (
	&(struct mlx5dv_obj){
	  .qp = {
	    .in = mq->ibv_qp,
	    .out = &dv_qp,
	  },
	  .cq = {
	    .in = mq->ibv_cq,
	    .out = &dv_cq,
	  },
	},
	MLX5DV_OBJ_CQ | MLX5DV_OBJ_QP);

      if (rv_ibv)
	{
	  log_err (dev, "mlx5dv_init_obj failed rv %d", rv_ibv);
	  rv = VNET_DEV_ERR_INIT_FAILED;
	  goto err;
	}

      rq_buf_mod = (u32) ((uword) dv_qp.rq.buf % sizeof (mlx5dv_wqe_ds_t));
      cq_buf_mod = (u32) ((uword) dv_cq.buf % sizeof (struct mlx5_cqe64));

      log_debug (dev,
		 "mlx5 rxq validate: size %u rq.wqe_cnt %u rq.stride %u "
		 "rq.buf_mod %u cq.cqe_cnt %u cq.cqe_size %u cq.buf_mod %u",
		 rxq->size, dv_qp.rq.wqe_cnt, dv_qp.rq.stride, rq_buf_mod, dv_cq.cqe_cnt,
		 dv_cq.cqe_size, cq_buf_mod);

      if (!is_pow2 (dv_qp.rq.wqe_cnt) || dv_qp.rq.wqe_cnt != rxq->size ||
	  dv_qp.rq.stride != (sizeof (mlx5dv_wqe_ds_t) << mq->log_wqe_sz) ||
	  (uword) dv_qp.rq.buf % sizeof (mlx5dv_wqe_ds_t) || !is_pow2 (dv_cq.cqe_cnt) ||
	  dv_cq.cqe_cnt < rxq->size || dv_cq.cqe_size != sizeof (struct mlx5_cqe64) ||
	  (uword) dv_cq.buf % sizeof (struct mlx5_cqe64))
	{
	  rv = VNET_DEV_ERR_UNSUPPORTED_DEVICE;
	  goto err;
	}

      mq->dv_sq_wqes = (mlx5dv_wqe_ds_t *) dv_qp.rq.buf;
      mq->dv_sq_dbrec = (u32 *) dv_qp.dbrec;
      mq->dv_cq_cqes = (struct mlx5_cqe64 *) dv_cq.buf;
      mq->dv_cq_dbrec = (u32 *) dv_cq.dbrec;
      mq->dv_cq_size = (u16) dv_cq.cqe_cnt;
      mq->dv_cq_log2 = (u8) min_log2 (dv_cq.cqe_cnt);

      qw0 = clib_host_to_net_u32 (buf_sz);
      {
	u32 wqe_sz = 1 << mq->log_wqe_sz;
	u64 qw0_nullseg = 0;
	u32 i;
	u32 j;

	for (i = 0; i < rxq->size; i++)
	  {
	    mlx5dv_wqe_ds_t *wqe = mq->dv_sq_wqes + (i << mq->log_wqe_sz);

	    for (j = 0; j < wqe_sz; j++)
	      {
		if (j < mq->n_ds_per_wqe)
		  wqe[j].dsz_and_lkey = qw0;
		else
		  wqe[j].dsz_and_lkey = qw0_nullseg;
	      }
	  }
      }

      if (mq->n_ds_per_wqe > 1)
	{
	  u32 i;
	  u32 extras_per;
	  u32 sz;

	  extras_per = mq->n_ds_per_wqe - 1;
	  sz = sizeof (mq->second_bufs[0]) * rxq->size * extras_per;
	  mq->second_bufs = clib_mem_alloc_aligned (sz, CLIB_CACHE_LINE_BYTES);
	  if (mq->second_bufs == 0)
	    {
	      rv = VNET_DEV_ERR_RESOURCE_NOT_AVAILABLE;
	      goto err;
	    }
	  clib_memset (mq->second_bufs, 0, sz);

	  sz = sizeof (mq->n_used_per_chain[0]) * rxq->size;
	  mq->n_used_per_chain = clib_mem_alloc_aligned (sz, CLIB_CACHE_LINE_BYTES);
	  if (mq->n_used_per_chain == 0)
	    {
	      clib_mem_free (mq->second_bufs);
	      mq->second_bufs = 0;
	      rv = VNET_DEV_ERR_RESOURCE_NOT_AVAILABLE;
	      goto err;
	    }
	  for (i = 0; i < rxq->size; i++)
	    mq->n_used_per_chain[i] = 0;
	  mq->n_total_additional_segs = 0;
	}
    }

  for (u32 i = 0; i < mq->dv_cq_size; i++)
    mq->dv_cq_cqes[i].op_own = 0xff;

err:
  return rv;
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
      else
	log_debug (dev, "ibv_destroy_qp ok");
    }

  if (tq->ibv_cq)
    {
      rv_ibv = ibv_destroy_cq (tq->ibv_cq);
      if (rv_ibv)
	log_err (dev, "ibv_destroy_cq failed rv %d", rv_ibv);
      else
	log_debug (dev, "ibv_destroy_cq ok");
    }

  if (tq->buffers)
    clib_mem_free (tq->buffers);
}

vnet_dev_rv_t
mlx5_txq_alloc (vlib_main_t *vm __clib_unused, vnet_dev_tx_queue_t *txq)
{
  vnet_dev_t *dev = txq->port->dev;
  mlx5_dev_t *rd;
  mlx5_txq_t *tq;
  struct ibv_cq_ex *cqex;
  struct mlx5dv_cq dv_cq = {};
  struct mlx5dv_qp dv_qp = {};
  vnet_dev_rv_t rv = VNET_DEV_OK;
  mlx5_wqe_t *tmpl;
  u8 ibv_port = txq->port->port_id;
  u32 sq_buf_mod;
  u32 cq_buf_mod;
  int rv_ibv;

  log_debug (dev, "mlx5_txq_alloc: queue %u", txq->queue_id);

  rd = vnet_dev_get_data (txq->port->dev);
  tq = vnet_dev_get_tx_queue_data (txq);
  ASSERT (tq->buffers == 0);
  tq->head = 0;
  tq->tail = 0;
  tq->dv_cq_idx = 0;

  tq->buffers = clib_mem_alloc_aligned (sizeof (u32) * txq->size, CLIB_CACHE_LINE_BYTES);
  if (tq->buffers == 0)
    return VNET_DEV_ERR_RESOURCE_NOT_AVAILABLE;

  cqex = mlx5dv_create_cq (rd->ctx,
			   &(struct ibv_cq_init_attr_ex){
			     .cqe = txq->size,
			   },
			   &(struct mlx5dv_cq_init_attr){
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
  log_debug (dev, "ibv_cq_ex_to_cq ok cqe %u", txq->size);

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
  log_debug (dev, "ibv_create_qp ok");

  rv_ibv = ibv_modify_qp (tq->ibv_qp,
			  &(struct ibv_qp_attr){
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
  log_debug (dev, "ibv_modify_qp init ok");

  rv_ibv = ibv_modify_qp (tq->ibv_qp,
			  &(struct ibv_qp_attr){
			    .qp_state = IBV_QPS_RTR,
			  },
			  IBV_QP_STATE);
  if (rv_ibv)
    {
      log_err (dev, "ibv_modify_qp rtr failed rv %d", rv_ibv);
      rv = VNET_DEV_ERR_INIT_FAILED;
      goto err;
    }
  log_debug (dev, "ibv_modify_qp rtr ok");

  rv_ibv = ibv_modify_qp (tq->ibv_qp,
			  &(struct ibv_qp_attr){
			    .qp_state = IBV_QPS_RTS,
			  },
			  IBV_QP_STATE);
  if (rv_ibv)
    {
      log_err (dev, "ibv_modify_qp rts failed rv %d", rv_ibv);
      rv = VNET_DEV_ERR_INIT_FAILED;
      goto err;
    }
  log_debug (dev, "ibv_modify_qp rts ok");

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
  tq->dv_cq_size = (u16) dv_cq.cqe_cnt;
  tq->dv_cq_log2 = (u8) min_log2 (dv_cq.cqe_cnt);

  for (u32 i = 0; i < tq->dv_cq_size; i++)
    tq->dv_cq_cqes[i].op_own = 0xff;

  tmpl = (mlx5_wqe_t *) tq->dv_wqe_tmpl;
  mlx5dv_set_ctrl_seg (&tmpl->ctrl, 0, MLX5_OPCODE_SEND, 0, tq->ibv_qp->qp_num, 0, RDMA_MLX5_WQE_DS,
		       0, 0);
  tmpl->eseg.inline_hdr_sz = clib_host_to_net_u16 (MLX5_ETH_L2_INLINE_HEADER_SIZE);
  mlx5dv_set_data_seg (&tmpl->dseg, 0, 0, 0);

err:
  return rv;
}
