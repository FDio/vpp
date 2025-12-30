/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vnet/dev/counters.h>
#include <mlx5.h>
#include <mlx5_ifc.h>
#include <common.h>
#include <errno.h>

VLIB_REGISTER_LOG_CLASS (mlx5_log, static) = {
  .class_name = "mlx5",
  .subclass_name = "counters",
};

enum
{
  MLX5_CMD_OP_RTS2RTS_QP = 0x505,
  MLX5_CMD_OP_ALLOC_Q_COUNTER = 0x771,
  MLX5_CMD_OP_DEALLOC_Q_COUNTER = 0x772,
  MLX5_CMD_OP_QUERY_VNIC_ENV = 0x76f,
  MLX5_CMD_OP_QUERY_Q_COUNTER = 0x773,
  MLX5_QP_OPTPAR_COUNTER_SET_ID = 1 << 25,
  MLX5_QUERY_VNIC_ENV_IN_OP_MOD_VPORT_DIAG_STATISTICS = 0x0,
};

typedef enum
{
  MLX5_PORT_VAL_RX_DROPS,
  MLX5_PORT_VAL_RX_STEERING_DISCARD,
  MLX5_PORT_VAL_RX_VPORT_DOWN,
  MLX5_PORT_VAL_RX_NO_BUFFER,
  MLX5_PORT_VAL_ERROR_QUEUES,
  MLX5_PORT_VAL_TOTAL_ERROR_QUEUES,
  MLX5_PORT_VAL_SQ_PRI_UPDATE_FLOW,
  MLX5_PORT_VAL_ASYNC_EQ_OVERRUN,
  MLX5_PORT_VAL_COMP_EQ_OVERRUN,
  MLX5_PORT_VAL_INVALID_COMMAND,
  MLX5_PORT_VAL_QUOTA_EXCEEDED_COMMAND,
  MLX5_PORT_VAL_CQ_OVERRUN,
  MLX5_PORT_VAL_ETH_WQE_TOO_SMALL,
  MLX5_PORT_VAL_STEERING_FAIL_GENERATED,
  MLX5_PORT_VAL_STEERING_FAIL_HANDLED,
  MLX5_PORT_VAL_TX_VPORT_DOWN,
  MLX5_PORT_VAL_N,
} mlx5_port_counter_value_id_t;

static vnet_dev_counter_t mlx5_port_counters[] = {
  VNET_DEV_CTR_RX_DROPS (MLX5_PORT_VAL_RX_DROPS),
  VNET_DEV_CTR_VENDOR (MLX5_PORT_VAL_RX_STEERING_DISCARD, RX, PACKETS, "steering discard"),
  VNET_DEV_CTR_VENDOR (MLX5_PORT_VAL_RX_VPORT_DOWN, RX, PACKETS, "vport down discard"),
  VNET_DEV_CTR_VENDOR (MLX5_PORT_VAL_RX_NO_BUFFER, RX, PACKETS, "out of buffer"),
  VNET_DEV_CTR_VENDOR (MLX5_PORT_VAL_ERROR_QUEUES, NA, NA, "error queues"),
  VNET_DEV_CTR_VENDOR (MLX5_PORT_VAL_TOTAL_ERROR_QUEUES, NA, NA, "total error queues"),
  VNET_DEV_CTR_VENDOR (MLX5_PORT_VAL_SQ_PRI_UPDATE_FLOW, NA, NA, "sq pri update flow"),
  VNET_DEV_CTR_VENDOR (MLX5_PORT_VAL_ASYNC_EQ_OVERRUN, NA, DESCRIPTORS, "async eq overrun"),
  VNET_DEV_CTR_VENDOR (MLX5_PORT_VAL_COMP_EQ_OVERRUN, NA, DESCRIPTORS, "comp eq overrun"),
  VNET_DEV_CTR_VENDOR (MLX5_PORT_VAL_INVALID_COMMAND, NA, COMMANDS, "invalid command"),
  VNET_DEV_CTR_VENDOR (MLX5_PORT_VAL_QUOTA_EXCEEDED_COMMAND, NA, COMMANDS, "quota exceeded cmd"),
  VNET_DEV_CTR_VENDOR (MLX5_PORT_VAL_CQ_OVERRUN, NA, DESCRIPTORS, "cq overrun"),
  VNET_DEV_CTR_VENDOR (MLX5_PORT_VAL_ETH_WQE_TOO_SMALL, NA, DESCRIPTORS, "eth wqe too small"),
  VNET_DEV_CTR_VENDOR (MLX5_PORT_VAL_STEERING_FAIL_GENERATED, NA, NA, "steering fail gen"),
  VNET_DEV_CTR_VENDOR (MLX5_PORT_VAL_STEERING_FAIL_HANDLED, NA, NA, "steering fail handled"),
  VNET_DEV_CTR_VENDOR (MLX5_PORT_VAL_TX_VPORT_DOWN, TX, PACKETS, "vport down discard"),
};

static vnet_dev_counter_t mlx5_rxq_counters[] = {
  VNET_DEV_CTR_RX_PACKETS (MLX5_RXQ_CTR_PACKETS),
  VNET_DEV_CTR_RX_BYTES (MLX5_RXQ_CTR_BYTES),
  VNET_DEV_CTR_RX_DROPS (MLX5_RXQ_CTR_DROPS_HW),
  VNET_DEV_CTR_VENDOR (MLX5_RXQ_CTR_IP4_CKSUM_BAD, RX, PACKETS, "ipv4 cksum errors"),
  VNET_DEV_CTR_VENDOR (MLX5_RXQ_CTR_CQ_OVERFLOW, RX, DESCRIPTORS, "cq overflow"),
};

static vnet_dev_counter_t mlx5_txq_counters[] = {
  VNET_DEV_CTR_TX_PACKETS (MLX5_TXQ_CTR_PACKETS),
  VNET_DEV_CTR_TX_BYTES (MLX5_TXQ_CTR_BYTES),
  VNET_DEV_CTR_TX_DROPS (MLX5_TXQ_CTR_DROPS),
  VNET_DEV_CTR_VENDOR (MLX5_TXQ_CTR_DROPS_HW, TX, PACKETS, "hardware drops"),
  VNET_DEV_CTR_VENDOR (MLX5_TXQ_CTR_BUFFER_PREPARE_FAIL, TX, BUFFERS, "buffer prepare failure"),
  VNET_DEV_CTR_VENDOR (MLX5_TXQ_CTR_CQ_OVERFLOW, TX, DESCRIPTORS, "cq overflow"),
  VNET_DEV_CTR_VENDOR (MLX5_TXQ_CTR_REQ_CQE_ERROR, TX, DESCRIPTORS, "req cqe error"),
  VNET_DEV_CTR_VENDOR (MLX5_TXQ_CTR_REQ_CQE_FLUSH_ERROR, TX, DESCRIPTORS, "req cqe flush error"),
  VNET_DEV_CTR_VENDOR (MLX5_TXQ_CTR_LOCAL_OP_ERROR, TX, DESCRIPTORS, "local op error"),
  VNET_DEV_CTR_VENDOR (MLX5_TXQ_CTR_REQ_BAD_RESPONSE, TX, DESCRIPTORS, "req bad response"),
  VNET_DEV_CTR_VENDOR (MLX5_TXQ_CTR_REQ_REMOTE_INV_REQ, TX, DESCRIPTORS, "req remote inv req"),
  VNET_DEV_CTR_VENDOR (MLX5_TXQ_CTR_REQ_REMOTE_ACCESS_ERR, TX, DESCRIPTORS,
		       "req remote access err"),
  VNET_DEV_CTR_VENDOR (MLX5_TXQ_CTR_REQ_REMOTE_OP_ERR, TX, DESCRIPTORS, "req remote op err"),
  VNET_DEV_CTR_VENDOR (MLX5_TXQ_CTR_REQ_RETRY_EXCEEDED, TX, DESCRIPTORS, "req retry exceeded"),
};

static int
mlx5_q_counter_is_unsupported (int rv_ibv, u32 status, u32 syndrome)
{
  if (rv_ibv && status == 0 && syndrome == 0)
    return 1;

  return 0;
}

vnet_dev_rv_t
mlx5_q_counter_setup (vnet_dev_t *dev, struct ibv_qp *qp, u8 *counter_set_id,
		      struct mlx5dv_devx_obj **counter_obj)
{
  mlx5_dev_t *rd = vnet_dev_get_data (dev);
  u32 in[DEVX_ST_SZ_DW (alloc_q_counter_in)] = {};
  u32 out[DEVX_ST_SZ_DW (alloc_q_counter_out)] = {};
  u32 min[DEVX_ST_SZ_DW (rts2rts_qp_in)] = {};
  u32 mout[DEVX_ST_SZ_DW (rts2rts_qp_out)] = {};
  struct mlx5dv_devx_obj *obj = 0;
  u32 status;
  u32 syndrome;
  int rv_ibv;

  if (rd->q_counter_disabled)
    return VNET_DEV_OK;

  DEVX_SET (alloc_q_counter_in, in, opcode, MLX5_CMD_OP_ALLOC_Q_COUNTER);
  obj = mlx5dv_devx_obj_create (rd->ctx, in, sizeof (in), out, sizeof (out));
  rv_ibv = obj == 0 ? errno : 0;
  status = DEVX_GET (alloc_q_counter_out, out, status);
  syndrome = DEVX_GET (alloc_q_counter_out, out, syndrome);
  if (rv_ibv || status)
    {
      if (rd->q_counter_disable_logged == 0)
	{
	  if (mlx5_q_counter_is_unsupported (rv_ibv, status, syndrome))
	    log_debug (dev, "q-counter unsupported, disabling per-queue hw counters");
	  else
	    log_notice (dev,
			"q-counter unavailable, disabling per-queue hw counters "
			"(alloc rv %d status 0x%x syndrome 0x%x)",
			rv_ibv, status, syndrome);
	  rd->q_counter_disable_logged = 1;
	}
      rd->q_counter_disabled = 1;
      *counter_set_id = 0;
      *counter_obj = 0;
      return VNET_DEV_OK;
    }

  *counter_set_id = DEVX_GET (alloc_q_counter_out, out, counter_set_id);
  *counter_obj = obj;

  DEVX_SET (rts2rts_qp_in, min, opcode, MLX5_CMD_OP_RTS2RTS_QP);
  DEVX_SET (rts2rts_qp_in, min, qpn, qp->qp_num);
  DEVX_SET (rts2rts_qp_in, min, opt_param_mask, MLX5_QP_OPTPAR_COUNTER_SET_ID);
  DEVX_SET (rts2rts_qp_in, min, qpc.counter_set_id, *counter_set_id);

  rv_ibv = mlx5dv_devx_qp_modify (qp, min, sizeof (min), mout, sizeof (mout));
  status = DEVX_GET (rts2rts_qp_out, mout, status);
  syndrome = DEVX_GET (rts2rts_qp_out, mout, syndrome);
  if (rv_ibv || status)
    {
      u32 din[DEVX_ST_SZ_DW (dealloc_q_counter_in)] = {};
      u32 dout[DEVX_ST_SZ_DW (dealloc_q_counter_out)] = {};

      if (rd->q_counter_disable_logged == 0)
	{
	  if (mlx5_q_counter_is_unsupported (rv_ibv, status, syndrome))
	    log_debug (dev, "q-counter unsupported, disabling per-queue hw counters");
	  else
	    log_notice (dev,
			"q-counter unavailable, disabling per-queue hw counters "
			"(rts2rts rv %d status 0x%x syndrome 0x%x)",
			rv_ibv, status, syndrome);
	  rd->q_counter_disable_logged = 1;
	}
      DEVX_SET (dealloc_q_counter_in, din, opcode, MLX5_CMD_OP_DEALLOC_Q_COUNTER);
      DEVX_SET (dealloc_q_counter_in, din, counter_set_id, *counter_set_id);
      mlx5dv_devx_general_cmd (rd->ctx, din, sizeof (din), dout, sizeof (dout));
      if (*counter_obj)
	{
	  mlx5dv_devx_obj_destroy (*counter_obj);
	  *counter_obj = 0;
	}
      rd->q_counter_disabled = 1;
      *counter_set_id = 0;
      return VNET_DEV_OK;
    }

  return VNET_DEV_OK;
}

void
mlx5_q_counter_teardown (u8 *counter_set_id, struct mlx5dv_devx_obj **counter_obj)
{
  if (*counter_obj == 0)
    return;

  mlx5dv_devx_obj_destroy (*counter_obj);
  *counter_obj = 0;
  *counter_set_id = 0;
}

static void
mlx5_port_counter_poll_port (vlib_main_t *vm, vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  mlx5_dev_t *rd = vnet_dev_get_data (dev);
  mlx5_port_t *mp = vnet_dev_get_port_data (port);
  u32 in[DEVX_ST_SZ_DW (query_vnic_env_in)] = {};
  u32 out[DEVX_ST_SZ_DW (query_vnic_env_out)] = {};
  void *vport_env;
  int rv_ibv;
  u64 values[MLX5_PORT_VAL_N] = {};

  if (port->counter_main == 0)
    return;

  DEVX_SET (query_vnic_env_in, in, opcode, MLX5_CMD_OP_QUERY_VNIC_ENV);
  DEVX_SET (query_vnic_env_in, in, op_mod, MLX5_QUERY_VNIC_ENV_IN_OP_MOD_VPORT_DIAG_STATISTICS);
  DEVX_SET (query_vnic_env_in, in, other_vport, 0);
  DEVX_SET (query_vnic_env_in, in, vport_number, 0);
  rv_ibv = mlx5dv_devx_general_cmd (rd->ctx, in, sizeof (in), out, sizeof (out));
  if (rv_ibv || DEVX_GET (query_vnic_env_out, out, status) != 0)
    {
      if (mp->counters_query_failed == 0)
	{
	  log_err (dev, "failed to query HW counters, suppressing repeated errors");
	  mp->counters_query_failed = 1;
	}
      return;
    }
  vport_env = DEVX_ADDR_OF (query_vnic_env_out, out, vport_env);
  values[MLX5_PORT_VAL_RX_STEERING_DISCARD] =
    DEVX_GET64 (vnic_diagnostic_statistics, vport_env, nic_receive_steering_discard);
  values[MLX5_PORT_VAL_RX_VPORT_DOWN] =
    DEVX_GET64 (vnic_diagnostic_statistics, vport_env, receive_discard_vport_down);
  values[MLX5_PORT_VAL_RX_NO_BUFFER] =
    DEVX_GET (vnic_diagnostic_statistics, vport_env, internal_rq_out_of_buffer);
  values[MLX5_PORT_VAL_ERROR_QUEUES] =
    DEVX_GET (vnic_diagnostic_statistics, vport_env, counter_error_queues);
  values[MLX5_PORT_VAL_TOTAL_ERROR_QUEUES] =
    DEVX_GET (vnic_diagnostic_statistics, vport_env, total_error_queues);
  values[MLX5_PORT_VAL_SQ_PRI_UPDATE_FLOW] =
    DEVX_GET (vnic_diagnostic_statistics, vport_env, send_queue_priority_update_flow);
  values[MLX5_PORT_VAL_ASYNC_EQ_OVERRUN] =
    DEVX_GET (vnic_diagnostic_statistics, vport_env, async_eq_overrun);
  values[MLX5_PORT_VAL_COMP_EQ_OVERRUN] =
    DEVX_GET (vnic_diagnostic_statistics, vport_env, comp_eq_overrun);
  values[MLX5_PORT_VAL_INVALID_COMMAND] =
    DEVX_GET (vnic_diagnostic_statistics, vport_env, invalid_command);
  values[MLX5_PORT_VAL_QUOTA_EXCEEDED_COMMAND] =
    DEVX_GET (vnic_diagnostic_statistics, vport_env, quota_exceeded_command);
  values[MLX5_PORT_VAL_CQ_OVERRUN] = DEVX_GET (vnic_diagnostic_statistics, vport_env, cq_overrun);
  values[MLX5_PORT_VAL_ETH_WQE_TOO_SMALL] =
    DEVX_GET (vnic_diagnostic_statistics, vport_env, eth_wqe_too_small);
  values[MLX5_PORT_VAL_STEERING_FAIL_GENERATED] =
    DEVX_GET64 (vnic_diagnostic_statistics, vport_env, generated_pkt_steering_fail);
  values[MLX5_PORT_VAL_STEERING_FAIL_HANDLED] =
    DEVX_GET64 (vnic_diagnostic_statistics, vport_env, handled_pkt_steering_fail);
  values[MLX5_PORT_VAL_TX_VPORT_DOWN] =
    DEVX_GET64 (vnic_diagnostic_statistics, vport_env, transmit_discard_vport_down);
  values[MLX5_PORT_VAL_RX_DROPS] = values[MLX5_PORT_VAL_RX_STEERING_DISCARD] +
				   values[MLX5_PORT_VAL_RX_VPORT_DOWN] +
				   values[MLX5_PORT_VAL_RX_NO_BUFFER];

  if (mp->counters_query_failed)
    {
      log_notice (dev, "HW counters query recovered");
      mp->counters_query_failed = 0;
    }

  foreach_vnet_dev_counter (c, port->counter_main)
    vnet_dev_counter_value_update (vm, c, values[c->user_data]);
}

static void
mlx5_port_counter_poll_rxq (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq)
{
  vnet_dev_t *dev = rxq->port->dev;
  mlx5_dev_t *rd = vnet_dev_get_data (dev);
  mlx5_rxq_t *mq = vnet_dev_get_rx_queue_data (rxq);
  vnet_dev_counter_t *rxq_counters;
  u32 in[DEVX_ST_SZ_DW (query_q_counter_in)] = {};
  u32 out[DEVX_ST_SZ_DW (query_q_counter_out)] = {};
  int rv_ibv;
  u64 drops = 0;

  if (mq->q_counter_valid == 0 || rxq->counter_main == 0)
    return;
  rxq_counters = rxq->counter_main->counters;

  DEVX_SET (query_q_counter_in, in, opcode, MLX5_CMD_OP_QUERY_Q_COUNTER);
  DEVX_SET (query_q_counter_in, in, counter_set_id, mq->q_counter_set_id);
  rv_ibv = mlx5dv_devx_general_cmd (rd->ctx, in, sizeof (in), out, sizeof (out));
  if (rv_ibv || DEVX_GET (query_q_counter_out, out, status))
    {
      if (mq->q_counter_query_failed == 0)
	{
	  log_err (dev, "rxq %u failed to query q-counter, suppressing repeated errors",
		   rxq->queue_id);
	  mq->q_counter_query_failed = 1;
	}
      return;
    }
  drops = DEVX_GET (query_q_counter_out, out, out_of_buffer);
  vnet_dev_counter_value_update (vm, rxq_counters + MLX5_RXQ_CTR_CQ_OVERFLOW,
				 DEVX_GET (query_q_counter_out, out, cq_overflow));

  if (mq->q_counter_query_failed)
    {
      log_notice (dev, "rxq %u q-counter query recovered", rxq->queue_id);
      mq->q_counter_query_failed = 0;
    }

  vnet_dev_counter_value_update (vm, rxq_counters + MLX5_RXQ_CTR_DROPS_HW, drops);
}

static void
mlx5_port_counter_poll_txq (vlib_main_t *vm, vnet_dev_tx_queue_t *txq)
{
  vnet_dev_t *dev = txq->port->dev;
  mlx5_dev_t *rd = vnet_dev_get_data (dev);
  mlx5_txq_t *tq = vnet_dev_get_tx_queue_data (txq);
  vnet_dev_counter_t *txq_counters;
  u32 in[DEVX_ST_SZ_DW (query_q_counter_in)] = {};
  u32 out[DEVX_ST_SZ_DW (query_q_counter_out)] = {};
  int rv_ibv;
  u64 hw_drops;

  if (tq->q_counter_valid == 0 || txq->counter_main == 0)
    return;
  txq_counters = txq->counter_main->counters;

  DEVX_SET (query_q_counter_in, in, opcode, MLX5_CMD_OP_QUERY_Q_COUNTER);
  DEVX_SET (query_q_counter_in, in, counter_set_id, tq->q_counter_set_id);
  rv_ibv = mlx5dv_devx_general_cmd (rd->ctx, in, sizeof (in), out, sizeof (out));
  if (rv_ibv || DEVX_GET (query_q_counter_out, out, status))
    {
      if (tq->q_counter_query_failed == 0)
	{
	  log_err (dev, "txq %u failed to query q-counter, suppressing repeated errors",
		   txq->queue_id);
	  tq->q_counter_query_failed = 1;
	}
      return;
    }

  if (tq->q_counter_query_failed)
    {
      log_notice (dev, "txq %u q-counter query recovered", txq->queue_id);
      tq->q_counter_query_failed = 0;
    }

  vnet_dev_counter_value_update (vm, txq_counters + MLX5_TXQ_CTR_CQ_OVERFLOW,
				 DEVX_GET (query_q_counter_out, out, cq_overflow));
  vnet_dev_counter_value_update (vm, txq_counters + MLX5_TXQ_CTR_REQ_CQE_ERROR,
				 DEVX_GET (query_q_counter_out, out, req_cqe_error));
  vnet_dev_counter_value_update (vm, txq_counters + MLX5_TXQ_CTR_REQ_CQE_FLUSH_ERROR,
				 DEVX_GET (query_q_counter_out, out, req_cqe_flush_error));
  vnet_dev_counter_value_update (vm, txq_counters + MLX5_TXQ_CTR_LOCAL_OP_ERROR,
				 DEVX_GET (query_q_counter_out, out, local_operation_error));
  vnet_dev_counter_value_update (vm, txq_counters + MLX5_TXQ_CTR_REQ_BAD_RESPONSE,
				 DEVX_GET (query_q_counter_out, out, req_bad_response));
  vnet_dev_counter_value_update (vm, txq_counters + MLX5_TXQ_CTR_REQ_REMOTE_INV_REQ,
				 DEVX_GET (query_q_counter_out, out, req_remote_invalid_request));
  vnet_dev_counter_value_update (vm, txq_counters + MLX5_TXQ_CTR_REQ_REMOTE_ACCESS_ERR,
				 DEVX_GET (query_q_counter_out, out, req_remote_access_errors));
  vnet_dev_counter_value_update (vm, txq_counters + MLX5_TXQ_CTR_REQ_REMOTE_OP_ERR,
				 DEVX_GET (query_q_counter_out, out, req_remote_operation_errors));
  vnet_dev_counter_value_update (
    vm, txq_counters + MLX5_TXQ_CTR_REQ_RETRY_EXCEEDED,
    DEVX_GET (query_q_counter_out, out, req_transport_retries_exceeded));

  hw_drops = DEVX_GET (query_q_counter_out, out, cq_overflow) +
	     DEVX_GET (query_q_counter_out, out, req_cqe_error) +
	     DEVX_GET (query_q_counter_out, out, req_cqe_flush_error);
  vnet_dev_counter_value_update (vm, txq_counters + MLX5_TXQ_CTR_DROPS_HW, hw_drops);
}

void
mlx5_port_counter_poll (vlib_main_t *vm, vnet_dev_port_t *port)
{
  mlx5_port_counter_poll_port (vm, port);
  foreach_vnet_dev_port_rx_queue (rxq, port)
    mlx5_port_counter_poll_rxq (vm, rxq);
  foreach_vnet_dev_port_tx_queue (txq, port)
    mlx5_port_counter_poll_txq (vm, txq);
}

vnet_dev_rv_t
mlx5_port_init_counters (vlib_main_t *vm, vnet_dev_port_t *port)
{
  if (port->counter_main == 0)
    vnet_dev_port_add_counters (vm, port, mlx5_port_counters, ARRAY_LEN (mlx5_port_counters));

  foreach_vnet_dev_port_rx_queue (rxq, port)
    if (rxq->counter_main == 0)
      vnet_dev_rx_queue_add_counters (vm, rxq, mlx5_rxq_counters, ARRAY_LEN (mlx5_rxq_counters));

  foreach_vnet_dev_port_tx_queue (txq, port)
    if (txq->counter_main == 0)
      vnet_dev_tx_queue_add_counters (vm, txq, mlx5_txq_counters, ARRAY_LEN (mlx5_txq_counters));

  return VNET_DEV_OK;
}
