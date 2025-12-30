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
  MLX5_CMD_OP_QUERY_VNIC_ENV = 0x76f,
  MLX5_CMD_OP_QUERY_Q_COUNTER = 0x773,
  MLX5_QUERY_VNIC_ENV_IN_OP_MOD_VPORT_DIAG_STATISTICS = 0x0,
};

typedef enum
{
  MLX5_PORT_VAL_RX_DROPS,
  MLX5_PORT_VAL_RX_STEERING_DISCARD,
  MLX5_PORT_VAL_RX_VPORT_DOWN,
  MLX5_PORT_VAL_RX_NO_BUFFER,
  MLX5_PORT_VAL_TX_VPORT_DOWN,
  MLX5_PORT_VAL_N,
} mlx5_port_counter_value_id_t;

static vnet_dev_counter_t mlx5_port_counters[] = {
  VNET_DEV_CTR_RX_DROPS (MLX5_PORT_VAL_RX_DROPS),
  VNET_DEV_CTR_VENDOR (MLX5_PORT_VAL_RX_STEERING_DISCARD, RX, PACKETS, "steering discard"),
  VNET_DEV_CTR_VENDOR (MLX5_PORT_VAL_RX_VPORT_DOWN, RX, PACKETS, "vport down discard"),
  VNET_DEV_CTR_VENDOR (MLX5_PORT_VAL_RX_NO_BUFFER, RX, PACKETS, "rq out-of-buffer"),
  VNET_DEV_CTR_VENDOR (MLX5_PORT_VAL_TX_VPORT_DOWN, TX, PACKETS, "vport down discard"),
};

static vnet_dev_counter_t mlx5_rxq_counters[] = {
  VNET_DEV_CTR_RX_PACKETS (MLX5_RXQ_CTR_PACKETS),
  VNET_DEV_CTR_RX_BYTES (MLX5_RXQ_CTR_BYTES),
  VNET_DEV_CTR_RX_DROPS (MLX5_RXQ_CTR_DROPS_HW),
  VNET_DEV_CTR_VENDOR (MLX5_RXQ_CTR_IP4_CKSUM_BAD, RX, PACKETS, "ip4 cksum bad"),
};

static vnet_dev_counter_t mlx5_txq_counters[] = {
  VNET_DEV_CTR_TX_PACKETS (MLX5_TXQ_CTR_PACKETS),
  VNET_DEV_CTR_TX_BYTES (MLX5_TXQ_CTR_BYTES),
  VNET_DEV_CTR_TX_DROPS (MLX5_TXQ_CTR_DROPS),
  VNET_DEV_CTR_VENDOR (MLX5_TXQ_CTR_DROPS_HW, TX, PACKETS, "hw drops/errors"),
  VNET_DEV_CTR_VENDOR (MLX5_TXQ_CTR_BUFFER_PREPARE_FAIL, TX, PACKETS, "buffer prepare fail"),
};

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
  vnet_dev_port_add_counters (vm, port, mlx5_port_counters, ARRAY_LEN (mlx5_port_counters));

  foreach_vnet_dev_port_rx_queue (rxq, port)
    vnet_dev_rx_queue_add_counters (vm, rxq, mlx5_rxq_counters, ARRAY_LEN (mlx5_rxq_counters));

  foreach_vnet_dev_port_tx_queue (txq, port)
    vnet_dev_tx_queue_add_counters (vm, txq, mlx5_txq_counters, ARRAY_LEN (mlx5_txq_counters));

  return VNET_DEV_OK;
}
