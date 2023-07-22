
/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>

#define VNET_DEV_MGMT_LOG2_N_OPS 6

typedef struct
{
  u16 head, tail;
  vnet_dev_mgmt_op_t mgmt_ops[1 << VNET_DEV_MGMT_LOG2_N_OPS];
} vnet_dev_mgmt_main_t;

vnet_dev_mgmt_main_t mgmt_main = {};

static void
_vnet_dev_exec_op (vlib_main_t *vm, vnet_dev_mgmt_op_t *op)
{
  ASSERT (vm->thread_index == op->thread_index);

  if (op->action == VNET_DEV_MGMT_OP_ACTION_RX_QUEUE_ASSIGN ||
      op->action == VNET_DEV_MGMT_OP_ACTION_RX_QUEUE_UNASSIGN)
    {
      vnet_hw_if_rx_node_runtime_t *rtd;
      vnet_dev_rx_queue_t *rxq = op->rx_queue;
      u32 node_index = rxq->port->rx_node_index;

      rtd = vlib_node_get_runtime_data (vm, node_index);

      if (op->action == VNET_DEV_MGMT_OP_ACTION_RX_QUEUE_ASSIGN)
	{
	  rtd->rx_queues[rtd->n_rx_queues++] = op->rx_queue;
	  if (rtd->n_rx_queues == 1)
	    vlib_node_set_state (vm, node_index, VLIB_NODE_STATE_POLLING);
	  __atomic_store_n (&rxq->rx_thread_assigned, 1, __ATOMIC_RELEASE);
	}
      else if (op->action == VNET_DEV_MGMT_OP_ACTION_RX_QUEUE_UNASSIGN)
	{
	  u32 i;
	  for (i = 0; i < rtd->n_rx_queues; i++)
	    if (rtd->rx_queues[i] == op->rx_queue)
	      break;
	  rtd->n_rx_queues--;
	  for (; i < rtd->n_rx_queues; i++)
	    rtd->rx_queues[i] = rtd->rx_queues[i + 1];
	  if (rtd->n_rx_queues == 0)
	    vlib_node_set_state (vm, node_index, VLIB_NODE_STATE_DISABLED);
	  __atomic_store_n (&rxq->rx_thread_assigned, 0, __ATOMIC_RELEASE);
	}
    }
}

static uword
dev_mgmt_fn (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  vnet_dev_mgmt_main_t *mm = &mgmt_main;
  u16 thread_index = vm->thread_index;
  const u16 mask = pow2_mask (VNET_DEV_MGMT_LOG2_N_OPS);
  u16 rv = 0, n_for_us = 0;
  u16 head = __atomic_load_n (&mm->head, __ATOMIC_ACQUIRE);
  u16 tail = __atomic_load_n (&mm->tail, __ATOMIC_ACQUIRE);

  if (head == tail)
    return 0;

  for (u16 i = tail; i < head; i++)
    if (mm->mgmt_ops[i & mask].thread_index == thread_index)
      n_for_us++;

  if (n_for_us == 0)
    return 0;

  for (u16 i = tail; i < head; i++)
    {
      vnet_dev_mgmt_op_t *op = mm->mgmt_ops + (i & mask);

      if (op->thread_index != thread_index)
	break;

      _vnet_dev_exec_op (vm, op);
      __atomic_store_n (&mm->tail, ++tail, __ATOMIC_RELEASE);

      if (--n_for_us == 0)
	break;
    }

  if (n_for_us)
    vlib_node_set_interrupt_pending (vm, node->node_index);

  return rv;
}

VLIB_REGISTER_NODE (dev_mgmt_node) = {
  .function = dev_mgmt_fn,
  .name = "dev-mgmt",
  .type = VLIB_NODE_TYPE_PRE_INPUT,
  .state = VLIB_NODE_STATE_INTERRUPT,
};

void
vnet_dev_mgmt_add_action (vlib_main_t *vm, vnet_dev_mgmt_op_t *ops, u32 n)
{
  vnet_dev_mgmt_main_t *mm = &mgmt_main;
  const u16 n_ops = 1u << VNET_DEV_MGMT_LOG2_N_OPS;
  const u16 mask = pow2_mask (VNET_DEV_MGMT_LOG2_N_OPS);
  u16 head = mm->head;
  u16 tail = __atomic_load_n (&mm->tail, __ATOMIC_ACQUIRE);
  u16 n_tries = 10;
  f64 t = 1e-5;

  if (head == tail)
    {
      for (; n > 0 && ops[0].thread_index == vm->thread_index; ops++, n--)
	_vnet_dev_exec_op (vm, ops);
      if (n == 0)
	return;
    }

  while (n_tries-- && n_ops - (head - tail) < n)
    {
      vlib_process_suspend (vm, t);
      t *= 2;
      tail = __atomic_load_n (&mm->tail, __ATOMIC_ACQUIRE);
    }

  if (n_ops - (head - tail) < n)
    clib_panic ("dev-mgmt queue deadlock");

  for (u16 i = 0; i < n; i++)
    mm->mgmt_ops[(head + i) & mask] = ops[i];

  __atomic_store_n (&mm->head, head + n, __ATOMIC_RELEASE);

  for (u16 i = 0; i < n; i++)
    {
      vlib_node_set_interrupt_pending (
	vlib_get_main_by_index (ops[i].thread_index), dev_mgmt_node.index);
    }
}
