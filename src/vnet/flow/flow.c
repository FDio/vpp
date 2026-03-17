/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2018 Cisco and/or its affiliates.
 */

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/flow/flow.h>

vnet_flow_main_t flow_main;

int
vnet_flow_add (vnet_main_t *vnm, vnet_flow_t *flow, u32 *flow_index)
{
  vnet_flow_main_t *fm = &flow_main;
  vnet_flow_t *f;

  if ((flow->actions & VNET_FLOW_ACTION_MARK) && flow->mark_flow_id == VNET_FLOW_MARK_INVALID)
    return VNET_FLOW_ERROR_INVALID_VALUE;

  pool_get (fm->global_flow_pool, f);
  *flow_index = f - fm->global_flow_pool;
  clib_memcpy_fast (f, flow, sizeof (vnet_flow_t));
  f->driver_data.opaque = ~0;
  f->driver_data.hw_if_index = ~0;
  f->index = *flow_index;
  return 0;
}

static_always_inline int
vnet_flow_enable_disable (vnet_main_t *vnm, u32 flow_index, u32 hw_if_index, bool enable)
{
  vnet_flow_t *f = vnet_get_flow (flow_index);
  vnet_flow_dev_op_t op = enable ? VNET_FLOW_DEV_OP_ADD_FLOW : VNET_FLOW_DEV_OP_DEL_FLOW;
  vnet_hw_interface_t *hi;
  vnet_device_class_t *dev_class;
  int rv;

  if (f == 0)
    return VNET_FLOW_ERROR_NO_SUCH_ENTRY;

  /* don't enable flow twice or don't disable if not enabled */
  if ((enable && f->driver_data.hw_if_index != ~0) || (!enable && f->driver_data.hw_if_index == ~0))
    return VNET_FLOW_ERROR_ALREADY_DONE;

  if (!enable)
    hw_if_index = f->driver_data.hw_if_index;

  if (!vnet_hw_interface_is_valid (vnm, hw_if_index))
    return VNET_FLOW_ERROR_NO_SUCH_INTERFACE;

  hi = vnet_get_hw_interface (vnm, hw_if_index);
  dev_class = vnet_get_device_class (vnm, hi->dev_class_index);

  if (dev_class->flow_ops_function == 0)
    return VNET_FLOW_ERROR_NOT_SUPPORTED;

  if (enable && f->actions & VNET_FLOW_ACTION_REDIRECT_TO_NODE)
    {
      vnet_hw_interface_t *hw = vnet_get_hw_interface (vnm, hw_if_index);
      f->redirect_device_input_next_index =
	vlib_node_add_next (vnm->vlib_main, hw->input_node_index, f->redirect_node_index);
    }

  rv = dev_class->flow_ops_function (vnm, op, hi->dev_instance, flow_index);
  if (rv)
    return rv;
  return 0;
}

int
vnet_flow_del (vnet_main_t *vnm, u32 flow_index)
{
  vnet_flow_main_t *fm = &flow_main;
  vnet_flow_t *f = vnet_get_flow (flow_index);
  int rv;

  rv = vnet_flow_enable_disable (vnm, flow_index, ~0, false);
  if (rv && rv != VNET_FLOW_ERROR_ALREADY_DONE)
    return rv;

  clib_memset (f, 0, sizeof (*f));
  pool_put (fm->global_flow_pool, f);
  return 0;
}

int
vnet_flow_enable (vnet_main_t *vnm, u32 flow_index, u32 hw_if_index)
{
  return vnet_flow_enable_disable (vnm, flow_index, hw_if_index, true);
}

int
vnet_flow_disable (vnet_main_t *vnm, u32 flow_index)
{
  return vnet_flow_enable_disable (vnm, flow_index, ~0, false);
}
