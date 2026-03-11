/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2018 Cisco and/or its affiliates.
 */

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/flow/flow.h>

vnet_flow_main_t flow_main;

static_always_inline vnet_flow_if_data_t *
vnet_flow_get_if_data (vnet_flow_t *f, u32 hw_if_index)
{
  vnet_flow_if_data_t *d;
  vec_foreach (d, f->if_data)
    if (d->hw_if_index == hw_if_index)
      return d;
  return 0;
}

int
vnet_flow_add (vnet_main_t * vnm, vnet_flow_t * flow, u32 * flow_index)
{
  vnet_flow_main_t *fm = &flow_main;
  vnet_flow_t *f;

  pool_get (fm->global_flow_pool, f);
  *flow_index = f - fm->global_flow_pool;
  clib_memcpy_fast (f, flow, sizeof (vnet_flow_t));
  f->if_data = 0;
  f->index = *flow_index;
  return 0;
}

vnet_flow_t *
vnet_get_flow (u32 flow_index)
{
  vnet_flow_main_t *fm = &flow_main;
  if (pool_is_free_index (fm->global_flow_pool, flow_index))
    return 0;

  return pool_elt_at_index (fm->global_flow_pool, flow_index);
}

int
vnet_flow_del (vnet_main_t * vnm, u32 flow_index)
{
  vnet_flow_main_t *fm = &flow_main;
  vnet_flow_t *f = vnet_get_flow (flow_index);

  if (f == 0)
    return VNET_FLOW_ERROR_NO_SUCH_ENTRY;

  /* vnet_flow_del remove the element from the vector */
  for (int i = vec_len (f->if_data) - 1; i >= 0; i--)
    vnet_flow_disable (vnm, flow_index, f->if_data[i].hw_if_index);

  vec_free (f->if_data);
  clib_memset (f, 0, sizeof (*f));
  pool_put (fm->global_flow_pool, f);
  return 0;
}

int
vnet_flow_enable (vnet_main_t * vnm, u32 flow_index, u32 hw_if_index)
{
  vnet_flow_t *f = vnet_get_flow (flow_index);
  vnet_hw_interface_t *hi;
  vnet_device_class_t *dev_class;
  vnet_flow_if_data_t *d;
  uword private_data;
  int rv;

  if (f == 0)
    return VNET_FLOW_ERROR_NO_SUCH_ENTRY;

  if (!vnet_hw_interface_is_valid (vnm, hw_if_index))
    return VNET_FLOW_ERROR_NO_SUCH_INTERFACE;

  /* don't enable flow twice */
  if (vnet_flow_get_if_data (f, hw_if_index) != 0)
    return VNET_FLOW_ERROR_ALREADY_DONE;

  hi = vnet_get_hw_interface (vnm, hw_if_index);
  dev_class = vnet_get_device_class (vnm, hi->dev_class_index);

  if (dev_class->flow_ops_function == 0)
    return VNET_FLOW_ERROR_NOT_SUPPORTED;

  if (f->actions & VNET_FLOW_ACTION_REDIRECT_TO_NODE)
    {
      vnet_hw_interface_t *hw = vnet_get_hw_interface (vnm, hw_if_index);
      f->redirect_device_input_next_index =
	vlib_node_add_next (vnm->vlib_main, hw->input_node_index,
			    f->redirect_node_index);
    }

  rv = dev_class->flow_ops_function (vnm, VNET_FLOW_DEV_OP_ADD_FLOW,
				     hi->dev_instance, flow_index,
				     &private_data);

  if (rv)
    return rv;

  vec_add2 (f->if_data, d, 1);
  d->hw_if_index = hw_if_index;
  d->private_data = private_data;
  return 0;
}

int
vnet_flow_disable (vnet_main_t * vnm, u32 flow_index, u32 hw_if_index)
{
  vnet_flow_t *f = vnet_get_flow (flow_index);
  vnet_hw_interface_t *hi;
  vnet_device_class_t *dev_class;
  vnet_flow_if_data_t *d;
  int rv;

  if (f == 0)
    return VNET_FLOW_ERROR_NO_SUCH_ENTRY;

  if (!vnet_hw_interface_is_valid (vnm, hw_if_index))
    return VNET_FLOW_ERROR_NO_SUCH_INTERFACE;

  /* don't disable if not enabled */
  if ((d = vnet_flow_get_if_data (f, hw_if_index)) == 0)
    return VNET_FLOW_ERROR_ALREADY_DONE;

  hi = vnet_get_hw_interface (vnm, hw_if_index);
  dev_class = vnet_get_device_class (vnm, hi->dev_class_index);

  if (dev_class->flow_ops_function == 0)
    return VNET_FLOW_ERROR_NOT_SUPPORTED;

  rv = dev_class->flow_ops_function (vnm, VNET_FLOW_DEV_OP_DEL_FLOW, hi->dev_instance, flow_index,
				     &d->private_data);

  if (rv)
    return rv;

  vec_del1 (f->if_data, d - f->if_data);
  return 0;
}
