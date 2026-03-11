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

static_always_inline vnet_flow_t *
vnet_get_flow_inline (u32 flow_index, bool template)
{
  vnet_flow_main_t *fm = &flow_main;
  vnet_flow_t *pool = template ? fm->global_flow_template_pool : fm->global_flow_pool;

  if (pool_is_free_index (pool, flow_index))
    return 0;

  return pool_elt_at_index (pool, flow_index);
}

static_always_inline int
vnet_flow_add_inline (vnet_main_t *vnm, vnet_flow_t *flow, u32 *flow_index, bool template)
{
  vnet_flow_main_t *fm = &flow_main;
  vnet_flow_t **ppool = template ? &fm->global_flow_template_pool : &fm->global_flow_pool;
  vnet_flow_t *pool = *ppool;
  vnet_flow_t *f;

  pool_get (pool, f);
  *flow_index = f - pool;
  clib_memcpy_fast (f, flow, sizeof (vnet_flow_t));
  f->if_data = 0;
  f->index = *flow_index;
  *ppool = pool;
  return 0;
}

static_always_inline int
vnet_flow_enable_inline (vnet_main_t *vnm, u32 flow_index, u32 hw_if_index,
			 uword passed_private_data, bool template)
{
  vnet_flow_t *f = vnet_get_flow_inline (flow_index, template);
  vnet_flow_dev_ops_function_t *dev_ops_function;
  vnet_hw_interface_t *hi;
  vnet_device_class_t *dev_class;
  vnet_flow_if_data_t *d;
  uword private_data = passed_private_data;
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

  if (template)
    dev_ops_function = dev_class->flow_template_ops_function;
  else
    dev_ops_function = dev_class->flow_ops_function;

  if (dev_ops_function == 0)
    return VNET_FLOW_ERROR_NOT_SUPPORTED;

  if (!template && f->actions & VNET_FLOW_ACTION_REDIRECT_TO_NODE)
    {
      vnet_hw_interface_t *hw = vnet_get_hw_interface (vnm, hw_if_index);
      f->redirect_device_input_next_index =
	vlib_node_add_next (vnm->vlib_main, hw->input_node_index,
			    f->redirect_node_index);
    }

  rv =
    dev_ops_function (vnm, VNET_FLOW_DEV_OP_ADD_FLOW, hi->dev_instance, flow_index, &private_data);

  if (rv)
    return rv;

  vec_add2 (f->if_data, d, 1);
  d->hw_if_index = hw_if_index;
  d->private_data = private_data;
  return 0;
}

static_always_inline int
vnet_flow_disable_inline (vnet_main_t *vnm, u32 flow_index, u32 hw_if_index, bool template)
{
  vnet_flow_t *f = vnet_get_flow_inline (flow_index, template);
  vnet_flow_dev_ops_function_t *dev_ops_function;
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

  if (template)
    dev_ops_function = dev_class->flow_template_ops_function;
  else
    dev_ops_function = dev_class->flow_ops_function;

  if (dev_ops_function == 0)
    return VNET_FLOW_ERROR_NOT_SUPPORTED;

  rv = dev_ops_function (vnm, VNET_FLOW_DEV_OP_DEL_FLOW, hi->dev_instance, flow_index,
			 &d->private_data);

  if (rv)
    return rv;

  vec_del1 (f->if_data, d - f->if_data);
  return 0;
}

static_always_inline int
vnet_flow_del_inline (vnet_main_t *vnm, u32 flow_index, bool template)
{
  vnet_flow_main_t *fm = &flow_main;
  vnet_flow_t **ppool = template ? &fm->global_flow_template_pool : &fm->global_flow_pool;
  vnet_flow_t *pool = *ppool;
  vnet_flow_t *f = vnet_get_flow_inline (flow_index, template);

  if (f == 0)
    return VNET_FLOW_ERROR_NO_SUCH_ENTRY;

  /* vnet_flow_del remove the element from the vector */
  for (int i = vec_len (f->if_data) - 1; i >= 0; i--)
    vnet_flow_disable_inline (vnm, flow_index, f->if_data[i].hw_if_index, template);

  vec_free (f->if_data);
  clib_memset (f, 0, sizeof (*f));
  pool_put (pool, f);
  *ppool = pool;
  return 0;
}

int
vnet_flow_add (vnet_main_t *vnm, vnet_flow_t *flow, u32 *flow_index)
{
  return vnet_flow_add_inline (vnm, flow, flow_index, false);
}

vnet_flow_t *
vnet_get_flow (u32 flow_index)
{
  return vnet_get_flow_inline (flow_index, false);
}

int
vnet_flow_del (vnet_main_t *vnm, u32 flow_index)
{
  return vnet_flow_del_inline (vnm, flow_index, false);
}

int
vnet_flow_enable (vnet_main_t *vnm, u32 flow_index, u32 hw_if_index)
{
  return vnet_flow_enable_inline (vnm, flow_index, hw_if_index, 0, false);
}
int
vnet_flow_disable (vnet_main_t *vnm, u32 flow_index, u32 hw_if_index)
{
  return vnet_flow_disable_inline (vnm, flow_index, hw_if_index, false);
}

vnet_flow_t *
vnet_get_flow_template (u32 flow_template_index)
{
  return vnet_get_flow_inline (flow_template_index, true);
}

int
vnet_flow_template_add (vnet_main_t *vnm, vnet_flow_t *template, u32 *flow_template_index)
{
  return vnet_flow_add_inline (vnm, template, flow_template_index, true);
}

int
vnet_flow_template_del (vnet_main_t *vnm, u32 flow_template_index)
{
  return vnet_flow_del_inline (vnm, flow_template_index, true);
}

int
vnet_flow_template_enable (vnet_main_t *vnm, u32 flow_index, u32 hw_if_index, u32 n_flows)
{
  return vnet_flow_enable_inline (vnm, flow_index, hw_if_index, n_flows, true);
}
int
vnet_flow_template_disable (vnet_main_t *vnm, u32 flow_index, u32 hw_if_index)
{
  return vnet_flow_disable_inline (vnm, flow_index, hw_if_index, true);
}

int
vnet_flow_async_range_enable (vnet_main_t *vnm, u32 flow_template_index, u32 *flow_indices,
			      u32 hw_if_index)
{
  vnet_flow_t *template = vnet_get_flow_inline (flow_template_index, true);
  vnet_hw_interface_t *hi;
  vnet_device_class_t *dev_class;
  vnet_flow_if_data_t *template_data, *flow_data;
  uword *private_data;
  vnet_flow_t *f;
  u32 count = vec_len (flow_indices);
  u32 *fi;
  int i;
  int rv = 0;

  if (count == 0)
    return VNET_FLOW_ERROR_NO_SUCH_ENTRY;

  if (!template)
    return VNET_FLOW_ERROR_NO_SUCH_ENTRY;

  if (!vnet_hw_interface_is_valid (vnm, hw_if_index))
    return VNET_FLOW_ERROR_NO_SUCH_INTERFACE;

  if ((template_data = vnet_flow_get_if_data (template, hw_if_index)) == 0)
    return VNET_FLOW_ERROR_ALREADY_DONE;

  hi = vnet_get_hw_interface (vnm, hw_if_index);
  dev_class = vnet_get_device_class (vnm, hi->dev_class_index);

  if (dev_class->flow_async_ops_function == 0)
    return VNET_FLOW_ERROR_NOT_SUPPORTED;

  private_data = clib_mem_alloc (sizeof (uword) * count);

  /* Pre-validation loop using direct pool access */
  i = 0;
  vec_foreach (fi, flow_indices)
    {
      f = vnet_get_flow_inline (*fi, false);

      if (!f)
	{
	  rv = VNET_FLOW_ERROR_NO_SUCH_ENTRY;
	  goto error;
	}

      /* don't enable flow twice */
      if (vnet_flow_get_if_data (f, hw_if_index))
	{
	  rv = VNET_FLOW_ERROR_ALREADY_DONE;
	  goto error;
	}

      if (f->actions & VNET_FLOW_ACTION_REDIRECT_TO_NODE)
	{
	  vnet_hw_interface_t *hw = vnet_get_hw_interface (vnm, hw_if_index);
	  f->redirect_device_input_next_index =
	    vlib_node_add_next (vnm->vlib_main, hw->input_node_index, f->redirect_node_index);
	}

      private_data[i++] = ~0;
    }

  rv =
    dev_class->flow_async_ops_function (vnm, VNET_FLOW_DEV_OP_ADD_FLOW, hi->dev_instance,
					flow_indices, &template_data->private_data, private_data);

  /* Check for failure after, as insertion could have worked for some flows. */
  i = 0;
  vec_foreach (fi, flow_indices)
    {
      f = vnet_get_flow_inline (*fi, false);
      if (private_data[i] != ~0)
	{
	  vec_add2 (f->if_data, flow_data, 1);
	  flow_data->hw_if_index = hw_if_index;
	  flow_data->private_data = private_data[i];
	}
      i++;
    }

  if (rv)
    goto error;

error:
  clib_mem_free (private_data);
  return rv;
}

int
vnet_flow_async_range_disable (vnet_main_t *vnm, u32 *flow_indices, u32 hw_if_index)
{
  vnet_hw_interface_t *hi;
  vnet_device_class_t *dev_class;
  vnet_flow_if_data_t *flow_data;
  uword *private_data;
  vnet_flow_t *f;
  u32 count = vec_len (flow_indices);
  u32 *fi;
  int i;
  int rv = 0;

  if (count == 0)
    return VNET_FLOW_ERROR_NO_SUCH_ENTRY;

  if (!vnet_hw_interface_is_valid (vnm, hw_if_index))
    return VNET_FLOW_ERROR_NO_SUCH_INTERFACE;

  hi = vnet_get_hw_interface (vnm, hw_if_index);
  dev_class = vnet_get_device_class (vnm, hi->dev_class_index);

  if (dev_class->flow_async_ops_function == 0)
    return VNET_FLOW_ERROR_NOT_SUPPORTED;

  private_data = clib_mem_alloc (sizeof (uword) * count);

  i = 0;
  vec_foreach (fi, flow_indices)
    {
      f = vnet_get_flow_inline (*fi, false);

      if (!f)
	{
	  rv = VNET_FLOW_ERROR_NO_SUCH_ENTRY;
	  goto error;
	}

      /* don't disable if not enabled */
      if ((flow_data = vnet_flow_get_if_data (f, hw_if_index)) == 0)
	{
	  rv = VNET_FLOW_ERROR_ALREADY_DONE;
	  goto error;
	}

      private_data[i++] = flow_data->private_data;
    }

  /* flow template private data is not needed to disable flows */
  rv = dev_class->flow_async_ops_function (vnm, VNET_FLOW_DEV_OP_DEL_FLOW, hi->dev_instance,
					   flow_indices, NULL, private_data);

  /* Check for failure after, as deletion could have worked for some flows.
   * We expect the device class function to set ~0 if the flow is deleted.
   */
  i = 0;
  vec_foreach (fi, flow_indices)
    {
      f = vnet_get_flow_inline (*fi, false);
      flow_data = vnet_flow_get_if_data (f, hw_if_index);
      if (private_data[i++] == ~0)
	vec_del1 (f->if_data, flow_data - f->if_data);
    }

  if (rv)
    goto error;

error:
  clib_mem_free (private_data);
  return rv;
}
