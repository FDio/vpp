/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2018 Cisco and/or its affiliates.
 */

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/flow/flow.h>

vnet_flow_main_t flow_main;

static_always_inline int
vnet_flow_add_inline (vnet_main_t *vnm, vnet_flow_t *flow, u32 *flow_index, bool template)
{
  vnet_flow_main_t *fm = &flow_main;
  vnet_flow_t **ppool = template ? &fm->global_flow_template_pool : &fm->global_flow_pool;
  vnet_flow_t *pool = *ppool;
  vnet_flow_t *f;

  if ((flow->actions & VNET_FLOW_ACTION_MARK) && flow->mark_flow_id == VNET_FLOW_MARK_INVALID)
    return VNET_FLOW_ERROR_INVALID_VALUE;

  pool_get_aligned (pool, f, CLIB_CACHE_LINE_BYTES);
  *flow_index = f - pool;

  /* copy CL0 hot fields */
  f->type = flow->type;
  f->index = *flow_index;
  f->actions = flow->actions;
  f->mark_flow_id = flow->mark_flow_id;
  f->redirect_node_index = flow->redirect_node_index;
  f->redirect_device_input_next_index = flow->redirect_device_input_next_index;
  f->redirect_queue = flow->redirect_queue;
  f->buffer_advance = flow->buffer_advance;
  f->driver_data.opaque = ~0;
  f->driver_data.hw_if_index = ~0;
  f->n_flows = 0;

  /* copy pattern */
  if (flow->type == VNET_FLOW_TYPE_GENERIC)
    {
      f->generic_pattern = clib_mem_alloc (sizeof (generic_pattern_t));
      clib_memcpy_fast (f->generic_pattern, flow->generic_pattern, sizeof (generic_pattern_t));
    }
  else
    {
      uword sz = vnet_flow_pattern_size (flow->type);
      if (sz)
	clib_memcpy_fast (&f->pattern, &flow->pattern, sz);
      f->generic_pattern = 0;
    }

  /* copy cold fields */
  f->rss_types = flow->rss_types;
  f->rss_fun = flow->rss_fun;
  f->queue_index = flow->queue_index;
  f->queue_num = flow->queue_num;

  *ppool = pool;
  return 0;
}

int
vnet_flow_add (vnet_main_t *vnm, vnet_flow_t *flow, u32 *flow_index)
{
  return vnet_flow_add_inline (vnm, flow, flow_index, false);
}

static_always_inline int
vnet_flow_enable_disable (vnet_main_t *vnm, u32 flow_index, u32 hw_if_index, uword n_flows,
			  bool template, bool enable)
{
  vnet_flow_t *f = template ? vnet_get_flow_template (flow_index) : vnet_get_flow (flow_index);
  vnet_flow_dev_op_t op = enable ? VNET_FLOW_DEV_OP_ADD_FLOW : VNET_FLOW_DEV_OP_DEL_FLOW;
  vnet_flow_dev_ops_function_t *dev_ops_function;
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

  if (template)
    dev_ops_function = dev_class->flow_template_ops_function;
  else
    dev_ops_function = dev_class->flow_ops_function;

  if (dev_ops_function == 0)
    return VNET_FLOW_ERROR_NOT_SUPPORTED;

  if (enable && !template && f->actions & VNET_FLOW_ACTION_REDIRECT_TO_NODE)
    {
      vnet_hw_interface_t *hw = vnet_get_hw_interface (vnm, hw_if_index);
      f->redirect_device_input_next_index =
	vlib_node_add_next (vnm->vlib_main, hw->input_node_index, f->redirect_node_index);
    }

  if (enable && template)
    f->n_flows = n_flows;

  rv = dev_ops_function (vnm, op, hi->dev_instance, flow_index);
  if (rv)
    return rv;
  return 0;
}

static_always_inline int
vnet_flow_del_inline (vnet_main_t *vnm, u32 flow_index, bool template)
{
  vnet_flow_main_t *fm = &flow_main;
  vnet_flow_t **ppool = template ? &fm->global_flow_template_pool : &fm->global_flow_pool;
  vnet_flow_t *pool = *ppool;
  vnet_flow_t *f = template ? vnet_get_flow_template (flow_index) : vnet_get_flow (flow_index);
  int rv;

  rv = vnet_flow_enable_disable (vnm, flow_index, ~0, 0, template, false);
  if (rv && rv != VNET_FLOW_ERROR_ALREADY_DONE)
    return rv;

  if (f->generic_pattern)
    clib_mem_free (f->generic_pattern);

  clib_memset (f, 0, sizeof (*f));
  pool_put (pool, f);
  *ppool = pool;
  return 0;
}

int
vnet_flow_del (vnet_main_t *vnm, u32 flow_index)
{
  return vnet_flow_del_inline (vnm, flow_index, false);
}

int
vnet_flow_enable (vnet_main_t *vnm, u32 flow_index, u32 hw_if_index)
{
  return vnet_flow_enable_disable (vnm, flow_index, hw_if_index, 0, false, true);
}

int
vnet_flow_disable (vnet_main_t *vnm, u32 flow_index)
{
  return vnet_flow_enable_disable (vnm, flow_index, ~0, 0, false, false);
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
  return vnet_flow_enable_disable (vnm, flow_index, hw_if_index, n_flows, true, true);
}

int
vnet_flow_template_disable (vnet_main_t *vnm, u32 flow_index, u32 hw_if_index)
{
  return vnet_flow_enable_disable (vnm, flow_index, hw_if_index, 0, true, false);
}

int
vnet_flow_async_range_enable (vnet_main_t *vnm, u32 flow_template_index, u32 *flow_indices,
			      u32 hw_if_index)
{
  vnet_flow_t *template = vnet_get_flow_template (flow_template_index);
  vnet_hw_interface_t *hi;
  vnet_device_class_t *dev_class;
  vnet_flow_t *f;
  u32 count = vec_len (flow_indices);
  u32 *fi;
  int rv = 0;

  if (count == 0)
    return VNET_FLOW_ERROR_NO_SUCH_ENTRY;

  if (!template)
    return VNET_FLOW_ERROR_NO_SUCH_ENTRY;

  if (!vnet_hw_interface_is_valid (vnm, hw_if_index))
    return VNET_FLOW_ERROR_NO_SUCH_INTERFACE;

  if (template->driver_data.hw_if_index == ~0)
    return VNET_FLOW_ERROR_NOT_SUPPORTED;

  hi = vnet_get_hw_interface (vnm, hw_if_index);
  dev_class = vnet_get_device_class (vnm, hi->dev_class_index);

  if (dev_class->flow_async_ops_function == 0)
    return VNET_FLOW_ERROR_NOT_SUPPORTED;

  /* Pre-validation loop using direct pool access */
  vec_foreach (fi, flow_indices)
    {
      f = vnet_get_flow (*fi);

      if (!f)
	{
	  rv = VNET_FLOW_ERROR_NO_SUCH_ENTRY;
	  goto error;
	}

      /* don't enable flow twice */
      if (f->driver_data.hw_if_index != ~0)
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
    }

  rv = dev_class->flow_async_ops_function (vnm, VNET_FLOW_DEV_OP_ADD_FLOW, hi->dev_instance,
					   flow_indices, flow_template_index);
error:
  return rv;
}

int
vnet_flow_async_range_disable (vnet_main_t *vnm, u32 *flow_indices, u32 hw_if_index)
{
  vnet_hw_interface_t *hi;
  vnet_device_class_t *dev_class;
  vnet_flow_t *f;
  u32 count = vec_len (flow_indices);
  u32 *fi;
  int rv = 0;

  if (count == 0)
    return VNET_FLOW_ERROR_NO_SUCH_ENTRY;

  if (!vnet_hw_interface_is_valid (vnm, hw_if_index))
    return VNET_FLOW_ERROR_NO_SUCH_INTERFACE;

  hi = vnet_get_hw_interface (vnm, hw_if_index);
  dev_class = vnet_get_device_class (vnm, hi->dev_class_index);

  if (dev_class->flow_async_ops_function == 0)
    return VNET_FLOW_ERROR_NOT_SUPPORTED;

  vec_foreach (fi, flow_indices)
    {
      f = vnet_get_flow (*fi);

      if (!f)
	{
	  rv = VNET_FLOW_ERROR_NO_SUCH_ENTRY;
	  goto error;
	}

      /* don't disable if not enabled */
      if (f->driver_data.hw_if_index == ~0)
	{
	  rv = VNET_FLOW_ERROR_ALREADY_DONE;
	  goto error;
	}
    }

  /* flow template private data is not needed to disable flows */
  rv = dev_class->flow_async_ops_function (vnm, VNET_FLOW_DEV_OP_DEL_FLOW, hi->dev_instance,
					   flow_indices, ~0);
error:
  return rv;
}
