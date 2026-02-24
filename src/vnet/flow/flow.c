/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2018-2026 Cisco and/or its affiliates.
 */

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/flow/flow.h>

vnet_flow_main_t flow_main;

int
vnet_flow_get_range (vnet_main_t *vnm, char *owner, u32 count, u32 *start)
{
  vnet_flow_main_t *fm = &flow_main;
  vnet_flow_range_t *r;

  /* skip 0 */
  if (fm->flows_used == 0)
    fm->flows_used = 1;

  *start = fm->flows_used;
  fm->flows_used += count;
  vec_add2 (fm->ranges, r, 1);
  r->start = *start;
  r->count = count;
  r->owner = format (0, "%s%c", owner, 0);
  return 0;
}

static_always_inline int
vnet_flow_add_inline (vnet_main_t *vnm, vnet_flow_t *flow, bool template, u32 *flow_index)
{
  vnet_flow_main_t *fm = &flow_main;
  vnet_flow_t **ppool = template ? &fm->global_flow_template_pool : &fm->global_flow_pool;
  vnet_flow_t *pool = *ppool;
  vnet_flow_t *f;

  pool_get (pool, f);
  *flow_index = f - pool;
  clib_memcpy_fast (f, flow, sizeof (vnet_flow_t));
  f->private_data = 0;
  f->index = *flow_index;
  // pre-allocate some space
  vec_validate_init_empty (f->private_data, 10, ~0);
  *ppool = pool;
  return 0;
}

static_always_inline int
vnet_flow_del_inline (vnet_main_t *vnm, u32 flow_index, bool template)
{
  vnet_flow_main_t *fm = &flow_main;
  vnet_flow_t *pool = template ? fm->global_flow_template_pool : fm->global_flow_pool;
  vnet_flow_t *f =
    template ? vnet_get_flow_async_template (flow_index) : vnet_get_flow (flow_index);
  u32 hw_if_index;

  if (f == 0)
    return VNET_FLOW_ERROR_NO_SUCH_ENTRY;

  for (hw_if_index = 0; hw_if_index < vec_len (f->private_data); hw_if_index++)
    {
      if (vec_elt (f->private_data, hw_if_index) != ~0)
	vnet_flow_disable (vnm, flow_index, hw_if_index);
    }

  vec_free (f->private_data);
  clib_memset (f, 0, sizeof (*f));
  pool_put (pool, f);
  return 0;
}

int
vnet_flow_add (vnet_main_t *vnm, vnet_flow_t *flow, u32 *flow_index)
{
  return vnet_flow_add_inline (vnm, flow, false, flow_index);
}

int
vnet_flow_add_async_template (vnet_main_t *vnm, vnet_flow_t *template, u32 *flow_template_index)
{
  return vnet_flow_add_inline (vnm, template, true, flow_template_index);
}

int
vnet_flow_del (vnet_main_t *vnm, u32 flow_index)
{
  return vnet_flow_del_inline (vnm, flow_index, false);
}

int
vnet_flow_del_async_template (vnet_main_t *vnm, u32 flow_template_index)
{
  return vnet_flow_del_inline (vnm, flow_template_index, true);
}

int
vnet_flow_enable (vnet_main_t *vnm, u32 flow_index, u32 hw_if_index)
{
  vnet_flow_t *f = vnet_get_flow (flow_index);
  vnet_hw_interface_t *hi;
  vnet_device_class_t *dev_class;
  uword private_data;
  int rv;

  if (f == 0)
    return VNET_FLOW_ERROR_NO_SUCH_ENTRY;

  if (!vnet_hw_interface_is_valid (vnm, hw_if_index))
    return VNET_FLOW_ERROR_NO_SUCH_INTERFACE;

  /* don't enable flow twice */
  if (vec_len (f->private_data) > hw_if_index && vec_elt (f->private_data, hw_if_index) != ~0)
    return VNET_FLOW_ERROR_ALREADY_DONE;

  hi = vnet_get_hw_interface (vnm, hw_if_index);
  dev_class = vnet_get_device_class (vnm, hi->dev_class_index);

  if (dev_class->flow_ops_function == 0)
    return VNET_FLOW_ERROR_NOT_SUPPORTED;

  if (f->actions & VNET_FLOW_ACTION_REDIRECT_TO_NODE)
    {
      vnet_hw_interface_t *hw = vnet_get_hw_interface (vnm, hw_if_index);
      f->redirect_device_input_next_index =
	vlib_node_add_next (vnm->vlib_main, hw->input_node_index, f->redirect_node_index);
    }

  rv = dev_class->flow_ops_function (vnm, VNET_FLOW_DEV_OP_ADD_FLOW, hi->dev_instance, flow_index,
				     &private_data);

  if (rv)
    return rv;

  vec_validate_init_empty (f->private_data, hw_if_index, ~0);
  vec_elt (f->private_data, hw_if_index) = private_data;
  return 0;
}

int
vnet_flow_disable (vnet_main_t *vnm, u32 flow_index, u32 hw_if_index)
{
  vnet_flow_t *f = vnet_get_flow (flow_index);
  vnet_hw_interface_t *hi;
  vnet_device_class_t *dev_class;
  uword *p;
  int rv;

  if (f == 0)
    return VNET_FLOW_ERROR_NO_SUCH_ENTRY;

  if (!vnet_hw_interface_is_valid (vnm, hw_if_index))
    return VNET_FLOW_ERROR_NO_SUCH_INTERFACE;

  /* don't disable if not enabled */
  if (vec_len (f->private_data) <= hw_if_index || vec_elt (f->private_data, hw_if_index) == ~0)
    return VNET_FLOW_ERROR_ALREADY_DONE;

  hi = vnet_get_hw_interface (vnm, hw_if_index);
  dev_class = vnet_get_device_class (vnm, hi->dev_class_index);

  p = vec_elt_at_index (f->private_data, hw_if_index);

  rv =
    dev_class->flow_ops_function (vnm, VNET_FLOW_DEV_OP_DEL_FLOW, hi->dev_instance, flow_index, p);

  if (rv)
    return rv;

  *p = ~0;
  return 0;
}

int
vnet_flow_async_template_enable (vnet_main_t *vnm, u32 flow_template_index, u32 hw_if_index,
				 u32 n_flows)
{
  vnet_flow_t *f = vnet_get_flow_async_template (flow_template_index);
  vnet_hw_interface_t *hi;
  vnet_device_class_t *dev_class;
  uword private_data;
  int rv;

  if (f == 0)
    return VNET_FLOW_ERROR_NO_SUCH_ENTRY;

  if (!vnet_hw_interface_is_valid (vnm, hw_if_index))
    return VNET_FLOW_ERROR_NO_SUCH_INTERFACE;

  /* don't enable flow twice */
  if (vec_len (f->private_data) > hw_if_index && vec_elt (f->private_data, hw_if_index) != ~0)
    return VNET_FLOW_ERROR_ALREADY_DONE;

  hi = vnet_get_hw_interface (vnm, hw_if_index);
  dev_class = vnet_get_device_class (vnm, hi->dev_class_index);

  if (dev_class->flow_async_template_ops_function == 0)
    return VNET_FLOW_ERROR_NOT_SUPPORTED;

  private_data = n_flows;

  rv = dev_class->flow_async_template_ops_function (
    vnm, VNET_FLOW_DEV_OP_ADD_FLOW, hi->dev_instance, flow_template_index, &private_data);

  if (rv)
    return rv;

  vec_validate_init_empty (f->private_data, hw_if_index, ~0);
  vec_elt (f->private_data, hw_if_index) = private_data;
  return 0;
}

int
vnet_flow_async_template_disable (vnet_main_t *vnm, u32 flow_template_index, u32 hw_if_index)
{
  vnet_flow_t *f = vnet_get_flow_async_template (flow_template_index);
  vnet_hw_interface_t *hi;
  vnet_device_class_t *dev_class;
  uword *p;
  int rv;

  if (f == 0)
    return VNET_FLOW_ERROR_NO_SUCH_ENTRY;

  if (!vnet_hw_interface_is_valid (vnm, hw_if_index))
    return VNET_FLOW_ERROR_NO_SUCH_INTERFACE;

  /* don't disable if not enabled */
  if (vec_len (f->private_data) <= hw_if_index || vec_elt (f->private_data, hw_if_index) == ~0)
    return VNET_FLOW_ERROR_ALREADY_DONE;

  hi = vnet_get_hw_interface (vnm, hw_if_index);
  dev_class = vnet_get_device_class (vnm, hi->dev_class_index);

  p = vec_elt_at_index (f->private_data, hw_if_index);
  rv = dev_class->flow_async_template_ops_function (vnm, VNET_FLOW_DEV_OP_DEL_FLOW,
						    hi->dev_instance, flow_template_index, p);
  if (rv)
    return rv;

  *p = ~0;
  return 0;
}

int
vnet_flow_async_enable (vnet_main_t *vnm, vnet_flow_range_t *range, u32 flow_template_index,
			u32 hw_if_index)
{
  vnet_flow_t __clib_unused *f, *template = vnet_get_flow_async_template (flow_template_index);
  vnet_hw_interface_t *hi;
  vnet_device_class_t *dev_class;
  uword private_template_data;
  uword *private_data;
  int rv;

  if (template == 0)
    return VNET_FLOW_ERROR_NO_SUCH_ENTRY;

  if (vec_len (template->private_data) <= hw_if_index ||
      vec_elt (template->private_data, hw_if_index) == ~0)
    return VNET_FLOW_ERROR_NO_SUCH_ENTRY;

  private_template_data = vec_elt (template->private_data, hw_if_index);

  if (!vnet_hw_interface_is_valid (vnm, hw_if_index))
    return VNET_FLOW_ERROR_NO_SUCH_INTERFACE;

  hi = vnet_get_hw_interface (vnm, hw_if_index);
  dev_class = vnet_get_device_class (vnm, hi->dev_class_index);

  if (dev_class->flow_async_ops_function == 0)
    return VNET_FLOW_ERROR_NOT_SUPPORTED;

  /* Use stack allocation for small counts to avoid heap alloc/free */
  private_data = clib_mem_alloc (sizeof (uword) * range->count);

  /* Pre-validation loop using direct pool access */
  for (u32 i = 0; i < range->count; i++)
    {
      f = vnet_flow_range_get_flow (range, i);

      /* don't enable flow twice */
      vec_validate_init_empty (f->private_data, hw_if_index, ~0);
      if (vec_elt (f->private_data, hw_if_index) != ~0)
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

  rv = dev_class->flow_async_ops_function (vnm, VNET_FLOW_DEV_OP_ADD_FLOW, hi->dev_instance, range,
					   &private_template_data, private_data);
  if (rv)
    goto error;

  /* Store private data with direct pool access */
  for (u32 i = 0; i < range->count; i++)
    {
      f = vnet_flow_range_get_flow (range, i);
      vec_elt (f->private_data, hw_if_index) = private_data[i];
    }

error:
  clib_mem_free (private_data);
  return rv;
}

int
vnet_flow_async_disable (vnet_main_t *vnm, vnet_flow_range_t *range, u32 flow_template_index,
			 u32 hw_if_index)
{
  vnet_flow_t *f, *template = vnet_get_flow_async_template (flow_template_index);
  vnet_hw_interface_t *hi;
  vnet_device_class_t *dev_class;
  uword private_template_data;
  uword *private_data;
  int rv;

  if (template == 0)
    return VNET_FLOW_ERROR_NO_SUCH_ENTRY;

  if (vec_len (template->private_data) <= hw_if_index ||
      vec_elt (template->private_data, hw_if_index) == ~0)
    return VNET_FLOW_ERROR_NO_SUCH_ENTRY;

  private_template_data = vec_elt (template->private_data, hw_if_index);

  if (!vnet_hw_interface_is_valid (vnm, hw_if_index))
    return VNET_FLOW_ERROR_NO_SUCH_INTERFACE;

  hi = vnet_get_hw_interface (vnm, hw_if_index);
  dev_class = vnet_get_device_class (vnm, hi->dev_class_index);

  /* Use stack allocation for small counts */
  private_data = clib_mem_alloc (sizeof (uword) * range->count);

  for (u32 i = 0; i < range->count; i++)
    {
      f = vnet_flow_range_get_flow (range, i);

      /* don't disable if not enabled */
      if (vec_len (f->private_data) <= hw_if_index || vec_elt (f->private_data, hw_if_index) == ~0)
	{
	  rv = VNET_FLOW_ERROR_ALREADY_DONE;
	  goto error;
	}

      private_data[i] = vec_elt (f->private_data, hw_if_index);
      vec_elt (f->private_data, hw_if_index) = ~0;
    }

  rv = dev_class->flow_async_ops_function (vnm, VNET_FLOW_DEV_OP_DEL_FLOW, hi->dev_instance, range,
					   &private_template_data, private_data);

  if (rv)
    goto error;

error:
  clib_mem_free (private_data);
  return rv;
}
