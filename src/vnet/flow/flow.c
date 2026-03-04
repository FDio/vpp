/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2018 Cisco and/or its affiliates.
 */

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/flow/flow.h>

vnet_flow_main_t flow_main;

static_always_inline vnet_flow_t *
vnet_get_flow_inline (u32 flow_index)
{
  vnet_flow_main_t *fm = &flow_main;
  if (pool_is_free_index (fm->global_flow_pool, flow_index))
    return 0;

  return pool_elt_at_index (fm->global_flow_pool, flow_index);
}

static_always_inline vnet_flow_range_t *
vnet_get_flow_range_inline (u32 range_index)
{
  vnet_flow_main_t *fm = &flow_main;
  if (pool_is_free_index (fm->ranges, range_index))
    return 0;
  return pool_elt_at_index (fm->ranges, range_index);
}

static_always_inline int
vnet_flow_add_inline (vnet_main_t *vnm, vnet_flow_t *flow, u32 *flow_index)
{
  vnet_flow_main_t *fm = &flow_main;
  vnet_flow_t *f;

  pool_get (fm->global_flow_pool, f);
  *flow_index = f - fm->global_flow_pool;
  clib_memcpy_fast (f, flow, sizeof (vnet_flow_t));
  f->private_data = 0;
  f->range_index = ~0;
  f->index = *flow_index;
  return 0;
}

static_always_inline int
vnet_flow_enable_inline (vnet_main_t *vnm, u32 flow_index, u32 hw_if_index)
{
  vnet_flow_t *f = vnet_get_flow_inline (flow_index);
  vnet_hw_interface_t *hi;
  vnet_device_class_t *dev_class;
  uword private_data;
  int rv;

  if (f == 0)
    return VNET_FLOW_ERROR_NO_SUCH_ENTRY;

  if (!vnet_hw_interface_is_valid (vnm, hw_if_index))
    return VNET_FLOW_ERROR_NO_SUCH_INTERFACE;

  /* don't enable flow twice */
  if (hash_get (f->private_data, hw_if_index) != 0)
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

  hash_set (f->private_data, hw_if_index, private_data);
  return 0;
}

static_always_inline int
vnet_flow_disable_inline (vnet_main_t *vnm, u32 flow_index, u32 hw_if_index)
{
  vnet_flow_t *f = vnet_get_flow_inline (flow_index);
  vnet_hw_interface_t *hi;
  vnet_device_class_t *dev_class;
  uword *p;
  int rv;

  if (f == 0)
    return VNET_FLOW_ERROR_NO_SUCH_ENTRY;

  if (!vnet_hw_interface_is_valid (vnm, hw_if_index))
    return VNET_FLOW_ERROR_NO_SUCH_INTERFACE;

  /* don't disable if not enabled */
  if ((p = hash_get (f->private_data, hw_if_index)) == 0)
    return VNET_FLOW_ERROR_ALREADY_DONE;

  hi = vnet_get_hw_interface (vnm, hw_if_index);
  dev_class = vnet_get_device_class (vnm, hi->dev_class_index);

  if (dev_class->flow_ops_function == 0)
    return VNET_FLOW_ERROR_NOT_SUPPORTED;

  rv =
    dev_class->flow_ops_function (vnm, VNET_FLOW_DEV_OP_DEL_FLOW, hi->dev_instance, flow_index, p);

  if (rv)
    return rv;

  hash_unset (f->private_data, hw_if_index);
  return 0;
}

static_always_inline int
vnet_flow_del_inline (vnet_main_t *vnm, u32 flow_index)
{
  vnet_flow_main_t *fm = &flow_main;
  vnet_flow_t *f = vnet_get_flow_inline (flow_index);
  uword hw_if_index;
  uword private_data;

  if (f == 0)
    return VNET_FLOW_ERROR_NO_SUCH_ENTRY;

  hash_foreach (hw_if_index, private_data, f->private_data,
		({ vnet_flow_disable_inline (vnm, flow_index, hw_if_index); }));

  hash_free (f->private_data);
  clib_memset (f, 0, sizeof (*f));
  pool_put (fm->global_flow_pool, f);
  return 0;
}

int
vnet_flow_add (vnet_main_t *vnm, vnet_flow_t *flow, u32 *flow_index)
{
  return vnet_flow_add_inline (vnm, flow, flow_index);
}

vnet_flow_t *
vnet_get_flow (u32 flow_index)
{
  return vnet_get_flow_inline (flow_index);
}

vnet_flow_range_t *
vnet_get_flow_range (u32 range_index)
{
  return vnet_get_flow_range_inline (range_index);
}

vnet_flow_t *
vnet_get_flow_range_flow (u32 range_index, u32 range_flow_index)
{
  u32 *flow_index;
  vnet_flow_range_t *range;
  range = vnet_get_flow_range_inline (range_index);

  if (!range || pool_is_free_index (range->flow_indices, range_flow_index))
    return 0;

  flow_index = pool_elt_at_index (range->flow_indices, range_flow_index);
  return vnet_get_flow_inline (*flow_index);
}

int
vnet_flow_del (vnet_main_t *vnm, u32 flow_index)
{
  return vnet_flow_del_inline (vnm, flow_index);
}

int
vnet_flow_enable (vnet_main_t *vnm, u32 flow_index, u32 hw_if_index)
{
  return vnet_flow_enable_inline (vnm, flow_index, hw_if_index);
}

int
vnet_flow_disable (vnet_main_t *vnm, u32 flow_index, u32 hw_if_index)
{
  return vnet_flow_disable_inline (vnm, flow_index, hw_if_index);
}

int
vnet_flow_create_range (vnet_main_t *vnm, char *owner, u32 count, u32 *range_index)
{
  vnet_flow_main_t *fm = &flow_main;
  vnet_flow_range_t *range;

  if (count == 0)
    return VNET_FLOW_ERROR_INVALID_VALUE;

  pool_get (fm->ranges, range);

  range->count = count;
  range->owner = format (0, "%s%c", owner, 0);
  pool_alloc (range->flow_indices, count);
  *range_index = range - fm->ranges;
  return 0;
}

int
vnet_flow_free_range (vnet_main_t *vnm, u32 range_index)
{
  vnet_flow_main_t *fm = &flow_main;
  vnet_flow_range_t *range = vnet_get_flow_range_inline (range_index);

  if (!range)
    return VNET_FLOW_ERROR_NO_SUCH_ENTRY;

  if (pool_elts (range->flow_indices))
    return VNET_FLOW_ERROR_ALREADY_EXISTS;

  vec_free (range->owner);
  pool_free (range->flow_indices);
  pool_put (fm->ranges, range);
  return 0;
}

int
vnet_flow_range_add (vnet_main_t *vnm, u32 range_index, vnet_flow_t *flow, u32 *range_flow_index)
{
  vnet_flow_range_t *range = vnet_get_flow_range_inline (range_index);
  vnet_flow_t *flow_copy;
  u32 flow_index;
  u32 *f;
  int rv;

  if (!range)
    return VNET_FLOW_ERROR_NO_SUCH_ENTRY;

  if (pool_elts (range->flow_indices) >= range->count)
    return VNET_FLOW_ERROR_INVALID_VALUE;

  if ((rv = vnet_flow_add_inline (vnm, flow, &flow_index)))
    return rv;

  flow_copy = vnet_get_flow_inline (flow_index);
  flow_copy->range_index = range_index;

  pool_get (range->flow_indices, f);
  *range_flow_index = f - range->flow_indices;
  *f = flow_index;
  return 0;
}

int
vnet_flow_range_del (vnet_main_t *vnm, u32 range_index, u32 range_flow_index)
{
  vnet_flow_range_t *range = vnet_get_flow_range_inline (range_index);
  u32 *flow_index;
  int rv;

  if (!range)
    return VNET_FLOW_ERROR_NO_SUCH_ENTRY;

  if (pool_is_free_index (range->flow_indices, range_flow_index))
    return VNET_FLOW_ERROR_NO_SUCH_ENTRY;

  flow_index = pool_elt_at_index (range->flow_indices, range_flow_index);

  if ((rv = vnet_flow_del_inline (vnm, *flow_index)))
    return rv;

  pool_put (range->flow_indices, flow_index);
  return 0;
}

int
vnet_flow_range_bind (vnet_main_t *vnm, u32 range_index, u32 flow_index, u32 *range_flow_index)
{
  vnet_flow_range_t *range = vnet_get_flow_range_inline (range_index);
  vnet_flow_t *flow = vnet_get_flow_inline (flow_index);
  u32 *f;

  if (!range || !flow)
    return VNET_FLOW_ERROR_NO_SUCH_ENTRY;

  if (flow->range_index != ~0)
    return VNET_FLOW_ERROR_ALREADY_DONE;

  if (pool_elts (range->flow_indices) >= range->count)
    return VNET_FLOW_ERROR_INVALID_VALUE;

  flow->range_index = range_index;
  pool_get (range->flow_indices, f);
  *range_flow_index = f - range->flow_indices;
  *f = flow_index;
  return 0;
}

int
vnet_flow_range_unbind (vnet_main_t *vnm, u32 range_index, u32 range_flow_index, u32 *flow_index)
{
  vnet_flow_range_t *range = vnet_get_flow_range_inline (range_index);
  vnet_flow_t *flow;

  if (!range)
    return VNET_FLOW_ERROR_NO_SUCH_ENTRY;

  if (pool_is_free_index (range->flow_indices, range_flow_index))
    return VNET_FLOW_ERROR_NO_SUCH_ENTRY;

  u32 *fi = pool_elt_at_index (range->flow_indices, range_flow_index);
  *flow_index = *fi;
  pool_put (range->flow_indices, fi);
  flow = vnet_get_flow_inline (*flow_index);
  flow->range_index = ~0;
  return 0;
}

int
vnet_flow_range_enable (vnet_main_t *vnm, u32 range_index, u32 range_flow_index, u32 hw_if_index)
{
  vnet_flow_range_t *range = vnet_get_flow_range_inline (range_index);
  u32 *flow_index;

  if (!range)
    return VNET_FLOW_ERROR_NO_SUCH_ENTRY;

  if (pool_is_free_index (range->flow_indices, range_flow_index))
    return VNET_FLOW_ERROR_NO_SUCH_ENTRY;

  flow_index = pool_elt_at_index (range->flow_indices, range_flow_index);
  return vnet_flow_enable_inline (vnm, *flow_index, hw_if_index);
}

int
vnet_flow_range_disable (vnet_main_t *vnm, u32 range_index, u32 range_flow_index, u32 hw_if_index)
{
  vnet_flow_range_t *range = vnet_get_flow_range_inline (range_index);
  u32 *flow_index;

  if (!range)
    return VNET_FLOW_ERROR_NO_SUCH_ENTRY;

  if (pool_is_free_index (range->flow_indices, range_flow_index))
    return VNET_FLOW_ERROR_NO_SUCH_ENTRY;

  flow_index = pool_elt_at_index (range->flow_indices, range_flow_index);
  return vnet_flow_disable_inline (vnm, *flow_index, hw_if_index);
}
