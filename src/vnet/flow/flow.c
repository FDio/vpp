/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2018 Cisco and/or its affiliates.
 */

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/flow/flow.h>
#include <vnet/flow/flow_inlines.h>

vnet_flow_main_t flow_main;

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

vnet_flow_t *
vnet_get_range_flow (vnet_flow_range_t *range, u32 range_flow_index)
{

  u32 *flow_index;
  if (pool_is_free_index (range->flow_indices, range_flow_index))
    return 0;

  flow_index = pool_elt_at_index (range->flow_indices, range_flow_index);
  return vnet_get_flow_inline (*flow_index);
}

int
vnet_flow_del (vnet_main_t * vnm, u32 flow_index)
{
  return vnet_flow_del_inline (vnm, flow_index);
}

int
vnet_flow_enable (vnet_main_t * vnm, u32 flow_index, u32 hw_if_index)
{
  return vnet_flow_enable_inline (vnm, flow_index, hw_if_index);
}

int
vnet_flow_disable (vnet_main_t * vnm, u32 flow_index, u32 hw_if_index)
{
  return vnet_flow_disable_inline (vnm, flow_index, hw_if_index);
}

vnet_flow_range_t *
vnet_flow_alloc_range (vnet_main_t *vnm, char *owner, u32 count)
{
  vnet_flow_main_t *fm = &flow_main;
  vnet_flow_range_t *range;

  pool_get (fm->ranges, range);

  range->count = count;
  range->owner = format (0, "%s%c", owner, 0);
  pool_alloc (range->flow_indices, count);
  return range;
}

int
vnet_flow_free_range (vnet_main_t *vnm, vnet_flow_range_t *range)
{
  vnet_flow_main_t *fm = &flow_main;

  pool_free (range->flow_indices);
  pool_put (fm->ranges, range);
  return 0;
}

int
vnet_flow_range_add (vnet_main_t *vnm, vnet_flow_range_t *range, vnet_flow_t *flow,
		     u32 *range_flow_index)
{
  u32 flow_index;
  u32 *f;
  int rv;

  if (pool_len (range->flow_indices) + 1 >= range->count)
    return -1;

  if ((rv = vnet_flow_add (vnm, flow, &flow_index)))
    return rv;

  pool_get (range->flow_indices, f);
  *range_flow_index = f - range->flow_indices;
  *f = flow_index;
  return 0;
}

int
vnet_flow_range_del (vnet_main_t *vnm, vnet_flow_range_t *range, u32 range_flow_index)
{
  u32 *flow_index;
  if (pool_is_free_index (range->flow_indices, range_flow_index))
    return 0;

  flow_index = pool_elt_at_index (range->flow_indices, range_flow_index);
  pool_put (range->flow_indices, flow_index);

  return vnet_flow_del_inline (vnm, *flow_index);
}

int
vnet_flow_range_enable (vnet_main_t *vnm, vnet_flow_range_t *range, u32 range_flow_index,
			u32 hw_if_index)
{
  u32 *flow_index;
  if (pool_is_free_index (range->flow_indices, range_flow_index))
    return 0;

  flow_index = pool_elt_at_index (range->flow_indices, range_flow_index);
  return vnet_flow_enable_inline (vnm, *flow_index, hw_if_index);
}

int
vnet_flow_range_disable (vnet_main_t *vnm, vnet_flow_range_t *range, u32 range_flow_index,
			 u32 hw_if_index)
{
  u32 *flow_index;
  if (pool_is_free_index (range->flow_indices, range_flow_index))
    return 0;

  flow_index = pool_elt_at_index (range->flow_indices, range_flow_index);
  return vnet_flow_disable_inline (vnm, *flow_index, hw_if_index);
}
