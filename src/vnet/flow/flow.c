/*
 * Copyright (c) 2018 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/flow/flow.h>

vnet_flow_main_t flow_main;

int
vnet_flow_get_range (vnet_main_t * vnm, char *owner, u32 count, u32 * start)
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

int
vnet_flow_add (vnet_main_t * vnm, vnet_flow_t * flow, u32 * flow_index)
{
  vnet_flow_main_t *fm = &flow_main;
  vnet_flow_t *f;

  pool_get (fm->global_flow_pool, f);
  *flow_index = f - fm->global_flow_pool;
  clib_memcpy (f, flow, sizeof (vnet_flow_t));
  f->private_data = 0;
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
  uword hw_if_index;
  uword private_data;

  if (f == 0)
    return VNET_FLOW_ERROR_NO_SUCH_ENTRY;

  /* *INDENT-OFF* */
  hash_foreach (hw_if_index, private_data, f->private_data,
    ({
     vnet_flow_disable (vnm, flow_index, hw_if_index);
    }));
  /* *INDENT-ON* */

  hash_free (f->private_data);
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
  uword private_data;
  int rv;

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
	vlib_node_add_next (vnm->vlib_main, hw->input_node_index,
			    f->redirect_node_index);
    }

  rv = dev_class->flow_ops_function (vnm, VNET_FLOW_DEV_OP_ADD_FLOW,
				     hi->dev_instance, flow_index,
				     &private_data);

  if (rv)
    return rv;

  hash_set (f->private_data, hw_if_index, private_data);
  return 0;
}

int
vnet_flow_disable (vnet_main_t * vnm, u32 flow_index, u32 hw_if_index)
{
  vnet_flow_t *f = vnet_get_flow (flow_index);
  vnet_hw_interface_t *hi;
  vnet_device_class_t *dev_class;
  uword *p;
  int rv;

  if (!vnet_hw_interface_is_valid (vnm, hw_if_index))
    return VNET_FLOW_ERROR_NO_SUCH_INTERFACE;

  /* don't disable if not enabled */
  if ((p = hash_get (f->private_data, hw_if_index)) == 0)
    return VNET_FLOW_ERROR_ALREADY_DONE;

  hi = vnet_get_hw_interface (vnm, hw_if_index);
  dev_class = vnet_get_device_class (vnm, hi->dev_class_index);

  rv = dev_class->flow_ops_function (vnm, VNET_FLOW_DEV_OP_DEL_FLOW,
				     hi->dev_instance, flow_index, p);

  if (rv)
    return rv;

  hash_unset (f->private_data, hw_if_index);
  return 0;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
