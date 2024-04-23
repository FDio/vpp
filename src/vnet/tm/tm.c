/*
 * Copyright (c) 2024 Marvell.
 * SPDX-License-Identifier: Apache-2.0
 * https://spdx.org/licenses/Apache-2.0.html
 */

#include <vnet/ethernet/ethernet.h>
#include <vnet/flow/flow.h>
#include <vppinfra/hash.h>

/* Global mapping of flow_name to flow_id */
uword *vnet_tm_flow_name_to_id_hash;
u32 vnet_tm_flow_id_start;

static u32 vnet_tm_next_local_id;

u32
vnet_tm_create_flow_id (const char *flow_name)
{
  uword *p;
  u32 flow_id;

  if (flow_name == 0 || flow_name[0] == 0)
    return 0;

  p = hash_get_mem (vnet_tm_flow_name_to_id_hash, flow_name);
  if (p)
    return (u32) p[0];

  flow_id = vnet_tm_flow_id_start + vnet_tm_next_local_id++;
  hash_set_mem (vnet_tm_flow_name_to_id_hash, format (0, "%s", flow_name), flow_id);
  return flow_id;
}

u32
vnet_tm_get_flow_id (const char *flow_name)
{
  uword *p;

  if (flow_name == 0 || flow_name[0] == 0)
    return 0;

  p = hash_get_mem (vnet_tm_flow_name_to_id_hash, flow_name);
  if (p)
    return p[0];

  return 0;
}

vnet_tm_system_t vnet_tm_system_main;

int
vnet_tm_system_register (vnet_tm_system_t *tm_sys, u32 hw_if_idx)
{
  vnet_main_t *vnm = vnet_get_main ();
  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, hw_if_idx);
  vnet_device_class_t *dev_class = vnet_get_device_class (vnm, hi->dev_class_index);

  dev_class->vnet_tm_sys_impl = tm_sys;

  /* Initialize the tm flow_name to flow_id mapping (once) */
  if (vnet_tm_flow_name_to_id_hash == 0)
    {
      vnet_tm_flow_name_to_id_hash = hash_create_string (0, sizeof (uword));
      vnet_tm_next_local_id = 0;
      vnet_flow_get_range (vnm, "tm", VNET_TM_MAX_FLOWS, &vnet_tm_flow_id_start);
    }

  return 0;
}

int
vnet_tm_sys_node_add (u32 hw_if_idx, u32 node_id, i32 parent_node_id, u32 priority, u32 weight,
		      u32 lvl, vnet_tm_node_params_t *params, const char *flow_name)
{
  vnet_main_t *vnm = vnet_get_main ();
  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, hw_if_idx);
  vnet_device_class_t *dev_class = vnet_get_device_class (vnm, hi->dev_class_index);
  int rv;

  if (dev_class->vnet_tm_sys_impl == 0)
    return VNET_API_ERROR_UNIMPLEMENTED;

  vnet_tm_create_flow_id (flow_name);

  rv = dev_class->vnet_tm_sys_impl->node_add (hw_if_idx, node_id, parent_node_id, priority, weight,
					      lvl, params, flow_name);

  return rv;
}

int
vnet_tm_sys_node_suspend (u32 hw_if_idx, u32 node_id)
{
  vnet_main_t *vnm = vnet_get_main ();
  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, hw_if_idx);
  vnet_device_class_t *dev_class = vnet_get_device_class (vnm, hi->dev_class_index);
  int rv;

  if (dev_class->vnet_tm_sys_impl == 0)
    return VNET_API_ERROR_UNIMPLEMENTED;

  rv = dev_class->vnet_tm_sys_impl->node_suspend (hw_if_idx, node_id);

  return rv;
}

int
vnet_tm_sys_node_resume (u32 hw_if_idx, u32 node_id)
{
  vnet_main_t *vnm = vnet_get_main ();
  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, hw_if_idx);
  vnet_device_class_t *dev_class = vnet_get_device_class (vnm, hi->dev_class_index);
  int rv;

  if (dev_class->vnet_tm_sys_impl == 0)
    return VNET_API_ERROR_UNIMPLEMENTED;

  rv = dev_class->vnet_tm_sys_impl->node_resume (hw_if_idx, node_id);

  return rv;
}

int
vnet_tm_sys_node_delete (u32 hw_if_idx, u32 node_idx)
{
  vnet_main_t *vnm = vnet_get_main ();
  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, hw_if_idx);
  vnet_device_class_t *dev_class = vnet_get_device_class (vnm, hi->dev_class_index);
  int rv;

  if (dev_class->vnet_tm_sys_impl == 0)
    return VNET_API_ERROR_UNIMPLEMENTED;

  rv = dev_class->vnet_tm_sys_impl->node_delete (hw_if_idx, node_idx);

  return rv;
}

int
vnet_tm_sys_shaper_profile_create (u32 hw_if_idx, vnet_tm_shaper_params_t *param)
{
  vnet_main_t *vnm = vnet_get_main ();
  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, hw_if_idx);
  vnet_device_class_t *dev_class = vnet_get_device_class (vnm, hi->dev_class_index);
  int rv;

  if (dev_class->vnet_tm_sys_impl == 0)
    return VNET_API_ERROR_UNIMPLEMENTED;

  rv = dev_class->vnet_tm_sys_impl->shaper_profile_create (hw_if_idx, param);

  return rv;
}

int
vnet_tm_sys_node_shaper_update (u32 hw_if_idx, u32 node_id, i32 shaper_id)
{
  vnet_main_t *vnm = vnet_get_main ();
  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, hw_if_idx);
  vnet_device_class_t *dev_class = vnet_get_device_class (vnm, hi->dev_class_index);
  int rv;

  if (dev_class->vnet_tm_sys_impl == 0)
    return VNET_API_ERROR_UNIMPLEMENTED;

  rv = dev_class->vnet_tm_sys_impl->node_shaper_update (hw_if_idx, node_id, shaper_id);

  return rv;
}

int
vnet_tm_sys_shaper_profile_delete (u32 hw_if_idx, i32 shaper_id)
{
  vnet_main_t *vnm = vnet_get_main ();
  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, hw_if_idx);
  vnet_device_class_t *dev_class = vnet_get_device_class (vnm, hi->dev_class_index);
  int rv;

  if (dev_class->vnet_tm_sys_impl == 0)
    return VNET_API_ERROR_UNIMPLEMENTED;

  rv = dev_class->vnet_tm_sys_impl->shaper_profile_delete (hw_if_idx, shaper_id);

  return rv;
}

int
vnet_tm_sys_node_sched_weight_update (u32 hw_if_idx, u32 node_id, u32 weight)
{
  vnet_main_t *vnm = vnet_get_main ();
  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, hw_if_idx);
  vnet_device_class_t *dev_class = vnet_get_device_class (vnm, hi->dev_class_index);
  int rv;

  if (dev_class->vnet_tm_sys_impl == 0)
    return VNET_API_ERROR_UNIMPLEMENTED;

  rv = dev_class->vnet_tm_sys_impl->node_sched_weight_update (hw_if_idx, node_id, weight);

  return rv;
}

int
vnet_tm_sys_node_read_stats (u32 hw_if_idx, u32 node_idx, vnet_tm_stats_params_t *param)
{
  vnet_main_t *vnm = vnet_get_main ();
  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, hw_if_idx);
  vnet_device_class_t *dev_class = vnet_get_device_class (vnm, hi->dev_class_index);
  int rv;

  if (dev_class->vnet_tm_sys_impl == 0)
    return VNET_API_ERROR_UNIMPLEMENTED;

  rv = dev_class->vnet_tm_sys_impl->node_read_stats (hw_if_idx, node_idx, param);

  return rv;
}

int
vnet_tm_sys_get_capabilities (u32 hw_if_idx, vnet_tm_capa_params_t *param)
{
  vnet_main_t *vnm = vnet_get_main ();
  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, hw_if_idx);
  vnet_device_class_t *dev_class = vnet_get_device_class (vnm, hi->dev_class_index);
  int rv;

  if (dev_class->vnet_tm_sys_impl == 0)
    return VNET_API_ERROR_UNIMPLEMENTED;

  rv = dev_class->vnet_tm_sys_impl->tm_get_capabilities (hw_if_idx, param);

  return rv;
}

int
vnet_tm_sys_level_get_capabilities (u32 hw_if_idx, vnet_tm_level_capa_params_t *param, u32 lvl)
{
  vnet_main_t *vnm = vnet_get_main ();
  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, hw_if_idx);
  vnet_device_class_t *dev_class = vnet_get_device_class (vnm, hi->dev_class_index);
  int rv;

  if (dev_class->vnet_tm_sys_impl == 0)
    return VNET_API_ERROR_UNIMPLEMENTED;

  rv = dev_class->vnet_tm_sys_impl->tm_level_get_capabilities (hw_if_idx, param, lvl);

  return rv;
}

int
vnet_tm_sys_start_tm (u32 hw_if_idx)
{
  vnet_main_t *vnm = vnet_get_main ();
  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, hw_if_idx);
  vnet_device_class_t *dev_class = vnet_get_device_class (vnm, hi->dev_class_index);
  int rv;

  if (dev_class->vnet_tm_sys_impl == 0)
    return VNET_API_ERROR_UNIMPLEMENTED;

  rv = dev_class->vnet_tm_sys_impl->start_tm (hw_if_idx);

  return rv;
}

int
vnet_tm_sys_stop_tm (u32 hw_if_idx)
{
  vnet_main_t *vnm = vnet_get_main ();
  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, hw_if_idx);
  vnet_device_class_t *dev_class = vnet_get_device_class (vnm, hi->dev_class_index);
  int rv;

  if (dev_class->vnet_tm_sys_impl == 0)
    return VNET_API_ERROR_UNIMPLEMENTED;

  rv = dev_class->vnet_tm_sys_impl->stop_tm (hw_if_idx);

  return rv;
}
