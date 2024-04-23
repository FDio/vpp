/*
 * Copyright (c) 2024 Marvell.
 * SPDX-License-Identifier: Apache-2.0
 * https://spdx.org/licenses/Apache-2.0.html
 */

#include <vnet/ethernet/ethernet.h>

tm_system_t tm_system_main;

int
tm_system_register (tm_system_t *tm_sys, u32 hw_if_idx)
{
  vnet_main_t *vnm = vnet_get_main ();
  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, hw_if_idx);
  vnet_device_class_t *dev_class =
    vnet_get_device_class (vnm, hi->dev_class_index);

  dev_class->tm_sys_impl = tm_sys;

  return 0;
}

int
tm_sys_node_add (u32 hw_if_idx, u32 node_id, u32 parent_node_id, u32 priority,
		 u32 weight, u32 lvl, tm_node_params_t *params)
{
  vnet_main_t *vnm = vnet_get_main ();
  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, hw_if_idx);
  vnet_device_class_t *dev_class =
    vnet_get_device_class (vnm, hi->dev_class_index);

  dev_class->tm_sys_impl->node_add (hw_if_idx, node_id, parent_node_id,
				    priority, weight, lvl, params);

  return 0;
}

int
tm_sys_node_suspend (u32 hw_if_idx, u32 node_id)
{
  vnet_main_t *vnm = vnet_get_main ();
  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, hw_if_idx);
  vnet_device_class_t *dev_class =
    vnet_get_device_class (vnm, hi->dev_class_index);

  dev_class->tm_sys_impl->node_suspend (hw_if_idx, node_id);

  return 0;
}

int
tm_sys_node_resume (u32 hw_if_idx, u32 node_id)
{
  vnet_main_t *vnm = vnet_get_main ();
  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, hw_if_idx);
  vnet_device_class_t *dev_class =
    vnet_get_device_class (vnm, hi->dev_class_index);

  dev_class->tm_sys_impl->node_resume (hw_if_idx, node_id);

  return 0;
}

int
tm_sys_node_delete (u32 hw_if_idx, u32 node_idx)
{
  vnet_main_t *vnm = vnet_get_main ();
  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, hw_if_idx);
  vnet_device_class_t *dev_class =
    vnet_get_device_class (vnm, hi->dev_class_index);

  dev_class->tm_sys_impl->node_delete (hw_if_idx, node_idx);

  return 0;
}

int
tm_sys_shaper_profile_create (u32 hw_if_idx, tm_shaper_params_t *param)
{
  vnet_main_t *vnm = vnet_get_main ();
  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, hw_if_idx);
  vnet_device_class_t *dev_class =
    vnet_get_device_class (vnm, hi->dev_class_index);

  dev_class->tm_sys_impl->shaper_profile_create (hw_if_idx, param);

  return 0;
}

int
tm_sys_node_shaper_update (u32 hw_if_idx, u32 node_id, u32 shaper_id)
{
  vnet_main_t *vnm = vnet_get_main ();
  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, hw_if_idx);
  vnet_device_class_t *dev_class =
    vnet_get_device_class (vnm, hi->dev_class_index);

  dev_class->tm_sys_impl->node_shaper_update (hw_if_idx, node_id, shaper_id);

  return 0;
}

int
tm_sys_shaper_profile_delete (u32 hw_if_idx, u32 shaper_id)
{
  vnet_main_t *vnm = vnet_get_main ();
  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, hw_if_idx);
  vnet_device_class_t *dev_class =
    vnet_get_device_class (vnm, hi->dev_class_index);

  dev_class->tm_sys_impl->shaper_profile_delete (hw_if_idx, shaper_id);

  return 0;
}

int
tm_sys_node_sched_weight_update (u32 hw_if_idx, u32 node_id, u32 weight)
{
  vnet_main_t *vnm = vnet_get_main ();
  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, hw_if_idx);
  vnet_device_class_t *dev_class =
    vnet_get_device_class (vnm, hi->dev_class_index);

  dev_class->tm_sys_impl->node_sched_weight_update (hw_if_idx, node_id,
						    weight);

  return 0;
}

int
tm_sys_node_read_stats (u32 hw_if_idx, u32 node_idx, tm_stats_params_t *param)
{
  vnet_main_t *vnm = vnet_get_main ();
  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, hw_if_idx);
  vnet_device_class_t *dev_class =
    vnet_get_device_class (vnm, hi->dev_class_index);

  dev_class->tm_sys_impl->node_read_stats (hw_if_idx, node_idx, param);

  return 0;
}

int
tm_sys_get_capabilities (u32 hw_if_idx, tm_capa_params_t *param)
{
  vnet_main_t *vnm = vnet_get_main ();
  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, hw_if_idx);
  vnet_device_class_t *dev_class =
    vnet_get_device_class (vnm, hi->dev_class_index);

  dev_class->tm_sys_impl->tm_get_capabilities (hw_if_idx, param);

  return 0;
}

int
tm_sys_level_get_capabilities (u32 hw_if_idx, tm_level_capa_params_t *param,
			       u32 lvl)
{
  vnet_main_t *vnm = vnet_get_main ();
  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, hw_if_idx);
  vnet_device_class_t *dev_class =
    vnet_get_device_class (vnm, hi->dev_class_index);

  dev_class->tm_sys_impl->tm_level_get_capabilities (hw_if_idx, param, lvl);

  return 0;
}

int
tm_sys_start_tm (u32 hw_if_idx)
{
  vnet_main_t *vnm = vnet_get_main ();
  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, hw_if_idx);
  vnet_device_class_t *dev_class =
    vnet_get_device_class (vnm, hi->dev_class_index);

  dev_class->tm_sys_impl->start_tm (hw_if_idx);

  return 0;
}

int
tm_sys_stop_tm (u32 hw_if_idx)
{
  vnet_main_t *vnm = vnet_get_main ();
  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, hw_if_idx);
  vnet_device_class_t *dev_class =
    vnet_get_device_class (vnm, hi->dev_class_index);

  dev_class->tm_sys_impl->stop_tm (hw_if_idx);

  return 0;
}
