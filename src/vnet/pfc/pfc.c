/*
 * Copyright (c) 2025 Marvell.
 * SPDX-License-Identifier: Apache-2.0
 * https://spdx.org/licenses/Apache-2.0.html
 */

#include <vnet/ethernet/ethernet.h>

pfc_system_t pfc_system_main;

int
pfc_system_register (pfc_system_t *pfc_sys, u32 hw_if_idx)
{
  vnet_main_t *vnm = vnet_get_main ();

  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, hw_if_idx);

  vnet_device_class_t *dev_class =
    vnet_get_device_class (vnm, hi->dev_class_index);

  dev_class->pfc_sys_impl = pfc_sys;

  return 0;
}

int
pfc_sys_configure (u32 hw_if_idx, pfc_params_t *params)
{
  vnet_main_t *vnm = vnet_get_main ();

  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, hw_if_idx);

  vnet_device_class_t *dev_class =
    vnet_get_device_class (vnm, hi->dev_class_index);

  dev_class->pfc_sys_impl->pfc_configure (hw_if_idx, params);

  return 0;
}

int
pfc_sys_get_capabilities (u32 hw_if_idx, pfc_capa_params_t *capa)
{
  vnet_main_t *vnm = vnet_get_main ();

  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, hw_if_idx);

  vnet_device_class_t *dev_class =
    vnet_get_device_class (vnm, hi->dev_class_index);

  dev_class->pfc_sys_impl->pfc_get_capabilities (hw_if_idx, capa);

  return 0;
}

int
pfc_sys_disable_pause_frame_flow_ctrl (u32 hw_if_idx, u32 disable)
{
  vnet_main_t *vnm = vnet_get_main ();

  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, hw_if_idx);

  vnet_device_class_t *dev_class =
    vnet_get_device_class (vnm, hi->dev_class_index);

  dev_class->pfc_sys_impl->pfc_disable_pause_frame_flow_ctrl (hw_if_idx,
							      disable);

  return 0;
}
