#include <vnet/ethernet/ethernet.h>

tm_system_t tm_system_main;

int
pktio_dev_tm_system_register (tm_system_t *tm_sys, u32 hw_if_idx)
{
  vnet_main_t *vnm = vnet_get_main ();

  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, hw_if_idx);

  vnet_device_class_t *dev_class =
    vnet_get_device_class (vnm, hi->dev_class_index);

  dev_class->tm_sys_impl = tm_sys;

  return 0;
}

int
tm_sys_node_create (u32 hw_if_idx, tm_node_params_t *args)
{
  vnet_main_t *vnm = vnet_get_main ();
  printf ("tm_sys_node_create:%d\n", hw_if_idx);
  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, hw_if_idx);

  vnet_device_class_t *dev_class =
    vnet_get_device_class (vnm, hi->dev_class_index);

  dev_class->tm_sys_impl->node_create (hw_if_idx, args);

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
tm_sys_node_connect (u32 hw_if_idx, tm_node_connect_params_t *param)
{
  vnet_main_t *vnm = vnet_get_main ();

  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, hw_if_idx);
  vnet_device_class_t *dev_class =
    vnet_get_device_class (vnm, hi->dev_class_index);

  dev_class->tm_sys_impl->node_connect (hw_if_idx, param);

  return 0;
}

int
tm_sys_node_disconnect (u32 hw_if_idx, u32 node_idx)
{
  vnet_main_t *vnm = vnet_get_main ();

  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, hw_if_idx);
  vnet_device_class_t *dev_class =
    vnet_get_device_class (vnm, hi->dev_class_index);

  dev_class->tm_sys_impl->node_disconnect (hw_if_idx, node_idx);

  return 0;
}

int
tm_sys_sched_create (u32 hw_if_idx, tm_sched_params_t *param)
{
  vnet_main_t *vnm = vnet_get_main ();

  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, hw_if_idx);
  vnet_device_class_t *dev_class =
    vnet_get_device_class (vnm, hi->dev_class_index);

  dev_class->tm_sys_impl->sched_create (hw_if_idx, param);

  return 0;
}

int
tm_sys_sched_delete (u32 hw_if_idx, u32 sched_id)
{
  vnet_main_t *vnm = vnet_get_main ();

  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, hw_if_idx);
  vnet_device_class_t *dev_class =
    vnet_get_device_class (vnm, hi->dev_class_index);

  dev_class->tm_sys_impl->sched_delete (hw_if_idx, sched_id);

  return 0;
}

int
tm_sys_shaper_create (u32 hw_if_idx, tm_shaper_params_t *param)
{
  vnet_main_t *vnm = vnet_get_main ();

  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, hw_if_idx);
  vnet_device_class_t *dev_class =
    vnet_get_device_class (vnm, hi->dev_class_index);

  dev_class->tm_sys_impl->shaper_create (hw_if_idx, param);

  return 0;
}

int
tm_sys_shaper_delete (u32 hw_if_idx, u32 shaper_id)
{
  vnet_main_t *vnm = vnet_get_main ();

  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, hw_if_idx);
  vnet_device_class_t *dev_class =
    vnet_get_device_class (vnm, hi->dev_class_index);

  dev_class->tm_sys_impl->shaper_delete (hw_if_idx, shaper_id);

  return 0;
}
