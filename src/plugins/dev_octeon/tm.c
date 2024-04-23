#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vnet/dev/pci.h>
#include <vnet/dev/counters.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>
#include <dev_octeon/octeon.h>

#include <base/roc_api.h>
#include <common.h>

int
oct_tm_sys_node_create (u32 hw_if_idx, tm_node_params_t *args)
{
  return 0;
}

int
oct_tm_sys_node_delete (u32 hw_if_idx, u32 node_idx)
{
  return 0;
}

int
oct_tm_sys_node_connect (u32 hw_if_idx, tm_node_connect_params_t *args)
{
  return 0;
}

int
oct_tm_sys_node_disconnect (u32 hw_if_idx, u32 node_idx)
{
  return 0;
}

int
oct_tm_sys_shaper_create (u32 hw_if_idx, tm_shaper_params_t *args)
{
  return 0;
}

int
oct_tm_sys_shaper_delete (u32 hw_if_idx, u32 shaper_id)
{
  return 0;
}

int
oct_tm_sys_sched_create (u32 hw_if_idx, tm_sched_params_t *args)
{
  return 0;
}

int
oct_tm_sys_sched_delete (u32 hw_if_idx, u32 sched_id)
{
  return 0;
}

tm_system_t dev_oct_tm_ops = {
  .node_create = oct_tm_sys_node_create,
  .node_delete = oct_tm_sys_node_delete,
  .node_connect = oct_tm_sys_node_connect,
  .node_disconnect = oct_tm_sys_node_disconnect,
  .shaper_create = oct_tm_sys_shaper_create,
  .shaper_delete = oct_tm_sys_shaper_delete,
  .sched_create = oct_tm_sys_sched_create,
  .sched_delete = oct_tm_sys_sched_delete,
};
