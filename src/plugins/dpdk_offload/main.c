#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>
#include <vlib/pci/pci.h>
#include <dpdk/device/dpdk.h>

#include "offload.h"

offload_main_t offload_main;

static clib_error_t *
unformat_offload_workers (unformat_input_t * input,
                          dpdk_offload_workers_config_t * offload)
{
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "num-rx-queues %u", &offload->num_rx_queues))
	continue;
      if (unformat (input, "workers %U", unformat_bitmap_list, &offload->workers))
	continue;
      return clib_error_return (0, "unknown input `%U'",
				format_unformat_error, input);
    }

  /* match workers to rx queues */
  int n_workers = clib_bitmap_count_set_bits (offload->workers);
  if (n_workers == 0)
    return 0;

  if (offload->num_rx_queues == 0)
    offload->num_rx_queues = n_workers;
  else if (offload->num_rx_queues != n_workers)
    return clib_error_return (0, "number of offload worker threads must be"
			      " equal to number of offload rx queues");

  return 0;
}

static clib_error_t *
unformat_offload_device_config (unformat_input_t * input, dpdk_offload_device_config_t * conf)
{
  unformat_input_t sub_input;
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
  {
    if (unformat (input, "vxlan %U", unformat_vlib_cli_sub_input, &sub_input))
    {
      clib_error_t * error = unformat_offload_workers (&sub_input, &conf->vxlan_rx.conf);
      if (error)
        return error;
      continue;
    }
    return clib_error_return (0, "unknown input `%U'", format_unformat_error, input);
  }

  return 0;
}

static clib_error_t *
unformat_offload_config (vlib_main_t * vm, unformat_input_t * input)
{
  unformat_input_t sub_input;
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
  {
    vlib_pci_addr_t pci_addr;
    if (unformat (input, "dev %U %U", unformat_vlib_pci_addr, &pci_addr,
                  unformat_vlib_cli_sub_input, &sub_input))
    {
      if ( hash_get (offload_main.conf_index_by_pci_addr, pci_addr.as_u32) )
	return clib_error_return (0, "duplicate configuration for PCI address %U",
				  format_vlib_pci_addr, &pci_addr);

      dpdk_offload_device_config_t * devconf;
      pool_get (offload_main.dev_confs, devconf);
      clib_error_t * error = unformat_offload_device_config (&sub_input, devconf);
      if (error)
        return error;

      hash_set (offload_main.conf_index_by_pci_addr, pci_addr.as_u32,
          devconf - offload_main.dev_confs);
      continue;
    }
    return clib_error_return (0, "unknown input `%U'", format_unformat_error, input);
  }

  return 0;
}

VLIB_CONFIG_FUNCTION (unformat_offload_config, "dpdk-offload");

static clib_error_t *
dpdk_offload_setup_workers (dpdk_device_t * xd, dpdk_offload_state_t * state, u32 node_idx)
{
  static clib_error_t * (*dpdk_setup_workers_) (dpdk_device_t * xd, u32 node_idx,
      int n_rx_queues, clib_bitmap_t * workers, dpdk_queue_range_t * q_range) = 0;
  if (dpdk_setup_workers_ == 0)
    {
      dpdk_setup_workers_ =
        vlib_get_plugin_symbol ("dpdk_plugin.so", "dpdk_setup_workers");
      if (!dpdk_setup_workers_)
        clib_warning ("missing dpdk_setup_workers");
    }
  dpdk_offload_workers_config_t * conf = &state->conf;
  return dpdk_setup_workers_ (xd, node_idx, conf->num_rx_queues, conf->workers, &state->q_range);
}

dpdk_offload_device_config_t *
dpdk_offload_get_device_config (dpdk_device_t * xd)
{
  uword * conf_idx = hash_get (offload_main.conf_index_by_device_index, xd->device_index);
  if (conf_idx == 0)
    return 0;

  return pool_elt_at_index(offload_main.dev_confs, conf_idx[0]);
}

void
init_offload (dpdk_main_t * dm, dpdk_device_t * xd, struct rte_eth_dev_info * dev_info)
{
  vlib_pci_addr_t pci_addr = {
    .domain = dev_info->pci_dev->addr.domain,
      .bus = dev_info->pci_dev->addr.bus,
      .slot = dev_info->pci_dev->addr.devid,
      .function = dev_info->pci_dev->addr.function,
  };
  uword * conf_idx = hash_get (offload_main.conf_index_by_pci_addr, pci_addr.as_u32);
  if (conf_idx == 0)
    return;

  clib_warning("device %U offload config", format_vlib_pci_addr, &pci_addr);
  hash_set (offload_main.conf_index_by_device_index, xd->device_index, *conf_idx);

  //XXX if pmd == i40e
  xd->port_conf.fdir_conf.mode = RTE_FDIR_MODE_PERFECT;

  dpdk_offload_device_config_t * dev_conf = pool_elt_at_index(offload_main.dev_confs, conf_idx[0]);
  dpdk_offload_setup_workers (xd, &dev_conf->vxlan_rx, dpdk_vxlan_offload_input_node.index);
}


static clib_error_t * dpdk_offload_main_init (vlib_main_t * vm)
{
  clib_warning("offload init");
  return 0;
}



VLIB_INIT_FUNCTION (dpdk_offload_main_init);

/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () = {
    .version = VPP_BUILD_VER,
    .description = "DPDK offload",
};
/* *INDENT-ON* */
