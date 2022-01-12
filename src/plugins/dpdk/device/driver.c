/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2021 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>

#include <dpdk/device/dpdk.h>

static const u32 supported_flow_actions_intel =
  (VNET_FLOW_ACTION_MARK | VNET_FLOW_ACTION_REDIRECT_TO_NODE |
   VNET_FLOW_ACTION_REDIRECT_TO_QUEUE | VNET_FLOW_ACTION_BUFFER_ADVANCE |
   VNET_FLOW_ACTION_COUNT | VNET_FLOW_ACTION_DROP | VNET_FLOW_ACTION_RSS);

#define DPDK_DRIVERS(...)                                                     \
  (dpdk_driver_name_t[])                                                      \
  {                                                                           \
    __VA_ARGS__, {}                                                           \
  }

static dpdk_driver_t dpdk_drivers[] = {
  {
    .drivers = DPDK_DRIVERS ({ "net_ice", "Intel E810 Family" },
			     { "net_igc", "Intel I225 2.5G Family" },
			     { "net_e1000_igb", "Intel e1000" },
			     { "net_e1000_em", "Intel 82540EM (e1000)" }),
    .enable_rxq_int = 1,
    .supported_flow_actions = supported_flow_actions_intel,
    .use_intel_phdr_cksum = 1,
  },
  {
    .drivers = DPDK_DRIVERS ({ "net_ixgbe", "Intel 82599" }),
    .enable_rxq_int = 1,
    .program_vlans = 1,
    .supported_flow_actions = supported_flow_actions_intel,
    .use_intel_phdr_cksum = 1,
  },
  {
    .drivers = DPDK_DRIVERS ({ "net_i40e", "Intel X710/XL710 Family" }),
    .enable_rxq_int = 1,
    .supported_flow_actions = supported_flow_actions_intel,
    .use_intel_phdr_cksum = 1,
    .int_unmaskable = 1,
  },
  {
    .drivers = DPDK_DRIVERS ({ "net_liovf", "Cavium Lio VF" },
			     { "net_thunderx", "Cavium ThunderX" }),
    .interface_name_prefix = "VirtualFunctionEthernet",
  },
  {
    .drivers = DPDK_DRIVERS ({ "net_iavf", "Intel iAVF" },
			     { "net_i40e_vf", "Intel X710/XL710 Family VF" }),
    .interface_name_prefix = "VirtualFunctionEthernet",
    .supported_flow_actions = supported_flow_actions_intel,
    .use_intel_phdr_cksum = 1,
    .int_unmaskable = 1,
  },
  {
    .drivers = DPDK_DRIVERS ({ "net_e1000_igb_vf", "Intel e1000 VF" },
			     { "net_ixgbe_vf", "Intel 82599 VF" }),
    .interface_name_prefix = "VirtualFunctionEthernet",
    .use_intel_phdr_cksum = 1,
  },
  {
    .drivers = DPDK_DRIVERS ({ "net_dpaa2", "NXP DPAA2 Mac" }),
    .interface_name_prefix = "TenGigabitEthernet",
  },
  {
    .drivers =
      DPDK_DRIVERS ({ "net_fm10k", "Intel FM10000 Family Ethernet Switch" }),
    .interface_name_prefix = "EthernetSwitch",
  },
  {
    .drivers = DPDK_DRIVERS ({ "net_cxgbe", "Chelsio T4/T5" }),
    .interface_number_from_port_id = 1,
  },
  {
    .drivers = DPDK_DRIVERS ({ "net_mlx4", "Mellanox ConnectX-3 Family" },
			     { "net_qede", "Cavium QLogic FastLinQ QL4xxxx" },
			     { "net_bnxt", "Broadcom NetXtreme E/S-Series" }),
  },
  {
    .drivers = DPDK_DRIVERS ({ "net_virtio_user", "Virtio User" }),
    .interface_name_prefix = "VirtioUser",
  },
  {
    .drivers = DPDK_DRIVERS ({ "net_vhost", "VhostEthernet" }),
    .interface_name_prefix = "VhostEthernet",
  },
  {
    .drivers = DPDK_DRIVERS ({ "mlx5_pci", "Mellanox ConnectX-4 Family" },
			     { "net_enic", "Cisco VIC" }),
    .use_intel_phdr_cksum = 1,
  },
  {
    .drivers = DPDK_DRIVERS ({ "net_failsafe", "FailsafeEthernet" }),
    .interface_name_prefix = "FailsafeEthernet",
    .enable_lsc_int = 1,
  },
  {
    .drivers = DPDK_DRIVERS ({ "AF_PACKET PMD", "af_packet" }),
    .interface_name_prefix = "af_packet",
  },
  {
    .drivers = DPDK_DRIVERS ({ "net_netvsc", "Microsoft Hyper-V Netvsc" }),
    .interface_name_prefix = "NetVSC",
  },
  {
    .drivers = DPDK_DRIVERS ({ "net_ena", "AWS ENA VF" }),
    .interface_name_prefix = "VirtualFunctionEthernet",
    .enable_rxq_int = 1,
    .disable_rx_scatter = 1,
  },
  {
    .drivers = DPDK_DRIVERS ({ "net_vmxnet3", "VMware VMXNET3" }),
    .interface_name_prefix = "GigabitEthernet",
  },
  {
    .drivers = DPDK_DRIVERS ({ "net_virtio", "Red Hat Virtio" }),
    .interface_name_prefix = "GigabitEthernet",
    .n_rx_desc = 256,
    .n_tx_desc = 256,
    .mq_mode_none = 1,
  }
};

dpdk_driver_t *
dpdk_driver_find (const char *name, const char **desc)
{
  for (int i = 0; i < ARRAY_LEN (dpdk_drivers); i++)
    {
      dpdk_driver_t *dr = dpdk_drivers + i;
      dpdk_driver_name_t *dn = dr->drivers;

      while (dn->name)
	{
	  if (name && !strcmp (name, dn->name))
	    {
	      *desc = dn->desc;
	      return dr;
	    }
	  dn++;
	}
    }
  return 0;
}
