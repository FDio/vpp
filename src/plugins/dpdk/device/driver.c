/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2021 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>

#include <dpdk/device/dpdk.h>

static const u32 supported_flow_actions_intel =
  (VNET_FLOW_ACTION_MARK | VNET_FLOW_ACTION_REDIRECT_TO_NODE |
   VNET_FLOW_ACTION_REDIRECT_TO_QUEUE | VNET_FLOW_ACTION_BUFFER_ADVANCE |
   VNET_FLOW_ACTION_COUNT | VNET_FLOW_ACTION_DROP | VNET_FLOW_ACTION_RSS);

static dpdk_driver_t dpdk_drivers[] = {
  {
    .name = "net_ice",
    .desc = "Intel E810 Family",
    .dev_flags = DPDK_DEVICE_FLAG_INTEL_PHDR_CKSUM,
    .enable_rxq_int = 1,
    .supported_flow_actions = supported_flow_actions_intel,
  },
  {
    .name = "net_i40e",
    .desc = "Intel X710/XL710 Family",
    .dev_flags =
      DPDK_DEVICE_FLAG_INTEL_PHDR_CKSUM | DPDK_DEVICE_FLAG_INT_UNMASKABLE,
    .enable_rxq_int = 1,
    .supported_flow_actions = supported_flow_actions_intel,
  },
  {
    .name = "net_ixgbe",
    .desc = "Intel 82599",
    .dev_flags = DPDK_DEVICE_FLAG_INTEL_PHDR_CKSUM,
    .enable_rxq_int = 1,
    .program_vlans = 1,
    .supported_flow_actions = supported_flow_actions_intel,
  },
  {
    .name = "net_igc",
    .desc = "Intel I225 2.5G Family",
    .dev_flags = DPDK_DEVICE_FLAG_INTEL_PHDR_CKSUM,
    .enable_rxq_int = 1,
    .supported_flow_actions = supported_flow_actions_intel,
  },
  {
    .name = "net_e1000_igb",
    .desc = "Intel e1000",
    .dev_flags = DPDK_DEVICE_FLAG_INTEL_PHDR_CKSUM,
    .enable_rxq_int = 1,
    .supported_flow_actions = supported_flow_actions_intel,
  },
  {
    .name = "net_e1000_em",
    .desc = "Intel 82540EM (e1000)",
    .dev_flags = DPDK_DEVICE_FLAG_INTEL_PHDR_CKSUM,
    .enable_rxq_int = 1,
    .supported_flow_actions = supported_flow_actions_intel,
  },
  {
    .name = "net_iavf",
    .desc = "Intel iAVF",
    .interface_name_prefix = "VirtualFunctionEthernet",
    .dev_flags =
      DPDK_DEVICE_FLAG_INTEL_PHDR_CKSUM | DPDK_DEVICE_FLAG_INT_UNMASKABLE,
    .supported_flow_actions = supported_flow_actions_intel,
  },
  {
    .name = "net_i40e_vf",
    .desc = "Intel X710/XL710 Family VF",
    .interface_name_prefix = "VirtualFunctionEthernet",
    .dev_flags =
      DPDK_DEVICE_FLAG_INTEL_PHDR_CKSUM | DPDK_DEVICE_FLAG_INT_UNMASKABLE,
  },
  {
    .name = "net_e1000_igb_vf",
    .desc = "Intel e1000 VF",
    .interface_name_prefix = "VirtualFunctionEthernet",
    .dev_flags = DPDK_DEVICE_FLAG_INTEL_PHDR_CKSUM,
  },
  {
    .name = "net_ixgbe_vf",
    .desc = "Intel 82599 VF",
    .interface_name_prefix = "VirtualFunctionEthernet",
    .dev_flags = DPDK_DEVICE_FLAG_INTEL_PHDR_CKSUM,
  },
  {
    .name = "net_dpaa2",
    .desc = "NXP DPAA2 Mac",
    .interface_name_prefix = "TenGigabitEthernet",
  },
  {
    .name = "net_fm10k",
    .desc = "Intel FM10000 Family Ethernet Switch",
    .interface_name_prefix = "EthernetSwitch",
  },
  {
    .name = "net_cxgbe",
    .desc = "Chelsio T4/T5",
    .interface_number_from_port_id = 1,
  },
  {
    .name = "net_mlx4",
    .desc = "Mellanox ConnectX-3 Family",
  },
  {
    .name = "net_qede",
    .desc = "Cavium QLogic FastLinQ QL4xxxx",
  },
  {
    .name = "net_bnxt",
    .desc = "Broadcom NetXtreme E/S-Series",
  },
  {
    .name = "net_virtio_user",
    .desc = "Virtio User",
    .interface_name_prefix = "VirtioUser",
  },
  {
    .name = "net_vhost",
    .desc = "VhostEthernet",
    .interface_name_prefix = "VhostEthernet",
  },
  {
    .name = "net_liovf",
    .desc = "Cavium Lio VF",
    .interface_name_prefix = "VirtualFunctionEthernet",
  },
  {
    .name = "net_thunderx",
    .desc = "Cavium ThunderX",
    .interface_name_prefix = "VirtualFunctionEthernet",
  },
  {
#if RTE_VERSION < RTE_VERSION_NUM(20, 8, 0, 0)
    .name = "net_mlx5",
#else
    .name = "mlx5_pci",
#endif
    .desc = "Mellanox ConnectX-4 Family",
    .dev_flags = DPDK_DEVICE_FLAG_INTEL_PHDR_CKSUM,
  },
  {
    .name = "net_failsafe",
    .desc = "FailsafeEthernet",
    .interface_name_prefix = "FailsafeEthernet",
    .enable_lsc_int = 1,
  },
  {
    .name = "AF_PACKET PMD",
    .desc = "af_packet",
    .interface_name_prefix = "af_packet",
  },
  {
    .name = "net_netvsc",
    .desc = "Microsoft Hyper-V Netvsc",
    .interface_name_prefix = "NetVSC",
  },
  {
    .name = "net_ena",
    .desc = "AWS ENA VF",
    .interface_name_prefix = "VirtualFunctionEthernet",
    .enable_rxq_int = 1,
    .disable_rx_scatter = 1,
  },
  {
    /* Cisco VIC */
    .name = "net_enic",
    .desc = "Cisco VIC",
    .dev_flags = DPDK_DEVICE_FLAG_INTEL_PHDR_CKSUM,
  },
  {
    /* vmxnet3 */
    .name = "net_vmxnet3",
    .desc = "VMware VMXNET3",
    .interface_name_prefix = "GigabitEthernet",
  },
  {
    .name = "net_virtio",
    .desc = "Red Hat Virtio",
    .interface_name_prefix = "GigabitEthernet",
    .n_rx_desc = 256,
    .n_tx_desc = 256,
    .mq_mode_none = 1,
  }
};

dpdk_driver_t *
dpdk_driver_find (const char *name)
{
  for (int i = 0; i < ARRAY_LEN (dpdk_drivers); i++)
    {
      dpdk_driver_t *dr = dpdk_drivers + i;
      if (name && !strcmp (name, dr->name))
	return dr;
    }
  return 0;
}
