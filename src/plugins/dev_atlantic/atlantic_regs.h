/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Damjan Marion
 */

#pragma once

#include <vppinfra/clib.h>
#include <vppinfra/error_bootstrap.h>
#include <vppinfra/format.h>
#include <vnet/vnet.h>
#include <vnet/dev/dev.h>

#define __(n, f) u32 f : n;

#define ATL_REG_STRUCT_IMPL(name_str, name_fields)                            \
  typedef union                                                               \
  {                                                                           \
    struct                                                                    \
    {                                                                         \
      name_fields                                                             \
    };                                                                        \
    u32 as_u32;                                                               \
  } name_str;                                                                 \
  STATIC_ASSERT_SIZEOF (name_str, 4);

#define ATL_REG_STRUCT(name) ATL_REG_STRUCT_IMPL (name, name##_fields)

#define atl_fw_softreset_reg_fields                                           \
  __ (14, _reserved_0_13)                                                     \
  __ (1, softreset_dis)                                                       \
  __ (1, softreset_reset)                                                     \
  __ (16, _reserved_16_31)

ATL_REG_STRUCT (atl_fw_softreset_reg);

/* Hardware revision register (low nibble carries silicon revision ID). */
#define atl_hw_revision_reg_fields                                            \
  __ (4, rev_id)                                                              \
  __ (28, _reserved_4_31)
ATL_REG_STRUCT (atl_hw_revision_reg);

/* Atlantic2 MCP host request interrupt register. */
#define atl_aq2_mcp_host_req_int_reg_fields                                   \
  __ (1, ready)                                                               \
  __ (31, _reserved_1_31)
ATL_REG_STRUCT (atl_aq2_mcp_host_req_int_reg);

/* Atlantic2 MIF boot status register. */
#define atl_aq2_mif_boot_reg_fields                                           \
  __ (16, _reserved_0_15)                                                     \
  __ (1, host_data_loaded)                                                    \
  __ (7, _reserved_17_23)                                                     \
  __ (1, boot_started)                                                        \
  __ (2, _reserved_25_26)                                                     \
  __ (1, crash_init)                                                          \
  __ (1, boot_code_failed)                                                    \
  __ (1, fw_init_failed)                                                      \
  __ (1, _reserved_30)                                                        \
  __ (1, fw_init_comp_success)
ATL_REG_STRUCT (atl_aq2_mif_boot_reg);

/* Atlantic2 firmware interface OUT transaction id register. */
#define atl_aq2_fw_interface_out_transaction_id_reg_fields                    \
  __ (16, id_a)                                                               \
  __ (16, id_b)
ATL_REG_STRUCT (atl_aq2_fw_interface_out_transaction_id_reg);

/* Atlantic2 firmware interface OUT version iface register. */
#define atl_aq2_fw_interface_out_version_iface_reg_fields                     \
  __ (4, iface_ver)                                                           \
  __ (28, _reserved_4_31)
ATL_REG_STRUCT (atl_aq2_fw_interface_out_version_iface_reg);

/* From if_aq_pci.c */
#define AQ_FW_SOFTRESET_REG			  0x0000
#define AQ_FW_VERSION_REG			  0x0018
#define AQ_HW_REVISION_REG			  0x001c
#define AQ2_HW_FPGA_VERSION_REG			  0x00f4
#define AQ_GLB_NVR_INTERFACE1_REG		  0x0100
#define AQ_FW_MBOX_CMD_REG			  0x0200
#define AQ_FW_MBOX_ADDR_REG			  0x0208
#define AQ_FW_MBOX_VAL_REG			  0x020C
#define AQ_FW_GLB_CPU_SEM_REG(i)		  (0x03a0 + (i) *4)
#define AQ_FW_GLB_CTL2_REG			  0x0404
#define AQ_GLB_GENERAL_PROVISIONING9_REG	  0x0520
#define AQ_GLB_NVR_PROVISIONING2_REG		  0x0534
#define AQ_INTR_STATUS_REG			  0x2000
#define AQ_INTR_STATUS_CLR_REG			  0x2050
#define AQ_INTR_MASK_REG			  0x2060
#define AQ_INTR_MASK_CLR_REG			  0x2070
#define AQ_INTR_AUTOMASK_REG			  0x2090
#define AQ_SMB_PROVISIONING_REG			  0x0604
#define AQ_SMB_TX_DATA_REG			  0x0608
#define AQ_SMB_BUS_REG				  0x0744
#define AQ_SMB_RX_DATA_REG			  0x0748
#define AQ_INTR_IRQ_MAP_TXRX_REG(i)		  (0x2100 + ((i) / 2) * 4)
#define AQ_GEN_INTR_MAP_REG(i)			  (0x2180 + (i) *4)
#define AQ_INTR_CTRL_REG			  0x2300
#define AQ_MBOXIF_POWER_GATING_CONTROL_REG	  0x32a8
#define FW_MPI_MBOX_ADDR_REG			  0x0360
#define FW1X_MPI_INIT1_REG			  0x0364
#define FW1X_MPI_INIT2_REG			  0x0370
#define FW1X_MPI_EFUSEADDR_REG			  0x0374
#define FW2X_MPI_EFUSEADDR_REG			  0x0364
#define FW2X_MPI_CONTROL_REG			  0x0368
#define FW2X_MPI_STATE_REG			  0x0370
#define FW_BOOT_EXIT_CODE_REG			  0x0388
#define FW_MPI_DAISY_CHAIN_STATUS_REG		  0x0704
#define AQ_PCI_REG_CONTROL_6_REG		  0x1014
#define FW_MPI_RESETCTRL_REG			  0x4000
#define RX_SYSCONTROL_REG			  0x5000
#define AQ2_FW_INTERFACE_IN_MAC_ADDRESS_REG	  0x12008
#define AQ2_MIF_HOST_FINISHED_STATUS_WRITE_REG	  0x0e00
#define AQ2_MIF_HOST_FINISHED_STATUS_READ_REG	  0x0e04
#define AQ2_MCP_HOST_REQ_INT_REG		  0x0f00
#define AQ2_MCP_HOST_REQ_INT_SET_REG		  0x0f04
#define AQ2_MCP_HOST_REQ_INT_CLR_REG		  0x0f08
#define AQ2_MIF_BOOT_REG			  0x3040
#define AQ2_FW_INTERFACE_OUT_TRANSACTION_ID_REG	  0x13000
#define AQ2_FW_INTERFACE_OUT_TRANSACTION_ID_B	  0xffff0000
#define AQ2_FW_INTERFACE_OUT_TRANSACTION_ID_B_S	  16
#define AQ2_FW_INTERFACE_OUT_TRANSACTION_ID_A	  0x0000ffff
#define AQ2_FW_INTERFACE_OUT_TRANSACTION_ID_A_S	  0
#define AQ2_FW_INTERFACE_OUT_VERSION_BUNDLE_REG	  0x13004
#define AQ2_FW_INTERFACE_OUT_VERSION_MAC_REG	  0x13008
#define AQ2_FW_INTERFACE_OUT_VERSION_PHY_REG	  0x1300c
#define AQ2_FW_INTERFACE_OUT_VERSION_BUILD	  0xffff0000
#define AQ2_FW_INTERFACE_OUT_VERSION_BUILD_S	  16
#define AQ2_FW_INTERFACE_OUT_VERSION_MINOR	  0x0000ff00
#define AQ2_FW_INTERFACE_OUT_VERSION_MINOR_S	  8
#define AQ2_FW_INTERFACE_OUT_VERSION_MAJOR	  0x000000ff
#define AQ2_FW_INTERFACE_OUT_VERSION_MAJOR_S	  0
#define AQ2_FW_INTERFACE_OUT_VERSION_IFACE_REG	  0x13010
#define AQ2_FW_INTERFACE_OUT_VERSION_IFACE_VER	  0x0000000f
#define AQ2_FW_INTERFACE_OUT_VERSION_IFACE_VER_A0 0
#define AQ2_FW_INTERFACE_OUT_VERSION_IFACE_VER_B0 1

#define AQ2_MIF_BOOT_HOST_DATA_LOADED	  (1 << 16)
#define AQ2_MIF_BOOT_BOOT_STARTED	  (1 << 24)
#define AQ2_MIF_BOOT_CRASH_INIT		  (1 << 27)
#define AQ2_MIF_BOOT_BOOT_CODE_FAILED	  (1 << 28)
#define AQ2_MIF_BOOT_CRASH_INIT		  (1 << 27)
#define AQ2_MIF_BOOT_FW_INIT_FAILED	  (1 << 29)
#define AQ2_MIF_BOOT_FW_INIT_COMP_SUCCESS (1U << 31)
#define AQ2_MCP_HOST_REQ_INT_READY	  (1 << 0)
