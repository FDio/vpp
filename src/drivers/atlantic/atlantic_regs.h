/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Damjan Marion
 */

#pragma once

#include <vppinfra/clib.h>
#include <vppinfra/error_bootstrap.h>
#include <vppinfra/format.h>
#include <vnet/vnet.h>
#include <vnet/dev/dev.h>

/* Registers */

#define ATL_REG_GLB_CPU_SCRATCH_SCP(i) (0x00000300 + (i) *0x4)

#define atl_reg_fw_softreset_t_fields                                                              \
  __ (14, _reserved_0_13)                                                                          \
  __ (1, softreset_dis)                                                                            \
  __ (1, softreset_reset)                                                                          \
  __ (16, _reserved_16_31)

#define atl_reg_glb_mif_id_t_fields                                                                \
  __ (8, mif_id)                                                                                   \
  __ (24, _reserved_8_31)

#define atl_reg_aq2_mcp_host_req_int_t_fields                                                      \
  __ (1, ready)                                                                                    \
  __ (31, _reserved_1_31)

#define atl_reg_aq2_mif_boot_t_fields                                                              \
  __ (16, _reserved_0_15)                                                                          \
  __ (1, host_data_loaded)                                                                         \
  __ (7, _reserved_17_23)                                                                          \
  __ (1, boot_started)                                                                             \
  __ (2, _reserved_25_26)                                                                          \
  __ (1, crash_init)                                                                               \
  __ (1, boot_code_failed)                                                                         \
  __ (1, fw_init_failed)                                                                           \
  __ (1, _reserved_30)                                                                             \
  __ (1, fw_init_comp_success)

#define atl_reg_aq2_fw_interface_out_transaction_id_t_fields                                       \
  __ (16, id_a)                                                                                    \
  __ (16, id_b)

#define atl_reg_aq2_fw_interface_out_link_status_t_fields                                          \
  __ (4, link_state)                                                                               \
  __ (4, link_rate)                                                                                \
  __ (1, pause_tx)                                                                                 \
  __ (1, pause_rx)                                                                                 \
  __ (1, eee)                                                                                      \
  __ (1, duplex)                                                                                   \
  __ (20, _reserved_12_31)

#define atl_reg_aq2_fw_interface_out_device_link_caps_t_fields                                     \
  __ (3, _reserved_0_2)                                                                            \
  __ (1, internal_loopback)                                                                        \
  __ (1, external_loopback)                                                                        \
  __ (1, rate_10m_hd)                                                                              \
  __ (1, rate_100m_hd)                                                                             \
  __ (1, rate_1g_hd)                                                                               \
  __ (1, rate_10m)                                                                                 \
  __ (1, rate_100m)                                                                                \
  __ (1, rate_1g)                                                                                  \
  __ (1, rate_2p5g)                                                                                \
  __ (1, rate_n2p5g)                                                                               \
  __ (1, rate_5g)                                                                                  \
  __ (1, rate_n5g)                                                                                 \
  __ (1, rate_10g)                                                                                 \
  __ (1, _reserved_16)                                                                             \
  __ (1, eee_100m)                                                                                 \
  __ (1, eee_1g)                                                                                   \
  __ (1, eee_2p5g)                                                                                 \
  __ (1, _reserved_20)                                                                             \
  __ (1, eee_5g)                                                                                   \
  __ (1, _reserved_22)                                                                             \
  __ (1, eee_10g)                                                                                  \
  __ (1, pause_rx)                                                                                 \
  __ (1, pause_tx)                                                                                 \
  __ (1, pfc)                                                                                      \
  __ (1, downshift)                                                                                \
  __ (4, downshift_retry)

#define atl_reg_aq2_fw_interface_out_lkp_link_caps_t_fields                                        \
  __ (5, _reserved_0_4)                                                                            \
  __ (1, rate_10m_hd)                                                                              \
  __ (1, rate_100m_hd)                                                                             \
  __ (1, rate_1g_hd)                                                                               \
  __ (1, rate_10m)                                                                                 \
  __ (1, rate_100m)                                                                                \
  __ (1, rate_1g)                                                                                  \
  __ (1, rate_2p5g)                                                                                \
  __ (1, rate_n2p5g)                                                                               \
  __ (1, rate_5g)                                                                                  \
  __ (1, rate_n5g)                                                                                 \
  __ (1, rate_10g)                                                                                 \
  __ (1, _reserved_16)                                                                             \
  __ (1, eee_100m)                                                                                 \
  __ (1, eee_1g)                                                                                   \
  __ (1, eee_2p5g)                                                                                 \
  __ (1, _reserved_20)                                                                             \
  __ (1, eee_5g)                                                                                   \
  __ (1, _reserved_22)                                                                             \
  __ (1, eee_10g)                                                                                  \
  __ (1, pause_rx)                                                                                 \
  __ (1, pause_tx)                                                                                 \
  __ (6, _reserved_26_31)

#define atl_reg_aq2_fw_interface_out_version_iface_t_fields                                        \
  __ (4, iface_ver)                                                                                \
  __ (28, _reserved_4_31)

#define atl_reg_aq2_launchtime_ctrl_t_fields                                                       \
  __ (8, _reserved_0_7)                                                                            \
  __ (8, ratio)                                                                                    \
  __ (16, _reserved_16_31)

#define atl_reg_tpb_tx_buf_t_fields                                                                \
  __ (1, en)                                                                                       \
  __ (1, _reserved_1)                                                                              \
  __ (1, scp_ins_en)                                                                               \
  __ (2, _reserved_3_4)                                                                            \
  __ (1, clk_gate_en)                                                                              \
  __ (2, _reserved_6_7)                                                                            \
  __ (1, tc_mode_en)                                                                               \
  __ (1, tc_q_rand_map_en)                                                                         \
  __ (22, _reserved_10_31)

#define atl_reg_thm_lso_tcp_flag_t_fields                                                          \
  __ (12, val)                                                                                     \
  __ (20, _reserved_12_31)

#define atl_reg_tx_tpo2_t_fields                                                                   \
  __ (16, _reserved_0_15)                                                                          \
  __ (1, en)                                                                                       \
  __ (15, _reserved_17_31)

#define atl_reg_tdm_dca_t_fields                                                                   \
  __ (4, mode)                                                                                     \
  __ (27, _reserved_4_30)                                                                          \
  __ (1, en)

#define atl_reg_rpb_rpf_rx_t_fields                                                                \
  __ (1, buf_en)                                                                                   \
  __ (3, _reserved_1_3)                                                                            \
  __ (2, fc_mode)                                                                                  \
  __ (2, _reserved_6_7)                                                                            \
  __ (1, tc_mode)                                                                                  \
  __ (23, _reserved_9_31)

#define atl_reg_aq2_rpf_redir2_t_fields                                                            \
  __ (9, hashtype)                                                                                 \
  __ (3, _reserved_9_11)                                                                           \
  __ (1, index)                                                                                    \
  __ (19, _reserved_13_31)

#define atl_reg_rx_flr_rss_control1_t_fields                                                       \
  __ (31, queues)                                                                                  \
  __ (1, en)

#define atl_reg_rpf_ethertype_filter_t_fields                                                      \
  __ (31, _reserved_0_30)                                                                          \
  __ (1, en)

#define atl_reg_rpf_l2uc_msw_t_fields                                                              \
  __ (16, macaddr_hi)                                                                              \
  __ (3, action)                                                                                   \
  __ (3, _reserved_19_21)                                                                          \
  __ (6, tag)                                                                                      \
  __ (3, _reserved_28_30)                                                                          \
  __ (1, en)

#define atl_reg_rpf_mcast_filter_t_fields                                                          \
  __ (31, _reserved_0_30)                                                                          \
  __ (1, en)

#define atl_reg_rpf_l2bc_t_fields                                                                  \
  __ (1, en)                                                                                       \
  __ (2, _reserved_1_2)                                                                            \
  __ (1, promisc)                                                                                  \
  __ (8, _reserved_4_11)                                                                           \
  __ (3, action)                                                                                   \
  __ (1, _reserved_15)                                                                             \
  __ (16, threshold)

#define atl_reg_rpf_vlan_tpid_t_fields                                                             \
  __ (16, inner)                                                                                   \
  __ (16, outer)

#define atl_reg_rpf_vlan_mode_t_fields                                                             \
  __ (1, _reserved_0)                                                                              \
  __ (1, promisc)                                                                                  \
  __ (1, accept_untagged)                                                                          \
  __ (3, untagged_action)                                                                          \
  __ (26, _reserved_6_31)

#define atl_reg_aq2_rpf_rec_tab_enable_t_fields                                                    \
  __ (16, mask)                                                                                    \
  __ (16, _reserved_16_31)

#define atl_reg_aq2_rpf_l2bc_tag_t_fields                                                          \
  __ (6, tag)                                                                                      \
  __ (26, _reserved_6_31)

#define atl_reg_aq2_rpf_new_ctrl_t_fields                                                          \
  __ (11, _reserved_0_10)                                                                          \
  __ (1, enable)                                                                                   \
  __ (20, _reserved_12_31)

#define atl_reg_rx_dma_dca_t_fields                                                                \
  __ (4, mode)                                                                                     \
  __ (27, _reserved_4_30)                                                                          \
  __ (1, en)

#define atl_reg_tps_desc_rate_t_fields                                                             \
  __ (11, lim)                                                                                     \
  __ (20, _reserved_11_30)                                                                         \
  __ (1, ta_rst)

#define atl_reg_tps_desc_vm_arb_mode_t_fields                                                      \
  __ (1, mode)                                                                                     \
  __ (31, _reserved_1_31)

#define atl_reg_tps_desc_tc_arb_mode_t_fields                                                      \
  __ (2, mode)                                                                                     \
  __ (30, _reserved_2_31)

#define atl_reg_tps_data_tc_arb_mode_t_fields                                                      \
  __ (1, mode)                                                                                     \
  __ (31, _reserved_1_31)

#define atl_reg_tps_data_tct_t_fields                                                              \
  __ (16, weight)                                                                                  \
  __ (16, credit_max)

#define atl_reg_tps_desc_tct_t_fields                                                              \
  __ (9, weight)                                                                                   \
  __ (19, _reserved_9_27)                                                                          \
  __ (4, credit_max)

#define atl_reg_tpb_txb_bufsize_t_fields                                                           \
  __ (8, bufsize)                                                                                  \
  __ (24, _reserved_8_31)

#define atl_reg_tpb_txb_thresh_t_fields                                                            \
  __ (13, lo)                                                                                      \
  __ (3, _reserved_13_15)                                                                          \
  __ (13, hi)                                                                                      \
  __ (3, _reserved_29_31)

#define atl_reg_rpb_rxb_bufsize_t_fields                                                           \
  __ (9, bufsize)                                                                                  \
  __ (23, _reserved_9_31)

#define atl_reg_rpb_rxb_xoff_t_fields                                                              \
  __ (13, lo)                                                                                      \
  __ (3, _reserved_13_15)                                                                          \
  __ (13, hi)                                                                                      \
  __ (2, _reserved_29_30)                                                                          \
  __ (1, en)

#define atl_reg_aq_intr_ctrl_t_fields                                                              \
  __ (2, irqmode)                                                                                  \
  __ (1, multivec)                                                                                 \
  __ (26, _reserved_3_28)                                                                          \
  __ (1, reset_dis)                                                                                \
  __ (2, _reserved_30_31)

#define atl_reg_rx_dma_desc_cache_init_t_fields                                                    \
  __ (1, init)                                                                                     \
  __ (31, _reserved_1_31)

#define atl_reg_rx_dma_desc_base_addrlsw_t_fields __ (32, addr)

#define atl_reg_rx_dma_desc_base_addrmsw_t_fields __ (32, addr)

#define atl_reg_rx_dma_desc_len_t_fields                                                           \
  __ (3, _reserved_0_2)                                                                            \
  __ (10, len)                                                                                     \
  __ (12, _reserved_13_24)                                                                         \
  __ (1, reset)                                                                                    \
  __ (2, _reserved_26_27)                                                                          \
  __ (1, header_split)                                                                             \
  __ (1, vlan_strip)                                                                               \
  __ (1, _reserved_30)                                                                             \
  __ (1, en)

#define atl_reg_rx_dma_desc_data_hdr_size_t_fields                                                 \
  __ (5, data_size)                                                                                \
  __ (3, _reserved_5_7)                                                                            \
  __ (5, hdr_size)                                                                                 \
  __ (19, _reserved_13_31)

#define atl_reg_rx_dma_desc_tail_ptr_t_fields                                                      \
  __ (13, ptr)                                                                                     \
  __ (19, _reserved_13_31)

#define atl_reg_rx_dma_int_desc_wrwb_en_t_fields                                                   \
  __ (2, _reserved_0_1)                                                                            \
  __ (1, wrwb_en)                                                                                  \
  __ (1, moderate_en)                                                                              \
  __ (28, _reserved_4_31)

#define atl_reg_tx_dma_desc_base_addrlsw_t_fields __ (32, addr)

#define atl_reg_tx_dma_desc_base_addrmsw_t_fields __ (32, addr)

#define atl_reg_tx_dma_desc_len_t_fields                                                           \
  __ (3, _reserved_0_2)                                                                            \
  __ (10, len)                                                                                     \
  __ (18, _reserved_13_30)                                                                         \
  __ (1, en)

#define atl_reg_tx_dma_desc_tail_ptr_t_fields                                                      \
  __ (13, ptr)                                                                                     \
  __ (19, _reserved_13_31)

#define atl_reg_tx_dma_int_desc_wrwb_en_t_fields                                                   \
  __ (1, _reserved_0)                                                                              \
  __ (1, wrwb_en)                                                                                  \
  __ (2, _reserved_2_3)                                                                            \
  __ (1, moderate_en)                                                                              \
  __ (27, _reserved_5_31)

#define atl_reg_aq2_cable_diag_lane_data_t_fields                                                  \
  __ (8, result_code)                                                                              \
  __ (8, dist)                                                                                     \
  __ (8, far_dist)                                                                                 \
  __ (8, _reserved_24_31)

#define atl_reg_aq2_cable_diag_status_t_fields                                                     \
  __ (8, transact_id)                                                                              \
  __ (4, status)                                                                                   \
  __ (20, _reserved_12_31)

#define atl_reg_aq2_fw_interface_in_link_control_t_fields                                          \
  __ (4, mode)                                                                                     \
  __ (28, _reserved_4_31)

#define atl_reg_aq2_fw_interface_in_link_options_t_fields                                          \
  __ (1, link_up)                                                                                  \
  __ (1, link_renegotiate)                                                                         \
  __ (1, minimal_link_speed)                                                                       \
  __ (1, internal_loopback)                                                                        \
  __ (1, external_loopback)                                                                        \
  __ (3, rate_hd)                                                                                  \
  __ (8, rate)                                                                                     \
  __ (5, eee)                                                                                      \
  __ (3, _reserved_21_23)                                                                          \
  __ (1, pause_rx)                                                                                 \
  __ (1, pause_tx)                                                                                 \
  __ (1, _reserved_26)                                                                             \
  __ (1, downshift)                                                                                \
  __ (4, _reserved_28_31)

#define atl_reg_aq2_fw_interface_in_cable_diag_control_t_fields                                    \
  __ (1, toggle)                                                                                   \
  __ (7, _reserved_1_7)                                                                            \
  __ (8, wait_timeout_sec)                                                                         \
  __ (16, _reserved_16_31)

#define atl_reg_aq2_mac_health_monitor_t_fields                                                    \
  __ (1, mac_ready)                                                                                \
  __ (1, mac_fault)                                                                                \
  __ (1, mac_flashless_finished)                                                                   \
  __ (5, _reserved_3_7)                                                                            \
  __ (8, mac_temperature)                                                                          \
  __ (16, mac_heart_beat)

#define atl_reg_aq2_phy_health_monitor_t_fields                                                    \
  __ (1, phy_ready)                                                                                \
  __ (1, phy_fault)                                                                                \
  __ (1, phy_hot_warning)                                                                          \
  __ (5, _reserved_3_7)                                                                            \
  __ (8, phy_temperature)                                                                          \
  __ (16, phy_heart_beat)

#define atl_reg_aq2_device_caps_t_fields                                                           \
  __ (1, finite_flashless)                                                                         \
  __ (1, cable_diag)                                                                               \
  __ (1, ncsi)                                                                                     \
  __ (1, avb)                                                                                      \
  __ (28, _reserved_4_31)

#define atl_reg_aq2_management_status_flags_t_fields                                               \
  __ (1, enable)                                                                                   \
  __ (31, _reserved_1_31)

#define atl_reg_mpi_control2_t_fields                                                              \
  __ (18, _reserved_0_17)                                                                          \
  __ (1, temperature)                                                                              \
  __ (13, _reserved_19_31)

#define atl_reg_mpi_state2_t_fields                                                                \
  __ (18, _reserved_0_17)                                                                          \
  __ (1, temperature)                                                                              \
  __ (13, _reserved_19_31)

#define ATL_REG_STRUCT(n)                                                                          \
  typedef union                                                                                    \
  {                                                                                                \
    struct                                                                                         \
    {                                                                                              \
      n##_fields;                                                                                  \
    };                                                                                             \
    u32 as_u32;                                                                                    \
  } n;                                                                                             \
  STATIC_ASSERT_SIZEOF (n, 4);

#define __(n, f) u32 f : n;
ATL_REG_STRUCT (atl_reg_fw_softreset_t);
ATL_REG_STRUCT (atl_reg_glb_mif_id_t);
ATL_REG_STRUCT (atl_reg_aq2_mcp_host_req_int_t);
ATL_REG_STRUCT (atl_reg_aq2_mif_boot_t);
ATL_REG_STRUCT (atl_reg_aq2_fw_interface_out_transaction_id_t);
ATL_REG_STRUCT (atl_reg_aq2_fw_interface_out_link_status_t);
ATL_REG_STRUCT (atl_reg_aq2_fw_interface_out_device_link_caps_t);
ATL_REG_STRUCT (atl_reg_aq2_fw_interface_out_lkp_link_caps_t);
ATL_REG_STRUCT (atl_reg_aq2_fw_interface_out_version_iface_t);
ATL_REG_STRUCT (atl_reg_aq2_launchtime_ctrl_t);
ATL_REG_STRUCT (atl_reg_tpb_tx_buf_t);
ATL_REG_STRUCT (atl_reg_thm_lso_tcp_flag_t);
ATL_REG_STRUCT (atl_reg_tx_tpo2_t);
ATL_REG_STRUCT (atl_reg_tdm_dca_t);
ATL_REG_STRUCT (atl_reg_rpb_rpf_rx_t);
ATL_REG_STRUCT (atl_reg_aq2_rpf_redir2_t);
ATL_REG_STRUCT (atl_reg_rx_flr_rss_control1_t);
ATL_REG_STRUCT (atl_reg_rpf_ethertype_filter_t);
ATL_REG_STRUCT (atl_reg_rpf_l2uc_msw_t);
ATL_REG_STRUCT (atl_reg_rpf_mcast_filter_t);
ATL_REG_STRUCT (atl_reg_rpf_l2bc_t);
ATL_REG_STRUCT (atl_reg_rpf_vlan_tpid_t);
ATL_REG_STRUCT (atl_reg_rpf_vlan_mode_t);
ATL_REG_STRUCT (atl_reg_aq2_rpf_rec_tab_enable_t);
ATL_REG_STRUCT (atl_reg_aq2_rpf_l2bc_tag_t);
ATL_REG_STRUCT (atl_reg_aq2_rpf_new_ctrl_t);
ATL_REG_STRUCT (atl_reg_rx_dma_dca_t);
ATL_REG_STRUCT (atl_reg_tps_desc_rate_t);
ATL_REG_STRUCT (atl_reg_tps_desc_vm_arb_mode_t);
ATL_REG_STRUCT (atl_reg_tps_desc_tc_arb_mode_t);
ATL_REG_STRUCT (atl_reg_tps_data_tc_arb_mode_t);
ATL_REG_STRUCT (atl_reg_tps_data_tct_t);
ATL_REG_STRUCT (atl_reg_tps_desc_tct_t);
ATL_REG_STRUCT (atl_reg_tpb_txb_bufsize_t);
ATL_REG_STRUCT (atl_reg_tpb_txb_thresh_t);
ATL_REG_STRUCT (atl_reg_rpb_rxb_bufsize_t);
ATL_REG_STRUCT (atl_reg_rpb_rxb_xoff_t);
ATL_REG_STRUCT (atl_reg_aq_intr_ctrl_t);
ATL_REG_STRUCT (atl_reg_rx_dma_desc_cache_init_t);
ATL_REG_STRUCT (atl_reg_rx_dma_desc_base_addrlsw_t);
ATL_REG_STRUCT (atl_reg_rx_dma_desc_base_addrmsw_t);
ATL_REG_STRUCT (atl_reg_rx_dma_desc_len_t);
ATL_REG_STRUCT (atl_reg_rx_dma_desc_data_hdr_size_t);
ATL_REG_STRUCT (atl_reg_rx_dma_desc_tail_ptr_t);
ATL_REG_STRUCT (atl_reg_rx_dma_int_desc_wrwb_en_t);
ATL_REG_STRUCT (atl_reg_tx_dma_desc_base_addrlsw_t);
ATL_REG_STRUCT (atl_reg_tx_dma_desc_base_addrmsw_t);
ATL_REG_STRUCT (atl_reg_tx_dma_desc_len_t);
ATL_REG_STRUCT (atl_reg_tx_dma_desc_tail_ptr_t);
ATL_REG_STRUCT (atl_reg_tx_dma_int_desc_wrwb_en_t);

#define atl_reg_aq2_rpf_act_art_req_tag_t_fields                                                   \
  __ (6, uc)                                                                                       \
  __ (1, allmc)                                                                                    \
  __ (3, et)                                                                                       \
  __ (4, vlan)                                                                                     \
  __ (1, untag)                                                                                    \
  __ (3, l3_v4)                                                                                    \
  __ (3, l3_v6)                                                                                    \
  __ (3, l4)                                                                                       \
  __ (3, unknown)                                                                                  \
  __ (2, flex)                                                                                     \
  __ (3, pcp)

#define atl_reg_aq2_rpf_act_art_req_action_t_fields                                                \
  __ (1, enable)                                                                                   \
  __ (1, _reserved_1)                                                                              \
  __ (5, index)                                                                                    \
  __ (1, rss)                                                                                      \
  __ (24, action)

#define atl_reg_intr_moderation_ctl_t_fields                                                       \
  __ (1, _reserved_0)                                                                              \
  __ (1, en)                                                                                       \
  __ (6, _reserved_2_7)                                                                            \
  __ (8, min)                                                                                      \
  __ (8, max)                                                                                      \
  __ (8, _reserved_24_31)

ATL_REG_STRUCT (atl_reg_aq2_rpf_act_art_req_tag_t);
ATL_REG_STRUCT (atl_reg_aq2_rpf_act_art_req_action_t);
ATL_REG_STRUCT (atl_reg_aq2_cable_diag_lane_data_t);
ATL_REG_STRUCT (atl_reg_aq2_cable_diag_status_t);
ATL_REG_STRUCT (atl_reg_intr_moderation_ctl_t);

#define atl_reg_aq2_fw_interface_in_request_policy_t_fields                                        \
  __ (1, promisc_all)                                                                              \
  __ (1, promisc_mcast)                                                                            \
  __ (5, promisc_rx_queue_tc_index)                                                                \
  __ (1, promisc_queue_or_tc)                                                                      \
  __ (1, bcast_accept)                                                                             \
  __ (1, _reserved_bcast_1)                                                                        \
  __ (5, bcast_rx_queue_tc_index)                                                                  \
  __ (1, bcast_queue_or_tc)                                                                        \
  __ (1, mcast_accept)                                                                             \
  __ (1, _reserved_mcast_1)                                                                        \
  __ (5, mcast_rx_queue_tc_index)                                                                  \
  __ (1, mcast_queue_or_tc)                                                                        \
  __ (8, _reserved_24_31)

ATL_REG_STRUCT (atl_reg_aq2_fw_interface_in_link_control_t);
ATL_REG_STRUCT (atl_reg_aq2_fw_interface_in_link_options_t);
ATL_REG_STRUCT (atl_reg_aq2_fw_interface_in_cable_diag_control_t);
ATL_REG_STRUCT (atl_reg_aq2_fw_interface_in_request_policy_t);
ATL_REG_STRUCT (atl_reg_aq2_mac_health_monitor_t);
ATL_REG_STRUCT (atl_reg_aq2_phy_health_monitor_t);
ATL_REG_STRUCT (atl_reg_aq2_device_caps_t);
ATL_REG_STRUCT (atl_reg_mpi_control2_t);
ATL_REG_STRUCT (atl_reg_mpi_state2_t);
#undef __

#define foreach_atl_reg                                                                            \
  _ (0x00000, FW_SOFTRESET, atl_reg_fw_softreset_t_fields)                                         \
  _ (0x00018, FW_VERSION, )                                                                        \
  _ (0x0001c, HW_REVISION, atl_reg_hw_revision_t_fields)                                           \
  _ (0x000f4, AQ2_HW_FPGA_VERSION, )                                                               \
  _ (0x00100, GLB_NVR_INTERFACE1, )                                                                \
  _ (0x00200, FW_MBOX_CMD, )                                                                       \
  _ (0x00208, FW_MBOX_ADDR, )                                                                      \
  _ (0x0020C, FW_MBOX_VAL, )                                                                       \
  _ (0x0036c, MPI_CONTROL2, atl_reg_mpi_control2_t_fields)                                         \
  _ (0x00374, MPI_STATE2, atl_reg_mpi_state2_t_fields)                                             \
  _ (0x003a0, FW_GLB_CPU_SEM0, )                                                                   \
  _ (0x00404, FW_GLB_CTL2, )                                                                       \
  _ (0x00520, GLB_GENERAL_PROVISIONING9, )                                                         \
  _ (0x00534, GLB_NVR_PROVISIONING2, )                                                             \
  _ (0x00604, SMB_PROVISIONING, )                                                                  \
  _ (0x00608, SMB_TX_DATA, )                                                                       \
  _ (0x00744, SMB_BUS, )                                                                           \
  _ (0x00748, SMB_RX_DATA, )                                                                       \
  _ (0x00f00, AQ2_MCP_HOST_REQ_INT, atl_reg_aq2_mcp_host_req_int_t_fields)                         \
  _ (0x00f04, AQ2_MCP_HOST_REQ_INT_SET, )                                                          \
  _ (0x00f08, AQ2_MCP_HOST_REQ_INT_CLR, )                                                          \
  _ (0x00e00, AQ2_MIF_HOST_FINISHED_STATUS_WRITE, )                                                \
  _ (0x00e04, AQ2_MIF_HOST_FINISHED_STATUS_READ, )                                                 \
  _ (0x01014, PCI_REG_CONTROL_6, )                                                                 \
  _ (0x02000, INTR_STATUS, )                                                                       \
  _ (0x02050, INTR_STATUS_CLR, )                                                                   \
  _ (0x02060, INTR_MASK, )                                                                         \
  _ (0x02070, INTR_MASK_CLR, )                                                                     \
  _ (0x02090, INTR_AUTOMASK, )                                                                     \
  _ (0x02300, INTR_CTRL, atl_reg_aq_intr_ctrl_t_fields)                                            \
  _ (0x03040, AQ2_MIF_BOOT, atl_reg_aq2_mif_boot_t_fields)                                         \
  _ (0x032a8, MBOXIF_POWER_GATING_CONTROL, )                                                       \
  _ (0x04000, FW_MPI_RESETCTRL, )                                                                  \
  _ (0x050f0, AQ2_RPF_L2BC_TAG, atl_reg_aq2_rpf_l2bc_tag_t_fields)                                 \
  _ (0x05100, RPF_L2BC, atl_reg_rpf_l2bc_t_fields)                                                 \
  _ (0x05104, AQ2_RPF_NEW_CTRL, atl_reg_aq2_rpf_new_ctrl_t_fields)                                 \
  _ (0x05110, RPF_L2UC_LSW0, )                                                                     \
  _ (0x05114, RPF_L2UC_MSW0, atl_reg_rpf_l2uc_msw_t_fields)                                        \
  _ (0x05250, RPF_MCAST_FILTER0, atl_reg_rpf_mcast_filter_t_fields)                                \
  _ (0x05270, RPF_MCAST_FILTER_MASK, )                                                             \
  _ (0x05280, RPF_VLAN_MODE, atl_reg_rpf_vlan_mode_t_fields)                                       \
  _ (0x05284, RPF_VLAN_TPID, atl_reg_rpf_vlan_tpid_t_fields)                                       \
  _ (0x05300, RPF_ETHERTYPE_FILTER0, atl_reg_rpf_ethertype_filter_t_fields)                        \
  _ (0x054c0, RX_FLR_RSS_CONTROL1, atl_reg_rx_flr_rss_control1_t_fields)                           \
  _ (0x054c4, RPF_RPB_RX_TC_UPT, )                                                                 \
  _ (0x054c8, AQ2_RPF_REDIR2, atl_reg_aq2_rpf_redir2_t_fields)                                     \
  _ (0x05700, RPB_RPF_RX, atl_reg_rpb_rpf_rx_t_fields)                                             \
  _ (0x05710, RPB_RXB_BUFSIZE0, atl_reg_rpb_rxb_bufsize_t_fields)                                  \
  _ (0x05714, RPB_RXB_XOFF0, atl_reg_rpb_rxb_xoff_t_fields)                                        \
  _ (0x05900, AQ2_RX_Q_TC_MAP0, )                                                                  \
  _ (0x05a00, RX_DMA_DESC_CACHE_INIT, atl_reg_rx_dma_desc_cache_init_t_fields)                     \
  _ (0x05b00, RX_DMA_DESC_BASE_ADDRLSW0, atl_reg_rx_dma_desc_base_addrlsw_t_fields)                \
  _ (0x05b04, RX_DMA_DESC_BASE_ADDRMSW0, atl_reg_rx_dma_desc_base_addrmsw_t_fields)                \
  _ (0x05b08, RX_DMA_DESC_LEN0, atl_reg_rx_dma_desc_len_t_fields)                                  \
  _ (0x05b0c, RX_DMA_DESC_HEAD_PTR0, )                                                             \
  _ (0x05b10, RX_DMA_DESC_TAIL_PTR0, atl_reg_rx_dma_desc_tail_ptr_t_fields)                        \
  _ (0x05b14, RX_DMA_DESC_STAT0, )                                                                 \
  _ (0x05b18, RX_DMA_DESC_DATA_HDR_SIZE0, atl_reg_rx_dma_desc_data_hdr_size_t_fields)              \
  _ (0x05a30, RX_DMA_INT_DESC_WRWB_EN, atl_reg_rx_dma_int_desc_wrwb_en_t_fields)                   \
  _ (0x05a10, RDM_RX_DMA_DESC_CACHE_INIT_DONE, )                                                   \
  _ (0x06180, RX_DMA_DCA, atl_reg_rx_dma_dca_t_fields)                                             \
  _ (0x06500, RPF_L3_V6_V4_SELECT, )                                                               \
  _ (0x06818, RPB_RX_DMA_DROP_PKT_CNT, )                                                           \
  _ (0x06ff0, AQ2_RPF_REC_TAB_ENABLE, atl_reg_aq2_rpf_rec_tab_enable_t_fields)                     \
  _ (0x07040, TX_TPO2, atl_reg_tx_tpo2_t_fields)                                                   \
  _ (0x07100, TPS_DATA_TC_ARB_MODE, atl_reg_tps_data_tc_arb_mode_t_fields)                         \
  _ (0x07110, TPS_DATA_TCT0, atl_reg_tps_data_tct_t_fields)                                        \
  _ (0x07200, TPS_DESC_TC_ARB_MODE, atl_reg_tps_desc_tc_arb_mode_t_fields)                         \
  _ (0x07210, TPS_DESC_TCT0, atl_reg_tps_desc_tct_t_fields)                                        \
  _ (0x07300, TPS_DESC_VM_ARB_MODE, atl_reg_tps_desc_vm_arb_mode_t_fields)                         \
  _ (0x07310, TPS_DESC_RATE, atl_reg_tps_desc_rate_t_fields)                                       \
  _ (0x07820, THM_LSO_TCP_FLAG1, atl_reg_thm_lso_tcp_flag_t_fields)                                \
  _ (0x07824, THM_LSO_TCP_FLAG2, atl_reg_thm_lso_tcp_flag_t_fields)                                \
  _ (0x07900, TPB_TX_BUF, atl_reg_tpb_tx_buf_t_fields)                                             \
  _ (0x07910, TPB_TXB_BUFSIZE0, atl_reg_tpb_txb_bufsize_t_fields)                                  \
  _ (0x07914, TPB_TXB_THRESH0, atl_reg_tpb_txb_thresh_t_fields)                                    \
  _ (0x0799c, AQ2_TX_Q_TC_MAP0, )                                                                  \
  _ (0x07a1c, AQ2_LAUNCHTIME_CTRL, atl_reg_aq2_launchtime_ctrl_t_fields)                           \
  _ (0x07b40, TX_DMA_INT_DESC_WRWB_EN, atl_reg_tx_dma_int_desc_wrwb_en_t_fields)                   \
  _ (0x07c00, TX_DMA_DESC_BASE_ADDRLSW0, atl_reg_tx_dma_desc_base_addrlsw_t_fields)                \
  _ (0x07c04, TX_DMA_DESC_BASE_ADDRMSW0, atl_reg_tx_dma_desc_base_addrmsw_t_fields)                \
  _ (0x07c08, TX_DMA_DESC_LEN0, atl_reg_tx_dma_desc_len_t_fields)                                  \
  _ (0x07c0c, TX_DMA_DESC_HEAD_PTR0, )                                                             \
  _ (0x07c10, TX_DMA_DESC_TAIL_PTR0, atl_reg_tx_dma_desc_tail_ptr_t_fields)                        \
  _ (0x08480, TDM_DCA, atl_reg_tdm_dca_t_fields)                                                   \
  _ (0x12000, AQ2_FW_INTERFACE_IN_MTU, )                                                           \
  _ (0x12008, AQ2_FW_INTERFACE_IN_MAC_ADDRESS, )                                                   \
  _ (0x12010, AQ2_FW_INTERFACE_IN_LINK_CONTROL, atl_reg_aq2_fw_interface_in_link_control_t_fields) \
  _ (0x12018, AQ2_FW_INTERFACE_IN_LINK_OPTIONS, atl_reg_aq2_fw_interface_in_link_options_t_fields) \
  _ (0x12a44, AQ2_FW_INTERFACE_IN_CABLE_DIAG_CONTROL,                                              \
     atl_reg_aq2_fw_interface_in_cable_diag_control_t_fields)                                      \
  _ (0x12a58, AQ2_FW_INTERFACE_IN_REQUEST_POLICY,                                                  \
     atl_reg_aq2_fw_interface_in_request_policy_t_fields)                                          \
  _ (0x13000, AQ2_FW_INTERFACE_OUT_TRANSACTION_ID,                                                 \
     atl_reg_aq2_fw_interface_out_transaction_id_t_fields)                                         \
  _ (0x13004, AQ2_FW_INTERFACE_OUT_VERSION_BUNDLE, )                                               \
  _ (0x13008, AQ2_FW_INTERFACE_OUT_VERSION_MAC, )                                                  \
  _ (0x1300c, AQ2_FW_INTERFACE_OUT_VERSION_PHY, )                                                  \
  _ (0x13010, AQ2_FW_INTERFACE_OUT_VERSION_IFACE,                                                  \
     atl_reg_aq2_fw_interface_out_version_iface_t_fields)                                          \
  _ (0x13014, AQ2_FW_INTERFACE_OUT_LINK_STATUS, atl_reg_aq2_fw_interface_out_link_status_t_fields) \
  _ (0x13610, AQ2_MAC_HEALTH_MONITOR, atl_reg_aq2_mac_health_monitor_t_fields)                     \
  _ (0x13620, AQ2_PHY_HEALTH_MONITOR, atl_reg_aq2_phy_health_monitor_t_fields)                     \
  _ (0x13630, AQ2_FW_INTERFACE_OUT_CABLE_DIAG_LANE0, atl_reg_aq2_cable_diag_lane_data_t_fields)    \
  _ (0x13634, AQ2_FW_INTERFACE_OUT_CABLE_DIAG_LANE1, atl_reg_aq2_cable_diag_lane_data_t_fields)    \
  _ (0x13638, AQ2_FW_INTERFACE_OUT_CABLE_DIAG_LANE2, atl_reg_aq2_cable_diag_lane_data_t_fields)    \
  _ (0x1363c, AQ2_FW_INTERFACE_OUT_CABLE_DIAG_LANE3, atl_reg_aq2_cable_diag_lane_data_t_fields)    \
  _ (0x13640, AQ2_FW_INTERFACE_OUT_CABLE_DIAG_STATUS, atl_reg_aq2_cable_diag_status_t_fields)      \
  _ (0x13648, AQ2_FW_INTERFACE_OUT_DEVICE_LINK_CAPS,                                               \
     atl_reg_aq2_fw_interface_out_device_link_caps_t_fields)                                       \
  _ (0x13660, AQ2_FW_INTERFACE_OUT_LKP_LINK_CAPS,                                                  \
     atl_reg_aq2_fw_interface_out_lkp_link_caps_t_fields)                                          \
  _ (0x13700, AQ2_FW_INTERFACE_OUT_STATS, )                                                        \
  _ (0x13774, AQ2_FW_INTERFACE_OUT_FILTER_CAPS, )                                                  \
  _ (0x13780, AQ2_FW_INTERFACE_OUT_DEVICE_CAPS, atl_reg_aq2_device_caps_t_fields)                  \
  _ (0x1378c, AQ2_FW_INTERFACE_OUT_MANAGEMENT_STATUS, )                                            \
  _ (0x14000, AQ2_RPF_ACT_ART_REQ_TAG0, atl_reg_aq2_rpf_act_art_req_tag_t_fields)                  \
  _ (0x14004, AQ2_RPF_ACT_ART_REQ_MASK0, atl_reg_aq2_rpf_act_art_req_tag_t_fields)                 \
  _ (0x14008, AQ2_RPF_ACT_ART_REQ_ACTION0, atl_reg_aq2_rpf_act_art_req_action_t_fields)

typedef struct
{
  u8 mac[6];
  u16 vlan;
  u32 flags;
  u32 rsvd[5];
} atl_aq2_management_status_t;

typedef enum
{
#define _(o, n, f) ATL_REG_##n = (o),
  foreach_atl_reg
#undef _
} atl_reg_addr_t;

typedef union
{
  u32 as_u32;
  atl_reg_fw_softreset_t fw_softreset;
  atl_reg_glb_mif_id_t hw_revision;
  atl_reg_aq2_mcp_host_req_int_t aq2_mcp_host_req_int;
  atl_reg_aq2_mif_boot_t aq2_mif_boot;
  atl_reg_aq2_fw_interface_out_transaction_id_t aq2_fw_interface_out_transaction_id;
  atl_reg_aq2_fw_interface_out_link_status_t aq2_fw_interface_out_link_status;
  atl_reg_aq2_fw_interface_out_device_link_caps_t aq2_fw_interface_out_device_link_caps;
  atl_reg_aq2_fw_interface_out_lkp_link_caps_t aq2_fw_interface_out_lkp_link_caps;
  atl_reg_aq2_fw_interface_out_version_iface_t aq2_fw_interface_out_version_iface;
  atl_reg_aq2_launchtime_ctrl_t aq2_launchtime_ctrl;
  atl_reg_tpb_tx_buf_t tpb_tx_buf;
  atl_reg_thm_lso_tcp_flag_t thm_lso_tcp_flag;
  atl_reg_tx_tpo2_t tx_tpo2;
  atl_reg_tdm_dca_t tdm_dca;
  atl_reg_rpb_rpf_rx_t rpb_rpf_rx;
  atl_reg_aq2_rpf_redir2_t aq2_rpf_redir2;
  atl_reg_rx_flr_rss_control1_t rx_flr_rss_control1;
  atl_reg_rpf_ethertype_filter_t rpf_ethertype_filter;
  atl_reg_rpf_l2uc_msw_t rpf_l2uc_msw;
  atl_reg_rpf_mcast_filter_t rpf_mcast_filter;
  atl_reg_rpf_l2bc_t rpf_l2bc;
  atl_reg_rpf_vlan_tpid_t rpf_vlan_tpid;
  atl_reg_rpf_vlan_mode_t rpf_vlan_mode;
  atl_reg_aq2_rpf_rec_tab_enable_t aq2_rpf_rec_tab_enable;
  atl_reg_aq2_rpf_l2bc_tag_t aq2_rpf_l2bc_tag;
  atl_reg_aq2_rpf_new_ctrl_t aq2_rpf_new_ctrl;
  atl_reg_rx_dma_dca_t rx_dma_dca;
  atl_reg_tps_desc_rate_t tps_desc_rate;
  atl_reg_tps_desc_vm_arb_mode_t tps_desc_vm_arb_mode;
  atl_reg_tps_desc_tc_arb_mode_t tps_desc_tc_arb_mode;
  atl_reg_tps_data_tc_arb_mode_t tps_data_tc_arb_mode;
  atl_reg_tps_data_tct_t tps_data_tct;
  atl_reg_tps_desc_tct_t tps_desc_tct;
  atl_reg_tpb_txb_bufsize_t tpb_txb_bufsize;
  atl_reg_tpb_txb_thresh_t tpb_txb_thresh;
  atl_reg_rpb_rxb_bufsize_t rpb_rxb_bufsize;
  atl_reg_rpb_rxb_xoff_t rpb_rxb_xoff;
  atl_reg_aq_intr_ctrl_t aq_intr_ctrl;
  atl_reg_rx_dma_desc_cache_init_t rx_dma_desc_cache_init;
  atl_reg_rx_dma_desc_base_addrlsw_t rx_dma_desc_base_addrlsw;
  atl_reg_rx_dma_desc_base_addrmsw_t rx_dma_desc_base_addrmsw;
  atl_reg_rx_dma_desc_len_t rx_dma_desc_len;
  atl_reg_rx_dma_desc_data_hdr_size_t rx_dma_desc_data_hdr_size;
  atl_reg_rx_dma_desc_tail_ptr_t rx_dma_desc_tail_ptr;
  atl_reg_rx_dma_int_desc_wrwb_en_t rx_dma_int_desc_wrwb_en;
  atl_reg_tx_dma_desc_base_addrlsw_t tx_dma_desc_base_addrlsw;
  atl_reg_tx_dma_desc_base_addrmsw_t tx_dma_desc_base_addrmsw;
  atl_reg_tx_dma_desc_len_t tx_dma_desc_len;
  atl_reg_tx_dma_desc_tail_ptr_t tx_dma_desc_tail_ptr;
  atl_reg_tx_dma_int_desc_wrwb_en_t tx_dma_int_desc_wrwb_en;
  atl_reg_intr_moderation_ctl_t intr_moderation_ctl;
  atl_reg_aq2_fw_interface_in_link_control_t aq2_fw_interface_in_link_control;
  atl_reg_aq2_fw_interface_in_link_options_t aq2_fw_interface_in_link_options;
  atl_reg_aq2_fw_interface_in_cable_diag_control_t aq2_fw_interface_in_cable_diag_control;
  atl_reg_aq2_fw_interface_in_request_policy_t aq2_fw_interface_in_request_policy;
  atl_reg_aq2_rpf_act_art_req_tag_t aq2_rpf_act_art_req_tag;
  atl_reg_aq2_rpf_act_art_req_action_t aq2_rpf_act_art_req_action;
  atl_reg_aq2_cable_diag_lane_data_t aq2_cable_diag_lane_data;
  atl_reg_aq2_cable_diag_status_t aq2_cable_diag_status;
  atl_reg_aq2_mac_health_monitor_t aq2_mac_health_monitor;
  atl_reg_aq2_phy_health_monitor_t aq2_phy_health_monitor;
  atl_reg_mpi_control2_t mpi_control2;
  atl_reg_mpi_state2_t mpi_state2;
} atl_reg_t;

typedef struct
{
  u32 version;
  u32 transaction_id;
  u32 error;
} atl_mbox_header_t;

typedef struct
{
  u32 stats[15];
} atl_mbox_stats_t;

typedef struct
{
  u8 reserved[6];
  u16 phy_fault_code;
  u16 phy_temperature;
  u8 cable_len;
  u8 reserved1;
} atl_mbox_info_t;

typedef struct
{
  atl_mbox_header_t header;
  atl_mbox_stats_t stats;
  atl_mbox_info_t info;
} atl_mbox_t;

typedef union
{
  struct
  {
    u16 phy_temperature;
    u8 cable_len;
    u8 reserved1;
  };
  u32 as_u32;
} atl_mbox_phy_temp_t;

#define ATL_REG_AQ_FW_GLB_CPU_SEM(i)	      (ATL_REG_FW_GLB_CPU_SEM0 + (i) *4)
#define ATL_REG_AQ_INTR_IRQ_MAP_TXRX(i)	      (0x2100 + ((i) / 2) * 4)
#define ATL_REG_AQ_GEN_INTR_MAP(i)	      (0x2180 + (i) *4)
#define ATL_REG_RPF_ETHERTYPE_FILTER(i)	      (ATL_REG_RPF_ETHERTYPE_FILTER0 + (i) *4)
#define ATL_REG_RPF_L2UC_LSW(i)		      (ATL_REG_RPF_L2UC_LSW0 + (i) *8)
#define ATL_REG_RPF_L2UC_MSW(i)		      (ATL_REG_RPF_L2UC_MSW0 + (i) *8)
#define ATL_REG_RPF_MCAST_FILTER(i)	      (ATL_REG_RPF_MCAST_FILTER0 + (i) *4)
#define ATL_REG_AQ2_RPF_ACT_ART_REQ_TAG(i)    (ATL_REG_AQ2_RPF_ACT_ART_REQ_TAG0 + (i) *0x10)
#define ATL_REG_AQ2_RPF_ACT_ART_REQ_MASK(i)   (ATL_REG_AQ2_RPF_ACT_ART_REQ_MASK0 + (i) *0x10)
#define ATL_REG_AQ2_RPF_ACT_ART_REQ_ACTION(i) (ATL_REG_AQ2_RPF_ACT_ART_REQ_ACTION0 + (i) *0x10)
#define ATL_REG_TPS_DATA_TCT(i)		      (ATL_REG_TPS_DATA_TCT0 + (i) *4)
#define ATL_REG_TPS_DESC_TCT(i)		      (ATL_REG_TPS_DESC_TCT0 + (i) *4)
#define ATL_REG_TPB_TXB_BUFSIZE(i)	      (ATL_REG_TPB_TXB_BUFSIZE0 + (i) *0x10)
#define ATL_REG_TPB_TXB_THRESH(i)	      (ATL_REG_TPB_TXB_THRESH0 + (i) *0x10)
#define ATL_REG_RPB_RXB_BUFSIZE(i)	      (ATL_REG_RPB_RXB_BUFSIZE0 + (i) *0x10)
#define ATL_REG_RPB_RXB_XOFF(i)		      (ATL_REG_RPB_RXB_XOFF0 + (i) *0x10)
#define ATL_REG_AQ2_RX_Q_TC_MAP(i)	      (ATL_REG_AQ2_RX_Q_TC_MAP0 + (i) *4)
#define ATL_REG_AQ2_TX_Q_TC_MAP(i)	      (ATL_REG_AQ2_TX_Q_TC_MAP0 + (i) *4)
#define ATL_REG_AQ2_ART_SEM		      ATL_REG_AQ_FW_GLB_CPU_SEM (3)

#define ATL_REG_RX_DMA_DESC_BASE_ADDRLSW(i)  (ATL_REG_RX_DMA_DESC_BASE_ADDRLSW0 + (i) *0x20)
#define ATL_REG_RX_DMA_DESC_BASE_ADDRMSW(i)  (ATL_REG_RX_DMA_DESC_BASE_ADDRMSW0 + (i) *0x20)
#define ATL_REG_RX_DMA_DESC_LEN(i)	     (ATL_REG_RX_DMA_DESC_LEN0 + (i) *0x20)
#define ATL_REG_RX_DMA_DESC_HEAD_PTR(i)	     (ATL_REG_RX_DMA_DESC_HEAD_PTR0 + (i) *0x20)
#define ATL_REG_RX_DMA_DESC_TAIL_PTR(i)	     (ATL_REG_RX_DMA_DESC_TAIL_PTR0 + (i) *0x20)
#define ATL_REG_RX_DMA_DESC_STAT(i)	     (ATL_REG_RX_DMA_DESC_STAT0 + (i) *0x20)
#define ATL_REG_RX_DMA_DESC_DATA_HDR_SIZE(i) (ATL_REG_RX_DMA_DESC_DATA_HDR_SIZE0 + (i) *0x20)

#define ATL_REG_RX_INTR_MODERATION_CTL(i) (0x05a40 + (i) *4)

#define ATL_REG_TX_DMA_DESC_BASE_ADDRLSW(i) (ATL_REG_TX_DMA_DESC_BASE_ADDRLSW0 + (i) *0x40)
#define ATL_REG_TX_DMA_DESC_BASE_ADDRMSW(i) (ATL_REG_TX_DMA_DESC_BASE_ADDRMSW0 + (i) *0x40)
#define ATL_REG_TX_DMA_DESC_LEN(i)	    (ATL_REG_TX_DMA_DESC_LEN0 + (i) *0x40)
#define ATL_REG_TX_DMA_DESC_HEAD_PTR(i)	    (ATL_REG_TX_DMA_DESC_HEAD_PTR0 + (i) *0x40)
#define ATL_REG_TX_DMA_DESC_TAIL_PTR(i)	    (ATL_REG_TX_DMA_DESC_TAIL_PTR0 + (i) *0x40)

#define ATL_REG_AQ2_TX_INTR_MODERATION_CTL(i) (0x07c28 + (i) *0x40)

#define ATL_REG_AQ2_RPF_RSS_REDIR(i)  (0x06200 + (i) *4)
#define ATL_REG_RPF_RSS_KEY_ADDR      0x054d0
#define ATL_REG_RPF_RSS_KEY_WR_DATA   0x054d4
#define ATL_REG_RPF_RSS_REDIR_ADDR    0x054e0
#define ATL_REG_RPF_RSS_REDIR_WR_DATA 0x054e4

#define ATL_RSS_DISABLED		 0x00000000
#define ATL_RSS_ENABLED_8TCS_2INDEX_BITS 0xA2222222
#define ATL_RSS_ENABLED_4TCS_3INDEX_BITS 0x80003333

#define AQ_HW_MAC_NUM 34

/* AQ2 action resolver table */
#define AQ2_RPF_INDEX_L2_PROMISC_OFF   0
#define AQ2_RPF_INDEX_VLAN_PROMISC_OFF 1
#define AQ2_RPF_INDEX_L3L4_USER	       8
#define AQ2_RPF_INDEX_ET_PCP_USER      24
#define AQ2_RPF_INDEX_VLAN_USER	       40
#define AQ2_RPF_INDEX_PCP_TO_TC	       56

#define RPF_RPB_RX_TC_UPT_MASK(i) (0x00000007 << ((i) *4))
