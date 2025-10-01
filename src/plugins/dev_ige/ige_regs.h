/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#ifndef _IGE_REGS_H_
#define _IGE_REGS_H_

#include <vppinfra/clib.h>
#include <vppinfra/error_bootstrap.h>
#include <vppinfra/format.h>
#include <vnet/vnet.h>
#include <vnet/dev/dev.h>

#define ige_reg_ctrl_t_fields                                                 \
  __ (1, full_duplex)                                                         \
  __ (1, _reserved1)                                                          \
  __ (1, gio_master_disable)                                                  \
  __ (3, _reserved3)                                                          \
  __ (1, set_link_up)                                                         \
  __ (9, _reserved7)                                                          \
  __ (1, sdp0_gpien)                                                          \
  __ (1, sdp1_gpien)                                                          \
  __ (1, sdp0_data)                                                           \
  __ (1, sdp1_data)                                                           \
  __ (1, adww3wuc)                                                            \
  __ (1, sdp0_wde)                                                            \
  __ (1, sdp0_iodir)                                                          \
  __ (1, sdp1_iodir)                                                          \
  __ (2, _reserved24)                                                         \
  __ (1, port_sw_reset)                                                       \
  __ (1, rx_flow_ctl_en)                                                      \
  __ (1, tx_flow_ctl_en)                                                      \
  __ (1, device_reset)                                                        \
  __ (1, vlan_mode_enable)                                                    \
  __ (1, phy_reset)

#define ige_reg_status_t_fields                                               \
  __ (1, full_duplex)                                                         \
  __ (1, link_up)                                                             \
  __ (2, _reserved2)                                                          \
  __ (1, tx_off)                                                              \
  __ (1, _reserved5)                                                          \
  __ (2, speed)                                                               \
  __ (2, asdv)                                                                \
  __ (1, phy_reset_asserted)                                                  \
  __ (8, _reserved11)                                                         \
  __ (1, gio_master_en_sts)                                                   \
  __ (1, dev_rst_set)                                                         \
  __ (1, rst_done)                                                            \
  __ (1, speed_2p5)                                                           \
  __ (7, _reserved23)                                                         \
  __ (1, lpi_ignore)                                                          \
  __ (1, _reserved31)

#define ige_reg_ctrl_ext_t_fields                                             \
  __ (2, _reserved0)                                                          \
  __ (1, sdp2_gpien)                                                          \
  __ (1, sdp3_gpien)                                                          \
  __ (2, _reserved4)                                                          \
  __ (1, sdp2_data)                                                           \
  __ (1, sdp3_data)                                                           \
  __ (2, _reserved8)                                                          \
  __ (1, sdp2_iodir)                                                          \
  __ (1, sdp3_iodir)                                                          \
  __ (1, _reserved12)                                                         \
  __ (1, eeprom_block_rst)                                                    \
  __ (2, _reserved14)                                                         \
  __ (1, no_snoop_dis)                                                        \
  __ (1, relaxed_ordering_dis)                                                \
  __ (2, _reserved18)                                                         \
  __ (1, phy_power_down_ena)                                                  \
  __ (5, _reserved121)                                                        \
  __ (1, ext_vlan_ena)                                                        \
  __ (1, _reserved127)                                                        \
  __ (1, driver_loaded)                                                       \
  __ (3, _reserved29)

#define ige_reg_mdic_t_fields                                                 \
  __ (16, data)                                                               \
  __ (5, regadd)                                                              \
  __ (5, _reserved21)                                                         \
  __ (2, opcode)                                                              \
  __ (1, ready)                                                               \
  __ (1, mid_ie)                                                              \
  __ (1, mid_err)                                                             \
  __ (1, _reserved31)

#define ige_reg_rctl_t_fields                                                 \
  __ (1, _reserved0)                                                          \
  __ (1, rx_enable)                                                           \
  __ (1, store_bad_packets)                                                   \
  __ (1, uc_promisc_ena)                                                      \
  __ (1, mc_promisc_ena)                                                      \
  __ (1, long_pkt_reception_ena)                                              \
  __ (2, loopback_mode)                                                       \
  __ (2, hash_select)                                                         \
  __ (2, _reserved10)                                                         \
  __ (2, mc_uc_tbl_off)                                                       \
  __ (1, _reserved14)                                                         \
  __ (1, bcast_accept_mode)                                                   \
  __ (2, rx_buf_sz)                                                           \
  __ (1, vlan_filter_ena)                                                     \
  __ (1, cannonical_form_ind_ena)                                             \
  __ (1, cannonical_form_ind_bit_val)                                         \
  __ (1, pad_small_rx_pkts)                                                   \
  __ (1, discard_pause_frames)                                                \
  __ (1, pass_mac_ctrl_frames)                                                \
  __ (2, _reserved24)                                                         \
  __ (1, strip_eth_crc)                                                       \
  __ (5, _reserved26)

#define ige_reg_tctl_t_fields                                                 \
  __ (1, _reserved0)                                                          \
  __ (1, tx_enable)                                                           \
  __ (1, _reserved2)                                                          \
  __ (1, pad_short_pkts)                                                      \
  __ (8, collision_threshold)                                                 \
  __ (10, backoff_slot_time)                                                  \
  __ (1, sw_xoff_tx)                                                          \
  __ (1, _reserved23)                                                         \
  __ (1, retransmit_on_late_colision)                                         \
  __ (7, reserved25)

#define ige_reg_txdctl_t_fields                                               \
  __ (5, pthresh)                                                             \
  __ (3, _reserved5)                                                          \
  __ (5, hthresh)                                                             \
  __ (3, _reserved13)                                                         \
  __ (5, wthresh)                                                             \
  __ (4, _reserved21)                                                         \
  __ (1, enable)                                                              \
  __ (1, sw_flush)                                                            \
  __ (1, priority)                                                            \
  __ (4, hwbthresh)

#define ige_reg_phpm_t_fields                                                 \
  __ (1, _reserved0)                                                          \
  __ (1, restart_autoneg)                                                     \
  __ (1, _reserved2)                                                          \
  __ (1, dis_1000_in_non_d0a)                                                 \
  __ (1, link_energy_detect)                                                  \
  __ (1, go_link_disc)                                                        \
  __ (1, disable_1000)                                                        \
  __ (1, spd_b2b_en)                                                          \
  __ (1, rst_compl)                                                           \
  __ (1, dis_100_in_non_d0a)                                                  \
  __ (1, ulp_req)                                                             \
  __ (1, disable_2500)                                                        \
  __ (1, dis_2500_in_non_d0a)                                                 \
  __ (1, ulp_trig)                                                            \
  __ (2, ulp_delay)                                                           \
  __ (1, link_enery_en)                                                       \
  __ (1, dev_off_en)                                                          \
  __ (1, dev_off_state)                                                       \
  __ (1, ulp_en)                                                              \
  __ (12, _reserved20)

#define ige_reg_manc_t_fields                                                 \
  __ (1, flow_ctrl_discard)                                                   \
  __ (1, ncsi_discard)                                                        \
  __ (12, _reserved2)                                                         \
  __ (1, fw_reset)                                                            \
  __ (1, tco_isolate)                                                         \
  __ (1, tco_reset)                                                           \
  __ (1, rcv_tco_en)                                                          \
  __ (1, keep_phy_link_up)                                                    \
  __ (1, rcv_all)                                                             \
  __ (1, inhibit_ulp)                                                         \
  __ (2, _reserved21)                                                         \
  __ (1, en_xsum_filter)                                                      \
  __ (1, en_ipv4_filter)                                                      \
  __ (1, fixed_net_type)                                                      \
  __ (1, net_type)                                                            \
  __ (1, ipv6_adv_only)                                                       \
  __ (1, en_bmc2os)                                                           \
  __ (1, en_bmc2net)                                                          \
  __ (1, mproxye)                                                             \
  __ (1, mproxya)

#define ige_reg_swsm_t_fields                                                 \
  __ (1, smbi)                                                                \
  __ (1, swesmbi)                                                             \
  __ (30, _reserved2)

#define ige_reg_fwsm_t_fields                                                 \
  __ (1, eep_fw_semaphore)                                                    \
  __ (3, fw_mode)                                                             \
  __ (2, _reserved4)                                                          \
  __ (1, eep_reload_ind)                                                      \
  __ (8, _reserved7)                                                          \
  __ (1, fw_val_bit)                                                          \
  __ (3, reset_ctr)                                                           \
  __ (6, ext_err_ind)                                                         \
  __ (1, pcie_config_err_ind)                                                 \
  __ (5, _reserved26)                                                         \
  __ (1, factory_mac_addr_restored)

#define ige_reg_sw_fw_sync_t_fields                                           \
  __ (1, sw_flash_sm)                                                         \
  __ (1, sw_phy_sm)                                                           \
  __ (1, sw_i2c_sm)                                                           \
  __ (1, sw_mac_csr_sm)                                                       \
  __ (3, _reserved4)                                                          \
  __ (1, sw_svr_sm)                                                           \
  __ (1, sw_mb_sm)                                                            \
  __ (1, _reserved9)                                                          \
  __ (1, sw_mng_sm)                                                           \
  __ (5, _reserved11)                                                         \
  __ (1, fw_flash_sm)                                                         \
  __ (1, fw_phy_sm)                                                           \
  __ (1, fw_i2c_sm)                                                           \
  __ (1, fw_mac_csr_sm)                                                       \
  __ (3, _reserved20)                                                         \
  __ (1, fw_svr_sm)                                                           \
  __ (8, _reserved24)

#define ige_reg_srrctl_t_fields                                               \
  __ (7, bsizepacket)                                                         \
  __ (1, _reserved7)                                                          \
  __ (6, bsizeheader)                                                         \
  __ (2, timer1_sel)                                                          \
  __ (1, _reserved16)                                                         \
  __ (2, timer0_sel)                                                          \
  __ (1, use_domain)                                                          \
  __ (5, rdmts)                                                               \
  __ (3, desc_type)                                                           \
  __ (2, _reserved28)                                                         \
  __ (1, timestamp)                                                           \
  __ (1, drop_en)

#define ige_reg_rxdctl_t_fields                                               \
  __ (5, pthresh)                                                             \
  __ (3, _reserved5)                                                          \
  __ (5, hthresh)                                                             \
  __ (3, _reserved13)                                                         \
  __ (5, wthresh)                                                             \
  __ (4, _reserved21)                                                         \
  __ (1, enable)                                                              \
  __ (1, swflush)                                                             \
  __ (5, _reserved27)

#define ige_reg_eec_t_fields                                                  \
  __ (6, _reserved0)                                                          \
  __ (1, flash_in_use)                                                        \
  __ (1, _reserved7)                                                          \
  __ (1, ee_pres)                                                             \
  __ (1, auto_rd)                                                             \
  __ (1, _reservedxi10)                                                       \
  __ (4, ee_size)                                                             \
  __ (4, pci_ana_done)                                                        \
  __ (1, flash_detected)                                                      \
  __ (2, _reserved20)                                                         \
  __ (1, shadow_modified)                                                     \
  __ (1, flupd)                                                               \
  __ (1, _reserved24)                                                         \
  __ (1, sec1val)                                                             \
  __ (1, fludone)                                                             \
  __ (5, _reserved27)

#define ige_reg_eemngctl_t_fields                                             \
  __ (11, addr)                                                               \
  __ (4, reserved11)                                                          \
  __ (1, cmd_valid)                                                           \
  __ (1, write)                                                               \
  __ (1, eebusy)                                                              \
  __ (1, cfg_done)                                                            \
  __ (12, _reserved19)                                                        \
  __ (1, done)

#define IGE_REG_STRUCT(n)                                                     \
  typedef union                                                               \
  {                                                                           \
    struct                                                                    \
    {                                                                         \
      n##_fields;                                                             \
    };                                                                        \
    u32 as_u32;                                                               \
  } n;                                                                        \
  STATIC_ASSERT_SIZEOF (n, 4);

#define __(n, f) u32 f : n;
IGE_REG_STRUCT (ige_reg_status_t);
IGE_REG_STRUCT (ige_reg_ctrl_t);
IGE_REG_STRUCT (ige_reg_ctrl_ext_t);
IGE_REG_STRUCT (ige_reg_mdic_t);
IGE_REG_STRUCT (ige_reg_rctl_t);
IGE_REG_STRUCT (ige_reg_tctl_t);
IGE_REG_STRUCT (ige_reg_txdctl_t);
IGE_REG_STRUCT (ige_reg_phpm_t);
IGE_REG_STRUCT (ige_reg_manc_t);
IGE_REG_STRUCT (ige_reg_swsm_t);
IGE_REG_STRUCT (ige_reg_fwsm_t);
IGE_REG_STRUCT (ige_reg_sw_fw_sync_t);
IGE_REG_STRUCT (ige_reg_srrctl_t);
IGE_REG_STRUCT (ige_reg_rxdctl_t);
IGE_REG_STRUCT (ige_reg_eec_t);
IGE_REG_STRUCT (ige_reg_eemngctl_t);
#undef __

#define foreach_ige_reg                                                       \
  _ (0x00000, CTRL, ige_reg_ctrl_t_fields)                                    \
  _ (0x00008, STATUS, ige_reg_status_t_fields)                                \
  _ (0x00018, CTRL_EXT, ige_reg_ctrl_ext_t_fields)                            \
  _ (0x00020, MDIC, ige_reg_mdic_t_fields)                                    \
  _ (0x00100, RCTL, ige_reg_rctl_t_fields)                                    \
  _ (0x00400, TCTL, ige_reg_tctl_t_fields)                                    \
  _ (0x00404, TCTL_EXT, )                                                     \
  _ (0x00e14, PHPM, ige_reg_phpm_t_fields)                                    \
  _ (0x01500, ICR, )                                                          \
  _ (0x0150c, IMC, )                                                          \
  _ (0x05400, RAL0, )                                                         \
  _ (0x05404, RAH0, )                                                         \
  _ (0x05820, MANC, ige_reg_manc_t_fields)                                    \
  _ (0x05b50, SWSM, ige_reg_swsm_t_fields)                                    \
  _ (0x05b54, FWSM, ige_reg_fwsm_t_fields)                                    \
  _ (0x05b5c, SW_FW_SYNC, ige_reg_sw_fw_sync_t_fields)                        \
  _ (0x0c000, RDBAL0, )                                                       \
  _ (0x0c004, RDBAH0, )                                                       \
  _ (0x0c008, RDLEN0, )                                                       \
  _ (0x0c00c, SRRCTL0, ige_reg_srrctl_t_fields)                               \
  _ (0x0c010, RDH0, )                                                         \
  _ (0x0c018, RDT0, )                                                         \
  _ (0x0c028, RXDCTL0, ige_reg_rxdctl_t_fields)                               \
  _ (0x0e000, TDBAL0, )                                                       \
  _ (0x0e004, TDBAH0, )                                                       \
  _ (0x0e008, TDLEN0, )                                                       \
  _ (0x0e010, TDH0, )                                                         \
  _ (0x0e018, TDT0, )                                                         \
  _ (0x0e028, TXDCTL0, ige_reg_txdctl_t_fields)                               \
  _ (0x12010, EEC, ige_reg_eec_t_fields)                                      \
  _ (0x12030, EEMNGCTL, ige_reg_eemngctl_t_fields)

#define IGE_REG_RDBAL(n)  (IGE_REG_RDBAL0 + (n) *0x40)
#define IGE_REG_RDBAH(n)  (IGE_REG_RDBAH0 + (n) *0x40)
#define IGE_REG_RDLEN(n)  (IGE_REG_RDLEN0 + (n) *0x40)
#define IGE_REG_SRRCTL(n) (IGE_REG_SRRCTL0 + (n) *0x40)
#define IGE_REG_RDH(n)	  (IGE_REG_RDH0 + (n) *0x40)
#define IGE_REG_RDT(n)	  (IGE_REG_RDT0 + (n) *0x40)
#define IGE_REG_RXDCTL(n) (IGE_REG_RXDCTL0 + (n) *0x40)
#define IGE_REG_SRRCTL(n) (IGE_REG_SRRCTL0 + (n) *0x40)
#define IGE_REG_TDBAL(n)  (IGE_REG_TDBAL0 + (n) *0x40)
#define IGE_REG_TDBAH(n)  (IGE_REG_TDBAH0 + (n) *0x40)
#define IGE_REG_TDLEN(n)  (IGE_REG_TDLEN0 + (n) *0x40)
#define IGE_REG_TDH(n)	  (IGE_REG_TDH0 + (n) *0x40)
#define IGE_REG_TDT(n)	  (IGE_REG_TDT0 + (n) *0x40)
#define IGE_REG_TXDCTL(n) (IGE_REG_TXDCTL0 + (n) *0x40)

typedef enum
{
#define _(o, n, f) IGE_REG_##n = (o),
  foreach_ige_reg
#undef _
} ige_reg_t;

#endif /* _IGE_REGS_H_ */
