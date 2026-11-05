/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Damjan Marion
 */

#include <ice.h>

vnet_dev_rv_t
ice_phy_type_for_speed (u32 link_speed_kbps, ice_phy_type_low_t *low, ice_phy_type_high_t *high)
{
  *low = (ice_phy_type_low_t) {};
  *high = (ice_phy_type_high_t) {};

  switch (link_speed_kbps)
    {
    case 0: /* Auto */
      break;
    case 100000: /* 100M */
      *low = (ice_phy_type_low_t) { .base_100_tx = 1, .sgmii_100m = 1 };
      break;
    case 1000000: /* 1G */
      *low = (ice_phy_type_low_t) {
	.base_1000_t = 1,
	.base_1000_sx = 1,
	.base_1000_lx = 1,
	.base_1000_kx = 1,
	.sgmii_1g = 1,
      };
      break;
    case 2500000: /* 2.5G */
      *low = (ice_phy_type_low_t) { .base_2500_t = 1, .base_2500_x = 1, .base_2500_kx = 1 };
      break;
    case 5000000: /* 5G */
      *low = (ice_phy_type_low_t) { .base_5g_t = 1, .base_5g_kr = 1 };
      break;
    case 10000000: /* 10G */
      *low = (ice_phy_type_low_t) {
	.base_10g_t = 1,
	.sfi_10g_da = 1,
	.base_10g_sr = 1,
	.base_10g_lr = 1,
	.base_10g_kr_cr1 = 1,
	.sfi_10g_aoc_acc = 1,
	.sfi_10g_c2c = 1,
      };
      break;
    case 25000000: /* 25G */
      *low = (ice_phy_type_low_t) {
	.base_25g_t = 1,
	.base_25g_cr = 1,
	.base_25g_cr_s = 1,
	.base_25g_cr1 = 1,
	.base_25g_sr = 1,
	.base_25g_lr = 1,
	.base_25g_kr = 1,
	.base_25g_kr_s = 1,
	.base_25g_kr1 = 1,
	.aui_25g_aoc_acc = 1,
	.aui_25g_c2c = 1,
      };
      break;
    case 40000000: /* 40G */
      *low = (ice_phy_type_low_t) {
	.base_40g_cr4 = 1,
	.base_40g_sr4 = 1,
	.base_40g_lr4 = 1,
	.base_40g_kr4 = 1,
	.xlaui_40g_aoc_acc = 1,
	.xlaui_40g = 1,
      };
      break;
    case 50000000: /* 50G */
      *low = (ice_phy_type_low_t) {
	.base_50g_cr2 = 1,
	.base_50g_sr2 = 1,
	.base_50g_lr2 = 1,
	.base_50g_kr2 = 1,
	.laui2_50g_aoc_acc = 1,
	.laui2_50g = 1,
	.aui2_50g_aoc_acc = 1,
	.aui2_50g = 1,
	.base_50g_cp = 1,
	.base_50g_sr = 1,
	.base_50g_fr = 1,
	.base_50g_lr = 1,
	.base_50g_kr_pam4 = 1,
	.aui1_50g_aoc_acc = 1,
	.aui1_50g = 1,
      };
      break;
    case 100000000: /* 100G */
      *low = (ice_phy_type_low_t) {
	.base_100g_cr4 = 1,
	.base_100g_sr4 = 1,
	.base_100g_lr4 = 1,
	.base_100g_kr4 = 1,
	.caui4_100g_aoc_acc = 1,
	.caui4_100g = 1,
	.aui4_100g_aoc_acc = 1,
	.aui4_100g = 1,
	.base_100g_cr_pam4 = 1,
	.base_100g_kr_pam4 = 1,
	.base_100g_cp2 = 1,
	.base_100g_sr2 = 1,
	.base_100g_dr = 1,
      };
      *high = (ice_phy_type_high_t) {
	.base_100g_kr2_pam4 = 1,
	.caui2_100g_aoc_acc = 1,
	.caui2_100g = 1,
	.aui2_100g_aoc_acc = 1,
	.aui2_100g = 1,
      };
      break;
    case 200000000:
      *high = (ice_phy_type_high_t) {
	.base_200g_cr4_pam4 = 1,
	.base_200g_sr4 = 1,
	.base_200g_fr4 = 1,
	.base_200g_lr4 = 1,
	.base_200g_dr4 = 1,
	.base_200g_kr4_pam4 = 1,
	.aui4_200g_aoc_acc = 1,
	.aui4_200g = 1,
	.aui8_200g_aoc_acc = 1,
	.aui8_200g = 1,
      };
      break;
    default:
      return VNET_DEV_ERR_NOT_SUPPORTED;
    }
  return VNET_DEV_OK;
}
