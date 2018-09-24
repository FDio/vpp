/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef included_vnet_optics_sfp_h
#define included_vnet_optics_sfp_h

#include <vppinfra/format.h>

#define foreach_sfp_id				\
  _ (UNKNOWN, "unknown")			\
  _ (GBIC, "GBIC")				\
  _ (ON_MB, "on-motherboard")			\
  _ (SFP, "SFP/SFP+/SFP28")			\
  _ (300_PIN_XBI, "300-pin-XBI")		\
  _ (XENPAK, "XENPAK")				\
  _ (XFP, "XFP")				\
  _ (XFF, "XFF")				\
  _ (XFP_E, "XFP-E")				\
  _ (XPAK, "XPAK")				\
  _ (X2, "X2")					\
  _ (DWDM_SFP, "DWDM-SFP")			\
  _ (QSFP, "QSFP")				\
  _ (QSFP_PLUS, "QSFP+")			\
  _ (CXP, "CXP")				\
  _ (SMM_HD_4X, "SMM-HD-4X")			\
  _ (SMM_HD_8X, "SMM-HD-8X")			\
  _ (QSFP28, "QSFP28")				\
  _ (CXP2, "CXP2")				\
  _ (SMM_HD_4X_FAN, "SMM-HD-4X-fanout")		\
  _ (SMM_HD_8X_FAN, "SMM-HD-8X-fanout")		\
  _ (CDFP, "CDFP")				\
  _ (MQSFP, "microQSFP")			\
  _ (QSFP_DD, "QSFP-DD")			\

typedef enum
{
#define _(f,s) SFP_ID_##f,
  foreach_sfp_id
#undef _
} sfp_id_t;

typedef struct
{
  u8 id;
  u8 extended_id;
  u8 connector_type;
  u8 compatibility[8];
  u8 encoding;
  u8 nominal_bit_rate_100mbits_per_sec;
  u8 reserved13;
  u8 length[5];
  u8 device_tech;
  u8 vendor_name[16];
  u8 ext_module_codes;
  u8 vendor_oui[3];
  u8 vendor_part_number[16];
  u8 vendor_revision[2];
  /* 16 bit value network byte order. */
  u8 wavelength_or_att[2];
  u8 wavelength_tolerance_or_att[2];
  u8 max_case_temp;
  u8 cc_base;

  u8 link_codes;
  u8 options[3];
  u8 vendor_serial_number[16];
  u8 vendor_date_code[8];
  u8 reserved92[3];
  u8 checksum_63_to_94;
  u8 vendor_specific[32];
  u8 reserved128[384];

  /* Vendor specific data follows. */
  u8 vendor_specific1[0];
} sfp_eeprom_t;

always_inline uword
sfp_eeprom_is_valid (sfp_eeprom_t * e)
{
  int i;
  u8 sum = 0;
  for (i = 0; i < 63; i++)
    sum += ((u8 *) e)[i];
  return sum == e->cc_base;
}

/* _ (byte_index, bit_index, name) */
#define foreach_sfp_compatibility		\
  _ (0, 0, 40g_active_cable)			\
  _ (0, 1, 40g_base_lr4)			\
  _ (0, 2, 40g_base_sr4)			\
  _ (0, 3, 40g_base_cr4)			\
  _ (0, 4, 10g_base_sr)				\
  _ (0, 5, 10g_base_lr)				\
  _ (0, 5, 10g_base_lrm)			\
  _ (1, 3, 40g_otn)				\
  _ (1, 2, oc48_long_reach)			\
  _ (1, 1, oc48_intermediate_reach)		\
  _ (1, 0, oc48_short_reach)			\
  _ (2, 6, oc12_long_reach)			\
  _ (2, 5, oc12_intermediate_reach)		\
  _ (2, 4, oc12_short_reach)			\
  _ (2, 2, oc3_long_reach)			\
  _ (2, 1, oc3_intermediate_reach)		\
  _ (2, 0, oc3_short_reach)			\
  _ (3, 3, 1g_base_t)				\
  _ (3, 2, 1g_base_cx)				\
  _ (3, 1, 1g_base_lx)				\
  _ (3, 0, 1g_base_sx)

typedef enum
{
#define _(a,b,f) SFP_COMPATIBILITY_##f,
  foreach_sfp_compatibility
#undef _
    SFP_N_COMPATIBILITY,
} sfp_compatibility_t;

u32 sfp_is_comatible (sfp_eeprom_t * e, sfp_compatibility_t c);

format_function_t format_sfp_eeprom;

#endif /* included_vnet_optics_sfp_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
