/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2016 Cisco and/or its affiliates.
 */

#ifndef included_vnet_optics_sfp_h
#define included_vnet_optics_sfp_h

#include <vppinfra/format.h>
#include <vnet/interface.h>

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

  /* NOTE: SFF8472 defines vendor revision as 4 bytes, followed by 2 bytes of
   * wavelength_or_att SFF8636 defines vendor revision as 2 bytes, followed by
   * u16 wavelength_or_att, then u16 wavelength_tolerance
   */
  u8 vendor_revision[4]; /* SFF8636 has wavelength in vendor_revision[2+3] */
  u16 wavelength_or_att; /* SFF8472 has wavelength here; SFF8636 has
			    wavelength_tolerance here */

  u8 reserved_62; /* Byte 62: Reserved */
  u8 cc_base;	  /* Byte 63: checksum for first 64 bytes */
  u8 option_values[2];
  u8 signalling_rate_max;
  u8 signalling_rate_min;
  u8 vendor_serial_number[16];
  u8 vendor_date_code[8];
  u8 diag_monitoring_type; /* Byte 92 */
  u8 reserved93[2];
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

/* Show the EEPROM module information */
void sfp_eeprom_module (vlib_main_t *vm, vnet_interface_eeprom_t *eeprom,
			u8 is_terse);
void sfp_eeprom_diagnostics (vlib_main_t *vm, vnet_interface_eeprom_t *eeprom,
			     u8 is_terse);

/* Base SFP EEPROM decoding function */
void sfp_eeprom_decode_base (vlib_main_t *vm, sfp_eeprom_t *se, u8 is_terse,
			     vnet_interface_eeprom_type_t eeprom_type);

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

#define foreach_sfp_encoding                                                  \
  _ (0x01, "8B/10B")                                                          \
  _ (0x02, "4B/5B")                                                           \
  _ (0x03, "NRZ")                                                             \
  _ (0x04, "4B/5B (FC-100)")                                                  \
  _ (0x05, "Manchester")                                                      \
  _ (0x06, "64B/66B")                                                         \
  _ (0x07, "256B/257B")                                                       \
  _ (0x08, "PAM4")

typedef enum
{
#define _(v, s) SFP_ENCODING_##v = v,
  foreach_sfp_encoding
#undef _
} sfp_encoding_t;

#define foreach_sfp_connector                                                 \
  _ (0x01, "SC")                                                              \
  _ (0x02, "Fibre Channel Style 1 copper")                                    \
  _ (0x03, "Fibre Channel Style 2 copper")                                    \
  _ (0x04, "BNC/TNC")                                                         \
  _ (0x05, "Fibre Channel coaxial")                                           \
  _ (0x06, "Fiber Jack")                                                      \
  _ (0x07, "LC")                                                              \
  _ (0x08, "MT-RJ")                                                           \
  _ (0x09, "MU")                                                              \
  _ (0x0A, "SG")                                                              \
  _ (0x0B, "Optical pigtail")                                                 \
  _ (0x0C, "MPO 1x12 Parallel Optic")                                         \
  _ (0x0D, "MPO 2x16 Parallel Optic")                                         \
  _ (0x20, "HSSDC II")                                                        \
  _ (0x21, "Copper pigtail")                                                  \
  _ (0x22, "RJ45")                                                            \
  _ (0x23, "No separable connector")                                          \
  _ (0x24, "MXC 2x16")                                                        \
  _ (0x25, "CS optical connector")                                            \
  _ (0x26, "SN optical connector")                                            \
  _ (0x27, "MPO 2x12 Parallel Optic")                                         \
  _ (0x28, "MPO 1x16 Parallel Optic")

typedef enum
{
#define _(v, s) SFP_CONNECTOR_##v = v,
  foreach_sfp_connector
#undef _
} sfp_connector_t;

format_function_t format_sfp_eeprom;
format_function_t format_sfp_id;
format_function_t format_sfp_encoding;
format_function_t format_sfp_connector;

#endif /* included_vnet_optics_sfp_h */
