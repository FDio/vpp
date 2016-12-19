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
  _ (unknown)					\
  _ (gbic)					\
  _ (on_motherboard)				\
  _ (sfp)

typedef enum
{
#define _(f) SFP_ID_##f,
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
  u8 link_length[5];
  u8 reserved19;
  u8 vendor_name[16];
  u8 reserved36;
  u8 vendor_oui[3];
  u8 vendor_part_number[16];
  u8 vendor_revision[4];
  /* 16 bit value network byte order. */
  u8 laser_wavelength_in_nm[2];
  u8 reserved62;
  u8 checksum_0_to_62;

  u8 options[2];
  u8 max_bit_rate_margin_percent;
  u8 min_bit_rate_margin_percent;
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
  return sum == e->checksum_0_to_62;
}

/* _ (byte_index, bit_index, name) */
#define foreach_sfp_compatibility		\
  _ (0, 4, 10g_base_sr)				\
  _ (0, 5, 10g_base_lr)				\
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
