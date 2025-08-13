/*
 * Copyright (c) 2025 Cisco and/or its affiliates.
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

#ifndef __included_dpdk_sff8472_h__
#define __included_dpdk_sff8472_h__

#include <vlib/vlib.h>
#include <vppinfra/types.h>
#include <vnet/ethernet/sfp.h>

/* SFF-8472 A0 page - Base ID fields (bytes 0-127) */
typedef struct
{
  u8 identifier;		 /* 0: Transceiver type */
  u8 ext_identifier;		 /* 1: Extended identifier */
  u8 connector;			 /* 2: Connector type */
  u8 transceiver[8];		 /* 3-10: Transceiver compliance codes */
  u8 encoding;			 /* 11: Encoding */
  u8 br_nominal;		 /* 12: Nominal signaling rate */
  u8 rate_identifier;		 /* 13: Rate identifier */
  u8 length_smf_km;		 /* 14: Length (SMF) - km */
  u8 length_smf;		 /* 15: Length (SMF) - 100m */
  u8 length_50um;		 /* 16: Length (50um OM2) - 10m */
  u8 length_625um;		 /* 17: Length (62.5um OM1) - 10m */
  u8 length_copper;		 /* 18: Length (Copper) - m */
  u8 length_om3;		 /* 19: Length (OM3) - 10m */
  u8 vendor_name[16];		 /* 20-35: Vendor name */
  u8 transceiver_ext;		 /* 36: Extended transceiver codes */
  u8 vendor_oui[3];		 /* 37-39: Vendor OUI */
  u8 vendor_pn[16];		 /* 40-55: Vendor PN */
  u8 vendor_rev[4];		 /* 56-59: Vendor revision */
  u8 wavelength[2];		 /* 60-61: Laser wavelength */
  u8 reserved_62;		 /* 62: Reserved */
  u8 cc_base;			 /* 63: Check code for base ID fields */
  u8 options[2];		 /* 64-65: Options */
  u8 br_max;			 /* 66: Upper bit rate margin */
  u8 br_min;			 /* 67: Lower bit rate margin */
  u8 vendor_sn[16];		 /* 68-83: Vendor serial number */
  u8 date_code[8];		 /* 84-91: Date code */
  u8 diagnostic_monitoring_type; /* 92: Diagnostic monitoring type */
  u8 enhanced_options;		 /* 93: Enhanced options */
  u8 sff8472_compliance;	 /* 94: SFF-8472 compliance */
  u8 cc_ext;			 /* 95: Check code for extended ID fields */
} sff8472_base_id_t;

/* SFF-8472 A2 page - Diagnostic fields */
typedef struct
{
  /* Alarm and warning thresholds (bytes 0-55) */
  u8 temp_high_alarm[2];       /* 0-1: Temperature high alarm */
  u8 temp_low_alarm[2];	       /* 2-3: Temperature low alarm */
  u8 temp_high_warning[2];     /* 4-5: Temperature high warning */
  u8 temp_low_warning[2];      /* 6-7: Temperature low warning */
  u8 voltage_high_alarm[2];    /* 8-9: Voltage high alarm */
  u8 voltage_low_alarm[2];     /* 10-11: Voltage low alarm */
  u8 voltage_high_warning[2];  /* 12-13: Voltage high warning */
  u8 voltage_low_warning[2];   /* 14-15: Voltage low warning */
  u8 bias_high_alarm[2];       /* 16-17: Bias high alarm */
  u8 bias_low_alarm[2];	       /* 18-19: Bias low alarm */
  u8 bias_high_warning[2];     /* 20-21: Bias high warning */
  u8 bias_low_warning[2];      /* 22-23: Bias low warning */
  u8 tx_power_high_alarm[2];   /* 24-25: TX power high alarm */
  u8 tx_power_low_alarm[2];    /* 26-27: TX power low alarm */
  u8 tx_power_high_warning[2]; /* 28-29: TX power high warning */
  u8 tx_power_low_warning[2];  /* 30-31: TX power low warning */
  u8 rx_power_high_alarm[2];   /* 32-33: RX power high alarm */
  u8 rx_power_low_alarm[2];    /* 34-35: RX power low alarm */
  u8 rx_power_high_warning[2]; /* 36-37: RX power high warning */
  u8 rx_power_low_warning[2];  /* 38-39: RX power low warning */
  u8 reserved_40_95[56];       /* 40-95: Reserved/Other fields */
  /* Real-time diagnostic values (bytes 96-105) */
  u8 temperature[2];	  /* 96-97: Temperature */
  u8 vcc[2];		  /* 98-99: Supply voltage */
  u8 tx_bias[2];	  /* 100-101: TX bias current */
  u8 tx_power[2];	  /* 102-103: TX average optical power */
  u8 rx_power[2];	  /* 104-105: RX average optical power */
  u8 reserved_106_109[4]; /* 106-109: Reserved */
  u8 status_control[2];	  /* 110-111: Status/Control */
} sff8472_diag_t;

/* Function declarations */
void sff8472_decode_sfp_eeprom (vlib_main_t *vm, sfp_eeprom_t *se,
				u8 is_terse);
void sff8472_decode_module (vlib_main_t *vm, u8 *eeprom_data, u32 length,
			    u8 is_terse);
void sff8472_decode_diagnostics (vlib_main_t *vm, u8 *eeprom_data, u32 length,
				 u8 is_terse);

#endif /* __included_dpdk_sff8472_h__ */
