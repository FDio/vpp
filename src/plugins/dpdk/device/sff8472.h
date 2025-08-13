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
void sff8472_decode_diagnostics (vlib_main_t *vm, u8 *eeprom_data, u32 length,
				 u8 is_terse);

#endif /* __included_dpdk_sff8472_h__ */
