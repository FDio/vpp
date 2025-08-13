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

#ifndef __included_ethernet_sff8472_h__
#define __included_ethernet_sff8472_h__

#include <vlib/vlib.h>
#include <vppinfra/types.h>
#include <vnet/ethernet/sfp.h>

/* SFF-8472 A2 page - Diagnostic fields */
typedef struct
{
  /* Alarm and warning thresholds (bytes 0-55) */
  u16 temp_high_alarm;	     /* 0-1: Temperature high alarm */
  u16 temp_low_alarm;	     /* 2-3: Temperature low alarm */
  u16 temp_high_warning;     /* 4-5: Temperature high warning */
  u16 temp_low_warning;	     /* 6-7: Temperature low warning */
  u16 voltage_high_alarm;    /* 8-9: Voltage high alarm */
  u16 voltage_low_alarm;     /* 10-11: Voltage low alarm */
  u16 voltage_high_warning;  /* 12-13: Voltage high warning */
  u16 voltage_low_warning;   /* 14-15: Voltage low warning */
  u16 bias_high_alarm;	     /* 16-17: Bias high alarm */
  u16 bias_low_alarm;	     /* 18-19: Bias low alarm */
  u16 bias_high_warning;     /* 20-21: Bias high warning */
  u16 bias_low_warning;	     /* 22-23: Bias low warning */
  u16 tx_power_high_alarm;   /* 24-25: TX power high alarm */
  u16 tx_power_low_alarm;    /* 26-27: TX power low alarm */
  u16 tx_power_high_warning; /* 28-29: TX power high warning */
  u16 tx_power_low_warning;  /* 30-31: TX power low warning */
  u16 rx_power_high_alarm;   /* 32-33: RX power high alarm */
  u16 rx_power_low_alarm;    /* 34-35: RX power low alarm */
  u16 rx_power_high_warning; /* 36-37: RX power high warning */
  u16 rx_power_low_warning;  /* 38-39: RX power low warning */
  u8 reserved_40_95[56];     /* 40-95: Reserved/Other fields */
  /* Real-time diagnostic values (bytes 96-105) */
  u16 temperature;	  /* 96-97: Temperature */
  u16 vcc;		  /* 98-99: Supply voltage */
  u16 tx_bias;		  /* 100-101: TX bias current */
  u16 tx_power;		  /* 102-103: TX average optical power */
  u16 rx_power;		  /* 104-105: RX average optical power */
  u8 reserved_106_109[4]; /* 106-109: Reserved */
  u8 status_control[2];	  /* 110-111: Status/Control */
} sff8472_diag_t;

/* Function declarations */
void sff8472_decode_diagnostics (vlib_main_t *vm,
				 vnet_interface_eeprom_t *eeprom, u8 is_terse);

#endif /* __included_ethernet_sff8472_h__ */
