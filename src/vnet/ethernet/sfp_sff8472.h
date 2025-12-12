/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco and/or its affiliates.
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
  u8 reserved_40_55[16];     /* 40-55: Reserved/Other fields */
  /* Calibration constants for external calibration (bytes 56-95) */
  u32 rx_power_cal[5];	/* 56-75: RX power calibration coefficients (IEEE 754
			   float) */
  u16 tx_bias_slope;	/* 76-77: TX bias slope calibration */
  u16 tx_bias_offset;	/* 78-79: TX bias offset calibration */
  u16 tx_power_slope;	/* 80-81: TX power slope calibration */
  u16 tx_power_offset;	/* 82-83: TX power offset calibration */
  u16 temp_slope;	/* 84-85: Temperature slope calibration */
  u16 temp_offset;	/* 86-87: Temperature offset calibration */
  u16 voltage_slope;	/* 88-89: Voltage slope calibration */
  u16 voltage_offset;	/* 90-91: Voltage offset calibration */
  u8 reserved_92_95[4]; /* 92-95: Reserved */
  /* Real-time diagnostic values (bytes 96-105) */
  u16 temperature;	    /* 96-97: Temperature */
  u16 vcc;		    /* 98-99: Supply voltage */
  u16 tx_bias;		    /* 100-101: TX bias current */
  u16 tx_power;		    /* 102-103: TX average optical power */
  u16 rx_power;		    /* 104-105: RX average optical power */
  u8 reserved_106_109[4];   /* 106-109: Reserved */
  u8 status_control[2];	    /* 110-111: Status/Control */
  u8 alarm1;		    /* 112: Temp, VCC, TX Bias, TX Power alarms */
  u8 alarm2;		    /* 113: Rx, Laser Temp, TEC current alarms */
  u8 tx_input_equalization; /* 114: Tx Input equalization HIGH / LOW */
  u8 rx_output_emphasis;    /* 115: Rx output emphasis HIGH / LOW */
  u8 warning1;		    /* 116: Temp, VCC, TX Bias, TX power warnings */
  u8 warning2;		    /* 117: Rx, Laser Temp, TEC current warning */
  u8 emc_status[2];	    /* 118-119: Extended Module Control status */
  u8 reserved_120_126[7];   /* 120-126: Vendor specific Locations */
  u8 page_select;	    /* 127: Page Select */
} sff8472_diag_t;

STATIC_ASSERT (sizeof (sff8472_diag_t) == 128,
	       "sff8472_diag_t must be 128 bytes");

/* Function declarations */
void sff8472_decode_diagnostics (vlib_main_t *vm,
				 vnet_interface_eeprom_t *eeprom, u8 is_terse);

#endif /* __included_ethernet_sff8472_h__ */
