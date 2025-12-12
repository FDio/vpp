/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco and/or its affiliates.
 */

#ifndef __included_ethernet_sff8636_h__
#define __included_ethernet_sff8636_h__

#include <vlib/vlib.h>
#include <vppinfra/types.h>

/* SFF-8636 is a 640 byte EEPROM.
 * Any SFF-8436-compliant module will generally respond correctly to an
 * SFF-8636 reader, because the lower and upper Page 00h structures are largely
 * preserved.
 */

typedef struct
{
  u8 identifier;	  // Byte 0
  u8 status[2];		  // Bytes 1-2 (see Table 6-2)
  u8 interrupt_flags[19]; // Bytes 3-21 (Tables 6-4, 6-5, 6-6)

  // ---------------- Device Free Side Monitors ----------------
  u16 temperature;     // Bytes 22-23 (1/256 °C per LSB)
  u8 reserved_fsm[2];  // Bytes 24-25 (vendor-specific / reserved)
  u16 vcc;	       // Bytes 26-27 (100 µV per LSB)
  u8 reserved_fsm2[6]; // Bytes 28-33 (vendor-specific / reserved)

  // ---------------- Per-lane channel monitors ----------------
  // Lane 1–4, each has 4 bytes: TX bias, TX power, RX power, reserved
  u16 rx_power[4];	 // Bytes 34-41 (2 bytes per lane, 0.1 µW scaling)
  u16 tx_bias[4];	 // Bytes 42-49 (2 bytes per lane, µA scaling)
  u16 tx_power[4];	 // Bytes 50-57 (2 bytes per lane, 0.1 µW scaling)
  u16 reserved_lane[4];	 // Bytes 58-65 (reserved/future use)
  u8 reserved_66_85[20]; // Bytes 66-85
  u8 control[13];     // Bytes 86-98 (Table 6-9; includes App Select bytes per
		      // Table 6-12)
  u8 reserved_99;     // Byte 99
  u8 hw_int_mask[7];  // Bytes 100-106 (Table 6-14)
  u8 reserved_107;    // Byte 107
  u8 device_props[7]; // Bytes 108-114 (Table 6-15; incl. PCIe use at 111-112
		      // per Fig 6-1)
  u8 reserved_115_118[4]; // Bytes 115-118
  u8 password_change[4];  // Bytes 119-122 (optional, write-only in device)
  u8 password_entry[4];	  // Bytes 123-126 (optional, write-only in device)
  u8 page_select;	  // Byte 127 (Page Select)

  // 128–255 (Base ID portion)
  u8 base_id[128]; // this is the standard sfp_eeprom_t at offset 0x80

  // 256-511 (page01, page02)
  u8 reserved_page01[128]; // 256-383
  u8 reserved_page02[128]; // 384-511

  // 512–559 : Free-Side Device Thresholds and Channel Thresholds
  // Typically: temp high alarm/warn, low warn/alarm; Vcc high/low thresholds,
  // etc.
  u16 temp_high_alarm;	// 512-513 (0.00390625 °C/LSB)
  u16 temp_low_alarm;	// 514-515
  u16 temp_high_warn;	// 516-517
  u16 temp_low_warn;	// 518-519
  u8 reserved_fsdct[8]; // 520-527

  u16 vcc_high_alarm;	 // 528-529 (100 µV/LSB)
  u16 vcc_low_alarm;	 // 530-531
  u16 vcc_high_warn;	 // 532-533
  u16 vcc_low_warn;	 // 534-535
  u8 reserved_fsdct2[8]; // 536-543

  u8 reserved_device_thresh[16]; // 544-559

  // 560–607 : Channel Thresholds (48 bytes)
  // Per-channel: TX bias, TX power, RX power alarms/warns
  u16 rx_power_high_alarm; // 560-56 (0.1 µW/LSB)
  u16 rx_power_low_alarm;  // 562-563
  u16 rx_power_high_warn;  // 564-565
  u16 rx_power_low_warn;   // 566-567

  u16 tx_bias_high_alarm;  // 568-569 (µA/LSB)
  u16 tx_bias_low_alarm;   // 570-571
  u16 tx_bias_high_warn;   // 572-573
  u16 tx_bias_low_warn;	   // 574-575
			   //
  u16 tx_power_high_alarm; // 576-577 (0.1 µW/LSB)
  u16 tx_power_low_alarm;  // 578-579
  u16 tx_power_high_warn;  // 580-581
  u16 tx_power_low_warn;   // 582-583

  u8 reserved_ct[24]; // 584-607

  // 608–613 : TX EQ / RX Output / Temp Control (6 bytes)
  u8 tx_eq_settings[4];	    // 608-611 (per-channel EQ/emphasis)
  u8 rx_output_settings;    // 612
  u8 temp_control_settings; // 613

  // 614–625 : Channel Controls (12 bytes)
  u8 channel_controls[12]; // 614-625 (enable, polarity, squelch, etc.)

  // 626–635 : Channel Monitor Masks (10 bytes)
  u8 channel_monitor_masks[10]; // 626-635 (interrupt mask bits per
				// channel/parameter)

  // 636–639 : Reserved
  u8 reserved_636_639[4]; // 636-639
} sff8636_eeprom_t;

STATIC_ASSERT (sizeof (sff8636_eeprom_t) == 640,
	       "sff8636_eeprom_t must be 640 bytes");

/* Function declarations */
void sff8636_decode_diagnostics (vlib_main_t *vm,
				 vnet_interface_eeprom_t *eeprom, u8 is_terse);

#endif /* __included_ethernet_sff8636_h__ */
