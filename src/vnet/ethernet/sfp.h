/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2016-2026 Cisco and/or its affiliates.
 */

#pragma once

#include <math.h>
#include <vlib/vlib.h>
#include <vppinfra/format.h>
#include <vnet/interface.h>

#define foreach_sfp_id                                                                             \
  _ (0x00, UNKNOWN, "unknown")                                                                     \
  _ (0x01, GBIC, "GBIC")                                                                           \
  _ (0x02, ON_MB, "on-motherboard")                                                                \
  _ (0x03, SFP, "SFP/SFP+/SFP28")                                                                  \
  _ (0x04, 300_PIN_XBI, "300-pin-XBI")                                                             \
  _ (0x05, XENPAK, "XENPAK")                                                                       \
  _ (0x06, XFP, "XFP")                                                                             \
  _ (0x07, XFF, "XFF")                                                                             \
  _ (0x08, XFP_E, "XFP-E")                                                                         \
  _ (0x09, XPAK, "XPAK")                                                                           \
  _ (0x0A, X2, "X2")                                                                               \
  _ (0x0B, DWDM_SFP, "DWDM-SFP")                                                                   \
  _ (0x0C, QSFP, "QSFP")                                                                           \
  _ (0x0D, QSFP_PLUS, "QSFP+")                                                                     \
  _ (0x0E, CXP, "CXP")                                                                             \
  _ (0x0F, SMM_HD_4X, "SMM-HD-4X")                                                                 \
  _ (0x10, SMM_HD_8X, "SMM-HD-8X")                                                                 \
  _ (0x11, QSFP28, "QSFP28")                                                                       \
  _ (0x12, CXP2, "CXP2")                                                                           \
  _ (0x13, CDFP, "CDFP")                                                                           \
  _ (0x14, SMM_HD_4X_FAN, "SMM-HD-4X-fanout")                                                      \
  _ (0x15, SMM_HD_8X_FAN, "SMM-HD-8X-fanout")                                                      \
  _ (0x16, CDFP_STYLE3, "CDFP (Style 3)")                                                          \
  _ (0x17, MQSFP, "microQSFP")                                                                     \
  _ (0x18, QSFP_DD, "QSFP-DD")

#define foreach_sff8636_transmitter_tech                                                           \
  _ (0x0, "850 nm VCSEL")                                                                          \
  _ (0x1, "1310 nm VCSEL")                                                                         \
  _ (0x2, "1550 nm VCSEL")                                                                         \
  _ (0x3, "1310 nm FP")                                                                            \
  _ (0x4, "1310 nm DFB")                                                                           \
  _ (0x5, "1550 nm DFB")                                                                           \
  _ (0x6, "1310 nm EML")                                                                           \
  _ (0x7, "1550 nm EML")                                                                           \
  _ (0x8, "Other/Undefined")                                                                       \
  _ (0x9, "1490 nm DFB")                                                                           \
  _ (0xA, "Copper cable unequalized")                                                              \
  _ (0xB, "Copper cable passive equalized")                                                        \
  _ (0xC, "Copper cable, near and far end limiting active equalizers")                             \
  _ (0xD, "Copper cable, far end limiting active equalizers")                                      \
  _ (0xE, "Copper cable, near end limiting active equalizers")                                     \
  _ (0xF, "Copper cable, linear active equalizers")

#define foreach_sff8472_compliance                                                                 \
  _ (0, 7, "10GBASE-ER")                                                                           \
  _ (0, 6, "10GBASE-LRM")                                                                          \
  _ (0, 5, "10GBASE-LR")                                                                           \
  _ (0, 4, "10GBASE-SR")                                                                           \
  _ (0, 3, "1X SX (InfiniBand)")                                                                   \
  _ (0, 2, "1X LX (InfiniBand)")                                                                   \
  _ (0, 1, "1X Copper Active (InfiniBand)")                                                        \
  _ (0, 0, "1X Copper Passive (InfiniBand)")                                                       \
  _ (1, 7, "ESCON MMF, 1310nm LED")                                                                \
  _ (1, 6, "ESCON SMF, 1310nm Laser")                                                              \
  _ (1, 5, "OC-192, short reach")                                                                  \
  _ (1, 4, "SONET reach specifier bit 1")                                                          \
  _ (1, 3, "SONET reach specifier bit 2")                                                          \
  _ (1, 2, "OC-48, long reach")                                                                    \
  _ (1, 1, "OC-48, intermediate reach")                                                            \
  _ (1, 0, "OC-48, short reach")                                                                   \
  _ (2, 6, "OC-12, single mode long reach")                                                        \
  _ (2, 5, "OC-12, single mode intermediate reach")                                                \
  _ (2, 4, "OC-12, short reach")                                                                   \
  _ (2, 2, "OC-3, single mode long reach")                                                         \
  _ (2, 1, "OC-3, single mode intermediate reach")                                                 \
  _ (2, 0, "OC-3, short reach")                                                                    \
  _ (3, 7, "BASE-PX")                                                                              \
  _ (3, 6, "BASE-BX10")                                                                            \
  _ (3, 5, "100BASE-FX")                                                                           \
  _ (3, 4, "100BASE-LX/LX10")                                                                      \
  _ (3, 3, "1000BASE-T")                                                                           \
  _ (3, 2, "1000BASE-CX")                                                                          \
  _ (3, 1, "1000BASE-LX")                                                                          \
  _ (3, 0, "1000BASE-SX")                                                                          \
  _ (4, 7, "FC very long distance (V)")                                                            \
  _ (4, 6, "FC short distance (S)")                                                                \
  _ (4, 5, "FC intermediate distance (I)")                                                         \
  _ (4, 4, "FC long distance (L)")                                                                 \
  _ (4, 3, "FC medium distance (M)")                                                               \
  _ (4, 2, "FC shortwave laser, linear Rx (SA)")                                                   \
  _ (4, 1, "FC longwave laser (LC)")                                                               \
  _ (4, 0, "FC electrical inter-enclosure (EL)")                                                   \
  _ (5, 7, "FC electrical intra-enclosure (EL)")                                                   \
  _ (5, 6, "FC shortwave laser w/o OFC (SN)")                                                      \
  _ (5, 5, "FC shortwave laser with OFC (SL)")                                                     \
  _ (5, 4, "FC longwave laser (LL)")                                                               \
  _ (5, 3, "SFP+ active cable")                                                                    \
  _ (5, 2, "SFP+ passive cable")                                                                   \
  _ (6, 7, "FC twin axial pair (TW)")                                                              \
  _ (6, 6, "FC twisted pair (TP)")                                                                 \
  _ (6, 5, "FC miniature coax (MI)")                                                               \
  _ (6, 4, "FC video coax (TV)")                                                                   \
  _ (6, 3, "FC multimode, 62.5um (M6)")                                                            \
  _ (6, 2, "FC multimode, 50um (M5, M5E)")                                                         \
  _ (6, 0, "FC single mode (SM)")                                                                  \
  _ (7, 7, "FC 1200 MBytes/sec")                                                                   \
  _ (7, 6, "FC 800 MBytes/sec")                                                                    \
  _ (7, 5, "FC 1600 MBytes/sec")                                                                   \
  _ (7, 4, "FC 400 MBytes/sec")                                                                    \
  _ (7, 3, "FC 3200 MBytes/sec")                                                                   \
  _ (7, 2, "FC 200 MBytes/sec")                                                                    \
  _ (7, 0, "FC 100 MBytes/sec")

#define foreach_sff8636_compliance                                                                 \
  _ (0, 6, "10GBASE-LRM")                                                                          \
  _ (0, 5, "10GBASE-LR")                                                                           \
  _ (0, 4, "10GBASE-SR")                                                                           \
  _ (0, 3, "40GBASE-CR4")                                                                          \
  _ (0, 2, "40GBASE-SR4")                                                                          \
  _ (0, 1, "40GBASE-LR4")                                                                          \
  _ (0, 0, "40G Active Cable (XLPPI)")                                                             \
  _ (1, 2, "OC-48, long reach")                                                                    \
  _ (1, 1, "OC-48, intermediate reach")                                                            \
  _ (1, 0, "OC-48, short reach")                                                                   \
  _ (2, 7, "SAS 24.0 Gbps")                                                                        \
  _ (2, 6, "SAS 12.0 Gbps")                                                                        \
  _ (2, 5, "SAS 6.0 Gbps")                                                                         \
  _ (2, 4, "SAS 3.0 Gbps")                                                                         \
  _ (3, 3, "1000BASE-T")                                                                           \
  _ (3, 2, "1000BASE-CX")                                                                          \
  _ (3, 1, "1000BASE-LX")                                                                          \
  _ (3, 0, "1000BASE-SX")                                                                          \
  _ (4, 7, "FC very long distance (V)")                                                            \
  _ (4, 6, "FC short distance (S)")                                                                \
  _ (4, 5, "FC intermediate distance (I)")                                                         \
  _ (4, 4, "FC long distance (L)")                                                                 \
  _ (4, 3, "FC medium (M)")                                                                        \
  _ (4, 1, "FC longwave laser (LC)")                                                               \
  _ (4, 0, "FC electrical inter-enclosure (EL)")                                                   \
  _ (5, 7, "FC electrical intra-enclosure")                                                        \
  _ (5, 6, "FC shortwave laser w/o OFC (SN)")                                                      \
  _ (5, 5, "FC shortwave laser with OFC (SL)")                                                     \
  _ (5, 4, "FC longwave laser (LL)")                                                               \
  _ (6, 7, "FC twin axial pair (TW)")                                                              \
  _ (6, 6, "FC shielded twisted pair (TP)")                                                        \
  _ (6, 5, "FC miniature coax (MI)")                                                               \
  _ (6, 4, "FC video coax (TV)")                                                                   \
  _ (6, 3, "FC multi-mode, 62.5um (M6)")                                                           \
  _ (6, 2, "FC multi-mode, 50um (M5)")                                                             \
  _ (6, 1, "FC multi-mode, 50um (OM3)")                                                            \
  _ (6, 0, "FC single mode (SM)")                                                                  \
  _ (7, 7, "FC 1200 MBps/channel")                                                                 \
  _ (7, 6, "FC 800 MBps")                                                                          \
  _ (7, 5, "FC 1600 MBps/channel")                                                                 \
  _ (7, 4, "FC 400 MBps")                                                                          \
  _ (7, 3, "FC 3200 MBps/channel")                                                                 \
  _ (7, 2, "FC 200 MBps")                                                                          \
  _ (7, 0, "FC 100 MBps")

#define foreach_sfp_encoding                                                                       \
  _ (0x01, "8B/10B")                                                                               \
  _ (0x02, "4B/5B")                                                                                \
  _ (0x03, "NRZ")                                                                                  \
  _ (0x04, "4B/5B (FC-100)")                                                                       \
  _ (0x05, "Manchester")                                                                           \
  _ (0x06, "64B/66B")                                                                              \
  _ (0x07, "256B/257B")                                                                            \
  _ (0x08, "PAM4")

#define foreach_sfp_connector                                                                      \
  _ (0x01, "SC")                                                                                   \
  _ (0x02, "Fibre Channel Style 1 copper")                                                         \
  _ (0x03, "Fibre Channel Style 2 copper")                                                         \
  _ (0x04, "BNC/TNC")                                                                              \
  _ (0x05, "Fibre Channel coaxial")                                                                \
  _ (0x06, "Fiber Jack")                                                                           \
  _ (0x07, "LC")                                                                                   \
  _ (0x08, "MT-RJ")                                                                                \
  _ (0x09, "MU")                                                                                   \
  _ (0x0A, "SG")                                                                                   \
  _ (0x0B, "Optical pigtail")                                                                      \
  _ (0x0C, "MPO 1x12 Parallel Optic")                                                              \
  _ (0x0D, "MPO 2x16 Parallel Optic")                                                              \
  _ (0x20, "HSSDC II")                                                                             \
  _ (0x21, "Copper pigtail")                                                                       \
  _ (0x22, "RJ45")                                                                                 \
  _ (0x23, "No separable connector")                                                               \
  _ (0x24, "MXC 2x16")                                                                             \
  _ (0x25, "CS optical connector")                                                                 \
  _ (0x26, "SN optical connector")                                                                 \
  _ (0x27, "MPO 2x12 Parallel Optic")                                                              \
  _ (0x28, "MPO 1x16 Parallel Optic")

typedef enum
{
#define _(v, f, s) SFP_ID_##f = v,
  foreach_sfp_id
#undef _
} sfp_id_t;

typedef enum
{
#define _(v, s) SFP_ENCODING_##v = v,
  foreach_sfp_encoding
#undef _
} sfp_encoding_t;

typedef enum
{
#define _(v, s) SFP_CONNECTOR_##v = v,
  foreach_sfp_connector
#undef _
} sfp_connector_t;

/* SFF-8472 Table 3.9, byte 92 - only meaningful for SFP/SFF-8472; this
 * struct offset holds an unrelated field when overlaid on a QSFP module */
typedef union
{
  struct
  {
    u8 _reserved_0_1 : 2;
    u8 address_change_required : 1;
    u8 received_power_is_avg : 1; /* 0 = OMA, 1 = average power */
    u8 externally_calibrated : 1;
    u8 internally_calibrated : 1;
    u8 ddm_supported : 1;
    u8 _reserved_7 : 1;
  };
  u8 as_u8;
} sff8472_diag_monitoring_type_t;

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
  sff8472_diag_monitoring_type_t diag_monitoring_type; /* Byte 92 */
  u8 reserved93[2];
  u8 checksum_63_to_94;
  u8 vendor_specific[32];

  /* further vendor-specific data follows, size varies by module */
  u8 vendor_specific1[];
} sfp_eeprom_t;

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

STATIC_ASSERT (sizeof (sff8472_diag_t) == 128, "sff8472_diag_t must be 128 bytes");

/* SFF-8636 is a 640 byte EEPROM.
 * Any SFF-8436-compliant module will generally respond correctly to an
 * SFF-8636 reader, because the lower and upper Page 00h structures are largely
 * preserved.
 */
typedef struct
{
  u8 identifier;	  /* Byte 0 */
  u8 status[2];		  /* Bytes 1-2 (see Table 6-2) */
  u8 interrupt_flags[19]; /* Bytes 3-21 (Tables 6-4, 6-5, 6-6) */

  /* ---------------- Device Free Side Monitors ---------------- */
  u16 temperature;     /* Bytes 22-23 (1/256 degC per LSB) */
  u8 reserved_fsm[2];  /* Bytes 24-25 (vendor-specific / reserved) */
  u16 vcc;	       /* Bytes 26-27 (100 uV per LSB) */
  u8 reserved_fsm2[6]; /* Bytes 28-33 (vendor-specific / reserved) */

  /* ---------------- Per-lane channel monitors ---------------- */
  /* Lane 1-4, each has 4 bytes: TX bias, TX power, RX power, reserved */
  u16 rx_power[4];	  /* Bytes 34-41 (2 bytes per lane, 0.1 uW scaling) */
  u16 tx_bias[4];	  /* Bytes 42-49 (2 bytes per lane, uA scaling) */
  u16 tx_power[4];	  /* Bytes 50-57 (2 bytes per lane, 0.1 uW scaling) */
  u16 reserved_lane[4];	  /* Bytes 58-65 (reserved/future use) */
  u8 reserved_66_85[20];  /* Bytes 66-85 */
  u8 control[13];	  /* Bytes 86-98 (Table 6-9; includes App Select bytes per
			      Table 6-12) */
  u8 reserved_99;	  /* Byte 99 */
  u8 hw_int_mask[7];	  /* Bytes 100-106 (Table 6-14) */
  u8 reserved_107;	  /* Byte 107 */
  u8 device_props[7];	  /* Bytes 108-114 (Table 6-15; incl. PCIe use at 111-112
			     per Fig 6-1) */
  u8 reserved_115_118[4]; /* Bytes 115-118 */
  u8 password_change[4];  /* Bytes 119-122 (optional, write-only in device) */
  u8 password_entry[4];	  /* Bytes 123-126 (optional, write-only in device) */
  u8 page_select;	  /* Byte 127 (Page Select) */

  /* 128-255 (Base ID portion) */
  u8 base_id[128]; /* this is the standard sfp_eeprom_t at offset 0x80 */

  /* 256-511 (page01, page02) */
  u8 reserved_page01[128]; /* 256-383 */
  u8 reserved_page02[128]; /* 384-511 */

  /* 512-559 : Free-Side Device Thresholds and Channel Thresholds
   * Typically: temp high alarm/warn, low warn/alarm; Vcc high/low thresholds,
   * etc. */
  u16 temp_high_alarm;	/* 512-513 (0.00390625 degC/LSB) */
  u16 temp_low_alarm;	/* 514-515 */
  u16 temp_high_warn;	/* 516-517 */
  u16 temp_low_warn;	/* 518-519 */
  u8 reserved_fsdct[8]; /* 520-527 */

  u16 vcc_high_alarm;	 /* 528-529 (100 uV/LSB) */
  u16 vcc_low_alarm;	 /* 530-531 */
  u16 vcc_high_warn;	 /* 532-533 */
  u16 vcc_low_warn;	 /* 534-535 */
  u8 reserved_fsdct2[8]; /* 536-543 */

  u8 reserved_device_thresh[16]; /* 544-559 */

  /* 560-607 : Channel Thresholds (48 bytes)
   * Per-channel: TX bias, TX power, RX power alarms/warns */
  u16 rx_power_high_alarm; /* 560-561 (0.1 uW/LSB) */
  u16 rx_power_low_alarm;  /* 562-563 */
  u16 rx_power_high_warn;  /* 564-565 */
  u16 rx_power_low_warn;   /* 566-567 */

  u16 tx_bias_high_alarm; /* 568-569 (uA/LSB) */
  u16 tx_bias_low_alarm;  /* 570-571 */
  u16 tx_bias_high_warn;  /* 572-573 */
  u16 tx_bias_low_warn;	  /* 574-575 */

  u16 tx_power_high_alarm; /* 576-577 (0.1 uW/LSB) */
  u16 tx_power_low_alarm;  /* 578-579 */
  u16 tx_power_high_warn;  /* 580-581 */
  u16 tx_power_low_warn;   /* 582-583 */

  u8 reserved_ct[24]; /* 584-607 */

  /* 608-613 : TX EQ / RX Output / Temp Control (6 bytes) */
  u8 tx_eq_settings[4];	    /* 608-611 (per-channel EQ/emphasis) */
  u8 rx_output_settings;    /* 612 */
  u8 temp_control_settings; /* 613 */

  /* 614-625 : Channel Controls (12 bytes) */
  u8 channel_controls[12]; /* 614-625 (enable, polarity, squelch, etc.) */

  /* 626-635 : Channel Monitor Masks (10 bytes) */
  u8 channel_monitor_masks[10]; /* 626-635 (interrupt mask bits per
				    channel/parameter) */

  /* 636-639 : Reserved */
  u8 reserved_636_639[4]; /* 636-639 */
} sff8636_eeprom_t;

STATIC_ASSERT (sizeof (sff8636_eeprom_t) == 640, "sff8636_eeprom_t must be 640 bytes");

always_inline f64
sfp_sff_convert_temperature (u16 raw_temp)
{
  i16 temp = (i16) clib_net_to_host_u16 (raw_temp);
  return (f64) temp / 256.0;
}

always_inline f64
sfp_sff_convert_voltage (u16 raw_voltage)
{
  /* 100 uV per LSB */
  return (f64) clib_net_to_host_u16 (raw_voltage) / 10000.0;
}

always_inline f64
sfp_sff_convert_current (u16 raw_current)
{
  /* 2 uA per LSB */
  return (f64) clib_net_to_host_u16 (raw_current) * 2.0 / 1000.0;
}

always_inline f64
sfp_sff_convert_power (u16 raw_power)
{
  /* 0.1 uW per LSB */
  return (f64) clib_net_to_host_u16 (raw_power) / 10000.0;
}

always_inline f64
sfp_sff_mw_to_dbm (f64 power_mw)
{
  if (power_mw <= 0.0)
    return -40.0; /* use -40 dBm for zero/negative power to avoid log(0) */
  return 10.0 * log10 (power_mw);
}

always_inline uword
sff8636_transmitter_tech_is_copper (u8 device_tech)
{
  return (device_tech >> 4) >= 0xA;
}

format_function_t format_sfp_id;
format_function_t format_sfp_encoding;
format_function_t format_sfp_connector;
format_function_t format_sff8636_transmitter_tech;
format_function_t format_sff8472_compliance;
format_function_t format_sff8636_compliance;
format_function_t format_sff8472_diagnostics;
format_function_t format_sff8636_diagnostics;
format_function_t format_sfp_eeprom_base;
__clib_export format_function_t format_sfp_eeprom_module;
format_function_t format_sfp_eeprom_diagnostics;
