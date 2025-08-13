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

#include <math.h>
#include <vlib/vlib.h>
#include <vppinfra/clib.h>
#include <dpdk/device/sff8472.h>

static inline u16
sff8472_read_u16 (u8 *data)
{
  return (data[0] << 8) | data[1];
}

static inline i16
sff8472_read_s16 (u8 *data)
{
  return (i16) ((data[0] << 8) | data[1]);
}

static f64
sff8472_convert_temperature (u8 *data)
{
  i16 temp = sff8472_read_s16 (data);
  return (f64) temp / 256.0;
}

static f64
sff8472_convert_voltage (u8 *data)
{
  u16 voltage = sff8472_read_u16 (data);
  return (f64) voltage / 10000.0;
}

static f64
sff8472_convert_current (u8 *data)
{
  u16 current = sff8472_read_u16 (data);
  return (f64) current * 2.0 / 1000.0;
}

static f64
sff8472_convert_power (u8 *data)
{
  u16 power = sff8472_read_u16 (data);
  return (f64) power / 10000.0;
}

static f64
sff8472_mw_to_dbm (f64 power_mw)
{
  if (power_mw <= 0.0)
    return -40.0; /* Use -40 dBm for zero/negative power to avoid log(0) */
  return 10.0 * log10 (power_mw);
}

void
sff8472_decode_sfp_eeprom (vlib_main_t *vm, sfp_eeprom_t *se, u8 is_terse)
{
  u8 vendor_name[17] = { 0 };
  u8 vendor_pn[17] = { 0 };
  u8 vendor_rev[3] = { 0 };
  u8 vendor_sn[17] = { 0 };
  u8 date_code[9] = { 0 };
  u16 wavelength;

  if (!se)
    {
      vlib_cli_output (vm, "  Warning: No SFP EEPROM data provided");
      return;
    }

  vlib_cli_output (vm, "  SFF-8472 Module Information:");
  if (!is_terse)
    {
      vlib_cli_output (vm, "    Identifier: 0x%02x (%U)", se->id,
		       format_sfp_id, se->id);
      vlib_cli_output (vm, "    Extended Identifier: 0x%02x", se->extended_id);
      vlib_cli_output (vm, "    Connector: 0x%02x (%U)", se->connector_type,
		       format_sfp_connector, se->connector_type);
      vlib_cli_output (vm, "    Encoding: 0x%02x (%U)", se->encoding,
		       format_sfp_encoding, se->encoding);
      vlib_cli_output (vm, "    Nominal Bit Rate: %u00 Mbps",
		       se->nominal_bit_rate_100mbits_per_sec);

      /* Length information */
      if (se->length[0])
	vlib_cli_output (vm, "    Length (SMF): %u km", se->length[0]);
      if (se->length[1])
	vlib_cli_output (vm, "    Length (SMF): %u00 m", se->length[1]);
      if (se->length[2])
	vlib_cli_output (vm, "    Length (OM2 50um): %u0 m", se->length[2]);
      if (se->length[3])
	vlib_cli_output (vm, "    Length (OM1 62.5um): %u0 m", se->length[3]);
      if (se->length[4])
	vlib_cli_output (vm, "    Length (Copper/OM3): %u m", se->length[4]);
    }

  /* Vendor information */
  clib_memcpy (vendor_name, se->vendor_name, 16);
  /* Trim trailing spaces */
  for (int i = 15; i >= 0 && vendor_name[i] == ' '; i--)
    vendor_name[i] = '\0';
  vlib_cli_output (vm, "    Vendor Name: %s", vendor_name);

  vlib_cli_output (vm, "    Vendor OUI: %02x:%02x:%02x", se->vendor_oui[0],
		   se->vendor_oui[1], se->vendor_oui[2]);

  clib_memcpy (vendor_pn, se->vendor_part_number, 16);
  /* Trim trailing spaces */
  for (int i = 15; i >= 0 && vendor_pn[i] == ' '; i--)
    vendor_pn[i] = '\0';
  vlib_cli_output (vm, "    Vendor Part Number: %s", vendor_pn);

  clib_memcpy (vendor_sn, se->vendor_serial_number, 16);
  /* Trim trailing spaces */
  for (int i = 15; i >= 0 && vendor_sn[i] == ' '; i--)
    vendor_sn[i] = '\0';
  vlib_cli_output (vm, "    Vendor Serial Number: %s", vendor_sn);

  if (!is_terse)
    {
      clib_memcpy (vendor_rev, se->vendor_revision, 2);
      /* Trim trailing spaces */
      for (int i = 1; i >= 0 && vendor_rev[i] == ' '; i--)
	vendor_rev[i] = '\0';
      vlib_cli_output (vm, "    Vendor Revision: %s", vendor_rev);

      /* Wavelength */
      wavelength = sff8472_read_u16 (se->wavelength_or_att);
      if (wavelength)
	vlib_cli_output (vm, "    Wavelength: %u nm", wavelength);

      clib_memcpy (date_code, se->vendor_date_code, 8);
      vlib_cli_output (vm, "    Date Code: %.8s", date_code);

      /* Options and compliance */
      vlib_cli_output (vm, "    Link Codes: 0x%02x", se->link_codes);
      vlib_cli_output (vm, "    Options: 0x%02x%02x%02x", se->options[0],
		       se->options[1], se->options[2]);
    }
}

void
sff8472_decode_diagnostics (vlib_main_t *vm, u8 *eeprom_data, u32 length,
			    u8 is_terse)
{
  f64 temp, vcc, tx_bias, tx_power, rx_power;
  f64 temp_high_alarm, temp_low_alarm, temp_high_warn, temp_low_warn;
  f64 vcc_high_alarm, vcc_low_alarm, vcc_high_warn, vcc_low_warn;
  f64 bias_high_alarm, bias_low_alarm, bias_high_warn, bias_low_warn;
  f64 tx_power_high_alarm, tx_power_low_alarm, tx_power_high_warn,
    tx_power_low_warn;
  f64 rx_power_high_alarm, rx_power_low_alarm, rx_power_high_warn,
    rx_power_low_warn;

  vlib_cli_output (vm, "");
  vlib_cli_output (vm, "  SFF-8472 Diagnostic Monitoring:");

  if (length <= 256)
    {
      vlib_cli_output (vm, "    Not supported (no A2h data)");
      return;
    }

  u8 *eeprom_data_a2 = eeprom_data;
  /* Check if we have A0h+A2h (512 bytes) */
  if (length >= 512)
    {
      eeprom_data_a2 = eeprom_data + 256; /* A2 starts at byte 256 */
    }

  sff8472_diag_t *diag = (sff8472_diag_t *) eeprom_data_a2;
  temp = sff8472_convert_temperature (diag->temperature);
  vcc = sff8472_convert_voltage (diag->vcc);
  tx_bias = sff8472_convert_current (diag->tx_bias);
  tx_power = sff8472_convert_power (diag->tx_power);
  rx_power = sff8472_convert_power (diag->rx_power);

  vlib_cli_output (vm, "    Current Values:");
  vlib_cli_output (vm, "      Temperature: %.2f °C", temp);
  vlib_cli_output (vm, "      Supply Voltage: %.4f V", vcc);
  vlib_cli_output (vm, "      TX Bias Current: %.2f mA", tx_bias);
  vlib_cli_output (vm, "      TX Average Power: %.4f mW (%.2f dBm)", tx_power,
		   sff8472_mw_to_dbm (tx_power));
  vlib_cli_output (vm, "      RX Average Power: %.4f mW (%.2f dBm)", rx_power,
		   sff8472_mw_to_dbm (rx_power));

  if (is_terse || length <= 256 + sizeof (sff8472_diag_t))
    {
      return;
    }

  temp_high_alarm = sff8472_convert_temperature (diag->temp_high_alarm);
  temp_low_alarm = sff8472_convert_temperature (diag->temp_low_alarm);
  temp_high_warn = sff8472_convert_temperature (diag->temp_high_warning);
  temp_low_warn = sff8472_convert_temperature (diag->temp_low_warning);

  vcc_high_alarm = sff8472_convert_voltage (diag->voltage_high_alarm);
  vcc_low_alarm = sff8472_convert_voltage (diag->voltage_low_alarm);
  vcc_high_warn = sff8472_convert_voltage (diag->voltage_high_warning);
  vcc_low_warn = sff8472_convert_voltage (diag->voltage_low_warning);

  bias_high_alarm = sff8472_convert_current (diag->bias_high_alarm);
  bias_low_alarm = sff8472_convert_current (diag->bias_low_alarm);
  bias_high_warn = sff8472_convert_current (diag->bias_high_warning);
  bias_low_warn = sff8472_convert_current (diag->bias_low_warning);

  tx_power_high_alarm = sff8472_convert_power (diag->tx_power_high_alarm);
  tx_power_low_alarm = sff8472_convert_power (diag->tx_power_low_alarm);
  tx_power_high_warn = sff8472_convert_power (diag->tx_power_high_warning);
  tx_power_low_warn = sff8472_convert_power (diag->tx_power_low_warning);

  rx_power_high_alarm = sff8472_convert_power (diag->rx_power_high_alarm);
  rx_power_low_alarm = sff8472_convert_power (diag->rx_power_low_alarm);
  rx_power_high_warn = sff8472_convert_power (diag->rx_power_high_warning);
  rx_power_low_warn = sff8472_convert_power (diag->rx_power_low_warning);

  vlib_cli_output (vm, "");
  vlib_cli_output (vm, "    Alarm Thresholds:");
  vlib_cli_output (vm, "      Temperature High: %.2f °C, Low: %.2f °C",
		   temp_high_alarm, temp_low_alarm);
  vlib_cli_output (vm, "      Voltage High: %.4f V, Low: %.4f V",
		   vcc_high_alarm, vcc_low_alarm);
  vlib_cli_output (vm, "      Bias Current High: %.2f mA, Low: %.2f mA",
		   bias_high_alarm, bias_low_alarm);
  vlib_cli_output (
    vm, "      TX Power High: %.4f mW (%.2f dBm), Low: %.4f mW (%.2f dBm)",
    tx_power_high_alarm, sff8472_mw_to_dbm (tx_power_high_alarm),
    tx_power_low_alarm, sff8472_mw_to_dbm (tx_power_low_alarm));
  vlib_cli_output (
    vm, "      RX Power High: %.4f mW (%.2f dBm), Low: %.4f mW (%.2f dBm)",
    rx_power_high_alarm, sff8472_mw_to_dbm (rx_power_high_alarm),
    rx_power_low_alarm, sff8472_mw_to_dbm (rx_power_low_alarm));

  vlib_cli_output (vm, "");
  vlib_cli_output (vm, "    Warning Thresholds:");
  vlib_cli_output (vm, "      Temperature High: %.2f °C, Low: %.2f °C",
		   temp_high_warn, temp_low_warn);
  vlib_cli_output (vm, "      Voltage High: %.4f V, Low: %.4f V",
		   vcc_high_warn, vcc_low_warn);
  vlib_cli_output (vm, "      Bias Current High: %.2f mA, Low: %.2f mA",
		   bias_high_warn, bias_low_warn);
  vlib_cli_output (
    vm, "      TX Power High: %.4f mW (%.2f dBm), Low: %.4f mW (%.2f dBm)",
    tx_power_high_warn, sff8472_mw_to_dbm (tx_power_high_warn),
    tx_power_low_warn, sff8472_mw_to_dbm (tx_power_low_warn));
  vlib_cli_output (
    vm, "      RX Power High: %.4f mW (%.2f dBm), Low: %.4f mW (%.2f dBm)",
    rx_power_high_warn, sff8472_mw_to_dbm (rx_power_high_warn),
    rx_power_low_warn, sff8472_mw_to_dbm (rx_power_low_warn));
}
