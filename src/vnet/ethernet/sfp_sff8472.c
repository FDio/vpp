/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco and/or its affiliates.
 */

#include <vlib/vlib.h>
#include <vppinfra/clib.h>
#include <vnet/ethernet/sfp.h>

u8 *
format_sff8472_compliance (u8 *s, va_list *args)
{
  u8 *c = va_arg (*args, u8 *);
  u8 first = 1;

#define _(byte, bit, name)                                                                         \
  if (c[byte] & (1 << (bit)))                                                                      \
    {                                                                                              \
      s = format (s, "%s%s", first ? "" : ", ", name);                                             \
      first = 0;                                                                                   \
    }
  foreach_sff8472_compliance
#undef _

    if (first) s = format (s, "none");

  return s;
}

static f64
sff8472_ieee754_to_f64 (u32 ieee754_be)
{
  union
  {
    u32 u;
    f32 f;
  } converter;
  converter.u = clib_net_to_host_u32 (ieee754_be);
  return (f64) converter.f;
}

static void
sff8472_apply_calibration (sff8472_diag_t *diag, f64 *temp, f64 *vcc,
			   f64 *tx_bias, f64 *tx_power, f64 *rx_power)
{
  f64 temp_slope, temp_offset;
  f64 vcc_slope, vcc_offset;
  f64 bias_slope, bias_offset;
  f64 txpwr_slope, txpwr_offset;
  f64 rx_raw;
  f64 rxpwr_cal[5];
  int i;

  /* Extract calibration constants */
  temp_slope = (f64) clib_net_to_host_u16 (diag->temp_slope) / 256.0;
  temp_offset = (f64) (i16) clib_net_to_host_u16 (diag->temp_offset);
  *temp = (*temp * temp_slope) + temp_offset;

  vcc_slope = (f64) clib_net_to_host_u16 (diag->voltage_slope) / 256.0;
  vcc_offset = (f64) (i16) clib_net_to_host_u16 (diag->voltage_offset);
  *vcc = (*vcc * vcc_slope) + vcc_offset;

  bias_slope = (f64) clib_net_to_host_u16 (diag->tx_bias_slope) / 256.0;
  bias_offset = (f64) (i16) clib_net_to_host_u16 (diag->tx_bias_offset);
  *tx_bias = (*tx_bias * bias_slope) + bias_offset;

  txpwr_slope = (f64) clib_net_to_host_u16 (diag->tx_power_slope) / 256.0;
  txpwr_offset = (f64) (i16) clib_net_to_host_u16 (diag->tx_power_offset);
  *tx_power = (*tx_power * txpwr_slope) + txpwr_offset;

  /* Apply polynomial calibration for RX Power
   * SFF-8472 section 9.3 External Calibration
   */
  for (i = 0; i < 5; i++)
    {
      rxpwr_cal[i] = sff8472_ieee754_to_f64 (diag->rx_power_cal[i]);
    }

  rx_raw = *rx_power;
  *rx_power = rxpwr_cal[0] + (rx_raw * rxpwr_cal[1]) +
	      (rx_raw * rx_raw * rxpwr_cal[2]) +
	      (rx_raw * rx_raw * rx_raw * rxpwr_cal[3]) +
	      (rx_raw * rx_raw * rx_raw * rx_raw * rxpwr_cal[4]);
}

u8 *
format_sff8472_diagnostics (u8 *s, va_list *args)
{
  vnet_interface_eeprom_t *eeprom = va_arg (*args, vnet_interface_eeprom_t *);
  u8 is_terse = va_arg (*args, u32);
  u32 indent = format_get_indent (s);
  f64 temp, vcc, tx_bias, tx_power, rx_power;
  f64 temp_high_alarm, temp_low_alarm, temp_high_warn, temp_low_warn;
  f64 vcc_high_alarm, vcc_low_alarm, vcc_high_warn, vcc_low_warn;
  f64 bias_high_alarm, bias_low_alarm, bias_high_warn, bias_low_warn;
  f64 tx_power_high_alarm, tx_power_low_alarm, tx_power_high_warn,
    tx_power_low_warn;
  f64 rx_power_high_alarm, rx_power_low_alarm, rx_power_high_warn,
    rx_power_low_warn;

  if (eeprom->eeprom_len <= 256)
    return format (s, "Not supported (no A2h data)");

  u8 *eeprom_data_a2 = eeprom->eeprom_raw;
  /* Check if we have A0h+A2h (512 bytes) */
  if (eeprom->eeprom_len >= 512)
    {
      eeprom_data_a2 = eeprom->eeprom_raw + 256; /* A2 starts at byte 256 */
    }

  sff8472_diag_t *diag = (sff8472_diag_t *) eeprom_data_a2;
  temp = sfp_sff_convert_temperature (diag->temperature);
  vcc = sfp_sff_convert_voltage (diag->vcc);
  tx_bias = sfp_sff_convert_current (diag->tx_bias);
  tx_power = sfp_sff_convert_power (diag->tx_power);
  rx_power = sfp_sff_convert_power (diag->rx_power);

  /* Check if external calibration is required (A0 page byte 92) */
  sff8472_diag_monitoring_type_t dmt = { .as_u8 = eeprom->eeprom_raw[92] };
  if (eeprom->eeprom_len >= 512 && dmt.externally_calibrated)
    {
      sff8472_apply_calibration (diag, &temp, &vcc, &tx_bias, &tx_power,
				 &rx_power);
    }

  s = format (s, "Current Values:");
  s = format_newline (s, indent + 2);
  s = format (s, "Temperature: %.2f °C", temp);
  s = format_newline (s, indent + 2);
  s = format (s, "Supply Voltage: %.4f V", vcc);
  s = format_newline (s, indent + 2);
  s = format (s, "TX Bias Current: %.2f mA", tx_bias);
  s = format_newline (s, indent + 2);
  s = format (s, "TX Average Power: %.4f mW (%.2f dBm)", tx_power, sfp_sff_mw_to_dbm (tx_power));
  s = format_newline (s, indent + 2);
  s = format (s, "RX Average Power: %.4f mW (%.2f dBm)", rx_power, sfp_sff_mw_to_dbm (rx_power));

  if (is_terse || eeprom->eeprom_len <= 256 + sizeof (sff8472_diag_t))
    return s;

  temp_high_alarm = sfp_sff_convert_temperature (diag->temp_high_alarm);
  temp_low_alarm = sfp_sff_convert_temperature (diag->temp_low_alarm);
  temp_high_warn = sfp_sff_convert_temperature (diag->temp_high_warning);
  temp_low_warn = sfp_sff_convert_temperature (diag->temp_low_warning);

  vcc_high_alarm = sfp_sff_convert_voltage (diag->voltage_high_alarm);
  vcc_low_alarm = sfp_sff_convert_voltage (diag->voltage_low_alarm);
  vcc_high_warn = sfp_sff_convert_voltage (diag->voltage_high_warning);
  vcc_low_warn = sfp_sff_convert_voltage (diag->voltage_low_warning);

  bias_high_alarm = sfp_sff_convert_current (diag->bias_high_alarm);
  bias_low_alarm = sfp_sff_convert_current (diag->bias_low_alarm);
  bias_high_warn = sfp_sff_convert_current (diag->bias_high_warning);
  bias_low_warn = sfp_sff_convert_current (diag->bias_low_warning);

  tx_power_high_alarm = sfp_sff_convert_power (diag->tx_power_high_alarm);
  tx_power_low_alarm = sfp_sff_convert_power (diag->tx_power_low_alarm);
  tx_power_high_warn = sfp_sff_convert_power (diag->tx_power_high_warning);
  tx_power_low_warn = sfp_sff_convert_power (diag->tx_power_low_warning);

  rx_power_high_alarm = sfp_sff_convert_power (diag->rx_power_high_alarm);
  rx_power_low_alarm = sfp_sff_convert_power (diag->rx_power_low_alarm);
  rx_power_high_warn = sfp_sff_convert_power (diag->rx_power_high_warning);
  rx_power_low_warn = sfp_sff_convert_power (diag->rx_power_low_warning);

  s = format_newline (s, indent);
  s = format (s, "Alarm Thresholds:");
  s = format_newline (s, indent + 2);
  s = format (s, "Temperature High: %.2f °C, Low: %.2f °C", temp_high_alarm, temp_low_alarm);
  s = format_newline (s, indent + 2);
  s = format (s, "Voltage High: %.4f V, Low: %.4f V", vcc_high_alarm, vcc_low_alarm);
  s = format_newline (s, indent + 2);
  s = format (s, "Bias Current High: %.2f mA, Low: %.2f mA", bias_high_alarm, bias_low_alarm);
  s = format_newline (s, indent + 2);
  s = format (s, "TX Power High: %.4f mW (%.2f dBm), Low: %.4f mW (%.2f dBm)", tx_power_high_alarm,
	      sfp_sff_mw_to_dbm (tx_power_high_alarm), tx_power_low_alarm,
	      sfp_sff_mw_to_dbm (tx_power_low_alarm));
  s = format_newline (s, indent + 2);
  s = format (s, "RX Power High: %.4f mW (%.2f dBm), Low: %.4f mW (%.2f dBm)", rx_power_high_alarm,
	      sfp_sff_mw_to_dbm (rx_power_high_alarm), rx_power_low_alarm,
	      sfp_sff_mw_to_dbm (rx_power_low_alarm));

  s = format_newline (s, indent);
  s = format (s, "Warning Thresholds:");
  s = format_newline (s, indent + 2);
  s = format (s, "Temperature High: %.2f °C, Low: %.2f °C", temp_high_warn, temp_low_warn);
  s = format_newline (s, indent + 2);
  s = format (s, "Voltage High: %.4f V, Low: %.4f V", vcc_high_warn, vcc_low_warn);
  s = format_newline (s, indent + 2);
  s = format (s, "Bias Current High: %.2f mA, Low: %.2f mA", bias_high_warn, bias_low_warn);
  s = format_newline (s, indent + 2);
  s = format (s, "TX Power High: %.4f mW (%.2f dBm), Low: %.4f mW (%.2f dBm)", tx_power_high_warn,
	      sfp_sff_mw_to_dbm (tx_power_high_warn), tx_power_low_warn,
	      sfp_sff_mw_to_dbm (tx_power_low_warn));
  s = format_newline (s, indent + 2);
  s = format (s, "RX Power High: %.4f mW (%.2f dBm), Low: %.4f mW (%.2f dBm)", rx_power_high_warn,
	      sfp_sff_mw_to_dbm (rx_power_high_warn), rx_power_low_warn,
	      sfp_sff_mw_to_dbm (rx_power_low_warn));

  return s;
}
