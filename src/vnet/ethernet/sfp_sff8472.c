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

void
styled_format_sff8472_diagnostics (styled_text_t *st, va_list *args)
{
  vnet_interface_eeprom_t *eeprom = va_arg (*args, vnet_interface_eeprom_t *);
  u8 is_terse = va_arg (*args, u32);
  f64 temp, vcc, tx_bias, tx_power, rx_power;
  f64 temp_high_alarm, temp_low_alarm, temp_high_warn, temp_low_warn;
  f64 vcc_high_alarm, vcc_low_alarm, vcc_high_warn, vcc_low_warn;
  f64 bias_high_alarm, bias_low_alarm, bias_high_warn, bias_low_warn;
  f64 tx_power_high_alarm, tx_power_low_alarm, tx_power_high_warn,
    tx_power_low_warn;
  f64 rx_power_high_alarm, rx_power_low_alarm, rx_power_high_warn,
    rx_power_low_warn;

  if (eeprom->eeprom_len <= 256)
    {
      styled_text_add (st, "Not supported (no A2h data)");
      return;
    }

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

  styled_text_add (st, "Current Values:");
  styled_sfp_add_value (st, 2, "Temperature", format_sfp_temperature, temp);
  styled_sfp_add_value (st, 2, "Supply Voltage", format_sfp_voltage, vcc);
  styled_sfp_add_value (st, 2, "TX Bias Current", format_sfp_current, tx_bias);
  styled_sfp_add_value (st, 2, "TX Average Power", format_sfp_power, tx_power);
  styled_sfp_add_value (st, 2, "RX Average Power", format_sfp_power, rx_power);

  if (is_terse || eeprom->eeprom_len <= 256 + sizeof (sff8472_diag_t))
    return;

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

  styled_text_add (st, "\nAlarm Thresholds:");
  styled_sfp_add_range (st, 2, "Temperature", format_sfp_temperature, temp_high_alarm,
			temp_low_alarm);
  styled_sfp_add_range (st, 2, "Voltage", format_sfp_voltage, vcc_high_alarm, vcc_low_alarm);
  styled_sfp_add_range (st, 2, "Bias Current", format_sfp_current, bias_high_alarm, bias_low_alarm);
  styled_sfp_add_range (st, 2, "TX Power", format_sfp_power, tx_power_high_alarm,
			tx_power_low_alarm);
  styled_sfp_add_range (st, 2, "RX Power", format_sfp_power, rx_power_high_alarm,
			rx_power_low_alarm);

  styled_text_add (st, "\nWarning Thresholds:");
  styled_sfp_add_range (st, 2, "Temperature", format_sfp_temperature, temp_high_warn,
			temp_low_warn);
  styled_sfp_add_range (st, 2, "Voltage", format_sfp_voltage, vcc_high_warn, vcc_low_warn);
  styled_sfp_add_range (st, 2, "Bias Current", format_sfp_current, bias_high_warn, bias_low_warn);
  styled_sfp_add_range (st, 2, "TX Power", format_sfp_power, tx_power_high_warn, tx_power_low_warn);
  styled_sfp_add_range (st, 2, "RX Power", format_sfp_power, rx_power_high_warn, rx_power_low_warn);
}
