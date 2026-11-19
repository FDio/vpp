/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco and/or its affiliates.
 */

#include <vlib/vlib.h>
#include <vppinfra/clib.h>
#include <vnet/interface.h>
#include <vnet/ethernet/sfp.h>

u8 *
format_sff8636_transmitter_tech (u8 *s, va_list *args)
{
  u32 tech = va_arg (*args, u32);
  char *t = 0;
  switch (tech)
    {
#define _(v, str)                                                                                  \
  case v:                                                                                          \
    t = str;                                                                                       \
    break;
      foreach_sff8636_transmitter_tech
#undef _
	default : return format (s, "unknown 0x%x", tech);
    }
  return format (s, "%s", t);
}

u8 *
format_sff8636_compliance (u8 *s, va_list *args)
{
  u8 *c = va_arg (*args, u8 *);
  u8 first = 1;

#define _(byte, bit, name)                                                                         \
  if (c[byte] & (1 << (bit)))                                                                      \
    {                                                                                              \
      s = format (s, "%s%s", first ? "" : ", ", name);                                             \
      first = 0;                                                                                   \
    }
  foreach_sff8636_compliance
#undef _

    if (first) s = format (s, "none");

  return s;
}

void
styled_format_sff8636_diagnostics (styled_text_t *st, va_list *args)
{
  vnet_interface_eeprom_t *eeprom = va_arg (*args, vnet_interface_eeprom_t *);
  u8 is_terse = va_arg (*args, u32);
  f64 temp, vcc;
  f64 temp_high_alarm, temp_low_alarm, temp_high_warn, temp_low_warn;
  f64 vcc_high_alarm, vcc_low_alarm, vcc_high_warn, vcc_low_warn;
  int i;

  /* current values live in the lower page (bytes 0-127), which is always
   * read regardless of page support - only the alarm/warning thresholds
   * below need the full upper-page 03h dump */
  if (eeprom->eeprom_len < STRUCT_OFFSET_OF (sff8636_eeprom_t, reserved_lane))
    {
      styled_text_add (st, "Not supported (insufficient data)");
      return;
    }

  sff8636_eeprom_t *diag = (sff8636_eeprom_t *) eeprom->eeprom_raw;

  if (eeprom->eeprom_len >= STRUCT_OFFSET_OF (sff8636_eeprom_t, reserved_page01))
    {
      sfp_eeprom_t *base = (sfp_eeprom_t *) diag->base_id;
      u8 tech = base->device_tech >> 4;
      u8 has_monitors = diag->temperature != 0 || diag->vcc != 0;

      /* Passive cables may omit the optional diagnostic monitors. */
      if (tech == 0xA || tech == 0xB)
	{
	  for (u32 lane = 0; lane < 4; lane++)
	    has_monitors |=
	      diag->tx_bias[lane] != 0 || diag->tx_power[lane] != 0 || diag->rx_power[lane] != 0;
	  if (!has_monitors)
	    {
	      styled_text_add (st, "Not supported (passive copper cable)");
	      return;
	    }
	}
    }

  temp = sfp_sff_convert_temperature (diag->temperature);
  vcc = sfp_sff_convert_voltage (diag->vcc);

  styled_text_add (st, "Current Values:");
  styled_sfp_add_value (st, 2, "Temperature", format_sfp_temperature, temp);
  styled_sfp_add_value (st, 2, "Supply Voltage", format_sfp_voltage, vcc);

  /* Per-lane values */
  for (i = 0; i < 4; i++)
    {
      f64 tx_bias, tx_power, rx_power;
      tx_bias = sfp_sff_convert_current (diag->tx_bias[i]);
      rx_power = sfp_sff_convert_power (diag->rx_power[i]);
      tx_power = sfp_sff_convert_power (diag->tx_power[i]);

      styled_text_add (st, "\n  Lane %d:", i + 1);
      styled_sfp_add_value (st, 4, "TX Bias Current", format_sfp_current, tx_bias);
      styled_sfp_add_value (st, 4, "TX Average Power", format_sfp_power, tx_power);
      styled_sfp_add_value (st, 4, "RX Average Power", format_sfp_power, rx_power);
    }

  if (is_terse)
    return;

  if (eeprom->eeprom_len < sizeof (sff8636_eeprom_t))
    {
      styled_text_add (
	st, "\nAlarm/Warning Thresholds: not available (module does not support upper page "
	    "03h)");
      return;
    }

  /* Temperature thresholds at bytes 512-519 */
  temp_high_alarm = sfp_sff_convert_temperature (diag->temp_high_alarm);
  temp_low_alarm = sfp_sff_convert_temperature (diag->temp_low_alarm);
  temp_high_warn = sfp_sff_convert_temperature (diag->temp_high_warn);
  temp_low_warn = sfp_sff_convert_temperature (diag->temp_low_warn);

  /* Voltage thresholds at bytes 520-527 */
  vcc_high_alarm = sfp_sff_convert_voltage (diag->vcc_high_alarm);
  vcc_low_alarm = sfp_sff_convert_voltage (diag->vcc_low_alarm);
  vcc_high_warn = sfp_sff_convert_voltage (diag->vcc_high_warn);
  vcc_low_warn = sfp_sff_convert_voltage (diag->vcc_low_warn);

  styled_text_add (st, "\nAlarm Thresholds:");
  styled_sfp_add_range (st, 2, "Temperature", format_sfp_temperature, temp_high_alarm,
			temp_low_alarm);
  styled_sfp_add_range (st, 2, "Voltage", format_sfp_voltage, vcc_high_alarm, vcc_low_alarm);
  styled_sfp_add_range (st, 2, "Bias Current", format_sfp_current,
			sfp_sff_convert_current (diag->tx_bias_high_alarm),
			sfp_sff_convert_current (diag->tx_bias_low_alarm));
  styled_sfp_add_range (st, 2, "TX Power", format_sfp_power,
			sfp_sff_convert_power (diag->tx_power_high_alarm),
			sfp_sff_convert_power (diag->tx_power_low_alarm));
  styled_sfp_add_range (st, 2, "RX Power", format_sfp_power,
			sfp_sff_convert_power (diag->rx_power_high_alarm),
			sfp_sff_convert_power (diag->rx_power_low_alarm));

  styled_text_add (st, "\nWarning Thresholds:");
  styled_sfp_add_range (st, 2, "Temperature", format_sfp_temperature, temp_high_warn,
			temp_low_warn);
  styled_sfp_add_range (st, 2, "Voltage", format_sfp_voltage, vcc_high_warn, vcc_low_warn);
  styled_sfp_add_range (st, 2, "RX Power", format_sfp_power,
			sfp_sff_convert_power (diag->rx_power_high_warn),
			sfp_sff_convert_power (diag->rx_power_low_warn));
}
