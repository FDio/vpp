/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco and/or its affiliates.
 */

#include <math.h>
#include <vlib/vlib.h>
#include <vppinfra/clib.h>
#include <vnet/interface.h>
#include <vnet/ethernet/sfp_sff8636.h>

static f64
sff8636_convert_temperature (u16 raw_temp)
{
  i16 temp = (i16) raw_temp;
  return (f64) temp / 256.0;
}

static f64
sff8636_convert_voltage (u16 raw_voltage)
{
  /* SFF-8636: 100 µV per LSB */
  return (f64) raw_voltage / 10000.0;
}

static f64
sff8636_convert_current (u16 raw_current)
{
  /* SFF-8636: 2 µA per LSB */
  return (f64) raw_current * 2.0 / 1000.0;
}

static f64
sff8636_convert_power (u16 raw_power)
{
  /* SFF-8636: 0.1 µW per LSB */
  return (f64) raw_power * 0.1 / 1000.0;
}

static f64
sff8636_mw_to_dbm (f64 power_mw)
{
  if (power_mw <= 0.0)
    return -40.0; /* Use -40 dBm for zero/negative power to avoid log(0) */
  return 10.0 * log10 (power_mw);
}

void
sff8636_decode_diagnostics (vlib_main_t *vm, vnet_interface_eeprom_t *eeprom,
			    u8 is_terse)
{
  f64 temp, vcc;
  f64 temp_high_alarm, temp_low_alarm, temp_high_warn, temp_low_warn;
  f64 vcc_high_alarm, vcc_low_alarm, vcc_high_warn, vcc_low_warn;
  int i;

  vlib_cli_output (vm, "  Module Diagnostics:");

  if (eeprom->eeprom_len < sizeof (sff8636_eeprom_t))
    {
      vlib_cli_output (vm, "    Not supported (insufficient data)");
      return;
    }

  sff8636_eeprom_t *diag = (sff8636_eeprom_t *) eeprom->eeprom_raw;
  temp =
    sff8636_convert_temperature (clib_net_to_host_u16 (diag->temperature));
  vcc = sff8636_convert_voltage (clib_net_to_host_u16 (diag->vcc));

  vlib_cli_output (vm, "    Current Values:");
  vlib_cli_output (vm, "      Temperature: %.2f °C", temp);
  vlib_cli_output (vm, "      Supply Voltage: %.4f V", vcc);

  /* Per-lane values */
  for (i = 0; i < 4; i++)
    {
      f64 tx_bias, tx_power, rx_power;
      tx_bias =
	sff8636_convert_current (clib_net_to_host_u16 (diag->tx_bias[i]));
      rx_power =
	sff8636_convert_power (clib_net_to_host_u16 (diag->rx_power[i]));
      tx_power =
	sff8636_convert_power (clib_net_to_host_u16 (diag->tx_power[i]));

      vlib_cli_output (vm, "      Lane %d:", i + 1);
      vlib_cli_output (vm, "        TX Bias Current: %.2f mA", tx_bias);
      vlib_cli_output (vm, "        TX Average Power: %.4f mW (%.2f dBm)",
		       tx_power, sff8636_mw_to_dbm (tx_power));
      vlib_cli_output (vm, "        RX Average Power: %.4f mW (%.2f dBm)",
		       rx_power, sff8636_mw_to_dbm (rx_power));
    }

  if (is_terse)
    {
      return;
    }

  /* Temperature thresholds at bytes 512-519 */
  temp_high_alarm =
    sff8636_convert_temperature (clib_net_to_host_u16 (diag->temp_high_alarm));
  temp_low_alarm =
    sff8636_convert_temperature (clib_net_to_host_u16 (diag->temp_low_alarm));
  temp_high_warn =
    sff8636_convert_temperature (clib_net_to_host_u16 (diag->temp_high_warn));
  temp_low_warn =
    sff8636_convert_temperature (clib_net_to_host_u16 (diag->temp_low_warn));

  /* Voltage thresholds at bytes 520-527 */
  vcc_high_alarm =
    sff8636_convert_voltage (clib_net_to_host_u16 (diag->vcc_high_alarm));
  vcc_low_alarm =
    sff8636_convert_voltage (clib_net_to_host_u16 (diag->vcc_low_alarm));
  vcc_high_warn =
    sff8636_convert_voltage (clib_net_to_host_u16 (diag->vcc_high_warn));
  vcc_low_warn =
    sff8636_convert_voltage (clib_net_to_host_u16 (diag->vcc_low_warn));

  vlib_cli_output (vm, "");
  vlib_cli_output (vm, "    Alarm Thresholds:");
  vlib_cli_output (vm, "      Temperature High: %.2f °C, Low: %.2f °C",
		   temp_high_alarm, temp_low_alarm);
  vlib_cli_output (vm, "      Voltage High: %.4f V, Low: %.4f V",
		   vcc_high_alarm, vcc_low_alarm);

  vlib_cli_output (
    vm, "      Bias Current High: %.2f mA, Low: %.2f mA",
    sff8636_convert_current (clib_net_to_host_u16 (diag->tx_bias_high_alarm)),
    sff8636_convert_current (clib_net_to_host_u16 (diag->tx_bias_low_alarm)));
  vlib_cli_output (
    vm,
    "      TX Power High: %.4f mW (%.2f dBm), Low: "
    "%.4f mW (%.2f dBm)",
    sff8636_convert_power (clib_net_to_host_u16 (diag->tx_power_high_alarm)),
    sff8636_mw_to_dbm (sff8636_convert_power (
      clib_net_to_host_u16 (diag->tx_power_high_alarm))),
    sff8636_convert_power (clib_net_to_host_u16 (diag->tx_power_low_alarm)),
    sff8636_mw_to_dbm (sff8636_convert_power (
      clib_net_to_host_u16 (diag->tx_power_low_alarm))));
  vlib_cli_output (
    vm,
    "      RX Power High: %.4f mW (%.2f dBm), Low: "
    "%.4f mW (%.2f dBm)",
    sff8636_convert_power (clib_net_to_host_u16 (diag->rx_power_high_alarm)),
    sff8636_mw_to_dbm (sff8636_convert_power (
      clib_net_to_host_u16 (diag->rx_power_high_alarm))),
    sff8636_convert_power (clib_net_to_host_u16 (diag->rx_power_low_alarm)),
    sff8636_mw_to_dbm (sff8636_convert_power (
      clib_net_to_host_u16 (diag->rx_power_low_alarm))));

  vlib_cli_output (vm, "");
  vlib_cli_output (vm, "    Warning Thresholds:");
  vlib_cli_output (vm, "      Temperature High: %.2f °C, Low: %.2f °C",
		   temp_high_warn, temp_low_warn);
  vlib_cli_output (vm, "      Voltage High: %.4f V, Low: %.4f V",
		   vcc_high_warn, vcc_low_warn);
  vlib_cli_output (
    vm,
    "      RX Power High: %.4f mW (%.2f dBm), Low: "
    "%.4f mW (%.2f dBm)",
    sff8636_convert_power (clib_net_to_host_u16 (diag->rx_power_high_warn)),
    sff8636_mw_to_dbm (
      sff8636_convert_power (clib_net_to_host_u16 (diag->rx_power_high_warn))),
    sff8636_convert_power (clib_net_to_host_u16 (diag->rx_power_low_warn)),
    sff8636_mw_to_dbm (
      sff8636_convert_power (clib_net_to_host_u16 (diag->rx_power_low_warn))));
}
