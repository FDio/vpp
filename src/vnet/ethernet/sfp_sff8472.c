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
#include <vnet/ethernet/sfp_sff8472.h>

static f64
sff8472_convert_temperature (u16 raw_temp)
{
  i16 temp = (i16) raw_temp;
  return (f64) temp / 256.0;
}

static f64
sff8472_convert_voltage (u16 raw_voltage)
{
  return (f64) raw_voltage / 10000.0;
}

static f64
sff8472_convert_current (u16 raw_current)
{
  return (f64) raw_current * 2.0 / 1000.0;
}

static f64
sff8472_convert_power (u16 raw_power)
{
  return (f64) raw_power / 10000.0;
}

static f64
sff8472_mw_to_dbm (f64 power_mw)
{
  if (power_mw <= 0.0)
    return -40.0; /* Use -40 dBm for zero/negative power to avoid log(0) */
  return 10.0 * log10 (power_mw);
}

void
sff8472_decode_diagnostics (vlib_main_t *vm, vnet_interface_eeprom_t *eeprom,
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

  vlib_cli_output (vm, "  Module Diagnostics:");
  if (eeprom->eeprom_len <= 256)
    {
      vlib_cli_output (vm, "    Not supported (no A2h data)");
      return;
    }

  u8 *eeprom_data_a2 = eeprom->eeprom_raw;
  /* Check if we have A0h+A2h (512 bytes) */
  if (eeprom->eeprom_len >= 512)
    {
      eeprom_data_a2 = eeprom->eeprom_raw + 256; /* A2 starts at byte 256 */
    }

  sff8472_diag_t *diag = (sff8472_diag_t *) eeprom_data_a2;
  temp =
    sff8472_convert_temperature (clib_net_to_host_u16 (diag->temperature));
  vcc = sff8472_convert_voltage (clib_net_to_host_u16 (diag->vcc));
  tx_bias = sff8472_convert_current (clib_net_to_host_u16 (diag->tx_bias));
  tx_power = sff8472_convert_power (clib_net_to_host_u16 (diag->tx_power));
  rx_power = sff8472_convert_power (clib_net_to_host_u16 (diag->rx_power));

  vlib_cli_output (vm, "    Current Values:");
  vlib_cli_output (vm, "      Temperature: %.2f °C", temp);
  vlib_cli_output (vm, "      Supply Voltage: %.4f V", vcc);
  vlib_cli_output (vm, "      TX Bias Current: %.2f mA", tx_bias);
  vlib_cli_output (vm, "      TX Average Power: %.4f mW (%.2f dBm)", tx_power,
		   sff8472_mw_to_dbm (tx_power));
  vlib_cli_output (vm, "      RX Average Power: %.4f mW (%.2f dBm)", rx_power,
		   sff8472_mw_to_dbm (rx_power));

  if (is_terse || eeprom->eeprom_len <= 256 + sizeof (sff8472_diag_t))
    {
      return;
    }

  temp_high_alarm =
    sff8472_convert_temperature (clib_net_to_host_u16 (diag->temp_high_alarm));
  temp_low_alarm =
    sff8472_convert_temperature (clib_net_to_host_u16 (diag->temp_low_alarm));
  temp_high_warn = sff8472_convert_temperature (
    clib_net_to_host_u16 (diag->temp_high_warning));
  temp_low_warn = sff8472_convert_temperature (
    clib_net_to_host_u16 (diag->temp_low_warning));

  vcc_high_alarm =
    sff8472_convert_voltage (clib_net_to_host_u16 (diag->voltage_high_alarm));
  vcc_low_alarm =
    sff8472_convert_voltage (clib_net_to_host_u16 (diag->voltage_low_alarm));
  vcc_high_warn = sff8472_convert_voltage (
    clib_net_to_host_u16 (diag->voltage_high_warning));
  vcc_low_warn =
    sff8472_convert_voltage (clib_net_to_host_u16 (diag->voltage_low_warning));

  bias_high_alarm =
    sff8472_convert_current (clib_net_to_host_u16 (diag->bias_high_alarm));
  bias_low_alarm =
    sff8472_convert_current (clib_net_to_host_u16 (diag->bias_low_alarm));
  bias_high_warn =
    sff8472_convert_current (clib_net_to_host_u16 (diag->bias_high_warning));
  bias_low_warn =
    sff8472_convert_current (clib_net_to_host_u16 (diag->bias_low_warning));

  tx_power_high_alarm =
    sff8472_convert_power (clib_net_to_host_u16 (diag->tx_power_high_alarm));
  tx_power_low_alarm =
    sff8472_convert_power (clib_net_to_host_u16 (diag->tx_power_low_alarm));
  tx_power_high_warn =
    sff8472_convert_power (clib_net_to_host_u16 (diag->tx_power_high_warning));
  tx_power_low_warn =
    sff8472_convert_power (clib_net_to_host_u16 (diag->tx_power_low_warning));

  rx_power_high_alarm =
    sff8472_convert_power (clib_net_to_host_u16 (diag->rx_power_high_alarm));
  rx_power_low_alarm =
    sff8472_convert_power (clib_net_to_host_u16 (diag->rx_power_low_alarm));
  rx_power_high_warn =
    sff8472_convert_power (clib_net_to_host_u16 (diag->rx_power_high_warning));
  rx_power_low_warn =
    sff8472_convert_power (clib_net_to_host_u16 (diag->rx_power_low_warning));

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
