/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vppinfra/format_table.h>
#include <edma_hw.h>
#include <qppe.h>
#include <ppe_hw.h>

u8 *
format_qppe_mac_port_status (u8 *s, va_list *args)
{
  vnet_dev_port_t *port = va_arg (*args, vnet_dev_port_t *);
  qppe_port_t *qp = vnet_dev_get_port_data (port);
  ppe_reg_xgmac_tx_config_t xgmac_tx;
  ppe_reg_xgmac_rx_config_t xgmac_rx;
  ppe_reg_gmac_enable_t gmac_enable;
  u32 indent = format_get_indent (s);

  if (qp->is_xgmac)
    {
      xgmac_tx.as_u32 = qppe_xgmac_reg_rd (port, HPPE_XGMAC_REG_TX_CONFIG);
      xgmac_rx.as_u32 = qppe_xgmac_reg_rd (port, HPPE_XGMAC_REG_RX_CONFIG);
      s = format (s, "\n%UXGMAC TX config 0x%08x (speed %u, TX %s)", format_white_space, indent,
		  xgmac_tx.as_u32, xgmac_tx.speed, xgmac_tx.tx_enable ? "enabled" : "disabled");
      s = format (s, "\n%UXGMAC RX config 0x%08x (RX %s)", format_white_space, indent,
		  xgmac_rx.as_u32, xgmac_rx.rx_enable ? "enabled" : "disabled");
    }
  else
    {
      gmac_enable.as_u32 = qppe_gmac_reg_rd (port, HPPE_GMAC_REG_ENABLE);
      s = format (s, "\n%UGMAC enable 0x%08x (TX %s, RX %s)", format_white_space, indent,
		  gmac_enable.as_u32, gmac_enable.tx_enable ? "enabled" : "disabled",
		  gmac_enable.rx_enable ? "enabled" : "disabled");
    }

  return s;
}

static const qppe_reg_field_t ppe_reg_gmac_enable_t_fields[] = {
#define _(n_bits, name)                                                                            \
  {                                                                                                \
    #name,                                                                                         \
    n_bits,                                                                                        \
  },
  foreach_ppe_reg_gmac_enable_t_fields
#undef _
};

static const qppe_reg_field_t ppe_reg_gmac_speed_t_fields[] = {
#define _(n_bits, name)                                                                            \
  {                                                                                                \
    #name,                                                                                         \
    n_bits,                                                                                        \
  },
  foreach_ppe_reg_gmac_speed_t_fields
#undef _
};

static const qppe_reg_field_t ppe_reg_xgmac_tx_config_t_fields[] = {
#define _(n_bits, name)                                                                            \
  {                                                                                                \
    #name,                                                                                         \
    n_bits,                                                                                        \
  },
  foreach_ppe_reg_xgmac_tx_config_t_fields
#undef _
};

static const qppe_reg_field_t ppe_reg_xgmac_rx_config_t_fields[] = {
#define _(n_bits, name)                                                                            \
  {                                                                                                \
    #name,                                                                                         \
    n_bits,                                                                                        \
  },
  foreach_ppe_reg_xgmac_rx_config_t_fields
#undef _
};

static const qppe_reg_field_t ppe_reg_xgmac_packet_filter_t_fields[] = {
#define _(n_bits, name)                                                                            \
  {                                                                                                \
    #name,                                                                                         \
    n_bits,                                                                                        \
  },
  foreach_ppe_reg_xgmac_packet_filter_t_fields
#undef _
};

static const qppe_reg_field_t ppe_reg_xgmac_watchdog_timeout_t_fields[] = {
#define _(n_bits, name)                                                                            \
  {                                                                                                \
    #name,                                                                                         \
    n_bits,                                                                                        \
  },
  foreach_ppe_reg_xgmac_watchdog_timeout_t_fields
#undef _
};

static const qppe_reg_field_t ppe_reg_xgmac_mmc_control_t_fields[] = {
#define _(n_bits, name)                                                                            \
  {                                                                                                \
    #name,                                                                                         \
    n_bits,                                                                                        \
  },
  foreach_ppe_reg_xgmac_mmc_control_t_fields
#undef _
};

static const qppe_reg_field_t ppe_reg_gmac_mib_control_t_fields[] = {
#define _(n_bits, name)                                                                            \
  {                                                                                                \
    #name,                                                                                         \
    n_bits,                                                                                        \
  },
  foreach_ppe_reg_gmac_mib_control_t_fields
#undef _
};

static const qppe_reg_field_t ppe_reg_gmac_mac_ctrl0_t_fields[] = {
#define _(n_bits, name)                                                                            \
  {                                                                                                \
    #name,                                                                                         \
    n_bits,                                                                                        \
  },
  foreach_ppe_reg_gmac_mac_ctrl0_t_fields
#undef _
};

static const qppe_reg_field_t ppe_reg_gmac_mac_ctrl1_t_fields[] = {
#define _(n_bits, name)                                                                            \
  {                                                                                                \
    #name,                                                                                         \
    n_bits,                                                                                        \
  },
  foreach_ppe_reg_gmac_mac_ctrl1_t_fields
#undef _
};

static const qppe_reg_field_t ppe_reg_gmac_mac_ctrl2_t_fields[] = {
#define _(n_bits, name)                                                                            \
  {                                                                                                \
    #name,                                                                                         \
    n_bits,                                                                                        \
  },
  foreach_ppe_reg_gmac_mac_ctrl2_t_fields
#undef _
};

static const qppe_reg_field_t ppe_reg_gmac_mac_dbg_ctrl_t_fields[] = {
#define _(n_bits, name)                                                                            \
  {                                                                                                \
    #name,                                                                                         \
    n_bits,                                                                                        \
  },
  foreach_ppe_reg_gmac_mac_dbg_ctrl_t_fields
#undef _
};

static const qppe_reg_field_t ppe_reg_gmac_mac_jumbo_size_t_fields[] = {
#define _(n_bits, name)                                                                            \
  {                                                                                                \
    #name,                                                                                         \
    n_bits,                                                                                        \
  },
  foreach_ppe_reg_gmac_mac_jumbo_size_t_fields
#undef _
};

static const qppe_reg_field_t ppe_reg_xgmac_mac_q0_tx_flow_ctrl_t_fields[] = {
#define _(n_bits, name)                                                                            \
  {                                                                                                \
    #name,                                                                                         \
    n_bits,                                                                                        \
  },
  foreach_ppe_reg_xgmac_mac_q0_tx_flow_ctrl_t_fields
#undef _
};

static const qppe_reg_field_t ppe_reg_xgmac_mac_rx_flow_ctrl_t_fields[] = {
#define _(n_bits, name)                                                                            \
  {                                                                                                \
    #name,                                                                                         \
    n_bits,                                                                                        \
  },
  foreach_ppe_reg_xgmac_mac_rx_flow_ctrl_t_fields
#undef _
};

static const qppe_reg_field_t ppe_reg_xgmac_mac_lpi_timers_control_t_fields[] = {
#define _(n_bits, name)                                                                            \
  {                                                                                                \
    #name,                                                                                         \
    n_bits,                                                                                        \
  },
  foreach_ppe_reg_xgmac_mac_lpi_timers_control_t_fields
#undef _
};

static const qppe_reg_field_t ppe_reg_xgmac_mac_lpi_auto_entry_timer_t_fields[] = {
#define _(n_bits, name)                                                                            \
  {                                                                                                \
    #name,                                                                                         \
    n_bits,                                                                                        \
  },
  foreach_ppe_reg_xgmac_mac_lpi_auto_entry_timer_t_fields
#undef _
};

static const qppe_reg_field_t ppe_reg_xgmac_mac_1us_tic_counter_t_fields[] = {
#define _(n_bits, name)                                                                            \
  {                                                                                                \
    #name,                                                                                         \
    n_bits,                                                                                        \
  },
  foreach_ppe_reg_xgmac_mac_1us_tic_counter_t_fields
#undef _
};

static const qppe_reg_field_t ppe_reg_xgmac_mac_snps_scs_t_fields[] = {
#define _(n_bits, name)                                                                            \
  {                                                                                                \
    #name,                                                                                         \
    n_bits,                                                                                        \
  },
  foreach_ppe_reg_xgmac_mac_snps_scs_t_fields
#undef _
};

static const qppe_reg_field_t ppe_reg_xgmac_mac_vlan_tag_t_fields[] = {
#define _(n_bits, name)                                                                            \
  {                                                                                                \
    #name,                                                                                         \
    n_bits,                                                                                        \
  },
  foreach_ppe_reg_xgmac_mac_vlan_tag_t_fields
#undef _
};

static const qppe_reg_field_t ppe_reg_xgmac_mac_rx_eth_type_match_t_fields[] = {
#define _(n_bits, name)                                                                            \
  {                                                                                                \
    #name,                                                                                         \
    n_bits,                                                                                        \
  },
  foreach_ppe_reg_xgmac_mac_rx_eth_type_match_t_fields
#undef _
};

static const qppe_reg_field_t ppe_reg_xgmac_mac_interrupt_enable_t_fields[] = {
#define _(n_bits, name)                                                                            \
  {                                                                                                \
    #name,                                                                                         \
    n_bits,                                                                                        \
  },
  foreach_ppe_reg_xgmac_mac_interrupt_enable_t_fields
#undef _
};

static const qppe_reg_field_t ppe_reg_xgmac_mmc_receive_interrupt_enable_t_fields[] = {
#define _(n_bits, name)                                                                            \
  {                                                                                                \
    #name,                                                                                         \
    n_bits,                                                                                        \
  },
  foreach_ppe_reg_xgmac_mmc_receive_interrupt_enable_t_fields
#undef _
};

static const qppe_reg_field_t ppe_reg_xgmac_mmc_transmit_interrupt_enable_t_fields[] = {
#define _(n_bits, name)                                                                            \
  {                                                                                                \
    #name,                                                                                         \
    n_bits,                                                                                        \
  },
  foreach_ppe_reg_xgmac_mmc_transmit_interrupt_enable_t_fields
#undef _
};
typedef struct
{
  const char *name;
  u32 reg;
  const qppe_reg_field_t *fields;
  uword n_fields;
} qppe_mac_config_reg_t;
static const qppe_mac_config_reg_t qppe_gmac_config_regs[] = {
  {
    "GMAC_ENABLE",
    HPPE_GMAC_REG_ENABLE,
    ppe_reg_gmac_enable_t_fields,
    ARRAY_LEN (ppe_reg_gmac_enable_t_fields),
  },
  {
    "GMAC_SPEED",
    HPPE_GMAC_REG_SPEED,
    ppe_reg_gmac_speed_t_fields,
    ARRAY_LEN (ppe_reg_gmac_speed_t_fields),
  },
  {
    "GMAC_CTRL0",
    HPPE_REG_GMAC_MAC_CTRL0,
    ppe_reg_gmac_mac_ctrl0_t_fields,
    ARRAY_LEN (ppe_reg_gmac_mac_ctrl0_t_fields),
  },
  {
    "GMAC_CTRL1",
    HPPE_REG_GMAC_MAC_CTRL1,
    ppe_reg_gmac_mac_ctrl1_t_fields,
    ARRAY_LEN (ppe_reg_gmac_mac_ctrl1_t_fields),
  },
  {
    "GMAC_CTRL2",
    HPPE_REG_GMAC_MAC_CTRL2,
    ppe_reg_gmac_mac_ctrl2_t_fields,
    ARRAY_LEN (ppe_reg_gmac_mac_ctrl2_t_fields),
  },
  {
    "GMAC_DBG_CTRL",
    HPPE_REG_GMAC_MAC_DBG_CTRL,
    ppe_reg_gmac_mac_dbg_ctrl_t_fields,
    ARRAY_LEN (ppe_reg_gmac_mac_dbg_ctrl_t_fields),
  },
  {
    "GMAC_JUMBO_SIZE",
    HPPE_REG_GMAC_MAC_JUMBO_SIZE,
    ppe_reg_gmac_mac_jumbo_size_t_fields,
    ARRAY_LEN (ppe_reg_gmac_mac_jumbo_size_t_fields),
  },
  {
    "GMAC_MIB_CTRL",
    HPPE_REG_GMAC_MAC_MIB_CTRL,
    ppe_reg_gmac_mib_control_t_fields,
    ARRAY_LEN (ppe_reg_gmac_mib_control_t_fields),
  },
};
static const qppe_mac_config_reg_t qppe_xgmac_config_regs[] = {
  {
    "XGMAC_VLAN_TAG",
    HPPE_REG_XGMAC_MAC_VLAN_TAG,
    ppe_reg_xgmac_mac_vlan_tag_t_fields,
    ARRAY_LEN (ppe_reg_xgmac_mac_vlan_tag_t_fields),
  },
  {
    "XGMAC_RX_ETH_TYPE_MATCH",
    HPPE_REG_XGMAC_MAC_RX_ETH_TYPE_MATCH,
    ppe_reg_xgmac_mac_rx_eth_type_match_t_fields,
    ARRAY_LEN (ppe_reg_xgmac_mac_rx_eth_type_match_t_fields),
  },
  {
    "XGMAC_INTERRUPT_ENABLE",
    HPPE_REG_XGMAC_MAC_INTERRUPT_ENABLE,
    ppe_reg_xgmac_mac_interrupt_enable_t_fields,
    ARRAY_LEN (ppe_reg_xgmac_mac_interrupt_enable_t_fields),
  },
  {
    "XGMAC_MMC_RECEIVE_INTERRUPT_ENABLE",
    HPPE_REG_XGMAC_MMC_RECEIVE_INTERRUPT_ENABLE,
    ppe_reg_xgmac_mmc_receive_interrupt_enable_t_fields,
    ARRAY_LEN (ppe_reg_xgmac_mmc_receive_interrupt_enable_t_fields),
  },
  {
    "XGMAC_MMC_TRANSMIT_INTERRUPT_ENABLE",
    HPPE_REG_XGMAC_MMC_TRANSMIT_INTERRUPT_ENABLE,
    ppe_reg_xgmac_mmc_transmit_interrupt_enable_t_fields,
    ARRAY_LEN (ppe_reg_xgmac_mmc_transmit_interrupt_enable_t_fields),
  },
  {
    "XGMAC_TX_CONFIGURATION",
    HPPE_XGMAC_REG_TX_CONFIG,
    ppe_reg_xgmac_tx_config_t_fields,
    ARRAY_LEN (ppe_reg_xgmac_tx_config_t_fields),
  },
  {
    "XGMAC_RX_CONFIGURATION",
    HPPE_XGMAC_REG_RX_CONFIG,
    ppe_reg_xgmac_rx_config_t_fields,
    ARRAY_LEN (ppe_reg_xgmac_rx_config_t_fields),
  },
  {
    "XGMAC_PACKET_FILTER",
    HPPE_XGMAC_REG_PACKET_FILTER,
    ppe_reg_xgmac_packet_filter_t_fields,
    ARRAY_LEN (ppe_reg_xgmac_packet_filter_t_fields),
  },
  {
    "XGMAC_WATCHDOG_TIMEOUT",
    HPPE_XGMAC_REG_WATCHDOG_TIMEOUT,
    ppe_reg_xgmac_watchdog_timeout_t_fields,
    ARRAY_LEN (ppe_reg_xgmac_watchdog_timeout_t_fields),
  },
  {
    "XGMAC_Q0_TX_FLOW_CTRL",
    HPPE_REG_XGMAC_MAC_Q0_TX_FLOW_CTRL,
    ppe_reg_xgmac_mac_q0_tx_flow_ctrl_t_fields,
    ARRAY_LEN (ppe_reg_xgmac_mac_q0_tx_flow_ctrl_t_fields),
  },
  {
    "XGMAC_RX_FLOW_CTRL",
    HPPE_REG_XGMAC_MAC_RX_FLOW_CTRL,
    ppe_reg_xgmac_mac_rx_flow_ctrl_t_fields,
    ARRAY_LEN (ppe_reg_xgmac_mac_rx_flow_ctrl_t_fields),
  },
  {
    "XGMAC_LPI_TIMERS_CONTROL",
    HPPE_REG_XGMAC_MAC_LPI_TIMERS_CONTROL,
    ppe_reg_xgmac_mac_lpi_timers_control_t_fields,
    ARRAY_LEN (ppe_reg_xgmac_mac_lpi_timers_control_t_fields),
  },
  {
    "XGMAC_LPI_AUTO_ENTRY_TIMER",
    HPPE_REG_XGMAC_MAC_LPI_AUTO_ENTRY_TIMER,
    ppe_reg_xgmac_mac_lpi_auto_entry_timer_t_fields,
    ARRAY_LEN (ppe_reg_xgmac_mac_lpi_auto_entry_timer_t_fields),
  },
  {
    "XGMAC_1US_TIC_COUNTER",
    HPPE_REG_XGMAC_MAC_1US_TIC_COUNTER,
    ppe_reg_xgmac_mac_1us_tic_counter_t_fields,
    ARRAY_LEN (ppe_reg_xgmac_mac_1us_tic_counter_t_fields),
  },
  {
    "XGMAC_SNPS_SCS",
    HPPE_REG_XGMAC_MAC_SNPS_SCS,
    ppe_reg_xgmac_mac_snps_scs_t_fields,
    ARRAY_LEN (ppe_reg_xgmac_mac_snps_scs_t_fields),
  },
  {
    "XGMAC_MMC_CONTROL",
    HPPE_REG_XGMAC_MMC_CONTROL,
    ppe_reg_xgmac_mmc_control_t_fields,
    ARRAY_LEN (ppe_reg_xgmac_mmc_control_t_fields),
  },
};

u8 *
format_qppe_mac_cfg (u8 *s, va_list *args)
{
  vnet_dev_t *dev = va_arg (*args, vnet_dev_t *);
  qppe_device_t *qd = vnet_dev_get_data (dev);
  u32 indent = format_get_indent (s), first = 1;

  if (!qd->regs)
    return s;

  foreach_vnet_dev_port (port, dev)
    {
      qppe_port_t *qp = vnet_dev_get_port_data (port);
      const qppe_mac_config_reg_t *regs =
	qp->is_xgmac ? qppe_xgmac_config_regs : qppe_gmac_config_regs;
      u32 n_regs =
	qp->is_xgmac ? ARRAY_LEN (qppe_xgmac_config_regs) : ARRAY_LEN (qppe_gmac_config_regs);

      for (u32 i = 0; i < n_regs; i++)
	{
	  u32 value = qp->is_xgmac ? qppe_xgmac_reg_rd (port, regs[i].reg) :
				     qppe_gmac_reg_rd (port, regs[i].reg);

	  if (!first)
	    {
	      s = format (s, "\n");
	      s = format_newline (s, indent);
	    }
	  first = 0;
	  s = format (s, "%s (port %u): 0x%08x", regs[i].name, port->port_id, value);
	  s = format_newline (s, indent + 2);
	  s = format (s, "%U", format_qppe_reg_fields, value, regs[i].fields, regs[i].n_fields);
	}
    }
  return s;
}

u8 *
format_qppe_mac_addresses (u8 *s, va_list *args)
{
  vnet_dev_t *dev = va_arg (*args, vnet_dev_t *);
  qppe_device_t *qd = vnet_dev_get_data (dev);
  table_t table = {};
  u32 row = 0, indent = format_get_indent (s);

  if (!qd->regs)
    return s;

  table_add_hdr_row (&table, 4, "port", "MAC", "address", "en");
  foreach_vnet_dev_port (port, dev)
    {
      qppe_port_t *qp = vnet_dev_get_port_data (port);
      vnet_dev_hw_addr_t addr;
      u32 high, low;

      if (qp->is_xgmac)
	{
	  high = qppe_xgmac_reg_rd (port, HPPE_XGMAC_REG_ADDR0_HIGH);
	  low = qppe_xgmac_reg_rd (port, HPPE_XGMAC_REG_ADDR0_LOW);
	  for (u32 i = 0; i < 4; i++)
	    addr.eth_mac[i] = low >> (8 * i);
	  addr.eth_mac[4] = high;
	  addr.eth_mac[5] = high >> 8;
	}
      else
	{
	  high = qppe_gmac_reg_rd (port, HPPE_GMAC_REG_ADDR0);
	  low = qppe_gmac_reg_rd (port, HPPE_GMAC_REG_ADDR1);
	  for (u32 i = 0; i < 4; i++)
	    addr.eth_mac[i] = low >> (8 * (3 - i));
	  addr.eth_mac[4] = high;
	  addr.eth_mac[5] = high >> 8;
	}
      table_format_cell (&table, row, 0, "%u", port->port_id);
      table_format_cell (&table, row, 1, "%s", qp->is_xgmac ? "XGMAC" : "GMAC");
      table_format_cell (&table, row, 2, "%U", format_vnet_dev_hw_addr, &addr);
      if (qp->is_xgmac)
	table_format_cell (&table, row, 3, "%u", high >> 31);
      else
	table_format_cell (&table, row, 3, "-");
      row++;
    }
  s = format (s, "MAC_ADDRESS0:");
  s = format_newline (s, indent + 2);
  if (row)
    s = format (s, "%U", format_table, &table);
  else
    s = format (s, "no ports");
  table_free (&table);
  return s;
}
