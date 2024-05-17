/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vnet/dev/counters.h>
#include <vnet/dev/bus/platform.h>
#include <dev_armada/musdk.h>
#include <dev_armada/pp2/pp2.h>

u8 *
format_pp2_ppio_link_info (u8 *s, va_list *args)
{
  struct pp2_ppio_link_info *li = va_arg (*args, struct pp2_ppio_link_info *);

  char *port_duplex[] = {
    [MV_NET_LINK_DUPLEX_HALF] = "half",
    [MV_NET_LINK_DUPLEX_FULL] = "full",
  };

  u32 port_speeds[] = {
    [MV_NET_LINK_SPEED_10] = 10,       [MV_NET_LINK_SPEED_100] = 100,
    [MV_NET_LINK_SPEED_1000] = 1000,   [MV_NET_LINK_SPEED_2500] = 2500,
    [MV_NET_LINK_SPEED_10000] = 10000,
  };

  char *port_phy_modes[] = {
    [MV_NET_PHY_MODE_NONE] = "NONE",
    [MV_NET_PHY_MODE_MII] = "MII",
    [MV_NET_PHY_MODE_GMII] = "GMII",
    [MV_NET_PHY_MODE_SGMII] = "SGMII",
    [MV_NET_PHY_MODE_TBI] = "TBI",
    [MV_NET_PHY_MODE_REVMII] = "REVMII",
    [MV_NET_PHY_MODE_RMII] = "RMII",
    [MV_NET_PHY_MODE_RGMII] = "RGMII",
    [MV_NET_PHY_MODE_RGMII_ID] = "RGMII_ID",
    [MV_NET_PHY_MODE_RGMII_RXID] = "RGMII_RXID",
    [MV_NET_PHY_MODE_RGMII_TXID] = "RGMII_TXID",
    [MV_NET_PHY_MODE_RTBI] = "RTBI",
    [MV_NET_PHY_MODE_SMII] = "SMII",
    [MV_NET_PHY_MODE_XGMII] = "XGMII",
    [MV_NET_PHY_MODE_MOCA] = "MOCA",
    [MV_NET_PHY_MODE_QSGMII] = "QSGMII",
    [MV_NET_PHY_MODE_XAUI] = "XAUI",
    [MV_NET_PHY_MODE_RXAUI] = "RXAUI",
    [MV_NET_PHY_MODE_KR] = "KR",
  };

  s =
    format (s, "duplex %s speed %d up %d phy_mode %s", port_duplex[li->duplex],
	    port_speeds[li->speed], li->up, port_phy_modes[li->phy_mode]);

  return s;
}

u8 *
format_mvpp2_port_status (u8 *s, va_list *args)
{
  vnet_dev_format_args_t __clib_unused *a =
    va_arg (*args, vnet_dev_format_args_t *);
  vnet_dev_port_t *port = va_arg (*args, vnet_dev_port_t *);
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  struct pp2_ppio_link_info li = {};

  if (mp->ppio == 0 || pp2_ppio_get_link_info (mp->ppio, &li))
    return format (s, "link info not available");

  return format (s, "%U", format_pp2_ppio_link_info, &li);
}

