/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2017 Cisco and/or its affiliates.
 */

/**
 * @file
 * @brief LLDP external definition
 */
#ifndef __included_lldp_h__
#define __included_lldp_h__

typedef enum lldp_cfg_err
{
  lldp_ok,
  lldp_not_supported,
  lldp_invalid_arg,
  lldp_internal_error,
} lldp_cfg_err_t;

lldp_cfg_err_t lldp_cfg_intf_set (u32 hw_if_index, u8 ** port_desc,
                u8 **mgmt_ip4, u8 **mgmt_ip6, u8 **mgmt_oid, int enable);
lldp_cfg_err_t lldp_cfg_set (u8 ** host, int hold_time, int tx_interval);

extern const u8 lldp_mac_addr[6];

#endif /* __included_lldp_h__ */
