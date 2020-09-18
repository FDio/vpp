/*
 * Copyright (c) 2017 Cisco and/or its affiliates.
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
} lldp_cfg_err_t;

lldp_cfg_err_t lldp_cfg_intf_set (u32 hw_if_index, u8 ** port_desc,
                u8 **mgmt_ip4, u8 **mgmt_ip6, u8 **mgmt_oid, int enable);
lldp_cfg_err_t lldp_cfg_set (u8 ** host, int hold_time, int tx_interval);


#endif /* __included_lldp_h__ */
