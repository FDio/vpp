/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
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

#include <vat/vat.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vppinfra/error.h>

#include <vnet/ip/ip.h>
#include <vnet/ip/ip_format_fns.h>
#include <vnet/ethernet/ethernet_format_fns.h>

/* define message IDs */
#include <lldp/lldp.api_enum.h>
#include <lldp/lldp.api_types.h>

typedef struct
{
  /* API message ID base */
  u16 msg_id_base;
  vat_main_t *vat_main;
} lldp_test_main_t;

lldp_test_main_t lldp_test_main;

#define __plugin_msg_base lldp_test_main.msg_id_base
#include <vlibapi/vat_helper_macros.h>

/* Macro to finish up custom dump fns */
#define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)
#define FINISH                                  \
    vec_add1 (s, 0);                            \
    vl_print (handle, (char *)s);               \
    vec_free (s);                               \
    return handle;

static int
api_lldp_config (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_lldp_config_t *mp;
  int tx_hold = 0;
  int tx_interval = 0;
  u8 *sys_name = NULL;
  int ret;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "system-name %s", &sys_name))
	;
      else if (unformat (i, "tx-hold %d", &tx_hold))
	;
      else if (unformat (i, "tx-interval %d", &tx_interval))
	;
      else
	{
	  clib_warning ("parse error '%U'", format_unformat_error, i);
	  return -99;
	}
    }

  vec_add1 (sys_name, 0);

  M (LLDP_CONFIG, mp);
  mp->tx_hold = htonl (tx_hold);
  mp->tx_interval = htonl (tx_interval);
  vl_api_vec_to_api_string (sys_name, &mp->system_name);
  vec_free (sys_name);

  S (mp);
  W (ret);
  return ret;
}

static int
api_sw_interface_set_lldp (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_sw_interface_set_lldp_t *mp;
  u32 sw_if_index = ~0;
  u32 enable = 1;
  u8 *port_desc = NULL, *mgmt_oid = NULL;
  ip4_address_t ip4_addr;
  ip6_address_t ip6_addr;
  int ret;

  clib_memset (&ip4_addr, 0, sizeof (ip4_addr));
  clib_memset (&ip6_addr, 0, sizeof (ip6_addr));

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "disable"))
	enable = 0;
      else
	if (unformat (i, "%U", unformat_sw_if_index, vam, &sw_if_index))
	;
      else if (unformat (i, "sw_if_index %d", &sw_if_index))
	;
      else if (unformat (i, "port-desc %s", &port_desc))
	;
      else if (unformat (i, "mgmt-ip4 %U", unformat_ip4_address, &ip4_addr))
	;
      else if (unformat (i, "mgmt-ip6 %U", unformat_ip6_address, &ip6_addr))
	;
      else if (unformat (i, "mgmt-oid %s", &mgmt_oid))
	;
      else
	break;
    }

  if (sw_if_index == ~0)
    {
      errmsg ("missing interface name or sw_if_index");
      return -99;
    }

  /* Construct the API message */
  vec_add1 (port_desc, 0);
  vec_add1 (mgmt_oid, 0);
  M (SW_INTERFACE_SET_LLDP, mp);
  mp->sw_if_index = ntohl (sw_if_index);
  mp->enable = enable;
  vl_api_vec_to_api_string (port_desc, &mp->port_desc);
  clib_memcpy (mp->mgmt_oid, mgmt_oid, vec_len (mgmt_oid));
  clib_memcpy (mp->mgmt_ip4, &ip4_addr, sizeof (ip4_addr));
  clib_memcpy (mp->mgmt_ip6, &ip6_addr, sizeof (ip6_addr));
  vec_free (port_desc);
  vec_free (mgmt_oid);

  S (mp);
  W (ret);
  return ret;
}

#include <lldp/lldp.api_test.c>
