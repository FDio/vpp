/*
 *------------------------------------------------------------------
 * arp_test.c
 *
 * Copyright (c) 2019 Cisco and/or its affiliates.
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
 *------------------------------------------------------------------
 */

#include <vat/vat.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vppinfra/error.h>

#include <vnet/ip/ip_format_fns.h>

#include <vpp/api/types.h>

typedef struct
{
  /* API message ID base */
  u16 msg_id_base;
  u32 ping_id;
  vat_main_t *vat_main;
} arp_test_main_t;

arp_test_main_t arp_test_main;

#define __plugin_msg_base arp_test_main.msg_id_base
#include <vlibapi/vat_helper_macros.h>
uword unformat_sw_if_index (unformat_input_t * input, va_list * args);

/* Declare message IDs */
#include <arp/arp.api_enum.h>
#include <arp/arp.api_types.h>
#include <vpp/api/vpe.api_types.h>

static int
api_proxy_arp_dump (vat_main_t * vam)
{
  return -1;
}

static int
api_proxy_arp_intfc_dump (vat_main_t * vam)
{
  return -1;
}

static void
vl_api_proxy_arp_details_t_handler (vl_api_proxy_arp_details_t * mp)
{
}

static void
vl_api_proxy_arp_intfc_details_t_handler (vl_api_proxy_arp_intfc_details_t *
					  mp)
{
}

static int
api_proxy_arp_add_del (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_proxy_arp_add_del_t *mp;
  u32 vrf_id = 0;
  u8 is_add = 1;
  vl_api_ip4_address_t lo, hi;
  u8 range_set = 0;
  int ret;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "vrf %d", &vrf_id))
	;
      else if (unformat (i, "%U - %U", unformat_vl_api_ip4_address, &lo,
			 unformat_vl_api_ip4_address, &hi))
	range_set = 1;
      else if (unformat (i, "del"))
	is_add = 0;
      else
	{
	  clib_warning ("parse error '%U'", format_unformat_error, i);
	  return -99;
	}
    }

  if (range_set == 0)
    {
      errmsg ("address range not set");
      return -99;
    }

  M (PROXY_ARP_ADD_DEL, mp);

  mp->proxy.table_id = ntohl (vrf_id);
  mp->is_add = is_add;
  clib_memcpy (mp->proxy.low, &lo, sizeof (lo));
  clib_memcpy (mp->proxy.hi, &hi, sizeof (hi));

  S (mp);
  W (ret);
  return ret;
}

static int
api_proxy_arp_intfc_enable_disable (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_proxy_arp_intfc_enable_disable_t *mp;
  u32 sw_if_index;
  u8 enable = 1;
  u8 sw_if_index_set = 0;
  int ret;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "%U", unformat_sw_if_index, vam, &sw_if_index))
	sw_if_index_set = 1;
      else if (unformat (i, "sw_if_index %d", &sw_if_index))
	sw_if_index_set = 1;
      else if (unformat (i, "enable"))
	enable = 1;
      else if (unformat (i, "disable"))
	enable = 0;
      else
	{
	  clib_warning ("parse error '%U'", format_unformat_error, i);
	  return -99;
	}
    }

  if (sw_if_index_set == 0)
    {
      errmsg ("missing interface name or sw_if_index");
      return -99;
    }

  M (PROXY_ARP_INTFC_ENABLE_DISABLE, mp);

  mp->sw_if_index = ntohl (sw_if_index);
  mp->enable = enable;

  S (mp);
  W (ret);
  return ret;
}

#include <arp/arp.api_test.c>


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
