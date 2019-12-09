/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
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
/*
 *------------------------------------------------------------------
 * vxlan_gpe_test.c - test harness for vxlan_gpe plugin
 *------------------------------------------------------------------
 */

#include <vat/vat.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>

#include <vppinfra/error.h>
#include <vnet/format_fns.h>
#include <vnet/ip/ip_types_api.h>

#define __plugin_msg_base ioam_vxlan_gpe_test_main.msg_id_base
#include <vlibapi/vat_helper_macros.h>

/* Declare message IDs */
#include <ioam/lib-vxlan-gpe/ioam_vxlan_gpe.api_enum.h>
#include <ioam/lib-vxlan-gpe/ioam_vxlan_gpe.api_types.h>

#include <ioam/lib-vxlan-gpe/vxlan_gpe_ioam_packet.h>
#include <ioam/lib-vxlan-gpe/vxlan_gpe_ioam.h>

typedef struct
{
  /* API message ID base */
  u16 msg_id_base;
  vat_main_t *vat_main;
} ioam_vxlan_gpe_test_main_t;

ioam_vxlan_gpe_test_main_t ioam_vxlan_gpe_test_main;

static int
api_vxlan_gpe_ioam_enable (vat_main_t * vam)
{
  unformat_input_t *input = vam->input;
  vl_api_vxlan_gpe_ioam_enable_t *mp;
  u32 id = 0;
  int has_trace_option = 0;
  int has_pow_option = 0;
  int has_ppc_option = 0;
  int ret;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "trace"))
	has_trace_option = 1;
      else if (unformat (input, "pow"))
	has_pow_option = 1;
      else if (unformat (input, "ppc encap"))
	has_ppc_option = PPC_ENCAP;
      else if (unformat (input, "ppc decap"))
	has_ppc_option = PPC_DECAP;
      else if (unformat (input, "ppc none"))
	has_ppc_option = PPC_NONE;
      else
	break;
    }
  M (VXLAN_GPE_IOAM_ENABLE, mp);
  mp->id = htons (id);
  mp->trace_ppc = has_ppc_option;
  mp->pow_enable = has_pow_option;
  mp->trace_enable = has_trace_option;


  S (mp);
  W (ret);
  return ret;
}


static int
api_vxlan_gpe_ioam_disable (vat_main_t * vam)
{
  vl_api_vxlan_gpe_ioam_disable_t *mp;
  int ret;

  M (VXLAN_GPE_IOAM_DISABLE, mp);
  S (mp);
  W (ret);
  return ret;
}

static int
api_vxlan_gpe_ioam_vni_enable (vat_main_t * vam)
{
  unformat_input_t *line_input = vam->input;
  vl_api_vxlan_gpe_ioam_vni_enable_t *mp;
  ip46_address_t local, remote;
  u8 local_set = 0;
  u8 remote_set = 0;
  u32 vni;
  u8 vni_set = 0;
  int ret;


  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "local %U", unformat_ip46_address, &local))
	{
	  local_set = 1;
	}
      else if (unformat (line_input, "remote %U",
			 unformat_ip46_address, &remote))
	{
	  remote_set = 1;
	}
      else if (unformat (line_input, "vni %d", &vni))
	vni_set = 1;
      else
	{
	  errmsg ("parse error '%U'\n", format_unformat_error, line_input);
	  return -99;
	}
    }

  if (local_set == 0)
    {
      errmsg ("tunnel local address not specified\n");
      return -99;
    }
  if (remote_set == 0)
    {
      errmsg ("tunnel remote address not specified\n");
      return -99;
    }
  if (ip46_address_is_ip4 (&local) != ip46_address_is_ip4 (&remote))
    {
      errmsg ("both IPv4 and IPv6 addresses specified");
      return -99;
    }

  if (vni_set == 0)
    {
      errmsg ("vni not specified\n");
      return -99;
    }

  M (VXLAN_GPE_IOAM_VNI_ENABLE, mp);

  ip_address_encode (&local,
		     ip46_address_is_ip4 (&local) ? IP46_TYPE_IP4 :
		     IP46_TYPE_IP6, &mp->local);
  ip_address_encode (&local,
		     ip46_address_is_ip4 (&remote) ? IP46_TYPE_IP4 :
		     IP46_TYPE_IP6, &mp->remote);

  mp->vni = ntohl (vni);

  S (mp);
  W (ret);
  return ret;
}

static int
api_vxlan_gpe_ioam_vni_disable (vat_main_t * vam)
{
  unformat_input_t *line_input = vam->input;
  vl_api_vxlan_gpe_ioam_vni_disable_t *mp;
  ip46_address_t local, remote;
  u8 local_set = 0;
  u8 remote_set = 0;
  u32 vni;
  u8 vni_set = 0;
  int ret;


  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "local %U", unformat_ip46_address, &local))
	{
	  local_set = 1;
	}
      else if (unformat (line_input, "remote %U",
			 unformat_ip46_address, &remote))
	{
	  remote_set = 1;
	}
      else if (unformat (line_input, "vni %d", &vni))
	vni_set = 1;
      else
	{
	  errmsg ("parse error '%U'\n", format_unformat_error, line_input);
	  return -99;
	}
    }

  if (local_set == 0)
    {
      errmsg ("tunnel local address not specified\n");
      return -99;
    }
  if (remote_set == 0)
    {
      errmsg ("tunnel remote address not specified\n");
      return -99;
    }
  if (ip46_address_is_ip4 (&local) != ip46_address_is_ip4 (&remote))
    {
      errmsg ("both IPv4 and IPv6 addresses specified");
      return -99;
    }

  if (vni_set == 0)
    {
      errmsg ("vni not specified\n");
      return -99;
    }

  M (VXLAN_GPE_IOAM_VNI_DISABLE, mp);

  ip_address_encode (&local,
		     ip46_address_is_ip4 (&local) ? IP46_TYPE_IP4 :
		     IP46_TYPE_IP6, &mp->local);
  ip_address_encode (&local,
		     ip46_address_is_ip4 (&remote) ? IP46_TYPE_IP4 :
		     IP46_TYPE_IP6, &mp->remote);

  mp->vni = ntohl (vni);

  S (mp);
  W (ret);
  return ret;
}

static int
api_vxlan_gpe_ioam_transit_enable (vat_main_t * vam)
{
  unformat_input_t *line_input = vam->input;
  vl_api_vxlan_gpe_ioam_transit_enable_t *mp;
  ip46_address_t local;
  u8 local_set = 0;
  u32 outer_fib_index = 0;
  int ret;


  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "dst-ip %U", unformat_ip46_address, &local))
	{
	  local_set = 1;
	}
      else if (unformat (line_input, "outer-fib-index %d", &outer_fib_index))
	;
      else
	{
	  errmsg ("parse error '%U'\n", format_unformat_error, line_input);
	  return -99;
	}
    }

  if (local_set == 0)
    {
      errmsg ("destination address not specified\n");
      return -99;
    }

  M (VXLAN_GPE_IOAM_TRANSIT_ENABLE, mp);


  if (!ip46_address_is_ip4 (&local))
    {
      errmsg ("IPv6 currently unsupported");
      return -1;
    }
  ip_address_encode (&local, IP46_TYPE_IP4, &mp->dst_addr);
  mp->outer_fib_index = htonl (outer_fib_index);

  S (mp);
  W (ret);
  return ret;
}

static int
api_vxlan_gpe_ioam_transit_disable (vat_main_t * vam)
{
  unformat_input_t *line_input = vam->input;
  vl_api_vxlan_gpe_ioam_transit_disable_t *mp;
  ip46_address_t local;
  u8 local_set = 0;
  u32 outer_fib_index = 0;
  int ret;


  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "dst-ip %U", unformat_ip46_address, &local))
	{
	  local_set = 1;
	}
      else if (unformat (line_input, "outer-fib-index %d", &outer_fib_index))
	;
      else
	{
	  errmsg ("parse error '%U'\n", format_unformat_error, line_input);
	  return -99;
	}
    }

  if (local_set == 0)
    {
      errmsg ("destination address not specified\n");
      return -99;
    }

  M (VXLAN_GPE_IOAM_TRANSIT_DISABLE, mp);


  if (!ip46_address_is_ip4 (&local))
    {
      return -1;
    }
  ip_address_encode (&local, IP46_TYPE_IP4, &mp->dst_addr);

  mp->outer_fib_index = htonl (outer_fib_index);

  S (mp);
  W (ret);
  return ret;
}

/* Override generated plugin register symbol */
#define vat_plugin_register vxlan_gpe_vat_plugin_register
#include <ioam/lib-vxlan-gpe/ioam_vxlan_gpe.api_test.c>

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
