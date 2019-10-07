/*
 * nsim.c - skeleton vpp-api-test plug-in
 *
 * Copyright (c) <current-year> <your-organization>
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

uword unformat_sw_if_index (unformat_input_t * input, va_list * args);

/* Declare message IDs */
#include <nsim/nsim.api_enum.h>
#include <nsim/nsim.api_types.h>

typedef struct
{
  /* API message ID base */
  u16 msg_id_base;
  vat_main_t *vat_main;
} nsim_test_main_t;

nsim_test_main_t nsim_test_main;

#define __plugin_msg_base nsim_test_main.msg_id_base
#include <vlibapi/vat_helper_macros.h>

static int
api_nsim_cross_connect_enable_disable (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  int enable_disable = 1;
  u32 sw_if_index0 = ~0;
  u32 sw_if_index1 = ~0;
  u32 tmp;
  vl_api_nsim_cross_connect_enable_disable_t *mp;
  int ret;

  /* Parse args required to build the message */
  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "%U", unformat_sw_if_index, vam, &tmp))
	{
	  if (sw_if_index0 == ~0)
	    sw_if_index0 = tmp;
	  else
	    sw_if_index1 = tmp;
	}
      else if (unformat (i, "sw_if_index %d", &tmp))
	{
	  if (sw_if_index0 == ~0)
	    sw_if_index0 = tmp;
	  else
	    sw_if_index1 = tmp;
	}
      else if (unformat (i, "disable"))
	enable_disable = 0;
      else
	break;
    }

  if (sw_if_index0 == ~0 || sw_if_index1 == ~0)
    {
      errmsg ("missing interface name / explicit sw_if_index number \n");
      return -99;
    }

  /* Construct the API message */
  M (NSIM_CROSS_CONNECT_ENABLE_DISABLE, mp);
  mp->sw_if_index0 = ntohl (sw_if_index0);
  mp->sw_if_index1 = ntohl (sw_if_index1);
  mp->enable_disable = enable_disable;

  /* send it... */
  S (mp);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

static int
api_nsim_output_feature_enable_disable (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  int enable_disable = 1;
  u32 sw_if_index = ~0;
  vl_api_nsim_output_feature_enable_disable_t *mp;
  int ret;

  /* Parse args required to build the message */
  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "%U", unformat_sw_if_index, vam, &sw_if_index))
	;
      else if (unformat (i, "sw_if_index %d", &sw_if_index))
	;
      else if (unformat (i, "disable"))
	enable_disable = 0;
      else
	break;
    }

  if (sw_if_index == ~0)
    {
      errmsg ("missing interface name / explicit sw_if_index number \n");
      return -99;
    }

  /* Construct the API message */
  M (NSIM_OUTPUT_FEATURE_ENABLE_DISABLE, mp);
  mp->sw_if_index = ntohl (sw_if_index);
  mp->enable_disable = enable_disable;

  /* send it... */
  S (mp);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

static uword
unformat_delay (unformat_input_t * input, va_list * args)
{
  f64 *result = va_arg (*args, f64 *);
  f64 tmp;

  if (unformat (input, "%f us", &tmp))
    *result = tmp * 1e-6;
  else if (unformat (input, "%f ms", &tmp))
    *result = tmp * 1e-3;
  else if (unformat (input, "%f sec", &tmp))
    *result = tmp;
  else
    return 0;

  return 1;
}

static uword
unformat_bandwidth (unformat_input_t * input, va_list * args)
{
  f64 *result = va_arg (*args, f64 *);
  f64 tmp;

  if (unformat (input, "%f gbit", &tmp))
    *result = tmp * 1e9;
  else if (unformat (input, "%f gbyte", &tmp))
    *result = tmp * 8e9;
  else
    return 0;
  return 1;
}

static int
api_nsim_configure (vat_main_t * vam)
{
  vl_api_nsim_configure_t *mp;
  unformat_input_t *i = vam->input;
  f64 delay = 0.0, bandwidth = 0.0;
  f64 packet_size = 1500.0;
  u32 packets_per_drop = 0;
  int ret;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "delay %U", unformat_delay, &delay))
	;
      else if (unformat (i, "bandwidth %U", unformat_bandwidth, &bandwidth))
	;
      else if (unformat (i, "packet-size %f", &packet_size))
	;
      else if (unformat (i, "packets-per-drop %u", &packets_per_drop))
	;
      else
	break;
    }

  if (delay == 0.0 || bandwidth == 0.0)
    {
      errmsg ("must specify delay and bandwidth");
      return -99;
    }

  /* Construct the API message */
  M (NSIM_CONFIGURE, mp);
  mp->delay_in_usec = (u32) (delay * 1e6);
  mp->delay_in_usec = ntohl (mp->delay_in_usec);
  mp->average_packet_size = (u32) (packet_size);
  mp->average_packet_size = ntohl (mp->average_packet_size);
  mp->bandwidth_in_bits_per_second = (u64) (bandwidth);
  mp->bandwidth_in_bits_per_second =
    clib_host_to_net_u64 (mp->bandwidth_in_bits_per_second);
  mp->packets_per_drop = ntohl (packets_per_drop);

  /* send it... */
  S (mp);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

#include <nsim/nsim.api_test.c>

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
