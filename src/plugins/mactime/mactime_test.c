/*
 * mactime.c - skeleton vpp-api-test plug-in
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
#include <vppinfra/time_range.h>
#include <vnet/ethernet/ethernet.h>

uword vat_unformat_sw_if_index (unformat_input_t * input, va_list * args);

/* Declare message IDs */
#include <mactime/mactime.api_enum.h>
#include <mactime/mactime.api_types.h>

typedef struct
{
  /* API message ID base */
  u16 msg_id_base;
  vat_main_t *vat_main;
} mactime_test_main_t;

mactime_test_main_t mactime_test_main;

#define __plugin_msg_base mactime_test_main.msg_id_base
#include <vlibapi/vat_helper_macros.h>

static int
api_mactime_enable_disable (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  int enable_disable = 1;
  u32 sw_if_index = ~0;
  vl_api_mactime_enable_disable_t *mp;
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
  M (MACTIME_ENABLE_DISABLE, mp);
  mp->sw_if_index = ntohl (sw_if_index);
  mp->enable_disable = enable_disable;

  /* send it... */
  S (mp);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

/* These two ought to be in a library somewhere but they aren't */
static uword
my_unformat_mac_address (unformat_input_t * input, va_list * args)
{
  u8 *a = va_arg (*args, u8 *);
  return unformat (input, "%x:%x:%x:%x:%x:%x", &a[0], &a[1], &a[2], &a[3],
		   &a[4], &a[5]);
}

static u8 *
my_format_mac_address (u8 * s, va_list * args)
{
  u8 *a = va_arg (*args, u8 *);
  return format (s, "%02x:%02x:%02x:%02x:%02x:%02x",
		 a[0], a[1], a[2], a[3], a[4], a[5]);
}

static int
api_mactime_add_del_range (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_mactime_add_del_range_t *mp;
  u8 mac_address[8];
  u8 *device_name = 0;
  clib_timebase_range_t *rp = 0;
  int name_set = 0;
  int mac_set = 0;
  u8 is_add = 1;
  u8 allow = 0;
  u8 allow_quota = 0;
  u8 drop = 0;
  u8 no_udp_10001 = 0;
  u64 data_quota = 0;
  int ret;
  int ii;

  /* Parse args required to build the message */
  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "name %s", &device_name))
	{
	  vec_add1 (device_name, 0);
	  name_set = 1;
	}
      else if (unformat (i, "allow-range %U",
			 unformat_clib_timebase_range_vector, &rp))
	allow = 1;
      else if (unformat (i, "allow-quota-range %U",
			 unformat_clib_timebase_range_vector, &rp))
	allow_quota = 1;
      else if (unformat (i, "drop-range %U",
			 unformat_clib_timebase_range_vector, &rp))
	drop = 1;
      else if (unformat (i, "allow-static"))
	allow = 1;
      else if (unformat (i, "drop-static"))
	drop = 1;
      else if (unformat (i, "no-udp-10001"))
	no_udp_10001 = 1;
      else if (unformat (i, "mac %U", my_unformat_mac_address, mac_address))
	mac_set = 1;
      else if (unformat (i, "del"))
	is_add = 0;
      else if (unformat (i, "data-quota %lldM", &data_quota))
	data_quota <<= 20;
      else if (unformat (i, "data-quota %lldG", &data_quota))
	data_quota <<= 30;
      else
	break;
    }

  /* Sanity checks */
  if (mac_set == 0)
    {
      vec_free (rp);
      vec_free (device_name);
      errmsg ("mac address required, not set\n");
      return -99;
    }

  /* allow-range / drop-range parse errors cause this condition */
  if (is_add && allow == 0 && drop == 0 && allow_quota == 0)
    {
      vec_free (rp);
      vec_free (device_name);
      errmsg ("parse error...\n");
      return -99;
    }

  /* Unlikely, but check anyhow */
  if (vec_len (device_name) > ARRAY_LEN (mp->device_name))
    {
      vec_free (rp);
      vec_free (device_name);
      errmsg ("device name too long, max %d\n", ARRAY_LEN (mp->device_name));
      return -99;
    }

  /* Cough up a device name if none set */
  if (name_set == 0)
    {
      device_name = format (0, "mac %U%c", my_format_mac_address,
			    mac_address, 0);
    }

  /* Construct the API message */
  M2 (MACTIME_ADD_DEL_RANGE, mp, sizeof (rp[0]) * vec_len (rp));
  mp->is_add = is_add;
  mp->drop = drop;
  mp->allow = allow;
  mp->allow_quota = allow_quota;
  mp->no_udp_10001 = no_udp_10001;
  mp->data_quota = clib_host_to_net_u64 (data_quota);
  memcpy (mp->mac_address, mac_address, sizeof (mp->mac_address));
  memcpy (mp->device_name, device_name, vec_len (device_name));
  mp->count = clib_host_to_net_u32 (vec_len (rp));

  for (ii = 0; ii < vec_len (rp); ii++)
    {
      mp->ranges[ii].start = rp[ii].start;
      mp->ranges[ii].end = rp[ii].end;
    }

  vec_free (rp);
  vec_free (device_name);

  /* send it... */
  S (mp);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

#include <mactime/mactime.api_test.c>

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
