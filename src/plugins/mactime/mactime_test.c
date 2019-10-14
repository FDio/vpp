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
#include <mactime/mactime_device.h>
#include <vpp-api/client/stat_client.h>

/* Declare message IDs */
#include <vnet/format_fns.h>
#include <mactime/mactime.api_enum.h>
#include <mactime/mactime.api_types.h>

typedef struct
{
  /* device table */
  mactime_device_t *devices;
  uword *device_by_device_name;
  u32 vpp_table_epoch;

  /* time range setup */
  f64 sunday_midnight;
  clib_timebase_t timebase;
  f64 timezone_offset;

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

#if VPP_API_TEST_BUILTIN
extern u8 *format_bytes_with_width (u8 * s, va_list * va);
#else
u8 *
format_bytes_with_width (u8 * s, va_list * va)
{
  uword nbytes = va_arg (*va, u64);
  int width = va_arg (*va, int);
  f64 nbytes_f64;
  u8 *fmt;
  char *suffix = "";

  if (width > 0)
    fmt = format (0, "%%%d.3f%%s%c", width, 0);
  else
    fmt = format (0, "%%.3f%%s%c", 0);

  if (nbytes > (1024ULL * 1024ULL * 1024ULL))
    {
      nbytes_f64 = ((f64) nbytes) / (1024.0 * 1024.0 * 1024.0);
      suffix = "G";
    }
  else if (nbytes > (1024ULL * 1024ULL))
    {
      nbytes_f64 = ((f64) nbytes) / (1024.0 * 1024.0);
      suffix = "M";
    }
  else if (nbytes > 1024ULL)
    {
      nbytes_f64 = ((f64) nbytes) / (1024.0);
      suffix = "K";
    }
  else
    {
      nbytes_f64 = (f64) nbytes;
      suffix = "B";
    }

  s = format (s, (char *) fmt, nbytes_f64, suffix);
  vec_free (fmt);
  return s;
}
#endif

static u8 *
format_device (u8 * s, va_list * args)
{
  mactime_device_t *dp = va_arg (*args, mactime_device_t *);
  mactime_test_main_t *mm = &mactime_test_main;
  int verbose = va_arg (*args, int);
  int current_status = 99;
  char *status_string;
  u8 *macstring = 0;
  f64 now;
  int j;

  if (dp == 0)
    {
      s = format (s, "%-15s %5s %18s %14s %10s %11s %13s",
		  "Device Name", "Index", "Addresses", "Status",
		  "AllowPkt", "AllowByte", "DropPkt");
      vec_add1 (s, '\n');
      return s;
    }

  now = clib_timebase_now (&mm->timebase);

  /* Check dynamic ranges */
  for (j = 0; j < vec_len (dp->ranges); j++)
    {
      clib_timebase_range_t *r = dp->ranges + j;
      f64 start0, end0;

      start0 = r->start + mm->sunday_midnight;
      end0 = r->end + mm->sunday_midnight;
      if (verbose)
	s = format (s, "  Range %d: %U - %U\n", j,
		    format_clib_timebase_time, start0,
		    format_clib_timebase_time, end0);

      if (now >= start0 && now <= end0)
	{
	  if (dp->flags & MACTIME_DEVICE_FLAG_DYNAMIC_ALLOW)
	    current_status = 3;
	  else if (dp->flags & MACTIME_DEVICE_FLAG_DYNAMIC_ALLOW_QUOTA)
	    current_status = 5;
	  else
	    current_status = 2;
	  if (verbose)
	    {
	      s = format (s, "  Time in range %d:", j);
	      s = format (s, "     %U - %U\n",
			  format_clib_timebase_time, start0,
			  format_clib_timebase_time, end0);
	    }
	  goto print;
	}
    }
  if (verbose && j)
    s = format (s, "  No range match.\n");
  if (dp->flags & MACTIME_DEVICE_FLAG_STATIC_DROP)
    current_status = 0;
  if (dp->flags & MACTIME_DEVICE_FLAG_STATIC_ALLOW)
    current_status = 1;
  if (dp->flags & MACTIME_DEVICE_FLAG_DYNAMIC_ALLOW)
    current_status = 2;
  if (dp->flags & MACTIME_DEVICE_FLAG_DYNAMIC_DROP)
    current_status = 3;
  if (dp->flags & MACTIME_DEVICE_FLAG_DYNAMIC_ALLOW_QUOTA)
    current_status = 4;

print:
  macstring = format (0, "%U", format_vl_api_mac_address_t, dp->mac_address);
  switch (current_status)
    {
    case 0:
      status_string = "static drop";
      break;
    case 1:
      status_string = "static allow";
      break;
    case 2:
      status_string = "dynamic drop";
      break;
    case 3:
      status_string = "dynamic allow";
      break;
    case 4:
      status_string = "d-quota inact";
      break;
    case 5:
      status_string = "d-quota activ";
      break;
    default:
      status_string = "code bug!";
      break;
    }

  s = format (s, "%-15s %5d %18s %14s\n",
	      dp->device_name, dp->pool_index, macstring, status_string);
  vec_free (macstring);

  if (dp->data_quota > 0)
    {
      s = format (s, "%-59s %s%U %s%U", " ", "Quota ",
		  format_bytes_with_width, dp->data_quota, 10,
		  "Use ", format_bytes_with_width, dp->data_used_in_range, 8);
      vec_add1 (s, '\n');
    }
  return s;
}

static int
api_mactime_dump (vat_main_t * vam)
{
  mactime_test_main_t *tm = &mactime_test_main;
  unformat_input_t *i = vam->input;
  vl_api_mactime_dump_t *mp;
  int verbose = 0;
  int ret;
  f64 now;
  mactime_device_t *dev;

  now = clib_timebase_now (&tm->timebase);

  if (PREDICT_FALSE ((now - tm->sunday_midnight) > 86400.0 * 7.0))
    tm->sunday_midnight = clib_timebase_find_sunday_midnight (now);

  /* Parse args required to build the message */
  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "force"))
	tm->vpp_table_epoch = 0;
      else if (unformat (i, "verbose"))
	verbose = 1;
      else
	break;
    }

  /* Construct the API message */
  M (MACTIME_DUMP, mp);
  mp->my_table_epoch = clib_host_to_net_u32 (tm->vpp_table_epoch);

  /* send it... */
  S (mp);

  /* Wait for a reply... */
  W (ret);

  fformat (vam->ofp, "%U", format_device, 0 /* header */ , 0 /* verbose */ );
  /* *INDENT-OFF* */
  pool_foreach (dev, tm->devices,
  ({
    fformat (vam->ofp, "%U", format_device, dev, verbose);
  }));
  /* *INDENT-ON* */

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

/* We shouldn't get these... */
static void
vl_api_mactime_details_t_handler (vl_api_mactime_details_t * mp)
{
  clib_warning ("WARNING: stub called...");
}

#include <mactime/mactime.api_test.c>

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
