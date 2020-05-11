/*
 * pkt_trace_test.c - skeleton vpp-api-test plug-in
 *
 * Copyright (c) 2020 cisco
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
#include <vpp-api/client/stat_client.h>

#define __plugin_msg_base pkt_trace_test_main.msg_id_base
#include <vlibapi/vat_helper_macros.h>

/* Declare message IDs */
#include <vnet/format_fns.h>
#include <vnet/pkt_trace.api_enum.h>
#include <vnet/pkt_trace.api_types.h>
#include <vpp/api/vpe.api_types.h>

typedef struct
{
  /* API message ID base */
  u16 msg_id_base;
  u32 ping_id;
  vat_main_t *vat_main;
} pkt_trace_test_main_t;

pkt_trace_test_main_t pkt_trace_test_main;

int
api_pkt_trace_set_filters (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_pkt_trace_set_filters_t *mp;
  u32 flag;
  u32 count;
  u32 node_index;
  u32 classifier;

  flag = TRACE_FF_NONE;
  count = 50;
  node_index = ~0;
  classifier = ~0;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "none"))
	flag = TRACE_FF_NONE;
      else if (unformat (i, "include_node %u", &node_index))
	flag = TRACE_FF_INCLUDE_NODE;
      else if (unformat (i, "exclude_node %u", &node_index))
	flag = TRACE_FF_EXCLUDE_NODE;
      else if (unformat (i, "include_classifier %u", &classifier))
	flag = TRACE_FF_INCLUDE_CLASSIFIER;
      else if (unformat (i, "exclude_classifier %u", &classifier))
	flag = TRACE_FF_EXCLUDE_CLASSIFIER;
      else if (unformat (i, "count %u", &count))
	;
      else
	{
	  clib_warning ("Unknown input: %U\n", format_unformat_error, i);
	  return -99;
	}
    }

  M (PKT_TRACE_SET_FILTERS, mp);
  mp->flag = htonl (flag);
  mp->node_index = htonl (node_index);
  mp->count = htonl (count);
  mp->classifier_table_index = htonl (classifier);

  int ret = 0;
  S (mp);
  W (ret);

  return ret;
}


int
api_pkt_trace_capture_packets (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_pkt_trace_capture_packets_t *mp;
  u32 node_index;
  u32 max;
  bool pre_capture_clear;
  bool use_filter;
  bool verbose;

  node_index = ~0;
  max = 50;
  pre_capture_clear = use_filter = verbose = false;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "node_index %u", &node_index))
	;
      else if (unformat (i, "max %u", &max))
	;
      else if (unformat (i, "pre_capture_clear"))
	pre_capture_clear = false;
      else if (unformat (i, "use_filter"))
	use_filter = false;
      else if (unformat (i, "verbose"))
	verbose = false;
      else
	{
	  clib_warning ("Unknown input: %U\n", format_unformat_error, i);
	  return -99;
	}
    }

  M (PKT_TRACE_CAPTURE_PACKETS, mp);
  mp->node_index = htonl (node_index);
  mp->max_packets = htonl (max);
  mp->use_filter = use_filter;
  mp->verbose = verbose;
  mp->pre_capture_clear = pre_capture_clear;

  int ret = 0;
  S (mp);
  W (ret);

  return ret;
}


int
api_pkt_trace_capture_dump (vat_main_t * vam)
{
  pkt_trace_test_main_t *pm = &pkt_trace_test_main;
  unformat_input_t *i = vam->input;
  vl_api_pkt_trace_capture_dump_t *mp;
  vl_api_control_ping_t *mp_ping;
  u32 max;

  max = 50;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "max %u", &max))
	;
      else
	{
	  clib_warning ("Unknown input: %U\n", format_unformat_error, i);
	  return -99;
	}
    }

  M (PKT_TRACE_CAPTURE_DUMP, mp);
  mp->max_packets_dumped = htonl (max);

  int ret = 0;
  S (mp);

  /* Use a control ping for synchronization */
  if (!pm->ping_id)
    pm->ping_id = vl_msg_api_get_msg_index ((u8 *) (VL_API_CONTROL_PING_CRC));
  mp_ping = vl_msg_api_alloc_as_if_client (sizeof (*mp_ping));
  mp_ping->_vl_msg_id = htons (pm->ping_id);
  mp_ping->client_index = vam->my_client_index;

  S (mp_ping);
  W (ret);

  return ret;
}


void
  vl_api_pkt_trace_capture_details_t_handler
  (vl_api_pkt_trace_capture_details_t * mp)
{
  vat_main_t *vam = &vat_main;

  fformat (vam->ofp,
	   "\nNumber: %d  Thread: %d  Size: %d\n%s\n",
	   ntohl (mp->packet_number),
	   ntohl (mp->thread_id), ntohl (mp->log_size), mp->packet_log.buf);
}


void
  vl_api_pkt_trace_capture_details_t_handler_json
  (vl_api_pkt_trace_capture_details_t * mp)
{
  clib_error ("pkt_trace_capture_details JSON not supported");
}


int
api_pkt_trace_clear_packets (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_pkt_trace_clear_packets_t *mp;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      clib_error ("Unexpected input: %U\n", format_unformat_error, i);
      return -99;
    }

  M (PKT_TRACE_CLEAR_PACKETS, mp);

  int ret = 0;
  S (mp);
  W (ret);

  return ret;
}

/* Override generated plugin register symbol */
#define vat_plugin_register pkt_trace_test_vat_plugin_register
#include <vnet/pkt_trace.api_test.c>

#if VPP_API_TEST_BUILTIN
static clib_error_t *
pkt_trace_api_hookup_shim (vlib_main_t * vm)
{
  pkt_trace_test_vat_plugin_register (&vat_main);
  return 0;
}

VLIB_API_INIT_FUNCTION (pkt_trace_api_hookup_shim);
#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
