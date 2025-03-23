/*
 * Copyright (c) 2024 InMon Corp.
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
#include <stdbool.h>

#define __plugin_msg_base sflow_test_main.msg_id_base
#include <vlibapi/vat_helper_macros.h>

uword unformat_sw_if_index (unformat_input_t *input, va_list *args);

/* Declare message IDs */
#include <sflow/sflow.api_enum.h>
#include <sflow/sflow.api_types.h>

/* for token names */
#include <sflow/sflow_common.h>

typedef struct
{
  /* API message ID base */
  u16 msg_id_base;
  vat_main_t *vat_main;
} sflow_test_main_t;

sflow_test_main_t sflow_test_main;

static int
api_sflow_enable_disable (vat_main_t *vam)
{
  unformat_input_t *i = vam->input;
  int enable_disable = 1;
  u32 hw_if_index = ~0;
  vl_api_sflow_enable_disable_t *mp;
  int ret;

  /* Parse args required to build the message */
  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "%U", unformat_sw_if_index, vam, &hw_if_index))
	;
      else if (unformat (i, "disable"))
	enable_disable = 0;
      else if (unformat (i, "enable"))
	enable_disable = 1;
      else
	break;
    }

  if (hw_if_index == ~0)
    {
      errmsg ("missing interface name / explicit hw_if_index number \n");
      return -99;
    }

  /* Construct the API message */
  M (SFLOW_ENABLE_DISABLE, mp);
  mp->hw_if_index = ntohl (hw_if_index);
  mp->enable_disable = enable_disable;

  /* send it... */
  S (mp);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

static void
vl_api_sflow_sampling_rate_get_reply_t_handler (
  vl_api_sflow_sampling_rate_get_reply_t *mp)
{
  vat_main_t *vam = sflow_test_main.vat_main;
  clib_warning ("sflow sampling_N: %d", ntohl (mp->sampling_N));
  vam->result_ready = 1;
}

static int
api_sflow_sampling_rate_get (vat_main_t *vam)
{
  vl_api_sflow_sampling_rate_get_t *mp;
  int ret;

  /* Construct the API message */
  M (SFLOW_SAMPLING_RATE_GET, mp);

  /* send it... */
  S (mp);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

static int
api_sflow_sampling_rate_set (vat_main_t *vam)
{
  unformat_input_t *i = vam->input;
  u32 sampling_N = ~0;
  vl_api_sflow_sampling_rate_set_t *mp;
  int ret;

  /* Parse args required to build the message */
  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "sampling_N %d", &sampling_N))
	;
      else
	break;
    }

  if (sampling_N == ~0)
    {
      errmsg ("missing sampling_N number \n");
      return -99;
    }

  /* Construct the API message */
  M (SFLOW_SAMPLING_RATE_SET, mp);
  mp->sampling_N = ntohl (sampling_N);

  /* send it... */
  S (mp);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

static void
vl_api_sflow_polling_interval_get_reply_t_handler (
  vl_api_sflow_polling_interval_get_reply_t *mp)
{
  vat_main_t *vam = sflow_test_main.vat_main;
  clib_warning ("sflow polling-interval: %d", ntohl (mp->polling_S));
  vam->result_ready = 1;
}

static int
api_sflow_polling_interval_get (vat_main_t *vam)
{
  vl_api_sflow_polling_interval_get_t *mp;
  int ret;

  /* Construct the API message */
  M (SFLOW_POLLING_INTERVAL_GET, mp);

  /* send it... */
  S (mp);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

static int
api_sflow_polling_interval_set (vat_main_t *vam)
{
  unformat_input_t *i = vam->input;
  u32 polling_S = ~0;
  vl_api_sflow_polling_interval_set_t *mp;
  int ret;

  /* Parse args required to build the message */
  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "polling_S %d", &polling_S))
	;
      else
	break;
    }

  if (polling_S == ~0)
    {
      errmsg ("missing polling_S number \n");
      return -99;
    }

  /* Construct the API message */
  M (SFLOW_POLLING_INTERVAL_SET, mp);
  mp->polling_S = ntohl (polling_S);

  /* send it... */
  S (mp);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

static void
vl_api_sflow_header_bytes_get_reply_t_handler (
  vl_api_sflow_header_bytes_get_reply_t *mp)
{
  vat_main_t *vam = sflow_test_main.vat_main;
  clib_warning ("sflow header-bytes: %d", ntohl (mp->header_B));
  vam->result_ready = 1;
}

static int
api_sflow_header_bytes_get (vat_main_t *vam)
{
  vl_api_sflow_header_bytes_get_t *mp;
  int ret;

  /* Construct the API message */
  M (SFLOW_HEADER_BYTES_GET, mp);

  /* send it... */
  S (mp);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

static int
api_sflow_header_bytes_set (vat_main_t *vam)
{
  unformat_input_t *i = vam->input;
  u32 header_B = ~0;
  vl_api_sflow_header_bytes_set_t *mp;
  int ret;

  /* Parse args required to build the message */
  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "header_B %d", &header_B))
	;
      else
	break;
    }

  if (header_B == ~0)
    {
      errmsg ("missing header_B number \n");
      return -99;
    }

  /* Construct the API message */
  M (SFLOW_HEADER_BYTES_SET, mp);
  mp->header_B = ntohl (header_B);

  /* send it... */
  S (mp);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

static void
vl_api_sflow_direction_get_reply_t_handler (
  vl_api_sflow_direction_get_reply_t *mp)
{
  vat_main_t *vam = sflow_test_main.vat_main;
  clib_warning ("sflow direction: %d", ntohl (mp->sampling_D));
  vam->result_ready = 1;
}

static int
api_sflow_direction_get (vat_main_t *vam)
{
  vl_api_sflow_direction_get_t *mp;
  int ret;

  /* Construct the API message */
  M (SFLOW_DIRECTION_GET, mp);

  /* send it... */
  S (mp);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

static int
api_sflow_direction_set (vat_main_t *vam)
{
  unformat_input_t *i = vam->input;
  u32 sampling_D = ~0;
  vl_api_sflow_direction_set_t *mp;
  int ret;

  /* Parse args required to build the message */
  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "sampling_D rx"))
	sampling_D = SFLOW_DIRN_INGRESS;
      else if (unformat (i, "sampling_D tx"))
	sampling_D = SFLOW_DIRN_INGRESS;
      else if (unformat (i, "sampling_D both"))
	sampling_D = SFLOW_DIRN_BOTH;
      else
	break;
    }

  if (sampling_D == ~0)
    {
      errmsg ("missing sampling_D direction\n");
      return -99;
    }

  /* Construct the API message */
  M (SFLOW_DIRECTION_SET, mp);
  mp->sampling_D = ntohl (sampling_D);

  /* send it... */
  S (mp);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

static void
vl_api_sflow_drop_monitoring_get_reply_t_handler (
  vl_api_sflow_drop_monitoring_get_reply_t *mp)
{
  vat_main_t *vam = sflow_test_main.vat_main;
  clib_warning ("sflow drop-monitoring: %d", ntohl (mp->drop_M));
  vam->result_ready = 1;
}

static int
api_sflow_drop_monitoring_get (vat_main_t *vam)
{
  vl_api_sflow_drop_monitoring_get_t *mp;
  int ret;

  /* Construct the API message */
  M (SFLOW_DROP_MONITORING_GET, mp);

  /* send it... */
  S (mp);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

static int
api_sflow_drop_monitoring_set (vat_main_t *vam)
{
  unformat_input_t *i = vam->input;
  u32 drop_M = 1;
  vl_api_sflow_drop_monitoring_set_t *mp;
  int ret;

  /* Parse args required to build the message */
  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "drop_M disable"))
	drop_M = 0;
      if (unformat (i, "drop_M enable"))
	drop_M = 1;
    }

  /* Construct the API message */
  M (SFLOW_DROP_MONITORING_SET, mp);
  mp->drop_M = ntohl (drop_M);

  /* send it... */
  S (mp);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

static void
vl_api_sflow_interface_details_t_handler (vl_api_sflow_interface_details_t *mp)
{
  vat_main_t *vam = sflow_test_main.vat_main;
  clib_warning ("sflow enable: %d", ntohl (mp->hw_if_index));
  vam->result_ready = 1;
}

static int
api_sflow_interface_dump (vat_main_t *vam)
{
  vl_api_sflow_interface_dump_t *mp;
  int ret;

  /* Construct the API message */
  M (SFLOW_INTERFACE_DUMP, mp);

  /* send it... */
  S (mp);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

/*
 * List of messages that the sflow test plugin sends,
 * and that the data plane plugin processes
 */
#include <sflow/sflow.api_test.c>

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
