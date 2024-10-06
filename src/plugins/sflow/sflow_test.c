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
  u32 sw_if_index = ~0;
  vl_api_sflow_enable_disable_t *mp;
  int ret;

  /* Parse args required to build the message */
  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "%U", unformat_sw_if_index, vam, &sw_if_index))
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
  M (SFLOW_ENABLE_DISABLE, mp);
  mp->sw_if_index = ntohl (sw_if_index);
  mp->enable_disable = enable_disable;

  /* send it... */
  S (mp);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

static int
api_sflow_sampling_rate (vat_main_t *vam)
{
  unformat_input_t *i = vam->input;
  u32 sampling_N = ~0;
  vl_api_sflow_sampling_rate_t *mp;
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
  M (SFLOW_SAMPLING_RATE, mp);
  mp->sampling_N = ntohl (sampling_N);

  /* send it... */
  S (mp);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

static int
api_sflow_polling_interval (vat_main_t *vam)
{
  unformat_input_t *i = vam->input;
  u32 polling_S = ~0;
  vl_api_sflow_polling_interval_t *mp;
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
  M (SFLOW_POLLING_INTERVAL, mp);
  mp->polling_S = ntohl (polling_S);

  /* send it... */
  S (mp);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

static int
api_sflow_header_bytes (vat_main_t *vam)
{
  unformat_input_t *i = vam->input;
  u32 header_B = ~0;
  vl_api_sflow_header_bytes_t *mp;
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
  M (SFLOW_HEADER_BYTES, mp);
  mp->header_B = ntohl (header_B);

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
