/*
 * Copyright (c) 2023 Cisco and/or its affiliates.
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
#include <vnet/api_errno.h>
#include <stdbool.h>

#define __plugin_msg_base tracenode_test_main.msg_id_base
#include <vlibapi/vat_helper_macros.h>

/* Declare message IDs */
#include <tracenode/tracenode.api_enum.h>
#include <tracenode/tracenode.api_types.h>

typedef struct
{
  /* API message ID base */
  u16 msg_id_base;
  vat_main_t *vat_main;
} tracenode_test_main_t;

tracenode_test_main_t tracenode_test_main;

int
api_tracenode_feature (vat_main_t *vam)
{
  unformat_input_t *i = vam->input;
  vl_api_tracenode_feature_t *mp;
  u32 sw_if_index;
  bool is_pcap, enable;

  sw_if_index = ~0;
  is_pcap = false;
  enable = true;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "disable"))
	enable = 0;
      else if (unformat (i, "pcap"))
	is_pcap = 1;
      else if (unformat (i, "%U", unformat_vnet_sw_interface, vnet_get_main (),
			 &sw_if_index))
	{
	  if (sw_if_index == 0)
	    {
	      clib_warning ("Local interface not supported...");
	      return -99;
	    }
	}

      else
	{
	  clib_warning ("Unknown input: %U\n", format_unformat_error, i);
	  return -99;
	}
    }

  M (TRACENODE_FEATURE, mp);
  mp->sw_if_index = htonl (sw_if_index);
  mp->is_pcap = is_pcap;
  mp->enable = enable;

  int ret = 0;
  S (mp);
  W (ret);

  return ret;
}

#include <tracenode/tracenode.api_test.c>

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
