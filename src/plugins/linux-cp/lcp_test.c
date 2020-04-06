/* Hey Emacs use -*- mode: C -*- */
/*
 * Copyright 2020 Rubicon Communications, LLC.
 * 
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

#include <sys/socket.h>
#include <linux/if.h>

#include <vat/vat.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vppinfra/error.h>

#include <vpp/api/types.h>

typedef struct
{
  u16 msg_id_base;
  u32 ping_id;
  vat_main_t *vat_main;
} lcp_test_main_t;

lcp_test_main_t lcp_test_main;

#define __plugin_msg_base lcp_test_main.msg_id_base
#include <vlibapi/vat_helper_macros.h>

/* Declare message IDs */
#include <vnet/format_fns.h>
#include <linux-cp/lcp.api_enum.h>
#include <linux-cp/lcp.api_types.h>
#include <vpp/api/vpe.api_types.h>


uword unformat_sw_if_index (unformat_input_t * input, va_list * args);


static int
api_lcp_itf_pair_add_del (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_lcp_itf_pair_add_del_t *mp;
  u8 is_add, is_del;
  u32 phy_sw_if_index;
  u8 *tap_name;
  int ret;

  is_add = is_del = 0;
  tap_name = 0;
  phy_sw_if_index = ~0;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "phy %U", unformat_sw_if_index, vam, &phy_sw_if_index))
        ;
      else if (unformat (i, "sw_if_index %d", &phy_sw_if_index))
        ;
      else if (unformat (i, "tap %s", &tap_name))
        ;
      else if (unformat (i, "add"))
        is_add = 1;
      else if (unformat (i, "del"))
        is_del = 1;
      else
        {
          clib_warning ("parse error '%U'", format_unformat_error, i);
          return -99;
        }
    }

  if (phy_sw_if_index == ~0)
    {
      errmsg ("PHY sw_if_index not set");
      vec_free (tap_name);
      return -99;
    }

  if (tap_name == 0)
    {
      errmsg ("tap name  not set");
      vec_free (tap_name);
      return -99;
    }

  if (is_add == is_del)
    {
      errmsg ("One of add or del must be specified");
      vec_free (tap_name);
      return -99;
    }

  M (LCP_ITF_PAIR_ADD_DEL, mp);

  mp->is_add = is_add;
  mp->sw_if_index = ntohl (phy_sw_if_index);
  clib_memcpy (mp->host_if_name, tap_name,
	       clib_strnlen((char *) tap_name, IFNAMSIZ - 1));
  vec_free (tap_name);

  S (mp);
  W (ret);

  return ret;
}


static int
api_lcp_itf_pair_dump (vat_main_t *vam)
{
  lcp_test_main_t *lcptm = &lcp_test_main;
  unformat_input_t *i = vam->input;
  vl_api_lcp_itf_pair_dump_t *mp;
  vl_api_control_ping_t *mp_ping;
  u32 sw_if_index;
  int ret;

  if (vam->json_output)
    {
      clib_warning ("JSON output not supported for lcp_itf_pair_dump");
      return -99;
    }

  sw_if_index = ~0;
  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "%U", unformat_sw_if_index, vam, &sw_if_index))
        ;
      else if (unformat (i, "sw_if_index %u", &sw_if_index))
        ;
      else
        break;
    }

  M (LCP_ITF_PAIR_DUMP, mp);

  mp->sw_if_index = htonl (sw_if_index);

  S (mp);

  if (!lcptm->ping_id)
    {
      lcptm->ping_id =
	vl_msg_api_get_msg_index ((u8 *) (VL_API_CONTROL_PING_CRC));
    }

  mp_ping = vl_msg_api_alloc_as_if_client (sizeof (*mp_ping));
  mp_ping->_vl_msg_id = htons (lcptm->ping_id);
  mp_ping->client_index = vam->my_client_index;

  vam->result_ready = 0;
  S (mp_ping);

  W (ret);

  return ret;
}


static void
vl_api_lcp_itf_pair_details_t_handler (vl_api_lcp_itf_pair_details_t *mp)
{
  vat_main_t *vam = lcp_test_main.vat_main;

  fformat (vam->ofp,
	   "phy sw_if_index %u host_sw_if_index %u vif_index %u\n",
	   ntohl (mp->phy_sw_if_index),
	   ntohl (mp->host_sw_if_index),
	   (char *) mp->host_tap_name,
	   ntohl (mp->vif_index));
}


#include <linux-cp/lcp.api_test.c>

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
