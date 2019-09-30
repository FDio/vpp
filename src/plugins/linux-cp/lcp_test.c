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

#include <plugins/linux-cp/lcp_interface.h>


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
  u8 is_add, is_del, is_tun;
  u32 phy_sw_if_index;
  u8 *host_if_name;
  u8 *ns;
  int ret;

  is_add = is_del = is_tun = 0;
  host_if_name = ns = 0;
  phy_sw_if_index = ~0;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "phy %U", unformat_sw_if_index, vam, &phy_sw_if_index))
	;
      else if (unformat (i, "sw_if_index %d", &phy_sw_if_index))
	;
      else if (unformat (i, "host_if %s", &host_if_name))
	;
      else if (unformat (i, "tun"))
	is_tun = 1;
      else if (unformat (i, "netns %s", &ns))
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
      vec_free (host_if_name);
      return -99;
    }

  if (host_if_name == 0)
    {
      errmsg ("host interface name not set");
      return -99;
    }

  if (is_add == is_del)
    {
      errmsg ("One of add or del must be specified");
      vec_free (host_if_name);
      return -99;
    }

  M (LCP_ITF_PAIR_ADD_DEL, mp);

  mp->is_add = is_add;
  mp->sw_if_index = ntohl (phy_sw_if_index);
  clib_memcpy (mp->host_if_name, host_if_name,
	       clib_strnlen ((char *) host_if_name, IFNAMSIZ - 1));
  mp->host_if_type = (is_tun) ? LCP_API_ITF_HOST_TUN : LCP_API_ITF_HOST_TAP;

  if (ns)
    clib_memcpy (mp->namespace, ns,
		 clib_strnlen ((char *) ns, LCP_NS_LEN - 1));

  vec_free (ns);
  vec_free (host_if_name);

  S (mp);
  W (ret);

  return ret;
}


static int
api_lcp_itf_pair_dump (vat_main_t * vam)
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
vl_api_lcp_itf_pair_details_t_handler (vl_api_lcp_itf_pair_details_t * mp)
{
  vat_main_t *vam = lcp_test_main.vat_main;

  fformat (vam->ofp,
	   "phy sw_if_index %u host_sw_if_index %u host_if_name %s "
	   "host_if_type %s vif_index %u netns %s\n",
	   ntohl (mp->phy_sw_if_index),
	   ntohl (mp->host_sw_if_index),
	   (char *) mp->host_if_name,
	   (mp->host_if_type == LCP_API_ITF_HOST_TUN) ? "tun" : "tap",
	   ntohl (mp->vif_index),
	   mp->namespace[0] ? (char *) mp->namespace : "<none>");
}


static int
api_lcp_default_ns_set (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_lcp_default_ns_set_t *mp;
  u8 *ns;
  int ret;

  if (vam->json_output)
    {
      clib_warning ("JSON output not supported for lcp_default_ns_set");
      return -99;
    }

  ns = 0;
  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "%s", &ns))
	;
      else
	break;
    }

  M (LCP_DEFAULT_NS_SET, mp);

  if (ns)
    {
      int len = clib_strnlen ((char *) ns, LCP_NS_LEN);
      if (len >= LCP_NS_LEN)
	{
	  clib_warning ("lcp_default_ns_set netns needs fewer than %d chars",
			LCP_NS_LEN);
	  return -99;
	}
      clib_strncpy ((char *) mp->namespace,
		    (char *) ns, sizeof (mp->namespace));
    }

  S (mp);
  W (ret);

  return ret;
}


static int
  vl_api_lcp_default_ns_get_reply_t_handler
  (vl_api_lcp_default_ns_get_reply_t * mp)
{
  vat_main_t *vam = lcp_test_main.vat_main;

  if (mp->namespace[0] == 0)
    fformat (vam->ofp, "default netns ''\n");
  else
    fformat (vam->ofp, "default netns '%s'\n", (char *) mp->namespace);

  return 0;
}


static int
api_lcp_default_ns_get (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_lcp_default_ns_get_t *mp;
  int ret;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
    }

  M (LCP_DEFAULT_NS_GET, mp);

  S (mp);
  W (ret);

  return ret;
}


#include <linux-cp/lcp.api_test.c>

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
