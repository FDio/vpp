/*
 *------------------------------------------------------------------
 * Copyright (c) 2020 Cisco and/or its affiliates.
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
 *------------------------------------------------------------------
 */

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vlib/pci/pci.h>
#include <vnet/ethernet/ethernet.h>

#include <vat/vat.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>

#include <vppinfra/error.h>
#include <af_xdp/af_xdp.h>

#define __plugin_msg_base af_xdp_test_main.msg_id_base
#include <vlibapi/vat_helper_macros.h>

/* declare message IDs */
#include <af_xdp/af_xdp.api_enum.h>
#include <af_xdp/af_xdp.api_types.h>

typedef struct
{
  /* API message ID base */
  u16 msg_id_base;
  vat_main_t *vat_main;
} af_xdp_test_main_t;

af_xdp_test_main_t af_xdp_test_main;

static vl_api_af_xdp_mode_t
api_af_xdp_mode (af_xdp_mode_t mode)
{
  switch (mode)
    {
    case AF_XDP_MODE_AUTO:
      return AF_XDP_API_MODE_AUTO;
    case AF_XDP_MODE_COPY:
      return AF_XDP_API_MODE_COPY;
    case AF_XDP_MODE_ZERO_COPY:
      return AF_XDP_API_MODE_ZERO_COPY;
    }
  return ~0;
}

/* af_xdp create API */
static int
api_af_xdp_create (vat_main_t * vam)
{
  vl_api_af_xdp_create_t *mp;
  af_xdp_create_if_args_t args;
  int ret;

  if (!unformat_user (vam->input, unformat_af_xdp_create_if_args, &args))
    {
      clib_warning ("unknown input `%U'", format_unformat_error, vam->input);
      return -99;
    }

  M (AF_XDP_CREATE, mp);

  snprintf ((char *) mp->host_if, sizeof (mp->host_if), "%s",
	    args.linux_ifname ? : "");
  snprintf ((char *) mp->name, sizeof (mp->name), "%s", args.name ? : "");
  mp->rxq_num = clib_host_to_net_u16 (args.rxq_num);
  mp->rxq_size = clib_host_to_net_u16 (args.rxq_size);
  mp->txq_size = clib_host_to_net_u16 (args.txq_size);
  mp->mode = api_af_xdp_mode (args.mode);
  if (args.flags & AF_XDP_CREATE_FLAGS_NO_SYSCALL_LOCK)
    mp->flags |= AF_XDP_API_FLAGS_NO_SYSCALL_LOCK;
  snprintf ((char *) mp->prog, sizeof (mp->prog), "%s", args.prog ? : "");

  S (mp);
  W (ret);

  return ret;
}

/* af_xdp-create reply handler */
static void
vl_api_af_xdp_create_reply_t_handler (vl_api_af_xdp_create_reply_t * mp)
{
  vat_main_t *vam = af_xdp_test_main.vat_main;
  i32 retval = ntohl (mp->retval);

  if (retval == 0)
    {
      fformat (vam->ofp, "created af_xdp with sw_if_index %d\n",
	       ntohl (mp->sw_if_index));
    }

  vam->retval = retval;
  vam->result_ready = 1;
  vam->regenerate_interface_table = 1;
}

/* af_xdp delete API */
static int
api_af_xdp_delete (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_af_xdp_delete_t *mp;
  u32 sw_if_index = 0;
  u8 index_defined = 0;
  int ret;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "sw_if_index %u", &sw_if_index))
	index_defined = 1;
      else
	{
	  clib_warning ("unknown input '%U'", format_unformat_error, i);
	  return -99;
	}
    }

  if (!index_defined)
    {
      errmsg ("missing sw_if_index\n");
      return -99;
    }

  M (AF_XDP_DELETE, mp);

  mp->sw_if_index = clib_host_to_net_u32 (sw_if_index);

  S (mp);
  W (ret);

  return ret;
}

#include <af_xdp/af_xdp.api_test.c>

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
