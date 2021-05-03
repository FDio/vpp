/*
 *------------------------------------------------------------------
 * Copyright (c) 2019 Cisco and/or its affiliates.
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
#include <rdma/rdma.h>

#define __plugin_msg_base rdma_test_main.msg_id_base
#include <vlibapi/vat_helper_macros.h>

/* declare message IDs */
#include <rdma/rdma.api_enum.h>
#include <rdma/rdma.api_types.h>

typedef struct
{
  /* API message ID base */
  u16 msg_id_base;
  vat_main_t *vat_main;
} rdma_test_main_t;

rdma_test_main_t rdma_test_main;

static vl_api_rdma_mode_t
api_rdma_mode (rdma_mode_t mode)
{
  switch (mode)
    {
    case RDMA_MODE_AUTO:
      return RDMA_API_MODE_AUTO;
    case RDMA_MODE_IBV:
      return RDMA_API_MODE_IBV;
    case RDMA_MODE_DV:
      return RDMA_API_MODE_DV;
    }
  return ~0;
}

static vl_api_rdma_rss4_t
api_rdma_rss4 (rdma_rss4_t rss4)
{
  switch (rss4)
    {
    case RDMA_RSS4_AUTO:
      return RDMA_API_RSS4_AUTO;
    case RDMA_RSS4_IP:
      return RDMA_API_RSS4_IP;
    case RDMA_RSS4_IP_UDP:
      return RDMA_API_RSS4_IP_UDP;
    case RDMA_RSS4_IP_TCP:
      return RDMA_API_RSS4_IP_TCP;
    }
  return ~0;
}

static vl_api_rdma_rss6_t
api_rdma_rss6 (rdma_rss6_t rss6)
{
  switch (rss6)
    {
    case RDMA_RSS6_AUTO:
      return RDMA_API_RSS6_AUTO;
    case RDMA_RSS6_IP:
      return RDMA_API_RSS6_IP;
    case RDMA_RSS6_IP_UDP:
      return RDMA_API_RSS6_IP_UDP;
    case RDMA_RSS6_IP_TCP:
      return RDMA_API_RSS6_IP_TCP;
    }
  return ~0;
}

/* rdma create API */
static int
api_rdma_create (vat_main_t * vam)
{
  vl_api_rdma_create_t *mp;
  rdma_create_if_args_t args;
  int ret;

  if (!unformat_user (vam->input, unformat_rdma_create_if_args, &args))
    {
      clib_warning ("unknown input `%U'", format_unformat_error, vam->input);
      return -99;
    }

  M (RDMA_CREATE, mp);

  snprintf ((char *) mp->host_if, sizeof (mp->host_if), "%s", args.ifname);
  snprintf ((char *) mp->name, sizeof (mp->name), "%s", args.name);
  mp->rxq_num = clib_host_to_net_u16 (args.rxq_num);
  mp->rxq_size = clib_host_to_net_u16 (args.rxq_size);
  mp->txq_size = clib_host_to_net_u16 (args.txq_size);
  mp->mode = api_rdma_mode (args.mode);

  S (mp);
  W (ret);

  return ret;
}

static int
api_rdma_create_v2 (vat_main_t * vam)
{
  vl_api_rdma_create_v2_t *mp;
  rdma_create_if_args_t args;
  int ret;

  if (!unformat_user (vam->input, unformat_rdma_create_if_args, &args))
    {
      clib_warning ("unknown input `%U'", format_unformat_error, vam->input);
      return -99;
    }

  M (RDMA_CREATE_V2, mp);

  snprintf ((char *) mp->host_if, sizeof (mp->host_if), "%s", args.ifname);
  if (args.name)
    snprintf ((char *) mp->name, sizeof (mp->name), "%s", args.name);
  else
    mp->name[0] = 0;
  mp->rxq_num = clib_host_to_net_u16 (args.rxq_num);
  mp->rxq_size = clib_host_to_net_u16 (args.rxq_size);
  mp->txq_size = clib_host_to_net_u16 (args.txq_size);
  mp->mode = api_rdma_mode (args.mode);
  mp->no_multi_seg = args.no_multi_seg;
  mp->max_pktlen = clib_host_to_net_u16 (args.max_pktlen);

  S (mp);
  W (ret);

  return ret;
}

static int
api_rdma_create_v3 (vat_main_t *vam)
{
  vl_api_rdma_create_v3_t *mp;
  rdma_create_if_args_t args;
  int ret;

  if (!unformat_user (vam->input, unformat_rdma_create_if_args, &args))
    {
      clib_warning ("unknown input `%U'", format_unformat_error, vam->input);
      return -99;
    }

  M (RDMA_CREATE_V3, mp);

  snprintf ((char *) mp->host_if, sizeof (mp->host_if), "%s", args.ifname);
  if (args.name)
    snprintf ((char *) mp->name, sizeof (mp->name), "%s", args.name);
  else
    mp->name[0] = 0;
  mp->rxq_num = clib_host_to_net_u16 (args.rxq_num);
  mp->rxq_size = clib_host_to_net_u16 (args.rxq_size);
  mp->txq_size = clib_host_to_net_u16 (args.txq_size);
  mp->mode = api_rdma_mode (args.mode);
  mp->no_multi_seg = args.no_multi_seg;
  mp->max_pktlen = clib_host_to_net_u16 (args.max_pktlen);
  mp->rss4 = api_rdma_rss4 (args.rss4);
  mp->rss6 = api_rdma_rss6 (args.rss6);

  S (mp);
  W (ret);

  return ret;
}

/* rdma-create reply handler */
static void
vl_api_rdma_create_reply_t_handler (vl_api_rdma_create_reply_t * mp)
{
  vat_main_t *vam = rdma_test_main.vat_main;
  i32 retval = ntohl (mp->retval);

  if (retval == 0)
    {
      fformat (vam->ofp, "created rdma with sw_if_index %d\n",
	       ntohl (mp->sw_if_index));
    }

  vam->retval = retval;
  vam->result_ready = 1;
  vam->regenerate_interface_table = 1;
}

/* rdma-create reply handler */
static void
vl_api_rdma_create_v2_reply_t_handler (vl_api_rdma_create_v2_reply_t * mp)
{
  vat_main_t *vam = rdma_test_main.vat_main;
  i32 retval = ntohl (mp->retval);

  if (retval == 0)
    {
      fformat (vam->ofp, "created rdma with sw_if_index %d\n",
	       ntohl (mp->sw_if_index));
    }

  vam->retval = retval;
  vam->result_ready = 1;
  vam->regenerate_interface_table = 1;
}

/* rdma-create reply handler v3 */
static void
vl_api_rdma_create_v3_reply_t_handler (vl_api_rdma_create_v3_reply_t *mp)
{
  vat_main_t *vam = rdma_test_main.vat_main;
  i32 retval = ntohl (mp->retval);

  if (retval == 0)
    {
      fformat (vam->ofp, "created rdma with sw_if_index %d\n",
	       ntohl (mp->sw_if_index));
    }

  vam->retval = retval;
  vam->result_ready = 1;
  vam->regenerate_interface_table = 1;
}

/* rdma delete API */
static int
api_rdma_delete (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_rdma_delete_t *mp;
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

  M (RDMA_DELETE, mp);

  mp->sw_if_index = clib_host_to_net_u32 (sw_if_index);

  S (mp);
  W (ret);

  return ret;
}

#include <rdma/rdma.api_test.c>

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
