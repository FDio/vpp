/*
 *------------------------------------------------------------------
 * Copyright (c) 2018 Cisco and/or its affiliates.
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
#include <vlib/pci/pci_types_api.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/format_fns.h>
#include <dpdk/device/dpdk.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>

/* define message IDs */
#include <dpdk/dpdk.api_enum.h>
#include <dpdk/dpdk.api_types.h>

#define REPLY_MSG_ID_BASE (dm->msg_id_base)
#include <vlibapi/api_helper_macros.h>

static void
vl_api_dpdk_create_t_handler (vl_api_dpdk_create_t *mp)
{
  vlib_main_t *vm = vlib_get_main ();
  dpdk_main_t *dm = &dpdk_main;
  vl_api_dpdk_create_reply_t *rmp;
  int rv = 0;
  int i = 0;
  dpdk_create_if_args_t args = {};

  pci_address_decode (&mp->pci_addr, &args.config.pci_addr);
  args.config.num_rx_queues = mp->num_rx_queues;
  args.config.num_tx_queues = mp->num_tx_queues;
  args.config.num_rx_desc = mp->num_rx_desc;
  args.config.num_tx_desc = mp->num_tx_desc;
  args.config.max_lro_pkt_size = mp->max_lro_pkt_size;
  args.config.rss_fn = mp->rss_fn;
  args.config.tso = mp->tso;
  args.config.name = mp->name[0] ? format (0, "%s", mp->name) : 0;
  args.config.tag = mp->tag[0] ? format (0, "%s", mp->tag) : 0;
  args.config.devargs = mp->devargs[0] ? format (0, "%s", mp->devargs) : 0;

  for (i = 0; i < mp->workers_number; i++)
    {
      clib_bitmap_set (args.config.workers, mp->workers[i], 1);
    }

  for (i = 0; i < mp->rss_queues_number; i++)
    {
      clib_bitmap_set (args.config.rss_queues, mp->rss_queues[i], 1);
    }

  rv = dpdk_create_if (vm, &args);

  REPLY_MACRO2_END (VL_API_DPDK_CREATE_REPLY,
		    ({ rmp->sw_if_index = args.sw_if_index; }));
}

static void
vl_api_dpdk_delete_t_handler (vl_api_dpdk_delete_t *mp)
{
  vlib_main_t *vm = vlib_get_main ();
  dpdk_main_t *dm = &dpdk_main;
  vl_api_dpdk_delete_reply_t *rmp;

  int rv = 0;

  rv = dpdk_delete_if (vm, mp->sw_if_index);

  REPLY_MACRO_END (VL_API_DPDK_DELETE_REPLY);
}

/* set tup the API message handling tables */
#include <dpdk/dpdk.api.c>
clib_error_t *
dpdk_plugin_api_hookup (vlib_main_t *vm)
{
  dpdk_main_t *dm = &dpdk_main;

  /* ask for a correctly-sized block of API message decode slots */
  dm->msg_id_base = setup_message_id_table ();
  return 0;
}

VLIB_API_INIT_FUNCTION (dpdk_plugin_api_hookup);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
