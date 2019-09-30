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
#include <vnet/ethernet/ethernet.h>

#include <vat/vat.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>

#include <vppinfra/error.h>
#include <vmxnet3/vmxnet3.h>

#define __plugin_msg_base vmxnet3_test_main.msg_id_base
#include <vlibapi/vat_helper_macros.h>

/* declare message IDs */
#include <vmxnet3/vmxnet3.api_enum.h>
#include <vmxnet3/vmxnet3.api_types.h>
#include <vpp/api/vpe.api_types.h>

typedef struct
{
  /* API message ID base */
  u16 msg_id_base;
  u32 ping_id;
  vat_main_t *vat_main;
} vmxnet3_test_main_t;

vmxnet3_test_main_t vmxnet3_test_main;

/* vmxnet3 create API */
static int
api_vmxnet3_create (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_vmxnet3_create_t *mp;
  vmxnet3_create_if_args_t args;
  int ret;
  u32 size;

  clib_memset (&args, 0, sizeof (vmxnet3_create_if_args_t));

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "%U", unformat_vlib_pci_addr, &args.addr))
	;
      else if (unformat (i, "elog"))
	args.enable_elog = 1;
      else if (unformat (i, "bind"))
	args.bind = 1;
      else if (unformat (i, "gso"))
	args.enable_gso = 1;
      else if (unformat (i, "rx-queue-size %u", &size))
	args.rxq_size = size;
      else if (unformat (i, "tx-queue-size %u", &size))
	args.txq_size = size;
      else if (unformat (i, "num-tx-queues %u", &size))
	args.txq_num = size;
      else if (unformat (i, "num-rx-queues %u", &size))
	args.rxq_num = size;
      else
	{
	  clib_warning ("unknown input '%U'", format_unformat_error, i);
	  return -99;
	}
    }

  M (VMXNET3_CREATE, mp);

  mp->pci_addr = clib_host_to_net_u32 (args.addr.as_u32);
  mp->enable_elog = clib_host_to_net_u16 (args.enable_elog);
  mp->rxq_size = clib_host_to_net_u16 (args.rxq_size);
  mp->txq_size = clib_host_to_net_u16 (args.txq_size);
  mp->txq_num = clib_host_to_net_u16 (args.txq_num);
  mp->rxq_num = clib_host_to_net_u16 (args.rxq_num);
  mp->bind = args.bind;
  mp->enable_gso = args.enable_gso;

  S (mp);
  W (ret);

  return ret;
}

/* vmxnet3-create reply handler */
static void
vl_api_vmxnet3_create_reply_t_handler (vl_api_vmxnet3_create_reply_t * mp)
{
  vat_main_t *vam = vmxnet3_test_main.vat_main;
  i32 retval = ntohl (mp->retval);

  if (retval == 0)
    {
      fformat (vam->ofp, "created vmxnet3 with sw_if_index %d\n",
	       ntohl (mp->sw_if_index));
    }

  vam->retval = retval;
  vam->result_ready = 1;
  vam->regenerate_interface_table = 1;
}

/* vmxnet3 delete API */
static int
api_vmxnet3_delete (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_vmxnet3_delete_t *mp;
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

  M (VMXNET3_DELETE, mp);

  mp->sw_if_index = clib_host_to_net_u32 (sw_if_index);

  S (mp);
  W (ret);

  return ret;
}

static int
api_vmxnet3_dump (vat_main_t * vam)
{
  vmxnet3_test_main_t *vxm = &vmxnet3_test_main;
  vl_api_vmxnet3_dump_t *mp;
  vl_api_control_ping_t *mp_ping;
  int ret;

  if (vam->json_output)
    {
      clib_warning ("JSON output not supported for vmxnet3_dump");
      return -99;
    }

  M (VMXNET3_DUMP, mp);
  S (mp);

  /* Use a control ping for synchronization */
  mp_ping = vl_msg_api_alloc_as_if_client (sizeof (*mp_ping));
  mp_ping->_vl_msg_id = htons (vxm->ping_id);
  mp_ping->client_index = vam->my_client_index;

  fformat (vam->ofp, "Sending ping id=%d\n", vxm->ping_id);

  vam->result_ready = 0;
  S (mp_ping);

  W (ret);
  return ret;
}

static u8 *
format_pci_addr (u8 * s, va_list * va)
{
  vlib_pci_addr_t *addr = va_arg (*va, vlib_pci_addr_t *);
  return format (s, "%04x:%02x:%02x.%x", addr->domain, addr->bus,
		 addr->slot, addr->function);
}

static void
vl_api_vmxnet3_details_t_handler (vl_api_vmxnet3_details_t * mp)
{
  vat_main_t *vam = vmxnet3_test_main.vat_main;
  u32 pci_addr = ntohl (mp->pci_addr);
  u16 qid;

  fformat (vam->ofp, "%s: sw_if_index %u mac %U\n"
	   "   version: %u\n"
	   "   PCI Address: %U\n"
	   "   state %s\n",
	   mp->if_name, ntohl (mp->sw_if_index), format_ethernet_address,
	   mp->hw_addr, mp->version,
	   format_pci_addr, &pci_addr, mp->admin_up_down ? "up" : "down");
  for (qid = 0; qid < mp->rx_count; qid++)
    {
      vl_api_vmxnet3_rx_list_t *rx_list = &mp->rx_list[qid];
      fformat (vam->ofp,
	       "   RX Queue %u\n"
	       "     RX completion next index %u\n"
	       "     ring 0 size %u fill %u consume %u produce %u\n"
	       "     ring 1 size %u fill %u consume %u produce %u\n",
	       qid,
	       ntohs (rx_list->rx_next),
	       ntohs (rx_list->rx_qsize), ntohs (rx_list->rx_fill[0]),
	       ntohs (rx_list->rx_consume[0]),
	       ntohs (rx_list->rx_produce[0]),
	       ntohs (rx_list->rx_qsize), ntohs (rx_list->rx_fill[1]),
	       ntohs (rx_list->rx_consume[1]),
	       ntohs (rx_list->rx_produce[1]));
    }
  for (qid = 0; qid < mp->tx_count; qid++)
    {
      vl_api_vmxnet3_tx_list_t *tx_list = &mp->tx_list[qid];
      fformat (vam->ofp,
	       "   TX Queue %u\n"
	       "     TX completion next index %u\n"
	       "     size %u consume %u produce %u\n",
	       qid,
	       ntohs (tx_list->tx_next),
	       ntohs (tx_list->tx_qsize), ntohs (tx_list->tx_consume),
	       ntohs (tx_list->tx_produce));
    }
}

#include <vmxnet3/vmxnet3.api_test.c>

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
