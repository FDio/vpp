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
#include <vmxnet3/vmxnet3_msg_enum.h>

/* Get CRC codes of the messages defined outside of this plugin */
#define vl_msg_name_crc_list
#include <vpp/api/vpe_all_api_h.h>
#undef vl_msg_name_crc_list

/* define message structures */
#define vl_typedefs
#include <vpp/api/vpe_all_api_h.h>
#include <vmxnet3/vmxnet3_all_api_h.h>
#undef vl_typedefs

/* declare message handlers for each api */
#define vl_endianfun
#include <vmxnet3/vmxnet3_all_api_h.h>
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...)
#define vl_printfun
#include <vmxnet3/vmxnet3_all_api_h.h>
#undef vl_printfun

/* get API version number */
#define vl_api_version(n,v) static u32 api_version=(v);
#include <vmxnet3/vmxnet3_all_api_h.h>
#undef vp_api_version

typedef struct
{
  /* API message ID base */
  u16 msg_id_base;
  u32 ping_id;
  vat_main_t *vat_main;
} vmxnet3_test_main_t;

vmxnet3_test_main_t vmxnet3_test_main;

#define foreach_standard_reply_retval_handler		\
_(vmxnet3_delete_reply)

#define _(n)                                            \
    static void vl_api_##n##_t_handler                  \
    (vl_api_##n##_t * mp)                               \
    {                                                   \
        vat_main_t * vam = vmxnet3_test_main.vat_main; 	\
        i32 retval = ntohl(mp->retval);                 \
        if (vam->async_mode) {                          \
            vam->async_errors += (retval < 0);          \
        } else {                                        \
            vam->retval = retval;                       \
            vam->result_ready = 1;                      \
        }                                               \
    }
foreach_standard_reply_retval_handler;
#undef _

#define foreach_vpe_api_reply_msg			\
_(VMXNET3_CREATE_REPLY, vmxnet3_create_reply)		\
_(VMXNET3_DELETE_REPLY, vmxnet3_delete_reply)           \
_(VMXNET3_DETAILS, vmxnet3_details)

/* vmxnet3 create API */
static int
api_vmxnet3_create (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_vmxnet3_create_t *mp;
  vmxnet3_create_if_args_t args;
  int ret;
  u32 x[4];

  memset (&args, 0, sizeof (vmxnet3_create_if_args_t));

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "%x:%x:%x.%x", &x[0], &x[1], &x[2], &x[3]))
	{
	  args.addr.domain = x[0];
	  args.addr.bus = x[1];
	  args.addr.slot = x[2];
	  args.addr.function = x[3];
	}
      else if (unformat (i, "elog"))
	args.enable_elog = 1;
      else if (unformat (i, "rx-queue-size %u", &args.rxq_size))
	;
      else if (unformat (i, "tx-queue-size %u", &args.txq_size))
	;
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

  fformat (vam->ofp, "%s: sw_if_index %u mac %U\n"
	   "   version: %u\n"
	   "   PCI Address: %U\n"
	   "   RX completion next index %u"
	   "   RX Queue %u\n"
	   "    ring 0 size %u fill %u consume %u produce %u\n"
	   "    ring 1 size %u fill %u consume %u produce %u\n"
	   "   TX completion next index %u"
	   "   TX Queue %u\n"
	   "    size %u consume %u produce %u\n"
	   "   state %s\n",
	   mp->if_name, ntohl (mp->sw_if_index), format_ethernet_address,
	   mp->hw_addr, mp->version,
	   format_pci_addr, &pci_addr,
	   ntohs (mp->rx_next),
	   ntohs (mp->rx_qid),
	   ntohs (mp->rx_qsize), ntohs (mp->rx_fill[0]),
	   ntohs (mp->rx_consume[0]),
	   ntohs (mp->rx_produce[0]),
	   ntohs (mp->rx_qsize), ntohs (mp->rx_fill[1]),
	   ntohs (mp->rx_consume[1]),
	   ntohs (mp->rx_produce[1]),
	   ntohs (mp->tx_next),
	   ntohs (mp->tx_qid),
	   ntohs (mp->tx_qsize), ntohs (mp->tx_consume),
	   ntohs (mp->tx_produce), mp->admin_up_down ? "up" : "down");
}

/*
 * List of messages that the api test plugin sends,
 * and that the data plane plugin processes
 */
#define foreach_vpe_api_msg					\
_(vmxnet3_create, "<pci-address> [rx-queue-size <size>] "	\
              "[tx-queue-size <size>]")				\
_(vmxnet3_delete, "<sw_if_index>")                              \
_(vmxnet3_dump, "")

static void
vmxnet3_vat_api_hookup (vat_main_t * vam)
{
  vmxnet3_test_main_t *vxm __attribute__ ((unused)) = &vmxnet3_test_main;
#define _(N,n)                                                  \
  vl_msg_api_set_handlers((VL_API_##N + vxm->msg_id_base),      \
                          #n,                                   \
                          vl_api_##n##_t_handler,               \
                          vl_noop_handler,                      \
                          vl_api_##n##_t_endian,                \
                          vl_api_##n##_t_print,                 \
                          sizeof(vl_api_##n##_t), 1);
  foreach_vpe_api_reply_msg;
#undef _

#define _(n,h)							\
  hash_set_mem (vam->function_by_name, #n, api_##n);
  foreach_vpe_api_msg;
#undef _

#define _(n,h) hash_set_mem (vam->help_by_name, #n, h);
  foreach_vpe_api_msg;
#undef _
}

clib_error_t *
vat_plugin_register (vat_main_t * vam)
{
  vmxnet3_test_main_t *vxm = &vmxnet3_test_main;
  u8 *name;

  vxm->vat_main = vam;

  name = format (0, "vmxnet3_%08x%c", api_version, 0);
  vxm->msg_id_base = vl_client_get_first_plugin_msg_id ((char *) name);

  /* Get the control ping ID */
#define _(id,n,crc) \
  const char *id ## _CRC __attribute__ ((unused)) = #n "_" #crc;
  foreach_vl_msg_name_crc_vpe;
#undef _
  vxm->ping_id = vl_msg_api_get_msg_index ((u8 *) (VL_API_CONTROL_PING_CRC));

  if (vxm->msg_id_base != (u16) ~ 0)
    vmxnet3_vat_api_hookup (vam);

  vec_free (name);

  return 0;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
