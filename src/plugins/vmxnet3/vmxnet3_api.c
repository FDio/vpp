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

#include <vmxnet3/vmxnet3.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>

/* define message IDs */
#include <vmxnet3/vmxnet3_msg_enum.h>

/* define message structures */
#define vl_typedefs
#include <vmxnet3/vmxnet3_all_api_h.h>
#undef vl_typedefs

/* define generated endian-swappers */
#define vl_endianfun
#include <vmxnet3/vmxnet3_all_api_h.h>
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)
#define vl_printfun
#include <vmxnet3/vmxnet3_all_api_h.h>
#undef vl_printfun

/* get the API version number */
#define vl_api_version(n,v) static u32 api_version=(v);
#include <vmxnet3/vmxnet3_all_api_h.h>
#undef vl_api_version

#include <vlibapi/api_helper_macros.h>

#define foreach_vmxnet3_plugin_api_msg	\
_(VMXNET3_CREATE, vmxnet3_create)	\
_(VMXNET3_DELETE, vmxnet3_delete)       \
_(VMXNET3_DUMP, vmxnet3_dump)

static void
vl_api_vmxnet3_create_t_handler (vl_api_vmxnet3_create_t * mp)
{
  vlib_main_t *vm = vlib_get_main ();
  vmxnet3_main_t *vmxm = &vmxnet3_main;
  vl_api_vmxnet3_create_reply_t *rmp;
  vmxnet3_create_if_args_t args;
  int rv;

  clib_memset (&args, 0, sizeof (vmxnet3_create_if_args_t));

  args.enable_elog = ntohl (mp->enable_elog);
  args.addr.as_u32 = ntohl (mp->pci_addr);
  args.rxq_size = ntohs (mp->rxq_size);
  args.txq_size = ntohs (mp->txq_size);

  vmxnet3_create_if (vm, &args);
  rv = args.rv;

  /* *INDENT-OFF* */
  REPLY_MACRO2 (VL_API_VMXNET3_CREATE_REPLY + vmxm->msg_id_base,
    ({
      rmp->sw_if_index = ntohl (args.sw_if_index);
    }));
  /* *INDENT-ON* */
}

static void
vl_api_vmxnet3_delete_t_handler (vl_api_vmxnet3_delete_t * mp)
{
  vlib_main_t *vm = vlib_get_main ();
  vnet_main_t *vnm = vnet_get_main ();
  vmxnet3_main_t *vmxm = &vmxnet3_main;
  vl_api_vmxnet3_delete_reply_t *rmp;
  vmxnet3_device_t *vd;
  vnet_hw_interface_t *hw;
  int rv = 0;

  hw = vnet_get_sup_hw_interface (vnm, htonl (mp->sw_if_index));
  if (hw == NULL || vmxnet3_device_class.index != hw->dev_class_index)
    {
      rv = VNET_API_ERROR_INVALID_INTERFACE;
      goto reply;
    }

  vd = pool_elt_at_index (vmxm->devices, hw->dev_instance);

  vmxnet3_delete_if (vm, vd);

reply:
  REPLY_MACRO (VL_API_VMXNET3_DELETE_REPLY + vmxm->msg_id_base);
}

static void
send_vmxnet3_details (vl_api_registration_t * reg, vmxnet3_device_t * vd,
		      u16 rx_qid, vmxnet3_rxq_t * rxq, u16 tx_qid,
		      vmxnet3_txq_t * txq, vnet_sw_interface_t * swif,
		      u8 * interface_name, u32 context)
{
  vl_api_vmxnet3_details_t *mp;
  vnet_main_t *vnm = vnet_get_main ();
  vmxnet3_main_t *vmxm = &vmxnet3_main;
  vnet_hw_interface_t *hwif;
  vmxnet3_rx_ring *ring;
  u16 rid;

  hwif = vnet_get_sup_hw_interface (vnm, swif->sw_if_index);

  mp = vl_msg_api_alloc (sizeof (*mp));
  clib_memset (mp, 0, sizeof (*mp));

  mp->_vl_msg_id = htons (VL_API_VMXNET3_DETAILS + vmxm->msg_id_base);
  mp->context = context;

  mp->sw_if_index = htonl (swif->sw_if_index);
  strncpy ((char *) mp->if_name,
	   (char *) interface_name, ARRAY_LEN (mp->if_name) - 1);

  if (hwif->hw_address)
    memcpy (mp->hw_addr, hwif->hw_address, ARRAY_LEN (mp->hw_addr));

  mp->version = vd->version;
  mp->pci_addr = ntohl (vd->pci_addr.as_u32);

  mp->rx_qsize = htons (rxq->size);
  mp->rx_next = htons (rxq->rx_comp_ring.next);
  for (rid = 0; rid < VMXNET3_RX_RING_SIZE; rid++)
    {
      ring = &rxq->rx_ring[rid];
      mp->rx_fill[rid] = htons (ring->fill);
      mp->rx_produce[rid] = htons (ring->produce);
      mp->rx_consume[rid] = htons (ring->consume);
    }
  mp->tx_qsize = htons (txq->size);
  mp->tx_next = htons (txq->tx_comp_ring.next);
  mp->tx_produce = htons (txq->tx_ring.produce);
  mp->tx_consume = htons (txq->tx_ring.consume);

  mp->admin_up_down = (swif->flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP) ? 1 : 0;

  vl_api_send_msg (reg, (u8 *) mp);
}

/**
 * @brief Message handler for vmxnet3_dump API.
 * @param mp vl_api_vmxnet3_dump_t * mp the api message
 */
static void
vl_api_vmxnet3_dump_t_handler (vl_api_vmxnet3_dump_t * mp)
{
  vmxnet3_main_t *vmxm = &vmxnet3_main;
  vnet_main_t *vnm = vnet_get_main ();
  vnet_sw_interface_t *swif;
  vmxnet3_device_t *vd;
  u8 *if_name = 0;
  vl_api_registration_t *reg;
  vmxnet3_rxq_t *rxq;
  vmxnet3_txq_t *txq;
  u16 qid = 0;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  /* *INDENT-OFF* */
  pool_foreach (vd, vmxm->devices,
    ({
      swif = vnet_get_sw_interface (vnm, vd->sw_if_index);
      if_name = format (if_name, "%U%c", format_vnet_sw_interface_name, vnm,
			swif, 0);
      rxq = vec_elt_at_index (vd->rxqs, qid);
      txq = vec_elt_at_index (vd->txqs, qid);
      send_vmxnet3_details (reg, vd, qid, rxq, qid, txq, swif, if_name,
			    mp->context);
      _vec_len (if_name) = 0;
    }));
  /* *INDENT-ON* */

  vec_free (if_name);
}

#define vl_msg_name_crc_list
#include <vmxnet3/vmxnet3_all_api_h.h>
#undef vl_msg_name_crc_list

static void
setup_message_id_table (vmxnet3_main_t * vmxm, api_main_t * am)
{
#define _(id,n,crc) \
  vl_msg_api_add_msg_name_crc (am, #n "_" #crc, id + vmxm->msg_id_base);
  foreach_vl_msg_name_crc_vmxnet3;
#undef _
}

/* set tup the API message handling tables */
clib_error_t *
vmxnet3_plugin_api_hookup (vlib_main_t * vm)
{
  vmxnet3_main_t *vmxm = &vmxnet3_main;
  api_main_t *am = &api_main;
  u8 *name;

  /* construct the API name */
  name = format (0, "vmxnet3_%08x%c", api_version, 0);

  /* ask for a correctly-sized block of API message decode slots */
  vmxm->msg_id_base = vl_msg_api_get_msg_ids
    ((char *) name, VL_MSG_FIRST_AVAILABLE);

#define _(N,n)							\
    vl_msg_api_set_handlers((VL_API_##N + vmxm->msg_id_base),	\
			   #n,					\
			   vl_api_##n##_t_handler,		\
			   vl_noop_handler,			\
			   vl_api_##n##_t_endian,		\
			   vl_api_##n##_t_print,		\
			   sizeof(vl_api_##n##_t), 1);
  foreach_vmxnet3_plugin_api_msg;
#undef _

  /* set up the (msg_name, crc, message-id) table */
  setup_message_id_table (vmxm, am);

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
