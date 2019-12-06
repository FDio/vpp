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
#include <vnet/format_fns.h>
#include <vmxnet3/vmxnet3.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>

/* define message IDs */
#include <vmxnet3/vmxnet3.api_enum.h>
#include <vmxnet3/vmxnet3.api_types.h>

#include <vlibapi/api_helper_macros.h>

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
  args.txq_num = ntohs (mp->txq_num);
  args.rxq_num = ntohs (mp->rxq_num);
  args.bind = mp->bind;
  args.enable_gso = mp->enable_gso;

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

  hw =
    vnet_get_sup_hw_interface_api_visible_or_null (vnm,
						   htonl (mp->sw_if_index));
  if (hw == NULL || vmxnet3_device_class.index != hw->dev_class_index)
    {
      rv = VNET_API_ERROR_INVALID_SW_IF_INDEX;
      goto reply;
    }

  vd = pool_elt_at_index (vmxm->devices, hw->dev_instance);

  vmxnet3_delete_if (vm, vd);

reply:
  REPLY_MACRO (VL_API_VMXNET3_DELETE_REPLY + vmxm->msg_id_base);
}

static void
send_vmxnet3_details (vl_api_registration_t * reg, vmxnet3_device_t * vd,
		      vnet_sw_interface_t * swif, u8 * interface_name,
		      u32 context)
{
  vl_api_vmxnet3_details_t *mp;
  vnet_main_t *vnm = vnet_get_main ();
  vmxnet3_main_t *vmxm = &vmxnet3_main;
  vnet_hw_interface_t *hwif;
  vmxnet3_rx_ring *ring;
  u16 rid, qid;

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
  mp->admin_up_down = (swif->flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP) ? 1 : 0;

  mp->rx_count = clib_min (vec_len (vd->rxqs), VMXNET3_RXQ_MAX);
  vec_foreach_index (qid, vd->rxqs)
  {
    vmxnet3_rxq_t *rxq = vec_elt_at_index (vd->rxqs, qid);
    vl_api_vmxnet3_rx_list_t *rx_list = &mp->rx_list[qid];

    ASSERT (qid < VMXNET3_RXQ_MAX);
    rx_list->rx_qsize = htons (rxq->size);
    rx_list->rx_next = htons (rxq->rx_comp_ring.next);
    for (rid = 0; rid < VMXNET3_RX_RING_SIZE; rid++)
      {
	ring = &rxq->rx_ring[rid];
	rx_list->rx_fill[rid] = htons (ring->fill);
	rx_list->rx_produce[rid] = htons (ring->produce);
	rx_list->rx_consume[rid] = htons (ring->consume);
      }
  }

  mp->tx_count = clib_min (vec_len (vd->txqs), VMXNET3_TXQ_MAX);
  vec_foreach_index (qid, vd->txqs)
  {
    vmxnet3_txq_t *txq = vec_elt_at_index (vd->txqs, qid);
    vl_api_vmxnet3_tx_list_t *tx_list = &mp->tx_list[qid];

    ASSERT (qid < VMXNET3_TXQ_MAX);
    tx_list->tx_qsize = htons (txq->size);
    tx_list->tx_next = htons (txq->tx_comp_ring.next);
    tx_list->tx_produce = htons (txq->tx_ring.produce);
    tx_list->tx_consume = htons (txq->tx_ring.consume);
  }

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

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  /* *INDENT-OFF* */
  pool_foreach (vd, vmxm->devices,
    ({
      swif = vnet_get_sw_interface (vnm, vd->sw_if_index);
      if_name = format (if_name, "%U%c", format_vnet_sw_interface_name, vnm,
			swif, 0);
      send_vmxnet3_details (reg, vd, swif, if_name, mp->context);
      _vec_len (if_name) = 0;
    }));
  /* *INDENT-ON* */

  vec_free (if_name);
}

/* set tup the API message handling tables */
#include <vmxnet3/vmxnet3.api.c>
clib_error_t *
vmxnet3_plugin_api_hookup (vlib_main_t * vm)
{
  vmxnet3_main_t *vmxm = &vmxnet3_main;

  /* ask for a correctly-sized block of API message decode slots */
  vmxm->msg_id_base = setup_message_id_table ();
  return 0;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
