/*
 *------------------------------------------------------------------
 * virtio_api.c - vnet virtio pci device driver API support
 *
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

#include <vnet/vnet.h>
#include <vlibmemory/api.h>

#include <vnet/interface.h>
#include <vnet/api_errno.h>
#include <vnet/ip/ip.h>
#include <vnet/devices/virtio/virtio.h>
#include <vnet/devices/virtio/pci.h>

#include <vnet/vnet_msg_enum.h>

#define vl_typedefs		/* define message structures */
#include <vnet/vnet_all_api_h.h>
#undef vl_typedefs

#define vl_endianfun		/* define message structures */
#include <vnet/vnet_all_api_h.h>
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)
#define vl_printfun
#include <vnet/vnet_all_api_h.h>
#undef vl_printfun

#include <vlibapi/api_helper_macros.h>

#define foreach_virtio_pci_api_msg                        \
_(VIRTIO_PCI_CREATE, virtio_pci_create)                   \
_(VIRTIO_PCI_DELETE, virtio_pci_delete)                   \
_(SW_INTERFACE_VIRTIO_PCI_DUMP, sw_interface_virtio_pci_dump)

static void
vl_api_virtio_pci_create_t_handler (vl_api_virtio_pci_create_t * mp)
{
  vlib_main_t *vm = vlib_get_main ();
  vl_api_virtio_pci_create_reply_t *rmp;
  vl_api_registration_t *reg;
  virtio_pci_create_if_args_t _a, *ap = &_a;

  clib_memset (ap, 0, sizeof (*ap));

  ap->addr = ntohl (mp->pci_addr);
  if (!mp->use_random_mac)
    {
      clib_memcpy (ap->mac_addr, mp->mac_address, 6);
      ap->mac_addr_set = 1;
    }
  ap->rxq_size = ntohs (mp->rx_ring_sz);
  ap->txq_size = ntohs (mp->tx_ring_sz);
  ap->sw_if_index = (u32) ~ 0;
  ap->features = clib_net_to_host_u64 (mp->features);

  virtio_pci_create_if (vm, ap);

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  rmp->_vl_msg_id = htons (VL_API_VIRTIO_PCI_CREATE_REPLY);
  rmp->context = mp->context;
  rmp->retval = htonl (ap->rv);
  rmp->sw_if_index = htonl (ap->sw_if_index);

  vl_api_send_msg (reg, (u8 *) rmp);
}

static void
virtio_pci_send_sw_interface_event_deleted (vpe_api_main_t * am,
					    vl_api_registration_t * reg,
					    u32 sw_if_index)
{
  vl_api_sw_interface_event_t *mp;

  mp = vl_msg_api_alloc (sizeof (*mp));
  clib_memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = htons (VL_API_SW_INTERFACE_EVENT);
  mp->sw_if_index = htonl (sw_if_index);

  mp->admin_up_down = 0;
  mp->link_up_down = 0;
  mp->deleted = 1;
  vl_api_send_msg (reg, (u8 *) mp);
}

static void
vl_api_virtio_pci_delete_t_handler (vl_api_virtio_pci_delete_t * mp)
{
  vnet_main_t *vnm = vnet_get_main ();
  vlib_main_t *vm = vlib_get_main ();
  virtio_main_t *vmx = &virtio_main;
  int rv = 0;
  vnet_hw_interface_t *hw;
  virtio_if_t *vif;
  vpe_api_main_t *vam = &vpe_api_main;
  vl_api_virtio_pci_delete_reply_t *rmp;
  vl_api_registration_t *reg;
  u32 sw_if_index = ntohl (mp->sw_if_index);

  hw = vnet_get_sup_hw_interface (vnm, htonl (mp->sw_if_index));
  if (hw == NULL || virtio_device_class.index != hw->dev_class_index)
    {
      rv = VNET_API_ERROR_INVALID_INTERFACE;
      goto reply;
    }

  vif = pool_elt_at_index (vmx->interfaces, hw->dev_instance);

  rv = virtio_pci_delete_if (vm, vif);

reply:
  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  rmp->_vl_msg_id = htons (VL_API_VIRTIO_PCI_DELETE_REPLY);
  rmp->context = mp->context;
  rmp->retval = htonl (rv);

  vl_api_send_msg (reg, (u8 *) rmp);

  if (!rv)
    {
      virtio_pci_send_sw_interface_event_deleted (vam, reg, sw_if_index);
    }
}

static void
virtio_pci_send_sw_interface_details (vpe_api_main_t * am,
				      vl_api_registration_t * reg,
				      virtio_if_t * vif, u32 context)
{
  vl_api_sw_interface_virtio_pci_details_t *mp;
  mp = vl_msg_api_alloc (sizeof (*mp));

  clib_memset (mp, 0, sizeof (*mp));

  mp->_vl_msg_id = htons (VL_API_SW_INTERFACE_VIRTIO_PCI_DETAILS);
  mp->pci_addr = htonl (vif->pci_addr.as_u32);
  mp->sw_if_index = htonl (vif->sw_if_index);
  mp->rx_ring_sz = htons (vif->rx_ring_sz);
  mp->tx_ring_sz = htons (vif->tx_ring_sz);
  clib_memcpy (mp->mac_addr, vif->mac_addr, 6);
  mp->features = clib_host_to_net_u64 (vif->features);

  mp->context = context;
  vl_api_send_msg (reg, (u8 *) mp);
}

static void
  vl_api_sw_interface_virtio_pci_dump_t_handler
  (vl_api_sw_interface_virtio_pci_dump_t * mp)
{
  vpe_api_main_t *am = &vpe_api_main;
  vl_api_registration_t *reg;
  virtio_main_t *vmx = &virtio_main;
  virtio_if_t *vif;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  pool_foreach (vif, vmx->interfaces, (
					{
					if (vif->type == VIRTIO_IF_TYPE_PCI)
					{
					virtio_pci_send_sw_interface_details
					(am, reg, vif, mp->context);}
					}
		));
}

#define vl_msg_name_crc_list
#include <vnet/vnet_all_api_h.h>
#undef vl_msg_name_crc_list

static void
setup_message_id_table (api_main_t * am)
{
#define _(id,n,crc) vl_msg_api_add_msg_name_crc (am, #n "_" #crc, id);
  foreach_vl_msg_name_crc_virtio;
#undef _
}

static clib_error_t *
virtio_pci_api_hookup (vlib_main_t * vm)
{
  api_main_t *am = &api_main;

#define _(N,n)                                                  \
    vl_msg_api_set_handlers(VL_API_##N, #n,                     \
                           vl_api_##n##_t_handler,              \
                           vl_noop_handler,                     \
                           vl_api_##n##_t_endian,               \
                           vl_api_##n##_t_print,                \
                           sizeof(vl_api_##n##_t), 1);
  foreach_virtio_pci_api_msg;
#undef _

  /*
   * Set up the (msg_name, crc, message-id) table
   */
  setup_message_id_table (am);

  return 0;
}

VLIB_API_INIT_FUNCTION (virtio_pci_api_hookup);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
