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
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/devices/virtio/virtio.h>
#include <vnet/devices/virtio/pci.h>

u8 *
format_virtio_device_name (u8 * s, va_list * args)
{
  u32 dev_instance = va_arg (*args, u32);
  virtio_main_t *mm = &virtio_main;
  virtio_if_t *vif = pool_elt_at_index (mm->interfaces, dev_instance);

  if (vif->type == VIRTIO_IF_TYPE_TAP)
    s = format (s, "tap%u", vif->id);
  else if (vif->type == VIRTIO_IF_TYPE_PCI)
    s = format (s, "virtio-%x/%x/%x/%x", vif->pci_addr.domain,
		vif->pci_addr.bus, vif->pci_addr.slot,
		vif->pci_addr.function);
  else
    s = format (s, "virtio-%lu", vif->dev_instance);

  return s;
}

u8 *
format_virtio_log_name (u8 * s, va_list * args)
{
  virtio_if_t *vif = va_arg (*args, virtio_if_t *);

  if (vif->type == VIRTIO_IF_TYPE_TAP)
    s = format (s, "tap%u", vif->id);
  else if (vif->type == VIRTIO_IF_TYPE_PCI)
    s = format (s, "%U", format_vlib_pci_addr, &vif->pci_addr);
  else
    s = format (s, "virtio-%lu", vif->dev_instance);

  return s;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
