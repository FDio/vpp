/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2018-2025 Cisco and/or its affiliates.
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

  if (vif->initial_if_name)
    return format (s, "%s", vif->initial_if_name);

  if (vif->type == VIRTIO_IF_TYPE_TAP)
    s = format (s, "tap%u", vif->id);
  else if (vif->type == VIRTIO_IF_TYPE_PCI)
    s = format (s, "virtio-%x/%x/%x/%x", vif->pci_addr.domain,
		vif->pci_addr.bus, vif->pci_addr.slot,
		vif->pci_addr.function);
  else if (vif->type == VIRTIO_IF_TYPE_TUN)
    s = format (s, "tun%u", vif->id);
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
  else if (vif->type == VIRTIO_IF_TYPE_TUN)
    s = format (s, "tun%u", vif->id);
  else if (vif->type == VIRTIO_IF_TYPE_PCI)
    s = format (s, "%U", format_vlib_pci_addr, &vif->pci_addr);
  else
    s = format (s, "virtio-%lu", vif->dev_instance);

  return s;
}
