/*
 * Copyright (c) 2017 Cisco and/or its affiliates.
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
 */

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vlib/pci/pci.h>
#include <vnet/vnet.h>
#include <vnet/ethernet/ethernet.h>
#include <ixge/ixge.h>

#include <ixge/inline.h>

u8 *
format_ixge_device_name (u8 * s, va_list * args)
{
  u32 i = va_arg (*args, u32);
  ixge_main_t *xm = &ixge_main;
  ixge_device_t *xd = vec_elt_at_index (xm->devices, i);
  vlib_pci_addr_t *addr = vlib_pci_get_addr (xd->pci_dev_handle);
  return format (s, "TenGigabitEthernet%x/%x/%x/%x",
		 addr->domain, addr->bus, addr->slot, addr->function);
}

u8 *
format_ixge_device_id (u8 * s, va_list * args)
{
  u32 device_id = va_arg (*args, u32);
  char *t = 0;
  switch (device_id)
    {
#define _(f,n) case n: t = #f; break;
      foreach_ixge_pci_device_id;
#undef _
    default:
      t = 0;
      break;
    }
  if (t == 0)
    s = format (s, "unknown 0x%x", device_id);
  else
    s = format (s, "%s", t);
  return s;
}

u8 *
format_ixge_link_status (u8 * s, va_list * args)
{
  ixge_device_t *xd = va_arg (*args, ixge_device_t *);
  u32 v = xd->link_status_at_last_link_change;

  s = format (s, "%s", (v & (1 << 30)) ? "up" : "down");

  {
    char *modes[] = {
      "1g", "10g parallel", "10g serial", "autoneg",
    };
    char *speeds[] = {
      "unknown", "100m", "1g", "10g",
    };
    s = format (s, ", mode %s, speed %s",
		modes[(v >> 26) & 3], speeds[(v >> 28) & 3]);
  }

  return s;
}

u8 *
format_ixge_device (u8 * s, va_list * args)
{
  u32 dev_instance = va_arg (*args, u32);
  CLIB_UNUSED (int verbose) = va_arg (*args, int);
  ixge_main_t *xm = &ixge_main;
  ixge_device_t *xd = vec_elt_at_index (xm->devices, dev_instance);
  ixge_phy_t *phy = xd->phys + xd->phy_index;
  u32 indent = format_get_indent (s);

  ixge_update_counters (xd);
  xd->link_status_at_last_link_change = xd->regs->xge_mac.link_status;

  s = format (s, "Intel 8259X: id %U\n%Ulink %U",
	      format_ixge_device_id, xd->device_id,
	      format_white_space, indent + 2, format_ixge_link_status, xd);

  {

    vlib_pci_addr_t *addr = vlib_pci_get_addr (xd->pci_dev_handle);
    vlib_pci_device_info_t *d = vlib_pci_get_device_info (addr, 0);

    if (d)
      s = format (s, "\n%UPCIe %U", format_white_space, indent + 2,
		  format_vlib_pci_link_speed, d);
  }

  s = format (s, "\n%U", format_white_space, indent + 2);
  if (phy->mdio_address != ~0)
    s = format (s, "PHY address %d, id 0x%x", phy->mdio_address, phy->id);
  else if (xd->sfp_eeprom.id == SFP_ID_sfp)
    s = format (s, "SFP %U", format_sfp_eeprom, &xd->sfp_eeprom);
  else
    s = format (s, "PHY not found");

  /* FIXME */
  {
    ixge_dma_queue_t *dq = vec_elt_at_index (xd->dma_queues[VLIB_RX], 0);
    ixge_dma_regs_t *dr = get_dma_regs (xd, VLIB_RX, 0);
    u32 hw_head_index = dr->head_index;
    u32 sw_head_index = dq->head_index;
    u32 nitems;

    nitems = ixge_ring_sub (dq, hw_head_index, sw_head_index);
    s = format (s, "\n%U%d unprocessed, %d total buffers on rx queue 0 ring",
		format_white_space, indent + 2, nitems, dq->n_descriptors);

    s = format (s, "\n%U%d buffers in driver rx cache",
		format_white_space, indent + 2,
		vec_len (xm->rx_buffers_to_add));

    s = format (s, "\n%U%d buffers on tx queue 0 ring",
		format_white_space, indent + 2,
		xd->dma_queues[VLIB_TX][0].tx.n_buffers_on_ring);
  }
  {
    u32 i;
    u64 v;
    static char *names[] = {
#define _(a,f) #f,
#define _64(a,f) _(a,f)
      foreach_ixge_counter
#undef _
#undef _64
    };

    for (i = 0; i < ARRAY_LEN (names); i++)
      {
	v = xd->counters[i] - xd->counters_last_clear[i];
	if (v != 0)
	  s = format (s, "\n%U%-40U%16Ld",
		      format_white_space, indent + 2,
		      format_c_identifier, names[i], v);
      }
  }

  return s;
}

u8 *
format_ixge_rx_from_hw_descriptor (u8 * s, va_list * va)
{
  ixge_rx_from_hw_descriptor_t *d =
    va_arg (*va, ixge_rx_from_hw_descriptor_t *);
  u32 s0 = d->status[0], s2 = d->status[2];
  u32 is_ip4, is_ip6, is_ip, is_tcp, is_udp;
  u32 indent = format_get_indent (s);

  s = format (s, "%s-owned",
	      (s2 & IXGE_RX_DESCRIPTOR_STATUS2_IS_OWNED_BY_SOFTWARE) ? "sw" :
	      "hw");
  s =
    format (s, ", length this descriptor %d, l3 offset %d",
	    d->n_packet_bytes_this_descriptor,
	    IXGE_RX_DESCRIPTOR_STATUS0_L3_OFFSET (s0));
  if (s2 & IXGE_RX_DESCRIPTOR_STATUS2_IS_END_OF_PACKET)
    s = format (s, ", end-of-packet");

  s = format (s, "\n%U", format_white_space, indent);

  if (s2 & IXGE_RX_DESCRIPTOR_STATUS2_ETHERNET_ERROR)
    s = format (s, "layer2 error");

  if (s0 & IXGE_RX_DESCRIPTOR_STATUS0_IS_LAYER2)
    {
      s = format (s, "layer 2 type %d", (s0 & 0x1f));
      return s;
    }

  if (s2 & IXGE_RX_DESCRIPTOR_STATUS2_IS_VLAN)
    s = format (s, "vlan header 0x%x\n%U", d->vlan_tag,
		format_white_space, indent);

  if ((is_ip4 = (s0 & IXGE_RX_DESCRIPTOR_STATUS0_IS_IP4)))
    {
      s = format (s, "ip4%s",
		  (s0 & IXGE_RX_DESCRIPTOR_STATUS0_IS_IP4_EXT) ? " options" :
		  "");
      if (s2 & IXGE_RX_DESCRIPTOR_STATUS2_IS_IP4_CHECKSUMMED)
	s = format (s, " checksum %s",
		    (s2 & IXGE_RX_DESCRIPTOR_STATUS2_IP4_CHECKSUM_ERROR) ?
		    "bad" : "ok");
    }
  if ((is_ip6 = (s0 & IXGE_RX_DESCRIPTOR_STATUS0_IS_IP6)))
    s = format (s, "ip6%s",
		(s0 & IXGE_RX_DESCRIPTOR_STATUS0_IS_IP6_EXT) ? " extended" :
		"");
  is_tcp = is_udp = 0;
  if ((is_ip = (is_ip4 | is_ip6)))
    {
      is_tcp = (s0 & IXGE_RX_DESCRIPTOR_STATUS0_IS_TCP) != 0;
      is_udp = (s0 & IXGE_RX_DESCRIPTOR_STATUS0_IS_UDP) != 0;
      if (is_tcp)
	s = format (s, ", tcp");
      if (is_udp)
	s = format (s, ", udp");
    }

  if (s2 & IXGE_RX_DESCRIPTOR_STATUS2_IS_TCP_CHECKSUMMED)
    s = format (s, ", tcp checksum %s",
		(s2 & IXGE_RX_DESCRIPTOR_STATUS2_TCP_CHECKSUM_ERROR) ? "bad" :
		"ok");
  if (s2 & IXGE_RX_DESCRIPTOR_STATUS2_IS_UDP_CHECKSUMMED)
    s = format (s, ", udp checksum %s",
		(s2 & IXGE_RX_DESCRIPTOR_STATUS2_UDP_CHECKSUM_ERROR) ? "bad" :
		"ok");

  return s;
}

u8 *
format_ixge_tx_descriptor (u8 * s, va_list * va)
{
  ixge_tx_descriptor_t *d = va_arg (*va, ixge_tx_descriptor_t *);
  u32 s0 = d->status0, s1 = d->status1;
  u32 indent = format_get_indent (s);
  u32 v;

  s = format (s, "buffer 0x%Lx, %d packet bytes, %d bytes this buffer",
	      d->buffer_address, s1 >> 14, d->n_bytes_this_buffer);

  s = format (s, "\n%U", format_white_space, indent);

  if ((v = (s0 >> 0) & 3))
    s = format (s, "reserved 0x%x, ", v);

  if ((v = (s0 >> 2) & 3))
    s = format (s, "mac 0x%x, ", v);

  if ((v = (s0 >> 4) & 0xf) != 3)
    s = format (s, "type 0x%x, ", v);

  s = format (s, "%s%s%s%s%s%s%s%s",
	      (s0 & (1 << 8)) ? "eop, " : "",
	      (s0 & (1 << 9)) ? "insert-fcs, " : "",
	      (s0 & (1 << 10)) ? "reserved26, " : "",
	      (s0 & (1 << 11)) ? "report-status, " : "",
	      (s0 & (1 << 12)) ? "reserved28, " : "",
	      (s0 & (1 << 13)) ? "is-advanced, " : "",
	      (s0 & (1 << 14)) ? "vlan-enable, " : "",
	      (s0 & (1 << 15)) ? "tx-segmentation, " : "");

  if ((v = s1 & 0xf) != 0)
    s = format (s, "status 0x%x, ", v);

  if ((v = (s1 >> 4) & 0xf))
    s = format (s, "context 0x%x, ", v);

  if ((v = (s1 >> 8) & 0x3f))
    s = format (s, "options 0x%x, ", v);

  return s;
}

u8 *
format_ixge_rx_dma_trace (u8 * s, va_list * va)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*va, vlib_main_t *);
  vlib_node_t *node = va_arg (*va, vlib_node_t *);
  vnet_main_t *vnm = vnet_get_main ();
  ixge_rx_dma_trace_t *t = va_arg (*va, ixge_rx_dma_trace_t *);
  ixge_main_t *xm = &ixge_main;
  ixge_device_t *xd = vec_elt_at_index (xm->devices, t->device_index);
  format_function_t *f;
  u32 indent = format_get_indent (s);

  {
    vnet_sw_interface_t *sw =
      vnet_get_sw_interface (vnm, xd->vlib_sw_if_index);
    s =
      format (s, "%U rx queue %d", format_vnet_sw_interface_name, vnm, sw,
	      t->queue_index);
  }

  s = format (s, "\n%Ubefore: %U",
	      format_white_space, indent,
	      format_ixge_rx_from_hw_descriptor, &t->before);
  s = format (s, "\n%Uafter : head/tail address 0x%Lx/0x%Lx",
	      format_white_space, indent,
	      t->after.rx_to_hw.head_address, t->after.rx_to_hw.tail_address);

  s = format (s, "\n%Ubuffer 0x%x: %U",
	      format_white_space, indent,
	      t->buffer_index, format_vnet_buffer, &t->buffer);

  s = format (s, "\n%U", format_white_space, indent);

  f = node->format_buffer;
  if (!f || !t->is_start_of_packet)
    f = format_hex_bytes;
  s = format (s, "%U", f, t->buffer.pre_data, sizeof (t->buffer.pre_data));

  return s;
}

u8 *
format_ixge_tx_dma_trace (u8 * s, va_list * va)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*va, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*va, vlib_node_t *);
  ixge_tx_dma_trace_t *t = va_arg (*va, ixge_tx_dma_trace_t *);
  vnet_main_t *vnm = vnet_get_main ();
  ixge_main_t *xm = &ixge_main;
  ixge_device_t *xd = vec_elt_at_index (xm->devices, t->device_index);
  format_function_t *f;
  u32 indent = format_get_indent (s);

  {
    vnet_sw_interface_t *sw =
      vnet_get_sw_interface (vnm, xd->vlib_sw_if_index);
    s =
      format (s, "%U tx queue %d", format_vnet_sw_interface_name, vnm, sw,
	      t->queue_index);
  }

  s = format (s, "\n%Udescriptor: %U",
	      format_white_space, indent,
	      format_ixge_tx_descriptor, &t->descriptor);

  s = format (s, "\n%Ubuffer 0x%x: %U",
	      format_white_space, indent,
	      t->buffer_index, format_vnet_buffer, &t->buffer);

  s = format (s, "\n%U", format_white_space, indent);

  f = format_ethernet_header_with_length;
  if (!f || !t->is_start_of_packet)
    f = format_hex_bytes;
  s = format (s, "%U", f, t->buffer.pre_data, sizeof (t->buffer.pre_data));

  return s;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
