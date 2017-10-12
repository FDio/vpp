/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
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

/*
 *   WARNING!
 *   This driver is not intended for production use and it is unsupported.
 *   It is provided for educational use only.
 *   Please use supported DPDK driver instead.
 */

#if __x86_64__ || __i386__
#include <vppinfra/vector.h>

#ifndef CLIB_HAVE_VEC128
#warning HACK: ixge driver wont really work, missing u32x4
typedef unsigned long long u32x4;
#endif

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vlib/pci/pci.h>
#include <vnet/vnet.h>
#include <ixge/ixge.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>

#define IXGE_ALWAYS_POLL 0

#define EVENT_SET_FLAGS 0
#define IXGE_HWBP_RACE_ELOG 0

#define PCI_VENDOR_ID_INTEL 0x8086

/* 10 GIG E (XGE) PHY IEEE 802.3 clause 45 definitions. */
#define XGE_PHY_DEV_TYPE_PMA_PMD 1
#define XGE_PHY_DEV_TYPE_PHY_XS 4
#define XGE_PHY_ID1 0x2
#define XGE_PHY_ID2 0x3
#define XGE_PHY_CONTROL 0x0
#define XGE_PHY_CONTROL_RESET (1 << 15)

ixge_main_t ixge_main;
static vlib_node_registration_t ixge_input_node;
static vlib_node_registration_t ixge_process_node;

static void
ixge_semaphore_get (ixge_device_t * xd)
{
  ixge_main_t *xm = &ixge_main;
  vlib_main_t *vm = xm->vlib_main;
  ixge_regs_t *r = xd->regs;
  u32 i;

  i = 0;
  while (!(r->software_semaphore & (1 << 0)))
    {
      if (i > 0)
	vlib_process_suspend (vm, 100e-6);
      i++;
    }
  do
    {
      r->software_semaphore |= 1 << 1;
    }
  while (!(r->software_semaphore & (1 << 1)));
}

static void
ixge_semaphore_release (ixge_device_t * xd)
{
  ixge_regs_t *r = xd->regs;
  r->software_semaphore &= ~3;
}

static void
ixge_software_firmware_sync (ixge_device_t * xd, u32 sw_mask)
{
  ixge_main_t *xm = &ixge_main;
  vlib_main_t *vm = xm->vlib_main;
  ixge_regs_t *r = xd->regs;
  u32 fw_mask = sw_mask << 5;
  u32 m, done = 0;

  while (!done)
    {
      ixge_semaphore_get (xd);
      m = r->software_firmware_sync;
      done = (m & fw_mask) == 0;
      if (done)
	r->software_firmware_sync = m | sw_mask;
      ixge_semaphore_release (xd);
      if (!done)
	vlib_process_suspend (vm, 10e-3);
    }
}

static void
ixge_software_firmware_sync_release (ixge_device_t * xd, u32 sw_mask)
{
  ixge_regs_t *r = xd->regs;
  ixge_semaphore_get (xd);
  r->software_firmware_sync &= ~sw_mask;
  ixge_semaphore_release (xd);
}

u32
ixge_read_write_phy_reg (ixge_device_t * xd, u32 dev_type, u32 reg_index,
			 u32 v, u32 is_read)
{
  ixge_regs_t *r = xd->regs;
  const u32 busy_bit = 1 << 30;
  u32 x;

  ASSERT (xd->phy_index < 2);
  ixge_software_firmware_sync (xd, 1 << (1 + xd->phy_index));

  ASSERT (reg_index < (1 << 16));
  ASSERT (dev_type < (1 << 5));
  if (!is_read)
    r->xge_mac.phy_data = v;

  /* Address cycle. */
  x =
    reg_index | (dev_type << 16) | (xd->
				    phys[xd->phy_index].mdio_address << 21);
  r->xge_mac.phy_command = x | busy_bit;
  /* Busy wait timed to take 28e-6 secs.  No suspend. */
  while (r->xge_mac.phy_command & busy_bit)
    ;

  r->xge_mac.phy_command = x | ((is_read ? 2 : 1) << 26) | busy_bit;
  while (r->xge_mac.phy_command & busy_bit)
    ;

  if (is_read)
    v = r->xge_mac.phy_data >> 16;

  ixge_software_firmware_sync_release (xd, 1 << (1 + xd->phy_index));

  return v;
}

static u32
ixge_read_phy_reg (ixge_device_t * xd, u32 dev_type, u32 reg_index)
{
  return ixge_read_write_phy_reg (xd, dev_type, reg_index, 0,	/* is_read */
				  1);
}

static void
ixge_write_phy_reg (ixge_device_t * xd, u32 dev_type, u32 reg_index, u32 v)
{
  (void) ixge_read_write_phy_reg (xd, dev_type, reg_index, v,	/* is_read */
				  0);
}

static void
ixge_i2c_put_bits (i2c_bus_t * b, int scl, int sda)
{
  ixge_main_t *xm = &ixge_main;
  ixge_device_t *xd = vec_elt_at_index (xm->devices, b->private_data);
  u32 v;

  v = 0;
  v |= (sda != 0) << 3;
  v |= (scl != 0) << 1;
  xd->regs->i2c_control = v;
}

static void
ixge_i2c_get_bits (i2c_bus_t * b, int *scl, int *sda)
{
  ixge_main_t *xm = &ixge_main;
  ixge_device_t *xd = vec_elt_at_index (xm->devices, b->private_data);
  u32 v;

  v = xd->regs->i2c_control;
  *sda = (v & (1 << 2)) != 0;
  *scl = (v & (1 << 0)) != 0;
}

static u16
ixge_read_eeprom (ixge_device_t * xd, u32 address)
{
  ixge_regs_t *r = xd->regs;
  u32 v;
  r->eeprom_read = (( /* start bit */ (1 << 0)) | (address << 2));
  /* Wait for done bit. */
  while (!((v = r->eeprom_read) & (1 << 1)))
    ;
  return v >> 16;
}

static void
ixge_sfp_enable_disable_laser (ixge_device_t * xd, uword enable)
{
  u32 tx_disable_bit = 1 << 3;
  if (enable)
    xd->regs->sdp_control &= ~tx_disable_bit;
  else
    xd->regs->sdp_control |= tx_disable_bit;
}

static void
ixge_sfp_enable_disable_10g (ixge_device_t * xd, uword enable)
{
  u32 is_10g_bit = 1 << 5;
  if (enable)
    xd->regs->sdp_control |= is_10g_bit;
  else
    xd->regs->sdp_control &= ~is_10g_bit;
}

static clib_error_t *
ixge_sfp_phy_init_from_eeprom (ixge_device_t * xd, u16 sfp_type)
{
  u16 a, id, reg_values_addr = 0;

  a = ixge_read_eeprom (xd, 0x2b);
  if (a == 0 || a == 0xffff)
    return clib_error_create ("no init sequence in eeprom");

  while (1)
    {
      id = ixge_read_eeprom (xd, ++a);
      if (id == 0xffff)
	break;
      reg_values_addr = ixge_read_eeprom (xd, ++a);
      if (id == sfp_type)
	break;
    }
  if (id != sfp_type)
    return clib_error_create ("failed to find id 0x%x", sfp_type);

  ixge_software_firmware_sync (xd, 1 << 3);
  while (1)
    {
      u16 v = ixge_read_eeprom (xd, ++reg_values_addr);
      if (v == 0xffff)
	break;
      xd->regs->core_analog_config = v;
    }
  ixge_software_firmware_sync_release (xd, 1 << 3);

  /* Make sure laser is off.  We'll turn on the laser when
     the interface is brought up. */
  ixge_sfp_enable_disable_laser (xd, /* enable */ 0);
  ixge_sfp_enable_disable_10g (xd, /* is_10g */ 1);

  return 0;
}

static void
ixge_sfp_device_up_down (ixge_device_t * xd, uword is_up)
{
  u32 v;

  if (is_up)
    {
      /* pma/pmd 10g serial SFI. */
      xd->regs->xge_mac.auto_negotiation_control2 &= ~(3 << 16);
      xd->regs->xge_mac.auto_negotiation_control2 |= 2 << 16;

      v = xd->regs->xge_mac.auto_negotiation_control;
      v &= ~(7 << 13);
      v |= (0 << 13);
      /* Restart autoneg. */
      v |= (1 << 12);
      xd->regs->xge_mac.auto_negotiation_control = v;

      while (!(xd->regs->xge_mac.link_partner_ability[0] & 0xf0000))
	;

      v = xd->regs->xge_mac.auto_negotiation_control;

      /* link mode 10g sfi serdes */
      v &= ~(7 << 13);
      v |= (3 << 13);

      /* Restart autoneg. */
      v |= (1 << 12);
      xd->regs->xge_mac.auto_negotiation_control = v;

      xd->regs->xge_mac.link_status;
    }

  ixge_sfp_enable_disable_laser (xd, /* enable */ is_up);

  /* Give time for link partner to notice that we're up. */
  if (is_up && vlib_in_process_context (vlib_get_main ()))
    {
      vlib_process_suspend (vlib_get_main (), 300e-3);
    }
}

always_inline ixge_dma_regs_t *
get_dma_regs (ixge_device_t * xd, vlib_rx_or_tx_t rt, u32 qi)
{
  ixge_regs_t *r = xd->regs;
  ASSERT (qi < 128);
  if (rt == VLIB_RX)
    return qi < 64 ? &r->rx_dma0[qi] : &r->rx_dma1[qi - 64];
  else
    return &r->tx_dma[qi];
}

static clib_error_t *
ixge_interface_admin_up_down (vnet_main_t * vnm, u32 hw_if_index, u32 flags)
{
  vnet_hw_interface_t *hif = vnet_get_hw_interface (vnm, hw_if_index);
  uword is_up = (flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP) != 0;
  ixge_main_t *xm = &ixge_main;
  ixge_device_t *xd = vec_elt_at_index (xm->devices, hif->dev_instance);
  ixge_dma_regs_t *dr = get_dma_regs (xd, VLIB_RX, 0);

  if (is_up)
    {
      xd->regs->rx_enable |= 1;
      xd->regs->tx_dma_control |= 1;
      dr->control |= 1 << 25;
      while (!(dr->control & (1 << 25)))
	;
    }
  else
    {
      xd->regs->rx_enable &= ~1;
      xd->regs->tx_dma_control &= ~1;
    }

  ixge_sfp_device_up_down (xd, is_up);

  return /* no error */ 0;
}

static void
ixge_sfp_phy_init (ixge_device_t * xd)
{
  ixge_phy_t *phy = xd->phys + xd->phy_index;
  i2c_bus_t *ib = &xd->i2c_bus;

  ib->private_data = xd->device_index;
  ib->put_bits = ixge_i2c_put_bits;
  ib->get_bits = ixge_i2c_get_bits;
  vlib_i2c_init (ib);

  vlib_i2c_read_eeprom (ib, 0x50, 0, 128, (u8 *) & xd->sfp_eeprom);

  if (vlib_i2c_bus_timed_out (ib) || !sfp_eeprom_is_valid (&xd->sfp_eeprom))
    xd->sfp_eeprom.id = SFP_ID_unknown;
  else
    {
      /* FIXME 5 => SR/LR eeprom ID. */
      clib_error_t *e =
	ixge_sfp_phy_init_from_eeprom (xd, 5 + xd->pci_function);
      if (e)
	clib_error_report (e);
    }

  phy->mdio_address = ~0;
}

static void
ixge_phy_init (ixge_device_t * xd)
{
  ixge_main_t *xm = &ixge_main;
  vlib_main_t *vm = xm->vlib_main;
  ixge_phy_t *phy = xd->phys + xd->phy_index;

  switch (xd->device_id)
    {
    case IXGE_82599_sfp:
    case IXGE_82599_sfp_em:
    case IXGE_82599_sfp_fcoe:
      /* others? */
      return ixge_sfp_phy_init (xd);

    default:
      break;
    }

  /* Probe address of phy. */
  {
    u32 i, v;

    phy->mdio_address = ~0;
    for (i = 0; i < 32; i++)
      {
	phy->mdio_address = i;
	v = ixge_read_phy_reg (xd, XGE_PHY_DEV_TYPE_PMA_PMD, XGE_PHY_ID1);
	if (v != 0xffff && v != 0)
	  break;
      }

    /* No PHY found? */
    if (i >= 32)
      return;
  }

  phy->id =
    ((ixge_read_phy_reg (xd, XGE_PHY_DEV_TYPE_PMA_PMD, XGE_PHY_ID1) << 16) |
     ixge_read_phy_reg (xd, XGE_PHY_DEV_TYPE_PMA_PMD, XGE_PHY_ID2));

  {
    ELOG_TYPE_DECLARE (e) =
    {
    .function = (char *) __FUNCTION__,.format =
	"ixge %d, phy id 0x%d mdio address %d",.format_args = "i4i4i4",};
    struct
    {
      u32 instance, id, address;
    } *ed;
    ed = ELOG_DATA (&vm->elog_main, e);
    ed->instance = xd->device_index;
    ed->id = phy->id;
    ed->address = phy->mdio_address;
  }

  /* Reset phy. */
  ixge_write_phy_reg (xd, XGE_PHY_DEV_TYPE_PHY_XS, XGE_PHY_CONTROL,
		      XGE_PHY_CONTROL_RESET);

  /* Wait for self-clearning reset bit to clear. */
  do
    {
      vlib_process_suspend (vm, 1e-3);
    }
  while (ixge_read_phy_reg (xd, XGE_PHY_DEV_TYPE_PHY_XS, XGE_PHY_CONTROL) &
	 XGE_PHY_CONTROL_RESET);
}

static u8 *
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

static u8 *
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

typedef struct
{
  ixge_descriptor_t before, after;

  u32 buffer_index;

  u16 device_index;

  u8 queue_index;

  u8 is_start_of_packet;

  /* Copy of VLIB buffer; packet data stored in pre_data. */
  vlib_buffer_t buffer;
} ixge_rx_dma_trace_t;

static u8 *
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
	      t->buffer_index, format_vlib_buffer, &t->buffer);

  s = format (s, "\n%U", format_white_space, indent);

  f = node->format_buffer;
  if (!f || !t->is_start_of_packet)
    f = format_hex_bytes;
  s = format (s, "%U", f, t->buffer.pre_data, sizeof (t->buffer.pre_data));

  return s;
}

#define foreach_ixge_error					\
  _ (none, "no error")						\
  _ (tx_full_drops, "tx ring full drops")			\
  _ (ip4_checksum_error, "ip4 checksum errors")			\
  _ (rx_alloc_fail, "rx buf alloc from free list failed")	\
  _ (rx_alloc_no_physmem, "rx buf alloc failed no physmem")

typedef enum
{
#define _(f,s) IXGE_ERROR_##f,
  foreach_ixge_error
#undef _
    IXGE_N_ERROR,
} ixge_error_t;

always_inline void
ixge_rx_next_and_error_from_status_x1 (ixge_device_t * xd,
				       u32 s00, u32 s02,
				       u8 * next0, u8 * error0, u32 * flags0)
{
  u8 is0_ip4, is0_ip6, n0, e0;
  u32 f0;

  e0 = IXGE_ERROR_none;
  n0 = IXGE_RX_NEXT_ETHERNET_INPUT;

  is0_ip4 = s02 & IXGE_RX_DESCRIPTOR_STATUS2_IS_IP4_CHECKSUMMED;
  n0 = is0_ip4 ? IXGE_RX_NEXT_IP4_INPUT : n0;

  e0 = (is0_ip4 && (s02 & IXGE_RX_DESCRIPTOR_STATUS2_IP4_CHECKSUM_ERROR)
	? IXGE_ERROR_ip4_checksum_error : e0);

  is0_ip6 = s00 & IXGE_RX_DESCRIPTOR_STATUS0_IS_IP6;
  n0 = is0_ip6 ? IXGE_RX_NEXT_IP6_INPUT : n0;

  n0 = (xd->per_interface_next_index != ~0) ?
    xd->per_interface_next_index : n0;

  /* Check for error. */
  n0 = e0 != IXGE_ERROR_none ? IXGE_RX_NEXT_DROP : n0;

  f0 = ((s02 & (IXGE_RX_DESCRIPTOR_STATUS2_IS_TCP_CHECKSUMMED
		| IXGE_RX_DESCRIPTOR_STATUS2_IS_UDP_CHECKSUMMED))
	? VNET_BUFFER_F_L4_CHECKSUM_COMPUTED : 0);

  f0 |= ((s02 & (IXGE_RX_DESCRIPTOR_STATUS2_TCP_CHECKSUM_ERROR
		 | IXGE_RX_DESCRIPTOR_STATUS2_UDP_CHECKSUM_ERROR))
	 ? 0 : VNET_BUFFER_F_L4_CHECKSUM_CORRECT);

  *error0 = e0;
  *next0 = n0;
  *flags0 = f0;
}

always_inline void
ixge_rx_next_and_error_from_status_x2 (ixge_device_t * xd,
				       u32 s00, u32 s02,
				       u32 s10, u32 s12,
				       u8 * next0, u8 * error0, u32 * flags0,
				       u8 * next1, u8 * error1, u32 * flags1)
{
  u8 is0_ip4, is0_ip6, n0, e0;
  u8 is1_ip4, is1_ip6, n1, e1;
  u32 f0, f1;

  e0 = e1 = IXGE_ERROR_none;
  n0 = n1 = IXGE_RX_NEXT_IP4_INPUT;

  is0_ip4 = s02 & IXGE_RX_DESCRIPTOR_STATUS2_IS_IP4_CHECKSUMMED;
  is1_ip4 = s12 & IXGE_RX_DESCRIPTOR_STATUS2_IS_IP4_CHECKSUMMED;

  n0 = is0_ip4 ? IXGE_RX_NEXT_IP4_INPUT : n0;
  n1 = is1_ip4 ? IXGE_RX_NEXT_IP4_INPUT : n1;

  e0 = (is0_ip4 && (s02 & IXGE_RX_DESCRIPTOR_STATUS2_IP4_CHECKSUM_ERROR)
	? IXGE_ERROR_ip4_checksum_error : e0);
  e1 = (is1_ip4 && (s12 & IXGE_RX_DESCRIPTOR_STATUS2_IP4_CHECKSUM_ERROR)
	? IXGE_ERROR_ip4_checksum_error : e1);

  is0_ip6 = s00 & IXGE_RX_DESCRIPTOR_STATUS0_IS_IP6;
  is1_ip6 = s10 & IXGE_RX_DESCRIPTOR_STATUS0_IS_IP6;

  n0 = is0_ip6 ? IXGE_RX_NEXT_IP6_INPUT : n0;
  n1 = is1_ip6 ? IXGE_RX_NEXT_IP6_INPUT : n1;

  n0 = (xd->per_interface_next_index != ~0) ?
    xd->per_interface_next_index : n0;
  n1 = (xd->per_interface_next_index != ~0) ?
    xd->per_interface_next_index : n1;

  /* Check for error. */
  n0 = e0 != IXGE_ERROR_none ? IXGE_RX_NEXT_DROP : n0;
  n1 = e1 != IXGE_ERROR_none ? IXGE_RX_NEXT_DROP : n1;

  *error0 = e0;
  *error1 = e1;

  *next0 = n0;
  *next1 = n1;

  f0 = ((s02 & (IXGE_RX_DESCRIPTOR_STATUS2_IS_TCP_CHECKSUMMED
		| IXGE_RX_DESCRIPTOR_STATUS2_IS_UDP_CHECKSUMMED))
	? VNET_BUFFER_F_L4_CHECKSUM_COMPUTED : 0);
  f1 = ((s12 & (IXGE_RX_DESCRIPTOR_STATUS2_IS_TCP_CHECKSUMMED
		| IXGE_RX_DESCRIPTOR_STATUS2_IS_UDP_CHECKSUMMED))
	? VNET_BUFFER_F_L4_CHECKSUM_COMPUTED : 0);

  f0 |= ((s02 & (IXGE_RX_DESCRIPTOR_STATUS2_TCP_CHECKSUM_ERROR
		 | IXGE_RX_DESCRIPTOR_STATUS2_UDP_CHECKSUM_ERROR))
	 ? 0 : VNET_BUFFER_F_L4_CHECKSUM_CORRECT);
  f1 |= ((s12 & (IXGE_RX_DESCRIPTOR_STATUS2_TCP_CHECKSUM_ERROR
		 | IXGE_RX_DESCRIPTOR_STATUS2_UDP_CHECKSUM_ERROR))
	 ? 0 : VNET_BUFFER_F_L4_CHECKSUM_CORRECT);

  *flags0 = f0;
  *flags1 = f1;
}

static void
ixge_rx_trace (ixge_main_t * xm,
	       ixge_device_t * xd,
	       ixge_dma_queue_t * dq,
	       ixge_descriptor_t * before_descriptors,
	       u32 * before_buffers,
	       ixge_descriptor_t * after_descriptors, uword n_descriptors)
{
  vlib_main_t *vm = xm->vlib_main;
  vlib_node_runtime_t *node = dq->rx.node;
  ixge_rx_from_hw_descriptor_t *bd;
  ixge_rx_to_hw_descriptor_t *ad;
  u32 *b, n_left, is_sop, next_index_sop;

  n_left = n_descriptors;
  b = before_buffers;
  bd = &before_descriptors->rx_from_hw;
  ad = &after_descriptors->rx_to_hw;
  is_sop = dq->rx.is_start_of_packet;
  next_index_sop = dq->rx.saved_start_of_packet_next_index;

  while (n_left >= 2)
    {
      u32 bi0, bi1, flags0, flags1;
      vlib_buffer_t *b0, *b1;
      ixge_rx_dma_trace_t *t0, *t1;
      u8 next0, error0, next1, error1;

      bi0 = b[0];
      bi1 = b[1];
      n_left -= 2;

      b0 = vlib_get_buffer (vm, bi0);
      b1 = vlib_get_buffer (vm, bi1);

      ixge_rx_next_and_error_from_status_x2 (xd,
					     bd[0].status[0], bd[0].status[2],
					     bd[1].status[0], bd[1].status[2],
					     &next0, &error0, &flags0,
					     &next1, &error1, &flags1);

      next_index_sop = is_sop ? next0 : next_index_sop;
      vlib_trace_buffer (vm, node, next_index_sop, b0, /* follow_chain */ 0);
      t0 = vlib_add_trace (vm, node, b0, sizeof (t0[0]));
      t0->is_start_of_packet = is_sop;
      is_sop = (b0->flags & VLIB_BUFFER_NEXT_PRESENT) == 0;

      next_index_sop = is_sop ? next1 : next_index_sop;
      vlib_trace_buffer (vm, node, next_index_sop, b1, /* follow_chain */ 0);
      t1 = vlib_add_trace (vm, node, b1, sizeof (t1[0]));
      t1->is_start_of_packet = is_sop;
      is_sop = (b1->flags & VLIB_BUFFER_NEXT_PRESENT) == 0;

      t0->queue_index = dq->queue_index;
      t1->queue_index = dq->queue_index;
      t0->device_index = xd->device_index;
      t1->device_index = xd->device_index;
      t0->before.rx_from_hw = bd[0];
      t1->before.rx_from_hw = bd[1];
      t0->after.rx_to_hw = ad[0];
      t1->after.rx_to_hw = ad[1];
      t0->buffer_index = bi0;
      t1->buffer_index = bi1;
      memcpy (&t0->buffer, b0, sizeof (b0[0]) - sizeof (b0->pre_data));
      memcpy (&t1->buffer, b1, sizeof (b1[0]) - sizeof (b0->pre_data));
      memcpy (t0->buffer.pre_data, b0->data + b0->current_data,
	      sizeof (t0->buffer.pre_data));
      memcpy (t1->buffer.pre_data, b1->data + b1->current_data,
	      sizeof (t1->buffer.pre_data));

      b += 2;
      bd += 2;
      ad += 2;
    }

  while (n_left >= 1)
    {
      u32 bi0, flags0;
      vlib_buffer_t *b0;
      ixge_rx_dma_trace_t *t0;
      u8 next0, error0;

      bi0 = b[0];
      n_left -= 1;

      b0 = vlib_get_buffer (vm, bi0);

      ixge_rx_next_and_error_from_status_x1 (xd,
					     bd[0].status[0], bd[0].status[2],
					     &next0, &error0, &flags0);

      next_index_sop = is_sop ? next0 : next_index_sop;
      vlib_trace_buffer (vm, node, next_index_sop, b0, /* follow_chain */ 0);
      t0 = vlib_add_trace (vm, node, b0, sizeof (t0[0]));
      t0->is_start_of_packet = is_sop;
      is_sop = (b0->flags & VLIB_BUFFER_NEXT_PRESENT) == 0;

      t0->queue_index = dq->queue_index;
      t0->device_index = xd->device_index;
      t0->before.rx_from_hw = bd[0];
      t0->after.rx_to_hw = ad[0];
      t0->buffer_index = bi0;
      memcpy (&t0->buffer, b0, sizeof (b0[0]) - sizeof (b0->pre_data));
      memcpy (t0->buffer.pre_data, b0->data + b0->current_data,
	      sizeof (t0->buffer.pre_data));

      b += 1;
      bd += 1;
      ad += 1;
    }
}

typedef struct
{
  ixge_tx_descriptor_t descriptor;

  u32 buffer_index;

  u16 device_index;

  u8 queue_index;

  u8 is_start_of_packet;

  /* Copy of VLIB buffer; packet data stored in pre_data. */
  vlib_buffer_t buffer;
} ixge_tx_dma_trace_t;

static u8 *
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
	      t->buffer_index, format_vlib_buffer, &t->buffer);

  s = format (s, "\n%U", format_white_space, indent);

  f = format_ethernet_header_with_length;
  if (!f || !t->is_start_of_packet)
    f = format_hex_bytes;
  s = format (s, "%U", f, t->buffer.pre_data, sizeof (t->buffer.pre_data));

  return s;
}

typedef struct
{
  vlib_node_runtime_t *node;

  u32 is_start_of_packet;

  u32 n_bytes_in_packet;

  ixge_tx_descriptor_t *start_of_packet_descriptor;
} ixge_tx_state_t;

static void
ixge_tx_trace (ixge_main_t * xm,
	       ixge_device_t * xd,
	       ixge_dma_queue_t * dq,
	       ixge_tx_state_t * tx_state,
	       ixge_tx_descriptor_t * descriptors,
	       u32 * buffers, uword n_descriptors)
{
  vlib_main_t *vm = xm->vlib_main;
  vlib_node_runtime_t *node = tx_state->node;
  ixge_tx_descriptor_t *d;
  u32 *b, n_left, is_sop;

  n_left = n_descriptors;
  b = buffers;
  d = descriptors;
  is_sop = tx_state->is_start_of_packet;

  while (n_left >= 2)
    {
      u32 bi0, bi1;
      vlib_buffer_t *b0, *b1;
      ixge_tx_dma_trace_t *t0, *t1;

      bi0 = b[0];
      bi1 = b[1];
      n_left -= 2;

      b0 = vlib_get_buffer (vm, bi0);
      b1 = vlib_get_buffer (vm, bi1);

      t0 = vlib_add_trace (vm, node, b0, sizeof (t0[0]));
      t0->is_start_of_packet = is_sop;
      is_sop = (b0->flags & VLIB_BUFFER_NEXT_PRESENT) == 0;

      t1 = vlib_add_trace (vm, node, b1, sizeof (t1[0]));
      t1->is_start_of_packet = is_sop;
      is_sop = (b1->flags & VLIB_BUFFER_NEXT_PRESENT) == 0;

      t0->queue_index = dq->queue_index;
      t1->queue_index = dq->queue_index;
      t0->device_index = xd->device_index;
      t1->device_index = xd->device_index;
      t0->descriptor = d[0];
      t1->descriptor = d[1];
      t0->buffer_index = bi0;
      t1->buffer_index = bi1;
      memcpy (&t0->buffer, b0, sizeof (b0[0]) - sizeof (b0->pre_data));
      memcpy (&t1->buffer, b1, sizeof (b1[0]) - sizeof (b0->pre_data));
      memcpy (t0->buffer.pre_data, b0->data + b0->current_data,
	      sizeof (t0->buffer.pre_data));
      memcpy (t1->buffer.pre_data, b1->data + b1->current_data,
	      sizeof (t1->buffer.pre_data));

      b += 2;
      d += 2;
    }

  while (n_left >= 1)
    {
      u32 bi0;
      vlib_buffer_t *b0;
      ixge_tx_dma_trace_t *t0;

      bi0 = b[0];
      n_left -= 1;

      b0 = vlib_get_buffer (vm, bi0);

      t0 = vlib_add_trace (vm, node, b0, sizeof (t0[0]));
      t0->is_start_of_packet = is_sop;
      is_sop = (b0->flags & VLIB_BUFFER_NEXT_PRESENT) == 0;

      t0->queue_index = dq->queue_index;
      t0->device_index = xd->device_index;
      t0->descriptor = d[0];
      t0->buffer_index = bi0;
      memcpy (&t0->buffer, b0, sizeof (b0[0]) - sizeof (b0->pre_data));
      memcpy (t0->buffer.pre_data, b0->data + b0->current_data,
	      sizeof (t0->buffer.pre_data));

      b += 1;
      d += 1;
    }
}

always_inline uword
ixge_ring_sub (ixge_dma_queue_t * q, u32 i0, u32 i1)
{
  i32 d = i1 - i0;
  ASSERT (i0 < q->n_descriptors);
  ASSERT (i1 < q->n_descriptors);
  return d < 0 ? q->n_descriptors + d : d;
}

always_inline uword
ixge_ring_add (ixge_dma_queue_t * q, u32 i0, u32 i1)
{
  u32 d = i0 + i1;
  ASSERT (i0 < q->n_descriptors);
  ASSERT (i1 < q->n_descriptors);
  d -= d >= q->n_descriptors ? q->n_descriptors : 0;
  return d;
}

always_inline uword
ixge_tx_descriptor_matches_template (ixge_main_t * xm,
				     ixge_tx_descriptor_t * d)
{
  u32 cmp;

  cmp = ((d->status0 & xm->tx_descriptor_template_mask.status0)
	 ^ xm->tx_descriptor_template.status0);
  if (cmp)
    return 0;
  cmp = ((d->status1 & xm->tx_descriptor_template_mask.status1)
	 ^ xm->tx_descriptor_template.status1);
  if (cmp)
    return 0;

  return 1;
}

static uword
ixge_tx_no_wrap (ixge_main_t * xm,
		 ixge_device_t * xd,
		 ixge_dma_queue_t * dq,
		 u32 * buffers,
		 u32 start_descriptor_index,
		 u32 n_descriptors, ixge_tx_state_t * tx_state)
{
  vlib_main_t *vm = xm->vlib_main;
  ixge_tx_descriptor_t *d, *d_sop;
  u32 n_left = n_descriptors;
  u32 *to_free = vec_end (xm->tx_buffers_pending_free);
  u32 *to_tx =
    vec_elt_at_index (dq->descriptor_buffer_indices, start_descriptor_index);
  u32 is_sop = tx_state->is_start_of_packet;
  u32 len_sop = tx_state->n_bytes_in_packet;
  u16 template_status = xm->tx_descriptor_template.status0;
  u32 descriptor_prefetch_rotor = 0;

  ASSERT (start_descriptor_index + n_descriptors <= dq->n_descriptors);
  d = &dq->descriptors[start_descriptor_index].tx;
  d_sop = is_sop ? d : tx_state->start_of_packet_descriptor;

  while (n_left >= 4)
    {
      vlib_buffer_t *b0, *b1;
      u32 bi0, fi0, len0;
      u32 bi1, fi1, len1;
      u8 is_eop0, is_eop1;

      /* Prefetch next iteration. */
      vlib_prefetch_buffer_with_index (vm, buffers[2], LOAD);
      vlib_prefetch_buffer_with_index (vm, buffers[3], LOAD);

      if ((descriptor_prefetch_rotor & 0x3) == 0)
	CLIB_PREFETCH (d + 4, CLIB_CACHE_LINE_BYTES, STORE);

      descriptor_prefetch_rotor += 2;

      bi0 = buffers[0];
      bi1 = buffers[1];

      to_free[0] = fi0 = to_tx[0];
      to_tx[0] = bi0;
      to_free += fi0 != 0;

      to_free[0] = fi1 = to_tx[1];
      to_tx[1] = bi1;
      to_free += fi1 != 0;

      buffers += 2;
      n_left -= 2;
      to_tx += 2;

      b0 = vlib_get_buffer (vm, bi0);
      b1 = vlib_get_buffer (vm, bi1);

      is_eop0 = (b0->flags & VLIB_BUFFER_NEXT_PRESENT) == 0;
      is_eop1 = (b1->flags & VLIB_BUFFER_NEXT_PRESENT) == 0;

      len0 = b0->current_length;
      len1 = b1->current_length;

      ASSERT (ixge_tx_descriptor_matches_template (xm, d + 0));
      ASSERT (ixge_tx_descriptor_matches_template (xm, d + 1));

      d[0].buffer_address =
	vlib_get_buffer_data_physical_address (vm, bi0) + b0->current_data;
      d[1].buffer_address =
	vlib_get_buffer_data_physical_address (vm, bi1) + b1->current_data;

      d[0].n_bytes_this_buffer = len0;
      d[1].n_bytes_this_buffer = len1;

      d[0].status0 =
	template_status | (is_eop0 <<
			   IXGE_TX_DESCRIPTOR_STATUS0_LOG2_IS_END_OF_PACKET);
      d[1].status0 =
	template_status | (is_eop1 <<
			   IXGE_TX_DESCRIPTOR_STATUS0_LOG2_IS_END_OF_PACKET);

      len_sop = (is_sop ? 0 : len_sop) + len0;
      d_sop[0].status1 =
	IXGE_TX_DESCRIPTOR_STATUS1_N_BYTES_IN_PACKET (len_sop);
      d += 1;
      d_sop = is_eop0 ? d : d_sop;

      is_sop = is_eop0;

      len_sop = (is_sop ? 0 : len_sop) + len1;
      d_sop[0].status1 =
	IXGE_TX_DESCRIPTOR_STATUS1_N_BYTES_IN_PACKET (len_sop);
      d += 1;
      d_sop = is_eop1 ? d : d_sop;

      is_sop = is_eop1;
    }

  while (n_left > 0)
    {
      vlib_buffer_t *b0;
      u32 bi0, fi0, len0;
      u8 is_eop0;

      bi0 = buffers[0];

      to_free[0] = fi0 = to_tx[0];
      to_tx[0] = bi0;
      to_free += fi0 != 0;

      buffers += 1;
      n_left -= 1;
      to_tx += 1;

      b0 = vlib_get_buffer (vm, bi0);

      is_eop0 = (b0->flags & VLIB_BUFFER_NEXT_PRESENT) == 0;

      len0 = b0->current_length;

      ASSERT (ixge_tx_descriptor_matches_template (xm, d + 0));

      d[0].buffer_address =
	vlib_get_buffer_data_physical_address (vm, bi0) + b0->current_data;

      d[0].n_bytes_this_buffer = len0;

      d[0].status0 =
	template_status | (is_eop0 <<
			   IXGE_TX_DESCRIPTOR_STATUS0_LOG2_IS_END_OF_PACKET);

      len_sop = (is_sop ? 0 : len_sop) + len0;
      d_sop[0].status1 =
	IXGE_TX_DESCRIPTOR_STATUS1_N_BYTES_IN_PACKET (len_sop);
      d += 1;
      d_sop = is_eop0 ? d : d_sop;

      is_sop = is_eop0;
    }

  if (tx_state->node->flags & VLIB_NODE_FLAG_TRACE)
    {
      to_tx =
	vec_elt_at_index (dq->descriptor_buffer_indices,
			  start_descriptor_index);
      ixge_tx_trace (xm, xd, dq, tx_state,
		     &dq->descriptors[start_descriptor_index].tx, to_tx,
		     n_descriptors);
    }

  _vec_len (xm->tx_buffers_pending_free) =
    to_free - xm->tx_buffers_pending_free;

  /* When we are done d_sop can point to end of ring.  Wrap it if so. */
  {
    ixge_tx_descriptor_t *d_start = &dq->descriptors[0].tx;

    ASSERT (d_sop - d_start <= dq->n_descriptors);
    d_sop = d_sop - d_start == dq->n_descriptors ? d_start : d_sop;
  }

  tx_state->is_start_of_packet = is_sop;
  tx_state->start_of_packet_descriptor = d_sop;
  tx_state->n_bytes_in_packet = len_sop;

  return n_descriptors;
}

static uword
ixge_interface_tx (vlib_main_t * vm,
		   vlib_node_runtime_t * node, vlib_frame_t * f)
{
  ixge_main_t *xm = &ixge_main;
  vnet_interface_output_runtime_t *rd = (void *) node->runtime_data;
  ixge_device_t *xd = vec_elt_at_index (xm->devices, rd->dev_instance);
  ixge_dma_queue_t *dq;
  u32 *from, n_left_tx, n_descriptors_to_tx, n_tail_drop;
  u32 queue_index = 0;		/* fixme parameter */
  ixge_tx_state_t tx_state;

  tx_state.node = node;
  tx_state.is_start_of_packet = 1;
  tx_state.start_of_packet_descriptor = 0;
  tx_state.n_bytes_in_packet = 0;

  from = vlib_frame_vector_args (f);

  dq = vec_elt_at_index (xd->dma_queues[VLIB_TX], queue_index);

  dq->head_index = dq->tx.head_index_write_back[0];

  /* Since head == tail means ring is empty we can send up to dq->n_descriptors - 1. */
  n_left_tx = dq->n_descriptors - 1;
  n_left_tx -= ixge_ring_sub (dq, dq->head_index, dq->tail_index);

  _vec_len (xm->tx_buffers_pending_free) = 0;

  n_descriptors_to_tx = f->n_vectors;
  n_tail_drop = 0;
  if (PREDICT_FALSE (n_descriptors_to_tx > n_left_tx))
    {
      i32 i, n_ok, i_eop, i_sop;

      i_sop = i_eop = ~0;
      for (i = n_left_tx - 1; i >= 0; i--)
	{
	  vlib_buffer_t *b = vlib_get_buffer (vm, from[i]);
	  if (!(b->flags & VLIB_BUFFER_NEXT_PRESENT))
	    {
	      if (i_sop != ~0 && i_eop != ~0)
		break;
	      i_eop = i;
	      i_sop = i + 1;
	    }
	}
      if (i == 0)
	n_ok = 0;
      else
	n_ok = i_eop + 1;

      {
	ELOG_TYPE_DECLARE (e) =
	{
	.function = (char *) __FUNCTION__,.format =
	    "ixge %d, ring full to tx %d head %d tail %d",.format_args =
	    "i2i2i2i2",};
	struct
	{
	  u16 instance, to_tx, head, tail;
	} *ed;
	ed = ELOG_DATA (&vm->elog_main, e);
	ed->instance = xd->device_index;
	ed->to_tx = n_descriptors_to_tx;
	ed->head = dq->head_index;
	ed->tail = dq->tail_index;
      }

      if (n_ok < n_descriptors_to_tx)
	{
	  n_tail_drop = n_descriptors_to_tx - n_ok;
	  vec_add (xm->tx_buffers_pending_free, from + n_ok, n_tail_drop);
	  vlib_error_count (vm, ixge_input_node.index,
			    IXGE_ERROR_tx_full_drops, n_tail_drop);
	}

      n_descriptors_to_tx = n_ok;
    }

  dq->tx.n_buffers_on_ring += n_descriptors_to_tx;

  /* Process from tail to end of descriptor ring. */
  if (n_descriptors_to_tx > 0 && dq->tail_index < dq->n_descriptors)
    {
      u32 n =
	clib_min (dq->n_descriptors - dq->tail_index, n_descriptors_to_tx);
      n = ixge_tx_no_wrap (xm, xd, dq, from, dq->tail_index, n, &tx_state);
      from += n;
      n_descriptors_to_tx -= n;
      dq->tail_index += n;
      ASSERT (dq->tail_index <= dq->n_descriptors);
      if (dq->tail_index == dq->n_descriptors)
	dq->tail_index = 0;
    }

  if (n_descriptors_to_tx > 0)
    {
      u32 n =
	ixge_tx_no_wrap (xm, xd, dq, from, 0, n_descriptors_to_tx, &tx_state);
      from += n;
      ASSERT (n == n_descriptors_to_tx);
      dq->tail_index += n;
      ASSERT (dq->tail_index <= dq->n_descriptors);
      if (dq->tail_index == dq->n_descriptors)
	dq->tail_index = 0;
    }

  /* We should only get full packets. */
  ASSERT (tx_state.is_start_of_packet);

  /* Report status when last descriptor is done. */
  {
    u32 i = dq->tail_index == 0 ? dq->n_descriptors - 1 : dq->tail_index - 1;
    ixge_tx_descriptor_t *d = &dq->descriptors[i].tx;
    d->status0 |= IXGE_TX_DESCRIPTOR_STATUS0_REPORT_STATUS;
  }

  /* Give new descriptors to hardware. */
  {
    ixge_dma_regs_t *dr = get_dma_regs (xd, VLIB_TX, queue_index);

    CLIB_MEMORY_BARRIER ();

    dr->tail_index = dq->tail_index;
  }

  /* Free any buffers that are done. */
  {
    u32 n = _vec_len (xm->tx_buffers_pending_free);
    if (n > 0)
      {
	vlib_buffer_free_no_next (vm, xm->tx_buffers_pending_free, n);
	_vec_len (xm->tx_buffers_pending_free) = 0;
	ASSERT (dq->tx.n_buffers_on_ring >= n);
	dq->tx.n_buffers_on_ring -= (n - n_tail_drop);
      }
  }

  return f->n_vectors;
}

static uword
ixge_rx_queue_no_wrap (ixge_main_t * xm,
		       ixge_device_t * xd,
		       ixge_dma_queue_t * dq,
		       u32 start_descriptor_index, u32 n_descriptors)
{
  vlib_main_t *vm = xm->vlib_main;
  vlib_node_runtime_t *node = dq->rx.node;
  ixge_descriptor_t *d;
  static ixge_descriptor_t *d_trace_save;
  static u32 *d_trace_buffers;
  u32 n_descriptors_left = n_descriptors;
  u32 *to_rx =
    vec_elt_at_index (dq->descriptor_buffer_indices, start_descriptor_index);
  u32 *to_add;
  u32 bi_sop = dq->rx.saved_start_of_packet_buffer_index;
  u32 bi_last = dq->rx.saved_last_buffer_index;
  u32 next_index_sop = dq->rx.saved_start_of_packet_next_index;
  u32 is_sop = dq->rx.is_start_of_packet;
  u32 next_index, n_left_to_next, *to_next;
  u32 n_packets = 0;
  u32 n_bytes = 0;
  u32 n_trace = vlib_get_trace_count (vm, node);
  vlib_buffer_t *b_last, b_dummy;

  ASSERT (start_descriptor_index + n_descriptors <= dq->n_descriptors);
  d = &dq->descriptors[start_descriptor_index];

  b_last = bi_last != ~0 ? vlib_get_buffer (vm, bi_last) : &b_dummy;
  next_index = dq->rx.next_index;

  if (n_trace > 0)
    {
      u32 n = clib_min (n_trace, n_descriptors);
      if (d_trace_save)
	{
	  _vec_len (d_trace_save) = 0;
	  _vec_len (d_trace_buffers) = 0;
	}
      vec_add (d_trace_save, (ixge_descriptor_t *) d, n);
      vec_add (d_trace_buffers, to_rx, n);
    }

  {
    uword l = vec_len (xm->rx_buffers_to_add);

    if (l < n_descriptors_left)
      {
	u32 n_to_alloc = 2 * dq->n_descriptors - l;
	u32 n_allocated;

	vec_resize (xm->rx_buffers_to_add, n_to_alloc);

	_vec_len (xm->rx_buffers_to_add) = l;
	n_allocated = vlib_buffer_alloc_from_free_list
	  (vm, xm->rx_buffers_to_add + l, n_to_alloc,
	   xm->vlib_buffer_free_list_index);
	_vec_len (xm->rx_buffers_to_add) += n_allocated;

	/* Handle transient allocation failure */
	if (PREDICT_FALSE (l + n_allocated <= n_descriptors_left))
	  {
	    if (n_allocated == 0)
	      vlib_error_count (vm, ixge_input_node.index,
				IXGE_ERROR_rx_alloc_no_physmem, 1);
	    else
	      vlib_error_count (vm, ixge_input_node.index,
				IXGE_ERROR_rx_alloc_fail, 1);

	    n_descriptors_left = l + n_allocated;
	  }
	n_descriptors = n_descriptors_left;
      }

    /* Add buffers from end of vector going backwards. */
    to_add = vec_end (xm->rx_buffers_to_add) - 1;
  }

  while (n_descriptors_left > 0)
    {
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_descriptors_left >= 4 && n_left_to_next >= 2)
	{
	  vlib_buffer_t *b0, *b1;
	  u32 bi0, fi0, len0, l3_offset0, s20, s00, flags0;
	  u32 bi1, fi1, len1, l3_offset1, s21, s01, flags1;
	  u8 is_eop0, error0, next0;
	  u8 is_eop1, error1, next1;
	  ixge_descriptor_t d0, d1;

	  vlib_prefetch_buffer_with_index (vm, to_rx[2], STORE);
	  vlib_prefetch_buffer_with_index (vm, to_rx[3], STORE);

	  CLIB_PREFETCH (d + 2, 32, STORE);

	  d0.as_u32x4 = d[0].as_u32x4;
	  d1.as_u32x4 = d[1].as_u32x4;

	  s20 = d0.rx_from_hw.status[2];
	  s21 = d1.rx_from_hw.status[2];

	  s00 = d0.rx_from_hw.status[0];
	  s01 = d1.rx_from_hw.status[0];

	  if (!
	      ((s20 & s21) & IXGE_RX_DESCRIPTOR_STATUS2_IS_OWNED_BY_SOFTWARE))
	    goto found_hw_owned_descriptor_x2;

	  bi0 = to_rx[0];
	  bi1 = to_rx[1];

	  ASSERT (to_add - 1 >= xm->rx_buffers_to_add);
	  fi0 = to_add[0];
	  fi1 = to_add[-1];

	  to_rx[0] = fi0;
	  to_rx[1] = fi1;
	  to_rx += 2;
	  to_add -= 2;

	  ASSERT (VLIB_BUFFER_KNOWN_ALLOCATED ==
		  vlib_buffer_is_known (vm, bi0));
	  ASSERT (VLIB_BUFFER_KNOWN_ALLOCATED ==
		  vlib_buffer_is_known (vm, bi1));
	  ASSERT (VLIB_BUFFER_KNOWN_ALLOCATED ==
		  vlib_buffer_is_known (vm, fi0));
	  ASSERT (VLIB_BUFFER_KNOWN_ALLOCATED ==
		  vlib_buffer_is_known (vm, fi1));

	  b0 = vlib_get_buffer (vm, bi0);
	  b1 = vlib_get_buffer (vm, bi1);

	  /*
	   * Turn this on if you run into
	   * "bad monkey" contexts, and you want to know exactly
	   * which nodes they've visited... See main.c...
	   */
	  VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b0);
	  VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b1);

	  CLIB_PREFETCH (b0->data, CLIB_CACHE_LINE_BYTES, LOAD);
	  CLIB_PREFETCH (b1->data, CLIB_CACHE_LINE_BYTES, LOAD);

	  is_eop0 = (s20 & IXGE_RX_DESCRIPTOR_STATUS2_IS_END_OF_PACKET) != 0;
	  is_eop1 = (s21 & IXGE_RX_DESCRIPTOR_STATUS2_IS_END_OF_PACKET) != 0;

	  ixge_rx_next_and_error_from_status_x2 (xd, s00, s20, s01, s21,
						 &next0, &error0, &flags0,
						 &next1, &error1, &flags1);

	  next0 = is_sop ? next0 : next_index_sop;
	  next1 = is_eop0 ? next1 : next0;
	  next_index_sop = next1;

	  b0->flags |= flags0 | (!is_eop0 << VLIB_BUFFER_LOG2_NEXT_PRESENT);
	  b1->flags |= flags1 | (!is_eop1 << VLIB_BUFFER_LOG2_NEXT_PRESENT);

	  vnet_buffer (b0)->sw_if_index[VLIB_RX] = xd->vlib_sw_if_index;
	  vnet_buffer (b1)->sw_if_index[VLIB_RX] = xd->vlib_sw_if_index;
	  vnet_buffer (b0)->sw_if_index[VLIB_TX] = (u32) ~ 0;
	  vnet_buffer (b1)->sw_if_index[VLIB_TX] = (u32) ~ 0;

	  b0->error = node->errors[error0];
	  b1->error = node->errors[error1];

	  len0 = d0.rx_from_hw.n_packet_bytes_this_descriptor;
	  len1 = d1.rx_from_hw.n_packet_bytes_this_descriptor;
	  n_bytes += len0 + len1;
	  n_packets += is_eop0 + is_eop1;

	  /* Give new buffers to hardware. */
	  d0.rx_to_hw.tail_address =
	    vlib_get_buffer_data_physical_address (vm, fi0);
	  d1.rx_to_hw.tail_address =
	    vlib_get_buffer_data_physical_address (vm, fi1);
	  d0.rx_to_hw.head_address = d[0].rx_to_hw.tail_address;
	  d1.rx_to_hw.head_address = d[1].rx_to_hw.tail_address;
	  d[0].as_u32x4 = d0.as_u32x4;
	  d[1].as_u32x4 = d1.as_u32x4;

	  d += 2;
	  n_descriptors_left -= 2;

	  /* Point to either l2 or l3 header depending on next. */
	  l3_offset0 = (is_sop && (next0 != IXGE_RX_NEXT_ETHERNET_INPUT))
	    ? IXGE_RX_DESCRIPTOR_STATUS0_L3_OFFSET (s00) : 0;
	  l3_offset1 = (is_eop0 && (next1 != IXGE_RX_NEXT_ETHERNET_INPUT))
	    ? IXGE_RX_DESCRIPTOR_STATUS0_L3_OFFSET (s01) : 0;

	  b0->current_length = len0 - l3_offset0;
	  b1->current_length = len1 - l3_offset1;
	  b0->current_data = l3_offset0;
	  b1->current_data = l3_offset1;

	  b_last->next_buffer = is_sop ? ~0 : bi0;
	  b0->next_buffer = is_eop0 ? ~0 : bi1;
	  bi_last = bi1;
	  b_last = b1;

	  if (CLIB_DEBUG > 0)
	    {
	      u32 bi_sop0 = is_sop ? bi0 : bi_sop;
	      u32 bi_sop1 = is_eop0 ? bi1 : bi_sop0;

	      if (is_eop0)
		{
		  u8 *msg = vlib_validate_buffer (vm, bi_sop0,
						  /* follow_buffer_next */ 1);
		  ASSERT (!msg);
		}
	      if (is_eop1)
		{
		  u8 *msg = vlib_validate_buffer (vm, bi_sop1,
						  /* follow_buffer_next */ 1);
		  ASSERT (!msg);
		}
	    }
	  if (0)		/* "Dave" version */
	    {
	      u32 bi_sop0 = is_sop ? bi0 : bi_sop;
	      u32 bi_sop1 = is_eop0 ? bi1 : bi_sop0;

	      if (is_eop0)
		{
		  to_next[0] = bi_sop0;
		  to_next++;
		  n_left_to_next--;

		  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
						   to_next, n_left_to_next,
						   bi_sop0, next0);
		}
	      if (is_eop1)
		{
		  to_next[0] = bi_sop1;
		  to_next++;
		  n_left_to_next--;

		  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
						   to_next, n_left_to_next,
						   bi_sop1, next1);
		}
	      is_sop = is_eop1;
	      bi_sop = bi_sop1;
	    }
	  if (1)		/* "Eliot" version */
	    {
	      /* Speculatively enqueue to cached next. */
	      u8 saved_is_sop = is_sop;
	      u32 bi_sop_save = bi_sop;

	      bi_sop = saved_is_sop ? bi0 : bi_sop;
	      to_next[0] = bi_sop;
	      to_next += is_eop0;
	      n_left_to_next -= is_eop0;

	      bi_sop = is_eop0 ? bi1 : bi_sop;
	      to_next[0] = bi_sop;
	      to_next += is_eop1;
	      n_left_to_next -= is_eop1;

	      is_sop = is_eop1;

	      if (PREDICT_FALSE
		  (!(next0 == next_index && next1 == next_index)))
		{
		  /* Undo speculation. */
		  to_next -= is_eop0 + is_eop1;
		  n_left_to_next += is_eop0 + is_eop1;

		  /* Re-do both descriptors being careful about where we enqueue. */
		  bi_sop = saved_is_sop ? bi0 : bi_sop_save;
		  if (is_eop0)
		    {
		      if (next0 != next_index)
			vlib_set_next_frame_buffer (vm, node, next0, bi_sop);
		      else
			{
			  to_next[0] = bi_sop;
			  to_next += 1;
			  n_left_to_next -= 1;
			}
		    }

		  bi_sop = is_eop0 ? bi1 : bi_sop;
		  if (is_eop1)
		    {
		      if (next1 != next_index)
			vlib_set_next_frame_buffer (vm, node, next1, bi_sop);
		      else
			{
			  to_next[0] = bi_sop;
			  to_next += 1;
			  n_left_to_next -= 1;
			}
		    }

		  /* Switch cached next index when next for both packets is the same. */
		  if (is_eop0 && is_eop1 && next0 == next1)
		    {
		      vlib_put_next_frame (vm, node, next_index,
					   n_left_to_next);
		      next_index = next0;
		      vlib_get_next_frame (vm, node, next_index,
					   to_next, n_left_to_next);
		    }
		}
	    }
	}

      /* Bail out of dual loop and proceed with single loop. */
    found_hw_owned_descriptor_x2:

      while (n_descriptors_left > 0 && n_left_to_next > 0)
	{
	  vlib_buffer_t *b0;
	  u32 bi0, fi0, len0, l3_offset0, s20, s00, flags0;
	  u8 is_eop0, error0, next0;
	  ixge_descriptor_t d0;

	  d0.as_u32x4 = d[0].as_u32x4;

	  s20 = d0.rx_from_hw.status[2];
	  s00 = d0.rx_from_hw.status[0];

	  if (!(s20 & IXGE_RX_DESCRIPTOR_STATUS2_IS_OWNED_BY_SOFTWARE))
	    goto found_hw_owned_descriptor_x1;

	  bi0 = to_rx[0];
	  ASSERT (to_add >= xm->rx_buffers_to_add);
	  fi0 = to_add[0];

	  to_rx[0] = fi0;
	  to_rx += 1;
	  to_add -= 1;

	  ASSERT (VLIB_BUFFER_KNOWN_ALLOCATED ==
		  vlib_buffer_is_known (vm, bi0));
	  ASSERT (VLIB_BUFFER_KNOWN_ALLOCATED ==
		  vlib_buffer_is_known (vm, fi0));

	  b0 = vlib_get_buffer (vm, bi0);

	  /*
	   * Turn this on if you run into
	   * "bad monkey" contexts, and you want to know exactly
	   * which nodes they've visited...
	   */
	  VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b0);

	  is_eop0 = (s20 & IXGE_RX_DESCRIPTOR_STATUS2_IS_END_OF_PACKET) != 0;
	  ixge_rx_next_and_error_from_status_x1
	    (xd, s00, s20, &next0, &error0, &flags0);

	  next0 = is_sop ? next0 : next_index_sop;
	  next_index_sop = next0;

	  b0->flags |= flags0 | (!is_eop0 << VLIB_BUFFER_LOG2_NEXT_PRESENT);

	  vnet_buffer (b0)->sw_if_index[VLIB_RX] = xd->vlib_sw_if_index;
	  vnet_buffer (b0)->sw_if_index[VLIB_TX] = (u32) ~ 0;

	  b0->error = node->errors[error0];

	  len0 = d0.rx_from_hw.n_packet_bytes_this_descriptor;
	  n_bytes += len0;
	  n_packets += is_eop0;

	  /* Give new buffer to hardware. */
	  d0.rx_to_hw.tail_address =
	    vlib_get_buffer_data_physical_address (vm, fi0);
	  d0.rx_to_hw.head_address = d0.rx_to_hw.tail_address;
	  d[0].as_u32x4 = d0.as_u32x4;

	  d += 1;
	  n_descriptors_left -= 1;

	  /* Point to either l2 or l3 header depending on next. */
	  l3_offset0 = (is_sop && (next0 != IXGE_RX_NEXT_ETHERNET_INPUT))
	    ? IXGE_RX_DESCRIPTOR_STATUS0_L3_OFFSET (s00) : 0;
	  b0->current_length = len0 - l3_offset0;
	  b0->current_data = l3_offset0;

	  b_last->next_buffer = is_sop ? ~0 : bi0;
	  bi_last = bi0;
	  b_last = b0;

	  bi_sop = is_sop ? bi0 : bi_sop;

	  if (CLIB_DEBUG > 0 && is_eop0)
	    {
	      u8 *msg =
		vlib_validate_buffer (vm, bi_sop, /* follow_buffer_next */ 1);
	      ASSERT (!msg);
	    }

	  if (0)		/* "Dave" version */
	    {
	      if (is_eop0)
		{
		  to_next[0] = bi_sop;
		  to_next++;
		  n_left_to_next--;

		  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
						   to_next, n_left_to_next,
						   bi_sop, next0);
		}
	    }
	  if (1)		/* "Eliot" version */
	    {
	      if (PREDICT_TRUE (next0 == next_index))
		{
		  to_next[0] = bi_sop;
		  to_next += is_eop0;
		  n_left_to_next -= is_eop0;
		}
	      else
		{
		  if (next0 != next_index && is_eop0)
		    vlib_set_next_frame_buffer (vm, node, next0, bi_sop);

		  vlib_put_next_frame (vm, node, next_index, n_left_to_next);
		  next_index = next0;
		  vlib_get_next_frame (vm, node, next_index,
				       to_next, n_left_to_next);
		}
	    }
	  is_sop = is_eop0;
	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

found_hw_owned_descriptor_x1:
  if (n_descriptors_left > 0)
    vlib_put_next_frame (vm, node, next_index, n_left_to_next);

  _vec_len (xm->rx_buffers_to_add) = (to_add + 1) - xm->rx_buffers_to_add;

  {
    u32 n_done = n_descriptors - n_descriptors_left;

    if (n_trace > 0 && n_done > 0)
      {
	u32 n = clib_min (n_trace, n_done);
	ixge_rx_trace (xm, xd, dq,
		       d_trace_save,
		       d_trace_buffers,
		       &dq->descriptors[start_descriptor_index], n);
	vlib_set_trace_count (vm, node, n_trace - n);
      }
    if (d_trace_save)
      {
	_vec_len (d_trace_save) = 0;
	_vec_len (d_trace_buffers) = 0;
      }

    /* Don't keep a reference to b_last if we don't have to.
       Otherwise we can over-write a next_buffer pointer after already haven
       enqueued a packet. */
    if (is_sop)
      {
	b_last->next_buffer = ~0;
	bi_last = ~0;
      }

    dq->rx.n_descriptors_done_this_call = n_done;
    dq->rx.n_descriptors_done_total += n_done;
    dq->rx.is_start_of_packet = is_sop;
    dq->rx.saved_start_of_packet_buffer_index = bi_sop;
    dq->rx.saved_last_buffer_index = bi_last;
    dq->rx.saved_start_of_packet_next_index = next_index_sop;
    dq->rx.next_index = next_index;
    dq->rx.n_bytes += n_bytes;

    return n_packets;
  }
}

static uword
ixge_rx_queue (ixge_main_t * xm,
	       ixge_device_t * xd,
	       vlib_node_runtime_t * node, u32 queue_index)
{
  ixge_dma_queue_t *dq =
    vec_elt_at_index (xd->dma_queues[VLIB_RX], queue_index);
  ixge_dma_regs_t *dr = get_dma_regs (xd, VLIB_RX, dq->queue_index);
  uword n_packets = 0;
  u32 hw_head_index, sw_head_index;

  /* One time initialization. */
  if (!dq->rx.node)
    {
      dq->rx.node = node;
      dq->rx.is_start_of_packet = 1;
      dq->rx.saved_start_of_packet_buffer_index = ~0;
      dq->rx.saved_last_buffer_index = ~0;
    }

  dq->rx.next_index = node->cached_next_index;

  dq->rx.n_descriptors_done_total = 0;
  dq->rx.n_descriptors_done_this_call = 0;
  dq->rx.n_bytes = 0;

  /* Fetch head from hardware and compare to where we think we are. */
  hw_head_index = dr->head_index;
  sw_head_index = dq->head_index;

  if (hw_head_index == sw_head_index)
    goto done;

  if (hw_head_index < sw_head_index)
    {
      u32 n_tried = dq->n_descriptors - sw_head_index;
      n_packets += ixge_rx_queue_no_wrap (xm, xd, dq, sw_head_index, n_tried);
      sw_head_index =
	ixge_ring_add (dq, sw_head_index,
		       dq->rx.n_descriptors_done_this_call);

      if (dq->rx.n_descriptors_done_this_call != n_tried)
	goto done;
    }
  if (hw_head_index >= sw_head_index)
    {
      u32 n_tried = hw_head_index - sw_head_index;
      n_packets += ixge_rx_queue_no_wrap (xm, xd, dq, sw_head_index, n_tried);
      sw_head_index =
	ixge_ring_add (dq, sw_head_index,
		       dq->rx.n_descriptors_done_this_call);
    }

done:
  dq->head_index = sw_head_index;
  dq->tail_index =
    ixge_ring_add (dq, dq->tail_index, dq->rx.n_descriptors_done_total);

  /* Give tail back to hardware. */
  CLIB_MEMORY_BARRIER ();

  dr->tail_index = dq->tail_index;

  vlib_increment_combined_counter (vnet_main.
				   interface_main.combined_sw_if_counters +
				   VNET_INTERFACE_COUNTER_RX,
				   0 /* thread_index */ ,
				   xd->vlib_sw_if_index, n_packets,
				   dq->rx.n_bytes);

  return n_packets;
}

static void
ixge_interrupt (ixge_main_t * xm, ixge_device_t * xd, u32 i)
{
  vlib_main_t *vm = xm->vlib_main;
  ixge_regs_t *r = xd->regs;

  if (i != 20)
    {
      ELOG_TYPE_DECLARE (e) =
      {
	.function = (char *) __FUNCTION__,.format =
	  "ixge %d, %s",.format_args = "i1t1",.n_enum_strings =
	  16,.enum_strings =
	{
      "flow director",
	    "rx miss",
	    "pci exception",
	    "mailbox",
	    "link status change",
	    "linksec key exchange",
	    "manageability event",
	    "reserved23",
	    "sdp0",
	    "sdp1",
	    "sdp2",
	    "sdp3",
	    "ecc", "descriptor handler error", "tcp timer", "other",},};
      struct
      {
	u8 instance;
	u8 index;
      } *ed;
      ed = ELOG_DATA (&vm->elog_main, e);
      ed->instance = xd->device_index;
      ed->index = i - 16;
    }
  else
    {
      u32 v = r->xge_mac.link_status;
      uword is_up = (v & (1 << 30)) != 0;

      ELOG_TYPE_DECLARE (e) =
      {
      .function = (char *) __FUNCTION__,.format =
	  "ixge %d, link status change 0x%x",.format_args = "i4i4",};
      struct
      {
	u32 instance, link_status;
      } *ed;
      ed = ELOG_DATA (&vm->elog_main, e);
      ed->instance = xd->device_index;
      ed->link_status = v;
      xd->link_status_at_last_link_change = v;

      vlib_process_signal_event (vm, ixge_process_node.index,
				 EVENT_SET_FLAGS,
				 ((is_up << 31) | xd->vlib_hw_if_index));
    }
}

always_inline u32
clean_block (u32 * b, u32 * t, u32 n_left)
{
  u32 *t0 = t;

  while (n_left >= 4)
    {
      u32 bi0, bi1, bi2, bi3;

      t[0] = bi0 = b[0];
      b[0] = 0;
      t += bi0 != 0;

      t[0] = bi1 = b[1];
      b[1] = 0;
      t += bi1 != 0;

      t[0] = bi2 = b[2];
      b[2] = 0;
      t += bi2 != 0;

      t[0] = bi3 = b[3];
      b[3] = 0;
      t += bi3 != 0;

      b += 4;
      n_left -= 4;
    }

  while (n_left > 0)
    {
      u32 bi0;

      t[0] = bi0 = b[0];
      b[0] = 0;
      t += bi0 != 0;
      b += 1;
      n_left -= 1;
    }

  return t - t0;
}

static void
ixge_tx_queue (ixge_main_t * xm, ixge_device_t * xd, u32 queue_index)
{
  vlib_main_t *vm = xm->vlib_main;
  ixge_dma_queue_t *dq =
    vec_elt_at_index (xd->dma_queues[VLIB_TX], queue_index);
  u32 n_clean, *b, *t, *t0;
  i32 n_hw_owned_descriptors;
  i32 first_to_clean, last_to_clean;
  u64 hwbp_race = 0;

  /* Handle case where head write back pointer update
   * arrives after the interrupt during high PCI bus loads.
   */
  while ((dq->head_index == dq->tx.head_index_write_back[0]) &&
	 dq->tx.n_buffers_on_ring && (dq->head_index != dq->tail_index))
    {
      hwbp_race++;
      if (IXGE_HWBP_RACE_ELOG && (hwbp_race == 1))
	{
	  ELOG_TYPE_DECLARE (e) =
	  {
	  .function = (char *) __FUNCTION__,.format =
	      "ixge %d tx head index race: head %4d, tail %4d, buffs %4d",.format_args
	      = "i4i4i4i4",};
	  struct
	  {
	    u32 instance, head_index, tail_index, n_buffers_on_ring;
	  } *ed;
	  ed = ELOG_DATA (&vm->elog_main, e);
	  ed->instance = xd->device_index;
	  ed->head_index = dq->head_index;
	  ed->tail_index = dq->tail_index;
	  ed->n_buffers_on_ring = dq->tx.n_buffers_on_ring;
	}
    }

  dq->head_index = dq->tx.head_index_write_back[0];
  n_hw_owned_descriptors = ixge_ring_sub (dq, dq->head_index, dq->tail_index);
  ASSERT (dq->tx.n_buffers_on_ring >= n_hw_owned_descriptors);
  n_clean = dq->tx.n_buffers_on_ring - n_hw_owned_descriptors;

  if (IXGE_HWBP_RACE_ELOG && hwbp_race)
    {
      ELOG_TYPE_DECLARE (e) =
      {
      .function = (char *) __FUNCTION__,.format =
	  "ixge %d tx head index race: head %4d, hw_owned %4d, n_clean %4d, retries %d",.format_args
	  = "i4i4i4i4i4",};
      struct
      {
	u32 instance, head_index, n_hw_owned_descriptors, n_clean, retries;
      } *ed;
      ed = ELOG_DATA (&vm->elog_main, e);
      ed->instance = xd->device_index;
      ed->head_index = dq->head_index;
      ed->n_hw_owned_descriptors = n_hw_owned_descriptors;
      ed->n_clean = n_clean;
      ed->retries = hwbp_race;
    }

  /*
   * This function used to wait until hardware owned zero descriptors.
   * At high PPS rates, that doesn't happen until the TX ring is
   * completely full of descriptors which need to be cleaned up.
   * That, in turn, causes TX ring-full drops and/or long RX service
   * interruptions.
   */
  if (n_clean == 0)
    return;

  /* Clean the n_clean descriptors prior to the reported hardware head */
  last_to_clean = dq->head_index - 1;
  last_to_clean = (last_to_clean < 0) ? last_to_clean + dq->n_descriptors :
    last_to_clean;

  first_to_clean = (last_to_clean) - (n_clean - 1);
  first_to_clean = (first_to_clean < 0) ? first_to_clean + dq->n_descriptors :
    first_to_clean;

  vec_resize (xm->tx_buffers_pending_free, dq->n_descriptors - 1);
  t0 = t = xm->tx_buffers_pending_free;
  b = dq->descriptor_buffer_indices + first_to_clean;

  /* Wrap case: clean from first to end, then start to last */
  if (first_to_clean > last_to_clean)
    {
      t += clean_block (b, t, (dq->n_descriptors - 1) - first_to_clean);
      first_to_clean = 0;
      b = dq->descriptor_buffer_indices;
    }

  /* Typical case: clean from first to last */
  if (first_to_clean <= last_to_clean)
    t += clean_block (b, t, (last_to_clean - first_to_clean) + 1);

  if (t > t0)
    {
      u32 n = t - t0;
      vlib_buffer_free_no_next (vm, t0, n);
      ASSERT (dq->tx.n_buffers_on_ring >= n);
      dq->tx.n_buffers_on_ring -= n;
      _vec_len (xm->tx_buffers_pending_free) = 0;
    }
}

/* RX queue interrupts 0 thru 7; TX 8 thru 15. */
always_inline uword
ixge_interrupt_is_rx_queue (uword i)
{
  return i < 8;
}

always_inline uword
ixge_interrupt_is_tx_queue (uword i)
{
  return i >= 8 && i < 16;
}

always_inline uword
ixge_tx_queue_to_interrupt (uword i)
{
  return 8 + i;
}

always_inline uword
ixge_rx_queue_to_interrupt (uword i)
{
  return 0 + i;
}

always_inline uword
ixge_interrupt_rx_queue (uword i)
{
  ASSERT (ixge_interrupt_is_rx_queue (i));
  return i - 0;
}

always_inline uword
ixge_interrupt_tx_queue (uword i)
{
  ASSERT (ixge_interrupt_is_tx_queue (i));
  return i - 8;
}

static uword
ixge_device_input (ixge_main_t * xm,
		   ixge_device_t * xd, vlib_node_runtime_t * node)
{
  ixge_regs_t *r = xd->regs;
  u32 i, s;
  uword n_rx_packets = 0;

  s = r->interrupt.status_write_1_to_set;
  if (s)
    r->interrupt.status_write_1_to_clear = s;

  /* *INDENT-OFF* */
  foreach_set_bit (i, s, ({
    if (ixge_interrupt_is_rx_queue (i))
      n_rx_packets += ixge_rx_queue (xm, xd, node, ixge_interrupt_rx_queue (i));

    else if (ixge_interrupt_is_tx_queue (i))
      ixge_tx_queue (xm, xd, ixge_interrupt_tx_queue (i));

    else
      ixge_interrupt (xm, xd, i);
  }));
  /* *INDENT-ON* */

  return n_rx_packets;
}

static uword
ixge_input (vlib_main_t * vm, vlib_node_runtime_t * node, vlib_frame_t * f)
{
  ixge_main_t *xm = &ixge_main;
  ixge_device_t *xd;
  uword n_rx_packets = 0;

  if (node->state == VLIB_NODE_STATE_INTERRUPT)
    {
      uword i;

      /* Loop over devices with interrupts. */
      /* *INDENT-OFF* */
      foreach_set_bit (i, node->runtime_data[0], ({
	xd = vec_elt_at_index (xm->devices, i);
	n_rx_packets += ixge_device_input (xm, xd, node);

	/* Re-enable interrupts since we're going to stay in interrupt mode. */
	if (! (node->flags & VLIB_NODE_FLAG_SWITCH_FROM_INTERRUPT_TO_POLLING_MODE))
	  xd->regs->interrupt.enable_write_1_to_set = ~0;
      }));
      /* *INDENT-ON* */

      /* Clear mask of devices with pending interrupts. */
      node->runtime_data[0] = 0;
    }
  else
    {
      /* Poll all devices for input/interrupts. */
      vec_foreach (xd, xm->devices)
      {
	n_rx_packets += ixge_device_input (xm, xd, node);

	/* Re-enable interrupts when switching out of polling mode. */
	if (node->flags &
	    VLIB_NODE_FLAG_SWITCH_FROM_POLLING_TO_INTERRUPT_MODE)
	  xd->regs->interrupt.enable_write_1_to_set = ~0;
      }
    }

  return n_rx_packets;
}

static char *ixge_error_strings[] = {
#define _(n,s) s,
  foreach_ixge_error
#undef _
};

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (ixge_input_node, static) = {
  .function = ixge_input,
  .type = VLIB_NODE_TYPE_INPUT,
  .name = "ixge-input",

  /* Will be enabled if/when hardware is detected. */
  .state = VLIB_NODE_STATE_DISABLED,

  .format_buffer = format_ethernet_header_with_length,
  .format_trace = format_ixge_rx_dma_trace,

  .n_errors = IXGE_N_ERROR,
  .error_strings = ixge_error_strings,

  .n_next_nodes = IXGE_RX_N_NEXT,
  .next_nodes = {
    [IXGE_RX_NEXT_DROP] = "error-drop",
    [IXGE_RX_NEXT_ETHERNET_INPUT] = "ethernet-input",
    [IXGE_RX_NEXT_IP4_INPUT] = "ip4-input",
    [IXGE_RX_NEXT_IP6_INPUT] = "ip6-input",
  },
};

VLIB_NODE_FUNCTION_MULTIARCH_CLONE (ixge_input)
CLIB_MULTIARCH_SELECT_FN (ixge_input)
/* *INDENT-ON* */

static u8 *
format_ixge_device_name (u8 * s, va_list * args)
{
  u32 i = va_arg (*args, u32);
  ixge_main_t *xm = &ixge_main;
  ixge_device_t *xd = vec_elt_at_index (xm->devices, i);
  return format (s, "TenGigabitEthernet%U",
		 format_vlib_pci_handle, &xd->pci_device.bus_address);
}

#define IXGE_COUNTER_IS_64_BIT (1 << 0)
#define IXGE_COUNTER_NOT_CLEAR_ON_READ (1 << 1)

static u8 ixge_counter_flags[] = {
#define _(a,f) 0,
#define _64(a,f) IXGE_COUNTER_IS_64_BIT,
  foreach_ixge_counter
#undef _
#undef _64
};

static void
ixge_update_counters (ixge_device_t * xd)
{
  /* Byte offset for counter registers. */
  static u32 reg_offsets[] = {
#define _(a,f) (a) / sizeof (u32),
#define _64(a,f) _(a,f)
    foreach_ixge_counter
#undef _
#undef _64
  };
  volatile u32 *r = (volatile u32 *) xd->regs;
  int i;

  for (i = 0; i < ARRAY_LEN (xd->counters); i++)
    {
      u32 o = reg_offsets[i];
      xd->counters[i] += r[o];
      if (ixge_counter_flags[i] & IXGE_COUNTER_NOT_CLEAR_ON_READ)
	r[o] = 0;
      if (ixge_counter_flags[i] & IXGE_COUNTER_IS_64_BIT)
	xd->counters[i] += (u64) r[o + 1] << (u64) 32;
    }
}

static u8 *
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

static u8 *
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

static u8 *
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

    s = format (s, "\n%UPCIe %U", format_white_space, indent + 2,
		format_vlib_pci_link_speed, &xd->pci_device);
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

static void
ixge_clear_hw_interface_counters (u32 instance)
{
  ixge_main_t *xm = &ixge_main;
  ixge_device_t *xd = vec_elt_at_index (xm->devices, instance);
  ixge_update_counters (xd);
  memcpy (xd->counters_last_clear, xd->counters, sizeof (xd->counters));
}

/*
 * Dynamically redirect all pkts from a specific interface
 * to the specified node
 */
static void
ixge_set_interface_next_node (vnet_main_t * vnm, u32 hw_if_index,
			      u32 node_index)
{
  ixge_main_t *xm = &ixge_main;
  vnet_hw_interface_t *hw = vnet_get_hw_interface (vnm, hw_if_index);
  ixge_device_t *xd = vec_elt_at_index (xm->devices, hw->dev_instance);

  /* Shut off redirection */
  if (node_index == ~0)
    {
      xd->per_interface_next_index = node_index;
      return;
    }

  xd->per_interface_next_index =
    vlib_node_add_next (xm->vlib_main, ixge_input_node.index, node_index);
}


/* *INDENT-OFF* */
VNET_DEVICE_CLASS (ixge_device_class) = {
  .name = "ixge",
  .tx_function = ixge_interface_tx,
  .format_device_name = format_ixge_device_name,
  .format_device = format_ixge_device,
  .format_tx_trace = format_ixge_tx_dma_trace,
  .clear_counters = ixge_clear_hw_interface_counters,
  .admin_up_down_function = ixge_interface_admin_up_down,
  .rx_redirect_to_node = ixge_set_interface_next_node,
};
/* *INDENT-ON* */

#define IXGE_N_BYTES_IN_RX_BUFFER  (2048)	// DAW-HACK: Set Rx buffer size so all packets < ETH_MTU_SIZE fit in the buffer (i.e. sop & eop for all descriptors).

static clib_error_t *
ixge_dma_init (ixge_device_t * xd, vlib_rx_or_tx_t rt, u32 queue_index)
{
  ixge_main_t *xm = &ixge_main;
  vlib_main_t *vm = xm->vlib_main;
  ixge_dma_queue_t *dq;
  clib_error_t *error = 0;

  vec_validate (xd->dma_queues[rt], queue_index);
  dq = vec_elt_at_index (xd->dma_queues[rt], queue_index);

  if (!xm->n_descriptors_per_cache_line)
    xm->n_descriptors_per_cache_line =
      CLIB_CACHE_LINE_BYTES / sizeof (dq->descriptors[0]);

  if (!xm->n_bytes_in_rx_buffer)
    xm->n_bytes_in_rx_buffer = IXGE_N_BYTES_IN_RX_BUFFER;
  xm->n_bytes_in_rx_buffer = round_pow2 (xm->n_bytes_in_rx_buffer, 1024);
  if (!xm->vlib_buffer_free_list_index)
    {
      xm->vlib_buffer_free_list_index =
	vlib_buffer_get_or_create_free_list (vm, xm->n_bytes_in_rx_buffer,
					     "ixge rx");
      ASSERT (xm->vlib_buffer_free_list_index != 0);
    }

  if (!xm->n_descriptors[rt])
    xm->n_descriptors[rt] = 4 * VLIB_FRAME_SIZE;

  dq->queue_index = queue_index;
  dq->n_descriptors =
    round_pow2 (xm->n_descriptors[rt], xm->n_descriptors_per_cache_line);
  dq->head_index = dq->tail_index = 0;

  dq->descriptors =
    vlib_physmem_alloc_aligned (vm, xm->physmem_region, &error,
				dq->n_descriptors *
				sizeof (dq->descriptors[0]),
				128 /* per chip spec */ );
  if (error)
    return error;

  memset (dq->descriptors, 0,
	  dq->n_descriptors * sizeof (dq->descriptors[0]));
  vec_resize (dq->descriptor_buffer_indices, dq->n_descriptors);

  if (rt == VLIB_RX)
    {
      u32 n_alloc, i;

      n_alloc = vlib_buffer_alloc_from_free_list
	(vm, dq->descriptor_buffer_indices,
	 vec_len (dq->descriptor_buffer_indices),
	 xm->vlib_buffer_free_list_index);
      ASSERT (n_alloc == vec_len (dq->descriptor_buffer_indices));
      for (i = 0; i < n_alloc; i++)
	{
	  vlib_buffer_t *b =
	    vlib_get_buffer (vm, dq->descriptor_buffer_indices[i]);
	  dq->descriptors[i].rx_to_hw.tail_address =
	    vlib_physmem_virtual_to_physical (vm, xm->physmem_region,
					      b->data);
	}
    }
  else
    {
      u32 i;

      dq->tx.head_index_write_back =
	vlib_physmem_alloc (vm,
			    vm->buffer_main->buffer_pools[0].physmem_region,
			    &error, CLIB_CACHE_LINE_BYTES);

      for (i = 0; i < dq->n_descriptors; i++)
	dq->descriptors[i].tx = xm->tx_descriptor_template;

      vec_validate (xm->tx_buffers_pending_free, dq->n_descriptors - 1);
    }

  {
    ixge_dma_regs_t *dr = get_dma_regs (xd, rt, queue_index);
    u64 a;

    a =
      vlib_physmem_virtual_to_physical (vm,
					vm->buffer_main->
					buffer_pools[0].physmem_region,
					dq->descriptors);
    dr->descriptor_address[0] = a & 0xFFFFFFFF;
    dr->descriptor_address[1] = a >> (u64) 32;
    dr->n_descriptor_bytes = dq->n_descriptors * sizeof (dq->descriptors[0]);
    dq->head_index = dq->tail_index = 0;

    if (rt == VLIB_RX)
      {
	ASSERT ((xm->n_bytes_in_rx_buffer / 1024) < 32);
	dr->rx_split_control =
	  ( /* buffer size */ ((xm->n_bytes_in_rx_buffer / 1024) << 0)
	   | (			/* lo free descriptor threshold (units of 64 descriptors) */
	       (1 << 22)) | (	/* descriptor type: advanced one buffer */
			      (1 << 25)) | (	/* drop if no descriptors available */
					     (1 << 28)));

	/* Give hardware all but last 16 cache lines' worth of descriptors. */
	dq->tail_index = dq->n_descriptors -
	  16 * xm->n_descriptors_per_cache_line;
      }
    else
      {
	/* Make sure its initialized before hardware can get to it. */
	dq->tx.head_index_write_back[0] = dq->head_index;

	a =
	  vlib_physmem_virtual_to_physical (vm,
					    vm->buffer_main->
					    buffer_pools[0].physmem_region,
					    dq->tx.head_index_write_back);
	dr->tx.head_index_write_back_address[0] = /* enable bit */ 1 | a;
	dr->tx.head_index_write_back_address[1] = (u64) a >> (u64) 32;
      }

    /* DMA on 82599 does not work with [13] rx data write relaxed ordering
       and [12] undocumented set. */
    if (rt == VLIB_RX)
      dr->dca_control &= ~((1 << 13) | (1 << 12));

    CLIB_MEMORY_BARRIER ();

    if (rt == VLIB_TX)
      {
	xd->regs->tx_dma_control |= (1 << 0);
	dr->control |= ((32 << 0)	/* prefetch threshold */
			| (64 << 8)	/* host threshold */
			| (0 << 16) /* writeback threshold */ );
      }

    /* Enable this queue and wait for hardware to initialize
       before adding to tail. */
    if (rt == VLIB_TX)
      {
	dr->control |= 1 << 25;
	while (!(dr->control & (1 << 25)))
	  ;
      }

    /* Set head/tail indices and enable DMA. */
    dr->head_index = dq->head_index;
    dr->tail_index = dq->tail_index;
  }

  return error;
}

static u32
ixge_flag_change (vnet_main_t * vnm, vnet_hw_interface_t * hw, u32 flags)
{
  ixge_device_t *xd;
  ixge_regs_t *r;
  u32 old;
  ixge_main_t *xm = &ixge_main;

  xd = vec_elt_at_index (xm->devices, hw->dev_instance);
  r = xd->regs;

  old = r->filter_control;

  if (flags & ETHERNET_INTERFACE_FLAG_ACCEPT_ALL)
    r->filter_control = old | (1 << 9) /* unicast promiscuous */ ;
  else
    r->filter_control = old & ~(1 << 9);

  return old;
}

static void
ixge_device_init (ixge_main_t * xm)
{
  vnet_main_t *vnm = vnet_get_main ();
  ixge_device_t *xd;

  /* Reset chip(s). */
  vec_foreach (xd, xm->devices)
  {
    ixge_regs_t *r = xd->regs;
    const u32 reset_bit = (1 << 26) | (1 << 3);

    r->control |= reset_bit;

    /* No need to suspend.  Timed to take ~1e-6 secs */
    while (r->control & reset_bit)
      ;

    /* Software loaded. */
    r->extended_control |= (1 << 28);

    ixge_phy_init (xd);

    /* Register ethernet interface. */
    {
      u8 addr8[6];
      u32 i, addr32[2];
      clib_error_t *error;

      addr32[0] = r->rx_ethernet_address0[0][0];
      addr32[1] = r->rx_ethernet_address0[0][1];
      for (i = 0; i < 6; i++)
	addr8[i] = addr32[i / 4] >> ((i % 4) * 8);

      error = ethernet_register_interface
	(vnm, ixge_device_class.index, xd->device_index,
	 /* ethernet address */ addr8,
	 &xd->vlib_hw_if_index, ixge_flag_change);
      if (error)
	clib_error_report (error);
    }

    {
      vnet_sw_interface_t *sw =
	vnet_get_hw_sw_interface (vnm, xd->vlib_hw_if_index);
      xd->vlib_sw_if_index = sw->sw_if_index;
    }

    ixge_dma_init (xd, VLIB_RX, /* queue_index */ 0);

    xm->n_descriptors[VLIB_TX] = 20 * VLIB_FRAME_SIZE;

    ixge_dma_init (xd, VLIB_TX, /* queue_index */ 0);

    /* RX/TX queue 0 gets mapped to interrupt bits 0 & 8. */
    r->interrupt.queue_mapping[0] = (( /* valid bit */ (1 << 7) |
				      ixge_rx_queue_to_interrupt (0)) << 0);

    r->interrupt.queue_mapping[0] |= (( /* valid bit */ (1 << 7) |
				       ixge_tx_queue_to_interrupt (0)) << 8);

    /* No use in getting too many interrupts.
       Limit them to one every 3/4 ring size at line rate
       min sized packets.
       No need for this since kernel/vlib main loop provides adequate interrupt
       limiting scheme. */
    if (0)
      {
	f64 line_rate_max_pps =
	  10e9 / (8 * (64 + /* interframe padding */ 20));
	ixge_throttle_queue_interrupt (r, 0,
				       .75 * xm->n_descriptors[VLIB_RX] /
				       line_rate_max_pps);
      }

    /* Accept all multicast and broadcast packets. Should really add them
       to the dst_ethernet_address register array. */
    r->filter_control |= (1 << 10) | (1 << 8);

    /* Enable frames up to size in mac frame size register. */
    r->xge_mac.control |= 1 << 2;
    r->xge_mac.rx_max_frame_size = (9216 + 14) << 16;

    /* Enable all interrupts. */
    if (!IXGE_ALWAYS_POLL)
      r->interrupt.enable_write_1_to_set = ~0;
  }
}

static uword
ixge_process (vlib_main_t * vm, vlib_node_runtime_t * rt, vlib_frame_t * f)
{
  vnet_main_t *vnm = vnet_get_main ();
  ixge_main_t *xm = &ixge_main;
  ixge_device_t *xd;
  uword event_type, *event_data = 0;
  f64 timeout, link_debounce_deadline;

  ixge_device_init (xm);

  /* Clear all counters. */
  vec_foreach (xd, xm->devices)
  {
    ixge_update_counters (xd);
    memset (xd->counters, 0, sizeof (xd->counters));
  }

  timeout = 30.0;
  link_debounce_deadline = 1e70;

  while (1)
    {
      /* 36 bit stat counters could overflow in ~50 secs.
         We poll every 30 secs to be conservative. */
      vlib_process_wait_for_event_or_clock (vm, timeout);

      event_type = vlib_process_get_events (vm, &event_data);

      switch (event_type)
	{
	case EVENT_SET_FLAGS:
	  /* 1 ms */
	  link_debounce_deadline = vlib_time_now (vm) + 1e-3;
	  timeout = 1e-3;
	  break;

	case ~0:
	  /* No events found: timer expired. */
	  if (vlib_time_now (vm) > link_debounce_deadline)
	    {
	      vec_foreach (xd, xm->devices)
	      {
		ixge_regs_t *r = xd->regs;
		u32 v = r->xge_mac.link_status;
		uword is_up = (v & (1 << 30)) != 0;

		vnet_hw_interface_set_flags
		  (vnm, xd->vlib_hw_if_index,
		   is_up ? VNET_HW_INTERFACE_FLAG_LINK_UP : 0);
	      }
	      link_debounce_deadline = 1e70;
	      timeout = 30.0;
	    }
	  break;

	default:
	  ASSERT (0);
	}

      if (event_data)
	_vec_len (event_data) = 0;

      /* Query stats every 30 secs. */
      {
	f64 now = vlib_time_now (vm);
	if (now - xm->time_last_stats_update > 30)
	  {
	    xm->time_last_stats_update = now;
	    vec_foreach (xd, xm->devices) ixge_update_counters (xd);
	  }
      }
    }

  return 0;
}

static vlib_node_registration_t ixge_process_node = {
  .function = ixge_process,
  .type = VLIB_NODE_TYPE_PROCESS,
  .name = "ixge-process",
};

clib_error_t *
ixge_init (vlib_main_t * vm)
{
  ixge_main_t *xm = &ixge_main;
  clib_error_t *error;

  xm->vlib_main = vm;
  memset (&xm->tx_descriptor_template, 0,
	  sizeof (xm->tx_descriptor_template));
  memset (&xm->tx_descriptor_template_mask, 0,
	  sizeof (xm->tx_descriptor_template_mask));
  xm->tx_descriptor_template.status0 =
    (IXGE_TX_DESCRIPTOR_STATUS0_ADVANCED |
     IXGE_TX_DESCRIPTOR_STATUS0_IS_ADVANCED |
     IXGE_TX_DESCRIPTOR_STATUS0_INSERT_FCS);
  xm->tx_descriptor_template_mask.status0 = 0xffff;
  xm->tx_descriptor_template_mask.status1 = 0x00003fff;

  xm->tx_descriptor_template_mask.status0 &=
    ~(IXGE_TX_DESCRIPTOR_STATUS0_IS_END_OF_PACKET
      | IXGE_TX_DESCRIPTOR_STATUS0_REPORT_STATUS);
  xm->tx_descriptor_template_mask.status1 &=
    ~(IXGE_TX_DESCRIPTOR_STATUS1_DONE);

  error = vlib_call_init_function (vm, pci_bus_init);

  return error;
}

VLIB_INIT_FUNCTION (ixge_init);


static void
ixge_pci_intr_handler (vlib_pci_device_t * dev)
{
  ixge_main_t *xm = &ixge_main;
  vlib_main_t *vm = xm->vlib_main;

  vlib_node_set_interrupt_pending (vm, ixge_input_node.index);

  /* Let node know which device is interrupting. */
  {
    vlib_node_runtime_t *rt =
      vlib_node_get_runtime (vm, ixge_input_node.index);
    rt->runtime_data[0] |= 1 << dev->private_data;
  }
}

static clib_error_t *
ixge_pci_init (vlib_main_t * vm, vlib_pci_device_t * dev)
{
  ixge_main_t *xm = &ixge_main;
  clib_error_t *error;
  void *r;
  ixge_device_t *xd;

  /* Allocate physmem region for DMA buffers */
  error = vlib_physmem_region_alloc (vm, "ixge decriptors", 2 << 20, 0,
				     VLIB_PHYSMEM_F_INIT_MHEAP,
				     &xm->physmem_region);
  if (error)
    return error;

  error = vlib_pci_map_resource (dev, 0, &r);
  if (error)
    return error;

  vec_add2 (xm->devices, xd, 1);

  if (vec_len (xm->devices) == 1)
    {
      ixge_input_node.function = ixge_input_multiarch_select ();
    }

  xd->pci_device = dev[0];
  xd->device_id = xd->pci_device.config0.header.device_id;
  xd->regs = r;
  xd->device_index = xd - xm->devices;
  xd->pci_function = dev->bus_address.function;
  xd->per_interface_next_index = ~0;


  /* Chip found so enable node. */
  {
    vlib_node_set_state (vm, ixge_input_node.index,
			 (IXGE_ALWAYS_POLL
			  ? VLIB_NODE_STATE_POLLING
			  : VLIB_NODE_STATE_INTERRUPT));

    dev->private_data = xd->device_index;
  }

  if (vec_len (xm->devices) == 1)
    {
      vlib_register_node (vm, &ixge_process_node);
      xm->process_node_index = ixge_process_node.index;
    }

  error = vlib_pci_bus_master_enable (dev);

  if (error)
    return error;

  return vlib_pci_intr_enable (dev);
}

/* *INDENT-OFF* */
PCI_REGISTER_DEVICE (ixge_pci_device_registration,static) = {
  .init_function = ixge_pci_init,
  .interrupt_handler = ixge_pci_intr_handler,
  .supported_devices = {
#define _(t,i) { .vendor_id = PCI_VENDOR_ID_INTEL, .device_id = i, },
    foreach_ixge_pci_device_id
#undef _
    { 0 },
  },
};
/* *INDENT-ON* */

void
ixge_set_next_node (ixge_rx_next_t next, char *name)
{
  vlib_node_registration_t *r = &ixge_input_node;

  switch (next)
    {
    case IXGE_RX_NEXT_IP4_INPUT:
    case IXGE_RX_NEXT_IP6_INPUT:
    case IXGE_RX_NEXT_ETHERNET_INPUT:
      r->next_nodes[next] = name;
      break;

    default:
      clib_warning ("%s: illegal next %d\n", __FUNCTION__, next);
      break;
    }
}

/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () = {
    .version = VPP_BUILD_VER,
    .default_disabled = 1,
    .description = "Intel 82599 Family Native Driver (experimental)",
};
#endif

/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
