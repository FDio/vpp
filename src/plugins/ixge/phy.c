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

/* 10 GIG E (XGE) PHY IEEE 802.3 clause 45 definitions. */
#define XGE_PHY_DEV_TYPE_PMA_PMD 1
#define XGE_PHY_DEV_TYPE_PHY_XS 4
#define XGE_PHY_ID1 0x2
#define XGE_PHY_ID2 0x3
#define XGE_PHY_CONTROL 0x0
#define XGE_PHY_CONTROL_RESET (1 << 15)

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

void
ixge_sfp_enable_disable_laser (ixge_device_t * xd, uword enable)
{
  u32 tx_disable_bit = 1 << 3;
  if (enable)
    xd->regs->sdp_control &= ~tx_disable_bit;
  else
    xd->regs->sdp_control |= tx_disable_bit;
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

void
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

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
