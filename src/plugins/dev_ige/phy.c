/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vnet/dev/pci.h>
#include <vnet/dev/counters.h>
#include <dev_ige/ige.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>

VLIB_REGISTER_LOG_CLASS (ige_log, static) = {
  .class_name = "ige",
  .subclass_name = "phy",
};

#define foreach_ige_phy_reg                                                   \
  _ (0x00, CTRL)                                                              \
  _ (0x01, STAT)                                                              \
  _ (0x02, PHYID1)                                                            \
  _ (0x03, PHYID2)                                                            \
  _ (0x04, AN_ADV)                                                            \
  _ (0x09, GCTRL)                                                             \
  _ (0x0a, GSTAT)                                                             \
  _ (0x0d, MMDCTRL)                                                           \
  _ (0x0e, MMDDATA)                                                           \
  _ (0x0f, XSTAT)

typedef enum
{
#define _(n, v) IGE_PHY_REG_##v = (n),
  foreach_ige_phy_reg
#undef _
} ige_phy_reg_t;

static char *phy_reg_names[] = {
#define _(n, v) [n] = #v,
  foreach_ige_phy_reg
#undef _
};

static vnet_dev_rv_t
ige_phy_acquire (vlib_main_t *vm, vnet_dev_t *dev)
{
  ige_reg_sw_fw_sync_t sw_fw_sync;
  int n_tries = 5;

  log_debug (dev, "phy_acquire:");

  while (n_tries-- > 0)
    {
      if (ige_reg_sw_fw_sync_acquire (vm, dev))
	{
	  ige_reg_rd (dev, IGE_REG_SW_FW_SYNC, &sw_fw_sync.as_u32);
	  log_debug (dev, "phy_acquire: sw_fw_sync 0x%04x");

	  if (sw_fw_sync.fw_phy_sm == 0)
	    {
	      sw_fw_sync.sw_phy_sm = 1;
	      ige_reg_wr (dev, IGE_REG_SW_FW_SYNC, sw_fw_sync.as_u32);
	      ige_reg_sw_fw_sync_release (vm, dev);
	      return 0;
	    }

	  ige_reg_sw_fw_sync_release (vm, dev);
	}
      vlib_process_suspend (vm, 1e-4);
    }

  log_err (dev, "failed to acquire PHY");
  return VNET_DEV_ERR_TIMEOUT;
}

static vnet_dev_rv_t
ige_phy_release (vlib_main_t *vm, vnet_dev_t *dev)
{
  ige_reg_sw_fw_sync_t sw_fw_sync;

  log_debug (dev, "phy_release:");

  /* release phy */
  if (ige_reg_sw_fw_sync_acquire (vm, dev) == 0)
    {
      log_err (dev, "sw_fw_sync ownership timeout");
      return VNET_DEV_ERR_TIMEOUT;
    }

  sw_fw_sync.sw_phy_sm = 0;
  ige_reg_wr (dev, IGE_REG_SW_FW_SYNC, sw_fw_sync.as_u32);
  ige_reg_sw_fw_sync_release (vm, dev);

  return 0;
}

static vnet_dev_rv_t
ige_phy_read (vlib_main_t *vm, vnet_dev_t *dev, u16 addr, u16 *data)
{
  ige_reg_mdic_t mdic = { .regadd = addr, .opcode = 2 };
  int n_tries = 10;
  f64 t;

  t = vlib_time_now (vm);
  ige_reg_wr (dev, IGE_REG_MDIC, mdic.as_u32);
  vlib_process_suspend (vm, 5e-5);
  ige_reg_rd (dev, IGE_REG_MDIC, &mdic.as_u32);

  while (mdic.ready == 0 && n_tries-- > 0)
    {
      vlib_process_suspend (vm, 2e-5);
      ige_reg_rd (dev, IGE_REG_MDIC, &mdic.as_u32);
    }

  t = vlib_time_now (vm) - t;
  if (t > 1e-4)
    log_warn (dev, "phy_read: register read took %.06f sec", t);

  if (mdic.ready == 0)
    {
      log_err (dev, "phy read timeout");
      return VNET_DEV_ERR_TIMEOUT;
    }

  if (addr < ARRAY_LEN (phy_reg_names) && phy_reg_names[addr])
    log_debug (dev, "reg %s data 0x%04x", phy_reg_names[addr], mdic.data);
  else
    log_debug (dev, "addr 0x%02x data 0x%04x", addr, mdic.data);

  *data = mdic.data;
  return 0;
}

static vnet_dev_rv_t
ige_phy_write (vlib_main_t *vm, vnet_dev_t *dev, u16 addr, u16 data)
{
  ige_reg_mdic_t mdic = { .regadd = addr, .opcode = 1, .data = data };
  int n_tries = 10;
  f64 t;

  t = vlib_time_now (vm);
  ige_reg_wr (dev, IGE_REG_MDIC, mdic.as_u32);
  vlib_process_suspend (vm, 5e-5);
  ige_reg_rd (dev, IGE_REG_MDIC, &mdic.as_u32);

  while (mdic.ready == 0 && n_tries-- > 0)
    {
      vlib_process_suspend (vm, 2e-5);
      ige_reg_rd (dev, IGE_REG_MDIC, &mdic.as_u32);
    }

  t = vlib_time_now (vm) - t;
  if (t > 1e-4)
    log_warn (dev, "phy_read: register read took %.06f sec", t);

  if (mdic.ready == 0)
    {
      log_err (dev, "phy read timeout");
      return VNET_DEV_ERR_TIMEOUT;
    }

  if (addr < ARRAY_LEN (phy_reg_names) && phy_reg_names[addr])
    log_debug (dev, "reg %s data 0x%04x", phy_reg_names[addr], mdic.data);
  else
    log_debug (dev, "addr 0x%02x data 0x%04x", addr, mdic.data);

  return 0;
}

#define foreach_ige_phy_type                                                  \
  _ (0x67c9dc00, GPY211, "Foxville LM B.1")                                   \
  _ (0x67c9dc80, GPY211, "Foxville LM B.2")                                   \
  _ (0x67c9dcc0, GPY211, "Foxville LM B.3 / Foxville Dock")                   \
  _ (0x67c9dc02, GPY211, "Foxville V B.1")                                    \
  _ (0x67c9dc82, GPY211, "Foxville V B.2")                                    \
  _ (0x67c9dcc2, GPY211, "Foxville V B.3")                                    \
  _ (0x67c9dc83, GPY211, "Foxville IT B.2")                                   \
  _ (0x67c9dcc3, GPY211, "Foxville IT B.3")                                   \
  _ (0x67c9dc18, GPY211, "FoxvilleC LM / Dock")                               \
  _ (0x67c9dc58, GPY211, "FoxvilleC V")                                       \
  _ (0x67c9dcd8, GPY211, "FoxvilleC IT")

static struct
{
  u32 phy_id;
  ige_phy_type_t type;
  char *name;
} phy_types[] = {
#define _(i, t, s)                                                            \
  {                                                                           \
    .phy_id = i,                                                              \
    .type = IGE_PHY_TYPE_##t,                                                 \
    .name = s,                                                                \
  },
  foreach_ige_phy_type
#undef _
};

vnet_dev_rv_t
ige_phy_mmd_write (vlib_main_t *vm, vnet_dev_t *dev, u8 dad, u16 addr,
		   u16 data)
{
  vnet_dev_rv_t rv;
  struct
  {
    u16 reg;
    u16 val;
  } seq[] = {
    { IGE_PHY_REG_MMDCTRL, dad },
    { IGE_PHY_REG_MMDDATA, addr },
    { IGE_PHY_REG_MMDCTRL, 0x4000 | dad },
    { IGE_PHY_REG_MMDDATA, data },
    { IGE_PHY_REG_MMDCTRL, 0 },
  };

  FOREACH_ARRAY_ELT (e, seq)
    {
      rv = ige_phy_write (vm, dev, e->reg, e->val);
      if (rv != VNET_DEV_OK)
	return rv;
    }

#if 0
  ige_phy_rw_t rw2[5] = { { .addr = 0xd, .data = 7, .wr = 1 },
			  { .addr = 0xe, .data = 0x20, .wr = 1 },
			  { .addr = 0xd, .data = 0x4007, .wr = 1 },
			  { .addr = 0xe, .data = 0x82, .wr = 1 },
			  { .addr = 0xd, .data = 0, .wr = 1 } };
#endif
  return VNET_DEV_OK;
}

typedef struct
{
  union
  {
    struct
    {
      u16 phy_id2;
      u16 phy_id1;
    };
    u32 phy_id;
    struct
    {
      u32 revision : 4;
      u32 model : 6;
      u32 oui : 22;
    };
  };
} ige_phy_id_t;

vnet_dev_rv_t
ige_phy_init (vlib_main_t *vm, vnet_dev_t *dev)
{
  ige_device_t *id = vnet_dev_get_data (dev);
  vnet_dev_rv_t rv;
  u16 reg;
  ige_phy_id_t phyid;

  if ((rv = ige_phy_acquire (vm, dev)) != VNET_DEV_OK)
    return rv;

  if ((rv = ige_phy_read (vm, dev, IGE_PHY_REG_PHYID1, &phyid.phy_id1)) !=
      VNET_DEV_OK)
    goto done;

  if ((rv = ige_phy_read (vm, dev, IGE_PHY_REG_PHYID2, &phyid.phy_id2)) !=
      VNET_DEV_OK)
    goto done;

  if (id->config.phy_type == IGE_PHY_TYPE_UNKNOWN)
    {
      FOREACH_ARRAY_ELT (e, phy_types)
	if (e->phy_id == phyid.phy_id)
	  {
	    log_debug (dev, "PHY is '%s' (oui 0x%x model 0x%x revision 0x%x",
		       e->name, phyid.oui, phyid.model, phyid.revision);
	    id->config.phy_type = e->type;
	    break;
	  }
    }

  if (id->config.phy_type == IGE_PHY_TYPE_UNKNOWN)
    {
      log_err (dev, "Unsupported phy 0x%08x", phyid);
      rv = VNET_DEV_ERR_UNSUPPORTED_DEVICE;
      goto done;
    }

  /* enable "1000BASE-T Full-Duplex" in GCTRL */
  if ((rv = ige_phy_read (vm, dev, IGE_PHY_REG_GCTRL, &reg)) != VNET_DEV_OK)
    goto done;
  log_debug (dev, "GCTRL was set to 0x%04x", reg);
  reg |= 0x200;
  if ((rv = ige_phy_write (vm, dev, IGE_PHY_REG_GCTRL, reg)) != VNET_DEV_OK)
    goto done;

  if (id->config.phy_type == IGE_PHY_TYPE_GPY211)
    {
      /* modify ANEG[7] device register ANEG_MGBT_AN_CTRL[0x20]:
       *   AB_2G5BT[7]  - 2.5 G BASE-T ability
       *   FR_2G5BT[5]  - 2.5 G BASE-T Fast Retrain Ability
       *   FR[1]        - Fast Retrain Ability
       */
      rv = ige_phy_mmd_write (vm, dev, 7, 0x20, 0xa2);
      if (rv != VNET_DEV_OK)
	goto done;
    }

done:
  return ige_phy_release (vm, dev);
}
