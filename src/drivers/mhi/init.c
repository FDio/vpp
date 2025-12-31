/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vnet/dev/bus/pci.h>
#include <mhi.h>
#include <mhi_regs.h>

VLIB_REGISTER_LOG_CLASS (mhi_log, static) = {
  .class_name = "mhi",
  .subclass_name = "init",
};

typedef struct
{
  u8 ch;
  u8 type;
  u8 er_index;
  u8 brstmode;
  u8 pollcfg;
  u16 elements;
} mhi_chan_cfg_t;

typedef struct
{
  u16 elements;
  u16 intmod;
  u8 ertype;
  u8 msivec;
} mhi_event_cfg_t;

#define MHI_CH_TYPE_OUTBOUND 1
#define MHI_CH_TYPE_INBOUND  2
#define MHI_DB_BRST_DISABLE  2
#define MHI_DB_BRST_ENABLE   3
#define MHI_EVENT_RING_SIZE  2048
#define MHI_DMA_ALIGN	     4096
#define MHI_DEV_WAKE_DB	     127

static const mhi_chan_cfg_t mhi_sdx65_channels[] = {
  {
    .ch = 2,
    .type = MHI_CH_TYPE_OUTBOUND,
    .er_index = 0,
    .brstmode = MHI_DB_BRST_DISABLE,
    .pollcfg = 0,
    .elements = 32,
  },
  {
    .ch = 3,
    .type = MHI_CH_TYPE_INBOUND,
    .er_index = 0,
    .brstmode = MHI_DB_BRST_DISABLE,
    .pollcfg = 0,
    .elements = 256,
  },
  {
    .ch = 4,
    .type = MHI_CH_TYPE_OUTBOUND,
    .er_index = 0,
    .brstmode = MHI_DB_BRST_DISABLE,
    .pollcfg = 0,
    .elements = 32,
  },
  {
    .ch = 5,
    .type = MHI_CH_TYPE_INBOUND,
    .er_index = 0,
    .brstmode = MHI_DB_BRST_DISABLE,
    .pollcfg = 0,
    .elements = 32,
  },
  {
    .ch = 8,
    .type = MHI_CH_TYPE_OUTBOUND,
    .er_index = 0,
    .brstmode = MHI_DB_BRST_DISABLE,
    .pollcfg = 0,
    .elements = 16,
  },
  {
    .ch = 9,
    .type = MHI_CH_TYPE_INBOUND,
    .er_index = 0,
    .brstmode = MHI_DB_BRST_DISABLE,
    .pollcfg = 0,
    .elements = 16,
  },
  {
    .ch = 12,
    .type = MHI_CH_TYPE_OUTBOUND,
    .er_index = 0,
    .brstmode = MHI_DB_BRST_DISABLE,
    .pollcfg = 0,
    .elements = 128,
  },
  {
    .ch = 13,
    .type = MHI_CH_TYPE_INBOUND,
    .er_index = 0,
    .brstmode = MHI_DB_BRST_DISABLE,
    .pollcfg = 0,
    .elements = 128,
  },
  {
    .ch = 14,
    .type = MHI_CH_TYPE_OUTBOUND,
    .er_index = 0,
    .brstmode = MHI_DB_BRST_DISABLE,
    .pollcfg = 0,
    .elements = 32,
  },
  {
    .ch = 15,
    .type = MHI_CH_TYPE_INBOUND,
    .er_index = 0,
    .brstmode = MHI_DB_BRST_DISABLE,
    .pollcfg = 0,
    .elements = 32,
  },
  {
    .ch = 18,
    .type = MHI_CH_TYPE_OUTBOUND,
    .er_index = 0,
    .brstmode = MHI_DB_BRST_DISABLE,
    .pollcfg = 0,
    .elements = 32,
  },
  {
    .ch = 19,
    .type = MHI_CH_TYPE_INBOUND,
    .er_index = 0,
    .brstmode = MHI_DB_BRST_DISABLE,
    .pollcfg = 0,
    .elements = 32,
  },
  {
    .ch = 32,
    .type = MHI_CH_TYPE_OUTBOUND,
    .er_index = 0,
    .brstmode = MHI_DB_BRST_DISABLE,
    .pollcfg = 0,
    .elements = 32,
  },
  {
    .ch = 33,
    .type = MHI_CH_TYPE_INBOUND,
    .er_index = 0,
    .brstmode = MHI_DB_BRST_DISABLE,
    .pollcfg = 0,
    .elements = 32,
  },
  {
    .ch = 100,
    .type = MHI_CH_TYPE_OUTBOUND,
    .er_index = 1,
    .brstmode = MHI_DB_BRST_ENABLE,
    .pollcfg = 0,
    .elements = 512,
  },
  {
    .ch = 101,
    .type = MHI_CH_TYPE_INBOUND,
    .er_index = 2,
    .brstmode = MHI_DB_BRST_ENABLE,
    .pollcfg = 0,
    .elements = 512,
  },
  {
    .ch = 102,
    .type = MHI_CH_TYPE_INBOUND,
    .er_index = 3,
    .brstmode = MHI_DB_BRST_ENABLE,
    .pollcfg = 0,
    .elements = 128,
  },
};

static const mhi_event_cfg_t mhi_sdx65_events[] = {
  {
    .elements = 2048,
    .intmod = 0,
    .ertype = 1,
    .msivec = 1,
  },
  {
    .elements = 2048,
    .intmod = 0,
    .ertype = 1,
    .msivec = 2,
  },
  {
    .elements = 2048,
    .intmod = 0,
    .ertype = 1,
    .msivec = 3,
  },
  {
    .elements = 1024,
    .intmod = 0,
    .ertype = 1,
    .msivec = 4,
  },
};

static vnet_dev_rv_t
mhi_event_init (vlib_main_t *vm, vnet_dev_t *dev)
{
  mhi_dev_t *md = vnet_dev_get_data (dev);
  vnet_dev_rv_t rv;
  u32 n_event = md->n_events;
  u64 addr;
  int i;

  if (!md->event_ctxt)
    {
      rv =
	vnet_dev_dma_mem_alloc (vm, dev, n_event * sizeof (mhi_event_ctxt_t),
				MHI_DMA_ALIGN, (void **) &md->event_ctxt);
      if (rv != VNET_DEV_OK)
	return rv;
      log_debug (dev, "alloc event_ctxt size %lu va %p",
		 n_event * sizeof (mhi_event_ctxt_t), md->event_ctxt);
    }

  vec_validate_init_empty (md->event_rings, n_event - 1, 0);
  for (i = 0; i < n_event; i++)
    {
      const mhi_event_cfg_t *ec = &mhi_sdx65_events[i];
      u32 event_ring_len = (u32) ec->elements * sizeof (mhi_tre_t);

      if (!md->event_rings[i])
	{
	  rv = vnet_dev_dma_mem_alloc (vm, dev, event_ring_len, event_ring_len,
				       (void **) &md->event_rings[i]);
	  if (rv != VNET_DEV_OK)
	    return rv;
	  log_debug (dev, "alloc event_ring %u size %u va %p", i,
		     event_ring_len, md->event_rings[i]);
	}
      clib_memset (md->event_rings[i], 0, event_ring_len);

      addr = vnet_dev_get_dma_addr (vm, dev, md->event_rings[i]);
      md->event_ctxt[i] = (mhi_event_ctxt_t){
	.rbase_lo = addr,
	.rbase_hi = addr >> 32,
	.rlen_lo = event_ring_len,
	.rp_lo = addr,
	.rp_hi = addr >> 32,
	.wp_lo = addr,
	.wp_hi = addr >> 32,
	.ertype = ec->ertype,
	.intmod = ec->intmod,
	.msivec = ec->msivec,
      };
    }

  return VNET_DEV_OK;
}

static vnet_dev_rv_t
mhi_chan_init (vlib_main_t *vm, vnet_dev_t *dev)
{
  mhi_dev_t *md = vnet_dev_get_data (dev);
  vnet_dev_rv_t rv;
  u32 n_chan = md->n_chans;
  u64 addr;
  int i;

  if (!md->chan_ctxt)
    {
      rv = vnet_dev_dma_mem_alloc (vm, dev, n_chan * sizeof (mhi_chan_ctxt_t),
				   0, (void **) &md->chan_ctxt);
      if (rv != VNET_DEV_OK)
	return rv;
      log_debug (dev, "alloc chan_ctxt size %lu va %p",
		 n_chan * sizeof (mhi_chan_ctxt_t), md->chan_ctxt);
    }
  clib_memset (md->chan_ctxt, 0, n_chan * sizeof (mhi_chan_ctxt_t));

  for (i = 0; i < ARRAY_LEN (mhi_sdx65_channels); i++)
    {
      const mhi_chan_cfg_t *c = &mhi_sdx65_channels[i];
      u32 ring_len = (u32) c->elements * sizeof (mhi_tre_t);
      u32 chcfg;

      if (!md->chan_rings[c->ch])
	{
	  rv = vnet_dev_dma_mem_alloc (vm, dev, ring_len, ring_len,
				       (void **) &md->chan_rings[c->ch]);
	  if (rv != VNET_DEV_OK)
	    return rv;
	  log_debug (dev, "alloc chan_ring %u size %u va %p", c->ch, ring_len,
		     md->chan_rings[c->ch]);
	}
      clib_memset (md->chan_rings[c->ch], 0, ring_len);

      addr = vnet_dev_get_dma_addr (vm, dev, md->chan_rings[c->ch]);

      chcfg = ((u32) c->brstmode << 8) | ((u32) c->pollcfg << 10);
      md->chan_ctxt[c->ch].chcfg = chcfg;
      md->chan_ctxt[c->ch].chtype = c->type;
      md->chan_ctxt[c->ch].erindex = c->er_index;
      md->chan_ctxt[c->ch].rbase_lo = (u32) addr;
      md->chan_ctxt[c->ch].rbase_hi = (u32) (addr >> 32);
      md->chan_ctxt[c->ch].rlen_lo = ring_len;
      md->chan_ctxt[c->ch].rlen_hi = (u32) (((u64) ring_len) >> 32);
      md->chan_ctxt[c->ch].rp_lo = (u32) addr;
      md->chan_ctxt[c->ch].rp_hi = (u32) (addr >> 32);
      md->chan_ctxt[c->ch].wp_lo = (u32) addr;
      md->chan_ctxt[c->ch].wp_hi = (u32) (addr >> 32);

      /* Also init ch_db pointer here? No, ch_db depends on CHDBOFF which needs
       * BAR map */
      /* But we are doing this early. BAR is mapped. CHDBOFF might be 0 if hot.
       */
      /* We can defer ch_db init to later. */
    }

  return VNET_DEV_OK;
}

static vnet_dev_rv_t
mhi_cmd_init (vlib_main_t *vm, vnet_dev_t *dev)
{
  mhi_dev_t *md = vnet_dev_get_data (dev);
  vnet_dev_rv_t rv;
  u32 n_cmd = md->n_cmds;
  u32 cmd_ring_len = MHI_CMD_RING_SIZE * sizeof (mhi_tre_t);
  u64 addr;

  if (!md->cmd_ctxt)
    {
      rv = vnet_dev_dma_mem_alloc (vm, dev, n_cmd * sizeof (mhi_cmd_ctxt_t),
				   MHI_DMA_ALIGN, (void **) &md->cmd_ctxt);
      if (rv != VNET_DEV_OK)
	return rv;
      log_debug (dev, "alloc cmd_ctxt size %lu va %p",
		 n_cmd * sizeof (mhi_cmd_ctxt_t), md->cmd_ctxt);
    }

  if (!md->cmd_ring)
    {
      rv = vnet_dev_dma_mem_alloc (vm, dev, cmd_ring_len, cmd_ring_len,
				   (void **) &md->cmd_ring);
      if (rv != VNET_DEV_OK)
	return rv;
      log_debug (dev, "alloc cmd_ring size %u va %p", cmd_ring_len,
		 md->cmd_ring);
    }
  clib_memset (md->cmd_ring, 0, cmd_ring_len);

  addr = vnet_dev_get_dma_addr (vm, dev, md->cmd_ring);
  md->cmd_ctxt[0] = (mhi_cmd_ctxt_t){
    .rbase_lo = (u32) addr,
    .rbase_hi = (u32) (addr >> 32),
    .rlen_lo = cmd_ring_len,
    .rp_lo = (u32) addr,
    .rp_hi = (u32) (addr >> 32),
    .wp_lo = (u32) addr,
    .wp_hi = (u32) (addr >> 32),
  };

  return VNET_DEV_OK;
}

static u8 *
mhi_probe (vlib_main_t *vm, vnet_dev_bus_index_t bus_index, void *dev_info)
{
  vnet_dev_bus_pci_device_info_t *di = dev_info;

  if (di->vendor_id == 0x17cb && di->device_id == 0x0308)
    return format (0, "Snapdragon X62 5G");

  return 0;
}

static vnet_dev_rv_t
mhi_init (vlib_main_t *vm, vnet_dev_t *dev)
{
  mhi_dev_t *md = vnet_dev_get_data (dev);
  vnet_dev_rv_t rv;
  u32 val, major;
  u32 bhi_off = 0;
  u64 addr;
  f64 timeout;
  mhi_reg_cfg_t cfg;
  mhi_reg_ctrl_t ctrl;

  md->n_events = ARRAY_LEN (mhi_sdx65_events);
  md->n_chans = 128;
  md->n_cmds = 1;

  rv = vnet_dev_pci_map_region (vm, dev, 0, (void **) &md->bar0);
  if (rv != VNET_DEV_OK)
    return rv;

  /* Initialize Rings early to catch stray DMA */
  if ((rv = mhi_event_init (vm, dev)) != VNET_DEV_OK)
    return rv;
  if ((rv = mhi_chan_init (vm, dev)) != VNET_DEV_OK)
    return rv;
  if ((rv = mhi_cmd_init (vm, dev)) != VNET_DEV_OK)
    return rv;

  /* Early Program Base Addresses */
  addr = vnet_dev_get_dma_addr (vm, dev, md->chan_ctxt);
  mhi_reg_wr64 (dev, MHI_REG_CCABAP_LOWER, addr);
  addr = vnet_dev_get_dma_addr (vm, dev, md->event_ctxt);
  mhi_reg_wr64 (dev, MHI_REG_ECABAP_LOWER, addr);
  addr = vnet_dev_get_dma_addr (vm, dev, md->cmd_ctxt);
  mhi_reg_wr64 (dev, MHI_REG_CRCBAP_LOWER, addr);

  rv = vnet_dev_pci_bus_master_enable (vm, dev);
  if (rv != VNET_DEV_OK)
    return rv;

  mhi_reg_rd (dev, MHI_REG_BHIOFF, &bhi_off);
  if (bhi_off == 0 || bhi_off == 0xFFFFFFFF)
    {
      log_err (dev, "MHI registers not populated (BHIOFF=0x%x)", bhi_off);
      return VNET_DEV_ERR_NOT_READY;
    }

  mhi_reg_rd (dev, MHI_REG_STATUS, &val);
  log_debug (dev, "Current STATUS: %U", format_mhi_reg_read, MHI_REG_STATUS, val);

  /* Trigger MHI Reset (Soft) */
  mhi_reg_rd (dev, MHI_REG_CTRL, &ctrl.as_u32);
  ctrl.reset = 1;
  mhi_reg_wr (dev, MHI_REG_CTRL, ctrl.as_u32);

  /* Wait for Reset to clear */
  timeout = vlib_time_now (vm) + 5.0;
  while (1)
    {
      mhi_reg_rd (dev, MHI_REG_CTRL, &val);
      if (((mhi_reg_ctrl_t){ .as_u32 = val }).reset == 0)
        break;
      if (vlib_time_now (vm) > timeout)
        {
          log_err (dev, "timeout waiting for MHI reset to clear");
          return VNET_DEV_ERR_TIMEOUT;
        }
      vlib_process_suspend (vm, 1e-3);
    }
  log_debug (dev, "MHI reset cleared");

  /* Wait for Ready */
  timeout = vlib_time_now (vm) + 10.0;
  while (1)
    {
      mhi_reg_rd (dev, MHI_REG_STATUS, &val);
      if (((mhi_reg_status_t){ .as_u32 = val }).ready)
        break;
      if (vlib_time_now (vm) > timeout)
        {
          log_err (dev, "timeout waiting for MHI ready");
          return VNET_DEV_ERR_TIMEOUT;
        }
      vlib_process_suspend (vm, 1e-3);
    }
  log_debug (dev, "MHI device ready");

  /* Call helpers again to re-program BARs and clean up any pre-reset writes */
  if ((rv = mhi_event_init (vm, dev)) != VNET_DEV_OK)
    return rv;
  if ((rv = mhi_chan_init (vm, dev)) != VNET_DEV_OK)
    return rv;
  if ((rv = mhi_cmd_init (vm, dev)) != VNET_DEV_OK)
    return rv;

  /* Re-program Base Addresses */
  addr = vnet_dev_get_dma_addr (vm, dev, md->chan_ctxt);
  mhi_reg_wr64 (dev, MHI_REG_CCABAP_LOWER, addr);
  addr = vnet_dev_get_dma_addr (vm, dev, md->event_ctxt);
  mhi_reg_wr64 (dev, MHI_REG_ECABAP_LOWER, addr);
  addr = vnet_dev_get_dma_addr (vm, dev, md->cmd_ctxt);
  mhi_reg_wr64 (dev, MHI_REG_CRCBAP_LOWER, addr);

  mhi_reg_rd (dev, MHI_REG_CTRL, &val);
  log_debug (dev, "%U", format_mhi_reg_read, MHI_REG_CTRL, val);

  mhi_reg_rd (dev, MHI_REG_BHIOFF, &val);
  mhi_reg_rd (dev, MHI_REG_VER, &val);
  log_info (dev, "MHI version %u.%u.%u (0x%x)", (val >> 24) & 0xff,
	    (val >> 16) & 0xff, val & 0xffff, val);

  mhi_reg_rd (dev, MHI_REG_STATUS, &val);
  log_debug (dev, "%U", format_mhi_reg_read, MHI_REG_STATUS, val);
  fformat(stderr, "%U", format_hexdump_u32, md->bar0, 64);

  mhi_reg_rd (dev, MHI_REG_CFG, &val);
  log_debug (dev, "%U", format_mhi_reg_read, MHI_REG_CFG, val);
  cfg.as_u32 = val;
  if (cfg.nch == 0 || cfg.ner == 0)
    {
      log_err (dev, "invalid MHI configuration: nch %u ner %u", cfg.nch,
	       cfg.ner);
      return VNET_DEV_ERR_TIMEOUT;
    }
  if (cfg.nch > md->n_chans)
    {
      log_err (dev, "Device has more channels (%u) than allocated (%u)",
	       cfg.nch, md->n_chans);
      return VNET_DEV_ERR_INVALID_VALUE;
    }
  md->n_chans = cfg.nch;

  log_info (dev,
	    "MHI configuration: channels %u (hw %u), event rings %u (hw %u)",
	    cfg.nch, cfg.nhwch, cfg.ner, cfg.nhwer);

  /* 2. Locate BHI Space */
  mhi_reg_rd (dev, MHI_REG_BHIOFF, &val);
  log_debug (dev, "%U", format_mhi_reg_read, MHI_REG_BHIOFF, val);
  md->bhi = (u8 *) md->bar0 + val;
  log_debug (dev, "BHI mapped at %p (offset 0x%x)", md->bhi, val);

  bhi_reg_rd (dev, BHI_REG_VER_MAJOR, &val);
  major = val;
  bhi_reg_rd (dev, BHI_REG_VER_MINOR, &val);
  log_info (dev, "BHI version %u.%u", major, val);

  bhi_reg_rd (dev, BHI_REG_SERIALNU, &val);
  log_info (dev, "Device serial number: 0x%x", val);

  bhi_reg_rd (dev, BHI_REG_MSMHWID0, &val);
  log_info (dev, "Device hardware ID: 0x%x", val);

  bhi_reg_rd (dev, BHI_REG_SBLANTIROLLVER, &val);
  log_info (dev, "SBL anti-rollback version: %u", val);

  bhi_reg_rd (dev, BHI_REG_EXECENV, &val);
  log_debug (dev, "%U", format_bhi_reg_read, BHI_REG_EXECENV, val);
  log_info (dev, "Execution environment: 0x%x", val);

  bhi_reg_rd (dev, BHI_REG_STATUS, &val);
  log_debug (dev, "%U", format_bhi_reg_read, BHI_REG_STATUS, val);
  log_info (dev, "BHI status: 0x%x", val);

  /* 4. Setup Interrupt Vector */
  log_debug (dev, "Setting BHI INTVEC to 0");
  bhi_reg_wr (dev, BHI_REG_INTVEC, 0);

  cfg.ner = md->n_events;
  cfg.nhwer = md->n_events > 0 ? md->n_events - 1 : 0;
  mhi_reg_wr (dev, MHI_REG_CFG, cfg.as_u32);

  mhi_reg_wr64 (dev, MHI_REG_MHICTRLBASE_LOWER, 0);
  mhi_reg_wr64 (dev, MHI_REG_MHICTRLLIMIT_LOWER, 0xffffffffULL);

  mhi_reg_wr64 (dev, MHI_REG_MHIDATABASE_LOWER, 0);
  mhi_reg_wr64 (dev, MHI_REG_MHIDATALIMIT_LOWER, 0xffffffffULL);

  rv = mhi_irq_init (vm, dev);
  if (rv != VNET_DEV_OK)
    return rv;

  u32 chdb_offset;
  mhi_reg_rd (dev, MHI_REG_CHDBOFF, &chdb_offset);
  for (int i = 0; i < md->n_chans; i++)
    md->ch_db[i] = (u8 *) md->bar0 + chdb_offset + (8 * i);
  u32 wake_db_off = chdb_offset + (8 * MHI_DEV_WAKE_DB);
  mhi_reg_wr64 (dev, wake_db_off, 1);

  /* 10. Check Execution Environment */
  bhi_reg_rd (dev, BHI_REG_EXECENV, &val);
  if (val == MHI_EE_AMSS)
    log_info (dev, "Device in %U", format_mhi_ee, val);
  else
    log_warn (dev, "Device in %U", format_mhi_ee, val);

  /* 11. Start MHI (Enable M0) */
  log_debug (dev, "Setting MHI State to M0");
  ctrl = (mhi_reg_ctrl_t){ .mhi_state = 2 }; /* M0 */
  mhi_reg_wr (dev, MHI_REG_CTRL, ctrl.as_u32);

  timeout = vlib_time_now (vm) + 5.0;
  while (1)
    {
      mhi_reg_rd (dev, MHI_REG_STATUS, &val);
      if (((mhi_reg_status_t){ .as_u32 = val }).mhi_state == 2) /* M0 */
	{
	  log_info (dev, "MHI entered M0 state");
	  mhi_reg_rd (dev, MHI_REG_STATUS, &val);
	  log_debug (dev, "MHI STATUS: %U", format_mhi_reg_read, MHI_REG_STATUS,
		    val);
	  break;
	}
      if (vlib_time_now (vm) > timeout)
	{
	  log_warn (dev,
		    "timeout waiting for MHI M0 state (current state: %u)",
		    ((mhi_reg_status_t){ .as_u32 = val }).mhi_state);
	  mhi_reg_rd (dev, MHI_REG_CTRL, &val);
	  log_warn (dev, "MHI CTRL: %U", format_mhi_reg_read, MHI_REG_CTRL, val);
	  mhi_reg_rd (dev, MHI_REG_STATUS, &val);
	  log_warn (dev, "MHI STATUS: %U", format_mhi_reg_read, MHI_REG_STATUS,
		    val);
	  bhi_reg_rd (dev, BHI_REG_ERRCODE, &val);
	  bhi_reg_rd (dev, BHI_REG_ERRDBG1, &val);
	  break;
	}
      vlib_process_suspend (vm, 1e-3);
    }

  return VNET_DEV_OK;
}

static void
mhi_deinit (vlib_main_t *vm, vnet_dev_t *dev)
{
  mhi_dev_t *md = vnet_dev_get_data (dev);
  u32 i;

  log_debug (dev, "deinit");

  if (md->event_rings)
    {
      mhi_tre_t **r;
      vec_foreach (r, md->event_rings)
	{
	  if (*r)
	    vnet_dev_dma_mem_free (vm, dev, *r);
	}
      vec_free (md->event_rings);
    }

  if (md->cmd_ring)
    vnet_dev_dma_mem_free (vm, dev, md->cmd_ring);

  for (i = 0; i < ARRAY_LEN (md->chan_rings); i++)
    {
      if (md->chan_rings[i])
	vnet_dev_dma_mem_free (vm, dev, md->chan_rings[i]);
    }

  if (md->chan_ctxt)
    vnet_dev_dma_mem_free (vm, dev, md->chan_ctxt);

  if (md->event_ctxt)
    vnet_dev_dma_mem_free (vm, dev, md->event_ctxt);
  if (md->cmd_ctxt)
    vnet_dev_dma_mem_free (vm, dev, md->cmd_ctxt);
}

VNET_DEV_REGISTER_DRIVER (mhi) = {
  .name = "mhi",
  .description = "Snapdragon X62 5G MHI driver",
  .bus = "pci",
  .device_data_sz = sizeof (mhi_dev_t),
  .ops = {
    .init = mhi_init,
    .deinit = mhi_deinit,
    .probe = mhi_probe,
  },
};
