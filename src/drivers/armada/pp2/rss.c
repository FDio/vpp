/* SPDX-License-Identifier: BSD-3-Clause AND Apache-2.0
 * Copyright (c) 2025 Marvell.
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#include <pp2/pp2.h>

VLIB_REGISTER_LOG_CLASS (mvpp2_log, static) = {
  .class_name = "armada",
  .subclass_name = "rss",
};

enum mv_pp22_rss_access_sel
{
  MVPP22_RSS_ACCESS_POINTER,
  MVPP22_RSS_ACCESS_TBL,
};

struct mv_pp22_rss_tbl_ptr
{
  u8 rxq_idx;
  u8 rss_tbl_ptr;
};

struct mv_pp22_rss_tbl_entry
{
  u8 tbl_id;
  u8 tbl_line;
  u8 width;
  u8 rxq;
};

union mv_pp22_rss_access_entry
{
  struct mv_pp22_rss_tbl_ptr pointer;
  struct mv_pp22_rss_tbl_entry entry;
};

struct mv_pp22_rss_entry
{
  enum mv_pp22_rss_access_sel sel;
  union mv_pp22_rss_access_entry u;
};

static int
mvpp2_rss_hw_table_get (vnet_dev_t *dev, mvpp2_device_t *md, u8 num_in_q)
{
  int i;

  for (i = 0; i < MVPP22_RSS_TBL_NUM; i++)
    {
      log_debug (dev, "%d num_in_q %d, %d\n", i, md->rss_tbl_map[i].num_in_q, num_in_q);
      if (md->rss_tbl_map[i].num_in_q == num_in_q)
	return md->rss_tbl_map[i].hw_tbl;
    }

  return -1;
}

static u16
mvpp2_rss_num_tables_get (mvpp2_device_t *md)
{
  return md->num_rss_tables;
}

static void
mvpp2_rss_num_tables_set (mvpp2_device_t *md, u16 num_tables)
{
  md->num_rss_tables = num_tables;
}

static int
mvpp2_rss_table_map_next_free (mvpp2_device_t *md)
{
  int i;

  for (i = 0; i < MVPP22_RSS_TBL_NUM; i++)
    if (md->rss_tbl_map[i].num_in_q == 0)
      return i;

  return i;
}

static int
mvpp2_rss_table_map_set (mvpp2_device_t *md, u16 idx, u16 hw_tbl, u16 num_in_q)
{
  if (idx > MVPP22_RSS_TBL_NUM || hw_tbl > MVPP22_RSS_TBL_NUM)
    return -EINVAL;

  md->rss_tbl_map[idx].hw_tbl = hw_tbl;
  md->rss_tbl_map[idx].num_in_q = num_in_q;

  return 0;
}

static int
mvpp2_rss_tbl_entry_set (vnet_dev_t *dev, mvpp2_device_t *md, struct mv_pp22_rss_entry *rss)
{
  unsigned int reg_val = 0;

  if (!rss || rss->sel > MVPP22_RSS_ACCESS_TBL)
    return -EINVAL;

  if (rss->sel == MVPP22_RSS_ACCESS_POINTER)
    {
      if (rss->u.pointer.rss_tbl_ptr >= MVPP22_RSS_TBL_NUM)
	return -EINVAL;
      /* Write index */
      reg_val |= rss->u.pointer.rxq_idx << MVPP22_RSS_IDX_RXQ_NUM_OFF;
      mvpp2_reg_write (md->pp_base, MVPP22_RSS_IDX_REG, reg_val);
      log_debug (dev, "rss queue %d, reg_val %x", rss->u.pointer.rxq_idx, reg_val);
      /* Write entry */
      reg_val = 0;
      reg_val &= (~MVPP22_RSS_RXQ2RSS_TBL_POINT_MASK);
      reg_val |= rss->u.pointer.rss_tbl_ptr << MVPP22_RSS_RXQ2RSS_TBL_POINT_OFF;
      mvpp2_reg_write (md->pp_base, MVPP22_RSS_RXQ2RSS_TBL_REG, reg_val);
      log_debug (dev, ", table %d, reg_val %x\n", rss->u.pointer.rss_tbl_ptr, reg_val);
    }
  else if (rss->sel == MVPP22_RSS_ACCESS_TBL)
    {
      if (rss->u.entry.tbl_id >= MVPP22_RSS_TBL_NUM ||
	  rss->u.entry.tbl_line >= MVPP22_RSS_TBL_LINE_NUM ||
	  rss->u.entry.width > MVPP22_RSS_WIDTH_MAX)
	return -EINVAL;
      /* Write index */
      reg_val |= (rss->u.entry.tbl_line << MVPP22_RSS_IDX_ENTRY_NUM_OFF |
		  rss->u.entry.tbl_id << MVPP22_RSS_IDX_TBL_NUM_OFF);
      mvpp2_reg_write (md->pp_base, MVPP22_RSS_IDX_REG, reg_val);
      /* Write entry */
      reg_val &= (~MVPP22_RSS_TBL_ENTRY_MASK);
      reg_val |= (rss->u.entry.rxq << MVPP22_RSS_TBL_ENTRY_OFF);
      mvpp2_reg_write (md->pp_base, MVPP22_RSS_TBL_ENTRY_REG, reg_val);
      reg_val &= (~MVPP22_RSS_WIDTH_MASK);
      reg_val |= (rss->u.entry.width << MVPP22_RSS_WIDTH_OFF);
      mvpp2_reg_write (md->pp_base, MVPP22_RSS_WIDTH_REG, reg_val);
    }
  return 0;
}

static int
mvpp2_rss_hw_tbl_set (vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  mvpp2_device_t *md = vnet_dev_get_data (port->dev);
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  struct mv_pp22_rss_entry rss_entry = {};
  int i;
  int entry_idx;
  u16 width;
  int hw_tbl;

  rss_entry.sel = MVPP22_RSS_ACCESS_TBL;

  for (i = 0; i < mp->num_tcs; i++)
    {
      if (mp->tc.tc_config.num_in_qs == 1)
	continue;

      hw_tbl = mvpp2_rss_hw_table_get (dev, md, mp->tc.tc_config.num_in_qs);
      if (hw_tbl < 0)
	{
	  log_err (dev, "%s RSS table index not found\n", __func__);
	  return -EFAULT;
	}
      rss_entry.u.entry.tbl_id = hw_tbl;

      width = max_log2 (mp->tc.tc_config.num_in_qs);
      log_debug (dev, "setting rss table %d, width %d\n", rss_entry.u.entry.tbl_id, width);
      rss_entry.u.entry.width = width;

      for (entry_idx = 0; entry_idx < MVPP22_RSS_TBL_LINE_NUM; entry_idx++)
	{
	  rss_entry.u.entry.tbl_line = entry_idx;
	  rss_entry.u.entry.rxq = entry_idx % mp->tc.tc_config.num_in_qs;
	  if (mvpp2_rss_tbl_entry_set (dev, md, &rss_entry))
	    return -1;
	}
    }
  return 0;
}

/* The function allocate a rss table for each phisical rxq,
 * they have same cos priority
 */
static int
mvpp2_rss_rxq_set (vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  mvpp2_device_t *md = vnet_dev_get_data (port->dev);
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  int i, j;
  struct mv_pp22_rss_entry rss_entry = {};
  int hw_tbl;

  rss_entry.sel = MVPP22_RSS_ACCESS_POINTER;

  for (i = 0; i < mp->num_tcs; i++)
    {
      if (mp->tc.tc_config.num_in_qs == 1)
	continue;

      /* Set the table index to be used according to rss_map */
      hw_tbl = mvpp2_rss_hw_table_get (dev, md, mp->tc.tc_config.num_in_qs);
      if (hw_tbl < 0)
	{
	  log_err (dev, "%s RSS table index not found %d. Check mvpp2x_sysfs.ko module is loaded\n",
		   __func__, mp->tc.tc_config.num_in_qs);
	  return -EFAULT;
	}
      rss_entry.u.pointer.rss_tbl_ptr = hw_tbl;

      for (j = 0; j < mp->tc.tc_config.num_in_qs; j++)
	{
	  rss_entry.u.pointer.rxq_idx = mp->tc.tc_config.first_rxq + j;
	  log_debug (dev, "%d rxq_idx %d rss_tbl %d\n", j, rss_entry.u.pointer.rxq_idx,
		     rss_entry.u.pointer.rss_tbl_ptr);
	  if (mvpp2_rss_tbl_entry_set (dev, md, &rss_entry))
	    return -EFAULT;
	}
    }
  return 0;
}

static int
mvpp2_rss_enable (vnet_dev_port_t *port, int en)
{
  int rc;

  rc = mvpp2_cls_rss_enable (port, en);
  if (rc)
    return -EINVAL;

  return 0;
}

static int
mvpp2_rss_table_map_alloc (vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  u16 req_tbls = 0, used_tbls, avail_tbls;
  int i, idx, req_ind[MVPP22_RSS_TBL_NUM] = {};
  mvpp2_device_t *md = vnet_dev_get_data (port->dev);
  int hw_tbl;
  u16 num_in_q;

  used_tbls = mvpp2_rss_num_tables_get (md);
  avail_tbls = MVPP22_RSS_TBL_NUM - used_tbls;

  /* Calculate number of TC's which require RSS */
  for (i = 0; i < mp->num_tcs; i++)
    {
      if (mp->tc.tc_config.num_in_qs == 1)
	continue;

      hw_tbl = mvpp2_rss_hw_table_get (dev, md, mp->tc.tc_config.num_in_qs);
      /* New hw_tbl required for this TC */
      if (hw_tbl < 0)
	{
	  if (req_tbls >= avail_tbls)
	    {
	      log_err (dev, "%s:Out of RSS tables\n", __func__);
	      goto rollback;
	    }
	  /* entry in rss_tbl_map is empty. Fill dB with new values */
	  idx = mvpp2_rss_table_map_next_free (md);
	  if (idx == MVPP22_RSS_TBL_NUM)
	    {
	      /* This should never happen */
	      log_err (dev, "%s: Unable to allocate new RSS table\n", __func__);
	      goto rollback;
	    }
	  mvpp2_rss_table_map_set (md, idx, idx, mp->tc.tc_config.num_in_qs);
	  req_ind[req_tbls] = idx;
	  req_tbls++;
	  hw_tbl = idx;
	  num_in_q = mp->tc.tc_config.num_in_qs;
	  log_debug (dev, "%s: rss_db_ind:%d, rss_hw_tbl_id:%d, num_in_q:%d\n", __func__, idx,
		     hw_tbl, num_in_q);
	}
    }

  mvpp2_rss_num_tables_set (md, (used_tbls + req_tbls));

  return 0;
rollback:
  for (i = 0; i < req_tbls; i++)
    mvpp2_rss_table_map_set (md, req_ind[i], 0, 0);
  return -ENOSPC;
}

void
mvpp2_rss_port_init (vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  int rc, i;
  u32 num_queues = 0;

  mp->rss_en = 1;

  /* Check total number of TC's and number of in_queues per TC do
   * not exceed maximum number of HW queues in port
   */
  for (i = 0; i < mp->num_tcs; i++)
    num_queues += mp->tc.tc_config.num_in_qs;

  if (num_queues > PP2_PPIO_MAX_NUM_TCS)
    {
      log_err (dev,
	       "not enough hw queues to allocate %d TC's and RSS. Needed %d queues, available %d\n",
	       mp->num_tcs, num_queues, PP2_PPIO_MAX_NUM_TCS);
      log_err (dev, "RSS is set to disabled\n");
      mp->rss_en = 0;
    }

  if (mp->hash_type == PP2_PPIO_HASH_T_NONE)
    mp->rss_en = 0;
  else
    {
      /* calculate the required driver RSS table map (not including the kernel rss map) */
      rc = mvpp2_rss_table_map_alloc (port);
      if (rc)
	{
	  log_err (dev, "Error in mvpp2_rss_table_map_alloc\n");
	  log_err (dev, "RSS is set to disabled\n");
	  mp->rss_en = 0;
	}
    }

  if (mp->rss_en != 0)
    {
      /* bind rxq to rss table for this port */
      if (mvpp2_rss_rxq_set (port))
	{
	  log_err (dev, "cannot allocate rss table for rxq\n");
	  log_err (dev, "RSS is set to disabled\n");
	  mp->rss_en = 0;
	}

      /* Init RSS table */
      if (mvpp2_rss_hw_tbl_set (port))
	{
	  log_err (dev, "cannot init rss hw table\n");
	  log_err (dev, "RSS is set to disabled\n");
	  mp->rss_en = 0;
	}
    }

  /* Enable or disable RSS*/
  if (mvpp2_rss_enable (port, mp->rss_en))
    {
      log_err (dev, "cannot enable rss\n");
      return;
    }
}
