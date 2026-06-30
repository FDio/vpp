/* SPDX-License-Identifier: BSD-3-Clause AND Apache-2.0
 * Copyright (c) 2025 Marvell.
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#include <pp2/pp2.h>

VLIB_REGISTER_LOG_CLASS (mvpp2_log, static) = {
  .class_name = "armada",
  .subclass_name = "classifier",
};

#define RETRIES_EXCEEDED (15000)

enum mv_pp2x_qos_src_tbl
{
  MVPP2_QOS_SRC_ACTION_TBL = 0,
  MVPP2_QOS_SRC_DSCP_PBIT_TBL,
};

static u8
mvpp2_cls_c2_tcam_port_get (struct mv_pp2x_cls_c2_entry *c2)
{
  return ((c2->tcam.words[4] >> 8) & 0xFF);
}

static u8
mvpp2_cls_c2_tcam_lkp_type_get (struct mv_pp2x_cls_c2_entry *c2)
{
  return (c2->tcam.words[4] & MVPP2_CLS_C2_HEK_LKP_TYPE_MASK);
}

static int
mvpp2_cls_c3_cpu_done (vnet_dev_t *dev)
{
  mvpp22_cls3_state_reg_t state;

  state.as_u32 = mvpp2_dev_reg_rd (dev, MVPP2_CLS3_STATE_REG);
  return state.cpu_done;
}

static void
mv_pp2x_cls_c2_rss_set (struct mv_pp2x_cls_c2_entry *c2, int rss_en)
{
  ASSERT (rss_en < (1 << MVPP2_CLS2_ACT_DUP_ATTR_RSSEN_BITS));

  c2->sram.regs.actions.rss = 3; /* update and lock */
  c2->sram.regs.rss_attr.rss_enable = rss_en;
}

void
mvpp2_cls_c2_hw_read (vnet_dev_t *dev, int index, struct mv_pp2x_cls_c2_entry *c2)
{
  unsigned int reg_val = 0;
  int tcm_idx;

  ASSERT (c2);
  ASSERT (index < MVPP2_CLS_C2_TCAM_SIZE);

  c2->index = index;

  /* write index reg */
  mvpp2_dev_reg_wr (dev, MVPP2_CLS2_TCAM_IDX_REG, index);

  /* read invalid bit */
  reg_val = mvpp2_dev_reg_rd (dev, MVPP2_CLS2_TCAM_INV_REG);

  c2->inv = (reg_val & MVPP2_CLS2_TCAM_INV_INVALID_MASK) >> MVPP2_CLS2_TCAM_INV_INVALID_OFF;

  if (c2->inv)
    return;

  for (tcm_idx = 0; tcm_idx < MVPP2_CLS_C2_TCAM_WORDS; tcm_idx++)
    c2->tcam.words[tcm_idx] = mvpp2_dev_reg_rd (dev, MVPP2_CLS2_TCAM_DATA_REG (tcm_idx));

  c2->sram.regs.action_tbl.as_u32 = mvpp2_dev_reg_rd (dev, MVPP2_CLS2_ACT_DATA_REG);
  c2->sram.regs.actions.as_u32 = mvpp2_dev_reg_rd (dev, MVPP2_CLS2_ACT_REG);
  c2->sram.regs.qos_attr.as_u32 = mvpp2_dev_reg_rd (dev, MVPP2_CLS2_ACT_QOS_ATTR_REG);
  c2->sram.regs.hwf_attr = mvpp2_dev_reg_rd (dev, MVPP2_CLS2_ACT_HWF_ATTR_REG);
  c2->sram.regs.rss_attr.as_u32 = mvpp2_dev_reg_rd (dev, MVPP2_CLS2_ACT_DUP_ATTR_REG);
  c2->sram.regs.seq_attr = mvpp2_dev_reg_rd (dev, MVPP21_CLS2_ACT_SEQ_ATTR_REG);
}

static void
mv_pp2x_cls_c2_hw_write (vnet_dev_t *dev, int index, struct mv_pp2x_cls_c2_entry *c2)
{
  int tcm_idx;

  ASSERT (c2);
  ASSERT (index < MVPP2_CLS_C2_TCAM_SIZE);

  c2->index = index;

  log_debug (dev,
	     "program C2 entry %u: tcam %08x %08x %08x %08x %08x, action-table %08x actions %08x "
	     "qos %08x hwf %08x rss %08x",
	     index, c2->tcam.words[0], c2->tcam.words[1], c2->tcam.words[2], c2->tcam.words[3],
	     c2->tcam.words[4], c2->sram.regs.action_tbl.as_u32, c2->sram.regs.actions.as_u32,
	     c2->sram.regs.qos_attr.as_u32, c2->sram.regs.hwf_attr, c2->sram.regs.rss_attr.as_u32);

  /* write index reg */
  mvpp2_dev_reg_wr (dev, MVPP2_CLS2_TCAM_IDX_REG, index);

  /* write valid bit */
  c2->inv = 0;
  mvpp2_dev_reg_wr (dev, MVPP2_CLS2_TCAM_INV_REG, ((c2->inv) << MVPP2_CLS2_TCAM_INV_INVALID_OFF));

  for (tcm_idx = 0; tcm_idx < MVPP2_CLS_C2_TCAM_WORDS; tcm_idx++)
    mvpp2_dev_reg_wr (dev, MVPP2_CLS2_TCAM_DATA_REG (tcm_idx), c2->tcam.words[tcm_idx]);

  /* write action_tbl CLSC2_ACT_DATA */
  mvpp2_dev_reg_wr (dev, MVPP2_CLS2_ACT_DATA_REG, c2->sram.regs.action_tbl.as_u32);

  /* write actions CLSC2_ACT */
  mvpp2_dev_reg_wr (dev, MVPP2_CLS2_ACT_REG, c2->sram.regs.actions.as_u32);

  /* write qos_attr CLSC2_ATTR0 */
  mvpp2_dev_reg_wr (dev, MVPP2_CLS2_ACT_QOS_ATTR_REG, c2->sram.regs.qos_attr.as_u32);

  /* write hwf_attr CLSC2_ATTR1 */
  mvpp2_dev_reg_wr (dev, MVPP2_CLS2_ACT_HWF_ATTR_REG, c2->sram.regs.hwf_attr);

  /* write rss_attr CLSC2_ATTR2 */
  mvpp2_dev_reg_wr (dev, MVPP2_CLS2_ACT_DUP_ATTR_REG, c2->sram.regs.rss_attr.as_u32);
}

vnet_dev_rv_t
mvpp2_cls_rss_enable (vnet_dev_port_t *port, int en)
{
  vnet_dev_t *dev = port->dev;
  int index;
  int c2_status;
  u32 n_updated = 0;
  u8 port_id;
  struct mv_pp2x_cls_c2_entry c2 = {};

  c2_status = mvpp2_dev_reg_rd (dev, MVPP2_CLS2_TCAM_CTRL_REG);
  if (!c2_status)
    {
      log_err (dev, "C2 is disabled");
      return VNET_DEV_ERR_NOT_READY;
    }

  for (index = 0; index < MVPP2_CLS_C2_TCAM_SIZE; index++)
    {
      mvpp2_cls_c2_hw_read (dev, index, &c2);
      if (c2.inv)
	continue;
      port_id = mvpp2_cls_c2_tcam_port_get (&c2);

      if (port_id == (1 << mvpp2_port_id (port)))
	{
	  /* Set RSS */
	  mv_pp2x_cls_c2_rss_set (&c2, en);
	  mv_pp2x_cls_c2_hw_write (dev, index, &c2);
	  n_updated++;
	}
    }
  log_debug (dev, "%s RSS on %u C2 entries for port %u", en ? "enabled" : "disabled", n_updated,
	     mvpp2_port_id (port));
  return VNET_DEV_OK;
}

vnet_dev_rv_t
mvpp2_cls_rss_is_enabled (vnet_dev_port_t *port, int *en)
{
  vnet_dev_t *dev = port->dev;
  struct mv_pp2x_cls_c2_entry c2 = {};
  u8 port_map = 1 << mvpp2_port_id (port);
  int index;

  ASSERT (en);

  if (!mvpp2_dev_reg_rd (dev, MVPP2_CLS2_TCAM_CTRL_REG))
    return VNET_DEV_ERR_NOT_READY;

  *en = 0;
  for (index = 0; index < MVPP2_CLS_C2_TCAM_SIZE; index++)
    {
      mvpp2_cls_c2_hw_read (dev, index, &c2);
      if (c2.inv || mvpp2_cls_c2_tcam_port_get (&c2) != port_map)
	continue;

      *en |= c2.sram.regs.rss_attr.rss_enable;
    }

  return VNET_DEV_OK;
}

vnet_dev_rv_t
mvpp2_cls_mng_modify_default_flows (vnet_dev_port_t *port)
{
  vnet_dev_t *dev = port->dev;
  int index;
  int c2_status;
  u32 n_updated = 0;
  u8 port_id;
  struct mv_pp2x_cls_c2_entry c2 = {};

  c2_status = mvpp2_dev_reg_rd (dev, MVPP2_CLS2_TCAM_CTRL_REG);
  if (!c2_status)
    {
      log_err (dev, "C2 is disabled");
      return VNET_DEV_ERR_NOT_READY;
    }

  for (index = 0; index < MVPP2_CLS_C2_TCAM_SIZE; index++)
    {
      mvpp2_cls_c2_hw_read (dev, index, &c2);
      if (c2.inv)
	continue;
      port_id = mvpp2_cls_c2_tcam_port_get (&c2);

      if (port_id == (1 << mvpp2_port_id (port)))
	{
	  c2.sram.regs.actions.color = 2; /* green */
	  c2.sram.regs.action_tbl.color_from_table = 0;

	  mv_pp2x_cls_c2_hw_write (dev, index, &c2);
	  n_updated++;
	}
    }

  log_debug (dev, "set green coloring on %u C2 entries for port %u", n_updated,
	     mvpp2_port_id (port));
  return VNET_DEV_OK;
}

static void
mv_pp2x_cls_c2_hw_inv (vnet_dev_t *dev, int index)
{
  ASSERT (index < MVPP2_CLS_C2_TCAM_SIZE);

  /* write index reg */
  mvpp2_dev_reg_wr (dev, MVPP2_CLS2_TCAM_IDX_REG, index);

  /* set invalid bit */
  mvpp2_dev_reg_wr (dev, MVPP2_CLS2_TCAM_INV_REG, (1 << MVPP2_CLS2_TCAM_INV_INVALID_OFF));

  /* trigger */
  mvpp2_dev_reg_wr (dev, MVPP2_CLS2_TCAM_DATA_REG (4), 0);
}

static int
mvpp2_cls_c3_hit_cntr_clear_done (vnet_dev_t *dev)
{
  mvpp22_cls3_state_reg_t state;

  state.as_u32 = mvpp2_dev_reg_rd (dev, MVPP2_CLS3_STATE_REG);
  return state.clear_counters_done;
}

static int
mvpp2_cls_c3_hit_cntrs_clear_all (vnet_dev_t *dev)
{
  int iter = 0;

  mvpp2_dev_reg_wr (dev, MVPP2_CLS3_CLEAR_COUNTERS_REG, MVPP2_CLS3_CLEAR_ALL);
  /* wait to clear het counters done bit */
  while (!mvpp2_cls_c3_hit_cntr_clear_done (dev))
    if (++iter >= RETRIES_EXCEEDED)
      {
	log_err (dev, "C3 counter clear timed out after %u attempts", iter);
	return -EBUSY;
      }

  return 0;
}

static int
mvpp2_cls_c3_hw_del (vnet_dev_t *dev, int index)
{
  mvpp22_cls3_hash_op_reg_t operation = {
    .table_addr = index,
    .delete = 1,
  };
  int iter = 0;

  ASSERT (index <= MVPP2_CLS3_HASH_OP_TBL_ADDR_MAX);

  /*trigger del operation*/
  mvpp2_dev_reg_wr (dev, MVPP2_CLS3_HASH_OP_REG, operation.as_u32);

  /* wait to cpu access done bit */
  while (!mvpp2_cls_c3_cpu_done (dev))
    if (++iter >= RETRIES_EXCEEDED)
      {
	log_err (dev, "C3 delete entry %u timed out after %u attempts", index, iter);
	return -EBUSY;
      }

  return 0;
}

static int
mvpp2_cls_c3_hw_del_all (vnet_dev_t *dev)
{
  int index, status;

  for (index = 0; index < MVPP2_CLS_C3_HASH_TBL_SIZE; index++)
    {
      status = mvpp2_cls_c3_hw_del (dev, index);
      if (status != 0)
	return status;
    }
  return 0;
}

static int
mvpp2_cls_c3_reset (vnet_dev_t *dev)
{
  int rc = 0;

  log_debug (dev, "reset C3 entries 0-%u", MVPP2_CLS_C3_HASH_TBL_SIZE - 1);

  /* clear all C3 HW entries */
  rc = mvpp2_cls_c3_hw_del_all (dev);
  if (rc)
    {
      log_err (dev, "failed to delete C3 hardware entries");
      return rc;
    }
  log_debug (dev, "C3 hardware entries deleted");

  /* clear all C3 HW counters */
  rc = mvpp2_cls_c3_hit_cntrs_clear_all (dev);
  if (rc)
    {
      log_err (dev, "failed to clear C3 hardware counters");
      return rc;
    }
  log_debug (dev, "C3 hardware counters cleared");

  return 0;
}

static void
mvpp2_cls_c2_reset (vnet_dev_t *dev)
{
  int index;

  /* Clear all TCAM entry, except last one added by LSP */
  log_debug (dev, "invalidate C2 entries %u-%u", MVPP2_C2_FIRST_ENTRY, MVPP2_CLS_C2_TCAM_SIZE - 1);
  for (index = MVPP2_C2_FIRST_ENTRY; index < MVPP2_CLS_C2_TCAM_SIZE; index++)
    mv_pp2x_cls_c2_hw_inv (dev, index);
}

vnet_dev_rv_t
mvpp2_cls_mng_init (vnet_dev_t *dev)
{
  mvpp2_device_t *md = vnet_dev_get_data (dev);
  vnet_dev_rv_t rv;

  if (md->classifier_initialized)
    {
      log_debug (dev, "classifier already initialized");
      return VNET_DEV_OK;
    }

  log_debug (dev, "initialize parser and classifier");
  rv = mvpp2_parser_init (dev);
  if (rv != VNET_DEV_OK)
    return rv;
  mvpp2_dev_reg_wr (dev, MVPP2_CLS_MODE_REG, 1);
  log_debug (dev, "classifier enabled");
  mvpp2_cls_c2_reset (dev);
  if (mvpp2_cls_c3_reset (dev))
    log_err (dev, "C3 reset failed");
  else
    log_debug (dev, "C3 reset complete");
  md->classifier_initialized = 1;
  return VNET_DEV_OK;
}

static void
mvpp2_c2_config_queue (struct mv_pp2x_cls_c2_entry *c2, u16 queue, int from)
{
  c2->sram.regs.actions.low_queue = 3;	/* update and lock */
  c2->sram.regs.actions.high_queue = 3; /* update and lock */
  c2->sram.regs.qos_attr.low_queue = queue;
  c2->sram.regs.qos_attr.high_queue = queue >> MVPP2_CLS2_ACT_QOS_ATTR_QL_BITS;
  c2->sram.regs.action_tbl.low_queue_from_table = from;
  c2->sram.regs.action_tbl.high_queue_from_table = from;
}

static void
mvpp2_c2_config_default_queue (vnet_dev_port_t *port, u16 queue)
{
  vnet_dev_t *dev = port->dev;
  int index;
  int c2_status;
  u32 n_updated = 0;
  u8 port_id, lkp_type;
  struct mv_pp2x_cls_c2_entry c2 = {};

  c2_status = mvpp2_dev_reg_rd (dev, MVPP2_CLS2_TCAM_CTRL_REG);
  if (!c2_status)
    {
      log_err (dev, "C2 is disabled");
      return;
    }

  for (index = 0; index < MVPP2_CLS_C2_TCAM_SIZE; index++)
    {
      mvpp2_cls_c2_hw_read (dev, index, &c2);
      if (c2.inv)
	continue;
      port_id = mvpp2_cls_c2_tcam_port_get (&c2);
      lkp_type = mvpp2_cls_c2_tcam_lkp_type_get (&c2);

      if (port_id != (1 << mvpp2_port_id (port)))
	continue;

      if (lkp_type == MVPP2_CLS_LKP_DEFAULT)
	{
	  mvpp2_c2_config_queue (&c2, queue, MVPP2_QOS_SRC_ACTION_TBL);
	  log_debug (dev, "update C2 entry %#x queue %u source %u", index, queue,
		     MVPP2_QOS_SRC_ACTION_TBL);
	  mv_pp2x_cls_c2_hw_write (dev, index, &c2);
	  n_updated++;
	}
      else if (lkp_type == MVPP2_CLS_LKP_DSCP_PRI || lkp_type == MVPP2_CLS_LKP_VLAN_PRI)
	{
	  mvpp2_c2_config_queue (&c2, queue, MVPP2_QOS_SRC_DSCP_PBIT_TBL);
	  log_debug (dev, "update C2 entry %#x queue %u source %u", index, queue,
		     MVPP2_QOS_SRC_DSCP_PBIT_TBL);
	  mv_pp2x_cls_c2_hw_write (dev, index, &c2);
	  n_updated++;
	}
    }
  log_debug (dev, "updated %u C2 default queue entries for port %u", n_updated,
	     mvpp2_port_id (port));
}

static void
mvpp2_cls_qos_table_set (vnet_dev_port_t *port, u8 select, u32 n_lines)
{
  vnet_dev_t *dev = port->dev;
  u8 queue = mvpp2_port_get_rxq_hw_id (port, 0);
  mvpp22_cls2_qos_tbl_reg_t data = {
    .queue = queue,
  };

  /* Color zero is green. */
  for (u32 line = 0; line < n_lines; line++)
    {
      mvpp22_cls2_dscp_pri_index_reg_t index = {
	.line = line,
	.select = select,
	.table_id = mvpp2_port_id (port),
      };

      mvpp2_dev_reg_wr (dev, MVPP2_CLS2_DSCP_PRI_INDEX_REG, index.as_u32);
      mvpp2_dev_reg_wr (dev, MVPP2_CLS2_QOS_TBL_REG, data.as_u32);
    }
  log_debug (dev, "program QoS table %u entries 0-%u to queue %u", select, n_lines - 1, queue);
}

void
mvpp2_cls_mng_config_default_cos_queue (vnet_dev_port_t *port)
{
  u32 rxq0_hw_id = mvpp2_port_get_rxq_hw_id (port, 0);

  mvpp2_c2_config_default_queue (port, rxq0_hw_id);
  mvpp2_cls_qos_table_set (port, MVPP2_QOS_TBL_SEL_DSCP, MVPP2_QOS_TBL_LINE_NUM_DSCP);
  mvpp2_cls_qos_table_set (port, MVPP2_QOS_TBL_SEL_PRI, MVPP2_QOS_TBL_LINE_NUM_PRI);
}

void
mvpp2x_cls_oversize_rxq_set (vnet_dev_port_t *port)
{
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);

  mvpp2_dev_reg_wr (port->dev, MVPP2_CLS_OVERSIZE_RXQ_LOW_REG (mp->id),
		    mvpp2_port_get_rxq_hw_id (port, 0));
  log_debug (port->dev, "port %u oversize packets use hardware RXQ %u", mp->id,
	     mvpp2_port_get_rxq_hw_id (port, 0));
}
