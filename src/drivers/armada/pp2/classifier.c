/* SPDX-License-Identifier: BSD-3-Clause AND Apache-2.0
 * Copyright (c) 2025 Marvell.
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#include <pp2/pp2.h>
#include <stdbool.h>

VLIB_REGISTER_LOG_CLASS (mvpp2_log, static) = {
  .class_name = "armada",
  .subclass_name = "classifier",
};

#define NOT_IN_USE	 (-1)
#define RETRIES_EXCEEDED (15000)

enum mv_pp2x_qos_tbl_sel
{
  MVPP2_QOS_TBL_SEL_PRI = 0,
  MVPP2_QOS_TBL_SEL_DSCP,
};

enum mv_pp2x_qos_src_tbl
{
  MVPP2_QOS_SRC_ACTION_TBL = 0,
  MVPP2_QOS_SRC_DSCP_PBIT_TBL,
};

enum mv_pp2x_cls_lkp_type
{
  MVPP2_CLS_LKP_HASH = 0,
  MVPP2_CLS_LKP_VLAN_PRI,
  MVPP2_CLS_LKP_DSCP_PRI,
  MVPP2_CLS_LKP_DEFAULT,
};

enum mv_pp2x_color_action_type
{
  /* Do not update color */
  MVPP2_COLOR_ACTION_TYPE_NO_UPDT = 0,
  /* Do not update color and lock */
  MVPP2_COLOR_ACTION_TYPE_NO_UPDT_LOCK,
  /* Update to green */
  MVPP2_COLOR_ACTION_TYPE_GREEN,
  /* Update to green and lock */
  MVPP2_COLOR_ACTION_TYPE_GREEN_LOCK,
  /* Update to yellow */
  MVPP2_COLOR_ACTION_TYPE_YELLOW,
  /* Update to yellow */
  MVPP2_COLOR_ACTION_TYPE_YELLOW_LOCK,
  /* Update to red */
  MVPP2_COLOR_ACTION_TYPE_RED,
  /* Update to red and lock */
  MVPP2_COLOR_ACTION_TYPE_RED_LOCK,
};

enum mv_pp2x_general_action_type
{
  /* The field will be not updated */
  MVPP2_ACTION_TYPE_NO_UPDT,
  /* The field will be not updated and lock */
  MVPP2_ACTION_TYPE_NO_UPDT_LOCK,
  /* The field will be updated */
  MVPP2_ACTION_TYPE_UPDT,
  /* The field will be updated and lock */
  MVPP2_ACTION_TYPE_UPDT_LOCK,
};

struct mv_pp2x_cls_c2_qos_entry
{
  u32 tbl_id;
  u32 tbl_sel;
  u32 tbl_line;
  u32 data;
};

struct pp2_cls_c3_shadow_hash_entry
{
  /* valid if size > 0 */
  /* size include the extension*/
  int ext_ptr;
  int size;
};

static struct pp2_cls_c3_shadow_hash_entry pp2_cls_c3_shadow_tbl[MVPP2_CLS_C3_HASH_TBL_SIZE];
static int pp2_cls_c3_shadow_ext_tbl[MVPP2_CLS_C3_EXT_TBL_SIZE];

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

static void
mv_pp2x_c2_sw_clear (struct mv_pp2x_cls_c2_entry *c2)
{
  *c2 = (struct mv_pp2x_cls_c2_entry) {};
}

static int
mvpp2_cls_c3_cpu_done (uintptr_t hif_base)
{
  u32 reg_val;

  reg_val = mvpp2_reg_read (hif_base, MVPP2_CLS3_STATE_REG);
  reg_val &= MVPP2_CLS3_STATE_CPU_DONE_MASK;
  reg_val >>= MVPP2_CLS3_STATE_CPU_DONE;
  return reg_val;
}

static vnet_dev_rv_t
mv_pp2x_range_validate (vnet_dev_t *dev, int value, int min, int max)
{
  if (((value) > (max)) || ((value) < (min)))
    {
      log_err (dev, "%s: value 0x%X (%d) is out of range [0x%X , 0x%X].\n", __func__, (value),
	       (value), (min), (max));
      return VNET_DEV_ERR_INVALID_ARG;
    }
  return VNET_DEV_OK;
}

static int
mv_pp2x_cls_c2_rss_set (struct mv_pp2x_cls_c2_entry *c2, int cmd, int rss_en)
{
  if (!c2 || cmd > MVPP2_ACTION_TYPE_UPDT_LOCK ||
      rss_en >= (1 << MVPP2_CLS2_ACT_DUP_ATTR_RSSEN_BITS))
    return -EINVAL;

  c2->sram.regs.actions &= ~MVPP2_CLS2_ACT_RSS_MASK;
  c2->sram.regs.actions |= (cmd << MVPP2_CLS2_ACT_RSS_OFF);

  c2->sram.regs.rss_attr &= ~MVPP2_CLS2_ACT_DUP_ATTR_RSSEN_MASK;
  c2->sram.regs.rss_attr |= (rss_en << MVPP2_CLS2_ACT_DUP_ATTR_RSSEN_OFF);

  return 0;
}

static vnet_dev_rv_t
mv_pp2x_ptr_validate (vnet_dev_t *dev, const void *ptr)
{
  if (!ptr)
    {
      log_err (dev, "%s: null pointer.\n", __func__);
      return VNET_DEV_ERR_INVALID_ARG;
    }
  return VNET_DEV_OK;
}

static vnet_dev_rv_t
mv_pp2x_cls_c2_hw_read (vnet_dev_t *dev, uintptr_t hif_base, int index,
			struct mv_pp2x_cls_c2_entry *c2)
{
  unsigned int reg_val = 0;
  int tcm_idx;

  if (mv_pp2x_ptr_validate (dev, c2) != VNET_DEV_OK)
    return VNET_DEV_ERR_INVALID_ARG;

  c2->index = index;

  /* write index reg */
  mvpp2_reg_write (hif_base, MVPP2_CLS2_TCAM_IDX_REG, index);

  /* read invalid bit */
  reg_val = mvpp2_reg_read (hif_base, MVPP2_CLS2_TCAM_INV_REG);

  c2->inv = (reg_val & MVPP2_CLS2_TCAM_INV_INVALID_MASK) >> MVPP2_CLS2_TCAM_INV_INVALID_OFF;

  if (c2->inv)
    return VNET_DEV_OK;

  for (tcm_idx = 0; tcm_idx < MVPP2_CLS_C2_TCAM_WORDS; tcm_idx++)
    c2->tcam.words[tcm_idx] = mvpp2_reg_read (hif_base, MVPP2_CLS2_TCAM_DATA_REG (tcm_idx));

  c2->sram.regs.action_tbl = mvpp2_reg_read (hif_base, MVPP2_CLS2_ACT_DATA_REG);
  c2->sram.regs.actions = mvpp2_reg_read (hif_base, MVPP2_CLS2_ACT_REG);
  c2->sram.regs.qos_attr = mvpp2_reg_read (hif_base, MVPP2_CLS2_ACT_QOS_ATTR_REG);
  c2->sram.regs.hwf_attr = mvpp2_reg_read (hif_base, MVPP2_CLS2_ACT_HWF_ATTR_REG);
  c2->sram.regs.rss_attr = mvpp2_reg_read (hif_base, MVPP2_CLS2_ACT_DUP_ATTR_REG);
  c2->sram.regs.seq_attr = mvpp2_reg_read (hif_base, MVPP21_CLS2_ACT_SEQ_ATTR_REG);

  return VNET_DEV_OK;
}

int
mv_pp2x_cls_c2_hw_write (uintptr_t hif_base, int index, struct mv_pp2x_cls_c2_entry *c2)
{
  int tcm_idx;

  if (!c2 || index >= MVPP2_CLS_C2_TCAM_SIZE)
    return -EINVAL;

  c2->index = index;

  /* write index reg */
  mvpp2_reg_write (hif_base, MVPP2_CLS2_TCAM_IDX_REG, index);

  /* write valid bit */
  c2->inv = 0;
  mvpp2_reg_write (hif_base, MVPP2_CLS2_TCAM_INV_REG,
		   ((c2->inv) << MVPP2_CLS2_TCAM_INV_INVALID_OFF));

  for (tcm_idx = 0; tcm_idx < MVPP2_CLS_C2_TCAM_WORDS; tcm_idx++)
    mvpp2_reg_write (hif_base, MVPP2_CLS2_TCAM_DATA_REG (tcm_idx), c2->tcam.words[tcm_idx]);

  /* write action_tbl CLSC2_ACT_DATA */
  mvpp2_reg_write (hif_base, MVPP2_CLS2_ACT_DATA_REG, c2->sram.regs.action_tbl);

  /* write actions CLSC2_ACT */
  mvpp2_reg_write (hif_base, MVPP2_CLS2_ACT_REG, c2->sram.regs.actions);

  /* write qos_attr CLSC2_ATTR0 */
  mvpp2_reg_write (hif_base, MVPP2_CLS2_ACT_QOS_ATTR_REG, c2->sram.regs.qos_attr);

  /* write hwf_attr CLSC2_ATTR1 */
  mvpp2_reg_write (hif_base, MVPP2_CLS2_ACT_HWF_ATTR_REG, c2->sram.regs.hwf_attr);

  /* write rss_attr CLSC2_ATTR2 */
  mvpp2_reg_write (hif_base, MVPP2_CLS2_ACT_DUP_ATTR_REG, c2->sram.regs.rss_attr);

  return 0;
}

vnet_dev_rv_t
mvpp2_cls_rss_enable (vnet_dev_port_t *port, int en)
{
  vnet_dev_t *dev = port->dev;
  mvpp2_device_t *md = vnet_dev_get_data (port->dev);
  int index;
  int c2_status;
  int rc;
  u8 port_id;
  struct mv_pp2x_cls_c2_entry c2;

  c2_status = mvpp2_reg_read (md->pp_base, MVPP2_CLS2_TCAM_CTRL_REG);
  if (!c2_status)
    {
      log_err (dev, "c2 is off\n");
      return VNET_DEV_ERR_NOT_READY;
    }

  mv_pp2x_c2_sw_clear (&c2);

  for (index = 0; index < MVPP2_CLS_C2_TCAM_SIZE; index++)
    {
      mv_pp2x_cls_c2_hw_read (dev, md->pp_base, index, &c2);
      port_id = mvpp2_cls_c2_tcam_port_get (&c2);

      if (c2.inv == 0 && port_id == (1 << mvpp2_port_id (port)))
	{
	  /* Set RSS */
	  rc = mv_pp2x_cls_c2_rss_set (&c2, MVPP2_ACTION_TYPE_UPDT_LOCK, en);
	  if (rc)
	    return VNET_DEV_ERR_INTERNAL;
	  mv_pp2x_cls_c2_hw_write (md->pp_base, index, &c2);

	  mv_pp2x_c2_sw_clear (&c2);
	  mv_pp2x_cls_c2_hw_read (dev, md->pp_base, index, &c2);
	}
    }
  return VNET_DEV_OK;
}

int
mv_pp2x_cls_c2_color_set (struct mv_pp2x_cls_c2_entry *c2, int cmd, int from)
{
  if (!c2 || cmd > MVPP2_COLOR_ACTION_TYPE_RED_LOCK)
    return -EINVAL;

  c2->sram.regs.actions &= ~MVPP2_CLS2_ACT_COLOR_MASK;
  c2->sram.regs.actions |= (cmd << MVPP2_CLS2_ACT_COLOR_OFF);

  if (from == 1)
    c2->sram.regs.action_tbl |= (1 << MVPP2_CLS2_ACT_DATA_TBL_COLOR_OFF);
  else
    c2->sram.regs.action_tbl &= ~(1 << MVPP2_CLS2_ACT_DATA_TBL_COLOR_OFF);

  return 0;
}

static int
mvpp2_c2_set_default_coloring (vnet_dev_port_t *port, int clear)
{
  vnet_dev_t *dev = port->dev;
  mvpp2_device_t *md = vnet_dev_get_data (port->dev);
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  int index;
  int c2_status;
  int rc;
  u8 port_id;
  struct mv_pp2x_cls_c2_entry c2;
  enum mv_pp2x_color_action_type color_action = 0;

  c2_status = mvpp2_reg_read (md->pp_base, MVPP2_CLS2_TCAM_CTRL_REG);
  if (!c2_status)
    {
      log_err (dev, "c2 is off\n");
      return -EINVAL;
    }

  if (clear)
    color_action = MVPP2_COLOR_ACTION_TYPE_GREEN;
  else
    {
      switch (mp->tc.tc_config.default_color)
	{
	case MVPP2_PORT_COLOR_GREEN:
	  color_action = MVPP2_COLOR_ACTION_TYPE_GREEN;
	  break;
	case MVPP2_PORT_COLOR_YELLOW:
	  color_action = MVPP2_COLOR_ACTION_TYPE_YELLOW;
	  break;
	case MVPP2_PORT_COLOR_RED:
	  color_action = MVPP2_COLOR_ACTION_TYPE_RED;
	  break;
	}
    }

  mv_pp2x_c2_sw_clear (&c2);

  for (index = 0; index < MVPP2_CLS_C2_TCAM_SIZE; index++)
    {
      mv_pp2x_cls_c2_hw_read (dev, md->pp_base, index, &c2);
      port_id = mvpp2_cls_c2_tcam_port_get (&c2);

      if (c2.inv == 0 && port_id == (1 << mvpp2_port_id (port)))
	{
	  rc = mv_pp2x_cls_c2_color_set (&c2, color_action, MVPP2_QOS_SRC_ACTION_TBL);
	  if (rc)
	    return rc;

	  mv_pp2x_cls_c2_hw_write (md->pp_base, index, &c2);
	}
    }

  return 0;
}

static void
mvpp2_cls_c3_shadow_init (void)
{
  /* clear hash shadow and extension shadow */
  int index;

  for (index = 0; index < MVPP2_CLS_C3_HASH_TBL_SIZE; index++)
    {
      pp2_cls_c3_shadow_tbl[index].size = 0;
      pp2_cls_c3_shadow_tbl[index].ext_ptr = NOT_IN_USE;
    }

  for (index = 0; index < MVPP2_CLS_C3_EXT_TBL_SIZE; index++)
    pp2_cls_c3_shadow_ext_tbl[index] = NOT_IN_USE;
}

static int
mvpp2_cls_mng_set_coloring (vnet_dev_port_t *port, int clear)
{
  vnet_dev_t *dev = port->dev;
  int rc;

  rc = mvpp2_c2_set_default_coloring (port, clear);
  if (rc)
    {
      log_err (dev, "%s(%d) mvpp2_c2_set_default_coloring fail\n", __func__, __LINE__);
      return -EINVAL;
    }

  return 0;
}

static int
mv_pp2x_cls_c2_hw_inv (uintptr_t hif_base, int index)
{
  if (!hif_base || index >= MVPP2_CLS_C2_TCAM_SIZE)
    return -EINVAL;

  /* write index reg */
  mvpp2_reg_write (hif_base, MVPP2_CLS2_TCAM_IDX_REG, index);

  /* set invalid bit */
  mvpp2_reg_write (hif_base, MVPP2_CLS2_TCAM_INV_REG, (1 << MVPP2_CLS2_TCAM_INV_INVALID_OFF));

  /* trigger */
  mvpp2_reg_write (hif_base, MVPP2_CLS2_TCAM_DATA_REG (4), 0);

  return 0;
}

static int
mvpp2_cls_c3_hit_cntr_clear_done (uintptr_t hif_base)
{
  u32 reg_val;

  reg_val = mvpp2_reg_read (hif_base, MVPP2_CLS3_STATE_REG);
  reg_val &= MVPP2_CLS3_STATE_CLEAR_CTR_DONE_MASK;
  reg_val >>= MVPP2_CLS3_STATE_CLEAR_CTR_DONE;
  return reg_val;
}

static int
mvpp2_cls_c3_hit_cntrs_clear_all (vnet_dev_t *dev, uintptr_t hif_base)
{
  int iter = 0;

  mvpp2_reg_write (hif_base, MVPP2_CLS3_CLEAR_COUNTERS_REG, MVPP2_CLS3_CLEAR_ALL);
  /* wait to clear het counters done bit */
  while (!mvpp2_cls_c3_hit_cntr_clear_done (hif_base))
    if (++iter >= RETRIES_EXCEEDED)
      {
	log_err (dev, "%s:Error - retries exceeded.\n", __func__);
	return -EBUSY;
      }

  return 0;
}

static int
mvpp2_cls_c3_init (vnet_dev_t *dev, uintptr_t hif_base)
{
  int rc;

  mvpp2_cls_c3_shadow_init ();
  rc = mvpp2_cls_c3_hit_cntrs_clear_all (dev, hif_base);
  return rc;
}

static void
mvpp2_cls_c3_shadow_clear (int index)
{
  int ext_ptr;

  pp2_cls_c3_shadow_tbl[index].size = 0;
  ext_ptr = pp2_cls_c3_shadow_tbl[index].ext_ptr;

  if (ext_ptr != NOT_IN_USE)
    pp2_cls_c3_shadow_ext_tbl[ext_ptr] = NOT_IN_USE;

  pp2_cls_c3_shadow_tbl[index].ext_ptr = NOT_IN_USE;
}

int
mvpp2_cls_mng_modify_default_flows (vnet_dev_port_t *port, int clear)
{
  vnet_dev_t *dev = port->dev;
  int rc;

  rc = mvpp2_cls_mng_set_coloring (port, clear);
  if (rc)
    {
      log_err (dev, "%s(%d) mvpp2_cls_mng_set_coloring fail\n", __func__, __LINE__);
      return -EINVAL;
    }

  return 0;
}

static int
mvpp2_cls_c3_hw_del (vnet_dev_t *dev, uintptr_t hif_base, int index)
{
  u32 reg_val = 0;
  int iter = 0;

  if (mv_pp2x_range_validate (dev, index, 0, MVPP2_CLS3_HASH_OP_TBL_ADDR_MAX))
    return -EINVAL;

  reg_val |= (index << MVPP2_CLS3_HASH_OP_TBL_ADDR);
  reg_val |= (1 << MVPP2_CLS3_HASH_OP_DEL);
  reg_val &= ~MVPP2_CLS3_MISS_PTR_MASK; /*set miss bit to 1*/

  /*trigger del operation*/
  mvpp2_reg_write (hif_base, MVPP2_CLS3_HASH_OP_REG, reg_val);

  /* wait to cpu access done bit */
  while (!mvpp2_cls_c3_cpu_done (hif_base))
    if (++iter >= RETRIES_EXCEEDED)
      {
	log_err (dev, "%s:Error - retries exceeded.\n", __func__);
	return -EBUSY;
      }

  /* delete form shadow and extension shadow if exist */
  mvpp2_cls_c3_shadow_clear (index);

  return 0;
}

static int
mvpp2_cls_c3_hw_del_all (vnet_dev_t *dev, uintptr_t hif_base)
{
  int index, status;

  for (index = 0; index < MVPP2_CLS_C3_HASH_TBL_SIZE; index++)
    {
      status = mvpp2_cls_c3_hw_del (dev, hif_base, index);
      if (status != 0)
	return status;
    }
  return 0;
}

static int
mvpp2_cls_c3_reset (vnet_dev_t *dev, mvpp2_device_t *md)
{
  int rc = 0;
  uintptr_t hif_base = md->pp_base;

  log_debug (dev, "reached\n");

  /* clear all C3 HW entries */
  rc = mvpp2_cls_c3_hw_del_all (dev, hif_base);
  if (rc)
    {
      log_err (dev, "fail to delete C3 HW entries\n");
      return rc;
    }
  log_debug (dev, "PP2_CLS C3 HW entries deleted\n");

  /* clear all C3 HW counters */
  rc = mvpp2_cls_c3_hit_cntrs_clear_all (dev, hif_base);
  if (rc)
    {
      log_err (dev, "fail to clear C3 HW counters\n");
      return rc;
    }
  log_debug (dev, "PP2_CLS C3 HW counters cleared\n");

  /* init PP2_CLS C3 HAL */
  rc = mvpp2_cls_c3_init (dev, hif_base);
  if (rc)
    {
      log_err (dev, "fail to init PP2_CLS C3 DB\n");
      return rc;
    }
  log_debug (dev, "PP2_CLS C3 DB initialized\n");

  return 0;
}

static int
mvpp2_cls_c2_reset (mvpp2_device_t *md)
{
  int index;
  uintptr_t hif_base = md->pp_base;

  /* Clear all TCAM entry, except last one added by LSP */
  for (index = MVPP2_C2_FIRST_ENTRY; index < MVPP2_CLS_C2_TCAM_SIZE; index++)
    mv_pp2x_cls_c2_hw_inv (hif_base, index);

  return 0;
}

static vnet_dev_rv_t
mv_pp2x_cls_hw_cls_enable (vnet_dev_t *dev, uintptr_t hif_base, uint32_t en)
{
  if (mv_pp2x_range_validate (dev, en, 0, 1) != VNET_DEV_OK)
    return VNET_DEV_ERR_INVALID_ARG;

  /* Enable classifier */
  mvpp2_reg_write (hif_base, MVPP2_CLS_MODE_REG, en);

  return VNET_DEV_OK;
}

static int
mvpp2_cls_c3_start (vnet_dev_t *dev, mvpp2_device_t *md)
{
  if (mvpp2_cls_c3_reset (dev, md))
    {
      log_err (dev, "PP2_CLS C3 start failed\n");
      return -EIO;
    }
  log_debug (dev, "PP2_CLS C3 started\n");

  return 0;
}

static int
mvpp2_cls_c2_start (vnet_dev_t *dev, mvpp2_device_t *md)
{
  if (mvpp2_cls_c2_reset (md))
    {
      log_err (dev, "MVPP2 C2 start failed\n");
      return -EINVAL;
    }

  return 0;
}

static vnet_dev_rv_t
mvpp2_cls_init (vnet_dev_t *dev, mvpp2_device_t *md)
{
  uintptr_t hif_base = md->pp_base;

  return mv_pp2x_cls_hw_cls_enable (dev, hif_base, true);
}

void
mvpp2_cls_mng_init (vnet_dev_t *dev)
{
  mvpp2_device_t *md = vnet_dev_get_data (dev);

  if (md->classifier_initialized)
    return; /*Already initialized*/

  mvpp2_parser_init (dev);
  mvpp2_cls_init (dev, md);
  mvpp2_cls_c2_start (dev, md);
  mvpp2_cls_c3_start (dev, md);
  md->classifier_initialized = 1;
}

static int
mv_pp2x_cls_c2_queue_high_set (struct mv_pp2x_cls_c2_entry *c2, int cmd, int queue, int from)
{
  if (!c2 || cmd > MVPP2_ACTION_TYPE_UPDT_LOCK || queue >= (1 << MVPP2_CLS2_ACT_QOS_ATTR_QH_BITS))
    return -EINVAL;

  /*set command */
  c2->sram.regs.actions &= ~MVPP2_CLS2_ACT_QH_MASK;
  c2->sram.regs.actions |= (cmd << MVPP2_CLS2_ACT_QH_OFF);

  /*set modify High queue value */
  c2->sram.regs.qos_attr &= ~MVPP2_CLS2_ACT_QOS_ATTR_QH_MASK;
  c2->sram.regs.qos_attr |=
    ((queue << MVPP2_CLS2_ACT_QOS_ATTR_QH_OFF) & MVPP2_CLS2_ACT_QOS_ATTR_QH_MASK);

  if (from == 1)
    c2->sram.regs.action_tbl |= (1 << MVPP2_CLS2_ACT_DATA_TBL_HIGH_Q_OFF);
  else
    c2->sram.regs.action_tbl &= ~(1 << MVPP2_CLS2_ACT_DATA_TBL_HIGH_Q_OFF);

  return 0;
}

static int
mv_pp2x_cls_c2_queue_low_set (struct mv_pp2x_cls_c2_entry *c2, int cmd, int queue, int from)
{
  if (!c2 || cmd > MVPP2_ACTION_TYPE_UPDT_LOCK || queue >= (1 << MVPP2_CLS2_ACT_QOS_ATTR_QL_BITS))
    return -EINVAL;

  /*set command */
  c2->sram.regs.actions &= ~MVPP2_CLS2_ACT_QL_MASK;
  c2->sram.regs.actions |= (cmd << MVPP2_CLS2_ACT_QL_OFF);

  /*set modify Low queue value */
  c2->sram.regs.qos_attr &= ~MVPP2_CLS2_ACT_QOS_ATTR_QL_MASK;
  c2->sram.regs.qos_attr |=
    ((queue << MVPP2_CLS2_ACT_QOS_ATTR_QL_OFF) & MVPP2_CLS2_ACT_QOS_ATTR_QL_MASK);

  if (from == 1)
    c2->sram.regs.action_tbl |= (1 << MVPP2_CLS2_ACT_DATA_TBL_LOW_Q_OFF);
  else
    c2->sram.regs.action_tbl &= ~(1 << MVPP2_CLS2_ACT_DATA_TBL_LOW_Q_OFF);

  return 0;
}

static int
mvpp2_c2_config_queue (struct mv_pp2x_cls_c2_entry *c2, u16 queue, int from)
{
  int q_low, q_high;
  int rc;

  q_high = ((u16) queue) >> MVPP2_CLS2_ACT_QOS_ATTR_QL_BITS;
  q_low = ((u16) queue) & ((1 << MVPP2_CLS2_ACT_QOS_ATTR_QL_BITS) - 1);

  rc = mv_pp2x_cls_c2_queue_low_set (c2, MVPP2_ACTION_TYPE_UPDT_LOCK, q_low, from);
  if (rc)
    return rc;
  rc = mv_pp2x_cls_c2_queue_high_set (c2, MVPP2_ACTION_TYPE_UPDT_LOCK, q_high, from);
  if (rc)
    return rc;

  return 0;
}

static int
mvpp2_c2_config_default_queue (vnet_dev_port_t *port, u16 queue)
{
  vnet_dev_t *dev = port->dev;
  mvpp2_device_t *md = vnet_dev_get_data (port->dev);
  int index;
  int c2_status;
  int rc;
  u8 port_id, lkp_type;
  struct mv_pp2x_cls_c2_entry c2;

  c2_status = mvpp2_reg_read (md->pp_base, MVPP2_CLS2_TCAM_CTRL_REG);
  if (!c2_status)
    {
      log_err (dev, "c2 is off\n");
      return -EINVAL;
    }

  mv_pp2x_c2_sw_clear (&c2);

  for (index = 0; index < MVPP2_CLS_C2_TCAM_SIZE; index++)
    {
      mv_pp2x_cls_c2_hw_read (dev, md->pp_base, index, &c2);
      port_id = mvpp2_cls_c2_tcam_port_get (&c2);
      lkp_type = mvpp2_cls_c2_tcam_lkp_type_get (&c2);

      if (c2.inv != 0 || port_id != (1 << mvpp2_port_id (port)))
	continue;

      if (lkp_type == MVPP2_CLS_LKP_DEFAULT)
	{
	  rc = mvpp2_c2_config_queue (&c2, queue, MVPP2_QOS_SRC_ACTION_TBL);
	  if (rc)
	    return -EFAULT;

	  log_debug (dev, "Writing index %#x, queue %d, from %d\n", index, queue,
		     MVPP2_QOS_SRC_ACTION_TBL);
	  mv_pp2x_cls_c2_hw_write (md->pp_base, index, &c2);
	}
      else if (lkp_type == MVPP2_CLS_LKP_DSCP_PRI || lkp_type == MVPP2_CLS_LKP_VLAN_PRI)
	{
	  rc = mvpp2_c2_config_queue (&c2, queue, MVPP2_QOS_SRC_DSCP_PBIT_TBL);
	  if (rc)
	    return -EFAULT;

	  log_debug (dev, "Writing index %#x, queue %d, from %d\n", index, queue,
		     MVPP2_QOS_SRC_DSCP_PBIT_TBL);
	  mv_pp2x_cls_c2_hw_write (md->pp_base, index, &c2);
	}
    }
  return 0;
}

static vnet_dev_rv_t
mv_pp2x_cls_c2_qos_color_set (vnet_dev_t *dev, struct mv_pp2x_cls_c2_qos_entry *qos, int color)
{
  if (mv_pp2x_ptr_validate (dev, qos) != VNET_DEV_OK)
    return VNET_DEV_ERR_INVALID_ARG;

  qos->data &= ~MVPP2_CLS2_QOS_TBL_COLOR_MASK;
  qos->data |= color << MVPP2_CLS2_QOS_TBL_COLOR_OFF;

  return VNET_DEV_OK;
}

static int
mv_pp2x_cls_c2_qos_hw_write (mvpp2_device_t *md, struct mv_pp2x_cls_c2_qos_entry *qos)
{
  unsigned int reg_val = 0;

  if (!qos || qos->tbl_sel > MVPP2_QOS_TBL_SEL_DSCP)
    return -EINVAL;

  if (qos->tbl_sel == MVPP2_QOS_TBL_SEL_DSCP)
    {
      /*dscp */
      if (qos->tbl_id >= MVPP2_QOS_TBL_NUM_DSCP || qos->tbl_line >= MVPP2_QOS_TBL_LINE_NUM_DSCP)
	return -EINVAL;
    }
  else
    {
      /*pri */
      if (qos->tbl_id >= MVPP2_QOS_TBL_NUM_PRI || qos->tbl_line >= MVPP2_QOS_TBL_LINE_NUM_PRI)
	return -EINVAL;
    }
  /* write index reg */
  reg_val |= (qos->tbl_line << MVPP2_CLS2_DSCP_PRI_INDEX_LINE_OFF);
  reg_val |= (qos->tbl_sel << MVPP2_CLS2_DSCP_PRI_INDEX_SEL_OFF);
  reg_val |= (qos->tbl_id << MVPP2_CLS2_DSCP_PRI_INDEX_TBL_ID_OFF);
  mvpp2_reg_write (md->pp_base, MVPP2_CLS2_DSCP_PRI_INDEX_REG, reg_val);

  /* write data reg */
  mvpp2_reg_write (md->pp_base, MVPP2_CLS2_QOS_TBL_REG, qos->data);

  return 0;
}

static int
mv_pp2x_cls_c2_qos_queue_set (struct mv_pp2x_cls_c2_qos_entry *qos, uint8_t queue)
{
  if (!qos)
    return -EINVAL;

  qos->data &= ~MVPP2_CLS2_QOS_TBL_QUEUENUM_MASK;
  qos->data |= (((uint32_t) queue) << MVPP2_CLS2_QOS_TBL_QUEUENUM_OFF);
  return 0;
}

static int
mv_pp2x_cls_c2_qos_tbl_fill_array (vnet_dev_port_t *port, u8 tbl_sel, uint8_t tc_values[])
{
  vnet_dev_t *dev = port->dev;
  mvpp2_device_t *md = vnet_dev_get_data (port->dev);
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  struct mv_pp2x_cls_c2_qos_entry qos_entry = {};
  u32 pri, line_num;
  u8 queue;
  enum mvpp2_port_color color;
  int rc;

  if (tbl_sel == MVPP2_QOS_TBL_SEL_PRI)
    line_num = MVPP2_QOS_TBL_LINE_NUM_PRI;
  else
    line_num = MVPP2_QOS_TBL_LINE_NUM_DSCP;

  qos_entry.tbl_id = mvpp2_port_id (port);
  qos_entry.tbl_sel = tbl_sel;

  /* Fill the QoS dscp/pbit table */
  for (pri = 0; pri < line_num; pri++)
    {
      qos_entry.tbl_line = pri;
      /* map cos queue to physical queue */
      /* Physical queue contains 2 parts: port ID and CPU ID,
       * CPU ID will be used in RSS
       */
      queue = mp->tc.tc_config.first_rxq;
      color = mp->tc.tc_config.default_color;
      log_debug (dev, "tc_val[%d] %d, queue %d, color %d\n", pri, tc_values[pri], queue,
		 (int) color);

      rc = mv_pp2x_cls_c2_qos_queue_set (&qos_entry, queue);
      if (rc)
	{
	  log_err (dev, "mv_pp2x_cls_c2_qos_queue_set failed\n");
	  return -EFAULT;
	}

      if (mv_pp2x_cls_c2_qos_color_set (dev, &qos_entry, color) != VNET_DEV_OK)
	{
	  log_info (dev, "mv_pp2x_cls_c2_qos_color_set failed\n");
	  return -EFAULT;
	}

      rc = mv_pp2x_cls_c2_qos_hw_write (md, &qos_entry);
      if (rc)
	{
	  log_err (dev, "mv_pp2x_cls_c2_qos_hw_write failed\n");
	  return -EFAULT;
	}
    }
  return 0;
}

static int
mvpp2_cls_mng_qos_tbl_dflt_set (vnet_dev_port_t *port, u16 queue)
{
  vnet_dev_t *dev = port->dev;
  int rc = 0;
  u32 i;
  u8 tc_array[MVPP2_QOS_TBL_LINE_NUM_DSCP];

  for (i = 0; i < MV_DSCP_NUM; i++)
    tc_array[i] = queue;

  rc = mv_pp2x_cls_c2_qos_tbl_fill_array (port, MVPP2_QOS_TBL_SEL_DSCP, tc_array);
  if (rc)
    {
      log_err (dev, "mv_pp2x_cls_c2_qos_tbl_fill_array failed\n");
      return -EINVAL;
    }

  rc = mv_pp2x_cls_c2_qos_tbl_fill_array (port, MVPP2_QOS_TBL_SEL_PRI, tc_array);
  if (rc)
    {
      log_err (dev, "mv_pp2x_cls_c2_qos_tbl_fill_array failed\n");
      return -EINVAL;
    }
  return 0;
}

void
mvpp2_cls_mng_config_default_cos_queue (vnet_dev_port_t *port)
{
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);
  mvpp2_c2_config_default_queue (port, mp->first_rxq);
  mvpp2_cls_mng_qos_tbl_dflt_set (port, mp->first_rxq);
}

void
mvpp2x_cls_oversize_rxq_set (vnet_dev_port_t *port)
{
  mvpp2_port_t *mp = vnet_dev_get_port_data (port);

  mvpp2_reg_write (mp->hif_base, MVPP2_CLS_OVERSIZE_RXQ_LOW_REG (mp->id), mp->first_rxq);
}
