/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vppinfra/format_table.h>
#include <edma_hw.h>
#include <qppe.h>
#include <ppe_hw.h>
#define QPPE_SCHED_MAX_WORDS 9

static const qppe_reg_field_t ppe_reg_sched_tdm_depth_cfg_t_fields[] = {
#define _(n_bits, name)                                                                            \
  {                                                                                                \
    #name,                                                                                         \
    n_bits,                                                                                        \
  },
  foreach_ppe_reg_sched_tdm_depth_cfg_t_fields
#undef _
};

static const qppe_reg_field_t ppe_reg_sched_shp_slot_cfg_l0_t_fields[] = {
#define _(n_bits, name)                                                                            \
  {                                                                                                \
    #name,                                                                                         \
    n_bits,                                                                                        \
  },
  foreach_ppe_reg_sched_shp_slot_cfg_l0_t_fields
#undef _
};

static const qppe_reg_field_t ppe_reg_sched_shp_slot_cfg_l1_t_fields[] = {
#define _(n_bits, name)                                                                            \
  {                                                                                                \
    #name,                                                                                         \
    n_bits,                                                                                        \
  },
  foreach_ppe_reg_sched_shp_slot_cfg_l1_t_fields
#undef _
};

static const qppe_reg_field_t ppe_reg_sched_shp_slot_cfg_port_t_fields[] = {
#define _(n_bits, name)                                                                            \
  {                                                                                                \
    #name,                                                                                         \
    n_bits,                                                                                        \
  },
  foreach_ppe_reg_sched_shp_slot_cfg_port_t_fields
#undef _
};

static const qppe_reg_field_t ppe_reg_sched_ipg_pre_len_cfg_t_fields[] = {
#define _(n_bits, name)                                                                            \
  {                                                                                                \
    #name,                                                                                         \
    n_bits,                                                                                        \
  },
  foreach_ppe_reg_sched_ipg_pre_len_cfg_t_fields
#undef _
};

static const qppe_reg_field_t ppe_reg_sched_min_max_mode_cfg_t_fields[] = {
#define _(n_bits, name)                                                                            \
  {                                                                                                \
    #name,                                                                                         \
    n_bits,                                                                                        \
  },
  foreach_ppe_reg_sched_min_max_mode_cfg_t_fields
#undef _
};

static const qppe_reg_field_t ppe_reg_sched_shp_cfg_l0_t_fields[] = {
#define _(n_bits, name)                                                                            \
  {                                                                                                \
    #name,                                                                                         \
    n_bits,                                                                                        \
  },
  foreach_ppe_reg_sched_shp_cfg_l0_t_fields
#undef _
};

static const qppe_reg_field_t ppe_reg_sched_shp_cfg_l1_t_fields[] = {
#define _(n_bits, name)                                                                            \
  {                                                                                                \
    #name,                                                                                         \
    n_bits,                                                                                        \
  },
  foreach_ppe_reg_sched_shp_cfg_l1_t_fields
#undef _
};
typedef struct
{
  const char *name;
  u32 reg;
  const qppe_reg_field_t *fields;
  uword n_fields;
} qppe_sched_reg_t;

static const qppe_sched_reg_t qppe_sched_config_regs[] = {
  {
    "TDM_DEPTH_CFG",
    HPPE_REG_SCHED_TDM_DEPTH_CFG,
    ppe_reg_sched_tdm_depth_cfg_t_fields,
    ARRAY_LEN (ppe_reg_sched_tdm_depth_cfg_t_fields),
  },
  {
    "SHP_SLOT_CFG_L0",
    HPPE_REG_SCHED_SHP_SLOT_CFG_L0,
    ppe_reg_sched_shp_slot_cfg_l0_t_fields,
    ARRAY_LEN (ppe_reg_sched_shp_slot_cfg_l0_t_fields),
  },
  {
    "SHP_SLOT_CFG_L1",
    HPPE_REG_SCHED_SHP_SLOT_CFG_L1,
    ppe_reg_sched_shp_slot_cfg_l1_t_fields,
    ARRAY_LEN (ppe_reg_sched_shp_slot_cfg_l1_t_fields),
  },
  {
    "SHP_SLOT_CFG_PORT",
    HPPE_REG_SCHED_SHP_SLOT_CFG_PORT,
    ppe_reg_sched_shp_slot_cfg_port_t_fields,
    ARRAY_LEN (ppe_reg_sched_shp_slot_cfg_port_t_fields),
  },
  {
    "IPG_PRE_LEN_CFG",
    HPPE_REG_SCHED_IPG_PRE_LEN_CFG,
    ppe_reg_sched_ipg_pre_len_cfg_t_fields,
    ARRAY_LEN (ppe_reg_sched_ipg_pre_len_cfg_t_fields),
  },
  {
    "MIN_MAX_MODE_CFG",
    APPE_REG_SCHED_MIN_MAX_MODE_CFG,
    ppe_reg_sched_min_max_mode_cfg_t_fields,
    ARRAY_LEN (ppe_reg_sched_min_max_mode_cfg_t_fields),
  },
};

static const qppe_sched_reg_t qppe_sched_status_regs[] = {
  {
    "SHP_CFG_L0",
    APPE_REG_SCHED_SHP_CFG_L0,
    ppe_reg_sched_shp_cfg_l0_t_fields,
    ARRAY_LEN (ppe_reg_sched_shp_cfg_l0_t_fields),
  },
  {
    "SHP_CFG_L1",
    APPE_REG_SCHED_SHP_CFG_L1,
    ppe_reg_sched_shp_cfg_l1_t_fields,
    ARRAY_LEN (ppe_reg_sched_shp_cfg_l1_t_fields),
  },
};

static u8 *
qppe_sched_format_regs (u8 *s, qppe_device_t *qd, const qppe_sched_reg_t *regs, u32 count)
{
  u32 indent = format_get_indent (s);

  for (u32 i = 0; i < count; i++)
    {
      u32 value = qppe_mmio_read32 (qd, regs[i].reg);

      if (i)
	{
	  s = format (s, "\n");
	  s = format_newline (s, indent);
	}
      s = format (s, "%s: 0x%08x", regs[i].name, value);
      s = format_newline (s, indent + 2);
      s = format (s, "%U", format_qppe_reg_fields, value, regs[i].fields, regs[i].n_fields);
    }
  return s;
}

u8 *
format_qppe_sched_cfg (u8 *s, va_list *args)
{
  vnet_dev_t *dev = va_arg (*args, vnet_dev_t *);
  qppe_device_t *qd = vnet_dev_get_data (dev);

  if (!qd->regs)
    return s;
  return qppe_sched_format_regs (s, qd, qppe_sched_config_regs, ARRAY_LEN (qppe_sched_config_regs));
}

typedef enum
{
  QPPE_SCHED_FIELD_NUMBER,
  QPPE_SCHED_FIELD_BITMAP,
  QPPE_SCHED_FIELD_METER_UNIT,
  QPPE_SCHED_FIELD_COMPENSATION,
  QPPE_SCHED_FIELD_QOS_DSCP,
  QPPE_SCHED_FIELD_ENABLED_VALUE,
} qppe_sched_field_format_t;

typedef struct
{
  const char *name;
  const char *subheader;
  u16 offset;
  u16 n_bits;
  qppe_sched_field_format_t format;
} qppe_sched_field_t;

typedef struct
{
  const char *name;
  const char *index_name;
  u32 reg;
  u16 n_entries;
  u16 stride;
  u16 map_size;
  u8 n_words;
  const qppe_sched_field_t *fields;
  uword n_fields;
} qppe_sched_table_t;

static const qppe_sched_field_t qppe_sched_l0_flow_map_tbl_fields[] = {
#define _(name, subheader, offset, n_bits, kind)                                                   \
  {                                                                                                \
    name, subheader, offset, n_bits, kind,                                                         \
  },
  foreach_qppe_sched_l0_flow_map_tbl_fields
#undef _
};
static const qppe_sched_field_t qppe_sched_l0_c_sp_cfg_tbl_fields[] = {
#define _(name, subheader, offset, n_bits, kind)                                                   \
  {                                                                                                \
    name, subheader, offset, n_bits, kind,                                                         \
  },
  foreach_qppe_sched_l0_c_sp_cfg_tbl_fields
#undef _
};
static const qppe_sched_field_t qppe_sched_l0_flow_port_map_tbl_fields[] = {
#define _(name, subheader, offset, n_bits, kind)                                                   \
  {                                                                                                \
    name, subheader, offset, n_bits, kind,                                                         \
  },
  foreach_qppe_sched_l0_flow_port_map_tbl_fields
#undef _
};
static const qppe_sched_field_t qppe_sched_l0_c_drr_head_tbl_fields[] = {
#define _(name, subheader, offset, n_bits, kind)                                                   \
  {                                                                                                \
    name, subheader, offset, n_bits, kind,                                                         \
  },
  foreach_qppe_sched_l0_c_drr_head_tbl_fields
#undef _
};
static const qppe_sched_field_t qppe_sched_l0_drr_credit_tbl_fields[] = {
#define _(name, subheader, offset, n_bits, kind)                                                   \
  {                                                                                                \
    name, subheader, offset, n_bits, kind,                                                         \
  },
  foreach_qppe_sched_l0_drr_credit_tbl_fields
#undef _
};
static const qppe_sched_field_t qppe_sched_l0_c_drr_ll_tbl_fields[] = {
#define _(name, subheader, offset, n_bits, kind)                                                   \
  {                                                                                                \
    name, subheader, offset, n_bits, kind,                                                         \
  },
  foreach_qppe_sched_l0_c_drr_ll_tbl_fields
#undef _
};
static const qppe_sched_field_t qppe_sched_l0_c_drr_reverse_ll_tbl_fields[] = {
#define _(name, subheader, offset, n_bits, kind)                                                   \
  {                                                                                                \
    name, subheader, offset, n_bits, kind,                                                         \
  },
  foreach_qppe_sched_l0_c_drr_reverse_ll_tbl_fields
#undef _
};
static const qppe_sched_field_t qppe_sched_l0_sp_entry_tbl_fields[] = {
#define _(name, subheader, offset, n_bits, kind)                                                   \
  {                                                                                                \
    name, subheader, offset, n_bits, kind,                                                         \
  },
  foreach_qppe_sched_l0_sp_entry_tbl_fields
#undef _
};
static const qppe_sched_field_t qppe_sched_l0_ens_q_head_tbl_fields[] = {
#define _(name, subheader, offset, n_bits, kind)                                                   \
  {                                                                                                \
    name, subheader, offset, n_bits, kind,                                                         \
  },
  foreach_qppe_sched_l0_ens_q_head_tbl_fields
#undef _
};
static const qppe_sched_field_t qppe_sched_l0_ens_q_entry_tbl_fields[] = {
#define _(name, subheader, offset, n_bits, kind)                                                   \
  {                                                                                                \
    name, subheader, offset, n_bits, kind,                                                         \
  },
  foreach_qppe_sched_l0_ens_q_entry_tbl_fields
#undef _
};
static const qppe_sched_field_t qppe_sched_l0_flow_status_tbl_fields[] = {
#define _(name, subheader, offset, n_bits, kind)                                                   \
  {                                                                                                \
    name, subheader, offset, n_bits, kind,                                                         \
  },
  foreach_qppe_sched_l0_flow_status_tbl_fields
#undef _
};
static const qppe_sched_field_t qppe_sched_rfc_block_tbl_fields[] = {
#define _(name, subheader, offset, n_bits, kind)                                                   \
  {                                                                                                \
    name, subheader, offset, n_bits, kind,                                                         \
  },
  foreach_qppe_sched_rfc_block_tbl_fields
#undef _
};
static const qppe_sched_field_t qppe_sched_rfc_status_tbl_fields[] = {
#define _(name, subheader, offset, n_bits, kind)                                                   \
  {                                                                                                \
    name, subheader, offset, n_bits, kind,                                                         \
  },
  foreach_qppe_sched_rfc_status_tbl_fields
#undef _
};
static const qppe_sched_field_t qppe_sched_deq_dis_tbl_fields[] = {
#define _(name, subheader, offset, n_bits, kind)                                                   \
  {                                                                                                \
    name, subheader, offset, n_bits, kind,                                                         \
  },
  foreach_qppe_sched_deq_dis_tbl_fields
#undef _
};

static const qppe_sched_field_t qppe_sched_l1_flow_map_tbl_fields[] = {
#define _(name, subheader, offset, n_bits, kind)                                                   \
  {                                                                                                \
    name, subheader, offset, n_bits, kind,                                                         \
  },
  foreach_qppe_sched_l1_flow_map_tbl_fields
#undef _
};
static const qppe_sched_field_t qppe_sched_l1_c_sp_cfg_tbl_fields[] = {
#define _(name, subheader, offset, n_bits, kind)                                                   \
  {                                                                                                \
    name, subheader, offset, n_bits, kind,                                                         \
  },
  foreach_qppe_sched_l1_c_sp_cfg_tbl_fields
#undef _
};
static const qppe_sched_field_t qppe_sched_l1_c_drr_head_tbl_fields[] = {
#define _(name, subheader, offset, n_bits, kind)                                                   \
  {                                                                                                \
    name, subheader, offset, n_bits, kind,                                                         \
  },
  foreach_qppe_sched_l1_c_drr_head_tbl_fields
#undef _
};
static const qppe_sched_field_t qppe_sched_l1_c_drr_ll_tbl_fields[] = {
#define _(name, subheader, offset, n_bits, kind)                                                   \
  {                                                                                                \
    name, subheader, offset, n_bits, kind,                                                         \
  },
  foreach_qppe_sched_l1_c_drr_ll_tbl_fields
#undef _
};
static const qppe_sched_field_t qppe_sched_l1_c_drr_reverse_ll_tbl_fields[] = {
#define _(name, subheader, offset, n_bits, kind)                                                   \
  {                                                                                                \
    name, subheader, offset, n_bits, kind,                                                         \
  },
  foreach_qppe_sched_l1_c_drr_reverse_ll_tbl_fields
#undef _
};
static const qppe_sched_field_t qppe_sched_l1_a_flow_entry_tbl_fields[] = {
#define _(name, subheader, offset, n_bits, kind)                                                   \
  {                                                                                                \
    name, subheader, offset, n_bits, kind,                                                         \
  },
  foreach_qppe_sched_l1_a_flow_entry_tbl_fields
#undef _
};
static const qppe_sched_field_t qppe_sched_l1_sp_entry_tbl_fields[] = {
#define _(name, subheader, offset, n_bits, kind)                                                   \
  {                                                                                                \
    name, subheader, offset, n_bits, kind,                                                         \
  },
  foreach_qppe_sched_l1_sp_entry_tbl_fields
#undef _
};
static const qppe_sched_field_t qppe_sched_l1_ens_q_head_tbl_fields[] = {
#define _(name, subheader, offset, n_bits, kind)                                                   \
  {                                                                                                \
    name, subheader, offset, n_bits, kind,                                                         \
  },
  foreach_qppe_sched_l1_ens_q_head_tbl_fields
#undef _
};
static const qppe_sched_field_t qppe_sched_psch_tdm_cfg_tbl_fields[] = {
#define _(name, subheader, offset, n_bits, kind)                                                   \
  {                                                                                                \
    name, subheader, offset, n_bits, kind,                                                         \
  },
  foreach_qppe_sched_psch_tdm_cfg_tbl_fields
#undef _
};
static const qppe_sched_field_t qppe_sched_l0_shp_credit_tbl_fields[] = {
#define _(name, subheader, offset, n_bits, kind)                                                   \
  {                                                                                                \
    name, subheader, offset, n_bits, kind,                                                         \
  },
  foreach_qppe_sched_l0_shp_credit_tbl_fields
#undef _
};
static const qppe_sched_field_t qppe_sched_l0_shp_cfg_tbl_fields[] = {
#define _(name, subheader, offset, n_bits, kind)                                                   \
  {                                                                                                \
    name, subheader, offset, n_bits, kind,                                                         \
  },
  foreach_qppe_sched_l0_shp_cfg_tbl_fields
#undef _
};
static const qppe_sched_field_t qppe_sched_l0_comp_tbl_fields[] = {
#define _(name, subheader, offset, n_bits, kind)                                                   \
  {                                                                                                \
    name, subheader, offset, n_bits, kind,                                                         \
  },
  foreach_qppe_sched_l0_comp_tbl_fields
#undef _
};
static const qppe_sched_field_t qppe_sched_l0_comp_cfg_tbl_fields[] = {
#define _(name, subheader, offset, n_bits, kind)                                                   \
  {                                                                                                \
    name, subheader, offset, n_bits, kind,                                                         \
  },
  foreach_qppe_sched_l0_comp_cfg_tbl_fields
#undef _
};
static const qppe_sched_field_t qppe_sched_l1_shp_cfg_tbl_fields[] = {
#define _(name, subheader, offset, n_bits, kind)                                                   \
  {                                                                                                \
    name, subheader, offset, n_bits, kind,                                                         \
  },
  foreach_qppe_sched_l1_shp_cfg_tbl_fields
#undef _
};
static const qppe_sched_field_t qppe_sched_psch_shp_sign_tbl_fields[] = {
#define _(name, subheader, offset, n_bits, kind)                                                   \
  {                                                                                                \
    name, subheader, offset, n_bits, kind,                                                         \
  },
  foreach_qppe_sched_psch_shp_sign_tbl_fields
#undef _
};
static const qppe_sched_field_t qppe_sched_psch_shp_credit_tbl_fields[] = {
#define _(name, subheader, offset, n_bits, kind)                                                   \
  {                                                                                                \
    name, subheader, offset, n_bits, kind,                                                         \
  },
  foreach_qppe_sched_psch_shp_credit_tbl_fields
#undef _
};
static const qppe_sched_field_t qppe_sched_psch_shp_cfg_tbl_fields[] = {
#define _(name, subheader, offset, n_bits, kind)                                                   \
  {                                                                                                \
    name, subheader, offset, n_bits, kind,                                                         \
  },
  foreach_qppe_sched_psch_shp_cfg_tbl_fields
#undef _
};
static const qppe_sched_field_t qppe_sched_psch_comp_tbl_fields[] = {
#define _(name, subheader, offset, n_bits, kind)                                                   \
  {                                                                                                \
    name, subheader, offset, n_bits, kind,                                                         \
  },
  foreach_qppe_sched_psch_comp_tbl_fields
#undef _
};
static const qppe_sched_field_t qppe_sched_psch_comp_cfg_tbl_fields[] = {
#define _(name, subheader, offset, n_bits, kind)                                                   \
  {                                                                                                \
    name, subheader, offset, n_bits, kind,                                                         \
  },
  foreach_qppe_sched_psch_comp_cfg_tbl_fields
#undef _
};
static const qppe_sched_field_t qppe_sched_qos_mapping_tbl_fields[] = {
#define _(name, subheader, offset, n_bits, kind)                                                   \
  {                                                                                                \
    name, subheader, offset, n_bits, kind,                                                         \
  },
  foreach_qppe_sched_qos_mapping_tbl_fields
#undef _
};
static const qppe_sched_table_t qppe_sched_tables[] = {
  {
    "L0_FLOW_MAP_TBL",
    "queue",
    HPPE_REG_SCHED_L0_FLOW_MAP_TBL,
    HPPE_SCHED_L0_FLOW_MAP_TBL_COUNT,
    HPPE_SCHED_L0_FLOW_MAP_TBL_STRIDE,
    0,
    HPPE_SCHED_L0_FLOW_MAP_TBL_WORDS,
    qppe_sched_l0_flow_map_tbl_fields,
    ARRAY_LEN (qppe_sched_l0_flow_map_tbl_fields),
  },
  {
    "L0_C_SP_CFG_TBL",
    "index",
    HPPE_REG_SCHED_L0_C_SP_CFG_TBL,
    HPPE_SCHED_L0_C_SP_CFG_TBL_COUNT,
    HPPE_SCHED_L0_C_SP_CFG_TBL_STRIDE,
    0,
    HPPE_SCHED_L0_C_SP_CFG_TBL_WORDS,
    qppe_sched_l0_c_sp_cfg_tbl_fields,
    ARRAY_LEN (qppe_sched_l0_c_sp_cfg_tbl_fields),
  },
  {
    "L0_E_SP_CFG_TBL",
    "index",
    HPPE_REG_SCHED_L0_E_SP_CFG_TBL,
    HPPE_SCHED_L0_E_SP_CFG_TBL_COUNT,
    HPPE_SCHED_L0_E_SP_CFG_TBL_STRIDE,
    0,
    HPPE_SCHED_L0_E_SP_CFG_TBL_WORDS,
    qppe_sched_l0_c_sp_cfg_tbl_fields,
    ARRAY_LEN (qppe_sched_l0_c_sp_cfg_tbl_fields),
  },
  {
    "L0_FLOW_PORT_MAP_TBL",
    "queue",
    HPPE_REG_SCHED_L0_FLOW_PORT_MAP_TBL,
    HPPE_SCHED_L0_FLOW_PORT_MAP_TBL_COUNT,
    HPPE_SCHED_L0_FLOW_PORT_MAP_TBL_STRIDE,
    0,
    HPPE_SCHED_L0_FLOW_PORT_MAP_TBL_WORDS,
    qppe_sched_l0_flow_port_map_tbl_fields,
    ARRAY_LEN (qppe_sched_l0_flow_port_map_tbl_fields),
  },
  {
    "L0_FLOW_STATUS_TBL",
    "queue",
    HPPE_REG_SCHED_L0_FLOW_STATUS_TBL,
    HPPE_SCHED_L0_FLOW_STATUS_TBL_COUNT,
    HPPE_SCHED_L0_FLOW_STATUS_TBL_STRIDE,
    0,
    HPPE_SCHED_L0_FLOW_STATUS_TBL_WORDS,
    qppe_sched_l0_flow_status_tbl_fields,
    ARRAY_LEN (qppe_sched_l0_flow_status_tbl_fields),
  },
  {
    "RFC_BLOCK_TBL",
    "queue",
    HPPE_REG_SCHED_RFC_BLOCK_TBL,
    HPPE_SCHED_RFC_BLOCK_TBL_COUNT,
    HPPE_SCHED_RFC_BLOCK_TBL_STRIDE,
    0,
    HPPE_SCHED_RFC_BLOCK_TBL_WORDS,
    qppe_sched_rfc_block_tbl_fields,
    ARRAY_LEN (qppe_sched_rfc_block_tbl_fields),
  },
  {
    "RFC_STATUS_TBL",
    "queue",
    HPPE_REG_SCHED_RFC_STATUS_TBL,
    HPPE_SCHED_RFC_STATUS_TBL_COUNT,
    HPPE_SCHED_RFC_STATUS_TBL_STRIDE,
    0,
    HPPE_SCHED_RFC_STATUS_TBL_WORDS,
    qppe_sched_rfc_status_tbl_fields,
    ARRAY_LEN (qppe_sched_rfc_status_tbl_fields),
  },
  {
    "DEQ_DIS_TBL",
    "queue",
    HPPE_REG_SCHED_DEQ_DIS_TBL,
    HPPE_SCHED_DEQ_DIS_TBL_COUNT,
    HPPE_SCHED_DEQ_DIS_TBL_STRIDE,
    0,
    HPPE_SCHED_DEQ_DIS_TBL_WORDS,
    qppe_sched_deq_dis_tbl_fields,
    ARRAY_LEN (qppe_sched_deq_dis_tbl_fields),
  },
  {
    "L1_FLOW_MAP_TBL",
    "index",
    HPPE_REG_SCHED_L1_FLOW_MAP_TBL,
    HPPE_SCHED_L1_FLOW_MAP_TBL_COUNT,
    HPPE_SCHED_L1_FLOW_MAP_TBL_STRIDE,
    0,
    HPPE_SCHED_L1_FLOW_MAP_TBL_WORDS,
    qppe_sched_l1_flow_map_tbl_fields,
    ARRAY_LEN (qppe_sched_l1_flow_map_tbl_fields),
  },
  {
    "L1_C_SP_CFG_TBL",
    "index",
    HPPE_REG_SCHED_L1_C_SP_CFG_TBL,
    HPPE_SCHED_L1_C_SP_CFG_TBL_COUNT,
    HPPE_SCHED_L1_C_SP_CFG_TBL_STRIDE,
    0,
    HPPE_SCHED_L1_C_SP_CFG_TBL_WORDS,
    qppe_sched_l1_c_sp_cfg_tbl_fields,
    ARRAY_LEN (qppe_sched_l1_c_sp_cfg_tbl_fields),
  },
  {
    "L1_E_SP_CFG_TBL",
    "index",
    HPPE_REG_SCHED_L1_E_SP_CFG_TBL,
    HPPE_SCHED_L1_E_SP_CFG_TBL_COUNT,
    HPPE_SCHED_L1_E_SP_CFG_TBL_STRIDE,
    0,
    HPPE_SCHED_L1_E_SP_CFG_TBL_WORDS,
    qppe_sched_l1_c_sp_cfg_tbl_fields,
    ARRAY_LEN (qppe_sched_l1_c_sp_cfg_tbl_fields),
  },
  {
    "L1_FLOW_PORT_MAP_TBL",
    "index",
    HPPE_REG_SCHED_L1_FLOW_PORT_MAP_TBL,
    HPPE_SCHED_L1_FLOW_PORT_MAP_TBL_COUNT,
    HPPE_SCHED_L1_FLOW_PORT_MAP_TBL_STRIDE,
    0,
    HPPE_SCHED_L1_FLOW_PORT_MAP_TBL_WORDS,
    qppe_sched_l0_flow_port_map_tbl_fields,
    ARRAY_LEN (qppe_sched_l0_flow_port_map_tbl_fields),
  },
  {
    "L1_FLOW_STATUS_TBL",
    "index",
    HPPE_REG_SCHED_L1_FLOW_STATUS_TBL,
    HPPE_SCHED_L1_FLOW_STATUS_TBL_COUNT,
    HPPE_SCHED_L1_FLOW_STATUS_TBL_STRIDE,
    0,
    HPPE_SCHED_L1_FLOW_STATUS_TBL_WORDS,
    qppe_sched_l0_flow_status_tbl_fields,
    ARRAY_LEN (qppe_sched_l0_flow_status_tbl_fields),
  },
  {
    "PSCH_TDM_CFG_TBL",
    "index",
    HPPE_REG_SCHED_PSCH_TDM_CFG_TBL,
    HPPE_SCHED_PSCH_TDM_CFG_TBL_COUNT,
    HPPE_SCHED_PSCH_TDM_CFG_TBL_STRIDE,
    0,
    HPPE_SCHED_PSCH_TDM_CFG_TBL_WORDS,
    qppe_sched_psch_tdm_cfg_tbl_fields,
    ARRAY_LEN (qppe_sched_psch_tdm_cfg_tbl_fields),
  },
  {
    "L0_SHP_CFG_TBL",
    "queue",
    HPPE_REG_SCHED_L0_SHP_CFG_TBL,
    HPPE_SCHED_L0_SHP_CFG_TBL_COUNT,
    HPPE_SCHED_L0_SHP_CFG_TBL_STRIDE,
    0,
    HPPE_SCHED_L0_SHP_CFG_TBL_WORDS,
    qppe_sched_l0_shp_cfg_tbl_fields,
    ARRAY_LEN (qppe_sched_l0_shp_cfg_tbl_fields),
  },
  {
    "L0_COMP_CFG_TBL",
    "queue",
    HPPE_REG_SCHED_L0_COMP_CFG_TBL,
    HPPE_SCHED_L0_COMP_CFG_TBL_COUNT,
    HPPE_SCHED_L0_COMP_CFG_TBL_STRIDE,
    0,
    HPPE_SCHED_L0_COMP_CFG_TBL_WORDS,
    qppe_sched_l0_comp_cfg_tbl_fields,
    ARRAY_LEN (qppe_sched_l0_comp_cfg_tbl_fields),
  },
  {
    "L1_SHP_CFG_TBL",
    "index",
    HPPE_REG_SCHED_L1_SHP_CFG_TBL,
    HPPE_SCHED_L1_SHP_CFG_TBL_COUNT,
    HPPE_SCHED_L1_SHP_CFG_TBL_STRIDE,
    0,
    HPPE_SCHED_L1_SHP_CFG_TBL_WORDS,
    qppe_sched_l1_shp_cfg_tbl_fields,
    ARRAY_LEN (qppe_sched_l1_shp_cfg_tbl_fields),
  },
  {
    "L1_COMP_CFG_TBL",
    "index",
    HPPE_REG_SCHED_L1_COMP_CFG_TBL,
    HPPE_SCHED_L1_COMP_CFG_TBL_COUNT,
    HPPE_SCHED_L1_COMP_CFG_TBL_STRIDE,
    0,
    HPPE_SCHED_L1_COMP_CFG_TBL_WORDS,
    qppe_sched_l0_comp_cfg_tbl_fields,
    ARRAY_LEN (qppe_sched_l0_comp_cfg_tbl_fields),
  },
  {
    "PSCH_SHP_CFG_TBL",
    "port",
    HPPE_REG_SCHED_PSCH_SHP_CFG_TBL,
    HPPE_SCHED_PSCH_SHP_CFG_TBL_COUNT,
    HPPE_SCHED_PSCH_SHP_CFG_TBL_STRIDE,
    0,
    HPPE_SCHED_PSCH_SHP_CFG_TBL_WORDS,
    qppe_sched_psch_shp_cfg_tbl_fields,
    ARRAY_LEN (qppe_sched_psch_shp_cfg_tbl_fields),
  },
  {
    "PSCH_COMP_CFG_TBL",
    "port",
    HPPE_REG_SCHED_PSCH_COMP_CFG_TBL,
    HPPE_SCHED_PSCH_COMP_CFG_TBL_COUNT,
    HPPE_SCHED_PSCH_COMP_CFG_TBL_STRIDE,
    0,
    HPPE_SCHED_PSCH_COMP_CFG_TBL_WORDS,
    qppe_sched_psch_comp_cfg_tbl_fields,
    ARRAY_LEN (qppe_sched_psch_comp_cfg_tbl_fields),
  },
  {
    "QOS_MAPPING_TBL (flow)",
    "flow",
    APPE_REG_SCHED_QOS_MAPPING_TBL_FLOW,
    APPE_SCHED_QOS_MAPPING_TBL_FLOW_COUNT,
    APPE_SCHED_QOS_MAPPING_TBL_FLOW_STRIDE,
    0,
    APPE_SCHED_QOS_MAPPING_TBL_FLOW_WORDS,
    qppe_sched_qos_mapping_tbl_fields,
    ARRAY_LEN (qppe_sched_qos_mapping_tbl_fields),
  },
  {
    "QOS_MAPPING_TBL (DSCP_TC)",
    "DSCP/TC",
    APPE_REG_SCHED_QOS_MAPPING_TBL_DSCP_TC,
    APPE_SCHED_QOS_MAPPING_TBL_DSCP_TC_COUNT,
    APPE_SCHED_QOS_MAPPING_TBL_DSCP_TC_STRIDE,
    APPE_SCHED_QOS_MAPPING_TBL_DSCP_TC_MAP_SIZE,
    APPE_SCHED_QOS_MAPPING_TBL_DSCP_TC_WORDS,
    qppe_sched_qos_mapping_tbl_fields,
    ARRAY_LEN (qppe_sched_qos_mapping_tbl_fields),
  },
  {
    "QOS_MAPPING_TBL (PCP_DEI)",
    "PCP/DEI",
    APPE_REG_SCHED_QOS_MAPPING_TBL_PCP_DEI,
    APPE_SCHED_QOS_MAPPING_TBL_PCP_DEI_COUNT,
    APPE_SCHED_QOS_MAPPING_TBL_PCP_DEI_STRIDE,
    APPE_SCHED_QOS_MAPPING_TBL_PCP_DEI_MAP_SIZE,
    APPE_SCHED_QOS_MAPPING_TBL_PCP_DEI_WORDS,
    qppe_sched_qos_mapping_tbl_fields,
    ARRAY_LEN (qppe_sched_qos_mapping_tbl_fields),
  },
};

static const qppe_sched_table_t qppe_sched_memory_tables[] = {
  {
    "L0_C_DRR_HEAD_TBL",
    "index",
    HPPE_REG_SCHED_L0_C_DRR_HEAD_TBL,
    HPPE_SCHED_L0_C_DRR_HEAD_TBL_COUNT,
    HPPE_SCHED_L0_C_DRR_HEAD_TBL_STRIDE,
    0,
    HPPE_SCHED_L0_C_DRR_HEAD_TBL_WORDS,
    qppe_sched_l0_c_drr_head_tbl_fields,
    ARRAY_LEN (qppe_sched_l0_c_drr_head_tbl_fields),
  },
  {
    "L0_E_DRR_HEAD_TBL",
    "index",
    HPPE_REG_SCHED_L0_E_DRR_HEAD_TBL,
    HPPE_SCHED_L0_E_DRR_HEAD_TBL_COUNT,
    HPPE_SCHED_L0_E_DRR_HEAD_TBL_STRIDE,
    0,
    HPPE_SCHED_L0_E_DRR_HEAD_TBL_WORDS,
    qppe_sched_l0_c_drr_head_tbl_fields,
    ARRAY_LEN (qppe_sched_l0_c_drr_head_tbl_fields),
  },
  {
    "L0_DRR_CREDIT_TBL",
    "queue",
    HPPE_REG_SCHED_L0_DRR_CREDIT_TBL,
    HPPE_SCHED_L0_DRR_CREDIT_TBL_COUNT,
    HPPE_SCHED_L0_DRR_CREDIT_TBL_STRIDE,
    0,
    HPPE_SCHED_L0_DRR_CREDIT_TBL_WORDS,
    qppe_sched_l0_drr_credit_tbl_fields,
    ARRAY_LEN (qppe_sched_l0_drr_credit_tbl_fields),
  },
  {
    "L0_C_DRR_LL_TBL",
    "queue",
    HPPE_REG_SCHED_L0_C_DRR_LL_TBL,
    HPPE_SCHED_L0_C_DRR_LL_TBL_COUNT,
    HPPE_SCHED_L0_C_DRR_LL_TBL_STRIDE,
    0,
    HPPE_SCHED_L0_C_DRR_LL_TBL_WORDS,
    qppe_sched_l0_c_drr_ll_tbl_fields,
    ARRAY_LEN (qppe_sched_l0_c_drr_ll_tbl_fields),
  },
  {
    "L0_C_DRR_REVERSE_LL_TBL",
    "queue",
    HPPE_REG_SCHED_L0_C_DRR_REVERSE_LL_TBL,
    HPPE_SCHED_L0_C_DRR_REVERSE_LL_TBL_COUNT,
    HPPE_SCHED_L0_C_DRR_REVERSE_LL_TBL_STRIDE,
    0,
    HPPE_SCHED_L0_C_DRR_REVERSE_LL_TBL_WORDS,
    qppe_sched_l0_c_drr_reverse_ll_tbl_fields,
    ARRAY_LEN (qppe_sched_l0_c_drr_reverse_ll_tbl_fields),
  },
  {
    "L0_E_DRR_LL_TBL",
    "queue",
    HPPE_REG_SCHED_L0_E_DRR_LL_TBL,
    HPPE_SCHED_L0_E_DRR_LL_TBL_COUNT,
    HPPE_SCHED_L0_E_DRR_LL_TBL_STRIDE,
    0,
    HPPE_SCHED_L0_E_DRR_LL_TBL_WORDS,
    qppe_sched_l0_c_drr_ll_tbl_fields,
    ARRAY_LEN (qppe_sched_l0_c_drr_ll_tbl_fields),
  },
  {
    "L0_E_DRR_REVERSE_LL_TBL",
    "queue",
    HPPE_REG_SCHED_L0_E_DRR_REVERSE_LL_TBL,
    HPPE_SCHED_L0_E_DRR_REVERSE_LL_TBL_COUNT,
    HPPE_SCHED_L0_E_DRR_REVERSE_LL_TBL_STRIDE,
    0,
    HPPE_SCHED_L0_E_DRR_REVERSE_LL_TBL_WORDS,
    qppe_sched_l0_c_drr_reverse_ll_tbl_fields,
    ARRAY_LEN (qppe_sched_l0_c_drr_reverse_ll_tbl_fields),
  },
  {
    "L0_SP_ENTRY_TBL",
    "index",
    HPPE_REG_SCHED_L0_SP_ENTRY_TBL,
    HPPE_SCHED_L0_SP_ENTRY_TBL_COUNT,
    HPPE_SCHED_L0_SP_ENTRY_TBL_STRIDE,
    0,
    HPPE_SCHED_L0_SP_ENTRY_TBL_WORDS,
    qppe_sched_l0_sp_entry_tbl_fields,
    ARRAY_LEN (qppe_sched_l0_sp_entry_tbl_fields),
  },
  {
    "L0_ENS_Q_LL_TBL",
    "queue",
    HPPE_REG_SCHED_L0_ENS_Q_LL_TBL,
    HPPE_SCHED_L0_ENS_Q_LL_TBL_COUNT,
    HPPE_SCHED_L0_ENS_Q_LL_TBL_STRIDE,
    0,
    HPPE_SCHED_L0_ENS_Q_LL_TBL_WORDS,
    qppe_sched_l0_c_drr_ll_tbl_fields,
    ARRAY_LEN (qppe_sched_l0_c_drr_ll_tbl_fields),
  },
  {
    "L0_ENS_Q_HEAD_TBL",
    "index",
    HPPE_REG_SCHED_L0_ENS_Q_HEAD_TBL,
    HPPE_SCHED_L0_ENS_Q_HEAD_TBL_COUNT,
    HPPE_SCHED_L0_ENS_Q_HEAD_TBL_STRIDE,
    0,
    HPPE_SCHED_L0_ENS_Q_HEAD_TBL_WORDS,
    qppe_sched_l0_ens_q_head_tbl_fields,
    ARRAY_LEN (qppe_sched_l0_ens_q_head_tbl_fields),
  },
  {
    "L0_ENS_Q_ENTRY_TBL",
    "queue",
    HPPE_REG_SCHED_L0_ENS_Q_ENTRY_TBL,
    HPPE_SCHED_L0_ENS_Q_ENTRY_TBL_COUNT,
    HPPE_SCHED_L0_ENS_Q_ENTRY_TBL_STRIDE,
    0,
    HPPE_SCHED_L0_ENS_Q_ENTRY_TBL_WORDS,
    qppe_sched_l0_ens_q_entry_tbl_fields,
    ARRAY_LEN (qppe_sched_l0_ens_q_entry_tbl_fields),
  },
  {
    "L1_C_DRR_HEAD_TBL",
    "index",
    HPPE_REG_SCHED_L1_C_DRR_HEAD_TBL,
    HPPE_SCHED_L1_C_DRR_HEAD_TBL_COUNT,
    HPPE_SCHED_L1_C_DRR_HEAD_TBL_STRIDE,
    0,
    HPPE_SCHED_L1_C_DRR_HEAD_TBL_WORDS,
    qppe_sched_l1_c_drr_head_tbl_fields,
    ARRAY_LEN (qppe_sched_l1_c_drr_head_tbl_fields),
  },
  {
    "L1_E_DRR_HEAD_TBL",
    "index",
    HPPE_REG_SCHED_L1_E_DRR_HEAD_TBL,
    HPPE_SCHED_L1_E_DRR_HEAD_TBL_COUNT,
    HPPE_SCHED_L1_E_DRR_HEAD_TBL_STRIDE,
    0,
    HPPE_SCHED_L1_E_DRR_HEAD_TBL_WORDS,
    qppe_sched_l1_c_drr_head_tbl_fields,
    ARRAY_LEN (qppe_sched_l1_c_drr_head_tbl_fields),
  },
  {
    "L1_DRR_CREDIT_TBL",
    "index",
    HPPE_REG_SCHED_L1_DRR_CREDIT_TBL,
    HPPE_SCHED_L1_DRR_CREDIT_TBL_COUNT,
    HPPE_SCHED_L1_DRR_CREDIT_TBL_STRIDE,
    0,
    HPPE_SCHED_L1_DRR_CREDIT_TBL_WORDS,
    qppe_sched_l0_drr_credit_tbl_fields,
    ARRAY_LEN (qppe_sched_l0_drr_credit_tbl_fields),
  },
  {
    "L1_C_DRR_LL_TBL",
    "index",
    HPPE_REG_SCHED_L1_C_DRR_LL_TBL,
    HPPE_SCHED_L1_C_DRR_LL_TBL_COUNT,
    HPPE_SCHED_L1_C_DRR_LL_TBL_STRIDE,
    0,
    HPPE_SCHED_L1_C_DRR_LL_TBL_WORDS,
    qppe_sched_l1_c_drr_ll_tbl_fields,
    ARRAY_LEN (qppe_sched_l1_c_drr_ll_tbl_fields),
  },
  {
    "L1_C_DRR_REVERSE_LL_TBL",
    "index",
    HPPE_REG_SCHED_L1_C_DRR_REVERSE_LL_TBL,
    HPPE_SCHED_L1_C_DRR_REVERSE_LL_TBL_COUNT,
    HPPE_SCHED_L1_C_DRR_REVERSE_LL_TBL_STRIDE,
    0,
    HPPE_SCHED_L1_C_DRR_REVERSE_LL_TBL_WORDS,
    qppe_sched_l1_c_drr_reverse_ll_tbl_fields,
    ARRAY_LEN (qppe_sched_l1_c_drr_reverse_ll_tbl_fields),
  },
  {
    "L1_E_DRR_LL_TBL",
    "index",
    HPPE_REG_SCHED_L1_E_DRR_LL_TBL,
    HPPE_SCHED_L1_E_DRR_LL_TBL_COUNT,
    HPPE_SCHED_L1_E_DRR_LL_TBL_STRIDE,
    0,
    HPPE_SCHED_L1_E_DRR_LL_TBL_WORDS,
    qppe_sched_l1_c_drr_ll_tbl_fields,
    ARRAY_LEN (qppe_sched_l1_c_drr_ll_tbl_fields),
  },
  {
    "L1_E_DRR_REVERSE_LL_TBL",
    "index",
    HPPE_REG_SCHED_L1_E_DRR_REVERSE_LL_TBL,
    HPPE_SCHED_L1_E_DRR_REVERSE_LL_TBL_COUNT,
    HPPE_SCHED_L1_E_DRR_REVERSE_LL_TBL_STRIDE,
    0,
    HPPE_SCHED_L1_E_DRR_REVERSE_LL_TBL_WORDS,
    qppe_sched_l1_c_drr_reverse_ll_tbl_fields,
    ARRAY_LEN (qppe_sched_l1_c_drr_reverse_ll_tbl_fields),
  },
  {
    "L1_A_FLOW_ENTRY_TBL",
    "index",
    HPPE_REG_SCHED_L1_A_FLOW_ENTRY_TBL,
    HPPE_SCHED_L1_A_FLOW_ENTRY_TBL_COUNT,
    HPPE_SCHED_L1_A_FLOW_ENTRY_TBL_STRIDE,
    0,
    HPPE_SCHED_L1_A_FLOW_ENTRY_TBL_WORDS,
    qppe_sched_l1_a_flow_entry_tbl_fields,
    ARRAY_LEN (qppe_sched_l1_a_flow_entry_tbl_fields),
  },
  {
    "L1_B_FLOW_ENTRY_TBL",
    "index",
    HPPE_REG_SCHED_L1_B_FLOW_ENTRY_TBL,
    HPPE_SCHED_L1_B_FLOW_ENTRY_TBL_COUNT,
    HPPE_SCHED_L1_B_FLOW_ENTRY_TBL_STRIDE,
    0,
    HPPE_SCHED_L1_B_FLOW_ENTRY_TBL_WORDS,
    qppe_sched_l1_a_flow_entry_tbl_fields,
    ARRAY_LEN (qppe_sched_l1_a_flow_entry_tbl_fields),
  },
  {
    "L1_SP_ENTRY_TBL",
    "index",
    HPPE_REG_SCHED_L1_SP_ENTRY_TBL,
    HPPE_SCHED_L1_SP_ENTRY_TBL_COUNT,
    HPPE_SCHED_L1_SP_ENTRY_TBL_STRIDE,
    0,
    HPPE_SCHED_L1_SP_ENTRY_TBL_WORDS,
    qppe_sched_l1_sp_entry_tbl_fields,
    ARRAY_LEN (qppe_sched_l1_sp_entry_tbl_fields),
  },
  {
    "L1_ENS_Q_LL_TBL",
    "index",
    HPPE_REG_SCHED_L1_ENS_Q_LL_TBL,
    HPPE_SCHED_L1_ENS_Q_LL_TBL_COUNT,
    HPPE_SCHED_L1_ENS_Q_LL_TBL_STRIDE,
    0,
    HPPE_SCHED_L1_ENS_Q_LL_TBL_WORDS,
    qppe_sched_l1_c_drr_ll_tbl_fields,
    ARRAY_LEN (qppe_sched_l1_c_drr_ll_tbl_fields),
  },
  {
    "L1_ENS_Q_HEAD_TBL",
    "index",
    HPPE_REG_SCHED_L1_ENS_Q_HEAD_TBL,
    HPPE_SCHED_L1_ENS_Q_HEAD_TBL_COUNT,
    HPPE_SCHED_L1_ENS_Q_HEAD_TBL_STRIDE,
    0,
    HPPE_SCHED_L1_ENS_Q_HEAD_TBL_WORDS,
    qppe_sched_l1_ens_q_head_tbl_fields,
    ARRAY_LEN (qppe_sched_l1_ens_q_head_tbl_fields),
  },
  {
    "L1_ENS_Q_ENTRY_TBL",
    "index",
    HPPE_REG_SCHED_L1_ENS_Q_ENTRY_TBL,
    HPPE_SCHED_L1_ENS_Q_ENTRY_TBL_COUNT,
    HPPE_SCHED_L1_ENS_Q_ENTRY_TBL_STRIDE,
    0,
    HPPE_SCHED_L1_ENS_Q_ENTRY_TBL_WORDS,
    qppe_sched_l0_ens_q_entry_tbl_fields,
    ARRAY_LEN (qppe_sched_l0_ens_q_entry_tbl_fields),
  },
  {
    "L0_SHP_CREDIT_TBL",
    "queue",
    HPPE_REG_SCHED_L0_SHP_CREDIT_TBL,
    HPPE_SCHED_L0_SHP_CREDIT_TBL_COUNT,
    HPPE_SCHED_L0_SHP_CREDIT_TBL_STRIDE,
    0,
    HPPE_SCHED_L0_SHP_CREDIT_TBL_WORDS,
    qppe_sched_l0_shp_credit_tbl_fields,
    ARRAY_LEN (qppe_sched_l0_shp_credit_tbl_fields),
  },
  {
    "L0_COMP_TBL",
    "queue",
    HPPE_REG_SCHED_L0_COMP_TBL,
    HPPE_SCHED_L0_COMP_TBL_COUNT,
    HPPE_SCHED_L0_COMP_TBL_STRIDE,
    0,
    HPPE_SCHED_L0_COMP_TBL_WORDS,
    qppe_sched_l0_comp_tbl_fields,
    ARRAY_LEN (qppe_sched_l0_comp_tbl_fields),
  },
  {
    "L1_SHP_CREDIT_TBL",
    "index",
    HPPE_REG_SCHED_L1_SHP_CREDIT_TBL,
    HPPE_SCHED_L1_SHP_CREDIT_TBL_COUNT,
    HPPE_SCHED_L1_SHP_CREDIT_TBL_STRIDE,
    0,
    HPPE_SCHED_L1_SHP_CREDIT_TBL_WORDS,
    qppe_sched_l0_shp_credit_tbl_fields,
    ARRAY_LEN (qppe_sched_l0_shp_credit_tbl_fields),
  },
  {
    "L1_COMP_TBL",
    "index",
    HPPE_REG_SCHED_L1_COMP_TBL,
    HPPE_SCHED_L1_COMP_TBL_COUNT,
    HPPE_SCHED_L1_COMP_TBL_STRIDE,
    0,
    HPPE_SCHED_L1_COMP_TBL_WORDS,
    qppe_sched_l0_comp_tbl_fields,
    ARRAY_LEN (qppe_sched_l0_comp_tbl_fields),
  },
  {
    "PSCH_SHP_SIGN_TBL",
    "port",
    HPPE_REG_SCHED_PSCH_SHP_SIGN_TBL,
    HPPE_SCHED_PSCH_SHP_SIGN_TBL_COUNT,
    HPPE_SCHED_PSCH_SHP_SIGN_TBL_STRIDE,
    0,
    HPPE_SCHED_PSCH_SHP_SIGN_TBL_WORDS,
    qppe_sched_psch_shp_sign_tbl_fields,
    ARRAY_LEN (qppe_sched_psch_shp_sign_tbl_fields),
  },
  {
    "PSCH_SHP_CREDIT_TBL",
    "port",
    HPPE_REG_SCHED_PSCH_SHP_CREDIT_TBL,
    HPPE_SCHED_PSCH_SHP_CREDIT_TBL_COUNT,
    HPPE_SCHED_PSCH_SHP_CREDIT_TBL_STRIDE,
    0,
    HPPE_SCHED_PSCH_SHP_CREDIT_TBL_WORDS,
    qppe_sched_psch_shp_credit_tbl_fields,
    ARRAY_LEN (qppe_sched_psch_shp_credit_tbl_fields),
  },
  {
    "PSCH_COMP_TBL",
    "port",
    HPPE_REG_SCHED_PSCH_COMP_TBL,
    HPPE_SCHED_PSCH_COMP_TBL_COUNT,
    HPPE_SCHED_PSCH_COMP_TBL_STRIDE,
    0,
    HPPE_SCHED_PSCH_COMP_TBL_WORDS,
    qppe_sched_psch_comp_tbl_fields,
    ARRAY_LEN (qppe_sched_psch_comp_tbl_fields),
  },
};

static u32
qppe_sched_bits (const u32 *words, u32 offset, u32 n_bits)
{
  u32 word = offset / 32, shift = offset % 32;
  u64 value = words[word];

  ASSERT (n_bits > 0 && n_bits <= 32);
  if (shift + n_bits > 32)
    {
      u64 high = words[word + 1];

      value |= high << 32;
    }
  return (value >> shift) & (((u64) 1 << n_bits) - 1);
}

static void
qppe_sched_range (table_t *table, u32 row, u32 col, u32 first, u32 last)
{
  if (first == last)
    table_format_cell (table, row, col, "%u", first);
  else
    table_format_cell (table, row, col, "%u-%u", first, last);
}

static u8 *
qppe_sched_format_table (u8 *s, qppe_device_t *qd, const qppe_sched_table_t *t)
{
  table_t table = {};
  u32 masks[QPPE_SCHED_MAX_WORDS] = {};
  u32 *entries = 0;
  u32 indent = format_get_indent (s), row = 0;
  u32 n_maps = t->map_size ? t->n_entries / t->map_size : 1;
  u32 map_size = t->map_size ? t->map_size : t->n_entries;
  u32 first_field_col = t->map_size ? 2 : 1;
  int header_row = -1;

  ASSERT (t->n_words <= QPPE_SCHED_MAX_WORDS);
  for (u32 f = 0; f < t->n_fields; f++)
    {
      const qppe_sched_field_t *field = t->fields + f;

      ASSERT (field->offset + field->n_bits <= t->n_words * 32);
      for (u32 bit = field->offset; bit < field->offset + field->n_bits; bit++)
	masks[bit / 32] |= 1u << (bit % 32);
    }
  vec_validate (entries, t->n_entries * t->n_words - 1);
  for (u32 i = 0; i < t->n_entries; i++)
    for (u32 w = 0; w < t->n_words; w++)
      entries[i * t->n_words + w] =
	qppe_mmio_read32 (qd, t->reg + i * t->stride + w * sizeof (u32)) & masks[w];

  table_add_hdr_row (&table, 0);
  for (u32 f = 0; f < t->n_fields; f++)
    if (t->fields[f].subheader[0])
      {
	table_add_hdr_row (&table, 0);
	header_row = -2;
	break;
      }
  if (t->map_size)
    table_format_cell (&table, header_row, 0, "group");
  table_format_cell (&table, header_row, first_field_col - 1, "%s", t->index_name);
  for (u32 f = 0; f < t->n_fields; f++)
    {
      table_format_cell (&table, header_row, first_field_col + f, "%s", t->fields[f].name);
      if (header_row == -2)
	table_format_cell (&table, -1, first_field_col + f, "%s", t->fields[f].subheader);
      if (strchr (t->fields[f].subheader, '/'))
	{
	  table_set_cell_align (&table, -2, first_field_col + f, TTAA_CENTER);
	  table_set_cell_align (&table, -1, first_field_col + f, TTAA_CENTER);
	}
    }
  for (u32 map = 0; map < n_maps; map++)
    {
      u32 first_map = map;
      u32 *values = entries + map * map_size * t->n_words;

      while (map + 1 < n_maps && !memcmp (values, entries + (map + 1) * map_size * t->n_words,
					  map_size * t->n_words * sizeof (entries[0])))
	map++;
      for (u32 i = 0; i < map_size; i++)
	{
	  u32 first = i;
	  u32 *words = values + i * t->n_words;

	  while (i + 1 < map_size &&
		 !memcmp (words, values + (i + 1) * t->n_words, t->n_words * sizeof (words[0])))
	    i++;
	  if (t->map_size)
	    qppe_sched_range (&table, row, 0, first_map, map);
	  qppe_sched_range (&table, row, first_field_col - 1, first, i);
	  for (u32 f = 0; f < t->n_fields; f++)
	    {
	      const qppe_sched_field_t *field = t->fields + f;
	      u32 col = first_field_col + f;

	      if (field->n_bits > 32)
		{
		  u8 *value = format (0, "0x");
		  u32 nibbles = (field->n_bits + 3) / 4;

		  for (u32 n = nibbles; n > 0; n--)
		    {
		      u32 offset = (n - 1) * 4;
		      u32 bits = clib_min (4, field->n_bits - offset);

		      value =
			format (value, "%x", qppe_sched_bits (words, field->offset + offset, bits));
		    }
		  table_format_cell (&table, row, col, "%v", value);
		  vec_free (value);
		}
	      else
		{
		  u32 value = qppe_sched_bits (words, field->offset, field->n_bits);

		  if (field->format == QPPE_SCHED_FIELD_BITMAP)
		    table_format_cell (&table, row, col, "%U", format_qppe_port_bitmap, value);
		  else if (field->format == QPPE_SCHED_FIELD_METER_UNIT)
		    table_format_cell (&table, row, col, "%s", value ? "packets" : "bytes");
		  else if (field->format == QPPE_SCHED_FIELD_COMPENSATION)
		    {
		      ppe_reg_sched_compensation_t comp = {
			.as_u32 = value,
		      };

		      table_format_cell (&table, row, col, "%u/%u/%u", comp.byte_count,
					 comp.byte_negative, comp.packet_count);
		      table_set_cell_align (&table, row, col, TTAA_CENTER);
		    }
		  else if (field->format == QPPE_SCHED_FIELD_QOS_DSCP)
		    {
		      ppe_reg_sched_qos_dscp_t dscp = {
			.as_u32 = value,
		      };

		      table_format_cell (&table, row, col, "%u/%u/%u", dscp.value, dscp.mask,
					 dscp.enable);
		      table_set_cell_align (&table, row, col, TTAA_CENTER);
		    }
		  else if (field->format == QPPE_SCHED_FIELD_ENABLED_VALUE)
		    {
		      ppe_reg_sched_enabled_value_t enabled = {
			.as_u32 = value,
		      };

		      table_format_cell (&table, row, col, "%u/%u", enabled.value, enabled.enable);
		      table_set_cell_align (&table, row, col, TTAA_CENTER);
		    }
		  else
		    table_format_cell (&table, row, col, "%u", value);
		}
	    }
	  row++;
	}
    }
  s = format (s, "%s:", t->name);
  s = format_newline (s, indent + 2);
  s = format (s, "%U", format_table, &table);
  table_free (&table);
  vec_free (entries);
  return s;
}

static u8 *
qppe_sched_format_tables (u8 *s, qppe_device_t *qd, const qppe_sched_table_t *tables, u32 count)
{
  u32 indent = format_get_indent (s);

  for (u32 i = 0; i < count; i++)
    {
      if (i)
	{
	  s = format (s, "\n");
	  s = format_newline (s, indent);
	}
      s = qppe_sched_format_table (s, qd, tables + i);
    }
  return s;
}

u8 *
format_qppe_sched_tables (u8 *s, va_list *args)
{
  vnet_dev_t *dev = va_arg (*args, vnet_dev_t *);
  qppe_device_t *qd = vnet_dev_get_data (dev);

  if (!qd->regs)
    return s;
  return qppe_sched_format_tables (s, qd, qppe_sched_tables, ARRAY_LEN (qppe_sched_tables));
}

u8 *
format_qppe_sched_memory (u8 *s, va_list *args)
{
  vnet_dev_t *dev = va_arg (*args, vnet_dev_t *);
  qppe_device_t *qd = vnet_dev_get_data (dev);
  u32 indent = format_get_indent (s);

  if (!qd->regs)
    return s;
  s = qppe_sched_format_regs (s, qd, qppe_sched_status_regs, ARRAY_LEN (qppe_sched_status_regs));
  s = format (s, "\n");
  s = format_newline (s, indent);
  return qppe_sched_format_tables (s, qd, qppe_sched_memory_tables,
				   ARRAY_LEN (qppe_sched_memory_tables));
}
