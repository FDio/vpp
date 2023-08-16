/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2023 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>

#include <dev_ena/ena.h>
#include <dev_ena/ena_inlines.h>
#include <vnet/ethernet/ethernet.h>

VLIB_REGISTER_LOG_CLASS (ena_log, static) = {
  .class_name = "ena",
  .subclass_name = "admin",
};

VLIB_REGISTER_LOG_CLASS (ena_stats_log, static) = {
  .class_name = "ena",
  .subclass_name = "admin-stats",
};

ena_aq_feat_info_t feat_info[] = {
#define _(v, ver, gt, st, n, s)                                               \
  [v] = { .name = #n,                                                         \
	  .version = (ver),                                                   \
	  .data_sz = sizeof (s),                                              \
	  .get = (gt),                                                        \
	  .set = (st) },
  foreach_ena_aq_feature_id
#undef _
};

ena_aq_feat_info_t *
ena_aq_get_feat_info (ena_aq_feature_id_t id)
{
  if (id >= ARRAY_LEN (feat_info) || feat_info[id].data_sz == 0)
    return 0;

  return feat_info + id;
}

void
ena_aq_free (vlib_main_t *vm, vnet_dev_t *dev)
{
  ena_device_t *ed = vnet_dev_get_data (dev);
  vnet_dev_dma_mem_free (vm, dev, ed->aq.cq_entries);
  vnet_dev_dma_mem_free (vm, dev, ed->aq.sq_entries);
  ed->aq.depth = 0;
}

vnet_dev_rv_t
ena_aq_olloc (vlib_main_t *vm, vnet_dev_t *dev, u16 depth)
{
  ena_device_t *ed = vnet_dev_get_data (dev);
  vnet_dev_dma_mem_free (vm, dev, ed->aq.cq_entries);
  vnet_dev_dma_mem_free (vm, dev, ed->aq.sq_entries);
  u32 sq_alloc_sz = sizeof (ena_aq_sq_entry_t) * depth;
  u32 cq_alloc_sz = sizeof (ena_aq_cq_entry_t) * depth;
  vnet_dev_rv_t rv;

  ASSERT (ed->aq.sq_entries == 0);
  ASSERT (ed->aq.cq_entries == 0);

  rv = vnet_dev_dma_mem_alloc (vm, dev, sq_alloc_sz, 0,
			       (void **) &ed->aq.sq_entries);
  if (rv != VNET_DEV_OK)
    goto err;

  rv = vnet_dev_dma_mem_alloc (vm, dev, cq_alloc_sz, 0,
			       (void **) &ed->aq.cq_entries);
  if (rv != VNET_DEV_OK)
    goto err;

  ed->aq.depth = depth;

  return VNET_DEV_OK;
err:
  ena_aq_free (vm, dev);
  return rv;
}

vnet_dev_rv_t
ena_aq_start (vlib_main_t *vm, vnet_dev_t *dev)
{
  ena_device_t *ed = vnet_dev_get_data (dev);
  u16 depth = ed->aq.depth;
  u32 sq_alloc_sz = sizeof (ena_aq_sq_entry_t) * depth;
  u32 cq_alloc_sz = sizeof (ena_aq_cq_entry_t) * depth;

  ASSERT (ed->aq_started == 0);

  ena_reg_aq_caps_t aq_caps = {
    .depth = depth,
    .entry_size = sizeof (ena_aq_sq_entry_t),
  };

  ena_reg_acq_caps_t acq_caps = {
    .depth = depth,
    .entry_size = sizeof (ena_aq_cq_entry_t),
  };

  clib_memset (ed->aq.sq_entries, 0, sq_alloc_sz);
  clib_memset (ed->aq.cq_entries, 0, cq_alloc_sz);

  ed->aq.sq_next = 0;
  ed->aq.cq_head = 0;

  ena_reg_set_dma_addr (vm, dev, ENA_REG_AQ_BASE_LO, ENA_REG_AQ_BASE_HI,
			ed->aq.sq_entries);
  ena_reg_set_dma_addr (vm, dev, ENA_REG_ACQ_BASE_LO, ENA_REG_ACQ_BASE_HI,
			ed->aq.cq_entries);

  ena_reg_write (dev, ENA_REG_AQ_CAPS, &aq_caps);
  ena_reg_write (dev, ENA_REG_ACQ_CAPS, &acq_caps);

  ed->aq_started = 1;

  return VNET_DEV_OK;
}

void
ena_aq_stop (vlib_main_t *vm, vnet_dev_t *dev)
{
  ena_device_t *ed = vnet_dev_get_data (dev);
  ena_reg_aq_caps_t aq_caps = {};
  ena_reg_acq_caps_t acq_caps = {};

  if (ed->aq_started)
    {
      ena_reg_write (dev, ENA_REG_AQ_CAPS, &aq_caps);
      ena_reg_write (dev, ENA_REG_ACQ_CAPS, &acq_caps);
      ed->aq_started = 0;
    }
}
vnet_dev_rv_t
ena_aq_req (vlib_main_t *vm, vnet_dev_t *dev, ena_aq_opcode_t opcode,
	    void *sqe_data, u8 sqe_data_sz, void *cqe_data, u8 cqe_data_sz)
{
  ena_device_t *ed = vnet_dev_get_data (dev);
  u32 next = ed->aq.sq_next++;
  u32 index = next & pow2_mask (ENA_ADMIN_QUEUE_LOG2_DEPTH);
  u8 phase = 1 & (~(next >> ENA_ADMIN_QUEUE_LOG2_DEPTH));
  ena_aq_sq_entry_t *sqe = ed->aq.sq_entries + index;
  ena_aq_cq_entry_t *cqe = ed->aq.cq_entries + index;
  f64 suspend_time = 1e-6;
  u32 my_process_index = vlib_get_current_process_node_index (vm);

  ena_log_debug (dev, "admin_req: called from '%U'", format_vlib_node_name, vm,
		 my_process_index);

  clib_memcpy_fast (&sqe->data, sqe_data, sqe_data_sz);
  sqe->opcode = opcode;
  sqe->command_id = index;
  sqe->phase = phase;

  ena_reg_write (dev, ENA_REG_AQ_DB, &ed->aq.sq_next);

  while (cqe->phase != phase)
    {
      vlib_process_suspend (vm, suspend_time);
      suspend_time *= 2;
      if (suspend_time > 1e-3)
	{
	  ena_log_err (dev, "admin queue timeout (opcode %U)",
		       format_ena_aq_opcode, opcode);
	  return VNET_DEV_ERR_TIMEOUT;
	}
    }

  if (cqe->status != ENA_ADMIN_COMPL_STATUS_SUCCESS)
    {
      ena_log_err (dev,
		   "cqe[%u]: opcode %U status %U ext_status %u sq_head_idx %u",
		   cqe - ed->aq.cq_entries, format_ena_aq_opcode, opcode,
		   format_ena_aq_status, cqe->status, cqe->extended_status,
		   cqe->sq_head_indx);
      return VNET_DEV_ERR_DEVICE_NO_REPLY;
    }

  ena_log_debug (dev, "cqe: status %u ext_status %u sq_head_idx %u",
		 cqe->status, cqe->extended_status, cqe->sq_head_indx);

  if (cqe_data && cqe_data_sz)
    clib_memcpy_fast (cqe_data, &cqe->data, cqe_data_sz);
  return VNET_DEV_OK;
}

vnet_dev_rv_t
ena_aq_set_feature (vlib_main_t *vm, vnet_dev_t *dev,
		    ena_aq_feature_id_t feat_id, void *data)
{
  vnet_dev_rv_t rv;

  struct
  {
    ena_aq_aq_ctrl_buff_info_t control_buffer;
    ena_aq_get_set_feature_common_desc_t feat_common;
    u32 data[11];
  } fd = {
    .feat_common.feature_id = feat_id,
    .feat_common.feature_version = feat_info[feat_id].version,
  };

  ena_log_debug (dev, "set_feature(%s):\n  %U", feat_info[feat_id].name,
		 format_ena_aq_feat_desc, feat_id, data);

  ASSERT (feat_info[feat_id].data_sz > 1);
  clib_memcpy (&fd.data, data, feat_info[feat_id].data_sz);

  rv = ena_aq_req (vm, dev, ENA_AQ_OPCODE_SET_FEATURE, &fd, sizeof (fd), 0, 0);

  if (rv != VNET_DEV_OK)
    ena_log_err (dev, "get_feature(%U) failed", format_ena_aq_feat_name,
		 feat_id);

  return rv;
}

vnet_dev_rv_t
ena_aq_get_feature (vlib_main_t *vm, vnet_dev_t *dev,
		    ena_aq_feature_id_t feat_id, void *data)
{
  vnet_dev_rv_t rv;

  struct
  {
    ena_aq_aq_ctrl_buff_info_t control_buffer;
    ena_aq_get_set_feature_common_desc_t feat_common;
    u32 data[11];
  } fd = {
    .feat_common.feature_id = feat_id,
    .feat_common.feature_version = feat_info[feat_id].version,
  };

  rv = ena_aq_req (vm, dev, ENA_AQ_OPCODE_GET_FEATURE, &fd, sizeof (fd), data,
		   feat_info[feat_id].data_sz);

  if (rv != VNET_DEV_OK)
    {
      ena_log_err (dev, "get_feature(%U) failed", format_ena_aq_feat_name,
		   feat_id);
      return rv;
    }

  ASSERT (feat_info[feat_id].data_sz > 1);

  ena_log_debug (dev, "get_feature(%s):\n  %U", feat_info[feat_id].name,
		 format_ena_aq_feat_desc, feat_id, data);

  return 0;
}

vnet_dev_rv_t
ena_aq_create_sq (vlib_main_t *vm, vnet_dev_t *dev,
		  ena_aq_create_sq_cmd_t *cmd, ena_aq_create_sq_resp_t *resp)
{
  vnet_dev_rv_t rv;

  ena_log_debug (dev, "create_sq_cmd_req:\n  %U", format_ena_aq_create_sq_cmd,
		 cmd);

  rv = ena_aq_req (vm, dev, ENA_AQ_OPCODE_CREATE_SQ, cmd, sizeof (*cmd), resp,
		   sizeof (*resp));

  if (rv != VNET_DEV_OK)
    ena_log_debug (dev, "create_sq_cmd_resp:\n  %U",
		   format_ena_aq_create_sq_resp, resp);
  return rv;
}

vnet_dev_rv_t
ena_aq_create_cq (vlib_main_t *vm, vnet_dev_t *dev,
		  ena_aq_create_cq_cmd_t *cmd, ena_aq_create_cq_resp_t *resp)
{
  vnet_dev_rv_t rv;

  ena_log_debug (dev, "create_cq_cmd_req:\n  %U", format_ena_aq_create_cq_cmd,
		 cmd);

  rv = ena_aq_req (vm, dev, ENA_AQ_OPCODE_CREATE_CQ, cmd, sizeof (*cmd), resp,
		   sizeof (*resp));

  if (rv != VNET_DEV_OK)
    ena_log_debug (dev, "create_cq_cmd_resp:\n  %U",
		   format_ena_aq_create_cq_resp, resp);

  return rv;
}

vnet_dev_rv_t
ena_aq_destroy_sq (vlib_main_t *vm, vnet_dev_t *dev,
		   ena_aq_destroy_sq_cmd_t *cmd)
{
  ena_log_debug (dev, "destroy_sq_cmd_req:\n  %U",
		 format_ena_aq_destroy_sq_cmd, cmd);

  return ena_aq_req (vm, dev, ENA_AQ_OPCODE_DESTROY_SQ, cmd, sizeof (*cmd), 0,
		     0);
}

vnet_dev_rv_t
ena_aq_destroy_cq (vlib_main_t *vm, vnet_dev_t *dev,
		   ena_aq_destroy_cq_cmd_t *cmd)
{
  ena_log_debug (dev, "destroy_cq_cmd_req:\n  %U",
		 format_ena_aq_destroy_cq_cmd, cmd);

  return ena_aq_req (vm, dev, ENA_AQ_OPCODE_DESTROY_CQ, cmd, sizeof (*cmd), 0,
		     0);
}

vnet_dev_rv_t
ena_aq_get_stats (vlib_main_t *vm, vnet_dev_t *dev, ena_aq_stats_type_t type,
		  ena_aq_stats_scope_t scope, u16 queue_idx, void *data)
{
  vnet_dev_rv_t rv;
  format_function_t *ff = 0;
  u8 data_sz[] = {
    [ENA_ADMIN_STATS_TYPE_BASIC] = sizeof (ena_aq_basic_stats_t),
    [ENA_ADMIN_STATS_TYPE_EXTENDED] = 0,
    [ENA_ADMIN_STATS_TYPE_ENI] = sizeof (ena_aq_eni_stats_t),
  };

  char *type_str[] = {
#define _(n, s) [n] = #s,
    foreach_ena_aq_stats_type
#undef _
  };

  char *scope_str[] = {
#define _(n, s) [n] = #s,
    foreach_ena_aq_stats_scope
#undef _
  };

  ena_aq_get_stats_cmd_t cmd = {
    .type = type,
    .scope = scope,
    .queue_idx = scope == ENA_ADMIN_STATS_SCOPE_SPECIFIC_QUEUE ? queue_idx : 0,
    .device_id = 0xffff,
  };

  if ((rv = ena_aq_req (vm, dev, ENA_AQ_OPCODE_GET_STATS, &cmd, sizeof (cmd),
			data, data_sz[type])))
    {
      ena_stats_log_err (dev, "get_stats(%s, %s) failed", type_str[type],
			 scope_str[scope]);
      return rv;
    }

  if (type == ENA_ADMIN_STATS_TYPE_BASIC)
    ff = format_ena_aq_basic_stats;
  else if (type == ENA_ADMIN_STATS_TYPE_ENI)
    ff = format_ena_aq_eni_stats;

  if (ff)
    ena_stats_log_debug (dev, "get_stats(%s, %s, %u):\n  %U", type_str[type],
			 scope_str[scope], queue_idx, ff, data);
  else
    ena_stats_log_debug (dev, "get_stats(%s, %s, %u): unknown data",
			 type_str[type], scope_str[scope], queue_idx);

  return VNET_DEV_OK;
}
