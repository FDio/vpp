/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2023 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>

#include <ena/ena.h>
#include <ena/ena_inlines.h>
#include <vnet/ethernet/ethernet.h>

VLIB_REGISTER_LOG_CLASS (ena_log, static) = {
  .class_name = "ena",
  .subclass_name = "admin",
};

VLIB_REGISTER_LOG_CLASS (ena_stats_log, static) = {
  .class_name = "ena",
  .subclass_name = "admin-stats",
};

ena_admin_feat_info_t feat_info[] = {
#define _(v, ver, gt, st, n, s)                                               \
  [v] = { .name = #n,                                                         \
	  .version = (ver),                                                   \
	  .data_sz = sizeof (s),                                              \
	  .get = (gt),                                                        \
	  .set = (st) },
  foreach_ena_admin_feature_id
#undef _
};

ena_admin_feat_info_t *
ena_admin_get_feat_info (ena_admin_feature_id_t id)
{
  if (id >= ARRAY_LEN (feat_info) || feat_info[id].data_sz == 0)
    return 0;

  return feat_info + id;
}

clib_error_t *
ena_admin_req (vlib_main_t *vm, ena_device_t *ed, ena_admin_opcode_t opcode,
	       void *sqe_data, u8 sqe_data_sz, void *cqe_data, u8 cqe_data_sz)
{
  u32 next = ed->admin_sq_next++;
  u32 index = next & pow2_mask (ENA_ADMIN_QUEUE_LOG2_DEPTH);
  u8 phase = 1 & (~(next >> ENA_ADMIN_QUEUE_LOG2_DEPTH));
  ena_admin_sq_entry_t *sqe = ed->admin_sq_entries + index;
  ena_admin_cq_entry_t *cqe = ed->admin_cq_entries + index;
  f64 suspend_time = 1e-6;
  u32 my_process_index = vlib_get_current_process_node_index (vm);

  ena_log_debug (ed, "admin_req: called from '%U'", format_vlib_node_name, vm,
		 my_process_index);

  if (ed->initialized && my_process_index != ena_process_node.index)
    {
      /* to avoid race only ENA process node is allowed to operate on AQ */
      uword event, *event_data = 0;

      ena_process_event_data_t ev_data = {
	.calling_process_index = my_process_index,
	.ed = ed,
	.admin_req = { .opcode = opcode,
		       .sqe_data = sqe_data,
		       .sqe_data_sz = sqe_data_sz,
		       .cqe_data = cqe_data,
		       .cqe_data_sz = cqe_data_sz }
      };

      vlib_process_signal_event_pointer (
	vm, ena_process_node.index, ENA_PROCESS_EVENT_ADMIN_REQ, &ev_data);
      vlib_process_wait_for_event_or_clock (vm, 5.0);
      event = vlib_process_get_events (vm, &event_data);

      if (event != ENA_PROCESS_EVENT_ADMIN_REQ)
	{
	  char *str;
	  if (event == ~0)
	    str = "timeout waiting for process node to respond";
	  else
	    str = "unexpected event received";
	  ev_data.err =
	    vnet_error (VNET_ERR_BUG, "ena_admin_req failed, %s", str);
	  ena_log_err (ed, "ena_admin_req failed, %s", str);
	}

      vec_free (event_data);
      return ev_data.err;
    }

  clib_memcpy_fast (&sqe->data, sqe_data, sqe_data_sz);
  sqe->opcode = opcode;
  sqe->command_id = index;
  sqe->phase = phase;

  ena_reg_write (ed, ENA_REG_AQ_DB, &ed->admin_sq_next);

  while (cqe->phase != phase)
    {
      vlib_process_suspend (vm, suspend_time);
      suspend_time *= 2;
      if (suspend_time > 1e-3)
	{
	  ena_log_err (ed, "admin queue timeout (opcode %U)",
		       format_ena_admin_opcode, opcode);
	  return clib_error_return (0, "admin queue timeout (opcode %U)",
				    format_ena_admin_opcode, opcode);
	}
    }

  if (cqe->status != ENA_ADMIN_COMPL_STATUS_SUCCESS)
    {
      ena_log_err (ed,
		   "cqe[%u]: opcode %U status %U ext_status %u sq_head_idx %u",
		   cqe - ed->admin_cq_entries, format_ena_admin_opcode, opcode,
		   format_ena_admin_status, cqe->status, cqe->extended_status,
		   cqe->sq_head_indx);
      return clib_error_return (0, "admin queue error (opcode %U, status %U)",
				format_ena_admin_opcode, opcode,
				format_ena_admin_status, cqe->status);
    }

  ena_log_debug (ed, "cqe: status %u ext_status %u sq_head_idx %u",
		 cqe->status, cqe->extended_status, cqe->sq_head_indx);

  if (cqe_data && cqe_data_sz)
    clib_memcpy_fast (cqe_data, &cqe->data, cqe_data_sz);
  return 0;
}

clib_error_t *
ena_admin_set_feature (vlib_main_t *vm, ena_device_t *ed,
		       ena_admin_feature_id_t feat_id, void *data)
{
  clib_error_t *err;

  struct
  {
    ena_admin_aq_ctrl_buff_info_t control_buffer;
    ena_admin_get_set_feature_common_desc_t feat_common;
    u32 data[11];
  } fd = { .feat_common.feature_id = feat_id,
	   .feat_common.feature_version = feat_info[feat_id].version };

  ena_log_debug (ed, "set_feature(%s):\n  %U", feat_info[feat_id].name,
		 format_ena_admin_feat_desc, feat_id, data);

  ASSERT (feat_info[feat_id].data_sz > 1);
  clib_memcpy (&fd.data, data, feat_info[feat_id].data_sz);

  if ((err = ena_admin_req (vm, ed, ENA_AQ_OPCODE_SET_FEATURE, &fd,
			    sizeof (fd), 0, 0)))
    {
      ena_log_err (ed, "get_feature(%U) failed", format_ena_admin_feat_name,
		   feat_id);
      return clib_error_return (err, "set_feature(%U) failed",
				format_ena_admin_feat_name, feat_id);
    }

  return 0;
}

clib_error_t *
ena_admin_get_feature (vlib_main_t *vm, ena_device_t *ed,
		       ena_admin_feature_id_t feat_id, void *data)
{
  clib_error_t *err;

  struct
  {
    ena_admin_aq_ctrl_buff_info_t control_buffer;
    ena_admin_get_set_feature_common_desc_t feat_common;
    u32 data[11];
  } fd = { .feat_common.feature_id = feat_id,
	   .feat_common.feature_version = feat_info[feat_id].version };

  if ((err = ena_admin_req (vm, ed, ENA_AQ_OPCODE_GET_FEATURE, &fd,
			    sizeof (fd), data, feat_info[feat_id].data_sz)))
    {
      ena_log_err (ed, "get_feature(%U) failed", format_ena_admin_feat_name,
		   feat_id);
      return clib_error_return (err, "get_feature(%U) failed",
				format_ena_admin_feat_name, feat_id);
    }

  ASSERT (feat_info[feat_id].data_sz > 1);

  ena_log_debug (ed, "get_feature(%s):\n  %U", feat_info[feat_id].name,
		 format_ena_admin_feat_desc, feat_id, data);

  return 0;
}

clib_error_t *
ena_admin_create_sq (vlib_main_t *vm, ena_device_t *ed,
		     ena_admin_create_sq_cmd_t *cmd,
		     ena_admin_create_sq_resp_t *resp)
{
  clib_error_t *err;

  ena_log_debug (ed, "create_sq_cmd_req:\n  %U",
		 format_ena_admin_create_sq_cmd, cmd);

  err = ena_admin_req (vm, ed, ENA_AQ_OPCODE_CREATE_SQ, cmd, sizeof (*cmd),
		       resp, sizeof (*resp));

  if (err == 0)
    ena_log_debug (ed, "create_sq_cmd_resp:\n  %U",
		   format_ena_admin_create_sq_resp, resp);
  return err;
}

clib_error_t *
ena_admin_create_cq (vlib_main_t *vm, ena_device_t *ed,
		     ena_admin_create_cq_cmd_t *cmd,
		     ena_admin_create_cq_resp_t *resp)
{
  clib_error_t *err;

  ena_log_debug (ed, "create_cq_cmd_req:\n  %U",
		 format_ena_admin_create_cq_cmd, cmd);

  err = ena_admin_req (vm, ed, ENA_AQ_OPCODE_CREATE_CQ, cmd, sizeof (*cmd),
		       resp, sizeof (*resp));

  if (err == 0)
    ena_log_debug (ed, "create_cq_cmd_resp:\n  %U",
		   format_ena_admin_create_cq_resp, resp);

  return err;
}

clib_error_t *
ena_admin_destroy_sq (vlib_main_t *vm, ena_device_t *ed,
		      ena_admin_destroy_sq_cmd_t *cmd)
{
  ena_log_debug (ed, "destroy_sq_cmd_req:\n  %U",
		 format_ena_admin_destroy_sq_cmd, cmd);

  return ena_admin_req (vm, ed, ENA_AQ_OPCODE_DESTROY_SQ, cmd, sizeof (*cmd),
			0, 0);
}

clib_error_t *
ena_admin_destroy_cq (vlib_main_t *vm, ena_device_t *ed,
		      ena_admin_destroy_cq_cmd_t *cmd)
{
  ena_log_debug (ed, "destroy_cq_cmd_req:\n  %U",
		 format_ena_admin_destroy_cq_cmd, cmd);

  return ena_admin_req (vm, ed, ENA_AQ_OPCODE_DESTROY_CQ, cmd, sizeof (*cmd),
			0, 0);
}

clib_error_t *
ena_admin_get_stats (vlib_main_t *vm, ena_device_t *ed,
		     ena_admin_stats_type_t type,
		     ena_admin_stats_scope_t scope, u16 queue_idx, void *data)
{
  clib_error_t *err;
  format_function_t *ff = 0;
  u8 data_sz[] = {
    [ENA_ADMIN_STATS_TYPE_BASIC] = sizeof (ena_admin_basic_stats_t),
    [ENA_ADMIN_STATS_TYPE_EXTENDED] = 0,
    [ENA_ADMIN_STATS_TYPE_ENI] = sizeof (ena_admin_eni_stats_t),
  };

  char *type_str[] = {
#define _(n, s) [n] = #s,
    foreach_ena_admin_stats_type
#undef _
  };

  char *scope_str[] = {
#define _(n, s) [n] = #s,
    foreach_ena_admin_stats_scope
#undef _
  };

  ena_admin_get_stats_cmd_t cmd = {
    .type = type,
    .scope = scope,
    .queue_idx = scope == ENA_ADMIN_STATS_SCOPE_SPECIFIC_QUEUE ? queue_idx : 0,
    .device_id = 0xffff
  };

  if ((err = ena_admin_req (vm, ed, ENA_AQ_OPCODE_GET_STATS, &cmd,
			    sizeof (cmd), data, data_sz[type])))
    {
      ena_stats_log_err (ed, "get_stats(%s, %s) failed", type_str[type],
			 scope_str[scope]);
      return clib_error_return (err, "get_stats(%s, %s) failed",
				type_str[type], scope_str[scope]);
    }

  if (err)
    return err;

  if (type == ENA_ADMIN_STATS_TYPE_BASIC)
    ff = format_ena_admin_basic_stats;
  else if (type == ENA_ADMIN_STATS_TYPE_ENI)
    ff = format_ena_admin_eni_stats;

  if (ff)
    ena_stats_log_debug (ed, "get_stats(%s, %s, %u):\n  %U", type_str[type],
			 scope_str[scope], queue_idx, ff, data);
  else
    ena_stats_log_debug (ed, "get_stats(%s, %s, %u): unknown data",
			 type_str[type], scope_str[scope], queue_idx);

  return 0;
}
