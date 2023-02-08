/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2023 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>

#include <ena/ena.h>
#include <ena/ena_inlines.h>

VLIB_REGISTER_LOG_CLASS (ena_log, static) = {
  .class_name = "ena",
  .subclass_name = "admin",
};

static clib_error_t *
ena_admin_req (vlib_main_t *vm, ena_device_t *ed, ena_aq_opcode_t opcode,
	       void *sqe_data, u8 sqe_data_sz, void *cqe_data, u8 cqe_data_sz)
{
  u32 next = ed->aq_next++;
  u32 index = next & pow2_mask (ENA_ADMIN_QUEUE_LOG2_DEPTH);
  u8 phase = 1 & (~(next >> ENA_ADMIN_QUEUE_LOG2_DEPTH));
  ena_aq_entry_t *sqe = ed->aq_entries + index;
  ena_acq_entry_t *cqe = ed->acq_entries + index;
  f64 suspend_time = 1e-6;

  clib_memcpy_fast (&sqe->data, sqe_data, sqe_data_sz);
  sqe->opcode = opcode;
  sqe->command_id = index;
  sqe->phase = phase;

  ena_reg_write (ed, ENA_REG_AQ_DB, &ed->aq_next);

  while (cqe->phase != phase)
    {
      vlib_process_suspend (vm, suspend_time);
      suspend_time *= 2;
      if (suspend_time > 1e-3)
	return clib_error_return (0, "timeout");
    }

  if (cqe_data && cqe_data_sz)
    clib_memcpy_fast (cqe_data, &cqe->data, cqe_data_sz);
  return 0;
}

clib_error_t *
ena_admin_set_feature (vlib_main_t *vm, ena_device_t *ed,
		       ena_aq_feature_id_t feat_id, void *data)
{
  clib_error_t *err;
  ena_aq_feature_data_t fd = { .feature_id = feat_id,
			       .feature_version =
				 ena_admin_feature_info[feat_id].version };

  ena_log_debug (ed, "set_feature %s:\n%U",
		 ena_admin_feature_info[feat_id].name,
		 format_ena_admin_feat_desc, feat_id, data);

  ASSERT (ena_admin_feature_info[feat_id].data_sz > 1);
  clib_memcpy (&fd.data, data, ena_admin_feature_info[feat_id].data_sz);

  if ((err = ena_admin_req (vm, ed, ENA_AQ_OPCODE_SET_FEATURE, &fd,
			    sizeof (ena_aq_feature_data_t), 0, 0)))
    return err;

  return 0;
}

clib_error_t *
ena_admin_get_feature (vlib_main_t *vm, ena_device_t *ed,
		       ena_aq_feature_id_t feat_id, void *data)
{
  clib_error_t *err;
  ena_aq_feature_data_t fd = { .feature_id = feat_id,
			       .feature_version =
				 ena_admin_feature_info[feat_id].version };

  if ((err = ena_admin_req (vm, ed, ENA_AQ_OPCODE_GET_FEATURE, &fd,
			    sizeof (ena_aq_feature_data_t), data,
			    ena_admin_feature_info[feat_id].data_sz)))
    return err;

  ASSERT (ena_admin_feature_info[feat_id].data_sz > 1);

  ena_log_debug (ed, "get_feature %s:\n%U",
		 ena_admin_feature_info[feat_id].name,
		 format_ena_admin_feat_desc, feat_id, data);

  return 0;
}

clib_error_t *
ena_admin_create_sq (vlib_main_t *vm, ena_device_t *ed,
		     ena_aq_create_sq_cmd_t *cmd,
		     ena_aq_create_sq_resp_t *resp)
{
  return ena_admin_req (vm, ed, ENA_AQ_OPCODE_DESTROY_SQ, cmd, sizeof (*cmd),
			resp, sizeof (*resp));
}

clib_error_t *
ena_admin_create_cq (vlib_main_t *vm, ena_device_t *ed,
		     ena_aq_create_cq_cmd_t *cmd,
		     ena_aq_create_cq_resp_t *resp)
{
  return ena_admin_req (vm, ed, ENA_AQ_OPCODE_DESTROY_CQ, cmd, sizeof (*cmd),
			resp, sizeof (*resp));
}

clib_error_t *
ena_admin_destroy_sq (vlib_main_t *vm, ena_device_t *ed,
		      ena_aq_destroy_sq_cmd_t *cmd)
{
  return ena_admin_req (vm, ed, ENA_AQ_OPCODE_DESTROY_SQ, cmd, sizeof (*cmd),
			0, 0);
}

clib_error_t *
ena_admin_destroy_cq (vlib_main_t *vm, ena_device_t *ed,
		      ena_aq_destroy_cq_cmd_t *cmd)
{
  return ena_admin_req (vm, ed, ENA_AQ_OPCODE_DESTROY_CQ, cmd, sizeof (*cmd),
			0, 0);
}

