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

static format_function_t format_ena_admin_opcode;
static format_function_t format_ena_admin_status;
static format_function_t format_ena_admin_feat_desc;
static format_function_t format_ena_admin_feat_name;

#define _dec(c, n) s = format (s, "\n                %-40s = %u", #n, (c)->n)
#define _hex(c, n) s = format (s, "\n                %-40s = 0x%x", #n, (c)->n)
#define _mem(c, n)                                                            \
  s = format (s, "\n                %-40s = %U", #n, format_ena_mem_addr,     \
	      &((c)->n))

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
	{
	  ena_log_err (ed, "admin queue timeout (opcode %U)",
		       format_ena_admin_opcode, opcode);
	  return clib_error_return (0, "admin queue timeout (opcode %U)",
				    format_ena_admin_opcode, opcode);
	}
    }

  if (cqe->status != ENA_ADMIN_COMPL_STATUS_SUCCESS)
    {
      ena_log_err (ed, "cqe: opcode %U status %U ext_status %u sq_head_idx %u",
		   format_ena_admin_opcode, opcode, format_ena_admin_status,
		   cqe->status, cqe->extended_status, cqe->sq_head_indx);
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
		       ena_aq_feature_id_t feat_id, void *data)
{
  clib_error_t *err;
  ena_aq_feature_data_t fd = { .feature_id = feat_id,
			       .feature_version =
				 ena_admin_feature_info[feat_id].version };

  ena_log_debug (ed, "set_feature(%s):%U",
		 ena_admin_feature_info[feat_id].name,
		 format_ena_admin_feat_desc, feat_id, data);

  ASSERT (ena_admin_feature_info[feat_id].data_sz > 1);
  clib_memcpy (&fd.data, data, ena_admin_feature_info[feat_id].data_sz);

  if ((err = ena_admin_req (vm, ed, ENA_AQ_OPCODE_SET_FEATURE, &fd,
			    sizeof (ena_aq_feature_data_t), 0, 0)))
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
		       ena_aq_feature_id_t feat_id, void *data)
{
  clib_error_t *err;
  ena_aq_feature_data_t fd = { .feature_id = feat_id,
			       .feature_version =
				 ena_admin_feature_info[feat_id].version };

  if ((err = ena_admin_req (vm, ed, ENA_AQ_OPCODE_GET_FEATURE, &fd,
			    sizeof (ena_aq_feature_data_t), data,
			    ena_admin_feature_info[feat_id].data_sz)))
    {
      ena_log_err (ed, "get_feature(%U) failed", format_ena_admin_feat_name,
		   feat_id);
      return clib_error_return (err, "get_feature(%U) failed",
				format_ena_admin_feat_name, feat_id);
    }

  ASSERT (ena_admin_feature_info[feat_id].data_sz > 1);

  ena_log_debug (ed, "get_feature(%s):%U",
		 ena_admin_feature_info[feat_id].name,
		 format_ena_admin_feat_desc, feat_id, data);

  return 0;
}

clib_error_t *
ena_admin_create_sq (vlib_main_t *vm, ena_device_t *ed,
		     ena_aq_create_sq_cmd_t *cmd,
		     ena_aq_create_sq_resp_t *resp)
{
  clib_error_t *err;

  if (ena_log_is_debug ())
    {
      u8 *s = 0;
      _dec (cmd, sq_direction);
      _dec (cmd, placement_policy);
      _dec (cmd, completion_policy);
      _dec (cmd, is_physically_contiguous);
      _dec (cmd, cq_idx);
      _dec (cmd, sq_depth);
      _mem (cmd, sq_ba);
      _mem (cmd, sq_head_writeback);
      ena_log_debug (ed, "create_sq_cmd_req:%v", s);
      vec_free (s);
    }

  err = ena_admin_req (vm, ed, ENA_AQ_OPCODE_CREATE_SQ, cmd, sizeof (*cmd),
		       resp, sizeof (*resp));

  if (ena_log_is_debug ())
    {
      u8 *s = 0;
      _dec (resp, sq_idx);
      _hex (resp, sq_doorbell_offset);
      _hex (resp, llq_descriptors_offset);
      _hex (resp, llq_headers_offset);
      ena_log_debug (ed, "create_sq_cmd_resp:%v", s);
      vec_free (s);
    }
  return err;
}

clib_error_t *
ena_admin_create_cq (vlib_main_t *vm, ena_device_t *ed,
		     ena_aq_create_cq_cmd_t *cmd,
		     ena_aq_create_cq_resp_t *resp)
{
  clib_error_t *err;

  if (ena_log_is_debug ())
    {
      u8 *s = 0;
      _dec (cmd, interrupt_mode_enabled);
      _dec (cmd, cq_entry_size_words);
      _dec (cmd, cq_depth);
      _hex (cmd, msix_vector);
      _mem (cmd, cq_ba);
      ena_log_debug (ed, "create_cq_cmd_req:%v", s);
      vec_free (s);
    }

  err = ena_admin_req (vm, ed, ENA_AQ_OPCODE_CREATE_CQ, cmd, sizeof (*cmd),
		       resp, sizeof (*resp));

  if (err == 0 && ena_log_is_debug ())
    {
      u8 *s = 0;
      _dec (resp, cq_idx);
      _dec (resp, cq_actual_depth);
      _dec (resp, numa_node_register_offset);
      _dec (resp, cq_head_db_register_offset);
      _dec (resp, cq_interrupt_unmask_register_offset);
      ena_log_debug (ed, "create_cq_cmd_resp:%v", s);
      vec_free (s);
    }

  return err;
}

clib_error_t *
ena_admin_destroy_sq (vlib_main_t *vm, ena_device_t *ed,
		      ena_aq_destroy_sq_cmd_t *cmd)
{
  ena_log_debug (ed, "destroy_sq_cmd_req: sq_idx %u sq_direction %u",
		 cmd->sq_idx, cmd->sq_direction);

  return ena_admin_req (vm, ed, ENA_AQ_OPCODE_DESTROY_SQ, cmd, sizeof (*cmd),
			0, 0);
}

clib_error_t *
ena_admin_destroy_cq (vlib_main_t *vm, ena_device_t *ed,
		      ena_aq_destroy_cq_cmd_t *cmd)
{
  ena_log_debug (ed, "destroy_cq_cmd_req: cq_idx %u", cmd->cq_idx);

  return ena_admin_req (vm, ed, ENA_AQ_OPCODE_DESTROY_CQ, cmd, sizeof (*cmd),
			0, 0);
}

/* format functions */

u8 *
format_ena_admin_opcode (u8 *s, va_list *args)
{
  u32 opcode = va_arg (*args, u32);

  char *opcode_names[] = {
#define _(v, s) [v] = #s,
    foreach_ena_aq_opcode
#undef _
  };

  if (opcode >= ARRAY_LEN (opcode_names) || opcode_names[opcode] == 0)
    return format (s, "UNKNOWN(%u)", opcode);
  return format (s, "%s", opcode_names[opcode]);
}

u8 *
format_ena_admin_status (u8 *s, va_list *args)
{
  u32 status = va_arg (*args, u32);

  char *status_names[] = {
#define _(v, s) [v] = #s,
    foreach_ena_admin_compl_status
#undef _
  };

  if (status >= ARRAY_LEN (status_names) || status_names[status] == 0)
    return format (s, "UNKNOWN(%u)", status);
  return format (s, "%s", status_names[status]);
}

static u8 *
format_ena_admin_aenq_groups (u8 *s, va_list *args)
{
  ena_admin_aenq_groups_t g = va_arg (*args, ena_admin_aenq_groups_t);
  u32 i, not_first = 0;

#define _(x)                                                                  \
  if (g.x)                                                                    \
    {                                                                         \
      s = format (s, "%s%s", not_first++ ? " " : "", #x);                     \
      g.x = 0;                                                                \
    }
  foreach_ena_admin_aenq_groups;
#undef _

  foreach_set_bit_index (i, g.as_u32)
    s = format (s, "%sunknown-%u", not_first++ ? " " : "", i);

  return s;
}

static u8 *
format_ena_admin_feat_name (u8 *s, va_list *args)
{
  ena_aq_feature_id_t feat_id = va_arg (*args, ena_aq_feature_id_t);
  char *feat_names[] = {
#define _(v, r, s, u) [v] = #s,
    foreach_ena_aq_feat_id
#undef _
  };

  if (feat_id >= ARRAY_LEN (feat_names) || feat_names[feat_id] == 0)
    return format (s, "UNKNOWN(%u)", feat_id);
  return format (s, "%s", feat_names[feat_id]);
}

static u8 *
format_ena_admin_feat_desc (u8 *s, va_list *args)
{
  ena_aq_feature_id_t feat_id = va_arg (*args, ena_aq_feature_id_t);
  void *data = va_arg (*args, void *);
  ena_admin_feature_info_t *fi = ena_admin_feature_info + feat_id;

  switch (feat_id)
    {
    case ENA_AQ_FEAT_ID_DEVICE_ATTRIBUTES:
      {
	ena_admin_device_attr_feature_desc_t *d = data;
	_dec (d, impl_id);
	_dec (d, device_version);
	_dec (d, phys_addr_width);
	_dec (d, virt_addr_width);
	s = format (s, " mac_addr %U", format_ethernet_address, d->mac_addr);
	_dec (d, max_mtu);
	s = format (s, " supported_feat 0x%x (%U)", d->supported_features,
		    format_ena_aq_feat_id_bitmap, d->supported_features);
      }
      break;
    case ENA_AQ_FEAT_ID_AENQ_CONFIG:
      {
	ena_admin_aenq_config_feature_desc_t *d = data;
	s = format (s, " supported_groups [%U]", format_ena_admin_aenq_groups,
		    d->supported_groups);
	s = format (s, " enabled_groups [%U]", format_ena_admin_aenq_groups,
		    d->enabled_groups);
      }
      break;
    case ENA_AQ_FEAT_ID_STATELESS_OFFLOAD_CONFIG:
      {
	ena_admin_stateless_offload_config_feature_desc_t *d = data;
	_hex (d, rx_supported);
	_hex (d, rx_enabled);
	_hex (d, tx);
      }
      break;

    case ENA_AQ_FEAT_ID_MAX_QUEUES_EXT:
      {
	ena_admin_max_queue_ext_feature_desc_t *d = data;
	_dec (d, max_rx_sq_num);
	_dec (d, max_rx_cq_num);
	_dec (d, max_tx_sq_num);
	_dec (d, max_tx_cq_num);
	_dec (d, max_rx_sq_depth);
	_dec (d, max_rx_cq_depth);
	_dec (d, max_tx_sq_depth);
	_dec (d, max_tx_cq_depth);
	_dec (d, version);
	_dec (d, max_tx_header_size);
	_dec (d, max_per_packet_tx_descs);
	_dec (d, max_per_packet_rx_descs);
      }
      break;

    case ENA_AQ_FEAT_ID_LLQ:
      {
	ena_admin_llq_feature_desc_t *d = data;
	_dec (d, max_llq_num);
	_dec (d, max_llq_depth);
	_dec (d, header_location_ctrl_supported);
	_dec (d, header_location_ctrl_enabled);
	_dec (d, entry_size_ctrl_supported);
	_dec (d, entry_size_ctrl_enabled);
	_dec (d, desc_num_before_header_supported);
	_dec (d, desc_num_before_header_enabled);
	_dec (d, descriptors_stride_ctrl_supported);
	_dec (d, descriptors_stride_ctrl_enabled);
	_hex (d, accel_mode.get.supported_flags);
	_dec (d, accel_mode.get.max_tx_burst_size);
	_hex (d, accel_mode.set.enabled_flags);
      }
      break;

    case ENA_AQ_FEAT_ID_HOST_ATTR_CONFIG:
      {
	ena_admin_host_attr_config_feature_desc_t *d = data;
	_mem (d, os_info_ba);
	_mem (d, debug_ba);
	_dec (d, debug_area_size);
      }
      break;

    default:
      s = format (s, "%U", format_hexdump, data, fi->data_sz);
      break;
    }

  return s;
}
