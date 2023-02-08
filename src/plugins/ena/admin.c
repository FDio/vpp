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
static format_function_t format_ena_admin_feat_id_bitmap;

static struct
{
  char *name;
  u8 version;
  u8 data_sz;
} feat_info[] = {
#define _(v, ver, n, s)                                                       \
  [v] = { .name = #n, .version = (ver), .data_sz = sizeof (s) },
  foreach_ena_admin_feature_id
#undef _
};

#define _indent	      "\n                %-40s = "
#define _dec(c, n)    s = format (s, _indent "%u", #n, (c)->n)
#define _dec64(c, n)  s = format (s, _indent "%lu", #n, (c)->n)
#define _hex(c, n)    s = format (s, _indent "0x%x", #n, (c)->n)
#define _fmp(c, n, f) s = format (s, _indent "%U", #n, f, &((c)->n))
#define _fmv(c, n, f) s = format (s, _indent "%U", #n, f, (c)->n)
#define _mem(c, n)    _fmp (c, n, format_ena_mem_addr)

static clib_error_t *
ena_admin_req (vlib_main_t *vm, ena_device_t *ed, ena_admin_opcode_t opcode,
	       void *sqe_data, u8 sqe_data_sz, void *cqe_data, u8 cqe_data_sz)
{
  u32 next = ed->aq_next++;
  u32 index = next & pow2_mask (ENA_ADMIN_QUEUE_LOG2_DEPTH);
  u8 phase = 1 & (~(next >> ENA_ADMIN_QUEUE_LOG2_DEPTH));
  ena_admin_sq_entry_t *sqe = ed->admin_sq_entries + index;
  ena_admin_cq_entry_t *cqe = ed->admin_cq_entries + index;
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

  ena_log_debug (ed, "set_feature(%s):%U", feat_info[feat_id].name,
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

  ena_log_debug (ed, "get_feature(%s):%U", feat_info[feat_id].name,
		 format_ena_admin_feat_desc, feat_id, data);

  return 0;
}

clib_error_t *
ena_admin_create_sq (vlib_main_t *vm, ena_device_t *ed,
		     ena_admin_create_sq_cmd_t *cmd,
		     ena_admin_create_sq_resp_t *resp)
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
		     ena_admin_create_cq_cmd_t *cmd,
		     ena_admin_create_cq_resp_t *resp)
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
		      ena_admin_destroy_sq_cmd_t *cmd)
{
  ena_log_debug (ed, "destroy_sq_cmd_req: sq_idx %u sq_direction %u",
		 cmd->sq_idx, cmd->sq_direction);

  return ena_admin_req (vm, ed, ENA_AQ_OPCODE_DESTROY_SQ, cmd, sizeof (*cmd),
			0, 0);
}

clib_error_t *
ena_admin_destroy_cq (vlib_main_t *vm, ena_device_t *ed,
		      ena_admin_destroy_cq_cmd_t *cmd)
{
  ena_log_debug (ed, "destroy_cq_cmd_req: cq_idx %u", cmd->cq_idx);

  return ena_admin_req (vm, ed, ENA_AQ_OPCODE_DESTROY_CQ, cmd, sizeof (*cmd),
			0, 0);
}

clib_error_t *
ena_admin_get_stats (vlib_main_t *vm, ena_device_t *ed,
		     ena_admin_stats_type_t type,
		     ena_admin_stats_scope_t scope, u16 queue_idx, void *data)
{
  clib_error_t *err;
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
      ena_log_err (ed, "get_stats(%s, %s) failed", type_str[type],
		   scope_str[scope]);
      return clib_error_return (err, "get_stats(%s, %s) failed",
				type_str[type], scope_str[scope]);
    }

  if (err == 0 && ena_log_is_debug ())
    {
      u8 *s = 0;
      if (type == ENA_ADMIN_STATS_TYPE_BASIC)
	{
	  ena_admin_basic_stats_t *r = data;
	  _dec64 (r, tx_bytes);
	  _dec64 (r, tx_pkts);
	  _dec64 (r, rx_bytes);
	  _dec64 (r, rx_pkts);
	  _dec64 (r, rx_drops);
	  _dec64 (r, tx_drops);
	}
      else if (type == ENA_ADMIN_STATS_TYPE_ENI)
	{
	  ena_admin_eni_stats_t *r = data;
	  _dec64 (r, bw_in_allowance_exceeded);
	  _dec64 (r, bw_out_allowance_exceeded);
	  _dec64 (r, pps_allowance_exceeded);
	  _dec64 (r, conntrack_allowance_exceeded);
	  _dec64 (r, linklocal_allowance_exceeded);
	}
      ena_log_debug (ed, "get_stats(%s, %s, %u):%v", type_str[type],
		     scope_str[scope], queue_idx, s);
      vec_free (s);
    }

  return 0;
}

/* format functions */

u8 *
format_ena_admin_opcode (u8 *s, va_list *args)
{
  u32 opcode = va_arg (*args, u32);

  char *opcode_names[] = {
#define _(v, s) [v] = #s,
    foreach_ena_admin_opcode
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
  ena_admin_feature_id_t feat_id = va_arg (*args, ena_admin_feature_id_t);
  char *feat_names[] = {
#define _(v, r, s, u) [v] = #s,
    foreach_ena_admin_feature_id
#undef _
  };

  if (feat_id >= ARRAY_LEN (feat_names) || feat_names[feat_id] == 0)
    return format (s, "UNKNOWN(%u)", feat_id);
  return format (s, "%s", feat_names[feat_id]);
}

static u8 *
format_ena_admin_feat_desc (u8 *s, va_list *args)
{
  ena_admin_feature_id_t feat_id = va_arg (*args, ena_admin_feature_id_t);
  void *data = va_arg (*args, void *);
  typeof (*feat_info) *fi = feat_info + feat_id;

  switch (feat_id)
    {
    case ENA_ADMIN_FEAT_ID_DEVICE_ATTRIBUTES:
      {
	ena_admin_device_attr_feature_desc_t *d = data;
	_dec (d, impl_id);
	_dec (d, device_version);
	_dec (d, phys_addr_width);
	_dec (d, virt_addr_width);
	_fmv (d, mac_addr, format_ethernet_address);
	_dec (d, max_mtu);
	_fmv (d, supported_features, format_ena_admin_feat_id_bitmap);
      }
      break;
    case ENA_ADMIN_FEAT_ID_AENQ_CONFIG:
      {
	ena_admin_aenq_config_feature_desc_t *d = data;
	_fmv (d, supported_groups, format_ena_admin_aenq_groups);
	_fmv (d, enabled_groups, format_ena_admin_aenq_groups);
      }
      break;
    case ENA_ADMIN_FEAT_ID_STATELESS_OFFLOAD_CONFIG:
      {
	ena_admin_stateless_offload_config_feature_desc_t *d = data;
	_hex (d, rx_supported);
	_hex (d, rx_enabled);
	_hex (d, tx);
      }
      break;

    case ENA_ADMIN_FEAT_ID_MAX_QUEUES_EXT:
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

    case ENA_ADMIN_FEAT_ID_LLQ:
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

    case ENA_ADMIN_FEAT_ID_HOST_ATTR_CONFIG:
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

u8 *
format_ena_admin_feat_id_bitmap (u8 *s, va_list *args)
{
  u32 bmp = va_arg (*args, u32);
  int i, not_first = 0;

  foreach_set_bit_index (i, bmp)
    {
      if (i >= ARRAY_LEN (feat_info) || feat_info[i].name == 0)
	s = format (s, "%sunknown-%u", not_first++ ? ", " : "", i);
      else
	s = format (s, "%s%s", not_first++ ? ", " : "", feat_info[i].name);
    }

  return s;
}
