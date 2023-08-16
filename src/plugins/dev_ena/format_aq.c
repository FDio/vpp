/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2023 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>

#include <dev_ena/ena.h>
#include <dev_ena/ena_inlines.h>
#include <vnet/ethernet/ethernet.h>

static char *opcode_names[] = {
#define _(v, s) [v] = #s,
  foreach_ena_aq_opcode
#undef _
};

static char *status_names[] = {
#define _(v, s) [v] = #s,
  foreach_ena_aq_compl_status
#undef _
};

#define __maxval(s, f) (u64) (((typeof ((s)[0])){ .f = -1LL }).f)

#define __name(s, n)                                                          \
  {                                                                           \
    s = format (s, "%s%U%-32s: ", line ? "\n" : "", format_white_space,       \
		line ? indent : 0, #n);                                       \
    line++;                                                                   \
  }

#define _format_number(s, d, n, ...)                                          \
  {                                                                           \
    __name (s, n);                                                            \
    if (d->n < 10)                                                            \
      s = format (s, "%u", d->n);                                             \
    else if (__maxval (d, n) <= 255)                                          \
      s = format (s, "0x%02x (%u)", d->n, d->n);                              \
    else if (__maxval (d, n) <= 65535)                                        \
      s = format (s, "0x%04x (%u)", d->n, d->n);                              \
    else                                                                      \
      s = format (s, "0x%08x (%u)", d->n, d->n);                              \
  }

#define _format_with_fn_and_ptr(s, c, n, f)                                   \
  {                                                                           \
    __name (s, n);                                                            \
    s = format (s, "%U", f, &((c)->n));                                       \
  }

#define _format_with_fn_and_val(s, c, n, f)                                   \
  {                                                                           \
    __name (s, n);                                                            \
    s = format (s, "%U", f, (c)->n);                                          \
  }
#define _format_ena_memory(s, c, n)                                           \
  _format_with_fn_and_ptr (s, c, n, format_ena_mem_addr)

u8 *
format_ena_aq_opcode (u8 *s, va_list *args)
{
  u32 opcode = va_arg (*args, u32);

  if (opcode >= ARRAY_LEN (opcode_names) || opcode_names[opcode] == 0)
    return format (s, "UNKNOWN(%u)", opcode);
  return format (s, "%s", opcode_names[opcode]);
}

u8 *
format_ena_aq_status (u8 *s, va_list *args)
{
  u32 status = va_arg (*args, u32);

  if (status >= ARRAY_LEN (status_names) || status_names[status] == 0)
    return format (s, "UNKNOWN(%u)", status);
  return format (s, "%s", status_names[status]);
}

u8 *
format_ena_aq_aenq_groups (u8 *s, va_list *args)
{
  ena_aq_aenq_groups_t g = va_arg (*args, ena_aq_aenq_groups_t);
  u32 i, not_first = 0;
  u32 indent = format_get_indent (s);

#define _(x)                                                                  \
  if (g.x)                                                                    \
    {                                                                         \
      if (format_get_indent (s) > 80)                                         \
	s = format (s, "\n%U", format_white_space, indent);                   \
      s = format (s, "%s%s", not_first++ ? " " : "", #x);                     \
      g.x = 0;                                                                \
    }
  foreach_ena_aq_aenq_groups;
#undef _

  foreach_set_bit_index (i, g.as_u32)
    s = format (s, "%sunknown-%u", not_first++ ? " " : "", i);

  return s;
}

u8 *
format_ena_aq_feat_id_bitmap (u8 *s, va_list *args)
{
  u32 bmp = va_arg (*args, u32);
  int i, line = 0;
  u32 indent = format_get_indent (s);

  foreach_set_bit_index (i, bmp)
    {
      ena_aq_feat_info_t *info = ena_aq_get_feat_info (i);
      if (line++)
	s = format (s, ", ");
      if (format_get_indent (s) > 80)
	s = format (s, "\n%U", format_white_space, indent);
      if (info)
	s = format (s, "%s", info->name);
      else
	s = format (s, "unknown-%u", i);
    }

  return s;
}

u8 *
format_ena_aq_feat_name (u8 *s, va_list *args)
{
  ena_aq_feature_id_t feat_id = va_arg (*args, int);
  char *feat_names[] = {
#define _(v, r, gt, st, s, u) [v] = #s,
    foreach_ena_aq_feature_id
#undef _
  };

  if (feat_id >= ARRAY_LEN (feat_names) || feat_names[feat_id] == 0)
    return format (s, "UNKNOWN(%u)", feat_id);
  return format (s, "%s", feat_names[feat_id]);
}

u8 *
format_ena_aq_feat_desc (u8 *s, va_list *args)
{
  ena_aq_feature_id_t feat_id = va_arg (*args, int);
  void *data = va_arg (*args, void *);
  ena_aq_feat_info_t *info = ena_aq_get_feat_info (feat_id);
  u32 indent = format_get_indent (s);
  u32 line = 0;

  switch (feat_id)
    {
    case ENA_ADMIN_FEAT_ID_DEVICE_ATTRIBUTES:
      {
	ena_aq_feat_device_attr_t *d = data;
	_format_number (s, d, impl_id);
	_format_number (s, d, device_version);
	_format_number (s, d, phys_addr_width);
	_format_number (s, d, virt_addr_width);
	_format_with_fn_and_val (s, d, mac_addr, format_ethernet_address);
	_format_number (s, d, max_mtu);
	_format_with_fn_and_val (s, d, supported_features,
				 format_ena_aq_feat_id_bitmap);
      }
      break;

    case ENA_ADMIN_FEAT_ID_AENQ_CONFIG:
      {
	ena_aq_feat_aenq_config_t *d = data;
	_format_with_fn_and_val (s, d, supported_groups,
				 format_ena_aq_aenq_groups);
	_format_with_fn_and_val (s, d, enabled_groups,
				 format_ena_aq_aenq_groups);
      }
      break;

    case ENA_ADMIN_FEAT_ID_INTERRUPT_MODERATION:
      {
	ena_aq_feat_intr_moder_t *d = data;
	_format_number (s, d, intr_delay_resolution);
      }
      break;

    case ENA_ADMIN_FEAT_ID_STATELESS_OFFLOAD_CONFIG:
      {
	ena_aq_feat_stateless_offload_config_t *d = data;
	_format_number (s, d, rx_supported);
	_format_number (s, d, rx_enabled);
	_format_number (s, d, tx);
      }
      break;

    case ENA_ADMIN_FEAT_ID_RSS_INDIRECTION_TABLE_CONFIG:
      {
	ena_aq_feat_rss_ind_table_config_t *d = data;
	_format_number (s, d, min_size);
	_format_number (s, d, max_size);
	_format_number (s, d, size);
	_format_number (s, d, one_entry_update);
	_format_number (s, d, inline_index);
	_format_number (s, d, inline_entry.cq_idx);
      }
      break;

    case ENA_ADMIN_FEAT_ID_MAX_QUEUES_NUM:
      {
	ena_aq_feat_max_queue_num_t *d = data;
	_format_number (s, d, max_sq_num);
	_format_number (s, d, max_sq_depth);
	_format_number (s, d, max_cq_num);
	_format_number (s, d, max_cq_depth);
	_format_number (s, d, max_legacy_llq_num);
	_format_number (s, d, max_legacy_llq_depth);
	_format_number (s, d, max_header_size);
	_format_number (s, d, max_packet_tx_descs);
	_format_number (s, d, max_packet_rx_descs);
      }
      break;

    case ENA_ADMIN_FEAT_ID_MAX_QUEUES_EXT:
      {
	ena_aq_feat_max_queue_ext_t *d = data;
	_format_number (s, d, max_rx_sq_num);
	_format_number (s, d, max_rx_cq_num);
	_format_number (s, d, max_tx_sq_num);
	_format_number (s, d, max_tx_cq_num);
	_format_number (s, d, max_rx_sq_depth);
	_format_number (s, d, max_rx_cq_depth);
	_format_number (s, d, max_tx_sq_depth);
	_format_number (s, d, max_tx_cq_depth);
	_format_number (s, d, version);
	_format_number (s, d, max_tx_header_size);
	_format_number (s, d, max_per_packet_tx_descs);
	_format_number (s, d, max_per_packet_rx_descs);
      }
      break;

    case ENA_ADMIN_FEAT_ID_RSS_HASH_FUNCTION:
      {
	ena_aq_feat_rss_hash_function_t *d = data;
	_format_number (s, d, supported_func);
	_format_number (s, d, selected_func);
	_format_number (s, d, init_val);
      }
      break;

    case ENA_ADMIN_FEAT_ID_LLQ:
      {
	ena_aq_feat_llq_t *d = data;
	_format_number (s, d, max_llq_num);
	_format_number (s, d, max_llq_depth);
	_format_number (s, d, header_location_ctrl_supported);
	_format_number (s, d, header_location_ctrl_enabled);
	_format_number (s, d, entry_size_ctrl_supported);
	_format_number (s, d, entry_size_ctrl_enabled);
	_format_number (s, d, desc_num_before_header_supported);
	_format_number (s, d, desc_num_before_header_enabled);
	_format_number (s, d, descriptors_stride_ctrl_supported);
	_format_number (s, d, descriptors_stride_ctrl_enabled);
	_format_number (s, d, accel_mode.get.supported_flags);
	_format_number (s, d, accel_mode.get.max_tx_burst_size);
	_format_number (s, d, accel_mode.set.enabled_flags);
      }
      break;

    case ENA_ADMIN_FEAT_ID_EXTRA_PROPERTIES_STRINGS:
      {
	ena_aq_feat_extra_properties_strings_t *d = data;
	_format_number (s, d, count);
      }
      break;

    case ENA_ADMIN_FEAT_ID_EXTRA_PROPERTIES_FLAGS:
      {
	ena_aq_feat_extra_properties_flags_t *d = data;
	_format_number (s, d, flags);
      }
      break;

    case ENA_ADMIN_FEAT_ID_HOST_ATTR_CONFIG:
      {
	ena_aq_feat_host_attr_config_t *d = data;
	_format_ena_memory (s, d, os_info_ba);
	_format_ena_memory (s, d, debug_ba);
	_format_number (s, d, debug_area_size);
      }
      break;

    default:
      if (info)
	s = format (s, "%U", format_hexdump, data, info->data_sz);
      break;
    }

  return s;
}

u8 *
format_ena_aq_create_sq_cmd (u8 *s, va_list *args)
{
  ena_aq_create_sq_cmd_t *cmd = va_arg (*args, ena_aq_create_sq_cmd_t *);
  u32 indent = format_get_indent (s);
  u32 line = 0;

  _format_number (s, cmd, sq_direction);
  _format_number (s, cmd, placement_policy);
  _format_number (s, cmd, completion_policy);
  _format_number (s, cmd, is_physically_contiguous);
  _format_number (s, cmd, cq_idx);
  _format_number (s, cmd, sq_depth);
  _format_ena_memory (s, cmd, sq_ba);
  _format_ena_memory (s, cmd, sq_head_writeback);
  return s;
}

u8 *
format_ena_aq_create_cq_cmd (u8 *s, va_list *args)
{
  ena_aq_create_cq_cmd_t *cmd = va_arg (*args, ena_aq_create_cq_cmd_t *);
  u32 indent = format_get_indent (s);
  u32 line = 0;

  _format_number (s, cmd, interrupt_mode_enabled);
  _format_number (s, cmd, cq_entry_size_words);
  _format_number (s, cmd, cq_depth);
  _format_number (s, cmd, msix_vector);
  _format_ena_memory (s, cmd, cq_ba);
  return s;
}

u8 *
format_ena_aq_create_sq_resp (u8 *s, va_list *args)
{
  ena_aq_create_sq_resp_t *resp = va_arg (*args, ena_aq_create_sq_resp_t *);
  u32 indent = format_get_indent (s);
  u32 line = 0;

  _format_number (s, resp, sq_idx);
  _format_number (s, resp, sq_doorbell_offset);
  _format_number (s, resp, llq_descriptors_offset);
  _format_number (s, resp, llq_headers_offset);
  return s;
}

u8 *
format_ena_aq_create_cq_resp (u8 *s, va_list *args)
{
  ena_aq_create_cq_resp_t *resp = va_arg (*args, ena_aq_create_cq_resp_t *);
  u32 indent = format_get_indent (s);
  u32 line = 0;

  _format_number (s, resp, cq_idx);
  _format_number (s, resp, cq_actual_depth);
  _format_number (s, resp, numa_node_register_offset);
  _format_number (s, resp, cq_head_db_register_offset);
  _format_number (s, resp, cq_interrupt_unmask_register_offset);
  return s;
}

u8 *
format_ena_aq_destroy_sq_cmd (u8 *s, va_list *args)
{
  ena_aq_destroy_sq_cmd_t *cmd = va_arg (*args, ena_aq_destroy_sq_cmd_t *);
  u32 indent = format_get_indent (s);
  u32 line = 0;

  _format_number (s, cmd, sq_idx);
  _format_number (s, cmd, sq_direction);
  return s;
}

u8 *
format_ena_aq_destroy_cq_cmd (u8 *s, va_list *args)
{
  ena_aq_destroy_cq_cmd_t *cmd = va_arg (*args, ena_aq_destroy_cq_cmd_t *);
  u32 indent = format_get_indent (s);
  u32 line = 0;

  _format_number (s, cmd, cq_idx);
  return s;
}

u8 *
format_ena_aq_basic_stats (u8 *s, va_list *args)
{
  ena_aq_basic_stats_t *st = va_arg (*args, ena_aq_basic_stats_t *);
  u32 indent = format_get_indent (s);
  u32 line = 0;

  _format_number (s, st, tx_bytes);
  _format_number (s, st, tx_pkts);
  _format_number (s, st, rx_bytes);
  _format_number (s, st, rx_pkts);
  _format_number (s, st, rx_drops);
  _format_number (s, st, tx_drops);
  return s;
}

u8 *
format_ena_aq_eni_stats (u8 *s, va_list *args)
{
  ena_aq_eni_stats_t *st = va_arg (*args, ena_aq_eni_stats_t *);
  u32 indent = format_get_indent (s);
  u32 line = 0;

  _format_number (s, st, bw_in_allowance_exceeded);
  _format_number (s, st, bw_out_allowance_exceeded);
  _format_number (s, st, pps_allowance_exceeded);
  _format_number (s, st, conntrack_allowance_exceeded);
  _format_number (s, st, linklocal_allowance_exceeded);
  return s;
}
