/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#include <vnet/feature/feature.h>
#include <vnet/ip/ip.h>
#include <vnet/sfdp/common.h>
#include <vnet/sfdp/sfdp.h>
#include <sfdp_services_sample/parser.h>

#define SAMPLE_PARSER_INVALID_TENANT_INDEX ((u16) ~0)

typedef struct
{
  u16 *tenant_idx_by_sw_if_index;
} sample_parser_main_t;

static sample_parser_main_t sample_parser_main;

typedef enum
{
  SAMPLE_PARSER_INPUT_NEXT_PARSER,
  SAMPLE_PARSER_INPUT_N_NEXT,
} sample_parser_input_next_t;

VLIB_NODE_FN (sample_parser_input_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  sfdp_main_t *sfdp = &sfdp_main;
  sample_parser_main_t *spm = &sample_parser_main;
  vlib_combined_counter_main_t *cm = &sfdp->tenant_data_ctr[SFDP_TENANT_DATA_COUNTER_INCOMING];
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
  u32 *from = vlib_frame_vector_args (frame);
  u16 nexts[VLIB_FRAME_SIZE], *next = nexts;
  u32 n_left = frame->n_vectors;
  u32 thread_index = vm->thread_index;

  vlib_get_buffers (vm, from, bufs, n_left);
  while (n_left)
    {
      u32 rx_sw_if_index = vnet_buffer (b[0])->sw_if_index[VLIB_RX];
      u16 tenant_idx = spm->tenant_idx_by_sw_if_index[rx_sw_if_index];
      ip4_header_t *ip = vlib_buffer_get_current (b[0]);
      u32 ip_header_len = ip4_header_bytes (ip);
      u8 supported = (ip->protocol == IP_PROTOCOL_TCP || ip->protocol == IP_PROTOCOL_UDP) &&
		     !ip4_is_fragment (ip) &&
		     vlib_buffer_has_space (b[0], ip_header_len + sizeof (udp_header_t));

      if (supported && tenant_idx != SAMPLE_PARSER_INVALID_TENANT_INDEX)
	{
	  sfdp_tenant_t *tenant = sfdp_tenant_at_index (sfdp, tenant_idx);
	  b[0]->flow_id = tenant->context_id;
	  sfdp_buffer (b[0])->tenant_index = tenant_idx;
	  next[0] = SAMPLE_PARSER_INPUT_NEXT_PARSER;
	  vlib_increment_combined_counter (cm, thread_index, tenant_idx, 1,
					   vlib_buffer_length_in_chain (vm, b[0]));
	}
      else
	vnet_feature_next_u16 (next, b[0]);

      b++;
      next++;
      n_left--;
    }

  vlib_buffer_enqueue_to_next (vm, node, from, nexts, frame->n_vectors);
  return frame->n_vectors;
}

VLIB_REGISTER_NODE (sample_parser_input_node) = {
  .name = "sample-parser-input",
  .vector_size = sizeof (u32),
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_next_nodes = SAMPLE_PARSER_INPUT_N_NEXT,
  .next_nodes = {
    [SAMPLE_PARSER_INPUT_NEXT_PARSER] = "sample-ip4-parser",
  },
};

VNET_FEATURE_INIT (sample_parser_input_feature, static) = {
  .arc_name = "ip4-unicast",
  .node_name = "sample-parser-input",
  .runs_before = VNET_FEATURES ("ip4-lookup"),
};

clib_error_t *
sample_parser_interface_enable_disable (u32 sw_if_index, u32 tenant_id, u8 disable)
{
  sfdp_main_t *sfdp = &sfdp_main;
  sample_parser_main_t *spm = &sample_parser_main;
  clib_bihash_kv_8_8_t kv = { .key = tenant_id };
  u32 old_len = vec_len (spm->tenant_idx_by_sw_if_index);

  if (clib_bihash_search_inline_8_8 (&sfdp->tenant_idx_by_id, &kv))
    return clib_error_return (0, "Tenant with id %u not found", tenant_id);
  if (!disable && vnet_feature_is_enabled ("ip4-unicast", "sfdp-interface-input-ip4", sw_if_index))
    return clib_error_return (0, "SFDP interface input is already enabled on interface");

  vec_validate_init_empty (spm->tenant_idx_by_sw_if_index, sw_if_index,
			   SAMPLE_PARSER_INVALID_TENANT_INDEX);
  if (!disable && spm->tenant_idx_by_sw_if_index[sw_if_index] != SAMPLE_PARSER_INVALID_TENANT_INDEX)
    return clib_error_return (0, "Sample parser is already enabled on interface");
  if (disable &&
      (sw_if_index >= old_len || spm->tenant_idx_by_sw_if_index[sw_if_index] != kv.value))
    return clib_error_return (0, "Sample parser is not enabled for tenant %u", tenant_id);

  if (vnet_feature_enable_disable ("ip4-unicast", "sample-parser-input", sw_if_index, !disable, 0,
				   0))
    return clib_error_return (0, "Unable to update sample parser feature");
  spm->tenant_idx_by_sw_if_index[sw_if_index] =
    disable ? SAMPLE_PARSER_INVALID_TENANT_INDEX : kv.value;
  return 0;
}

static clib_error_t *
sample_parser_interface_command_fn (vlib_main_t *vm, unformat_input_t *input,
				    vlib_cli_command_t *cmd)
{
  unformat_input_t line_input_, *line_input = &line_input_;
  u32 sw_if_index = ~0, tenant_id = ~0;
  clib_error_t *err = 0;
  u8 disable = 0;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;
  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "tenant %u", &tenant_id))
	;
      else if (unformat (line_input, "disable"))
	disable = 1;
      else if (unformat (line_input, "%U", unformat_vnet_sw_interface, vnet_get_main (),
			 &sw_if_index))
	;
      else
	{
	  err = unformat_parse_error (line_input);
	  goto done;
	}
    }
  if (sw_if_index == ~0)
    err = clib_error_return (0, "Missing interface");
  else if (tenant_id == ~0)
    err = clib_error_return (0, "Missing tenant id");
  else
    err = sample_parser_interface_enable_disable (sw_if_index, tenant_id, disable);

done:
  unformat_free (line_input);
  return err;
}

VLIB_CLI_COMMAND (sample_parser_interface_command, static) = {
  .path = "set sfdp sample-parser",
  .short_help = "set sfdp sample-parser <interface> tenant <tenant-id> [disable]",
  .function = sample_parser_interface_command_fn,
};
