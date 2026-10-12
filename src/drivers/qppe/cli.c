/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <edma_hw.h>
#include <qppe.h>

#include <string.h>

static clib_error_t *
qppe_cli_show (vlib_main_t *vm, unformat_input_t *input, format_function_t *const *formatters,
	       u32 n_formatters)
{
  vnet_dev_main_t *dm = &vnet_dev_main;

  if (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    return clib_error_return (0, "unknown input `%U'", format_unformat_error, input);

  pool_foreach_pointer (dev, dm->devices)
    {
      vnet_dev_driver_t *dr = pool_elt_at_index (dm->drivers, dev->driver_index);

      if (strcmp (dr->registration->name, "qppe") != 0)
	continue;

      vlib_cli_output (vm, "device '%s':", dev->device_id);
      for (u32 i = 0; i < n_formatters; i++)
	{
	  if (i)
	    vlib_cli_output (vm, "\n");
	  vlib_cli_output (vm, "  %U", formatters[i], dev);
	}
    }

  return 0;
}

static clib_error_t *
show_qppe_acl_cmd_fn (vlib_main_t *vm, unformat_input_t *input,
		      __clib_unused vlib_cli_command_t *cmd)
{
  format_function_t *const formatters[] = {
    format_qppe_acl_ipo_tbl,
    format_qppe_acl_pre_ipo_tbl,
  };

  return qppe_cli_show (vm, input, formatters, ARRAY_LEN (formatters));
}

VLIB_CLI_COMMAND (show_qppe_acl_cmd, static) = {
  .path = "show qppe acl",
  .short_help = "show qppe acl",
  .function = show_qppe_acl_cmd_fn,
  .is_mp_safe = 1,
};

static clib_error_t *
show_qppe_edma_cmd_fn (vlib_main_t *vm, unformat_input_t *input,
		       __clib_unused vlib_cli_command_t *cmd)
{
  format_function_t *const formatters[] = {
    format_qppe_edma_cfg,
    format_qppe_edma_status,
    format_qppe_edma_rxdesc_rings,
    format_qppe_edma_rxfill_rings,
    format_qppe_edma_txdesc_rings,
    format_qppe_edma_txcmpl_rings,
    format_qppe_edma_ring_queue_map,
    format_qppe_edma_qid2rid,
    format_qppe_edma_rxdesc2fill_map,
    format_qppe_edma_txdesc2cmpl_map,
    format_qppe_edma_service_tbl,
    format_qppe_edma_in_l2_service_tbl,
    format_qppe_edma_eg_service_tbl,
    format_qppe_edma_tl_service_tbl,
  };

  return qppe_cli_show (vm, input, formatters, ARRAY_LEN (formatters));
}

VLIB_CLI_COMMAND (show_qppe_edma_cmd, static) = {
  .path = "show qppe edma",
  .short_help = "show qppe edma",
  .function = show_qppe_edma_cmd_fn,
  .is_mp_safe = 1,
};

static clib_error_t *
show_qppe_edma_errors_cmd_fn (vlib_main_t *vm, unformat_input_t *input,
			      __clib_unused vlib_cli_command_t *cmd)
{
  format_function_t *const formatters[] = {
    format_qppe_edma_errors,
    format_qppe_edma_rxfill_descriptors,
  };

  return qppe_cli_show (vm, input, formatters, ARRAY_LEN (formatters));
}

VLIB_CLI_COMMAND (show_qppe_edma_errors_cmd, static) = {
  .path = "show qppe edma errors",
  .short_help = "show qppe edma errors (reads clear-on-read interrupt status)",
  .function = show_qppe_edma_errors_cmd_fn,
};

static clib_error_t *
show_qppe_vsi_cmd_fn (vlib_main_t *vm, unformat_input_t *input,
		      __clib_unused vlib_cli_command_t *cmd)
{
  format_function_t *const formatters[] = {
    format_qppe_rule_and_action_tbl, format_qppe_vsi_tbl,
    format_qppe_vsi_remap_tbl,	     format_qppe_port_vsi_enqueue_map,
    format_qppe_l2_vp_port_tbl,	     format_qppe_vsi_vp_learning,
    format_qppe_vsi_vp_isolation,    format_qppe_vsi_l3_vp_port_tbl,
    format_qppe_vsi_egress_tags,     format_qppe_vsi_counters,
  };

  return qppe_cli_show (vm, input, formatters, ARRAY_LEN (formatters));
}

VLIB_CLI_COMMAND (show_qppe_vsi_cmd, static) = {
  .path = "show qppe vsi",
  .short_help = "show qppe vsi",
  .function = show_qppe_vsi_cmd_fn,
  .is_mp_safe = 1,
};

static clib_error_t *
show_qppe_fdb_cmd_fn (vlib_main_t *vm, unformat_input_t *input,
		      __clib_unused vlib_cli_command_t *cmd)
{
  format_function_t *const formatters[] = {
    format_qppe_fdb_cfg,
    format_qppe_fdb_port_ctrl,
    format_qppe_fdb_learning_limits,
    format_qppe_fdb_reserved_table,
    format_qppe_fdb_table,
  };

  return qppe_cli_show (vm, input, formatters, ARRAY_LEN (formatters));
}

VLIB_CLI_COMMAND (show_qppe_fdb_cmd, static) = {
  .path = "show qppe fdb",
  .short_help = "show qppe fdb",
  .function = show_qppe_fdb_cmd_fn,
  .is_mp_safe = 1,
};

static clib_error_t *
show_qppe_bm_cmd_fn (vlib_main_t *vm, unformat_input_t *input,
		     __clib_unused vlib_cli_command_t *cmd)
{
  format_function_t *const formatters[] = {
    format_qppe_bm_cfg,		 format_qppe_bm_shared_group_cfg,    format_qppe_bm_port_fc_cfg,
    format_qppe_bm_deq_fifo_cfg, format_qppe_bm_port_status,	     format_qppe_bm_port_profile,
    format_qppe_bm_group_status, format_qppe_bm_total_react_profile,
  };

  return qppe_cli_show (vm, input, formatters, ARRAY_LEN (formatters));
}

VLIB_CLI_COMMAND (show_qppe_bm_cmd, static) = {
  .path = "show qppe bm",
  .short_help = "show qppe bm",
  .function = show_qppe_bm_cmd_fn,
  .is_mp_safe = 1,
};

static clib_error_t *
show_qppe_bm_memory_cmd_fn (vlib_main_t *vm, unformat_input_t *input,
			    __clib_unused vlib_cli_command_t *cmd)
{
  format_function_t *const formatters[] = {
    format_qppe_bm_llm,
    format_qppe_bm_rcm,
    format_qppe_bm_dm,
  };

  return qppe_cli_show (vm, input, formatters, ARRAY_LEN (formatters));
}

VLIB_CLI_COMMAND (show_qppe_bm_memory_cmd, static) = {
  .path = "show qppe bm memory",
  .short_help = "show qppe bm memory",
  .function = show_qppe_bm_memory_cmd_fn,
  .is_mp_safe = 1,
};

static clib_error_t *
show_qppe_ac_cmd_fn (vlib_main_t *vm, unformat_input_t *input,
		     __clib_unused vlib_cli_command_t *cmd)
{
  format_function_t *const formatters[] = {
    format_qppe_ac_grp_cfg,
    format_qppe_ac_unicast_queue_cfg,
    format_qppe_ac_multicast_queue_cfg,
    format_qppe_ac_grp_cnt,
    format_qppe_ac_unicast_queue_cnt,
    format_qppe_ac_multicast_queue_cnt,
    format_qppe_ac_grp_drop_state,
    format_qppe_ac_unicast_queue_drop_state,
    format_qppe_ac_multicast_queue_drop_state,
    format_qppe_ac_mseq,
  };

  return qppe_cli_show (vm, input, formatters, ARRAY_LEN (formatters));
}

VLIB_CLI_COMMAND (show_qppe_ac_cmd, static) = {
  .path = "show qppe ac",
  .short_help = "show qppe ac",
  .function = show_qppe_ac_cmd_fn,
  .is_mp_safe = 1,
};

static clib_error_t *
show_qppe_rss_cmd_fn (vlib_main_t *vm, unformat_input_t *input,
		      __clib_unused vlib_cli_command_t *cmd)
{
  format_function_t *const formatters[] = {
    format_qppe_rss_cfg,
  };

  return qppe_cli_show (vm, input, formatters, ARRAY_LEN (formatters));
}

VLIB_CLI_COMMAND (show_qppe_rss_cmd, static) = {
  .path = "show qppe rss",
  .short_help = "show qppe rss",
  .function = show_qppe_rss_cmd_fn,
  .is_mp_safe = 1,
};

static clib_error_t *
show_qppe_qm_cmd_fn (vlib_main_t *vm, unformat_input_t *input,
		     __clib_unused vlib_cli_command_t *cmd)
{
  format_function_t *const formatters[] = {
    format_qppe_qm_cfg,
    format_qppe_ucast_queue_map_tbl,
    format_qppe_qm_ucast_hash_map,
    format_qppe_ucast_priority_map,
    format_qppe_mcast_priority_map,
    format_qppe_mcast_queue_map,
    format_qppe_qm_aggregation,
    format_qppe_enq_deq_opr,
    format_qppe_qm_unicast_head,
    format_qppe_qm_multicast_head,
  };

  return qppe_cli_show (vm, input, formatters, ARRAY_LEN (formatters));
}

VLIB_CLI_COMMAND (show_qppe_qm_cmd, static) = {
  .path = "show qppe qm",
  .short_help = "show qppe qm",
  .function = show_qppe_qm_cmd_fn,
  .is_mp_safe = 1,
};

static clib_error_t *
show_qppe_qm_memory_cmd_fn (vlib_main_t *vm, unformat_input_t *input,
			    __clib_unused vlib_cli_command_t *cmd)
{
  format_function_t *const formatters[] = {
    format_qppe_qm_unicast_links,
    format_qppe_qm_multicast_links,
    format_qppe_qm_packet_descriptors,
  };

  return qppe_cli_show (vm, input, formatters, ARRAY_LEN (formatters));
}

VLIB_CLI_COMMAND (show_qppe_qm_memory_cmd, static) = {
  .path = "show qppe qm memory",
  .short_help = "show qppe qm memory",
  .function = show_qppe_qm_memory_cmd_fn,
  .is_mp_safe = 1,
};

static clib_error_t *
show_qppe_mac_cmd_fn (vlib_main_t *vm, unformat_input_t *input,
		      __clib_unused vlib_cli_command_t *cmd)
{
  format_function_t *const formatters[] = {
    format_qppe_mac_cfg,
    format_qppe_mac_addresses,
  };

  return qppe_cli_show (vm, input, formatters, ARRAY_LEN (formatters));
}

VLIB_CLI_COMMAND (show_qppe_mac_cmd, static) = {
  .path = "show qppe mac",
  .short_help = "show qppe mac",
  .function = show_qppe_mac_cmd_fn,
  .is_mp_safe = 1,
};

static clib_error_t *
show_qppe_port_cmd_fn (vlib_main_t *vm, unformat_input_t *input,
		       __clib_unused vlib_cli_command_t *cmd)
{
  format_function_t *const formatters[] = {
    format_qppe_port_cfg,
    format_qppe_port_my_mac_tbl,
    format_qppe_port_forward_fifo,
    format_qppe_port_mru_mtu_ctrl_tbl,
    format_qppe_port_mc_mtu_ctrl_tbl,
    format_qppe_port_tdm,
  };

  return qppe_cli_show (vm, input, formatters, ARRAY_LEN (formatters));
}

VLIB_CLI_COMMAND (show_qppe_port_cmd, static) = {
  .path = "show qppe port",
  .short_help = "show qppe port",
  .function = show_qppe_port_cmd_fn,
  .is_mp_safe = 1,
};

static clib_error_t *
show_qppe_sched_cmd_fn (vlib_main_t *vm, unformat_input_t *input,
			__clib_unused vlib_cli_command_t *cmd)
{
  format_function_t *const formatters[] = {
    format_qppe_sched_cfg,
    format_qppe_sched_tables,
  };

  return qppe_cli_show (vm, input, formatters, ARRAY_LEN (formatters));
}

VLIB_CLI_COMMAND (show_qppe_sched_cmd, static) = {
  .path = "show qppe sched",
  .short_help = "show qppe sched",
  .function = show_qppe_sched_cmd_fn,
  .is_mp_safe = 1,
};

static clib_error_t *
show_qppe_sched_memory_cmd_fn (vlib_main_t *vm, unformat_input_t *input,
			       __clib_unused vlib_cli_command_t *cmd)
{
  format_function_t *const formatters[] = {
    format_qppe_sched_memory,
  };

  return qppe_cli_show (vm, input, formatters, ARRAY_LEN (formatters));
}

VLIB_CLI_COMMAND (show_qppe_sched_memory_cmd, static) = {
  .path = "show qppe sched memory",
  .short_help = "show qppe sched memory",
  .function = show_qppe_sched_memory_cmd_fn,
  .is_mp_safe = 1,
};
