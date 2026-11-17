/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Damjan Marion
 */

#pragma once

#include <vppinfra/clib.h>

struct mlx5_ifc_rqc_bits
{
  u8 reserved_at_0[0x8];
  u8 state[0x4];
  u8 reserved_at_c[0x54];
  u8 counter_set_id[0x8];
  u8 reserved_at_68[0x718];
};

struct mlx5_ifc_modify_rq_in_bits
{
  u8 opcode[0x10];
  u8 uid[0x10];
  u8 reserved_at_20[0x10];
  u8 op_mod[0x10];
  u8 rq_state[0x4];
  u8 reserved_at_44[0x4];
  u8 rqn[0x18];
  u8 reserved_at_60[0x20];
  u8 modify_bitmask[0x40];
  u8 reserved_at_c0[0x40];
  struct mlx5_ifc_rqc_bits ctx;
};

struct mlx5_ifc_modify_rq_out_bits
{
  u8 status[0x8];
  u8 reserved_at_8[0x18];
  u8 syndrome[0x20];
  u8 reserved_at_40[0x40];
};

struct mlx5_ifc_alloc_q_counter_in_bits
{
  u8 opcode[0x10];
  u8 uid[0x10];
  u8 reserved_at_20[0x10];
  u8 op_mod[0x10];
  u8 reserved_at_40[0x40];
};

struct mlx5_ifc_alloc_q_counter_out_bits
{
  u8 status[0x8];
  u8 reserved_at_8[0x18];
  u8 syndrome[0x20];
  u8 reserved_at_40[0x18];
  u8 counter_set_id[0x8];
  u8 reserved_at_60[0x20];
};

struct mlx5_ifc_vnic_diagnostic_statistics_bits
{
  u8 counter_error_queues[0x20];
  u8 total_error_queues[0x20];
  u8 send_queue_priority_update_flow[0x20];
  u8 reserved_at_60[0x20];
  u8 nic_receive_steering_discard[0x40];
  u8 receive_discard_vport_down[0x40];
  u8 transmit_discard_vport_down[0x40];
  u8 async_eq_overrun[0x20];
  u8 comp_eq_overrun[0x20];
  u8 reserved_at_180[0x20];
  u8 invalid_command[0x20];
  u8 quota_exceeded_command[0x20];
  u8 internal_rq_out_of_buffer[0x20];
  u8 cq_overrun[0x20];
  u8 eth_wqe_too_small[0x20];
  u8 reserved_at_220[0xc0];
  u8 generated_pkt_steering_fail[0x40];
  u8 handled_pkt_steering_fail[0x40];
  u8 reserved_at_360[0xc80];
};

struct mlx5_ifc_query_vnic_env_out_bits
{
  u8 status[0x8];
  u8 reserved_at_8[0x18];
  u8 syndrome[0x20];
  u8 reserved_at_40[0x40];
  struct mlx5_ifc_vnic_diagnostic_statistics_bits vport_env;
};

struct mlx5_ifc_query_vnic_env_in_bits
{
  u8 opcode[0x10];
  u8 reserved_at_10[0x10];
  u8 reserved_at_20[0x10];
  u8 op_mod[0x10];
  u8 other_vport[0x1];
  u8 reserved_at_41[0xf];
  u8 vport_number[0x10];
  u8 reserved_at_60[0x20];
};

struct mlx5_ifc_query_q_counter_in_bits
{
  u8 opcode[0x10];
  u8 reserved_at_10[0x10];
  u8 reserved_at_20[0x10];
  u8 op_mod[0x10];
  u8 other_vport[0x1];
  u8 reserved_at_41[0xf];
  u8 vport_number[0x10];
  u8 reserved_at_60[0x60];
  u8 clear[0x1];
  u8 aggregate[0x1];
  u8 reserved_at_c2[0x1e];
  u8 reserved_at_e0[0x18];
  u8 counter_set_id[0x8];
};

struct mlx5_ifc_query_q_counter_out_bits
{
  u8 status[0x8];
  u8 reserved_at_8[0x18];
  u8 syndrome[0x20];
  u8 reserved_at_40[0x40];
  u8 rx_write_requests[0x20];
  u8 reserved_at_a0[0x20];
  u8 rx_read_requests[0x20];
  u8 reserved_at_e0[0x20];
  u8 rx_atomic_requests[0x20];
  u8 reserved_at_120[0x20];
  u8 rx_dct_connect[0x20];
  u8 reserved_at_160[0x20];
  u8 out_of_buffer[0x20];
  u8 reserved_at_1a0[0x20];
  u8 out_of_sequence[0x20];
  u8 reserved_at_1e0[0x20];
  u8 duplicate_request[0x20];
  u8 reserved_at_220[0x20];
  u8 rnr_nak_retry_err[0x20];
  u8 reserved_at_260[0x20];
  u8 packet_seq_err[0x20];
  u8 reserved_at_2a0[0x20];
  u8 implied_nak_seq_err[0x20];
  u8 reserved_at_2e0[0x20];
  u8 local_ack_timeout_err[0x20];
  u8 reserved_at_320[0x60];
  u8 req_rnr_retries_exceeded[0x20];
  u8 reserved_at_3a0[0x20];
  u8 resp_local_length_error[0x20];
  u8 req_local_length_error[0x20];
  u8 resp_local_qp_error[0x20];
  u8 local_operation_error[0x20];
  u8 resp_local_protection[0x20];
  u8 req_local_protection[0x20];
  u8 resp_cqe_error[0x20];
  u8 req_cqe_error[0x20];
  u8 req_mw_binding[0x20];
  u8 req_bad_response[0x20];
  u8 req_remote_invalid_request[0x20];
  u8 resp_remote_invalid_request[0x20];
  u8 req_remote_access_errors[0x20];
  u8 resp_remote_access_errors[0x20];
  u8 req_remote_operation_errors[0x20];
  u8 req_transport_retries_exceeded[0x20];
  u8 cq_overflow[0x20];
  u8 resp_cqe_flush_error[0x20];
  u8 req_cqe_flush_error[0x20];
  u8 reserved_at_620[0x20];
  u8 roce_adp_retrans[0x20];
  u8 roce_adp_retrans_to[0x20];
  u8 roce_slow_restart[0x20];
  u8 roce_slow_restart_cnps[0x20];
  u8 roce_slow_restart_trans[0x20];
  u8 reserved_at_6e0[0x120];
};

enum
{
  MLX5_CMD_OP_QUERY_HCA_CAP = 0x100,
  MLX5_HCA_CAP_OP_MOD_GENERAL_DEVICE_CUR = 0x1,
};

struct mlx5_ifc_cmd_hca_cap_bits
{
  u8 reserved_at_0[0x290];
  u8 max_wqe_sz_sq[0x10];
  u8 reserved_at_2a0[0x7d60];
};

struct mlx5_ifc_query_hca_cap_out_bits
{
  u8 status[0x8];
  u8 reserved_at_8[0x18];
  u8 syndrome[0x20];
  u8 reserved_at_40[0x40];
  struct mlx5_ifc_cmd_hca_cap_bits capability;
};

struct mlx5_ifc_query_hca_cap_in_bits
{
  u8 opcode[0x10];
  u8 reserved_at_10[0x10];
  u8 reserved_at_20[0x10];
  u8 op_mod[0x10];
  u8 other_function[0x1];
  u8 reserved_at_41[0xf];
  u8 function_id[0x10];
  u8 reserved_at_60[0x20];
};
