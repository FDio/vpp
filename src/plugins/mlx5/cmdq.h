/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef included_mlx5_cmdq_h
#define included_mlx5_cmdq_h

typedef struct
{
  void *entry;
  volatile void *hca;
  u8 *in;
  u8 *out;
  u8 slot;
  /* lock */
  int in_use;
} mlx5_cmdq_t;

typedef struct
{
  u8 state;
  u8 admin_state;
  u16 max_tx_speed;
} mlx5_nic_vport_state_t;

enum
{
  MLX5_HCA_CAP_TYPE_DEVICE = 0,
  MLX5_HCA_CAP_TYPE_NET_OFFLOAD = 1,
  MLX5_HCA_CAP_TYPE_QOS = 0xC,
};
typedef enum
{
  MLX5_REG_RW_WRITE = 0,
  MLX5_REG_RW_READ = 1,
} mlx5_reg_rw_t;



static inline u32 mlx5_get_bits (void *start, int offset, int first,
				 int last);
static inline void mlx5_set_bits (void *start, int offset, int first,
				  int last, u32 value);

clib_error_t *mlx5_cmd_query_hca_cap (mlx5_cmdq_t * cmdq, int is_current,
				      u8 type, u8 * data);
clib_error_t *mlx5_cmd_init_hca (mlx5_cmdq_t * cmdq);
clib_error_t *mlx5_cmd_enable_hca (mlx5_cmdq_t * cmdq);
clib_error_t *mlx5_cmd_query_pages (mlx5_cmdq_t * cmdq, u16 type,
				    u32 * num_pages);
clib_error_t *mlx5_cmd_manage_pages (mlx5_cmdq_t * cmdq, i32 num_pages);
clib_error_t *mlx5_cmd_set_hca_cap (mlx5_cmdq_t * cmdq, u8 type, u8 * data);

/* issi */
clib_error_t *mlx5_cmd_query_issi (mlx5_cmdq_t * cmdq, u16 * current_issi,
				   u32 * supported_issi);
clib_error_t *mlx5_cmd_set_issi (mlx5_cmdq_t * cmdq, u16 current_issi);
clib_error_t *mlx5_cmd_query_special_contexts (mlx5_cmdq_t * cmdq,
					       u32 * resd_lkey,
					       u32 * null_mkey);

/* eq */
clib_error_t *mlx5_cmd_create_eq (mlx5_cmdq_t * cmdq, u8 * eqn, void *ctx,
				  u64 bitmask, void *physmem, int num_pages);
clib_error_t *mlx5_cmd_query_eq (mlx5_cmdq_t * cmdq, u8 eqn, u8 * ctx,
				 u64 * bitmask);
clib_error_t *mlx5_cmd_gen_eqe (mlx5_cmdq_t * cmdq, u8 eqn, u8 type,
				u8 sub_type);

/* cq */
clib_error_t *mlx5_cmd_create_cq (mlx5_cmdq_t * cmdq, u32 * cq, void *ctx,
				  void *physmem, int num_pages);
clib_error_t *mlx5_cmd_destroy_cq (mlx5_cmdq_t * cmdq, u32 cqn);
clib_error_t *mlx5_cmd_query_cq (mlx5_cmdq_t * cmdq, u32 cqn, u8 * ctx);

/* nic vport */
clib_error_t *mlx5_cmd_query_nic_vport_state (mlx5_cmdq_t * cmdq,
					      mlx5_nic_vport_state_t * state);
clib_error_t *mlx5_cmd_modify_nic_vport_state (mlx5_cmdq_t * cmdq, u8 state);
clib_error_t *mlx5_cmd_query_nic_vport_context (mlx5_cmdq_t * cmdq, u8 * ctx);

/* q counter */
#define foreach_mlx5_q_counter \
  _(0x10, rx_write_requests)			\
  _(0x18, rx_read_requests)			\
  _(0x20, rx_atomic_requests)			\
  _(0x28, rx_dct_connect)			\
  _(0x30, out_of_buffer)			\
  _(0x38, out_of_sequence)			\
  _(0x40, duplicate_request)			\
  _(0x48, rnr_nak_retry_err)			\
  _(0x50, packet_seq_err)			\
  _(0x58, implied_nak_seq_err)			\
  _(0x60, local_ack_timeout_err)		\
  _(0x78, resp_local_length_error)		\
  _(0x7c, req_local_length_error)		\
  _(0x80, resp_local_qp_error)			\
  _(0x84, local_operation_error)		\
  _(0x88, resp_local_protection)		\
  _(0x8c, req_local_protection)			\
  _(0x90, resp_cqe_error)			\
  _(0x94, req_cqe_error)			\
  _(0x98, req_mw_binding)			\
  _(0x9c, req_bad_response)			\
  _(0xa0, req_remote_invalid_request)		\
  _(0xa4, resp_remote_invalid_request)		\
  _(0xa8, req_remote_access_errors)		\
  _(0xac, resp_remote_access_errors)		\
  _(0xb0, req_remote_operation_errors)		\
  _(0xb4, req_transport_retries_exceeded)	\
  _(0xb8, cq_overflow)				\
  _(0xbc, resp_cqe_flush_error)			\
  _(0xc0, req_cqe_flush_error)			\

typedef struct
{
#define _(a, b) u32 b;
  foreach_mlx5_q_counter
#undef _
} mlx5_q_counter_t;

clib_error_t *mlx5_cmd_alloc_q_counter (mlx5_cmdq_t * cmdq,
					u8 * counter_set_id);
clib_error_t *mlx5_cmd_dealloc_q_counter (mlx5_cmdq_t * cmdq,
					  u8 counter_set_id);
clib_error_t *mlx5_cmd_query_q_counter (mlx5_cmdq_t * cmdq, u8 counter_set_id,
					int clear, mlx5_q_counter_t * cnt);

/* pd, uar, td */
clib_error_t *mlx5_cmd_alloc_pd (mlx5_cmdq_t * cmdq, u32 * pd);
clib_error_t *mlx5_cmd_alloc_uar (mlx5_cmdq_t * cmdq, u32 * uar);
clib_error_t *mlx5_cmd_access_register (mlx5_cmdq_t * cmdq, mlx5_reg_rw_t rw,
					u16 register_id, u32 argument,
					u8 * data);
clib_error_t *mlx5_cmd_alloc_transport_domain (mlx5_cmdq_t * cmdq, u32 * td);

/* sq */
clib_error_t *mlx5_cmd_create_sq (mlx5_cmdq_t * cmdq, u32 * sqn, void *sq_ctx,
				  void *wq_ctx, void *physmem, int num_pages);
clib_error_t *mlx5_cmd_modify_sq (mlx5_cmdq_t * cmdq, u32 sqn, u8 state);
clib_error_t *mlx5_cmd_destroy_sq (mlx5_cmdq_t * cmdq, u32 sqn);
clib_error_t *mlx5_cmd_query_sq (mlx5_cmdq_t * cmdq, u32 sqn, u8 * sq_ctx,
				 u8 * wq_ctx);

/* tir */
clib_error_t *mlx5_cmd_create_tir (mlx5_cmdq_t * cmdq, u32 * tirn, void *ctx);

/* rq */
clib_error_t *mlx5_cmd_create_rq (mlx5_cmdq_t * cmdq, u32 * rqn, void *rq_ctx,
				  void *wq_ctx, void *physmem, int num_pages);
clib_error_t *mlx5_cmd_modify_rq (mlx5_cmdq_t * cmdq, u32 rqn, u8 state);
clib_error_t *mlx5_cmd_destroy_rq (mlx5_cmdq_t * cmdq, u32 rqn);
clib_error_t *mlx5_cmd_query_rq (mlx5_cmdq_t * cmdq, u32 rqn, u8 * rq_ctx,
				 u8 * wq_ctx);

/* tis */
clib_error_t *mlx5_cmd_create_tis (mlx5_cmdq_t * cmdq, u8 prio, u32 td,
				   u32 * tisn);

/* rqtn */
clib_error_t *mlx5_cmd_create_rqt (mlx5_cmdq_t * cmdq, u32 * rqtn, void *ctx);

/* flow table */
clib_error_t *mlx5_cmd_create_flow_table (mlx5_cmdq_t * cmdq, u8 table_type,
					  void *ctx, u32 * table_id);
clib_error_t *mlx5_cmd_destroy_flow_table (mlx5_cmdq_t * cmdq, u8 table_type,
					   u32 table_id);
clib_error_t *mlx5_cmd_set_flow_table_root (mlx5_cmdq_t * cmdq, u8 table_type,
					    u32 table_id);
clib_error_t *mlx5_cmd_create_flow_group (mlx5_cmdq_t * cmdq, u8 table_type,
					  u32 table_id, u32 start_flow_index,
					  u32 end_flow_index,
					  u8 match_criteria_enable,
					  u8 * match_criteria,
					  u32 * group_id);
clib_error_t *mlx5_cmd_set_flow_table_entry (mlx5_cmdq_t * cmdq,
					     u8 table_type, u32 table_id,
					     u8 modify_enable_mask,
					     u32 flow_index, u8 * ctx);

clib_error_t *mlx5_cmd_alloc_flow_counter (mlx5_cmdq_t * cmdq,
					   u16 * flow_counter_id);
clib_error_t *mlx5_cmd_dealloc_flow_counter (mlx5_cmdq_t * cmdq,
					     u16 flow_counter_id);
clib_error_t *mlx5_cmd_query_flow_counter (mlx5_cmdq_t * cmdq,
					   u16 flow_counter_id,
					   u16 num_of_counters, int clear,
					   u8 * counters);
#endif /* included_mlx5_cmdq_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
