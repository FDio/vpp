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

#endif /* included_mlx5_cmdq_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
