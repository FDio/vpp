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

#ifndef included_mlx5_fields_h
#define included_mlx5_fields_h

/*
 *  QUERY_HCA_CAP general Device capabilites fields
 */

#define MLX5_HCA_CAP_SZ 0x1000
#define foreach_hca_general_dev_cap \
  _(0x00, 31, 31, access_other_hca_roce)	\
  _(0x10, 31, 24, log_max_srq_sz)		\
  _(0x10, 23, 16, log_max_qp_sz)		\
  _(0x10,  4,  0, log_max_qp)			\
  _(0x14, 20, 16, log_max_srq)			\
  _(0x18, 23, 16, log_max_cq_sz)		\
  _(0x18,  4,  0, log_max_cq)			\
  _(0x1c, 31, 24, log_max_eq_sz)		\
  _(0x1c, 21, 16, log_max_mkey)			\
  _(0x1c,  3,  0, log_max_eq)			\
  _(0x20, 31, 24, max_indirection)		\
  _(0x20, 23, 23, fixed_buffer_size)		\
  _(0x20, 22, 16, log_max_mrw_sz)		\
  _(0x20, 15, 15, panic_teardown)		\
  _(0x20, 13,  8, log_max_bsf_list_size)	\
  _(0x20,  7,  7, umr_extended_translation_offset)\
  _(0x20,  6,  6, null_mkey)			\
  _(0x20,  5,  0, log_max_klm_list_size)	\
  _(0x24, 21, 16, log_max_ra_req_dc)		\
  _(0x24,  5,  0, log_max_ra_res_dc)		\
  _(0x28, 21, 16, log_max_ra_req_qp)		\
  _(0x28,  5,  0, log_max_ra_res_qp)		\
  _(0x2c, 31, 31, end_pad)			\
  _(0x2c, 30, 30, cc_query_allowed)		\
  _(0x2c, 29, 29, cc_modify_allowed)		\
  _(0x2c, 28, 28, start_pad)			\
  _(0x2c, 27, 27, cache_line_128byte)		\
  _(0x2c, 16, 16, qcam_reg)			\
  _(0x2c, 15,  0, gid_table_size)		\
  _(0x30, 31, 31, out_of_seq_cnt)		\
  _(0x30, 30, 30, vport_counters)		\
  _(0x30, 29, 29, retransmission_q_counters)	\
  _(0x30, 27, 27, modify_rq_counter_set_id)	\
  _(0x30, 26, 26, rq_delay_drop)		\
  _(0x30, 25, 16, max_qp_cnt)			\
  _(0x30, 15,  0, pkey_table_size)		\
  _(0x34, 31, 31, vport_group_manager)		\
  _(0x34, 30, 30, vhca_group_manager)		\
  _(0x34, 29, 29, ib_virt)			\
  _(0x34, 28, 28, eth_virt)			\
  _(0x34, 26, 26, ets)				\
  _(0x34, 25, 25, nic_flow_table)		\
  _(0x34, 24, 24, eswitch_flow_table)		\
  _(0x34, 23, 23, early_vf_enable)		\
  _(0x34, 22, 22, mcam_reg)			\
  _(0x34, 21, 21, pcam_reg)			\
  _(0x34, 20, 16, local_ca_ack_delay)		\
  _(0x34, 15, 15, port_module_event)		\
  _(0x34, 14, 14, enhanced_error_q_counters)	\
  _(0x34, 13, 13, ports_check)			\
  _(0x34, 11, 11, disable_link_up)		\
  _(0x34, 10, 10, beacon_led)			\
  _(0x34,  9,  8, port_type)			\
  _(0x34,  7,  0, num_ports)			\
  _(0x38, 30, 30, pps)				\
  _(0x38, 29, 29, pps_modify)			\
  _(0x38, 28, 24, log_max_msg)			\
  _(0x38, 23, 23, multipath_xrc_qp)		\
  _(0x38, 22, 22, multipath_dc_qp)		\
  _(0x38, 21, 21, multipath_rc_qp)		\
  _(0x38, 19, 16, max_tc)			\
  _(0x38, 14, 14, dcbx)				\
  _(0x38, 13, 13, general_notification_event)	\
  _(0x38,  9,  9, rol_s)			\
  _(0x38,  8,  8, rol_g)			\
  _(0x38,  6,  6, wol_s)			\
  _(0x38,  5,  5, wol_g)			\
  _(0x38,  4,  4, wol_a)			\
  _(0x38,  3,  3, wol_b)			\
  _(0x38,  2,  2, wol_m)			\
  _(0x38,  1,  1, wol_u)			\
  _(0x38,  0,  0, wol_p)			\
  _(0x3c, 31, 16, stat_rate_support)		\
  _(0x3c,  3,  0, cqe_version)			\
  _(0x40, 31, 31, compact_address_vector)	\
  _(0x40, 30, 30, striding_rq)			\
  _(0x40, 28, 28, ipoib_enhanced_offloads)	\
  _(0x40, 27, 27, ipoib_basic_offloads)		\
  _(0x40, 21, 20, umr_fence)			\
  _(0x40, 19, 19, dc_req_scat_data_cqe)		\
  _(0x40, 18, 18, dc_connect_qp)		\
  _(0x40, 17, 17, dc_cnak_trace)		\
  _(0x40, 16, 16, drain_sigerr)			\
  _(0x40, 15, 14, cmdif_checksum)		\
  _(0x40, 13, 13, sigerr_cqe)			\
  _(0x40, 11, 11, wq_signature)			\
  _(0x40, 10, 10, sctr_data_cqe)		\
  _(0x40,  8,  8, sho)				\
  _(0x40,  7,  7, tph)				\
  _(0x40,  6,  6, rf)				\
  _(0x40,  5,  5, dct)				\
  _(0x40,  4,  4, qos)				\
  _(0x40,  3,  3, eth_net_offloads)		\
  _(0x40,  2,  2, roce)				\
  _(0x40,  1,  1, atomic)			\
  _(0x40,  0,  0, extended_retry_count)		\
  _(0x44, 31, 31, cq_oi)			\
  _(0x44, 30, 30, cq_resize)			\
  _(0x44, 29, 29, cq_moderation)		\
  _(0x44, 25, 25, cq_eq_remap)			\
  _(0x44, 24, 24, pg)				\
  _(0x44, 23, 23, block_lb_mc)			\
  _(0x44, 21, 21, scqe_break_moderation)	\
  _(0x44, 20, 20, cq_period_start_from_cqe)	\
  _(0x44, 19, 19, cd)				\
  _(0x44, 17, 17, apm)				\
  _(0x44, 16, 16, vector_calc)			\
  _(0x44, 15, 15, umr_ptr_rlky)			\
  _(0x44, 14, 14, imaicl)			\
  _(0x44,  9,  9, qkv)				\
  _(0x44,  8,  8, pkv)				\
  _(0x44,  7,  7, set_deth_sqpn)		\
  _(0x44,  3,  3, xrc)				\
  _(0x44,  2,  2, ud)				\
  _(0x44,  1,  1, uc)				\
  _(0x44,  0,  0, rc)				\
  _(0x48, 31, 31, uar_4k)			\
  _(0x48, 21, 16, uar_sz)			\
  _(0x48,  7,  0, log_pg_sz)			\
  _(0x4c, 31, 31, bf)				\
  _(0x4c, 30, 30, driver_version)		\
  _(0x4c, 29, 29, pad_tx_eth_packet)		\
  _(0x4c, 20, 16, log_bf_reg_size)		\
  _(0x4c,  4,  4, lag_master)			\
  _(0x4c,  3,  0, num_lag_ports)		\
  _(0x50, 15,  0, max_wqe_sz_sq)		\
  _(0x54, 15,  0, max_wqe_sz_rq)		\
  _(0x58, 15,  0, max_wqe_sz_sq_dc)		\
  _(0x5c, 24,  0, max_qp_mcg)			\
  _(0x60,  7,  0, log_max_mcg)			\
  _(0x64, 28, 24, log_max_transport_domain)	\
  _(0x64, 20, 16, log_max_pd)			\
  _(0x64,  4,  0, log_max_xrcd)			\
  _(0x68, 23, 16, log_max_flow_counter_bulk)	\
  _(0x68, 15,  0, max_flow_counter)		\
  _(0x6c, 31, 31, modify_tis)			\
  _(0x6c, 28, 24, log_max_rq)			\
  _(0x6c, 20, 16, log_max_sq)			\
  _(0x6c, 12,  8, log_max_tir)			\
  _(0x6c,  4,  0, log_max_tis)			\
  _(0x70, 31, 31, basic_cyclic_rcv_wqe)		\
  _(0x70, 28, 24, log_max_rmp)			\
  _(0x70, 20, 16, log_max_rqt)			\
  _(0x70, 12,  8, log_max_rqt_size)		\
  _(0x70,  4,  0, log_max_tis_per_sq)		\
  _(0x74, 28, 24, log_max_stride_sz_rq)		\
  _(0x74, 20, 16, log_min_stride_sz_rq)		\
  _(0x74, 12,  8, log_max_stride_sz_sq)		\
  _(0x74,  4,  0, log_min_stride_sz_sq)		\
  _(0x78,  4,  0, log_max_wq_sz)		\
  _(0x7c, 31, 31, nic_vport_change_event)	\
  _(0x7c, 30, 30, disable_local_lb)		\
  _(0x7c, 20, 16, log_max_vlan_list)		\
  _(0x7c, 12,  8, log_max_current_mc_list)	\
  _(0x7c,  4,  0, log_max_current_uc_list)	\
  _(0x90, 28, 24, log_max_l2_table)		\
  _(0x90, 15,  0, log_uar_page_sz)		\
  _(0x98, 31,  0, device_frequency_mhz)		\
  _(0x9c, 31,  0, device_frequency_khz)		\
  _(0xa0, 29, 29, nvmf_target_offload)		\
  _(0xa4, 31,  0, num_of_uars_per_page)		\
  _(0xac, 12,  8, log_max_guaranteed_connections)\
  _(0xac,  4,  0, log_max_dct_connections)	\
  _(0xb4,  0,  0, cqe_compression)		\
  _(0xb8, 31, 16, cqe_compression_timeout)	\
  _(0xb8, 15,  0, cqe_compression_max_num)	\
  _(0xbc, 19, 16, log_max_tm_offloaded_op_size)	\
  _(0xbc, 15, 15, tag_matching)			\
  _(0xbc, 14, 14, rndv_offload_rc)		\
  _(0xbc, 13, 13, rndv_offload_dc)		\
  _(0xbc, 12,  8, log_tag_matching_list_sz)	\
  _(0xbc,  4,  0, log_max_xrq)

#define _(a, b, c, d) \
  static inline void mlx5_set_hca_cap_##d (void * p, u32 val) \
{ mlx5_set_bits (p, a, b, c, val); }
foreach_hca_general_dev_cap
#undef _
#define foreach_hca_net_offload_cap \
  _(0x00, 31, 31, csum_cap)			\
  _(0x00, 30, 30, vlan_cap)			\
  _(0x00, 29, 29, lro_cap)			\
  _(0x00, 28, 28, lro_psh_flag)			\
  _(0x00, 27, 27, lro_time_stamp)		\
  _(0x00, 26, 25, lro_max_msg_sz_mode)		\
  _(0x00, 24, 24, wqe_vlan_insert)		\
  _(0x00, 23, 23, self_lb_en_modifiable)	\
  _(0x00, 22, 22, self_lb_mc)			\
  _(0x00, 21, 21, self_lb_uc)			\
  _(0x00, 20, 16, max_lso_cap)			\
  _(0x00, 15, 14, multi_pkt_send_wqe)		\
  _(0x00, 13, 12, wqe_inline_mode)		\
  _(0x00, 11, 8, rss_ind_tbl_cap)		\
  _(0x00, 7, 7, reg_umr_sq)			\
  _(0x00, 6, 6, scatter_fcs)			\
  _(0x00, 5, 5, enhanced_multi_pkt_send_wqe)	\
  _(0x00, 4, 4, tunnel_lso_const_out_ip_id)	\
  _(0x00, 1, 1, tunnel_statless_gre)		\
  _(0x00, 0, 0, tunnel_stateless_vxlan)		\
  _(0x04, 31, 31, swp)				\
  _(0x04, 30, 30, swp_csum)			\
  _(0x04, 29, 29, swp_lso)			\
  _(0x08, 15, 0, lro_min_mss_size)		\
  _(0x30, 31, 0, lro_timer_supported_periods_0)	\
  _(0x34, 31, 0, lro_timer_supported_periods_1)	\
  _(0x38, 31, 0, lro_timer_supported_periods_2)	\
  _(0x3c, 31, 0, lro_timer_supported_periods_3)
#define foreach_hca_qos_cap \
  _(0x00, 31, 31, packet_pacing)		\
  _(0x00, 30, 30, esw_scheduling)		\
  _(0x00, 29, 29, esw_bw_share)			\
  _(0x00, 28, 28, esw_rate_limit)		\
  _(0x00, 27, 27, hll)				\
  _(0x00, 26, 26, packet_pacing_burst_bound)	\
  _(0x08, 31, 0, packet_pacing_max_rate)	\
  _(0x0c, 31, 0, packet_pacing_min_rate)	\
  _(0x10, 15, 0, packet_pacing_rate_table_size)	\
  _(0x14, 31, 16, esw_element_type)		\
  _(0x14, 15, 0, esw_tsar_type)			\
  _(0x18, 15, 0, max_qos_para_vport)		\
  _(0x1c, 31, 0, max_tsar_bw_share)


#define MLX5_NIC_VPORT_CTX_SZ 0x100
#define foreach_nic_vport_ctx_field \
  _(0x00, 31, 31, multi_prio_sq)			\
  _(0x00, 26, 24, min_wqe_inline_mode)			\
  _(0x00,  2,  2, disable_mc_local_lb)			\
  _(0x00,  1,  1, disable_uc_local_lb)			\
  _(0x00,  0,  0, roce_en)				\
  _(0x04, 31, 31, arm_change_event)			\
  _(0x04,  4,  4, event_on_mtu)				\
  _(0x04,  3,  3, event_on_promisc_change)		\
  _(0x04,  2,  2, event_on_vlan_change)			\
  _(0x04,  1,  1, event_on_mc_address_change)		\
  _(0x04,  0,  0, event_on_uc_address_change)		\
  _(0x24, 15,  0, mtu)					\
  _(0x28, 63,  0, system_image_guid)			\
  _(0x30, 63,  0, port_guid)				\
  _(0x38, 63,  0, node_guid)				\
  _(0x68, 31, 16, qkey_violation_counter)		\
  _(0xf0, 31, 31, promisc_uc)				\
  _(0xf0, 30, 30, promisc_mc)				\
  _(0xf0, 29, 29, promisc_all)				\
  _(0xf0, 26, 24, allowed_list_type)			\
  _(0xf0, 11,  0, allowed_list_size)			\
  _(0xf0, 63,  0, permanent_address)
#define _(a, b, c, d) \
  static inline void mlx5_set_nic_vport_ctx_field_##d (void * p, u32 val)  \
    { mlx5_set_bits (p, a, b, c, val); } \
  static inline u32 mlx5_get_nic_vport_ctx_field_##d (void * p)  \
    { return mlx5_get_bits (p, a, b, c); }
  foreach_nic_vport_ctx_field
#undef _
#define mlx5_set_nic_vport_ctx_field(a, b, c) mlx5_set_nic_vport_ctx_field_##b(a, c)
#define mlx5_get_nic_vport_ctx_field(a, b) mlx5_get_nic_vport_ctx_field_##b(a)
/*
 *  EQ context fields
 */
#define MLX5_EQ_CTX_SZ 0x40
#define foreach_eq_ctx_field \
  _(0x00, 31, 28, status)		\
  _(0x00, 18, 18, ec)			\
  _(0x00, 17, 17, oi)			\
  _(0x00, 11,  8, st)			\
  _(0x0c, 28, 24, log_eq_size)		\
  _(0x0c, 23,  0, uar_page)		\
  _(0x14,  7,  0, intr)			\
  _(0x18, 28, 24, log_page_size)	\
  _(0x28, 23,  0, consumer_counter)	\
  _(0x2c, 23,  0, producer_counter)
#define _(a, b, c, d) \
  static inline void mlx5_set_eq_ctx_field_##d (void * p, u32 val) \
{ mlx5_set_bits (p, a, b, c, val); }
  foreach_eq_ctx_field
#undef _
#define mlx5_set_eq_ctx_field(a, b, c) mlx5_set_eq_ctx_field_##b(a, c)
/*
 *  CQ context fields
 */
#define MLX5_CQ_CTX_SZ 0x40
#define foreach_cq_ctx_field \
  _(0x00, 31, 28, status)				\
  _(0x00, 23, 21, cqe_sz)				\
  _(0x00, 20, 20, cc)					\
  _(0x00, 18, 18, scqe_break_moderation_en)		\
  _(0x00, 17, 17, oi)					\
  _(0x00, 16, 15, cq_period_mode)			\
  _(0x00, 14, 14, cqe_compression_en)			\
  _(0x00, 13, 12, mini_cqe_res_format)			\
  _(0x00, 11,  8, st)					\
  _(0x08, 11,  6, page_offset)				\
  _(0x0c, 28, 24, log_cq_size)				\
  _(0x0c, 23,  0, uar_page)				\
  _(0x10, 27, 16, cq_period)				\
  _(0x10, 15,  0, cq_max_count)				\
  _(0x14,  7,  0, c_eqn)				\
  _(0x18, 28, 24, log_page_size)			\
  _(0x20, 23,  0, last_notified_index)			\
  _(0x24, 23,  0, last_solicit_index)			\
  _(0x28, 23,  0, consumer_counter)			\
  _(0x2c, 23,  0, producer_counter)			\
  _(0x38, 63,  0, dbr_addr)
#define _(a, b, c, d) \
  static inline void mlx5_set_cq_ctx_field_##d (void * p, u32 val) \
{ mlx5_set_bits (p, a, b, c, val); }
  foreach_cq_ctx_field
#undef _
#define mlx5_set_cq_ctx_field(a, b, c) mlx5_set_cq_ctx_field_##b(a, c)
/*
 *  SQ context fields
 */
#define MLX5_SQ_CTX_SZ 0x30
#define foreach_sq_ctx_field \
  _(0x00, 31, 31, rlkey)				\
  _(0x00, 30, 30, cd_master)				\
  _(0x00, 29, 29, fre)					\
  _(0x00, 28, 28, flush_in_error_en)			\
  _(0x00, 27, 27, allow_multi_pkt_send_wqe)		\
  _(0x00, 26, 24, min_wqe_inline_mode)			\
  _(0x00, 23, 20, state)				\
  _(0x00, 19, 19, reg_umr)				\
  _(0x00, 18, 18, allow_swp)			\
  _(0x04, 23,  0, user_index)				\
  _(0x08, 23,  0, cqn)					\
  _(0x1c, 15,  0, packet_pacing_rate_limit_index)	\
  _(0x20, 31, 16, tis_lst_sz)				\
  _(0x2c, 23,  0, tis_num_0)
#define _(a, b, c, d) \
  static inline void mlx5_set_sq_ctx_field_##d (void * p, u32 val) \
{ mlx5_set_bits (p, a, b, c, val); }
  foreach_sq_ctx_field
#undef _
#define mlx5_set_sq_ctx_field(a, b, c) mlx5_set_sq_ctx_field_##b(a, c)
/*
 *  TIR context fields
 */
#define MLX5_TIR_CTX_SZ 240
#define foreach_tir_ctx_field \
  _(0x04, 31, 28, disp_type)				\
  _(0x10, 27, 12, lro_timeout_period_usecs)		\
  _(0x10, 11, 8, lro_enable_mask)			\
  _(0x10, 7, 0, lro_max_ip_payload_size)		\
  _(0x1c, 23, 0, inline_rqn)				\
  _(0x20, 31, 31, rx_hash_symmetric)			\
  _(0x20, 29, 29, tunneled_offload_en)			\
  _(0x20, 23, 0, indirect_table)			\
  _(0x24, 31, 28, rx_hash_fn)				\
  _(0x24, 25, 24, self_lb_block)			\
  _(0x24, 23, 0, transport_domain)
#define _(a, b, c, d) \
  static inline void mlx5_set_tir_ctx_field_##d (void * p, u32 val) \
{ mlx5_set_bits (p, a, b, c, val); }
  foreach_tir_ctx_field
#undef _
#define mlx5_set_tir_ctx_field(a, b, c) mlx5_set_tir_ctx_field_##b(a, c)
/*
 *  RQ context fields
 */
#define MLX5_RQ_CTX_SZ 0x30
#define foreach_rq_ctx_field \
  _(0x00, 31, 31, rlkey)				\
  _(0x00, 30, 30, delay_drop_en)			\
  _(0x00, 29, 29, scatter_fcs)				\
  _(0x00, 28, 28, vlan_strip_disable)			\
  _(0x00, 27, 24, mem_rq_type)				\
  _(0x00, 23, 20, state)				\
  _(0x00, 18, 18, flush_in_error_en)			\
  _(0x04, 23,  0, user_index)				\
  _(0x08, 23,  0, cqn)					\
  _(0x0c, 31, 24, counter_set_id)			\
  _(0x10, 23,  0, rmpn)
#define _(a, b, c, d) \
  static inline void mlx5_set_rq_ctx_field_##d (void * p, u32 val) \
{ mlx5_set_bits (p, a, b, c, val); }
  foreach_rq_ctx_field
#undef _
#define mlx5_set_rq_ctx_field(a, b, c) mlx5_set_rq_ctx_field_##b(a, c)
/*
 *  RQT context fields
 */
#define MLX5_RQT_CTX_SZ 244
/*
 *  WQ context fields
 */
#define MLX5_WQ_CTX_SZ 0xc0
#define foreach_wq_ctx_field \
  _(0x00, 31, 28, wq_type)				\
  _(0x00, 27, 27, wq_signature)				\
  _(0x00, 26, 25, end_padding_mode)			\
  _(0x00, 24, 24, cd_slave)				\
  _(0x04, 31, 31, hds_skip_first_sge)			\
  _(0x04, 30, 28, log2_hds_buf_size)			\
  _(0x04, 20, 16, page_offset)				\
  _(0x04, 15,  0, lwm)					\
  _(0x08, 23,  0, pd)					\
  _(0x0c, 23,  0, uar_page)				\
  _(0x10, 63,  0, dbr_addr)				\
  _(0x18, 31,  0, hw_counter)				\
  _(0x1c, 31,  0, sw_counter)				\
  _(0x20, 19, 16, log_wq_stride)			\
  _(0x20, 12,  8, log_wq_pg_sz)				\
  _(0x20,  4,  0, log_wq_sz)				\
  _(0x24, 10,  0, single_wqe_log_num_of_strides)	\
  _(0x24,  7,  7, two_byte_shift_en)			\
  _(0x24,  2,  0, single_stride_log_num_of_bytes)
#define _(a, b, c, d) \
  static inline void mlx5_set_wq_ctx_field_##d (void * p, u32 val) \
{ mlx5_set_bits (p, a, b, c, val); }
  foreach_wq_ctx_field
#undef _
#define mlx5_set_wq_ctx_field(a, b, c) mlx5_set_wq_ctx_field_##b(a, c)
/*
 *  Flow Table context fields
 */
#define  MLX5_FLOW_TABLE_CTX_SZ 40
  enum
{
  MLX5_FLOW_TABLE_TYPE_NIC_RX = 0,
  MLX5_FLOW_TABLE_TYPE_NIC_TX = 1,
};

#define foreach_flow_table_ctx_field \
  _(0x00, 31, 31, encap_en)			\
  _(0x00, 30, 30, decap_en)			\
  _(0x00, 27, 24, table_miss_action)		\
  _(0x00, 23, 16, level)			\
  _(0x00,  7,  0, log_size)			\
  _(0x04, 23,  0, table_miss_id)		\
  _(0x08, 23,  0, lag_master_next_table_id)

#define _(a, b, c, d) \
  static inline void mlx5_set_flow_table_ctx_field_##d (void * p, u32 val) \
{ mlx5_set_bits (p, a, b, c, val); }
foreach_flow_table_ctx_field
#undef _
#define mlx5_set_flow_table_ctx_field(a, b, c) mlx5_set_flow__ctx_field_##b(a, c)
/*
 *  Flow context fields
 */
#define  MLX5_FLOW_CTX_SZ 0x320
#define foreach_flow_ctx_field \
  _(0x04, 31, 0, group_id)			\
  _(0x08, 23, 0, flow_tag)			\
  _(0x0c, 15, 0, action)			\
  _(0x10, 23, 0, destination_list_size)		\
  _(0x14, 23, 0, flow_counter_list_size)	\
  _(0x18, 31, 0, encap_id)			\
  _(0x1c, 31, 0, modify_header_id)		\
  _(0x300, 31, 24, destination_type_0)		\
  _(0x300, 23, 0, destination_id_0)		\
  _(0x300, 15, 0, flow_counter_id_0)		\
  _(0x308, 31, 24, destination_type_1)		\
  _(0x308, 23, 0, destination_id_1)		\
  _(0x308, 15, 0, flow_counter_id_1)		\
  _(0x310, 31, 24, destination_type_2)		\
  _(0x310, 23, 0, destination_id_2)		\
  _(0x310, 15, 0, flow_counter_id_2)		\
  _(0x318, 31, 24, destination_type_3)		\
  _(0x318, 23, 0, destination_id_3)		\
  _(0x318, 15, 0, flow_counter_id_3)
#define _(a, b, c, d) \
  static inline void mlx5_set_flow_ctx_field_##d (void * p, u32 val) \
{ mlx5_set_bits (p, a, b, c, val); }
  foreach_flow_ctx_field
#undef _
#define mlx5_set_flow_ctx_field(a, b, c) mlx5_set_flow_ctx_field_##b(a, c)
/*
 *  Registers
 */
#define forach_mlx5_register \
  _(0x5003, PMTU,   0x40) \
  _(0x5008, PPCNT, 0x100) \
  _(0x5031, PDDR,  0x100)
  enum
{
#define _(a, b, c) MLX5_REG_##b = a,
  forach_mlx5_register
#undef _
};

static inline int
mlx5_sizeof_reg (u16 r)
{
  switch (r)
    {
#define _(a,b,c) case a: return c;
      forach_mlx5_register
#undef _
    default:
      return 0;
    }
}

/*
 * PPCMT Register
 */
#define foreach_reg_ppcmt_802_3_counter \
  _(0x00, frames_transmitted_ok) \
  _(0x08, frames_received_ok) \
  _(0x10, frame_check_sequence_errors) \
  _(0x18, alignment_errors) \
  _(0x20, octets_transmitted_ok) \
  _(0x28, octets_received_ok) \
  _(0x30, multicast_frames_xmitted_ok) \
  _(0x38, broadcast_frames_xmitted_ok) \
  _(0x40, multicast_frames_received_ok) \
  _(0x48, broadcast_frames_received_ok) \
  _(0x50, in_range_length_errors) \
  _(0x58, out_of_range_length_field) \
  _(0x60, frame_too_long_errors) \
  _(0x68, symbol_error_during_carrier) \
  _(0x70, mac_control_frames_transmitted) \
  _(0x78, mac_control_frames_received) \
  _(0x80, unsupported_opcodes_received) \
  _(0x88, pause_mac_ctrl_frames_received) \
  _(0x90, pause_mac_ctrl_frames_transmitted)

#define foreach_reg_ppcmt_discard_counter \
  _(0x00, ingress_general) \
  _(0x08, ingress_policy_engine) \
  _(0x10, ingress_vlan_membership) \
  _(0x18, ingress_tag_frame_type) \
  _(0x20, egress_vlan_membership) \
  _(0x28, loopback_filter) \
  _(0x30, egress_general) \
  _(0x40, egress_hoq) \
  _(0x48, port_isolation) \
  _(0x50, egress_policy_engine) \
  _(0x58, ingress_tx_link_down) \
  _(0x60, egress_stp_filter) \
  _(0x68, egress_hoq_stall)

#define foreach_reg_ppcmt_phy_layer_counter \
  _(0x08, phy_received_bits) \
  _(0x10, phy_symbol_errors) \
  _(0x18, phy_corrected_bits)

#endif /* included_mlx5_fields_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
