/*
 * Copyright (c) 2021 Marvell.
 * SPDX-License-Identifier: Apache-2.0
 * https://spdx.org/licenses/Apache-2.0.html
 */

/**
 * @file
 * @brief ONP pktio interface.
 */

#ifndef included_onp_pktio_pktio_h
#define included_onp_pktio_pktio_h

#include <onp/drv/inc/pktio.h>

#define ONP_DEV_PCI_ADDR_ANY (-1)

/** @anchor ONP_MIN_N_RX_QUEUES **/
/*
 * Min. valid value for number of receive queues(RQs) per pktio. If not passed
 * in startup configuration, default value becomes number of worker threads
 */
#define ONP_MIN_N_RX_QUEUES 1

/** @anchor ONP_MAX_N_RX_QUEUES **/
/* Max number of receive queues allowed per pktio */
#define ONP_MAX_N_RX_QUEUES 64

/** @anchor ONP_MIN_N_TX_QUEUES **/
/*
 * Min. valid value for number of send/transmit queues(SQs) per pktio. If not
 * passed in startup configuration, default value becomes number of VPP threads
 */
#define ONP_MIN_N_TX_QUEUES 1

/** @anchor ONP_MAX_N_TX_QUEUES **/
/* Max number of SQs allowed per pktio */
#define ONP_MAX_N_TX_QUEUES 64

/** @anchor ONP_DEFAULT_N_RX_DESC **/
#define ONP_DEFAULT_N_RX_DESC 4096

/** @anchor ONP_MAX_N_RX_DESC **/
/*
 * While NIX is capable of supporting 1M Rx descriptors per RQ but it is not
 * practically feasible. Limiting maximum value of num-rx-desc per RQ for
 * better cache utilization
 */
#define ONP_MAX_N_RX_DESC 16384

/** @anchor ONP_DEFAULT_N_TX_DESC **/
#define ONP_DEFAULT_N_TX_DESC 4096

/** @anchor ONP_MAX_N_TX_DESC **/
/*
 * While NIX is capable of supporting any number Tx descriptors per SQ.
 * Limiting maximum value of num-tx-desc per SQ for better cache utilization
 */
#define ONP_MAX_N_TX_DESC 16384

/** @anchor ONP_N_PKT_BUF **/
#define ONP_N_PKT_BUF 8192

/** @anchor ONP_MIN_VEC_SIZE **/
/*
 * Minimum burst/vector size to sustain traffic. Initial resources like memory
 * buffers are allocated based on this macro
 */
#define ONP_MIN_VEC_SIZE 2

/** @anchor ONP_RX_BURST_SIZE **/
/* Maximum burst/vector size in receive functions */
#define ONP_RX_BURST_SIZE CNXK_FRAME_SIZE

/** @anchor ONP_RSS_DEFAULT_MIN_VEC */
/*
 * Minimum burst/vec size
 */
#define ONP_RSS_DEFAULT_MIN_VEC ONP_RX_BURST_SIZE

/** @anchor ONP_RSS_DEFAULT_MAX_VEC */
/*
 * Maximum burst/vec size
 */
#define ONP_RSS_DEFAULT_MAX_VEC ONP_RX_BURST_SIZE

#define foreach_onp_pktio_flags                                               \
  _ (0, INITIALIZED, "initialized")                                           \
  _ (1, ERROR, "error")                                                       \
  _ (2, ADMIN_UP, "admin-up")                                                 \
  _ (3, LINK_UP, "link-up")                                                   \
  _ (4, ELOG, "elog")                                                         \
  _ (5, PROMISC, "promisc")

#define ONP_INTF_NAME_MAX_SIZE 32

enum
{
#define _(a, b, c) ONP_DEVICE_F_##b = (1 << a),
  foreach_onp_pktio_flags
#undef _
};

extern vnet_device_class_t onp_pktio_device_class;
extern vlib_node_registration_t onp_pktio_input_node;

#define ONP_PKTIO_INPUT_NODE_INDEX onp_pktio_input_node.index

typedef struct
{
  u32 buffer_index;
  u32 pktio_index;
  u32 queue_index;
  u32 next_node_index;
  u8 data[256];
  u8 driver_data[64];
  vlib_buffer_t buffer;
} onp_rx_trace_t;

typedef struct
{
  u32 buffer_index;
  u32 dev_id;
  u32 qid;
  u8 data[256];
  vlib_buffer_t buf;
} onp_tx_trace_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (c0);
  cnxk_drv_pktio_rxq_recv_func_t pktio_recv_func;
  cnxk_drv_pktio_rxq_recv_func_t pktio_recv_func_with_trace;
  u32 vnet_hw_rq_index;
  u32 mode;
  u16 req_burst_size;
} onp_pktio_rxq_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (c0);
  cnxk_drv_pktio_txq_send_func_t pktio_send_func;
  cnxk_drv_pktio_txq_send_func_t pktio_send_func_order;
} onp_pktio_txq_t;

/* clang-format off */
/*
 * Default value: ~0 indicates that default value depends upon runtime
 * configurations like number of available VPP worker threads etc.
 *
 * (config_name, variable, default-val, min_val, max_val, print)
 */
#define foreach_onp_pktio_config_item                                                                         \
_ (num-rx-queues, n_rx_q, ~0, ONP_MIN_N_RX_QUEUES, ONP_MAX_N_RX_QUEUES, 1)                                    \
_ (num-tx-queues, n_tx_q, ~0, ONP_MIN_N_TX_QUEUES, ONP_MAX_N_TX_QUEUES, 1)                                    \
_ (num-rx-desc, n_rx_desc, ONP_DEFAULT_N_RX_DESC, 256, ONP_MAX_N_RX_DESC, 1)                                  \
_ (num-tx-desc, n_tx_desc, ONP_DEFAULT_N_TX_DESC, 256, ONP_MAX_N_TX_DESC, 1)                                  \
_ (rq-min-vec-size, rxq_min_vec_size, ONP_RSS_DEFAULT_MIN_VEC, 1, ONP_RX_BURST_SIZE, 1)                       \
_ (rq-max-vec-size, rxq_max_vec_size, ONP_RSS_DEFAULT_MAX_VEC, 1, ONP_RX_BURST_SIZE, 1)
/* clang-format on */

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (c0);
  /* RX TX OPs functions */
  onp_pktio_rxq_t *onp_pktio_rxqs;

  CLIB_CACHE_LINE_ALIGN_MARK (c1);
  /* RX TX OPs functions */
  onp_pktio_txq_t *onp_pktio_txqs;

  /* Fast path cache line */
  CLIB_CACHE_LINE_ALIGN_MARK (c2);

  /* vnet hw and sw if index */
  u32 hw_if_index;
  u32 sw_if_index;

  u64 rx_offload_flags;
  u64 tx_offload_flags;

  u32 pktio_flags;

  u16 cnxk_pktio_index;
  u16 onp_pktio_index;
  u16 cnxk_pool_index;
  u16 vlib_buffer_pool_index;

  u16 per_interface_next_index;

#define _(name, var, val, min, max, p) u32 var;
  foreach_onp_pktio_config_item;
#undef _
  /* Slow path cache line */
  CLIB_CACHE_LINE_ALIGN_MARK (c3);
  vlib_pci_addr_t pktio_pci_addr;

  u8 *xstats_names[CNXK_PKTIO_MAX_XSTATS_COUNT];

  u32 xstats_count;

  u8 numa_node;
  u8 name[ONP_INTF_NAME_MAX_SIZE];

  u32 init_done_magic_num;
} onp_pktio_t;

typedef struct
{
  vlib_pci_addr_t pktio_pci_addr;

#define _(name, var, value, min, max, p) u32 var;
  foreach_onp_pktio_config_item;
#undef _

#define _(name, var, val, min, max, p) u64 is_##var##_configured : 1;
  foreach_onp_pktio_config_item;
#undef _

  u32 is_pci_addr_configured : 1;
  u32 is_name_configured : 1;
  u8 *name;
} onp_pktio_config_t;

#define onp_get_pktio(index) (pool_elt_at_index (onp_main.onp_pktios, index))

format_function_t format_onp_pktio_name;
format_function_t format_onp_pktio;
format_function_t format_onp_pktio_tx_trace;
format_function_t format_onp_pktio_rx_trace;
format_function_t format_onp_pktio_flow;

u32 onp_pktio_flag_change (vnet_main_t *vnm, vnet_hw_interface_t *hw,
			   u32 flags);

int onp_pktio_assign_and_enable_all_rqs (vlib_main_t *vm, i32 onp_pktio_index,
					 u32 node_index, u32 thread_index,
					 int is_enable);

int onp_pktio_txqs_fp_set (vlib_main_t *vm, u32 onp_pktio_index,
			   int is_enable);

int onp_pktio_assign_rq_to_node (vlib_main_t *vm, u32 onp_pktio_index,
				 u32 rq_index, u32 thread_index,
				 u32 node_index, int is_assign_node);

void onp_pktio_hw_interface_assign_rx_thread (onp_pktio_t *od,
					      u16 n_rx_queues);

int onp_pktio_flow_ops (vnet_main_t *vnm, vnet_flow_dev_op_t op,
			u32 dev_instance, u32 flow_index, uword *private_data);

#endif /* included_onp_pktio_pktio_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
