/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#ifndef _VNET_DEV_H_
#define _VNET_DEV_H_

#include <vppinfra/clib.h>
#include <vppinfra/error_bootstrap.h>
#include <vppinfra/format.h>
#include <vnet/vnet.h>
#include <vnet/dev/types.h>
#include <vnet/dev/args.h>

#define VNET_DEV_DEVICE_ID_PREFIX_DELIMITER "/"

#define foreach_vnet_dev_port_type                                            \
  _ (0, UNKNOWN)                                                              \
  _ (1, ETHERNET)

typedef enum
{
#define _(b, n) VNET_DEV_PORT_TYPE_##n = (1U << (b)),
  foreach_vnet_dev_port_type
#undef _
} vnet_dev_port_type_t;

#define foreach_vnet_dev_port_caps                                            \
  _ (interrupt_mode)                                                          \
  _ (rss)                                                                     \
  _ (change_max_rx_frame_size)                                                \
  _ (mac_filter)

#define foreach_vnet_dev_port_rx_offloads _ (ip4_cksum)

#define foreach_vnet_dev_port_tx_offloads                                     \
  _ (ip4_cksum)                                                               \
  _ (tcp_gso)                                                                 \
  _ (udp_gso)

typedef union
{
  struct
  {
#define _(n) u8 n : 1;
    foreach_vnet_dev_port_caps
#undef _
  };
  u8 as_number;
} vnet_dev_port_caps_t;

typedef union
{
  struct
  {
#define _(n) u8 n : 1;
    foreach_vnet_dev_port_rx_offloads
#undef _
  };
  u8 as_number;
} vnet_dev_port_rx_offloads_t;

typedef union
{
  struct
  {
#define _(n) u8 n : 1;
    foreach_vnet_dev_port_tx_offloads
#undef _
  };
  u8 as_number;
} vnet_dev_port_tx_offloads_t;

typedef union
{
  u8 eth_mac[6];
  u8 raw[8];
} vnet_dev_hw_addr_t;

typedef struct vnet_dev_bus_registration vnet_dev_bus_registration_t;
typedef struct vnet_dev_driver_registration vnet_dev_driver_registration_t;

typedef struct vnet_dev vnet_dev_t;
typedef struct vnet_dev_port vnet_dev_port_t;
typedef struct vnet_dev_rx_queue vnet_dev_rx_queue_t;
typedef struct vnet_dev_tx_queue vnet_dev_tx_queue_t;
typedef struct vnet_dev_bus_registration vnet_dev_bus_registration_t;
typedef struct vnet_dev_driver_registration vnet_dev_driver_registration_t;
typedef struct vnet_dev_counter vnet_dev_counter_t;
typedef struct vnet_dev_counter_main vnet_dev_counter_main_t;
typedef struct vnet_dev_port_cfg_change_req vnet_dev_port_cfg_change_req_t;

typedef vnet_dev_rv_t (vnet_dev_op_t) (vlib_main_t *, vnet_dev_t *);
typedef vnet_dev_rv_t (vnet_dev_port_op_t) (vlib_main_t *, vnet_dev_port_t *);
typedef vnet_dev_rv_t (vnet_dev_port_cfg_change_op_t) (
  vlib_main_t *, vnet_dev_port_t *, vnet_dev_port_cfg_change_req_t *);
typedef vnet_dev_rv_t (vnet_dev_rx_queue_op_t) (vlib_main_t *,
						vnet_dev_rx_queue_t *);
typedef vnet_dev_rv_t (vnet_dev_tx_queue_op_t) (vlib_main_t *,
						vnet_dev_tx_queue_t *);
typedef void (vnet_dev_op_no_rv_t) (vlib_main_t *, vnet_dev_t *);
typedef void (vnet_dev_port_op_no_rv_t) (vlib_main_t *, vnet_dev_port_t *);
typedef void (vnet_dev_rx_queue_op_no_rv_t) (vlib_main_t *,
					     vnet_dev_rx_queue_t *);
typedef void (vnet_dev_tx_queue_op_no_rv_t) (vlib_main_t *,
					     vnet_dev_tx_queue_t *);

typedef u16 vnet_dev_queue_id_t;
typedef u16 vnet_dev_bus_index_t;
typedef u16 vnet_dev_driver_index_t;

typedef struct
{
  vnet_dev_rx_queue_op_t *alloc;
  vnet_dev_rx_queue_op_t *start;
  vnet_dev_rx_queue_op_no_rv_t *stop;
  vnet_dev_rx_queue_op_no_rv_t *free;
  format_function_t *format_info;
} vnet_dev_rx_queue_ops_t;

typedef struct
{
  vnet_dev_tx_queue_op_t *alloc;
  vnet_dev_tx_queue_op_t *start;
  vnet_dev_tx_queue_op_no_rv_t *stop;
  vnet_dev_tx_queue_op_no_rv_t *free;
  format_function_t *format_info;
} vnet_dev_tx_queue_ops_t;

typedef struct
{
  u16 data_size;
  u16 min_size;
  u16 max_size;
  u16 default_size;
  u8 multiplier;
  u8 size_is_power_of_two : 1;
} vnet_dev_queue_config_t;

#define foreach_vnet_dev_port_cfg_type                                        \
  _ (PROMISC_MODE)                                                            \
  _ (MAX_RX_FRAME_SIZE)                                                       \
  _ (CHANGE_PRIMARY_HW_ADDR)                                                  \
  _ (ADD_SECONDARY_HW_ADDR)                                                   \
  _ (REMOVE_SECONDARY_HW_ADDR)                                                \
  _ (RXQ_INTR_MODE_ENABLE)                                                    \
  _ (RXQ_INTR_MODE_DISABLE)                                                   \
  _ (ADD_RX_FLOW)                                                             \
  _ (DEL_RX_FLOW)                                                             \
  _ (GET_RX_FLOW_COUNTER)                                                     \
  _ (RESET_RX_FLOW_COUNTER)

typedef enum
{
  VNET_DEV_PORT_CFG_UNKNOWN,
#define _(n) VNET_DEV_PORT_CFG_##n,
  foreach_vnet_dev_port_cfg_type
#undef _
} __clib_packed vnet_dev_port_cfg_type_t;

typedef struct vnet_dev_port_cfg_change_req
{
  vnet_dev_port_cfg_type_t type;
  u8 validated : 1;
  u8 all_queues : 1;

  union
  {
    u8 promisc : 1;
    vnet_dev_hw_addr_t addr;
    u16 max_rx_frame_size;
    vnet_dev_queue_id_t queue_id;
    struct
    {
      u32 flow_index;
      uword *private_data;
    };
  };

} vnet_dev_port_cfg_change_req_t;

typedef struct
{
  vnet_dev_hw_addr_t hw_addr;
  u16 max_rx_queues;
  u16 max_tx_queues;
  u16 max_supported_rx_frame_size;
  vnet_dev_port_type_t type;
  vnet_dev_port_caps_t caps;
  vnet_dev_port_rx_offloads_t rx_offloads;
  vnet_dev_port_tx_offloads_t tx_offloads;
} vnet_dev_port_attr_t;

typedef enum
{
  VNET_DEV_PERIODIC_OP_TYPE_DEV = 1,
  VNET_DEV_PERIODIC_OP_TYPE_PORT = 2,
} __clib_packed vnet_dev_periodic_op_type_t;

typedef struct
{
  f64 interval;
  f64 last_run;
  vnet_dev_periodic_op_type_t type;
  union
  {
    vnet_dev_t *dev;
    vnet_dev_port_t *port;
    void *arg;
  };
  union
  {
    vnet_dev_op_no_rv_t *dev_op;
    vnet_dev_port_op_no_rv_t *port_op;
    void *op;
  };
} vnet_dev_periodic_op_t;

typedef struct
{
  struct _vlib_node_fn_registration *registrations;
  format_function_t *format_trace;
  vlib_error_desc_t *error_counters;
  u16 n_error_counters;
} vnet_dev_node_t;

typedef struct
{
  vnet_dev_op_t *alloc;
  vnet_dev_op_t *init;
  vnet_dev_op_no_rv_t *deinit;
  vnet_dev_op_t *reset;
  vnet_dev_op_no_rv_t *free;
  u8 *(*probe) (vlib_main_t *, vnet_dev_bus_index_t, void *);
  format_function_t *format_info;
} vnet_dev_ops_t;

typedef struct
{
  vnet_dev_port_op_t *alloc;
  vnet_dev_port_op_t *init;
  vnet_dev_port_cfg_change_op_t *config_change;
  vnet_dev_port_cfg_change_op_t *config_change_validate;
  vnet_dev_port_op_t *start;
  vnet_dev_port_op_no_rv_t *stop;
  vnet_dev_port_op_no_rv_t *deinit;
  vnet_dev_port_op_no_rv_t *free;
  format_function_t *format_status;
  format_function_t *format_flow;
} vnet_dev_port_ops_t;

typedef union
{
  struct
  {
    u8 update_next_index : 1;
    u8 update_feature_arc : 1;
    u8 suspend_off : 1;
    u8 suspend_on : 1;
  };
  u8 as_number;
} vnet_dev_rx_queue_rt_req_t;

typedef struct vnet_dev_rx_queue
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  vnet_dev_port_t *port;
  u16 rx_thread_index;
  u16 index;
  vnet_dev_counter_main_t *counter_main;
  CLIB_CACHE_LINE_ALIGN_MARK (runtime0);
  vnet_dev_rx_queue_t *next_on_thread;
  u8 interrupt_mode : 1;
  u8 enabled : 1;
  u8 started : 1;
  u8 suspended : 1;
  vnet_dev_queue_id_t queue_id;
  u16 size;
  u16 next_index;
  vnet_dev_rx_queue_rt_req_t runtime_request;
  CLIB_CACHE_LINE_ALIGN_MARK (runtime1);
  vlib_buffer_template_t buffer_template;
  CLIB_CACHE_LINE_ALIGN_MARK (driver_data);
  u8 data[];
} vnet_dev_rx_queue_t;

STATIC_ASSERT_SIZEOF (vnet_dev_rx_queue_t, 3 * CLIB_CACHE_LINE_BYTES);

typedef struct vnet_dev_tx_queue
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  vnet_dev_port_t *port;
  clib_bitmap_t *assigned_threads;
  u16 index;
  vnet_dev_counter_main_t *counter_main;
  CLIB_CACHE_LINE_ALIGN_MARK (runtime0);
  vnet_dev_queue_id_t queue_id;
  u8 started : 1;
  u8 enabled : 1;
  u8 lock_needed : 1;
  u8 lock;
  u16 size;
  CLIB_ALIGN_MARK (private_data, 16);
  u8 data[];
} vnet_dev_tx_queue_t;

STATIC_ASSERT_SIZEOF (vnet_dev_tx_queue_t, 2 * CLIB_CACHE_LINE_BYTES);

typedef struct vnet_dev_port
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  vnet_dev_t *dev;
  vnet_dev_port_id_t port_id;
  vnet_dev_driver_index_t driver_index;
  u8 initialized : 1;
  u8 started : 1;
  u8 link_up : 1;
  u8 promisc : 1;
  u8 interface_created : 1;
  u8 rx_node_assigned : 1;
  vnet_dev_counter_main_t *counter_main;
  vnet_dev_queue_config_t rx_queue_config;
  vnet_dev_queue_config_t tx_queue_config;
  vnet_dev_port_attr_t attr;
  u32 max_rx_frame_size;
  vnet_dev_hw_addr_t primary_hw_addr;
  vnet_dev_hw_addr_t *secondary_hw_addr;
  u32 index;
  u32 speed;
  vnet_dev_rx_queue_t **rx_queues;
  vnet_dev_tx_queue_t **tx_queues;
  vnet_dev_port_ops_t port_ops;
  vnet_dev_arg_t *args;
  vnet_dev_rx_queue_ops_t rx_queue_ops;
  vnet_dev_tx_queue_ops_t tx_queue_ops;
  vnet_dev_node_t rx_node;
  vnet_dev_node_t tx_node;

  struct
  {
    vnet_dev_if_name_t name;
    u32 dev_instance;
    u32 rx_node_index;
    u32 current_config_index;
    u16 rx_next_index;
    u16 redirect_to_node_next_index;
    u8 feature_arc_index;
    u8 feature_arc : 1;
    u8 redirect_to_node : 1;
    u8 default_is_intr_mode : 1;
    u32 tx_node_index;
    u32 hw_if_index;
    u32 sw_if_index;
    u16 num_rx_queues;
    u16 num_tx_queues;
    u16 txq_sz;
    u16 rxq_sz;
  } intf;

  CLIB_CACHE_LINE_ALIGN_MARK (data0);
  u8 data[];
} vnet_dev_port_t;

typedef struct vnet_dev
{
  vnet_dev_device_id_t device_id;
  u16 initialized : 1;
  u16 not_first_init : 1;
  u16 va_dma : 1;
  u16 process_node_quit : 1;
  u16 process_node_periodic : 1;
  u16 poll_stats : 1;
  u16 bus_index;
  u8 numa_node;
  u16 max_rx_queues;
  u16 max_tx_queues;
  vnet_dev_driver_index_t driver_index;
  u32 index;
  u32 process_node_index;
  u8 bus_data[32] __clib_aligned (16);
  vnet_dev_ops_t ops;
  vnet_dev_port_t **ports;
  vnet_dev_periodic_op_t *periodic_ops;
  u8 *description;
  vnet_dev_arg_t *args;
  u8 __clib_aligned (16)
  data[];
} vnet_dev_t;

typedef struct
{
  u16 vendor_id, device_id;
  char *description;
} vnet_dev_match_t;

#define VNET_DEV_MATCH(...)                                                   \
  (vnet_dev_match_t[])                                                        \
  {                                                                           \
    __VA_ARGS__, {}                                                           \
  }

typedef struct
{
  vnet_dev_op_t *device_open;
  vnet_dev_op_no_rv_t *device_close;
  vnet_dev_rv_t (*dma_mem_alloc_fn) (vlib_main_t *, vnet_dev_t *, u32, u32,
				     void **);
  void (*dma_mem_free_fn) (vlib_main_t *, vnet_dev_t *, void *);
  void *(*get_device_info) (vlib_main_t *, char *);
  void (*free_device_info) (vlib_main_t *, void *);
  format_function_t *format_device_info;
  format_function_t *format_device_addr;
} vnet_dev_bus_ops_t;

struct vnet_dev_bus_registration
{
  vnet_dev_bus_registration_t *next_registration;
  vnet_dev_driver_name_t name;
  u16 device_data_size;
  vnet_dev_bus_ops_t ops;
};

struct vnet_dev_driver_registration
{
  vnet_dev_driver_registration_t *next_registration;
  u8 bus_master_enable : 1;
  vnet_dev_driver_name_t name;
  vnet_dev_bus_name_t bus;
  u16 device_data_sz;
  u16 runtime_temp_space_sz;
  vnet_dev_match_t *match;
  int priority;
  vnet_dev_ops_t ops;
  vnet_dev_arg_t *args;
};

typedef struct
{
  u32 index;
  vnet_dev_bus_registration_t *registration;
  vnet_dev_bus_ops_t ops;
} vnet_dev_bus_t;

typedef struct
{
  u32 index;
  void *dev_data;
  vnet_dev_driver_registration_t *registration;
  u32 dev_class_index;
  vnet_dev_bus_index_t bus_index;
  vnet_dev_ops_t ops;
} vnet_dev_driver_t;

typedef struct
{
  vnet_dev_bus_t *buses;
  vnet_dev_driver_t *drivers;
  vnet_dev_t **devices;
  vnet_dev_port_t **ports_by_dev_instance;
  vnet_dev_bus_registration_t *bus_registrations;
  vnet_dev_driver_registration_t *driver_registrations;
  void *runtime_temp_spaces;
  u32 log2_runtime_temp_space_sz;
  u32 *free_process_node_indices;
  u32 *free_rx_node_indices;
  uword *device_index_by_id;

  u8 *startup_config;
  u16 next_rx_queue_thread;
  u8 eth_port_rx_feature_arc_index;
} vnet_dev_main_t;

extern vnet_dev_main_t vnet_dev_main;

typedef struct
{
  struct
  {
    vnet_dev_port_attr_t attr;
    vnet_dev_port_ops_t ops;
    vnet_dev_arg_t *args;
    u16 data_size;
    void *initial_data;
  } port;

  vnet_dev_node_t *rx_node;
  vnet_dev_node_t *tx_node;

  struct
  {
    vnet_dev_queue_config_t config;
    vnet_dev_rx_queue_ops_t ops;
  } rx_queue;

  struct
  {
    vnet_dev_queue_config_t config;
    vnet_dev_tx_queue_ops_t ops;
  } tx_queue;
} vnet_dev_port_add_args_t;

typedef struct
{
  union
  {
    struct
    {
      u8 link_speed : 1;
      u8 link_state : 1;
      u8 link_duplex : 1;
    };
    u8 any;
  } change;
  u8 link_state : 1;
  u8 full_duplex : 1;
  u32 link_speed;
} vnet_dev_port_state_changes_t;

/* args.c */
vnet_dev_rv_t vnet_dev_arg_parse (vlib_main_t *, vnet_dev_t *,
				  vnet_dev_arg_t *, u8 *);
void vnet_dev_arg_free (vnet_dev_arg_t **);
void vnet_dev_arg_clear_value (vnet_dev_arg_t *);
format_function_t format_vnet_dev_arg_type;
format_function_t format_vnet_dev_arg_value;
format_function_t format_vnet_dev_args;

/* dev.c */
vnet_dev_t *vnet_dev_alloc (vlib_main_t *, vnet_dev_device_id_t,
			    vnet_dev_driver_t *);
void vnet_dev_free (vlib_main_t *, vnet_dev_t *);
vnet_dev_rv_t vnet_dev_init (vlib_main_t *, vnet_dev_t *);
void vnet_dev_deinit (vlib_main_t *, vnet_dev_t *);
vnet_dev_rv_t vnet_dev_reset (vlib_main_t *, vnet_dev_t *);
void vnet_dev_detach (vlib_main_t *, vnet_dev_t *);
vnet_dev_rv_t vnet_dev_port_add (vlib_main_t *, vnet_dev_t *,
				 vnet_dev_port_id_t,
				 vnet_dev_port_add_args_t *);
vnet_dev_rv_t vnet_dev_dma_mem_alloc (vlib_main_t *, vnet_dev_t *, u32, u32,
				      void **);
void vnet_dev_dma_mem_free (vlib_main_t *, vnet_dev_t *, void *);
vnet_dev_bus_t *vnet_dev_find_device_bus (vlib_main_t *, vnet_dev_device_id_t);
void *vnet_dev_get_device_info (vlib_main_t *, vnet_dev_device_id_t);

/* error.c */
clib_error_t *vnet_dev_port_err (vlib_main_t *, vnet_dev_port_t *,
				 vnet_dev_rv_t, char *, ...);
int vnet_dev_flow_err (vlib_main_t *, vnet_dev_rv_t);

/* handlers.c */
clib_error_t *vnet_dev_port_set_max_frame_size (vnet_main_t *,
						vnet_hw_interface_t *, u32);
u32 vnet_dev_port_eth_flag_change (vnet_main_t *, vnet_hw_interface_t *, u32);
clib_error_t *vnet_dev_port_mac_change (vnet_hw_interface_t *, const u8 *,
					const u8 *);
clib_error_t *vnet_dev_add_del_mac_address (vnet_hw_interface_t *, const u8 *,
					    u8);
int vnet_dev_flow_ops_fn (vnet_main_t *, vnet_flow_dev_op_t, u32, u32,
			  uword *);
clib_error_t *vnet_dev_interface_set_rss_queues (vnet_main_t *,
						 vnet_hw_interface_t *,
						 clib_bitmap_t *);
void vnet_dev_clear_hw_interface_counters (u32);
void vnet_dev_set_interface_next_node (vnet_main_t *, u32, u32);

/* port.c */
vnet_dev_rv_t vnet_dev_port_start (vlib_main_t *, vnet_dev_port_t *);
vnet_dev_rv_t vnet_dev_port_start_all_rx_queues (vlib_main_t *,
						 vnet_dev_port_t *);
vnet_dev_rv_t vnet_dev_port_start_all_tx_queues (vlib_main_t *,
						 vnet_dev_port_t *);
void vnet_dev_port_stop (vlib_main_t *, vnet_dev_port_t *);
void vnet_dev_port_deinit (vlib_main_t *, vnet_dev_port_t *);
void vnet_dev_port_free (vlib_main_t *, vnet_dev_port_t *);
void vnet_dev_port_add_counters (vlib_main_t *, vnet_dev_port_t *,
				 vnet_dev_counter_t *, u16);
void vnet_dev_port_free_counters (vlib_main_t *, vnet_dev_port_t *);
void vnet_dev_port_update_tx_node_runtime (vlib_main_t *, vnet_dev_port_t *);
void vnet_dev_port_state_change (vlib_main_t *, vnet_dev_port_t *,
				 vnet_dev_port_state_changes_t);
void vnet_dev_port_clear_counters (vlib_main_t *, vnet_dev_port_t *);
vnet_dev_rv_t
vnet_dev_port_cfg_change_req_validate (vlib_main_t *, vnet_dev_port_t *,
				       vnet_dev_port_cfg_change_req_t *);
vnet_dev_rv_t vnet_dev_port_cfg_change (vlib_main_t *, vnet_dev_port_t *,
					vnet_dev_port_cfg_change_req_t *);
vnet_dev_rv_t vnet_dev_port_if_create (vlib_main_t *, vnet_dev_port_t *);
vnet_dev_rv_t vnet_dev_port_if_remove (vlib_main_t *, vnet_dev_port_t *);

/* queue.c */
vnet_dev_rv_t vnet_dev_rx_queue_alloc (vlib_main_t *, vnet_dev_port_t *, u16);
vnet_dev_rv_t vnet_dev_tx_queue_alloc (vlib_main_t *, vnet_dev_port_t *, u16);
void vnet_dev_rx_queue_free (vlib_main_t *, vnet_dev_rx_queue_t *);
void vnet_dev_tx_queue_free (vlib_main_t *, vnet_dev_tx_queue_t *);
void vnet_dev_rx_queue_add_counters (vlib_main_t *, vnet_dev_rx_queue_t *,
				     vnet_dev_counter_t *, u16);
void vnet_dev_rx_queue_free_counters (vlib_main_t *, vnet_dev_rx_queue_t *);
void vnet_dev_tx_queue_add_counters (vlib_main_t *, vnet_dev_tx_queue_t *,
				     vnet_dev_counter_t *, u16);
void vnet_dev_tx_queue_free_counters (vlib_main_t *, vnet_dev_tx_queue_t *);
vnet_dev_rv_t vnet_dev_rx_queue_start (vlib_main_t *, vnet_dev_rx_queue_t *);
vnet_dev_rv_t vnet_dev_tx_queue_start (vlib_main_t *, vnet_dev_tx_queue_t *);
void vnet_dev_rx_queue_stop (vlib_main_t *, vnet_dev_rx_queue_t *);
void vnet_dev_tx_queue_stop (vlib_main_t *, vnet_dev_tx_queue_t *);

/* process.c */
vnet_dev_rv_t vnet_dev_process_create (vlib_main_t *, vnet_dev_t *);
vnet_dev_rv_t vnet_dev_process_call_op (vlib_main_t *, vnet_dev_t *,
					vnet_dev_op_t *);
vnet_dev_rv_t vnet_dev_process_call_op_no_rv (vlib_main_t *, vnet_dev_t *,
					      vnet_dev_op_no_rv_t *);
void vnet_dev_process_call_op_no_wait (vlib_main_t *, vnet_dev_t *,
				       vnet_dev_op_no_rv_t *);
vnet_dev_rv_t vnet_dev_process_call_port_op (vlib_main_t *, vnet_dev_port_t *,
					     vnet_dev_port_op_t *);
vnet_dev_rv_t vnet_dev_process_call_port_op_no_rv (vlib_main_t *vm,
						   vnet_dev_port_t *,
						   vnet_dev_port_op_no_rv_t *);
void vnet_dev_process_call_port_op_no_wait (vlib_main_t *, vnet_dev_port_t *,
					    vnet_dev_port_op_no_rv_t *);
vnet_dev_rv_t
vnet_dev_process_port_cfg_change_req (vlib_main_t *, vnet_dev_port_t *,
				      vnet_dev_port_cfg_change_req_t *);
void vnet_dev_process_quit (vlib_main_t *, vnet_dev_t *);
void vnet_dev_poll_dev_add (vlib_main_t *, vnet_dev_t *, f64,
			    vnet_dev_op_no_rv_t *);
void vnet_dev_poll_dev_remove (vlib_main_t *, vnet_dev_t *,
			       vnet_dev_op_no_rv_t *);
void vnet_dev_poll_port_add (vlib_main_t *, vnet_dev_port_t *, f64,
			     vnet_dev_port_op_no_rv_t *);
void vnet_dev_poll_port_remove (vlib_main_t *, vnet_dev_port_t *,
				vnet_dev_port_op_no_rv_t *);

typedef struct
{
  u16 thread_index;
  u8 completed;
  u8 in_order;
  vnet_dev_port_t *port;
} vnet_dev_rt_op_t;

vnet_dev_rv_t vnet_dev_rt_exec_ops (vlib_main_t *, vnet_dev_t *,
				    vnet_dev_rt_op_t *, u32);

/* format.c */
typedef struct
{
  u8 counters : 1;
  u8 show_zero_counters : 1;
  u8 debug : 1;
} vnet_dev_format_args_t;

format_function_t format_vnet_dev_addr;
format_function_t format_vnet_dev_flags;
format_function_t format_vnet_dev_hw_addr;
format_function_t format_vnet_dev_info;
format_function_t format_vnet_dev_interface_info;
format_function_t format_vnet_dev_interface_name;
format_function_t format_vnet_dev_log;
format_function_t format_vnet_dev_port_caps;
format_function_t format_vnet_dev_port_flags;
format_function_t format_vnet_dev_port_info;
format_function_t format_vnet_dev_port_rx_offloads;
format_function_t format_vnet_dev_port_tx_offloads;
format_function_t format_vnet_dev_rv;
format_function_t format_vnet_dev_rx_queue_info;
format_function_t format_vnet_dev_tx_queue_info;
format_function_t format_vnet_dev_flow;
unformat_function_t unformat_vnet_dev_flags;
unformat_function_t unformat_vnet_dev_port_flags;

typedef struct
{
  vnet_dev_rx_queue_t *first_rx_queue;
} vnet_dev_rx_node_runtime_t;

STATIC_ASSERT (sizeof (vnet_dev_rx_node_runtime_t) <=
		 VLIB_NODE_RUNTIME_DATA_SIZE,
	       "must fit into runtime data");

#define foreach_vnet_dev_port_rx_next                                         \
  _ (ETH_INPUT, "ethernet-input")                                             \
  _ (DROP, "error-drop")

typedef enum
{
#define _(n, s) VNET_DEV_ETH_RX_PORT_NEXT_##n,
  foreach_vnet_dev_port_rx_next
#undef _
    VNET_DEV_ETH_RX_PORT_N_NEXTS
} vnet_dev_eth_port_rx_next_t;

extern u16 vnet_dev_default_next_index_by_port_type[];
extern vlib_node_registration_t port_rx_eth_node;

typedef vnet_interface_output_runtime_t vnet_dev_tx_node_runtime_t;

STATIC_ASSERT (sizeof (vnet_dev_tx_node_runtime_t) <=
		 VLIB_NODE_RUNTIME_DATA_SIZE,
	       "must fit into runtime data");

#define VNET_DEV_REGISTER_BUS(x, ...)                                         \
  __VA_ARGS__ vnet_dev_bus_registration_t __vnet_dev_bus_registration_##x;    \
  static void __clib_constructor __vnet_dev_bus_registration_fn_##x (void)    \
  {                                                                           \
    vnet_dev_main_t *dm = &vnet_dev_main;                                     \
    __vnet_dev_bus_registration_##x.next_registration =                       \
      dm->bus_registrations;                                                  \
    dm->bus_registrations = &__vnet_dev_bus_registration_##x;                 \
  }                                                                           \
  __VA_ARGS__ vnet_dev_bus_registration_t __vnet_dev_bus_registration_##x

#define VNET_DEV_REGISTER_DRIVER(x, ...)                                      \
  __VA_ARGS__ vnet_dev_driver_registration_t                                  \
    __vnet_dev_driver_registration_##x;                                       \
  static void __clib_constructor __vnet_dev_driver_registration_fn_##x (void) \
  {                                                                           \
    vnet_dev_main_t *dm = &vnet_dev_main;                                     \
    __vnet_dev_driver_registration_##x.next_registration =                    \
      dm->driver_registrations;                                               \
    dm->driver_registrations = &__vnet_dev_driver_registration_##x;           \
  }                                                                           \
  __VA_ARGS__ vnet_dev_driver_registration_t __vnet_dev_driver_registration_##x

#define VNET_DEV_NODE_FN(node)                                                \
  uword CLIB_MARCH_SFX (node##_fn) (vlib_main_t *, vlib_node_runtime_t *,     \
				    vlib_frame_t *);                          \
  static vlib_node_fn_registration_t CLIB_MARCH_SFX (                         \
    node##_fn_registration) = {                                               \
    .function = &CLIB_MARCH_SFX (node##_fn),                                  \
  };                                                                          \
                                                                              \
  static void __clib_constructor CLIB_MARCH_SFX (                             \
    node##_fn_multiarch_register) (void)                                      \
  {                                                                           \
    extern vnet_dev_node_t node;                                              \
    vlib_node_fn_registration_t *r;                                           \
    r = &CLIB_MARCH_SFX (node##_fn_registration);                             \
    r->march_variant = CLIB_MARCH_SFX (CLIB_MARCH_VARIANT_TYPE);              \
    r->next_registration = (node).registrations;                              \
    (node).registrations = r;                                                 \
  }                                                                           \
  uword CLIB_MARCH_SFX (node##_fn)

#define foreach_vnet_dev_port(p, d) pool_foreach_pointer (p, d->ports)
#define foreach_vnet_dev_port_rx_queue(q, p)                                  \
  pool_foreach_pointer (q, p->rx_queues)
#define foreach_vnet_dev_port_tx_queue(q, p)                                  \
  pool_foreach_pointer (q, p->tx_queues)

#include <vnet/dev/dev_funcs.h>

#endif /* _VNET_DEV_H_ */
