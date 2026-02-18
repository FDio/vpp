/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023-2026 Cisco Systems, Inc.
 */

#ifndef _VNET_DEV_H_
#define _VNET_DEV_H_

#include <vppinfra/clib.h>
#include <vppinfra/error_bootstrap.h>
#include <vppinfra/format.h>
#include <vnet/vnet.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/dev/types.h>
#include <vppinfra/args.h>

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
  _ (mac_filter)                                                              \
  _ (secondary_interfaces)

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

typedef struct vnet_dev_driver vnet_dev_driver_t;
typedef struct vnet_dev vnet_dev_t;
typedef struct vnet_dev_port vnet_dev_port_t;
typedef struct vnet_dev_rx_queue vnet_dev_rx_queue_t;
typedef struct vnet_dev_tx_queue vnet_dev_tx_queue_t;
typedef struct vnet_dev_bus_registration vnet_dev_bus_registration_t;
typedef struct vnet_dev_driver_registration vnet_dev_driver_registration_t;
typedef struct vnet_dev_counter vnet_dev_counter_t;
typedef struct vnet_dev_counter_main vnet_dev_counter_main_t;
typedef struct vnet_dev_port_cfg_change_req vnet_dev_port_cfg_change_req_t;

typedef vnet_dev_rv_t (vnet_dev_drv_op_t) (vlib_main_t *, vnet_dev_driver_t *);
typedef void (vnet_dev_drv_op_no_rv_t) (vlib_main_t *, vnet_dev_driver_t *);
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
typedef vnet_dev_rv_t (vnet_dev_op_with_ptr_t) (vlib_main_t *, vnet_dev_t *,
						void *);
typedef vnet_dev_rv_t (vnet_dev_port_op_with_ptr_t) (vlib_main_t *,
						     vnet_dev_port_t *,
						     void *);

typedef u16 vnet_dev_queue_id_t;
typedef u16 vnet_dev_bus_index_t;
typedef u16 vnet_dev_driver_index_t;

typedef struct
{
  vnet_dev_rx_queue_op_t *alloc;
  vnet_dev_rx_queue_op_t *start;
  vnet_dev_rx_queue_op_no_rv_t *stop;
  vnet_dev_rx_queue_op_no_rv_t *free;
  vnet_dev_rx_queue_op_no_rv_t *clear_counters;
  format_function_t *format_info;
} vnet_dev_rx_queue_ops_t;

typedef struct
{
  vnet_dev_tx_queue_op_t *alloc;
  vnet_dev_tx_queue_op_t *start;
  vnet_dev_tx_queue_op_no_rv_t *stop;
  vnet_dev_tx_queue_op_no_rv_t *free;
  vnet_dev_tx_queue_op_no_rv_t *clear_counters;
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

#define foreach_vnet_dev_port_cfg_type                                                             \
  _ (PROMISC_MODE)                                                                                 \
  _ (MAX_RX_FRAME_SIZE)                                                                            \
  _ (CHANGE_PRIMARY_HW_ADDR)                                                                       \
  _ (ADD_SECONDARY_HW_ADDR)                                                                        \
  _ (REMOVE_SECONDARY_HW_ADDR)                                                                     \
  _ (RXQ_INTR_MODE_ENABLE)                                                                         \
  _ (RXQ_INTR_MODE_DISABLE)                                                                        \
  _ (ADD_RX_FLOW)                                                                                  \
  _ (DEL_RX_FLOW)                                                                                  \
  _ (GET_RX_FLOW_COUNTER)                                                                          \
  _ (RESET_RX_FLOW_COUNTER)                                                                        \
  _ (SET_RSS_CONFIG)

typedef enum
{
  VNET_DEV_PORT_CFG_UNKNOWN,
#define _(n) VNET_DEV_PORT_CFG_##n,
  foreach_vnet_dev_port_cfg_type
#undef _
} __clib_packed vnet_dev_port_cfg_type_t;

typedef struct
{
  vnet_dev_rss_key_t key;
  vnet_eth_rss_hash_t hash;
} vnet_dev_port_rss_config_t;

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
    vnet_dev_port_rss_config_t rss_config;
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
  vnet_eth_rss_hash_t rss_types;
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
  vnet_dev_bus_index_t bus_index;
  void *device_info;
  u64 probe_handle;
} vnet_dev_probe_args_t;

typedef struct
{
  vnet_dev_drv_op_t *config_args;
  vnet_dev_op_t *alloc;
  vnet_dev_op_t *init;
  vnet_dev_op_no_rv_t *deinit;
  vnet_dev_op_t *reset;
  vnet_dev_op_no_rv_t *free;
  u8 *(*probe) (vlib_main_t *, vnet_dev_probe_args_t *);
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
  vnet_dev_port_op_no_rv_t *clear_counters;
  vnet_dev_port_op_with_ptr_t *add_sec_if;
  vnet_dev_port_op_with_ptr_t *del_sec_if;
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

typedef struct
{
  vlib_buffer_template_t buffer_template;
  u32 sw_if_index;
  u16 next_index;
  u16 sec_if_index;
} vnet_dev_rx_queue_if_rt_data_t;

typedef struct vnet_dev_rx_queue
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  vnet_dev_port_t *port;
  u16 rx_thread_index;
  u16 index;
  u16 size;
  u8 interrupt_mode : 1;
  u8 enabled : 1;
  u8 started : 1;
  u8 suspended : 1;
  vnet_dev_rx_queue_rt_req_t runtime_request;
  vnet_dev_counter_main_t *counter_main;
  vnet_dev_rx_queue_t *next_on_thread;
  vnet_dev_queue_id_t queue_id;
  vnet_dev_rx_queue_if_rt_data_t **sec_if_rt_data;
  CLIB_CACHE_LINE_ALIGN_MARK (runtime1);
  vnet_dev_rx_queue_if_rt_data_t if_rt_data;
  CLIB_CACHE_LINE_ALIGN_MARK (driver_data);
  u8 data[];
} vnet_dev_rx_queue_t;

#if CLIB_CACHE_LINE_BYTES > 64
STATIC_ASSERT_SIZEOF (vnet_dev_rx_queue_t, 2 * CLIB_CACHE_LINE_BYTES);
#else
STATIC_ASSERT_SIZEOF (vnet_dev_rx_queue_t, 3 * CLIB_CACHE_LINE_BYTES);
#endif

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

typedef struct
{
  vnet_dev_if_name_t name;
  u8 interface_created : 1;
  u8 feature_arc : 1;
  u8 redirect_to_node : 1;
  u8 feature_arc_index;
  u16 rx_next_index;
  u32 index;
  u32 sw_if_index;
  u32 hw_if_index;
  u32 dev_instance;
  u32 tx_node_index;
  u32 next_index;
  u32 current_config_index;
  u16 redirect_to_node_next_index;
  u32 user_data;
  clib_args_handle_t args;
} vnet_dev_port_interface_t;

typedef struct
{
  u32 rx_node_index;
  u8 default_is_intr_mode : 1;
  u16 num_rx_queues;
  u16 num_tx_queues;
  u16 txq_sz;
  u16 rxq_sz;
  vnet_dev_port_interface_t primary_interface;
  vnet_dev_port_interface_t **secondary_interfaces;
} vnet_dev_port_interfaces_t;

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
  clib_args_handle_t args;
  clib_args_handle_t sec_if_args;
  vnet_dev_rx_queue_ops_t rx_queue_ops;
  vnet_dev_tx_queue_ops_t tx_queue_ops;
  vnet_dev_node_t rx_node;
  vnet_dev_node_t tx_node;
  vnet_dev_port_interfaces_t *interfaces;
  vnet_dev_port_rss_config_t *rss_config;

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
  u64 probe_handle;
  u32 process_node_index;
  u8 bus_data[32] __clib_aligned (16);
  vnet_dev_ops_t ops;
  vnet_dev_port_t **ports;
  vnet_dev_periodic_op_t *periodic_ops;
  u8 *description;
  clib_args_handle_t args;
  void **dma_allocs;
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
  u8 passive : 1;
  vnet_dev_driver_name_t name;
  char *description;
  vnet_dev_bus_name_t bus;
  u16 runtime_temp_space_sz;
  vnet_dev_match_t *match;
  int priority;
  struct
  {
    vnet_dev_ops_t ops;
    clib_arg_t *args;
    u16 data_sz;
  } device;
  struct
  {
    struct
    {
      vnet_dev_drv_op_t *init;
      vnet_dev_drv_op_no_rv_t *deinit;
    } ops;
    clib_arg_t *args;
  } driver;
};

typedef struct
{
  u32 index;
  vnet_dev_bus_registration_t *registration;
  vnet_dev_bus_ops_t ops;
} vnet_dev_bus_t;

typedef struct vnet_dev_driver
{
  u32 index;
  void *dev_data;
  vnet_dev_driver_registration_t *registration;
  char *description;
  u32 dev_class_index;
  vnet_dev_bus_index_t bus_index;
  vnet_dev_ops_t ops;
  clib_args_handle_t args;
  u8 initialized;
} vnet_dev_driver_t;

typedef struct
{
  vnet_dev_port_t *port;
  u32 sec_if_index;
  u8 is_primary_if : 1;
} vnet_dev_instance_t;

typedef struct
{
  vnet_dev_bus_t *buses;
  vnet_dev_driver_t *drivers;
  vnet_dev_t **devices;
  vnet_dev_instance_t *dev_instances;
  vnet_dev_bus_registration_t *bus_registrations;
  vnet_dev_driver_registration_t *driver_registrations;
  void *runtime_temp_spaces;
  u32 log2_runtime_temp_space_sz;
  u32 *free_process_node_indices;
  u32 *free_rx_node_indices;
  uword *device_index_by_id;

  /* startup config */
  u8 *startup_config;
  u32 *process_nodes_waiting_for_startup_conf;
  u8 startup_config_completed;

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
    clib_arg_t *args;
    clib_arg_t *sec_if_args;
    u16 data_size;
    void *initial_data;
    vnet_dev_rss_key_t default_rss_key;
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

/* config.c */
void vnet_dev_wait_for_startup_config_complete (vlib_main_t *);

/* dev.c */
vnet_dev_t *vnet_dev_alloc (vlib_main_t *, vnet_dev_device_id_t,
			    vnet_dev_driver_t *);
vnet_dev_op_no_rv_t vnet_dev_free;
vnet_dev_op_t vnet_dev_init;
vnet_dev_op_no_rv_t vnet_dev_deinit;
vnet_dev_op_t vnet_dev_reset;
vnet_dev_op_no_rv_t vnet_dev_detach;
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
clib_error_t *vnet_dev_port_set_max_frame_size (vnet_main_t *, vnet_hw_interface_t *, u32);
u32 vnet_dev_port_eth_flag_change (vnet_main_t *, vnet_hw_interface_t *, u32);
clib_error_t *vnet_dev_port_set_rss_config (vnet_main_t *, vnet_hw_interface_t *,
					    vnet_eth_rss_config_t *);
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

typedef struct
{
  vnet_dev_if_name_t name;
  u16 num_rx_queues;
  u16 num_tx_queues;
  u16 rxq_sz;
  u16 txq_sz;
  u8 default_is_intr_mode : 1;
  u8 consistent_qp : 1;
  u8 queue_per_thread : 1;

  /* return */
  u32 sw_if_index;
} vnet_dev_port_if_create_args_t;

typedef struct
{
  vnet_dev_if_name_t name;
  u8 *args;

  /* return */
  u32 sw_if_index;
} vnet_dev_port_sec_if_create_args_t;

typedef struct
{
  u32 sw_if_index;
} vnet_dev_port_del_sec_if_args_t;

vnet_dev_port_op_t vnet_dev_port_start;
vnet_dev_port_op_t vnet_dev_port_start_all_rx_queues;
vnet_dev_port_op_t vnet_dev_port_start_all_tx_queues;
vnet_dev_port_op_no_rv_t vnet_dev_port_stop;
vnet_dev_port_op_no_rv_t vnet_dev_port_deinit;
vnet_dev_port_op_no_rv_t vnet_dev_port_free;
vnet_dev_port_op_with_ptr_t vnet_dev_port_add_sec_if;
vnet_dev_port_op_with_ptr_t vnet_dev_port_del_sec_if;

void vnet_dev_port_add_counters (vlib_main_t *, vnet_dev_port_t *,
				 vnet_dev_counter_t *, u16);
vnet_dev_port_op_no_rv_t vnet_dev_port_free_counters;
vnet_dev_port_op_no_rv_t vnet_dev_port_update_tx_node_runtime;
void vnet_dev_port_state_change (vlib_main_t *, vnet_dev_port_t *,
				 vnet_dev_port_state_changes_t);
vnet_dev_port_op_no_rv_t vnet_dev_port_clear_counters;
vnet_dev_rv_t
vnet_dev_port_cfg_change_req_validate (vlib_main_t *, vnet_dev_port_t *,
				       vnet_dev_port_cfg_change_req_t *);
vnet_dev_rv_t vnet_dev_port_cfg_change (vlib_main_t *, vnet_dev_port_t *,
					vnet_dev_port_cfg_change_req_t *);
vnet_dev_port_op_with_ptr_t vnet_dev_port_if_create;
vnet_dev_port_op_t vnet_dev_port_if_remove;

/* queue.c */
vnet_dev_rv_t vnet_dev_rx_queue_alloc (vlib_main_t *, vnet_dev_port_t *, u16,
				       vnet_dev_queue_id_t,
				       clib_thread_index_t);
vnet_dev_rv_t vnet_dev_tx_queue_alloc (vlib_main_t *, vnet_dev_port_t *, u16,
				       vnet_dev_queue_id_t);
vnet_dev_rx_queue_op_no_rv_t vnet_dev_rx_queue_free;
vnet_dev_tx_queue_op_no_rv_t vnet_dev_tx_queue_free;
void vnet_dev_rx_queue_add_counters (vlib_main_t *, vnet_dev_rx_queue_t *,
				     vnet_dev_counter_t *, u16);
vnet_dev_rx_queue_op_no_rv_t vnet_dev_rx_queue_free_counters;
void vnet_dev_tx_queue_add_counters (vlib_main_t *, vnet_dev_tx_queue_t *,
				     vnet_dev_counter_t *, u16);
vnet_dev_tx_queue_op_no_rv_t vnet_dev_tx_queue_free_counters;
vnet_dev_rx_queue_op_t vnet_dev_rx_queue_start;
vnet_dev_tx_queue_op_t vnet_dev_tx_queue_start;
vnet_dev_rx_queue_op_no_rv_t vnet_dev_rx_queue_stop;
vnet_dev_tx_queue_op_no_rv_t vnet_dev_tx_queue_stop;

/* process.c */
vnet_dev_op_t vnet_dev_process_create;
vnet_dev_rv_t vnet_dev_process_call_op (vlib_main_t *, vnet_dev_t *,
					vnet_dev_op_t *);
vnet_dev_rv_t vnet_dev_process_call_op_no_rv (vlib_main_t *, vnet_dev_t *,
					      vnet_dev_op_no_rv_t *);
vnet_dev_rv_t vnet_dev_process_call_op_with_ptr (vlib_main_t *, vnet_dev_t *,
						 vnet_dev_op_with_ptr_t *,
						 void *);
void vnet_dev_process_call_op_no_wait (vlib_main_t *, vnet_dev_t *,
				       vnet_dev_op_no_rv_t *);
vnet_dev_rv_t vnet_dev_process_call_port_op (vlib_main_t *, vnet_dev_port_t *,
					     vnet_dev_port_op_t *);
vnet_dev_rv_t vnet_dev_process_call_port_op_no_rv (vlib_main_t *vm,
						   vnet_dev_port_t *,
						   vnet_dev_port_op_no_rv_t *);
vnet_dev_rv_t
vnet_dev_process_call_port_op_with_ptr (vlib_main_t *, vnet_dev_port_t *,
					vnet_dev_port_op_with_ptr_t *, void *);
void vnet_dev_process_call_port_op_no_wait (vlib_main_t *, vnet_dev_port_t *,
					    vnet_dev_port_op_no_rv_t *);
vnet_dev_rv_t
vnet_dev_process_port_cfg_change_req (vlib_main_t *, vnet_dev_port_t *,
				      vnet_dev_port_cfg_change_req_t *);
vnet_dev_op_no_rv_t vnet_dev_process_quit;
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
  clib_thread_index_t thread_index;
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
  u8 debug : 3;
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
format_function_t format_vnet_dev_port_primary_intf_name;
format_function_t format_vnet_dev_rv;
format_function_t format_vnet_dev_rx_queue_info;
format_function_t format_vnet_dev_tx_queue_info;
format_function_t format_vnet_dev_flow;
unformat_function_t unformat_vnet_dev_vector;
unformat_function_t unformat_vnet_dev_flags;
unformat_function_t unformat_vnet_dev_port_flags;
unformat_function_t unformat_vnet_dev_rss_key;

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
