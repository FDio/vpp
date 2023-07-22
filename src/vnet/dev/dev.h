/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#ifndef _VNET_DEV_H_
#define _VNET_DEV_H_

#include <vppinfra/clib.h>
#include <vppinfra/error_bootstrap.h>
#include <vppinfra/format.h>
#include <vlib/node.h>
#include <vnet/vnet.h>

#define VNET_DEV_MAX_DEVICE_ID_LEN	    32
#define VNET_DEV_MAX_IF_NAME_LEN	    16
#define VNET_DEV_MAX_DRIVER_NAME_LEN	    16
#define VNET_DEV_MAX_BUS_NAME_LEN	    6
#define VNET_DEV_DEVICE_ID_PREFIX_DELIMITER "/"

#define foreach_vnet_dev_rv_type                                              \
  _ (1, TIMEOUT, "timeout")                                                   \
  _ (2, RESOURCE_NOT_AVAILABLE, "resource not available")                     \
  _ (3, BUS, "bus error")                                                     \
  _ (4, DRIVER_NOT_AVAILABLE, "driver not available")                         \
  _ (5, PHYSMEM_ALLOC, "DMA memory allocation error")                         \
  _ (6, BUFFER_ALLOC_FAIL, "packet buffer allocation failure")                \
  _ (7, PROCESS_REPLY, "dev process reply error")                             \
  _ (8, ALREADY_IN_USE, "already in use")                                     \
  _ (9, NOT_FOUND, "not found")                                               \
  _ (10, INVALID_DEVICE_ID, "invalid device id")                              \
  _ (11, INVALID_PORT_ID, "invalid port id")                                  \
  _ (12, INVALID_NUM_RX_QUEUES, "invalid number of rx queues")                \
  _ (13, INVALID_NUM_TX_QUEUES, "invalid number of tx queues")                \
  _ (14, INVALID_RX_QUEUE_SIZE, "invalid rx queue size")                      \
  _ (15, INVALID_TX_QUEUE_SIZE, "invalid tx queue size")                      \
  _ (16, NOT_READY, "not ready")                                              \
  _ (17, DEVICE_NO_REPLY, "no reply from device")                             \
  _ (18, UNSUPPORTED_DEV_VER, "unsupported device version")

typedef enum
{
  VNET_DEV_OK = 0,
#define _(v, n, d) VNET_DEV_ERR_##n = -(v),
  foreach_vnet_dev_rv_type
#undef _
} vnet_dev_rv_t;

#define foreach_vnet_dev_port_type                                            \
  _ (0, UNKNOWN)                                                              \
  _ (1, ETHERNET)

#define VNET_DEV_MAX_HW_ADDR_SZ	     6
#define VNET_DEV_THREAD_NOT_ASSIGNED 0xffff

typedef enum
{
#define _(b, n) VNET_DEV_PORT_TYPE_##n = (1U << (b)),
  foreach_vnet_dev_port_type
#undef _
} vnet_dev_port_type_t;

typedef struct vnet_dev vnet_dev_t;
typedef struct vnet_dev_port vnet_dev_port_t;
typedef struct vnet_dev_rx_queue vnet_dev_rx_queue_t;
typedef struct vnet_dev_tx_queue vnet_dev_tx_queue_t;
typedef struct vnet_dev_bus_registration vnet_dev_bus_registration_t;
typedef struct vnet_dev_driver_registration vnet_dev_driver_registration_t;

typedef vnet_dev_rv_t (vnet_dev_op_t) (vlib_main_t *, vnet_dev_t *);
typedef vnet_dev_rv_t (vnet_dev_port_op_t) (vlib_main_t *, vnet_dev_port_t *);
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

typedef u16 vnet_dev_port_id_t;
typedef u16 vnet_dev_queue_id_t;
typedef u16 vnet_dev_bus_index_t;
typedef u16 vnet_dev_driver_index_t;

typedef struct
{
  vnet_dev_rx_queue_op_t *alloc;
  vnet_dev_rx_queue_op_t *start;
  vnet_dev_rx_queue_op_no_rv_t *stop;
  vnet_dev_rx_queue_op_no_rv_t *free;
} vnet_dev_rx_queue_ops_t;

typedef struct
{
  vnet_dev_tx_queue_op_t *alloc;
  vnet_dev_tx_queue_op_t *start;
  vnet_dev_tx_queue_op_no_rv_t *stop;
  vnet_dev_tx_queue_op_no_rv_t *free;
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

typedef struct
{
  u8 hw_addr[VNET_DEV_MAX_HW_ADDR_SZ];
  u16 max_rx_queues;
  u16 max_tx_queues;
  u16 max_frame_size;
  u16 data_size;
  vnet_dev_port_type_t type;
} vnet_dev_port_config_t;

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
    vnet_dev_op_t *dev_op;
    vnet_dev_port_op_t *port_op;
    void *op;
  };
} vnet_dev_periodic_op_t;

typedef struct
{
  struct _vlib_node_fn_registration *registrations;
} vnet_dev_node_fn_t;

typedef struct
{
  vnet_dev_node_fn_t *node_fn;
  format_function_t *format_trace;
  vlib_error_desc_t *error_counters;
  u16 n_error_counters;
} vnet_dev_node_t;

typedef struct
{
  vnet_dev_op_t *device_init;
  vnet_dev_op_no_rv_t *device_free;
  u8 *(*probe) (vlib_main_t *, vnet_dev_bus_index_t, void *);
  format_function_t *format_info;
} vnet_dev_ops_t;

typedef struct
{
  vnet_dev_port_op_t *init;
  vnet_dev_port_op_t *config_change;
  vnet_dev_port_op_t *start;
  vnet_dev_port_op_no_rv_t *stop;
  vnet_dev_port_op_no_rv_t *free;
  format_function_t *format_status;
} vnet_dev_port_ops_t;

typedef struct vnet_dev_rx_queue
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  u8 started : 1;
  vnet_dev_port_t *port;
  u16 rx_thread_index;
  u8 rx_thread_assigned;
  u16 index;
  CLIB_CACHE_LINE_ALIGN_MARK (runtime0);
  vnet_dev_queue_id_t queue_id;
  u16 size;
  u8 buffer_pool_index;
  CLIB_ALIGN_MARK (private_data, 16);
  u8 data[];
} vnet_dev_rx_queue_t;

STATIC_ASSERT_SIZEOF (vnet_dev_rx_queue_t, 2 * CLIB_CACHE_LINE_BYTES);

typedef struct vnet_dev_tx_queue
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  vnet_dev_port_t *port;
  u16 index;
  CLIB_CACHE_LINE_ALIGN_MARK (runtime0);
  vnet_dev_queue_id_t queue_id;
  u8 started : 1;
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
  vnet_dev_port_type_t type;
  vnet_dev_driver_index_t driver_index;
  u8 started : 1;
  u8 admin_up : 1;
  u8 link_up : 1;
  u8 rx_node_created : 1;
  u8 interface_assigned : 1;
  vnet_dev_queue_config_t rx_queue_config;
  vnet_dev_queue_config_t tx_queue_config;
  vnet_dev_port_config_t config;
  u32 index;
  u32 dev_if_index;
  u32 rx_node_index;
  u32 speed;
  vnet_dev_rx_queue_t **rx_queues;
  vnet_dev_tx_queue_t **tx_queues;
  vnet_dev_port_ops_t port_ops;
  vnet_dev_rx_queue_ops_t rx_queue_ops;
  vnet_dev_tx_queue_ops_t tx_queue_ops;
  vnet_dev_node_t rx_node;
  vnet_dev_node_t tx_node;
  CLIB_CACHE_LINE_ALIGN_MARK (data0);
  u8 data[];
} vnet_dev_port_t;

typedef struct vnet_dev
{
  char device_id[VNET_DEV_MAX_DEVICE_ID_LEN];
  u16 initialized : 1;
  u16 va_dma : 1;
  u16 bus_index;
  u8 numa_node;
  u16 max_rx_queues;
  u16 max_tx_queues;
  vnet_dev_driver_index_t driver_index;
  u32 index;
  u32 process_node_index;
  u8 bus_data[16] __clib_aligned (16);
  vnet_dev_ops_t ops;
  vnet_dev_port_t **ports;
  vnet_dev_periodic_op_t *periodic_ops;
  u8 *description;
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
  format_function_t *format_device_info;
  format_function_t *format_device_addr;
} vnet_dev_bus_ops_t;

struct vnet_dev_bus_registration
{
  vnet_dev_bus_registration_t *next_registration;
  char name[VNET_DEV_MAX_DRIVER_NAME_LEN];
  u16 device_data_size;
  vnet_dev_bus_ops_t ops;
};

struct vnet_dev_driver_registration
{
  vnet_dev_driver_registration_t *next_registration;
  u8 bus_master_enable : 1;
  char name[VNET_DEV_MAX_DRIVER_NAME_LEN];
  char bus[VNET_DEV_MAX_BUS_NAME_LEN];
  u16 device_data_sz;
  vnet_dev_match_t *match;
  int priority;
  vnet_dev_ops_t ops;
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
  char name[VNET_DEV_MAX_IF_NAME_LEN];
  vnet_dev_driver_index_t driver_index;
  u16 dev_index;
  u16 port_index;
  u32 hw_if_index;
  u32 sw_if_index;
} vnet_dev_if_t;

typedef struct
{
  vnet_dev_bus_t *buses;
  vnet_dev_driver_t *drivers;
  vnet_dev_t **devices;
  vnet_dev_bus_registration_t *bus_registrations;
  vnet_dev_driver_registration_t *driver_registrations;
  vnet_dev_if_t *interfaces;
  u32 *free_process_node_indices;
  u32 *free_rx_node_indices;
  uword *device_index_by_id;

  u8 *startup_config;
  u16 next_rx_queue_thread;
} vnet_dev_main_t;

extern vnet_dev_main_t vnet_dev_main;

typedef struct
{
  char device_id[VNET_DEV_MAX_DEVICE_ID_LEN];
  char driver_name[VNET_DEV_MAX_IF_NAME_LEN];
} vnet_dev_attach_args_t;

typedef struct
{
  char device_id[VNET_DEV_MAX_DEVICE_ID_LEN];
} vnet_dev_detach_args_t;

typedef struct
{
  char device_id[VNET_DEV_MAX_DEVICE_ID_LEN];
  char intf_name[VNET_DEV_MAX_IF_NAME_LEN];
  u16 num_rx_queues;
  u16 num_tx_queues;
  u16 rx_queue_size;
  u16 tx_queue_size;
  vnet_dev_port_id_t port_id;
} vnet_dev_create_if_args_t;

typedef struct
{
  struct
  {
    vnet_dev_port_config_t config;
    vnet_dev_port_ops_t ops;
  } port;

  vnet_dev_node_t rx_node;
  vnet_dev_node_t tx_node;

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
      u8 admin_state : 1;
    };
    u8 any;
  } change;
  u8 admin_state : 1;
} vnet_dev_port_config_changes_t;

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

/* dev.c */
vnet_dev_rv_t vnet_dev_attach (vlib_main_t *, vnet_dev_attach_args_t *);
vnet_dev_rv_t vnet_dev_detach (vlib_main_t *, vnet_dev_detach_args_t *);
vnet_dev_rv_t vnet_dev_create_if (vlib_main_t *, vnet_dev_create_if_args_t *);

vnet_dev_rv_t vnet_dev_port_add (vlib_main_t *, vnet_dev_t *,
				 vnet_dev_port_id_t,
				 vnet_dev_port_add_args_t *);
void vnet_dev_port_state_change (vlib_main_t *, vnet_dev_port_t *,
				 vnet_dev_port_state_changes_t);
vnet_dev_rv_t vnet_dev_port_config_change (vlib_main_t *, vnet_dev_port_t *,
					   vnet_dev_port_config_changes_t);
vnet_dev_rv_t vnet_dev_dma_mem_alloc (vlib_main_t *, vnet_dev_t *, u32, u32,
				      void **);
void vnet_dev_dma_mem_free (vlib_main_t *, vnet_dev_t *, void *);

/* port.c */
vnet_dev_rv_t vnet_dev_port_start (vlib_main_t *, vnet_dev_port_t *);
void vnet_dev_port_stop (vlib_main_t *, vnet_dev_port_t *);
void vnet_dev_port_remove (vlib_main_t *, vnet_dev_port_t *);

/* process.c */
vnet_dev_rv_t vnet_dev_process_create (vlib_main_t *, vnet_dev_t *);
void vnet_dev_process_quit (vlib_main_t *, vnet_dev_t *);
void vnet_dev_poll_dev_add (vlib_main_t *, vnet_dev_t *, f64, vnet_dev_op_t *);
void vnet_dev_poll_dev_remove (vlib_main_t *, vnet_dev_t *, vnet_dev_op_t *);
void vnet_dev_poll_port_add (vlib_main_t *, vnet_dev_port_t *, f64,
			     vnet_dev_port_op_t *);
void vnet_dev_poll_port_remove (vlib_main_t *, vnet_dev_port_t *,
				vnet_dev_port_op_t *);

/* mgmt.c */
typedef enum
{
  VNET_DEV_MGMT_OP_ACTION_UNKNOWN,
  VNET_DEV_MGMT_OP_ACTION_RX_QUEUE_ASSIGN,
  VNET_DEV_MGMT_OP_ACTION_RX_QUEUE_UNASSIGN,
} __clib_packed vnet_dev_mgmt_op_action_t;

typedef struct
{
  u16 thread_index;
  vnet_dev_mgmt_op_action_t action;
  union
  {
    vnet_dev_rx_queue_t *rx_queue;
    vnet_dev_tx_queue_t *tx_queue;
  };
} vnet_dev_mgmt_op_t;

void vnet_dev_mgmt_add_action (vlib_main_t *, vnet_dev_mgmt_op_t *, u32);

/* format.c */
format_function_t format_vnet_dev_addr;
format_function_t format_vnet_dev_interface_name;
format_function_t format_vnet_dev_interface_info;
format_function_t format_vnet_dev_rv;
format_function_t format_vnet_dev_info;
format_function_t format_vnet_dev_port_info;
format_function_t format_vnet_dev_rx_queue_info;
format_function_t format_vnet_dev_tx_queue_info;

typedef struct
{
  u32 sw_if_index;
  u32 hw_if_index;
  u16 next_index;
  u8 n_rx_queues;
  vnet_dev_rx_queue_t *rx_queues[4];
  vnet_dev_rx_queue_t **rx_queues_ptr;
} vnet_dev_rx_node_runtime_t;

STATIC_ASSERT (sizeof (vnet_dev_rx_node_runtime_t) <=
		 VLIB_NODE_RUNTIME_DATA_SIZE,
	       "must fit into runtime data");

static_always_inline vnet_dev_rx_node_runtime_t *
vnet_dev_get_rx_node_runtime (vlib_node_runtime_t *node)
{
  return (void *) node->runtime_data;
}

typedef struct
{
  u32 hw_if_index;
  u8 lock_required;
  u8 lock;
  vnet_dev_tx_queue_t *tx_queue;
} vnet_dev_tx_node_runtime_t;

STATIC_ASSERT (sizeof (vnet_dev_tx_node_runtime_t) <=
		 VLIB_NODE_RUNTIME_DATA_SIZE,
	       "must fit into runtime data");

static_always_inline vnet_dev_tx_node_runtime_t *
vnet_dev_get_tx_node_runtime (vlib_node_runtime_t *node)
{
  return (void *) node->runtime_data;
}

static_always_inline vnet_dev_rx_queue_t **
foreach_vnet_dev_rx_queue_runtime_helper (vlib_node_runtime_t *node)
{
  vnet_dev_rx_node_runtime_t *rt = vnet_dev_get_rx_node_runtime (node);
  if (PREDICT_TRUE (rt->n_rx_queues <= ARRAY_LEN (rt->rx_queues)))
    return rt->rx_queues;
  return rt->rx_queues_ptr;
}

#define foreach_vnet_dev_rx_queue_runtime(q, node)                            \
  for (vnet_dev_rx_queue_t *                                                  \
	 *__qp = foreach_vnet_dev_rx_queue_runtime_helper (node),             \
	**__last = __qp + (vnet_dev_get_rx_node_runtime (node))->n_rx_queues, \
	*(q) = *__qp;                                                         \
       __qp < __last; __qp++, (q) = *__qp)

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
    extern vnet_dev_node_fn_t node;                                           \
    vlib_node_fn_registration_t *r;                                           \
    r = &CLIB_MARCH_SFX (node##_fn_registration);                             \
    r->march_variant = CLIB_MARCH_SFX (CLIB_MARCH_VARIANT_TYPE);              \
    r->next_registration = (node).registrations;                              \
    (node).registrations = r;                                                 \
  }                                                                           \
  uword CLIB_MARCH_SFX (node##_fn)

#include <vnet/dev/dev_funcs.h>

#endif /* _VNET_DEV_H_ */
