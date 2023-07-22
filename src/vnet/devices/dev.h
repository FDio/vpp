/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#ifndef _VNET_DEV_H_
#define _VNET_DEV_H_

#include "vppinfra/cache.h"
#include <vppinfra/clib.h>
#include <vppinfra/error_bootstrap.h>
#include <vppinfra/format.h>
#include <vlib/pci/pci.h>
#include <vnet/vnet.h>

#define foreach_vnet_dev_rv_type                                              \
  _ (1, TIMEOUT)                                                              \
  _ (2, RESOURCE_NOT_AVAILABLE)                                               \
  _ (3, PCI)

typedef enum
{
  VNET_DEV_OK = 0,
#define _(v, n) VNET_DEV_ERR_##n = -(v),
  foreach_vnet_dev_rv_type
#undef _
} vnet_dev_rv_t;

#define foreach_vnet_dev_bus_type                                             \
  _ (0, UNKNOWN)                                                              \
  _ (1, PCIE)

#define foreach_vnet_dev_port_type                                            \
  _ (0, UNKNOWN)                                                              \
  _ (1, ETHERNET)

#define VNET_DEV_MAX_HW_ADDR_SZ 6

typedef enum
{
#define _(b, n) VNET_DEV_BUS_TYPE_##n = (1U << (b)),
  foreach_vnet_dev_bus_type
#undef _
} vnet_dev_bus_type_t;

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

typedef vnet_dev_rv_t (vnet_dev_op_t) (vlib_main_t *, vnet_dev_t *);
typedef vnet_dev_rv_t (vnet_dev_port_op_t) (vlib_main_t *, vnet_dev_port_t *);
typedef vnet_dev_rv_t (vnet_dev_rx_queue_op_t) (vlib_main_t *,
						vnet_dev_rx_queue_t *);
typedef vnet_dev_rv_t (vnet_dev_tx_queue_op_t) (vlib_main_t *,
						vnet_dev_tx_queue_t *);
typedef u16 vnet_dev_port_id_t;
typedef u16 vnet_dev_queue_id_t;
typedef u16 vnet_dev_driver_index_t;

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
  vnet_dev_op_t *device_init;
  vnet_dev_op_t *device_free;
  vlib_node_function_t *rx_node_fn;
  vlib_node_function_t *tx_node_fn;
  vnet_dev_port_op_t *port_init;
  vnet_dev_port_op_t *port_free;
  vnet_dev_rx_queue_op_t *rx_queue_alloc;
  vnet_dev_rx_queue_op_t *rx_queue_start;
  vnet_dev_rx_queue_op_t *rx_queue_stop;
  vnet_dev_rx_queue_op_t *rx_queue_free;
  vnet_dev_tx_queue_op_t *tx_queue_alloc;
  vnet_dev_tx_queue_op_t *tx_queue_start;
  vnet_dev_tx_queue_op_t *tx_queue_stop;
  vnet_dev_tx_queue_op_t *tx_queue_free;
} vnet_dev_ops_t;

typedef struct vnet_dev_rx_queue
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  vnet_dev_queue_id_t queue_id;
  vnet_dev_port_t *port;
  u16 n_desc;
  CLIB_CACHE_LINE_ALIGN_MARK (data0);
  u8 data[];
} vnet_dev_rx_queue_t;

typedef struct vnet_dev_tx_queue
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  vnet_dev_queue_id_t queue_id;
  vnet_dev_port_t *port;
  u16 n_desc;
  CLIB_CACHE_LINE_ALIGN_MARK (data0);
  u8 data[];
} vnet_dev_tx_queue_t;

typedef struct vnet_dev_port
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  vnet_dev_t *dev;
  vnet_dev_port_id_t port_id;
  vnet_dev_port_type_t type;
  u8 hw_addr[VNET_DEV_MAX_HW_ADDR_SZ];
  vnet_dev_driver_index_t driver_index;
  u16 max_rx_queues;
  u16 max_tx_queues;
  u32 dev_instrance;
  u32 hw_if_index;
  u32 sw_if_index;
  u32 rx_node_index;
  vnet_dev_rx_queue_t **rx_queues;
  vnet_dev_tx_queue_t **tx_queues;
  CLIB_CACHE_LINE_ALIGN_MARK (data0);
  u8 data[];
} vnet_dev_port_t;

typedef struct vnet_dev
{
  u16 initialized : 1;
  u16 va_dma : 1;
  vnet_dev_bus_type_t bus_type;
  u8 numa_node;
  u16 max_rx_queues;
  u16 max_tx_queues;
  vnet_dev_driver_index_t driver_index;
  u32 index;
  u32 process_node_index;
  struct
  {
    vlib_pci_addr_t addr;
    vlib_pci_dev_handle_t handle;
  } pci;
  vnet_dev_ops_t ops;
  vnet_dev_port_t **ports;
  vnet_dev_periodic_op_t *periodic_ops;
  u8 *name;
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
    __VA_ARGS__,                                                              \
    {                                                                         \
    }                                                                         \
  }

typedef struct vnet_dev_registration
{
  struct vnet_dev_registration *next_registration;
  u8 bus_master_enable : 1;
  char *name;
  u16 max_rx_queues;
  u16 max_tx_queues;
  vnet_dev_bus_type_t bus_type;
  u32 device_data_sz;
  vnet_dev_match_t *match;
  int priority;
  vnet_dev_ops_t ops;
} vnet_dev_driver_registration_t;

typedef struct
{
  u32 index;
  void *dev_data;
  vnet_dev_driver_registration_t *registration;
  vnet_dev_t **devices;
  u32 dev_class_index;
} vnet_dev_driver_t;

typedef struct
{
  vnet_dev_driver_index_t driver_index;
  u16 dev_index;
  u16 port_index;
  u8 *name;
} vnet_dev_if_t;

typedef struct
{
  vnet_dev_driver_t *drivers;
  vnet_dev_driver_registration_t *registrations;
  vnet_dev_if_t *interfaces;
  u32 *free_process_node_indices;
} vnet_dev_main_t;

extern vnet_dev_main_t vnet_dev_main;

typedef struct
{
  vlib_pci_addr_t pci_addr;
  u8 *name;
  vnet_dev_bus_type_t bus_type;
} vnet_dev_attach_args_t;

typedef struct
{
  vnet_dev_port_type_t type;
  u8 hw_addr[VNET_DEV_MAX_HW_ADDR_SZ];
  u32 data_sz;
  u16 max_rx_queues;
  u16 max_tx_queues;
} vnet_dev_port_add_args_t;

typedef struct
{
  union
  {
    struct
    {
      u8 link_speed_change : 1;
      u8 link_state_change : 1;
    };
    u8 any;
  };
  u8 link_state;
  u32 link_speed;
} vnet_dev_port_state_changes_t;

/* init.c */
clib_error_t *vnet_dev_attach (vlib_main_t *, vnet_dev_attach_args_t);
clib_error_t *vnet_dev_detach (vlib_main_t *, u32);
clib_error_t *vnet_dev_detach (vlib_main_t *, u32);
void vnet_dev_port_add (vlib_main_t *, vnet_dev_t *, vnet_dev_port_id_t,
			vnet_dev_port_add_args_t);
void vnet_dev_port_state_change (vlib_main_t *vm, vnet_dev_port_t *port,
				 vnet_dev_port_state_changes_t changes);

/* process.c */
void vnet_dev_process_create (vlib_main_t *, vnet_dev_t *);
void vnet_dev_process_quit (vlib_main_t *, vnet_dev_t *);
void vnet_dev_poll_dev_add (vlib_main_t *, vnet_dev_t *, f64, vnet_dev_op_t *);
void vnet_dev_poll_dev_remove (vlib_main_t *, vnet_dev_t *, vnet_dev_op_t *);
void vnet_dev_poll_port_add (vlib_main_t *, vnet_dev_port_t *, f64,
			     vnet_dev_port_op_t *);
void vnet_dev_poll_port_remove (vlib_main_t *, vnet_dev_port_t *,
				vnet_dev_port_op_t *);

/* format.c */
format_function_t format_vnet_dev_addr;
format_function_t format_vnet_dev_interface_name;
format_function_t format_vnet_dev_interface_info;

#define VNET_DEV_REGISTER_DRIVER(x, ...)                                      \
  __VA_ARGS__ vnet_dev_driver_registration_t __vnet_dev_registration_##x;     \
  static void __clib_constructor __vnet_dev_registration_fn_##x (void)        \
  {                                                                           \
    vnet_dev_main_t *dm = &vnet_dev_main;                                     \
    __vnet_dev_registration_##x.next_registration = dm->registrations;        \
    dm->registrations = &__vnet_dev_registration_##x;                         \
  }                                                                           \
  __VA_ARGS__ vnet_dev_driver_registration_t __vnet_dev_registration_##x

static_always_inline void *
vnet_dev_get_data (vnet_dev_t *dev)
{
  return dev->data;
}

static_always_inline vnet_dev_t *
vnet_dev_from_data (void *p)
{
  return (void *) ((u8 *) p - STRUCT_OFFSET_OF (vnet_dev_t, data));
}

static_always_inline void *
vnet_dev_get_port_data (vnet_dev_port_t *port)
{
  return port->data;
}

static_always_inline void *
vnet_dev_get_rx_queue_data (vnet_dev_rx_queue_t *rxq)
{
  return rxq->data;
}

static_always_inline void *
vnet_dev_get_tx_queue_data (vnet_dev_tx_queue_t *txq)
{
  return txq->data;
}

#endif /* _VNET_DEV_H_ */
