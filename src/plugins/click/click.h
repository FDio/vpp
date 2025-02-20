/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2025 Cisco Systems, Inc.
 */

#ifndef __click_click_h__
#define __click_click_h__

#include <vlib/vlib.h>
#include <click/vppclick.h>
#include <click/elog.h>

#define CLICK_PKT_Q_SZ		 64
#define CLICK_PKT_ALLOC_BATCH_SZ 64

typedef struct
{
  vppclick_fd_event_t *fd_events;
} click_thread_t;

typedef struct
{
  vppclick_ctx_t *ctx;
  u32 internal_node_index;
  u32 input_node_index;
  f64 *next_run_time;
  u8 *name;
  click_thread_t *threads;
} click_instance_t;

typedef struct
{
  vppclick_pkt_queue_t *to_vpp;
  vppclick_pkt_queue_t *from_vpp;
  u32 instance_index;
} click_interface_t;

typedef struct
{
  u32 instance_index;
  vppclick_ctx_t *ctx;
} click_node_runtime_t;

typedef struct
{
  click_instance_t *instances;
  click_interface_t *interfaces;
} click_main_t;

extern click_main_t click_main;
extern vlib_node_registration_t click_node;
extern vlib_node_registration_t click_input_node;
extern vlib_node_registration_t click_process_node;

typedef struct
{
  u8 *name;
  u8 *router_file;

  /* return */
  u32 index;
} click_instance_create_args_t;

clib_error_t *click_instance_create (vlib_main_t *,
				     click_instance_create_args_t *);

typedef enum
{
  CLICK_PROCESS_EVENT_START = 1,
  CLICK_PROCESS_EVENT_STOP,
} click_process_event_t;

static_always_inline click_node_runtime_t *
click_get_node_rt (vlib_node_runtime_t *rt)
{
  return (void *) rt->runtime_data;
}

static_always_inline click_node_runtime_t *
click_get_node_rt_from_index (vlib_main_t *vm, u32 node_index)
{
  return click_get_node_rt (vlib_node_get_runtime (vm, node_index));
}

/* file.c */
vppclick_register_fd_cb_t click_register_fd;
vppclick_get_fd_events_cb_t click_get_fd_events;

/* packet.c */
vppclick_pkt_alloc_cb_t click_pkt_alloc;
vppclick_pkt_free_cb_t click_pkt_free;

#define log_debug(fmt, ...) vlib_log_debug (click_log.class, fmt, __VA_ARGS__)
#define log_err(fmt, ...)   vlib_log_err (click_log.class, fmt, __VA_ARGS__)

#endif /* __click_click_h__ */
