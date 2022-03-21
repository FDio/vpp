/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2022 Cisco Systems, Inc.
 * Copyright (c) 2022 Intel and/or its affiliates.
 */

#ifndef included_vlib_dma_h
#define included_vlib_dma_h
#include <vlib/vlib.h>
#include <stdbool.h>
#include <vppinfra/llist.h>

typedef struct
{
#define DMA_CAPA_DEV_TO_MEM	(1 << 1)
#define DMA_CAPA_MEM_TO_DEV	(1 << 2)
#define DMA_CAPA_SVA		(1 << 3)
#define DMA_CAPA_HANDLE_ERROR	(1 << 4)
#define DMA_CAPA_SCATTER_GATHER (1 << 5)
  u32 dma_cap;
  u32 max_transfers;
  u32 max_transfer_size;
  bool ordered;
  u16 numa_node;
} vlib_dma_cap_t;

typedef void (*vlib_dma_completion_cb_fn_t) (vlib_main_t *vm, u16 n_transfers,
					     u16 cookie);

typedef struct
{
  u64 submitted; /* count of dma transfer submitted to dma device */
  u64 completed; /* count of completed dma transfers, exclude failed
		    completions */
  u64 fallback;	 /* count of dma transfers fallbacked to cpu */
} vlib_dma_stats_t;

typedef enum
{
  /* dma device is unused */
  DMA_BACKEND_UNUSED,
  /* dma backend is ready for service */
  DMA_BACKEND_READY,
  /* dma backend assigned to work thread */
  DMA_BACKEND_ASSIGNED,
} vlib_dma_state_t;
typedef struct
{
  u32 thread_index;	  /* assigned thread index */
  u32 config_num;	  /* number of configs utilizing this backend */
  vlib_dma_state_t state; /* whether dma is assigned to specific thread */
  vlib_dma_cap_t cap;	  /* capability of this backend */
} vlib_dma_backend_status_t;

typedef struct
{
  int (*get_capabilities) (void *backend, vlib_dma_cap_t *cap);
  void (*add_dma_transfer) (vlib_main_t *vm, void *backend_data, u8 *dst,
			    u8 *src, u32 size);
  u16 (*do_dma_transfer) (vlib_main_t *vm, void *backend_data, u16 cookie);
  u16 (*get_completed) (vlib_main_t *vm, void *backend_data,
			vlib_dma_completion_cb_fn_t *cb, u16 *cookie);
  int (*configure) (vlib_main_t *vm, void *backend, u32 flags, u16 size,
		    vlib_dma_completion_cb_fn_t cb, void **backend_data);
  int (*get_stats) (void *backend, vlib_dma_stats_t *stats);
  int (*reset_stats) (void *backend);
} vlib_dma_config_fn_t;

typedef struct
{
  char *name;
  const vlib_dma_config_fn_t *config_fn;
} vlib_dma_register_backend_args_t;

typedef struct
{
  char *name;
  vlib_dma_config_fn_t *fn;	    /* backend dma ops */
  vlib_dma_backend_status_t status; /* backend status */
  void *instance;		    /* backend instance*/
} vlib_dma_backend_t;

typedef struct
{
  vlib_dma_config_fn_t *fn; /* ops provided by backend */
  void *backend_data;	    /* per config datapath context */
  u32 backend_index;
  /* stats */
  u64 n_bytes;
  u64 n_transfers;
} vlib_dma_config_t;

typedef struct
{
  /* flags */
  u32 barrier_before_last : 1; /* ensure last transfer is visible after all
				  previous ones */
  u32 cpu_fallback : 1;	       /* use CPU if no DMA resources available */
  u32 max_transfers;
  u32 max_transfer_size;
  vlib_dma_completion_cb_fn_t
    cb; /* callback function calld when trasfer is complete */
} vlib_dma_config_args_t;

/* request dma backend for dma config, return -1 when failed */
int vlib_dma_config (vlib_main_t *vm, vlib_dma_config_args_t *args);
/* release dma config and its backend */
int vlib_dma_release (vlib_main_t *vm, u32 config_index);

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  vlib_dma_backend_t *backend; /* assigned backends */
  u32 *reg_configs;	       /* registered configs */
  u32 thread_index;
} vlib_dma_thread_t;
typedef struct
{
  vlib_dma_backend_t *backends; /* pool of DMA backends */
  vlib_dma_config_t *configs;	/* pool of DMA configs */
  vlib_dma_thread_t *threads;
  clib_spinlock_t lock;
} vlib_dma_main_t;

extern vlib_dma_main_t dma_main;

int vlib_dma_register_backend (vlib_main_t *vm, void *instance,
			       vlib_dma_register_backend_args_t *args);

static_always_inline void
vlib_dma_add_transfer (vlib_main_t *vm, u32 config_index, u8 *dst, u8 *src,
		       u32 size)
{
  vlib_dma_main_t *dm = &dma_main;
  vlib_dma_config_t *config = vec_elt_at_index (dm->configs, config_index);
  config->fn->add_dma_transfer (vm, config->backend_data, dst, src, size);
  config->n_transfers++;
  config->n_bytes += size;
}

static_always_inline u16
vlib_dma_transfer (vlib_main_t *vm, u32 config_index, u16 cookie)
{
  vlib_dma_main_t *dm = &dma_main;
  vlib_dma_config_t *config = vec_elt_at_index (dm->configs, config_index);
  return config->fn->do_dma_transfer (vm, config->backend_data, cookie);
}

format_function_t format_dma_config;
format_function_t format_dma_backend;

#endif /* included_vlib_dma_h */
