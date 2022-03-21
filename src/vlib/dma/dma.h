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

typedef struct
{
  u8 *src;
  u8 *dst;
  u32 size;
} vlib_dma_transfer_t;

typedef void (*vlib_dma_transfer_fn_t) (vlib_main_t *vm, u32 config_index,
					vlib_dma_transfer_t *args,
					u32 n_transfers, u16 app_hint);
typedef void (*vnet_dma_completion_cb_fn_t) (vlib_main_t *vm,
					     vlib_dma_transfer_t *args,
					     u32 n_transfers, u16 app_hint);

typedef struct
{
  u64 submitted; /* count of dma transfer submitted to dma device */
  u64 completed; /* count of completed dma transfers, exclude failed
		    completions */
  u64 errors;	 /* count of dma transfers failed to complete */
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
  int (*get_capabilities) (void *ctx, vlib_dma_cap_t *cap);
  int (*dma_transfer) (void *ctx, vlib_dma_transfer_t **trans, u16 num,
		       void *opaque, u16 app_hint);
  int (*configure) (void *ctx, u16 size, u32 numa_node,
		    vlib_dma_transfer_t **array);
  u16 (*get_completed) (void *ctx, vlib_dma_transfer_t **trans, void **opaque,
			u16 *app_hint);
  int (*get_stats) (void *ctx, vlib_dma_stats_t *stats);
  int (*reset_stats) (void *ctx);
} vlib_dma_config_fn_t;

typedef struct
{
  char *name;
  const vlib_dma_config_fn_t *config_fn;
} vlib_dma_register_backend_args_t;

typedef struct
{
  char *name;
  vlib_dma_config_fn_t *fn;	    /* ops provided by backend */
  vlib_dma_backend_status_t status; /* backend status */
  void *ctx;			    /* dma context for each backend */
} vlib_dma_backend_t;

typedef struct
{
  vlib_dma_backend_t *backend;
  vnet_dma_completion_cb_fn_t
    cb; /* callback funcion when transfer completed */
} vlib_dma_config_data_t;

typedef struct
{
  vlib_dma_config_data_t data; /* per config private data */
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
  vnet_dma_completion_cb_fn_t
    cb; /* callback function calld when trasfer is complete */
} vlib_dma_config_args_t;

/* request dma backend for dma config, return -1 when failed */
int vlib_dma_config (vlib_main_t *vm, vlib_dma_config_args_t *args,
		     vlib_dma_transfer_t **array);
/* release dma config and its backend */
int vlib_dma_release (vlib_main_t *vm, u32 config_index);

#define VLIB_DMA_FRAME_POOL_SIZE 1024
typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  vlib_dma_backend_t *backend;	   /* assigned backends */
  vlib_dma_config_t **reg_configs; /* registered configs */
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

int vlib_dma_register_backend (vlib_main_t *vm, void *ctx,
			       vlib_dma_register_backend_args_t *args);

static_always_inline void
dma_sw_copy (vlib_dma_transfer_t **args, u32 n_transfers)
{
  u32 i;
  vlib_dma_transfer_t *transfer;
  for (i = 0; i < n_transfers; i++)
    {
      transfer = args[i];
      clib_memcpy_fast (transfer->dst, transfer->src, transfer->size);
    }
}

static_always_inline u32
vlib_dma_transfer (vlib_main_t *vm, u32 config_index,
		   vlib_dma_transfer_t **args, u32 n_transfers, u16 app_hint)
{
  vlib_dma_main_t *dm = &dma_main;
  vlib_dma_config_t *config = dm->configs + config_index;
  vlib_dma_backend_t *backend;

  if (PREDICT_FALSE (config == NULL) || n_transfers == 0)
    return 0;

  backend = config->data.backend;
  /* fallback to software copy when no backend */
  if (PREDICT_FALSE (backend == NULL))
    dma_sw_copy (args, n_transfers);
  else
    backend->fn->dma_transfer (backend->ctx, args, n_transfers,
			       config->data.cb, app_hint);
  config->n_transfers += n_transfers;
  return n_transfers;
}

format_function_t format_dma_config;
format_function_t format_dma_backend;

#endif /* included_vlib_dma_h */
