/*
 * Copyright (c) 2022 Cisco & Intel and/or its affiliates.
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
  u8 *dst;
  u8 *src;
  u32 size;
} vlib_dma_transfer_t;

typedef void (*vlib_dma_transfer_fn_t) (vlib_main_t *vm, u32 config_index,
					vlib_dma_transfer_t *args,
					u32 n_transfers, void *opaque);
typedef int32_t (*vnet_dma_completion_cb_fn_t) (vlib_main_t *vm,
						vlib_dma_transfer_t *args,
						u32 n_transfers, void *opaque);

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
  /* dma backend register to vlib */
  DMA_BACKEND_REGISTERED,
  /* dma backend is ready for service */
  DMA_BACKEND_READY,
} vlib_dma_state_t;

typedef enum
{
  /* dma trans is successful */
  DMA_TRANSFER_SUCCESSFUL,
  /* dma trans is abort due to device stop */
  DMA_TRANSFER_USER_ABORT,
  DMA_TRANSFER_INVALID_ADDR,
  DMA_TRANSFER_INVALID_LENGTH,
  DMA_TRANSFER_BUS_ERROR,
  DMA_TRANSFER_PAGE_FAULT,
  DMA_TRANSFER_UNKNOWN_ERROR,
} vlib_dma_transfer_status_t;

typedef enum vlib_dma_frame_state_t_
{
  VLIB_DMA_FRAME_STATE_NOT_PROCESSED,
  VLIB_DMA_FRAME_STATE_PENDING,
  VLIB_DMA_FRAME_STATE_WORK_IN_PROGRESS,
  VLIB_DMA_FRAME_STATE_SUCCESS,
  VLIB_DMA_FRAME_STATE_ELT_ERROR,
} vlib_dma_frame_state_t;

#define DMA_BACKEND_MAX_CONFIG 4
#define DMA_MAX_CONFIGS	       VLIB_MAX_CPUS * 8

typedef struct
{
  u32 thread_index;   /* assigned thread index */
  u32 config_num;     /* number of configs utilizing this backend */
  bool assigned;      /* whether dma is assigned to specific thread */
  vlib_dma_cap_t cap; /* capability of this backend */
} vlib_dma_backend_status_t;

#define VLIB_DMA_FRAME_SIZE 32
typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  vlib_main_t *vm; /* polling thread same as enqueue thread */
  vlib_dma_transfer_t trans[VLIB_DMA_FRAME_SIZE];
  vlib_dma_frame_state_t state;
  u32 config_index; /* index of gloal configs */
  u16 n_transfers;
  void *opaque;
} vlib_dma_frame_t;

typedef struct
{
  int (*get_capabilities) (void *ctx, vlib_dma_cap_t *cap);
  int (*configure) (void *ctx);
  int (*dma_transfer) (void *ctx, vlib_dma_frame_t *frame);
  u16 (*get_completed_count) (void *ctx, vlib_dma_frame_t **frame);
  u16 (*get_completed_status) (void *ctx, vlib_dma_frame_t *frame,
			       vlib_dma_transfer_status_t *status);
  int (*get_stats) (void *ctx, vlib_dma_stats_t *stats);
  int (*reset_stats) (void *ctx);
  int (*get_state) (void *ctx, vlib_dma_state_t *state);
} vlib_dma_config_fn_t;

typedef struct
{
  char *name;
  const vlib_dma_config_fn_t *config_fn;
} vlib_dma_register_backend_args_t;

typedef struct
{
  char *name;
  vlib_dma_config_fn_t *fn; /* callback funcion provided by backend */
  vlib_dma_backend_status_t status; /* backend status */
  void *ctx;		    /* dma context for each backend */
} vlib_dma_backend_t;

typedef struct
{
  vlib_dma_backend_t *backend;
  vnet_dma_completion_cb_fn_t cb; /* callback funcion when transfer completed */
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
int vlib_dma_config (vlib_main_t *vm, vlib_dma_config_args_t *args);
/* release dma config and its backend */
int vlib_dma_release (vlib_main_t *vm, u32 config_index);

typedef struct
{
  void **frames;
  u32 config_index;
  bool inorder;
  u16 head; /* start of pending frame */
  u16 tail; /* end of pending frame */
  u16 mask;
} vlib_frames_queue_t;

#define VLIB_DMA_FRAME_POOL_SIZE 1024
typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  vlib_dma_frame_t *frame_pool;
  u32 *queue_map;		 /* mapping for quick get queue */
  vlib_dma_backend_t *backend;  /* assigned backends */
  clib_bitmap_t *active_ids;	 /* bitmaps for active backend */
  vlib_frames_queue_t *queues;	 /* list for configs pending frames */
  u32 thread_index;
} vlib_dma_thread_t;

typedef struct
{
  vlib_dma_backend_t *backends;	     /* pool of DMA backends */
  vlib_dma_config_t *configs;	     /* pool of DMA configs */
  vlib_dma_thread_t *threads;
  clib_spinlock_t lock;
} vlib_dma_main_t;

int vlib_dma_register_backend (vlib_main_t *vm, void *ctx,
			       vlib_dma_register_backend_args_t *args);

u32 vlib_dma_transfer (vlib_main_t *vm, u32 config_index,
		       vlib_dma_transfer_t *args, u32 n_transfers,
		       void *opaque);

extern vlib_dma_main_t dma_main;

format_function_t format_dma_config;
format_function_t format_dma_backend;

#endif /* included_vlib_dma_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */