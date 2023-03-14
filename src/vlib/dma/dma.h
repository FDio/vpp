/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2022 Cisco Systems, Inc.
 */

#ifndef included_vlib_dma_h
#define included_vlib_dma_h
#include <vlib/vlib.h>

#define dma_log_debug(f, ...)                                                 \
  vlib_log (VLIB_LOG_LEVEL_DEBUG, dma_log.class, "%s: " f, __func__,          \
	    ##__VA_ARGS__)

#define dma_log_info(f, ...)                                                  \
  vlib_log (VLIB_LOG_LEVEL_INFO, dma_log.class, "%s: " f, __func__,           \
	    ##__VA_ARGS__)

struct vlib_dma_batch;
struct vlib_dma_config_data;

typedef int (vlib_dma_config_add_fn) (vlib_main_t *vm,
				      struct vlib_dma_config_data *cfg);
typedef void (vlib_dma_config_del_fn) (vlib_main_t *vm,
				       struct vlib_dma_config_data *cfg);
typedef struct vlib_dma_batch *(vlib_dma_batch_new_fn) (
  vlib_main_t *vm, struct vlib_dma_config_data *);
typedef int (vlib_dma_batch_submit_fn) (vlib_main_t *vm,
					struct vlib_dma_batch *b);
typedef void (vlib_dma_batch_callback_fn) (vlib_main_t *vm,
					   struct vlib_dma_batch *b);
typedef struct
{
  union
  {
    struct
    {
      u32 barrier_before_last : 1;
      u32 sw_fallback : 1;
    };
    u32 features;
  };
  u16 max_batches;
  u16 max_transfers;
  u32 max_transfer_size;
  vlib_dma_batch_callback_fn *callback_fn;
} vlib_dma_config_t;

typedef struct vlib_dma_batch
{
  vlib_dma_batch_submit_fn *submit_fn;
  vlib_dma_batch_callback_fn *callback_fn;
  uword cookie;
  u16 src_ptr_off;
  u16 dst_ptr_off;
  u16 size_off;
  u16 stride;
  u16 n_enq;
} vlib_dma_batch_t;

typedef struct
{
  char *name;
  vlib_dma_config_add_fn *config_add_fn;
  vlib_dma_config_del_fn *config_del_fn;
  format_function_t *info_fn;
} vlib_dma_backend_t;

typedef struct vlib_dma_config_data
{
  vlib_dma_config_t cfg;
  vlib_dma_batch_new_fn *batch_new_fn;
  uword private_data;
  u32 backend_index;
  u32 config_index;
} vlib_dma_config_data_t;

typedef struct
{
  vlib_dma_backend_t *backends;
  vlib_dma_config_data_t *configs;
} vlib_dma_main_t;

extern vlib_dma_main_t vlib_dma_main;

clib_error_t *vlib_dma_register_backend (vlib_main_t *vm,
					 vlib_dma_backend_t *b);

int vlib_dma_config_add (vlib_main_t *vm, vlib_dma_config_t *b);
void vlib_dma_config_del (vlib_main_t *vm, u32 config_index);
u8 *vlib_dma_config_info (u8 *s, va_list *args);

static_always_inline vlib_dma_batch_t *
vlib_dma_batch_new (vlib_main_t *vm, u32 config_index)
{
  vlib_dma_main_t *dm = &vlib_dma_main;
  vlib_dma_config_data_t *cd = pool_elt_at_index (dm->configs, config_index);

  return cd->batch_new_fn (vm, cd);
}

static_always_inline void
vlib_dma_batch_set_cookie (vlib_main_t *vm, vlib_dma_batch_t *batch,
			   uword cookie)
{
  batch->cookie = cookie;
}

static_always_inline uword
vlib_dma_batch_get_cookie (vlib_main_t *vm, vlib_dma_batch_t *batch)
{
  return batch->cookie;
}

static_always_inline void
vlib_dma_batch_add (vlib_main_t *vm, vlib_dma_batch_t *batch, void *dst,
		    void *src, u32 size)
{
  u8 *p = (u8 *) batch + batch->n_enq * batch->stride;

  *((void **) (p + batch->dst_ptr_off)) = dst;
  *((void **) (p + batch->src_ptr_off)) = src;
  *((u32 *) (p + batch->size_off)) = size;

  batch->n_enq++;
}

static_always_inline void
vlib_dma_batch_submit (vlib_main_t *vm, vlib_dma_batch_t *batch)
{
  batch->submit_fn (vm, batch);
}

#endif
