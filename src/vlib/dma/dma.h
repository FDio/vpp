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

typedef void (*vlib_dma_completion_cb_fn_t) (vlib_main_t *vm, u32 n_transfers,
					     u32 cookie);

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

} vlib_dma_backend_status_t;

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

typedef struct
{
  void *driver_data;
  u16 n_enq;
  u16 stride;
  u16 src_ptr_offset;
  u16 dst_ptr_offset;
  u16 size_offset;
} vlib_dma_transfer_template_t;

typedef struct
{
  int (*get_capabilities) (void *backend, vlib_dma_cap_t *cap);
  u32 (*dma_transfer) (vlib_main_t *vm, vlib_dma_transfer_template_t *template,
		       u32 cookie);
  u32 (*get_completed) (vlib_main_t *vm, void *result_data);
  int (*configure) (void *backend, vlib_main_t *vm,
		    vlib_dma_config_args_t *args, void *backend_data,
		    void *result_data, vlib_dma_transfer_template_t *template);
  int (*get_stats) (void *backend, vlib_dma_stats_t *stats);
  int (*reset_stats) (void *backend);
  u8 *(*dump_info) (void *backend, u8 *s);
} vlib_dma_config_fn_t;

typedef struct
{
  char *name;
  const vlib_dma_config_fn_t *config_fn;
} vlib_dma_register_backend_args_t;

typedef struct
{
  char *name;
  vlib_dma_config_fn_t *fn; /* backend dma ops */
  void *instance;	    /* backend instance*/
  u32 inflight_batch;	    /* backend inflight batch */
  u32 max_transfer;	    /* maximum inflight batch */
  u32 thread_index;	    /* assigned thread index */
  u32 attached_num;	    /* number of configs utilizing this backend */
  vlib_dma_state_t state;   /* whether dma is assigned to specific thread */
  vlib_dma_cap_t cap;	    /* capability of this backend */
} vlib_dma_backend_t;

typedef enum
{
  DMA_TRANSFER_NULL,
  DMA_TRANSFER_INFLIGHT,
  DMA_TRANSFER_FINISHED,
  DMA_TRANSFER_FALLBACK,
} vlib_dma_transfer_state_t;

typedef struct
{
  vlib_dma_transfer_state_t state;
  uword record_addr;
  u32 cookie;
  u32 n_transfers;
} vlib_dma_record_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  vlib_dma_config_fn_t *fn; /* ops provided by backend */

  void *backend_data; /* per config datapath context */
  u32 data_num;	      /* number of dma buffer */
  u32 data_head;      /* dma buffer ring header */
  u32 data_tail;      /* dma buffer ring tail */
  u32 data_size;      /* size each backend data */

  void *result_data;		  /* per config results data */
  vlib_dma_record_t *results;	  /* per config results ring */
  vlib_dma_completion_cb_fn_t cb; /* direct callback for cpu */

  u32 backend_index;			 /* backend index */
  vlib_dma_transfer_template_t template; /* template of dma transfer */
  u8 cpu_fallback : 1;			 /* do cpu fallback in no resource */
  /* stats */
  u64 n_bytes;
  u64 n_transfers;
} vlib_dma_config_t;

typedef struct __attribute__ ((packed, aligned (64)))
{
  u64 data[8];
} dma_desc_t;

typedef struct __attribute__ ((packed, aligned (64)))
{
  dma_desc_t private_data;
  dma_desc_t result;
} dma_result_t;

typedef struct __attribute__ ((packed, aligned (64)))
{
  dma_desc_t private_data;
  dma_desc_t batch_desc;
  dma_desc_t desc[0];
} vlib_dma_backend_data_t;

#define dma_backend_data_size(num)                                            \
  sizeof (vlib_dma_backend_data_t) + num * sizeof (dma_desc_t);

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

typedef struct
{
  u8 *dst;
  u8 *src;
  u32 size;
} vlib_dma_transfer_t;

extern vlib_dma_main_t dma_main;

int vlib_dma_register_backend (vlib_main_t *vm, void *instance,
			       vlib_dma_register_backend_args_t *args);

#define DMA_DRIVER_DATE config->template.driver_data
#define DMA_STRIDE	config->template.stride
#define DMA_DST_OFFSET	config->template.dst_ptr_offset
#define DMA_SRC_OFFSET	config->template.src_ptr_offset
#define DMA_SIZE_OFFSET config->template.size_offset
#define DMA_DESC_ADDR(type, i)                                                \
  (DMA_DRIVER_DATE + i * DMA_STRIDE + DMA_##type##_OFFSET)

#define DMA_DATA_ADDR(config)                                                 \
  config->backend_data + config->data_tail * config->data_size

#define DMA_ADD_ONE_TRANSFER(i)                                               \
  do                                                                          \
    {                                                                         \
      vlib_dma_transfer_t *dma_transfer = args + i;                           \
      *(u8 **) (DMA_DESC_ADDR (DST, i)) = dma_transfer->dst;                  \
      *(u8 **) (DMA_DESC_ADDR (SRC, i)) = dma_transfer->src;                  \
      *(u32 *) (DMA_DESC_ADDR (SIZE, i)) = dma_transfer->size;                \
      config->n_transfers++;                                                  \
      config->n_bytes += dma_transfer->size;                                  \
      config->template.n_enq++;                                               \
    }                                                                         \
  while (0);

#define DMA_FALLBACK_TRANSFER(iov, i)                                         \
  do                                                                          \
    {                                                                         \
      vlib_dma_transfer_t *dma_transfer = iov + i;                            \
      clib_memcpy_fast (dma_transfer->dst, dma_transfer->src,                 \
			dma_transfer->size);                                  \
    }                                                                         \
  while (0);

#define DMA_CONFIG_ADD_TAIL(config)                                           \
  do                                                                          \
    {                                                                         \
      config->data_tail++;                                                    \
      if (config->data_tail == config->data_num)                              \
	config->data_tail = 0;                                                \
    }                                                                         \
  while (0);

#define DMA_CONFIG_ADD_HEAD(config)                                           \
  do                                                                          \
    {                                                                         \
      config->data_head++;                                                    \
      if (config->data_head == config->data_num)                              \
	config->data_head = 0;                                                \
    }                                                                         \
  while (0);

/** \brief Initiate n dma transfers
 * @param vm            vm vlib_main_t pointer
 * @param config_index  index of config
 * @param args          transfer vectors
 * @param n_transfers   n_transfers
 * @param cookie        value returned in completion callback
 * @return 0 on success, ~0 on error
 */
static_always_inline u32
vlib_dma_transfer (vlib_main_t *vm, u32 config_index,
		   vlib_dma_transfer_t *args, u32 n_transfers, u32 cookie)
{
  vlib_dma_main_t *dm = &dma_main;
  vlib_dma_config_t *config = vec_elt_at_index (dm->configs, config_index);
  vlib_dma_backend_t *backend =
    vec_elt_at_index (dm->backends, config->backend_index);
  u32 i, ret;
  u32 slots;
  if (config->data_tail >= config->data_head)
    slots = config->data_tail - config->data_head;
  else
    slots = config->data_num - config->data_head + config->data_tail;

  if (slots == config->data_num)
    return ~0;

  vlib_dma_record_t *record = config->results + config->data_tail;
  record->cookie = cookie;

  if (backend->inflight_batch == backend->max_transfer && config->cpu_fallback)
    {
      for (i = 0; i < n_transfers; i++)
	DMA_FALLBACK_TRANSFER (args, i);

      record->state = DMA_TRANSFER_FALLBACK;
      record->n_transfers = n_transfers;
      DMA_CONFIG_ADD_TAIL (config);
      return 0;
    }

  void *driver_data = DMA_DATA_ADDR (config);
  config->template.driver_data = driver_data;
  config->template.n_enq = 0;

  for (i = 0; i < n_transfers; i++)
    DMA_ADD_ONE_TRANSFER (i);
  config->template.n_enq = i;
  ret = config->fn->dma_transfer (vm, &config->template, cookie);

  record->state = DMA_TRANSFER_INFLIGHT;
  record->n_transfers = n_transfers;
  backend->inflight_batch++;
  DMA_CONFIG_ADD_TAIL (config);

  if (PREDICT_FALSE (ret != n_transfers))
    return ~0;

  return 0;
}

/** \brief Retrieve completed transfers of config
 * @param vm            vm vlib_main_t pointer
 * @param config_index  index of config
 * @param cb            callback function of config
 * @param cookie        cookie saved when requested transfer
 * @return number of completed transfers
 */
static_always_inline u32
vlib_dma_get_completed (vlib_main_t *vm, u32 config_index,
			vlib_dma_completion_cb_fn_t *cb, u32 *cookie)
{
  vlib_dma_main_t *dm = &dma_main;
  u32 ret, num = 0;
  vlib_dma_config_t *config = vec_elt_at_index (dm->configs, config_index);
  vlib_dma_backend_t *backend =
    vec_elt_at_index (dm->backends, config->backend_index);

  if (config->data_head == config->data_tail)
    return 0;

  vlib_dma_record_t *record = config->results + config->data_head;
  if (record->state == DMA_TRANSFER_INFLIGHT)
    {
      ret = config->fn->get_completed (vm, (void *) record->record_addr);
      if (!ret)
	{
	  backend->inflight_batch--;
	  record->state = DMA_TRANSFER_NULL;
	}
    }

  if (!ret || record->state == DMA_TRANSFER_FALLBACK)
    {
      DMA_CONFIG_ADD_HEAD (config);
      *cookie = record->cookie;
      *cb = config->cb;
      num = record->n_transfers;
    }

  return num;
}

/** \brief Dump backend internal information
 * @param config_index  index of config
 * @param s             string
 * @return string contain internal information
 */
static_always_inline u8 *
vlib_dma_dump_info (u32 config_index, u8 *s)
{
  vlib_dma_main_t *dm = &dma_main;
  vlib_dma_config_t *config = dm->configs + config_index;
  return config->fn->dump_info (config->backend_data, s);
}

format_function_t format_dma_config;
format_function_t format_dma_backend;

#endif /* included_vlib_dma_h */
