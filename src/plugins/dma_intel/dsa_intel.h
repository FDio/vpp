/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2022 Intel and/or its affiliates.
 */

#ifndef __dma_intel_dsa_intel_h__
#define __dma_intel_dsa_intel_h__

#include <vlib/vlib.h>
#include <vlib/dma/dma.h>
#include <vlib/pci/pci.h>
#include <vppinfra/format.h>
typedef struct
{
  u32 pasid;
  u32 op_flags;
  u64 completion;
  union
  {
    void *src;
    void *desc_addr;
  };
  void *dst;
  u32 size;
  u16 intr_handle;
  /* remaining 26 bytes are reserved */
  u16 __reserved[13];
} intel_dsa_desc_t;

STATIC_ASSERT_SIZEOF (intel_dsa_desc_t, 64);

#define DSA_DEV_PATH "/dev/dsa"
#define SYS_DSA_PATH "/sys/bus/dsa/devices"

typedef enum
{
  INTEL_DSA_DEVICE_TYPE_UNKNOWN,
  INTEL_DSA_DEVICE_TYPE_KERNEL,
  INTEL_DSA_DEVICE_TYPE_USER,
  INTEL_DSA_DEVICE_TYPE_MDEV,
} intel_dsa_wq_type_t;

enum dsa_ops
{
  INTEL_DSA_OP_NOP = 0,
  INTEL_DSA_OP_BATCH,
  INTEL_DSA_OP_DRAIN,
  INTEL_DSA_OP_MEMMOVE,
  INTEL_DSA_OP_FILL
};
#define INTEL_DSA_OP_SHIFT		     24
#define INTEL_DSA_FLAG_FENCE		     (1 << 0)
#define INTEL_DSA_FLAG_BLOCK_ON_FAULT	     (1 << 1)
#define INTEL_DSA_FLAG_COMPLETION_ADDR_VALID (1 << 2)
#define INTEL_DSA_FLAG_REQUEST_COMPLETION    (1 << 3)
#define INTEL_DSA_FLAG_CACHE_CONTROL	     (1 << 8)

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  volatile void *portal; /* portal exposed by dedicated work queue */
  int fd;
  u64 submitted;
  u64 completed;
  u64 sw_fallback;
  u32 max_transfer_size; /* maximum size of each transfer */
  u16 max_transfers;	 /* maximum number referenced in a batch */
  u16 n_threads;	 /* number of threads using this channel */
  u16 n_enq;		 /* number of batches currently enqueued */
  union
  {
    u16 wq_control;
    struct
    {
      u16 type : 2;
      u16 state : 1;
      u16 ats_disable : 1;
      u16 block_on_fault : 1;
      u16 mode : 1;
    };
  };
  u8 lock;     /* spinlock, only used if m_threads > 1 */
  u8 numa;     /* numa node */
  u8 size;     /* size of work queue */
  u8 did;      /* dsa device id */
  u8 qid;      /* work queue id */
  u8 no_batch; /* batch descriptor not allowed */
} intel_dsa_channel_t;

typedef struct intel_dsa_batch
{
  CLIB_CACHE_LINE_ALIGN_MARK (start);
  vlib_dma_batch_t batch; /* must be first */
  intel_dsa_channel_t *ch;
  u32 config_heap_index;
  u32 max_transfers;
  u32 config_index;
  union
  {
    struct
    {
      u32 barrier_before_last : 1;
      u32 sw_fallback : 1;
    };
    u32 features;
  };
  CLIB_CACHE_LINE_ALIGN_MARK (completion_cl);
#define INTEL_DSA_STATUS_IDLE	     0x0
#define INTEL_DSA_STATUS_SUCCESS     0x1
#define INTEL_DSA_STATUS_BUSY	     0xa
#define INTEL_DSA_STATUS_CPU_SUCCESS 0xb
  u8 status;
  /* to avoid read-modify-write completion is written as 64-byte
   * DMA FILL operation */
  CLIB_CACHE_LINE_ALIGN_MARK (descriptors);
  intel_dsa_desc_t descs[0];
} intel_dsa_batch_t;

STATIC_ASSERT_OFFSET_OF (intel_dsa_batch_t, batch, 0);

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  intel_dsa_batch_t batch_template;
  u32 alloc_size;
  u32 max_transfers;
  intel_dsa_batch_t **freelist;
} intel_dsa_config_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  intel_dsa_channel_t *ch; /* channel used by this thread */
  intel_dsa_batch_t **pending_batches;
} intel_dsa_thread_t;

typedef struct
{
  intel_dsa_channel_t ***channels;
  intel_dsa_thread_t *dsa_threads;
  intel_dsa_config_t *dsa_config_heap;
  uword *dsa_config_heap_handle_by_config_index;
  /* spin lock protect pmem */
  clib_spinlock_t lock;
} intel_dsa_main_t;

extern intel_dsa_main_t intel_dsa_main;
extern vlib_dma_backend_t intel_dsa_backend;
format_function_t format_intel_dsa_addr;

#define dsa_log_debug(f, ...)                                                 \
  vlib_log (VLIB_LOG_LEVEL_DEBUG, intel_dsa_log.class, "%s: " f, __func__,    \
	    ##__VA_ARGS__)

#define dsa_log_info(f, ...)                                                  \
  vlib_log (VLIB_LOG_LEVEL_INFO, intel_dsa_log.class, "%s: " f, __func__,     \
	    ##__VA_ARGS__)

#define dsa_log_error(f, ...)                                                 \
  vlib_log (VLIB_LOG_LEVEL_ERR, intel_dsa_log.class, "%s: " f, __func__,      \
	    ##__VA_ARGS__)

#endif
