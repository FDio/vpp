/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2022 Cisco Systems, Inc.
 */

#ifndef __dma_intel_dma_intel_h__
#define __dma_intel_dma_intel_h__

#include <vlib/vlib.h>
#include <vlib/dma/dma.h>
#include <vlib/pci/pci.h>
#include <vppinfra/format.h>

typedef struct
{
  u32 size;
  union
  {
    u32 desc_control;
    struct
    {
      u32 int_comp : 1;
      u32 source_snoop : 1;
      u32 dst_snoop : 1;
      u32 comp_upd : 1;
      u32 fence : 1;
      u32 null_transfer : 1;
      u32 src_pg_break : 1;
      u32 dst_pg_break : 1;
      u32 bundle : 1;
      u32 dst_dca_ena : 1;
      u32 buffer_hint : 1;
      u32 resv_11_23 : 13;
      u32 op_type : 8;
    };
  };
  void *src;
  void *dst;
  void *next;
  u64 qw[4];
} intel_cbdma_desc_t;

STATIC_ASSERT_SIZEOF (intel_cbdma_desc_t, 64);

typedef struct
{
  union
  {
    u8 chancnt;
    u8 chancnt_num_chan : 4;
  };
  u8 xfercap;
  u8 genctrl;
  u8 intrctrl;
  u32 attnstatus;
  union
  {
    u8 cbver;
    struct
    {
      u8 cbver_minor : 4;
      u8 cbver_major : 4;
    };
  };
  u8 resv09[3];
  u16 intrdelay;
  u16 cs_status;
  u32 dmacapability;
  u32 dca_offset;
  u8 resv16[0x68];
  u16 chanctrl;
  u16 dma_comp;
  u8 chancmd;
  u16 dmacount;
  u64 chansts;
  void *chainaddr;
  void *chancmp;
  u8 resv_a0_a7[8];
  u32 chanerr;
  u32 chanerrmask;
} intel_cbdma_bar_t;

STATIC_ASSERT_OFFSET_OF (intel_cbdma_bar_t, chansts, 0x88);
STATIC_ASSERT_OFFSET_OF (intel_cbdma_bar_t, chancmp, 0x98);
STATIC_ASSERT_OFFSET_OF (intel_cbdma_bar_t, chanerr, 0xa8);

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  volatile intel_cbdma_bar_t *regs; /* DMA registers */
  volatile void **completion; /* pointer to memory where completion records are
				 written, equal to COMPSTS register */
  intel_cbdma_desc_t *comp_descs; /* ring of completion registers */
  u64 submitted;		  /* number of submitted transfers */
  u64 completed;		  /* number of completed transfers */
  u64 sw_fallback;		  /* number of fall back transfers */
  u16 next;			  /* next completion desc to be used */
  u16 dmacount;			  /* copy of dmacount register */
  u16 n_threads;		  /* number of threads using this channel */
  u16 n_enq;			  /* number of batches currently enqueued */
  u16 mask;			  /* ring mask */
  u8 lock;			  /*  spinlock, only used if m_threads > 1 */
  u8 numa;			  /* numa node */
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline1);
  vlib_pci_dev_handle_t pci_handle;
  vlib_pci_addr_t addr; /* pci addr */
} __clib_packed intel_cbdma_channel_t;

typedef struct intel_cbdma_batch
{
  CLIB_CACHE_LINE_ALIGN_MARK (start);
  vlib_dma_batch_t batch; /* must be first */
  intel_cbdma_channel_t *ch;
  u32 config_heap_index;
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
  u64 completion;
  /* to avoid read-modify-write completion is written as 64-byte
   * DMA FILL operation */
  CLIB_CACHE_LINE_ALIGN_MARK (descriptors);
  intel_cbdma_desc_t descs[0];
} intel_cbdma_batch_t;

STATIC_ASSERT_OFFSET_OF (intel_cbdma_batch_t, batch, 0);

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  intel_cbdma_batch_t batch_template;
  u32 alloc_size;
  u32 max_transfers;
  intel_cbdma_batch_t **freelist;
} intel_cbdma_config_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  intel_cbdma_channel_t *ch; /* channel used by this thread */
  intel_cbdma_batch_t **pending_batches;
} intel_cbdma_thread_t;

typedef struct
{
  intel_cbdma_channel_t ***channels;
  intel_cbdma_thread_t *cbdma_threads;
  intel_cbdma_config_t *cbdma_config_heap;
  uword *cbdma_config_heap_handle_by_config_index;
  /* spin lock protect pmem */
  clib_spinlock_t lock;
} intel_cbdma_main_t;

extern intel_cbdma_main_t intel_cbdma_main;

format_function_t format_cbdma_registers;
format_function_t format_cbdma_descs;
extern vlib_dma_backend_t intel_cbdma_backend;

#define INTEL_CBDMA_LOG2_N_COMPLETIONS 4

extern vlib_log_class_registration_t intel_cbdma_log;

#define cbdma_log_debug(f, ...)                                               \
  vlib_log (VLIB_LOG_LEVEL_DEBUG, intel_cbdma_log.class, "%s: " f, __func__,  \
	    ##__VA_ARGS__)

#endif
