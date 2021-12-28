/*
 *------------------------------------------------------------------
 * Copyright (c) 2021 Intel and/or its affiliates.
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
 *------------------------------------------------------------------
 */

#ifndef _DSA_H_
#define _DSA_H_

#include <vppinfra/types.h>
#include <vppinfra/error_bootstrap.h>
#include <vppinfra/lock.h>

#include <vlib/log.h>
#include <vlib/pci/pci.h>
#include <vlib/linux/idxd.h>

#define DSA_RING_SZ  4096
#define DSA_BATCH_SZ 64

#define DSA_RING_SZ_MAX 4096
#define DSA_RING_SZ_MIN

#define IDXD_CMD_OP_SHIFT 24
enum dsa_ops
{
  dsa_op_nop = 0,
  dsa_op_batch,
  dsa_op_drain,
  dsa_op_memmove,
  dsa_op_fill
};

#define IDXD_FLAG_FENCE			(1 << 0)
#define IDXD_FLAG_COMPLETION_ADDR_VALID (1 << 2)
#define IDXD_FLAG_REQUEST_COMPLETION	(1 << 3)
#define IDXD_FLAG_CACHE_CONTROL		(1 << 8)

extern vlib_log_class_registration_t dsa_log;

#define dsa_log_err(dev, f, ...)                                              \
  vlib_log (VLIB_LOG_LEVEL_ERR, dsa_log.class, "%U: " f,                      \
	    format_vlib_dsa_addr, &dev->addr, ##__VA_ARGS__)

#define dsa_log_warn(dev, f, ...)                                             \
  vlib_log (VLIB_LOG_LEVEL_WARNING, dsa_log.class, "%U: " f,                  \
	    format_vlib_dsa_addr, &dev->addr, ##__VA_ARGS__)

#define dsa_log_debug(dev, f, ...)                                            \
  vlib_log (VLIB_LOG_LEVEL_DEBUG, dsa_log.class, "%U: " f,                    \
	    format_vlib_dsa_addr, &dev->addr, ##__VA_ARGS__)

typedef struct
{
  union
  {
    struct
    {
      u32 pasid;
      u32 op_flags;
      uword completion;

      union
      {
	uword src;	 /* source address for copy ops etc. */
	uword desc_addr; /* descriptor pointer for batch */
      };
      uword dst;

      u32 size;	       /* length of data for op, or batch size */
      u16 intr_handle; /* completion interrupt handle */

      /* remaining 26 bytes are reserved */
      u16 __reserved[13];
    };
    u64 qword[8];
#ifdef CLIB_HAVE_VEC512
    u64x8 as_u64x8;
#endif
  };
} dsa_desc_t;

typedef struct __attribute__ ((aligned (32)))
{
  union
  {
    struct
    {
      u8 status;
      u8 result;
      /* 16-bits pad here */
      u16 pad;
      u32 completed_size; /* data length, or descriptors for batch */

      uword fault_address;
      u32 invalid_flags;
    };
    u64 qword[4];
#ifdef CLIB_HAVE_VEC512
    u64x4 as_u64x4;
#endif
  };
} dsa_completion_t;

STATIC_ASSERT_SIZEOF (dsa_desc_t, 64);

typedef struct
{
  u64 enqueue_failed;
  u64 enqueued;
  u64 started;
  u64 completed;
} dsa_stats_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  // stats
  dsa_stats_t xstats;
  // what should be in the device
  vlib_main_t *vm;
  u32 numa_node;
  u32 dev_instance;
  vlib_dsa_dev_handle_t dsa_dev_handle;
  vlib_dsa_addr_t addr;
  u8 *name;
  // portal
  void *portal;
  // for desc addr convert
  uword desc_iova;
  // batch required
  u16 max_batches;
  // current batch info
  u16 batch_idx_read;
  u16 batch_idx_write;

  u16 batch_start;
  u16 batch_size;

  u16 batch_check_start;
  u16 *batch_idx_ring;
  u64 nop_op;
  // desc ring
  u16 desc_ring_mask;
  dsa_desc_t *desc_ring;

} dsa_device_t;

typedef struct
{
  u16 msg_id_base;

  dsa_device_t **devices;
} dsa_main_t;

extern dsa_main_t dsa_main;

typedef struct
{
  vlib_dsa_addr_t addr;
  u8 *name;
  u16 ring_size;
  u16 batch_size;
  /* return */
  int rv;
  clib_error_t *error;
} dsa_create_args_t;

typedef struct memcpy_info_
{
  uint64_t src_addr;
  uint64_t dst_addr;
  uint64_t length;
} memcpy_info_t;

int dsa_create_device (vlib_main_t *vm, dsa_create_args_t *args);
void dsa_delete_device (vlib_main_t *vm, u32 dev_instance);
int dsa_enqueue_copy (vlib_dsa_dev_handle_t h, uint64_t src, uint64_t dst,
		      u32 length);
void dsa_do_copies (vlib_dsa_dev_handle_t h);
int dsa_get_enqueued_count (vlib_dsa_dev_handle_t h);
int dsa_get_completed_count (vlib_dsa_dev_handle_t h);

static_always_inline dsa_device_t *
dsa_get_device (u32 dev_instance)
{
  if (!dsa_main.devices)
    return NULL;
  return pool_elt_at_index (dsa_main.devices, dev_instance)[0];
}

#endif /* DSA_H */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
