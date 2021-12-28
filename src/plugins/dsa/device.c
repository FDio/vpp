/*
 *------------------------------------------------------------------
 * Copyright (c) 2018 Cisco and/or its affiliates.
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

#include <vlib/vlib.h>
#include <vppinfra/ring.h>
#include <vlib/unix/unix.h>
#include <vlib/pci/pci.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/interface/rx_queue_funcs.h>
#include <vnet/interface/tx_queue_funcs.h>

#include <dsa/dsa.h>

VLIB_REGISTER_LOG_CLASS (dsa_log) = {
  .class_name = "dsa",
};

dsa_main_t dsa_main;
void dsa_delete_device (vlib_main_t *vm, u32 dev_instance);

static u8
dsa_validate_args (dsa_create_args_t *args)
{
  // Fixed ring size and batch size in POC
  args->ring_size = DSA_RING_SZ;
  args->batch_size = DSA_BATCH_SZ;

  return 0;
}

int
dsa_create_device (vlib_main_t *vm, dsa_create_args_t *args)
{
  dsa_main_t *dm = &dsa_main;
  dsa_device_t *dd, **ddp;
  vlib_dsa_dev_handle_t h;
  linux_dsa_device_t *ldd;
  clib_error_t *err = 0;

  /* check input args */
  if (dsa_validate_args (args) != 0)
    return -1;

  pool_foreach (ddp, dm->devices)
    {
      if ((*ddp)->addr.as_u32 == args->addr.as_u32)
	{
	  args->rv = VNET_API_ERROR_ADDRESS_IN_USE;
	  args->error = clib_error_return (err, "%U: %s", format_vlib_dsa_addr,
					   &args->addr, "dsa address in use");
	  return (*ddp)->dev_instance;
	}
    }

  pool_get (dm->devices, ddp);
  ddp[0] = dd =
    clib_mem_alloc_aligned (sizeof (dsa_device_t), CLIB_CACHE_LINE_BYTES);
  clib_memset (dd, 0, sizeof (dsa_device_t));
  dd->dev_instance = ddp - dm->devices;
  dd->name = vec_dup (args->name);

  if ((err = vlib_dsa_device_open (vm, &args->addr, &h)))
    goto error;

  dd->dsa_dev_handle = h;
  ldd = linux_dsa_get_device (h);
  dd->numa_node = ldd->numa_node;

  dd->max_batches = args->batch_size;
  dd->desc_ring_mask = args->ring_size - 1;
  // get physical continously memory
  dd->desc_ring = clib_pmalloc_alloc_aligned_on_numa (
    vm->physmem_main.pmalloc_main, args->ring_size * 2 * sizeof (dsa_desc_t),
    CLIB_CACHE_LINE_BYTES, 0);
  if (dd->desc_ring == NULL)
    goto error;
  dd->desc_iova = (uword) dd->desc_ring;

  dd->batch_idx_ring = clib_mem_alloc_aligned (
    (dd->max_batches + 1) * sizeof (u16), CLIB_CACHE_LINE_BYTES);
  if (dd->batch_idx_ring == NULL)
    goto error;

  clib_memset (dd->batch_idx_ring, 0, (dd->max_batches + 1) * sizeof (u16));

  if ((err = vlib_dsa_device_map (vm, h, &dd->portal)))
    goto error;

  return dd->dev_instance;

error:
  dsa_delete_device (vm, dd->dev_instance);
  args->rv = VNET_API_ERROR_INVALID_INTERFACE;
  args->error =
    clib_error_return (err, "dsa-addr %U", format_vlib_dsa_addr, &args->addr);
  dsa_log_err (dd, "error: %U", format_clib_error, args->error);
  return -1;
}

void
dsa_delete_device (vlib_main_t *vm, u32 dev_instance)
{
  dsa_main_t *dm = &dsa_main;
  dsa_device_t *dd;

  dd = dsa_get_device (dev_instance);
  if (!dd)
    return;

  if (dd->portal)
    vlib_dsa_device_unmap (dd->dsa_dev_handle, dd->portal);

  vlib_physmem_free (vm, dd->desc_ring);
  clib_mem_free (dd->batch_idx_ring);

  vec_free (dd->name);
  dev_instance = dd->dev_instance;
  pool_put_index (dm->devices, dev_instance);
  clib_mem_free (dd);
}

static_always_inline void
__dsa_movdir64b (volatile void *dst, const dsa_desc_t *src)
{
  asm volatile(".byte 0x66, 0x0f, 0x38, 0xf8, 0x02"
	       :
	       : "a"(dst), "d"(src)
	       : "memory");
}

static_always_inline uword
__desc_idx_to_iova (dsa_device_t *dev, uint16_t n)
{
  return dev->desc_iova + (n * sizeof (dsa_desc_t));
}

static_always_inline int
__dsa_write_desc (dsa_device_t *dev, const uint32_t op_flags, uword src,
		  uword dst, u32 size)
{
  u16 write_idx = dev->batch_start + dev->batch_size;
  u16 mask = dev->desc_ring_mask;
  /* first check batch ring space then desc ring space */
  if ((dev->batch_idx_read == 0 && dev->batch_idx_write == dev->max_batches) ||
      dev->batch_idx_write + 1 == dev->batch_idx_read)
    goto failed;

  // /* for descriptor ring, we always need a slot for batch completion */
  // if (((write_idx + 2) & mask) == idxd->hdls_read ||
  // 		((write_idx + 1) & mask) == idxd->hdls_read)
  // 	goto failed;

  /* write desc and handle. Note, descriptors don't wrap */
  dev->desc_ring[write_idx].pasid = 0;
  dev->desc_ring[write_idx].op_flags =
    op_flags | IDXD_FLAG_COMPLETION_ADDR_VALID;
  dev->desc_ring[write_idx].completion =
    __desc_idx_to_iova (dev, write_idx & mask);
  dev->desc_ring[write_idx].src = src;
  dev->desc_ring[write_idx].dst = dst;
  dev->desc_ring[write_idx].size = size;

  dev->batch_size++;

  dev->xstats.enqueued++;

  // rte_prefetch0_write(&idxd->desc_ring[write_idx + 1]);
  return 1;

failed:
  dev->xstats.enqueue_failed++;
  return 0;
}

static_always_inline int
__dsa_enqueue_nop (dsa_device_t *dev)
{
  /* only op field needs filling - zero src, dst and length */
  return __dsa_write_desc (dev, dsa_op_nop << IDXD_CMD_OP_SHIFT, 0, 0, 0);
}

static_always_inline int __attribute__ ((__unused__))
__dsa_fence (dsa_device_t *dev)
{
  /* only op field needs filling - zero src, dst and length */
  return __dsa_write_desc (dev, IDXD_FLAG_FENCE, 0, 0, 0);
}

static_always_inline int
__dsa_perform_ops (dsa_device_t *dev)
{
  if (dev->batch_size == 0)
    return 0;

  if (dev->batch_size == 1)
    {
      /* use a NOP as a null descriptor, so batch_size >= 2 */
      if (__dsa_enqueue_nop (dev) != 1)
	return -1;
      dev->nop_op |= 1ULL << dev->batch_idx_write;
    }
  else
    dev->nop_op &= ~(1ULL << dev->batch_idx_write);

  /* write completion beyond last desc in the batch */
  u16 comp_idx = (dev->batch_start + dev->batch_size) & dev->desc_ring_mask;
  *((u64 *) &dev->desc_ring[comp_idx]) = 0; /* zero start of desc */

  const dsa_desc_t batch_desc = {
    .op_flags = (dsa_op_batch << IDXD_CMD_OP_SHIFT) |
		IDXD_FLAG_COMPLETION_ADDR_VALID | IDXD_FLAG_REQUEST_COMPLETION,
    .desc_addr = __desc_idx_to_iova (dev, dev->batch_start),
    .completion = __desc_idx_to_iova (dev, comp_idx),
    .size = dev->batch_size,
  };

  _mm_sfence (); /* fence before writing desc to device */
  __dsa_movdir64b (dev->portal, &batch_desc);
  dev->xstats.started += dev->batch_size;
  dev->batch_start += dev->batch_size + 1;
  dev->batch_start &= dev->desc_ring_mask;
  dev->batch_size = 0;

  dev->batch_idx_ring[dev->batch_idx_write++] = comp_idx;
  if (dev->batch_idx_write > dev->max_batches)
    dev->batch_idx_write = 0;

  return 0;
}

static_always_inline int
__dsa_completed_ops (dsa_device_t *dev, u16 *unsuccessful)
{
  u16 n = 0;
  u16 batch_check_id = 0;
  u16 nop_ops = 0;

  *unsuccessful = 0;
  u16 idx_begin = dev->batch_check_start;
  u16 batch_begin = dev->batch_idx_read;

  while (dev->batch_idx_read != dev->batch_idx_write)
    {
      u16 idx_to_chk = dev->batch_idx_ring[dev->batch_idx_read];
      volatile dsa_completion_t *comp_to_chk =
	(dsa_completion_t *) &dev->desc_ring[idx_to_chk];
      u8 batch_status = comp_to_chk->status;
      if (batch_status == 0)
	break;
      comp_to_chk->status = 0;
      // if anything wrong in the batch, mark all failed, upper level will
      // handle the issue
      if (batch_status > 1)
	{
	  // this batch size has issue, set unsucessful number and return
	  *unsuccessful += idx_to_chk - dev->batch_check_start;
	}
      dev->batch_check_start = (idx_to_chk + 1) & dev->desc_ring_mask;
      batch_check_id = dev->batch_idx_read;
      // this batch has nop op
      if (dev->nop_op & (1ULL << batch_check_id))
	nop_ops++;

      dev->batch_idx_read++;
      if (dev->batch_idx_read > dev->max_batches)
	dev->batch_idx_read = 0;

      //     if (*unsuccessful)
      //       break;
    }

  if (dev->batch_idx_read != batch_begin)
    {
      if (dev->batch_idx_ring[batch_check_id] >= idx_begin)
	n = dev->batch_idx_ring[batch_check_id] - idx_begin;
      else
	n = dev->desc_ring_mask + dev->batch_idx_ring[batch_check_id] -
	    idx_begin + 1;
    }

  n -= nop_ops;
  dev->xstats.completed += n;
  //  if (n)
  //    printf("dsa_completed_ops found %d completed\n", n);
  return n;
}

int
dsa_enqueue_copy (vlib_dsa_dev_handle_t h, uint64_t src, uint64_t dst,
		  u32 length)
{
  dsa_device_t *dd = (dsa_device_t *) dsa_get_device (h);

  if (!dd)
    return -1;

  return __dsa_write_desc (
    dd, (dsa_op_memmove << IDXD_CMD_OP_SHIFT) | IDXD_FLAG_CACHE_CONTROL, src,
    dst, length);
}

void
dsa_do_copies (vlib_dsa_dev_handle_t h)
{
  dsa_device_t *dd = (dsa_device_t *) dsa_get_device (h);
  __dsa_perform_ops (dd);
  return;
}

int
dsa_get_completed_count (vlib_dsa_dev_handle_t h)
{
  u16 unsuccessful;
  dsa_device_t *dd = (dsa_device_t *) dsa_get_device (h);
  // TODO: return error information to framework
  return __dsa_completed_ops (dd, &unsuccessful);
}

int
dsa_get_enqueued_count (vlib_dsa_dev_handle_t h)
{
  dsa_device_t *dd = (dsa_device_t *) dsa_get_device (h);
  // TODO: what's the meaning for enqueued count? submitted not checked?
  return (dd->xstats.enqueued);
}

clib_error_t *
dsa_init (vlib_main_t *vm)
{
  return 0;
}

VLIB_INIT_FUNCTION (dsa_init) = {
  .runs_after = VLIB_INITS ("linux_dsa_init"),
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
