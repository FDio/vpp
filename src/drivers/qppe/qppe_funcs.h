/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#pragma once

static_always_inline void
qppe_dma_cache_clean (void *addr, int size)
{
  uword start = pointer_to_uword (addr) & ~(CLIB_CACHE_LINE_BYTES - 1);

  for (; size > 0; start += CLIB_CACHE_LINE_BYTES, size -= CLIB_CACHE_LINE_BYTES)
    asm volatile ("dc cvac, %0" : : "r"(start) : "memory");
}

static_always_inline void
qppe_dma_cache_clean_invalidate (void *addr, uword size)
{
  uword start = pointer_to_uword (addr) & ~(CLIB_CACHE_LINE_BYTES - 1);

  for (; size > 0; start += CLIB_CACHE_LINE_BYTES, size -= CLIB_CACHE_LINE_BYTES)
    asm volatile ("dc civac, %0" : : "r"(start) : "memory");
}

static_always_inline u32
qppe_mmio_read32 (qppe_device_t *qd, u32 offset)
{
  return __atomic_load_n ((u32 *) ((u8 *) qd->regs + offset), __ATOMIC_ACQUIRE);
}

static_always_inline void
qppe_mmio_write32 (qppe_device_t *qd, u32 offset, u32 value)
{
  __atomic_store_n ((u32 *) ((u8 *) qd->regs + offset), value, __ATOMIC_RELEASE);
}

static_always_inline u32
qppe_edma_reg_rd (qppe_device_t *qd, u32 reg)
{
  return qppe_mmio_read32 (qd, EDMA_BASE_OFFSET + reg);
}

static_always_inline void
qppe_edma_reg_wr (qppe_device_t *qd, u32 reg, u32 value)
{
  qppe_mmio_write32 (qd, EDMA_BASE_OFFSET + reg, value);
}
