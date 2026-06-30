/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Marvell.
 */

#pragma once

#include <stddef.h>
#include <stdint.h>

struct mv_sys_dma_mem_region
{
  void *dma_virt_base;
  uint64_t dma_phys_base;
  uint64_t size;
  int manage;
  void *priv;
  uint32_t mem_id;
};

int mv_sys_dma_mem_init (size_t size);
void mv_sys_dma_mem_destroy (void);
void *mv_sys_dma_mem_region_alloc (struct mv_sys_dma_mem_region *mem, size_t size, size_t align);
void mv_sys_dma_mem_region_free (struct mv_sys_dma_mem_region *mem, void *ptr);
uint64_t mv_sys_dma_mem_region_virt2phys (struct mv_sys_dma_mem_region *mem, void *va);
struct mv_sys_dma_mem_region *mv_sys_dma_mem_region_get (uint32_t mem_id);
