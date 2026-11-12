/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Damjan Marion
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vnet/dev/log.h>

VLIB_REGISTER_LOG_CLASS (dev_log, static) = {
  .class_name = "dev",
  .subclass_name = "dma-slab",
};

#define VNET_DEV_DMA_SLAB_SIZE	   (1 << 16)
#define VNET_DEV_DMA_SLAB_N_LINES  (VNET_DEV_DMA_SLAB_SIZE / CLIB_CACHE_LINE_BYTES)
#define VNET_DEV_DMA_SLAB_MAX_SIZE 1024

typedef struct vnet_dev_dma_slab_config vnet_dev_dma_slab_config_t;

/* header at the start of each slab, bitmaps have one bit per cache line */
typedef struct
{
  vnet_dev_dma_slab_config_t *config;
  u16 n_used;
  u8 va_dma_mapped : 1;
  uword used[VNET_DEV_DMA_SLAB_N_LINES / uword_bits];
  uword cont[VNET_DEV_DMA_SLAB_N_LINES / uword_bits]; /* line continues previous allocation */
} vnet_dev_dma_slab_t;

#define VNET_DEV_DMA_SLAB_HDR_LINES                                                                \
  (round_pow2 (sizeof (vnet_dev_dma_slab_t), CLIB_CACHE_LINE_BYTES) / CLIB_CACHE_LINE_BYTES)

/* slabs on one NUMA node and bus */
struct vnet_dev_dma_slab_config
{
  vnet_dev_dma_slab_t **slabs;
  u32 n_used;
  u8 numa_node;
  u16 bus_index;
};

static vnet_dev_dma_slab_config_t **dma_slab_configs;

static_always_inline vnet_dev_dma_slab_t *
vnet_dev_dma_slab_from_va (void *va)
{
  return (vnet_dev_dma_slab_t *) ((uword) va & ~(VNET_DEV_DMA_SLAB_SIZE - 1));
}

u64
vnet_dev_dma_slab_get_dma_addr (vlib_main_t *vm, vnet_dev_t *dev, void *va)
{
  ASSERT (dev->va_dma == 0 || vnet_dev_dma_slab_from_va (va)->va_dma_mapped);
  return vnet_dev_get_dma_addr (vm, dev, va);
}

static vnet_dev_dma_slab_config_t *
vnet_dev_dma_slab_get_config (vnet_dev_t *dev)
{
  vnet_dev_dma_slab_config_t *c;

  vec_foreach_pointer (cfg, dma_slab_configs)
    if (cfg->numa_node == dev->numa_node && cfg->bus_index == dev->bus_index)
      return cfg;

  c = clib_mem_alloc (sizeof (*c));
  *c = (vnet_dev_dma_slab_config_t) {
    .numa_node = dev->numa_node,
    .bus_index = dev->bus_index,
  };
  vec_add1 (dma_slab_configs, c);
  return c;
}

static vnet_dev_dma_slab_t *
vnet_dev_dma_slab_new (vlib_main_t *vm, vnet_dev_t *dev, vnet_dev_dma_slab_config_t *c)
{
  vnet_dev_bus_t *bus = pool_elt_at_index (vnet_dev_main.buses, c->bus_index);
  vnet_dev_dma_slab_t *s;
  u64 dma;

  s = vlib_physmem_alloc_aligned_on_numa (vm, VNET_DEV_DMA_SLAB_SIZE, VNET_DEV_DMA_SLAB_SIZE,
					  c->numa_node);
  if (s == 0)
    {
      log_err (dev, "slab memory allocation failed");
      return 0;
    }

  if (bus->ops.dma_mem_map_fn && bus->ops.dma_mem_map_fn (vm, dev, s) != VNET_DEV_OK)
    {
      vlib_physmem_free (vm, s);
      return 0;
    }

  clib_memset (s, 0, VNET_DEV_DMA_SLAB_SIZE);

  dma = vnet_dev_get_dma_addr (vm, dev, s);
  if (vnet_dev_get_dma_addr (vm, dev, (u8 *) s + VNET_DEV_DMA_SLAB_SIZE - 1) !=
      dma + VNET_DEV_DMA_SLAB_SIZE - 1)
    {
      log_err (dev, "slab memory is not DMA contiguous");
      vlib_physmem_free (vm, s);
      return 0;
    }

  /* memory is mapped for VA DMA only when the allocating device uses it */
  *s = (vnet_dev_dma_slab_t) {
    .config = c,
    .va_dma_mapped = dev->va_dma,
  };
  uword_bitmap_set_bits_at_index (s->used, 0, VNET_DEV_DMA_SLAB_HDR_LINES);
  clib_mem_poison ((u8 *) s + VNET_DEV_DMA_SLAB_HDR_LINES * CLIB_CACHE_LINE_BYTES,
		   VNET_DEV_DMA_SLAB_SIZE - VNET_DEV_DMA_SLAB_HDR_LINES * CLIB_CACHE_LINE_BYTES);

  vec_add1 (c->slabs, s);
  log_debug (dev, "slab %p on numa %u, dma 0x%lx", s, c->numa_node, dma);
  return s;
}

static_always_inline i32
vnet_dev_dma_slab_find (vnet_dev_dma_slab_t *s, u32 n_lines, u32 step)
{
  if (s->n_used + VNET_DEV_DMA_SLAB_HDR_LINES + n_lines > VNET_DEV_DMA_SLAB_N_LINES)
    return -1;

  for (u32 i = round_pow2 (VNET_DEV_DMA_SLAB_HDR_LINES, step);
       i + n_lines <= VNET_DEV_DMA_SLAB_N_LINES; i += step)
    if (uword_bitmap_get_multiple (s->used, i, n_lines) == 0)
      return i;

  return -1;
}

void *
vnet_dev_dma_slab_alloc (vlib_main_t *vm, vnet_dev_t *dev, u32 size, u32 align)
{
  vnet_dev_bus_t *bus = pool_elt_at_index (vnet_dev_main.buses, dev->bus_index);
  vnet_dev_dma_slab_config_t *c;
  vnet_dev_dma_slab_t *s = 0;
  u32 n_lines, step;
  i32 i = -1;

  ASSERT (vm->thread_index == 0);

  align = align ? align : CLIB_CACHE_LINE_BYTES;
  if (size == 0 || size > VNET_DEV_DMA_SLAB_MAX_SIZE || is_pow2 (align) == 0 ||
      align < CLIB_CACHE_LINE_BYTES || align > VNET_DEV_DMA_SLAB_MAX_SIZE)
    return 0;

  n_lines = round_pow2 (size, CLIB_CACHE_LINE_BYTES) / CLIB_CACHE_LINE_BYTES;
  step = align / CLIB_CACHE_LINE_BYTES;
  c = vnet_dev_dma_slab_get_config (dev);

  /* first fit in stable slab order keeps allocations packed so other slabs can drain */
  vec_foreach_pointer (slab, c->slabs)
    if ((i = vnet_dev_dma_slab_find (slab, n_lines, step)) >= 0)
      {
	s = slab;
	break;
      }

  if (s == 0)
    {
      if ((s = vnet_dev_dma_slab_new (vm, dev, c)) == 0)
	return 0;
      i = vnet_dev_dma_slab_find (s, n_lines, step);
      ASSERT (i >= 0);
    }

  if (dev->va_dma && s->va_dma_mapped == 0)
    {
      if (bus->ops.dma_mem_map_fn == 0 || bus->ops.dma_mem_map_fn (vm, dev, s) != VNET_DEV_OK)
	return 0;
      s->va_dma_mapped = 1;
    }

  uword_bitmap_set_bits_at_index (s->used, i, n_lines);
  if (n_lines > 1)
    uword_bitmap_set_bits_at_index (s->cont, i + 1, n_lines - 1);
  s->n_used += n_lines;
  c->n_used += n_lines;
  clib_mem_unpoison ((u8 *) s + i * CLIB_CACHE_LINE_BYTES, size);
  return (u8 *) s + i * CLIB_CACHE_LINE_BYTES;
}

void
vnet_dev_dma_slab_free (vlib_main_t *vm, vnet_dev_t *dev, void *va)
{
  vnet_dev_dma_slab_t *s = vnet_dev_dma_slab_from_va (va);
  vnet_dev_dma_slab_config_t *c = s->config;
  u32 i = ((u8 *) va - (u8 *) s) / CLIB_CACHE_LINE_BYTES;
  u32 n_lines = 1;

  ASSERT (vm->thread_index == 0);
  ASSERT (uword_bitmap_is_bit_set (s->used, i) && uword_bitmap_is_bit_set (s->cont, i) == 0);

  while (i + n_lines < VNET_DEV_DMA_SLAB_N_LINES && uword_bitmap_is_bit_set (s->cont, i + n_lines))
    n_lines++;

  clib_mem_unpoison (va, n_lines * CLIB_CACHE_LINE_BYTES);
  clib_memset (va, 0, n_lines * CLIB_CACHE_LINE_BYTES);
  clib_mem_poison (va, n_lines * CLIB_CACHE_LINE_BYTES);
  uword_bitmap_clear_bits_at_index (s->used, i, n_lines);
  if (n_lines > 1)
    uword_bitmap_clear_bits_at_index (s->cont, i + 1, n_lines - 1);
  s->n_used -= n_lines;
  c->n_used -= n_lines;

  /* keep the last slab to avoid churn on alloc/free of a single element */
  if (s->n_used || vec_len (c->slabs) == 1)
    return;

  vec_delete (c->slabs, 1, vec_search (c->slabs, s));
  log_debug (dev, "slab %p on numa %u freed", s, c->numa_node);
  clib_mem_unpoison (s, VNET_DEV_DMA_SLAB_SIZE);
  vlib_physmem_free (vm, s);
}

u8 *
format_vnet_dev_dma_slabs (u8 *s, va_list *args)
{
  vnet_dev_main_t *dm = &vnet_dev_main;
  u32 indent = format_get_indent (s);

  s = format (s, "%-8s%-10s%-8s%-12s%-12s", "numa", "bus", "slabs", "used-bytes", "free-bytes");

  vec_foreach_pointer (c, dma_slab_configs)
    {
      vnet_dev_bus_t *bus = pool_elt_at_index (dm->buses, c->bus_index);
      u32 n_lines = vec_len (c->slabs) * (VNET_DEV_DMA_SLAB_N_LINES - VNET_DEV_DMA_SLAB_HDR_LINES);

      s = format_newline (s, indent);
      s = format (s, "%-8u%-10s%-8u%-12u%-12u", c->numa_node, bus->registration->name,
		  vec_len (c->slabs), c->n_used * CLIB_CACHE_LINE_BYTES,
		  (n_lines - c->n_used) * CLIB_CACHE_LINE_BYTES);
    }

  return s;
}
