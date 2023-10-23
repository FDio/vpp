/*
 * Copyright (c) 2021 Marvell.
 * SPDX-License-Identifier: Apache-2.0
 * https://spdx.org/licenses/Apache-2.0.html
 */

#ifndef included_onp_drv_roc_memzone_h
#define included_onp_drv_roc_memzone_h

#define PLT_MEMZONE_PHYS_CONTIG 0x00000001
#define PLT_MEMZONE_NAMESIZE	(64)

typedef struct cnxk_plt_memzone
{
  u32 index;
  union
  {
    void *addr;
    u64 addr_64;
    plt_iova_t iova;
  };
} cnxk_plt_memzone_t;

typedef struct cnxk_plt_memzone_list
{
  cnxk_plt_memzone_t *mem_pool;
  uword *memzone_by_name;
} cnxk_plt_memzone_list_t;

static cnxk_plt_memzone_list_t memzone_list;

#define plt_memzone	   cnxk_plt_memzone
#define plt_memzone_free   cnxk_plt_memzone_free
#define plt_memzone_lookup cnxk_plt_memzone_lookup

#define plt_memzone_reserve_aligned(name, sz, flags, align)                   \
  cnxk_plt_memzone_reserve_aligned (name, sz, 0, flags, align)

#define plt_memzone_reserve_cache_align(name, sz)                             \
  cnxk_plt_memzone_reserve_aligned (name, sz, 0, 0, CLIB_CACHE_LINE_BYTES)

static_always_inline void
cnxk_plt_free (void *addr)
{
  vlib_main_t *vm = vlib_get_main ();

  cnxk_drv_physmem_free (vm, addr);
}

static_always_inline void *
cnxk_plt_realloc (void *addr, u32 size, u32 align)
{
  ALWAYS_ASSERT (0);

  return 0;
}

static_always_inline void *
cnxk_plt_zmalloc (u32 size, u32 align)
{
  vlib_main_t *vm = vlib_get_main ();

  return cnxk_drv_physmem_alloc (vm, size, align);
}

static_always_inline cnxk_plt_memzone_t *
memzone_get (u32 index)
{
  if (index == ((u32) ~0))
    return 0;

  return pool_elt_at_index (memzone_list.mem_pool, index);
}

static_always_inline int
cnxk_plt_memzone_free (const cnxk_plt_memzone_t *name)
{
  uword *p;
  p = hash_get_mem (memzone_list.memzone_by_name, name);

  if (p[0] == ((u32) ~0))
    return -EINVAL;

  hash_unset_mem (memzone_list.memzone_by_name, name);

  pool_put_index (memzone_list.mem_pool, p[0]);

  return 0;
}

static_always_inline cnxk_plt_memzone_t *
cnxk_plt_memzone_lookup (const char *name)
{
  uword *p;
  p = hash_get_mem (memzone_list.memzone_by_name, name);
  if (p)
    return memzone_get (p[0]);

  return 0;
}

static_always_inline cnxk_plt_memzone_t *
cnxk_plt_memzone_reserve_aligned (const char *name, u64 len, u8 socket,
				  u32 flags, u32 align)
{
  cnxk_plt_memzone_t *mem_pool;
  void *p = NULL;

  pool_get_zero (memzone_list.mem_pool, mem_pool);

  p = cnxk_plt_zmalloc (len, align);
  if (!p)
    return NULL;

  mem_pool->addr = p;
  mem_pool->index = mem_pool - memzone_list.mem_pool;
  hash_set_mem (memzone_list.memzone_by_name, name, mem_pool->index);

  return mem_pool;
}

static inline const void *
plt_lmt_region_reserve_aligned (const char *name, size_t len, uint32_t align)
{
  return plt_memzone_reserve_aligned (name, len, PLT_MEMZONE_PHYS_CONTIG,
				      align);
}

#endif /* included_onp_drv_roc_memzone_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
