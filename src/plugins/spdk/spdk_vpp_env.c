/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco and/or its affiliates.
 */

/*
 * SPDK environment implementation for an application embedded in VPP.
 *
 * SPDK itself only depends on the API in spdk/env.h.  Its usual env_dpdk
 * implementation is deliberately not linked here: VPP owns the worker
 * threads, CPU placement and physically backed memory.  PCI access is kept
 * disabled until an SPDK PCI provider backed by VPP's PCI/VFIO layer exists.
 */

#define _GNU_SOURCE

#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <numa.h>

#include <vlib/vlib.h>
#include <vlib/physmem_funcs.h>
#include <vppinfra/os.h>
#include <vppinfra/time.h>

#include <spdk/cpuset.h>
#include <spdk/env.h>

#include "spdk_plugin.h"

#define SPDK_VPP_DEFAULT_ALIGNMENT CLIB_CACHE_LINE_BYTES

typedef struct spdk_vpp_allocation
{
  void *ptr;
  size_t size;
  int numa_id;
  bool physical;
  bool huge;
  size_t mapped_size;
  struct spdk_vpp_allocation *next;
} spdk_vpp_allocation_t;

typedef struct spdk_vpp_memzone
{
  char *name;
  void *ptr;
  size_t size;
  struct spdk_vpp_memzone *next;
} spdk_vpp_memzone_t;

struct spdk_ring
{
  pthread_spinlock_t lock;
  void **objects;
  size_t size;
  size_t count;
  size_t head;
  size_t tail;
};

struct spdk_mempool
{
  pthread_spinlock_t lock;
  char name[SPDK_MAX_MEMPOOL_NAME_LEN + 1];
  void *storage;
  void **free_objects;
  size_t capacity;
  size_t count;
  size_t element_size;
  size_t element_stride;
  struct spdk_mempool *next;
};

typedef struct spdk_vpp_mem_registration
{
  void *address;
  size_t size;
  struct spdk_vpp_mem_registration *next;
} spdk_vpp_mem_registration_t;

typedef struct spdk_vpp_translation
{
  uint64_t address;
  uint64_t size;
  uint64_t translation;
  struct spdk_vpp_translation *next;
} spdk_vpp_translation_t;

struct spdk_mem_map
{
  pthread_rwlock_t lock;
  uint64_t default_translation;
  const struct spdk_mem_map_ops *ops;
  void *cb_ctx;
  spdk_vpp_translation_t *translations;
  struct spdk_mem_map *next;
};

struct spdk_pci_driver
{
  char *name;
  struct spdk_pci_id *id_table;
  uint32_t flags;
  struct spdk_pci_driver *next;
};

static pthread_mutex_t spdk_vpp_memory_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t spdk_vpp_mempool_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t spdk_vpp_map_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t spdk_vpp_pci_lock = PTHREAD_MUTEX_INITIALIZER;
static spdk_vpp_allocation_t *spdk_vpp_allocations;
static spdk_vpp_memzone_t *spdk_vpp_memzones;
static struct spdk_mempool *spdk_vpp_mempools;
static struct spdk_mem_map *spdk_vpp_maps;
static spdk_vpp_mem_registration_t *spdk_vpp_registrations;
static struct spdk_pci_driver *spdk_vpp_pci_drivers;
static struct spdk_cpuset spdk_vpp_core_mask;
static uint32_t spdk_vpp_main_core = SPDK_ENV_LCORE_ID_ANY;
static bool spdk_vpp_env_initialized;
static __thread uint32_t spdk_vpp_current_core = SPDK_ENV_LCORE_ID_ANY;

static inline vlib_main_t *
spdk_vpp_vm (void)
{
  return vlib_get_first_main ();
}

static inline bool
spdk_vpp_physmem_contains (const void *ptr)
{
  clib_pmalloc_main_t *pm = spdk_vpp_vm ()->physmem_main.pmalloc_main;
  uword address = pointer_to_uword (ptr);
  uword base;

  if (pm == NULL || pm->base == NULL)
    return false;

  base = pointer_to_uword (pm->base);
  return address >= base && ((address - base) >> pm->def_log2_page_sz) < vec_len (pm->pages);
}

static spdk_vpp_allocation_t *
spdk_vpp_find_allocation (const void *ptr, spdk_vpp_allocation_t ***link)
{
  spdk_vpp_allocation_t **current = &spdk_vpp_allocations;

  while (*current)
    {
      if ((*current)->ptr == ptr)
	{
	  if (link)
	    *link = current;
	  return *current;
	}
      current = &(*current)->next;
    }

  return NULL;
}

static void *
spdk_vpp_allocate (size_t size, size_t align, int numa_id, bool zero)
{
  spdk_vpp_allocation_t *allocation;
  vlib_main_t *vm = spdk_vpp_vm ();
  clib_pmalloc_main_t *pm = vm->physmem_main.pmalloc_main;
  void *ptr = NULL;
  bool physical = false;
  bool huge = false;
  size_t mapped_size = 0;
  size_t page_size = 0;

  if (size == 0)
    return NULL;
  if (align == 0)
    align = SPDK_VPP_DEFAULT_ALIGNMENT;
  if (align < SPDK_VPP_DEFAULT_ALIGNMENT)
    align = SPDK_VPP_DEFAULT_ALIGNMENT;
  if ((align & (align - 1)) != 0)
    return NULL;

  /*
   * VPP's physical allocator intentionally limits one allocation to one
   * physical-memory page. Prefer it for objects which can fit in a page. Use
   * anonymous hugepages for larger software-only objects so large Malloc
   * bdevs do not consume the small pool of normal RAM left on a hugepage-heavy
   * target. A final aligned-heap fallback keeps no-PCI operation possible on
   * systems without hugepages. spdk_vtophys() rejects both fallbacks, so they
   * are never advertised to a DMA device.
   */
  pthread_mutex_lock (&spdk_vpp_memory_lock);
  if (pm != NULL)
    page_size = 1ULL << pm->def_log2_page_sz;
  if (page_size != 0 && size <= page_size && align <= page_size)
    {
      if (numa_id == SPDK_ENV_NUMA_ID_ANY)
	ptr = vlib_physmem_alloc_aligned (vm, size, align);
      else
	ptr = vlib_physmem_alloc_aligned_on_numa (vm, size, align, numa_id);
      physical = ptr != NULL;
    }

  if (ptr == NULL && page_size != 0 && size > page_size / 2 && align <= page_size &&
      size <= SIZE_MAX - (page_size - 1))
    {
      mapped_size = (size + page_size - 1) & ~(page_size - 1);
      ptr = mmap (NULL, mapped_size, PROT_READ | PROT_WRITE,
		  MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB, -1, 0);
      if (ptr == MAP_FAILED)
	ptr = NULL;
      else
	huge = true;
    }

  if (ptr == NULL && posix_memalign (&ptr, align, size) != 0)
    ptr = NULL;

  allocation = calloc (1, sizeof (*allocation));
  if (ptr == NULL || allocation == NULL)
    {
      if (physical)
	vlib_physmem_free (vm, ptr);
      else if (huge)
	munmap (ptr, mapped_size);
      else
	free (ptr);
      free (allocation);
      pthread_mutex_unlock (&spdk_vpp_memory_lock);
      return NULL;
    }

  allocation->ptr = ptr;
  allocation->size = size;
  allocation->numa_id = numa_id;
  allocation->physical = physical;
  allocation->huge = huge;
  allocation->mapped_size = mapped_size;
  allocation->next = spdk_vpp_allocations;
  spdk_vpp_allocations = allocation;
  pthread_mutex_unlock (&spdk_vpp_memory_lock);

  if (zero)
    memset (ptr, 0, size);
  return ptr;
}

void *
spdk_malloc (size_t size, size_t align, uint64_t *unused, int numa_id, uint32_t flags)
{
  (void) flags;
  if (unused != NULL)
    return NULL;
  return spdk_vpp_allocate (size, align, numa_id, false);
}

void *
spdk_zmalloc (size_t size, size_t align, uint64_t *unused, int numa_id, uint32_t flags)
{
  (void) flags;
  if (unused != NULL)
    return NULL;
  return spdk_vpp_allocate (size, align, numa_id, true);
}

void
spdk_free (void *ptr)
{
  spdk_vpp_allocation_t **link;
  spdk_vpp_allocation_t *allocation;

  if (ptr == NULL)
    return;

  pthread_mutex_lock (&spdk_vpp_memory_lock);
  allocation = spdk_vpp_find_allocation (ptr, &link);
  if (allocation)
    {
      *link = allocation->next;
      if (allocation->physical)
	vlib_physmem_free (spdk_vpp_vm (), ptr);
      else if (allocation->huge)
	munmap (ptr, allocation->mapped_size);
      else
	free (ptr);
      free (allocation);
    }
  pthread_mutex_unlock (&spdk_vpp_memory_lock);
}

void *
spdk_realloc (void *ptr, size_t size, size_t align)
{
  spdk_vpp_allocation_t *allocation;
  size_t old_size;
  int numa_id;
  void *new_ptr;

  if (ptr == NULL)
    return spdk_vpp_allocate (size, align, SPDK_ENV_NUMA_ID_ANY, false);
  if (size == 0)
    {
      spdk_free (ptr);
      return NULL;
    }

  pthread_mutex_lock (&spdk_vpp_memory_lock);
  allocation = spdk_vpp_find_allocation (ptr, NULL);
  if (allocation == NULL)
    {
      pthread_mutex_unlock (&spdk_vpp_memory_lock);
      return NULL;
    }
  old_size = allocation->size;
  numa_id = allocation->numa_id;
  pthread_mutex_unlock (&spdk_vpp_memory_lock);

  new_ptr = spdk_vpp_allocate (size, align, numa_id, false);
  if (new_ptr)
    {
      memcpy (new_ptr, ptr, clib_min (old_size, size));
      spdk_free (ptr);
    }
  return new_ptr;
}

void *
spdk_dma_malloc (size_t size, size_t align, uint64_t *unused)
{
  return spdk_malloc (size, align, unused, SPDK_ENV_NUMA_ID_ANY, SPDK_MALLOC_DMA);
}

void *
spdk_dma_malloc_socket (size_t size, size_t align, uint64_t *unused, int numa_id)
{
  return spdk_malloc (size, align, unused, numa_id, SPDK_MALLOC_DMA);
}

void *
spdk_dma_zmalloc (size_t size, size_t align, uint64_t *unused)
{
  return spdk_zmalloc (size, align, unused, SPDK_ENV_NUMA_ID_ANY, SPDK_MALLOC_DMA);
}

void *
spdk_dma_zmalloc_socket (size_t size, size_t align, uint64_t *unused, int numa_id)
{
  return spdk_zmalloc (size, align, unused, numa_id, SPDK_MALLOC_DMA);
}

void *
spdk_dma_realloc (void *ptr, size_t size, size_t align, uint64_t *unused)
{
  if (unused != NULL)
    return NULL;
  return spdk_realloc (ptr, size, align);
}

void
spdk_dma_free (void *ptr)
{
  spdk_free (ptr);
}

void *
spdk_memzone_reserve_aligned (const char *name, size_t len, int numa_id, unsigned flags,
			      unsigned align)
{
  spdk_vpp_memzone_t *zone;

  (void) flags;
  if (name == NULL || strlen (name) >= SPDK_MAX_MEMZONE_NAME_LEN)
    return NULL;

  pthread_mutex_lock (&spdk_vpp_memory_lock);
  for (zone = spdk_vpp_memzones; zone; zone = zone->next)
    if (strcmp (zone->name, name) == 0)
      {
	pthread_mutex_unlock (&spdk_vpp_memory_lock);
	return NULL;
      }
  pthread_mutex_unlock (&spdk_vpp_memory_lock);

  zone = calloc (1, sizeof (*zone));
  if (zone == NULL)
    return NULL;
  zone->name = strdup (name);
  zone->ptr = spdk_zmalloc (len, align, NULL, numa_id, SPDK_MALLOC_DMA | SPDK_MALLOC_SHARE);
  zone->size = len;
  if (zone->name == NULL || zone->ptr == NULL)
    {
      spdk_free (zone->ptr);
      free (zone->name);
      free (zone);
      return NULL;
    }

  pthread_mutex_lock (&spdk_vpp_memory_lock);
  zone->next = spdk_vpp_memzones;
  spdk_vpp_memzones = zone;
  pthread_mutex_unlock (&spdk_vpp_memory_lock);
  return zone->ptr;
}

void *
spdk_memzone_reserve (const char *name, size_t len, int numa_id, unsigned flags)
{
  return spdk_memzone_reserve_aligned (name, len, numa_id, flags, SPDK_VPP_DEFAULT_ALIGNMENT);
}

void *
spdk_memzone_lookup (const char *name)
{
  spdk_vpp_memzone_t *zone;
  void *ptr = NULL;

  pthread_mutex_lock (&spdk_vpp_memory_lock);
  for (zone = spdk_vpp_memzones; zone; zone = zone->next)
    if (strcmp (zone->name, name) == 0)
      {
	ptr = zone->ptr;
	break;
      }
  pthread_mutex_unlock (&spdk_vpp_memory_lock);
  return ptr;
}

int
spdk_memzone_free (const char *name)
{
  spdk_vpp_memzone_t **link = &spdk_vpp_memzones;
  spdk_vpp_memzone_t *zone;

  pthread_mutex_lock (&spdk_vpp_memory_lock);
  while ((zone = *link) != NULL && strcmp (zone->name, name) != 0)
    link = &zone->next;
  if (zone)
    *link = zone->next;
  pthread_mutex_unlock (&spdk_vpp_memory_lock);

  if (zone == NULL)
    return -1;
  spdk_free (zone->ptr);
  free (zone->name);
  free (zone);
  return 0;
}

void
spdk_memzone_dump (FILE *f)
{
  spdk_vpp_memzone_t *zone;

  pthread_mutex_lock (&spdk_vpp_memory_lock);
  for (zone = spdk_vpp_memzones; zone; zone = zone->next)
    fprintf (f, "%s: %p (%zu bytes)\n", zone->name, zone->ptr, zone->size);
  pthread_mutex_unlock (&spdk_vpp_memory_lock);
}

static struct spdk_mempool *
spdk_vpp_mempool_create (const char *name, size_t count, size_t element_size, int numa_id,
			 spdk_mempool_obj_cb_t *constructor, void *constructor_arg)
{
  struct spdk_mempool *pool;
  int spin_rc = 0;
  size_t i;

  if (name == NULL || count == 0 || element_size == 0 || strlen (name) > SPDK_MAX_MEMPOOL_NAME_LEN)
    return NULL;

  pthread_mutex_lock (&spdk_vpp_mempool_lock);
  for (pool = spdk_vpp_mempools; pool; pool = pool->next)
    if (strcmp (pool->name, name) == 0)
      {
	pthread_mutex_unlock (&spdk_vpp_mempool_lock);
	return NULL;
      }
  pthread_mutex_unlock (&spdk_vpp_mempool_lock);

  pool = calloc (1, sizeof (*pool));
  if (pool == NULL)
    return NULL;
  snprintf (pool->name, sizeof (pool->name), "%s", name);
  pool->capacity = count;
  pool->count = count;
  pool->element_size = element_size;
  pool->element_stride =
    (element_size + SPDK_VPP_DEFAULT_ALIGNMENT - 1) & ~(SPDK_VPP_DEFAULT_ALIGNMENT - 1);
  pool->storage = spdk_zmalloc (pool->element_stride * count, SPDK_VPP_DEFAULT_ALIGNMENT, NULL,
				numa_id, SPDK_MALLOC_DMA);
  pool->free_objects = calloc (count, sizeof (*pool->free_objects));
  if (pool->storage && pool->free_objects)
    spin_rc = pthread_spin_init (&pool->lock, PTHREAD_PROCESS_PRIVATE);
  if (pool->storage == NULL || pool->free_objects == NULL || spin_rc != 0)
    {
      clib_warning (
	"SPDK mempool '%s' allocation failed: objects %llu size %llu storage %p index %p", name,
	(unsigned long long) count, (unsigned long long) element_size, pool->storage,
	pool->free_objects);
      spdk_free (pool->storage);
      free (pool->free_objects);
      free (pool);
      return NULL;
    }

  for (i = 0; i < count; i++)
    {
      void *object = (uint8_t *) pool->storage + i * pool->element_stride;
      pool->free_objects[i] = object;
      if (constructor)
	constructor (pool, constructor_arg, object, i);
    }

  pthread_mutex_lock (&spdk_vpp_mempool_lock);
  pool->next = spdk_vpp_mempools;
  spdk_vpp_mempools = pool;
  pthread_mutex_unlock (&spdk_vpp_mempool_lock);
  return pool;
}

struct spdk_mempool *
spdk_mempool_create (const char *name, size_t count, size_t element_size, size_t cache_size,
		     int numa_id)
{
  (void) cache_size;
  return spdk_vpp_mempool_create (name, count, element_size, numa_id, NULL, NULL);
}

struct spdk_mempool *
spdk_mempool_create_ctor (const char *name, size_t count, size_t element_size, size_t cache_size,
			  int numa_id, spdk_mempool_obj_cb_t *constructor, void *constructor_arg)
{
  (void) cache_size;
  return spdk_vpp_mempool_create (name, count, element_size, numa_id, constructor, constructor_arg);
}

char *
spdk_mempool_get_name (struct spdk_mempool *pool)
{
  return pool ? pool->name : NULL;
}

void
spdk_mempool_free (struct spdk_mempool *pool)
{
  struct spdk_mempool **link = &spdk_vpp_mempools;

  if (pool == NULL)
    return;
  pthread_mutex_lock (&spdk_vpp_mempool_lock);
  while (*link && *link != pool)
    link = &(*link)->next;
  if (*link)
    *link = pool->next;
  pthread_mutex_unlock (&spdk_vpp_mempool_lock);

  pthread_spin_destroy (&pool->lock);
  spdk_free (pool->storage);
  free (pool->free_objects);
  free (pool);
}

int
spdk_mempool_get_bulk (struct spdk_mempool *pool, void **objects, size_t count)
{
  size_t i;

  if (pool == NULL || objects == NULL)
    return -EINVAL;
  pthread_spin_lock (&pool->lock);
  if (pool->count < count)
    {
      pthread_spin_unlock (&pool->lock);
      return -ENOENT;
    }
  for (i = 0; i < count; i++)
    objects[i] = pool->free_objects[--pool->count];
  pthread_spin_unlock (&pool->lock);
  return 0;
}

void *
spdk_mempool_get (struct spdk_mempool *pool)
{
  void *object = NULL;
  return spdk_mempool_get_bulk (pool, &object, 1) == 0 ? object : NULL;
}

void
spdk_mempool_put_bulk (struct spdk_mempool *pool, void **objects, size_t count)
{
  size_t i;

  if (pool == NULL || objects == NULL)
    return;
  pthread_spin_lock (&pool->lock);
  for (i = 0; i < count && pool->count < pool->capacity; i++)
    pool->free_objects[pool->count++] = objects[i];
  pthread_spin_unlock (&pool->lock);
}

void
spdk_mempool_put (struct spdk_mempool *pool, void *object)
{
  spdk_mempool_put_bulk (pool, &object, 1);
}

size_t
spdk_mempool_count (const struct spdk_mempool *pool)
{
  size_t count;

  if (pool == NULL)
    return 0;
  pthread_spin_lock ((pthread_spinlock_t *) &pool->lock);
  count = pool->count;
  pthread_spin_unlock ((pthread_spinlock_t *) &pool->lock);
  return count;
}

uint32_t
spdk_mempool_obj_iter (struct spdk_mempool *pool, spdk_mempool_obj_cb_t object_cb, void *cb_arg)
{
  size_t i;

  if (pool == NULL || object_cb == NULL)
    return 0;
  for (i = 0; i < pool->capacity; i++)
    object_cb (pool, cb_arg, (uint8_t *) pool->storage + i * pool->element_stride, i);
  return pool->capacity;
}

uint32_t
spdk_mempool_mem_iter (struct spdk_mempool *pool, spdk_mempool_mem_cb_t memory_cb, void *cb_arg)
{
  uint64_t size;

  if (pool == NULL || memory_cb == NULL)
    return 0;
  size = pool->element_stride * pool->capacity;
  memory_cb (pool, cb_arg, pool->storage, spdk_vtophys (pool->storage, &size),
	     pool->element_stride * pool->capacity, 0);
  return 1;
}

struct spdk_mempool *
spdk_mempool_lookup (const char *name)
{
  struct spdk_mempool *pool;

  pthread_mutex_lock (&spdk_vpp_mempool_lock);
  for (pool = spdk_vpp_mempools; pool; pool = pool->next)
    if (strcmp (pool->name, name) == 0)
      break;
  pthread_mutex_unlock (&spdk_vpp_mempool_lock);
  return pool;
}

struct spdk_ring *
spdk_ring_create (enum spdk_ring_type type, size_t count, int numa_id)
{
  struct spdk_ring *ring;

  (void) type;
  (void) numa_id;
  if (count == 0)
    return NULL;
  ring = calloc (1, sizeof (*ring));
  if (ring == NULL)
    return NULL;
  ring->objects = calloc (count, sizeof (*ring->objects));
  ring->size = count;
  if (ring->objects == NULL || pthread_spin_init (&ring->lock, PTHREAD_PROCESS_PRIVATE) != 0)
    {
      free (ring->objects);
      free (ring);
      return NULL;
    }
  return ring;
}

void
spdk_ring_free (struct spdk_ring *ring)
{
  if (ring == NULL)
    return;
  pthread_spin_destroy (&ring->lock);
  free (ring->objects);
  free (ring);
}

size_t
spdk_ring_count (struct spdk_ring *ring)
{
  size_t count;
  pthread_spin_lock (&ring->lock);
  count = ring->count;
  pthread_spin_unlock (&ring->lock);
  return count;
}

size_t
spdk_ring_enqueue (struct spdk_ring *ring, void **objects, size_t count, size_t *free_space)
{
  size_t i, available;

  pthread_spin_lock (&ring->lock);
  available = ring->size - ring->count;
  count = clib_min (count, available);
  for (i = 0; i < count; i++)
    {
      ring->objects[ring->tail] = objects[i];
      ring->tail = (ring->tail + 1) % ring->size;
    }
  ring->count += count;
  if (free_space)
    *free_space = ring->size - ring->count;
  pthread_spin_unlock (&ring->lock);
  return count;
}

size_t
spdk_ring_dequeue (struct spdk_ring *ring, void **objects, size_t count)
{
  size_t i;

  pthread_spin_lock (&ring->lock);
  count = clib_min (count, ring->count);
  for (i = 0; i < count; i++)
    {
      objects[i] = ring->objects[ring->head];
      ring->head = (ring->head + 1) % ring->size;
    }
  ring->count -= count;
  pthread_spin_unlock (&ring->lock);
  return count;
}

void
spdk_env_opts_init (struct spdk_env_opts *opts)
{
  size_t opts_size;

  if (opts == NULL)
    return;
  opts_size = opts->opts_size;
  memset (opts, 0, sizeof (*opts));
  opts->opts_size = opts_size;
  opts->name = "vpp_spdk";
  opts->core_mask = "0x1";
  opts->shm_id = -1;
  opts->mem_channel = -1;
  opts->main_core = -1;
  opts->mem_size = -1;
  opts->no_pci = true;
}

int
spdk_env_init (const struct spdk_env_opts *opts)
{
  uint32_t first_core;

  if (opts == NULL || opts->core_mask == NULL)
    return -EINVAL;
  if (!opts->no_pci)
    {
      fprintf (stderr, "SPDK VPP env requires no_pci until a VPP PCI provider is configured\n");
      return -ENOTSUP;
    }
  if (spdk_cpuset_parse (&spdk_vpp_core_mask, opts->core_mask) != 0 ||
      spdk_cpuset_count (&spdk_vpp_core_mask) == 0)
    return -EINVAL;

  first_core = spdk_env_get_first_core ();
  spdk_vpp_main_core = opts->main_core >= 0 ? opts->main_core : first_core;
  if (!spdk_cpuset_get_cpu (&spdk_vpp_core_mask, spdk_vpp_main_core))
    return -EINVAL;
  spdk_vpp_env_initialized = true;
  return 0;
}

void
spdk_env_fini (void)
{
  spdk_vpp_env_initialized = false;
  spdk_vpp_main_core = SPDK_ENV_LCORE_ID_ANY;
  spdk_cpuset_zero (&spdk_vpp_core_mask);
}

uint32_t
spdk_env_get_core_count (void)
{
  return spdk_cpuset_count (&spdk_vpp_core_mask);
}

uint32_t
spdk_env_get_current_core (void)
{
  return spdk_vpp_current_core;
}

void
spdk_vpp_env_set_current_core (uint32_t core)
{
  spdk_vpp_current_core = core;
}

uint32_t
spdk_env_get_main_core (void)
{
  return spdk_vpp_main_core;
}

uint32_t
spdk_env_get_next_core (uint32_t previous)
{
  uint32_t core;

  for (core = previous + 1; core < SPDK_CPUSET_SIZE; core++)
    if (spdk_cpuset_get_cpu (&spdk_vpp_core_mask, core))
      return core;
  return SPDK_ENV_LCORE_ID_ANY;
}

uint32_t
spdk_env_get_first_core (void)
{
  return spdk_env_get_next_core (UINT32_MAX);
}

uint32_t
spdk_env_get_last_core (void)
{
  uint32_t core, last = SPDK_ENV_LCORE_ID_ANY;

  SPDK_ENV_FOREACH_CORE (core)
  last = core;
  return last;
}

int32_t
spdk_env_get_numa_id (uint32_t core)
{
  int node = numa_available () >= 0 ? numa_node_of_cpu (core) : 0;
  return node >= 0 ? node : SPDK_ENV_NUMA_ID_ANY;
}

int32_t
spdk_env_get_first_numa_id (void)
{
  return 0;
}

int32_t
spdk_env_get_last_numa_id (void)
{
  int node = numa_available () >= 0 ? numa_max_node () : 0;
  return node >= 0 ? node : 0;
}

int32_t
spdk_env_get_next_numa_id (int32_t previous)
{
  return previous < spdk_env_get_last_numa_id () ? previous + 1 : INT32_MAX;
}

void
spdk_env_get_cpuset (struct spdk_cpuset *cpuset)
{
  spdk_cpuset_copy (cpuset, &spdk_vpp_core_mask);
}

bool
spdk_env_core_get_smt_cpuset (struct spdk_cpuset *cpuset, uint32_t core)
{
  (void) cpuset;
  (void) core;
  return false;
}

int
spdk_env_thread_launch_pinned (uint32_t core, thread_start_fn fn, void *arg)
{
  (void) core;
  (void) fn;
  (void) arg;
  return -ENOTSUP;
}

void
spdk_env_thread_wait_all (void)
{
}

bool
spdk_process_is_primary (void)
{
  return true;
}

uint64_t
spdk_get_ticks (void)
{
  return clib_cpu_time_now ();
}

uint64_t
spdk_get_ticks_hz (void)
{
  f64 frequency = spdk_vpp_vm ()->clib_time.clocks_per_second;
  return frequency > 0 ? (uint64_t) frequency : (uint64_t) os_cpu_clock_frequency ();
}

void
spdk_delay_us (unsigned int us)
{
  usleep (us);
}

void
spdk_pause (void)
{
  CLIB_PAUSE ();
}

bool
spdk_iommu_is_enabled (void)
{
  /* PCI is disabled in this environment, so no SPDK device owns an IOMMU map. */
  return false;
}

uint64_t
spdk_vtophys (const void *buffer, uint64_t *size)
{
  clib_pmalloc_main_t *pm = spdk_vpp_vm ()->physmem_main.pmalloc_main;
  uint64_t page_size, offset;

  if (!spdk_vpp_physmem_contains (buffer))
    return SPDK_VTOPHYS_ERROR;
  page_size = 1ULL << pm->lookup_log2_page_sz;
  offset = pointer_to_uword (buffer) & (page_size - 1);
  if (size)
    *size = clib_min (*size, page_size - offset);
  return vlib_physmem_get_pa (spdk_vpp_vm (), (void *) buffer);
}

int32_t
spdk_mem_get_numa_id (const void *buffer, uint64_t *size)
{
  clib_pmalloc_arena_t *arena;
  clib_pmalloc_main_t *pm = spdk_vpp_vm ()->physmem_main.pmalloc_main;

  if (!spdk_vpp_physmem_contains (buffer))
    return SPDK_ENV_NUMA_ID_ANY;
  if (size)
    {
      uint64_t ignored = spdk_vtophys (buffer, size);
      (void) ignored;
    }
  arena = clib_pmalloc_get_arena (pm, (void *) buffer);
  return arena->numa_node;
}

int
spdk_mem_get_fd_and_offset (void *address, uint64_t *offset)
{
  clib_pmalloc_arena_t *arena;
  clib_pmalloc_main_t *pm = spdk_vpp_vm ()->physmem_main.pmalloc_main;

  if (!spdk_vpp_physmem_contains (address))
    return -EINVAL;
  arena = clib_pmalloc_get_arena (pm, address);
  if (offset)
    *offset = pointer_to_uword (address) - pointer_to_uword (pm->base) -
	      ((uword) arena->first_page_index << pm->def_log2_page_sz);
  return arena->fd >= 0 ? arena->fd : -ENOTSUP;
}

struct spdk_mem_map *
spdk_mem_map_alloc (uint64_t default_translation, const struct spdk_mem_map_ops *ops, void *cb_ctx)
{
  struct spdk_mem_map *map = calloc (1, sizeof (*map));
  spdk_vpp_mem_registration_t *registration;

  if (map == NULL || pthread_rwlock_init (&map->lock, NULL) != 0)
    {
      free (map);
      return NULL;
    }
  map->default_translation = default_translation;
  map->ops = ops;
  map->cb_ctx = cb_ctx;

  pthread_mutex_lock (&spdk_vpp_map_lock);
  map->next = spdk_vpp_maps;
  spdk_vpp_maps = map;
  if (ops && ops->notify_cb)
    for (registration = spdk_vpp_registrations; registration; registration = registration->next)
      if (ops->notify_cb (cb_ctx, map, SPDK_MEM_MAP_NOTIFY_REGISTER, registration->address,
			  registration->size) != 0)
	break;
  pthread_mutex_unlock (&spdk_vpp_map_lock);
  return map;
}

void
spdk_mem_map_free (struct spdk_mem_map **map_pointer)
{
  struct spdk_mem_map **link;
  struct spdk_mem_map *map;
  spdk_vpp_translation_t *translation;

  if (map_pointer == NULL || (map = *map_pointer) == NULL)
    return;
  pthread_mutex_lock (&spdk_vpp_map_lock);
  link = &spdk_vpp_maps;
  while (*link && *link != map)
    link = &(*link)->next;
  if (*link)
    *link = map->next;
  pthread_mutex_unlock (&spdk_vpp_map_lock);

  while ((translation = map->translations) != NULL)
    {
      map->translations = translation->next;
      free (translation);
    }
  pthread_rwlock_destroy (&map->lock);
  free (map);
  *map_pointer = NULL;
}

int
spdk_mem_map_set_translation (struct spdk_mem_map *map, uint64_t address, uint64_t size,
			      uint64_t translation)
{
  spdk_vpp_translation_t *entry = calloc (1, sizeof (*entry));
  if (entry == NULL)
    return -ENOMEM;
  entry->address = address;
  entry->size = size;
  entry->translation = translation;
  pthread_rwlock_wrlock (&map->lock);
  entry->next = map->translations;
  map->translations = entry;
  pthread_rwlock_unlock (&map->lock);
  return 0;
}

int
spdk_mem_map_clear_translation (struct spdk_mem_map *map, uint64_t address, uint64_t size)
{
  spdk_vpp_translation_t **link, *entry;

  pthread_rwlock_wrlock (&map->lock);
  link = &map->translations;
  while ((entry = *link) != NULL)
    {
      if (entry->address == address && entry->size == size)
	{
	  *link = entry->next;
	  free (entry);
	  pthread_rwlock_unlock (&map->lock);
	  return 0;
	}
      link = &entry->next;
    }
  pthread_rwlock_unlock (&map->lock);
  return -ENOENT;
}

uint64_t
spdk_mem_map_translate (const struct spdk_mem_map *map, uint64_t address, uint64_t *size)
{
  spdk_vpp_translation_t *entry;
  uint64_t result = map->default_translation;

  pthread_rwlock_rdlock ((pthread_rwlock_t *) &map->lock);
  for (entry = map->translations; entry; entry = entry->next)
    if (address >= entry->address && address < entry->address + entry->size)
      {
	uint64_t offset = address - entry->address;
	result = entry->translation + offset;
	if (size)
	  *size = clib_min (*size, entry->size - offset);
	break;
      }
  pthread_rwlock_unlock ((pthread_rwlock_t *) &map->lock);
  return result;
}

static int
spdk_vpp_mem_notify (enum spdk_mem_map_notify_action action, void *address, size_t size)
{
  struct spdk_mem_map *map;
  int rc = 0;

  for (map = spdk_vpp_maps; map; map = map->next)
    if (map->ops && map->ops->notify_cb)
      {
	rc = map->ops->notify_cb (map->cb_ctx, map, action, address, size);
	if (rc)
	  break;
      }
  return rc;
}

int
spdk_mem_register (void *address, size_t size)
{
  spdk_vpp_mem_registration_t *registration;
  int rc;

  if (address == NULL || size == 0 || !spdk_vpp_physmem_contains (address) ||
      !spdk_vpp_physmem_contains ((uint8_t *) address + size - 1))
    return -EINVAL;
  registration = calloc (1, sizeof (*registration));
  if (registration == NULL)
    return -ENOMEM;
  registration->address = address;
  registration->size = size;

  pthread_mutex_lock (&spdk_vpp_map_lock);
  rc = spdk_vpp_mem_notify (SPDK_MEM_MAP_NOTIFY_REGISTER, address, size);
  if (rc == 0)
    {
      registration->next = spdk_vpp_registrations;
      spdk_vpp_registrations = registration;
    }
  pthread_mutex_unlock (&spdk_vpp_map_lock);
  if (rc)
    free (registration);
  return rc;
}

int
spdk_mem_unregister (void *address, size_t size)
{
  spdk_vpp_mem_registration_t **link, *registration;
  int rc;

  pthread_mutex_lock (&spdk_vpp_map_lock);
  link = &spdk_vpp_registrations;
  while ((registration = *link) != NULL &&
	 (registration->address != address || registration->size != size))
    link = &registration->next;
  if (registration == NULL)
    {
      pthread_mutex_unlock (&spdk_vpp_map_lock);
      return -ENOENT;
    }
  rc = spdk_vpp_mem_notify (SPDK_MEM_MAP_NOTIFY_UNREGISTER, address, size);
  if (rc == 0)
    *link = registration->next;
  pthread_mutex_unlock (&spdk_vpp_map_lock);
  if (rc == 0)
    free (registration);
  return rc;
}

int
spdk_mem_reserve (void *address, size_t size)
{
  (void) address;
  (void) size;
  return 0;
}

void
spdk_pci_driver_register (const char *name, struct spdk_pci_id *id_table, uint32_t flags)
{
  struct spdk_pci_driver *driver = calloc (1, sizeof (*driver));
  if (driver == NULL)
    return;
  driver->name = strdup (name);
  driver->id_table = id_table;
  driver->flags = flags;
  pthread_mutex_lock (&spdk_vpp_pci_lock);
  driver->next = spdk_vpp_pci_drivers;
  spdk_vpp_pci_drivers = driver;
  pthread_mutex_unlock (&spdk_vpp_pci_lock);
}

struct spdk_pci_driver *
spdk_pci_get_driver (const char *name)
{
  struct spdk_pci_driver *driver;
  pthread_mutex_lock (&spdk_vpp_pci_lock);
  for (driver = spdk_vpp_pci_drivers; driver; driver = driver->next)
    if (strcmp (driver->name, name) == 0)
      break;
  pthread_mutex_unlock (&spdk_vpp_pci_lock);
  return driver;
}

struct spdk_pci_driver *
spdk_pci_nvme_get_driver (void)
{
  return spdk_pci_get_driver ("nvme");
}
struct spdk_pci_driver *
spdk_pci_vmd_get_driver (void)
{
  return spdk_pci_get_driver ("vmd");
}
struct spdk_pci_driver *
spdk_pci_ioat_get_driver (void)
{
  return spdk_pci_get_driver ("ioat");
}
struct spdk_pci_driver *
spdk_pci_idxd_get_driver (void)
{
  return spdk_pci_get_driver ("idxd");
}
struct spdk_pci_driver *
spdk_pci_ae4dma_get_driver (void)
{
  return spdk_pci_get_driver ("ae4dma");
}
struct spdk_pci_driver *
spdk_pci_virtio_get_driver (void)
{
  return spdk_pci_get_driver ("virtio");
}

int
spdk_pci_enumerate (struct spdk_pci_driver *driver, spdk_pci_enum_cb cb, void *cb_ctx)
{
  (void) driver;
  (void) cb;
  (void) cb_ctx;
  return 0;
}

void
spdk_pci_for_each_device (void *ctx, void (*fn) (void *, struct spdk_pci_device *))
{
  (void) ctx;
  (void) fn;
}

int
spdk_pci_device_map_bar (struct spdk_pci_device *device, uint32_t bar, void **address,
			 uint64_t *physical_address, uint64_t *size)
{
  return device && device->map_bar ?
	   device->map_bar (device, bar, address, physical_address, size) :
	   -ENOTSUP;
}

int
spdk_pci_device_unmap_bar (struct spdk_pci_device *device, uint32_t bar, void *address)
{
  return device && device->unmap_bar ? device->unmap_bar (device, bar, address) : -ENOTSUP;
}

int
spdk_pci_device_enable_interrupt (struct spdk_pci_device *d)
{
  (void) d;
  return -ENOTSUP;
}
int
spdk_pci_device_disable_interrupt (struct spdk_pci_device *d)
{
  (void) d;
  return -ENOTSUP;
}
int
spdk_pci_device_get_interrupt_efd (struct spdk_pci_device *d)
{
  (void) d;
  return -ENOTSUP;
}
int
spdk_pci_device_enable_interrupts (struct spdk_pci_device *d, uint32_t n)
{
  (void) d;
  (void) n;
  return -ENOTSUP;
}
int
spdk_pci_device_disable_interrupts (struct spdk_pci_device *d)
{
  (void) d;
  return -ENOTSUP;
}
int
spdk_pci_device_get_interrupt_efd_by_index (struct spdk_pci_device *d, uint32_t i)
{
  (void) d;
  (void) i;
  return -ENOTSUP;
}

uint32_t
spdk_pci_device_get_domain (struct spdk_pci_device *d)
{
  return d->addr.domain;
}
uint8_t
spdk_pci_device_get_bus (struct spdk_pci_device *d)
{
  return d->addr.bus;
}
uint8_t
spdk_pci_device_get_dev (struct spdk_pci_device *d)
{
  return d->addr.dev;
}
uint8_t
spdk_pci_device_get_func (struct spdk_pci_device *d)
{
  return d->addr.func;
}
struct spdk_pci_addr
spdk_pci_device_get_addr (struct spdk_pci_device *d)
{
  return d->addr;
}
uint16_t
spdk_pci_device_get_vendor_id (struct spdk_pci_device *d)
{
  return d->id.vendor_id;
}
uint16_t
spdk_pci_device_get_device_id (struct spdk_pci_device *d)
{
  return d->id.device_id;
}
uint16_t
spdk_pci_device_get_subvendor_id (struct spdk_pci_device *d)
{
  return d->id.subvendor_id;
}
uint16_t
spdk_pci_device_get_subdevice_id (struct spdk_pci_device *d)
{
  return d->id.subdevice_id;
}
struct spdk_pci_id
spdk_pci_device_get_id (struct spdk_pci_device *d)
{
  return d->id;
}
int
spdk_pci_device_get_numa_id (struct spdk_pci_device *d)
{
  return d->numa_id;
}
const char *
spdk_pci_device_get_type (const struct spdk_pci_device *d)
{
  return d->type;
}
bool
spdk_pci_device_is_removed (struct spdk_pci_device *d)
{
  return d->internal.removed;
}

int
spdk_pci_device_cfg_read (struct spdk_pci_device *device, void *buffer, uint32_t length,
			  uint32_t offset)
{
  return device && device->cfg_read ? device->cfg_read (device, buffer, length, offset) : -ENOTSUP;
}

int
spdk_pci_device_cfg_write (struct spdk_pci_device *device, void *buffer, uint32_t length,
			   uint32_t offset)
{
  return device && device->cfg_write ? device->cfg_write (device, buffer, length, offset) :
				       -ENOTSUP;
}

int
spdk_pci_device_cfg_read8 (struct spdk_pci_device *d, uint8_t *v, uint32_t o)
{
  return spdk_pci_device_cfg_read (d, v, sizeof (*v), o);
}
int
spdk_pci_device_cfg_read16 (struct spdk_pci_device *d, uint16_t *v, uint32_t o)
{
  return spdk_pci_device_cfg_read (d, v, sizeof (*v), o);
}
int
spdk_pci_device_cfg_read32 (struct spdk_pci_device *d, uint32_t *v, uint32_t o)
{
  return spdk_pci_device_cfg_read (d, v, sizeof (*v), o);
}
int
spdk_pci_device_cfg_write8 (struct spdk_pci_device *d, uint8_t v, uint32_t o)
{
  return spdk_pci_device_cfg_write (d, &v, sizeof (v), o);
}
int
spdk_pci_device_cfg_write16 (struct spdk_pci_device *d, uint16_t v, uint32_t o)
{
  return spdk_pci_device_cfg_write (d, &v, sizeof (v), o);
}
int
spdk_pci_device_cfg_write32 (struct spdk_pci_device *d, uint32_t v, uint32_t o)
{
  return spdk_pci_device_cfg_write (d, &v, sizeof (v), o);
}

int
spdk_pci_device_claim (struct spdk_pci_device *d)
{
  (void) d;
  return -ENOTSUP;
}
void
spdk_pci_device_unclaim (struct spdk_pci_device *d)
{
  (void) d;
}
void
spdk_pci_device_detach (struct spdk_pci_device *d)
{
  (void) d;
}
int
spdk_pci_device_attach (struct spdk_pci_driver *d, spdk_pci_enum_cb cb, void *c,
			struct spdk_pci_addr *a)
{
  (void) d;
  (void) cb;
  (void) c;
  (void) a;
  return -ENOTSUP;
}
int
spdk_pci_device_allow (struct spdk_pci_addr *a)
{
  (void) a;
  return -ENOTSUP;
}
int
spdk_pci_hook_device (struct spdk_pci_driver *d, struct spdk_pci_device *p)
{
  (void) d;
  (void) p;
  return -ENOTSUP;
}
void
spdk_pci_unhook_device (struct spdk_pci_device *d)
{
  (void) d;
}
void
spdk_pci_register_device_provider (struct spdk_pci_device_provider *p)
{
  (void) p;
}

int
spdk_pci_addr_compare (const struct spdk_pci_addr *a, const struct spdk_pci_addr *b)
{
  if (a->domain != b->domain)
    return a->domain < b->domain ? -1 : 1;
  if (a->bus != b->bus)
    return a->bus < b->bus ? -1 : 1;
  if (a->dev != b->dev)
    return a->dev < b->dev ? -1 : 1;
  if (a->func != b->func)
    return a->func < b->func ? -1 : 1;
  return 0;
}

int
spdk_pci_addr_parse (struct spdk_pci_addr *address, const char *text)
{
  unsigned domain = 0, bus, device, function;
  int fields;

  fields = sscanf (text, "%x:%x:%x.%x", &domain, &bus, &device, &function);
  if (fields != 4)
    {
      fields = sscanf (text, "%x:%x.%x", &bus, &device, &function);
      if (fields != 3)
	return -EINVAL;
    }
  if (domain > UINT32_MAX || bus > UINT8_MAX || device > 31 || function > 7)
    return -EINVAL;
  address->domain = domain;
  address->bus = bus;
  address->dev = device;
  address->func = function;
  return 0;
}

int
spdk_pci_addr_fmt (char *text, size_t size, const struct spdk_pci_addr *address)
{
  int length = snprintf (text, size, "%04x:%02x:%02x.%x", address->domain, address->bus,
			 address->dev, address->func);
  return length < 0 || (size_t) length >= size ? -ENOSPC : 0;
}

int
spdk_pci_event_listen (void)
{
  return -ENOTSUP;
}
int
spdk_pci_get_event (int fd, struct spdk_pci_event *event)
{
  (void) fd;
  (void) event;
  return -ENOTSUP;
}
int
spdk_pci_register_error_handler (spdk_pci_error_handler h, void *c)
{
  (void) h;
  (void) c;
  return 0;
}
void
spdk_pci_unregister_error_handler (spdk_pci_error_handler h)
{
  (void) h;
}

void
spdk_unaffinitize_thread (void)
{
  cpu_set_t cpuset;
  long cpu_count = sysconf (_SC_NPROCESSORS_CONF);
  long cpu;

  CPU_ZERO (&cpuset);
  for (cpu = 0; cpu < cpu_count && cpu < CPU_SETSIZE; cpu++)
    CPU_SET (cpu, &cpuset);
  pthread_setaffinity_np (pthread_self (), sizeof (cpuset), &cpuset);
}

void *
spdk_call_unaffinitized (void *cb (void *), void *arg)
{
  cpu_set_t saved;
  void *result;

  if (pthread_getaffinity_np (pthread_self (), sizeof (saved), &saved) != 0)
    return cb (arg);
  spdk_unaffinitize_thread ();
  result = cb (arg);
  pthread_setaffinity_np (pthread_self (), sizeof (saved), &saved);
  return result;
}

int
spdk_get_tid (void)
{
  return syscall (SYS_gettid);
}
