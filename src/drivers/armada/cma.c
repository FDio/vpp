/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Marvell.
 */

#include <cma.h>

#include <fcntl.h>
#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>

#include <vppinfra/mem.h>

#define MUSDK_DEV_FILE "/dev/musdk-cma"

#define MUSDK_IOC_TYPE_BASE 0x23
#define MUSDK_IOC_NUM(n)    (n)
#define MUSDK_IOC_CMA_ALLOC _IOW (MUSDK_IOC_TYPE_BASE, MUSDK_IOC_NUM (1), uint64_t)
#define MUSDK_IOC_CMA_FREE  _IOW (MUSDK_IOC_TYPE_BASE, MUSDK_IOC_NUM (2), uint64_t)

#define MVCONF_DBG_LEVEL  0
#define MV_DBG_L_ERR	  3
#define MV_DBG_L_DBG	  7
#define log_fmt(fmt, ...) fmt, ##__VA_ARGS__
#define mv_print(_level, fmt, ...)                                                                 \
  do                                                                                               \
    {                                                                                              \
      if ((_level) <= (MVCONF_DBG_LEVEL))                                                          \
	{                                                                                          \
	  struct timespec spec;                                                                    \
	  clock_gettime (CLOCK_BOOTTIME, &spec);                                                   \
	  printf ("[%5lu.%06lu] ", spec.tv_sec, spec.tv_nsec / 1000);                              \
	  printf (log_fmt (fmt, ##__VA_ARGS__));                                                   \
	}                                                                                          \
    }                                                                                              \
  while (0)
#define pr_err(fmt, ...)  mv_print (MV_DBG_L_ERR, "[ERROR] " fmt, ##__VA_ARGS__)
#define pr_warn(fmt, ...) pr_err (fmt, ##__VA_ARGS__)
#define pr_crit(fmt, ...) pr_err (fmt, ##__VA_ARGS__)
#ifdef DEBUG
#define pr_debug(fmt, ...) mv_print (MV_DBG_L_DBG, "[DBG] " fmt, ##__VA_ARGS__)
#else
#define pr_debug(...)
#endif

#define BUG abort
#define BUG_ON(_cond)                                                                              \
  do                                                                                               \
    {                                                                                              \
      if (_cond)                                                                                   \
	{                                                                                          \
	  pr_crit ("[%s:%d] found BUG!\n", __FILE__, __LINE__);                                    \
	  BUG ();                                                                                  \
	}                                                                                          \
    }                                                                                              \
  while (0)

#define MEM_DMA_MAX_REGIONS   16
#define MEM_MNG_ILLEGAL_BASE  (-1)
#define MEM_MNG_MAX_ALIGNMENT 20
#define MEM_MNG_MAX_NAME_LEN  32
#define MAKE_ALIGNED(addr, align)                                                                  \
  (((uint64_t) (addr) + ((align) - 1)) & (~(((uint64_t) (align)) - 1)))

typedef struct dma_spinlock
{
  char lock;
} dma_spinlock_t;

typedef struct mem_blk
{
  struct mem_blk *next;
  uint64_t base;
  uint64_t end;
  char name[MEM_MNG_MAX_NAME_LEN];
} mem_blk_t;

typedef mem_blk_t free_mem_blk_t;
typedef mem_blk_t busy_mem_blk_t;

typedef struct mem_mng
{
  dma_spinlock_t *lock;
  mem_blk_t *blks;
  mem_blk_t *busy_blks;
  mem_blk_t *free_blks[MEM_MNG_MAX_ALIGNMENT + 1];
  uint64_t free_mem_size;
} mm_t;

struct sys_dma
{
  struct mem_mng *mm;
  void *mem;
  void *dma_virt_base;
  uint64_t dma_phys_base;
  size_t dma_size;
  int en;
};

struct sys_mem_dma_region_priv
{
  struct mem_mng *mm;
  void *mem;
};

struct cma_buf_info
{
  void *uvaddr;
  uint64_t paddr;
  size_t size;
};

static int fd = -1;
static uint64_t __dma_phys_base;
static void *__dma_virt_base;
static size_t __dma_size;
static struct sys_dma *sys_dma;
static struct mv_sys_dma_mem_region *sys_dma_regions[MEM_DMA_MAX_REGIONS];

static inline void
spin_lock_init (dma_spinlock_t *spinlock)
{
  __atomic_clear (&spinlock->lock, __ATOMIC_RELAXED);
}

static dma_spinlock_t *
spin_lock_create (void)
{
  dma_spinlock_t *lock = clib_mem_alloc_or_null (sizeof (*lock));

  if (lock)
    spin_lock_init (lock);
  return lock;
}

static void
spin_lock_destroy (dma_spinlock_t *lock)
{
  if (lock)
    clib_mem_free (lock);
}

static inline void
spin_lock (dma_spinlock_t *spinlock)
{
  while (__atomic_test_and_set (&spinlock->lock, __ATOMIC_ACQUIRE))
    while (__atomic_load_n (&spinlock->lock, __ATOMIC_RELAXED))
      ;
}

static inline void
spin_unlock (dma_spinlock_t *spinlock)
{
  __atomic_clear (&spinlock->lock, __ATOMIC_RELEASE);
}

#define spin_lock_irqsave(_lock, _flags)                                                           \
  do                                                                                               \
    {                                                                                              \
      (_flags) = 0;                                                                                \
      spin_lock (_lock);                                                                           \
    }                                                                                              \
  while (0)
#define spin_unlock_irqrestore(_lock, _flags)                                                      \
  do                                                                                               \
    {                                                                                              \
      (_flags) = (_flags);                                                                         \
      spin_unlock (_lock);                                                                         \
    }                                                                                              \
  while (0)

static mem_blk_t *create_new_blk (uint64_t base, uint64_t size);
static free_mem_blk_t *create_free_blk (uint64_t base, uint64_t size);
static busy_mem_blk_t *create_busy_blk (uint64_t base, uint64_t size, const char *name);
static int cut_free_blk (mm_t *mm, uint64_t hold_base, uint64_t hold_end);
static void add_busy_blk (mm_t *mm, busy_mem_blk_t *new_blk);
static int add_free_blk (mm_t *mm, uint64_t base, uint64_t end);
static int mem_mng_init (uint64_t base, uint64_t size, struct mem_mng **mm);
static void mem_mng_free (struct mem_mng *mm);
static uint64_t mem_mng_get (struct mem_mng *mm, uint64_t size, uint64_t alignment,
			     const char *name);
static uint64_t mem_mng_put (struct mem_mng *mm, uint64_t base);
static uint64_t get_greater_align (mm_t *mm, uint64_t size, uint64_t alignment, const char *name);
static bool mem_region_exist (struct mv_sys_dma_mem_region *mem);

static void *
mem_calloc (size_t count, size_t size)
{
  size_t bytes;
  void *p;

  if (__builtin_mul_overflow (count, size, &bytes))
    return NULL;

  p = clib_mem_alloc_or_null (bytes);
  if (p)
    memset (p, 0, bytes);

  return p;
}

static int
cma_init (void)
{
  if (fd >= 0)
    return 0;

  fd = open (MUSDK_DEV_FILE, O_RDWR);

  if (fd < 0)
    {
      pr_err ("CMA: open() failed\n");
      return -1;
    }
  return 0;
}

static void *
cma_calloc (size_t size)
{
  struct cma_buf_info *ptr;
  uint64_t param;
  off_t pgoff;
  void *ret;
  int err;

  if (fd < 0)
    return NULL;

  ptr = mem_calloc (1, sizeof (struct cma_buf_info));
  if (!ptr)
    return NULL;

  param = size;
  if ((err = ioctl (fd, MUSDK_IOC_CMA_ALLOC, &param)) != 0)
    {
      pr_err ("CMA: ioctl(MUSDK_IOC_CMA_ALLOC) failed. size=%zu, error=%d\n", size, err);
      clib_mem_free (ptr);
      return 0;
    }

  pgoff = param;
  ret = mmap (NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, pgoff);
  if (ret == MAP_FAILED)
    {
      pr_err ("CMA: mmap() payload failed (%d)\n", (int) (uintptr_t) ret);
      clib_mem_free (ptr);
      return 0;
    }
  ptr->uvaddr = ret;
  ptr->paddr = param;
  ptr->size = size;

  pr_debug ("%s: cma_buf_info = %p, uvaddr=%p, paddr=0x%lx, size=%ld\n", __func__, ptr, ptr->uvaddr,
	    ptr->paddr, ptr->size);

  return (void *) ptr;
}

static void
cma_free (void *handle)
{
  struct cma_buf_info *ptr = (struct cma_buf_info *) handle;
  uint64_t paddr;
  int err;

  if (!ptr || fd < 0)
    return;

  pr_debug ("free %p of %zu bytes\n", ptr, ptr->size);

  paddr = ptr->paddr;

  munmap (ptr->uvaddr, ptr->size);

  err = ioctl (fd, MUSDK_IOC_CMA_FREE, &paddr);
  if (err)
    pr_err ("CMA: ioctl() MUSDK_IOC_CMA_FREE failed (%d)\n", err);

  clib_mem_free (ptr);
}

static void *
cma_get_vaddr (void *handle)
{
  struct cma_buf_info *ptr = (struct cma_buf_info *) handle;

  if (!ptr)
    return NULL;

  pr_debug ("cma_buf_info = %p, vaddr = %p\n", ptr, ptr->uvaddr);

  return ptr->uvaddr;
}

static uint64_t
cma_get_paddr (void *handle)
{
  struct cma_buf_info *ptr = (struct cma_buf_info *) handle;

  if (!ptr)
    return 0;

  pr_debug ("cma_admin = %p, paddr = 0x%lx\n", ptr, ptr->paddr);

  return ptr->paddr;
}

static size_t
cma_get_size (void *handle)
{
  struct cma_buf_info *ptr = (struct cma_buf_info *) handle;

  if (!ptr)
    return 0;

  return ptr->size;
}

static mem_blk_t *
create_new_blk (u64 base, u64 size)
{
  mem_blk_t *mem_blk;

  mem_blk = (mem_blk_t *) clib_mem_alloc_or_null (sizeof (mem_blk_t));
  if (!mem_blk)
    {
      pr_err ("no mem for block obj!\n");
      return NULL;
    }

  mem_blk->base = base;
  mem_blk->end = base + size;
  mem_blk->next = NULL;

  return mem_blk;
}

static free_mem_blk_t *
create_free_blk (u64 base, u64 size)
{
  free_mem_blk_t *free_blk;

  free_blk = (free_mem_blk_t *) clib_mem_alloc_or_null (sizeof (free_mem_blk_t));
  if (!free_blk)
    {
      pr_err ("no mem for free-block obj!\n");
      return NULL;
    }

  free_blk->base = base;
  free_blk->end = base + size;
  free_blk->next = NULL;

  return free_blk;
}

static int
mem_mng_init (u64 base, u64 size, struct mem_mng **mm)
{
  mm_t *mm_o;
  u64 new_base, new_size;
  int i;

  if (!size)
    {
      pr_err ("Illegal size (should be positive)!\n");
      return -EINVAL;
    }

  /* Initializes a new MM object */
  mm_o = (mm_t *) clib_mem_alloc_or_null (sizeof (mm_t));
  if (!mm_o)
    {
      pr_err ("no mem for mem-mng obj!\n");
      return -ENOMEM;
    }

  mm_o->lock = spin_lock_create ();
  if (!mm_o->lock)
    {
      if (mm_o)
	clib_mem_free (mm_o);
      pr_err ("failed to create spinlock!\n");
      return -ENOMEM;
    }

  /* Initializes counter of free memory to total size */
  mm_o->free_mem_size = size;

  /* A busy list is empty */
  mm_o->busy_blks = 0;

  /* Initializes a new memory block */
  if ((mm_o->blks = create_new_blk (base, size)) == NULL)
    {
      mem_mng_free (mm_o);
      pr_err ("failed to create new mem block!\n");
      return -ENOMEM;
    }

  /* Initializes a new free block for each free list*/
  for (i = 0; i <= MEM_MNG_MAX_ALIGNMENT; i++)
    {
      new_base = MAKE_ALIGNED (base, (0x1 << i));
      new_size = size - (new_base - base);

      if ((mm_o->free_blks[i] = create_free_blk (new_base, new_size)) == NULL)
	{
	  mem_mng_free (mm_o);
	  pr_err ("failed to create free mem block!\n");
	  return -ENOMEM;
	}
    }

  *mm = mm_o;

  return 0;
}

static void
mem_mng_free (struct mem_mng *mm)
{
  mem_blk_t *mem_blk;
  busy_mem_blk_t *busy_blk;
  free_mem_blk_t *free_blk;
  void *blk;
  int i;

  if (!mm)
    {
      pr_err ("Invalid handle provided!\n");
      return;
    }

  /* release memory allocated for busy blocks */
  busy_blk = mm->busy_blks;
  while (busy_blk)
    {
      blk = busy_blk;
      busy_blk = busy_blk->next;
      if (blk)
	clib_mem_free (blk);
    }

  /* release memory allocated for free blocks */
  for (i = 0; i <= MEM_MNG_MAX_ALIGNMENT; i++)
    {
      free_blk = mm->free_blks[i];
      while (free_blk)
	{
	  blk = free_blk;
	  free_blk = free_blk->next;
	  if (blk)
	    clib_mem_free (blk);
	}
    }

  /* release memory allocated for memory blocks */
  mem_blk = mm->blks;
  while (mem_blk)
    {
      blk = mem_blk;
      mem_blk = mem_blk->next;
      if (blk)
	clib_mem_free (blk);
    }

  if (mm->lock)
    spin_lock_destroy (mm->lock);

  /* release memory allocated for MM object itself */
  if (mm)
    clib_mem_free (mm);
}

void
mv_sys_dma_mem_destroy (void)
{
  if (!sys_dma)
    return;

  mem_mng_free (sys_dma->mm);
  BUG_ON (!sys_dma);
  if (sys_dma->dma_virt_base)
    cma_free (sys_dma->mem);
  if (sys_dma)
    clib_mem_free (sys_dma);
  sys_dma = NULL;
  __dma_phys_base = 0;
  __dma_virt_base = NULL;
}

int
mv_sys_dma_mem_init (size_t size)
{
  struct sys_dma *i_sys_dma;
  int err;

#ifdef MVCONF_SYSLOG
  /* Enable the logging facility
   * Temporarily set always print to stderr
   */
  log_init (1);
#endif

  if (sys_dma)
    {
      pr_err ("Dma object already exits.\n");
      return -EEXIST;
    }
  else
    {
      i_sys_dma = (struct sys_dma *) clib_mem_alloc_or_null (sizeof (struct sys_dma));
      if (!i_sys_dma)
	{
	  pr_err ("No mem for sys-dma object\n");
	  return -ENOMEM;
	}
      memset (i_sys_dma, 0, sizeof (struct sys_dma));
    }

  BUG_ON (!i_sys_dma);

  if (!i_sys_dma->en)
    {
      err = cma_init ();
      if (err)
	{
	  pr_err ("Failed to init DMA memory (%d)!\n", err);
	  return err;
	}
      i_sys_dma->en = 1;
    }

  i_sys_dma->mem = cma_calloc ((size_t) size);
  if (!i_sys_dma->mem)
    {
      pr_err ("Failed to allocate DMA memory!\n");
      return -ENOMEM;
    }

  i_sys_dma->dma_virt_base = (void *) cma_get_vaddr (i_sys_dma->mem);
  i_sys_dma->dma_phys_base = cma_get_paddr (i_sys_dma->mem);
  pr_debug ("init_mem dma_phys_base(0x%" PRIdma ")\n", i_sys_dma->dma_phys_base);

  i_sys_dma->dma_size = (size_t) cma_get_size (i_sys_dma->mem);

  err = mem_mng_init ((u64) (uintptr_t) i_sys_dma->dma_virt_base, size, &i_sys_dma->mm);
  if (err != 0)
    return err;

  if (!sys_dma)
    {
      sys_dma = i_sys_dma;
      __dma_phys_base = sys_dma->dma_phys_base;
      __dma_virt_base = sys_dma->dma_virt_base;
      __dma_size = sys_dma->dma_size;
    }
  pr_debug ("[%s] __dma_phys_base(0x%lx) __dma_virt_base(%p) __dma_size (%zu)\n", __func__,
	    __dma_phys_base, __dma_virt_base, __dma_size);
#ifdef DEBUG
  memset (__dma_virt_base, 0xA, size);
#endif
  return 0;
}

static u64
get_greater_align (mm_t *mm, u64 size, u64 alignment, const char *name)
{
  free_mem_blk_t *free_blk;
  busy_mem_blk_t *new_blk;
  u64 hold_base, hold_end, align_base = 0;

  /* goes over free blocks of the 64 byte alignment list
     and look for a block of the suitable size and
     base address according to the alignment. */
  free_blk = mm->free_blks[MEM_MNG_MAX_ALIGNMENT];

  while (free_blk)
    {
      align_base = MAKE_ALIGNED (free_blk->base, alignment);

      /* the block is found if the aligned base inside the block
       * and has the anough size. */
      if (align_base >= free_blk->base && align_base < free_blk->end &&
	  size <= (free_blk->end - align_base))
	break;
      else
	free_blk = free_blk->next;
    }

  /* If such block isn't found */
  if (!free_blk)
    return (u64) (MEM_MNG_ILLEGAL_BASE);

  hold_base = align_base;
  hold_end = align_base + size;

  /* init a new busy block */
  if ((new_blk = create_busy_blk (hold_base, size, name)) == NULL)
    return (u64) (MEM_MNG_ILLEGAL_BASE);

  /* calls Update routine to update a lists of free blocks */
  if (cut_free_blk (mm, hold_base, hold_end) != 0)
    {
      if (new_blk)
	clib_mem_free (new_blk);
      return (u64) (MEM_MNG_ILLEGAL_BASE);
    }

  /* insert the new busy block into the list of busy blocks */
  add_busy_blk (mm, new_blk);

  return (hold_base);
}

static u64
mem_mng_get (struct mem_mng *mm, u64 size, u64 alignment, const char *name)
{
  free_mem_blk_t *free_blk;
  busy_mem_blk_t *new_blk;
  u64 hold_base, hold_end, j, i = 0;
  unsigned long flags;

  if (!mm)
    {
      pr_err ("Invalid handle provided!\n");
      return (u64) MEM_MNG_ILLEGAL_BASE;
    }

  if (!name || (strlen (name) >= MEM_MNG_MAX_NAME_LEN))
    {
      pr_err ("Invalid name provided!\n");
      return (u64) MEM_MNG_ILLEGAL_BASE;
    }

  /* checks that alignment value is greater then zero */
  if (alignment == 0)
    alignment = 1;

  j = alignment;

  /* checks if alignment is a power of two, if it correct and if the
     required size is multiple of the given alignment. */
  while ((j & 0x1) == 0)
    {
      i++;
      j = j >> 1;
    }

  /* if the given alignment isn't power of two, returns an error */
  if (j != 1)
    {
      pr_err ("Illegal alignment (should be power of 2)!\n");
      return (u64) MEM_MNG_ILLEGAL_BASE;
    }

  if (i > MEM_MNG_MAX_ALIGNMENT)
    return get_greater_align (mm, size, alignment, name);

  spin_lock_irqsave (mm->lock, flags);
  /* look for a block of the size greater or equal to the required size. */
  free_blk = mm->free_blks[i];
  while (free_blk && (free_blk->end - free_blk->base) < size)
    free_blk = free_blk->next;

  /* If such block is found */
  if (!free_blk)
    {
      spin_unlock_irqrestore (mm->lock, flags);
      return (u64) (MEM_MNG_ILLEGAL_BASE);
    }

  hold_base = free_blk->base;
  hold_end = hold_base + size;

  /* init a new busy block */
  if ((new_blk = create_busy_blk (hold_base, size, name)) == NULL)
    {
      spin_unlock_irqrestore (mm->lock, flags);
      return (u64) (MEM_MNG_ILLEGAL_BASE);
    }

  /* calls Update routine to update a lists of free blocks */
  if (cut_free_blk (mm, hold_base, hold_end) != 0)
    {
      spin_unlock_irqrestore (mm->lock, flags);
      if (new_blk)
	clib_mem_free (new_blk);
      return (u64) (MEM_MNG_ILLEGAL_BASE);
    }

  /* Decreasing the allocated memory size from free memory size */
  mm->free_mem_size -= size;

  /* insert the new busy block into the list of busy blocks */
  add_busy_blk (mm, new_blk);
  spin_unlock_irqrestore (mm->lock, flags);

  return (hold_base);
}

static u64
mem_mng_put (struct mem_mng *mm, u64 base)
{
  busy_mem_blk_t *busy_blk, *prev_blk;
  u64 size;
  unsigned long flags;

  if (!mm)
    {
      pr_err ("Invalid handle provided!\n");
      return (u64) MEM_MNG_ILLEGAL_BASE;
    }

  /* Look for a busy block that have the given base value.
   * That block will be returned back to the memory.
   */
  prev_blk = 0;

  spin_lock_irqsave (mm->lock, flags);
  busy_blk = mm->busy_blks;
  while (busy_blk && base != busy_blk->base)
    {
      prev_blk = busy_blk;
      busy_blk = busy_blk->next;
    }

  if (!busy_blk)
    {
      spin_unlock_irqrestore (mm->lock, flags);
      return (u64) 0;
    }

  if (add_free_blk (mm, busy_blk->base, busy_blk->end) != 0)
    {
      spin_unlock_irqrestore (mm->lock, flags);
      return (u64) 0;
    }

  /* removes a busy block form the list of busy blocks */
  if (prev_blk)
    prev_blk->next = busy_blk->next;
  else
    mm->busy_blks = busy_blk->next;

  size = busy_blk->end - busy_blk->base;

  /* Adding the deallocated memory size to free memory size */
  mm->free_mem_size += size;

  if (busy_blk)
    clib_mem_free (busy_blk);
  spin_unlock_irqrestore (mm->lock, flags);

  return (size);
}

static void *
mv_sys_dma_mem_alloc (size_t size, size_t align)
{
  u64 ans;

  if (!sys_dma)
    {
      pr_err ("no dma obj (not initialized?)!\n");
      return NULL;
    }

  ans = mem_mng_get (sys_dma->mm, size, align, "temp");
  if (ans == MEM_MNG_ILLEGAL_BASE)
    {
      pr_err ("failed to alloc mem!\n");
      return NULL;
    }

  return (void *) (uintptr_t) ans;
}

static void
mv_sys_dma_mem_free (void *ptr)
{
  if (!sys_dma)
    {
      pr_err ("no dma obj (not initialized?)!\n");
      return;
    }

  mem_mng_put (sys_dma->mm, (u64) (uintptr_t) ptr);
}

static uint64_t
mv_sys_dma_mem_virt2phys (void *va)
{
  return ((uint64_t) (uintptr_t) va - (uint64_t) (uintptr_t) __dma_virt_base) + __dma_phys_base;
}

void *
mv_sys_dma_mem_region_alloc (struct mv_sys_dma_mem_region *mem, size_t size, size_t align)
{
  u64 ans;
  struct sys_mem_dma_region_priv *priv;
  static bool warn_once;

  if (!mem)
    {
      if (!warn_once)
	{
	  pr_warn ("(%s) redirected to mv_sys_dma_mem_alloc()\n", __func__);
	  warn_once = true;
	}
      return mv_sys_dma_mem_alloc (size, align);
    }

  if (!mem_region_exist (mem))
    {
      pr_err ("memory region not created\n");
      return NULL;
    }

  priv = mem->priv;
  ans = mem_mng_get (priv->mm, size, align, "temp");
  if (ans == MEM_MNG_ILLEGAL_BASE)
    {
      pr_err ("failed to alloc mem!\n");
      return NULL;
    }

  return (void *) (uintptr_t) ans;
}

void
mv_sys_dma_mem_region_free (struct mv_sys_dma_mem_region *mem, void *ptr)
{
  struct sys_mem_dma_region_priv *priv;

  if (!mem)
    {
      mv_sys_dma_mem_free (ptr);
      return;
    }

  if (!mem_region_exist (mem))
    {
      pr_err ("memory region not created\n");
      return;
    }

  priv = mem->priv;
  mem_mng_put (priv->mm, (u64) (uintptr_t) ptr);
}

uint64_t
mv_sys_dma_mem_region_virt2phys (struct mv_sys_dma_mem_region *mem, void *va)
{
  if (!mem)
    return mv_sys_dma_mem_virt2phys (va);
  return ((uint64_t) (uintptr_t) va - (uint64_t) (uintptr_t) mem->dma_virt_base) +
	 mem->dma_phys_base;
}

struct mv_sys_dma_mem_region *
mv_sys_dma_mem_region_get (uint32_t mem_id)
{
  int i;

  for (i = 0; i < MEM_DMA_MAX_REGIONS; i++)
    {
      if (sys_dma_regions[i] && sys_dma_regions[i]->mem_id == mem_id)
	return sys_dma_regions[i];
    }
  return NULL;
}

static busy_mem_blk_t *
create_busy_blk (u64 base, u64 size, const char *name)
{
  busy_mem_blk_t *busy_blk;

  busy_blk = (busy_mem_blk_t *) clib_mem_alloc_or_null (sizeof (busy_mem_blk_t));
  if (!busy_blk)
    {
      pr_err ("no mem for busy-block obj!\n");
      return NULL;
    }

  busy_blk->base = base;
  busy_blk->end = base + size;

  strcpy (busy_blk->name, name);
  busy_blk->next = NULL;

  return busy_blk;
}

static int
cut_free_blk (mm_t *mm, u64 hold_base, u64 hold_end)
{
  free_mem_blk_t *prev_blk, *curr_blk, *new_blk;
  u64 alignment, align_base, base, end;
  int i;

  for (i = 0; i <= MEM_MNG_MAX_ALIGNMENT; i++)
    {
      prev_blk = new_blk = 0;
      curr_blk = mm->free_blks[i];

      alignment = (u64) (0x1 << i);
      align_base = MAKE_ALIGNED (hold_end, alignment);

      while (curr_blk)
	{
	  base = curr_blk->base;
	  end = curr_blk->end;

	  if ((hold_base <= base) && (hold_end <= end) && (hold_end > base))
	    {
	      if (align_base >= end || (align_base < end && ((end - align_base) < alignment)))
		{
		  if (prev_blk)
		    prev_blk->next = curr_blk->next;
		  else
		    mm->free_blks[i] = curr_blk->next;
		  if (curr_blk)
		    clib_mem_free (curr_blk);
		}
	      else
		curr_blk->base = align_base;
	      break;
	    }
	  else if ((hold_base > base) && (hold_end <= end))
	    {
	      if ((hold_base - base) >= alignment)
		{
		  if ((align_base < end) && ((end - align_base) >= alignment))
		    {
		      if ((new_blk = create_free_blk (align_base, end - align_base)) == NULL)
			{
			  pr_err ("failed to create free block!\n");
			  return -ENOMEM;
			}
		      new_blk->next = curr_blk->next;
		      curr_blk->next = new_blk;
		    }
		  curr_blk->end = hold_base;
		}
	      else if ((align_base < end) && ((end - align_base) >= alignment))
		curr_blk->base = align_base;
	      else
		{
		  if (prev_blk)
		    prev_blk->next = curr_blk->next;
		  else
		    mm->free_blks[i] = curr_blk->next;
		  if (curr_blk)
		    clib_mem_free (curr_blk);
		}
	      break;
	    }
	  else
	    {
	      prev_blk = curr_blk;
	      curr_blk = curr_blk->next;
	    }
	}
    }

  return 0;
}

static void
add_busy_blk (mm_t *mm, busy_mem_blk_t *new_blk)
{
  busy_mem_blk_t *curr_blk, *prev_blk;

  /* finds a place of a new busy block in the list of busy blocks */
  prev_blk = 0;
  curr_blk = mm->busy_blks;

  while (curr_blk && new_blk->base > curr_blk->base)
    {
      prev_blk = curr_blk;
      curr_blk = curr_blk->next;
    }

  /* insert the new busy block into the list of busy blocks */
  if (curr_blk)
    new_blk->next = curr_blk;
  if (prev_blk)
    prev_blk->next = new_blk;
  else
    mm->busy_blks = new_blk;
}

static int
add_free_blk (mm_t *mm, u64 base, u64 end)
{
  free_mem_blk_t *prev_blk, *curr_blk, *new_blk;
  u64 alignment, align_base;
  int i;

  /* Updates free lists to include  a just released block */
  for (i = 0; i <= MEM_MNG_MAX_ALIGNMENT; i++)
    {
      prev_blk = new_blk = 0;
      curr_blk = mm->free_blks[i];

      alignment = (u64) (0x1 << i);
      align_base = MAKE_ALIGNED (base, alignment);

      /* Goes to the next free list if there is no block to free */
      if (align_base >= end)
	continue;

      /* Looks for a free block that should be updated */
      while (curr_blk)
	{
	  if (align_base <= curr_blk->end)
	    {
	      if (end > curr_blk->end)
		{
		  free_mem_blk_t *nextB;
		  while (curr_blk->next && end > curr_blk->next->end)
		    {
		      nextB = curr_blk->next;
		      curr_blk->next = curr_blk->next->next;
		      if (nextB)
			clib_mem_free (nextB);
		    }

		  nextB = curr_blk->next;
		  if (!nextB || (nextB && end < nextB->base))
		    curr_blk->end = end;
		  else
		    {
		      curr_blk->end = nextB->end;
		      curr_blk->next = nextB->next;
		      if (nextB)
			clib_mem_free (nextB);
		    }
		}
	      else if ((end < curr_blk->base) && ((end - align_base) >= alignment))
		{
		  if ((new_blk = create_free_blk (align_base, end - align_base)) == NULL)
		    {
		      pr_err ("failed to create free block!\n");
		      return -ENOMEM;
		    }

		  new_blk->next = curr_blk;
		  if (prev_blk)
		    prev_blk->next = new_blk;
		  else
		    mm->free_blks[i] = new_blk;
		  break;
		}

	      if ((align_base < curr_blk->base) && (end >= curr_blk->base))
		curr_blk->base = align_base;

	      /* if size of the free block is less then alignment
	       * deletes that free block from the free list. */
	      if ((curr_blk->end - curr_blk->base) < alignment)
		{
		  if (prev_blk)
		    prev_blk->next = curr_blk->next;
		  else
		    mm->free_blks[i] = curr_blk->next;
		  if (curr_blk)
		    clib_mem_free (curr_blk);
		  curr_blk = NULL;
		}
	      break;
	    }
	  else
	    {
	      prev_blk = curr_blk;
	      curr_blk = curr_blk->next;
	    }
	}

      /* If no free block found to be updated, insert a new free block
       * to the end of the free list.
       */
      if (!curr_blk && ((((u64) (end - base)) & ((u64) (alignment - 1))) == 0))
	{
	  if ((new_blk = create_free_blk (align_base, end - base)) == NULL)
	    {
	      pr_err ("failed to create free block!\n");
	      return -ENOMEM;
	    }

	  if (prev_blk)
	    prev_blk->next = new_blk;
	  else
	    mm->free_blks[i] = new_blk;
	}

      /* Update boundaries of the new free block */
      if ((alignment == 1) && !new_blk)
	{
	  if (curr_blk && base > curr_blk->base)
	    base = curr_blk->base;
	  if (curr_blk && end < curr_blk->end)
	    end = curr_blk->end;
	}
    }

  return 0;
}

static bool
mem_region_exist (struct mv_sys_dma_mem_region *mem)
{
  int i;

  for (i = 0; i < MEM_DMA_MAX_REGIONS; i++)
    if (sys_dma_regions[i] == mem)
      return true;
  return false;
}
