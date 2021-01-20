/*
 *------------------------------------------------------------------
 * svm.c - shared VM allocation, mmap(...MAP_FIXED...)
 * library
 *
 * Copyright (c) 2009 Cisco and/or its affiliates.
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

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <signal.h>
#include <pthread.h>
#include <unistd.h>
#include <time.h>
#include <fcntl.h>
#include <string.h>
#include <vppinfra/clib.h>
#include <vppinfra/vec.h>
#include <vppinfra/hash.h>
#include <vppinfra/bitmap.h>
#include <vppinfra/fifo.h>
#include <vppinfra/time.h>
#include <vppinfra/heap.h>
#include <vppinfra/pool.h>
#include <vppinfra/format.h>

#include "svm.h"

static svm_region_t *root_rp;
static int root_rp_refcount;

#define MAXLOCK 2
static pthread_mutex_t *mutexes_held[MAXLOCK];
static int nheld;

svm_region_t *
svm_get_root_rp (void)
{
  return root_rp;
}

#define MUTEX_DEBUG

u64
svm_get_global_region_base_va ()
{
#ifdef CLIB_SANITIZE_ADDR
  return 0x200000000000;
#endif

#if __aarch64__
  /* On AArch64 VA space can have different size, from 36 to 48 bits.
     Here we are trying to detect VA bits by parsing /proc/self/maps
     address ranges */
  int fd;
  unformat_input_t input;
  u64 start, end = 0;
  u8 bits = 0;

  if ((fd = open ("/proc/self/maps", 0)) < 0)
    clib_unix_error ("open '/proc/self/maps'");

  unformat_init_clib_file (&input, fd);
  while (unformat_check_input (&input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (&input, "%llx-%llx", &start, &end))
	end--;
      unformat_skip_line (&input);
    }
  unformat_free (&input);
  close (fd);

  bits = count_leading_zeros (end);
  bits = 64 - bits;
  if (bits >= 36 && bits <= 48)
    return ((1ul << bits) / 4) - (2 * SVM_GLOBAL_REGION_SIZE);
  else
    clib_unix_error ("unexpected va bits '%u'", bits);
#endif

  /* default value */
  return 0x130000000ULL;
}

static void
region_lock (svm_region_t * rp, int tag)
{
  pthread_mutex_lock (&rp->mutex);
#ifdef MUTEX_DEBUG
  rp->mutex_owner_pid = getpid ();
  rp->mutex_owner_tag = tag;
#endif
  ASSERT (nheld < MAXLOCK);	//NOSONAR
  /*
   * Keep score of held mutexes so we can try to exit
   * cleanly if the world comes to an end at the worst possible
   * moment
   */
  mutexes_held[nheld++] = &rp->mutex;
}

static void
region_unlock (svm_region_t * rp)
{
  int i, j;
#ifdef MUTEX_DEBUG
  rp->mutex_owner_pid = 0;
  rp->mutex_owner_tag = 0;
#endif

  for (i = nheld - 1; i >= 0; i--)
    {
      if (mutexes_held[i] == &rp->mutex)
	{
	  for (j = i; j < MAXLOCK - 1; j++)
	    mutexes_held[j] = mutexes_held[j + 1];
	  nheld--;
	  goto found;
	}
    }
  ASSERT (0);

found:
  CLIB_MEMORY_BARRIER ();
  pthread_mutex_unlock (&rp->mutex);
}


static u8 *
format_svm_flags (u8 * s, va_list * args)
{
  uword f = va_arg (*args, uword);

  if (f & SVM_FLAGS_MHEAP)
    s = format (s, "MHEAP ");
  if (f & SVM_FLAGS_FILE)
    s = format (s, "FILE ");
  if (f & SVM_FLAGS_NODATA)
    s = format (s, "NODATA ");
  if (f & SVM_FLAGS_NEED_DATA_INIT)
    s = format (s, "INIT ");

  return (s);
}

static u8 *
format_svm_size (u8 * s, va_list * args)
{
  uword size = va_arg (*args, uword);

  if (size >= (1 << 20))
    {
      s = format (s, "(%d mb)", size >> 20);
    }
  else if (size >= (1 << 10))
    {
      s = format (s, "(%d kb)", size >> 10);
    }
  else
    {
      s = format (s, "(%d bytes)", size);
    }
  return (s);
}

u8 *
format_svm_region (u8 * s, va_list * args)
{
  svm_region_t *rp = va_arg (*args, svm_region_t *);
  int verbose = va_arg (*args, int);
  int i;
  uword lo, hi;

  s = format (s, "%s: base va 0x%x size 0x%x %U\n",
	      rp->region_name, rp->virtual_base,
	      rp->virtual_size, format_svm_size, rp->virtual_size);
  s = format (s, "  user_ctx 0x%x, bitmap_size %d\n",
	      rp->user_ctx, rp->bitmap_size);

  if (verbose)
    {
      s = format (s, "  flags: 0x%x %U\n", rp->flags,
		  format_svm_flags, rp->flags);
      s = format (s,
		  "  region_heap 0x%x data_base 0x%x data_heap 0x%x\n",
		  rp->region_heap, rp->data_base, rp->data_heap);
    }

  s = format (s, "  %d clients, pids: ", vec_len (rp->client_pids));

  for (i = 0; i < vec_len (rp->client_pids); i++)
    s = format (s, "%d ", rp->client_pids[i]);

  s = format (s, "\n");

  if (verbose)
    {
      lo = hi = ~0;

      s = format (s, "  VM in use: ");

      for (i = 0; i < rp->bitmap_size; i++)
	{
	  if (clib_bitmap_get_no_check (rp->bitmap, i) != 0)
	    {
	      if (lo == ~0)
		{
		  hi = lo = rp->virtual_base + i * MMAP_PAGESIZE;
		}
	      else
		{
		  hi = rp->virtual_base + i * MMAP_PAGESIZE;
		}
	    }
	  else
	    {
	      if (lo != ~0)
		{
		  hi = rp->virtual_base + i * MMAP_PAGESIZE - 1;
		  s = format (s, "   0x%x - 0x%x (%dk)\n", lo, hi,
			      (hi - lo) >> 10);
		  lo = hi = ~0;
		}
	    }
	}
    }

  return (s);
}

/*
 * rnd_pagesize
 * Round to a pagesize multiple, presumably 4k works
 */
static u64
rnd_pagesize (u64 size)
{
  u64 rv;

  rv = (size + (MMAP_PAGESIZE - 1)) & ~(MMAP_PAGESIZE - 1);
  return (rv);
}

/*
 * svm_data_region_setup
 */
static int
svm_data_region_create (svm_map_region_args_t * a, svm_region_t * rp)
{
  int fd;
  u8 junk = 0;
  uword map_size;

  map_size = rp->virtual_size - (MMAP_PAGESIZE +
				 (a->pvt_heap_size ? a->pvt_heap_size :
				  SVM_PVT_MHEAP_SIZE));

  if (a->flags & SVM_FLAGS_FILE)
    {
      struct stat statb;

      fd = open (a->backing_file, O_RDWR | O_CREAT, 0777);

      if (fd < 0)
	{
	  clib_unix_warning ("open");
	  return -1;
	}

      if (fstat (fd, &statb) < 0)
	{
	  clib_unix_warning ("fstat");
	  close (fd);
	  return -2;
	}

      if (statb.st_mode & S_IFREG)
	{
	  if (statb.st_size == 0)
	    {
	      if (lseek (fd, map_size, SEEK_SET) == (off_t) - 1)
		{
		  clib_unix_warning ("seek region size");
		  close (fd);
		  return -3;
		}
	      if (write (fd, &junk, 1) != 1)
		{
		  clib_unix_warning ("set region size");
		  close (fd);
		  return -3;
		}
	    }
	  else
	    {
	      map_size = rnd_pagesize (statb.st_size);
	    }
	}
      else
	{
	  map_size = a->backing_mmap_size;
	}

      ASSERT (map_size <= rp->virtual_size -
	      (MMAP_PAGESIZE + SVM_PVT_MHEAP_SIZE));

      if (mmap (rp->data_base, map_size, PROT_READ | PROT_WRITE,
		MAP_SHARED | MAP_FIXED, fd, 0) == MAP_FAILED)
	{
	  clib_unix_warning ("mmap");
	  close (fd);
	  return -3;
	}
      close (fd);
      CLIB_MEM_UNPOISON (rp->data_base, map_size);
      rp->backing_file = (char *) format (0, "%s%c", a->backing_file, 0);
      rp->flags |= SVM_FLAGS_FILE;
    }

  if (a->flags & SVM_FLAGS_MHEAP)
    {
      rp->data_heap = clib_mem_create_heap (rp->data_base, map_size,
					    1 /* locked */ , "svm data");

      rp->flags |= SVM_FLAGS_MHEAP;
    }
  return 0;
}

static int
svm_data_region_map (svm_map_region_args_t * a, svm_region_t * rp)
{
  int fd;
  u8 junk = 0;
  uword map_size;
  struct stat statb;

  map_size = rp->virtual_size -
    (MMAP_PAGESIZE
     + (a->pvt_heap_size ? a->pvt_heap_size : SVM_PVT_MHEAP_SIZE));

  if (a->flags & SVM_FLAGS_FILE)
    {

      fd = open (a->backing_file, O_RDWR, 0777);

      if (fd < 0)
	{
	  clib_unix_warning ("open");
	  return -1;
	}

      if (fstat (fd, &statb) < 0)
	{
	  clib_unix_warning ("fstat");
	  close (fd);
	  return -2;
	}

      if (statb.st_mode & S_IFREG)
	{
	  if (statb.st_size == 0)
	    {
	      if (lseek (fd, map_size, SEEK_SET) == (off_t) - 1)
		{
		  clib_unix_warning ("seek region size");
		  close (fd);
		  return -3;
		}
	      if (write (fd, &junk, 1) != 1)
		{
		  clib_unix_warning ("set region size");
		  close (fd);
		  return -3;
		}
	    }
	  else
	    {
	      map_size = rnd_pagesize (statb.st_size);
	    }
	}
      else
	{
	  map_size = a->backing_mmap_size;
	}

      ASSERT (map_size <= rp->virtual_size
	      - (MMAP_PAGESIZE
		 +
		 (a->pvt_heap_size ? a->pvt_heap_size : SVM_PVT_MHEAP_SIZE)));

      if (mmap (rp->data_base, map_size, PROT_READ | PROT_WRITE,
		MAP_SHARED | MAP_FIXED, fd, 0) == MAP_FAILED)
	{
	  clib_unix_warning ("mmap");
	  close (fd);
	  return -3;
	}
      close (fd);
      CLIB_MEM_UNPOISON (rp->data_base, map_size);
    }
  return 0;
}

u8 *
shm_name_from_svm_map_region_args (svm_map_region_args_t * a)
{
  u8 *shm_name;
  int root_path_offset = 0;
  int name_offset = 0;

  if (a->root_path)
    {
      /* Tolerate present or absent slashes */
      if (a->root_path[0] == '/')
	root_path_offset++;

      if (a->name[0] == '/')
	name_offset = 1;

      shm_name = format (0, "/%s-%s%c", &a->root_path[root_path_offset],
			 &a->name[name_offset], 0);
    }
  else
    shm_name = format (0, "%s%c", a->name, 0);
  return (shm_name);
}

void
svm_region_init_mapped_region (svm_map_region_args_t * a, svm_region_t * rp)
{
  pthread_mutexattr_t attr;
  pthread_condattr_t cattr;
  int nbits, words, bit;
  int overhead_space;
  void *oldheap;
  uword data_base;
  ASSERT (rp);
  int rv;

  clib_memset (rp, 0, sizeof (*rp));

  if (pthread_mutexattr_init (&attr))
    clib_unix_warning ("mutexattr_init");

  if (pthread_mutexattr_setpshared (&attr, PTHREAD_PROCESS_SHARED))
    clib_unix_warning ("mutexattr_setpshared");

  if (pthread_mutex_init (&rp->mutex, &attr))
    clib_unix_warning ("mutex_init");

  if (pthread_mutexattr_destroy (&attr))
    clib_unix_warning ("mutexattr_destroy");

  if (pthread_condattr_init (&cattr))
    clib_unix_warning ("condattr_init");

  if (pthread_condattr_setpshared (&cattr, PTHREAD_PROCESS_SHARED))
    clib_unix_warning ("condattr_setpshared");

  if (pthread_cond_init (&rp->condvar, &cattr))
    clib_unix_warning ("cond_init");

  if (pthread_condattr_destroy (&cattr))
    clib_unix_warning ("condattr_destroy");

  region_lock (rp, 1);

  rp->virtual_base = a->baseva;
  rp->virtual_size = a->size;

  rp->region_heap = clib_mem_create_heap
    (uword_to_pointer (a->baseva + MMAP_PAGESIZE, void *),
     (a->pvt_heap_size !=
      0) ? a->pvt_heap_size : SVM_PVT_MHEAP_SIZE, 1 /* locked */ ,
     "svm region");

  oldheap = svm_push_pvt_heap (rp);

  rp->region_name = (char *) format (0, "%s%c", a->name, 0);
  vec_add1 (rp->client_pids, getpid ());

  nbits = rp->virtual_size / MMAP_PAGESIZE;

  ASSERT (nbits > 0);
  rp->bitmap_size = nbits;
  words = (nbits + BITS (uword) - 1) / BITS (uword);
  vec_validate (rp->bitmap, words - 1);

  overhead_space = MMAP_PAGESIZE /* header */  +
    ((a->pvt_heap_size != 0) ? a->pvt_heap_size : SVM_PVT_MHEAP_SIZE);

  bit = 0;
  data_base = (uword) rp->virtual_base;

  if (a->flags & SVM_FLAGS_NODATA)
    rp->flags |= SVM_FLAGS_NEED_DATA_INIT;

  do
    {
      clib_bitmap_set_no_check (rp->bitmap, bit, 1);
      bit++;
      overhead_space -= MMAP_PAGESIZE;
      data_base += MMAP_PAGESIZE;
    }
  while (overhead_space > 0);

  rp->data_base = (void *) data_base;

  /*
   * Note: although the POSIX spec guarantees that only one
   * process enters this block, we have to play games
   * to hold off clients until e.g. the mutex is ready
   */
  rp->version = SVM_VERSION;

  /* setup the data portion of the region */

  rv = svm_data_region_create (a, rp);
  if (rv)
    {
      clib_warning ("data_region_create: %d", rv);
    }

  region_unlock (rp);

  svm_pop_heap (oldheap);
}

/*
 * svm_map_region
 */
void *
svm_map_region (svm_map_region_args_t * a)
{
  int svm_fd;
  svm_region_t *rp;
  int deadman = 0;
  u8 junk = 0;
  void *oldheap;
  int rv;
  int pid_holding_region_lock;
  u8 *shm_name;
  int dead_region_recovery = 0;
  int time_left;
  struct stat stat;
  struct timespec ts, tsrem;

  ASSERT ((a->size & ~(MMAP_PAGESIZE - 1)) == a->size);
  ASSERT (a->name);

  shm_name = shm_name_from_svm_map_region_args (a);

  if (CLIB_DEBUG > 1)
    clib_warning ("[%d] map region %s: shm_open (%s)",
		  getpid (), a->name, shm_name);

  svm_fd = shm_open ((char *) shm_name, O_RDWR | O_CREAT | O_EXCL, 0777);

  if (svm_fd >= 0)
    {
      if (fchmod (svm_fd, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP) < 0)
	clib_unix_warning ("segment chmod");
      /* This turns out to fail harmlessly if the client starts first */
      if (fchown (svm_fd, a->uid, a->gid) < 0)
	clib_unix_warning ("segment chown [ok if client starts first]");

      vec_free (shm_name);

      if (lseek (svm_fd, a->size, SEEK_SET) == (off_t) - 1)
	{
	  clib_warning ("seek region size");
	  close (svm_fd);
	  return (0);
	}
      if (write (svm_fd, &junk, 1) != 1)
	{
	  clib_warning ("set region size");
	  close (svm_fd);
	  return (0);
	}

      rp = mmap (uword_to_pointer (a->baseva, void *), a->size,
		 PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, svm_fd, 0);

      if (rp == (svm_region_t *) MAP_FAILED)
	{
	  clib_unix_warning ("mmap create");
	  close (svm_fd);
	  return (0);
	}
      close (svm_fd);
      CLIB_MEM_UNPOISON (rp, a->size);

      svm_region_init_mapped_region (a, rp);

      return ((void *) rp);
    }
  else
    {
      svm_fd = shm_open ((char *) shm_name, O_RDWR, 0777);

      vec_free (shm_name);

      if (svm_fd < 0)
	{
	  perror ("svm_region_map(mmap open)");
	  return (0);
	}

      /* Reset ownership in case the client started first */
      if (fchown (svm_fd, a->uid, a->gid) < 0)
	clib_unix_warning ("segment chown [ok if client starts first]");

      time_left = 20;
      while (1)
	{
	  if (0 != fstat (svm_fd, &stat))
	    {
	      clib_warning ("fstat failed: %d", errno);
	      close (svm_fd);
	      return (0);
	    }
	  if (stat.st_size > 0)
	    {
	      break;
	    }
	  if (0 == time_left)
	    {
	      clib_warning ("waiting for resize of shm file timed out");
	      close (svm_fd);
	      return (0);
	    }
	  ts.tv_sec = 0;
	  ts.tv_nsec = 100000000;
	  while (nanosleep (&ts, &tsrem) < 0)
	    ts = tsrem;
	  time_left--;
	}

      rp = mmap (0, MMAP_PAGESIZE,
		 PROT_READ | PROT_WRITE, MAP_SHARED, svm_fd, 0);

      if (rp == (svm_region_t *) MAP_FAILED)
	{
	  close (svm_fd);
	  clib_warning ("mmap");
	  return (0);
	}

      CLIB_MEM_UNPOISON (rp, MMAP_PAGESIZE);

      /*
       * We lost the footrace to create this region; make sure
       * the winner has crossed the finish line.
       */
      while (rp->version == 0 && deadman++ < 5)
	{
	  sleep (1);
	}

      /*
       * <bleep>-ed?
       */
      if (rp->version == 0)
	{
	  clib_warning ("rp->version %d not %d", rp->version, SVM_VERSION);
	  close (svm_fd);
	  munmap (rp, a->size);
	  return (0);
	}
      /* Remap now that the region has been placed */
      a->baseva = rp->virtual_base;
      a->size = rp->virtual_size;
      munmap (rp, MMAP_PAGESIZE);

      rp = (void *) mmap (uword_to_pointer (a->baseva, void *), a->size,
			  PROT_READ | PROT_WRITE,
			  MAP_SHARED | MAP_FIXED, svm_fd, 0);
      if ((uword) rp == (uword) MAP_FAILED)
	{
	  clib_unix_warning ("mmap");
	  close (svm_fd);
	  return (0);
	}

      close (svm_fd);

      CLIB_MEM_UNPOISON (rp, a->size);

      if ((uword) rp != rp->virtual_base)
	{
	  clib_warning ("mmap botch");
	}

      /*
       * Try to fix the region mutex if it is held by
       * a dead process
       */
      pid_holding_region_lock = rp->mutex_owner_pid;
      if (pid_holding_region_lock && kill (pid_holding_region_lock, 0) < 0)
	{
	  pthread_mutexattr_t attr;
	  clib_warning
	    ("region %s mutex held by dead pid %d, tag %d, force unlock",
	     rp->region_name, pid_holding_region_lock, rp->mutex_owner_tag);
	  /* owner pid is nonexistent */
	  if (pthread_mutexattr_init (&attr))
	    clib_unix_warning ("mutexattr_init");
	  if (pthread_mutexattr_setpshared (&attr, PTHREAD_PROCESS_SHARED))
	    clib_unix_warning ("mutexattr_setpshared");
	  if (pthread_mutex_init (&rp->mutex, &attr))
	    clib_unix_warning ("mutex_init");
	  dead_region_recovery = 1;
	}

      if (dead_region_recovery)
	clib_warning ("recovery: attempt to re-lock region");

      region_lock (rp, 2);
      oldheap = svm_push_pvt_heap (rp);
      vec_add1 (rp->client_pids, getpid ());

      if (dead_region_recovery)
	clib_warning ("recovery: attempt svm_data_region_map");

      rv = svm_data_region_map (a, rp);
      if (rv)
	{
	  clib_warning ("data_region_map: %d", rv);
	}

      if (dead_region_recovery)
	clib_warning ("unlock and continue");

      region_unlock (rp);

      svm_pop_heap (oldheap);

      return ((void *) rp);

    }
  return 0;			/* NOTREACHED *///NOSONAR
}

static void
svm_mutex_cleanup (void)
{
  int i;
  for (i = 0; i < nheld; i++)
    {
      pthread_mutex_unlock (mutexes_held[i]);	//NOSONAR
    }
}

static int
svm_region_init_internal (svm_map_region_args_t * a)
{
  svm_region_t *rp;
  u64 ticks = clib_cpu_time_now ();
  uword randomize_baseva;

  /* guard against klutz calls */
  if (root_rp)
    return -1;

  root_rp_refcount++;

  atexit (svm_mutex_cleanup);

  /* Randomize the shared-VM base at init time */
  if (MMAP_PAGESIZE <= (4 << 10))
    randomize_baseva = (ticks & 15) * MMAP_PAGESIZE;
  else
    randomize_baseva = (ticks & 3) * MMAP_PAGESIZE;

  a->baseva += randomize_baseva;

  rp = svm_map_region (a);
  if (!rp)
    return -1;

  region_lock (rp, 3);

  /* Set up the main region data structures */
  if (rp->flags & SVM_FLAGS_NEED_DATA_INIT)
    {
      svm_main_region_t *mp = 0;
      void *oldheap;

      rp->flags &= ~(SVM_FLAGS_NEED_DATA_INIT);

      oldheap = svm_push_pvt_heap (rp);
      vec_validate (mp, 0);
      mp->name_hash = hash_create_string (0, sizeof (uword));
      mp->root_path = a->root_path ? format (0, "%s%c", a->root_path, 0) : 0;
      mp->uid = a->uid;
      mp->gid = a->gid;
      rp->data_base = mp;
      svm_pop_heap (oldheap);
    }
  region_unlock (rp);
  root_rp = rp;

  return 0;
}

void
svm_region_init (void)
{
  svm_map_region_args_t _a, *a = &_a;

  clib_memset (a, 0, sizeof (*a));
  a->root_path = 0;
  a->name = SVM_GLOBAL_REGION_NAME;
  a->baseva = svm_get_global_region_base_va ();
  a->size = SVM_GLOBAL_REGION_SIZE;
  a->flags = SVM_FLAGS_NODATA;
  a->uid = 0;
  a->gid = 0;

  svm_region_init_internal (a);
}

int
svm_region_init_chroot (const char *root_path)
{
  svm_map_region_args_t _a, *a = &_a;

  clib_memset (a, 0, sizeof (*a));
  a->root_path = root_path;
  a->name = SVM_GLOBAL_REGION_NAME;
  a->baseva = svm_get_global_region_base_va ();
  a->size = SVM_GLOBAL_REGION_SIZE;
  a->flags = SVM_FLAGS_NODATA;
  a->uid = 0;
  a->gid = 0;

  return svm_region_init_internal (a);
}

void
svm_region_init_chroot_uid_gid (const char *root_path, int uid, int gid)
{
  svm_map_region_args_t _a, *a = &_a;

  clib_memset (a, 0, sizeof (*a));
  a->root_path = root_path;
  a->name = SVM_GLOBAL_REGION_NAME;
  a->baseva = svm_get_global_region_base_va ();
  a->size = SVM_GLOBAL_REGION_SIZE;
  a->flags = SVM_FLAGS_NODATA;
  a->uid = uid;
  a->gid = gid;

  svm_region_init_internal (a);
}

void
svm_region_init_args (svm_map_region_args_t * a)
{
  svm_region_init_internal (a);
}

void *
svm_region_find_or_create (svm_map_region_args_t * a)
{
  svm_main_region_t *mp;
  svm_region_t *rp;
  uword need_nbits;
  int index, i;
  void *oldheap;
  uword *p;
  u8 *name;
  svm_subregion_t *subp;

  ASSERT (root_rp);

  a->size += MMAP_PAGESIZE +
    ((a->pvt_heap_size != 0) ? a->pvt_heap_size : SVM_PVT_MHEAP_SIZE);
  a->size = rnd_pagesize (a->size);

  region_lock (root_rp, 4);
  oldheap = svm_push_pvt_heap (root_rp);
  mp = root_rp->data_base;

  ASSERT (mp);

  /* Map the named region from the correct chroot environment */
  if (a->root_path == NULL)
    a->root_path = (char *) mp->root_path;

  /*
   * See if this region is already known. If it is, we're
   * almost done...
   */
  p = hash_get_mem (mp->name_hash, a->name);

  if (p)
    {
      rp = svm_map_region (a);
      region_unlock (root_rp);
      svm_pop_heap (oldheap);
      return rp;
    }

  /* Create the region. */
  ASSERT ((a->size & ~(MMAP_PAGESIZE - 1)) == a->size);

  need_nbits = a->size / MMAP_PAGESIZE;

  index = 1;			/* $$$ fixme, figure out how many bit to really skip */

  /*
   * Scan the virtual space allocation bitmap, looking for a large
   * enough chunk
   */
  do
    {
      if (clib_bitmap_get_no_check (root_rp->bitmap, index) == 0)
	{
	  for (i = 0; i < (need_nbits - 1); i++)
	    {
	      if (clib_bitmap_get_no_check (root_rp->bitmap, index + i) == 1)
		{
		  index = index + i;
		  goto next;
		}
	    }
	  break;
	}
      index++;
    next:;
    }
  while (index < root_rp->bitmap_size);

  /* Completely out of VM? */
  if (index >= root_rp->bitmap_size)
    {
      clib_warning ("region %s: not enough VM to allocate 0x%llx (%lld)",
		    root_rp->region_name, a->size, a->size);
      svm_pop_heap (oldheap);
      region_unlock (root_rp);
      return 0;
    }

  /*
   * Mark virtual space allocated
   */
#if CLIB_DEBUG > 1
  clib_warning ("set %d bits at index %d", need_nbits, index);
#endif

  for (i = 0; i < need_nbits; i++)
    {
      clib_bitmap_set_no_check (root_rp->bitmap, index + i, 1);
    }

  /* Place this region where it goes... */
  a->baseva = root_rp->virtual_base + index * MMAP_PAGESIZE;

  rp = svm_map_region (a);

  pool_get (mp->subregions, subp);
  name = format (0, "%s%c", a->name, 0);
  subp->subregion_name = name;

  hash_set_mem (mp->name_hash, name, subp - mp->subregions);

  svm_pop_heap (oldheap);

  region_unlock (root_rp);

  return (rp);
}

void
svm_region_unlink (svm_region_t * rp)
{
  svm_map_region_args_t _a, *a = &_a;
  svm_main_region_t *mp;
  u8 *shm_name;

  ASSERT (root_rp);
  ASSERT (rp);
  ASSERT (vec_c_string_is_terminated (rp->region_name));

  mp = root_rp->data_base;
  ASSERT (mp);

  a->root_path = (char *) mp->root_path;
  a->name = rp->region_name;
  shm_name = shm_name_from_svm_map_region_args (a);
  if (CLIB_DEBUG > 1)
    clib_warning ("[%d] shm_unlink (%s)", getpid (), shm_name);
  shm_unlink ((const char *) shm_name);
  vec_free (shm_name);
}

/*
 * svm_region_unmap
 *
 * Let go of the indicated region. If the calling process
 * is the last customer, throw it away completely.
 * The root region mutex guarantees atomicity with respect to
 * a new region client showing up at the wrong moment.
 */
void
svm_region_unmap_internal (void *rp_arg, u8 is_client)
{
  int i, mypid = getpid ();
  int nclients_left;
  void *oldheap;
  uword virtual_base, virtual_size;
  svm_region_t *rp = rp_arg;
  char *name;

  /*
   * If we take a signal while holding one or more shared-memory
   * mutexes, we may end up back here from an otherwise
   * benign exit handler. Bail out to avoid a recursive
   * mutex screw-up.
   */
  if (nheld)
    return;

  ASSERT (rp);
  ASSERT (root_rp);

  if (CLIB_DEBUG > 1)
    clib_warning ("[%d] unmap region %s", getpid (), rp->region_name);

  region_lock (root_rp, 5);
  region_lock (rp, 6);

  oldheap = svm_push_pvt_heap (rp);	/* nb vec_delete() in the loop */

  /* Remove the caller from the list of mappers */
  CLIB_MEM_UNPOISON (rp->client_pids, vec_bytes (rp->client_pids));
  for (i = 0; i < vec_len (rp->client_pids); i++)
    {
      if (rp->client_pids[i] == mypid)
	{
	  vec_delete (rp->client_pids, 1, i);
	  goto found;
	}
    }
  clib_warning ("pid %d AWOL", mypid);

found:

  svm_pop_heap (oldheap);

  nclients_left = vec_len (rp->client_pids);
  virtual_base = rp->virtual_base;
  virtual_size = rp->virtual_size;

  if (nclients_left == 0)
    {
      int index, nbits, i;
      svm_main_region_t *mp;
      uword *p;
      svm_subregion_t *subp;

      /* Kill the region, last guy on his way out */

      oldheap = svm_push_pvt_heap (root_rp);
      name = vec_dup (rp->region_name);

      virtual_base = rp->virtual_base;
      virtual_size = rp->virtual_size;

      /* Figure out which bits to clear in the root region bitmap */
      index = (virtual_base - root_rp->virtual_base) / MMAP_PAGESIZE;

      nbits = (virtual_size + MMAP_PAGESIZE - 1) / MMAP_PAGESIZE;

#if CLIB_DEBUG > 1
      clib_warning ("clear %d bits at index %d", nbits, index);
#endif
      /* Give back the allocated VM */
      for (i = 0; i < nbits; i++)
	{
	  clib_bitmap_set_no_check (root_rp->bitmap, index + i, 0);
	}

      mp = root_rp->data_base;

      p = hash_get_mem (mp->name_hash, name);

      /* Better never happen ... */
      if (p == NULL)
	{
	  region_unlock (rp);
	  region_unlock (root_rp);
	  svm_pop_heap (oldheap);
	  clib_warning ("Region name '%s' not found?", name);
	  return;
	}

      /* Remove from the root region subregion pool */
      subp = mp->subregions + p[0];
      pool_put (mp->subregions, subp);

      hash_unset_mem (mp->name_hash, name);

      vec_free (name);

      region_unlock (rp);

      /* If a client asks for the cleanup, don't unlink the backing
       * file since we can't tell if it has been recreated. */
      if (!is_client)
	svm_region_unlink (rp);

      munmap ((void *) virtual_base, virtual_size);
      region_unlock (root_rp);
      svm_pop_heap (oldheap);
      return;
    }

  region_unlock (rp);
  region_unlock (root_rp);

  munmap ((void *) virtual_base, virtual_size);
}

void
svm_region_unmap (void *rp_arg)
{
  svm_region_unmap_internal (rp_arg, 0 /* is_client */ );
}

void
svm_region_unmap_client (void *rp_arg)
{
  svm_region_unmap_internal (rp_arg, 1 /* is_client */ );
}

/*
 * svm_region_exit
 */
static void
svm_region_exit_internal (u8 is_client)
{
  void *oldheap;
  int i, mypid = getpid ();
  uword virtual_base, virtual_size;

  /* It felt so nice we did it twice... */
  if (root_rp == 0)
    return;

  if (--root_rp_refcount > 0)
    return;

  /*
   * If we take a signal while holding one or more shared-memory
   * mutexes, we may end up back here from an otherwise
   * benign exit handler. Bail out to avoid a recursive
   * mutex screw-up.
   */
  if (nheld)
    return;

  region_lock (root_rp, 7);
  oldheap = svm_push_pvt_heap (root_rp);

  virtual_base = root_rp->virtual_base;
  virtual_size = root_rp->virtual_size;

  CLIB_MEM_UNPOISON (root_rp->client_pids, vec_bytes (root_rp->client_pids));
  for (i = 0; i < vec_len (root_rp->client_pids); i++)
    {
      if (root_rp->client_pids[i] == mypid)
	{
	  vec_delete (root_rp->client_pids, 1, i);
	  goto found;
	}
    }
  clib_warning ("pid %d AWOL", mypid);

found:

  if (!is_client && vec_len (root_rp->client_pids) == 0)
    svm_region_unlink (root_rp);

  region_unlock (root_rp);
  svm_pop_heap (oldheap);

  root_rp = 0;
  munmap ((void *) virtual_base, virtual_size);
}

void
svm_region_exit (void)
{
  svm_region_exit_internal (0 /* is_client */ );
}

void
svm_region_exit_client (void)
{
  svm_region_exit_internal (1 /* is_client */ );
}

void
svm_client_scan_this_region_nolock (svm_region_t * rp)
{
  int j;
  int mypid = getpid ();
  void *oldheap;

  for (j = 0; j < vec_len (rp->client_pids); j++)
    {
      if (mypid == rp->client_pids[j])
	continue;
      if (rp->client_pids[j] && (kill (rp->client_pids[j], 0) < 0))
	{
	  clib_warning ("%s: cleanup ghost pid %d",
			rp->region_name, rp->client_pids[j]);
	  /* nb: client vec in rp->region_heap */
	  oldheap = svm_push_pvt_heap (rp);
	  vec_delete (rp->client_pids, 1, j);
	  j--;
	  svm_pop_heap (oldheap);
	}
    }
}


/*
 * Scan svm regions for dead clients
 */
void
svm_client_scan (const char *root_path)
{
  int i, j;
  svm_main_region_t *mp;
  svm_map_region_args_t *a = 0;
  svm_region_t *root_rp;
  svm_region_t *rp;
  svm_subregion_t *subp;
  u8 *name = 0;
  u8 **svm_names = 0;
  void *oldheap;
  int mypid = getpid ();

  vec_validate (a, 0);

  svm_region_init_chroot (root_path);

  root_rp = svm_get_root_rp ();

  pthread_mutex_lock (&root_rp->mutex);

  mp = root_rp->data_base;

  for (j = 0; j < vec_len (root_rp->client_pids); j++)
    {
      if (mypid == root_rp->client_pids[j])
	continue;
      if (root_rp->client_pids[j] && (kill (root_rp->client_pids[j], 0) < 0))
	{
	  clib_warning ("%s: cleanup ghost pid %d",
			root_rp->region_name, root_rp->client_pids[j]);
	  /* nb: client vec in root_rp->region_heap */
	  oldheap = svm_push_pvt_heap (root_rp);
	  vec_delete (root_rp->client_pids, 1, j);
	  j--;
	  svm_pop_heap (oldheap);
	}
    }

  /*
   * Snapshoot names, can't hold root rp mutex across
   * find_or_create.
   */
  /* *INDENT-OFF* */
  pool_foreach (subp, mp->subregions)  {
        name = vec_dup (subp->subregion_name);
        vec_add1(svm_names, name);
      }
  /* *INDENT-ON* */

  pthread_mutex_unlock (&root_rp->mutex);

  for (i = 0; i < vec_len (svm_names); i++)
    {
      vec_validate (a, 0);
      a->root_path = root_path;
      a->name = (char *) svm_names[i];
      rp = svm_region_find_or_create (a);
      if (rp)
	{
	  pthread_mutex_lock (&rp->mutex);

	  svm_client_scan_this_region_nolock (rp);

	  pthread_mutex_unlock (&rp->mutex);
	  svm_region_unmap (rp);
	  vec_free (svm_names[i]);
	}
      vec_free (a);
    }
  vec_free (svm_names);

  svm_region_exit ();

  vec_free (a);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
